defmodule :m_ssl_trace do
  use Bitwise
  @behaviour :gen_server
  require Record

  Record.defrecord(:r_state, :state,
    file: :undefined,
    types_on: [],
    io_device: :undefined,
    write_fun: :undefined
  )

  def start() do
    start(&:io.format/2)
  end

  def start(:file) do
    start(&:io.format/2, [:file])
  end

  def start(ioFmtFun)
      when is_function(ioFmtFun, 2) or
             is_function(ioFmtFun, 3) do
    start(ioFmtFun, [])
  end

  def start(ioFmtFun, traceOpts)
      when is_function(
             ioFmtFun,
             2
           ) or
             is_function(ioFmtFun, 3) or
             is_list(traceOpts) do
    writeFun = fn f, a, s ->
      ioFmtFun.(f, a)
      s
    end

    {:ok, pid} =
      :gen_server.start({:local, :ssl_trace}, :ssl_trace, [{:write_fun, writeFun}, traceOpts], [])

    true = :erlang.is_process_alive(pid)

    try do
      :dbg.start()
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end

    start_tracer(ioFmtFun, traceOpts)
    :dbg.p(:all, [:timestamp, :c])
    {:ok, get_all_trace_profiles()}
  end

  def stop() do
    try do
      :dbg.stop()
      :ok = :gen_server.call(:ssl_trace, :file_close, 15000)
      :gen_server.stop(:ssl_trace)
    catch
      _, _ ->
        :ok
    end
  end

  def on() do
    on(get_all_trace_profiles())
  end

  def on(type) do
    switch(:on, type)
  end

  def off() do
    off(get_all_trace_profiles())
  end

  def off(type) do
    switch(:off, type)
  end

  def is_on() do
    :gen_server.call(:ssl_trace, :get_on, 15000)
  end

  def is_off() do
    get_all_trace_profiles() -- is_on()
  end

  def write(fmt, args) do
    :gen_server.call(:ssl_trace, {:write, fmt, args}, 15000)
  end

  def init(args) do
    try do
      :ets.new(:ssl_trace, [:public, :named_table])
    catch
      :exit, :badarg ->
        :ok
    end

    {:ok, r_state(write_fun: :proplists.get_value(:write_fun, args))}
  end

  def handle_call({:switch, :on, profiles}, _From, state) do
    for p <- profiles do
      enable_profile(p)
    end

    nowOn = :lists.usort(profiles ++ r_state(state, :types_on))
    {:reply, {:ok, nowOn}, r_state(state, types_on: nowOn)}
  end

  def handle_call({:switch, :off, profiles}, _From, state) do
    stillOn = r_state(state, :types_on) -- profiles

    for p <- profiles do
      disable_profile(p)
    end

    {:reply, {:ok, stillOn}, r_state(state, types_on: stillOn)}
  end

  def handle_call(:get_on, _From, state) do
    {:reply, r_state(state, :types_on), state}
  end

  def handle_call({:file_open, file}, _From, state) do
    {:ok, iODevice} = :file.open(file, [:write])
    {:reply, {:ok, iODevice}, r_state(state, io_device: iODevice)}
  end

  def handle_call(:file_close, _From, r_state(io_device: iODevice) = state) do
    case is_pid(iODevice) do
      true ->
        :ok = :file.close(iODevice)

      _ ->
        :ok
    end

    {:reply, :ok, r_state(state, io_device: :undefined)}
  end

  def handle_call({:write, fmt, args}, _From, state) do
    r_state(io_device: iODevice, write_fun: writeFun0) = state
    writeFun = get_write_fun(iODevice, writeFun0)
    writeFun.(fmt, args, :processed)
    {:reply, :ok, state}
  end

  def handle_call(c, _From, state) do
    :io.format(:"*** Unknown call: ~p~n", [c])
    {:reply, {:error, {:unknown_call, c}}, state}
  end

  def handle_cast({:new_proc, pid}, state) do
    :erlang.monitor(:process, pid)
    {:noreply, state}
  end

  def handle_cast(c, state) do
    :io.format(:"*** Unknown cast: ~p~n", [c])
    {:noreply, state}
  end

  def handle_info(
        {:DOWN, _MonitorRef, :process, pid, _Info},
        state
      ) do
    :timer.apply_after(20000, :ssl_trace, :ets_delete, [:ssl_trace, pid])
    {:noreply, state}
  end

  def handle_info(c, state) do
    :io.format(:"*** Unknown info: ~p~n", [c])
    {:noreply, state}
  end

  defp get_proc_stack(pid) when is_pid(pid) do
    try do
      :ets.lookup_element(:ssl_trace, pid, 2)
    catch
      :error, :badarg ->
        new_proc(pid)
        :ets.insert(:ssl_trace, {pid, []})
        []
    end
  end

  defp new_proc(pid) when is_pid(pid) do
    :gen_server.cast(:ssl_trace, {:new_proc, pid})
  end

  defp put_proc_stack(pid, stack)
       when is_pid(pid) and
              is_list(stack) do
    :ets.insert(:ssl_trace, {pid, stack})
  end

  def ets_delete(tab, key) do
    try do
      :ets.delete(tab, key)
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end
  end

  defp start_tracer(writeFun, traceOpts)
       when is_function(
              writeFun,
              2
            ) do
    start_tracer(
      fn f, a, s ->
        writeFun.(f, a)
        s
      end,
      traceOpts
    )
  end

  defp start_tracer(writeFun, traceOpts)
       when is_function(
              writeFun,
              3
            ) do
    acc0 = [{:budget, :proplists.get_value(:budget, traceOpts, 10000)}]

    acc1 =
      case :lists.member(:file, traceOpts) do
        true ->
          traceFile =
            case :init.get_argument(:ssl_trace_file) do
              {:ok, [[path]]} ->
                path

              _ ->
                ~c"ssl_trace.txt"
            end

          [{:file, traceFile} | acc0]

        _ ->
          acc0
      end

    start_dbg_tracer(writeFun, acc1)
  end

  defp start_dbg_tracer(writeFun, initHandlerAcc0)
       when is_function(writeFun, 3) do
    handler = fn arg, acc0 ->
      try_handle_trace(:gen_server.call(:ssl_trace, :get_on, 15000), arg, writeFun, acc0)
    end

    initHandlerAcc1 =
      case :proplists.get_value(
             :file,
             initHandlerAcc0
           ) do
        :undefined ->
          initHandlerAcc0

        file ->
          {:ok, iODevice} =
            :gen_server.call(
              :ssl_trace,
              {:file_open, file},
              15000
            )

          [{:io_device, iODevice} | initHandlerAcc0]
      end

    :dbg.tracer(:process, {handler, initHandlerAcc1})
  end

  defp try_handle_trace(profilesOn, arg, writeFun0, handlerAcc) do
    iODevice = :proplists.get_value(:io_device, handlerAcc)
    writeFun = get_write_fun(iODevice, writeFun0)
    budget0 = :proplists.get_value(:budget, handlerAcc, 0)
    timestamp = trace_ts(arg)
    pid = trace_pid(arg)
    traceInfo = trace_info(arg)
    module = trace_module(traceInfo)
    processStack = get_proc_stack(pid)
    role = :proplists.get_value(:role, processStack, :"?")

    budget1 =
      :lists.foldl(
        fn profile, bAcc ->
          case bAcc > 1 do
            true ->
              try do
                module.handle_trace(profile, traceInfo, processStack)
              catch
                _, _ ->
                  bAcc
              else
                {:skip, newProcessStack} ->
                  put_proc_stack(pid, newProcessStack)
                  reduce_budget(bAcc, writeFun)

                {txt, newProcessStack} when is_list(txt) ->
                  put_proc_stack(pid, newProcessStack)

                  write_txt(
                    writeFun,
                    timestamp,
                    pid,
                    common_prefix(
                      traceInfo,
                      role,
                      profile
                    ) ++ txt
                  )

                  reduce_budget(bAcc, writeFun)
              end

            _ ->
              bAcc
          end
        end,
        budget0,
        profilesOn
      )

    budget2 =
      case budget1 == budget0 and budget0 > 0 do
        true ->
          writeFun.(
            ~c"~.100s ~W~n",
            [
              :io_lib.format(
                ~c"~s ~p ~s ",
                [
                  :lists.flatten(timestamp),
                  pid,
                  common_prefix(
                    traceInfo,
                    role,
                    ~c"   "
                  )
                ]
              ),
              traceInfo,
              7
            ],
            :processed
          )

          reduce_budget(budget0, writeFun)

        _ ->
          budget1
      end

    [
      {:budget, budget2}
      | :proplists.delete(
          :budget,
          handlerAcc
        )
    ]
  end

  defp get_write_fun(iODevice, writeFun0) do
    case is_pid(iODevice) do
      true ->
        fn format, args, return ->
          :ok = :io.format(iODevice, format, args)
          return
        end

      false ->
        writeFun0
    end
  end

  defp reduce_budget(b, _) when b > 1 do
    b - 1
  end

  defp reduce_budget(_, writeFun) do
    case :erlang.get(:no_budget_msg_written) do
      :undefined ->
        writeFun.(~c"No more trace budget!~n", [], :processed)
        :erlang.put(:no_budget_msg_written, true)

      _ ->
        :ok
    end

    0
  end

  defp write_txt(writeFun, timestamp, pid, txt)
       when is_list(txt) do
    writeFun.(~c"~s ~p ~ts~n", [timestamp, pid, txt], :processed)
  end

  defp get_all_trace_profiles() do
    unsorted =
      for {profile, _TraceOn, _TraceOff, _TracedFuns} <- trace_profiles() do
        profile
      end

    :lists.usort(unsorted)
  end

  defp switch(x, profile)
       when is_atom(profile) or
              is_tuple(profile) do
    switch(x, [profile])
  end

  defp switch(x, profiles) when is_list(profiles) do
    case :erlang.whereis(:ssl_trace) do
      :undefined ->
        start()

      _ ->
        :ok
    end

    case unknown_types(profiles, get_all_trace_profiles(), []) do
      [] ->
        :gen_server.call(:ssl_trace, {:switch, x, profiles}, 15000)

      l ->
        {:error, {:unknown, l}}
    end
  end

  defp unknown_types([], _AllProfiles, acc) do
    acc
  end

  defp unknown_types([profile | tail], allProfiles, acc)
       when is_atom(profile) do
    case :lists.member(profile, allProfiles) do
      false ->
        unknown_types(tail, allProfiles, [profile | acc])

      _ ->
        unknown_types(tail, allProfiles, acc)
    end
  end

  defp unknown_types([modProfile = {_Mod, profile} | tail], allProfiles, acc)
       when is_tuple(modProfile) do
    unknown_types([profile | tail], allProfiles, acc)
  end

  defp trace_pid(t)
       when :erlang.element(1, t) == :trace or
              :erlang.element(1, t) == :trace_ts do
    :erlang.element(2, t)
  end

  defp trace_ts(t) when :erlang.element(1, t) == :trace_ts do
    ts(:erlang.element(tuple_size(t), t))
  end

  defp ts({_, _, usec} = now) when is_integer(usec) do
    {_Date, {hH, mM, sS}} = :calendar.now_to_local_time(now)
    :io_lib.format(~c"~.2.0w:~.2.0w:~.2.0w.~.6.0w", [hH, mM, sS, usec])
  end

  defp ts(_) do
    ~c"-"
  end

  defp trace_info(t) do
    case :erlang.tuple_to_list(t) do
      [:trace, _Pid | info] ->
        :erlang.list_to_tuple(info)

      [:trace_ts, _Pid | infoTS] ->
        :erlang.list_to_tuple(:lists.droplast(infoTS))
    end
  end

  defp trace_module(info) do
    {module, _, _} = :erlang.element(2, info)
    module
  end

  defp common_prefix({:call, {m, f, args}}, role, profile) do
    [:io_lib.format(~c"~s (~w) -> ~w:~w/~w ", [profile, role, m, f, length(args)])]
  end

  defp common_prefix({:return_from, {m, f, arity}, _Return}, role, profile) do
    [:io_lib.format(~c"~s (~w) <- ~w:~w/~w returned ", [profile, role, m, f, arity])]
  end

  defp common_prefix({:exception_from, {m, f, arity}, reason}, role, profile) do
    [
      :io_lib.format(
        ~c"~s (~w) exception_from ~w:~w/~w  ~w",
        [profile, role, m, f, arity, reason]
      )
    ]
  end

  defp common_prefix(_E, _Role, _Profile) do
    []
  end

  defp enable_profile(profile) when is_atom(profile) do
    for m <- modules(profile) do
      enable_profile({m, profile})
    end
  end

  defp enable_profile({module, profile})
       when is_atom(module) or
              is_atom(profile) do
    {^profile, traceOn, _, allFuns} = profile(profile)
    funs = :proplists.get_value(module, allFuns)
    process_profile(module, traceOn, funs)
  end

  defp disable_profile(profile) when is_atom(profile) do
    for m <- modules(profile) do
      disable_profile({m, profile})
    end
  end

  defp disable_profile({module, profile})
       when is_atom(module) or
              is_atom(profile) do
    {^profile, _, traceOff, allFuns} = profile(profile)
    funs = :proplists.get_value(module, allFuns)
    process_profile(module, traceOff, funs)
  end

  defp process_profile(module, action, funs) when is_atom(module) do
    for {f, a} <- funs do
      action.(module, f, a)
    end
  end

  defp profile(p) do
    :lists.keyfind(p, 1, trace_profiles())
  end

  defp modules(p) do
    {_, _, _, funs} = profile(p)
    :proplists.get_keys(funs)
  end

  def trace_profiles() do
    [
      {:api,
       fn m, f, a ->
         :dbg.tpl(m, f, a, :x)
       end,
       fn m, f, a ->
         :dbg.ctpl(m, f, a)
       end,
       [
         {:ssl, [{:listen, 2}, {:connect, 3}, {:handshake, 2}, {:close, 1}]},
         {:ssl_gen_statem,
          [{:initial_hello, 3}, {:connect, 8}, {:close, 2}, {:terminate_alert, 1}]},
         {:tls_gen_connection, [{:start_connection_tree, 5}, {:socket_control, 6}]}
       ]},
      {:csp,
       fn m, f, a ->
         :dbg.tpl(m, f, a, :x)
       end,
       fn m, f, a ->
         :dbg.ctpl(m, f, a)
       end,
       [
         {:ssl_handshake,
          [
            {:maybe_add_certificate_status_request, 4},
            {:client_hello_extensions, 10},
            {:cert_status_check, 5},
            {:get_ocsp_responder_list, 1},
            {:handle_ocsp_extension, 2},
            {:path_validation, 10},
            {:handle_server_hello_extensions, 10},
            {:handle_client_hello_extensions, 10},
            {:cert_status_check, 5}
          ]},
         {:public_key,
          [
            {:ocsp_extensions, 1},
            {:pkix_ocsp_validate, 5},
            {:ocsp_responder_id, 1},
            {:otp_cert, 1}
          ]},
         {:pubkey_ocsp,
          [
            {:find_responder_cert, 2},
            {:do_verify_ocsp_signature, 4},
            {:verify_ocsp_response, 3},
            {:verify_ocsp_nonce, 2},
            {:verify_ocsp_signature, 5},
            {:do_verify_ocsp_response, 3},
            {:is_responder, 2},
            {:find_single_response, 3},
            {:ocsp_status, 1},
            {:match_single_response, 4}
          ]},
         {:ssl, [{:opt_ocsp, 3}]},
         {:ssl_certificate, [{:verify_cert_extensions, 4}]},
         {:ssl_test_lib, [{:init_openssl_server, 3}, {:openssl_server_loop, 3}]},
         {:tls_connection, [{:wait_ocsp_stapling, 3}]},
         {:dtls_connection, [{:initial_hello, 3}, {:hello, 3}, {:connection, 3}]},
         {:tls_dtls_connection, [{:wait_ocsp_stapling, 3}, {:certify, 3}]},
         {:tls_handshake, [{:ocsp_nonce, 1}, {:ocsp_expect, 1}, {:client_hello, 11}]},
         {:dtls_handshake, [{:client_hello, 8}]}
       ]},
      {:crt,
       fn m, f, a ->
         :dbg.tpl(m, f, a, :x)
       end,
       fn m, f, a ->
         :dbg.ctpl(m, f, a)
       end,
       [
         {:public_key,
          [{:pkix_path_validation, 3}, {:path_validation, 2}, {:pkix_decode_cert, 2}]},
         {:ssl_certificate,
          [
            {:validate, 3},
            {:trusted_cert_and_paths, 4},
            {:certificate_chain, 3},
            {:certificate_chain, 5},
            {:issuer, 1}
          ]},
         {:ssl_cipher, [{:filter, 3}]},
         {:ssl_gen_statem, [{:initial_hello, 3}]},
         {:ssl_handshake,
          [
            {:path_validate, 11},
            {:path_validation, 10},
            {:select_hashsign, 5},
            {:get_cert_params, 1},
            {:cert_curve, 3},
            {:maybe_check_hostname, 3},
            {:maybe_check_hostname, 3}
          ]},
         {:ssl_pkix_db, [{:decode_cert, 2}]},
         {:tls_handshake_1_3, [{:path_validation, 10}]},
         {:tls_server_connection_1_3, [{:init, 1}]},
         {:tls_client_connection_1_3, [{:init, 1}]},
         {:tls_connection, [{:init, 1}]},
         {:dtls_connection, [{:init, 1}]}
       ]},
      {:kdt,
       fn m, f, a ->
         :dbg.tpl(m, f, a, :x)
       end,
       fn m, f, a ->
         :dbg.ctpl(m, f, a)
       end,
       [
         {:tls_gen_connection_1_3, [{:handle_key_update, 2}]},
         {:tls_sender, [{:init, 3}, {:time_to_rekey, 6}, {:send_post_handshake_data, 4}]},
         {:tls_v1, [{:update_traffic_secret, 2}]}
       ]},
      {:rle,
       fn m, f, a ->
         :dbg.tpl(m, f, a, :x)
       end,
       fn m, f, a ->
         :dbg.ctpl(m, f, a)
       end,
       [
         {:ssl, [{:listen, 2}, {:connect, 3}]},
         {:ssl_gen_statem, [{:init, 1}]},
         {:tls_server_session_ticket, [{:init, 1}]},
         {:tls_sender, [{:init, 3}]}
       ]},
      {:ssn,
       fn m, f, a ->
         :dbg.tpl(m, f, a, :x)
       end,
       fn m, f, a ->
         :dbg.ctpl(m, f, a)
       end,
       [
         {:tls_server_session_ticket,
          [
            {:handle_call, 3},
            {:handle_cast, 2},
            {:handle_info, 2},
            {:terminate, 2},
            {:start_link, 7},
            {:init, 1},
            {:initial_state, 1},
            {:validate_binder, 5},
            {:stateful_store, 0},
            {:stateful_ticket_store, 6},
            {:stateful_use, 4},
            {:stateful_use, 6},
            {:stateful_usable_ticket, 5},
            {:stateful_living_ticket, 2},
            {:stateful_psk_ticket_id, 1},
            {:generate_stateless_ticket, 5},
            {:stateless_use, 6},
            {:stateless_usable_ticket, 5},
            {:stateless_living_ticket, 5},
            {:in_window, 2},
            {:stateless_anti_replay, 5}
          ]},
         {:tls_handshake_1_3, [{:get_ticket_data, 3}]}
       ]},
      {:hbn,
       fn m, f, a ->
         :dbg.tpl(m, f, a, :x)
       end,
       fn m, f, a ->
         :dbg.ctpl(m, f, a)
       end,
       [
         {:tls_sender, [{:connection, 3}, {:hibernate_after, 3}]},
         {:dtls_connection, [{:connection, 3}, {:gen_info, 3}]},
         {:dtls_gen_connection, [{:handle_info, 3}]},
         {:ssl_gen_statem, [{:hibernate_after, 3}, {:handle_common_event, 4}]}
       ]},
      {:ct,
       fn m, f, a ->
         :dbg.tpl(m, f, a, :x)
       end,
       fn m, f, a ->
         :dbg.ctpl(m, f, a)
       end,
       [
         {:test_server,
          [
            {:ts_tc, 3},
            {:user_callback, 5},
            {:fw_error_notify, 4},
            {:get_loc, 1},
            {:set_tc_state, 1},
            {:init_per_testcase, 3},
            {:run_test_case_msgloop, 1},
            {:run_test_case_eval1, 6},
            {:do_init_tc_call, 4},
            {:process_return_val, 6},
            {:do_end_tc_call, 4},
            {:end_per_testcase, 3},
            {:call_end_conf, 7},
            {:do_call_end_conf, 7},
            {:call_end_conf, 7},
            {:handle_tc_exit, 2},
            {:capture_start, 0},
            {:capture_stop, 0},
            {:capture_get, 0},
            {:fail, 0},
            {:fail, 1},
            {:timetrap, 4},
            {:start_node, 3},
            {:comment, 1}
          ]}
       ]}
    ]
  end
end
