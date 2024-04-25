defmodule :m_gen_server do
  use Bitwise
  require Record

  Record.defrecord(:r_callback_cache, :callback_cache,
    module: :undefined,
    handle_call: :undefined,
    handle_cast: :undefined,
    handle_info: :undefined
  )

  def start(module, args, options)
      when is_atom(module) and
             is_list(options) do
    :gen.start(:gen_server, :nolink, module, args, options)
  end

  def start(module, args, options) do
    :erlang.error(:badarg, [module, args, options])
  end

  def start(serverName, module, args, options)
      when is_tuple(serverName) and is_atom(module) and
             is_list(options) do
    :gen.start(:gen_server, :nolink, serverName, module, args, options)
  end

  def start(serverName, module, args, options) do
    :erlang.error(
      :badarg,
      [serverName, module, args, options]
    )
  end

  def start_link(module, args, options)
      when is_atom(module) and
             is_list(options) do
    :gen.start(:gen_server, :link, module, args, options)
  end

  def start_link(module, args, options) do
    :erlang.error(:badarg, [module, args, options])
  end

  def start_link(serverName, module, args, options)
      when is_tuple(serverName) and is_atom(module) and
             is_list(options) do
    :gen.start(:gen_server, :link, serverName, module, args, options)
  end

  def start_link(serverName, module, args, options) do
    :erlang.error(
      :badarg,
      [serverName, module, args, options]
    )
  end

  def start_monitor(module, args, options)
      when is_atom(module) and
             is_list(options) do
    :gen.start(:gen_server, :monitor, module, args, options)
  end

  def start_monitor(module, args, options) do
    :erlang.error(:badarg, [module, args, options])
  end

  def start_monitor(serverName, module, args, options)
      when is_tuple(serverName) and is_atom(module) and
             is_list(options) do
    :gen.start(:gen_server, :monitor, serverName, module, args, options)
  end

  def start_monitor(serverName, module, args, options) do
    :erlang.error(
      :badarg,
      [serverName, module, args, options]
    )
  end

  def stop(serverRef) do
    :gen.stop(serverRef)
  end

  def stop(serverRef, reason, timeout) do
    :gen.stop(serverRef, reason, timeout)
  end

  def call(serverRef, request) do
    case (try do
            :gen.call(serverRef, :"$gen_call", request)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      {:ok, res} ->
        res

      {:EXIT, reason} ->
        exit({reason, {:gen_server, :call, [serverRef, request]}})
    end
  end

  def call(serverRef, request, timeout) do
    case (try do
            :gen.call(serverRef, :"$gen_call", request, timeout)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      {:ok, res} ->
        res

      {:EXIT, reason} ->
        exit({reason, {:gen_server, :call, [serverRef, request, timeout]}})
    end
  end

  def send_request(serverRef, request) do
    try do
      :gen.send_request(serverRef, :"$gen_call", request)
    catch
      :error, :badarg ->
        :erlang.error(:badarg, [serverRef, request])
    end
  end

  def send_request(serverRef, request, label, reqIdCol) do
    try do
      :gen.send_request(serverRef, :"$gen_call", request, label, reqIdCol)
    catch
      :error, :badarg ->
        :erlang.error(
          :badarg,
          [serverRef, request, label, reqIdCol]
        )
    end
  end

  def wait_response(reqId, waitTime) do
    try do
      :gen.wait_response(reqId, waitTime)
    catch
      :error, :badarg ->
        :erlang.error(:badarg, [reqId, waitTime])
    end
  end

  def wait_response(reqIdCol, waitTime, delete) do
    try do
      :gen.wait_response(reqIdCol, waitTime, delete)
    catch
      :error, :badarg ->
        :erlang.error(:badarg, [reqIdCol, waitTime, delete])
    end
  end

  def receive_response(reqId, timeout) do
    try do
      :gen.receive_response(reqId, timeout)
    catch
      :error, :badarg ->
        :erlang.error(:badarg, [reqId, timeout])
    end
  end

  def receive_response(reqIdCol, timeout, delete) do
    try do
      :gen.receive_response(reqIdCol, timeout, delete)
    catch
      :error, :badarg ->
        :erlang.error(:badarg, [reqIdCol, timeout, delete])
    end
  end

  def check_response(msg, reqId) do
    try do
      :gen.check_response(msg, reqId)
    catch
      :error, :badarg ->
        :erlang.error(:badarg, [msg, reqId])
    end
  end

  def check_response(msg, reqIdCol, delete) do
    try do
      :gen.check_response(msg, reqIdCol, delete)
    catch
      :error, :badarg ->
        :erlang.error(:badarg, [msg, reqIdCol, delete])
    end
  end

  def reqids_new() do
    :gen.reqids_new()
  end

  def reqids_size(reqIdCollection) do
    try do
      :gen.reqids_size(reqIdCollection)
    catch
      :error, :badarg ->
        :erlang.error(:badarg, [reqIdCollection])
    end
  end

  def reqids_add(reqId, label, reqIdCollection) do
    try do
      :gen.reqids_add(reqId, label, reqIdCollection)
    catch
      :error, :badarg ->
        :erlang.error(:badarg, [reqId, label, reqIdCollection])
    end
  end

  def reqids_to_list(reqIdCollection) do
    try do
      :gen.reqids_to_list(reqIdCollection)
    catch
      :error, :badarg ->
        :erlang.error(:badarg, [reqIdCollection])
    end
  end

  def cast({:global, name}, request) do
    try do
      :global.send(name, cast_msg(request))
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end

    :ok
  end

  def cast({:via, mod, name}, request) do
    try do
      mod.send(name, cast_msg(request))
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end

    :ok
  end

  def cast({name, node} = dest, request)
      when is_atom(name) and is_atom(node) do
    do_cast(dest, request)
  end

  def cast(dest, request) when is_atom(dest) do
    do_cast(dest, request)
  end

  def cast(dest, request) when is_pid(dest) do
    do_cast(dest, request)
  end

  defp do_cast(dest, request) do
    do_send(dest, cast_msg(request))
    :ok
  end

  defp cast_msg(request) do
    {:"$gen_cast", request}
  end

  def reply(client, reply) do
    :gen.reply(client, reply)
  end

  def abcast(name, request) when is_atom(name) do
    do_abcast([node() | :erlang.nodes()], name, cast_msg(request))
  end

  def abcast(nodes, name, request)
      when is_list(nodes) and
             is_atom(name) do
    do_abcast(nodes, name, cast_msg(request))
  end

  defp do_abcast([node | nodes], name, msg) when is_atom(node) do
    do_send({name, node}, msg)
    do_abcast(nodes, name, msg)
  end

  defp do_abcast([], _, _) do
    :abcast
  end

  def multi_call(name, request) when is_atom(name) do
    multi_call([node() | :erlang.nodes()], name, request, :infinity)
  end

  def multi_call(nodes, name, request)
      when is_list(nodes) and
             is_atom(name) do
    multi_call(nodes, name, request, :infinity)
  end

  def multi_call(nodes, name, request, timeout)
      when (is_list(nodes) and is_atom(name) and
              timeout === :infinity) or (is_integer(timeout) and timeout >= 0) do
    alias = __MODULE__.alias()

    try do
      timer =
        cond do
          timeout == :infinity ->
            :undefined

          true ->
            :erlang.start_timer(timeout, self(), alias)
        end

      reqs = mc_send(nodes, name, alias, request, timer, [])
      mc_recv(reqs, alias, timer, [], [])
    after
      _ = unalias(alias)
    end
  end

  defp mc_send([], _Name, _Alias, _Request, _Timer, reqs) do
    reqs
  end

  defp mc_send([node | nodes], name, alias, request, timer, reqs)
       when is_atom(node) do
    nN = {name, node}

    mon =
      try do
        :erlang.monitor(:process, nN, [{:tag, alias}])
      catch
        :error, :badarg ->
          m = make_ref()
          send(alias, {alias, m, :process, nN, :noconnection})
          m
      end

    try do
      _ =
        :erlang.send(
          nN,
          {:"$gen_call", {self(), [[:alias | alias] | mon]}, request},
          [:noconnect]
        )

      :ok
    catch
      _, _ ->
        :ok
    end

    mc_send(nodes, name, alias, request, timer, [[node | mon] | reqs])
  end

  defp mc_send(_BadNodes, _Name, alias, _Request, timer, reqs) do
    unalias(alias)
    mc_cancel_timer(timer, alias)
    _ = mc_recv_tmo(reqs, alias, [], [])
    :erlang.error(:badarg)
  end

  defp mc_recv([], alias, timer, replies, badNodes) do
    mc_cancel_timer(timer, alias)
    unalias(alias)
    {replies, badNodes}
  end

  defp mc_recv([[node | mon] | restReqs] = reqs, alias, timer, replies, badNodes) do
    receive do
      {[[:alias | ^alias] | ^mon], reply} ->
        :erlang.demonitor(mon, [:flush])
        mc_recv(restReqs, alias, timer, [{node, reply} | replies], badNodes)

      {^alias, ^mon, :process, _, _} ->
        mc_recv(restReqs, alias, timer, replies, [node | badNodes])

      {:timeout, ^timer, ^alias} ->
        unalias(alias)
        mc_recv_tmo(reqs, alias, replies, badNodes)
    end
  end

  defp mc_recv_tmo([], _Alias, replies, badNodes) do
    {replies, badNodes}
  end

  defp mc_recv_tmo([[node | mon] | restReqs], alias, replies, badNodes) do
    :erlang.demonitor(mon)

    receive do
      {[[:alias | ^alias] | ^mon], reply} ->
        mc_recv_tmo(restReqs, alias, [{node, reply} | replies], badNodes)

      {^alias, ^mon, :process, _, _} ->
        mc_recv_tmo(restReqs, alias, replies, [node | badNodes])
    after
      0 ->
        mc_recv_tmo(restReqs, alias, replies, [node | badNodes])
    end
  end

  defp mc_cancel_timer(:undefined, _Alias) do
    :ok
  end

  defp mc_cancel_timer(timer, alias) do
    case :erlang.cancel_timer(timer) do
      false ->
        receive do
          {:timeout, ^timer, ^alias} ->
            :ok
        end

      _ ->
        :ok
    end
  end

  def enter_loop(mod, options, state)
      when is_atom(mod) and
             is_list(options) do
    enter_loop(mod, options, state, self(), :infinity)
  end

  def enter_loop(mod, options, state, serverName = {scope, _})
      when (is_atom(mod) and is_list(options) and
              scope == :local) or
             (is_atom(mod) and is_list(options) and
                scope == :global) do
    enter_loop(mod, options, state, serverName, :infinity)
  end

  def enter_loop(mod, options, state, serverName = {:via, _, _})
      when is_atom(mod) and is_list(options) do
    enter_loop(mod, options, state, serverName, :infinity)
  end

  def enter_loop(mod, options, state, timeoutOrHibernate)
      when (is_atom(mod) and is_list(options) and
              timeoutOrHibernate === :infinity) or
             (is_integer(timeoutOrHibernate) and timeoutOrHibernate >= 0) or
             (is_atom(mod) and is_list(options) and
                timeoutOrHibernate === :hibernate) do
    enter_loop(mod, options, state, self(), timeoutOrHibernate)
  end

  def enter_loop(mod, options, state, {:continue, _} = continue)
      when is_atom(mod) and is_list(options) do
    enter_loop(mod, options, state, self(), continue)
  end

  def enter_loop(mod, options, state, serverName, timeoutOrHibernate)
      when (is_atom(mod) and is_list(options) and
              timeoutOrHibernate === :infinity) or
             (is_integer(timeoutOrHibernate) and timeoutOrHibernate >= 0) or
             (is_atom(mod) and is_list(options) and
                timeoutOrHibernate === :hibernate) do
    name = :gen.get_proc_name(serverName)
    parent = :gen.get_parent()
    debug = :gen.debug_options(name, options)
    hibernateAfterTimeout = :gen.hibernate_after(options)
    cbCache = create_callback_cache(mod)
    loop(parent, name, state, cbCache, timeoutOrHibernate, hibernateAfterTimeout, debug)
  end

  def enter_loop(mod, options, state, serverName, {:continue, _} = continue)
      when is_atom(mod) and is_list(options) do
    name = :gen.get_proc_name(serverName)
    parent = :gen.get_parent()
    debug = :gen.debug_options(name, options)
    hibernateAfterTimeout = :gen.hibernate_after(options)
    cbCache = create_callback_cache(mod)
    loop(parent, name, state, cbCache, continue, hibernateAfterTimeout, debug)
  end

  def init_it(starter, :self, name, mod, args, options) do
    init_it(starter, self(), name, mod, args, options)
  end

  def init_it(starter, parent, name0, mod, args, options) do
    name = :gen.name(name0)
    debug = :gen.debug_options(name, options)
    hibernateAfterTimeout = :gen.hibernate_after(options)
    cbCache = create_callback_cache(mod)

    case init_it(mod, args) do
      {:ok, {:ok, state}} ->
        :proc_lib.init_ack(starter, {:ok, self()})
        loop(parent, name, state, cbCache, :infinity, hibernateAfterTimeout, debug)

      {:ok, {:ok, state, timeoutOrHibernate}}
      when timeoutOrHibernate === :infinity or
             (is_integer(timeoutOrHibernate) and timeoutOrHibernate >= 0) or
             timeoutOrHibernate === :hibernate ->
        :proc_lib.init_ack(starter, {:ok, self()})
        loop(parent, name, state, cbCache, timeoutOrHibernate, hibernateAfterTimeout, debug)

      {:ok, {:ok, state, {:continue, _} = continue}} ->
        :proc_lib.init_ack(starter, {:ok, self()})
        loop(parent, name, state, cbCache, continue, hibernateAfterTimeout, debug)

      {:ok, {:stop, reason}} ->
        :gen.unregister_name(name0)
        exit(reason)

      {:ok, {:error, _Reason} = eRROR} ->
        :gen.unregister_name(name0)
        :proc_lib.init_fail(starter, eRROR, {:exit, :normal})

      {:ok, :ignore} ->
        :gen.unregister_name(name0)
        :proc_lib.init_fail(starter, :ignore, {:exit, :normal})

      {:ok, else__} ->
        :gen.unregister_name(name0)
        exit({:bad_return_value, else__})

      {:EXIT, class, reason, stacktrace} ->
        :gen.unregister_name(name0)
        :erlang.raise(class, reason, stacktrace)
    end
  end

  defp init_it(mod, args) do
    try do
      {:ok, mod.init(args)}
    catch
      r ->
        {:ok, r}

      class, r ->
        {:EXIT, class, r, __STACKTRACE__}
    end
  end

  defp loop(
         parent,
         name,
         state,
         cbCache,
         {:continue, continue} = msg,
         hibernateAfterTimeout,
         debug
       ) do
    reply = try_handle_continue(cbCache, continue, state)

    case debug do
      [] ->
        handle_common_reply(
          reply,
          parent,
          name,
          :undefined,
          msg,
          cbCache,
          hibernateAfterTimeout,
          state
        )

      _ ->
        debug1 = :sys.handle_debug(debug, &print_event/3, name, msg)

        handle_common_reply(
          reply,
          parent,
          name,
          :undefined,
          msg,
          cbCache,
          hibernateAfterTimeout,
          state,
          debug1
        )
    end
  end

  defp loop(parent, name, state, cbCache, :hibernate, hibernateAfterTimeout, debug) do
    mod = r_callback_cache(cbCache, :module)

    :proc_lib.hibernate(:gen_server, :wake_hib, [
      parent,
      name,
      state,
      mod,
      hibernateAfterTimeout,
      debug
    ])
  end

  defp loop(parent, name, state, cbCache, :infinity, hibernateAfterTimeout, debug) do
    receive do
      msg ->
        decode_msg(
          msg,
          parent,
          name,
          state,
          cbCache,
          :infinity,
          hibernateAfterTimeout,
          debug,
          false
        )
    after
      hibernateAfterTimeout ->
        loop(parent, name, state, cbCache, :hibernate, hibernateAfterTimeout, debug)
    end
  end

  defp loop(parent, name, state, cbCache, time, hibernateAfterTimeout, debug) do
    msg =
      receive do
        input ->
          input
      after
        time ->
          :timeout
      end

    decode_msg(msg, parent, name, state, cbCache, time, hibernateAfterTimeout, debug, false)
  end

  defp create_callback_cache(mod) do
    r_callback_cache(
      module: mod,
      handle_call: Function.capture(mod, :handle_call, 3),
      handle_cast: Function.capture(mod, :handle_cast, 2),
      handle_info: Function.capture(mod, :handle_info, 2)
    )
  end

  def wake_hib(parent, name, state, mod, hibernateAfterTimeout, debug) do
    msg =
      receive do
        input ->
          input
      end

    cbCache = create_callback_cache(mod)
    decode_msg(msg, parent, name, state, cbCache, :hibernate, hibernateAfterTimeout, debug, true)
  end

  defp decode_msg(msg, parent, name, state, cbCache, time, hibernateAfterTimeout, debug, hib) do
    case msg do
      {:system, from, req} ->
        :sys.handle_system_msg(
          req,
          from,
          parent,
          :gen_server,
          debug,
          [name, state, cbCache, time, hibernateAfterTimeout],
          hib
        )

      {:EXIT, ^parent, reason} ->
        r_callback_cache(module: mod) = cbCache

        terminate(
          reason,
          :erlang.element(
            2,
            :erlang.process_info(
              self(),
              :current_stacktrace
            )
          ),
          name,
          :undefined,
          msg,
          mod,
          state,
          debug
        )

      _Msg when debug === [] ->
        handle_msg(msg, parent, name, state, cbCache, hibernateAfterTimeout)

      _Msg ->
        debug1 = :sys.handle_debug(debug, &print_event/3, name, {:in, msg})
        handle_msg(msg, parent, name, state, cbCache, hibernateAfterTimeout, debug1)
    end
  end

  defp do_send(dest, msg) do
    try do
      :erlang.send(dest, msg)
    catch
      :error, _ ->
        :ok
    end

    :ok
  end

  defp try_dispatch({:"$gen_cast", msg}, cbCache, state) do
    try_handle_cast(cbCache, msg, state)
  end

  defp try_dispatch(info, cbCache, state) do
    try_handle_info(cbCache, info, state)
  end

  defp try_handle_continue(r_callback_cache(module: mod), msg, state) do
    try do
      {:ok, mod.handle_continue(msg, state)}
    catch
      r ->
        {:ok, r}

      class, r ->
        {:EXIT, class, r, __STACKTRACE__}
    end
  end

  defp try_handle_info(r_callback_cache(module: mod, handle_info: handleInfo), msg, state) do
    try do
      {:ok, handleInfo.(msg, state)}
    catch
      r ->
        {:ok, r}

      :error, :undef = r ->
        case :erlang.function_exported(mod, :handle_info, 2) do
          false ->
            case :logger.allow(:warning, :gen_server) do
              true ->
                :erlang.apply(:logger, :macro_log, [
                  %{
                    mfa: {:gen_server, :try_handle_info, 3},
                    line: 1102,
                    file: ~c"otp/lib/stdlib/src/gen_server.erl"
                  },
                  :warning,
                  %{label: {:gen_server, :no_handle_info}, module: mod, message: msg},
                  %{
                    domain: [:otp],
                    report_cb: &:gen_server.format_log/2,
                    error_logger: %{tag: :warning_msg, report_cb: &:gen_server.format_log/1}
                  }
                ])

              false ->
                :ok
            end

            {:ok, {:noreply, state}}

          true ->
            {:EXIT, :error, r, __STACKTRACE__}
        end

      class, r ->
        {:EXIT, class, r, __STACKTRACE__}
    end
  end

  defp try_handle_cast(r_callback_cache(handle_cast: handleCast), msg, state) do
    try do
      {:ok, handleCast.(msg, state)}
    catch
      r ->
        {:ok, r}

      class, r ->
        {:EXIT, class, r, __STACKTRACE__}
    end
  end

  defp try_handle_call(r_callback_cache(handle_call: handleCall), msg, from, state) do
    try do
      {:ok, handleCall.(msg, from, state)}
    catch
      r ->
        {:ok, r}

      class, r ->
        {:EXIT, class, r, __STACKTRACE__}
    end
  end

  defp try_terminate(mod, reason, state) do
    case :erlang.function_exported(mod, :terminate, 2) do
      true ->
        try do
          {:ok, mod.terminate(reason, state)}
        catch
          r ->
            {:ok, r}

          class, r ->
            {:EXIT, class, r, __STACKTRACE__}
        end

      false ->
        {:ok, :ok}
    end
  end

  defp handle_msg({:"$gen_call", from, msg}, parent, name, state, cbCache, hibernateAfterTimeout) do
    result = try_handle_call(cbCache, msg, from, state)

    case result do
      {:ok, {:reply, reply, nState}} ->
        reply(from, reply)
        loop(parent, name, nState, cbCache, :infinity, hibernateAfterTimeout, [])

      {:ok, {:reply, reply, nState, timeoutOrHibernate}}
      when timeoutOrHibernate === :infinity or
             (is_integer(timeoutOrHibernate) and timeoutOrHibernate >= 0) or
             timeoutOrHibernate === :hibernate ->
        reply(from, reply)
        loop(parent, name, nState, cbCache, timeoutOrHibernate, hibernateAfterTimeout, [])

      {:ok, {:reply, reply, nState, {:continue, _} = continue}} ->
        reply(from, reply)
        loop(parent, name, nState, cbCache, continue, hibernateAfterTimeout, [])

      {:ok, {:stop, reason, reply, nState}} ->
        try do
          mod = r_callback_cache(cbCache, :module)

          terminate(
            reason,
            :erlang.element(
              2,
              :erlang.process_info(
                self(),
                :current_stacktrace
              )
            ),
            name,
            from,
            msg,
            mod,
            nState,
            []
          )
        after
          reply(from, reply)
        end

      other ->
        handle_common_reply(other, parent, name, from, msg, cbCache, hibernateAfterTimeout, state)
    end
  end

  defp handle_msg(msg, parent, name, state, cbCache, hibernateAfterTimeout) do
    reply = try_dispatch(msg, cbCache, state)

    handle_common_reply(
      reply,
      parent,
      name,
      :undefined,
      msg,
      cbCache,
      hibernateAfterTimeout,
      state
    )
  end

  defp handle_msg(
         {:"$gen_call", from, msg},
         parent,
         name,
         state,
         cbCache,
         hibernateAfterTimeout,
         debug
       ) do
    result = try_handle_call(cbCache, msg, from, state)

    case result do
      {:ok, {:reply, reply, nState}} ->
        debug1 = reply(name, from, reply, nState, debug)
        loop(parent, name, nState, cbCache, :infinity, hibernateAfterTimeout, debug1)

      {:ok, {:reply, reply, nState, timeoutOrHibernate}}
      when timeoutOrHibernate === :infinity or
             (is_integer(timeoutOrHibernate) and timeoutOrHibernate >= 0) or
             timeoutOrHibernate === :hibernate ->
        debug1 = reply(name, from, reply, nState, debug)
        loop(parent, name, nState, cbCache, timeoutOrHibernate, hibernateAfterTimeout, debug1)

      {:ok, {:reply, reply, nState, {:continue, _} = continue}} ->
        debug1 = reply(name, from, reply, nState, debug)
        loop(parent, name, nState, cbCache, continue, hibernateAfterTimeout, debug1)

      {:ok, {:stop, reason, reply, nState}} ->
        try do
          mod = r_callback_cache(cbCache, :module)

          terminate(
            reason,
            :erlang.element(
              2,
              :erlang.process_info(
                self(),
                :current_stacktrace
              )
            ),
            name,
            from,
            msg,
            mod,
            nState,
            debug
          )
        after
          _ = reply(name, from, reply, nState, debug)
        end

      other ->
        handle_common_reply(
          other,
          parent,
          name,
          from,
          msg,
          cbCache,
          hibernateAfterTimeout,
          state,
          debug
        )
    end
  end

  defp handle_msg(msg, parent, name, state, cbCache, hibernateAfterTimeout, debug) do
    reply = try_dispatch(msg, cbCache, state)

    handle_common_reply(
      reply,
      parent,
      name,
      :undefined,
      msg,
      cbCache,
      hibernateAfterTimeout,
      state,
      debug
    )
  end

  defp handle_common_reply(reply, parent, name, from, msg, cbCache, hibernateAfterTimeout, state) do
    mod = r_callback_cache(cbCache, :module)

    case reply do
      {:ok, {:noreply, nState}} ->
        loop(parent, name, nState, cbCache, :infinity, hibernateAfterTimeout, [])

      {:ok, {:noreply, nState, timeoutOrHibernate}}
      when timeoutOrHibernate === :infinity or
             (is_integer(timeoutOrHibernate) and timeoutOrHibernate >= 0) or
             timeoutOrHibernate === :hibernate ->
        loop(parent, name, nState, cbCache, timeoutOrHibernate, hibernateAfterTimeout, [])

      {:ok, {:noreply, nState, {:continue, _} = continue}} ->
        loop(parent, name, nState, cbCache, continue, hibernateAfterTimeout, [])

      {:ok, {:stop, reason, nState}} ->
        terminate(
          reason,
          :erlang.element(
            2,
            :erlang.process_info(
              self(),
              :current_stacktrace
            )
          ),
          name,
          from,
          msg,
          mod,
          nState,
          []
        )

      {:EXIT, class, reason, stacktrace} ->
        terminate(class, reason, stacktrace, name, from, msg, mod, state, [])

      {:ok, badReply} ->
        terminate(
          {:bad_return_value, badReply},
          :erlang.element(
            2,
            :erlang.process_info(
              self(),
              :current_stacktrace
            )
          ),
          name,
          from,
          msg,
          mod,
          state,
          []
        )
    end
  end

  defp handle_common_reply(
         reply,
         parent,
         name,
         from,
         msg,
         cbCache,
         hibernateAfterTimeout,
         state,
         debug
       ) do
    mod = r_callback_cache(cbCache, :module)

    case reply do
      {:ok, {:noreply, nState}} ->
        debug1 = :sys.handle_debug(debug, &print_event/3, name, {:noreply, nState})
        loop(parent, name, nState, cbCache, :infinity, hibernateAfterTimeout, debug1)

      {:ok, {:noreply, nState, timeoutOrHibernate}}
      when timeoutOrHibernate === :infinity or
             (is_integer(timeoutOrHibernate) and timeoutOrHibernate >= 0) or
             timeoutOrHibernate === :hibernate ->
        debug1 = :sys.handle_debug(debug, &print_event/3, name, {:noreply, nState})
        loop(parent, name, nState, cbCache, timeoutOrHibernate, hibernateAfterTimeout, debug1)

      {:ok, {:noreply, nState, {:continue, _} = continue}} ->
        debug1 = :sys.handle_debug(debug, &print_event/3, name, {:noreply, nState})
        loop(parent, name, nState, cbCache, continue, hibernateAfterTimeout, debug1)

      {:ok, {:stop, reason, nState}} ->
        terminate(
          reason,
          :erlang.element(
            2,
            :erlang.process_info(
              self(),
              :current_stacktrace
            )
          ),
          name,
          from,
          msg,
          mod,
          nState,
          debug
        )

      {:EXIT, class, reason, stacktrace} ->
        terminate(class, reason, stacktrace, name, from, msg, mod, state, debug)

      {:ok, badReply} ->
        terminate(
          {:bad_return_value, badReply},
          :erlang.element(
            2,
            :erlang.process_info(
              self(),
              :current_stacktrace
            )
          ),
          name,
          from,
          msg,
          mod,
          state,
          debug
        )
    end
  end

  defp reply(name, from, reply, state, debug) do
    reply(from, reply)
    :sys.handle_debug(debug, &print_event/3, name, {:out, reply, from, state})
  end

  def system_continue(parent, debug, [name, state, cbCache, time, hibernateAfterTimeout]) do
    loop(parent, name, state, cbCache, time, hibernateAfterTimeout, debug)
  end

  def system_terminate(reason, _Parent, debug, [
        name,
        state,
        cbCache,
        _Time,
        _HibernateAfterTimeout
      ]) do
    mod = r_callback_cache(cbCache, :module)

    terminate(
      reason,
      :erlang.element(
        2,
        :erlang.process_info(
          self(),
          :current_stacktrace
        )
      ),
      name,
      :undefined,
      [],
      mod,
      state,
      debug
    )
  end

  def system_code_change(
        [name, state, cbCache, time, hibernateAfterTimeout],
        _Module,
        oldVsn,
        extra
      ) do
    mod = r_callback_cache(cbCache, :module)

    case (try do
            mod.code_change(oldVsn, state, extra)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      {:ok, newState} ->
        {:ok, [name, newState, cbCache, time, hibernateAfterTimeout]}

      else__ ->
        else__
    end
  end

  def system_get_state([_Name, state, _Mod, _Time, _HibernateAfterTimeout]) do
    {:ok, state}
  end

  def system_replace_state(
        stateFun,
        [name, state, cbCache, time, hibernateAfterTimeout]
      ) do
    nState = stateFun.(state)
    {:ok, nState, [name, nState, cbCache, time, hibernateAfterTimeout]}
  end

  defp print_event(dev, {:in, msg}, name) do
    case msg do
      {:"$gen_call", {from, _Tag}, call} ->
        :io.format(dev, ~c"*DBG* ~tp got call ~tp from ~tw~n", [name, call, from])

      {:"$gen_cast", cast} ->
        :io.format(dev, ~c"*DBG* ~tp got cast ~tp~n", [name, cast])

      _ ->
        :io.format(dev, ~c"*DBG* ~tp got ~tp~n", [name, msg])
    end
  end

  defp print_event(dev, {:out, msg, {to, _Tag}, state}, name) do
    :io.format(dev, ~c"*DBG* ~tp sent ~tp to ~tw, new state ~tp~n", [name, msg, to, state])
  end

  defp print_event(dev, {:noreply, state}, name) do
    :io.format(dev, ~c"*DBG* ~tp new state ~tp~n", [name, state])
  end

  defp print_event(dev, event, name) do
    :io.format(dev, ~c"*DBG* ~tp dbg  ~tp~n", [name, event])
  end

  defp terminate(reason, stacktrace, name, from, msg, mod, state, debug) do
    terminate(:exit, reason, stacktrace, false, name, from, msg, mod, state, debug)
  end

  defp terminate(class, reason, stacktrace, name, from, msg, mod, state, debug) do
    terminate(class, reason, stacktrace, true, name, from, msg, mod, state, debug)
  end

  defp terminate(class, reason, stacktrace, reportStacktrace, name, from, msg, mod, state, debug) do
    reply = try_terminate(mod, catch_result(class, reason, stacktrace), state)

    case reply do
      {:EXIT, c, r, s} ->
        error_info(r, s, name, from, msg, mod, state, debug)
        :erlang.raise(c, r, s)

      _ ->
        case {class, reason} do
          {:exit, :normal} ->
            :ok

          {:exit, :shutdown} ->
            :ok

          {:exit, {:shutdown, _}} ->
            :ok

          _ when reportStacktrace ->
            error_info(reason, stacktrace, name, from, msg, mod, state, debug)

          _ ->
            error_info(reason, :undefined, name, from, msg, mod, state, debug)
        end
    end

    case stacktrace do
      [] ->
        apply(:erlang, class, [reason])

      _ ->
        :erlang.raise(class, reason, stacktrace)
    end
  end

  defp catch_result(:error, reason, stacktrace) do
    {reason, stacktrace}
  end

  defp catch_result(:exit, reason, _Stacktrace) do
    reason
  end

  defp error_info(_Reason, _ST, :application_controller, _From, _Msg, _Mod, _State, _Debug) do
    :ok
  end

  defp error_info(reason, sT, name, from, msg, mod, state, debug) do
    log = :sys.get_log(debug)

    status =
      :gen.format_status(
        mod,
        :terminate,
        %{reason: reason, state: state, message: msg, log: log},
        [:erlang.get(), state]
      )

    reportReason =
      cond do
        sT == :undefined ->
          :maps.get(:reason, status)

        true ->
          {:maps.get(:reason, status), sT}
      end

    case :logger.allow(:error, :gen_server) do
      true ->
        :erlang.apply(:logger, :macro_log, [
          %{
            mfa: {:gen_server, :error_info, 8},
            line: 1391,
            file: ~c"otp/lib/stdlib/src/gen_server.erl"
          },
          :error,
          %{
            label: {:gen_server, :terminate},
            name: name,
            last_message: :maps.get(:message, status),
            state:
              :maps.get(
                :EXIT,
                status,
                :maps.get(
                  :"$status",
                  status,
                  :maps.get(
                    :state,
                    status
                  )
                )
              ),
            log:
              format_log_state(
                mod,
                :maps.get(
                  :log,
                  status
                )
              ),
            reason: reportReason,
            client_info: client_stacktrace(from)
          },
          %{
            domain: [:otp],
            report_cb: &:gen_server.format_log/2,
            error_logger: %{tag: :error, report_cb: &:gen_server.format_log/1}
          }
        ])

      false ->
        :ok
    end

    :ok
  end

  defp client_stacktrace(:undefined) do
    :undefined
  end

  defp client_stacktrace({from, _Tag}) do
    client_stacktrace(from)
  end

  defp client_stacktrace(from)
       when is_pid(from) and
              node(from) === node() do
    case :erlang.process_info(
           from,
           [:current_stacktrace, :registered_name]
         ) do
      :undefined ->
        {from, :dead}

      [{:current_stacktrace, stacktrace}, {:registered_name, []}] ->
        {from, {from, stacktrace}}

      [{:current_stacktrace, stacktrace}, {:registered_name, name}] ->
        {from, {name, stacktrace}}
    end
  end

  defp client_stacktrace(from) when is_pid(from) do
    {from, :remote}
  end

  def format_log(report) do
    depth = :error_logger.get_format_depth()
    formatOpts = %{chars_limit: :unlimited, depth: depth, single_line: false, encoding: :utf8}

    format_log_multi(
      limit_report(report, depth),
      formatOpts
    )
  end

  defp limit_report(report, :unlimited) do
    report
  end

  defp limit_report(
         %{
           label: {:gen_server, :terminate},
           last_message: msg,
           state: state,
           log: log,
           reason: reason,
           client_info: client
         } = report,
         depth
       ) do
    Map.merge(report, %{
      last_message: :io_lib.limit_term(msg, depth),
      state: :io_lib.limit_term(state, depth),
      log:
        for l <- log do
          :io_lib.limit_term(l, depth)
        end,
      reason: :io_lib.limit_term(reason, depth),
      client_info: limit_client_report(client, depth)
    })
  end

  defp limit_report(
         %{label: {:gen_server, :no_handle_info}, message: msg} = report,
         depth
       ) do
    Map.put(report, :message, :io_lib.limit_term(msg, depth))
  end

  defp limit_client_report({from, {name, stacktrace}}, depth) do
    {from, {name, :io_lib.limit_term(stacktrace, depth)}}
  end

  defp limit_client_report(client, _) do
    client
  end

  def format_log(report, formatOpts0) do
    default = %{chars_limit: :unlimited, depth: :unlimited, single_line: false, encoding: :utf8}
    formatOpts = :maps.merge(default, formatOpts0)

    ioOpts =
      case formatOpts do
        %{chars_limit: :unlimited} ->
          []

        %{chars_limit: limit} ->
          [{:chars_limit, limit}]
      end

    {format, args} = format_log_single(report, formatOpts)
    :io_lib.format(format, args, ioOpts)
  end

  defp format_log_single(
         %{
           label: {:gen_server, :terminate},
           name: name,
           last_message: msg,
           state: state,
           log: log,
           reason: reason,
           client_info: client
         },
         %{single_line: true, depth: depth} = formatOpts
       ) do
    p = p(formatOpts)

    format1 =
      :lists.append([
        ~c"Generic server ",
        p,
        ~c" terminating. Reason: ",
        p,
        ~c". Last message: ",
        p,
        ~c". State: ",
        p,
        ~c"."
      ])

    {serverLogFormat, serverLogArgs} =
      format_server_log_single(
        log,
        formatOpts
      )

    {clientLogFormat, clientLogArgs} =
      format_client_log_single(
        client,
        formatOpts
      )

    args1 =
      case depth do
        :unlimited ->
          [name, fix_reason(reason), msg, state]

        _ ->
          [name, depth, fix_reason(reason), depth, msg, depth, state, depth]
      end

    {format1 ++ serverLogFormat ++ clientLogFormat, args1 ++ serverLogArgs ++ clientLogArgs}
  end

  defp format_log_single(
         %{label: {:gen_server, :no_handle_info}, module: mod, message: msg},
         %{single_line: true, depth: depth} = formatOpts
       ) do
    p = p(formatOpts)

    format =
      :lists.append([~c"Undefined handle_info in ", p, ~c". Unhandled message: ", p, ~c"."])

    args =
      case depth do
        :unlimited ->
          [mod, msg]

        _ ->
          [mod, depth, msg, depth]
      end

    {format, args}
  end

  defp format_log_single(report, formatOpts) do
    format_log_multi(report, formatOpts)
  end

  defp format_log_multi(
         %{
           label: {:gen_server, :terminate},
           name: name,
           last_message: msg,
           state: state,
           log: log,
           reason: reason,
           client_info: client
         },
         %{depth: depth} = formatOpts
       ) do
    reason1 = fix_reason(reason)

    {clientFmt, clientArgs} =
      format_client_log(
        client,
        formatOpts
      )

    p = p(formatOpts)

    format =
      :lists.append(
        [
          ~c"** Generic server ",
          p,
          ~c" terminating \n** Last message in was ",
          p,
          ~c"~n** When Server state == ",
          p,
          ~c"~n** Reason for termination ==~n** ",
          p,
          ~c"~n"
        ] ++
          case log do
            [] ->
              []

            _ ->
              [
                ~c"** Log ==~n** ["
                | :lists.join(
                    ~c",~n    ",
                    :lists.duplicate(
                      length(log),
                      p
                    )
                  )
              ] ++ [~c"]~n"]
          end
      ) ++ clientFmt

    args =
      case depth do
        :unlimited ->
          [name, msg, state, reason1] ++ log ++ clientArgs

        _ ->
          [name, depth, msg, depth, state, depth, reason1, depth] ++
            case log do
              [] ->
                []

              _ ->
                :lists.flatmap(
                  fn l ->
                    [l, depth]
                  end,
                  log
                )
            end ++ clientArgs
      end

    {format, args}
  end

  defp format_log_multi(
         %{label: {:gen_server, :no_handle_info}, module: mod, message: msg},
         %{depth: depth} = formatOpts
       ) do
    p = p(formatOpts)
    format = ~c"** Undefined handle_info in ~p~n** Unhandled message: " ++ p ++ ~c"~n"

    args =
      case depth do
        :unlimited ->
          [mod, msg]

        _ ->
          [mod, msg, depth]
      end

    {format, args}
  end

  defp fix_reason({:undef, [{m, f, a, l} | mFAs]} = reason) do
    case :code.is_loaded(m) do
      false ->
        {:"module could not be loaded", [{m, f, a, l} | mFAs]}

      _ ->
        case :erlang.function_exported(m, f, length(a)) do
          true ->
            reason

          false ->
            {:"function not exported", [{m, f, a, l} | mFAs]}
        end
    end
  end

  defp fix_reason(reason) do
    reason
  end

  defp format_server_log_single([], _) do
    {~c"", []}
  end

  defp format_server_log_single(log, formatOpts) do
    args =
      case :maps.get(:depth, formatOpts) do
        :unlimited ->
          [log]

        depth ->
          [log, depth]
      end

    {~c" Log: " ++ p(formatOpts), args}
  end

  defp format_client_log_single(:undefined, _) do
    {~c"", []}
  end

  defp format_client_log_single({from, :dead}, _) do
    {~c" Client ~0p is dead.", [from]}
  end

  defp format_client_log_single({from, :remote}, _) do
    {~c" Client ~0p is remote on node ~0p.", [from, node(from)]}
  end

  defp format_client_log_single({_From, {name, stacktrace0}}, formatOpts) do
    p = p(formatOpts)
    stacktrace = :lists.sublist(stacktrace0, 4)

    args =
      case :maps.get(:depth, formatOpts) do
        :unlimited ->
          [name, stacktrace]

        depth ->
          [name, depth, stacktrace, depth]
      end

    {~c" Client " ++ p ++ ~c" stacktrace: " ++ p ++ ~c".", args}
  end

  defp format_client_log(:undefined, _) do
    {~c"", []}
  end

  defp format_client_log({from, :dead}, _) do
    {~c"** Client ~p is dead~n", [from]}
  end

  defp format_client_log({from, :remote}, _) do
    {~c"** Client ~p is remote on node ~p~n", [from, node(from)]}
  end

  defp format_client_log({_From, {name, stacktrace}}, formatOpts) do
    p = p(formatOpts)
    format = :lists.append([~c"** Client ", p, ~c" stacktrace~n", ~c"** ", p, ~c"~n"])

    args =
      case :maps.get(:depth, formatOpts) do
        :unlimited ->
          [name, stacktrace]

        depth ->
          [name, depth, stacktrace, depth]
      end

    {format, args}
  end

  defp p(%{single_line: single, depth: depth, encoding: enc}) do
    ~c"~" ++ single(single) ++ mod(enc) ++ p(depth)
  end

  defp p(:unlimited) do
    ~c"p"
  end

  defp p(_Depth) do
    ~c"P"
  end

  defp single(true) do
    ~c"0"
  end

  defp single(false) do
    ~c""
  end

  defp mod(:latin1) do
    ~c""
  end

  defp mod(_) do
    ~c"t"
  end

  def format_status(opt, statusData) do
    [pDict, sysState, parent, debug, [name, state, cbCache, _Time, _HibernateAfterTimeout]] =
      statusData

    mod = r_callback_cache(cbCache, :module)
    header = :gen.format_status_header(~c"Status for generic server", name)

    status =
      case :gen.format_status(mod, opt, %{state: state, log: :sys.get_log(debug)}, [pDict, state]) do
        %{EXIT: r} = m ->
          Map.put(m, :"$status", [{:data, [{~c"State", r}]}])

        %{"$status": s} = m when is_list(s) ->
          m

        %{"$status": s} = m ->
          %{m | "$status": [s]}

        %{state: s} = m ->
          Map.put(m, :"$status", [{:data, [{~c"State", s}]}])
      end

    [
      {:header, header},
      {:data,
       [
         {~c"Status", sysState},
         {~c"Parent", parent},
         {~c"Logged events",
          format_log_state(
            mod,
            :maps.get(
              :log,
              status
            )
          )}
       ]}
      | :maps.get(:"$status", status)
    ]
  end

  defp format_log_state(mod, log) do
    case :erlang.function_exported(mod, :format_status, 1) do
      false ->
        for event <- log do
          case event do
            {:out, msg, from, state} ->
              status =
                :gen.format_status(mod, :terminate, %{state: state}, [:erlang.get(), state])

              {:out, msg, from, :maps.get(:state, status)}

            {:noreply, state} ->
              status =
                :gen.format_status(mod, :terminate, %{state: state}, [:erlang.get(), state])

              {:noreply, :maps.get(:state, status)}

            _ ->
              event
          end
        end

      true ->
        log
    end
  end
end
