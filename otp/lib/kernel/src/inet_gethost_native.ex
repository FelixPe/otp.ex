defmodule :m_inet_gethost_native do
  use Bitwise
  @behaviour :supervisor_bridge
  require Record
  Record.defrecord(:r_hostent, :hostent, h_name: :undefined,
                                   h_aliases: [], h_addrtype: :undefined,
                                   h_length: :undefined, h_addr_list: [])
  Record.defrecord(:r_statistics, :statistics, netdb_timeout: 0,
                                      netdb_internal: 0, port_crash: 0,
                                      notsup: 0, host_not_found: 0,
                                      try_again: 0, no_recovery: 0, no_data: 0)
  Record.defrecord(:r_request, :request, rid: :undefined,
                                   req: :undefined, timer_ref: :undefined,
                                   req_ts: :undefined)
  Record.defrecord(:r_state, :state, port: :noport,
                                 timeout: 8000, requests: :undefined,
                                 req_index: :undefined, req_clients: :undefined,
                                 parent: :undefined, pool_size: 4,
                                 statistics: :undefined)
  def init([]) do
    ref = make_ref()
    saveTE = :erlang.process_flag(:trap_exit, true)
    pid = spawn_link(:inet_gethost_native, :server_init,
                       [self(), ref])
    receive do
      ^ref ->
        :erlang.process_flag(:trap_exit, saveTE)
        {:ok, pid, pid}
      {:EXIT, ^pid, message} ->
        :erlang.process_flag(:trap_exit, saveTE)
        {:error, message}
    after 10000 ->
      :erlang.process_flag(:trap_exit, saveTE)
      {:error, {:timeout, :inet_gethost_native}}
    end
  end

  def start_link() do
    :supervisor_bridge.start_link({:local,
                                     :inet_gethost_native_sup},
                                    :inet_gethost_native, [])
  end

  def terminate(_Reason, pid) do
    (try do
      :erlang.exit(pid, :kill)
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end)
    :ok
  end

  defp run_once() do
    port = do_open_port(get_poolsize(), get_extra_args())
    timeout = :inet_db.res_option(:timeout) * 4
    :persistent_term.put({:inet_gethost_native, :timeout},
                           timeout)
    rID = 1
    {clientHandle, request} = (receive do
                                 {reqH, {1, proto0, name0}}
                                     when is_reference(reqH) ->
                                   {reqH,
                                      [<<rID :: size(32), 1 :: size(8),
                                           proto0 :: size(8)>>,
                                           name0, 0]}
                                 {reqH, {2, proto1, data1}}
                                     when is_reference(reqH) ->
                                   {reqH,
                                      <<rID :: size(32), 2 :: size(8),
                                          proto1 :: size(8), data1 :: binary>>}
                               after timeout ->
                                 exit(:normal)
                               end)
    _ = ((try do
           :erlang.port_command(port, request)
         catch
           :error, e -> {:EXIT, {e, __STACKTRACE__}}
           :exit, e -> {:EXIT, e}
           e -> e
         end))
    receive do
      {^port,
         {:data, <<^rID :: size(32), binReply :: binary>>}} ->
        send(clientHandle, {clientHandle, {:ok, binReply}})
    after timeout ->
      send(clientHandle, {clientHandle, {:error, :timeout}})
    end
  end

  def server_init(starter, ref) do
    _ = :erlang.process_flag(:trap_exit, true)
    case (:erlang.whereis(:inet_gethost_native)) do
      :undefined ->
        case ((try do
                :erlang.register(:inet_gethost_native, self())
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end)) do
          true ->
            send(starter, ref)
          _ ->
            exit({:already_started,
                    :erlang.whereis(:inet_gethost_native)})
        end
      winner ->
        exit({:already_started, winner})
    end
    _ = :erlang.process_flag(:message_queue_data, :off_heap)
    poolsize = get_poolsize()
    port = do_open_port(poolsize, get_extra_args())
    timeout = :inet_db.res_option(:timeout) * 4
    :persistent_term.put({:inet_gethost_native, :timeout},
                           timeout)
    :erlang.put(:rid, 0)
    :erlang.put(:num_requests, 0)
    requestTab = :ets.new(:ign_requests,
                            [:set, :protected, {:keypos, r_request(:rid)}])
    requestIndex = :ets.new(:ign_req_index,
                              [:set, :protected])
    requestClients = :ets.new(:ign_req_clients,
                                [:bag, :protected])
    state = r_state(port: port, timeout: timeout,
                requests: requestTab, req_index: requestIndex,
                req_clients: requestClients, pool_size: poolsize,
                statistics: r_statistics(), parent: starter)
    main_loop(state)
  end

  def main_loop(state) do
    receive do
      any ->
        handle_message(any, state)
    end
  end

  defp handle_message({clientHandle, {1, proto, name} = req}, state)
      when is_reference(clientHandle) do
    do_handle_call(clientHandle, req,
                     [<<1 :: size(8), proto :: size(8)>>, name, 0], state)
    main_loop(state)
  end

  defp handle_message({clientHandle, {2, proto, data} = req}, state)
      when is_reference(clientHandle) do
    do_handle_call(clientHandle, req,
                     <<2 :: size(8), proto :: size(8), data :: binary>>,
                     state)
    main_loop(state)
  end

  defp handle_message({clientHandle, {4, ctl, data}}, state)
      when is_reference(clientHandle) do
    _ = ((try do
           :erlang.port_command(r_state(state, :port),
                                  <<4294967295 :: size(32), 4 :: size(8),
                                      ctl :: size(8), data :: binary>>)
         catch
           :error, e -> {:EXIT, {e, __STACKTRACE__}}
           :exit, e -> {:EXIT, e}
           e -> e
         end))
    send(clientHandle, {clientHandle, :ok})
    main_loop(state)
  end

  defp handle_message({clientHandle, :restart_port}, state)
      when is_reference(clientHandle) do
    newPort = restart_port(state)
    send(clientHandle, {clientHandle, :ok})
    main_loop(r_state(state, port: newPort))
  end

  defp handle_message({port, {:data, data}}, state = r_state(port: port)) do
    newState = (case (data) do
                  <<rID :: size(32), binReply :: binary>> ->
                    case (binReply) do
                      <<unit, _ :: binary>> when unit === 0 or unit === 4 or
                                                   unit === 16
                                                 ->
                        case (:ets.take(r_state(state, :requests), rID)) do
                          [] ->
                            state
                          [r_request(timer_ref: timerRef, req: req)] ->
                            _ = :erlang.cancel_timer(timerRef,
                                                       [{:async, true}, {:info,
                                                                           false}])
                            :ets.delete(r_state(state, :req_index), req)
                            :lists.foreach(fn {_, clientHandle} ->
                                                send(clientHandle, {clientHandle,
                                                                      {:ok,
                                                                         binReply}})
                                           end,
                                             :ets.take(r_state(state, :req_clients),
                                                         rID))
                            :erlang.put(:num_requests,
                                          :erlang.get(:num_requests) - 1)
                            state
                        end
                      _UnitError ->
                        newPort = restart_port(state)
                        r_state(state, port: newPort)
                    end
                  _BasicFormatError ->
                    newPort = restart_port(state)
                    r_state(state, port: newPort)
                end)
    main_loop(newState)
  end

  defp handle_message({:EXIT, port, _Reason},
            state = r_state(port: port)) do
    :noop
    newPort = restart_port(state)
    main_loop(r_state(state, port: newPort))
  end

  defp handle_message({port, :eof}, state = r_state(port: port)) do
    :noop
    newPort = restart_port(state)
    main_loop(r_state(state, port: newPort))
  end

  defp handle_message({:timeout, timerRef, rID}, state) do
    case (:ets.lookup(r_state(state, :requests), rID)) do
      [] ->
        :ok
      [r_request(timer_ref: ^timerRef, req: req,
           req_ts: :undefined)] ->
        :ets.delete(r_state(state, :requests), rID)
        :ets.delete(r_state(state, :req_index), req)
        :ets.delete(r_state(state, :req_clients), rID)
        :erlang.put(:num_requests,
                      :erlang.get(:num_requests) - 1)
        _ = ((try do
               :erlang.port_command(r_state(state, :port),
                                      <<rID :: size(32), 3>>)
             catch
               :error, e -> {:EXIT, {e, __STACKTRACE__}}
               :exit, e -> {:EXIT, e}
               e -> e
             end))
        :ok
      [r_request(timer_ref: ^timerRef, req_ts: reqTs)] ->
        timeoutTime = :erlang.convert_time_unit(reqTs, :native,
                                                  :millisecond) + r_state(state, :timeout)
        newTimerRef = :erlang.start_timer(timeoutTime, self(),
                                            rID, [{:abs, true}])
        true = :ets.update_element(r_state(state, :requests), rID,
                                     [{r_request(:timer_ref), newTimerRef}, {r_request(:req_ts),
                                                                       :undefined}])
        :ok
      [r_request()] ->
        :ok
    end
    main_loop(state)
  end

  defp handle_message({:system, from, req}, state) do
    :sys.handle_system_msg(req, from, r_state(state, :parent),
                             :inet_gethost_native, [], state)
  end

  defp handle_message(_, state) do
    main_loop(state)
  end

  defp do_handle_call(clientHandle, req, rData, state) do
    case (:ets.lookup(r_state(state, :req_index), req)) do
      [{_, rID}] ->
        true = :ets.update_element(r_state(state, :requests), rID,
                                     {r_request(:req_ts), :erlang.monotonic_time()})
        :ok
      [] ->
        rID = get_rid()
        _ = ((try do
               :erlang.port_command(r_state(state, :port),
                                      [<<rID :: size(32)>> | rData])
             catch
               :error, e -> {:EXIT, {e, __STACKTRACE__}}
               :exit, e -> {:EXIT, e}
               e -> e
             end))
        timeout = r_state(state, :timeout)
        timerRef = :erlang.start_timer(timeout, self(), rID)
        :ets.insert(r_state(state, :requests),
                      r_request(rid: rID, req: req, timer_ref: timerRef))
        :ets.insert(r_state(state, :req_index), {req, rID})
    end
    :ets.insert(r_state(state, :req_clients), {rID, clientHandle})
    :ok
  end

  defp get_rid() do
    new = rem(:erlang.get(:rid) + 1, 134217727)
    :erlang.put(:rid, new)
    new
  end

  defp foreach(fun, table) do
    foreach(fun, table, :ets.first(table))
  end

  defp foreach(_Fun, _Table, :"$end_of_table") do
    :ok
  end

  defp foreach(fun, table, key) do
    [object] = :ets.lookup(table, key)
    fun.(object)
    foreach(fun, table, :ets.next(table, key))
  end

  defp restart_port(r_state(port: port, requests: requests)) do
    _ = ((try do
           :erlang.port_close(port)
         catch
           :error, e -> {:EXIT, {e, __STACKTRACE__}}
           :exit, e -> {:EXIT, e}
           e -> e
         end))
    newPort = do_open_port(get_poolsize(), get_extra_args())
    foreach(fn r_request(rid: rID, req: {op, proto, rdata}) ->
                 case (op) do
                   1 ->
                     :erlang.port_command(newPort,
                                            [<<rID :: size(32), 1 :: size(8),
                                                 proto :: size(8)>>,
                                                 rdata, 0])
                   2 ->
                     :erlang.port_command(newPort,
                                            <<rID :: size(32), 2 :: size(8),
                                                proto :: size(8),
                                                rdata :: binary>>)
                 end
            end,
              requests)
    newPort
  end

  defp do_open_port(poolsize, extraArgs) do
    args = [:erlang.integer_to_list(poolsize)] ++ extraArgs
    opts = [:overlapped_io, {:args, args}, {:packet, 4},
                                               :eof, :binary]
    {:ok, [binDir]} = :init.get_argument(:bindir)
    prog = :filename.join(binDir, 'inet_gethost')
    open_executable(prog, opts)
  end

  defp open_executable(prog, opts) do
    try do
      :erlang.open_port({:spawn_executable, prog}, opts)
    catch
      :error, :badarg when hd(opts) === :overlapped_io ->
        open_executable(prog, tl(opts))
      :error, reason ->
        :erlang.halt('Can not execute ' ++ prog ++ ' : ' ++ term2string(reason))
    end
  end

  defp term2string(term) do
    :unicode.characters_to_list(:io_lib.format('~tw', [term]))
  end

  defp get_extra_args() do
    (case (:application.get_env(:kernel,
                                  :gethost_prioritize)) do
       {:ok, false} ->
         ['-ng']
       _ ->
         []
     end) ++ (case (:application.get_env(:kernel,
                                           :gethost_extra_args)) do
                {:ok, l} when is_list(l) ->
                  :string.tokens(l, ' ')
                _ ->
                  []
              end)
  end

  defp get_poolsize() do
    case (:application.get_env(:kernel,
                                 :gethost_poolsize)) do
      {:ok, i} when is_integer(i) ->
        i
      _ ->
        4
    end
  end

  def system_continue(_Parent, _, state) do
    main_loop(state)
  end

  def system_terminate(reason, _Parent, _, _State) do
    exit(reason)
  end

  def system_code_change(state, _Module, _OldVsn, _Extra) do
    {:ok, state}
  end

  def gethostbyname(name) do
    gethostbyname(name, :inet)
  end

  def gethostbyname(name, :inet) when is_list(name) do
    getit(1, 1, name, name)
  end

  def gethostbyname(name, :inet6) when is_list(name) do
    getit(1, 2, name, name)
  end

  def gethostbyname(name, type) when is_atom(name) do
    gethostbyname(:erlang.atom_to_list(name), type)
  end

  def gethostbyname(_, _) do
    {:error, :formerr}
  end

  def gethostbyaddr({a, b, c, d} = addr) when (is_integer(a) and
                                      a < 256 and is_integer(b) and b < 256 and
                                      is_integer(c) and c < 256 and
                                      is_integer(d) and d < 256) do
    getit(2, 1, <<a, b, c, d>>, addr)
  end

  def gethostbyaddr({a, b, c, d, e, f, g, h} = addr)
      when (is_integer(a) and a < 65536 and is_integer(b) and
              b < 65536 and is_integer(c) and c < 65536 and
              is_integer(d) and d < 65536 and is_integer(e) and
              e < 65536 and is_integer(f) and f < 65536 and
              is_integer(g) and g < 65536 and is_integer(h) and
              h < 65536) do
    getit(2, 2,
            <<a :: size(16), b :: size(16), c :: size(16),
                d :: size(16), e :: size(16), f :: size(16),
                g :: size(16), h :: size(16)>>,
            addr)
  end

  def gethostbyaddr(addr) when is_list(addr) do
    case (:inet_parse.address(addr)) do
      {:ok, iP} ->
        gethostbyaddr(iP)
      _Error ->
        {:error, :formerr}
    end
  end

  def gethostbyaddr(addr) when is_atom(addr) do
    gethostbyaddr(:erlang.atom_to_list(addr))
  end

  def gethostbyaddr(_) do
    {:error, :formerr}
  end

  def control({:debug_level, level}) when is_integer(level) do
    getit(4, 0, <<level :: size(32)>>, :undefined)
  end

  def control(:soft_restart) do
    getit(:restart_port, :undefined)
  end

  def control(_) do
    {:error, :formerr}
  end

  defp getit(op, proto, data, defaultName) do
    getit({op, proto, data}, defaultName)
  end

  defp getit(req, defaultName) do
    pid = ensure_started()
    defaultTimeout = r_state(r_state(), :timeout)
    timeout = :persistent_term.get({:inet_gethost_native,
                                      :timeout},
                                     defaultTimeout)
    case (call(pid, req, timeout)) do
      {:ok, binHostent} ->
        parse_address(binHostent, defaultName)
      :ok ->
        :ok
      {:error, _} = result ->
        result
    end
  end

  defp call(pid, req, timeout) do
    reqHandle = monitor(:process, pid,
                          [{:alias, :reply_demonitor}])
    send(pid, {reqHandle, req})
    wait_reply(reqHandle, timeout)
  end

  defp wait_reply(reqHandle, timeout) do
    receive do
      {^reqHandle, result} ->
        result
      {:DOWN, ^reqHandle, :process, _, reason} ->
        {:error, reason}
    after timeout ->
      case (unalias(reqHandle)) do
        true ->
          :erlang.demonitor(reqHandle, [:flush])
          {:error, :timeout}
        false ->
          wait_reply(reqHandle, :infinity)
      end
    end
  end

  defp ensure_started() do
    case (:erlang.whereis(:inet_gethost_native)) do
      :undefined ->
        childSpec = {:inet_gethost_native_sup,
                       {:inet_gethost_native, :start_link, []}, :temporary,
                       1000, :worker, [:inet_gethost_native]}
        ensure_started([:kernel_safe_sup, :net_sup], childSpec)
      pid ->
        pid
    end
  end

  defp ensure_started([supervisor | supervisors], childSpec) do
    case (:erlang.whereis(supervisor)) do
      :undefined ->
        ensure_started(supervisors, childSpec)
      _ ->
        do_start(supervisor, childSpec)
        case (:erlang.whereis(:inet_gethost_native)) do
          :undefined ->
            exit({:could_not_start_server, :inet_gethost_native})
          pid ->
            pid
        end
    end
  end

  defp ensure_started([], _ChildSpec) do
    spawn(&run_once/0)
  end

  defp do_start(sup, c) do
    {child, _, _, _, _, _} = c
    case (:supervisor.start_child(sup, c)) do
      {:ok, _} ->
        :ok
      {:error, {:already_started, pid}} when is_pid(pid) ->
        :ok
      {:error, {{:already_started, pid}, _Child}}
          when is_pid(pid) ->
        :ok
      {:error, :already_present} ->
        _ = :supervisor.delete_child(sup, child)
        do_start(sup, c)
    end
  end

  defp parse_address(binHostent, defaultName) do
    case ((try do
            (
              case (binHostent) do
                <<0, errstring :: binary>> ->
                  {:error, :erlang.list_to_atom(listify(errstring))}
                <<length, naddr :: size(32), t0 :: binary>>
                    when length === 4 ->
                  {t1, addresses} = pick_addresses_v4(naddr, t0)
                  {name, names} = expand_default_name(pick_names(t1),
                                                        defaultName)
                  return_hostent(length, addresses, name, names)
                <<length, naddr :: size(32), t0 :: binary>>
                    when length === 16 ->
                  {t1, addresses} = pick_addresses_v6(naddr, t0)
                  {name, names} = expand_default_name(pick_names(t1),
                                                        defaultName)
                  return_hostent(length, addresses, name, names)
                _Else ->
                  {:error,
                     {:internal_error, {:malformed_response, binHostent}}}
              end
            )
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      {:EXIT, reason} ->
        reason
      normal ->
        normal
    end
  end

  defp return_hostent(length, addresses, name, aliases) do
    case (addresses) do
      [] ->
        {:error, :nxdomain}
      [_ | _] ->
        addrtype = (case (length) do
                      4 ->
                        :inet
                      16 ->
                        :inet6
                    end)
        hostent = r_hostent(h_length: length, h_addrtype: addrtype,
                      h_name: name, h_aliases: aliases,
                      h_addr_list: addresses)
        {:ok, hostent}
    end
  end

  defp expand_default_name([], defaultName) when is_list(defaultName) do
    {defaultName, []}
  end

  defp expand_default_name([], defaultName) when is_tuple(defaultName) do
    {:inet_parse.ntoa(defaultName), []}
  end

  defp expand_default_name([name | names], defaultName)
      when is_list(defaultName) or is_tuple(defaultName) do
    {name, names}
  end

  defp listify(bin) do
    n = byte_size(bin) - 1
    <<bin2 :: size(n) - binary, ch>> = bin
    case (ch) do
      0 ->
        listify(bin2)
      _ ->
        :erlang.binary_to_list(bin)
    end
  end

  defp pick_addresses_v4(0, tail) do
    {tail, []}
  end

  defp pick_addresses_v4(n, <<a, b, c, d, tail :: binary>>) do
    {nTail, oList} = pick_addresses_v4(n - 1, tail)
    {nTail, [{a, b, c, d} | oList]}
  end

  defp pick_addresses_v6(0, tail) do
    {tail, []}
  end

  defp pick_addresses_v6(num,
            <<a :: size(16), b :: size(16), c :: size(16),
                d :: size(16), e :: size(16), f :: size(16),
                g :: size(16), h :: size(16), tail :: binary>>) do
    {nTail, oList} = pick_addresses_v6(num - 1, tail)
    {nTail, [{a, b, c, d, e, f, g, h} | oList]}
  end

  defp ndx(ch, bin) do
    ndx(ch, 0, byte_size(bin), bin)
  end

  defp ndx(_, n, n, _) do
    :undefined
  end

  defp ndx(ch, i, n, bin) do
    case (bin) do
      <<_ :: size(i) - binary, ^ch, _ :: binary>> ->
        i
      _ ->
        ndx(ch, i + 1, n, bin)
    end
  end

  defp pick_names(<<length :: size(32), namelist :: binary>>) do
    pick_names(length, namelist)
  end

  defp pick_names(0, <<>>) do
    []
  end

  defp pick_names(0, _) do
    exit({:error, :format_error})
  end

  defp pick_names(_N, <<>>) do
    exit({:error, :format_error})
  end

  defp pick_names(n, bin) do
    ndx = ndx(0, bin)
    <<str :: size(ndx) - binary, 0, rest :: binary>> = bin
    [:erlang.binary_to_list(str) | pick_names(n - 1, rest)]
  end

end