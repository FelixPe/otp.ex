defmodule :m_rpc do
  use Bitwise
  @behaviour :gen_server
  def start() do
    :gen_server.start({:local, :rex}, :rpc, [],
                        [{:spawn_opt, [{:message_queue_data, :off_heap}]}])
  end

  def start_link() do
    :gen_server.start_link({:local, :rex}, :rpc, [],
                             [{:spawn_opt, [{:message_queue_data, :off_heap}]}])
  end

  def stop() do
    stop(:rex)
  end

  defp stop(rpc) do
    :gen_server.call(rpc, :stop, :infinity)
  end

  def init([]) do
    :erlang.process_flag(:trap_exit, true)
    {:ok, %{nodes_observer: start_nodes_observer()}}
  end

  def handle_call({:call, mod, fun, args, gleader}, to, s) do
    execCall = fn () ->
                    set_group_leader(gleader)
                    gleaderBeforeCall = :erlang.group_leader()
                    reply = execute_call(mod, fun, args)
                    case (gleader) do
                      {:send_stdout_to_caller, _} ->
                        ref = :erlang.make_ref()
                        send(gleaderBeforeCall, {:stop, self(), ref, to, reply})
                        receive do
                          ^ref ->
                            :ok
                        end
                      _ ->
                        reply(to, reply)
                    end
               end
    try do
      {_, mon} = spawn_monitor(execCall)
      {:noreply, :maps.put(mon, to, s)}
    catch
      :error, :system_limit ->
        {:reply, {:badrpc, {:EXIT, :system_limit}}, s}
    end
  end

  def handle_call({:block_call, mod, fun, args, gleader}, _To,
           s) do
    myGL = :erlang.group_leader()
    set_group_leader(gleader)
    reply = execute_call(mod, fun, args)
    :erlang.group_leader(myGL, self())
    {:reply, reply, s}
  end

  def handle_call(:stop, _To, s) do
    {:stop, :normal, :stopped, s}
  end

  def handle_call(_, _To, s) do
    {:noreply, s}
  end

  def handle_cast({:cast, mod, fun, args, gleader}, s) do
    _ = (try do
           spawn(fn () ->
                      set_group_leader(gleader)
                      :erpc.execute_cast(mod, fun, args)
                 end)
         catch
           :error, :system_limit ->
             :ok
         end)
    {:noreply, s}
  end

  def handle_cast(_, s) do
    {:noreply, s}
  end

  def handle_info({:DOWN, m, :process, p, _},
           %{nodes_observer: {p, m}} = s) do
    {:noreply,
       Map.put(s, :nodes_observer, start_nodes_observer())}
  end

  def handle_info({:DOWN, m, :process, _, :normal}, s) do
    {:noreply, :maps.remove(m, s)}
  end

  def handle_info({:DOWN, m, :process, _, reason}, s) do
    case (:maps.get(m, s, :undefined)) do
      :undefined ->
        {:noreply, s}
      {_, _} = to ->
        reply(to, {:badrpc, {:EXIT, reason}})
        {:noreply, :maps.remove(m, s)}
    end
  end

  def handle_info({from, {:sbcast, name, msg}}, s) do
    _ = (case ((try do
                 send(name, msg)
               catch
                 :error, e -> {:EXIT, {e, __STACKTRACE__}}
                 :exit, e -> {:EXIT, e}
                 e -> e
               end)) do
           {:EXIT, _} ->
             send(from, {:rex, node(), {:nonexisting_name, name}})
           _ ->
             send(from, {:rex, node(), node()})
         end)
    {:noreply, s}
  end

  def handle_info({from, {:send, name, msg}}, s) do
    _ = (case ((try do
                 send(name, {from, msg})
               catch
                 :error, e -> {:EXIT, {e, __STACKTRACE__}}
                 :exit, e -> {:EXIT, e}
                 e -> e
               end)) do
           {:EXIT, _} ->
             send(from, {:rex, node(), {:nonexisting_name, name}})
           _ ->
             :ok
         end)
    {:noreply, s}
  end

  def handle_info({from, {:call, mod, fun, args, gleader}}, s) do
    to = {:rex, from}
    newGleader = (case (gleader) do
                    :send_stdout_to_caller ->
                      {:send_stdout_to_caller, from}
                    _ ->
                      gleader
                  end)
    request = {:call, mod, fun, args, newGleader}
    case (handle_call(request, to, s)) do
      {:noreply, _NewS} = return ->
        return
      {:reply, reply, newS} ->
        reply(to, reply)
        {:noreply, newS}
    end
  end

  def handle_info({from, :features_request}, s) do
    send(from, {:features_reply, node(), [:erpc]})
    {:noreply, s}
  end

  def handle_info(_, s) do
    {:noreply, s}
  end

  def terminate(_, _S) do
    :ok
  end

  def code_change(_, s, _) do
    {:ok, s}
  end

  defp reply({:rex, from}, reply) do
    send(from, {:rex, reply})
    :ok
  end

  defp reply({from, _} = to, reply) when is_pid(from) do
    :gen_server.reply(to, reply)
  end

  defp execute_call(mod, fun, args) do
    try do
      {:return, return} = :erpc.execute_call(mod, fun, args)
      return
    catch
      result ->
        result
      :exit, reason ->
        {:badrpc, {:EXIT, reason}}
      :error, reason ->
        case (:erpc.is_arg_error(reason, mod, fun, args)) do
          true ->
            {:badrpc, {:EXIT, reason}}
          false ->
            rpcStack = :erpc.trim_stack(__STACKTRACE__, mod, fun,
                                          args)
            {:badrpc, {:EXIT, {reason, rpcStack}}}
        end
    end
  end

  defp set_group_leader(gleader) when is_pid(gleader) do
    :erlang.group_leader(gleader, self())
  end

  defp set_group_leader({:send_stdout_to_caller, callerPid}) do
    :erlang.group_leader(cnode_call_group_leader_start(callerPid),
                           self())
  end

  defp set_group_leader(:user) do
    gleader = (case (:erlang.whereis(:user)) do
                 pid when is_pid(pid) ->
                   pid
                 :undefined ->
                   proxy_user()
               end)
    :erlang.group_leader(gleader, self())
  end

  defp proxy_user() do
    case (:erlang.whereis(:rex_proxy_user)) do
      pid when is_pid(pid) ->
        pid
      :undefined ->
        pid = spawn(fn () ->
                         proxy_user_loop()
                    end)
        try do
          :erlang.register(:rex_proxy_user, pid)
        catch
          :error, _ ->
            :erlang.exit(pid, :kill)
            proxy_user()
        else
          true ->
            pid
        end
    end
  end

  defp proxy_user_loop() do
    :timer.sleep(200)
    case (:erlang.whereis(:user)) do
      pid when is_pid(pid) ->
        proxy_user_flush()
      :undefined ->
        proxy_user_loop()
    end
  end

  def proxy_user_flush() do
    receive do
      msg ->
        send(:user, msg)
    after 10 * 1000 ->
      :erlang.hibernate(:rpc, :proxy_user_flush, [])
    end
    proxy_user_flush()
  end

  defp start_nodes_observer() do
    init = fn () ->
                :erlang.process_flag(:priority, :high)
                :erlang.process_flag(:trap_exit, true)
                tab = :ets.new(:rex_nodes_observer,
                                 [{:read_concurrency, true}, :protected])
                :persistent_term.put(:rex_nodes_observer, tab)
                :ok = :net_kernel.monitor_nodes(true)
                :lists.foreach(fn n ->
                                    send(self(), {:nodeup, n})
                               end,
                                 [node() | :erlang.nodes()])
                nodes_observer_loop(tab)
           end
    spawn_monitor(init)
  end

  defp nodes_observer_loop(tab) do
    receive do
      {:nodeup, :nonode@nohost} ->
        :ok
      {:nodeup, n} ->
        send({:rex, n}, {self(), :features_request})
      {:nodedown, n} ->
        :ets.delete(tab, n)
      {:features_reply, n, featureList} ->
        try do
          spawnRpc = :lists.member(:erpc, featureList)
          :ets.insert(tab, {n, spawnRpc})
        catch
          _, _ ->
            :ets.insert(tab, {n, false})
        end
      _ ->
        :ignore
    end
    nodes_observer_loop(tab)
  end

  def call(n, m, f, a) do
    call(n, m, f, a, :infinity)
  end

  def call(n, m, f, a, t) do
    try do
      :erpc.call(n, m, f, a, t)
    catch
      class_, reason_ ->
        rpcify_exception(class_, reason_)
    else
      {:EXIT, _} = badRpc_ ->
        {:badrpc, badRpc_}
      result_ ->
        result_
    end
  end

  def block_call(n, m, f, a) do
    block_call(n, m, f, a, :infinity)
  end

  def block_call(n, m, f, a, timeout) when (is_atom(n) and
                                      is_atom(m) and is_list(a) and
                                      timeout == :infinity or is_integer(timeout) and 0 <= timeout and timeout <= 4294967295) do
    do_srv_call(n,
                  {:block_call, m, f, a, :erlang.group_leader()}, timeout)
  end

  defp rpcify_exception(:throw, {:EXIT, _} = badRpc) do
    {:badrpc, badRpc}
  end

  defp rpcify_exception(:throw, return) do
    return
  end

  defp rpcify_exception(:exit, {:exception, exit}) do
    {:badrpc, {:EXIT, exit}}
  end

  defp rpcify_exception(:exit, {:signal, reason}) do
    {:badrpc, {:EXIT, reason}}
  end

  defp rpcify_exception(:exit, reason) do
    exit(reason)
  end

  defp rpcify_exception(:error, {:exception, error, stack}) do
    {:badrpc, {:EXIT, {error, stack}}}
  end

  defp rpcify_exception(:error, {:erpc, :badarg}) do
    :erlang.error(:badarg)
  end

  defp rpcify_exception(:error, {:erpc, :noconnection}) do
    {:badrpc, :nodedown}
  end

  defp rpcify_exception(:error, {:erpc, :timeout}) do
    {:badrpc, :timeout}
  end

  defp rpcify_exception(:error, {:erpc, :notsup}) do
    {:badrpc, :notsup}
  end

  defp rpcify_exception(:error, {:erpc, error}) do
    {:badrpc, {:EXIT, error}}
  end

  defp rpcify_exception(:error, reason) do
    :erlang.error(reason)
  end

  defp do_srv_call(node, request, :infinity) do
    rpc_check((try do
                :gen_server.call({:rex, node}, request, :infinity)
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end))
  end

  defp do_srv_call(node, request, timeout) do
    tag = make_ref()
    {receiver, mref} = :erlang.spawn_monitor(fn () ->
                                                  :erlang.process_flag(:trap_exit,
                                                                         true)
                                                  result = :gen_server.call({:rex,
                                                                               node},
                                                                              request,
                                                                              timeout)
                                                  exit({self(), tag, result})
                                             end)
    receive do
      {:DOWN, ^mref, _, _, {^receiver, ^tag, result}} ->
        rpc_check(result)
      {:DOWN, ^mref, _, _, reason} ->
        rpc_check_t({:EXIT, reason})
    end
  end

  defp rpc_check_t({:EXIT, {:timeout, _}}) do
    {:badrpc, :timeout}
  end

  defp rpc_check_t({:EXIT, {:timeout_value, _}}) do
    :erlang.error(:badarg)
  end

  defp rpc_check_t(x) do
    rpc_check(x)
  end

  defp rpc_check({:EXIT, {{:nodedown, _}, _}}) do
    {:badrpc, :nodedown}
  end

  defp rpc_check({:EXIT, _} = exit) do
    {:badrpc, exit}
  end

  defp rpc_check(x) do
    x
  end

  def server_call(node, name, replyWrapper, msg)
      when (is_atom(node) and is_atom(name)) do
    cond do
      (node() === :nonode@nohost and
         node !== :nonode@nohost) ->
        {:error, :nodedown}
      true ->
        ref = :erlang.monitor(:process, {name, node})
        send({name, node}, {self(), msg})
        receive do
          {:DOWN, ^ref, _, _, _} ->
            {:error, :nodedown}
          {^replyWrapper, ^node, reply} ->
            :erlang.demonitor(ref, [:flush])
            reply
        end
    end
  end

  def cast(node, mod, fun, args) do
    try do
      :ok = :erpc.cast(node, mod, fun, args)
    catch
      :error, {:erpc, :badarg} ->
        :erlang.error(:badarg)
    end
    true
  end

  def abcast(name, mess) do
    abcast([node() | :erlang.nodes()], name, mess)
  end

  def abcast([node | tail], name, mess) do
    dest = {name, node}
    try do
      :erlang.send(dest, mess)
    catch
      :error, _ ->
        :ok
    end
    abcast(tail, name, mess)
  end

  def abcast([], _, _) do
    :abcast
  end

  def sbcast(name, mess) do
    sbcast([node() | :erlang.nodes()], name, mess)
  end

  def sbcast(nodes, name, mess) do
    monitors = send_nodes(nodes, :rex,
                            {:sbcast, name, mess}, [])
    rec_nodes(:rex, monitors)
  end

  def eval_everywhere(mod, fun, args) do
    eval_everywhere([node() | :erlang.nodes()], mod, fun,
                      args)
  end

  def eval_everywhere(nodes, mod, fun, args) do
    :lists.foreach(fn node ->
                        cast(node, mod, fun, args)
                   end,
                     nodes)
    :abcast
  end

  defp send_nodes([node | tail], name, msg, monitors)
      when is_atom(node) do
    monitor = start_monitor(node, name)
    (try do
      send({name, node}, {self(), msg})
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end)
    send_nodes(tail, name, msg, [monitor | monitors])
  end

  defp send_nodes([_Node | tail], name, msg, monitors) do
    send_nodes(tail, name, msg, monitors)
  end

  defp send_nodes([], _Name, _Req, monitors) do
    monitors
  end

  defp start_monitor(node, name) do
    cond do
      (node() === :nonode@nohost and
         node !== :nonode@nohost) ->
        ref = make_ref()
        send(self(), {:DOWN, ref, :process, {name, node},
                        :noconnection})
        {node, ref}
      true ->
        {node, :erlang.monitor(:process, {name, node})}
    end
  end

  def multicall(m, f, a) do
    multicall(m, f, a, :infinity)
  end

  def multicall(nodes, m, f, a) when is_list(nodes) do
    multicall(nodes, m, f, a, :infinity)
  end

  def multicall(m, f, a, timeout) do
    multicall([node() | :erlang.nodes()], m, f, a, timeout)
  end

  def multicall(nodes, m, f, a, timeout) do
    eRpcRes = (try do
                 :erpc.multicall(nodes, m, f, a, timeout)
               catch
                 :error, {:erpc, :badarg} ->
                   :erlang.error(:badarg)
               end)
    rpcmulticallify(nodes, eRpcRes, [], [])
  end

  defp rpcmulticallify([], [], ok, err) do
    {:lists.reverse(ok), :lists.reverse(err)}
  end

  defp rpcmulticallify([_N | ns], [{:ok, {:EXIT, _} = exit} | rlts],
            ok, err) do
    rpcmulticallify(ns, rlts, [{:badrpc, exit} | ok], err)
  end

  defp rpcmulticallify([_N | ns], [{:ok, return} | rlts], ok, err) do
    rpcmulticallify(ns, rlts, [return | ok], err)
  end

  defp rpcmulticallify([n | ns], [{:error, {:erpc, reason}} | rlts],
            ok, err)
      when reason == :timeout or reason == :noconnection do
    rpcmulticallify(ns, rlts, ok, [n | err])
  end

  defp rpcmulticallify([_N | ns], [{class, reason} | rlts], ok, err) do
    rpcmulticallify(ns, rlts,
                      [rpcify_exception(class, reason) | ok], err)
  end

  def multi_server_call(name, msg) do
    multi_server_call([node() | :erlang.nodes()], name, msg)
  end

  def multi_server_call(nodes, name, msg) when (is_list(nodes) and
                                   is_atom(name)) do
    monitors = send_nodes(nodes, name, msg, [])
    rec_nodes(name, monitors)
  end

  defp rec_nodes(name, nodes) do
    rec_nodes(name, nodes, [], [])
  end

  defp rec_nodes(_Name, [], badnodes, replies) do
    {replies, badnodes}
  end

  defp rec_nodes(name, [{n, r} | tail], badnodes, replies) do
    receive do
      {:DOWN, ^r, _, _, _} ->
        rec_nodes(name, tail, [n | badnodes], replies)
      {:rex, ^n, {:nonexisting_name, _}} ->
        :erlang.demonitor(r, [:flush])
        rec_nodes(name, tail, [n | badnodes], replies)
      {^name, ^n, reply} ->
        :erlang.demonitor(r, [:flush])
        rec_nodes(name, tail, badnodes, [reply | replies])
    end
  end

  def async_call(node, mod, fun, args) do
    try do
      :erpc.send_request(node, mod, fun, args)
    catch
      :error, {:erpc, :badarg} ->
        :erlang.error(:badarg)
    end
  end

  def yield(key) do
    try do
      :erpc.receive_response(key)
    catch
      class_, reason_ ->
        rpcify_exception(class_, reason_)
    else
      {:EXIT, _} = badRpc_ ->
        {:badrpc, badRpc_}
      result_ ->
        result_
    end
  end

  def nb_yield(key, tmo) do
    try do
      :erpc.wait_response(key, tmo)
    catch
      class, reason ->
        {:value, rpcify_exception(class, reason)}
    else
      :no_response ->
        :timeout
      {:response, {:EXIT, _} = badRpc} ->
        {:value, {:badrpc, badRpc}}
      {:response, r} ->
        {:value, r}
    end
  end

  def nb_yield(key) do
    nb_yield(key, 0)
  end

  def parallel_eval(argL) do
    nodes = [node() | :erlang.nodes()]
    keys = map_nodes(argL, nodes, nodes)
    for k <- keys do
      yield(k)
    end
  end

  defp map_nodes([], _, _) do
    []
  end

  defp map_nodes(argL, [], original) do
    map_nodes(argL, original, original)
  end

  defp map_nodes([{m, f, a} | tail], [node | moreNodes],
            original) do
    [:rpc.async_call(node, m, f, a) | map_nodes(tail,
                                                  moreNodes, original)]
  end

  def pmap({m, f}, as, list) do
    check(parallel_eval(build_args(m, f, as, list, [])), [])
  end

  defp build_args(m, f, as, [arg | tail], acc) do
    build_args(m, f, as, tail, [{m, f, [arg | as]} | acc])
  end

  defp build_args(m, f, _, [], acc) when (is_atom(m) and
                                    is_atom(f)) do
    acc
  end

  defp check([{:badrpc, _} | _], _) do
    exit(:badrpc)
  end

  defp check([x | t], ack) do
    check(t, [x | ack])
  end

  defp check([], ack) do
    ack
  end

  def pinfo(pid) when node(pid) === node() do
    :erlang.process_info(pid)
  end

  def pinfo(pid) do
    call(node(pid), :erlang, :process_info, [pid])
  end

  def pinfo(pid, item) when node(pid) === node() do
    :erlang.process_info(pid, item)
  end

  def pinfo(pid, item) do
    block_call(node(pid), :erlang, :process_info,
                 [pid, item])
  end

  require Record
  Record.defrecord(:r_cnode_call_group_leader_state, :cnode_call_group_leader_state, caller_pid: :undefined)
  defp cnode_call_group_leader_loop(state) do
    receive do
      {:io_request, from, replyAs, request} ->
        {_, reply,
           newState} = cnode_call_group_leader_request(request,
                                                         state)
        send(from, {:io_reply, replyAs, reply})
        cnode_call_group_leader_loop(newState)
      {:stop, stopRequesterPid, ref, to, reply} ->
        reply(to, reply)
        send(stopRequesterPid, ref)
        :ok
      _Unknown ->
        cnode_call_group_leader_loop(state)
    end
  end

  defp cnode_call_group_leader_request({:put_chars, encoding, chars}, state) do
    cnode_call_group_leader_put_chars(chars, encoding,
                                        state)
  end

  defp cnode_call_group_leader_request({:put_chars, encoding, module, function, args},
            state) do
    try do
      cnode_call_group_leader_request({:put_chars, encoding,
                                         apply(module, function, args)},
                                        state)
    catch
      _, _ ->
        {:error, {:error, function}, state}
    end
  end

  defp cnode_call_group_leader_request({:requests, reqs}, state) do
    cnode_call_group_leader_multi_request(reqs,
                                            {:ok, :ok, state})
  end

  defp cnode_call_group_leader_request({:get_until, _, _, _, _, _}, state) do
    {:error, {:error, :enotsup}, state}
  end

  defp cnode_call_group_leader_request({:get_chars, _, _, _}, state) do
    {:error, {:error, :enotsup}, state}
  end

  defp cnode_call_group_leader_request({:get_line, _, _}, state) do
    {:error, {:error, :enotsup}, state}
  end

  defp cnode_call_group_leader_request({:get_geometry, _}, state) do
    {:error, {:error, :enotsup}, state}
  end

  defp cnode_call_group_leader_request({:setopts, _Opts}, state) do
    {:error, {:error, :enotsup}, state}
  end

  defp cnode_call_group_leader_request(:getopts, state) do
    {:error, {:error, :enotsup}, state}
  end

  defp cnode_call_group_leader_request(_Other, state) do
    {:error, {:error, :request}, state}
  end

  defp cnode_call_group_leader_multi_request([r | rs], {:ok, _Res, state}) do
    cnode_call_group_leader_multi_request(rs,
                                            cnode_call_group_leader_request(r,
                                                                              state))
  end

  defp cnode_call_group_leader_multi_request([_ | _], error) do
    error
  end

  defp cnode_call_group_leader_multi_request([], result) do
    result
  end

  defp cnode_call_group_leader_put_chars(chars, encoding, state) do
    cNodePid = r_cnode_call_group_leader_state(state, :caller_pid)
    case (:unicode.characters_to_binary(chars, encoding,
                                          :utf8)) do
      data when is_binary(data) ->
        send(cNodePid, {:rex_stdout, data})
        {:ok, :ok, state}
      error ->
        {:error, {:error, error}, :state}
    end
  end

  defp cnode_call_group_leader_init(callerPid) do
    state = r_cnode_call_group_leader_state(caller_pid: callerPid)
    cnode_call_group_leader_loop(state)
  end

  defp cnode_call_group_leader_start(callerPid) do
    spawn_link(fn () ->
                    cnode_call_group_leader_init(callerPid)
               end)
  end

end