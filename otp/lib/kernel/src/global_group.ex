defmodule :m_global_group do
  use Bitwise
  import Kernel, except: [send: 2]
  @behaviour :gen_server
  require Record

  Record.defrecord(:r_state, :state,
    sync_state: :no_conf,
    group_name: [],
    nodes: %{},
    other_grps: [],
    monitor: [],
    group_publish_type: :normal,
    connections: :undefined,
    erpc_requests: :undefined,
    config_check: :undefined
  )

  Record.defrecord(:r_gconf, :gconf,
    parameter_value: :invalid,
    node_name: :undefined,
    group_name: [],
    group_publish_type: :normal,
    group_list: [],
    group_map: :all,
    other_groups: [],
    state: :no_conf
  )

  def global_groups() do
    request(:global_groups)
  end

  def monitor_nodes(flag) do
    case flag do
      true ->
        request({:monitor_nodes, flag})

      false ->
        request({:monitor_nodes, flag})

      _ ->
        {:error, :not_boolean}
    end
  end

  def own_nodes() do
    request(:own_nodes)
  end

  def registered_names(arg) do
    request({:registered_names, arg})
  end

  def send(name, msg) do
    request({:send, name, msg})
  end

  def send(group, name, msg) do
    request({:send, group, name, msg})
  end

  def whereis_name(name) do
    request({:whereis_name, name})
  end

  def whereis_name(group, name) do
    request({:whereis_name, group, name})
  end

  def global_groups_changed(newPara) do
    request({:global_groups_changed, newPara})
  end

  def global_groups_added(newPara) do
    request({:global_groups_added, newPara})
  end

  def global_groups_removed(newPara) do
    request({:global_groups_removed, newPara})
  end

  def sync() do
    request(:sync)
  end

  def info() do
    request(:info, 3000)
  end

  def ng_add_check(node, othersNG) do
    ng_add_check(node, :normal, othersNG)
  end

  def ng_add_check(node, pubType, othersNG) do
    request({:ng_add_check, node, pubType, othersNG})
  end

  def registered_names_test(arg) do
    request({:registered_names_test, arg})
  end

  def send_test(name, msg) do
    request({:send_test, name, msg})
  end

  def whereis_name_test(name) do
    request({:whereis_name_test, name})
  end

  defp request(req) do
    request(req, :infinity)
  end

  defp request(req, time) do
    case :erlang.whereis(:global_group) do
      p when is_pid(p) ->
        :gen_server.call(:global_group, req, time)

      _Other ->
        {:error, :global_group_not_runnig}
    end
  end

  def start() do
    :gen_server.start({:local, :global_group}, :global_group, [], [])
  end

  def start_link() do
    :gen_server.start_link({:local, :global_group}, :global_group, [], [])
  end

  def stop() do
    :gen_server.call(:global_group, :stop, :infinity)
  end

  def init([]) do
    _ = :erlang.process_flag(:async_dist, true)
    :erlang.process_flag(:priority, :max)

    :ok =
      :net_kernel.monitor_nodes(
        true,
        %{connection_id: true}
      )

    :erlang.put(:registered_names, [:undefined])
    :erlang.put(:send, [:undefined])
    :erlang.put(:whereis_name, [:undefined])
    :erlang.process_flag(:trap_exit, true)
    gGC = spawn_link(&global_group_check_dispatcher/0)
    :erlang.register(:global_group_check, gGC)
    :erlang.put(:global_group_check, gGC)

    conns =
      :lists.foldl(
        fn {n, %{connection_id: cId}}, cs ->
          Map.put(cs, n, cId)
        end,
        %{},
        nodes(:visible, %{connection_id: true})
      )

    s =
      initial_group_setup(
        fetch_new_group_conf(
          true,
          node()
        ),
        conns,
        :erpc.reqids_new()
      )

    {:ok, s}
  end

  defp initial_group_setup(r_gconf(state: :no_conf), conns, reqs) do
    r_state(connections: conns, erpc_requests: reqs)
  end

  defp initial_group_setup(r_gconf(state: {:error, _Err, nodeGrps}), _Conns, _Reqs) do
    exit({:error, {:"invalid global_groups definition", nodeGrps}})
  end

  defp initial_group_setup(
         r_gconf(
           node_name: nodeName,
           group_name: defGroupName,
           group_list: defNodesT,
           group_publish_type: pubTpGrp,
           other_groups: defOther
         ),
         conns,
         reqs
       ) do
    defNodes = :lists.delete(nodeName, defNodesT)
    connectedNodes = :maps.keys(conns)
    disconnectNodes = connectedNodes -- defNodes
    notConnectedOwnNodes = defNodes -- connectedNodes
    connectedOwnNodes = defNodes -- notConnectedOwnNodes
    disconnect_nodes(disconnectNodes, conns)
    newReqs = schedule_conf_changed_checks(defNodes, reqs, conns)

    nodes0 =
      :lists.foldl(
        fn node, acc ->
          Map.put(acc, node, :sync_error)
        end,
        %{},
        connectedOwnNodes
      )

    nodes =
      :lists.foldl(
        fn node, acc ->
          Map.put(acc, node, :no_contact)
        end,
        nodes0,
        notConnectedOwnNodes
      )

    r_state(
      group_publish_type: pubTpGrp,
      sync_state: :synced,
      group_name: defGroupName,
      nodes: nodes,
      other_grps: defOther,
      connections: conns,
      erpc_requests: newReqs
    )
  end

  def handle_call(:sync, _From, r_state(nodes: oldNodes, connections: conns) = s) do
    case lookup_group_conf(true) do
      r_gconf(
        state: :no_conf,
        group_name: defGroupName,
        group_list: _DefNodesT,
        group_publish_type: pubTpGrp,
        other_groups: defOther
      ) ->
        {:reply, :ok,
         r_state(s,
           sync_state: :no_conf,
           group_name: defGroupName,
           nodes: %{},
           group_publish_type: pubTpGrp,
           other_grps: defOther
         )}

      r_gconf(state: {:error, _Err, nodeGrps}) ->
        exit({:error, {:"invalid global_groups definition", nodeGrps}})

      r_gconf(
        group_name: defGroupName,
        group_list: defNodesT,
        group_publish_type: pubTpGrp,
        other_groups: defOther
      ) ->
        defNodes = :lists.delete(node(), defNodesT)
        disconnect_nodes(:erlang.nodes() -- defNodes, conns)
        syncSession = make_ref()

        cCMsg =
          {:conf_check, 3, node(), {self(), syncSession}, :sync, defGroupName, pubTpGrp,
           defNodesT}

        {newNodes, mons} =
          :lists.foldl(
            fn n, {nacc, macc} ->
              gG = {:global_group, n}
              m = :erlang.monitor(:process, gG)
              :gen_server.cast(gG, cCMsg)
              nS = :maps.get(n, oldNodes, :no_contact)
              {Map.put(nacc, n, nS), Map.put(macc, n, m)}
            end,
            {%{}, %{}},
            defNodes
          )

        {:reply, :ok,
         r_state(s,
           sync_state: :synced,
           group_name: defGroupName,
           nodes: newNodes,
           other_grps: defOther,
           group_publish_type: pubTpGrp,
           config_check: {syncSession, mons}
         )}
    end
  end

  def handle_call(:global_groups, _From, s) do
    result =
      case r_state(s, :sync_state) do
        :no_conf ->
          :undefined

        :synced ->
          other =
            :lists.foldl(
              fn {n, _L}, acc ->
                acc ++ [n]
              end,
              [],
              r_state(s, :other_grps)
            )

          {r_state(s, :group_name), other}
      end

    {:reply, result, s}
  end

  def handle_call({:monitor_nodes, flag}, {pid, _}, stateIn) do
    {res, state} = monitor_nodes(flag, pid, stateIn)
    {:reply, res, state}
  end

  def handle_call(:own_nodes, _From, s) do
    nodes =
      case r_state(s, :sync_state) do
        :no_conf ->
          [node() | :erlang.nodes()]

        :synced ->
          get_own_nodes(true)
      end

    {:reply, nodes, s}
  end

  def handle_call({:registered_names, {:group, group}}, _From, s)
      when group === r_state(s, :group_name) do
    res = :global.registered_names()
    {:reply, res, s}
  end

  def handle_call({:registered_names, {:group, group}}, from, s) do
    case :lists.keysearch(group, 1, r_state(s, :other_grps)) do
      false ->
        {:reply, [], s}

      {:value, {^group, []}} ->
        {:reply, [], s}

      {:value, {^group, nodes}} ->
        pid =
          :global_search.start(
            :names,
            {:group, nodes, from}
          )

        wait = :erlang.get(:registered_names)
        :erlang.put(:registered_names, [{pid, from} | wait])
        {:noreply, s}
    end
  end

  def handle_call({:registered_names, {:node, node}}, _From, s)
      when node === node() do
    res = :global.registered_names()
    {:reply, res, s}
  end

  def handle_call({:registered_names, {:node, node}}, from, s) do
    pid = :global_search.start(:names, {:node, node, from})
    wait = :erlang.get(:registered_names)
    :erlang.put(:registered_names, [{pid, from} | wait])
    {:noreply, s}
  end

  def handle_call({:send, name, msg}, from, s) do
    case :global.whereis_name(name) do
      :undefined ->
        pid =
          :global_search.start(
            :send,
            {:any, r_state(s, :other_grps), name, msg, from}
          )

        wait = :erlang.get(:send)
        :erlang.put(:send, [{pid, from, name, msg} | wait])
        {:noreply, s}

      found ->
        send(found, msg)
        {:reply, found, s}
    end
  end

  def handle_call({:send, {:group, grp}, name, msg}, _From, s)
      when grp === r_state(s, :group_name) do
    case :global.whereis_name(name) do
      :undefined ->
        {:reply, {:badarg, {name, msg}}, s}

      pid ->
        send(pid, msg)
        {:reply, pid, s}
    end
  end

  def handle_call({:send, {:group, group}, name, msg}, from, s) do
    case :lists.keysearch(group, 1, r_state(s, :other_grps)) do
      false ->
        {:reply, {:badarg, {name, msg}}, s}

      {:value, {^group, []}} ->
        {:reply, {:badarg, {name, msg}}, s}

      {:value, {^group, nodes}} ->
        pid =
          :global_search.start(
            :send,
            {:group, nodes, name, msg, from}
          )

        wait = :erlang.get(:send)
        :erlang.put(:send, [{pid, from, name, msg} | wait])
        {:noreply, s}
    end
  end

  def handle_call({:send, {:node, node}, name, msg}, from, s) do
    pid =
      :global_search.start(
        :send,
        {:node, node, name, msg, from}
      )

    wait = :erlang.get(:send)
    :erlang.put(:send, [{pid, from, name, msg} | wait])
    {:noreply, s}
  end

  def handle_call({:whereis_name, name}, from, s) do
    case :global.whereis_name(name) do
      :undefined ->
        pid =
          :global_search.start(
            :whereis,
            {:any, r_state(s, :other_grps), name, from}
          )

        wait = :erlang.get(:whereis_name)
        :erlang.put(:whereis_name, [{pid, from} | wait])
        {:noreply, s}

      found ->
        {:reply, found, s}
    end
  end

  def handle_call({:whereis_name, {:group, group}, name}, _From, s)
      when group === r_state(s, :group_name) do
    res = :global.whereis_name(name)
    {:reply, res, s}
  end

  def handle_call({:whereis_name, {:group, group}, name}, from, s) do
    case :lists.keysearch(group, 1, r_state(s, :other_grps)) do
      false ->
        {:reply, :undefined, s}

      {:value, {^group, []}} ->
        {:reply, :undefined, s}

      {:value, {^group, nodes}} ->
        pid =
          :global_search.start(
            :whereis,
            {:group, nodes, name, from}
          )

        wait = :erlang.get(:whereis_name)
        :erlang.put(:whereis_name, [{pid, from} | wait])
        {:noreply, s}
    end
  end

  def handle_call({:whereis_name, {:node, node}, name}, from, s) do
    pid =
      :global_search.start(
        :whereis,
        {:node, node, name, from}
      )

    wait = :erlang.get(:whereis_name)
    :erlang.put(:whereis_name, [{pid, from} | wait])
    {:noreply, s}
  end

  def handle_call(
        {:global_groups_changed, newPara},
        _From,
        r_state(erpc_requests: reqs, nodes: oldNodes, connections: conns) = s
      ) do
    r_gconf(
      group_name: newGroupName,
      group_publish_type: pubTpGrp,
      group_list: newNodesListT,
      other_groups: newOther,
      state: gState
    ) = new_group_conf(true, newPara)

    case gState do
      :no_conf ->
        exit({:error, :"no global_groups definiton"})

      {:error, _Err, nodeGrps} ->
        exit({:error, {:"invalid global_groups definition", nodeGrps}})

      _ ->
        :ok
    end

    newNodesList = :lists.delete(node(), newNodesListT)

    force_nodedown(
      :erlang.nodes(:connected) -- newNodesList,
      conns
    )

    newNodes =
      :lists.foldl(
        fn n, nacc ->
          nS = :maps.get(n, oldNodes, :no_contact)
          Map.put(nacc, n, nS)
        end,
        %{},
        newNodesList
      )

    newReqs = schedule_conf_changed_checks(newNodesList, reqs, conns)

    newS =
      r_state(s,
        group_name: newGroupName,
        nodes: newNodes,
        other_grps: newOther,
        group_publish_type: pubTpGrp,
        erpc_requests: newReqs,
        config_check: :undefined
      )

    {:reply, :ok, newS}
  end

  def handle_call(
        {:global_groups_added, newPara},
        _From,
        r_state(connections: conns, erpc_requests: reqs) = s
      ) do
    r_gconf(
      group_name: newGroupName,
      group_publish_type: pubTpGrp,
      group_list: newNodesList,
      other_groups: newOther,
      state: gState
    ) = new_group_conf(true, newPara)

    case gState do
      :no_conf ->
        exit({:error, :"no global_groups definiton"})

      {:error, _Err, nodeGrps} ->
        exit({:error, {:"invalid global_groups definition", nodeGrps}})

      _ ->
        :ok
    end

    force_nodedown(
      :erlang.nodes(:connected) -- newNodesList,
      conns
    )

    nGACArgs = [node(), pubTpGrp, newNodesList]

    {newReqs, newNodes} =
      :lists.foldl(
        fn n, {racc, nacc} ->
          cId = :maps.get(n, conns, :not_connected)

          nRacc =
            :erpc.send_request(
              n,
              :global_group,
              :ng_add_check,
              nGACArgs,
              {:ng_add_check, n, cId},
              racc
            )

          what =
            cond do
              cId == :not_connected ->
                :no_contact

              true ->
                :sync_error
            end

          {nRacc, Map.put(nacc, n, what)}
        end,
        {reqs, %{}},
        :lists.delete(node(), newNodesList)
      )

    newS =
      r_state(s,
        sync_state: :synced,
        group_name: newGroupName,
        nodes: newNodes,
        erpc_requests: newReqs,
        other_grps: newOther,
        group_publish_type: pubTpGrp,
        config_check: :undefined
      )

    {:reply, :ok, newS}
  end

  def handle_call({:global_groups_removed, _NewPara}, _From, s) do
    r_gconf(
      group_name: newGroupName,
      group_publish_type: pubTpGrp,
      group_list: _NewNodes,
      other_groups: newOther,
      state: :no_conf
    ) = new_group_conf(true, :undefined)

    newS =
      r_state(s,
        sync_state: :no_conf,
        group_name: newGroupName,
        nodes: %{},
        other_grps: newOther,
        group_publish_type: pubTpGrp,
        config_check: :undefined
      )

    {:reply, :ok, newS}
  end

  def handle_call(
        {:ng_add_check, node, pubType, othersNG},
        _From,
        r_state(group_publish_type: ownPubType) = s
      ) do
    ownNodes = get_own_nodes(true)

    case {pubType, :lists.sort(othersNG)} do
      {^ownPubType, ^ownNodes} ->
        {:reply, :agreed, node_state(:sync, node, s)}

      _ ->
        {:reply, :not_agreed, node_state(:sync_error, node, s)}
    end
  end

  def handle_call(:info, _From, s) do
    {inSync, syncError, noContact} =
      :maps.fold(
        fn
          n, :sync, {iSacc, sEacc, nCacc} ->
            {[n | iSacc], sEacc, nCacc}

          n, :sync_error, {iSacc, sEacc, nCacc} ->
            {iSacc, [n | sEacc], nCacc}

          n, :no_contact, {iSacc, sEacc, nCacc} ->
            {iSacc, sEacc, [n | nCacc]}
        end,
        {[], [], []},
        r_state(s, :nodes)
      )

    reply = [
      {:state, r_state(s, :sync_state)},
      {:own_group_name, r_state(s, :group_name)},
      {:own_group_nodes, get_own_nodes(true)},
      {:synced_nodes, :lists.sort(inSync)},
      {:sync_error, :lists.sort(syncError)},
      {:no_contact, :lists.sort(noContact)},
      {:other_groups, r_state(s, :other_grps)},
      {:monitoring, r_state(s, :monitor)}
    ]

    {:reply, reply, s}
  end

  def handle_call(:get, _From, s) do
    {:reply, :erlang.get(), s}
  end

  def handle_call({:registered_names_test, {:node, :test3844zty}}, from, s) do
    pid =
      :global_search.start(
        :names_test,
        {:node, :test3844zty}
      )

    wait = :erlang.get(:registered_names)
    :erlang.put(:registered_names, [{pid, from} | wait])
    {:noreply, s}
  end

  def handle_call({:registered_names_test, {:node, _Node}}, _From, s) do
    {:reply, {:error, :illegal_function_call}, s}
  end

  def handle_call({:send_test, name, :test3844zty}, from, s) do
    pid = :global_search.start(:send_test, :test3844zty)
    wait = :erlang.get(:send)

    :erlang.put(
      :send,
      [{pid, from, name, :test3844zty} | wait]
    )

    {:noreply, s}
  end

  def handle_call({:send_test, _Name, _Msg}, _From, s) do
    {:reply, {:error, :illegal_function_call}, s}
  end

  def handle_call({:whereis_name_test, :test3844zty}, from, s) do
    pid = :global_search.start(:whereis_test, :test3844zty)
    wait = :erlang.get(:whereis_name)
    :erlang.put(:whereis_name, [{pid, from} | wait])
    {:noreply, s}
  end

  def handle_call({:whereis_name_test, _Name}, _From, s) do
    {:reply, {:error, :illegal_function_call}, s}
  end

  def handle_call(call, _From, s) do
    {:reply, {:illegal_message, call}, s}
  end

  def handle_cast({:registered_names, user}, s) do
    res = :global.registered_names()
    send(user, {:registered_names_res, res})
    {:noreply, s}
  end

  def handle_cast({:registered_names_res, result, pid, from}, s) do
    :erlang.unlink(pid)
    send(pid, :kill)
    wait = :erlang.get(:registered_names)
    newWait = :lists.delete({pid, from}, wait)
    :erlang.put(:registered_names, newWait)
    :gen_server.reply(from, result)
    {:noreply, s}
  end

  def handle_cast({:send_res, result, name, msg, pid, from}, s) do
    case result do
      {:badarg, {^name, ^msg}} ->
        :continue

      toPid ->
        send(toPid, msg)
    end

    :erlang.unlink(pid)
    send(pid, :kill)
    wait = :erlang.get(:send)
    newWait = :lists.delete({pid, from, name, msg}, wait)
    :erlang.put(:send, newWait)
    :gen_server.reply(from, result)
    {:noreply, s}
  end

  def handle_cast({:find_name, user, name}, s) do
    res = :global.whereis_name(name)
    send(user, {:find_name_res, res})
    {:noreply, s}
  end

  def handle_cast({:find_name_res, result, pid, from}, s) do
    :erlang.unlink(pid)
    send(pid, :kill)
    wait = :erlang.get(:whereis_name)
    newWait = :lists.delete({pid, from}, wait)
    :erlang.put(:whereis_name, newWait)
    :gen_server.reply(from, result)
    {:noreply, s}
  end

  def handle_cast(
        {:conf_check, vsn, node, from, :sync, cCName, cCNodes},
        s
      ) do
    handle_cast(
      {:conf_check, vsn, node, from, :sync, cCName, :normal, cCNodes},
      s
    )
  end

  def handle_cast(
        {:conf_check, vsn, node, from, :sync, cCName, pubType, cCNodes},
        r_state(connections: conns) = s
      ) do
    try do
      cId =
        case :maps.get(node, conns, :undefined) do
          :undefined ->
            throw({:noreply, s})

          cId0 ->
            cId0
        end

      to =
        cond do
          is_integer(vsn) and vsn >= 3 ->
            case from do
              {pid, _Session} when is_pid(pid) ->
                pid

              _Garbage ->
                throw({:noreply, s})
            end

          true ->
            {:global_group_check, node}
        end

      case lookup_group_conf(true) do
        r_gconf(state: :no_conf) ->
          disconnect_nodes([node], conns)
          send(to, {:config_error, vsn, from, node()})
          {:noreply, s}

        r_gconf(state: {:error, _Err, _NodeGrps}) ->
          disconnect_nodes([node], conns)
          send(to, {:config_error, vsn, from, node()})
          {:noreply, node_state(:remove, node, s)}

        r_gconf(group_name: ^cCName, group_list: ^cCNodes, group_publish_type: ^pubType) ->
          send(:global_name_server, {:group_nodeup, node, cId})
          send(to, {:config_ok, vsn, from, node()})
          {:noreply, node_state(:sync, node, s)}

        r_gconf() ->
          disconnect_nodes([node], conns)
          send(to, {:config_error, vsn, from, node()})
          {:noreply, node_state(:sync_error, node, s)}
      end
    catch
      {:noreply, _} = return ->
        return
    end
  end

  def handle_cast(_Cast, s) do
    {:noreply, s}
  end

  def handle_info(msg, r_state(erpc_requests: requests) = s) do
    try do
      :erpc.check_response(msg, requests, true)
    catch
      class, {reason, label, newRequests} ->
        {:noreply,
         handle_erpc_response(class, reason, label, r_state(s, erpc_requests: newRequests))}
    else
      noMatch
      when noMatch == :no_request or
             noMatch == :no_response ->
        continue_handle_info(msg, s)

      {{:response, result}, label, newRequests} ->
        {:noreply,
         handle_erpc_response(:ok, result, label, r_state(s, erpc_requests: newRequests))}
    end
  end

  defp continue_handle_info(
         {:nodeup, node, %{connection_id: :undefined}},
         r_state(connections: conns, erpc_requests: reqs)
       ) do
    s = initial_group_setup(alive_state_change_group_conf(node), conns, reqs)
    send_monitor(r_state(s, :monitor), {:nodeup, node}, r_state(s, :sync_state))
    {:noreply, s}
  end

  defp continue_handle_info(
         {:nodeup, node, %{connection_id: cId}},
         r_state(sync_state: :no_conf, connections: conns) = s
       ) do
    send_monitor(r_state(s, :monitor), {:nodeup, node}, r_state(s, :sync_state))
    {:noreply, r_state(s, connections: Map.put(conns, node, cId))}
  end

  defp continue_handle_info(
         {:nodeup, node, %{connection_id: cId}},
         r_state(erpc_requests: reqs, connections: conns) = s
       ) do
    newConns = Map.put(conns, node, cId)

    case member(true, node) do
      false ->
        disconnect_nodes([node], newConns)
        {:noreply, r_state(s, connections: newConns)}

      true ->
        newReqs =
          :erpc.send_request(
            node,
            :global_group,
            :get_own_nodes,
            [],
            {:nodeup_conf_check, node, cId},
            reqs
          )

        {:noreply,
         node_state(:sync_error, node, r_state(s, erpc_requests: newReqs, connections: newConns))}
    end
  end

  defp continue_handle_info(
         {:nodedown, node, %{connection_id: :undefined}},
         s
       ) do
    r_gconf(
      state: :no_conf,
      group_name: defGroupName,
      group_list: _DefNodes,
      group_publish_type: pubTpGrp,
      other_groups: defOther
    ) = alive_state_change_group_conf(:nonode@nohost)

    send_monitor(r_state(s, :monitor), {:nodedown, node}, :no_conf)

    {:noreply,
     r_state(s,
       group_publish_type: pubTpGrp,
       sync_state: :no_conf,
       group_name: defGroupName,
       nodes: %{},
       other_grps: defOther,
       config_check: :undefined
     )}
  end

  defp continue_handle_info(
         {:nodedown, node, _Info},
         r_state(sync_state: :no_conf, monitor: monitor, connections: conns) = s
       ) do
    send_monitor(monitor, {:nodedown, node}, :no_conf)
    {:noreply, r_state(s, connections: :maps.remove(node, conns))}
  end

  defp continue_handle_info(
         {:nodedown, node, _Info},
         r_state(sync_state: syncState, monitor: monitor, connections: conns) = s
       ) do
    send_monitor(monitor, {:nodedown, node}, syncState)
    {:noreply, node_state(:no_contact, node, r_state(s, connections: :maps.remove(node, conns)))}
  end

  defp continue_handle_info(
         {:disconnect_node, node},
         r_state(monitor: monitor, sync_state: syncState, nodes: nodes, connections: conns) = s
       ) do
    case {syncState, :maps.get(node, nodes, :not_member)} do
      {:synced, :sync} ->
        send_monitor(monitor, {:nodedown, node}, syncState)

      _ ->
        :ok
    end

    cId = :maps.get(node, conns, :not_connected)
    send(:global_name_server, {:group_nodedown, node, cId})
    {:noreply, node_state(:sync_error, node, s)}
  end

  defp continue_handle_info(
         {:config_ok, 3, {pid, cCSession}, node},
         r_state(
           config_check: {cCSession, mons},
           connections: conns
         ) = s0
       )
       when pid == self() do
    try do
      {mon, newMons} =
        case :maps.take(node, mons) do
          :error ->
            throw({:noreply, s0})

          monTake ->
            monTake
        end

      :erlang.demonitor(mon)

      s1 =
        cond do
          map_size(newMons) == 0 ->
            r_state(s0, config_check: :undefined)

          true ->
            r_state(s0, config_check: {cCSession, newMons})
        end

      cId =
        case :maps.get(node, conns, :undefined) do
          :undefined ->
            throw({:noreply, s1})

          cId0 ->
            cId0
        end

      send(:global_name_server, {:group_nodeup, node, cId})
      {:noreply, node_state(:sync, node, s0)}
    catch
      {:noreply, _} = return ->
        return
    end
  end

  defp continue_handle_info(
         {:config_error, 3, {pid, cCSession}, node},
         r_state(
           config_check: {cCSession, mons},
           connections: conns
         ) = s0
       )
       when pid == self() do
    try do
      {mon, newMons} =
        case :maps.take(node, mons) do
          :error ->
            throw({:noreply, s0})

          monTake ->
            monTake
        end

      :erlang.demonitor(mon)

      s1 =
        cond do
          map_size(newMons) == 0 ->
            r_state(s0, config_check: :undefined)

          true ->
            r_state(s0, config_check: {cCSession, newMons})
        end

      cId = :maps.get(node, conns, :not_connected)
      send(:global_name_server, {:group_nodedown, node, cId})
      log_sync_error(node)
      {:noreply, node_state(:sync_error, node, s1)}
    catch
      {:noreply, _} = return ->
        return
    end
  end

  defp continue_handle_info(
         {:DOWN, mon, :process, {:global_group, node}, reason},
         r_state(
           config_check: {cCSession, mons},
           connections: conns
         ) = s0
       ) do
    try do
      newMons =
        case :maps.take(node, mons) do
          {^mon, newMons0} ->
            newMons0

          _ ->
            throw({:noreply, s0})
        end

      s1 =
        cond do
          map_size(newMons) == 0 ->
            r_state(s0, config_check: :undefined)

          true ->
            r_state(s0, config_check: {cCSession, newMons})
        end

      cId = :maps.get(node, conns, :not_connected)
      send(:global_name_server, {:group_nodedown, node, cId})

      what =
        cond do
          reason == :noconnection ->
            :no_contact

          true ->
            log_sync_error(node)
            :sync_error
        end

      {:noreply, node_state(what, node, s1)}
    catch
      {:noreply, _} = return ->
        return
    end
  end

  defp continue_handle_info({:EXIT, exitPid, reason}, s) do
    check_exit(exitPid, reason)
    {:noreply, s}
  end

  defp continue_handle_info(_Info, s) do
    {:noreply, s}
  end

  def terminate(_Reason, _S) do
    :ok
  end

  def code_change(_OldVsn, state, _Extra) do
    {:ok, state}
  end

  defp log_sync_error(node) do
    txt =
      :io_lib.format(
        ~c"global_group: Could not synchronize with node ~p~nbecause global_groups parameter were not in agreement.~n",
        [node]
      )

    :error_logger.error_report(txt)
    :ok
  end

  defp schedule_conf_changed_checks(nodes, requests, connections) do
    :lists.foldl(
      fn node, requestsAcc ->
        cId = :maps.get(node, connections, :not_connected)

        :erpc.send_request(
          node,
          :global_group,
          :get_own_nodes,
          [],
          {:conf_changed_check, node, cId},
          requestsAcc
        )
      end,
      requests,
      nodes
    )
  end

  defp handle_erpc_response(
         :ok,
         nodes,
         {:nodeup_conf_check, node, reqCId},
         r_state(connections: conns) = s
       )
       when is_list(nodes) do
    case :maps.get(node, conns, :undefined) do
      cId
      when reqCId == cId or (reqCId == :not_connected and is_integer(cId)) ->
        ownNodes = get_own_nodes(true)

        case :lists.sort(nodes) do
          ^ownNodes ->
            send_monitor(r_state(s, :monitor), {:nodeup, node}, r_state(s, :sync_state))
            send(:global_name_server, {:group_nodeup, node, cId})
            node_state(:sync, node, s)

          _ ->
            disconnect_nodes([node], conns)
            node_state(:sync_error, node, s)
        end

      _ ->
        s
    end
  end

  defp handle_erpc_response(
         :error,
         {:erpc, :noconnection},
         {:nodeup_conf_check, node, reqCId},
         r_state(connections: conns) = s
       ) do
    case :maps.get(node, conns, :undefined) do
      cId
      when reqCId == cId or (reqCId == :not_connected and is_integer(cId)) ->
        node_state(:no_contact, node, s)

      _ ->
        s
    end
  end

  defp handle_erpc_response(
         _,
         _,
         {:nodeup_conf_check, node, reqCId},
         r_state(connections: conns) = s
       ) do
    case :maps.get(node, conns, :undefined) do
      cId
      when reqCId == cId or (reqCId == :not_connected and is_integer(cId)) ->
        disconnect_nodes([node], conns)
        node_state(:sync_error, node, s)

      _ ->
        s
    end
  end

  defp handle_erpc_response(
         :ok,
         nodes,
         {:conf_changed_check, node, reqCId},
         r_state(connections: conns) = s
       )
       when is_list(nodes) do
    case :maps.get(node, conns, :undefined) do
      cId
      when reqCId == cId or (reqCId == :not_connected and is_integer(cId)) ->
        ownNodes = get_own_nodes(true)

        case :lists.sort(nodes) do
          ^ownNodes ->
            node_state(:sync, node, s)

          _ ->
            disconnect_nodes([node], conns)
            node_state(:sync_error, node, s)
        end

      _ ->
        s
    end
  end

  defp handle_erpc_response(
         :error,
         {:erpc, :noconnection},
         {:conf_changed_check, node, reqCId},
         r_state(connections: conns) = s
       ) do
    case :maps.get(node, conns, :undefined) do
      cId
      when reqCId == cId or (reqCId == :not_connected and is_integer(cId)) ->
        node_state(:no_contact, node, s)

      _ ->
        s
    end
  end

  defp handle_erpc_response(
         _,
         _,
         {:conf_changed_check, node, reqCId},
         r_state(connections: conns) = s
       ) do
    case :maps.get(node, conns, :undefined) do
      cId
      when reqCId == cId or (reqCId == :not_connected and is_integer(cId)) ->
        disconnect_nodes([node], conns)
        node_state(:sync_error, node, s)

      _ ->
        s
    end
  end

  defp handle_erpc_response(
         :ok,
         :agreed,
         {:ng_add_check, node, reqCId},
         r_state(connections: conns) = s
       ) do
    case :maps.get(node, conns, :undefined) do
      cId
      when reqCId == cId or (reqCId == :not_connected and is_integer(cId)) ->
        node_state(:sync, node, s)

      _ ->
        s
    end
  end

  defp handle_erpc_response(
         :error,
         {:erpc, :noconnection},
         {:ng_add_check, node, reqCId},
         r_state(connections: conns) = s
       ) do
    case :maps.get(node, conns, :undefined) do
      cId
      when reqCId == cId or (reqCId == :not_connected and is_integer(cId)) ->
        node_state(:no_contact, node, s)

      _ ->
        s
    end
  end

  defp handle_erpc_response(_, _, {:ng_add_check, node, reqCId}, r_state(connections: conns) = s) do
    case :maps.get(node, conns, :undefined) do
      cId
      when reqCId == cId or (reqCId == :not_connected and is_integer(cId)) ->
        disconnect_nodes([node], conns)
        node_state(:sync_error, node, s)

      _ ->
        s
    end
  end

  defp node_state(what, node, r_state(nodes: ns) = s)
       when what == :sync or what == :sync_error or
              what == :no_contact do
    case member(true, node) do
      true ->
        r_state(s, nodes: Map.put(ns, node, what))

      false ->
        r_state(s, nodes: :maps.remove(node, ns))
    end
  end

  defp node_state(:remove, node, r_state(nodes: ns) = s) do
    case member(true, node) do
      true ->
        :erlang.error({:removing_node_state_of_member_node, node})

      false ->
        r_state(s, nodes: :maps.remove(node, ns))
    end
  end

  defp config_scan(myNode, nodeGrps) do
    config_scan(myNode, :normal, nodeGrps, :no_name, [], [])
  end

  defp config_scan(_MyNode, pubType, [], own_name, ownNodes, otherNodeGrps) do
    {own_name, pubType, :lists.sort(ownNodes), :lists.reverse(otherNodeGrps)}
  end

  defp config_scan(myNode, pubType, [grpTuple | nodeGrps], own_name, ownNodes, otherNodeGrps) do
    {name, pubTypeGroup, nodes} = grp_tuple(grpTuple)

    case :lists.member(myNode, nodes) do
      true ->
        case own_name do
          :no_name ->
            config_scan(myNode, pubTypeGroup, nodeGrps, name, nodes, otherNodeGrps)

          _ ->
            {:error, {:"node defined twice", {own_name, name}}}
        end

      false ->
        config_scan(myNode, pubType, nodeGrps, own_name, ownNodes, [{name, nodes} | otherNodeGrps])
    end
  end

  defp grp_tuple({name, nodes}) do
    {name, :normal, nodes}
  end

  defp grp_tuple({name, :hidden, nodes}) do
    {name, :hidden, nodes}
  end

  defp grp_tuple({name, :normal, nodes}) do
    {name, :normal, nodes}
  end

  defp fetch_new_group_conf(gG) do
    fetch_new_group_conf(gG, :undefined)
  end

  defp fetch_new_group_conf(gG, nodeName) do
    gGConf =
      case :application.get_env(
             :kernel,
             :global_groups
           ) do
        :undefined ->
          :undefined

        {:ok, v} ->
          v
      end

    new_group_conf(gG, gGConf, nodeName)
  end

  defp new_group_conf(gG, kernParamValue) do
    new_group_conf(gG, kernParamValue, :undefined)
  end

  defp new_group_conf(gG, kernParamValue, nodeName) do
    case :persistent_term.get(:global_group, r_gconf()) do
      r_gconf(
        parameter_value: ^kernParamValue,
        node_name: name
      ) = gConf
      when nodeName == name or nodeName == :undefined ->
        gConf

      r_gconf(node_name: name) ->
        useNodeName =
          cond do
            nodeName == :undefined ->
              name

            true ->
              nodeName
          end

        gConf = make_group_conf(useNodeName, kernParamValue)

        cond do
          gG == true ->
            :persistent_term.put(:global_group, gConf)

          true ->
            :ok
        end

        gConf
    end
  end

  defp alive_state_change_group_conf(nodeName) when nodeName != :undefined do
    case :persistent_term.get(:global_group, r_gconf()) do
      r_gconf(parameter_value: paramValue)
      when paramValue != :invalid ->
        new_group_conf(true, paramValue, nodeName)

      r_gconf() ->
        fetch_new_group_conf(true, nodeName)
    end
  end

  defp lookup_group_conf(gG) do
    try do
      :persistent_term.get(:global_group)
    catch
      :error, :badarg ->
        fetch_new_group_conf(gG)
    end
  end

  defp global_group_check_dispatcher() do
    receive do
      {:config_ok, _Vsn, _From, _Node} = msg ->
        send(:global_group, msg)
        :ok

      {:config_error, _Vsn, _From, _Node} = msg ->
        send(:global_group, msg)
        :ok

      _Garbage ->
        :ok
    end

    global_group_check_dispatcher()
  end

  defp monitor_nodes(true, pid, state) do
    :erlang.link(pid)
    monitor = r_state(state, :monitor)
    {:ok, r_state(state, monitor: [pid | monitor])}
  end

  defp monitor_nodes(false, pid, state) do
    monitor = r_state(state, :monitor)
    state1 = r_state(state, monitor: delete_all(pid, monitor))
    do_unlink(pid, state1)
    {:ok, state1}
  end

  defp monitor_nodes(_, _, state) do
    {:error, state}
  end

  defp delete_all(from, [from | tail]) do
    delete_all(from, tail)
  end

  defp delete_all(from, [h | tail]) do
    [h | delete_all(from, tail)]
  end

  defp delete_all(_, []) do
    []
  end

  defp do_unlink(pid, state) do
    case :lists.member(pid, r_state(state, :monitor)) do
      true ->
        false

      _ ->
        :erlang.unlink(pid)
    end
  end

  defp send_monitor([p | t], m, :no_conf) do
    _ = safesend_nc(p, m)
    send_monitor(t, m, :no_conf)
  end

  defp send_monitor([p | t], m, syncState) do
    _ = safesend(p, m)
    send_monitor(t, m, syncState)
  end

  defp send_monitor([], _, _) do
    :ok
  end

  defp safesend(name, {msg, node}) when is_atom(name) do
    case member(true, node) do
      true ->
        case :erlang.whereis(name) do
          :undefined ->
            {msg, node}

          p when is_pid(p) ->
            send(p, {msg, node})
        end

      false ->
        :not_own_group
    end
  end

  defp safesend(pid, {msg, node}) do
    case member(true, node) do
      true ->
        send(pid, {msg, node})

      false ->
        :not_own_group
    end
  end

  defp safesend_nc(name, {msg, node}) when is_atom(name) do
    case :erlang.whereis(name) do
      :undefined ->
        {msg, node}

      p when is_pid(p) ->
        send(p, {msg, node})
    end
  end

  defp safesend_nc(pid, {msg, node}) do
    send(pid, {msg, node})
  end

  defp check_exit(exitPid, reason) do
    check_exit_reg(:erlang.get(:registered_names), exitPid, reason)
    check_exit_send(:erlang.get(:send), exitPid, reason)
    check_exit_where(:erlang.get(:whereis_name), exitPid, reason)
    check_exit_ggc(exitPid, reason)
  end

  defp check_exit_reg(:undefined, _ExitPid, _Reason) do
    :ok
  end

  defp check_exit_reg(reg, exitPid, reason) do
    case :lists.keysearch(exitPid, 1, :lists.delete(:undefined, reg)) do
      {:value, {^exitPid, from}} ->
        newReg = :lists.delete({exitPid, from}, reg)
        :erlang.put(:registered_names, newReg)
        :gen_server.reply(from, {:error, reason})

      false ->
        :not_found_ignored
    end
  end

  defp check_exit_send(:undefined, _ExitPid, _Reason) do
    :ok
  end

  defp check_exit_send(send, exitPid, _Reason) do
    case :lists.keysearch(exitPid, 1, :lists.delete(:undefined, send)) do
      {:value, {^exitPid, from, name, msg}} ->
        newSend =
          :lists.delete(
            {exitPid, from, name, msg},
            send
          )

        :erlang.put(:send, newSend)
        :gen_server.reply(from, {:badarg, {name, msg}})

      false ->
        :not_found_ignored
    end
  end

  defp check_exit_where(:undefined, _ExitPid, _Reason) do
    :ok
  end

  defp check_exit_where(where, exitPid, reason) do
    case :lists.keysearch(exitPid, 1, :lists.delete(:undefined, where)) do
      {:value, {^exitPid, from}} ->
        newWhere = :lists.delete({exitPid, from}, where)
        :erlang.put(:whereis_name, newWhere)
        :gen_server.reply(from, {:error, reason})

      false ->
        :not_found_ignored
    end
  end

  defp check_exit_ggc(exitPid, reason) do
    case :erlang.get(:global_group_check) do
      ^exitPid ->
        exit(reason)

      _ ->
        :ok
    end
  end

  defp disconnect_nodes(disconnectNodes, conns) do
    :lists.foreach(
      fn node ->
        cId = :maps.get(node, conns, :not_connected)
        send(:global_name_server, {:group_nodedown, node, cId})
        send({:global_group, node}, {:disconnect_node, node()})
      end,
      disconnectNodes
    )
  end

  defp force_nodedown(disconnectNodes, conns) do
    :lists.foreach(
      fn node ->
        cId = :maps.get(node, conns, :not_connected)
        send(:global_name_server, {:group_nodedown, node, cId})
        :erlang.disconnect_node(node)
      end,
      disconnectNodes
    )
  end

  def get_own_nodes_with_errors() do
    case lookup_group_conf(false) do
      r_gconf(state: {:error, error, _NodeGrps}) ->
        {:error, error}

      r_gconf(group_list: []) ->
        {:ok, :all}

      r_gconf(group_list: nodes) ->
        {:ok, nodes}
    end
  end

  def get_own_nodes() do
    get_own_nodes(false)
  end

  defp get_own_nodes(gG) when is_boolean(gG) do
    get_own_nodes(lookup_group_conf(gG))
  end

  defp get_own_nodes(r_gconf(group_list: nodes)) do
    nodes
  end

  def group_configured() do
    group_configured(lookup_group_conf(false))
  end

  defp group_configured(gConf) do
    case gConf do
      r_gconf(state: :no_conf) ->
        false

      r_gconf() ->
        true
    end
  end

  def participant(node) do
    case lookup_group_conf(false) do
      r_gconf(group_map: :all) ->
        true

      r_gconf(group_map: %{^node => :ok}) ->
        true

      r_gconf() ->
        false
    end
  end

  def member(node) do
    member(false, node)
  end

  defp member(gG, node) do
    case lookup_group_conf(gG) do
      r_gconf(group_map: %{^node => :ok}) ->
        true

      r_gconf() ->
        false
    end
  end

  def publish(ownPublishType, node)
      when (ownPublishType == :normal or ownPublishType == :hidden) and is_atom(node) do
    case lookup_group_conf(false) do
      r_gconf(group_map: :all) when ownPublishType == :normal ->
        true

      r_gconf(group_map: :all) when ownPublishType == :hidden ->
        false

      r_gconf(group_publish_type: :normal)
      when ownPublishType == :normal ->
        true

      r_gconf(group_map: %{^node => :ok}) ->
        true

      r_gconf() ->
        false
    end
  end
end
