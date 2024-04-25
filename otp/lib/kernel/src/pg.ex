defmodule :m_pg do
  use Bitwise
  def start_link() do
    start_link(:pg)
  end

  def start(scope) when is_atom(scope) do
    :gen_server.start({:local, scope}, :pg, [scope], [])
  end

  def start_link(scope) when is_atom(scope) do
    :gen_server.start_link({:local, scope}, :pg, [scope],
                             [])
  end

  def join(group, pidOrPids) do
    join(:pg, group, pidOrPids)
  end

  def join(scope, group, pidOrPids)
      when is_pid(pidOrPids) or is_list(pidOrPids) do
    :ok = ensure_local(pidOrPids)
    :gen_server.call(scope, {:join_local, group, pidOrPids},
                       :infinity)
  end

  def leave(group, pidOrPids) do
    leave(:pg, group, pidOrPids)
  end

  def leave(scope, group, pidOrPids)
      when is_pid(pidOrPids) or is_list(pidOrPids) do
    :ok = ensure_local(pidOrPids)
    :gen_server.call(scope,
                       {:leave_local, group, pidOrPids}, :infinity)
  end

  def monitor_scope() do
    monitor_scope(:pg)
  end

  def monitor_scope(scope) do
    :gen_server.call(scope, :monitor, :infinity)
  end

  def monitor(group) do
    :pg.monitor(:pg, group)
  end

  def monitor(scope, group) do
    :gen_server.call(scope, {:monitor, group}, :infinity)
  end

  def demonitor(ref) do
    :pg.demonitor(:pg, ref)
  end

  def demonitor(scope, ref) do
    :gen_server.call(scope, {:demonitor, ref},
                       :infinity) === :ok and flush(ref)
  end

  def get_members(group) do
    get_members(:pg, group)
  end

  def get_members(scope, group) do
    try do
      :ets.lookup_element(scope, group, 2, [])
    catch
      :error, :badarg ->
        []
    end
  end

  def get_local_members(group) do
    get_local_members(:pg, group)
  end

  def get_local_members(scope, group) do
    try do
      :ets.lookup_element(scope, group, 3, [])
    catch
      :error, :badarg ->
        []
    end
  end

  def which_groups() do
    which_groups(:pg)
  end

  def which_groups(scope) when is_atom(scope) do
    for [g] <- :ets.match(scope, {:"$1", :_, :_}) do
      g
    end
  end

  def which_local_groups() do
    which_local_groups(:pg)
  end

  def which_local_groups(scope) when is_atom(scope) do
    :ets.select(scope,
                  [{{:"$1", :_, :"$2"}, [{:"=/=", :"$2", []}], [:"$1"]}])
  end

  require Record
  Record.defrecord(:r_state, :state, scope: :undefined,
                                 local: %{}, remote: %{}, scope_monitors: %{},
                                 group_monitors: %{}, monitored_groups: %{})
  def init([scope]) do
    :ok = :net_kernel.monitor_nodes(true)
    broadcast(for node <- :erlang.nodes() do
                {scope, node}
              end,
                {:discover, self()})
    ^scope = :ets.new(scope,
                        [:set, :protected, :named_table, {:read_concurrency,
                                                            true}])
    {:ok, r_state(scope: scope)}
  end

  def handle_cast({:sync, peer, groups},
           r_state(scope: scope, remote: remote,
               scope_monitors: scopeMon,
               monitored_groups: mG) = state) do
    {:noreply,
       r_state(state, remote: handle_sync(scope, scopeMon, mG, peer,
                                      remote, groups))}
  end

  def handle_cast(_, _State) do
    :erlang.error(:badarg)
  end

  def handle_info({:join, peer, group, pidOrPids},
           r_state(scope: scope, remote: remote,
               scope_monitors: scopeMon,
               monitored_groups: mG) = state) do
    case (:maps.get(peer, remote, [])) do
      {mRef, remoteGroups} ->
        join_remote_update_ets(scope, scopeMon, mG, group,
                                 pidOrPids)
        newRemoteGroups = join_remote(group, pidOrPids,
                                        remoteGroups)
        {:noreply,
           r_state(state, remote: Map.put(remote, peer,
                                              {mRef, newRemoteGroups}))}
      [] ->
        {:noreply, state}
    end
  end

  def handle_info({:leave, peer, pidOrPids, groups},
           r_state(scope: scope, remote: remote,
               scope_monitors: scopeMon,
               monitored_groups: mG) = state) do
    case (:maps.get(peer, remote, [])) do
      {mRef, remoteMap} ->
        _ = leave_remote_update_ets(scope, scopeMon, mG,
                                      pidOrPids, groups)
        newRemoteMap = leave_remote(pidOrPids, remoteMap,
                                      groups)
        {:noreply,
           r_state(state, remote: Map.put(remote, peer,
                                              {mRef, newRemoteMap}))}
      [] ->
        {:noreply, state}
    end
  end

  def handle_info({:discover, peer}, state) do
    handle_discover(peer, state)
  end

  def handle_info({:discover, peer, _ProtocolVersion}, state) do
    handle_discover(peer, state)
  end

  def handle_info({:DOWN, mRef, :process, pid, _Info},
           r_state(scope: scope, local: local, remote: remote,
               scope_monitors: scopeMon, monitored_groups: mG) = state)
      when node(pid) === node() do
    case (:maps.take(pid, local)) do
      :error ->
        {:noreply, state}
      {{^mRef, groups}, newLocal} ->
        for group <- groups do
          leave_local_update_ets(scope, scopeMon, mG, group, pid)
        end
        broadcast(:maps.keys(remote),
                    {:leave, self(), pid, groups})
        {:noreply, r_state(state, local: newLocal)}
    end
  end

  def handle_info({:DOWN, mRef, :process, pid, _Info},
           r_state(scope: scope, remote: remote,
               scope_monitors: scopeMon,
               monitored_groups: mG) = state) do
    case (:maps.take(pid, remote)) do
      {{^mRef, remoteMap}, newRemote} ->
        :maps.foreach(fn group, pids ->
                           leave_remote_update_ets(scope, scopeMon, mG, pids,
                                                     [group])
                      end,
                        remoteMap)
        {:noreply, r_state(state, remote: newRemote)}
      :error ->
        {:noreply, state}
    end
  end

  def handle_info({{:DOWN, :scope_monitors}, mRef, :process, _Pid,
            _Info},
           r_state(scope_monitors: scopeMon) = state) do
    {:noreply,
       r_state(state, scope_monitors: :maps.remove(mRef, scopeMon))}
  end

  def handle_info({{:DOWN, :group_monitors}, mRef, :process, pid,
            _Info},
           r_state(group_monitors: gMs, monitored_groups: mG) = state) do
    case (:maps.take(mRef, gMs)) do
      :error ->
        {:noreply, state}
      {{^pid, group}, newGM} ->
        {:noreply,
           r_state(state, group_monitors: newGM, 
                      monitored_groups: demonitor_group({pid, mRef}, group,
                                                          mG))}
    end
  end

  def handle_info({:nodedown, _Node}, state) do
    {:noreply, state}
  end

  def handle_info({:nodeup, node}, state) when node === node() do
    {:noreply, state}
  end

  def handle_info({:nodeup, node}, r_state(scope: scope) = state) do
    :erlang.send({scope, node}, {:discover, self()},
                   [:noconnect])
    {:noreply, state}
  end

  def handle_info(_Info, _State) do
    :erlang.error(:badarg)
  end

  def terminate(_Reason, r_state(scope: scope)) do
    true = :ets.delete(scope)
  end

  defp handle_discover(peer,
            r_state(remote: remote, local: local) = state) do
    :gen_server.cast(peer,
                       {:sync, self(), all_local_pids(local)})
    case (:maps.is_key(peer, remote)) do
      true ->
        {:noreply, state}
      false ->
        mRef = :erlang.monitor(:process, peer)
        :erlang.send(peer, {:discover, self()}, [:noconnect])
        {:noreply,
           r_state(state, remote: Map.put(remote, peer, {mRef, %{}}))}
    end
  end

  defp handle_discover(_, _) do
    :erlang.error(:badarg)
  end

  defp ensure_local(pid) when (is_pid(pid) and
                       node(pid) === node()) do
    :ok
  end

  defp ensure_local(pids) when is_list(pids) do
    :lists.foreach(fn pid when (is_pid(pid) and
                                  node(pid) === node())
                               ->
                        :ok
                      bad ->
                        :erlang.error({:nolocal, bad})
                   end,
                     pids)
  end

  defp ensure_local(bad) do
    :erlang.error({:nolocal, bad})
  end

  defp handle_sync(scope, scopeMon, mG, peer, remote, groups) do
    {mRef, remoteGroups} = (case (:maps.find(peer,
                                               remote)) do
                              :error ->
                                {:erlang.monitor(:process, peer), %{}}
                              {:ok, mRef0} ->
                                mRef0
                            end)
    _ = sync_groups(scope, scopeMon, mG, remoteGroups,
                      groups)
    Map.put(remote, peer, {mRef, :maps.from_list(groups)})
  end

  defp sync_groups(scope, scopeMon, mG, remoteGroups, []) do
    for {group, pids} <- :maps.to_list(remoteGroups) do
      leave_remote_update_ets(scope, scopeMon, mG, pids,
                                [group])
    end
  end

  defp sync_groups(scope, scopeMon, mG, remoteGroups,
            [{group, pids} | tail]) do
    case (:maps.take(group, remoteGroups)) do
      {^pids, newRemoteGroups} ->
        sync_groups(scope, scopeMon, mG, newRemoteGroups, tail)
      {oldPids, newRemoteGroups} ->
        [{_Group, allOldPids, localPids}] = :ets.lookup(scope,
                                                          group)
        allNewPids = pids ++ allOldPids -- oldPids
        true = :ets.insert(scope,
                             {group, allNewPids, localPids})
        sync_groups(scope, scopeMon, mG, newRemoteGroups, tail)
      :error ->
        join_remote_update_ets(scope, scopeMon, mG, group, pids)
        sync_groups(scope, scopeMon, mG, remoteGroups, tail)
    end
  end

  defp join_local(pid, group, local) when is_pid(pid) do
    case (:maps.find(pid, local)) do
      {:ok, {mRef, groups}} ->
        :maps.put(pid, {mRef, [group | groups]}, local)
      :error ->
        mRef = :erlang.monitor(:process, pid)
        Map.put(local, pid, {mRef, [group]})
    end
  end

  defp join_local([], _Group, local) do
    local
  end

  defp join_local([pid | tail], group, local) do
    join_local(tail, group, join_local(pid, group, local))
  end

  defp join_local_update_ets(scope, scopeMon, mG, group, pid)
      when is_pid(pid) do
    case (:ets.lookup(scope, group)) do
      [{_Group, all, local}] ->
        :ets.insert(scope, {group, [pid | all], [pid | local]})
      [] ->
        :ets.insert(scope, {group, [pid], [pid]})
    end
    notify_group(scopeMon, mG, :join, group, [pid])
  end

  defp join_local_update_ets(scope, scopeMon, mG, group, pids) do
    case (:ets.lookup(scope, group)) do
      [{_Group, all, local}] ->
        :ets.insert(scope, {group, pids ++ all, pids ++ local})
      [] ->
        :ets.insert(scope, {group, pids, pids})
    end
    notify_group(scopeMon, mG, :join, group, pids)
  end

  defp join_remote_update_ets(scope, scopeMon, mG, group, pid)
      when is_pid(pid) do
    case (:ets.lookup(scope, group)) do
      [{_Group, all, local}] ->
        :ets.insert(scope, {group, [pid | all], local})
      [] ->
        :ets.insert(scope, {group, [pid], []})
    end
    notify_group(scopeMon, mG, :join, group, [pid])
  end

  defp join_remote_update_ets(scope, scopeMon, mG, group, pids) do
    case (:ets.lookup(scope, group)) do
      [{_Group, all, local}] ->
        :ets.insert(scope, {group, pids ++ all, local})
      [] ->
        :ets.insert(scope, {group, pids, []})
    end
    notify_group(scopeMon, mG, :join, group, pids)
  end

  defp join_remote(group, pid, remoteGroups) when is_pid(pid) do
    :maps.update_with(group,
                        fn list ->
                             [pid | list]
                        end,
                        [pid], remoteGroups)
  end

  defp join_remote(group, pids, remoteGroups) do
    :maps.update_with(group,
                        fn list ->
                             pids ++ list
                        end,
                        pids, remoteGroups)
  end

  defp leave_local(pid, group, local) when is_pid(pid) do
    case (:maps.find(pid, local)) do
      {:ok, {mRef, [^group]}} ->
        :erlang.demonitor(mRef)
        :maps.remove(pid, local)
      {:ok, {mRef, groups}} ->
        case (:lists.member(group, groups)) do
          true ->
            :maps.put(pid, {mRef, :lists.delete(group, groups)},
                        local)
          false ->
            local
        end
      _ ->
        local
    end
  end

  defp leave_local([], _Group, local) do
    local
  end

  defp leave_local([pid | tail], group, local) do
    leave_local(tail, group, leave_local(pid, group, local))
  end

  defp leave_local_update_ets(scope, scopeMon, mG, group, pid)
      when is_pid(pid) do
    case (:ets.lookup(scope, group)) do
      [{_Group, [^pid], [^pid]}] ->
        :ets.delete(scope, group)
        notify_group(scopeMon, mG, :leave, group, [pid])
      [{_Group, all, local}] ->
        :ets.insert(scope,
                      {group, :lists.delete(pid, all),
                         :lists.delete(pid, local)})
        notify_group(scopeMon, mG, :leave, group, [pid])
      [] ->
        true
    end
  end

  defp leave_local_update_ets(scope, scopeMon, mG, group, pids) do
    case (:ets.lookup(scope, group)) do
      [{_Group, all, local}] ->
        case (all -- pids) do
          [] ->
            :ets.delete(scope, group)
          newAll ->
            :ets.insert(scope, {group, newAll, local -- pids})
        end
        notify_group(scopeMon, mG, :leave, group, pids)
      [] ->
        true
    end
  end

  defp leave_remote_update_ets(scope, scopeMon, mG, pid, groups)
      when is_pid(pid) do
    _ = (for group <- groups do
           case (:ets.lookup(scope, group)) do
             [{_Group, [^pid], []}] ->
               :ets.delete(scope, group)
               notify_group(scopeMon, mG, :leave, group, [pid])
             [{_Group, all, local}] ->
               :ets.insert(scope,
                             {group, :lists.delete(pid, all), local})
               notify_group(scopeMon, mG, :leave, group, [pid])
             [] ->
               true
           end
         end)
  end

  defp leave_remote_update_ets(scope, scopeMon, mG, pids, groups) do
    _ = (for group <- groups do
           case (:ets.lookup(scope, group)) do
             [{_Group, all, local}] ->
               case (all -- pids) do
                 [] when local === [] ->
                   :ets.delete(scope, group)
                 newAll ->
                   :ets.insert(scope, {group, newAll, local})
               end
               notify_group(scopeMon, mG, :leave, group, pids)
             [] ->
               true
           end
         end)
  end

  defp leave_remote(pid, remoteMap, groups) when is_pid(pid) do
    leave_remote([pid], remoteMap, groups)
  end

  defp leave_remote(pids, remoteMap, groups) do
    :lists.foldl(fn group, acc ->
                      case (:maps.get(group, acc) -- pids) do
                        [] ->
                          :maps.remove(group, acc)
                        remaining ->
                          Map.put(acc, group, remaining)
                      end
                 end,
                   remoteMap, groups)
  end

  defp all_local_pids(local) do
    :maps.to_list(:maps.fold(fn pid, {_Ref, groups}, acc ->
                                  :lists.foldl(fn group, acc1 ->
                                                    Map.put(acc1, group,
                                                                    [pid |
                                                                         :maps.get(group,
                                                                                     acc1,
                                                                                     [])])
                                               end,
                                                 acc, groups)
                             end,
                               %{}, local))
  end

  defp broadcast([], _Msg) do
    :ok
  end

  defp broadcast([dest | tail], msg) do
    :erlang.send(dest, msg, [:noconnect])
    broadcast(tail, msg)
  end

  defp demonitor_group(tag, group, mG) do
    case (:maps.find(group, mG)) do
      {:ok, [^tag]} ->
        :maps.remove(group, mG)
      {:ok, tags} ->
        :maps.put(group, tags -- [tag], mG)
    end
  end

  defp notify_group(scopeMonitors, mG, action, group, pids) do
    :maps.foreach(fn ref, pid ->
                       :erlang.send(pid, {ref, action, group, pids},
                                      [:noconnect])
                  end,
                    scopeMonitors)
    case (:maps.find(group, mG)) do
      :error ->
        :ok
      {:ok, monitors} ->
        for {pid, ref} <- monitors do
          :erlang.send(pid, {ref, action, group, pids},
                         [:noconnect])
        end
        :ok
    end
  end

  defp flush(ref) do
    receive do
      {^ref, verb, _Group, _Pids} when verb === :join or
                                         verb === :leave
                                       ->
        flush(ref)
    after 0 ->
      :ok
    end
  end

end