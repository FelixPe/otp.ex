defmodule :m_global do
  use Bitwise
  import Kernel, except: [send: 2]
  @behaviour :gen_server
  require Record

  Record.defrecord(:r_conf, :conf,
    connect_all: :undefined,
    prevent_over_part: :undefined
  )

  Record.defrecord(:r_state, :state,
    conf: :EFE_TODO_NESTED_RECORD,
    known: %{},
    synced: [],
    resolvers: [],
    syncers: [],
    node_name: node(),
    the_locker: :undefined,
    the_registrar: :undefined,
    trace: :undefined,
    global_lock_down: false
  )

  def start() do
    :gen_server.start({:local, :global_name_server}, :global, [], [])
  end

  def start_link() do
    :gen_server.start_link({:local, :global_name_server}, :global, [], [])
  end

  def stop() do
    :gen_server.call(:global_name_server, :stop, :infinity)
  end

  def sync() do
    case check_sync_nodes() do
      {:error, _} = error ->
        error

      syncNodes ->
        :gen_server.call(:global_name_server, {:sync, syncNodes}, :infinity)
    end
  end

  def sync(nodes) do
    case check_sync_nodes(nodes) do
      {:error, _} = error ->
        error

      syncNodes ->
        :gen_server.call(:global_name_server, {:sync, syncNodes}, :infinity)
    end
  end

  def send(name, msg) do
    case whereis_name(name) do
      pid when is_pid(pid) ->
        send(pid, msg)
        pid

      :undefined ->
        exit({:badarg, {name, msg}})
    end
  end

  def whereis_name(name) do
    where(name)
  end

  def register_name(name, pid) when is_pid(pid) do
    register_name(name, pid, &random_exit_name/3)
  end

  def register_name(name, pid, method0) when is_pid(pid) do
    method = allow_tuple_fun(method0)

    fun = fn nodes ->
      case where(name) === :undefined and
             check_dupname(
               name,
               pid
             ) do
        true ->
          _ = :gen_server.multi_call(nodes, :global_name_server, {:register, name, pid, method})
          :yes

        _ ->
          :no
      end
    end

    :ok
    :gen_server.call(:global_name_server, {:registrar, fun}, :infinity)
  end

  defp check_dupname(name, pid) do
    case :ets.lookup(:global_pid_names, pid) do
      [] ->
        true

      pidNames ->
        case :application.get_env(
               :kernel,
               :global_multi_name_action
             ) do
          {:ok, :allow} ->
            true

          _ ->
            s = ~c"global: ~w registered under several names: ~tw\n"

            names = [
              name
              | for {_Pid, name1} <- pidNames do
                  name1
                end
            ]

            :logger.log(:error, s, [pid, names])
            false
        end
    end
  end

  def unregister_name(name) do
    case where(name) do
      :undefined ->
        :ok

      _ ->
        fun = fn nodes ->
          _ = :gen_server.multi_call(nodes, :global_name_server, {:unregister, name})
          :ok
        end

        :ok
        :gen_server.call(:global_name_server, {:registrar, fun}, :infinity)
    end
  end

  def re_register_name(name, pid) when is_pid(pid) do
    re_register_name(name, pid, &random_exit_name/3)
  end

  def re_register_name(name, pid, method0) when is_pid(pid) do
    method = allow_tuple_fun(method0)

    fun = fn nodes ->
      _ = :gen_server.multi_call(nodes, :global_name_server, {:register, name, pid, method})
      :yes
    end

    :ok
    :gen_server.call(:global_name_server, {:registrar, fun}, :infinity)
  end

  def registered_names() do
    mS =
      :ets.fun2ms(fn {name, _Pid, _M, _R} ->
        name
      end)

    :ets.select(:global_names, mS)
  end

  def register_name_external(name, pid) when is_pid(pid) do
    register_name_external(name, pid, &random_exit_name/3)
  end

  def register_name_external(name, pid, method) when is_pid(pid) do
    fun = fn nodes ->
      case where(name) do
        :undefined ->
          _ =
            :gen_server.multi_call(
              nodes,
              :global_name_server,
              {:register_ext, name, pid, method, node()}
            )

          :yes

        _Pid ->
          :no
      end
    end

    :ok
    :gen_server.call(:global_name_server, {:registrar, fun}, :infinity)
  end

  def unregister_name_external(name) do
    unregister_name(name)
  end

  def set_lock(id) do
    set_lock(id, [node() | :erlang.nodes()], :infinity, 1)
  end

  def set_lock(id, nodes) do
    set_lock(id, nodes, :infinity, 1)
  end

  def set_lock(id, nodes, retries)
      when is_integer(retries) and
             retries >= 0 do
    set_lock(id, nodes, retries, 1)
  end

  def set_lock(id, nodes, :infinity) do
    set_lock(id, nodes, :infinity, 1)
  end

  defp set_lock({_ResourceId, _LockRequesterId}, [], _Retries, _Times) do
    true
  end

  defp set_lock({_ResourceId, _LockRequesterId} = id, nodes, retries, times) do
    :ok

    case set_lock_on_nodes(id, nodes) do
      true ->
        :ok
        true

      false = reply when retries === 0 ->
        reply

      false ->
        random_sleep(times)
        set_lock(id, nodes, dec(retries), times + 1)
    end
  end

  def del_lock(id) do
    del_lock(id, [node() | :erlang.nodes()])
  end

  def del_lock({_ResourceId, _LockRequesterId} = id, nodes) do
    :ok
    _ = :gen_server.multi_call(nodes, :global_name_server, {:del_lock, id})
    true
  end

  def trans(id, fun) do
    trans(id, fun, [node() | :erlang.nodes()], :infinity)
  end

  def trans(id, fun, nodes) do
    trans(id, fun, nodes, :infinity)
  end

  def trans(id, fun, nodes, retries) do
    case set_lock(id, nodes, retries) do
      true ->
        try do
          fun.()
        after
          del_lock(id, nodes)
        end

      false ->
        :aborted
    end
  end

  def info() do
    :gen_server.call(:global_name_server, :info, :infinity)
  end

  def disconnect() do
    :gen_server.call(:global_name_server, :disconnect, :infinity)
  end

  def init([]) do
    _ = :erlang.process_flag(:async_dist, true)
    :erlang.process_flag(:trap_exit, true)

    :ok =
      :net_kernel.monitor_nodes(
        true,
        %{connection_id: true}
      )

    known =
      :lists.foldl(
        fn {n, %{connection_id: cId}}, cs ->
          Map.put(cs, {:connection_id, n}, cId)
        end,
        %{},
        nodes(:visible, %{connection_id: true})
      )

    _ =
      :ets.new(
        :global_locks,
        [:set, :named_table, :protected]
      )

    _ =
      :ets.new(
        :global_names,
        [:set, :named_table, :protected, {:read_concurrency, true}]
      )

    _ =
      :ets.new(
        :global_names_ext,
        [:set, :named_table, :protected]
      )

    _ =
      :ets.new(
        :global_pid_names,
        [:bag, :named_table, :protected]
      )

    _ =
      :ets.new(
        :global_pid_ids,
        [:bag, :named_table, :protected]
      )

    _ =
      :ets.new(
        :global_lost_connections,
        [:set, :named_table, :protected]
      )

    _ =
      :ets.new(
        :global_node_resources,
        [:set, :named_table, :protected]
      )

    doTrace = :os.getenv(~c"GLOBAL_HIGH_LEVEL_TRACE") === ~c"TRUE"

    t0 =
      case doTrace do
        true ->
          send_high_level_trace()
          []

        false ->
          :no_trace
      end

    ca =
      case :application.get_env(
             :kernel,
             :connect_all
           ) do
        {:ok, caBool} when is_boolean(caBool) ->
          caBool

        {:ok, caInvalid} ->
          :erlang.error({:invalid_parameter_value, :connect_all, caInvalid})

        :undefined ->
          caBool =
            case :init.get_argument(:connect_all) do
              {:ok, [[~c"false" | _] | _]} ->
                false

              _ ->
                true
            end

          :ok = :application.set_env(:kernel, :connect_all, caBool, [{:timeout, :infinity}])
          caBool
      end

    pOP =
      case :application.get_env(
             :kernel,
             :prevent_overlapping_partitions
           ) do
        {:ok, popBool} when is_boolean(popBool) ->
          popBool

        {:ok, popInvalid} ->
          :erlang.error({:invalid_parameter_value, :prevent_overlapping_partitions, popInvalid})

        :undefined ->
          true
      end

    s =
      r_state(
        the_locker: start_the_locker(doTrace),
        known: known,
        trace: t0,
        the_registrar: start_the_registrar(),
        conf: r_conf(connect_all: ca, prevent_over_part: pOP)
      )

    _ =
      :rand.seed(
        :default,
        rem(:erlang.monotonic_time(:nanosecond), 1_000_000_000) +
          rem(:erlang.system_time(:nanosecond), 1_000_000_000)
      )

    creX = :rand.uniform(1 <<< (59 - 1 - -(1 <<< 59))) - 1 &&& ~~~(1 <<< (32 - 1))
    :erlang.put(:creation_extension, creX)
    {:ok, trace_message(s, {:init, node()}, [])}
  end

  def handle_call({:registrar, fun}, from, s) do
    send(r_state(s, :the_registrar), {:trans_all_known, fun, from})
    {:noreply, s}
  end

  def handle_call({:register, name, pid, method}, {fromPid, _Tag}, s0) do
    s = ins_name(name, pid, method, fromPid, [], s0)
    {:reply, :yes, s}
  end

  def handle_call({:unregister, name}, _From, s0) do
    s = delete_global_name2(name, s0)
    {:reply, :ok, s}
  end

  def handle_call({:register_ext, name, pid, method, regNode}, {fromPid, _Tag}, s0) do
    s = ins_name_ext(name, pid, method, regNode, fromPid, [], s0)
    {:reply, :yes, s}
  end

  def handle_call({:set_lock, lock}, {pid, _Tag}, s0) do
    {reply, s} = handle_set_lock(lock, pid, s0)
    {:reply, reply, s}
  end

  def handle_call({:del_lock, lock}, {pid, _Tag}, s0) do
    s = handle_del_lock(lock, pid, s0)
    {:reply, true, s}
  end

  def handle_call(:get_known, _From, s) do
    {:reply, mk_known_list(0, s), s}
  end

  def handle_call(:get_synced, _From, s) do
    {:reply, r_state(s, :synced), s}
  end

  def handle_call({:sync, nodes}, from, s) do
    pid =
      start_sync(
        :lists.delete(
          node(),
          nodes
        ) -- r_state(s, :synced),
        from
      )

    {:noreply, r_state(s, syncers: [pid | r_state(s, :syncers)])}
  end

  def handle_call(:get_protocol_version, _From, s) do
    {:reply, 8, s}
  end

  def handle_call(:get_names_ext, _From, s) do
    {:reply, get_names_ext(), s}
  end

  def handle_call(:info, _From, s) do
    {:reply, s, s}
  end

  def handle_call(:disconnect, _From, r_state(known: known) = s0) do
    nodes =
      :maps.fold(
        fn
          {:connection_id, n}, _, ns
          when is_atom(n) ->
            case :global_group.participant(n) do
              false ->
                ns

              true ->
                :ok
                :net_kernel.async_disconnect(n)
                [n | ns]
            end

          _, _, ns ->
            ns
        end,
        [],
        known
      )

    s1 =
      :lists.foldl(
        fn n, sAcc0 ->
          receive do
            {:nodedown, ^n, i} ->
              :ok
          end

          :ok
          sAcc1 = trace_message(sAcc0, {:nodedown, n, i}, [])
          sAcc2 = handle_nodedown(n, sAcc1, :ignore_node)

          newKnown =
            :maps.remove(
              {:connection_id, n},
              r_state(sAcc2, :known)
            )

          r_state(sAcc2, known: newKnown)
        end,
        s0,
        nodes
      )

    {:reply, nodes, s1}
  end

  def handle_call(:high_level_trace_start, _From, s) do
    send(r_state(s, :the_locker), {:do_trace, true})
    send_high_level_trace()
    {:reply, :ok, trace_message(r_state(s, trace: []), {:init, node()}, [])}
  end

  def handle_call(:high_level_trace_stop, _From, s) do
    r_state(the_locker: theLocker, trace: trace) = s
    send(theLocker, {:do_trace, false})
    wait_high_level_trace()
    {:reply, trace, r_state(s, trace: :no_trace)}
  end

  def handle_call(:high_level_trace_get, _From, r_state(trace: trace) = s) do
    {:reply, trace, r_state(s, trace: [])}
  end

  def handle_call(:stop, _From, s) do
    {:stop, :normal, :stopped, s}
  end

  def handle_call(request, from, s) do
    :logger.log(
      :warning,
      ~c"The global_name_server received an unexpected message:\nhandle_call(~tp, ~tp, _)\n",
      [request, from]
    )

    {:noreply, s}
  end

  def handle_cast({:init_connect, vsn, node, initMsg}, s0) do
    :ok

    s =
      case vsn do
        {hisVsn, hisTag} when hisVsn > 8 ->
          init_connect(8, node, initMsg, hisTag, hisVsn, s0)

        {hisVsn, hisTag} ->
          init_connect(hisVsn, node, initMsg, hisTag, hisVsn, s0)

        tuple when is_tuple(tuple) ->
          list = :erlang.tuple_to_list(tuple)
          [hisVsn, hisTag | _] = list
          init_connect(8, node, initMsg, hisTag, hisVsn, s0)

        _ ->
          txt = :io_lib.format(~c"Illegal global protocol version ~p Node: ~p\n", [vsn, node])
          :logger.log(:info, :lists.flatten(txt))
          s0
      end

    {:noreply, s}
  end

  def handle_cast({:lock_is_set, node, myTag, lockId}, s) do
    :ok

    case :erlang.get({:sync_tag_my, node}) do
      ^myTag ->
        lock_is_set(node, r_state(s, :resolvers), lockId)
        {:noreply, s}

      _ ->
        newS = cancel_locker(node, s, myTag)
        {:noreply, newS}
    end
  end

  def handle_cast(
        {:exchange, node, nameList, _NameExtList, myTag},
        s
      ) do
    case :erlang.get({:sync_tag_my, node}) do
      ^myTag ->
        exchange(node, nameList, r_state(s, :resolvers))
        {:noreply, s}

      _ ->
        newS = cancel_locker(node, s, myTag)
        {:noreply, newS}
    end
  end

  def handle_cast(
        {:exchange_ops, node, myTag, ops, resolved},
        s0
      ) do
    :ok
    s = trace_message(s0, {:exit_resolver, node}, [myTag])

    case :erlang.get({:sync_tag_my, node}) do
      ^myTag ->
        known = mk_known_list(node_vsn(node, s), s)

        :gen_server.cast(
          {:global_name_server, node},
          {:resolved, node(), resolved, known, :unused, get_names_ext(),
           :erlang.get({:sync_tag_his, node})}
        )

        case :erlang.get({:save_ops, node}) do
          {:resolved, hisKnown, names_ext, hisResolved} ->
            :erlang.put({:save_ops, node}, ops)
            newS = resolved(node, hisResolved, hisKnown, names_ext, s)
            {:noreply, newS}

          :undefined ->
            :erlang.put({:save_ops, node}, ops)
            {:noreply, s}
        end

      _ ->
        newS = cancel_locker(node, s, myTag)
        {:noreply, newS}
    end
  end

  def handle_cast(
        {:resolved, node, hisResolved, hisKnown, _Unused, names_ext, myTag},
        s
      ) do
    :ok

    case :erlang.get({:sync_tag_my, node}) do
      ^myTag ->
        case :erlang.get({:save_ops, node}) do
          ops when is_list(ops) ->
            newS = resolved(node, hisResolved, hisKnown, names_ext, s)
            {:noreply, newS}

          :undefined ->
            resolved = {:resolved, hisKnown, names_ext, hisResolved}
            :erlang.put({:save_ops, node}, resolved)
            {:noreply, s}
        end

      _ ->
        newS = cancel_locker(node, s, myTag)
        {:noreply, newS}
    end
  end

  def handle_cast(
        {:new_nodes, node, ops, names_ext, nodes, extraInfo},
        s
      ) do
    :ok
    newS = new_nodes(ops, node, names_ext, nodes, extraInfo, s)
    {:noreply, newS}
  end

  def handle_cast(
        {:in_sync, node, _IsKnown},
        r_state(known: known, synced: synced) = s0
      ) do
    :ok

    :lists.foreach(
      fn pid ->
        send(pid, {:synced, [node]})
      end,
      r_state(s0, :syncers)
    )

    nSynced =
      case :lists.member(node, synced) do
        true ->
          synced

        false ->
          [node | synced]
      end

    s1 =
      r_state(s0,
        known:
          :maps.remove(
            {:pending, node},
            known
          ),
        synced: nSynced
      )

    s2 = cancel_locker(node, s1, :erlang.get({:sync_tag_my, node}))
    reset_node_state(node)
    {:noreply, s2}
  end

  def handle_cast({:async_del_name, _Name, _Pid}, s) do
    {:noreply, s}
  end

  def handle_cast({:async_del_lock, _ResourceId, _Pid}, s) do
    {:noreply, s}
  end

  def handle_cast(
        {:lock_set, pid, _Set, _HisKnown, myTag} = message,
        s
      ) do
    r_state(the_locker: locker) = s
    node = node(pid)

    case :erlang.get({:sync_tag_my, node}) do
      ^myTag ->
        send(locker, message)
        :ok

      _NewMyTag ->
        :ok
    end

    {:noreply, s}
  end

  def handle_cast(
        {:lock_set, _Pid, _Set, _HisKnown} = message,
        s
      ) do
    r_state(the_locker: locker) = s
    send(locker, message)
    {:noreply, s}
  end

  def handle_cast(request, s) do
    :logger.log(
      :warning,
      ~c"The global_name_server received an unexpected message:\nhandle_cast(~tp, _)\n",
      [request]
    )

    {:noreply, s}
  end

  def handle_info(
        {:EXIT, locker, _Reason} = exit,
        r_state(the_locker: locker) = s
      ) do
    {:stop, {:locker_died, exit}, r_state(s, the_locker: :undefined)}
  end

  def handle_info(
        {:EXIT, registrar, _} = exit,
        r_state(the_registrar: registrar) = s
      ) do
    {:stop, {:registrar_died, exit}, r_state(s, the_registrar: :undefined)}
  end

  def handle_info({:EXIT, pid, _Reason}, s) when is_pid(pid) do
    :ok
    syncers = :lists.delete(pid, r_state(s, :syncers))
    {:noreply, r_state(s, syncers: syncers)}
  end

  def handle_info({:nodedown, node, _Info}, s)
      when node === r_state(s, :node_name) do
    {:noreply, change_our_node_name(node(), s)}
  end

  def handle_info({:nodedown, node, info}, s0) do
    :ok
    s1 = trace_message(s0, {:nodedown, node, info}, [])

    nodeDownType =
      case :global_group.participant(node) do
        true ->
          :disconnected

        false ->
          :ignore_node
      end

    s2 = handle_nodedown(node, s1, nodeDownType)

    known =
      :maps.remove(
        {:connection_id, node},
        r_state(s2, :known)
      )

    {:noreply, r_state(s2, known: known)}
  end

  def handle_info({:extra_nodedown, node}, s0) do
    :ok
    s1 = trace_message(s0, {:extra_nodedown, node}, [])

    nodeDownType =
      case :global_group.participant(node) do
        true ->
          :disconnected

        false ->
          :ignore_node
      end

    :lists.foreach(
      fn pid ->
        send(pid, {:nodedown, node})
      end,
      r_state(s1, :syncers)
    )

    s2 = handle_nodedown(node, s1, nodeDownType)

    known =
      :maps.remove(
        {:connection_id, node},
        r_state(s2, :known)
      )

    {:noreply, r_state(s2, known: known)}
  end

  def handle_info(
        {:group_nodedown, node, cId},
        r_state(
          known: known,
          conf:
            r_conf(
              connect_all: cA,
              prevent_over_part: pOP
            )
        ) = s0
      ) do
    :ok
    s1 = trace_message(s0, {:group_nodedown, node, cId}, [])

    s =
      case :maps.get({:connection_id, node}, known, :not_connected) do
        ^cId ->
          s2 = delete_node_resources(node, s1)

          :lists.foreach(
            fn pid ->
              send(pid, {:nodedown, node})
            end,
            r_state(s2, :syncers)
          )

          nodeDownType =
            case cA and pOP and :global_group.member(node) do
              false ->
                :ignore_node

              true ->
                :disconnected
            end

          handle_nodedown(node, s2, nodeDownType)

        _ ->
          s1
      end

    {:noreply, s}
  end

  def handle_info({:nodeup, node, _Info}, s)
      when node === node() do
    :ok
    {:noreply, change_our_node_name(node, s)}
  end

  def handle_info(
        {:nodeup, node, %{connection_id: cId}},
        r_state(known: known, conf: r_conf(connect_all: false)) = s
      ) do
    {:noreply, r_state(s, known: Map.put(known, {:connection_id, node}, cId))}
  end

  def handle_info(
        {:nodeup, node, %{connection_id: cId}},
        r_state(known: known) = s0
      ) do
    :ok
    s1 = r_state(s0, known: Map.put(known, {:connection_id, node}, cId))
    s2 = trace_message(s1, {:nodeup, node}, [])

    s3 =
      case :global_group.group_configured() do
        false ->
          handle_nodeup(node, s2)

        true ->
          s2
      end

    {:noreply, s3}
  end

  def handle_info(
        {:group_nodeup, node, cId},
        r_state(known: known) = s0
      ) do
    :ok
    s1 = trace_message(s0, {:group_nodeup, node, cId}, [])

    s2 =
      case :maps.get({:connection_id, node}, known, :not_connected) do
        ^cId ->
          handle_nodeup(node, s1)

        _ ->
          s1
      end

    {:noreply, s2}
  end

  def handle_info({:whereis, name, from}, s) do
    _ = do_whereis(name, from)
    {:noreply, s}
  end

  def handle_info(
        {:lost_connection, nodeA, xCreationA, opIdA, nodeB} = msg,
        r_state(
          conf:
            r_conf(
              connect_all: true,
              prevent_over_part: true
            )
        ) = s0
      ) do
    lcKey = {nodeA, nodeB}

    s1 =
      case get_lost_connection_info(lcKey) do
        {^xCreationA, opId, _Tmr} when opIdA <= opId ->
          s0

        {_, _, tmr} ->
          gns_volatile_multicast(msg, nodeA, 7, true, s0)
          save_lost_connection_info(lcKey, xCreationA, opIdA, tmr)

          rmNode =
            case node() == nodeB do
              false ->
                nodeB

              true ->
                nodeA
            end

          case is_node_potentially_known(
                 rmNode,
                 s0
               ) and :global_group.participant(rmNode) do
            false ->
              s0

            true ->
              {nDType, what} =
                case node_vsn(rmNode, s0) do
                  vsn when vsn < 7 ->
                    :net_kernel.async_disconnect(rmNode)
                    {:remove_connection, ~c"disconnected old"}

                  vsn ->
                    gns_volatile_send(
                      rmNode,
                      {:remove_connection, node()}
                    )

                    case :global_group.member(rmNode) and vsn >= 8 do
                      true ->
                        {:ignore_node, ~c"excluded global group member"}

                      false ->
                        {:remove_connection, ~c"requested disconnect from"}
                    end
                end

              :logger.log(
                :warning,
                ~c"'global' at node ~p ~s node ~p in order to prevent overlapping partitions",
                [node(), what, rmNode]
              )

              handle_nodedown(rmNode, s0, nDType)
          end
      end

    {:noreply, s1}
  end

  def handle_info(
        {:lost_connection, _NodeA, _XCreationA, _OpIdA, _NodeB},
        s
      ) do
    {:noreply, s}
  end

  def handle_info({:timeout, _, _} = tmoMsg, s) do
    remove_lost_connection_info(tmoMsg)
    {:noreply, s}
  end

  def handle_info({:remove_connection, node}, s0) do
    s2 =
      case is_node_potentially_known(node, s0) do
        false ->
          s0

        true ->
          {nDType, what} =
            case :global_group.member(node) do
              true ->
                send(:global_group, {:disconnect_node, node})
                {:ignore_node, ~c"excluded global group member"}

              false ->
                :net_kernel.async_disconnect(node)
                {:remove_connection, ~c"disconnected"}
            end

          s1 = handle_nodedown(node, s0, nDType)

          :logger.log(
            :warning,
            ~c"'global' at node ~p ~s node ~p in order to prevent overlapping partitions",
            [node(), what, node]
          )

          s1
      end

    {:noreply, s2}
  end

  def handle_info({:cancel_connect, node, myTag}, s0) do
    s3 =
      case :erlang.get({:sync_tag_my, node}) do
        ^myTag ->
          s1 = cancel_locker(node, s0, myTag)
          reset_node_state(node)

          s2 =
            r_state(s1,
              known:
                :maps.remove(
                  {:pending, node},
                  r_state(s1, :known)
                )
            )

          restart_connect(node, myTag, s2)

        _ ->
          s0
      end

    {:noreply, s3}
  end

  def handle_info(
        {:init_connect_ack, node, hisMyTag, hisHisTag},
        s0
      ) do
    myMyTag = :erlang.get({:sync_tag_my, node})
    myHisTag = :erlang.get({:sync_tag_his, node})

    s1 =
      case myMyTag === hisMyTag and myHisTag === hisHisTag do
        true ->
          s0

        false ->
          send_cancel_connect_message(node, hisHisTag)
          restart_connect(node, myMyTag, s0)
      end

    {:noreply, s1}
  end

  def handle_info({:prepare_shutdown, from, ref}, s0) do
    s1 =
      r_state(s0,
        conf:
          r_conf(
            connect_all: false,
            prevent_over_part: false
          )
      )

    send(from, {ref, :ok})
    {:noreply, s1}
  end

  def handle_info(:known, s) do
    :io.format(~c">>>> ~p\n", [r_state(s, :known)])
    {:noreply, s}
  end

  def handle_info(:high_level_trace, s) do
    case s do
      r_state(trace: [{node, _Time, _M, nodes, _X} | _]) ->
        send_high_level_trace()
        cNode = node()
        cNodes = :erlang.nodes()

        case {cNode, cNodes} do
          {^node, ^nodes} ->
            {:noreply, s}

          _ ->
            {new, _, old} =
              :sofs.symmetric_partition(
                :sofs.set([
                  cNode
                  | cNodes
                ]),
                :sofs.set([node | nodes])
              )

            m = {:nodes_changed, {:sofs.to_external(new), :sofs.to_external(old)}}
            {:noreply, trace_message(s, m, [])}
        end

      _ ->
        {:noreply, s}
    end
  end

  def handle_info({:trace_message, m}, s) do
    {:noreply, trace_message(s, m, [])}
  end

  def handle_info({:trace_message, m, x}, s) do
    {:noreply, trace_message(s, m, x)}
  end

  def handle_info(
        {:DOWN, monitorRef, :process, _Pid, _Info},
        s0
      ) do
    delete_node_resource_info(monitorRef)
    s1 = delete_lock(monitorRef, s0)
    s = del_name(monitorRef, s1)
    {:noreply, s}
  end

  def handle_info(message, s) do
    :logger.log(
      :warning,
      ~c"The global_name_server received an unexpected message:\nhandle_info(~tp, _)\n",
      [message]
    )

    {:noreply, s}
  end

  defp save_node_resource_info(node, mon) do
    newRes =
      case :ets.lookup(
             :global_node_resources,
             node
           ) do
        [] ->
          %{mon => :ok}

        [{^node, oldRes}] ->
          Map.put(oldRes, mon, :ok)
      end

    true =
      :ets.insert(
        :global_node_resources,
        [{node, newRes}, {mon, node}]
      )

    :ok
  end

  defp delete_node_resource_info(mon) do
    case :ets.lookup(:global_node_resources, mon) do
      [] ->
        :ok

      [{^mon, node}] ->
        [{^node, oldRes}] =
          :ets.lookup(
            :global_node_resources,
            node
          )

        newRes = :maps.remove(mon, oldRes)
        true = :ets.delete(:global_node_resources, mon)

        case :maps.size(newRes) do
          0 ->
            true = :ets.delete(:global_node_resources, node)
            :ok

          _ ->
            true =
              :ets.insert(
                :global_node_resources,
                {node, newRes}
              )

            :ok
        end
    end
  end

  defp delete_node_resources(node, r_state() = state) do
    case :ets.lookup(:global_node_resources, node) do
      [] ->
        state

      [{^node, resources}] ->
        true = :ets.delete(:global_node_resources, node)

        :maps.fold(
          fn mon, :ok, accS0 ->
            :erlang.demonitor(mon, [:flush])
            true = :ets.delete(:global_node_resources, mon)
            accS1 = delete_lock(mon, accS0)
            del_name(mon, accS1)
          end,
          state,
          resources
        )
    end
  end

  defp wait_high_level_trace() do
    receive do
      :high_level_trace ->
        :ok
    after
      500 + 1 ->
        :ok
    end
  end

  defp send_high_level_trace() do
    :erlang.send_after(500, self(), :high_level_trace)
  end

  defp trans_all_known(fun) do
    id = {:global, self()}
    nodes = set_lock_known(id, 0)

    try do
      fun.(nodes)
    after
      delete_global_lock(id, nodes)
    end
  end

  defp set_lock_known(id, times) do
    known = get_known()
    nodes = [node() | known]
    boss = the_boss(nodes)

    case set_lock_on_nodes(id, [boss]) do
      true ->
        case lock_on_known_nodes(id, known, nodes) do
          true ->
            nodes

          false ->
            del_lock(id, [boss])
            random_sleep(times)
            set_lock_known(id, times + 1)
        end

      false ->
        random_sleep(times)
        set_lock_known(id, times + 1)
    end
  end

  defp lock_on_known_nodes(id, known, nodes) do
    case set_lock_on_nodes(id, nodes) do
      true ->
        get_known() -- known === []

      false ->
        false
    end
  end

  defp set_lock_on_nodes(_Id, []) do
    true
  end

  defp set_lock_on_nodes(id, nodes) do
    case local_lock_check(id, nodes) do
      true ->
        msg = {:set_lock, id}
        {replies, _} = :gen_server.multi_call(nodes, :global_name_server, msg)
        :ok
        check_replies(replies, id, replies)

      false = reply ->
        reply
    end
  end

  defp local_lock_check(_Id, [_] = _Nodes) do
    true
  end

  defp local_lock_check(id, nodes) do
    not :lists.member(
      node(),
      nodes
    ) or can_set_lock(id) !== false
  end

  defp check_replies([{_Node, true} | t], id, replies) do
    check_replies(t, id, replies)
  end

  defp check_replies([{_Node, false = reply} | _T], _Id, [_]) do
    reply
  end

  defp check_replies([{_Node, false = reply} | _T], id, replies) do
    trueReplyNodes =
      for {n, true} <- replies do
        n
      end

    :ok
    _ = :gen_server.multi_call(trueReplyNodes, :global_name_server, {:del_lock, id})
    reply
  end

  defp check_replies([], _Id, _Replies) do
    true
  end

  defp init_connect(vsn, node, initMsg, hisTag, hisVsn, r_state(known: known0) = s0) do
    try do
      s1 =
        case :maps.is_key({:pending, node}, known0) do
          false ->
            s0

          true ->
            cond do
              hisVsn < 8 ->
                :erlang.disconnect_node(node)

                :logger.log(
                  :error,
                  ~c"'global' at node ~p got an out of sync connection attempt from old version ~p node ~p. Disconnecting from it.",
                  [node(), hisVsn, node]
                )

                throw({:return, s0})

              true ->
                send_cancel_connect_message(node, hisTag)
                myOldTag = :erlang.get({:sync_tag_my, node})
                restart_connect(node, myOldTag, s0)
            end
        end

      :erlang.put({:prot_vsn, node}, vsn)
      :erlang.put({:sync_tag_his, node}, hisTag)

      case :lists.keyfind(node, 1, r_state(s1, :resolvers)) do
        {^node, myTag, _Resolver} ->
          ^myTag = :erlang.get({:sync_tag_my, node})
          {:locker, _NoLongerAPid, _HisKnown0, hisTheLocker} = initMsg
          :ok
          hisKnown = []

          send(
            r_state(s1, :the_locker),
            {:his_the_locker, hisTheLocker, {vsn, hisKnown}, hisTag, myTag}
          )

          cond do
            hisVsn < 8 ->
              :ok

            true ->
              gns_volatile_send(
                node,
                {:init_connect_ack, node(), hisTag, myTag}
              )
          end

          known1 = r_state(s1, :known)
          r_state(s1, known: Map.put(known1, {:pending, node}, hisVsn))

        false ->
          :ok

          :erlang.put(
            {:pre_connect, node},
            {vsn, initMsg, hisTag}
          )

          s1
      end
    catch
      {:return, s} ->
        s
    end
  end

  defp restart_connect(node, myTag, s0) do
    s1 = cancel_locker(node, s0, myTag)
    reset_node_state(node)

    s2 =
      r_state(s1,
        known:
          :maps.remove(
            {:pending, node},
            r_state(s1, :known)
          )
      )

    cond do
      is_integer(myTag) ->
        handle_nodeup(node, s2)

      true ->
        s2
    end
  end

  defp lock_is_set(node, resolvers, lockId) do
    :gen_server.cast(
      {:global_name_server, node},
      {:exchange, node(), get_names(), _ExtNames = [], :erlang.get({:sync_tag_his, node})}
    )

    :erlang.put({:lock_id, node}, lockId)

    case :erlang.get({:wait_lock, node}) do
      {:exchange, nameList} ->
        :erlang.put({:wait_lock, node}, :lock_is_set)
        exchange(node, nameList, resolvers)

      :undefined ->
        :erlang.put({:wait_lock, node}, :lock_is_set)
    end
  end

  defp exchange(node, nameList, resolvers) do
    :ok

    case :erlang.erase({:wait_lock, node}) do
      :lock_is_set ->
        {^node, _Tag, resolver} = :lists.keyfind(node, 1, resolvers)
        send(resolver, {:resolve, nameList, node})

      :undefined ->
        :erlang.put({:wait_lock, node}, {:exchange, nameList})
    end
  end

  defp resolved(node, hisResolved, hisKnown, names_ext, s0) do
    ops = :erlang.erase({:save_ops, node}) ++ hisResolved
    known = r_state(s0, :known)
    synced = r_state(s0, :synced)
    newNodes = make_node_vsn_list([node | hisKnown], s0)
    hisKnownNodes = node_list(hisKnown)
    sync_others(hisKnownNodes)
    extraInfo = [{:vsn, :erlang.get({:prot_vsn, node})}, {:lock, :erlang.get({:lock_id, node})}]
    s1 = do_ops(ops, node(), names_ext, extraInfo, s0)

    :lists.foreach(
      fn pid ->
        send(pid, {:synced, [node]})
      end,
      r_state(s1, :syncers)
    )

    s2 =
      :lists.foldl(
        fn cnclNode, accS ->
          f = fn tag, cnclS ->
            cancel_locker(cnclNode, cnclS, tag)
          end

          cancel_resolved_locker(cnclNode, f, accS)
        end,
        s1,
        hisKnownNodes
      )

    newNodesMsg = {:new_nodes, node(), ops, names_ext, newNodes, extraInfo}

    newNodesF = fn ->
      :maps.foreach(
        fn
          n, v when is_atom(n) and v >= 7 ->
            :gen_server.cast(
              {:global_name_server, n},
              newNodesMsg
            )

          n, _OldV when is_atom(n) ->
            :gen_server.cast(
              {:global_name_server, n},
              {:new_nodes, node(), ops, names_ext, node_list(newNodes), extraInfo}
            )

          _, _ ->
            :ok
        end,
        known
      )
    end

    f = fn tag, cnclS ->
      cancel_locker(node, cnclS, tag, newNodesF)
    end

    s3 = cancel_resolved_locker(node, f, s2)
    {addedNodes, s4} = add_to_known(newNodes, s3)
    send(r_state(s4, :the_locker), {:add_to_known, addedNodes})

    s5 =
      trace_message(s4, {:added, addedNodes}, [
        {:new_nodes, newNodes},
        {:abcast, known},
        {:ops, ops}
      ])

    r_state(s5, synced: [node | synced])
  end

  defp cancel_resolved_locker(node, cancelFun, r_state(known: known) = s0) do
    tag = :erlang.get({:sync_tag_my, node})
    :ok
    s1 = r_state(s0, known: :maps.remove({:pending, node}, known))
    s2 = cancelFun.(tag, s1)
    reset_node_state(node)
    s2
  end

  defp new_nodes(ops, connNode, names_ext, nodes, extraInfo, s0) do
    {addedNodes, s1} = add_to_known(nodes, s0)
    sync_others(addedNodes)
    s2 = do_ops(ops, connNode, names_ext, extraInfo, s1)
    :ok
    send(r_state(s2, :the_locker), {:add_to_known, addedNodes})
    trace_message(s2, {:added, addedNodes}, [{:ops, ops}])
  end

  defp do_whereis(name, from) do
    case is_global_lock_set() do
      false ->
        :gen_server.reply(from, where(name))

      true ->
        send_again({:whereis, name, from})
    end
  end

  def terminate(_Reason, _S) do
    true = :ets.delete(:global_names)
    true = :ets.delete(:global_names_ext)
    true = :ets.delete(:global_locks)
    true = :ets.delete(:global_pid_names)
    true = :ets.delete(:global_pid_ids)
    :ok
  end

  def code_change(_OldVsn, s, _Extra) do
    {:ok, s}
  end

  defp start_resolver(node, myTag) do
    spawn(fn ->
      resolver(node, myTag)
    end)
  end

  defp resolver(node, tag) do
    receive do
      {:resolve, nameList, ^node} ->
        :ok
        {ops, resolved} = exchange_names(nameList, node, [], [])
        exchange = {:exchange_ops, node, tag, ops, resolved}
        :gen_server.cast(:global_name_server, exchange)
        exit(:normal)

      _ ->
        resolver(node, tag)
    end
  end

  defp resend_pre_connect(node) do
    case :erlang.erase({:pre_connect, node}) do
      {vsn, initMsg, hisTag} ->
        :gen_server.cast(
          self(),
          {:init_connect, {vsn, hisTag}, node, initMsg}
        )

      _ ->
        :ok
    end
  end

  defp ins_name(name, pid, method, fromPidOrNode, extraInfo, s0) do
    :ok
    s1 = delete_global_name_keep_pid(name, s0)
    s = trace_message(s1, {:ins_name, node(pid)}, [name, pid])
    insert_global_name(name, pid, method, fromPidOrNode, extraInfo, s)
  end

  defp ins_name_ext(name, pid, method, regNode, fromPidOrNode, extraInfo, s0) do
    :ok
    s1 = delete_global_name_keep_pid(name, s0)
    dolink_ext(pid, regNode)
    s = trace_message(s1, {:ins_name_ext, node(pid)}, [name, pid])

    true =
      :ets.insert(
        :global_names_ext,
        {name, pid, regNode}
      )

    insert_global_name(name, pid, method, fromPidOrNode, extraInfo, s)
  end

  defp where(name) do
    case :ets.lookup(:global_names, name) do
      [{_Name, pid, _Method, _Ref}] ->
        cond do
          node(pid) == node() ->
            case :erlang.is_process_alive(pid) do
              true ->
                pid

              false ->
                :undefined
            end

          true ->
            pid
        end

      [] ->
        :undefined
    end
  end

  defp handle_set_lock(id, pid, s) do
    :ok

    case can_set_lock(id) do
      {true, pidRefs} ->
        case pid_is_locking(pid, pidRefs) do
          true ->
            {true, s}

          false ->
            {true, insert_lock(id, pid, pidRefs, s)}
        end

      false = reply ->
        {reply, s}
    end
  end

  defp can_set_lock({resourceId, lockRequesterId}) do
    case :ets.lookup(:global_locks, resourceId) do
      [{^resourceId, ^lockRequesterId, pidRefs}] ->
        {true, pidRefs}

      [{^resourceId, _LockRequesterId2, _PidRefs}] ->
        false

      [] ->
        {true, []}
    end
  end

  defp insert_lock({resourceId, lockRequesterId} = id, pid, pidRefs, s) do
    ref = :erlang.monitor(:process, pid)
    save_node_resource_info(node(pid), ref)
    true = :ets.insert(:global_pid_ids, {pid, resourceId})
    true = :ets.insert(:global_pid_ids, {ref, resourceId})
    lock = {resourceId, lockRequesterId, [{pid, ref} | pidRefs]}
    true = :ets.insert(:global_locks, lock)
    trace_message(s, {:ins_lock, node(pid)}, [id, pid])
  end

  defp is_global_lock_set() do
    is_lock_set(:global)
  end

  defp is_lock_set(resourceId) do
    :ets.member(:global_locks, resourceId)
  end

  defp handle_del_lock({resourceId, lockReqId}, pid, s0) do
    :ok

    case :ets.lookup(:global_locks, resourceId) do
      [{^resourceId, ^lockReqId, pidRefs}] ->
        remove_lock(resourceId, lockReqId, pid, pidRefs, false, s0)

      _ ->
        s0
    end
  end

  defp remove_lock(resourceId, lockRequesterId, pid, [{pid, ref}], down, s0) do
    :ok
    delete_node_resource_info(ref)
    true = :erlang.demonitor(ref, [:flush])
    true = :ets.delete(:global_locks, resourceId)

    true =
      :ets.delete_object(
        :global_pid_ids,
        {pid, resourceId}
      )

    true =
      :ets.delete_object(
        :global_pid_ids,
        {ref, resourceId}
      )

    s =
      case resourceId do
        :global ->
          r_state(s0, global_lock_down: down)

        _ ->
          s0
      end

    trace_message(s, {:rem_lock, node(pid)}, [{resourceId, lockRequesterId}, pid])
  end

  defp remove_lock(resourceId, lockRequesterId, pid, pidRefs0, _Down, s) do
    :ok

    pidRefs =
      case :lists.keyfind(pid, 1, pidRefs0) do
        {^pid, ref} ->
          delete_node_resource_info(ref)
          true = :erlang.demonitor(ref, [:flush])

          true =
            :ets.delete_object(
              :global_pid_ids,
              {ref, resourceId}
            )

          :lists.keydelete(pid, 1, pidRefs0)

        false ->
          pidRefs0
      end

    lock = {resourceId, lockRequesterId, pidRefs}
    true = :ets.insert(:global_locks, lock)

    true =
      :ets.delete_object(
        :global_pid_ids,
        {pid, resourceId}
      )

    trace_message(s, {:rem_lock, node(pid)}, [{resourceId, lockRequesterId}, pid])
  end

  defp do_ops(ops, connNode, names_ext, extraInfo, s0) do
    :ok

    xInserts =
      for {name2, pid2, regNode} <- names_ext,
          {:insert, {name, pid, method}} <- ops,
          name === name2,
          pid === pid2 do
        {name, pid, regNode, method}
      end

    s1 =
      :lists.foldl(
        fn {name, pid, regNode, method}, s1 ->
          ins_name_ext(name, pid, method, regNode, connNode, extraInfo, s1)
        end,
        s0,
        xInserts
      )

    xNames =
      for {name, _Pid, _RegNode, _Method} <- xInserts do
        name
      end

    inserts =
      for {:insert, {name, pid, method}} <- ops,
          not :lists.member(name, xNames) do
        {name, pid, node(pid), method}
      end

    s2 =
      :lists.foldl(
        fn {name, pid, _RegNode, method}, s2 ->
          ins_name(name, pid, method, connNode, extraInfo, s2)
        end,
        s1,
        inserts
      )

    delNames =
      for {:delete, name} <- ops do
        name
      end

    :lists.foldl(
      fn name, s ->
        delete_global_name2(name, s)
      end,
      s2,
      delNames
    )
  end

  defp sync_others(nodes) do
    n =
      case :application.get_env(
             :kernel,
             :global_connect_retries
           ) do
        {:ok, nRetries}
        when is_integer(nRetries) and
               nRetries >= 0 ->
          nRetries

        _ ->
          0
      end

    :lists.foreach(
      fn node ->
        spawn(fn ->
          sync_other(node, n)
        end)
      end,
      nodes
    )
  end

  defp sync_other(node, n) do
    :erlang.monitor_node(node, true, [:allow_passive_connect])

    receive do
      {:nodedown, ^node} when n > 0 ->
        sync_other(node, n - 1)

      {:nodedown, ^node} ->
        :ok
        :logger.log(:warning, ~c"'global' at ~w failed to connect to ~w\n", [node(), node])
        send(:global_name_server, {:extra_nodedown, node})
    after
      0 ->
        :gen_server.cast(
          {:global_name_server, node},
          {:in_sync, node(), true}
        )
    end
  end

  defp insert_global_name(name, pid, method, fromPidOrNode, extraInfo, s) do
    ref = :erlang.monitor(:process, pid)
    save_node_resource_info(node(pid), ref)

    true =
      :ets.insert(
        :global_names,
        {name, pid, method, ref}
      )

    true = :ets.insert(:global_pid_names, {pid, name})
    true = :ets.insert(:global_pid_names, {ref, name})

    case lock_still_set(fromPidOrNode, extraInfo, s) do
      true ->
        s

      false ->
        delete_global_name2(name, s)
    end
  end

  defp lock_still_set(pidOrNode, extraInfo, s) do
    case :ets.lookup(:global_locks, :global) do
      [{:global, _LockReqId, pidRefs}] when is_pid(pidOrNode) ->
        :lists.keymember(pidOrNode, 1, pidRefs)

      [{:global, lockReqId, _PidRefs}] when is_atom(pidOrNode) ->
        {:global, lockId} = extra_info(:lock, extraInfo)
        lockReqId === lockId

      [] ->
        not r_state(s, :global_lock_down)
    end
  end

  defp extra_info(tag, extraInfo) do
    case (try do
            :lists.keyfind(tag, 1, extraInfo)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      {^tag, info} ->
        info

      _ ->
        :undefined
    end
  end

  defp del_name(ref, s) do
    nameL =
      for {_, name} <-
            :ets.lookup(
              :global_pid_names,
              ref
            ),
          {_, _Pid, _Method, ref1} <-
            :ets.lookup(
              :global_names,
              name
            ),
          ref1 === ref do
        name
      end

    case nameL do
      [name] ->
        delete_global_name2(name, s)

      [] ->
        s
    end
  end

  defp delete_global_name_keep_pid(name, s) do
    case :ets.lookup(:global_names, name) do
      [{^name, pid, _Method, ref}] ->
        delete_global_name2(name, pid, ref, s)

      [] ->
        s
    end
  end

  defp delete_global_name2(name, s) do
    case :ets.lookup(:global_names, name) do
      [{^name, pid, _Method, ref}] ->
        true = :ets.delete(:global_names, name)
        delete_global_name2(name, pid, ref, s)

      [] ->
        s
    end
  end

  defp delete_global_name2(name, pid, ref, s) do
    delete_node_resource_info(ref)
    true = :erlang.demonitor(ref, [:flush])
    delete_global_name(name, pid)
    :ok

    true =
      :ets.delete_object(
        :global_pid_names,
        {pid, name}
      )

    true =
      :ets.delete_object(
        :global_pid_names,
        {ref, name}
      )

    case :ets.lookup(:global_names_ext, name) do
      [{^name, ^pid, regNode}] ->
        true = :ets.delete(:global_names_ext, name)
        :ok
        dounlink_ext(pid, regNode)

      [] ->
        :ok
        :ok
    end

    trace_message(s, {:del_name, node(pid)}, [name, pid])
  end

  defp delete_global_name(_Name, _Pid) do
    :ok
  end

  Record.defrecord(:r_multi, :multi,
    local: [],
    remote: [],
    known: [],
    the_boss: :undefined,
    just_synced: false,
    do_trace: :undefined
  )

  Record.defrecord(:r_him, :him,
    node: :undefined,
    locker: :undefined,
    vsn: :undefined,
    my_tag: :undefined,
    his_tag: :undefined
  )

  defp start_the_locker(doTrace) do
    spawn_link(init_the_locker_fun(doTrace))
  end

  defp init_the_locker_fun(doTrace) do
    fn ->
      :erlang.process_flag(:trap_exit, true)
      s0 = r_multi(do_trace: doTrace)
      s1 = update_locker_known({:add, get_known()}, s0)
      loop_the_locker(s1)
      :erlang.error(:locker_exited)
    end
  end

  defp loop_the_locker(s) do
    :ok

    receive do
      message ->
        the_locker_message(message, s)
    after
      0 ->
        timeout =
          case {r_multi(s, :local), r_multi(s, :remote)} do
            {[], []} ->
              :infinity

            _ ->
              cond do
                r_multi(s, :just_synced) ->
                  0

                r_multi(s, :known) === [] ->
                  200

                true ->
                  :erlang.min(1000 + 100 * length(r_multi(s, :known)), 3000)
              end
          end

        s1 = r_multi(s, just_synced: false)

        receive do
          message ->
            the_locker_message(message, s1)
        after
          timeout ->
            case is_global_lock_set() do
              true ->
                loop_the_locker(s1)

              false ->
                select_node(s1)
            end
        end
    end
  end

  defp the_locker_message(
         {:his_the_locker, hisTheLocker, hisKnown0, hisTag, myTag} = _HtlMsg,
         s
       ) do
    :ok
    {hisVsn, _HisKnown} = hisKnown0
    true = hisVsn > 4

    him =
      r_him(
        node: node(hisTheLocker),
        my_tag: myTag,
        his_tag: hisTag,
        locker: hisTheLocker,
        vsn: hisVsn
      )

    loop_the_locker(add_node(him, s))
  end

  defp the_locker_message(
         {:cancel, _Node, :undefined, :no_fun} = _CMsg,
         s
       ) do
    :ok
    loop_the_locker(s)
  end

  defp the_locker_message({:cancel, node, tag, :no_fun} = _CMsg, s) do
    :ok
    loop_the_locker(remove_node(node, tag, s))
  end

  defp the_locker_message({:lock_set, _Pid, false, _, _} = _Msg, s) do
    :ok
    loop_the_locker(s)
  end

  defp the_locker_message({:lock_set, _Pid, false, _} = _Msg, s) do
    :ok
    loop_the_locker(s)
  end

  defp the_locker_message(
         {:lock_set, pid, true, _HisKnown, myTag} = _Msg,
         s
       ) do
    node = node(pid)
    :ok

    case find_node_tag(node, s) do
      {true, ^myTag, hisVsn, hisTag} ->
        lockId = locker_lock_id(pid, hisVsn)
        {isLockSet, s1} = lock_nodes_safely(lockId, [], s)
        send_lock_set(s1, isLockSet, pid, hisVsn, hisTag)
        known2 = [node() | r_multi(s1, :known)]
        :ok

        case isLockSet do
          true ->
            :gen_server.cast(
              :global_name_server,
              {:lock_is_set, node, myTag, lockId}
            )

            :ok
            wait_cancel_lock(node, lockId, myTag, known2, :the_locker_message_wait_cancel, s1)
            s2 = r_multi(s1, just_synced: true)
            loop_the_locker(remove_node(node, myTag, s2))

          false ->
            loop_the_locker(r_multi(s1, just_synced: false))
        end

      false ->
        :ok
        send_lock_set(s, false, pid, _HisVsn = 5, 0)
        loop_the_locker(s)
    end
  end

  defp the_locker_message({:lock_set, pid, true, hisKnown}, s) do
    case find_node_tag(node(pid), s) do
      {true, myTag, _HisVsn, _HisTag} ->
        the_locker_message(
          {:lock_set, pid, true, hisKnown, myTag},
          s
        )

      false ->
        :ok
        send_lock_set(s, false, pid, _HisVsn = 5, 0)
        loop_the_locker(s)
    end
  end

  defp the_locker_message({:add_to_known, nodes}, s) do
    s1 = update_locker_known({:add, nodes}, s)
    loop_the_locker(s1)
  end

  defp the_locker_message({:remove_from_known, node}, s) do
    s1 = update_locker_known({:remove, node}, s)
    loop_the_locker(s1)
  end

  defp the_locker_message({:do_trace, doTrace}, s) do
    loop_the_locker(r_multi(s, do_trace: doTrace))
  end

  defp the_locker_message({:get_state, _, _} = msg, s) do
    get_state_reply(msg, :the_locker_message, s)
    loop_the_locker(s)
  end

  defp the_locker_message(other, s) do
    unexpected_message(other, :locker)
    :ok
    loop_the_locker(s)
  end

  defp get_state_reply({:get_state, from, ref}, where, s) do
    send(from, {ref, where, s})
    :ok
  end

  def get_locker() do
    r_state(the_locker: theLocker) = info()
    theLocker
  end

  defp select_node(s) do
    useRemote = r_multi(s, :local) === []

    others1 =
      cond do
        useRemote ->
          r_multi(s, :remote)

        true ->
          r_multi(s, :local)
      end

    others2 = exclude_known(others1, r_multi(s, :known))

    s1 =
      cond do
        useRemote ->
          r_multi(s, remote: others2)

        true ->
          r_multi(s, local: others2)
      end

    cond do
      others2 === [] ->
        loop_the_locker(s1)

      true ->
        him = random_element(others2)
        r_him(locker: hisTheLocker, vsn: hisVsn, node: node, my_tag: myTag, his_tag: hisTag) = him
        hisNode = [node]
        us = [node() | hisNode]
        lockId = locker_lock_id(hisTheLocker, hisVsn)
        :ok
        {isLockSet, s2} = lock_nodes_safely(lockId, hisNode, s1)

        case isLockSet do
          true ->
            known1 = us ++ r_multi(s2, :known)
            send_lock_set(s2, true, hisTheLocker, hisVsn, hisTag)
            s3 = lock_is_set(s2, him, myTag, known1, lockId)
            loop_the_locker(s3)

          false ->
            loop_the_locker(s2)
        end
    end
  end

  defp send_lock_set(s, isLockSet, hisTheLocker, vsn, hisTag) do
    :ok

    message =
      cond do
        vsn < 8 ->
          {:lock_set, self(), isLockSet, r_multi(s, :known)}

        true ->
          {:lock_set, self(), isLockSet, r_multi(s, :known), hisTag}
      end

    cond do
      vsn < 6 ->
        send(hisTheLocker, message)
        :ok

      true ->
        :gen_server.cast(
          {:global_name_server, node(hisTheLocker)},
          message
        )
    end
  end

  defp locker_lock_id(pid, vsn) when vsn > 4 do
    {:global, :lists.sort([self(), pid])}
  end

  defp lock_nodes_safely(lockId, extra, s0) do
    first = delete_nonode([r_multi(s0, :the_boss)])

    case [node()] === first or can_set_lock(lockId) !== false do
      true ->
        case set_lock(lockId, first, 0) do
          true ->
            s = update_locker_known(s0)
            second = delete_nonode([node() | extra] -- first)

            case set_lock(lockId, second, 0) do
              true ->
                known = r_multi(s, :known)

                case set_lock(lockId, known -- first, 0) do
                  true ->
                    _ = locker_trace(s, :ok, {first, known})
                    {true, s}

                  false ->
                    soFar = first ++ second
                    del_lock(lockId, soFar)
                    _ = locker_trace(s, :not_ok, {known, soFar})
                    {false, s}
                end

              false ->
                del_lock(lockId, first)
                _ = locker_trace(s, :not_ok, {second, first})
                {false, s}
            end

          false ->
            _ = locker_trace(s0, :not_ok, {first, []})
            {false, s0}
        end

      false ->
        {false, s0}
    end
  end

  defp delete_nonode(l) do
    :lists.delete(:nonode@nohost, l)
  end

  defp locker_trace(r_multi(do_trace: false), _, _Nodes) do
    :ok
  end

  defp locker_trace(r_multi(do_trace: true), :ok, ns) do
    send(:global_name_server, {:trace_message, {:locker_succeeded, node()}, ns})
  end

  defp locker_trace(r_multi(do_trace: true), :not_ok, ns) do
    send(:global_name_server, {:trace_message, {:locker_failed, node()}, ns})
  end

  defp locker_trace(r_multi(do_trace: true), :rejected, ns) do
    send(:global_name_server, {:trace_message, {:lock_rejected, node()}, ns})
  end

  defp update_locker_known(s) do
    receive do
      {:add_to_known, nodes} ->
        s1 = update_locker_known({:add, nodes}, s)
        update_locker_known(s1)

      {:remove_from_known, node} ->
        s1 = update_locker_known({:remove, node}, s)
        update_locker_known(s1)
    after
      0 ->
        s
    end
  end

  defp update_locker_known(upd, s) do
    known =
      case upd do
        {:add, nodes} ->
          nodes ++ r_multi(s, :known)

        {:remove, node} ->
          :lists.delete(node, r_multi(s, :known))
      end

    theBoss = the_boss([node() | known])
    newS = r_multi(s, known: known, the_boss: theBoss)
    newS
  end

  defp random_element(l) do
    e = rem(abs(:erlang.monotonic_time() ^^^ :erlang.unique_integer()), length(l))
    :lists.nth(e + 1, l)
  end

  defp exclude_known(others, known) do
    for n <- others,
        not :lists.member(r_him(n, :node), known) do
      n
    end
  end

  defp lock_is_set(s, him, myTag, known1, lockId) do
    node = r_him(him, :node)

    receive do
      {:lock_set, p, true, _, ^myTag} when node(p) === node ->
        lock_is_set_true_received(s, him, myTag, known1, lockId, p)

      {:lock_set, p, true, _, _OldMyTag} when node(p) === node ->
        lock_is_set(s, him, myTag, known1, lockId)

      {:lock_set, p, true, _} when node(p) === node ->
        lock_is_set_true_received(s, him, myTag, known1, lockId, p)

      {:lock_set, p, false, _, ^myTag} when node(p) === node ->
        :ok
        _ = locker_trace(s, :rejected, known1)
        delete_global_lock(lockId, known1)
        s

      {:lock_set, p, false, _, _OldMyTag}
      when node(p) === node ->
        lock_is_set(s, him, myTag, known1, lockId)

      {:lock_set, p, false, _} when node(p) === node ->
        :ok
        _ = locker_trace(s, :rejected, known1)
        delete_global_lock(lockId, known1)
        s

      {:cancel, ^node, ^myTag, fun} = _CMsg ->
        :ok
        call_fun(fun)
        _ = locker_trace(s, :rejected, known1)
        delete_global_lock(lockId, known1)
        remove_node(node, myTag, s)

      {:get_state, _, _} = msg ->
        get_state_reply(msg, :lock_is_set, s)
        lock_is_set(s, him, myTag, known1, lockId)
    end
  end

  defp lock_is_set_true_received(s, him, myTag, known1, lockId, p) do
    node = node(p)

    :gen_server.cast(
      :global_name_server,
      {:lock_is_set, node, myTag, lockId}
    )

    :ok
    wait_cancel_lock(node, lockId, myTag, known1, :lock_is_set_wait_cancel, s)

    r_multi(s,
      just_synced: true,
      local: :lists.delete(him, r_multi(s, :local)),
      remote: :lists.delete(him, r_multi(s, :remote))
    )
  end

  defp wait_cancel_lock(node, lockId, myTag, known, where, s) do
    receive do
      {:cancel, ^node, ^myTag, fun} = _CMsg ->
        :ok
        call_fun(fun)
        delete_global_lock(lockId, known)

      {:get_state, _, _} = msg ->
        get_state_reply(msg, where, s)
        wait_cancel_lock(node, lockId, myTag, known, where, s)
    end
  end

  defp call_fun(:no_fun) do
    :ok
  end

  defp call_fun(fun) do
    fun.()
  end

  defp delete_global_lock(lockId, nodes) do
    theBoss = the_boss(nodes)
    del_lock(lockId, :lists.delete(theBoss, nodes))
    del_lock(lockId, [theBoss])
  end

  defp the_boss(nodes) do
    :lists.max(nodes)
  end

  defp find_node_tag(node, s) do
    case find_node_tag2(node, r_multi(s, :local)) do
      false ->
        find_node_tag2(node, r_multi(s, :remote))

      reply ->
        reply
    end
  end

  defp find_node_tag2(_Node, []) do
    false
  end

  defp find_node_tag2(
         node,
         [
           r_him(node: node, my_tag: myTag, vsn: hisVsn, his_tag: hisTag)
           | _
         ]
       ) do
    {true, myTag, hisVsn, hisTag}
  end

  defp find_node_tag2(node, [_E | rest]) do
    find_node_tag2(node, rest)
  end

  defp remove_node(node, tag, s) do
    r_multi(s,
      local: remove_node2(node, tag, r_multi(s, :local)),
      remote: remove_node2(node, tag, r_multi(s, :remote))
    )
  end

  defp remove_node2(_Node, _Tag, []) do
    []
  end

  defp remove_node2(node, tag, [r_him(node: node, my_tag: tag) | rest]) do
    rest
  end

  defp remove_node2(node, tag, [e | rest]) do
    [e | remove_node2(node, tag, rest)]
  end

  defp add_node(him, s) do
    case is_node_local(r_him(him, :node)) do
      true ->
        r_multi(s, local: [him | r_multi(s, :local)])

      false ->
        r_multi(s, remote: [him | r_multi(s, :remote)])
    end
  end

  defp is_node_local(node) do
    {:ok, host} = :inet.gethostname()

    case (try do
            split_node(:erlang.atom_to_list(node), ?@, [])
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      [_, ^host] ->
        true

      _ ->
        false
    end
  end

  defp split_node([chr | t], chr, ack) do
    [:lists.reverse(ack) | split_node(t, chr, [])]
  end

  defp split_node([h | t], chr, ack) do
    split_node(t, chr, [h | ack])
  end

  defp split_node([], _, ack) do
    [:lists.reverse(ack)]
  end

  defp cancel_locker(node, s, tag) do
    cancel_locker(node, s, tag, :no_fun)
  end

  defp cancel_locker(node, s, tag, toBeRunOnLockerF) do
    cMsg = {:cancel, node, tag, toBeRunOnLockerF}
    send(r_state(s, :the_locker), cMsg)
    resolvers = r_state(s, :resolvers)
    :ok
    send_cancel_connect(node, tag, s)

    case :lists.keyfind(node, 1, resolvers) do
      {_, ^tag, resolver} ->
        :ok
        :erlang.exit(resolver, :kill)
        s1 = trace_message(s, {:kill_resolver, node}, [tag, resolver])
        r_state(s1, resolvers: :lists.keydelete(node, 1, resolvers))

      _ ->
        s
    end
  end

  defp send_cancel_connect(node, myTag, r_state(known: known)) do
    try do
      case :maps.find({:pending, node}, known) do
        {:ok, vsn} when vsn < 8 ->
          throw(:ignore)

        :error ->
          throw(:ignore)

        {:ok, _Vsn} ->
          :ok
      end

      case :erlang.get({:sync_tag_my, node}) do
        ^myTag ->
          :ok

        _ ->
          throw(:ignore)
      end

      send_cancel_connect_message(
        node,
        :erlang.get({:sync_tag_his, node})
      )
    catch
      :ignore ->
        :ok
    end
  end

  defp send_cancel_connect_message(node, hisTag) do
    msg = {:cancel_connect, node(), hisTag}
    to = {:global_name_server, node}
    _ = :erlang.send(to, msg, [:noconnect])
    :ok
  end

  defp reset_node_state(node) do
    :ok
    :erlang.erase({:wait_lock, node})
    :erlang.erase({:save_ops, node})
    :erlang.erase({:pre_connect, node})
    :erlang.erase({:prot_vsn, node})
    :erlang.erase({:sync_tag_my, node})
    :erlang.erase({:sync_tag_his, node})
    :erlang.erase({:lock_id, node})
  end

  defp exchange_names([{name, pid, method} | tail], node, ops, res) do
    case :ets.lookup(:global_names, name) do
      [{^name, ^pid, _Method, _Ref2}] ->
        exchange_names(tail, node, ops, res)

      [{^name, pid2, method2, _Ref2}] when node() < node ->
        node2 = node(pid2)

        case :rpc.call(node2, :global, :resolve_it, [method2, name, pid, pid2]) do
          ^pid ->
            op = {:insert, {name, pid, method}}
            exchange_names(tail, node, [op | ops], res)

          ^pid2 ->
            op = {:insert, {name, pid2, method2}}
            exchange_names(tail, node, ops, [op | res])

          :none ->
            op = {:delete, name}
            exchange_names(tail, node, [op | ops], [op | res])

          {:badrpc, badrpc} ->
            :logger.log(
              :info,
              ~c"global: badrpc ~w received when conflicting name ~tw was found\n",
              [badrpc, name]
            )

            op = {:insert, {name, pid, method}}
            exchange_names(tail, node, [op | ops], res)

          else__ ->
            :logger.log(
              :info,
              ~c"global: Resolve method ~w for conflicting name ~tw returned ~tw\n",
              [method, name, else__]
            )

            op = {:delete, name}
            exchange_names(tail, node, [op | ops], [op | res])
        end

      [{^name, _Pid2, _Method, _Ref}] ->
        exchange_names(tail, node, ops, res)

      _ ->
        exchange_names(tail, node, [{:insert, {name, pid, method}} | ops], res)
    end
  end

  defp exchange_names([], _, ops, res) do
    :ok
    {ops, res}
  end

  def resolve_it(method, name, pid1, pid2) do
    try do
      method.(name, pid1, pid2)
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end
  end

  defp minmax(p1, p2) do
    cond do
      node(p1) < node(p2) ->
        {p1, p2}

      true ->
        {p2, p1}
    end
  end

  def random_exit_name(name, pid, pid2) do
    {min, max} = minmax(pid, pid2)
    :logger.log(:info, ~c"global: Name conflict terminating ~tw\n", [{name, max}])
    :erlang.exit(max, :kill)
    min
  end

  def random_notify_name(name, pid, pid2) do
    {min, max} = minmax(pid, pid2)
    send(max, {:global_name_conflict, name})
    min
  end

  def notify_all_name(name, pid, pid2) do
    send(pid, {:global_name_conflict, name, pid2})
    send(pid2, {:global_name_conflict, name, pid})
    :none
  end

  defp dolink_ext(pid, regNode) when regNode === node() do
    :erlang.link(pid)
  end

  defp dolink_ext(_, _) do
    :ok
  end

  defp dounlink_ext(pid, regNode) when regNode === node() do
    unlink_pid(pid)
  end

  defp dounlink_ext(_Pid, _RegNode) do
    :ok
  end

  defp unlink_pid(pid) do
    case :ets.member(:global_pid_names, pid) do
      false ->
        case :ets.member(:global_pid_ids, pid) do
          false ->
            :erlang.unlink(pid)

          true ->
            :ok
        end

      true ->
        :ok
    end
  end

  defp pid_is_locking(pid, pidRefs) do
    :lists.keyfind(pid, 1, pidRefs) !== false
  end

  defp delete_lock(ref, s0) do
    locks = pid_locks(ref)

    f = fn {resourceId, lockRequesterId, pidRefs}, s ->
      {pid, ^ref} = :lists.keyfind(ref, 2, pidRefs)
      remove_lock(resourceId, lockRequesterId, pid, pidRefs, true, s)
    end

    :lists.foldl(f, s0, locks)
  end

  defp pid_locks(ref) do
    l =
      :lists.flatmap(
        fn {_, resourceId} ->
          :ets.lookup(:global_locks, resourceId)
        end,
        :ets.lookup(:global_pid_ids, ref)
      )

    for lock = {_Id, _Req, pidRefs} <- l,
        ref_is_locking(ref, pidRefs) do
      lock
    end
  end

  defp ref_is_locking(ref, pidRefs) do
    :lists.keyfind(ref, 2, pidRefs) !== false
  end

  defp handle_nodeup(
         node,
         r_state(the_locker: theLocker, resolvers: rs, known: known) = s0
       ) do
    case :maps.is_key(
           node,
           known
         ) or :lists.keymember(node, 1, rs) do
      true ->
        s0

      false ->
        resend_pre_connect(node)
        myTag = :erlang.unique_integer([:monotonic])
        :erlang.put({:sync_tag_my, node}, myTag)
        notAPid = :no_longer_a_pid
        locker = {:locker, notAPid, known, theLocker}
        initC = {:init_connect, {8, myTag}, node(), locker}
        :ok
        :gen_server.cast({:global_name_server, node}, initC)
        resolver = start_resolver(node, myTag)
        s1 = trace_message(s0, {:new_resolver, node}, [myTag, resolver])
        r_state(s1, resolvers: [{node, myTag, resolver} | rs])
    end
  end

  defp handle_nodedown(node, r_state(synced: syncs, known: known0) = s, what) do
    newS = cancel_locker(node, s, :erlang.get({:sync_tag_my, node}))
    send(r_state(newS, :the_locker), {:remove_from_known, node})
    reset_node_state(node)

    known1 =
      case what do
        :remove_connection ->
          :maps.put({:removing, node}, :yes, known0)

        :ignore_node ->
          :maps.remove({:removing, node}, known0)

        :disconnected ->
          case :maps.get({:removing, node}, known0, :no) do
            :yes ->
              :maps.remove({:removing, node}, known0)

            :no ->
              inform_connection_loss(node, s)
              known0
          end
      end

    known2 = :maps.remove({:pending, node}, known1)
    known3 = :maps.remove(node, known2)

    r_state(newS,
      known: known3,
      synced: :lists.delete(node, syncs)
    )
  end

  defp inform_connection_loss(
         node,
         r_state(
           conf:
             r_conf(
               connect_all: true,
               prevent_over_part: true
             )
         ) = s
       ) do
    msg =
      {:lost_connection, node(),
       :erlang.get(:creation_extension) + :erlang.system_info(:creation) - -(1 <<< 59),
       :erlang.unique_integer([:monotonic]), node}

    gns_volatile_multicast(msg, node, 7, true, s)
  end

  defp inform_connection_loss(_Node, r_state()) do
    :ok
  end

  defp gns_volatile_send(node, msg) do
    _ = :erlang.send({:global_name_server, node}, msg, [:noconnect])
    :ok
  end

  defp gns_volatile_multicast(msg, ignoreNode, minVer, alsoPend, r_state(known: known)) do
    :maps.foreach(
      fn
        node, ver
        when is_atom(node) and
               node !== ignoreNode and ver >= minVer ->
          _ = :erlang.send({:global_name_server, node}, msg, [:noconnect])

        {:pending, node}, ver
        when alsoPend == true and
               node !== ignoreNode and
               ver >= minVer ->
          _ = :erlang.send({:global_name_server, node}, msg, [:noconnect])

        _, _ ->
          :ok
      end,
      known
    )

    :ok
  end

  defp is_node_potentially_known(node, r_state(known: known)) do
    :maps.is_key(node, known) or
      :maps.is_key(
        {:pending, node},
        known
      )
  end

  defp node_vsn(node, r_state()) when node() == node do
    8
  end

  defp node_vsn(node, r_state(known: known)) do
    case :maps.find(node, known) do
      {:ok, ver} ->
        ver

      :error ->
        case :maps.find({:pending, node}, known) do
          {:ok, ver} ->
            ver

          :error ->
            0
        end
    end
  end

  defp node_list(nList) do
    :lists.map(
      fn
        n when is_atom(n) ->
          n

        {n, _V} when is_atom(n) ->
          n
      end,
      nList
    )
  end

  defp make_node_vsn_list(nList, r_state() = s) do
    :lists.map(
      fn
        {n, 0} when is_atom(n) ->
          {n, node_vsn(n, s)}

        n when is_atom(n) ->
          {n, node_vsn(n, s)}

        {n, v} = nV when is_atom(n) and is_integer(v) ->
          nV
      end,
      nList
    )
  end

  defp mk_known_list(vsn, r_state(known: known)) when vsn < 7 do
    :lists.foldl(
      fn
        {n, _V}, ns when is_atom(n) ->
          [n | ns]

        _, ns ->
          ns
      end,
      [],
      :maps.to_list(known)
    )
  end

  defp mk_known_list(_Vsn, r_state(known: known)) do
    :lists.foldl(
      fn
        {n, _V} = nV, nVs when is_atom(n) ->
          [nV | nVs]

        _, ns ->
          ns
      end,
      [],
      :maps.to_list(known)
    )
  end

  defp add_to_known(addKnown, r_state(known: known) = s) do
    fun = fn
      n, acc when n == node() ->
        acc

      {n, _V}, acc when n == node() ->
        acc

      n, {a, k} = acc when is_atom(n) ->
        case :maps.is_key(n, k) do
          true ->
            acc

          false ->
            {[n | a], :maps.put(n, 0, k)}
        end

      {n, v}, {a, k} = acc ->
        case :maps.find(n, k) do
          :error ->
            {[n | a], :maps.put(n, v, k)}

          {:ok, nV} when nV >= 0 ->
            acc

          {:ok, _UnknownVsn} ->
            {a, :maps.put(n, v, k)}
        end
    end

    {added, newKnown} = :lists.foldl(fun, {[], known}, addKnown)
    {added, r_state(s, known: newKnown)}
  end

  defp get_lost_connection_info(lcKey) do
    case :ets.lookup(:global_lost_connections, lcKey) do
      [{^lcKey, lcValue}] ->
        lcValue

      _ ->
        {:undefined, :undefined, :undefined}
    end
  end

  defp save_lost_connection_info(lcKey, xCre, opId, :undefined) do
    tmr = :erlang.start_timer(60 * 60 * 1000, self(), {:lost_connection, lcKey})
    value = {xCre, opId, tmr}

    _ =
      :ets.insert(
        :global_lost_connections,
        {lcKey, value}
      )

    :ok
  end

  defp save_lost_connection_info(lcKey, xCre, opId, oldTmr) do
    _ =
      :erlang.cancel_timer(
        oldTmr,
        [{:async, true}, {:info, false}]
      )

    save_lost_connection_info(lcKey, xCre, opId, :undefined)
  end

  defp remove_lost_connection_info({:timeout, tmr, {:lost_connection, lcKey}}) do
    case :ets.lookup(:global_lost_connections, lcKey) do
      [{^lcKey, {_, _, ^tmr}}] ->
        _ = :ets.delete(:global_lost_connections, lcKey)
        :ok

      _ ->
        :ok
    end
  end

  defp remove_lost_connection_info(_) do
    :ok
  end

  defp get_names() do
    :ets.select(
      :global_names,
      :ets.fun2ms(fn {name, pid, method, _Ref} ->
        {name, pid, method}
      end)
    )
  end

  defp get_names_ext() do
    :ets.tab2list(:global_names_ext)
  end

  defp get_known() do
    :gen_server.call(:global_name_server, :get_known, :infinity)
  end

  defp random_sleep(times) do
    _ =
      case rem(times, 10) do
        0 ->
          _ = :rand.seed(:exsplus)

        _ ->
          :ok
      end

    tmax =
      cond do
        times > 5 ->
          8000

        true ->
          div((1 <<< times) * 1000, 8)
      end

    t = :rand.uniform(tmax)
    :ok

    receive do
    after
      t ->
        :ok
    end
  end

  defp dec(:infinity) do
    :infinity
  end

  defp dec(n) do
    n - 1
  end

  defp send_again(msg) do
    me = self()

    spawn(fn ->
      timer(me, msg)
    end)
  end

  defp timer(pid, msg) do
    random_sleep(5)
    send(pid, msg)
  end

  defp change_our_node_name(newNode, s) do
    s1 = trace_message(s, {:new_node_name, newNode}, [])
    r_state(s1, node_name: newNode)
  end

  defp trace_message(r_state(trace: :no_trace) = s, _M, _X) do
    s
  end

  defp trace_message(s, m, x) do
    r_state(s, trace: [trace_message(m, x) | r_state(s, :trace)])
  end

  defp trace_message(m, x) do
    {node(), :erlang.timestamp(), m, :erlang.nodes(), x}
  end

  defp start_sync(nodes, from) do
    spawn_link(fn ->
      sync_init(nodes, from)
    end)
  end

  defp sync_init(nodes, from) do
    :lists.foreach(
      fn node ->
        :erlang.monitor_node(node, true)
      end,
      nodes
    )

    sync_loop(nodes, from)
  end

  defp sync_loop([], from) do
    :gen_server.reply(from, :ok)
  end

  defp sync_loop(nodes, from) do
    receive do
      {:nodedown, node} ->
        :erlang.monitor_node(node, false)
        sync_loop(:lists.delete(node, nodes), from)

      {:synced, sNodes} ->
        :lists.foreach(
          fn n ->
            :erlang.monitor_node(n, false)
          end,
          sNodes
        )

        sync_loop(nodes -- sNodes, from)
    end
  end

  defp check_sync_nodes() do
    case get_own_nodes() do
      {:ok, :all} ->
        :erlang.nodes()

      {:ok, nodesNG} ->
        intersection(nodesNG, :erlang.nodes())

      {:error, _} = error ->
        error
    end
  end

  defp check_sync_nodes(syncNodes) do
    case get_own_nodes() do
      {:ok, :all} ->
        syncNodes

      {:ok, nodesNG} ->
        ownNodeGroup = intersection(nodesNG, :erlang.nodes())
        illegalSyncNodes = syncNodes -- [node() | ownNodeGroup]

        case illegalSyncNodes do
          [] ->
            syncNodes

          _ ->
            {:error,
             {~c"Trying to sync nodes not defined in the own global group", illegalSyncNodes}}
        end

      {:error, _} = error ->
        error
    end
  end

  defp get_own_nodes() do
    case :global_group.get_own_nodes_with_errors() do
      {:error, error} ->
        {:error, {~c"global_groups definition error", error}}

      okTup ->
        okTup
    end
  end

  defp start_the_registrar() do
    spawn_link(fn ->
      loop_the_registrar()
    end)
  end

  defp loop_the_registrar() do
    receive do
      {:trans_all_known, fun, from} ->
        :ok
        :gen_server.reply(from, trans_all_known(fun))

      other ->
        unexpected_message(other, :register)
    end

    loop_the_registrar()
  end

  defp unexpected_message({:EXIT, _Pid, _Reason}, _What) do
    :ok
  end

  defp unexpected_message(message, what) do
    :logger.log(
      :warning,
      ~c"The global_name_server ~w process received an unexpected message:\n~tp\n",
      [what, message]
    )
  end

  defp intersection(_, []) do
    []
  end

  defp intersection(l1, l2) do
    l1 -- l1 -- l2
  end

  defp allow_tuple_fun({m, f}) when is_atom(m) and is_atom(f) do
    Function.capture(m, f, 3)
  end

  defp allow_tuple_fun(fun) when is_function(fun, 3) do
    fun
  end
end
