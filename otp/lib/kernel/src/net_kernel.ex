defmodule :m_net_kernel do
  use Bitwise
  import :error_logger, only: [error_msg: 2]
  @behaviour :gen_server
  require Record
  Record.defrecord(:r_state, :state, node: :undefined,
                                 type: :undefined, tick: :undefined,
                                 connecttime: :undefined,
                                 connections: :undefined, conn_owners: %{},
                                 dist_ctrlrs: %{}, pend_owners: %{},
                                 listen: :undefined, allowed: :undefined,
                                 verbose: 0, dyn_name_pool: %{},
                                 supervisor: :undefined, req_map: %{})
  Record.defrecord(:r_listen, :listen, listen: :undefined,
                                  accept: :undefined, address: :undefined,
                                  module: :undefined)
  Record.defrecord(:r_net_address, :net_address, address: :undefined,
                                       host: :undefined, protocol: :undefined,
                                       family: :undefined)
  Record.defrecord(:r_connection, :connection, node: :undefined,
                                      conn_id: :undefined, state: :undefined,
                                      owner: :undefined, ctrlr: :undefined,
                                      pending_owner: :undefined,
                                      address: :EFE_TODO_NESTED_RECORD,
                                      waiting: [], type: :undefined,
                                      remote_name_type: :undefined,
                                      creation: :undefined, named_me: false)
  Record.defrecord(:r_barred_connection, :barred_connection, node: :undefined)
  Record.defrecord(:r_tick, :tick, ticker: :undefined,
                                time: :undefined, intensity: :undefined)
  Record.defrecord(:r_tick_change, :tick_change, ticker: :undefined,
                                       time: :undefined, intensity: :undefined,
                                       how: :undefined)
  def dflag_unicode_io(_) do
    :erlang.nif_error(:undef)
  end

  def kernel_apply(m, f, a) do
    request({:apply, m, f, a})
  end

  def allow(nodes) do
    request({:allow, nodes})
  end

  def allowed() do
    request(:allowed)
  end

  def longnames() do
    request(:longnames)
  end

  def nodename() do
    request(:nodename)
  end

  def get_state() do
    case (:erlang.whereis(:net_kernel)) do
      :undefined ->
        case (retry_request_maybe(:get_state)) do
          :ignored ->
            %{started: :no}
          reply ->
            reply
        end
      _ ->
        request(:get_state)
    end
  end

  def stop() do
    :erl_distribution.stop()
  end

  def node_info(node) do
    get_node_info(node)
  end

  def node_info(node, key) do
    get_node_info(node, key)
  end

  def nodes_info() do
    get_nodes_info()
  end

  def i() do
    print_info()
  end

  def i(node) do
    print_info(node)
  end

  def verbose(level) when is_integer(level) do
    request({:verbose, level})
  end

  def set_net_ticktime(t, tP) when (is_integer(t) and t > 0 and
                        is_integer(tP) and tP >= 0) do
    ticktime_res(request({:new_ticktime, t * 1000,
                            tP * 1000}))
  end

  def set_net_ticktime(t) when is_integer(t) do
    set_net_ticktime(t, 60)
  end

  def get_net_ticktime() do
    ticktime_res(request(:ticktime))
  end

  def monitor_nodes(flag) do
    case ((try do
            :erlang.process_flag(:monitor_nodes, flag)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      n when is_integer(n) ->
        :ok
      _ ->
        mk_monitor_nodes_error(flag, [])
    end
  end

  def monitor_nodes(flag, opts) do
    try do
      mapOpts = (cond do
                   is_map(opts) ->
                     :error = :maps.find(:list, opts)
                     opts
                   is_list(opts) ->
                     :lists.foldl(fn :nodedown_reason, acc ->
                                       Map.put(acc, :nodedown_reason, true)
                                     :connection_id, acc ->
                                       Map.put(acc, :connection_id, true)
                                     {:node_type, val}, acc ->
                                       case (:maps.find(:node_type, acc)) do
                                         :error ->
                                           :ok
                                         {:ok, ^val} ->
                                           :ok
                                       end
                                       Map.put(acc, :node_type, val)
                                  end,
                                    %{list: true}, opts)
                 end)
      true = is_integer(:erlang.process_flag({:monitor_nodes,
                                                mapOpts},
                                               flag))
      :ok
    catch
      _, _ ->
        mk_monitor_nodes_error(flag, opts)
    end
  end

  defp ticktime_res({a, i}) when (is_atom(a) and is_integer(i)) do
    {a, div(i, 1000)}
  end

  defp ticktime_res(i) when is_integer(i) do
    div(i, 1000)
  end

  defp ticktime_res(a) when is_atom(a) do
    a
  end

  def passive_cnct(node) do
    case (request({:passive_cnct, node})) do
      :ignored ->
        false
      other ->
        other
    end
  end

  def disconnect(node) do
    request({:disconnect, node})
  end

  def async_disconnect(node) do
    :gen_server.cast(:net_kernel, {:async_disconnect, node})
  end

  def publish_on_node(node) when is_atom(node) do
    :global_group.publish(:persistent_term.get({:net_kernel,
                                                  :publish_type},
                                                 :hidden),
                            node)
  end

  def connect_node(node) when is_atom(node) do
    request({:connect, :normal, node})
  end

  def hidden_connect_node(node) when is_atom(node) do
    request({:connect, :hidden, node})
  end

  def passive_connect_monitor(from, node) do
    :ok = monitor_nodes(true, [{:node_type, :all}])
    reply = (case (:lists.member(node,
                                   :erlang.nodes([:connected]))) do
               true ->
                 true
               _ ->
                 receive do
                   {:nodeup, ^node, _} ->
                     true
                 after connecttime() ->
                   false
                 end
             end)
    :ok = monitor_nodes(false, [{:node_type, :all}])
    {pid, tag} = from
    :erlang.send(pid, {tag, reply})
  end

  defp request(req) do
    case (:erlang.whereis(:net_kernel)) do
      p when is_pid(p) ->
        try do
          :gen_server.call(:net_kernel, req, :infinity)
        catch
          :exit, {reason, _} when reason === :noproc or
                                    reason === :shutdown or reason === :killed
                                  ->
            retry_request_maybe(req)
        end
      _ ->
        retry_request_maybe(req)
    end
  end

  defp retry_request_maybe(req) do
    case (:erts_internal.dynamic_node_name()) do
      true ->
        receive do after 100 ->
          :ok
        end
        request(req)
      false ->
        :ignored
    end
  end

  def start(name, options) when (is_atom(name) and
                                is_map(options)) do
    try do
      :maps.foreach(fn :name_domain, val
                           when val == :shortnames or val == :longnames ->
                         :ok
                       :net_ticktime, val when (is_integer(val) and val > 0) ->
                         :ok
                       :net_tickintensity, val when (is_integer(val) and
                                                       4 <= val and val <= 1000)
                                                    ->
                         :ok
                       :dist_listen, val when is_boolean(val) ->
                         :ok
                       :hidden, val when is_boolean(val) ->
                         :ok
                       opt, val ->
                         :erlang.error({:invalid_option, opt, val})
                    end,
                      options)
    catch
      :error, reason ->
        :erlang.error(reason, [name, options])
    end
    :erl_distribution.start(Map.put(options, :name, name))
  end

  def start(name, options) when is_map(options) do
    :erlang.error(:invalid_name, [name, options])
  end

  def start(name, options) do
    :erlang.error(:invalid_options, [name, options])
  end

  def start([name]) when is_atom(name) do
    start([name, :longnames, 15000])
  end

  def start([name, nameDomain]) when (is_atom(name) and
                                     is_atom(nameDomain)) do
    start([name, nameDomain, 15000])
  end

  def start([name, nameDomain, tickTime])
      when (is_atom(name) and is_atom(nameDomain) and
              is_integer(tickTime) and tickTime > 0) do
    netTickTime = div(tickTime * 4 - 1, 1000) + 1
    start(name,
            %{name_domain: nameDomain, net_ticktime: netTickTime,
                net_tickintensity: 4})
  end

  def start_link(startOpts) do
    case (:gen_server.start_link({:local, :net_kernel},
                                   :net_kernel, make_init_opts(startOpts),
                                   [])) do
      {:ok, pid} ->
        {:ok, pid}
      {:error, {:already_started, pid}} ->
        {:ok, pid}
      _Error ->
        exit(:nodistribution)
    end
  end

  defp make_init_opts(opts) do
    nTT1 = (case (:maps.find(:net_ticktime, opts)) do
              {:ok, nTT0} ->
                nTT0 * 1000
              :error ->
                case (:application.get_env(:kernel, :net_ticktime)) do
                  {:ok, nTT0} when (is_integer(nTT0) and nTT0 < 1) ->
                    1000
                  {:ok, nTT0} when is_integer(nTT0) ->
                    nTT0 * 1000
                  _ ->
                    60000
                end
            end)
    nTI = (case (:maps.find(:net_tickintensity, opts)) do
             {:ok, nTI0} ->
               nTI0
             :error ->
               case (:application.get_env(:kernel,
                                            :net_tickintensity)) do
                 {:ok, nTI0} when (is_integer(nTI0) and nTI0 < 4) ->
                   4
                 {:ok, nTI0} when (is_integer(nTI0) and nTI0 > 1000) ->
                   1000
                 {:ok, nTI0} when is_integer(nTI0) ->
                   nTI0
                 _ ->
                   4
               end
           end)
    nTT = (cond do
             rem(nTT1, nTI) === 0 ->
               nTT1
             true ->
               (div(nTT1, nTI) + 1) * nTI
           end)
    nD = (case (:maps.find(:name_domain, opts)) do
            {:ok, nD0} ->
              nD0
            :error ->
              :longnames
          end)
    dL = (case (split_node(:maps.get(:name, opts))) do
            {'undefined', _} ->
              false
            _ ->
              case (:maps.find(:dist_listen, opts)) do
                :error ->
                  dist_listen_argument()
                {:ok, false} ->
                  false
                _ ->
                  true
              end
          end)
    h = (case (dL) do
           false ->
             true
           true ->
             case (:maps.find(:hidden, opts)) do
               :error ->
                 hidden_argument()
               {:ok, true} ->
                 true
               _ ->
                 false
             end
         end)
    Map.merge(opts, %{net_ticktime: nTT,
                        net_tickintensity: nTI, name_domain: nD,
                        dist_listen: dL, hidden: h})
  end

  def init(%{name: name, name_domain: nameDomain,
             net_ticktime: netTicktime,
             net_tickintensity: netTickIntensity,
             clean_halt: cleanHalt, supervisor: supervisor,
             dist_listen: distListen, hidden: hidden}) do
    _ = :erlang.process_flag(:async_dist, true)
    :erlang.process_flag(:trap_exit, true)
    :persistent_term.put({:net_kernel, :publish_type},
                           cond do
                             hidden ->
                               :hidden
                             true ->
                               :normal
                           end)
    case (init_node(name, nameDomain, cleanHalt,
                      distListen)) do
      {:ok, node, listeners} ->
        :erlang.process_flag(:priority, :max)
        tickInterval = div(netTicktime, netTickIntensity)
        ticker = spawn_link(:net_kernel, :ticker,
                              [self(), tickInterval])
        {:ok,
           r_state(node: node, type: nameDomain,
               tick: r_tick(ticker: ticker, time: netTicktime,
                         intensity: netTickIntensity),
               connecttime: connecttime(),
               connections: :ets.new(:sys_dist,
                                       [:named_table, :protected, {:keypos,
                                                                     r_connection(:node)}]),
               listen: listeners, allowed: [], verbose: 0,
               supervisor: supervisor)}
      error ->
        _ = :persistent_term.erase({:net_kernel, :publish_type})
        :erts_internal.dynamic_node_name(false)
        {:stop, error}
    end
  end

  defp do_auto_connect_1(node, connId, from, state) do
    case (:ets.lookup(:sys_dist, node)) do
      [r_barred_connection()] ->
        case (connId) do
          :passive_cnct ->
            spawn(:net_kernel, :passive_connect_monitor,
                    [from, node])
            {:noreply, state}
          _ ->
            :erts_internal.abort_pending_connection(node, connId)
            {:reply, false, state}
        end
      connLookup ->
        do_auto_connect_2(node, connId, from, state, connLookup)
    end
  end

  defp do_auto_connect_2(node, :passive_cnct, from, state, connLookup) do
    try do
      :erts_internal.new_connection(node)
    catch
      _, _ ->
        :error_logger.error_msg('~n** Cannot get connection id for node ~w~n', [node])
        {:reply, false, state}
    else
      connId ->
        do_auto_connect_2(node, connId, from, state, connLookup)
    end
  end

  defp do_auto_connect_2(node, connId, from, state, connLookup) do
    case (connLookup) do
      [r_connection(conn_id: ^connId, state: :up)] ->
        {:reply, true, state}
      [r_connection(conn_id: ^connId, waiting: waiting) = conn] ->
        case (from) do
          :noreply ->
            :ok
          _ ->
            :ets.insert(:sys_dist,
                          r_connection(conn, waiting: [from | waiting]))
        end
        {:noreply, state}
      _ ->
        case (:application.get_env(:kernel,
                                     :dist_auto_connect)) do
          {:ok, :never} ->
            :noop
            :erts_internal.abort_pending_connection(node, connId)
            {:reply, false, state}
          {:ok, :once} when (connLookup !== [] and
                               r_connection(hd(connLookup), :state) === :up)
                            ->
            :noop
            {:reply, false, state}
          _ ->
            case (setup(node, connId, :normal, from, state)) do
              {:ok, setupPid} ->
                owners = r_state(state, :conn_owners)
                {:noreply,
                   r_state(state, conn_owners: Map.put(owners, setupPid, node))}
              _Error ->
                :noop
                :erts_internal.abort_pending_connection(node, connId)
                {:reply, false, state}
            end
        end
    end
  end

  defp do_explicit_connect([r_connection(conn_id: connId, state: :up)], _, _, connId,
            _From, state) do
    {:reply, true, state}
  end

  defp do_explicit_connect([r_connection(conn_id: connId) = conn], _, _, connId, from,
            state)
      when r_connection(conn, :state) === :pending or
             r_connection(conn, :state) === :up_pending do
    waiting = r_connection(conn, :waiting)
    :ets.insert(:sys_dist,
                  r_connection(conn, waiting: [from | waiting]))
    {:noreply, state}
  end

  defp do_explicit_connect([r_barred_connection()], type, node, connId, from, state) do
    do_explicit_connect([], type, node, connId, from, state)
  end

  defp do_explicit_connect(_ConnLookup, type, node, connId, from, state) do
    case (setup(node, connId, type, from, state)) do
      {:ok, setupPid} ->
        owners = r_state(state, :conn_owners)
        {:noreply,
           r_state(state, conn_owners: Map.put(owners, setupPid, node))}
      _Error ->
        :noop
        {:reply, false, state}
    end
  end

  def handle_call({:passive_cnct, node}, from, state)
      when node === node() do
    async_reply({:reply, true, state}, from)
  end

  def handle_call({:passive_cnct, node}, from, state) do
    verbose({:passive_cnct, node}, 1, state)
    r = do_auto_connect_1(node, :passive_cnct, from, state)
    return_call(r, from)
  end

  def handle_call({:connect, _, node}, from, state)
      when node === node() do
    async_reply({:reply, true, state}, from)
  end

  def handle_call({:connect, _Type, _Node}, _From,
           r_state(supervisor: {:restart, _}) = state) do
    {:noreply, state}
  end

  def handle_call({:connect, type, node}, from, state) do
    verbose({:connect, type, node}, 1, state)
    connLookup = :ets.lookup(:sys_dist, node)
    r = (try do
           :erts_internal.new_connection(node)
         catch
           _, _ ->
             :error_logger.error_msg('~n** Cannot get connection id for node ~w~n', [node])
             {:reply, false, state}
         else
           connId ->
             r1 = do_explicit_connect(connLookup, type, node, connId,
                                        from, state)
             case (r1) do
               {:reply, true, _S} ->
                 :ok
               {:noreply, _S} ->
                 :ok
               {:reply, false, _S} ->
                 :erts_internal.abort_pending_connection(node, connId)
             end
             r1
         end)
    return_call(r, from)
  end

  def handle_call({:disconnect, node}, from, state)
      when node === node() do
    async_reply({:reply, false, state}, from)
  end

  def handle_call({:disconnect, node}, from, state) do
    verbose({:disconnect, node}, 1, state)
    {reply, state1} = do_disconnect(node, state, false)
    async_reply({:reply, reply, state1}, from)
  end

  def handle_call({:spawn, m, f, a, gleader}, {from, tag}, state)
      when is_pid(from) do
    do_spawn([:no_link, {from, tag}, m, f, a, gleader], [],
               state)
  end

  def handle_call({:spawn_link, m, f, a, gleader}, {from, tag},
           state)
      when is_pid(from) do
    do_spawn([:link, {from, tag}, m, f, a, gleader], [],
               state)
  end

  def handle_call({:spawn_opt, m, f, a, o, l, gleader},
           {from, tag}, state)
      when is_pid(from) do
    do_spawn([l, {from, tag}, m, f, a, gleader], o, state)
  end

  def handle_call({:allow, nodes}, from, state) do
    case (all_atoms(nodes)) do
      true ->
        allowed = r_state(state, :allowed)
        async_reply({:reply, :ok,
                       r_state(state, allowed: allowed ++ nodes)},
                      from)
      false ->
        async_reply({:reply, :error, state}, from)
    end
  end

  def handle_call(:allowed, from, r_state(allowed: allowed) = state) do
    async_reply({:reply, {:ok, allowed}, state}, from)
  end

  def handle_call({:is_auth, _Node}, from, state) do
    async_reply({:reply, :yes, state}, from)
  end

  def handle_call({:apply, _Mod, _Fun, _Args}, {pid, _Tag} = from,
           state)
      when (is_pid(pid) and node(pid) === node()) do
    async_reply({:reply, :not_implemented, state}, from)
  end

  def handle_call(:longnames, from, state) do
    async_reply({:reply, :erlang.get(:longnames), state},
                  from)
  end

  def handle_call(:nodename, from, state) do
    async_reply({:reply, r_state(state, :node), state}, from)
  end

  def handle_call({:verbose, level}, from, state) do
    async_reply({:reply, r_state(state, :verbose),
                   r_state(state, verbose: level)},
                  from)
  end

  def handle_call(:ticktime, from, r_state(tick: r_tick(time: t)) = state) do
    async_reply({:reply, t, state}, from)
  end

  def handle_call(:ticktime, from, r_state(tick: r_tick_change(time: t)) = state) do
    async_reply({:reply, {:ongoing_change_to, t}, state},
                  from)
  end

  def handle_call({:new_ticktime, t, _TP}, from,
           r_state(tick: r_tick(time: t)) = state) do
    :ok
    async_reply({:reply, :unchanged, state}, from)
  end

  def handle_call({:new_ticktime, t, tP}, from,
           r_state(tick: r_tick(ticker: tckr, time: oT,
                       intensity: i)) = state) do
    :ok
    {nT, nIntrvl} = (case (t < i) do
                       true ->
                         {i, 1}
                       _ ->
                         nIntrvl0 = div(t, i)
                         case (rem(t, i)) do
                           0 ->
                             {t, nIntrvl0}
                           _ ->
                             {(nIntrvl0 + 1) * i, nIntrvl0 + 1}
                         end
                     end)
    case (nT == oT) do
      true ->
        async_reply({:reply, :unchanged, state}, from)
      false ->
        start_aux_ticker(nIntrvl, div(oT, i), tP)
        how = (case (nT > oT) do
                 true ->
                   :ok
                   send(tckr, {:new_ticktime, nIntrvl})
                   :longer
                 false ->
                   :ok
                   :shorter
               end)
        async_reply({:reply, :change_initiated,
                       r_state(state, tick: r_tick_change(ticker: tckr, time: nT, intensity: i,
                                          how: how))},
                      from)
    end
  end

  def handle_call({:new_ticktime, _T, _TP}, from,
           r_state(tick: r_tick_change(time: t)) = state) do
    async_reply({:reply, {:ongoing_change_to, t}, state},
                  from)
  end

  def handle_call({:setopts, :new, opts}, from, state) do
    setopts_new(opts, from, state)
  end

  def handle_call({:setopts, node, opts}, from, state) do
    opts_node(:setopts, node, opts, from, state)
  end

  def handle_call({:getopts, node, opts}, from, state) do
    opts_node(:getopts, node, opts, from, state)
  end

  def handle_call(:get_state, from, state) do
    started = (case (r_state(state, :supervisor)) do
                 :net_sup ->
                   :static
                 _ ->
                   :dynamic
               end)
    {nameType,
       name} = (case ({:erts_internal.dynamic_node_name(),
                         node()}) do
                  {false, node} ->
                    {:static, node}
                  {true, :nonode@nohost} ->
                    {:dynamic, :undefined}
                  {true, node} ->
                    {:dynamic, node}
                end)
    nameDomain = (case (:erlang.get(:longnames)) do
                    true ->
                      :longnames
                    false ->
                      :shortnames
                  end)
    return = %{started: started, name_type: nameType,
                 name: name, name_domain: nameDomain}
    async_reply({:reply, return, state}, from)
  end

  def handle_call(_Msg, _From, state) do
    {:noreply, state}
  end

  def handle_cast({:async_disconnect, node}, state)
      when node === node() do
    {:noreply, state}
  end

  def handle_cast({:async_disconnect, node}, state) do
    verbose({:async_disconnect, node}, 1, state)
    {_Reply, state1} = do_disconnect(node, state, true)
    {:noreply, state1}
  end

  def handle_cast(_, state) do
    {:noreply, state}
  end

  def code_change(_OldVsn, state, _Extra) do
    {:ok, state}
  end

  def terminate(reason, state) do
    case (state) do
      r_state(supervisor: {:restart, _}) ->
        :ok
      _ ->
        _ = :persistent_term.erase({:net_kernel, :publish_type})
        :erts_internal.dynamic_node_name(false)
    end
    case (reason) do
      :no_network ->
        :ok
      _ ->
        :lists.foreach(fn r_listen(listen: listen, module: mod) ->
                            case (listen) do
                              :undefined ->
                                :ignore
                              _ ->
                                mod.close(listen)
                            end
                       end,
                         r_state(state, :listen))
    end
    :lists.foreach(fn node ->
                        verbose({:net_kernel, 960, :nodedown, node}, 1, state)
                   end,
                     get_nodes_up_normal() ++ [node()])
  end

  def handle_info({:auto_connect, node, dHandle}, state) do
    verbose({:auto_connect, node, dHandle}, 1, state)
    connId = dHandle
    newState = (case (do_auto_connect_1(node, connId,
                                          :noreply, state)) do
                  {:noreply, s} ->
                    s
                  {:reply, true, s} ->
                    s
                  {:reply, false, s} ->
                    s
                end)
    {:noreply, newState}
  end

  def handle_info({:accept, acceptPid, socket, family,
            proto} = accept,
           state) do
    case (get_proto_mod(family, proto,
                          r_state(state, :listen))) do
      {:ok, mod} ->
        pid = mod.accept_connection(acceptPid, socket,
                                      r_state(state, :node), r_state(state, :allowed),
                                      r_state(state, :connecttime))
        verbose({accept, pid}, 2, state)
        send(acceptPid, {self(), :controller, pid})
        {:noreply, state}
      _ ->
        verbose({accept, :unsupported_protocol}, 2, state)
        send(acceptPid, {self(), :unsupported_protocol})
        {:noreply, state}
    end
  end

  def handle_info({:dist_ctrlr, ctrlr, node, setupPid} = msg,
           r_state(dist_ctrlrs: distCtrlrs) = state) do
    case (:ets.lookup(:sys_dist, node)) do
      [conn]
          when r_connection(conn, :state) === :pending and r_connection(conn, :owner) === setupPid and r_connection(conn, :ctrlr) === :undefined and (is_port(ctrlr) or is_pid(ctrlr)) and node(ctrlr) == node()
               ->
        :erlang.link(ctrlr)
        verbose(msg, 2, state)
        :ets.insert(:sys_dist, r_connection(conn, ctrlr: ctrlr))
        {:noreply,
           r_state(state, dist_ctrlrs: Map.put(distCtrlrs, ctrlr, node))}
      _ ->
        error_msg('Net kernel got ~tw~n', [msg])
        {:noreply, state}
    end
  end

  def handle_info({setupPid,
            {:nodeup, node, address, type, namedMe} = nodeup},
           r_state(tick: tick) = state) do
    case (:ets.lookup(:sys_dist, node)) do
      [conn]
          when r_connection(conn, :state) === :pending and r_connection(conn, :owner) === setupPid and r_connection(conn, :ctrlr) != :undefined
               ->
        :ets.insert(:sys_dist,
                      r_connection(conn, state: :up,  address: address,  waiting: [], 
                                type: type,  named_me: namedMe))
        tickIntensity = (case (tick) do
                           r_tick(intensity: tI) ->
                             tI
                           r_tick_change(intensity: tI) ->
                             tI
                         end)
        send(setupPid, {self(), :inserted, tickIntensity})
        reply_waiting(node, r_connection(conn, :waiting), true)
        state1 = (case (namedMe) do
                    true ->
                      r_state(state, node: node())
                    false ->
                      state
                  end)
        verbose(nodeup, 1, state1)
        verbose({:nodeup, node, setupPid, r_connection(conn, :ctrlr)}, 2,
                  state1)
        {:noreply, state1}
      _ ->
        send(setupPid, {self(), :bad_request})
        {:noreply, state}
    end
  end

  def handle_info({acceptPid,
            {:accept_pending, myNode, nodeOrHost, type}},
           state0) do
    {nameType, node, creation, connLookup,
       state} = ensure_node_name(nodeOrHost, state0)
    case (connLookup) do
      [r_connection(state: :pending) = conn] ->
        cond do
          myNode > node ->
            send(acceptPid, {self(),
                               {:accept_pending, :nok_pending}})
            verbose({:accept_pending_nok, node, acceptPid}, 2,
                      state)
            {:noreply, state}
          true ->
            oldOwner = r_connection(conn, :owner)
            case (:maps.is_key(oldOwner, r_state(state, :conn_owners))) do
              true ->
                verbose({:remark, oldOwner, acceptPid}, 2, state)
                :ok
                :erlang.exit(oldOwner, :remarked)
                receive do
                  {:EXIT, ^oldOwner, _} = exit ->
                    verbose(exit, 2, state)
                    true
                end
              false ->
                verbose({:accept_pending, oldOwner, :inconsistency}, 2,
                          state)
                :ok
            end
            :ets.insert(:sys_dist, r_connection(conn, owner: acceptPid))
            send(acceptPid, {self(),
                               {:accept_pending, :ok_pending}})
            owners = :maps.remove(oldOwner, r_state(state, :conn_owners))
            {:noreply,
               r_state(state, conn_owners: Map.put(owners, acceptPid, node))}
        end
      [r_connection(state: :up) = conn] ->
        send(acceptPid, {self(),
                           {:accept_pending, :up_pending}})
        :ets.insert(:sys_dist,
                      r_connection(conn, pending_owner: acceptPid,  state: :up_pending))
        pend = r_state(state, :pend_owners)
        {:noreply,
           r_state(state, pend_owners: Map.put(pend, acceptPid, node))}
      [r_connection(state: :up_pending)] ->
        send(acceptPid, {self(),
                           {:accept_pending, :already_pending}})
        {:noreply, state}
      _ ->
        try do
          :erts_internal.new_connection(node)
        catch
          _, _ ->
            :error_logger.error_msg('~n** Cannot get connection id for node ~w~n', [node])
            send(acceptPid, {self(),
                               {:accept_pending, :nok_pending}})
            {:noreply, state}
        else
          connId ->
            :ets.insert(:sys_dist,
                          r_connection(node: node, conn_id: connId, state: :pending,
                              owner: acceptPid, type: type,
                              remote_name_type: nameType, creation: creation))
            ret = (case (nameType) do
                     :static ->
                       :ok
                     :dynamic ->
                       {:ok, node, creation}
                   end)
            send(acceptPid, {self(), {:accept_pending, ret}})
            owners = r_state(state, :conn_owners)
            {:noreply,
               r_state(state, conn_owners: Map.put(owners, acceptPid, node))}
        end
    end
  end

  def handle_info({setupPid, {:is_pending, node}}, state) do
    reply = (case (:maps.get(setupPid,
                               r_state(state, :conn_owners), :undefined)) do
               ^node ->
                 true
               _ ->
                 false
             end)
    send(setupPid, {self(), {:is_pending, reply}})
    {:noreply, state}
  end

  def handle_info({acceptPid, {:wait_pending, node}}, state) do
    case (get_conn(node)) do
      {:ok,
         r_connection(state: :up_pending, ctrlr: oldCtrlr,
             pending_owner: ^acceptPid)} ->
        :ok
        :erlang.exit(oldCtrlr, :wait_pending)
      _ ->
        :ignore
    end
    {:noreply, state}
  end

  def handle_info({reqId, reply}, r_state(req_map: reqMap) = s)
      when :erlang.is_map_key(reqId, reqMap) do
    handle_async_response(:reply, reqId, reply, s)
  end

  def handle_info({:DOWN, reqId, :process, _Pid, reason},
           r_state(req_map: reqMap) = s)
      when :erlang.is_map_key(reqId, reqMap) do
    handle_async_response(:down, reqId, reason, s)
  end

  def handle_info({:EXIT, from, reason}, state) do
    handle_exit(from, reason, state)
  end

  def handle_info({from, :registered_send, to, mess}, state) do
    send(from, to, mess)
    {:noreply, state}
  end

  def handle_info({from, :badcookie, _To, _Mess}, state) do
    :error_logger.error_msg('~n** Got OLD cookie from ~w~n', [getnode(from)])
    {_Reply, state1} = do_disconnect(getnode(from), state,
                                       false)
    {:noreply, state1}
  end

  def handle_info(:tick, state) do
    :ok
    :maps.foreach(fn pid, _Node ->
                       send(pid, {self(), :tick})
                  end,
                    r_state(state, :conn_owners))
    {:noreply, state}
  end

  def handle_info(:aux_tick, state) do
    :ok
    :maps.foreach(fn pid, _Node ->
                       send(pid, {self(), :aux_tick})
                  end,
                    r_state(state, :conn_owners))
    {:noreply, state}
  end

  def handle_info(:transition_period_end,
           r_state(tick: r_tick_change(ticker: tckr, time: t, intensity: i,
                       how: how)) = state) do
    :ok
    case (how) do
      :shorter ->
        interval = div(t, i)
        send(tckr, {:new_ticktime, interval})
        :ok
      _ ->
        :ok
    end
    {:noreply,
       r_state(state, tick: r_tick(ticker: tckr, time: t, intensity: i))}
  end

  def handle_info(x, state) do
    error_msg('Net kernel got ~tw~n', [x])
    {:noreply, state}
  end

  defp ensure_node_name(node, state) when is_atom(node) do
    {:static, node, :undefined,
       :ets.lookup(:sys_dist, node), state}
  end

  defp ensure_node_name(host, state0) when is_list(host) do
    case (:string.split(host, '@', :all)) do
      [^host] ->
        {node, creation, state1} = generate_node_name(host,
                                                        state0)
        case (:ets.lookup(:sys_dist, node)) do
          [r_connection()] ->
            ensure_node_name(host, state1)
          connLookup ->
            {:dynamic, node, creation, connLookup, state1}
        end
      _ ->
        {:error, host, :undefined, [], state0}
    end
  end

  defp generate_node_name(host, state0) do
    namePool = r_state(state0, :dyn_name_pool)
    case (:maps.get(host, namePool, [])) do
      [] ->
        name = :erlang.integer_to_list(:rand.uniform(1 <<< 64),
                                         36)
        {:erlang.list_to_atom(name ++ '@' ++ host),
           create_creation(), state0}
      [{node, creation} | rest] ->
        {node, creation,
           r_state(state0, dyn_name_pool: Map.put(namePool, host, rest))}
    end
  end

  defp handle_exit(pid, reason, state) do
    (try do
      do_handle_exit(pid, reason, state)
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end)
  end

  defp do_handle_exit(pid, reason, state) do
    listen_exit(pid, reason, state)
    accept_exit(pid, reason, state)
    conn_own_exit(pid, reason, state)
    dist_ctrlr_exit(pid, reason, state)
    pending_own_exit(pid, reason, state)
    ticker_exit(pid, reason, state)
    restarter_exit(pid, reason, state)
    verbose({:EXIT, pid, reason}, 2, state)
    {:noreply, state}
  end

  defp listen_exit(pid, reason, state) do
    case (:lists.keymember(pid, r_listen(:listen),
                             r_state(state, :listen))) do
      true ->
        verbose({:listen_exit, pid, reason}, 2, state)
        error_msg('** Netkernel terminating ... **\n', [])
        throw({:stop, :no_network, state})
      false ->
        false
    end
  end

  defp accept_exit(pid, reason, state) do
    listen = r_state(state, :listen)
    case (:lists.keysearch(pid, r_listen(:accept), listen)) do
      {:value, listenR} ->
        listenS = r_listen(listenR, :listen)
        mod = r_listen(listenR, :module)
        verbose({:accept_exit, pid, reason, mod}, 2, state)
        acceptPid = mod.accept(listenS)
        l = :lists.keyreplace(pid, r_listen(:accept), listen,
                                r_listen(listenR, accept: acceptPid))
        throw({:noreply, r_state(state, listen: l)})
      _ ->
        false
    end
  end

  defp conn_own_exit(pid, reason, r_state(conn_owners: owners) = state) do
    case (:maps.get(pid, owners, :undefined)) do
      :undefined ->
        false
      node ->
        verbose({:conn_own_exit, pid, reason, node}, 2, state)
        throw({:noreply, nodedown(pid, node, reason, state)})
    end
  end

  defp dist_ctrlr_exit(pid, reason, r_state(dist_ctrlrs: dCs) = state) do
    case (:maps.get(pid, dCs, :undefined)) do
      :undefined ->
        false
      node ->
        verbose({:dist_ctrlr_exit, pid, reason, node}, 2, state)
        throw({:noreply, nodedown(pid, node, reason, state)})
    end
  end

  defp pending_own_exit(pid, reason, r_state(pend_owners: pend) = state) do
    case (:maps.get(pid, pend, :undefined)) do
      :undefined ->
        false
      node ->
        state1 = r_state(state, pend_owners: :maps.remove(pid, pend))
        case (get_conn(node)) do
          {:ok, conn} when r_connection(conn, :state) === :up_pending ->
            verbose({:pending_own_exit, pid, reason, node,
                       :up_pending},
                      2, state)
            reply_waiting(node, r_connection(conn, :waiting), true)
            conn1 = r_connection(conn, state: :up,  waiting: [], 
                              pending_owner: :undefined)
            :ets.insert(:sys_dist, conn1)
          _ ->
            verbose({:pending_own_exit, pid, reason, node}, 2,
                      state)
            :ok
        end
        throw({:noreply, state1})
    end
  end

  defp ticker_exit(pid, reason,
            r_state(tick: r_tick(ticker: pid, time: t) = tck) = state) do
    verbose({:ticker_exit, pid, reason, tck}, 2, state)
    tckr = restart_ticker(t)
    throw({:noreply, r_state(state, tick: r_tick(tck, ticker: tckr))})
  end

  defp ticker_exit(pid, reason,
            r_state(tick: r_tick_change(ticker: pid, time: t) = tckCng) = state) do
    verbose({:ticker_exit, pid, reason, tckCng}, 2, state)
    tckr = restart_ticker(t)
    throw({:noreply, reason,
             r_state(state, tick: r_tick_change(tckCng, ticker: tckr))})
  end

  defp ticker_exit(_, _, _) do
    false
  end

  defp restarter_exit(pid, reason, state) do
    case (r_state(state, :supervisor)) do
      {:restart, ^pid} ->
        verbose({:restarter_exit, pid, reason}, 2, state)
        error_msg('** Distribution restart failed, net_kernel terminating... **\n', [])
        throw({:stop, :restarter_exit, state})
      _ ->
        false
    end
  end

  defp nodedown(exited, node, reason, state) do
    case (get_conn(node)) do
      {:ok, conn} ->
        nodedown(conn, exited, node, reason, r_connection(conn, :type),
                   state)
      _ ->
        state
    end
  end

  defp get_conn(node) do
    case (:ets.lookup(:sys_dist, node)) do
      [conn = r_connection()] ->
        {:ok, conn}
      _ ->
        :error
    end
  end

  defp delete_owner(owner, r_state(conn_owners: owners) = state) do
    r_state(state, conn_owners: :maps.remove(owner, owners))
  end

  defp delete_ctrlr(ctrlr, r_state(dist_ctrlrs: dCs) = state) do
    r_state(state, dist_ctrlrs: :maps.remove(ctrlr, dCs))
  end

  defp nodedown(conn, exited, node, reason, type, state) do
    case (r_connection(conn, :state)) do
      :pending ->
        pending_nodedown(conn, exited, node, type, state)
      :up ->
        up_nodedown(conn, exited, node, reason, type, state)
      :up_pending ->
        up_pending_nodedown(conn, exited, node, reason, type,
                              state)
      _ ->
        state
    end
  end

  defp pending_nodedown(r_connection(owner: owner, waiting: waiting,
              conn_id: cID) = conn,
            exited, node, type, state0)
      when owner === exited do
    state2 = (case (:erts_internal.abort_pending_connection(node,
                                                              cID)) do
                false ->
                  state0
                true ->
                  state1 = delete_connection(conn, false, state0)
                  reply_waiting(node, waiting, false)
                  case (type) do
                    :normal ->
                      verbose({:net_kernel, 1441, :nodedown, node}, 1, state1)
                    _ ->
                      :ok
                  end
                  state1
              end)
    delete_owner(owner, state2)
  end

  defp pending_nodedown(r_connection(owner: owner, ctrlr: ctrlr,
              waiting: waiting) = conn,
            exited, node, type, state0)
      when ctrlr === exited do
    state1 = delete_connection(conn, true, state0)
    reply_waiting(node, waiting, true)
    case (type) do
      :normal ->
        verbose({:net_kernel, 1463, :nodedown, node}, 1, state1)
      _ ->
        :ok
    end
    delete_owner(owner, delete_ctrlr(ctrlr, state1))
  end

  defp pending_nodedown(_Conn, _Exited, _Node, _Type, state) do
    state
  end

  defp up_pending_nodedown(r_connection(owner: owner, ctrlr: ctrlr,
              pending_owner: acceptPid) = conn,
            exited, node, _Reason, _Type, state)
      when ctrlr === exited do
    conn1 = r_connection(conn, owner: acceptPid, 
                      conn_id: :erts_internal.new_connection(node), 
                      ctrlr: :undefined,  pending_owner: :undefined, 
                      state: :pending)
    :ets.insert(:sys_dist, conn1)
    send(acceptPid, {self(), :pending})
    pend = :maps.remove(acceptPid, r_state(state, :pend_owners))
    owners = r_state(state, :conn_owners)
    state1 = r_state(state, conn_owners: Map.put(owners, acceptPid,
                                                     node), 
                        pend_owners: pend)
    delete_owner(owner, delete_ctrlr(ctrlr, state1))
  end

  defp up_pending_nodedown(r_connection(owner: owner), exited, _Node, _Reason, _Type,
            state)
      when owner === exited do
    delete_owner(owner, state)
  end

  defp up_pending_nodedown(_Conn, _Exited, _Node, _Reason, _Type, state) do
    state
  end

  defp up_nodedown(r_connection(owner: owner, ctrlr: ctrlr) = conn, exited,
            node, _Reason, type, state0)
      when ctrlr === exited do
    state1 = delete_connection(conn, true, state0)
    case (type) do
      :normal ->
        verbose({:net_kernel, 1503, :nodedown, node}, 1, state1)
      _ ->
        :ok
    end
    delete_owner(owner, delete_ctrlr(ctrlr, state1))
  end

  defp up_nodedown(r_connection(owner: owner), exited, _Node, _Reason, _Type,
            state)
      when owner === exited do
    delete_owner(owner, state)
  end

  defp up_nodedown(_Conn, _Exited, _Node, _Reason, _Type, state) do
    state
  end

  defp delete_connection(r_connection(named_me: true), _, state) do
    restart_distr(state)
  end

  defp delete_connection(r_connection(node: node) = conn, mayBeBarred, state) do
    barrIt = mayBeBarred and (case (:application.get_env(:kernel,
                                                           :dist_auto_connect)) do
                                {:ok, :once} ->
                                  true
                                _ ->
                                  false
                              end)
    case (barrIt) do
      true ->
        :ets.insert(:sys_dist, r_barred_connection(node: node))
      _ ->
        :ets.delete(:sys_dist, node)
    end
    case (r_connection(conn, :remote_name_type)) do
      :dynamic ->
        [_Name,
             host] = :string.split(:erlang.atom_to_list(node), '@',
                                     :all)
        namePool0 = r_state(state, :dyn_name_pool)
        dynNames = :maps.get(host, namePool0, [])
        false = :lists.keyfind(node, 1, dynNames)
        freeName = {node, next_creation(r_connection(conn, :creation))}
        namePool1 = Map.put(namePool0, host,
                                         [freeName | dynNames])
        r_state(state, dyn_name_pool: namePool1)
      :static ->
        state
    end
  end

  defp restart_distr(state) do
    restarter = spawn_link(fn () ->
                                restart_distr_do(r_state(state, :supervisor))
                           end)
    r_state(state, supervisor: {:restart, restarter})
  end

  defp restart_distr_do(netSup) do
    :erlang.process_flag(:trap_exit, true)
    :ok = :supervisor.terminate_child(:kernel_sup, netSup)
    case (:supervisor.restart_child(:kernel_sup, netSup)) do
      {:ok, pid} when is_pid(pid) ->
        :ok
    end
  end

  defp check_opt(opt, opts) do
    check_opt(opt, opts, false, [])
  end

  defp check_opt(_Opt, [], false, _OtherOpts) do
    false
  end

  defp check_opt(_Opt, [], {true, oRes}, otherOpts) do
    {true, oRes, otherOpts}
  end

  defp check_opt(opt, [opt | restOpts], false, otherOpts) do
    check_opt(opt, restOpts, {true, opt}, otherOpts)
  end

  defp check_opt(opt, [opt | restOpts], {true, opt} = oRes,
            otherOpts) do
    check_opt(opt, restOpts, oRes, otherOpts)
  end

  defp check_opt({opt, :value} = tOpt,
            [{opt, _Val} = oRes | restOpts], false, otherOpts) do
    check_opt(tOpt, restOpts, {true, oRes}, otherOpts)
  end

  defp check_opt({opt, :value} = tOpt,
            [{opt, _Val} = oRes | restOpts], {true, oRes} = tORes,
            otherOpts) do
    check_opt(tOpt, restOpts, tORes, otherOpts)
  end

  defp check_opt({opt, :value},
            [{opt, _Val} = oRes1 | _RestOpts],
            {true, {opt, _OtherVal} = oRes2}, _OtherOpts) do
    throw({:error,
             {:option_value_mismatch, [oRes1, oRes2]}})
  end

  defp check_opt(opt, [otherOpt | restOpts], tORes, otherOpts) do
    check_opt(opt, restOpts, tORes, [otherOpt | otherOpts])
  end

  defp check_options(opts) when is_list(opts) do
    restOpts1 = (case (check_opt({:node_type, :value},
                                   opts)) do
                   {true, {:node_type, type}, rO1}
                       when type === :visible or type === :hidden or
                              type === :all
                            ->
                     rO1
                   {true, {:node_type, _Type} = opt, _RO1} ->
                     throw({:error, {:bad_option_value, opt}})
                   false ->
                     opts
                 end)
    restOpts2 = (case (check_opt(:nodedown_reason,
                                   restOpts1)) do
                   {true, :nodedown_reason, rO2} ->
                     rO2
                   false ->
                     restOpts1
                 end)
    case (restOpts2) do
      [] ->
        {:error, :internal_error}
      _ ->
        {:error, {:unknown_options, restOpts2}}
    end
  end

  defp check_options(opts) when is_map(opts) do
    badMap0 = (case (:maps.find(:connection_id, opts)) do
                 :error ->
                   opts
                 {:ok, cIdBool} when is_boolean(cIdBool) ->
                   :maps.remove(:connection_id, opts)
                 {:ok, badCIdVal} ->
                   throw({:error,
                            {:bad_option_value, %{connection_id: badCIdVal}}})
               end)
    badMap1 = (case (:maps.find(:nodedown_reason,
                                  badMap0)) do
                 :error ->
                   badMap0
                 {:ok, nRBool} when is_boolean(nRBool) ->
                   :maps.remove(:nodedown_reason, badMap0)
                 {:ok, badNRVal} ->
                   throw({:error,
                            {:bad_option_value, %{nodedown_reason: badNRVal}}})
               end)
    badMap2 = (case (:maps.find(:node_type, badMap1)) do
                 :error ->
                   badMap1
                 {:ok, nTVal} when nTVal == :visible or
                                     nTVal == :hidden or nTVal == :all
                                   ->
                   :maps.remove(:node_type, badMap1)
                 {:ok, badNTVal} ->
                   throw({:error,
                            {:bad_option_value, %{node_type: badNTVal}}})
               end)
    cond do
      map_size(badMap2) == 0 ->
        {:error, :internal_error}
      true ->
        throw({:error, {:unknown_options, badMap2}})
    end
  end

  defp check_options(opts) do
    {:error, {:invalid_options, opts}}
  end

  defp mk_monitor_nodes_error(flag, _Opts) when (flag !== true and
                               flag !== false) do
    :error
  end

  defp mk_monitor_nodes_error(_Flag, opts) do
    case ((try do
            check_options(opts)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      {:error, _} = error ->
        error
      unexpectedError ->
        {:error, {:internal_error, unexpectedError}}
    end
  end

  defp do_disconnect(node, state, async) do
    case (:ets.lookup(:sys_dist, node)) do
      [conn] when r_connection(conn, :state) === :up ->
        disconnect_ctrlr(r_connection(conn, :ctrlr), state, async)
      [conn] when r_connection(conn, :state) === :up_pending ->
        disconnect_ctrlr(r_connection(conn, :ctrlr), state, async)
      _ ->
        {false, state}
    end
  end

  defp disconnect_ctrlr(ctrlr, s0, async) do
    :erlang.exit(ctrlr, :disconnect)
    s2 = (case (async) do
            true ->
              s0
            false ->
              receive do
                {:EXIT, ^ctrlr, reason} ->
                  {_, s1} = handle_exit(ctrlr, reason, s0)
                  s1
              end
          end)
    {true, s2}
  end

  defp get_nodes_up_normal() do
    :ets.select(:sys_dist,
                  [{r_connection(node: :"$1", state: :up, type: :normal, _: :_), [],
                      [:"$1"]}])
  end

  def ticker(kernel, tick) when is_integer(tick) do
    :erlang.process_flag(:priority, :max)
    :ok
    ticker_loop(kernel, tick)
  end

  def ticker_loop(kernel, tick) do
    receive do
      {:new_ticktime, newTick} ->
        :ok
        :net_kernel.ticker_loop(kernel, newTick)
    after tick ->
      send(kernel, :tick)
      :net_kernel.ticker_loop(kernel, tick)
    end
  end

  defp start_aux_ticker(newTick, oldTick, transitionPeriod) do
    spawn_link(:net_kernel, :aux_ticker,
                 [self(), newTick, oldTick, transitionPeriod])
  end

  def aux_ticker(netKernel, newTick, oldTick, transitionPeriod) do
    :erlang.process_flag(:priority, :max)
    :ok
    tickInterval = (case (newTick > oldTick) do
                      true ->
                        oldTick
                      false ->
                        newTick
                    end)
    noOfTicks = (case (transitionPeriod > 0) do
                   true ->
                     1 + (div(transitionPeriod - 1, tickInterval) + 1)
                   false ->
                     1
                 end)
    aux_ticker1(netKernel, tickInterval, noOfTicks)
  end

  defp aux_ticker1(netKernel, _, 1) do
    send(netKernel, :transition_period_end)
    send(netKernel, :aux_tick)
    :bye
  end

  defp aux_ticker1(netKernel, tickInterval, noOfTicks) do
    send(netKernel, :aux_tick)
    receive do after tickInterval ->
      aux_ticker1(netKernel, tickInterval, noOfTicks - 1)
    end
  end

  defp send(_From, to, mess) do
    case (:erlang.whereis(to)) do
      :undefined ->
        mess
      p when is_pid(p) ->
        send(p, mess)
    end
  end

  def do_spawn(spawnFuncArgs, spawnOpts, state) do
    [_, from | _] = spawnFuncArgs
    case ((try do
            :erlang.spawn_opt(:net_kernel, :spawn_func,
                                spawnFuncArgs, spawnOpts)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      {:EXIT, {reason, _}} ->
        async_reply({:reply, {:EXIT, {reason, []}}, state},
                      from)
      {:EXIT, reason} ->
        async_reply({:reply, {:EXIT, {reason, []}}, state},
                      from)
      _ ->
        {:noreply, state}
    end
  end

  def spawn_func(:link, {from, tag}, m, f, a, gleader) do
    :erlang.link(from)
    :gen_server.reply({from, tag}, self())
    :erlang.group_leader(gleader, self())
    apply(m, f, a)
  end

  def spawn_func(_, {from, tag}, m, f, a, gleader) do
    :gen_server.reply({from, tag}, self())
    :erlang.group_leader(gleader, self())
    apply(m, f, a)
  end

  defp setup(node, connId, type, from, state) do
    case (setup_check(node, state)) do
      {:ok, l} ->
        mod = r_listen(l, :module)
        lAddr = r_listen(l, :address)
        myNode = r_state(state, :node)
        pid = mod.setup(node, type, myNode, r_state(state, :type),
                          r_state(state, :connecttime))
        verbose({:setup, node, type, myNode, r_state(state, :type),
                   pid},
                  2, state)
        addr = r_net_address(lAddr, address: :undefined,  host: :undefined)
        waiting = (case (from) do
                     :noreply ->
                       []
                     _ ->
                       [from]
                   end)
        :ets.insert(:sys_dist,
                      r_connection(node: node, conn_id: connId, state: :pending,
                          owner: pid, waiting: waiting, address: addr,
                          type: :normal, remote_name_type: :static))
        {:ok, pid}
      error ->
        error
    end
  end

  defp setup_check(node, state) do
    allowed = r_state(state, :allowed)
    case (:lists.member(node, allowed)) do
      false when allowed !== [] ->
        error_msg('** Connection attempt with disallowed node ~w ** ~n', [node])
        {:error, :bad_node}
      _ ->
        case (select_mod(node, r_state(state, :listen))) do
          {:ok, _L} = oK ->
            oK
          error ->
            error
        end
    end
  end

  defp select_mod(node, [l | ls]) do
    mod = r_listen(l, :module)
    case (mod.select(node)) do
      true ->
        {:ok, l}
      false ->
        select_mod(node, ls)
    end
  end

  defp select_mod(node, []) do
    {:error, {:unsupported_address_type, node}}
  end

  defp get_proto_mod(family, protocol, [l | ls]) do
    a = r_listen(l, :address)
    cond do
      (r_listen(l, :accept) !== :undefined and
         r_net_address(a, :family) === family and
         r_net_address(a, :protocol) === protocol) ->
        {:ok, r_listen(l, :module)}
      true ->
        get_proto_mod(family, protocol, ls)
    end
  end

  defp get_proto_mod(_Family, _Protocol, []) do
    :error
  end

  defp init_node(name, longOrShortNames, cleanHalt, listen) do
    case (create_name(name, longOrShortNames, 1)) do
      {:ok, node} ->
        case (start_protos(node, cleanHalt, listen)) do
          {:ok, ls} ->
            {:ok, node, ls}
          error ->
            error
        end
      error ->
        error
    end
  end

  defp create_name(name, longOrShortNames, try) do
    :erlang.put(:longnames,
                  case (longOrShortNames) do
                    :shortnames ->
                      false
                    :longnames ->
                      true
                  end)
    {head, host1} = create_hostpart(name, longOrShortNames)
    case (host1) do
      {:ok, hostPart} ->
        case (valid_name_head(head)) do
          true ->
            {:ok, :erlang.list_to_atom(head ++ hostPart)}
          false ->
            :error_logger.info_msg('Invalid node name!\nPlease check your configuration\n')
            {:error, :badarg}
        end
      {:error, :long} when try === 1 ->
        :inet_config.do_load_resolv(:os.type(), :longnames)
        create_name(name, longOrShortNames, 0)
      {:error, :hostname_not_allowed} ->
        :error_logger.info_msg('Invalid node name!\nPlease check your configuration\n')
        {:error, :badarg}
      {:error, type} ->
        :error_logger.info_msg(:lists.concat(['Can\'t set ', type, ' node name!\nPlease check your configuration\n']))
        {:error, :badarg}
    end
  end

  defp create_hostpart(name, longOrShortNames) do
    {head, host} = split_node(name)
    host1 = (case ({host, longOrShortNames}) do
               {[?@, _ | _] = ^host, :longnames} ->
                 validate_hostname(host)
               {[?@, _ | _], :shortnames} ->
                 case (:lists.member(?., host)) do
                   true ->
                     {:error, :short}
                   _ ->
                     validate_hostname(host)
                 end
               {_, :shortnames} ->
                 case (:inet_db.gethostname()) do
                   h when (is_list(h) and length(h) > 0) ->
                     {:ok, '@' ++ h}
                   _ ->
                     {:error, :short}
                 end
               {_, :longnames} ->
                 case ({:inet_db.gethostname(),
                          :inet_db.res_option(:domain)}) do
                   {h, d} when (is_list(d) and is_list(h) and
                                  length(d) > 0 and length(h) > 0)
                               ->
                     {:ok, '@' ++ h ++ '.' ++ d}
                   _ ->
                     {:error, :long}
                 end
             end)
    {head, host1}
  end

  defp validate_hostname([?@ | hostPart] = host) do
    {:ok, mP} = :re.compile('^[!-Ã¿]*$', [:unicode])
    case (:re.run(hostPart, mP)) do
      {:match, _} ->
        {:ok, host}
      :nomatch ->
        {:error, :hostname_not_allowed}
    end
  end

  defp valid_name_head(head) do
    {:ok, mP} = :re.compile('^[0-9A-Za-z_\\-]+$', [:unicode])
    case (:re.run(head, mP)) do
      {:match, _} ->
        true
      :nomatch ->
        false
    end
  end

  defp split_node(name) do
    :lists.splitwith(fn c ->
                          c !== ?@
                     end,
                       :erlang.atom_to_list(name))
  end

  def protocol_childspecs() do
    case (:init.get_argument(:proto_dist)) do
      {:ok, [protos]} ->
        protocol_childspecs(protos)
      _ ->
        protocol_childspecs(['inet_tcp'])
    end
  end

  defp protocol_childspecs([]) do
    []
  end

  defp protocol_childspecs([h | t]) do
    mod = :erlang.list_to_atom(h ++ '_dist')
    case ((try do
            mod.childspecs()
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      {:ok, childspecs} when is_list(childspecs) ->
        childspecs ++ protocol_childspecs(t)
      _ ->
        protocol_childspecs(t)
    end
  end

  def epmd_module() do
    case (:init.get_argument(:epmd_module)) do
      {:ok, [[module | _] | _]} ->
        :erlang.list_to_atom(module)
      _ ->
        :erl_epmd
    end
  end

  defp dist_listen_argument() do
    case (:init.get_argument(:dist_listen)) do
      {:ok, [['false' | _] | _]} ->
        false
      _ ->
        true
    end
  end

  defp hidden_argument() do
    case (:init.get_argument(:hidden)) do
      {:ok, [[] | _]} ->
        true
      {:ok, [['true' | _] | _]} ->
        true
      _ ->
        false
    end
  end

  defp start_protos(node, cleanHalt, listen) do
    case (:init.get_argument(:proto_dist)) do
      {:ok, [protos]} ->
        start_protos(node, protos, cleanHalt, listen)
      _ ->
        start_protos(node, ['inet_tcp'], cleanHalt, listen)
    end
  end

  defp start_protos(node, ps, cleanHalt, listen) do
    listeners = (case (listen) do
                   false ->
                     start_protos_no_listen(node, ps, [], cleanHalt)
                   _ ->
                     start_protos_listen(node, ps, cleanHalt)
                 end)
    case (listeners) do
      [] ->
        case (cleanHalt) do
          true ->
            :erlang.halt(1)
          false ->
            {:error, :badarg}
        end
      ls ->
        {:ok, ls}
    end
  end

  defp start_protos_no_listen(node, [proto | ps], ls, cleanHalt) do
    {name, '@' ++ host} = split_node(node)
    ok = (case (name) do
            'undefined' ->
              :erts_internal.dynamic_node_name(true)
              true
            _ ->
              set_node(node, create_creation()) === :ok
          end)
    case (ok) do
      true ->
        :auth.sync_cookie()
        mod = :erlang.list_to_atom(proto ++ '_dist')
        address = (try do
                     mod.address(host)
                   catch
                     :error, :undef ->
                       mod.address()
                   end)
        l = r_listen(listen: :undefined, address: address,
                accept: :undefined, module: mod)
        start_protos_no_listen(node, ps, [l | ls], cleanHalt)
      false ->
        s = 'invalid node name: ' ++ :erlang.atom_to_list(node)
        proto_error(cleanHalt, proto, s)
        start_protos_no_listen(node, ps, ls, cleanHalt)
    end
  end

  defp start_protos_no_listen(_Node, [], ls, _CleanHalt) do
    ls
  end

  defp create_creation() do
    cr = (try do
            :binary.decode_unsigned(:crypto.strong_rand_bytes(4))
          catch
            _, _ ->
              :rand.uniform(1 <<< 32 - 1)
          else
            creation ->
              creation
          end)
    wrap_creation(cr)
  end

  defp next_creation(creation) do
    wrap_creation(creation + 1)
  end

  defp wrap_creation(cr) when cr >= 4 and cr < 1 <<< 32 do
    cr
  end

  defp wrap_creation(cr) do
    wrap_creation((cr + 4) &&& (1 <<< 32 - 1))
  end

  defp start_protos_listen(node, ps, cleanHalt) do
    case (split_node(node)) do
      {'undefined', _} ->
        :erlang.error({:internal_error, 'Dynamic node name and dist listen both enabled'})
      {name, '@' ++ host} ->
        start_protos_listen(:erlang.list_to_atom(name), host,
                              node, ps, [], cleanHalt)
    end
  end

  defp start_protos_listen(name, host, node, [proto | ps], ls,
            cleanHalt) do
    mod = :erlang.list_to_atom(proto ++ '_dist')
    try do
      try do
        mod.listen(name, host)
      catch
        :error, :undef ->
          mod.listen(name)
      end
    catch
      :error, :undef ->
        proto_error(cleanHalt, proto, 'not supported')
        start_protos_listen(name, host, node, ps, ls, cleanHalt)
      _, reason ->
        register_error(cleanHalt, proto, reason)
        start_protos_listen(name, host, node, ps, ls, cleanHalt)
    else
      {:ok, {socket, address, creation}} ->
        case (set_node(node, creation)) do
          :ok ->
            acceptPid = mod.accept(socket)
            :auth.sync_cookie()
            l = r_listen(listen: socket, address: address,
                    accept: acceptPid, module: mod)
            start_protos_listen(name, host, node, ps, [l | ls],
                                  cleanHalt)
          _ ->
            mod.close(socket)
            s = 'invalid node name: ' ++ :erlang.atom_to_list(node)
            proto_error(cleanHalt, proto, s)
            start_protos_listen(name, host, node, ps, ls, cleanHalt)
        end
      {:error, :duplicate_name} ->
        s = 'the name ' ++ :erlang.atom_to_list(node) ++ ' seems to be in use by another Erlang node'
        proto_error(cleanHalt, proto, s)
        start_protos_listen(name, host, node, ps, ls, cleanHalt)
      {:error, reason} ->
        register_error(cleanHalt, proto, reason)
        start_protos_listen(name, host, node, ps, ls, cleanHalt)
    end
  end

  defp start_protos_listen(_Name, _Host, _Node, [], ls, _CleanHalt) do
    ls
  end

  defp register_error(false, proto, reason) do
    s = :io_lib.format('register/listen error: ~p', [reason])
    proto_error(false, proto, :lists.flatten(s))
  end

  defp register_error(true, proto, reason) do
    s = 'Protocol \'' ++ proto ++ '\': register/listen error: '
    :erlang.display_string(:stdout, s)
    :erlang.display(reason)
  end

  defp proto_error(cleanHalt, proto, string) do
    s = 'Protocol \'' ++ proto ++ '\': ' ++ string ++ '\n'
    case (cleanHalt) do
      false ->
        :error_logger.info_msg(s)
      true ->
        :erlang.display_string(s)
    end
  end

  defp set_node(node, creation) when creation < 0 do
    set_node(node, create_creation())
  end

  defp set_node(node, creation)
      when node() === :nonode@nohost do
    case ((try do
            :erlang.setnode(node, creation)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      true ->
        :ok
      {:EXIT, reason} ->
        {:error, reason}
    end
  end

  defp set_node(node, _Creation) when node() === node do
    :ok
  end

  def connecttime() do
    case (:application.get_env(:kernel, :net_setuptime)) do
      {:ok, time} when (is_number(time) and time >= 120) ->
        120 * 1000
      {:ok, time} when (is_number(time) and time > 0) ->
        round(time * 1000)
      _ ->
        7000
    end
  end

  defp get_node_info(node) do
    case (:ets.lookup(:sys_dist, node)) do
      [r_connection(owner: owner, state: :up, address: addr,
           type: type)] ->
        mRef = :erlang.monitor(:process, owner)
        send(owner, {self(), :get_status})
        receive do
          {^owner, :get_status, {:ok, read, write}} ->
            :erlang.demonitor(mRef, [:flush])
            {:ok,
               [{:owner, owner}, {:state, :up}, {:address, addr},
                                                    {:type, type}, {:in, read},
                                                                       {:out,
                                                                          write}]}
          {:DOWN, ^mRef, :process, ^owner, _Info} ->
            {:error, :bad_node}
        end
      [r_connection(owner: owner, state: state, address: addr,
           type: type)] ->
        {:ok,
           [{:owner, owner}, {:state, state}, {:address, addr},
                                                  {:type, type}, {:in, 0},
                                                                     {:out, 0}]}
      _ ->
        {:error, :bad_node}
    end
  end

  defp get_node_info(node, key) do
    case (get_node_info(node)) do
      {:ok, info} ->
        case (:lists.keyfind(key, 1, info)) do
          {^key, value} ->
            {:ok, value}
          false ->
            {:error, :invalid_key}
        end
      {:error, :bad_node} ->
        {:error, :bad_node}
    end
  end

  defp get_nodes_info() do
    conns = :ets.select(:sys_dist, [{r_connection(_: :_), [], [:"$_"]}])
    info = multi_info(conns, {self(), :get_status}, %{}, [])
    {:ok, info}
  end

  defp multi_info([], _Msg, pidToRef, nodeInfos) do
    multi_receive(pidToRef, nodeInfos)
  end

  defp multi_info([r_connection(owner: owner, state: :up) = conn | conns],
            msg, pidToRef, nodeInfos) do
    mRef = :erlang.monitor(:process, owner)
    send(owner, msg)
    multi_info(conns, msg,
                 :maps.put(owner, {mRef, conn}, pidToRef), nodeInfos)
  end

  defp multi_info([r_connection(node: node, owner: owner, type: type,
               state: state, address: addr) |
               conns],
            msg, pidToRef, nodeInfos) do
    multi_info(conns, msg, pidToRef,
                 [{node,
                     [{:owner, owner}, {:state, state}, {:address, addr},
                                                            {:type, type}, {:in,
                                                                              0},
                                                                               {:out,
                                                                                  0}]} |
                      nodeInfos])
  end

  defp multi_receive(pidToRef, nodeInfos)
      when map_size(pidToRef) === 0 do
    nodeInfos
  end

  defp multi_receive(pidToRef, nodeInfos) do
    receive do
      {distProc, :get_status, {:ok, read, write}} ->
        {{mRef,
            r_connection(node: node, owner: owner, type: type, state: state,
                address: addr)},
           newRefs} = :maps.take(distProc, pidToRef)
        :erlang.demonitor(mRef, [:flush])
        multi_receive(newRefs,
                        [{node,
                            [{:owner, owner}, {:state, state}, {:address, addr},
                                                                   {:type,
                                                                      type},
                                                                       {:in,
                                                                          read},
                                                                           {:out,
                                                                              write}]} |
                             nodeInfos])
      {:DOWN, _MRef, :process, pid, _Info} ->
        multi_receive(:maps.remove(pid, pidToRef), nodeInfos)
    end
  end

  defp reply_waiting(_Node, waiting, rep) do
    case (rep) do
      false ->
        :noop
      _ ->
        :ok
    end
    reply_waiting1(:lists.reverse(waiting), rep)
  end

  defp reply_waiting1([from | w], rep) do
    :gen_server.reply(from, rep)
    reply_waiting1(w, rep)
  end

  defp reply_waiting1([], _) do
    :ok
  end

  defp all_atoms([]) do
    true
  end

  defp all_atoms([n | tail]) when is_atom(n) do
    all_atoms(tail)
  end

  defp all_atoms(_) do
    false
  end

  defp restart_ticker(time) do
    :ok
    send(self(), :aux_tick)
    spawn_link(:net_kernel, :ticker, [self(), time])
  end

  defp print_info() do
    nformat('Node', 'State', 'Type', 'In', 'Out', 'Address')
    {:ok, nodesInfo} = nodes_info()
    {in__, out} = :lists.foldl(&display_info/2, {0, 0},
                                 nodesInfo)
    nformat('Total', '', '', :erlang.integer_to_list(in__),
              :erlang.integer_to_list(out), '')
  end

  defp display_info({node, info}, {i, o}) do
    state = :erlang.atom_to_list(fetch(:state, info))
    in__ = fetch(:in, info)
    out = fetch(:out, info)
    type = :erlang.atom_to_list(fetch(:type, info))
    address = fmt_address(fetch(:address, info))
    nformat(:erlang.atom_to_list(node), state, type,
              :erlang.integer_to_list(in__),
              :erlang.integer_to_list(out), address)
    {i + in__, o + out}
  end

  defp fmt_address(:undefined) do
    '-'
  end

  defp fmt_address(a) do
    case (r_net_address(a, :family)) do
      :inet ->
        case (r_net_address(a, :address)) do
          {iP, port} ->
            :inet_parse.ntoa(iP) ++ ':' ++ :erlang.integer_to_list(port)
          _ ->
            '-'
        end
      :inet6 ->
        case (r_net_address(a, :address)) do
          {iP, port} ->
            :inet_parse.ntoa(iP) ++ '/' ++ :erlang.integer_to_list(port)
          _ ->
            '-'
        end
      _ ->
        :lists.flatten(:io_lib.format('~p', [r_net_address(a, :address)]))
    end
  end

  defp fetch(key, info) do
    case (:lists.keysearch(key, 1, info)) do
      {:value, {_, val}} ->
        val
      false ->
        0
    end
  end

  defp nformat(a1, a2, a3, a4, a5, a6) do
    :io.format('~-20s ~-7s ~-6s ~8s ~8s ~s~n', [a1, a2, a3, a4, a5, a6])
  end

  defp print_info(node) do
    case (node_info(node)) do
      {:ok, info} ->
        state = fetch(:state, info)
        in__ = fetch(:in, info)
        out = fetch(:out, info)
        type = fetch(:type, info)
        address = fmt_address(fetch(:address, info))
        :io.format('Node     = ~p~nState    = ~p~nType     = ~p~nIn       = ~p~nOut      = ~p~nAddress  = ~s~n', [node, state, type, in__, out, address])
      error ->
        error
    end
  end

  defp verbose(term, level, r_state(verbose: verbose))
      when verbose >= level do
    :error_logger.info_report({:net_kernel, term})
  end

  defp verbose(_, _, _) do
    :ok
  end

  defp getnode(p) when is_pid(p) do
    node(p)
  end

  defp getnode(p) do
    p
  end

  defp return_call({:noreply, _State} = r, _From) do
    r
  end

  defp return_call(r, from) do
    async_reply(r, from)
  end

  defp async_reply({:reply, _Msg, _State} = res, _From) do
    res
  end

  defp handle_async_response(responseType, reqId, result,
            r_state(req_map: reqMap0) = s0) do
    cond do
      responseType == :down ->
        :ok
      true ->
        _ = :erlang.demonitor(reqId, [:flush])
        :ok
    end
    case (:maps.take(reqId, reqMap0)) do
      {{setGetOpts, from}, reqMap1}
          when setGetOpts == :setopts or setGetOpts == :getopts ->
        reply = (case (responseType) do
                   :reply ->
                     result
                   :down ->
                     {:error, :noconnection}
                 end)
        :gen_server.reply(from, reply)
        {:noreply, r_state(s0, req_map: reqMap1)}
      {{:setopts_new, op}, reqMap1} ->
        case (:maps.get(op, reqMap1)) do
          {:setopts_new, from, 1} ->
            :gen_server.reply(from, :ok)
            reqMap2 = :maps.remove(op, reqMap1)
            {:noreply, r_state(s0, req_map: reqMap2)}
          {:setopts_new, from, n} ->
            reqMap2 = Map.put(reqMap1, op,
                                         {:setopts_new, from, n - 1})
            {:noreply, r_state(s0, req_map: reqMap2)}
        end
    end
  end

  defp send_owner_request(reqOpMap, label, owner, msg) do
    reqId = :erlang.monitor(:process, owner)
    send(owner, {self(), reqId, msg})
    Map.put(reqOpMap, reqId, label)
  end

  def setopts(node, opts) when (is_atom(node) and
                             is_list(opts)) do
    request({:setopts, node, opts})
  end

  defp setopts_new(opts, from, state) do
    case (setopts_on_listen(opts, r_state(state, :listen))) do
      :ok ->
        setopts_new_1(opts, from, state)
      fail ->
        async_reply({:reply, fail, state}, from)
    end
  end

  defp setopts_on_listen(_, []) do
    :ok
  end

  defp setopts_on_listen(opts, [r_listen(listen: lSocket, module: mod) | t]) do
    try do
      mod.setopts(lSocket, opts)
    catch
      :error, :undef ->
        {:error, :enotsup}
    else
      :ok ->
        setopts_on_listen(opts, t)
      fail ->
        fail
    end
  end

  defp setopts_new_1(opts, from, r_state(req_map: reqMap0) = state) do
    connectOpts = (case (:application.get_env(:kernel,
                                                :inet_dist_connect_options)) do
                     {:ok, cO} ->
                       cO
                     _ ->
                       []
                   end)
    :application.set_env(:kernel,
                           :inet_dist_connect_options,
                           merge_opts(opts, connectOpts))
    listenOpts = (case (:application.get_env(:kernel,
                                               :inet_dist_listen_options)) do
                    {:ok, lO} ->
                      lO
                    _ ->
                      []
                  end)
    :application.set_env(:kernel, :inet_dist_listen_options,
                           merge_opts(opts, listenOpts))
    case (:lists.keyfind(:nodelay, 1, opts)) do
      {:nodelay, nD} when is_boolean(nD) ->
        :application.set_env(:kernel, :dist_nodelay, nD)
      _ ->
        :ignore
    end
    pendingConns = :ets.select(:sys_dist,
                                 [{:_, [{:"=/=", {:element, r_connection(:state), :"$_"}, :up}],
                                     [:"$_"]}])
    op = make_ref()
    sendReq = fn reqMap, n, owner ->
                   {send_owner_request(reqMap, {:setopts_new, op}, owner,
                                         {:setopts, opts}),
                      n + 1}
              end
    {reqMap1, noReqs} = :lists.foldl(fn r_connection(state: :pending,
                                            owner: owner),
                                          {reqMap, n} ->
                                          sendReq.(reqMap, n, owner)
                                        r_connection(state: :up_pending,
                                            pending_owner: owner),
                                          {reqMap, n} ->
                                          sendReq.(reqMap, n, owner)
                                        _, acc ->
                                          acc
                                     end,
                                       {reqMap0, 0}, pendingConns)
    cond do
      noReqs == 0 ->
        async_reply({:reply, :ok, state}, from)
      true ->
        reqMap2 = Map.put(reqMap1, op,
                                     {:setopts_new, from, noReqs})
        {:noreply, r_state(state, req_map: reqMap2)}
    end
  end

  defp merge_opts([], b) do
    b
  end

  defp merge_opts([h | t], b0) do
    {key, _} = h
    b1 = :lists.filter(fn {k, _} ->
                            k !== key
                       end,
                         b0)
    merge_opts(t, [h | b1])
  end

  def getopts(node, opts) when (is_atom(node) and
                             is_list(opts)) do
    request({:getopts, node, opts})
  end

  defp opts_node(op, node, opts, from,
            r_state(req_map: reqMap0) = s0) do
    case (:ets.lookup(:sys_dist, node)) do
      [conn] when r_connection(conn, :state) === :up ->
        reqMap1 = send_owner_request(reqMap0, {op, from},
                                       r_connection(conn, :owner), {op, opts})
        s1 = r_state(s0, req_map: reqMap1)
        {:noreply, s1}
      _ ->
        async_reply({:reply, {:error, :noconnection}, s0}, from)
    end
  end

end