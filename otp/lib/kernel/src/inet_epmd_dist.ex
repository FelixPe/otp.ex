defmodule :m_inet_epmd_dist do
  use Bitwise
  require Record

  Record.defrecord(:r_net_address, :net_address,
    address: :undefined,
    host: :undefined,
    protocol: :undefined,
    family: :undefined
  )

  Record.defrecord(:r_hs_data, :hs_data,
    kernel_pid: :undefined,
    other_node: :undefined,
    this_node: :undefined,
    socket: :undefined,
    timer: :undefined,
    this_flags: :undefined,
    allowed: :undefined,
    other_version: :undefined,
    other_flags: :undefined,
    other_started: :undefined,
    f_send: :undefined,
    f_recv: :undefined,
    f_setopts_pre_nodeup: :undefined,
    f_setopts_post_nodeup: :undefined,
    f_getll: :undefined,
    f_address: :undefined,
    mf_tick: :undefined,
    mf_getstat: :undefined,
    request_type: :normal,
    mf_setopts: :undefined,
    mf_getopts: :undefined,
    f_handshake_complete: :undefined,
    add_flags: :undefined,
    reject_flags: :undefined,
    require_flags: :undefined,
    this_creation: :undefined,
    other_creation: :undefined
  )

  def net_address() do
    family = :inet_tcp.family()
    r_net_address(protocol: :tcp, family: family)
  end

  def listen_open(_NetAddress, options) do
    {:ok, merge_options(options, [{:active, false}, {:packet, 2}], [])}
  end

  def listen_close(listenSocket) do
    :inet_tcp.close(listenSocket)
  end

  def accept_controller(_NetAddress, controller, socket) do
    :inet_tcp.controlling_process(socket, controller)
    socket
  end

  def accepted(netAddress, _Timer, socket) do
    hs_data(netAddress, socket)
  end

  def hs_data(netAddress, socket) do
    nodelay = nodelay()

    r_hs_data(
      socket: socket,
      f_send: &:inet_tcp.send/2,
      f_recv: &:inet_tcp.recv/3,
      f_setopts_pre_nodeup: fn s when s === socket ->
        f_setopts_pre_nodeup(s, nodelay)
      end,
      f_setopts_post_nodeup: fn s when s === socket ->
        f_setopts_post_nodeup(s, nodelay)
      end,
      f_address: fn s, node when s === socket ->
        f_address(netAddress, node)
      end,
      f_getll: &:inet.getll/1,
      mf_tick: &:inet_epmd_dist.tick/1,
      mf_getstat: &:inet_epmd_dist.getstat/1,
      mf_setopts: &:inet_epmd_dist.setopts/2,
      mf_getopts: &:inet_epmd_dist.getopts/2
    )
  end

  defp f_setopts_pre_nodeup(socket, nodelay) do
    :inet.setopts(
      socket,
      [{:active, false}, {:packet, 4}, nodelay]
    )
  end

  defp f_setopts_post_nodeup(socket, nodelay) do
    :inet.setopts(
      socket,
      [{:active, true}, {:packet, 4}, {:deliver, :port}, :binary, nodelay]
    )
  end

  def f_address(netAddress, node) do
    case :dist_util.split_node(node) do
      {:node, _Name, host} ->
        r_net_address(netAddress, host: host)

      other ->
        :dist_util.shutdown(:inet_epmd_dist, 214, node, {:split_node, other})
    end
  end

  def tick(socket) when is_port(socket) do
    result = :inet_tcp.send(socket, [], [:force])
    _ = result === {:error, :closed} and send(self(), {:tcp_closed, socket})
    result
  end

  def getstat(socket) do
    case :inet.getstat(
           socket,
           [:recv_cnt, :send_cnt, :send_pend]
         ) do
      {:ok, stat} ->
        split_stat(stat, 0, 0, 0)

      error ->
        error
    end
  end

  defp split_stat([{:recv_cnt, r} | stat], _, w, p) do
    split_stat(stat, r, w, p)
  end

  defp split_stat([{:send_cnt, w} | stat], r, _, p) do
    split_stat(stat, r, w, p)
  end

  defp split_stat([{:send_pend, p} | stat], r, w, _) do
    split_stat(stat, r, w, p)
  end

  defp split_stat([], r, w, p) do
    {:ok, r, w, p}
  end

  def setopts(s, opts) do
    case (for {k, _} = opt <- opts,
              k === :active or k === :deliver or k === :packet do
            opt
          end) do
      [] ->
        :inet.setopts(s, opts)

      opts1 ->
        {:error, {:badopts, opts1}}
    end
  end

  def getopts(s, optNames) do
    :inet.getopts(s, optNames)
  end

  def address(host) do
    try do
      pt_init(host)
      pt_get(:net_address)
    catch
      :error, reason ->
        :error_logger.error_msg(~c"error : ~p in ~n    ~p~n", [reason, __STACKTRACE__])
        :erlang.raise(:error, reason, __STACKTRACE__)
    end
  end

  defp get_port_range() do
    case :application.get_env(
           :kernel,
           :inet_dist_listen_min
         ) do
      {:ok, n} when is_integer(n) ->
        case :application.get_env(
               :kernel,
               :inet_dist_listen_max
             ) do
          {:ok, m} when is_integer(m) ->
            {n, m}

          _ ->
            {n, n}
        end

      _ ->
        {0, 0}
    end
  end

  defp listen_loop(port, netAddress, listenOptions, lastPort, distMod)
       when port <= lastPort do
    case distMod.listen_port(netAddress, port, listenOptions) do
      {:error, :eaddrinuse} ->
        listen_loop(port + 1, netAddress, listenOptions, lastPort, distMod)

      result ->
        result
    end
  end

  defp listen_loop(_, _, _, _, _) do
    {:error, :eaddrinuse}
  end

  def close(listenSocket) do
    pt_get(:dist_mod).listen_close(listenSocket)
  end

  def accept({netAddress, stateL}) do
    try do
      netKernel = self()
      distMod = pt_get(:dist_mod)

      acceptLoop =
        spawn_link(fn ->
          _ = :erlang.process_flag(:trap_exit, true)

          accept_loop(
            stateL,
            netAddress,
            netKernel,
            distMod,
            :erlang.system_info(:schedulers_online),
            %{}
          )
        end)

      acceptLoop
    catch
      :error, reason ->
        :error_logger.error_msg(~c"error : ~p in ~n    ~p~n", [reason, __STACKTRACE__])
        :erlang.raise(:error, reason, __STACKTRACE__)
    end
  end

  defp accept_loop(stateL, netAddress, netKernel, distMod, maxPending, acceptors)
       when map_size(acceptors) <= maxPending do
    acceptRef = make_ref()
    acceptor = spawn_link(acceptor_fun(stateL, netAddress, netKernel, distMod, acceptRef))

    accept_loop(
      stateL,
      netAddress,
      netKernel,
      distMod,
      maxPending,
      Map.put(acceptors, acceptor, acceptRef)
    )
  end

  defp accept_loop(stateL, netAddress, netKernel, distMod, maxPending, acceptors) do
    receive do
      msg ->
        case msg do
          {:EXIT, acceptor, reason}
          when :erlang.is_map_key(acceptor, acceptors) ->
            acceptRef = :maps.get(acceptor, acceptors)

            case reason do
              ^acceptRef ->
                accept_loop(
                  stateL,
                  netAddress,
                  netKernel,
                  distMod,
                  maxPending,
                  :maps.remove(acceptor, acceptors)
                )

              {:accept, _} ->
                exit(reason)

              _ ->
                :error_logger.warning_msg(
                  ~c"~w:~w acceptor ~w failed: ~p",
                  [:inet_epmd_dist, :accept_loop, acceptor, reason]
                )

                accept_loop(
                  stateL,
                  netAddress,
                  netKernel,
                  distMod,
                  maxPending,
                  :maps.remove(acceptor, acceptors)
                )
            end

          {:EXIT, ^netKernel, reason} ->
            exit(reason)

          _ ->
            :error_logger.warning_msg(
              ~c"~w:~w unknown message: ~p",
              [:inet_epmd_dist, :accept_loop, msg]
            )

            accept_loop(stateL, netAddress, netKernel, distMod, maxPending, acceptors)
        end
    end
  end

  defp acceptor_fun(
         stateL,
         r_net_address(family: family, protocol: protocol) = netAddress,
         netKernel,
         distMod,
         acceptRef
       ) do
    fn ->
      {stateA, peerAddress} =
        distMod.accept_open(
          netAddress,
          stateL
        )

      netAddress_1 = r_net_address(netAddress, address: peerAddress)
      acceptor = self()
      send(netKernel, {:accept, acceptor, netAddress_1, family, protocol})

      receive do
        {^netKernel, :controller, controller} ->
          stateD = distMod.accept_controller(netAddress_1, controller, stateA)
          send(controller, {acceptor, :controller, distMod, stateD})
          exit(acceptRef)

        {^netKernel, :unsupported_protocol = reason} ->
          exit(reason)
      end
    end
  end

  def accept_connection(acceptor, netAddress, myNode, allowed, setupTime) do
    try do
      netKernel = self()

      controller =
        :erlang.spawn_opt(
          fn ->
            accept_controller(acceptor, netAddress, myNode, allowed, setupTime, netKernel)
          end,
          :dist_util.net_ticker_spawn_options()
        )

      controller
    catch
      :error, reason ->
        :error_logger.error_msg(~c"error : ~p in ~n    ~p~n", [reason, __STACKTRACE__])
        :erlang.raise(:error, reason, __STACKTRACE__)
    end
  end

  defp accept_controller(acceptor, netAddress, myNode, allowed, setupTime, netKernel) do
    receive do
      {^acceptor, :controller, distMod, stateD} ->
        timer = :dist_util.start_timer(setupTime)

        case distMod.accepted(netAddress, timer, stateD) do
          r_hs_data() = hsData ->
            :dist_util.handshake_other_started(
              r_hs_data(hsData,
                kernel_pid: netKernel,
                this_node: myNode,
                timer: timer,
                allowed: allowed
              )
            )

          {:error, reason} ->
            :dist_util.shutdown(:inet_epmd_dist, 490, {{distMod, :accepted}, reason})
        end
    end
  end

  def select(node) do
    try do
      case :dist_util.split_node(node) do
        {:node, name, host} ->
          r_net_address(family: family) = pt_get(:net_address)
          epmdMod = :net_kernel.epmd_module()

          case call_epmd_function(epmdMod, :address_please, [name, host, family]) do
            {:ok, _Addr} ->
              true

            {:ok, _Addr, _Port, _Creation} ->
              true

            _ ->
              false
          end

        _ ->
          false
      end
    catch
      :error, reason ->
        :error_logger.error_msg(~c"error : ~p in ~n    ~p~n", [reason, __STACKTRACE__])
        :erlang.raise(:error, reason, __STACKTRACE__)
    end
  end

  def setup(node, type, myNode, longOrShortNames, setupTime) do
    try do
      netKernel = self()

      controller =
        :erlang.spawn_opt(
          fn ->
            setup(node, type, myNode, longOrShortNames, setupTime, netKernel)
          end,
          :dist_util.net_ticker_spawn_options()
        )

      controller
    catch
      :error, reason ->
        :error_logger.error_msg(~c"error : ~p in ~n    ~p~n", [reason, __STACKTRACE__])
        :erlang.raise(:error, reason, __STACKTRACE__)
    end
  end

  defp setup(node, type, myNode, longOrShortNames, setupTime, netKernel) do
    timer = :dist_util.start_timer(setupTime)
    distMod = pt_get(:dist_mod)
    r_net_address(family: family) = netAddress = pt_get(:net_address)
    {name, host} = split_node(node, longOrShortNames, family)
    erlEpmd = :net_kernel.epmd_module()

    {address, version} =
      case call_epmd_function(
             erlEpmd,
             :address_please,
             [name, host, family]
           ) do
        {:ok, ip, port, ver} ->
          {{ip, port}, ver}

        {:ok, ip} ->
          case erlEpmd.port_please(name, ip) do
            {:port, port, ver} ->
              {{ip, port}, ver}

            other ->
              :dist_util.shutdown(:inet_epmd_dist, 561, node, {:port_please, other})
          end

        other ->
          :dist_util.shutdown(:inet_epmd_dist, 564, node, {:address_please, other})
      end

    netAddress_1 =
      r_net_address(netAddress,
        host: host,
        address: address
      )

    :dist_util.reset_timer(timer)

    case distMod.connect(netAddress_1, timer, connect_options()) do
      r_hs_data() = hsData ->
        :dist_util.handshake_we_started(
          r_hs_data(hsData,
            kernel_pid: netKernel,
            other_node: node,
            this_node: myNode,
            timer: timer,
            other_version: version,
            request_type: type
          )
        )

      {:error, reason} ->
        :dist_util.shutdown(:inet_epmd_dist, 586, node, {{distMod, :connect}, reason})
    end
  end

  defp find_netmask(ip, [{_Name, items} | ifaddrs]) do
    find_netmask(ip, ifaddrs, items)
  end

  defp find_netmask(_, []) do
    {:error, :no_netmask}
  end

  defp find_netmask(ip, _Ifaddrs, [{:addr, ip}, {:netmask, netmask} | _]) do
    {:ok, netmask}
  end

  defp find_netmask(ip, ifaddrs, [_ | items]) do
    find_netmask(ip, ifaddrs, items)
  end

  defp find_netmask(ip, ifaddrs, []) do
    find_netmask(ip, ifaddrs)
  end

  defp mask(addr, mask) do
    mask(addr, mask, 1)
  end

  defp mask(addr, mask, n) when n <= tuple_size(addr) do
    [
      :erlang.element(n, addr) &&& :erlang.element(n, mask)
      | mask(addr, mask, n + 1)
    ]
  end

  defp mask(_, _, _) do
    []
  end

  defp split_node(node, longOrShortNames, family) do
    case :dist_util.split_node(node) do
      {:node, name, host} ->
        dots = members(?., host)

        cond do
          longOrShortNames === :longnames and 0 < dots ->
            {name, host}

          longOrShortNames === :longnames ->
            case :inet.parse_strict_address(host, family) do
              {:ok, _} ->
                {name, host}

              {:error, reason} ->
                :error_logger.error_msg(
                  ~c"** System running to use fully qualified hostnames **~n** Hostname ~ts is illegal **~n",
                  [host]
                )

                :dist_util.shutdown(:inet_epmd_dist, 672, node, {:parse_address, reason})
            end

          longOrShortNames === :shortnames and 0 < dots ->
            :error_logger.error_msg(
              ~c"** System NOT running to use fully qualified hostnames **~n** Hostname ~ts is illegal **~n",
              [host]
            )

            :dist_util.shutdown(:inet_epmd_dist, 680, node)

          longOrShortNames === :shortnames ->
            {name, host}
        end

      other ->
        :error_logger.error_msg(~c"** Nodename ~p illegal **~n", [node])
        :dist_util.shutdown(:inet_epmd_dist, 686, node, {:split_node, other})
    end
  end

  defp members(x, [x | t]) do
    members(x, t) + 1
  end

  defp members(x, [_ | t]) do
    members(x, t)
  end

  defp members(_, []) do
    0
  end

  defp call_epmd_function(mod, fun, args) do
    case :erlang.function_exported(mod, fun, length(args)) do
      true ->
        apply(mod, fun, args)

      _ ->
        apply(:erl_epmd, fun, args)
    end
  end

  defp listen_options() do
    defaultOpts = [{:reuseaddr, true}, {:backlog, 128}]

    forcedOpts =
      case :application.get_env(
             :kernel,
             :inet_dist_use_interface
           ) do
        {:ok, ip} ->
          [{:ip, ip}]

        :undefined ->
          []
      end

    inetDistListenOpts =
      case :application.get_env(
             :kernel,
             :inet_dist_listen_options
           ) do
        {:ok, opts} ->
          opts

        :undefined ->
          []
      end

    merge_options(inetDistListenOpts, forcedOpts, defaultOpts)
  end

  defp connect_options() do
    case :application.get_env(
           :kernel,
           :inet_dist_connect_options
         ) do
      {:ok, connectOpts} ->
        connectOpts

      _ ->
        []
    end
  end

  def nodelay() do
    case :application.get_env(:kernel, :dist_nodelay) do
      :undefined ->
        {:nodelay, true}

      {:ok, true} ->
        {:nodelay, true}

      {:ok, false} ->
        {:nodelay, false}

      _ ->
        {:nodelay, true}
    end
  end

  def merge_options(opts, forcedOpts, defaultOpts) do
    forced = merge_options(forcedOpts)
    default = merge_options(defaultOpts)
    forcedOpts ++ merge_options(opts, forced, defaultOpts, default)
  end

  defp merge_options(opts) do
    :lists.foldr(
      fn opt, acc ->
        case expand_option(opt) do
          {optName, optVal} ->
            :maps.put(optName, optVal, acc)

          _ ->
            acc
        end
      end,
      %{},
      opts
    )
  end

  defp merge_options([opt | opts], forced, defaultOpts, default) do
    case expand_option(opt) do
      {optName, _} ->
        default_1 = :maps.remove(optName, default)

        cond do
          :erlang.is_map_key(optName, forced) ->
            merge_options(opts, forced, defaultOpts, default_1)

          true ->
            [opt | merge_options(opts, forced, defaultOpts, default_1)]
        end

      _ ->
        [opt | merge_options(opts, forced, defaultOpts, default)]
    end
  end

  defp merge_options([], _Forced, defaultOpts, default) do
    for opt <- defaultOpts,
        :erlang.is_map_key(
          :erlang.element(
            1,
            expand_option(opt)
          ),
          default
        ) do
      opt
    end
  end

  defp expand_option(opt) do
    cond do
      opt === :list or opt === :binary ->
        {:mode, opt}

      opt === :inet or opt === :inet6 or opt === :local ->
        {:family, opt}

      true ->
        opt
    end
  end

  defp pt_get(key)
       when key === :dist_mod or
              key === :net_address do
    :persistent_term.get({:inet_epmd_dist, key})
  end
end
