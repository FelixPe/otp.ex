defmodule :m_inet_tcp_dist do
  use Bitwise
  import :error_logger, only: [error_msg: 2]
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

  def select(node) do
    gen_select(:inet_tcp, node)
  end

  def gen_select(driver, node) do
    fam_select(driver.family(), node)
  end

  def fam_select(family, node) do
    case :dist_util.split_node(node) do
      {:node, name, host} ->
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
  end

  def address() do
    gen_address(:inet_tcp)
  end

  def gen_address(driver) do
    fam_address(driver.family())
  end

  def fam_address(family) do
    {:ok, host} = :inet.gethostname()
    r_net_address(host: host, protocol: :tcp, family: family)
  end

  def gen_hs_data(driver, socket) do
    nodelay = nodelay()

    r_hs_data(
      socket: socket,
      f_send: Function.capture(driver, :send, 2),
      f_recv: Function.capture(driver, :recv, 3),
      f_setopts_pre_nodeup: fn s ->
        :inet.setopts(
          s,
          [{:active, false}, {:packet, 4}, nodelay]
        )
      end,
      f_setopts_post_nodeup: fn s ->
        :inet.setopts(
          s,
          [{:active, true}, {:packet, 4}, {:deliver, :port}, :binary, nodelay]
        )
      end,
      f_getll: &:inet.getll/1,
      mf_tick: fn s ->
        :inet_tcp_dist.tick(driver, s)
      end,
      mf_getstat: &:inet_tcp_dist.getstat/1,
      mf_setopts: &:inet_tcp_dist.setopts/2,
      mf_getopts: &:inet_tcp_dist.getopts/2
    )
  end

  def listen(name) do
    {:ok, host} = :inet.gethostname()
    listen(name, host)
  end

  def listen(name, host) do
    gen_listen(:inet_tcp, name, host)
  end

  defp listen_loop(_Driver, first, last, _Options)
       when first > last do
    {:error, :eaddrinuse}
  end

  defp listen_loop(driver, first, last, options) do
    case driver.listen(first, options) do
      {:error, :eaddrinuse} ->
        listen_loop(driver, first + 1, last, options)

      other ->
        other
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

  def merge_options(opts, forcedOpts) do
    merge_options(opts, forcedOpts, [])
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

  def accept(listen) do
    gen_accept(:inet_tcp, listen)
  end

  def gen_accept(driver, listen) do
    :erlang.spawn_opt(:inet_tcp_dist, :accept_loop, [driver, self(), listen], [
      :link,
      {:priority, :max}
    ])
  end

  def accept_loop(driver, kernel, listen) do
    case driver.accept(listen) do
      {:ok, socket} ->
        send(kernel, {:accept, self(), socket, driver.family(), :tcp})
        _ = controller(driver, kernel, socket)
        accept_loop(driver, kernel, listen)

      error ->
        exit(error)
    end
  end

  defp controller(driver, kernel, socket) do
    receive do
      {^kernel, :controller, pid} ->
        flush_controller(pid, socket)
        driver.controlling_process(socket, pid)
        flush_controller(pid, socket)
        send(pid, {self(), :controller})

      {^kernel, :unsupported_protocol} ->
        exit(:unsupported_protocol)
    end
  end

  defp flush_controller(pid, socket) do
    receive do
      {:tcp, ^socket, data} ->
        send(pid, {:tcp, socket, data})
        flush_controller(pid, socket)

      {:tcp_closed, ^socket} ->
        send(pid, {:tcp_closed, socket})
        flush_controller(pid, socket)
    after
      0 ->
        :ok
    end
  end

  def accept_connection(acceptPid, socket, myNode, allowed, setupTime) do
    gen_accept_connection(:inet_tcp, acceptPid, socket, myNode, allowed, setupTime)
  end

  def gen_accept_connection(driver, acceptPid, socket, myNode, allowed, setupTime) do
    :erlang.spawn_opt(
      :inet_tcp_dist,
      :do_accept,
      [driver, self(), acceptPid, socket, myNode, allowed, setupTime],
      :dist_util.net_ticker_spawn_options()
    )
  end

  def do_accept(driver, kernel, acceptPid, socket, myNode, allowed, setupTime) do
    receive do
      {^acceptPid, :controller} ->
        timer = :dist_util.start_timer(setupTime)

        case check_ip(driver, socket) do
          true ->
            family = driver.family()

            hSData =
              r_hs_data(
                gen_hs_data(
                  driver,
                  socket
                ),
                kernel_pid: kernel,
                this_node: myNode,
                timer: timer,
                this_flags: 0,
                allowed: allowed,
                f_address: fn s, node ->
                  get_remote_id(
                    family,
                    s,
                    node
                  )
                end
              )

            :dist_util.handshake_other_started(hSData)

          {false, iP} ->
            error_msg(~c"** Connection attempt from disallowed IP ~w ** ~n", [iP])
            :dist_util.shutdown(:inet_tcp_dist, 364, :no_node)
        end
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

  defp get_remote_id(family, socket, node) do
    case :inet.peername(socket) do
      {:ok, address} ->
        case split_node(:erlang.atom_to_list(node), ?@, []) do
          [_, host] ->
            r_net_address(address: address, host: host, protocol: :tcp, family: family)

          _ ->
            :dist_util.shutdown(:inet_tcp_dist, 396, :no_node)
        end

      {:error, _Reason} ->
        :dist_util.shutdown(:inet_tcp_dist, 399, :no_node)
    end
  end

  def setup(node, type, myNode, longOrShortNames, setupTime) do
    gen_setup(:inet_tcp, node, type, myNode, longOrShortNames, setupTime)
  end

  def gen_setup(driver, node, type, myNode, longOrShortNames, setupTime) do
    :erlang.spawn_opt(
      :inet_tcp_dist,
      :do_setup,
      [driver, self(), node, type, myNode, longOrShortNames, setupTime],
      :dist_util.net_ticker_spawn_options()
    )
  end

  def do_setup(driver, kernel, node, type, myNode, longOrShortNames, setupTime) do
    :ok
    timer = :dist_util.start_timer(setupTime)
    family = driver.family()

    {r_net_address(address: {ip, tcpPort}) = netAddress, connectOptions, version} =
      fam_setup(family, node, longOrShortNames, Function.capture(driver, :parse_address, 1))

    :dist_util.reset_timer(timer)

    case driver.connect(ip, tcpPort, connectOptions) do
      {:ok, socket} ->
        hSData =
          r_hs_data(
            gen_hs_data(
              driver,
              socket
            ),
            kernel_pid: kernel,
            other_node: node,
            this_node: myNode,
            timer: timer,
            this_flags: 0,
            other_version: version,
            f_address: fn _, _ ->
              netAddress
            end,
            request_type: type
          )

        :dist_util.handshake_we_started(hSData)

      _ ->
        :ok
        :dist_util.shutdown(:inet_tcp_dist, 448, node)
    end
  end

  def fam_setup(family, node, longOrShortNames, parseAddress) do
    :ok
    [name, host] = splitnode(parseAddress, node, longOrShortNames)
    erlEpmd = :net_kernel.epmd_module()

    case call_epmd_function(erlEpmd, :address_please, [name, host, family]) do
      {:ok, ip, tcpPort, version} ->
        :ok
        fam_setup(family, host, ip, tcpPort, version)

      {:ok, ip} ->
        case erlEpmd.port_please(name, ip) do
          {:port, tcpPort, version} ->
            :ok
            fam_setup(family, host, ip, tcpPort, version)

          _ ->
            :ok
            :dist_util.shutdown(:inet_tcp_dist, 470, node)
        end

      _Other ->
        :ok
        :dist_util.shutdown(:inet_tcp_dist, 474, node)
    end
  end

  defp fam_setup(family, host, ip, tcpPort, version) do
    netAddress = r_net_address(address: {ip, tcpPort}, host: host, protocol: :tcp, family: family)
    {netAddress, connect_options(), version}
  end

  defp connect_options() do
    merge_options(
      case :application.get_env(
             :kernel,
             :inet_dist_connect_options
           ) do
        {:ok, connectOpts} ->
          connectOpts

        _ ->
          []
      end,
      [{:active, false}, {:packet, 2}]
    )
  end

  def close(socket) do
    :inet_tcp.close(socket)
  end

  defp splitnode(parseAddress, node, longOrShortNames) do
    case split_node(:erlang.atom_to_list(node), ?@, []) do
      [name | tail] when tail !== [] ->
        host = :lists.append(tail)

        case split_node(host, ?., []) do
          [_] when longOrShortNames === :longnames ->
            case parseAddress.(host) do
              {:ok, _} ->
                [name, host]

              _ ->
                error_msg(
                  ~c"** System running to use fully qualified hostnames **~n** Hostname ~ts is illegal **~n",
                  [host]
                )

                :dist_util.shutdown(:inet_tcp_dist, 519, node)
            end

          l
          when length(l) > 1 and
                 longOrShortNames === :shortnames ->
            error_msg(
              ~c"** System NOT running to use fully qualified hostnames **~n** Hostname ~ts is illegal **~n",
              [host]
            )

            :dist_util.shutdown(:inet_tcp_dist, 526, node)

          _ ->
            [name, host]
        end

      [_] ->
        error_msg(~c"** Nodename ~p illegal, no '@' character **~n", [node])
        :dist_util.shutdown(:inet_tcp_dist, 533, node)

      _ ->
        error_msg(~c"** Nodename ~p illegal **~n", [node])
        :dist_util.shutdown(:inet_tcp_dist, 536, node)
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

  defp call_epmd_function(mod, fun, args) do
    case :erlang.function_exported(mod, fun, length(args)) do
      true ->
        apply(mod, fun, args)

      _ ->
        apply(:erl_epmd, fun, args)
    end
  end

  defp check_ip(driver, socket) do
    case :application.get_env(:check_ip) do
      {:ok, true} ->
        case get_ifs(socket) do
          {:ok, iFs, iP} ->
            check_ip(driver, iFs, iP)

          _ ->
            :dist_util.shutdown(:inet_tcp_dist, 564, :no_node)
        end

      _ ->
        true
    end
  end

  defp get_ifs(socket) do
    case :inet.peername(socket) do
      {:ok, {iP, _}} ->
        case :inet.getif(socket) do
          {:ok, iFs} ->
            {:ok, iFs, iP}

          error ->
            error
        end

      error ->
        error
    end
  end

  defp check_ip(driver, [{ownIP, _, netmask} | iFs], peerIP) do
    case {driver.mask(netmask, peerIP), driver.mask(netmask, ownIP)} do
      {m, m} ->
        true

      _ ->
        check_ip(driver, iFs, peerIP)
    end
  end

  defp check_ip(_Driver, [], peerIP) do
    {false, peerIP}
  end

  def is_node_name(node) when is_atom(node) do
    case split_node(:erlang.atom_to_list(node), ?@, []) do
      [_, _Host] ->
        true

      _ ->
        false
    end
  end

  def is_node_name(_Node) do
    false
  end

  def tick(driver, socket) do
    case driver.send(socket, [], [:force]) do
      {:error, :closed} ->
        send(self(), {:tcp_closed, socket})
        {:error, :closed}

      r ->
        r
    end
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

  def getopts(s, opts) do
    :inet.getopts(s, opts)
  end
end
