defmodule :m_gen_tcp_socket do
  use Bitwise
  import Kernel, except: [send: 2]
  @behaviour :gen_statem
  require Record
  Record.defrecord(:r_connect_opts, :connect_opts, ifaddr: :undefined,
                                        port: 0, fd: - 1, opts: [])
  Record.defrecord(:r_listen_opts, :listen_opts, ifaddr: :undefined,
                                       port: 0, backlog: 5, fd: - 1, opts: [])
  Record.defrecord(:r_udp_opts, :udp_opts, ifaddr: :undefined,
                                    port: 0, fd: - 1, opts: [{:active, true}])
  Record.defrecord(:r_sctp_opts, :sctp_opts, ifaddr: :undefined,
                                     port: 0, fd: - 1, type: :seqpacket,
                                     opts: [{:mode, :binary}, {:buffer, 65536},
                                                                  {:sndbuf,
                                                                     65536},
                                                                      {:recbuf,
                                                                         1024},
                                                                          {:sctp_events,
                                                                             :undefined}])
  defp socket_inherit_opts() do
    [:priority]
  end

  def connect(sockAddr, opts, timeout) do
    timer = :inet.start_timer(timeout)
    try do
      connect_lookup(sockAddr, opts, timer)
    after
      _ = :inet.stop_timer(timer)
    end
  end

  def connect(address, port, opts, timeout) do
    timer = :inet.start_timer(timeout)
    try do
      connect_lookup(address, port, opts, timer)
    after
      _ = :inet.stop_timer(timer)
    end
  end

  defp connect_lookup(%{family: domain, addr: address,
              port: port} = _SockAddr,
            opts0, timer) do
    opts1 = internalize_setopts(opts0)
    {mod, opts2} = :inet.tcp_module(opts1, address)
    connect_lookup(domain, address, port, mod, opts2, timer)
  end

  defp connect_lookup(address, port, opts0, timer) do
    opts1 = internalize_setopts(opts0)
    {mod, opts2} = :inet.tcp_module(opts1, address)
    domain = domain(mod)
    connect_lookup(domain, address, port, mod, opts2, timer)
  end

  defp connect_lookup(domain, address, port, mod, opts0, timer) do
    {startOpts, opts} = split_start_opts(opts0)
    errRef = make_ref()
    try do
      iPs = val(errRef, mod.getaddrs(address, timer))
      tP = val(errRef, mod.getserv(port))
      cO = val(errRef, :inet.connect_options(opts, mod))
      sAs = sockaddrs(iPs, tP, domain)
      {sAs, cO}
    catch
      {^errRef, reason} ->
        case ((
                {:error, reason}
              )) do
          {:error, :badarg} ->
            exit(:badarg)
          oTHER__ ->
            oTHER__
        end
    else
      {addrs,
         r_connect_opts(fd: fd, ifaddr: bindAddr, port: bindPort,
             opts: connectOpts)} ->
        bindSockaddr = bind_addr(domain, bindAddr, bindPort)
        extraOpts = extra_opts(fd)
        connect_open(addrs, domain, connectOpts, startOpts,
                       extraOpts, timer, bindSockaddr)
    end
  end

  defp connect_open(addrs, domain, connectOpts, startOpts,
            extraOpts, timer, bindAddr) do
    case (start_server(domain,
                         [{:timeout, :inet.timeout(timer)} | startOpts],
                         extraOpts)) do
      {:ok, server} ->
        errRef = make_ref()
        try do
          try_setopts(errRef, server, startOpts, connectOpts)
          try_bind(errRef, server, domain, bindAddr, extraOpts)
          socket = try_connect(errRef, server, addrs, timer)
          mSock = {:"$inet", :gen_tcp_socket, {server, socket}}
          {:ok, mSock}
        catch
          {^errRef, reason} ->
            close_server(server)
            case ((
                    {:error, reason}
                  )) do
              {:error, :badarg} ->
                exit(:badarg)
              oTHER__ ->
                oTHER__
            end
        end
      {:error, _Reason} = error ->
        case ((
                error
              )) do
          {:error, :badarg} ->
            exit(:badarg)
          oTHER__ ->
            oTHER__
        end
    end
  end

  defp try_connect(errRef, server, addrs, timer) do
    defaultError = {:error, :einval}
    val(errRef,
          connect_loop(addrs, server, defaultError, timer))
  end

  defp connect_loop([], _Server, error, _Timer) do
    error
  end

  defp connect_loop([addr | addrs], server, _Error, timer) do
    result = call(server,
                    {:connect, addr, :inet.timeout(timer)})
    case (result) do
      {:ok, _Socket} ->
        result
      {:error, :badarg} ->
        result
      {:error, :einval} ->
        result
      {:error, :timeout} ->
        result
      {:error, _} ->
        connect_loop(addrs, server, result, timer)
    end
  end

  defp extra_opts(fd) when is_integer(fd) do
    cond do
      fd < 0 ->
        %{}
      true ->
        %{fd: fd}
    end
  end

  defp extra_opts(openOpts) when is_list(openOpts) do
    :maps.from_list(openOpts)
  end

  defp default_any(_Domain, :undefined, %{fd: _}) do
    :undefined
  end

  defp default_any(domain, :undefined, _Opts) do
    cond do
      domain === :inet or domain === :inet6 ->
        %{family: domain, addr: :any, port: 0}
      true ->
        :undefined
    end
  end

  defp default_any(_Domain, bindAddr, _Opts) do
    bindAddr
  end

  defp bind_addr(domain, %{family: domain} = bindSockaddr,
            _BindPort) do
    bindSockaddr
  end

  defp bind_addr(domain, bindIP, bindPort)
      when bindIP === :undefined and bindPort === 0 do
    case (:os.type()) do
      {:win32, :nt} ->
        addr = which_bind_address(domain, bindIP)
        %{family: domain, addr: addr, port: bindPort}
      _ ->
        :undefined
    end
  end

  defp bind_addr(:local = domain, bindIP, _BindPort) do
    case (bindIP) do
      :any ->
        :undefined
      {:local, path} ->
        %{family: domain, path: path}
    end
  end

  defp bind_addr(domain, bindIP, bindPort)
      when domain === :inet or domain === :inet6 do
    addr = which_bind_address(domain, bindIP)
    %{family: domain, addr: addr, port: bindPort}
  end

  defp which_bind_address(domain, bindIP) when bindIP === :undefined do
    which_default_bind_address(domain)
  end

  defp which_bind_address(_Domain, bindIP) do
    bindIP
  end

  defp which_default_bind_address(domain) do
    case (:os.type()) do
      {:win32, :nt} ->
        which_default_bind_address2(domain)
      _ ->
        :any
    end
  end

  defp which_default_bind_address2(domain) do
    case (net_getifaddrs(domain)) do
      {:ok, addrs} ->
        upNonLoopbackAddrs = (for (%{flags:
                                     flags} = addr) <- addrs,
                                    not
                                    :lists.member(:loopback,
                                                    flags) and :lists.member(:up,
                                                                               flags) do
                                addr
                              end)
        case (upNonLoopbackAddrs) do
          [%{addr: %{addr: addr}} | _] ->
            addr
          _ ->
            :any
        end
      {:error, _} ->
        :any
    end
  end

  defp net_getifaddrs(:local = _Domain) do
    :net.getifaddrs(%{family: :local, flags: :any})
  end

  defp net_getifaddrs(domain) do
    :net.getifaddrs(domain)
  end

  defp call_bind(_Server, :undefined) do
    :ok
  end

  defp call_bind(server, bindAddr) do
    call(server, {:bind, bindAddr})
  end

  defp default_active_true(opts) do
    case (:lists.keyfind(:active, 1, opts)) do
      {:active, _} ->
        opts
      _ ->
        [{:active, true} | opts]
    end
  end

  def listen(port, opts) do
    opts_1 = internalize_setopts(opts)
    {mod, opts_2} = :inet.tcp_module(opts_1)
    {startOpts, opts_3} = split_start_opts(opts_2)
    case (mod.getserv(port)) do
      {:ok, tP} ->
        case (:inet.listen_options([{:port, tP} | opts_3],
                                     mod)) do
          {:error, :badarg} ->
            exit(:badarg)
          {:ok,
             r_listen_opts(fd: fd, ifaddr: bindAddr, port: bindPort,
                 opts: listenOpts, backlog: backlog)} ->
            domain = domain(mod)
            bindSockaddr = bind_addr(domain, bindAddr, bindPort)
            extraOpts = extra_opts(fd)
            listen_open(domain, listenOpts, startOpts, extraOpts,
                          backlog, bindSockaddr)
        end
      {:error, _} = error ->
        case ((
                error
              )) do
          {:error, :badarg} ->
            exit(:badarg)
          oTHER__ ->
            oTHER__
        end
    end
  end

  defp listen_open(domain, listenOpts, startOpts, extraOpts,
            backLog, bindAddr) do
    case (start_server(domain,
                         [{:timeout, :infinity} | startOpts], extraOpts)) do
      {:ok, server} ->
        errRef = make_ref()
        try do
          case (:os.type()) do
            {:win32, :nt} ->
              try_bind(errRef, server, domain, bindAddr, extraOpts)
              try_setopts(errRef, server, startOpts, listenOpts)
              socket = try_listen(errRef, server, backLog)
              mSock = {:"$inet", :gen_tcp_socket, {server, socket}}
              {:ok, mSock}
            _ ->
              try_setopts(errRef, server, startOpts, listenOpts)
              try_bind(errRef, server, domain, bindAddr, extraOpts)
              socket = try_listen(errRef, server, backLog)
              mSock = {:"$inet", :gen_tcp_socket, {server, socket}}
              {:ok, mSock}
          end
        catch
          {^errRef, reason} ->
            close_server(server)
            case ((
                    {:error, reason}
                  )) do
              {:error, :badarg} ->
                exit(:badarg)
              oTHER__ ->
                oTHER__
            end
        end
      {:error, {:shutdown, reason}} ->
        case ((
                {:error, reason}
              )) do
          {:error, :badarg} ->
            exit(:badarg)
          oTHER__ ->
            oTHER__
        end
      {:error, _} = error ->
        case ((
                error
              )) do
          {:error, :badarg} ->
            exit(:badarg)
          oTHER__ ->
            oTHER__
        end
    end
  end

  defp try_bind(errRef, server, domain, bindAddr0, extraOpts) do
    bindAddr1 = default_any(domain, bindAddr0, extraOpts)
    ok(errRef, call_bind(server, bindAddr1))
  end

  defp try_setopts(errRef, server, startOpts, operationOpts) do
    setOpts = default_active_true([{:start_opts,
                                      startOpts} |
                                       setopts_opts(errRef, operationOpts)])
    ok(errRef, call(server, {:setopts, setOpts}))
  end

  defp try_listen(errRef, server, backLog) do
    val(errRef, call(server, {:listen, backLog}))
  end

  def accept({:"$inet", :gen_tcp_socket,
            {listenServer, listenSocket}},
           timeout) do
    timer = :inet.start_timer(timeout)
    errRef = make_ref()
    try do
      %{start_opts: startOpts} = (serverData = val(errRef,
                                                     call(listenServer,
                                                            :get_server_opts)))
      server = val(errRef,
                     start_server(serverData,
                                    [{:timeout, :inet.timeout(timer)} |
                                         startOpts]))
      socket = val({errRef, server},
                     call(server,
                            {:accept, listenSocket, :inet.timeout(timer)}))
      {:ok, {:"$inet", :gen_tcp_socket, {server, socket}}}
    catch
      {{^errRef, srv}, reason} ->
        stop_server(srv)
        case ((
                {:error, reason}
              )) do
          {:error, :badarg} ->
            exit(:badarg)
          oTHER__ ->
            oTHER__
        end
      {^errRef, reason} ->
        case ((
                {:error, reason}
              )) do
          {:error, :badarg} ->
            exit(:badarg)
          oTHER__ ->
            oTHER__
        end
    after
      _ = :inet.stop_timer(timer)
    end
  end

  def send({:"$inet", :gen_tcp_socket, {server, socket}}, data) do
    case (:socket.getopt(socket, {:otp, :meta})) do
      {:ok,
         %{packet: packet, send_timeout: sendTimeout} = meta} ->
        cond do
          packet === 1 or packet === 2 or packet === 4 ->
            size = :erlang.iolist_size(data)
            header = <<size
                       ::
                       size(packet) - unit(8) - integer - big - unsigned>>
            header_Data = [header, data]
            result = socket_send(socket, header_Data, sendTimeout)
            send_result(server, header_Data, meta, result)
          true ->
            result = socket_send(socket, data, sendTimeout)
            send_result(server, data, meta, result)
        end
      {:ok, _BadMeta} ->
        exit(:badarg)
      {:error, _} = error ->
        error
    end
  end

  defp send_result(server, data, meta, result) do
    case (result) do
      {:error, reason} ->
        case (reason) do
          :econnreset ->
            case (:maps.get(:show_econnreset, meta)) do
              true ->
                result
              false ->
                {:error, :closed}
            end
          {:completion_status, %{info: :econnreset = r}} ->
            case (:maps.get(:show_econnreset, meta)) do
              true ->
                {:error, r}
              false ->
                {:error, :closed}
            end
          {:completion_status, :econnreset = r} ->
            case (:maps.get(:show_econnreset, meta)) do
              true ->
                {:error, r}
              false ->
                {:error, :closed}
            end
          %{info: :econnreset = r} ->
            case (:maps.get(:show_econnreset, meta)) do
              true ->
                {:error, r}
              false ->
                {:error, :closed}
            end
          {:completion_status, %{info: :econnaborted}} ->
            case (:maps.get(:show_econnreset, meta)) do
              true ->
                {:error, :econnreset}
              false ->
                {:error, :closed}
            end
          {:completion_status, :econnaborted} ->
            case (:maps.get(:show_econnreset, meta)) do
              true ->
                {:error, :econnreset}
              false ->
                {:error, :closed}
            end
          %{info: :econnaborted} ->
            case (:maps.get(:show_econnreset, meta)) do
              true ->
                {:error, :econnreset}
              false ->
                {:error, :closed}
            end
          :econnaborted ->
            case (:maps.get(:show_econnreset, meta)) do
              true ->
                {:error, :econnreset}
              false ->
                {:error, :closed}
            end
          {:completion_status, %{info: :netname_deleted}} ->
            case (:maps.get(:show_econnreset, meta)) do
              true ->
                {:error, :econnreset}
              false ->
                {:error, :closed}
            end
          {:completion_status, :netname_deleted} ->
            case (:maps.get(:show_econnreset, meta)) do
              true ->
                {:error, :econnreset}
              false ->
                {:error, :closed}
            end
          %{info: :netname_deleted} ->
            case (:maps.get(:show_econnreset, meta)) do
              true ->
                {:error, :econnreset}
              false ->
                {:error, :closed}
            end
          :netname_deleted ->
            case (:maps.get(:show_econnreset, meta)) do
              true ->
                {:error, :econnreset}
              false ->
                {:error, :closed}
            end
          {:completion_status, %{info: :too_many_cmds}} ->
            {:error, :closed}
          {:completion_status, :too_many_cmds} ->
            {:error, :closed}
          %{info: :too_many_cmds} ->
            {:error, :closed}
          :too_many_cmds ->
            {:error, :closed}
          {:timeout = r, restData} when is_binary(restData) ->
            case (:maps.get(:send_timeout_close, meta)) do
              true ->
                close_server(server)
                {:error, r}
              false ->
                result
            end
          :timeout ->
            case (:maps.get(:send_timeout_close, meta)) do
              true ->
                close_server(server)
                result
              false ->
                {:error, {reason, :erlang.iolist_to_binary(data)}}
            end
          _ ->
            case ((
                    result
                  )) do
              {:error, :badarg} ->
                exit(:badarg)
              oTHER__ ->
                oTHER__
            end
        end
      :ok ->
        :ok
    end
  end

  def sendfile({:"$inet", :gen_tcp_socket, {_Server, socket}},
           fileHandle, offset, count) do
    case (:socket.getopt(socket, {:otp, :meta})) do
      {:ok, %{packet: _}} ->
        try do
          :socket.sendfile(socket, fileHandle, offset, count,
                             :infinity)
        catch
          class, reason when (class === :error and
                                reason === :badarg)
                             ->
            case (__STACKTRACE__) do
              [{:socket, :sendfile, args, _} | _] when args === 5 or
                                                         tl(tl(tl(tl(tl(args))))) === []
                                                       ->
                {class, reason}
              _ ->
                :erlang.raise(class, reason, __STACKTRACE__)
            end
          class, :notsup when class === :error ->
            {class, :enotsup}
        end
      {:ok, _BadMeta} ->
        {:error, :badarg}
      {:error, _} = error ->
        error
    end
  end

  def recv({:"$inet", :gen_tcp_socket, {server, _Socket}}, length,
           timeout) do
    case ((
            call(server, {:recv, length, timeout})
          )) do
      {:error, :badarg} ->
        exit(:badarg)
      oTHER__ ->
        oTHER__
    end
  end

  def shutdown({:"$inet", :gen_tcp_socket, {server, _Socket}}, how) do
    result = call(server, {:shutdown, how})
    case ((
            result
          )) do
      {:error, :badarg} ->
        exit(:badarg)
      oTHER__ ->
        oTHER__
    end
  end

  def close({:"$inet", :gen_tcp_socket, {server, _Socket}}) do
    case ((
            close_server(server)
          )) do
      {:error, :badarg} ->
        exit(:badarg)
      oTHER__ ->
        oTHER__
    end
  end

  defp close_server(server) do
    result = call(server, :close)
    stop_server(server)
    result
  end

  def controlling_process({:"$inet", :gen_tcp_socket, {server, _Socket}} = s,
           newOwner)
      when is_pid(newOwner) do
    case (call(server, {:controlling_process, newOwner})) do
      :ok ->
        :ok
      :transfer ->
        controlling_process(s, newOwner, server)
      {:error, _} = error ->
        error
    end
  end

  defp controlling_process(s, newOwner, server) do
    receive do
      {:tcp, ^s, _Data} = msg ->
        controlling_process(s, newOwner, server, msg)
      {:tcp_closed, ^s} = msg ->
        controlling_process(s, newOwner, server, msg)
      {^s, {:data, _Data}} = msg ->
        controlling_process(s, newOwner, server, msg)
    after 0 ->
      call(server, :controlling_process)
    end
  end

  defp controlling_process(s, newOwner, server, msg) do
    send(newOwner, msg)
    controlling_process(s, newOwner, server)
  end

  def monitor({:"$inet", :gen_tcp_socket,
            {_Server, eSock}} = socket) do
    case (:socket_registry.monitor(eSock,
                                     %{msocket: socket})) do
      {:error, reason} ->
        :erlang.error({:invalid, reason})
      mRef when is_reference(mRef) ->
        mRef
    end
  end

  def monitor(socket) do
    :erlang.error(:badarg, [socket])
  end

  def cancel_monitor(mRef) when is_reference(mRef) do
    :socket.cancel_monitor(mRef)
  end

  def cancel_monitor(mRef) do
    :erlang.error(:badarg, [mRef])
  end

  def setopts({:"$inet", :gen_tcp_socket, {server, _Socket}}, opts)
      when is_list(opts) do
    try do
      (
        call(server, {:setopts, internalize_setopts(opts)})
      )
    catch
      :exit, :badarg ->
        {:error, :einval}
    end
  end

  def getopts({:"$inet", :gen_tcp_socket, {server, _Socket}}, opts)
      when is_list(opts) do
    try do
      (
        call(server, {:getopts, internalize_getopts(opts)})
      )
    catch
      :exit, :badarg ->
        {:error, :einval}
    end
  end

  def sockname({:"$inet", :gen_tcp_socket, {_Server, socket}}) do
    case (:socket.sockname(socket)) do
      {:ok, sockAddr} ->
        {:ok, address(sockAddr)}
      {:error, _} = error ->
        error
    end
  end

  def socknames(socket) do
    case (sockname(socket)) do
      {:ok, addr} ->
        {:ok, [addr]}
      {:error, _} = error ->
        error
    end
  end

  def peername({:"$inet", :gen_tcp_socket, {_Server, socket}}) do
    case (:socket.peername(socket)) do
      {:ok, sockAddr} ->
        {:ok, address(sockAddr)}
      {:error, _} = error ->
        error
    end
  end

  def getstat({:"$inet", :gen_tcp_socket, {server, _Socket}}, what)
      when is_list(what) do
    call(server, {:getstat, what})
  end

  def info({:"$inet", :gen_tcp_socket, {server, _Socket}}) do
    case (call(server, :info)) do
      {:error, :closed} ->
        %{rstates: [:closed], wstates: [:closed]}
      other ->
        other
    end
  end

  def socket_to_list({:"$inet", :gen_tcp_socket, {_Server, socket}}) do
    '#Socket' ++ id = :socket.to_list(socket)
    '#InetSocket' ++ id
  end

  def socket_to_list(socket) do
    :erlang.error(:badarg, [socket])
  end

  def which_sockets() do
    which_sockets(:socket.which_sockets(:tcp))
  end

  defp which_sockets(socks) do
    which_sockets(socks, [])
  end

  defp which_sockets([], acc) do
    acc
  end

  defp which_sockets([sock | socks], acc) do
    case (:socket.getopt(sock, {:otp, :meta})) do
      {:ok, :undefined} ->
        which_sockets(socks, acc)
      {:ok, _Meta} ->
        %{owner: owner} = :socket.info(sock)
        mSock = {:"$inet", :gen_tcp_socket, {owner, sock}}
        which_sockets(socks, [mSock | acc])
      _ ->
        which_sockets(socks, acc)
    end
  end

  def which_packet_type({:"$inet", :gen_tcp_socket, {_Server, socket}}) do
    case (:socket.getopt(socket, {:otp, :meta})) do
      {:ok, %{packet: type}} ->
        {:ok, type}
      _ ->
        :error
    end
  end

  def unrecv({:"$inet", :gen_tcp_socket, {_Server, _Socket}},
           _Data) do
    {:error, :enotsup}
  end

  def fdopen(fd, opts) when (is_integer(fd) and 0 <= fd and
                           is_list(opts)) do
    opts_1 = internalize_setopts(opts)
    {mod, opts_2} = :inet.tcp_module(opts_1)
    domain = domain(mod)
    {startOpts, opts_3} = split_start_opts(opts_2)
    extraOpts = extra_opts(fd)
    case (start_server(domain,
                         [{:timeout, :infinity} | startOpts], extraOpts)) do
      {:ok, server} ->
        errRef = make_ref()
        try do
          setopts = [{:start_opts, startOpts} |
                         setopts_opts(errRef, opts_3)]
          ok(errRef, call(server, {:setopts, setopts}))
          socket = val(errRef, call(server, :fdopen))
          {:ok, {:"$inet", :gen_tcp_socket, {server, socket}}}
        catch
          {^errRef, reason} ->
            close_server(server)
            case ((
                    {:error, reason}
                  )) do
              {:error, :badarg} ->
                exit(:badarg)
              oTHER__ ->
                oTHER__
            end
        end
      {:error, {:shutdown, reason}} ->
        case ((
                {:error, reason}
              )) do
          {:error, :badarg} ->
            exit(:badarg)
          oTHER__ ->
            oTHER__
        end
      {:error, _} = error ->
        case ((
                error
              )) do
          {:error, :badarg} ->
            exit(:badarg)
          oTHER__ ->
            oTHER__
        end
    end
  end

  defp socket_send(socket, data, timeout) do
    result = :socket.send(socket, data, timeout)
    case (result) do
      {:error, {:timeout = _Reason, restData}} = e
          when is_binary(restData) ->
        e
      {:error, {_Reason, restData}} when is_binary(restData)
                                         ->
        {:error, :econnreset}
      {:error, reason} ->
        {:error,
           case (reason) do
             :epipe ->
               :econnreset
             _ ->
               reason
           end}
      {:ok, restData} when is_binary(restData) ->
        {:error, :econnreset}
      :ok ->
        :ok
    end
  end

  defp socket_recv_peek(socket, length) do
    options = [:peek]
    result = :socket.recv(socket, length, options, :nowait)
    result
  end

  defp socket_recv(socket, length) do
    result = :socket.recv(socket, length, :nowait)
    result
  end

  defp socket_close(socket) do
    case (:socket.close(socket)) do
      :ok ->
        :ok
      {:error, :closed} ->
        :ok
    end
  end

  defp socket_cancel(socket, selectInfo) do
    case (:socket.cancel(socket, selectInfo)) do
      :ok ->
        :ok
      {:error, :closed} ->
        :ok
      {:error, _} = eRROR ->
        eRROR
    end
  end

  defp ok(_ErrRef, :ok) do
    :ok
  end

  defp ok(errRef, {:error, reason}) do
    throw({errRef, reason})
  end

  defp val(_ErrRef, {:ok, val}) do
    val
  end

  defp val(errRef, {:error, reason}) do
    throw({errRef, reason})
  end

  defp address(sockAddr) do
    case (sockAddr) do
      %{family: family, addr: iP, port: port}
          when family === :inet or family === :inet6 ->
        {iP, port}
      %{family: :local, path: path} ->
        {:local, path}
    end
  end

  defp domain(mod) do
    case (mod) do
      :inet_tcp ->
        :inet
      :inet6_tcp ->
        :inet6
      :local_tcp ->
        :local
    end
  end

  defp sockaddrs([], _TP, _Domain) do
    []
  end

  defp sockaddrs([{:local, path} | iPs], tP, domain)
      when domain === :local do
    [%{family: domain, path: path} | sockaddrs(iPs, tP,
                                                 domain)]
  end

  defp sockaddrs([iP | iPs], tP, domain) do
    [%{family: domain, addr: iP, port: tP} | sockaddrs(iPs,
                                                         tP, domain)]
  end

  defp internalize_setopts(opts) do
    for opt <- opts do
      case (opt) do
        :binary ->
          {:mode, :binary}
        :list ->
          {:mode, :list}
        :inet ->
          {:tcp_module, :inet_tcp}
        :inet6 ->
          {:tcp_module, :inet6_tcp}
        :local ->
          {:tcp_module, :local_tcp}
        {tag, _} when is_atom(tag) ->
          opt
        {:raw, level, key, value} ->
          {:raw, {level, key, value}}
        _ ->
          exit(:badarg)
      end
    end
  end

  defp internalize_getopts(opts) do
    for opt <- opts do
      case (opt) do
        tag when is_atom(tag) ->
          opt
        {:raw, _} ->
          opt
        {:raw, level, key, valueSpec} ->
          {:raw, {level, key, valueSpec}}
        _ ->
          exit(:badarg)
      end
    end
  end

  defp externalize_getopts(opts) do
    for opt <- opts do
      case (opt) do
        {:raw, {level, key, value}} ->
          {:raw, level, key, value}
        {tag, _} when is_atom(tag) ->
          opt
        _ ->
          exit(:badarg)
      end
    end
  end

  defp split_start_opts(opts) do
    {startOpts,
       nonStartOpts} = :lists.partition(fn {:sys_debug, _} ->
                                             true
                                           _ ->
                                             false
                                        end,
                                          opts)
    {for opt <- startOpts do
       case (opt) do
         {:sys_debug, val} ->
           {:debug, val}
         _ ->
           opt
       end
     end,
       nonStartOpts}
  end

  defp setopts_opts(errRef, opts) do
    socketOpts = socket_opts()
    serverOpts = server_opts()
    for ({tag, _} = opt) <- opts,
          (cond do
             :erlang.is_map_key(tag, socketOpts) ->
               true
             :erlang.is_map_key(tag, serverOpts) ->
               true
             true ->
               case (ignore_optname(tag)) do
                 true ->
                   false
                 false ->
                   throw({errRef, :badarg})
               end
           end) do
      opt
    end
  end

  defp socket_setopt(socket, :raw, value) do
    case (value) do
      {level, key, val} ->
        try do
          :socket.setopt_native(socket, {level, key}, val)
        catch
          {:invalid, _} ->
            {:error, :einval}
        else
          res ->
            res
        end
      _ ->
        {:error, :einval}
    end
  end

  defp socket_setopt(socket, {domain, _} = opt, value)
      when is_atom(domain) do
    res = :socket.setopt(socket, opt,
                           socket_setopt_value(opt, value))
    res
  end

  defp socket_setopt(socket, domainProps, value)
      when is_list(domainProps) do
    case (:socket.getopt(socket, :otp, :domain)) do
      {:ok, domain} ->
        case (:lists.keysearch(domain, 1, domainProps)) do
          {:value, {^domain, opt}} ->
            res = :socket.setopt(socket, opt,
                                   socket_setopt_value(opt, value))
            res
          false ->
            {:error, :einval}
        end
      {:error, _} ->
        {:error, :einval}
    end
  end

  defp socket_setopt_value({:socket, :linger}, {onOff, linger}) do
    %{onoff: onOff, linger: linger}
  end

  defp socket_setopt_value({:socket, :bindtodevice}, deviceBin)
      when is_binary(deviceBin) do
    :erlang.binary_to_list(deviceBin)
  end

  defp socket_setopt_value(_Opt, value) do
    value
  end

  defp socket_getopt(socket, :raw, val) do
    case (val) do
      {level, key, valueSpec} ->
        case (:socket.getopt_native(socket, {level, key},
                                      valueSpec)) do
          {:ok, value} ->
            {:ok, {level, key, value}}
          {:error, {:invalid, _} = _Reason} ->
            {:error, :einval}
          {:error, _Reason} = eRROR ->
            eRROR
        end
      _ ->
        {:error, :einval}
    end
  end

  defp socket_getopt(socket, {domain, _} = opt, _)
      when is_atom(domain) do
    res = :socket.getopt(socket, opt)
    socket_getopt_value(opt, res)
  end

  defp socket_getopt(socket, domainProps, _)
      when is_list(domainProps) do
    case (:socket.getopt(socket, :otp, :domain)) do
      {:ok, domain} ->
        case (:lists.keysearch(domain, 1, domainProps)) do
          {:value, {^domain, opt}} ->
            res = :socket.getopt(socket, opt)
            socket_getopt_value(opt, res)
          false ->
            {:error, :einval}
        end
      {:error, _DReason} ->
        {:error, :einval}
    end
  end

  defp socket_getopt_value({:socket, :linger},
            {:ok, %{onoff: onOff, linger: linger}}) do
    {:ok, {onOff, linger}}
  end

  defp socket_getopt_value({level, :pktoptions}, {:ok, pktOpts})
      when (level === :ip and is_list(pktOpts)) or
             (level === :ipv6 and is_list(pktOpts)) do
    {:ok,
       for %{type: type, value: value} <- pktOpts do
         {type, value}
       end}
  end

  defp socket_getopt_value(_Tag, {:ok, _Value} = ok) do
    ok
  end

  defp socket_getopt_value(_Tag, {:error, _} = error) do
    error
  end

  defp socket_copy_opt(socket, tag, targetSocket) when is_atom(tag) do
    case (socket_opts()) do
      %{^tag => {_Level, _Key} = opt} ->
        case (:socket.is_supported(:options, opt)) do
          true ->
            case (:socket.getopt(socket, opt)) do
              {:ok, value} ->
                :socket.setopt(targetSocket, opt, value)
              {:error, _Reason} = error ->
                error
            end
          false ->
            :ok
        end
      %{} = _X ->
        {:error, :einval}
    end
  end

  defp ignore_optname(tag) do
    case (tag) do
      :tcp_module ->
        true
      :ip ->
        true
      :backlog ->
        true
      :high_msgq_watermark ->
        true
      :high_watermark ->
        true
      :low_msgq_watermark ->
        true
      :low_watermark ->
        true
      :nopush ->
        case (nopush_or_cork()) do
          :undefined ->
            true
          _ ->
            false
        end
      _ ->
        false
    end
  end

  defp socket_opts() do
    opts = %{buffer: {:otp, :rcvbuf}, debug: {:otp, :debug},
               fd: {:otp, :fd},
               bind_to_device: {:socket, :bindtodevice},
               dontroute: {:socket, :dontroute},
               exclusiveaddruse: {:socket, :exclusiveaddruse},
               keepalive: {:socket, :keepalive},
               linger: {:socket, :linger},
               priority: {:socket, :priority},
               recbuf: {:socket, :rcvbuf},
               reuseaddr: {:socket, :reuseaddr},
               sndbuf: {:socket, :sndbuf}, nodelay: {:tcp, :nodelay},
               recvtos: {:ip, :recvtos}, recvttl: {:ip, :recvttl},
               tos: {:ip, :tos}, ttl: {:ip, :ttl},
               recvtclass: {:ipv6, :recvtclass},
               ipv6_v6only: {:ipv6, :v6only}, tclass: {:ipv6, :tclass},
               raw: :raw,
               pktoptions:
               [{:inet, {:ip, :pktoptions}}, {:inet6,
                                                {:ipv6, :pktoptions}}]}
    case (nopush_or_cork()) do
      :undefined ->
        opts
      nopushOpt ->
        :maps.put(:nopush, {:tcp, nopushOpt}, opts)
    end
  end

  defp nopush_or_cork() do
    case (:os.type()) do
      {:unix, :darwin} ->
        :undefined
      _ ->
        optsSup = :socket.supports(:options)
        noPushKey = {:tcp, :nopush}
        case (:lists.keysearch(noPushKey, 1, optsSup)) do
          {:value, {^noPushKey, true}} ->
            :nopush
          _ ->
            corkKey = {:tcp, :cork}
            case (:lists.keysearch(corkKey, 1, optsSup)) do
              {:value, {^corkKey, true}} ->
                :cork
              _ ->
                :undefined
            end
        end
    end
  end

  defp server_read_write_opts() do
    %{packet: :raw, packet_size: 67108864,
        show_econnreset: false}
  end

  defp server_read_opts() do
    :maps.merge(%{active: false, mode: :list, header: 0,
                    deliver: :term, start_opts: [], line_delimiter: ?\n,
                    exit_on_close: true},
                  server_read_write_opts())
  end

  defp server_write_opts() do
    :maps.merge(%{send_timeout: :infinity,
                    send_timeout_close: false, delay_send: false},
                  server_read_write_opts())
  end

  defp server_opts() do
    :maps.merge(server_read_opts(), server_write_opts())
  end

  defp meta(d) do
    :maps.with(:maps.keys(server_write_opts()), d)
  end

  defp start_server(domain, startOpts, extraOpts) do
    owner = self()
    arg = {:open, domain, extraOpts, owner}
    case (:gen_statem.start(:gen_tcp_socket, arg,
                              startOpts)) do
      {:ok, server} ->
        {:ok, server}
      {:error, _} = error ->
        error
    end
  end

  defp start_server(serverData, startOpts) do
    owner = self()
    arg = {:prepare, serverData, owner}
    case (:gen_statem.start(:gen_tcp_socket, arg,
                              startOpts)) do
      {:ok, server} ->
        {:ok, server}
      {:error, _} = error ->
        error
    end
  end

  defp call(server, call) do
    try do
      :gen_statem.call(server, call)
    catch
      :exit, {:noproc, {:gen_statem, :call, _Args}} ->
        {:error, :closed}
      :exit, {{:shutdown, _}, _} ->
        {:error, :closed}
      c, e ->
        error_msg('~w call failed: ~n      Call:  ~p~n      Class: ~p~n      Error: ~p~n      Stack: ~p',
                    [:gen_tcp_socket, call, c, e, __STACKTRACE__])
        :erlang.raise(c, e, __STACKTRACE__)
    end
  end

  defp stop_server(server) do
    try do
      :gen_statem.stop(server, {:shutdown, :closed},
                         :infinity)
    catch
      _, _ ->
        :ok
    else
      _ ->
        :ok
    end
  end

  def callback_mode() do
    :handle_event_function
  end

  Record.defrecord(:r_controlling_process, :controlling_process, owner: :undefined,
                                               state: :undefined)
  Record.defrecord(:r_accept, :accept, info: :undefined,
                                  from: :undefined, listen_socket: :undefined)
  Record.defrecord(:r_connect, :connect, info: :undefined,
                                   from: :undefined, addr: :undefined)
  Record.defrecord(:r_recv, :recv, info: :undefined)
  Record.defrecord(:r_params, :params, socket: :undefined,
                                  owner: :undefined, owner_mon: :undefined)
  def init({:open, domain, extraOpts, owner}) do
    :erlang.process_flag(:trap_exit, true)
    ownerMon = :erlang.monitor(:process, owner)
    extra = %{}
    case (socket_open(domain, extraOpts, extra)) do
      {:ok, socket} ->
        d = server_opts()
        :ok = :socket.setopt(socket, {:otp, :iow}, true)
        :ok = :socket.setopt(socket, {:otp, :meta}, meta(d))
        p = r_params(socket: socket, owner: owner, owner_mon: ownerMon)
        {:ok, :connect,
           {p, Map.merge(d, %{type: :undefined, buffer: <<>>})}}
      {:error, reason} ->
        {:stop, {:shutdown, reason}}
    end
  end

  def init({:prepare, d, owner}) do
    :erlang.process_flag(:trap_exit, true)
    ownerMon = :erlang.monitor(:process, owner)
    p = r_params(owner: owner, owner_mon: ownerMon)
    {:ok, :accept,
       {p, Map.merge(d, %{type: :undefined, buffer: <<>>})}}
  end

  def init(arg) do
    error_report([{:badarg,
                     {:gen_tcp_socket, :init, [arg]}}])
    :erlang.error(:badarg, [arg])
  end

  defp socket_open(domain, %{fd: fD} = extraOpts, extra) do
    opts = Map.merge(:maps.merge(extra,
                                   :maps.remove(:fd, extraOpts)), %{dup: false,
                                                                      domain:
                                                                      domain,
                                                                      type:
                                                                      :stream,
                                                                      protocol:
                                                                      proto(domain)})
    :socket.open(fD, opts)
  end

  defp socket_open(domain, extraOpts, extra) do
    opts = :maps.merge(extra, extraOpts)
    :socket.open(domain, :stream, proto(domain), opts)
  end

  defp proto(domain) do
    case (domain) do
      :inet ->
        :tcp
      :inet6 ->
        :tcp
      _ ->
        :default
    end
  end

  def terminate(_Reason, state, {_P, _} = p_D) do
    case (state) do
      r_controlling_process(state: oldState) ->
        terminate(oldState, p_D)
      _ ->
        terminate(state, p_D)
    end
  end

  defp terminate(state, {r_params(socket: socket) = p, d}) do
    case (state) do
      :closed ->
        :ok
      :closed_read ->
        _ = socket_close(socket)
        :ok
      :closed_read_write ->
        _ = socket_close(socket)
        :ok
      _ ->
        case (state) do
          :accept ->
            :ok
          r_accept() ->
            :ok
          _ ->
            _ = socket_close(socket)
            :ok
        end
        {_D_1, actionsR} = (case (state) do
                              r_controlling_process(state: oldState) ->
                                cleanup_close_read(p, d, oldState, :closed)
                              _ ->
                                cleanup_close_read(p, d, state, :closed)
                            end)
        for ({:reply, _From,
                _Msg} = reply) <- reverse(actionsR) do
          :gen_statem.reply(reply)
        end
        :ok
    end
    :void
  end

  defp module_socket(r_params(socket: socket)) do
    {:"$inet", :gen_tcp_socket, {self(), socket}}
  end

  defp is_packet_option_value(value) do
    case (value) do
      0 ->
        true
      1 ->
        true
      2 ->
        true
      4 ->
        true
      :raw ->
        true
      :sunrm ->
        true
      :asn1 ->
        true
      :cdr ->
        true
      :fcgi ->
        true
      :line ->
        true
      :tpkt ->
        true
      :http ->
        true
      :httph ->
        true
      :http_bin ->
        true
      :httph_bin ->
        true
      _ ->
        false
    end
  end

  def handle_event({:call, from}, :get_server_opts, _State,
           {_P, d}) do
    serverData = :maps.with(:maps.keys(server_opts()), d)
    {:keep_state_and_data,
       [{:reply, from, {:ok, serverData}}]}
  end

  def handle_event(:info, {:DOWN, ownerMon, _, _, reason}, _State,
           {r_params(owner_mon: ownerMon) = _P, _D} = p_D) do
    {:stop, {:shutdown, reason}, p_D}
  end

  def handle_event(:info, {:"$socket", socket, :counter_wrap, counter},
           :connected = _State, {r_params(socket: socket) = p, d}) do
    {:keep_state, {p, wrap_counter(counter, d)}}
  end

  def handle_event(:info, {:"$socket", socket, :counter_wrap, counter},
           r_recv() = _State, {r_params(socket: socket) = p, d}) do
    {:keep_state, {p, wrap_counter(counter, d)}}
  end

  def handle_event(:info, {:"$socket", _Socket, :counter_wrap, _Counter},
           _State, _P_D) do
    {:keep_state_and_data, [:postpone]}
  end

  def handle_event({:call, {caller, _} = from},
           {:controlling_process, newOwner}, state,
           {p, _D} = p_D) do
    case (p) do
      r_params(owner: ^newOwner) ->
        {:keep_state_and_data, [{:reply, from, :ok}]}
      r_params(owner: ^caller) ->
        {:next_state, r_controlling_process(owner: newOwner, state: state), p_D,
           [{:reply, from, :transfer}]}
      r_params() ->
        {:keep_state_and_data,
           [{:reply, from, {:error, :not_owner}}]}
    end
  end

  def handle_event({:call, {owner, _} = from}, :controlling_process,
           r_controlling_process(owner: newOwner, state: state),
           {r_params(owner: owner, owner_mon: ownerMon) = p, d}) do
    newOwnerMon = :erlang.monitor(:process, newOwner)
    true = :erlang.demonitor(ownerMon, [:flush])
    {:next_state, state,
       {r_params(p, owner: newOwner,  owner_mon: newOwnerMon), d},
       [{:reply, from, :ok}]}
  end

  def handle_event(_Type, _Content, r_controlling_process(), _StateData) do
    {:keep_state_and_data, [:postpone]}
  end

  def handle_event({:call, from}, :close, state, {p, d} = p_D) do
    case (state) do
      :closed_read ->
        {:next_state, :closed, p_D,
           [{:reply, from, socket_close(r_params(p, :socket))}]}
      :closed_read_write ->
        {:next_state, :closed, p_D,
           [{:reply, from, socket_close(r_params(p, :socket))}]}
      :closed ->
        {:keep_state_and_data, [{:reply, from, :ok}]}
      _ ->
        next_state(p,
                     cleanup_close_read(p, %{d | active: false}, state,
                                          :closed),
                     :closed, [{:reply, from, socket_close(r_params(p, :socket))}])
    end
  end

  def handle_event({:call, from}, {:getopts, opts}, state,
           {p, d}) do
    result = (case (state_getopts(p, d, state, opts)) do
                {:ok, optVals} ->
                  {:ok, externalize_getopts(optVals)}
                {:error, _} = eRROR ->
                  eRROR
              end)
    {:keep_state_and_data, [{:reply, from, result}]}
  end

  def handle_event({:call, from}, {:setopts, opts}, state,
           {p, d}) do
    {result_1, d_1} = state_setopts(p, d, state, opts)
    result = (case (result_1) do
                {:error, :enoprotoopt} ->
                  _ = :socket.setopt(r_params(p, :socket), {:otp, :meta},
                                       meta(d_1))
                  {:error, :einval}
                {:error, {:invalid, _}} ->
                  _ = :socket.setopt(r_params(p, :socket), {:otp, :meta},
                                       meta(d_1))
                  {:error, :einval}
                {:error, :einval} ->
                  _ = :socket.setopt(r_params(p, :socket), {:otp, :meta},
                                       meta(d_1))
                  result_1
                _ ->
                  :ok = :socket.setopt(r_params(p, :socket), {:otp, :meta},
                                         meta(d_1))
                  result_1
              end)
    reply = {:reply, from, result}
    case (state) do
      :connected ->
        handle_connected(p, handle_buffered(p, d_1), [reply])
      _ ->
        {:keep_state, {p, d_1}, [reply]}
    end
  end

  def handle_event({:call, from}, {:getstat, what}, state,
           {p, d}) do
    case (state) do
      :closed ->
        {:keep_state_and_data,
           [{:reply, from, {:error, :closed}}]}
      _ ->
        {d_1, result} = getstat(r_params(p, :socket), d, what)
        {:keep_state, {p, d_1}, [{:reply, from, {:ok, result}}]}
    end
  end

  def handle_event({:call, from}, :info, state, {p, d}) do
    case (state) do
      :closed ->
        {:keep_state_and_data,
           [{:reply, from,
               %{rstates: [:closed], wstates: [:closed]}}]}
      _ ->
        {d_1, result} = handle_info(r_params(p, :socket), r_params(p, :owner),
                                      d)
        {:keep_state, {p, d_1}, [{:reply, from, result}]}
    end
  end

  def handle_event(type, content, :closed = state, p_D) do
    handle_closed(type, content, state, p_D)
  end

  def handle_event({:call, from}, {:shutdown, how} = _SHUTDOWN,
           state, {p, d}) do
    case (state) do
      :closed_read when how === :read ->
        {:keep_state_and_data, [{:reply, from, :ok}]}
      :closed_read_write when how === :read_write ->
        {:keep_state_and_data, [{:reply, from, :ok}]}
      _ ->
        case (handle_shutdown(p, state, how)) do
          {:keep, sRes} ->
            {:keep_state_and_data, [{:reply, from, sRes}]}
          {nextState, sRes} ->
            next_state(p,
                         cleanup_close_read(p, %{d | active: false}, state,
                                              :closed),
                         nextState, [{:reply, from, sRes}])
        end
    end
  end

  def handle_event(type, content, state, p_D)
      when state === :closed_read or state === :closed_read_write do
    handle_closed(type, content, state, p_D)
  end

  def handle_event({:call, from}, {:accept, listenSocket, timeout},
           :accept = _State, {p, d}) do
    handle_accept(p, d, from, listenSocket, timeout,
                    :accept)
  end

  def handle_event(type, content, :accept = state, p_D) do
    handle_unexpected(type, content, state, p_D)
  end

  def handle_event(:info, {:"$socket", listenSocket, :select, selectRef},
           r_accept(info: {:select_info, _, selectRef}, from: from,
               listen_socket: listenSocket),
           {p, d}) do
    handle_accept(p, d, from, listenSocket, :update,
                    :select)
  end

  def handle_event(:info,
           {:"$socket", listenSocket, :completion,
              {completionRef, completionStatus}},
           r_accept(info: {:completion_info, _, completionRef},
               from: from, listen_socket: listenSocket),
           {p, d}) do
    handle_accept(p, d, from, listenSocket, :update,
                    completionStatus)
  end

  def handle_event(:info,
           {:"$socket", listenSocket, :abort, {selectRef, reason}},
           r_accept(info: {:select_info, _, selectRef}, from: from,
               listen_socket: listenSocket),
           {p, d}) do
    {:next_state, :closed, {p, d},
       [{:reply, from, {:error, reason}}]}
  end

  def handle_event(:info,
           {:"$socket", listenSocket, :abort, {completionRef, reason}},
           r_accept(info: {:completion_info, _, completionRef},
               from: from, listen_socket: listenSocket),
           {p, d}) do
    {:next_state, :closed, {p, d},
       [{:reply, from, {:error, reason}}]}
  end

  def handle_event({:timeout, :accept}, :accept,
           r_accept(info: selectInfo, from: from,
               listen_socket: listenSocket),
           {p, d}) do
    _ = socket_cancel(listenSocket, selectInfo)
    {:next_state, :closed, {p, d},
       [{:reply, from, {:error, :timeout}}]}
  end

  def handle_event(type, content, r_accept() = state, p_D) do
    handle_unexpected(type, content, state, p_D)
  end

  def handle_event({:call, from}, {:bind, bindAddr} = _BIND, _State,
           {p, _D}) do
    result = :socket.bind(r_params(p, :socket), bindAddr)
    {:keep_state_and_data, [{:reply, from, result}]}
  end

  def handle_event({:call, from}, {:listen, backlog} = _LISTEN,
           _State, {r_params(socket: socket) = p, d}) do
    result = (case (:socket.listen(socket, backlog)) do
                :ok ->
                  {:ok, socket}
                {:error, _} = error ->
                  error
              end)
    {:keep_state, {p, Map.put(d, :type, :listen)},
       [{:reply, from, result}]}
  end

  def handle_event({:call, from}, {:recv, _Length, _Timeout},
           _State, {_P, %{active: active} = _D})
      when active !== false do
    {:keep_state_and_data,
       [{:reply, from, {:error, :einval}}]}
  end

  def handle_event({:call, from}, {:connect, addr, timeout},
           :connect = _State, {p, d}) do
    handle_connect(p, d, from, addr, timeout, :connect)
  end

  def handle_event({:call, from}, {:recv, _Length, _Timeout},
           :connect = _State, _P_D) do
    {:keep_state_and_data,
       [{:reply, from, {:error, :enotconn}}]}
  end

  def handle_event({:call, from}, :fdopen, :connect = _State,
           {r_params(socket: socket) = p, d}) do
    handle_connected(p, Map.put(d, :type, :fdopen),
                       [{:reply, from, {:ok, socket}}])
  end

  def handle_event(type, content, :connect = state, p_D) do
    handle_unexpected(type, content, state, p_D)
  end

  def handle_event(:info, {:"$socket", socket, :select, selectRef},
           r_connect(info: {:select_info, _, selectRef}, from: from,
               addr: addr) = _State,
           {r_params(socket: socket) = p, d}) do
    handle_connect(p, d, from, addr, :update, :select)
  end

  def handle_event(:info, {:"$socket", socket, :abort, {selectRef, reason}},
           r_connect(info: {:select_info, _, selectRef},
               from: from) = _State,
           {r_params(socket: socket) = _P, _D} = p_D) do
    _ = socket_close(socket)
    {:next_state, :closed, p_D,
       [{:reply, from, {:error, reason}}]}
  end

  def handle_event(:info,
           {:"$socket", socket, :completion,
              {completionRef, completionStatus}},
           r_connect(info: {:completion_info, _, completionRef},
               from: from, addr: addr) = _State,
           {r_params(socket: socket) = p, d}) do
    handle_connect(p, d, from, addr, :update,
                     completionStatus)
  end

  def handle_event(:info,
           {:"$socket", socket, :abort, {completionRef, reason}},
           r_connect(info: {:completion_info, _, completionRef},
               from: from) = _State,
           {r_params(socket: socket) = _P, _D} = p_D) do
    _ = socket_close(socket)
    newReason = (case (reason) do
                   {:completion_status, %{info: :netname_deleted}} ->
                     :closed
                   {:completion_status, :netname_deleted} ->
                     :closed
                   {:completion_status, %{info: iNFO}} ->
                     iNFO
                   {:completion_status, iNFO} ->
                     iNFO
                   _ ->
                     reason
                 end)
    {:next_state, :closed, p_D,
       [{:reply, from, {:error, newReason}}]}
  end

  def handle_event({:timeout, :connect}, :connect,
           r_connect(info: selectInfo, from: from),
           {r_params(socket: socket) = _P, _D} = p_D) do
    _ = socket_cancel(socket, selectInfo)
    _ = socket_close(socket)
    {:next_state, :closed, p_D,
       [{:reply, from, {:error, :timeout}}]}
  end

  def handle_event({:call, from}, {:recv, _Length, _Timeout},
           r_connect() = _State, _P_D) do
    {:keep_state_and_data,
       [{:reply, from, {:error, :enotconn}}]}
  end

  def handle_event(type, content, r_connect() = state, p_D) do
    handle_unexpected(type, content, state, p_D)
  end

  def handle_event({:call, from}, {:recv, length, timeout}, state,
           {p, d}) do
    case (state) do
      :connected ->
        handle_recv_start(p, d, from, length, timeout)
      r_recv() ->
        {:keep_state_and_data, [:postpone]}
    end
  end

  def handle_event(:info, {:"$socket", socket, :select, selectRef},
           r_recv(info: {:select_info, _, selectRef}) = _State,
           {r_params(socket: socket) = p, d}) do
    handle_recv(p, d, [], :recv)
  end

  def handle_event(:info, {:"$socket", socket, :abort, {selectRef, reason}},
           r_recv(info: {:select_info, _, selectRef}) = _State,
           {r_params(socket: socket) = p, d}) do
    handle_connected(p,
                       cleanup_recv_reply(p, d, [], reason))
  end

  def handle_event(:info,
           {:"$socket", socket, :completion,
              {completionRef, completionStatus}},
           r_recv(info: {:completion_info, _, completionRef}) = _State,
           {r_params(socket: socket) = p, d}) do
    handle_recv(p, d, [], completionStatus)
  end

  def handle_event(:info,
           {:"$socket", socket, :abort, {completionRef, reason}},
           r_recv(info: {:completion_info, _, completionRef}) = _State,
           {r_params(socket: socket) = p, d}) do
    newReason = (case (reason) do
                   {:completion_status, %{info: :netname_deleted}} ->
                     :closed
                   {:completion_status, :netname_deleted} ->
                     :closed
                   {:completion_status, %{info: iNFO}} ->
                     iNFO
                   {:completion_status, iNFO} ->
                     iNFO
                   _ ->
                     reason
                 end)
    handle_connected(p,
                       cleanup_recv_reply(p, d, [], newReason))
  end

  def handle_event({:timeout, :recv}, :recv, r_recv() = state, {p, d}) do
    handle_connected(p, cleanup_recv(p, d, state, :timeout))
  end

  def handle_event(type, content, state, p_D) do
    handle_unexpected(type, content, state, p_D)
  end

  defp handle_shutdown(r_params(socket: socket), :closed_write = _State,
            :read = how) do
    handle_shutdown2(socket, :closed_read_write, how)
  end

  defp handle_shutdown(r_params(socket: socket), :closed_read = _State,
            :write = how) do
    handle_shutdown2(socket, :closed_read_write, how)
  end

  defp handle_shutdown(r_params(socket: socket), :connected = _State,
            :write = how) do
    {:keep, :socket.shutdown(socket, how)}
  end

  defp handle_shutdown(r_params(socket: socket), r_recv() = _State,
            :write = how) do
    {:keep, :socket.shutdown(socket, how)}
  end

  defp handle_shutdown(r_params(socket: socket), :connected = _State,
            :read = how) do
    handle_shutdown2(socket, :closed_read, how)
  end

  defp handle_shutdown(r_params(socket: socket), r_recv() = _State, :read = how) do
    handle_shutdown2(socket, :closed_read, how)
  end

  defp handle_shutdown(r_params(socket: socket), :connected = _State,
            :read_write = how) do
    handle_shutdown2(socket, :closed_read_write, how)
  end

  defp handle_shutdown(r_params(socket: socket), r_recv() = _State,
            :read_write = how) do
    handle_shutdown2(socket, :closed_read_write, how)
  end

  defp handle_shutdown(_Params, _State, _How) do
    {:keep, {:error, :enotconn}}
  end

  defp handle_shutdown2(socket, nextState, how) do
    case (:socket.shutdown(socket, how)) do
      :ok ->
        {nextState, :ok}
      error ->
        {:keep, error}
    end
  end

  defp handle_unexpected(type, content, state, {p, _D}) do
    warning_msg('Received unexpected event:~n   Socket:     ~p~n   State:      ~p~n   Event Type: ~p~n   Content:    ~p', [r_params(p, :socket), state, type, content])
    case (type) do
      {:call, from} ->
        {:keep_state_and_data,
           [{:reply, from, {:error, :einval}}]}
      _ ->
        :keep_state_and_data
    end
  end

  defp handle_closed(type, content, state, {p, _D}) do
    case (type) do
      {:call, from} ->
        {:keep_state_and_data,
           [{:reply, from, {:error, :closed}}]}
      _ ->
        warning_msg('Received unexpected event when closed:~n   Socket:     ~p~n   State:      ~p~n   Event Type: ~p~n   Content:    ~p', [r_params(p, :socket), state, type, content])
        :keep_state_and_data
    end
  end

  defp handle_connect(r_params(socket: socket) = p, d, from, addr, timeout,
            status)
      when status === :connect do
    case (:socket.connect(socket, addr, :nowait)) do
      :ok ->
        handle_connected(p, Map.put(d, :type, :connect),
                           [{{:timeout, :connect}, :cancel}, {:reply, from,
                                                                {:ok, socket}}])
      {:select, {:select_info, _, _} = info} ->
        {:next_state, r_connect(info: info, from: from, addr: addr),
           {p, Map.put(d, :type, :connect)},
           [{{:timeout, :connect}, timeout, :connect}]}
      {:completion, {:completion_info, _, _} = info} ->
        {:next_state, r_connect(info: info, from: from, addr: addr),
           {p, Map.put(d, :type, :connect)},
           [{{:timeout, :connect}, timeout, :connect}]}
      {:error, _} = error ->
        {:next_state, :connect, {p, d},
           [{{:timeout, :connect}, :cancel}, {:reply, from,
                                                error}]}
    end
  end

  defp handle_connect(r_params(socket: socket) = p, d, from, addr, timeout,
            status)
      when status === :select do
    case (:socket.connect(socket, addr, :nowait)) do
      :ok ->
        handle_connected(p, Map.put(d, :type, :connect),
                           [{{:timeout, :connect}, :cancel}, {:reply, from,
                                                                {:ok, socket}}])
      {:select, {:select_info, _, _} = info} ->
        {:next_state, r_connect(info: info, from: from, addr: addr),
           {p, Map.put(d, :type, :connect)},
           [{{:timeout, :connect}, timeout, :connect}]}
      {:error, _} = error ->
        {:next_state, :connect, {p, d},
           [{{:timeout, :connect}, :cancel}, {:reply, from,
                                                error}]}
    end
  end

  defp handle_connect(r_params(socket: socket) = p, d, from, _Addr, _Timeout,
            :ok) do
    handle_connected(p, Map.put(d, :type, :connect),
                       [{{:timeout, :connect}, :cancel}, {:reply, from,
                                                            {:ok, socket}}])
  end

  defp handle_connect(r_params() = p, d, from, _Addr, _Timeout,
            {:error, _Reason} = error) do
    {:next_state, :connect, {p, d},
       [{{:timeout, :connect}, :cancel}, {:reply, from,
                                            error}]}
  end

  defp handle_accept(p, d, from, listenSocket, timeout, status)
      when status === :select or status === :accept do
    case (:socket.accept(listenSocket, :nowait)) do
      {:ok, socket} ->
        handle_accept_success(p, d, from, listenSocket, socket)
      {:select, {:select_info, _, _} = selectInfo} ->
        {:next_state,
           r_accept(info: selectInfo, from: from,
               listen_socket: listenSocket),
           {p, Map.put(d, :type, :accept)},
           [{{:timeout, :accept}, timeout, :accept}]}
      {:completion,
         {:completion_info, _, _} = completionInfo} ->
        {:next_state,
           r_accept(info: completionInfo, from: from,
               listen_socket: listenSocket),
           {p, Map.put(d, :type, :accept)},
           [{{:timeout, :accept}, timeout, :accept}]}
      {:error, _Reason} = error ->
        handle_accept_failure(p, d, from, error)
    end
  end

  defp handle_accept(p, d, from, listenSocket, _Timeout,
            {:ok, socket}) do
    handle_accept_success(p, d, from, listenSocket, socket)
  end

  defp handle_accept(p, d, from, _ListenSocket, _Timeout,
            {:error, _Reason} = error) do
    handle_accept_failure(p, d, from, error)
  end

  defp handle_accept_success(p, d, from, listenSocket, accSocket) do
    :ok = :socket.setopt(accSocket, {:otp, :iow}, true)
    :ok = :socket.setopt(accSocket, {:otp, :meta}, meta(d))
    for opt <- socket_inherit_opts() do
      :ok = socket_copy_opt(listenSocket, opt, accSocket)
    end
    handle_connected(r_params(p, socket: accSocket),
                       Map.put(d, :type, :accept),
                       [{{:timeout, :accept}, :cancel}, {:reply, from,
                                                           {:ok, accSocket}}])
  end

  defp handle_accept_failure(p, d, from, error) do
    {:next_state, :accept, {p, d},
       [{{:timeout, :accept}, :cancel}, {:reply, from, error}]}
  end

  defp handle_connected(p, {d, actionsR}) do
    handle_connected(p, d, actionsR)
  end

  defp handle_connected(p, d, actionsR) do
    case (d) do
      %{active: false} ->
        {:next_state, :connected, {p, d}, reverse(actionsR)}
      %{active: _} ->
        handle_recv(p, recv_start(d), actionsR, :recv)
    end
  end

  defp handle_recv_start(p, %{packet: packet, buffer: buffer} = d, from,
            length, timeout)
      when (packet === :raw and 0 < length) or
             (packet === 0 and 0 < length) do
    size = :erlang.iolist_size(buffer)
    cond do
      length <= size ->
        {data,
           newBuffer} = :erlang.split_binary(condense_buffer(buffer),
                                               length)
        handle_recv_deliver(p,
                              Map.merge(%{d | buffer: newBuffer}, %{recv_length:
                                                                    length,
                                                                      recv_from:
                                                                      from}),
                              [], data)
      true ->
        n = length - size
        handle_recv(p,
                      Map.merge(d, %{recv_length: n, recv_from: from}),
                      [{{:timeout, :recv}, timeout, :recv}], :recv)
    end
  end

  defp handle_recv_start(p, d, from, _Length, timeout) do
    handle_recv(p,
                  Map.merge(d, %{recv_length: 0, recv_from: from}),
                  [{{:timeout, :recv}, timeout, :recv}], :recv)
  end

  defp handle_recv(p, %{packet: packet, recv_length: length} = d,
            actionsR, cS) do
    cond do
      0 < length ->
        handle_recv_length(p, d, actionsR, length, cS)
      packet === :raw or packet === 0 ->
        handle_recv_length(p, d, actionsR, length, cS)
      packet === 1 or packet === 2 or packet === 4 ->
        handle_recv_peek(p, d, actionsR, packet, cS)
      true ->
        handle_recv_packet(p, d, actionsR, cS)
    end
  end

  defp handle_recv_peek(p, d, actionsR, packet, cS) do
    case (d) do
      %{buffer: buffer} when is_list(buffer) ->
        data = condense_buffer(buffer)
        handle_recv_peek(p, %{d | buffer: data}, actionsR,
                           packet, cS)
      %{buffer:
        <<data :: size(packet) - binary, _Rest :: binary>>} ->
        handle_recv_peek2(p, d, actionsR, packet, data)
      %{buffer: <<shortData :: binary>>} when cS === :recv ->
        n = packet - byte_size(shortData)
        case (socket_recv_peek(r_params(p, :socket), n)) do
          {:ok, <<finalData :: binary>>} ->
            handle_recv_peek2(p, d, actionsR, packet,
                                <<shortData :: binary, finalData :: binary>>)
          {:select, select} ->
            {:next_state,
               r_recv(info: case (select) do
                         {{:select_info, _, _} = selectInfo, _Data} ->
                           selectInfo
                         {:select_info, _, _} = selectInfo ->
                           selectInfo
                       end),
               {p, d}, reverse(actionsR)}
          {:completion, completion} ->
            {:next_state, r_recv(info: completion), {p, d},
               reverse(actionsR)}
          {:error, {reason, <<_Data :: binary>>}} ->
            handle_recv_error(p, d, actionsR, reason)
          {:error, reason} ->
            handle_recv_error(p, d, actionsR, reason)
        end
      %{buffer: <<shortData :: binary>>} ->
        case (cS) do
          {:ok, <<finalData :: binary>>} ->
            handle_recv_peek2(p, d, actionsR, packet,
                                <<shortData :: binary, finalData :: binary>>)
          {:error, {reason, <<_Data :: binary>>}} ->
            handle_recv_error(p, d, actionsR, reason)
          {:error, reason} ->
            handle_recv_error(p, d, actionsR, reason)
        end
    end
  end

  defp handle_recv_peek2(p, d, actionsR, packet, data) do
    <<n
      ::
      size(packet) - unit(8) - integer - big -
        unsigned>> = data
    %{packet_size: packetSize} = d
    cond do
      (0 < packetSize and packetSize < n) ->
        handle_recv_error(p, d, actionsR, :emsgsize)
      true ->
        handle_recv_length(p, d, actionsR, packet + n, :recv)
    end
  end

  defp handle_buffered(_P, %{recv_from: _From} = d) do
    d
  end

  defp handle_buffered(p, %{active: active} = d)
      when active !== false do
    case (d) do
      %{buffer: buffer} when is_list(buffer) and buffer !== []
                             ->
        data = condense_buffer(buffer)
        handle_buffered(p, d, data)
      %{buffer: data}
          when is_binary(data) and byte_size(data) > 0 ->
        handle_buffered(p, d, data)
      _ ->
        d
    end
  end

  defp handle_buffered(_P, d) do
    d
  end

  defp handle_buffered(p,
            %{packet: :line, line_delimiter: lineDelimiter,
                packet_size: packetSize} = d,
            data) do
    decodeOpts = [{:line_delimiter, lineDelimiter},
                      {:line_length, packetSize}]
    handle_buffered(p, d, data, decodeOpts)
  end

  defp handle_buffered(p, d, data) do
    handle_buffered(p, d, data, [])
  end

  defp handle_buffered(p, %{packet_size: packetSize} = d, data,
            decocdeOpts0) do
    decodeOpts = [{:packet_size, packetSize} | decocdeOpts0]
    type = decode_packet(d)
    case (:erlang.decode_packet(type, data, decodeOpts)) do
      {:ok, decoded, rest} ->
        d2 = deliver_buffered_data(p, d, decoded)
        buffer = (case (rest) do
                    <<>> ->
                      rest
                    <<_ :: binary>> ->
                      [rest]
                  end)
        %{d2 | buffer: buffer}
      {:more, _} ->
        d
      {:error, reason} ->
        warning_msg('Failed decoding message~n   Socket:          ~p~n   Socket server:   ~p~n   Packet type:     ~p~n   byte_size(Data): ~p~n   Reason:          ~p',
                      [r_params(p, :socket), self(), type, byte_size(data), reason])
        d
    end
  end

  defp deliver_buffered_data(r_params(owner: owner) = p,
            %{active: active, mode: mode, header: header,
                deliver: deliver, packet: packet} = d,
            data) do
    deliverData = deliver_data(data, mode, header, packet)
    moduleSocket = module_socket(p)
    send(owner, case (deliver) do
                  :term ->
                    {tag(packet), moduleSocket, deliverData}
                  :port ->
                    {moduleSocket, {:data, deliverData}}
                end)
    case (active) do
      true ->
        recv_start(next_packet(d, packet, data))
      :once ->
        recv_stop(next_packet(d, packet, data, false))
      1 ->
        send(owner, {:tcp_passive, moduleSocket})
        recv_stop(next_packet(d, packet, data, false))
      n when is_integer(n) ->
        recv_start(next_packet(d, packet, data, active - 1))
    end
  end

  defp handle_recv_packet(p, d, actionsR, cS) do
    case (d) do
      %{buffer: buffer} when is_list(buffer) ->
        data = condense_buffer(buffer)
        handle_recv_decode(p, d, actionsR, data, cS)
      %{buffer: data} when is_binary(data) ->
        handle_recv_more(p, d, actionsR, data, cS)
    end
  end

  defp handle_recv_length(p, %{buffer: buffer} = d, actionsR, length,
            cS) do
    handle_recv_length(p, d, actionsR, length, buffer, cS)
  end

  defp handle_recv_length(p, d, actionsR, length, buffer, cS)
      when 0 < length and cS === :recv do
    case (socket_recv(r_params(p, :socket), length)) do
      {:ok, <<data :: binary>>} ->
        handle_recv_deliver(p, %{d | buffer: <<>>}, actionsR,
                              condense_buffer([data | buffer]))
      {:select, {{:select_info, _, _} = selectInfo, data}} ->
        n = length - byte_size(data)
        {:next_state, r_recv(info: selectInfo),
           {p, %{d | buffer: [data | buffer], recv_length: n}},
           reverse(actionsR)}
      {:select, {:select_info, _, _} = selectInfo} ->
        {:next_state, r_recv(info: selectInfo),
           {p, %{d | buffer: buffer}}, reverse(actionsR)}
      {:completion,
         {:completion_info, _, _} = completionInfo} ->
        {:next_state, r_recv(info: completionInfo),
           {p, %{d | buffer: buffer}}, reverse(actionsR)}
      {:error, {reason, <<data :: binary>>}} ->
        handle_recv_error(p, %{d | buffer: [data | buffer]},
                            actionsR, reason)
      {:error, reason} ->
        handle_recv_error(p, %{d | buffer: buffer}, actionsR,
                            reason)
    end
  end

  defp handle_recv_length(p, d, actionsR, length, buffer, cS)
      when 0 < length do
    case (cS) do
      {:ok, <<data :: binary>>} ->
        handle_recv_deliver(p, %{d | buffer: <<>>}, actionsR,
                              condense_buffer([data | buffer]))
      {:error, {reason, <<data :: binary>>}} ->
        handle_recv_error(p, %{d | buffer: [data | buffer]},
                            actionsR, reason)
      {:error, reason} ->
        handle_recv_error(p, %{d | buffer: buffer}, actionsR,
                            reason)
    end
  end

  defp handle_recv_length(p, d, actionsR, _0, buffer, cS)
      when cS === :recv do
    case (buffer) do
      <<>> ->
        socket = r_params(p, :socket)
        case (socket_recv(socket, 0)) do
          {:ok, <<data :: binary>>} ->
            handle_recv_deliver(p, d, actionsR, data)
          {:select, {{:select_info, _, _} = selectInfo, data}} ->
            case (:socket.cancel(socket, selectInfo)) do
              :ok ->
                handle_recv_deliver(p, d, actionsR, data)
              {:error, reason} ->
                handle_recv_error(p, d, actionsR, reason, data)
            end
          {:select, {:select_info, _, _} = selectInfo} ->
            {:next_state, r_recv(info: selectInfo), {p, d},
               reverse(actionsR)}
          {:completion,
             {:completion_info, _, _} = completionInfo} ->
            {:next_state, r_recv(info: completionInfo), {p, d},
               reverse(actionsR)}
          {:error, {reason, <<data :: binary>>}} ->
            handle_recv_error(p, d, actionsR, reason, data)
          {:error, reason} ->
            handle_recv_error(p, d, actionsR, reason)
        end
      <<data :: binary>> ->
        handle_recv_deliver(p, %{d | buffer: <<>>}, actionsR,
                              data)
      _ when is_list(buffer) ->
        data = condense_buffer(buffer)
        handle_recv_deliver(p, %{d | buffer: <<>>}, actionsR,
                              data)
    end
  end

  defp handle_recv_length(p, d, actionsR, _0, buffer, cS) do
    case (buffer) do
      <<>> ->
        case (cS) do
          {:ok, <<data :: binary>>} ->
            handle_recv_deliver(p, d, actionsR, data)
          {:error, reason} ->
            handle_recv_error(p, d, actionsR, reason)
        end
      <<_ :: binary>> ->
        case (cS) do
          {:ok, <<data :: binary>>} ->
            handle_recv_deliver(p, %{d | buffer: <<>>}, actionsR,
                                  condense_buffer([data, buffer]))
          {:error, reason} ->
            handle_recv_error(p, d, actionsR, reason)
        end
      _ when is_list(buffer) ->
        case (cS) do
          {:ok, <<data :: binary>>} ->
            handle_recv_deliver(p, %{d | buffer: <<>>}, actionsR,
                                  condense_buffer([data | buffer]))
          {:error, reason} ->
            handle_recv_error(p, d, actionsR, reason)
        end
    end
  end

  defp handle_recv_decode(p,
            %{packet: :line, line_delimiter: lineDelimiter,
                packet_size: packetSize} = d,
            actionsR, data, cS) do
    decodeOpts = [{:line_delimiter, lineDelimiter},
                      {:line_length, packetSize}]
    handle_recv_decode(p, d, actionsR, data, decodeOpts, cS)
  end

  defp handle_recv_decode(p, d, actionsR, data, cS) do
    handle_recv_decode(p, d, actionsR, data, [], cS)
  end

  defp handle_recv_decode(p, %{packet_size: packetSize} = d, actionsR,
            data, decocdeOpts0, cS) do
    decodeOpts = [{:packet_size, packetSize} | decocdeOpts0]
    case (:erlang.decode_packet(decode_packet(d), data,
                                  decodeOpts)) do
      {:ok, decoded, rest} ->
        buffer = (case (rest) do
                    <<>> ->
                      rest
                    <<_ :: binary>> ->
                      [rest]
                  end)
        handle_recv_deliver(p, %{d | buffer: buffer}, actionsR,
                              decoded)
      {:more, :undefined} ->
        handle_recv_more(p, d, actionsR, data, cS)
      {:more, length} ->
        n = length - byte_size(data)
        handle_recv_length(p, d, actionsR, n, data, cS)
      {:error, reason} ->
        handle_recv_error(p, %{d | buffer: data}, actionsR,
                            case (reason) do
                              :invalid ->
                                :emsgsize
                              _ ->
                                reason
                            end)
    end
  end

  defp handle_recv_error_decode(p, %{packet_size: packetSize} = d, actionsR,
            reason, data) do
    case (:erlang.decode_packet(decode_packet(d), data,
                                  [{:packet_size, packetSize}, {:line_length,
                                                                  packetSize}])) do
      {:ok, decoded, rest} ->
        buffer = (case (rest) do
                    <<>> ->
                      rest
                    <<_ :: binary>> ->
                      [rest]
                  end)
        handle_recv_error(p, %{d | buffer: buffer}, actionsR,
                            reason, decoded)
      {:more, _} ->
        handle_recv_error(p, %{d | buffer: data}, actionsR,
                            reason)
      {:error, ^reason} ->
        handle_recv_error(p, %{d | buffer: data}, actionsR,
                            case (reason) do
                              :invalid ->
                                :emsgsize
                              _ ->
                                reason
                            end)
    end
  end

  defp handle_recv_more(p, d, actionsR, bufferedData, cS)
      when cS === :recv do
    case (socket_recv(r_params(p, :socket), 0)) do
      {:ok, <<moreData :: binary>>} ->
        data = catbin(bufferedData, moreData)
        handle_recv_decode(p, d, actionsR, data, :recv)
      {:select, {:select_info, _, _} = selectInfo} ->
        {:next_state, r_recv(info: selectInfo),
           {p, %{d | buffer: bufferedData}}, reverse(actionsR)}
      {:completion,
         {:completion_info, _, _} = completionInfo} ->
        {:next_state, r_recv(info: completionInfo),
           {p, %{d | buffer: bufferedData}}, reverse(actionsR)}
      {:error, {reason, <<moreData :: binary>>}} ->
        data = catbin(bufferedData, moreData)
        handle_recv_error_decode(p, d, actionsR, reason, data)
      {:error, reason} ->
        handle_recv_error(p, %{d | buffer: bufferedData},
                            actionsR, reason)
    end
  end

  defp handle_recv_more(p, d, actionsR, bufferedData, cS) do
    case (cS) do
      {:ok, <<moreData :: binary>>} ->
        data = catbin(bufferedData, moreData)
        handle_recv_decode(p, d, actionsR, data, :recv)
      {:error, reason} ->
        handle_recv_error(p, %{d | buffer: bufferedData},
                            actionsR, reason)
    end
  end

  defp handle_recv_deliver(p, d, actionsR, data) do
    handle_connected(p,
                       recv_data_deliver(p, d, actionsR, data))
  end

  defp handle_recv_error(p, d, actionsR, reason, data) do
    {d_1, actionsR_1} = recv_data_deliver(p, d, actionsR,
                                            data)
    handle_recv_error(p, d_1, actionsR_1, reason)
  end

  defp handle_recv_error(p, d, actionsR, reason) do
    {d_1, actionsR_1} = cleanup_recv_reply(p,
                                             %{d | buffer: <<>>}, actionsR,
                                             reason)
    cond do
      reason === :timeout or reason === :emsgsize ->
        {:next_state, :connected,
           {p, recv_stop(%{d | active: false})},
           reverse(actionsR_1)}
      reason === :closed ->
        {:next_state, :closed_read, {p, d_1},
           reverse(actionsR_1)}
      true ->
        _ = socket_close(r_params(p, :socket))
        {:next_state, :closed, {p, d_1}, reverse(actionsR_1)}
    end
  end

  defp next_state(p, {d, actionsR}, state, actions) do
    {:next_state, state, {p, d}, reverse(actionsR, actions)}
  end

  defp cleanup_close_read(p, d, state, reason) do
    case (state) do
      r_accept(info: selectInfo, from: from,
          listen_socket: listenSocket) ->
        _ = socket_cancel(listenSocket, selectInfo)
        {d, [{:reply, from, {:error, reason}}]}
      r_connect(info: info, from: from) ->
        _ = socket_cancel(r_params(p, :socket), info)
        {d, [{:reply, from, {:error, reason}}]}
      _ ->
        cleanup_recv(p, d, state, reason)
    end
  end

  defp cleanup_recv(p, d, state, reason) do
    case (state) do
      r_recv(info: info) ->
        _ = socket_cancel(r_params(p, :socket), info)
        cleanup_recv_reply(p, d, [], reason)
      _ ->
        cleanup_recv_reply(p, d, [], reason)
    end
  end

  defp cleanup_recv_reply(p, %{show_econnreset: showEconnreset} = d,
            actionsR, reason) do
    case (d) do
      %{active: false} ->
        :ok
      %{active: _} ->
        moduleSocket = module_socket(p)
        owner = r_params(p, :owner)
        cond do
          reason === :timeout or reason === :emsgsize ->
            send(owner, {:tcp_error, moduleSocket, reason})
            :ok
          (reason === :closed and showEconnreset === false) or
            (reason === :econnreset and showEconnreset === false) ->
            send(owner, {:tcp_closed, moduleSocket})
            :ok
          reason === :closed ->
            send(owner, {:tcp_error, moduleSocket, :econnreset})
            send(owner, {:tcp_closed, moduleSocket})
            :ok
          true ->
            send(owner, {:tcp_error, moduleSocket, reason})
            send(owner, {:tcp_closed, moduleSocket})
            :ok
        end
    end
    {recv_stop(%{d | active: false}),
       case (d) do
         %{recv_from: from} ->
           reason_1 = (case (reason) do
                         :econnreset when showEconnreset === false ->
                           :closed
                         :closed when showEconnreset === true ->
                           :econnreset
                         _ ->
                           reason
                       end)
           [{:reply, from, {:error, reason_1}}, {{:timeout, :recv},
                                                   :cancel} |
                                                    actionsR]
         %{} ->
           actionsR
       end}
  end

  defp recv_start(d) do
    Map.put(d, :recv_length, 0)
  end

  defp recv_stop(d) do
    :maps.without([:recv_from, :recv_length], d)
  end

  defp decode_packet(%{packet: packet} = d) do
    case (d) do
      %{packet: :http, recv_httph: true} ->
        :httph
      %{packet: :http_bin, recv_httph: true} ->
        :httph_bin
      %{packet: ^packet} ->
        packet
    end
  end

  defp recv_data_deliver(r_params(owner: owner) = p,
            %{mode: mode, header: header, deliver: deliver,
                packet: packet} = d,
            actionsR, data) do
    deliverData = deliver_data(data, mode, header, packet)
    case (d) do
      %{recv_from: from} ->
        {recv_stop(next_packet(d, packet, data)),
           [{:reply, from, {:ok, deliverData}}, {{:timeout, :recv},
                                                   :cancel} |
                                                    actionsR]}
      %{active: false} ->
        d_1 = %{d
                |
                buffer: unrecv_buffer(data, :maps.get(:buffer, d))}
        {recv_stop(next_packet(d_1, packet, data)), actionsR}
      %{active: active} ->
        moduleSocket = module_socket(p)
        send(owner, case (deliver) do
                      :term ->
                        {tag(packet), moduleSocket, deliverData}
                      :port ->
                        {moduleSocket, {:data, deliverData}}
                    end)
        case (active) do
          true ->
            {recv_start(next_packet(d, packet, data)), actionsR}
          :once ->
            {recv_stop(next_packet(d, packet, data, false)),
               actionsR}
          1 ->
            send(owner, {:tcp_passive, moduleSocket})
            {recv_stop(next_packet(d, packet, data, false)),
               actionsR}
          n when is_integer(n) ->
            {recv_start(next_packet(d, packet, data, active - 1)),
               actionsR}
        end
    end
  end

  defp next_packet(d, packet, data) do
    cond do
      packet === :http or packet === :http_bin ->
        case (data) do
          {:http_request, _HttpMethod, _HttpUri, _HttpVersion} ->
            Map.put(d, :recv_httph, true)
          {:http_response, _HttpVersion, _Integer, _HttpString} ->
            Map.put(d, :recv_httph, true)
          {:http_header, _Integer, _HttpField, _Reserver,
             _Value} ->
            d
          :http_eoh ->
            Map.put(d, :recv_httph, false)
          {:http_error, _HttpString} ->
            d
        end
      true ->
        d
    end
  end

  defp next_packet(d, packet, data, active) do
    cond do
      packet === :http or packet === :http_bin ->
        case (data) do
          {:http_request, _HttpMethod, _HttpUri, _HttpVersion} ->
            Map.merge(d, %{recv_httph: true, active: active})
          {:http_response, _HttpVersion, _Integer, _HttpString} ->
            Map.merge(d, %{recv_httph: true, active: active})
          {:http_header, _Integer, _HttpField, _Reserver,
             _Value} ->
            Map.put(d, :active, active)
          :http_eoh ->
            Map.merge(d, %{recv_httph: false, active: active})
          {:http_error, _HttpString} ->
            Map.put(d, :active, active)
        end
      true ->
        Map.put(d, :active, active)
    end
  end

  defp catbin(<<>>, bin) when is_binary(bin) do
    bin
  end

  defp catbin(bin, <<>>) when is_binary(bin) do
    bin
  end

  defp catbin(bin1, bin2) when (is_binary(bin1) and
                              is_binary(bin2)) do
    <<bin1 :: binary, bin2 :: binary>>
  end

  defp unrecv_buffer(data, buffer) do
    case (buffer) do
      <<>> ->
        data
      _ when is_binary(buffer) ->
        [data, buffer]
      _ ->
        [data | buffer]
    end
  end

  defp condense_buffer([bin]) when is_binary(bin) do
    bin
  end

  defp condense_buffer(buffer) do
    :erlang.iolist_to_binary(reverse_improper(buffer, []))
  end

  defp deliver_data(data, mode, header, packet) do
    cond do
      packet === 1 or packet === 2 or packet === 4 ->
        <<_Size
          ::
          size(packet) - unit(8) - integer - big - unsigned,
            payload :: binary>> = data
        deliver_data(payload, mode, header)
      packet === :http or packet === :http_bin or
        packet === :httph or packet === :httph_bin ->
        data
      true ->
        deliver_data(data, mode, header)
    end
  end

  defp deliver_data(data, :list, _N) do
    :erlang.binary_to_list(data)
  end

  defp deliver_data(data, :binary, 0) do
    data
  end

  defp deliver_data(data, :binary, n) do
    case (data) do
      <<_ :: size(n) - binary>> ->
        :erlang.binary_to_list(data)
      <<header :: size(n) - binary, payload :: binary>> ->
        :erlang.binary_to_list(header) ++ payload
    end
  end

  defp tag(packet) do
    cond do
      packet === :http or packet === :http_bin or
        packet === :httph or packet === :httph_bin ->
        :http
      true ->
        :tcp
    end
  end

  def socket_setopts(socket, opts) do
    try do
      (
        socket_setopts(socket,
                         for opt <- internalize_setopts(opts),
                               :erlang.element(1, opt) !== :tcp_module do
                           opt
                         end,
                         socket_opts())
      )
    catch
      :exit, :badarg ->
        {:error, :einval}
    end
  end

  defp socket_setopts(_Socket, [], _SocketOpts) do
    :ok
  end

  defp socket_setopts(socket, [{tag, val} | opts], socketOpts) do
    case (socketOpts) do
      %{^tag => name} ->
        _ = socket_setopt(socket, name, val)
        socket_setopts(socket, opts, socketOpts)
      %{} ->
        socket_setopts(socket, opts, socketOpts)
    end
  end

  defp state_setopts(_P, d, _State, []) do
    {:ok, d}
  end

  defp state_setopts(p, d, state, [{tag, val} | opts]) do
    socketOpts = socket_opts()
    case (:maps.is_key(tag, socketOpts)) do
      true ->
        case (r_params(p, :socket)) do
          :undefined ->
            {{:error, :closed}, d}
          socket ->
            case (socket_setopt(socket, :maps.get(tag, socketOpts),
                                  val)) do
              :ok ->
                state_setopts(p, d, state, opts)
              {:error, _} = error ->
                {error, d}
            end
        end
      false ->
        case (:maps.is_key(tag, server_write_opts())) do
          true when state === :closed ->
            {{:error, :einval}, d}
          true ->
            state_setopts_server(p, d, state, opts, tag, val)
          false ->
            case (:maps.is_key(tag, server_read_opts())) do
              true when state === :closed or state === :closed_read or
                          state === :closed_read_write
                        ->
                {{:error, :einval}, d}
              true ->
                state_setopts_server(p, d, state, opts, tag, val)
              false ->
                case (ignore_optname(tag)) do
                  true ->
                    state_setopts(p, d, state, opts)
                  false ->
                    {{:error, :einval}, d}
                end
            end
        end
    end
  end

  defp state_setopts_server(p, d, state, opts, tag, value) do
    case (tag) do
      :active ->
        state_setopts_active(p, d, state, opts, value)
      :packet ->
        case (is_packet_option_value(value)) do
          true ->
            case (d) do
              %{recv_httph: _} ->
                state_setopts(p,
                                :maps.remove(:recv_httph,
                                               Map.put(d, :packet, value)),
                                state, opts)
              %{} ->
                state_setopts(p, Map.put(d, :packet, value), state,
                                opts)
            end
          false ->
            {{:error, :einval}, d}
        end
      _ ->
        state_setopts(p, Map.put(d, tag, value), state, opts)
    end
  end

  defp state_setopts_active(p, d, state, opts, active) do
    cond do
      active === :once or active === true ->
        state_setopts(p, %{d | active: active}, state, opts)
      active === false ->
        case (d) do
          %{active: oldActive} when is_integer(oldActive) ->
            send(r_params(p, :owner), {:tcp_passive, module_socket(p)})
            :ok
          %{active: _OldActive} ->
            :ok
        end
        state_setopts(p, %{d | active: active}, state, opts)
      (is_integer(active) and - 32768 <= active and
         active <= 32767) ->
        n = (case (d) do
               %{active: oldActive} when is_integer(oldActive) ->
                 oldActive + active
               %{active: _OldActive} ->
                 active
             end)
        cond do
          32767 < n ->
            {{:error, :einval}, d}
          n <= 0 ->
            send(r_params(p, :owner), {:tcp_passive, module_socket(p)})
            state_setopts(p, %{d | active: false}, state, opts)
          true ->
            state_setopts(p, %{d | active: n}, state, opts)
        end
      true ->
        {{:error, :einval}, d}
    end
  end

  defp state_getopts(p, d, state, opts) do
    state_getopts(p, d, state, opts, [])
  end

  defp state_getopts(_P, _D, _State, [], acc) do
    {:ok, reverse(acc)}
  end

  defp state_getopts(p, d, state, [tag | tags], acc) do
    socketOpts = socket_opts()
    {key, val} = (case (tag) do
                    {_, _} ->
                      tag
                    _ when is_atom(tag) ->
                      {tag, tag}
                  end)
    case (:maps.is_key(key, socketOpts)) do
      true ->
        case (r_params(p, :socket)) do
          :undefined ->
            {:error, :closed}
          socket ->
            case (socket_getopt(socket, :maps.get(key, socketOpts),
                                  val)) do
              {:ok, value} ->
                state_getopts(p, d, state, tags, [{key, value} | acc])
              {:error, :einval} = eRROR ->
                eRROR
              {:error, _Reason} ->
                state_getopts(p, d, state, tags, acc)
            end
        end
      false ->
        case (:maps.is_key(key, server_write_opts())) do
          true when state === :closed ->
            {:error, :einval}
          true ->
            value = :maps.get(key, d)
            state_getopts(p, d, state, tags, [{key, value} | acc])
          false ->
            case (:maps.is_key(key, server_read_opts())) do
              true when state === :closed or state === :closed_read or
                          state === :closed_read_write
                        ->
                {:error, :einval}
              true ->
                value = :maps.get(key, d)
                state_getopts(p, d, state, tags, [{key, value} | acc])
              false ->
                case (ignore_optname(key)) do
                  true ->
                    state_getopts(p, d, state, tags, acc)
                  false ->
                    {:error, :einval}
                end
            end
        end
    end
  end

  defp handle_info(socket, owner, %{active: active} = d) do
    counters_1 = socket_info_counters(socket)
    {d_1, wrapped} = receive_counter_wrap(socket, d, [])
    info = (%{counters: counters_2} = :socket.info(socket))
    counters_3 = :maps.merge(counters_1,
                               :maps.with(wrapped, counters_2))
    counters_4 = :maps.from_list(getstat_what(d_1,
                                                counters_3))
    {d_1,
       Map.merge(info, %{counters: counters_4, owner: owner,
                           active: active})}
  end

  defp getstat(socket, d, what) do
    counters_1 = socket_info_counters(socket)
    {d_1, wrapped} = receive_counter_wrap(socket, d, [])
    counters_2 = socket_info_counters(socket)
    counters_3 = :maps.merge(counters_1,
                               :maps.with(wrapped, counters_2))
    {d_1, getstat_what(what, d_1, counters_3)}
  end

  defp getstat_what(d, c) do
    getstat_what(:inet.stats(), d, c)
  end

  defp getstat_what([], _D, _C) do
    []
  end

  defp getstat_what([tag | what], d, c) do
    val = (case (tag) do
             :recv_oct ->
               counter_value(:read_byte, d, c)
             :recv_cnt ->
               counter_value(:read_pkg, d, c)
             :recv_max ->
               getstat_avg(:read_byte, d, c, :read_pkg)
             :recv_avg ->
               getstat_avg(:read_byte, d, c, :read_pkg)
             :recv_dvi ->
               0
             :send_oct ->
               counter_value(:write_byte, d, c)
             :send_cnt ->
               counter_value(:write_pkg, d, c)
             :send_max ->
               getstat_avg(:write_byte, d, c, :write_pkg)
             :send_avg ->
               getstat_avg(:write_byte, d, c, :write_pkg)
             :send_pend ->
               0
           end)
    [{tag, val} | getstat_what(what, d, c)]
  end

  defp getstat_avg(sumTag, d, c, cntTag) do
    cnt = counter_value(cntTag, d, c)
    cond do
      cnt === 0 ->
        counter_value(sumTag, d, c)
      true ->
        round(counter_value(sumTag, d, c) / cnt)
    end
  end

  defp socket_info_counters(socket) do
    %{counters: counters} = :socket.info(socket)
    counters
  end

  defp receive_counter_wrap(socket, d, wrapped) do
    receive do
      {:"$socket", ^socket, :counter_wrap, counter} ->
        receive_counter_wrap(socket, wrap_counter(counter, d),
                               [counter | wrapped])
    after 0 ->
      {d, wrapped}
    end
  end

  defp wrap_counter(counter, d) do
    case (d) do
      %{^counter => n} ->
        %{d | counter => n + 1}
      %{} ->
        Map.put(d, counter, 1)
    end
  end

  defp counter_value(counter, d, counters) do
    case (d) do
      %{^counter => wraps} ->
        wraps <<< 32 + :maps.get(counter, counters)
      %{} ->
        :maps.get(counter, counters)
    end
  end

  defp reverse([]) do
    []
  end

  defp reverse([_] = l) do
    l
  end

  defp reverse([a, b]) do
    [b, a]
  end

  defp reverse(l) do
    :lists.reverse(l)
  end

  defp reverse([], l) do
    l
  end

  defp reverse([a], l) do
    [a | l]
  end

  defp reverse([a, b], l) do
    [b, a | l]
  end

  defp reverse(l1, l2) do
    :lists.reverse(l1, l2)
  end

  defp reverse_improper([h | t], acc) do
    reverse_improper(t, [h | acc])
  end

  defp reverse_improper([], acc) do
    acc
  end

  defp reverse_improper(t, acc) do
    [t | acc]
  end

  defp error_msg(f, a) do
    :error_logger.error_msg(f ++ '~n', a)
  end

  defp warning_msg(f, a) do
    :error_logger.error_msg(f ++ '~n', a)
  end

  defp error_report(report) do
    :error_logger.error_report(report)
  end

end