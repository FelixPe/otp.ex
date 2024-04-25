defmodule :m_gen_udp_socket do
  use Bitwise
  import Kernel, except: [send: 2]
  @behaviour :gen_statem
  require Record
  Record.defrecord(:r_connect_opts, :connect_opts, ifaddr: :undefined, port: 0, fd: -1, opts: [])

  Record.defrecord(:r_listen_opts, :listen_opts,
    ifaddr: :undefined,
    port: 0,
    backlog: 5,
    fd: -1,
    opts: []
  )

  Record.defrecord(:r_udp_opts, :udp_opts,
    ifaddr: :undefined,
    port: 0,
    fd: -1,
    opts: [{:active, true}]
  )

  Record.defrecord(:r_sctp_opts, :sctp_opts,
    ifaddr: :undefined,
    port: 0,
    fd: -1,
    type: :seqpacket,
    opts: [
      {:mode, :binary},
      {:buffer, 65536},
      {:sndbuf, 65536},
      {:recbuf, 1024},
      {:sctp_events, :undefined}
    ]
  )

  def close({:"$inet", :gen_udp_socket, {server, _Socket}}) do
    case close_server(server) do
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

  def connect({:"$inet", :gen_udp_socket, {_Server, socket}}, address, port) do
    {mod, _} = :inet.udp_module([], address)
    domain = domain(mod)

    try do
      dest =
        case mod.getaddr(address) do
          {:ok, iP} when domain === :local ->
            dest2sockaddr(iP)

          {:ok, iP} ->
            dest2sockaddr({iP, port})

          {:error, _Reason} = eRROR ->
            throw(eRROR)
        end

      case :os.type() do
        {:unix, :linux} ->
          case :socket.peername(socket) do
            {:error, :enotconn} ->
              :socket.connect(socket, dest)

            {:error, :closed} = error ->
              error

            _X ->
              _ = :socket.connect(socket, %{family: :unspec})
              :socket.connect(socket, dest)
          end

        _ ->
          :socket.connect(socket, dest)
      end
    catch
      e ->
        e
    end
  end

  def open(service, opts) do
    open_lookup(service, opts)
  end

  defp open_lookup(service, opts0) do
    {einvalOpts, opts_1} = setopts_split(:einval, opts0)
    einvalOpts === [] or exit(:badarg)
    {mod, opts_2} = :inet.udp_module(opts_1)
    domain = domain(mod)
    {startOpts, opts_3} = setopts_split(:start, opts_2)
    errRef = make_ref()

    try do
      port = val(errRef, mod.getserv(service))
      opts_4 = [{:port, port} | opts_3]

      r_udp_opts(fd: fd, ifaddr: bindIP, port: bindPort, opts: openOpts) =
        val(
          errRef,
          :inet.udp_options(opts_4, mod)
        )

      bindAddr = bind_addr(domain, bindIP, bindPort, fd)
      extraOpts = extra_opts(fd)
      do_open(mod, bindAddr, domain, openOpts, startOpts, extraOpts)
    catch
      {^errRef, reason} ->
        case {:error, reason} do
          {:error, :badarg} ->
            exit(:badarg)

          oTHER__ ->
            oTHER__
        end
    end
  end

  defp do_open(mod, bindAddr, domain, openOpts, opts, extraOpts) do
    {socketOpts, startOpts} = setopts_split(:socket, opts)

    case start_server(mod, domain, start_opts(startOpts), extraOpts) do
      {:ok, server} ->
        {setOpts0, _} =
          setopts_split(
            %{socket: [], server_read: [], server_write: []},
            openOpts
          )

        setOpts = default_active_true([{:start_opts, startOpts}] ++ socketOpts ++ setOpts0)
        errRef = make_ref()

        try do
          ok(
            errRef,
            call_bind(
              server,
              default_any(domain, extraOpts, bindAddr)
            )
          )

          ok(
            errRef,
            call(server, {:setopts, socketOpts ++ setOpts})
          )

          socket = val(errRef, call(server, :get_socket))
          {:ok, {:"$inet", :gen_udp_socket, {server, socket}}}
        catch
          {^errRef, reason} ->
            close_server(server)

            case {:error, reason} do
              {:error, :badarg} ->
                exit(:badarg)

              oTHER__ ->
                oTHER__
            end
        end

      {:error, _} = error ->
        case error do
          {:error, :badarg} ->
            exit(:badarg)

          oTHER__ ->
            oTHER__
        end
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

  defp default_any(_Domain, %{fd: _}, _BindAddr) do
    :undefined
  end

  defp default_any(domain, _ExtraOpts, :undefined = undefined) do
    cond do
      domain === :inet or domain === :inet6 ->
        %{family: domain, addr: :any, port: 0}

      true ->
        undefined
    end
  end

  defp default_any(_Domain, _ExtraOpts, bindAddr) do
    bindAddr
  end

  defp bind_addr(domain, bindIP, bindPort, fd)
       when (bindIP === :undefined and bindPort === 0) or (is_integer(fd) and 0 <= fd) do
    case :os.type() do
      {:win32, :nt} ->
        addr = which_bind_address(domain, bindIP)
        %{family: domain, addr: addr, port: bindPort}

      _ ->
        :undefined
    end
  end

  defp bind_addr(:local = domain, bindIP, _BindPort, _Fd) do
    case bindIP do
      :any ->
        :undefined

      {:local, path} ->
        %{family: domain, path: path}
    end
  end

  defp bind_addr(domain, bindIP, bindPort, _Fd)
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
    case :os.type() do
      {:win32, :nt} ->
        which_default_bind_address2(domain)

      _ ->
        :any
    end
  end

  defp which_default_bind_address2(domain) do
    case net_getifaddrs(domain) do
      {:ok, addrs} ->
        upNonLoopbackAddrs =
          for %{flags: flags, addr: %{addr: _A}} = addr <- addrs,
              not :lists.member(
                :loopback,
                flags
              ) and
                :lists.member(
                  :up,
                  flags
                ) do
            addr
          end

        case upNonLoopbackAddrs do
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
    case :lists.keyfind(:active, 1, opts) do
      {:active, _} ->
        opts

      _ ->
        [{:active, true} | opts]
    end
  end

  def send(
        {:"$inet", :gen_udp_socket, {_Server, socket}},
        data
      ) do
    socket_send(socket, data)
  end

  def send(_Socket, _Data) do
    exit(:badarg)
  end

  defp make_iov(bin) when is_binary(bin) do
    [bin]
  end

  defp make_iov(iOV) when is_list(iOV) do
    iOV
  end

  defp dest2sockaddr({addr, port})
       when is_tuple(addr) and tuple_size(addr) === 4 and is_integer(port) do
    %{family: :inet, port: port, addr: addr}
  end

  defp dest2sockaddr({addr, port})
       when is_tuple(addr) and tuple_size(addr) === 8 and is_integer(port) do
    %{family: :inet6, port: port, addr: addr}
  end

  defp dest2sockaddr({:local = fam, path})
       when is_binary(path) or is_list(path) do
    %{family: fam, path: path}
  end

  defp dest2sockaddr({fam, {addr, port}})
       when is_atom(fam) and (fam === :inet or fam === :inet6) and is_integer(port) do
    %{family: fam, port: port, addr: addr}
  end

  defp dest2sockaddr(_Arg) do
    exit(:badarg)
  end

  defp make_cmsghdrs(ancData) when is_list(ancData) do
    for aD <- ancData do
      make_cmsghdr(aD)
    end
  end

  defp make_cmsghdrs(_Arg) do
    exit(:badarg)
  end

  defp make_cmsghdr({:tos = type, byte}) do
    %{level: :ip, type: type, data: byte}
  end

  defp make_cmsghdr({:tclass = type, byte}) do
    %{level: :ipv6, type: type, data: byte}
  end

  defp make_cmsghdr({:ttl = type, byte}) do
    %{level: :ip, type: type, data: byte}
  end

  defp make_cmsghdr(_Arg) do
    exit(:badarg)
  end

  def send(socket, destination, data) do
    do_sendto(socket, dest2sockaddr(destination), data)
  end

  def send(socket, {_, _} = destination, portZero, data)
      when portZero === 0 do
    send(socket, destination, data)
  end

  def send(_Socket, {_, _} = _Destination, portZero, _Data)
      when is_integer(portZero) do
    {:error, :einval}
  end

  def send(socket, {_, _} = destination, ancData, data) do
    do_sendmsg(socket, dest2sockaddr(destination), make_iov(data), make_cmsghdrs(ancData))
  end

  def send(socket, addr, port, data)
      when is_tuple(addr) and (tuple_size(addr) === 4 or tuple_size(addr) === 8) and
             is_integer(port) do
    send(socket, {addr, port}, data)
  end

  def send({:"$inet", :gen_udp_socket, {_, eSock}} = socket, host, service, data)
      when is_list(host) or is_atom(host) do
    case :socket.getopt(eSock, {:otp, :domain}) do
      {:ok, domain} ->
        case :inet.getaddr(host, domain) do
          {:ok, addr} ->
            {:ok, %{mod: mod}} =
              :socket.getopt(
                eSock,
                {:otp, :meta}
              )

            case mod.getserv(service) do
              {:ok, port} ->
                send(socket, {addr, port}, data)

              {:error, :einval} ->
                exit(:badarg)

              {:error, _} = eRROR ->
                eRROR
            end

          {:error, :einval} ->
            exit(:badarg)

          {:error, _} = eRROR ->
            eRROR
        end

      eRROR ->
        eRROR
    end
  end

  def send(_Socket, _Arg1, _Arg2, _Arg3) do
    exit(:badarg)
  end

  def send(socket, addr, port, ancData, data)
      when is_tuple(addr) and (tuple_size(addr) === 4 or tuple_size(addr) === 8) and
             is_integer(port) do
    send(socket, {addr, port}, ancData, data)
  end

  def send({:"$inet", :gen_udp_socket, {_, eSock}} = socket, host, service, ancData, data)
      when is_list(host) or is_atom(host) do
    case :socket.getopt(eSock, {:otp, :domain}) do
      {:ok, domain} ->
        case :inet.getaddr(host, domain) do
          {:ok, addr} ->
            {:ok, %{mod: mod}} =
              :socket.getopt(
                eSock,
                {:otp, :meta}
              )

            case mod.getserv(service) do
              {:ok, port} ->
                send(socket, {addr, port}, ancData, data)

              {:error, :einval} ->
                exit(:badarg)

              {:error, _} = eRROR ->
                eRROR
            end

          {:error, :einval} ->
            exit(:badarg)

          {:error, _} = eRROR ->
            eRROR
        end

      eRROR ->
        eRROR
    end
  end

  def send(_Socket, _Arg1, _Arg2, _Arg3, _Arg4) do
    exit(:badarg)
  end

  defp do_sendto({:"$inet", :gen_udp_socket, {_Server, socket}}, dest, data) do
    case socket_sendto(socket, dest, data) do
      {:error, {:invalid, _}} ->
        exit(:badarg)

      any ->
        any
    end
  end

  defp do_sendmsg({:"$inet", :gen_udp_socket, {_Server, socket}}, sockAddr, iOV, ctrl)
       when is_list(iOV) and is_list(ctrl) do
    msgHdr = %{addr: sockAddr, iov: iOV, ctrl: ctrl}

    case socket_sendmsg(socket, msgHdr) do
      {:error, {:invalid, _}} ->
        exit(:badarg)

      any ->
        any
    end
  end

  def recv(socket, length) do
    recv(socket, length, :infinity)
  end

  def recv({:"$inet", :gen_udp_socket, {server, _Socket}}, length, timeout) do
    case call(server, {:recv, length, timeout}) do
      {:error, :badarg} ->
        exit(:badarg)

      oTHER__ ->
        oTHER__
    end
  end

  def controlling_process(
        {:"$inet", :gen_udp_socket, {server, _Socket}} = s,
        newOwner
      )
      when is_pid(newOwner) do
    case call(server, {:controlling_process, newOwner}) do
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
      {:udp, ^s, _Data} = msg ->
        controlling_process(s, newOwner, server, msg)

      {:udp_closed, ^s} = msg ->
        controlling_process(s, newOwner, server, msg)

      {^s, {:data, _Data}} = msg ->
        controlling_process(s, newOwner, server, msg)
    after
      0 ->
        call(server, :controlling_process)
    end
  end

  defp controlling_process(s, newOwner, server, msg) do
    send(newOwner, msg)
    controlling_process(s, newOwner, server)
  end

  def monitor({:"$inet", :gen_udp_socket, {_Server, eSock}} = socket) do
    case :socket_registry.monitor(
           eSock,
           %{msocket: socket}
         ) do
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

  def setopts({:"$inet", :gen_udp_socket, {server, _Socket}}, opts)
      when is_list(opts) do
    call(server, {:setopts, opts})
  end

  def getopts({:"$inet", :gen_udp_socket, {server, _Socket}}, opts)
      when is_list(opts) do
    call(server, {:getopts, opts})
  end

  def sockname({:"$inet", :gen_udp_socket, {_Server, socket}}) do
    case :socket.sockname(socket) do
      {:ok, sockAddr} ->
        {:ok, address(sockAddr)}

      {:error, _} = error ->
        error
    end
  end

  def socknames(socket) do
    case sockname(socket) do
      {:ok, addr} ->
        {:ok, [addr]}

      {:error, _} = error ->
        error
    end
  end

  def peername({:"$inet", :gen_udp_socket, {_Server, socket}}) do
    case :socket.peername(socket) do
      {:ok, sockAddr} ->
        {:ok, address(sockAddr)}

      {:error, _} = error ->
        error
    end
  end

  def getstat({:"$inet", :gen_udp_socket, {server, _Socket}}, what)
      when is_list(what) do
    call(server, {:getstat, what})
  end

  def info({:"$inet", :gen_udp_socket, {server, _Socket}}) do
    case call(server, :info) do
      {:error, :closed} ->
        %{rstates: [:closed], wstates: [:closed]}

      other ->
        other
    end
  end

  def socket_to_list({:"$inet", :gen_udp_socket, {_Server, socket}}) do
    ~c"#Socket" ++ id = :socket.to_list(socket)
    ~c"#InetSocket" ++ id
  end

  def socket_to_list(socket) do
    :erlang.error(:badarg, [socket])
  end

  def which_sockets() do
    which_sockets(:socket.which_sockets(:udp))
  end

  defp which_sockets(socks) do
    which_sockets(socks, [])
  end

  defp which_sockets([], acc) do
    acc
  end

  defp which_sockets([sock | socks], acc) do
    case :socket.getopt(sock, {:otp, :meta}) do
      {:ok, :undefined} ->
        which_sockets(socks, acc)

      {:ok, _Meta} ->
        %{owner: owner} = :socket.info(sock)
        mSock = {:"$inet", :gen_udp_socket, {owner, sock}}
        which_sockets(socks, [mSock | acc])

      _ ->
        which_sockets(socks, acc)
    end
  end

  defp socket_recvfrom(socket, length) do
    :socket.recvfrom(socket, length, :nowait)
  end

  defp socket_recvmsg(socket, length) do
    :socket.recvmsg(socket, length, 0, :nowait)
  end

  defp socket_send(socket, data) do
    :socket.send(socket, data)
  end

  defp socket_sendto(socket, dest, data) do
    res = :socket.sendto(socket, data, dest)
    res
  end

  defp socket_sendmsg(socket, msgHdr) do
    :socket.sendmsg(socket, msgHdr)
  end

  defp socket_close(socket) do
    case :socket.close(socket) do
      :ok ->
        :ok

      {:error, :closed} ->
        :ok
    end
  end

  defp socket_cancel(socket, info) do
    case :socket.cancel(socket, info) do
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

  defp domain(mod) do
    case mod do
      :inet_udp ->
        :inet

      :inet6_udp ->
        :inet6

      :local_udp ->
        :local
    end
  end

  defp address(sockAddr) do
    case sockAddr do
      %{family: family, addr: iP, port: port}
      when family === :inet or family === :inet6 ->
        {iP, port}

      %{family: :local, path: path} ->
        {:local, path}
    end
  end

  defp setopts_split(filterTags, opts) do
    setopts_split(filterTags, opts, [], [])
  end

  defp setopts_split(_FilterTags, [], true__, false__) do
    {reverse(true__), reverse(false__)}
  end

  defp setopts_split(filterTags, [opt | opts], true__, false__) do
    opt_1 = conv_setopt(opt)

    case member(filterTags, setopt_categories(opt_1)) do
      true ->
        setopts_split(filterTags, opts, [opt_1 | true__], false__)

      false ->
        setopts_split(filterTags, opts, true__, [opt_1 | false__])
    end
  end

  defp member(x, y) when is_atom(x) and is_map(y) do
    case y do
      %{^x => _} ->
        true

      %{} ->
        false
    end
  end

  defp member(x, y) when is_map(x) and is_map(y) do
    :maps.fold(
      fn
        _, _, true ->
          true

        key, _, false ->
          :maps.is_key(key, y)
      end,
      false,
      x
    )
  end

  defp conv_setopt(:binary) do
    {:mode, :binary}
  end

  defp conv_setopt(:list) do
    {:mode, :list}
  end

  defp conv_setopt(:inet) do
    {:udp_module, :inet_udp}
  end

  defp conv_setopt(:inet6) do
    {:udp_module, :inet6_udp}
  end

  defp conv_setopt(:local) do
    {:udp_module, :local_udp}
  end

  defp conv_setopt(other) do
    other
  end

  defp socket_setopt(socket, {:raw, level, key, value}) do
    try do
      :socket.setopt_native(socket, {level, key}, value)
    catch
      {:invalid, _} ->
        {:error, :einval}
    end
  end

  defp socket_setopt(socket, {:raw, {level, key, value}}) do
    try do
      :socket.setopt_native(socket, {level, key}, value)
    catch
      {:invalid, _} ->
        {:error, :einval}
    end
  end

  defp socket_setopt(socket, {tag, value}) do
    case socket_opt() do
      %{^tag => {domain, _} = opt} when is_atom(domain) ->
        socket_setopt_opt(socket, opt, tag, value)

      %{^tag => opts} when is_list(opts) ->
        socket_setopt_opts(opts, socket, tag, value)

      %{} ->
        {:error, :einval}
    end
  end

  defp socket_setopt_opt(socket, opt, tag, value) do
    val = socket_setopt_value(tag, value, opt)
    res = :socket.setopt(socket, opt, val)
    res
  end

  defp socket_setopt_opts([], _Socket, _Tag, _Value) do
    :ok
  end

  defp socket_setopt_opts([{_Level, _OptKey} = opt | opts], socket, tag, value) do
    res = :socket.setopt(socket, opt, socket_setopt_value(tag, value, opt))

    case res do
      :ok ->
        socket_setopt_opts(opts, socket, tag, value)

      {:error, _Reason} ->
        {:error, :einval}
    end
  end

  defp socket_setopt_opts(opts, socket, tag, value) do
    case :socket.getopt(socket, :otp, :domain) do
      {:ok, domain} ->
        case :lists.keysearch(domain, 1, opts) do
          {:value, {^domain, level, optKey}} ->
            opt = {level, optKey}
            res = :socket.setopt(socket, opt, socket_setopt_value(tag, value, opt))
            res

          false ->
            {:error, :einval}
        end

      {:error, _} ->
        {:error, :einval}
    end
  end

  defp socket_setopt_value(:recbuf, value, {:otp, :rcvbuf})
       when value > 65536 do
    65536
  end

  defp socket_setopt_value(_Tag, value, _) do
    value
  end

  defp socket_getopt(socket, {:raw, level, key, valueSpec}) do
    case :socket.getopt_native(socket, {level, key}, valueSpec) do
      {:error, {:invalid, _} = _Reason} ->
        {:error, :einval}

      eLSE ->
        eLSE
    end
  end

  defp socket_getopt(socket, {:raw, {level, key, valueSpec}}) do
    case :socket.getopt_native(socket, {level, key}, valueSpec) do
      {:error, {:invalid, _} = _Reason} ->
        {:error, :einval}

      eLSE ->
        eLSE
    end
  end

  defp socket_getopt(socket, tag) when is_atom(tag) do
    case socket_opt() do
      %{^tag => {domain, _} = opt} when is_atom(domain) ->
        socket_getopt_opt(socket, opt, tag)

      %{^tag => opts} when is_list(opts) ->
        socket_getopt_opts(opts, socket, tag)

      %{} = __X__ ->
        {:error, :einval}
    end
  end

  defp socket_getopt_opt(socket, opt, tag) do
    res = :socket.getopt(socket, opt)
    socket_getopt_value(tag, res)
  end

  defp socket_getopt_opts([{_Domain, _} = opt | _], socket, tag) do
    socket_getopt_opt(socket, opt, tag)
  end

  defp socket_getopt_opts(opts, socket, tag) do
    case :socket.getopt(socket, :otp, :domain) do
      {:ok, domain} ->
        case :lists.keysearch(domain, 1, opts) do
          {:value, {^domain, level, optKey}} ->
            opt = {level, optKey}
            res = :socket.getopt(socket, opt)
            socket_getopt_value(tag, res)

          false ->
            {:error, :einval}
        end

      {:error, _DReason} ->
        {:error, :einval}
    end
  end

  defp socket_getopt_value(_Tag, {:ok, _Value} = ok) do
    ok
  end

  defp socket_getopt_value(_Tag, {:error, _} = error) do
    error
  end

  defp start_opts([{:sys_debug, d} | opts]) do
    [{:debug, d} | start_opts(opts)]
  end

  defp start_opts([opt | opts]) do
    [opt | start_opts(opts)]
  end

  defp start_opts([]) do
    []
  end

  defp setopt_categories(opt) do
    case opt do
      {:raw, _, _, _} ->
        %{socket: []}

      {:raw, {_, _, _}} ->
        %{socket: []}

      {tag, _} ->
        opt_categories(tag)

      _ ->
        :ignore
    end
  end

  defp getopt_categories(opt) do
    case opt do
      {:raw, _, _, _} ->
        %{socket: []}

      {:raw, {_, _, _}} ->
        %{socket: []}

      _ ->
        opt_categories(opt)
    end
  end

  defp opt_categories(tag) when is_atom(tag) do
    case tag do
      :sys_debug ->
        %{start: []}

      :debug ->
        %{socket: [], start: []}

      _
      when tag === :recvtos or tag === :recvttl or tag === :recvtclass ->
        %{socket: [], recv_method: []}

      _ ->
        case :maps.is_key(tag, socket_opt()) do
          true ->
            %{socket: []}

          false ->
            case :maps.is_key(tag, ignore_opt()) do
              true ->
                %{ignore: []}

              false ->
                :maps.merge(
                  case :maps.is_key(
                         tag,
                         server_read_opts()
                       ) do
                    true ->
                      %{server_read: []}

                    false ->
                      %{}
                  end,
                  case :maps.is_key(tag, server_write_opts()) do
                    true ->
                      %{server_write: []}

                    false ->
                      %{}
                  end
                )
            end
        end
    end
  end

  defp ignore_opt() do
    %{udp_module: [], ip: [], high_msgq_watermark: [], low_msgq_watermark: []}
  end

  defp socket_opt() do
    %{
      buffer: {:otp, :rcvbuf},
      debug: {:otp, :debug},
      fd: {:otp, :fd},
      broadcast: {:socket, :broadcast},
      bind_to_device: {:socket, :bindtodevice},
      dontroute: {:socket, :dontroute},
      exclusiveaddruse: {:socket, :exclusiveaddruse},
      keepalive: {:socket, :keepalive},
      priority: {:socket, :priority},
      recbuf: [{:socket, :rcvbuf}, {:otp, :rcvbuf}],
      reuseaddr: {:socket, :reuseaddr},
      sndbuf: {:socket, :sndbuf},
      recvtos: {:ip, :recvtos},
      recvttl: {:ip, :recvttl},
      tos: {:ip, :tos},
      ttl: {:ip, :ttl},
      add_membership: {:ip, :add_membership},
      drop_membership: {:ip, :drop_membership},
      multicast_if: {:ip, :multicast_if},
      multicast_ttl: {:ip, :multicast_ttl},
      multicast_loop: {:ip, :multicast_loop},
      recvtclass: {:ipv6, :recvtclass},
      ipv6_v6only: {:ipv6, :v6only},
      tclass: {:ipv6, :tclass},
      pktoptions: [{:inet, :ip, :pktoptions}, {:inet6, :ipv6, :pktoptions}]
    }
  end

  defp server_read_write_opts() do
    %{mod: :undefined}
  end

  defp server_read_opts() do
    :maps.merge(
      %{
        active: false,
        mode: :list,
        header: 0,
        deliver: :term,
        read_packets: 5,
        start_opts: [],
        exit_on_close: true
      },
      server_read_write_opts()
    )
  end

  defp server_write_opts() do
    :maps.merge(%{}, server_read_write_opts())
  end

  defp server_opts() do
    :maps.merge(server_read_opts(), server_write_opts())
  end

  defp meta(d) do
    :maps.with(:maps.keys(server_write_opts()), d)
  end

  defp start_server(mod, domain, startOpts, extraOpts) do
    owner = self()
    arg = {mod, domain, extraOpts, owner}

    case :gen_statem.start(:gen_udp_socket, arg, startOpts) do
      {:ok, _} = oK ->
        oK

      {:error, {:shutdown, reason}} ->
        {:error, reason}

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
    end
  end

  defp stop_server(server) do
    try do
      :gen_statem.stop(server)
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

  Record.defrecord(:r_controlling_process, :controlling_process,
    owner: :undefined,
    state: :undefined
  )

  Record.defrecord(:r_recv, :recv, info: :undefined)

  Record.defrecord(:r_params, :params,
    socket: :undefined,
    owner: :undefined,
    owner_mon: :undefined,
    recv_method: []
  )

  def init({mod, domain, extraOpts, owner}) do
    :erlang.process_flag(:trap_exit, true)
    ownerMon = :erlang.monitor(:process, owner)

    proto =
      cond do
        domain === :local ->
          :default

        true ->
          :udp
      end

    extra = %{}

    case socket_open(domain, proto, extraOpts, extra) do
      {:ok, socket} ->
        d0 = server_opts()
        d = Map.put(d0, :mod, mod)
        :ok = :socket.setopt(socket, {:otp, :iow}, true)
        :ok = :socket.setopt(socket, {:otp, :meta}, meta(d))
        p = r_params(socket: socket, owner: owner, owner_mon: ownerMon)
        state = :open
        data = {p, d}
        {:ok, state, data}

      {:error, reason} ->
        {:stop, {:shutdown, reason}}
    end
  end

  def init(arg) do
    :error_logger.error_report([{:badarg, {:gen_udp_socket, :init, [arg]}}])
    :erlang.error(:badarg, [arg])
  end

  defp socket_open(domain, proto, %{fd: fD} = extraOpts, extra) do
    opts =
      Map.merge(
        :maps.merge(
          extra,
          :maps.remove(:fd, extraOpts)
        ),
        %{dup: false, domain: domain, type: :dgram, protocol: proto}
      )

    case :socket.open(fD, opts) do
      {:ok, socket} = oK ->
        case :socket.info(socket) do
          %{ctype: :fromfd, domain: ^domain, type: :dgram, protocol: _SelectedProto} ->
            oK

          _INVALID ->
            try do
              :socket.close(socket)
            catch
              :error, e -> {:EXIT, {e, __STACKTRACE__}}
              :exit, e -> {:EXIT, e}
              e -> e
            end

            {:error, :einval}
        end

      {:error, _Reason} = eRROR ->
        eRROR
    end
  end

  defp socket_open(domain, proto, extraOpts, extra) do
    opts = :maps.merge(extra, extraOpts)
    :socket.open(domain, :dgram, proto, opts)
  end

  def terminate(_Reason, state, {_P, _} = p_D) do
    case state do
      r_controlling_process(state: oldState) ->
        terminate(oldState, p_D)

      _ ->
        terminate(state, p_D)
    end
  end

  defp terminate(state, {r_params(socket: socket) = p, d}) do
    case state do
      :closed ->
        :ok

      :closed_read ->
        _ = socket_close(socket)
        :ok

      :closed_read_write ->
        _ = socket_close(socket)
        :ok

      _ ->
        _ = socket_close(socket)

        {_D_1, actionsR} =
          case state do
            r_controlling_process(state: oldState) ->
              cleanup_close_read(p, d, oldState, :closed)

            _ ->
              cleanup_close_read(p, d, state, :closed)
          end

        for {:reply, _From, _Msg} = reply <- reverse(actionsR) do
          :gen_statem.reply(reply)
        end

        :ok
    end

    :void
  end

  defp module_socket(r_params(socket: socket)) do
    {:"$inet", :gen_udp_socket, {self(), socket}}
  end

  def handle_event({:call, from}, :get_socket, _State, {r_params(socket: socket), _D}) do
    {:keep_state_and_data, [{:reply, from, {:ok, socket}}]}
  end

  def handle_event({:call, from}, :get_server_opts, _State, {_P, d}) do
    serverOpts = :maps.with(:maps.keys(server_opts()), d)
    {:keep_state_and_data, [{:reply, from, {:ok, serverOpts}}]}
  end

  def handle_event(
        :info,
        {:DOWN, ownerMon, _, _, reason} = _DOWN,
        _State,
        {r_params(owner_mon: ownerMon) = _P, _D} = p_D
      ) do
    {:stop, {:shutdown, reason}, p_D}
  end

  def handle_event(
        :info,
        {:"$socket", socket, :counter_wrap, counter},
        :open = _State,
        {r_params(socket: socket) = p, d}
      ) do
    {:keep_state, {p, wrap_counter(counter, d)}}
  end

  def handle_event(
        :info,
        {:"$socket", socket, :counter_wrap, counter},
        r_recv() = _State,
        {r_params(socket: socket) = p, d}
      ) do
    {:keep_state, {p, wrap_counter(counter, d)}}
  end

  def handle_event(:info, {:"$socket", _Socket, :counter_wrap, _Counter}, _State, _P_D) do
    {:keep_state_and_data, [:postpone]}
  end

  def handle_event(
        {:call, {caller, _} = from},
        {:controlling_process, newOwner},
        state,
        {p, _D} = p_D
      ) do
    case p do
      r_params(owner: ^newOwner) ->
        {:keep_state_and_data, [{:reply, from, :ok}]}

      r_params(owner: ^caller) ->
        {:next_state, r_controlling_process(owner: newOwner, state: state), p_D,
         [{:reply, from, :transfer}]}

      r_params() ->
        {:keep_state_and_data, [{:reply, from, {:error, :not_owner}}]}
    end
  end

  def handle_event(
        {:call, {owner, _} = from},
        :controlling_process,
        r_controlling_process(owner: newOwner, state: state),
        {r_params(owner: owner, owner_mon: ownerMon) = p, d}
      ) do
    newOwnerMon = :erlang.monitor(:process, newOwner)
    true = :erlang.demonitor(ownerMon, [:flush])

    {:next_state, state, {r_params(p, owner: newOwner, owner_mon: newOwnerMon), d},
     [{:reply, from, :ok}]}
  end

  def handle_event(_Type, _Content, r_controlling_process(), _StateData) do
    {:keep_state_and_data, [:postpone]}
  end

  def handle_event({:call, from}, :close, state, {p, d} = p_D) do
    case state do
      :closed_read ->
        {:next_state, :closed, p_D, [{:reply, from, socket_close(r_params(p, :socket))}]}

      :closed_read_write ->
        {:next_state, :closed, p_D, [{:reply, from, socket_close(r_params(p, :socket))}]}

      :closed ->
        {:keep_state_and_data, [{:reply, from, :ok}]}

      _ ->
        next_state(p, cleanup_close_read(p, %{d | active: false}, state, :closed), :closed, [
          {:reply, from, socket_close(r_params(p, :socket))}
        ])
    end
  end

  def handle_event({:call, from}, {:getopts, opts}, state, {p, d}) do
    result = state_getopts(p, d, state, opts)
    {:keep_state_and_data, [{:reply, from, result}]}
  end

  def handle_event({:call, from}, {:setopts, opts}, state, {p, d}) do
    {result_1, {p_1, d_1}} = state_setopts(p, d, state, opts)

    result =
      case result_1 do
        {:error, :enoprotoopt} ->
          _ = :socket.setopt(r_params(p, :socket), {:otp, :meta}, meta(d_1))
          {:error, :einval}

        {:error, {:invalid, _}} ->
          _ = :socket.setopt(r_params(p, :socket), {:otp, :meta}, meta(d_1))
          {:error, :einval}

        {:error, :einval} ->
          _ = :socket.setopt(r_params(p_1, :socket), {:otp, :meta}, meta(d_1))
          result_1

        _ ->
          :ok = :socket.setopt(r_params(p_1, :socket), {:otp, :meta}, meta(d_1))
          result_1
      end

    reply = {:reply, from, result}
    handle_reading(state, p_1, d_1, [reply])
  end

  def handle_event({:call, from}, {:getstat, what}, state, {p, d}) do
    case state do
      :closed ->
        {:keep_state_and_data, [{:reply, from, {:error, :closed}}]}

      _ ->
        {d_1, result} = getstat(r_params(p, :socket), d, what)
        {:keep_state, {p, d_1}, [{:reply, from, {:ok, result}}]}
    end
  end

  def handle_event({:call, from}, :info, state, {p, d}) do
    case state do
      :closed ->
        {:keep_state_and_data, [{:reply, from, %{rstates: [:closed], wstates: [:closed]}}]}

      _ ->
        {d_1, result} = handle_info(state, r_params(p, :socket), r_params(p, :owner), d)
        {:keep_state, {p, d_1}, [{:reply, from, result}]}
    end
  end

  def handle_event(type, content, :closed = state, p_D) do
    handle_closed(type, content, state, p_D)
  end

  def handle_event({:call, from}, {:shutdown, how} = _SHUTDOWN, state, {p, d}) do
    case state do
      :closed_read when how === :read ->
        {:keep_state_and_data, [{:reply, from, :ok}]}

      :closed_read_write when how === :read_write ->
        {:keep_state_and_data, [{:reply, from, :ok}]}

      _ ->
        case handle_shutdown(p, state, how) do
          {:keep, sRes} ->
            {:keep_state_and_data, [{:reply, from, sRes}]}

          {nextState, sRes} ->
            next_state(
              p,
              cleanup_close_read(p, %{d | active: false}, state, :closed),
              nextState,
              [{:reply, from, sRes}]
            )
        end
    end
  end

  def handle_event(type, content, state, p_D)
      when state === :closed_read or state === :closed_read_write do
    handle_closed(type, content, state, p_D)
  end

  def handle_event({:call, from}, {:bind, bindAddr} = _BIND, _State, {p, _D}) do
    result = :socket.bind(r_params(p, :socket), bindAddr)
    {:keep_state_and_data, [{:reply, from, result}]}
  end

  def handle_event(
        {:call, from},
        {:recv, _Length, _Timeout},
        _State,
        {_P, %{active: active} = _D}
      )
      when active !== false do
    {:keep_state_and_data, [{:reply, from, {:error, :einval}}]}
  end

  def handle_event({:call, from}, {:recv, length, timeout}, state, {p, d}) do
    case state do
      :open ->
        handle_recv_start(p, d, from, length, timeout)

      r_recv() ->
        {:keep_state_and_data, [:postpone]}
    end
  end

  def handle_event(
        :info,
        {:"$socket", socket, :select, selectRef},
        r_recv(info: {:select_info, _, selectRef}),
        {r_params(socket: socket) = p, d}
      ) do
    handle_recv(p, d, [], :recv)
  end

  def handle_event(
        :info,
        {:"$socket", socket, :completion, {completionRef, completionStatus}},
        r_recv(info: {:completion_info, _, completionRef}),
        {r_params(socket: socket) = p, d}
      ) do
    handle_recv(p, d, [], completionStatus)
  end

  def handle_event(
        :info,
        {:"$socket", socket, :abort, {selectRef, reason}},
        r_recv(info: {:select_info, _, selectRef}),
        {r_params(socket: socket) = p, d}
      ) do
    handle_reading(p, cleanup_recv_reply(p, d, [], reason))
  end

  def handle_event(
        :info,
        {:"$socket", socket, :abort, {handle, reason}},
        r_recv(info: {:completion_info, _, handle}),
        {r_params(socket: socket) = p, d}
      ) do
    handle_reading(p, cleanup_recv_reply(p, d, [], reason))
  end

  def handle_event({:timeout, :recv}, :recv, r_recv() = state, {p, d}) do
    handle_reading(p, cleanup_recv(p, d, state, :timeout))
  end

  def handle_event(type, content, state, p_D) do
    handle_unexpected(type, content, state, p_D)
  end

  defp handle_shutdown(r_params(socket: socket), :open = _State, :write = how) do
    {:keep, :socket.shutdown(socket, how)}
  end

  defp handle_shutdown(r_params(socket: socket), r_recv() = _State, :write = how) do
    {:keep, :socket.shutdown(socket, how)}
  end

  defp handle_shutdown(r_params(socket: socket), :open = _State, :read = how) do
    handle_shutdown2(socket, :closed_read, how)
  end

  defp handle_shutdown(r_params(socket: socket), r_recv() = _State, :read = how) do
    handle_shutdown2(socket, :closed_read, how)
  end

  defp handle_shutdown(r_params(socket: socket), :open = _State, :read_write = how) do
    handle_shutdown2(socket, :closed_read_write, how)
  end

  defp handle_shutdown(r_params(socket: socket), r_recv() = _State, :read_write = how) do
    handle_shutdown2(socket, :closed_read_write, how)
  end

  defp handle_shutdown(_Params, state, _How) do
    {:keep, {:error, {:invalid_state, state}}}
  end

  defp handle_shutdown2(socket, nextState, how) do
    case :socket.shutdown(socket, how) do
      :ok ->
        {nextState, :ok}

      error ->
        {:keep, error}
    end
  end

  defp handle_unexpected(type, content, state, {p, _D}) do
    :error_logger.warning_report([
      {:module, :gen_udp_socket},
      {:socket, r_params(p, :socket)},
      {:unknown_event, {type, content}},
      {:state, state}
    ])

    case type do
      {:call, from} ->
        {:keep_state_and_data, [{:reply, from, {:error, :einval}}]}

      _ ->
        :keep_state_and_data
    end
  end

  defp handle_closed(type, content, state, {p, _D}) do
    case type do
      {:call, from} ->
        {:keep_state_and_data, [{:reply, from, {:error, :closed}}]}

      _ ->
        :error_logger.warning_report([
          {:module, :gen_udp_socket},
          {:socket, r_params(p, :socket)},
          {:unknown_event, {type, content}},
          {:state, state}
        ])

        :keep_state_and_data
    end
  end

  defp handle_reading(:open = _State, p, %{active: active} = d, actionsR)
       when active !== false do
    handle_recv(p, recv_start(d), actionsR, :recv)
  end

  defp handle_reading(
         r_recv(info: info) = _State,
         r_params(socket: socket) = p,
         %{active: active} = d,
         actionsR
       )
       when active === false do
    _ = socket_cancel(socket, info)
    {d2, actionsR2} = cleanup_recv_reply(p, d, actionsR, :normal)
    {:next_state, :open, {p, recv_stop(%{d2 | active: false})}, reverse(actionsR2)}
  end

  defp handle_reading(_State, p, d, actionsR) do
    {:keep_state, {p, d}, actionsR}
  end

  defp handle_reading(p, {d, actionsR}) do
    handle_reading(p, d, actionsR)
  end

  defp handle_reading(p, d, actionsR) do
    case d do
      %{active: false} ->
        {:next_state, :open, {p, d}, reverse(actionsR)}

      %{active: _} ->
        handle_recv(p, recv_start(d), actionsR, :recv)
    end
  end

  defp handle_recv_start(p, d, from, length, timeout) do
    handle_recv(
      p,
      Map.merge(d, %{recv_length: length, recv_from: from}),
      [{{:timeout, :recv}, timeout, :recv}],
      :recv
    )
  end

  defp handle_recv(
         r_params(socket: socket, recv_method: []) = p,
         %{recv_length: length} = d,
         actionsR,
         cS
       )
       when cS === :recv do
    case socket_recvfrom(socket, length) do
      {:ok, {source, <<data::binary>>}} ->
        handle_recv_deliver(p, d, actionsR, {source, data})

      {:select, {:select_info, _, _} = selectInfo} ->
        {:next_state, r_recv(info: selectInfo), {p, d}, reverse(actionsR)}

      {:completion, {:completion_info, _, _} = completionInfo} ->
        {:next_state, r_recv(info: completionInfo), {p, d}, reverse(actionsR)}

      {:error, reason} ->
        handle_recv_error(p, d, actionsR, reason)
    end
  end

  defp handle_recv(r_params(recv_method: []) = p, d, actionsR, cS) do
    case cS do
      {:ok, {source, <<data::binary>>}} ->
        handle_recv_deliver(p, d, actionsR, {source, data})

      {:error, reason0} ->
        reason =
          case reason0 do
            {:completion_status, %{info: :more_data = _INFO}} ->
              :emsgsize

            {:completion_status, :more_data = _INFO} ->
              :emsgsize

            {:completion_status, %{info: iNFO}} ->
              iNFO

            {:completion_status, iNFO} ->
              iNFO

            _ ->
              reason0
          end

        handle_recv_error(p, d, actionsR, reason)
    end
  end

  defp handle_recv(r_params(socket: socket) = p, %{recv_length: length} = d, actionsR, cS)
       when cS === :recv do
    case socket_recvmsg(socket, length) do
      {:ok, msgHdr} ->
        handle_recv_deliver(p, d, actionsR, msgHdr)

      {:select, {:select_info, _, _} = selectInfo} ->
        {:next_state, r_recv(info: selectInfo), {p, d}, reverse(actionsR)}

      {:completion, {:completion_info, _, _} = completionInfo} ->
        {:next_state, r_recv(info: completionInfo), {p, d}, reverse(actionsR)}

      {:error, reason} ->
        handle_recv_error(p, d, actionsR, reason)
    end
  end

  defp handle_recv(p, d, actionsR, cS) do
    case cS do
      {:ok, msgHdr} ->
        handle_recv_deliver(p, d, actionsR, msgHdr)

      {:error, reason} ->
        handle_recv_error(p, d, actionsR, reason)
    end
  end

  defp handle_recv_deliver(p, d, actionsR, data) do
    handle_reading(
      p,
      recv_data_deliver(p, d, actionsR, data)
    )
  end

  defp handle_recv_error(p, d, actionsR, reason) do
    {d_1, actionsR_1} = cleanup_recv_reply(p, d, actionsR, reason)

    case reason do
      :closed ->
        {:next_state, :closed_read, {p, d_1}, reverse(actionsR_1)}

      :emsgsize ->
        {:next_state, :open, {p, recv_stop(%{d | active: false})}, reverse(actionsR_1)}

      _ ->
        {:next_state, :open, {p, recv_stop(%{d | active: false})}, reverse(actionsR_1)}
    end
  end

  defp next_state(p, {d, actionsR}, state, actions) do
    {:next_state, state, {p, d}, reverse(actionsR, actions)}
  end

  defp cleanup_close_read(p, d, state, reason) do
    cleanup_recv(p, d, state, reason)
  end

  defp cleanup_recv(p, d, state, reason) do
    case state do
      r_recv(info: info) ->
        _ = socket_cancel(r_params(p, :socket), info)
        cleanup_recv_reply(p, d, [], reason)

      _ ->
        cleanup_recv_reply(p, d, [], reason)
    end
  end

  defp cleanup_recv_reply(p, d, actionsR, reason0) do
    reason =
      case d do
        %{active: false} ->
          reason0

        %{active: _} ->
          moduleSocket = module_socket(p)
          owner = r_params(p, :owner)

          case reason0 do
            :timeout ->
              send(owner, {:udp_error, moduleSocket, reason0})
              reason0

            :closed ->
              send(owner, {:udp_closed, moduleSocket})
              reason0

            :emsgsize ->
              send(owner, {:udp_error, moduleSocket, reason0})
              reason0

            {:completion_status, %{info: :more_data = _INFO}} ->
              r = :emsgsize
              send(owner, {:udp_error, moduleSocket, r})
              r

            {:completion_status, :more_data = _INFO} ->
              r = :emsgsize
              send(owner, {:udp_error, moduleSocket, r})
              r

            {:completion_status, %{info: iNFO}} ->
              send(owner, {:udp_error, moduleSocket, iNFO})
              iNFO

            {:completion_status, iNFO} ->
              send(owner, {:udp_error, moduleSocket, iNFO})
              iNFO

            _ ->
              send(owner, {:udp_error, moduleSocket, reason0})
              send(owner, {:udp_closed, moduleSocket})
              reason0
          end
      end

    {recv_stop(%{d | active: false}),
     case d do
       %{recv_from: from} ->
         [
           {:reply, from, {:error, reason}},
           {{:timeout, :recv}, :cancel}
           | actionsR
         ]

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

  defp recv_data_deliver(
         r_params(owner: owner) = p,
         %{mode: mode, deliver: deliver} = d,
         actionsR,
         data
       ) do
    {iP, port, ancData, deliverData} =
      deliver_data(
        data,
        mode
      )

    case d do
      %{recv_from: from} ->
        {recv_stop(d),
         [
           {:reply, from, {:ok, mk_recv_reply(iP, port, ancData, deliverData)}},
           {{:timeout, :recv}, :cancel} | actionsR
         ]}

      %{active: false} ->
        {recv_stop(d), actionsR}

      %{active: active} ->
        moduleSocket = module_socket(p)
        _ = deliver_recv_msg(owner, active, deliver, moduleSocket, iP, port, ancData, deliverData)

        case active do
          true ->
            {recv_start(d), actionsR}

          :once ->
            {recv_stop(Map.put(d, :active, false)), actionsR}

          1 ->
            send(owner, {:udp_passive, moduleSocket})
            {recv_stop(Map.put(d, :active, false)), actionsR}

          n when is_integer(n) ->
            {recv_start(Map.put(d, :active, active - 1)), actionsR}
        end
    end
  end

  defp mk_recv_reply(iP, port, :undefined = _AncData, data) do
    {iP, port, data}
  end

  defp mk_recv_reply(iP, port, ancData, data) do
    {iP, port, ancData, data}
  end

  defp deliver_recv_msg(pid, active, deliver, socket, iP, port, ancData, data) do
    send(pid, mk_recv_msg(active, deliver, socket, iP, port, ancData, data))
  end

  defp mk_recv_msg(true = _Active, :port = _Deliver, socket, iP, port, :undefined, data) do
    {socket, {:data, [iP, port, data]}}
  end

  defp mk_recv_msg(true = _Active, :port = _Deliver, socket, iP, port, ancData, data) do
    {socket, {:data, [iP, port, ancData, data]}}
  end

  defp mk_recv_msg(_Active, _Deliver, socket, iP, port, :undefined, data) do
    {:udp, socket, iP, port, data}
  end

  defp mk_recv_msg(_Active, _Deliver, socket, iP, port, ancData, data) do
    {:udp, socket, iP, port, ancData, data}
  end

  defp deliver_data(
         {%{family: :local = fam, path: path}, <<data::binary>>},
         mode
       ) do
    {{fam, path}, 0, :undefined, deliver_data_mode(data, mode)}
  end

  defp deliver_data(
         {%{family: fam, addr: addr, port: port}, <<data::binary>>},
         mode
       )
       when fam === :inet or fam === :inet6 do
    {addr, port, :undefined, deliver_data_mode(data, mode)}
  end

  defp deliver_data(
         %{addr: %{family: :local = fam, path: path}, iov: iOV, ctrl: ctrl},
         mode
       ) do
    data = deliver_data_mode(iOV, mode)
    ctrl2 = ctrl2ancdata(ctrl)
    {{fam, path}, 0, ctrl2, data}
  end

  defp deliver_data(
         %{addr: %{family: fam, addr: addr, port: port}, iov: iOV, ctrl: ctrl},
         mode
       )
       when fam === :inet or fam === :inet6 do
    data = deliver_data_mode(iOV, mode)
    ctrl2 = ctrl2ancdata(ctrl)
    {addr, port, ctrl2, data}
  end

  defp deliver_data(
         {%{family: :unspec, addr: addr}, <<data::binary>>},
         mode
       )
       when is_binary(addr) do
    {{:unspec, addr}, 0, :undefined, deliver_data_mode(data, mode)}
  end

  defp deliver_data({unspec, <<data::binary>>}, mode)
       when is_binary(unspec) do
    {{:unspec, unspec}, 0, :undefined, deliver_data_mode(data, mode)}
  end

  defp deliver_data_mode(data, :list) when is_binary(data) do
    :erlang.binary_to_list(data)
  end

  defp deliver_data_mode(data, :binary) when is_binary(data) do
    data
  end

  defp deliver_data_mode(iOV, :list) when is_list(iOV) do
    deliver_data_mode_bin(iOV)
  end

  defp deliver_data_mode(iOV, :binary) when is_list(iOV) do
    :erlang.iolist_to_binary(iOV)
  end

  defp deliver_data_mode_bin([bin]) do
    bin
  end

  defp deliver_data_mode_bin([bin1, bin2]) do
    <<bin1::binary, bin2::binary>>
  end

  defp deliver_data_mode_bin([bin1, bin2, bin3]) do
    <<bin1::binary, bin2::binary, bin3::binary>>
  end

  defp deliver_data_mode_bin([bin1, bin2, bin3, bin4]) do
    <<bin1::binary, bin2::binary, bin3::binary, bin4::binary>>
  end

  defp deliver_data_mode_bin(iOV) do
    deliver_data_mode_bin(iOV, <<>>)
  end

  defp deliver_data_mode_bin([], acc) do
    acc
  end

  defp deliver_data_mode_bin([bin | iOV], acc) do
    deliver_data_mode_bin(
      iOV,
      <<bin::binary, acc::binary>>
    )
  end

  defp ctrl2ancdata(cTRL) do
    ctrl2ancdata(cTRL, [])
  end

  defp ctrl2ancdata([], ancData) do
    :lists.reverse(ancData)
  end

  defp ctrl2ancdata(
         [
           %{level: :ip, type: tOS, value: value, data: _Data}
           | cTRL
         ],
         ancData
       )
       when tOS === :tos or tOS === :recvtos do
    ctrl2ancdata(cTRL, [{:tos, value} | ancData])
  end

  defp ctrl2ancdata(
         [
           %{level: :ip, type: tTL, value: value, data: _Data}
           | cTRL
         ],
         ancData
       )
       when tTL === :ttl or tTL === :recvttl do
    ctrl2ancdata(cTRL, [{:ttl, value} | ancData])
  end

  defp ctrl2ancdata(
         [
           %{level: :ipv6, type: :tclass, value: tClass, data: _Data}
           | cTRL
         ],
         ancData
       ) do
    ctrl2ancdata(cTRL, [{:tclass, tClass} | ancData])
  end

  defp ctrl2ancdata([_ | cTRL], ancData) do
    ctrl2ancdata(cTRL, ancData)
  end

  defp state_setopts(p, d, _State, []) do
    {:ok, {p, d}}
  end

  defp state_setopts(p, d, state, [opt | opts]) do
    opt_1 = conv_setopt(opt)

    case setopt_categories(opt_1) do
      %{socket: _, recv_method: _} ->
        recvMethod = r_params(p, :recv_method)

        recvMethod2 =
          case opt_1 do
            {tag, true} ->
              m = :lists.member(tag, recvMethod)

              cond do
                m ->
                  recvMethod

                true ->
                  [tag | recvMethod]
              end

            {tag, false} ->
              :lists.delete(tag, recvMethod)
          end

        p_1 = r_params(p, recv_method: recvMethod2)

        case r_params(p_1, :socket) do
          :undefined ->
            {{:error, :closed}, {p, d, state}}

          socket ->
            case socket_setopt(socket, opt_1) do
              :ok ->
                state_setopts(p_1, d, state, opts)

              {:error, _} = error ->
                {error, {p_1, d}}
            end
        end

      %{socket: _} ->
        case r_params(p, :socket) do
          :undefined ->
            {{:error, :closed}, {p, d}}

          socket ->
            case socket_setopt(socket, opt_1) do
              :ok ->
                state_setopts(p, d, state, opts)

              {:error, _} = error ->
                {error, {p, d}}
            end
        end

      %{server_write: _} when state === :closed ->
        {{:error, :einval}, {p, d}}

      %{server_write: _} ->
        state_setopts_server(p, d, state, opts, opt_1)

      %{server_read: _} when state === :closed ->
        {{:error, :einval}, {p, d}}

      %{server_read: _}
      when state === :closed_read or state === :closed_read_write ->
        {{:error, :einval}, {p, d}}

      %{server_read: _} ->
        state_setopts_server(p, d, state, opts, opt_1)

      %{ignore: _} ->
        state_setopts(p, d, state, opts)

      %{} = _EXTRA ->
        {{:error, :einval}, {p, d}}
    end
  end

  defp state_setopts_server(p, d, state, opts, {tag, value}) do
    case tag do
      :active ->
        state_setopts_active(p, d, state, opts, value)

      _ ->
        state_setopts(p, Map.put(d, tag, value), state, opts)
    end
  end

  defp state_setopts_active(p, d, state, opts, active) do
    cond do
      active === :once or active === true ->
        state_setopts(p, %{d | active: active}, state, opts)

      active === false ->
        case d do
          %{active: oldActive} when is_integer(oldActive) ->
            send(r_params(p, :owner), {:udp_passive, module_socket(p)})
            :ok

          _ ->
            :ok
        end

        state_setopts(p, %{d | active: active}, state, opts)

      is_integer(active) and -32768 <= active and
          active <= 32767 ->
        n =
          case d do
            %{active: oldActive} when is_integer(oldActive) ->
              oldActive + active

            %{active: _OldActive} ->
              active
          end

        cond do
          32767 < n ->
            {{:error, :einval}, {p, d}}

          n <= 0 ->
            send(r_params(p, :owner), {:udp_passive, module_socket(p)})
            state_setopts(p, %{d | active: false}, state, opts)

          true ->
            state_setopts(p, %{d | active: n}, state, opts)
        end

      true ->
        {{:error, :einval}, {p, d}}
    end
  end

  defp state_getopts(p, d, state, opts) do
    state_getopts(p, d, state, opts, [])
  end

  defp state_getopts(_P, _D, _State, [], acc) do
    {:ok, reverse(acc)}
  end

  defp state_getopts(p, d, state, [tag | tags], acc) do
    case getopt_categories(tag) do
      %{socket: _} ->
        case r_params(p, :socket) do
          :undefined ->
            {:error, :closed}

          socket ->
            case socket_getopt(socket, tag) do
              {:ok, value} ->
                state_getopts(p, d, state, tags, [{tag, value} | acc])

              {:error, _Reason} ->
                state_getopts(p, d, state, tags, acc)
            end
        end

      %{server_write: _} when state === :closed ->
        {:error, :einval}

      %{server_write: _} ->
        value = :maps.get(tag, d)
        state_getopts(p, d, state, tags, [{tag, value} | acc])

      %{server_read: _} when state === :closed ->
        {:error, :einval}

      %{server_read: _}
      when state === :closed_read or state === :closed_read_write ->
        {:error, :einval}

      %{server_read: _} ->
        value = :maps.get(tag, d)
        state_getopts(p, d, state, tags, [{tag, value} | acc])

      %{} = _EXTRA ->
        {:error, :einval}
    end
  end

  defp handle_info(state, socket, owner, %{active: active} = d) do
    counters_1 = socket_info_counters(socket)
    {d_1, wrapped} = receive_counter_wrap(socket, d, [])
    info = %{counters: counters_2} = :socket.info(socket)

    counters_3 =
      :maps.merge(
        counters_1,
        :maps.with(wrapped, counters_2)
      )

    counters_4 =
      :maps.from_list(
        getstat_what(
          d_1,
          counters_3
        )
      )

    simpleState = simplify_state(state)

    {d_1,
     Map.merge(info, %{counters: counters_4, istate: simpleState, owner: owner, active: active})}
  end

  defp simplify_state(r_recv()) do
    :recv
  end

  defp simplify_state(state) do
    state
  end

  defp getstat(socket, d, what) do
    counters_1 = socket_info_counters(socket)
    {d_1, wrapped} = receive_counter_wrap(socket, d, [])
    counters_2 = socket_info_counters(socket)

    counters_3 =
      :maps.merge(
        counters_1,
        :maps.with(wrapped, counters_2)
      )

    {d_1, getstat_what(what, d_1, counters_3)}
  end

  defp getstat_what(d, c) do
    getstat_what(:inet.stats(), d, c)
  end

  defp getstat_what([], _D, _C) do
    []
  end

  defp getstat_what([tag | what], d, c) do
    val =
      case tag do
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
      end

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
        receive_counter_wrap(socket, wrap_counter(counter, d), [counter | wrapped])
    after
      0 ->
        {d, wrapped}
    end
  end

  defp wrap_counter(counter, d) do
    case d do
      %{^counter => n} ->
        %{d | counter => n + 1}

      %{} ->
        Map.put(d, counter, 1)
    end
  end

  defp counter_value(counter, d, counters) do
    case d do
      %{^counter => wraps} ->
        wraps <<< (32 + :maps.get(counter, counters))

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
end
