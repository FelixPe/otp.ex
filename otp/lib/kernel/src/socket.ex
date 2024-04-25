defmodule :m_socket do
  use Bitwise
  import Kernel, except: [send: 2]
  require Record

  Record.defrecord(:r_file_info, :file_info,
    size: :undefined,
    type: :undefined,
    access: :undefined,
    atime: :undefined,
    mtime: :undefined,
    ctime: :undefined,
    mode: :undefined,
    links: :undefined,
    major_device: :undefined,
    minor_device: :undefined,
    inode: :undefined,
    uid: :undefined,
    gid: :undefined
  )

  Record.defrecord(:r_file_descriptor, :file_descriptor,
    module: :undefined,
    data: :undefined
  )

  def number_of() do
    :socket_registry.number_of()
  end

  def which_sockets() do
    :socket_registry.which_sockets(true)
  end

  def which_sockets(domain)
      when domain === :inet or
             domain === :inet6 or domain === :local do
    :socket_registry.which_sockets({:domain, domain})
  end

  def which_sockets(type)
      when type === :stream or type === :dgram or
             type === :seqpacket do
    :socket_registry.which_sockets({:type, type})
  end

  def which_sockets(proto)
      when proto === :sctp or proto === :tcp or
             proto === :udp do
    :socket_registry.which_sockets({:protocol, proto})
  end

  def which_sockets(owner) when is_pid(owner) do
    :socket_registry.which_sockets({:owner, owner})
  end

  def which_sockets(filter) when is_function(filter, 1) do
    :socket_registry.which_sockets(filter)
  end

  def which_sockets(other) do
    :erlang.error(:badarg, [other])
  end

  def number_of_monitors() do
    :socket_registry.number_of_monitors()
  end

  def number_of_monitors(pid) when is_pid(pid) do
    :socket_registry.number_of_monitors(pid)
  end

  def which_monitors(pid) when is_pid(pid) do
    :socket_registry.which_monitors(pid)
  end

  def which_monitors({:"$socket", sockRef} = socket)
      when is_reference(sockRef) do
    :socket_registry.which_monitors(socket)
  end

  def which_monitors(socket) do
    :erlang.error(:badarg, [socket])
  end

  def monitored_by({:"$socket", sockRef} = socket)
      when is_reference(sockRef) do
    :socket_registry.monitored_by(socket)
  end

  def monitored_by(socket) do
    :erlang.error(:badarg, [socket])
  end

  def to_list({:"$socket", sockRef}) when is_reference(sockRef) do
    ~c"#Ref" ++ id = :erlang.ref_to_list(sockRef)
    ~c"#Socket" ++ id
  end

  def to_list(socket) do
    :erlang.error(:badarg, [socket])
  end

  def which_socket_kind({:"$socket", sockRef} = socket)
      when is_reference(sockRef) do
    case :prim_socket.getopt(sockRef, {:otp, :meta}) do
      {:ok, :undefined} ->
        :plain

      {:ok, _} ->
        :compat

      {:error, _} ->
        :erlang.error(:badarg, [socket])
    end
  end

  def which_socket_kind(socket) do
    :erlang.error(:badarg, [socket])
  end

  def debug(d) when is_boolean(d) do
    :prim_socket.debug(d)
  end

  def debug(d) do
    :erlang.error(:badarg, [d])
  end

  def socket_debug(d) when is_boolean(d) do
    :prim_socket.socket_debug(d)
  end

  def socket_debug(d) do
    :erlang.error(:badarg, [d])
  end

  def use_registry(d) when is_boolean(d) do
    :prim_socket.use_registry(d)
  end

  def tables() do
    %{
      protocols: table(:protocols),
      options: table(:options),
      ioctl_requests: table(:ioctl_requests),
      ioctl_flags: table(:ioctl_flags),
      msg_flags: table(:msg_flags)
    }
  end

  def table(table) do
    :prim_socket.p_get(table)
  end

  defp default_info_keys() do
    [
      :domain,
      :type,
      :protocol,
      :fd,
      :owner,
      :local_address,
      :remote_address,
      :recv,
      :sent,
      :state
    ]
  end

  def i() do
    do_i(which_sockets(), default_info_keys())
  end

  def i(infoKeys) when is_list(infoKeys) do
    do_i(which_sockets(), infoKeys)
  end

  def i(domain)
      when domain === :inet or domain === :inet6 or domain === :local do
    do_i(which_sockets(domain), default_info_keys())
  end

  def i(proto)
      when proto === :tcp or proto === :udp or proto === :sctp do
    do_i(which_sockets(proto), default_info_keys())
  end

  def i(type)
      when type === :dgram or type === :seqpacket or type === :stream do
    do_i(which_sockets(type), default_info_keys())
  end

  def i(domain, infoKeys)
      when (domain === :inet or domain === :inet6 or domain === :local) and is_list(infoKeys) do
    do_i(which_sockets(domain), infoKeys)
  end

  def i(proto, infoKeys)
      when (proto === :tcp or proto === :udp or proto === :sctp) and is_list(infoKeys) do
    do_i(which_sockets(proto), infoKeys)
  end

  def i(type, infoKeys)
      when (type === :dgram or type === :seqpacket or type === :stream) and is_list(infoKeys) do
    do_i(which_sockets(type), infoKeys)
  end

  defp do_i(sockets, infoKeys) do
    lines =
      case i_sockets(sockets, infoKeys) do
        [] ->
          []

        infoLines ->
          [header_line(infoKeys) | infoLines]
      end

    maxs =
      :lists.foldl(
        fn line, max0 ->
          smax(max0, line)
        end,
        :lists.duplicate(length(infoKeys), 0),
        lines
      )

    fmt =
      :lists.append(
        for n <- maxs do
          ~c"~-" ++ :erlang.integer_to_list(n) ++ ~c"s "
        end
      ) ++ ~c"~n"

    :lists.foreach(
      fn line ->
        :io.format(fmt, line)
      end,
      lines
    )
  end

  defp header_line(fields) do
    for f <- fields do
      header_field(:erlang.atom_to_list(f))
    end
  end

  defp header_field([c | cs]) do
    [:string.to_upper(c) | header_field_rest(cs)]
  end

  defp header_field_rest([?_, c | cs]) do
    [?\s, :string.to_upper(c) | header_field_rest(cs)]
  end

  defp header_field_rest([c | cs]) do
    [c | header_field_rest(cs)]
  end

  defp header_field_rest([]) do
    []
  end

  defp smax([max | ms], [str | strs]) do
    n = length(str)

    [
      cond do
        n > max ->
          n

        true ->
          max
      end
      | smax(ms, strs)
    ]
  end

  defp smax([], []) do
    []
  end

  defp i_sockets(sockets, infoKeys) do
    for socket <- sockets do
      i_socket(socket, infoKeys)
    end
  end

  defp i_socket(socket, infoKeys) do
    info = %{protocol: proto} = info(socket)
    i_socket(proto, socket, info, infoKeys)
  end

  defp i_socket(proto, socket, info, infoKeys) do
    for infoKey <- infoKeys do
      i_socket_info(proto, socket, info, infoKey)
    end
  end

  defp i_socket_info(_Proto, _Socket, %{domain: domain} = _Info, :domain) do
    :erlang.atom_to_list(domain)
  end

  defp i_socket_info(_Proto, _Socket, %{type: type} = _Info, :type) do
    :string.to_upper(:erlang.atom_to_list(type))
  end

  defp i_socket_info(proto, _Socket, %{type: type} = _Info, :protocol) do
    :string.to_upper(
      :erlang.atom_to_list(
        cond do
          proto === 0 ->
            case type do
              :stream ->
                :tcp

              :dgram ->
                :udp

              _ ->
                :unknown
            end

          true ->
            proto
        end
      )
    )
  end

  defp i_socket_info(_Proto, socket, _Info, :fd) do
    try do
      :socket.getopt(socket, :otp, :fd)
    catch
      _, _ ->
        ~c" "
    else
      {:ok, fD} ->
        :erlang.integer_to_list(fD)

      {:error, _} ->
        ~c" "
    end
  end

  defp i_socket_info(_Proto, _Socket, %{owner: pid} = _Info, :owner) do
    :erlang.pid_to_list(pid)
  end

  defp i_socket_info(proto, socket, _Info, :local_address) do
    case sockname(socket) do
      {:ok, addr} ->
        fmt_sockaddr(addr, proto)

      {:error, _} ->
        ~c" "
    end
  end

  defp i_socket_info(proto, socket, _Info, :remote_address) do
    try do
      peername(socket)
    catch
      _, _ ->
        ~c" "
    else
      {:ok, addr} ->
        fmt_sockaddr(addr, proto)

      {:error, _} ->
        ~c" "
    end
  end

  defp i_socket_info(_Proto, _Socket, %{counters: %{read_byte: n}} = _Info, :recv) do
    :erlang.integer_to_list(n)
  end

  defp i_socket_info(_Proto, _Socket, %{counters: %{write_byte: n}} = _Info, :sent) do
    :erlang.integer_to_list(n)
  end

  defp i_socket_info(_Proto, _Socket, %{rstates: rStates, wstates: wStates} = _Info, :state) do
    fmt_states(rStates, wStates)
  end

  defp i_socket_info(_Proto, _Socket, _Info, _Key) do
    ~c" "
  end

  defp fmt_states([], []) do
    ~c" "
  end

  defp fmt_states(rStates, []) do
    fmt_states(rStates) ++ ~c", -"
  end

  defp fmt_states([], wStates) do
    ~c" - , " ++ fmt_states(wStates)
  end

  defp fmt_states(rStates, wStates) do
    fmt_states(rStates) ++ ~c" , " ++ fmt_states(wStates)
  end

  defp fmt_states([h]) do
    fmt_state(h)
  end

  defp fmt_states([h | t]) do
    fmt_state(h) ++ ~c":" ++ fmt_states(t)
  end

  defp fmt_state(:accepting) do
    ~c"A"
  end

  defp fmt_state(:bound) do
    ~c"BD"
  end

  defp fmt_state(:busy) do
    ~c"BY"
  end

  defp fmt_state(:connected) do
    ~c"CD"
  end

  defp fmt_state(:connecting) do
    ~c"CG"
  end

  defp fmt_state(:listen) do
    ~c"LN"
  end

  defp fmt_state(:listening) do
    ~c"LG"
  end

  defp fmt_state(:open) do
    ~c"O"
  end

  defp fmt_state(:selected) do
    ~c"SD"
  end

  defp fmt_state(x) when is_atom(x) do
    :string.uppercase(:erlang.atom_to_list(x))
  end

  defp fmt_sockaddr(%{family: fam, addr: addr, port: port}, proto)
       when fam === :inet or fam === :inet6 do
    case addr do
      {0, 0, 0, 0} ->
        ~c"*:" ++ fmt_port(port, proto)

      {0, 0, 0, 0, 0, 0, 0, 0} ->
        ~c"*:" ++ fmt_port(port, proto)

      {127, 0, 0, 1} ->
        ~c"localhost:" ++ fmt_port(port, proto)

      {0, 0, 0, 0, 0, 0, 0, 1} ->
        ~c"localhost:" ++ fmt_port(port, proto)

      iP ->
        :inet_parse.ntoa(iP) ++ ~c":" ++ fmt_port(port, proto)
    end
  end

  defp fmt_sockaddr(%{family: :local, path: path}, _Proto) do
    ~c"local:" ++
      cond do
        is_list(path) ->
          path

        is_binary(path) ->
          :erlang.binary_to_list(path)
      end
  end

  defp fmt_port(n, proto) do
    case :inet.getservbyport(n, proto) do
      {:ok, name} ->
        f(~c"~s (~w)", [name, n])

      _ ->
        :erlang.integer_to_list(n)
    end
  end

  def info() do
    try do
      :prim_socket.info()
    catch
      :error, :undef ->
        case __STACKTRACE__ do
          [{:prim_socket, :info, [], _} | _] ->
            :erlang.raise(:error, :notsup, __STACKTRACE__)

          _ ->
            :erlang.raise(:error, :undef, __STACKTRACE__)
        end
    end
  end

  def info({:"$socket", sockRef}) when is_reference(sockRef) do
    :prim_socket.info(sockRef)
  end

  def info(socket) do
    :erlang.error(:badarg, [socket])
  end

  def monitor({:"$socket", sockRef} = socket)
      when is_reference(sockRef) do
    case :prim_socket.setopt(sockRef, {:otp, :use_registry}, true) do
      :ok ->
        :socket_registry.monitor(socket)

      {:error, :closed = sReason} ->
        mRef = make_ref()
        send(self(), {:DOWN, mRef, :socket, socket, sReason})
        mRef
    end
  end

  def monitor(socket) do
    :erlang.error(:badarg, [socket])
  end

  def cancel_monitor(mRef) when is_reference(mRef) do
    case :socket_registry.cancel_monitor(mRef) do
      :ok ->
        true

      {:error, :unknown_monitor} ->
        false

      {:error, :not_owner} ->
        :erlang.error(:badarg, [mRef])

      {:error, reason} ->
        :erlang.error({:invalid, reason})
    end
  end

  def cancel_monitor(mRef) do
    :erlang.error(:badarg, [mRef])
  end

  def supports() do
    for key1 <- [:ioctl_requests, :ioctl_flags, :options, :msg_flags, :protocols] do
      {key1, supports(key1)}
    end ++ :prim_socket.supports()
  end

  def supports(key) do
    :prim_socket.supports(key)
  end

  def supports(key1, key2) do
    :prim_socket.supports(key1, key2)
  end

  def is_supported(key1) do
    :prim_socket.is_supported(key1)
  end

  def is_supported(key1, key2) do
    :prim_socket.is_supported(key1, key2)
  end

  def is_supported(:options, level, opt)
      when is_atom(level) and
             is_atom(opt) do
    is_supported(:options, {level, opt})
  end

  def options() do
    :lists.sort(supports(:options))
  end

  def options(level) do
    for {{lvl, opt}, supported} <- options(),
        lvl === level do
      {opt, supported}
    end
  end

  def options(level, supported) do
    for {opt, sup} <- options(level), sup === supported do
      opt
    end
  end

  def option({level, opt}) do
    :lists.member(opt, options(level, true))
  end

  def option(level, opt) do
    option({level, opt})
  end

  def protocols() do
    :lists.sort(supports(:protocols))
  end

  def protocol(proto) do
    case :lists.keysearch(proto, 1, protocols()) do
      {:value, {^proto, supported}} ->
        supported

      false ->
        false
    end
  end

  def open(fD) when is_integer(fD) do
    open(fD, %{})
  end

  def open(fD) do
    :erlang.error(:badarg, [fD])
  end

  def open(fD, opts) when is_map(opts) do
    cond do
      is_integer(fD) ->
        case :prim_socket.open(fD, opts) do
          {:ok, sockRef} ->
            socket = {:"$socket", sockRef}
            {:ok, socket}

          {:error, _} = eRROR ->
            eRROR
        end

      true ->
        :erlang.error(:badarg, [fD, opts])
    end
  end

  def open(domain, type) do
    open(domain, type, 0)
  end

  def open(domain, type, opts) when is_map(opts) do
    open(domain, type, 0, opts)
  end

  def open(domain, type, protocol) do
    open(domain, type, protocol, %{})
  end

  def open(domain, type, protocol, opts)
      when is_map(opts) do
    case :prim_socket.open(domain, type, protocol, opts) do
      {:ok, sockRef} ->
        socket = {:"$socket", sockRef}
        {:ok, socket}

      {:error, _} = eRROR ->
        eRROR
    end
  end

  def open(domain, type, protocol, opts) do
    :erlang.error(:badarg, [domain, type, protocol, opts])
  end

  def bind({:"$socket", sockRef}, addr)
      when is_reference(sockRef) do
    cond do
      addr === :any or addr === :broadcast or
          addr === :loopback ->
        case :prim_socket.getopt(sockRef, {:otp, :domain}) do
          {:ok, domain} when domain === :inet or domain === :inet6 ->
            :prim_socket.bind(
              sockRef,
              %{family: domain, addr: addr}
            )

          {:ok, _Domain} ->
            {:error, :eafnosupport}

          {:error, _} = eRROR ->
            eRROR
        end

      is_atom(addr) ->
        {:error, {:invalid, {:sockaddr, addr}}}

      true ->
        :prim_socket.bind(sockRef, addr)
    end
  end

  def bind(socket, addr) do
    :erlang.error(:badarg, [socket, addr])
  end

  def bind({:"$socket", sockRef}, addrs, action)
      when is_reference(sockRef) and is_list(addrs) and (action === :add or action === :remove) do
    :prim_socket.bind(sockRef, addrs, action)
  end

  def bind(socket, addrs, action) do
    :erlang.error(:badarg, [socket, addrs, action])
  end

  def connect(socket, sockAddr) do
    connect(socket, sockAddr, :infinity)
  end

  def connect({:"$socket", sockRef}, sockAddr, timeoutOrHandle)
      when is_reference(sockRef) do
    case deadline(timeoutOrHandle) do
      :invalid ->
        :erlang.error({:invalid, {:timeout, timeoutOrHandle}})

      :nowait ->
        handle = make_ref()
        connect_nowait(sockRef, sockAddr, handle)

      :handle ->
        handle = timeoutOrHandle
        connect_nowait(sockRef, sockAddr, handle)

      deadline ->
        connect_deadline(sockRef, sockAddr, deadline)
    end
  end

  def connect(socket, sockAddr, timeout) do
    :erlang.error(:badarg, [socket, sockAddr, timeout])
  end

  defp connect_nowait(sockRef, sockAddr, handle) do
    case :prim_socket.connect(sockRef, handle, sockAddr) do
      :select ->
        {:select, {:select_info, :connect, handle}}

      :completion ->
        {:completion, {:completion_info, :connect, handle}}

      result ->
        result
    end
  end

  defp connect_deadline(sockRef, sockAddr, deadline) do
    ref = make_ref()

    case :prim_socket.connect(sockRef, ref, sockAddr) do
      :select ->
        timeout = timeout(deadline)

        receive do
          {:"$socket", _Socket, :select, ^ref} ->
            :prim_socket.connect(sockRef)

          {:"$socket", _Socket, :abort, {^ref, reason}} ->
            {:error, reason}
        after
          timeout ->
            _ = cancel(sockRef, :connect, ref)
            {:error, :timeout}
        end

      :completion ->
        timeout = timeout(deadline)

        receive do
          {:"$socket", _Socket, :completion, {^ref, completionStatus}} ->
            completionStatus

          {:"$socket", _Socket, :abort, {^ref, reason}} ->
            {:error, reason}
        after
          timeout ->
            _ = cancel(sockRef, :connect, ref)
            {:error, :timeout}
        end

      result ->
        result
    end
  end

  def connect({:"$socket", sockRef}) when is_reference(sockRef) do
    :prim_socket.connect(sockRef)
  end

  def connect(socket) do
    :erlang.error(:badarg, [socket])
  end

  def listen(socket) do
    listen(socket, 5)
  end

  def listen({:"$socket", sockRef}, backlog)
      when is_reference(sockRef) and is_integer(backlog) do
    :prim_socket.listen(sockRef, backlog)
  end

  def listen(socket, backlog) do
    :erlang.error(:badarg, [socket, backlog])
  end

  def accept(listenSocket) do
    accept(listenSocket, :infinity)
  end

  def accept({:"$socket", lSockRef}, timeout)
      when is_reference(lSockRef) do
    case deadline(timeout) do
      :invalid ->
        :erlang.error({:invalid, {:timeout, timeout}})

      :nowait ->
        handle = make_ref()
        accept_nowait(lSockRef, handle)

      :handle ->
        handle = timeout
        accept_nowait(lSockRef, handle)

      deadline ->
        accept_deadline(lSockRef, deadline)
    end
  end

  def accept(listenSocket, timeout) do
    :erlang.error(:badarg, [listenSocket, timeout])
  end

  defp accept_nowait(lSockRef, handle) do
    case :prim_socket.accept(lSockRef, handle) do
      :select ->
        {:select, {:select_info, :accept, handle}}

      :completion ->
        {:completion, {:completion_info, :accept, handle}}

      result ->
        accept_result(lSockRef, handle, result)
    end
  end

  defp accept_deadline(lSockRef, deadline) do
    accRef = make_ref()

    case :prim_socket.accept(lSockRef, accRef) do
      :select ->
        timeout = timeout(deadline)

        receive do
          {:"$socket", {:"$socket", ^lSockRef}, :select, ^accRef} ->
            accept_deadline(lSockRef, deadline)

          {:"$socket", _Socket, :abort, {^accRef, reason}} ->
            {:error, reason}
        after
          timeout ->
            _ = cancel(lSockRef, :accept, accRef)
            {:error, :timeout}
        end

      :completion ->
        timeout = timeout(deadline)

        receive do
          {:"$socket", {:"$socket", ^lSockRef}, :completion, {^accRef, completionStatus}} ->
            completionStatus

          {:"$socket", _Socket, :abort, {^accRef, reason}} ->
            {:error, reason}
        after
          timeout ->
            _ = cancel(lSockRef, :accept, accRef)
            {:error, :timeout}
        end

      result ->
        accept_result(lSockRef, accRef, result)
    end
  end

  defp accept_result(lSockRef, accRef, result) do
    case result do
      {:ok, sockRef} ->
        socket = {:"$socket", sockRef}
        {:ok, socket}

      {:error, _} = eRROR ->
        _ = cancel(lSockRef, :accept, accRef)
        eRROR
    end
  end

  def send(socket, data) do
    send(socket, data, [], :infinity)
  end

  def send(socket, data, flags_Cont)
      when is_list(flags_Cont) or is_tuple(flags_Cont) do
    send(socket, data, flags_Cont, :infinity)
  end

  def send(socket, data, timeout) do
    send(socket, data, [], timeout)
  end

  def send({:"$socket", sockRef}, data, {:select_info, selectTag, _} = cont, timeout)
      when is_reference(sockRef) and is_binary(data) do
    case selectTag do
      {:send, contData} ->
        case deadline(timeout) do
          :invalid ->
            :erlang.error({:invalid, {:timeout, timeout}})

          :nowait ->
            selectHandle = make_ref()
            send_nowait_cont(sockRef, data, contData, selectHandle)

          :handle ->
            selectHandle = timeout
            send_nowait_cont(sockRef, data, contData, selectHandle)

          deadline ->
            hasWritten = false
            send_deadline_cont(sockRef, data, contData, deadline, hasWritten)
        end

      _ ->
        {:error, {:invalid, cont}}
    end
  end

  def send({:"$socket", sockRef}, data, flags, timeout)
      when is_reference(sockRef) and is_binary(data) and
             is_list(flags) do
    case deadline(timeout) do
      :invalid ->
        :erlang.error({:invalid, {:timeout, timeout}})

      :nowait ->
        handle = make_ref()
        send_nowait(sockRef, data, flags, handle)

      :handle ->
        handle = timeout
        send_nowait(sockRef, data, flags, handle)

      deadline ->
        send_deadline(sockRef, data, flags, deadline)
    end
  end

  def send({:"$socket", sockRef} = socket, [bin], flags, timeout)
      when is_reference(sockRef) and is_binary(bin) do
    send(socket, bin, flags, timeout)
  end

  def send({:"$socket", sockRef} = socket, data, flags, timeout)
      when is_reference(sockRef) and is_list(data) do
    try do
      :erlang.list_to_binary(data)
    catch
      :error, :badarg ->
        :erlang.error({:invalid, {:data, data}})
    else
      bin ->
        send(socket, bin, flags, timeout)
    end
  end

  def send(socket, data, flags, timeout) do
    :erlang.error(:badarg, [socket, data, flags, timeout])
  end

  defp send_nowait(sockRef, bin, flags, handle) do
    send_common_nowait_result(handle, :send, :prim_socket.send(sockRef, bin, flags, handle))
  end

  defp send_nowait_cont(sockRef, bin, cont, selectHandle) do
    send_common_nowait_result(
      selectHandle,
      :send,
      :prim_socket.send(sockRef, bin, cont, selectHandle)
    )
  end

  defp send_deadline(sockRef, bin, flags, deadline) do
    handle = make_ref()
    hasWritten = false

    send_common_deadline_result(
      sockRef,
      bin,
      handle,
      deadline,
      hasWritten,
      :send,
      &send_deadline_cont/5,
      :prim_socket.send(sockRef, bin, flags, handle)
    )
  end

  defp send_deadline_cont(sockRef, bin, cont, deadline, hasWritten) do
    handle = make_ref()

    send_common_deadline_result(
      sockRef,
      bin,
      handle,
      deadline,
      hasWritten,
      :send,
      &send_deadline_cont/5,
      :prim_socket.send(sockRef, bin, cont, handle)
    )
  end

  defp send_common_nowait_result(handle, op, result) do
    case result do
      :completion ->
        {:completion, {:completion_info, op, handle}}

      {:select, contData} ->
        {:select, {:select_info, {op, contData}, handle}}

      {:select, data, contData} ->
        {:select, {{:select_info, {op, contData}, handle}, data}}

      ^result ->
        result
    end
  end

  defp send_common_deadline_result(
         sockRef,
         data,
         handle,
         deadline,
         hasWritten,
         op,
         fun,
         sendResult
       ) do
    case sendResult do
      {:select, cont} ->
        timeout = timeout(deadline)

        receive do
          {:"$socket", _Socket, :select, ^handle} ->
            fun.(sockRef, data, cont, deadline, hasWritten)

          {:"$socket", _Socket, :abort, {^handle, reason}} ->
            send_common_error(reason, data, hasWritten)
        after
          timeout ->
            _ = cancel(sockRef, op, handle)
            send_common_error(:timeout, data, hasWritten)
        end

      {:select, data_1, cont} ->
        timeout = timeout(deadline)

        receive do
          {:"$socket", _Socket, :select, ^handle} ->
            fun.(sockRef, data_1, cont, deadline, true)

          {:"$socket", _Socket, :abort, {^handle, reason}} ->
            send_common_error(reason, data_1, true)
        after
          timeout ->
            _ = cancel(sockRef, op, handle)
            send_common_error(:timeout, data_1, true)
        end

      :completion ->
        timeout = timeout(deadline)

        receive do
          {:"$socket", _Socket, :completion, {^handle, completionStatus}} ->
            completionStatus

          {:"$socket", _Socket, :abort, {^handle, reason}} ->
            send_common_error(reason, data, false)
        after
          timeout ->
            _ = cancel(sockRef, op, handle)
            send_common_error(:timeout, data, false)
        end

      {:error, {_Reason, restIOV}} = error
      when is_list(restIOV) ->
        error

      {:error, reason} ->
        send_common_error(reason, data, hasWritten)

      result ->
        result
    end
  end

  defp send_common_error(reason, data, hasWritten) do
    case hasWritten do
      false ->
        {:error, reason}

      true ->
        case data do
          bin when is_binary(bin) ->
            {:error, {reason, bin}}

          iOVec when is_list(iOVec) ->
            {:error, {reason, iOVec}}

          %{iov: iOVec} = _Msg ->
            {:error, {reason, iOVec}}
        end
    end
  end

  def sendto(socket, data, dest_Cont) do
    sendto(socket, data, dest_Cont, [])
  end

  def sendto(socket, data, dest, flags) when is_list(flags) do
    sendto(socket, data, dest, flags, :infinity)
  end

  def sendto({:"$socket", sockRef} = socket, data, {:select_info, selectTag, _} = cont, timeout)
      when is_reference(sockRef) do
    case selectTag do
      {:sendto, contData} ->
        case data do
          bin when is_binary(bin) ->
            sendto_timeout_cont(sockRef, bin, contData, timeout)

          [bin] when is_binary(bin) ->
            sendto_timeout_cont(sockRef, bin, contData, timeout)

          iOV when is_list(iOV) ->
            try do
              :erlang.list_to_binary(iOV)
            catch
              :error, :badarg ->
                :erlang.error({:invalid, {:data, data}})
            else
              bin ->
                sendto_timeout_cont(sockRef, bin, contData, timeout)
            end

          _ ->
            :erlang.error(:badarg, [socket, data, cont, timeout])
        end

      _ ->
        {:error, {:invalid, cont}}
    end
  end

  def sendto(socket, data, dest, timeout) do
    sendto(socket, data, dest, [], timeout)
  end

  def sendto({:"$socket", sockRef}, data, dest, flags, timeout)
      when is_reference(sockRef) and is_binary(data) and
             is_list(flags) do
    case deadline(timeout) do
      :invalid ->
        :erlang.error({:invalid, {:timeout, timeout}})

      :nowait ->
        selectHandle = make_ref()
        sendto_nowait(sockRef, data, dest, flags, selectHandle)

      :handle ->
        handle = timeout
        sendto_nowait(sockRef, data, dest, flags, handle)

      deadline ->
        hasWritten = false
        sendto_deadline(sockRef, data, dest, flags, deadline, hasWritten)
    end
  end

  def sendto({:"$socket", sockRef} = socket, [bin], dest, flags, timeout)
      when is_reference(sockRef) and is_binary(bin) do
    sendto(socket, bin, dest, flags, timeout)
  end

  def sendto({:"$socket", sockRef} = socket, data, dest, flags, timeout)
      when is_reference(sockRef) and is_list(data) do
    try do
      :erlang.list_to_binary(data)
    catch
      :error, :badarg ->
        :erlang.error({:invalid, {:data, data}})
    else
      bin ->
        sendto(socket, bin, dest, flags, timeout)
    end
  end

  def sendto(socket, data, dest, flags, timeout) do
    :erlang.error(
      :badarg,
      [socket, data, dest, flags, timeout]
    )
  end

  defp sendto_timeout_cont(sockRef, bin, cont, timeout) do
    case deadline(timeout) do
      :invalid ->
        :erlang.error({:invalid, {:timeout, timeout}})

      :nowait ->
        selectHandle = make_ref()
        sendto_nowait_cont(sockRef, bin, cont, selectHandle)

      :handle ->
        handle = timeout
        sendto_nowait_cont(sockRef, bin, cont, handle)

      deadline ->
        hasWritten = false
        sendto_deadline_cont(sockRef, bin, cont, deadline, hasWritten)
    end
  end

  defp sendto_nowait(sockRef, bin, to, flags, handle) do
    send_common_nowait_result(
      handle,
      :sendto,
      :prim_socket.sendto(sockRef, bin, to, flags, handle)
    )
  end

  defp sendto_nowait_cont(sockRef, bin, cont, handle) do
    send_common_nowait_result(handle, :sendto, :prim_socket.sendto(sockRef, bin, cont, handle))
  end

  defp sendto_deadline(sockRef, bin, to, flags, deadline, hasWritten) do
    handle = make_ref()

    send_common_deadline_result(
      sockRef,
      bin,
      handle,
      deadline,
      hasWritten,
      :sendto,
      &sendto_deadline_cont/5,
      :prim_socket.sendto(sockRef, bin, to, flags, handle)
    )
  end

  defp sendto_deadline_cont(sockRef, bin, cont, deadline, hasWritten) do
    handle = make_ref()

    send_common_deadline_result(
      sockRef,
      bin,
      handle,
      deadline,
      hasWritten,
      :sendto,
      &sendto_deadline_cont/5,
      :prim_socket.sendto(sockRef, bin, cont, handle)
    )
  end

  def sendmsg(socket, msg) do
    sendmsg(socket, msg, [], :infinity)
  end

  def sendmsg(socket, data, flags_Cont)
      when is_list(flags_Cont) or is_tuple(flags_Cont) do
    sendmsg(socket, data, flags_Cont, :infinity)
  end

  def sendmsg(socket, msg, timeout) do
    sendmsg(socket, msg, [], timeout)
  end

  def sendmsg(
        {:"$socket", sockRef} = socket,
        restData,
        {:select_info, selectTag, _} = cont,
        timeout
      ) do
    case selectTag do
      {:sendmsg, contData} ->
        case restData do
          %{iov: iOV} ->
            sendmsg_timeout_cont(sockRef, iOV, contData, timeout)

          iOV when is_list(iOV) ->
            sendmsg_timeout_cont(sockRef, iOV, contData, timeout)

          _ ->
            :erlang.error(
              :badarg,
              [socket, restData, cont, timeout]
            )
        end

      _ ->
        {:error, {:invalid, cont}}
    end
  end

  def sendmsg({:"$socket", sockRef}, %{iov: iOV} = msg, flags, timeout)
      when is_reference(sockRef) and is_list(flags) do
    case deadline(timeout) do
      :invalid ->
        :erlang.error({:invalid, {:timeout, timeout}})

      :nowait ->
        handle = make_ref()
        sendmsg_nowait(sockRef, msg, flags, handle, iOV)

      :handle ->
        handle = timeout
        sendmsg_nowait(sockRef, msg, flags, handle, iOV)

      deadline ->
        hasWritten = false
        sendmsg_deadline(sockRef, msg, flags, deadline, hasWritten, iOV)
    end
  end

  def sendmsg(socket, msg, flags, timeout) do
    :erlang.error(:badarg, [socket, msg, flags, timeout])
  end

  defp sendmsg_timeout_cont(sockRef, restData, cont, timeout) do
    case deadline(timeout) do
      :invalid ->
        :erlang.error({:invalid, {:timeout, timeout}})

      :nowait ->
        selectHandle = make_ref()
        sendmsg_nowait_cont(sockRef, restData, cont, selectHandle)

      :handle ->
        selectHandle = timeout
        sendmsg_nowait_cont(sockRef, restData, cont, selectHandle)

      deadline ->
        hasWritten = false
        sendmsg_deadline_cont(sockRef, restData, cont, deadline, hasWritten)
    end
  end

  defp sendmsg_nowait(sockRef, msg, flags, handle, iOV) do
    send_common_nowait_result(
      handle,
      :sendmsg,
      :prim_socket.sendmsg(sockRef, msg, flags, handle, iOV)
    )
  end

  defp sendmsg_nowait_cont(sockRef, restData, cont, selectHandle) do
    send_common_nowait_result(
      selectHandle,
      :sendmsg,
      :prim_socket.sendmsg(sockRef, restData, cont, selectHandle)
    )
  end

  defp sendmsg_deadline(sockRef, msg, flags, deadline, hasWritten, iOV) do
    handle = make_ref()

    send_common_deadline_result(
      sockRef,
      iOV,
      handle,
      deadline,
      hasWritten,
      :sendmsg,
      &sendmsg_deadline_cont/5,
      :prim_socket.sendmsg(sockRef, msg, flags, handle, iOV)
    )
  end

  defp sendmsg_deadline_cont(sockRef, data, cont, deadline, hasWritten) do
    selectHandle = make_ref()

    send_common_deadline_result(
      sockRef,
      data,
      selectHandle,
      deadline,
      hasWritten,
      :sendmsg,
      &sendmsg_deadline_cont/5,
      :prim_socket.sendmsg(sockRef, data, cont, selectHandle)
    )
  end

  def sendfile(socket, fileHandle) do
    sendfile(socket, fileHandle, 0, 0, :infinity)
  end

  def sendfile(socket, fileHandle, timeout) do
    sendfile(socket, fileHandle, 0, 0, timeout)
  end

  def sendfile(socket, fileHandle_Cont, offset, count) do
    sendfile(socket, fileHandle_Cont, offset, count, :infinity)
  end

  def sendfile({:"$socket", sockRef} = socket, fileHandle_Cont, offset, count, timeout)
      when is_integer(offset) and is_integer(count) and
             0 <= count do
    case fileHandle_Cont do
      r_file_descriptor(module: module) = fileHandle ->
        getFRef = :internal_get_nif_resource

        try do
          apply(module, getFRef, [fileHandle])
        catch
          class, reason
          when class === :error and
                 reason === :undef ->
            case __STACKTRACE__ do
              [{^module, ^getFRef, args, _} | _]
              when args === 1 or
                     tl(args) === [] ->
                :erlang.error(
                  :badarg,
                  [socket, fileHandle_Cont, offset, count, timeout]
                )

              _ ->
                :erlang.raise(class, reason, __STACKTRACE__)
            end
        else
          fRef ->
            state = {fRef, offset, count}
            sendfile_int(sockRef, state, timeout)
        end

      {:select_info, selectTag, _} = cont ->
        case selectTag do
          {:sendfile, fRef} ->
            state = {fRef, offset, count}
            sendfile_int(sockRef, state, timeout)

          :sendfile ->
            state = {offset, count}
            sendfile_int(sockRef, state, timeout)

          _ ->
            {:error, {:invalid, cont}}
        end

      _ ->
        :erlang.error(
          :badarg,
          [socket, fileHandle_Cont, offset, count, timeout]
        )
    end
  end

  def sendfile(socket, fileHandle_Cont, offset, count, timeout) do
    :erlang.error(
      :badarg,
      [socket, fileHandle_Cont, offset, count, timeout]
    )
  end

  defp sendfile_int(sockRef, state, timeout) do
    case deadline(timeout) do
      :invalid ->
        :erlang.error({:invalid, {:timeout, timeout}})

      :nowait ->
        selectHandle = make_ref()
        sendfile_nowait(sockRef, state, selectHandle)

      :handle ->
        selectHandle = timeout
        sendfile_nowait(sockRef, state, selectHandle)

      deadline ->
        bytesSent = 0
        sendfile_deadline(sockRef, state, bytesSent, deadline)
    end
  end

  defp prim_socket_sendfile(sockRef, {fRef, offset, count}, selectHandle) do
    :prim_socket.sendfile(sockRef, fRef, offset, count, selectHandle)
  end

  defp prim_socket_sendfile(sockRef, {offset, count}, selectHandle) do
    :prim_socket.sendfile(sockRef, offset, count, selectHandle)
  end

  defp sendfile_nowait(sockRef, state, selectHandle) do
    case prim_socket_sendfile(sockRef, state, selectHandle) do
      :select ->
        {fRef, _Offset, _Count} = state
        {:select, {:select_info, {:sendfile, fRef}, selectHandle}}

      {:select, bytesSent} ->
        {:select, {{:select_info, :sendfile, selectHandle}, bytesSent}}

      result ->
        result
    end
  end

  defp sendfile_deadline(sockRef, state, bytesSent_0, deadline) do
    selectHandle = make_ref()

    case prim_socket_sendfile(sockRef, state, selectHandle) do
      :select ->
        timeout = timeout(deadline)

        receive do
          {:"$socket", _Socket, :select, ^selectHandle} ->
            sendfile_deadline(sockRef, state, bytesSent_0, deadline)

          {:"$socket", _Socket, :abort, {^selectHandle, reason}} ->
            {:error, reason}
        after
          timeout ->
            _ = cancel(sockRef, :sendfile, selectHandle)
            {:error, :timeout}
        end

      {:select, bytesSent} ->
        timeout = timeout(deadline)
        bytesSent_1 = bytesSent_0 + bytesSent

        receive do
          {:"$socket", _Socket, :select, ^selectHandle} ->
            sendfile_deadline(sockRef, sendfile_next(bytesSent, state), bytesSent_1, deadline)

          {:"$socket", _Socket, :abort, {^selectHandle, reason}} ->
            {:error, {reason, bytesSent_1}}
        after
          timeout ->
            _ = cancel(sockRef, :sendfile, selectHandle)
            {:error, {:timeout, bytesSent_1}}
        end

      {:error, _} = result when tuple_size(state) === 3 ->
        result

      {:error, reason} when tuple_size(state) === 2 ->
        {:error, {reason, bytesSent_0}}

      {:ok, bytesSent} ->
        {:ok, bytesSent_0 + bytesSent}
    end
  end

  defp sendfile_next(bytesSent, {_FRef, offset, count}) do
    sendfile_next(bytesSent, offset, count)
  end

  defp sendfile_next(bytesSent, {offset, count}) do
    sendfile_next(bytesSent, offset, count)
  end

  defp sendfile_next(bytesSent, offset, count) do
    {offset + bytesSent,
     cond do
       count === 0 ->
         0

       bytesSent < count ->
         count - bytesSent
     end}
  end

  def recv(socket) do
    recv(socket, 0, [], :infinity)
  end

  def recv(socket, flags) when is_list(flags) do
    recv(socket, 0, flags, :infinity)
  end

  def recv(socket, length)
      when is_integer(length) and length >= 0 do
    recv(socket, length, [], :infinity)
  end

  def recv(socket, flags, timeout) when is_list(flags) do
    recv(socket, 0, flags, timeout)
  end

  def recv(socket, length, flags) when is_list(flags) do
    recv(socket, length, flags, :infinity)
  end

  def recv(socket, length, timeout) do
    recv(socket, length, [], timeout)
  end

  def recv({:"$socket", sockRef}, length, flags, timeout)
      when is_reference(sockRef) and is_integer(length) and
             length >= 0 and is_list(flags) do
    case deadline(timeout) do
      :invalid ->
        :erlang.error({:invalid, {:timeout, timeout}})

      :nowait ->
        handle = make_ref()
        recv_nowait(sockRef, length, flags, handle, <<>>)

      :handle ->
        handle = timeout
        recv_nowait(sockRef, length, flags, handle, <<>>)

      :zero ->
        case :prim_socket.recv(sockRef, length, flags, :zero) do
          :ok ->
            {:error, :timeout}

          result ->
            result
        end

      deadline ->
        recv_deadline(sockRef, length, flags, deadline, <<>>)
    end
  end

  def recv(socket, length, flags, timeout) do
    :erlang.error(:badarg, [socket, length, flags, timeout])
  end

  defp recv_nowait(sockRef, length, flags, handle, acc) do
    case :prim_socket.recv(sockRef, length, flags, handle) do
      {:more, bin} ->
        {:ok, bincat(acc, bin)}

      {:select, bin} ->
        {:select, {{:select_info, :recv, handle}, bincat(acc, bin)}}

      :select ->
        cond do
          byte_size(acc) === 0 ->
            {:select, {:select_info, :recv, handle}}

          true ->
            {:select, {{:select_info, :recv, handle}, acc}}
        end

      :completion ->
        {:completion, {:completion_info, :recv, handle}}

      result ->
        recv_result(acc, result)
    end
  end

  defp recv_deadline(sockRef, length, flags, deadline, acc) do
    handle = make_ref()

    case :prim_socket.recv(sockRef, length, flags, handle) do
      {:more, bin} ->
        timeout = timeout(deadline)

        cond do
          0 < timeout ->
            recv_deadline(sockRef, length, flags, deadline, bincat(acc, bin))

          true ->
            {:ok, bincat(acc, bin)}
        end

      {:select, bin} ->
        timeout = timeout(deadline)

        receive do
          {:"$socket", {:"$socket", ^sockRef}, :select, ^handle} ->
            cond do
              0 < timeout ->
                recv_deadline(sockRef, length - byte_size(bin), flags, deadline, bincat(acc, bin))

              true ->
                {:error, {:timeout, bincat(acc, bin)}}
            end

          {:"$socket", _Socket, :abort, {^handle, reason}} ->
            {:error, {reason, bincat(acc, bin)}}
        after
          timeout ->
            _ = cancel(sockRef, :recv, handle)
            {:error, {:timeout, bincat(acc, bin)}}
        end

      :select when length === 0 and 0 < byte_size(acc) ->
        _ = cancel(sockRef, :recv, handle)
        {:ok, acc}

      :select ->
        timeout = timeout(deadline)

        receive do
          {:"$socket", {:"$socket", ^sockRef}, :select, ^handle} ->
            cond do
              0 < timeout ->
                recv_deadline(sockRef, length, flags, deadline, acc)

              true ->
                recv_error(acc, :timeout)
            end

          {:"$socket", _Socket, :abort, {^handle, reason}} ->
            recv_error(acc, reason)
        after
          timeout ->
            _ = cancel(sockRef, :recv, handle)
            recv_error(acc, :timeout)
        end

      :completion ->
        timeout = timeout(deadline)

        receive do
          {:"$socket", {:"$socket", ^sockRef}, :completion, {^handle, {:ok, _Bin} = oK}}
          when length === 0 ->
            recv_result(acc, oK)

          {:"$socket", {:"$socket", ^sockRef}, :completion, {^handle, {:ok, bin} = oK}}
          when length === byte_size(bin) ->
            recv_result(acc, oK)

          {:"$socket", {:"$socket", ^sockRef}, :completion, {^handle, {:ok, bin}}} ->
            cond do
              0 < timeout ->
                recv_deadline(sockRef, length - byte_size(bin), flags, deadline, bincat(acc, bin))

              true ->
                {:error, {:timeout, bincat(acc, bin)}}
            end

          {:"$socket", {:"$socket", ^sockRef}, :completion, {^handle, {:error, reason}}} ->
            recv_error(acc, reason)

          {:"$socket", _Socket, :abort, {^handle, reason}} ->
            recv_error(acc, reason)
        after
          timeout ->
            _ = cancel(sockRef, :recv, handle)
            recv_error(acc, :timeout)
        end

      {:ok, bin} when length > byte_size(bin) ->
        timeout = timeout(deadline)

        cond do
          0 < timeout ->
            recv_deadline(sockRef, length - byte_size(bin), flags, deadline, bincat(acc, bin))

          true ->
            {:error, {:timeout, bincat(acc, bin)}}
        end

      result ->
        recv_result(acc, result)
    end
  end

  defp recv_result(acc, result) do
    case result do
      {:ok, bin} ->
        {:ok, bincat(acc, bin)}

      {:error, _} = eRROR when byte_size(acc) === 0 ->
        eRROR

      {:error, reason} ->
        {:error, {reason, acc}}
    end
  end

  defp recv_error(acc, reason) do
    cond do
      byte_size(acc) === 0 ->
        {:error, reason}

      true ->
        {:error, {reason, acc}}
    end
  end

  def recvfrom(socket) do
    recvfrom(socket, 0)
  end

  def recvfrom(socket, flags) when is_list(flags) do
    recvfrom(socket, 0, flags, :infinity)
  end

  def recvfrom(socket, bufSz) do
    recvfrom(socket, bufSz, [], :infinity)
  end

  def recvfrom(socket, flags, timeout) when is_list(flags) do
    recvfrom(socket, 0, flags, timeout)
  end

  def recvfrom(socket, bufSz, flags) when is_list(flags) do
    recvfrom(socket, bufSz, flags, :infinity)
  end

  def recvfrom(socket, bufSz, timeout) do
    recvfrom(socket, bufSz, [], timeout)
  end

  def recvfrom({:"$socket", sockRef}, bufSz, flags, timeout)
      when is_reference(sockRef) and is_integer(bufSz) and
             0 <= bufSz and is_list(flags) do
    case deadline(timeout) do
      :invalid ->
        :erlang.error({:invalid, {:timeout, timeout}})

      :nowait ->
        handle = make_ref()
        recvfrom_nowait(sockRef, bufSz, handle, flags)

      :handle ->
        handle = timeout
        recvfrom_nowait(sockRef, bufSz, handle, flags)

      :zero ->
        case :prim_socket.recvfrom(sockRef, bufSz, flags, :zero) do
          :ok ->
            {:error, :timeout}

          result ->
            recvfrom_result(result)
        end

      deadline ->
        recvfrom_deadline(sockRef, bufSz, flags, deadline)
    end
  end

  def recvfrom(socket, bufSz, flags, timeout) do
    :erlang.error(:badarg, [socket, bufSz, flags, timeout])
  end

  defp recvfrom_nowait(sockRef, bufSz, handle, flags) do
    case :prim_socket.recvfrom(sockRef, bufSz, flags, handle) do
      :select = tag ->
        {tag, {:select_info, :recvfrom, handle}}

      :completion = tag ->
        {tag, {:completion_info, :recvfrom, handle}}

      result ->
        recvfrom_result(result)
    end
  end

  defp recvfrom_deadline(sockRef, bufSz, flags, deadline) do
    handle = make_ref()

    case :prim_socket.recvfrom(sockRef, bufSz, flags, handle) do
      :select ->
        timeout = timeout(deadline)

        receive do
          {:"$socket", {:"$socket", ^sockRef}, :select, ^handle} ->
            recvfrom_deadline(sockRef, bufSz, flags, deadline)

          {:"$socket", _Socket, :abort, {^handle, reason}} ->
            {:error, reason}
        after
          timeout ->
            _ = cancel(sockRef, :recvfrom, handle)
            {:error, :timeout}
        end

      :completion ->
        timeout = timeout(deadline)

        receive do
          {:"$socket", {:"$socket", ^sockRef}, :completion, {^handle, completionStatus}} ->
            recvfrom_result(completionStatus)

          {:"$socket", _Socket, :abort, {^handle, reason}} ->
            {:error, reason}
        after
          timeout ->
            _ = cancel(sockRef, :recvfrom, handle)
            {:error, :timeout}
        end

      result ->
        recvfrom_result(result)
    end
  end

  defp recvfrom_result(result) do
    case result do
      {:ok, {_Source, _NewData}} = oK ->
        oK

      {:error, _Reason} = eRROR ->
        eRROR
    end
  end

  def recvmsg(socket) do
    recvmsg(socket, 0, 0, [], :infinity)
  end

  def recvmsg(socket, flags) when is_list(flags) do
    recvmsg(socket, 0, 0, flags, :infinity)
  end

  def recvmsg(socket, timeout) do
    recvmsg(socket, 0, 0, [], timeout)
  end

  def recvmsg(socket, bufSz, ctrlSz, timeout) do
    recvmsg(socket, bufSz, ctrlSz, [], timeout)
  end

  def recvmsg(socket, flags, timeout) when is_list(flags) do
    recvmsg(socket, 0, 0, flags, timeout)
  end

  def recvmsg(socket, bufSz, ctrlSz)
      when is_integer(bufSz) and is_integer(ctrlSz) do
    recvmsg(socket, bufSz, ctrlSz, [], :infinity)
  end

  def recvmsg({:"$socket", sockRef}, bufSz, ctrlSz, flags, timeout)
      when is_reference(sockRef) and is_integer(bufSz) and
             0 <= bufSz and is_integer(ctrlSz) and 0 <= ctrlSz and
             is_list(flags) do
    case deadline(timeout) do
      :invalid ->
        :erlang.error({:invalid, {:timeout, timeout}})

      :nowait ->
        handle = make_ref()
        recvmsg_nowait(sockRef, bufSz, ctrlSz, flags, handle)

      :handle ->
        handle = timeout
        recvmsg_nowait(sockRef, bufSz, ctrlSz, flags, handle)

      :zero ->
        case :prim_socket.recvmsg(sockRef, bufSz, ctrlSz, flags, :zero) do
          :ok ->
            {:error, :timeout}

          result ->
            recvmsg_result(result)
        end

      deadline ->
        recvmsg_deadline(sockRef, bufSz, ctrlSz, flags, deadline)
    end
  end

  def recvmsg(socket, bufSz, ctrlSz, flags, timeout) do
    :erlang.error(
      :badarg,
      [socket, bufSz, ctrlSz, flags, timeout]
    )
  end

  defp recvmsg_nowait(sockRef, bufSz, ctrlSz, flags, handle) do
    case :prim_socket.recvmsg(sockRef, bufSz, ctrlSz, flags, handle) do
      :select ->
        {:select, {:select_info, :recvmsg, handle}}

      :completion ->
        {:completion, {:completion_info, :recvmsg, handle}}

      result ->
        recvmsg_result(result)
    end
  end

  defp recvmsg_deadline(sockRef, bufSz, ctrlSz, flags, deadline) do
    handle = make_ref()

    case :prim_socket.recvmsg(sockRef, bufSz, ctrlSz, flags, handle) do
      :select ->
        timeout = timeout(deadline)

        receive do
          {:"$socket", {:"$socket", ^sockRef}, :select, ^handle} ->
            recvmsg_deadline(sockRef, bufSz, ctrlSz, flags, deadline)

          {:"$socket", _Socket, :abort, {^handle, reason}} ->
            {:error, reason}
        after
          timeout ->
            _ = cancel(sockRef, :recvmsg, handle)
            {:error, :timeout}
        end

      :completion ->
        timeout = timeout(deadline)

        receive do
          {:"$socket", {:"$socket", ^sockRef}, :completion, {^handle, completionStatus}} ->
            recvmsg_result(completionStatus)

          {:"$socket", _Socket, :abort, {^handle, reason}} ->
            {:error, reason}
        after
          timeout ->
            _ = cancel(sockRef, :recvmsg, handle)
            {:error, :timeout}
        end

      result ->
        recvmsg_result(result)
    end
  end

  defp recvmsg_result(result) do
    case result do
      {:ok, _Msg} = oK ->
        oK

      {:error, _Reason} = eRROR ->
        eRROR
    end
  end

  def close({:"$socket", sockRef}) when is_reference(sockRef) do
    case :prim_socket.close(sockRef) do
      :ok ->
        :prim_socket.finalize_close(sockRef)

      {:ok, closeRef} ->
        receive do
          {:"$socket", {:"$socket", ^sockRef}, :close, ^closeRef} ->
            :prim_socket.finalize_close(sockRef)
        end

      {:error, _} = eRROR ->
        eRROR
    end
  end

  def close(socket) do
    :erlang.error(:badarg, [socket])
  end

  def shutdown({:"$socket", sockRef}, how) when is_reference(sockRef) do
    :prim_socket.shutdown(sockRef, how)
  end

  def shutdown(socket, how) do
    :erlang.error(:badarg, [socket, how])
  end

  def setopt({:"$socket", sockRef}, socketOption, value)
      when is_reference(sockRef) do
    :prim_socket.setopt(sockRef, socketOption, value)
  end

  def setopt(socket, socketOption, value) do
    :erlang.error(:badarg, [socket, socketOption, value])
  end

  def setopt(socket, level, opt, value)
      when is_integer(opt) and is_binary(value) do
    setopt_native(socket, {level, opt}, value)
  end

  def setopt(socket, level, opt, value) do
    setopt(socket, {level, opt}, value)
  end

  def setopt_native({:"$socket", sockRef}, socketOption, value)
      when is_reference(sockRef) do
    :prim_socket.setopt_native(sockRef, socketOption, value)
  end

  def setopt_native(socket, socketOption, value) do
    :erlang.error(:badarg, [socket, socketOption, value])
  end

  def getopt({:"$socket", sockRef}, socketOption)
      when is_reference(sockRef) do
    :prim_socket.getopt(sockRef, socketOption)
  end

  def getopt(socket, level, {nativeOpt, valueSpec})
      when is_integer(nativeOpt) do
    getopt_native(socket, {level, nativeOpt}, valueSpec)
  end

  def getopt(socket, level, opt) do
    getopt(socket, {level, opt})
  end

  def getopt_native({:"$socket", sockRef}, socketOption, valueSpec) do
    :prim_socket.getopt_native(sockRef, socketOption, valueSpec)
  end

  def sockname({:"$socket", sockRef}) when is_reference(sockRef) do
    :prim_socket.sockname(sockRef)
  end

  def sockname(socket) do
    :erlang.error(:badarg, [socket])
  end

  def peername({:"$socket", sockRef}) when is_reference(sockRef) do
    :prim_socket.peername(sockRef)
  end

  def peername(socket) do
    :erlang.error(:badarg, [socket])
  end

  def ioctl({:"$socket", sockRef}, :gifconf = getRequest) do
    :prim_socket.ioctl(sockRef, getRequest)
  end

  def ioctl({:"$socket", sockRef}, getRequest)
      when :nread === getRequest or :nwrite === getRequest or :nspace === getRequest do
    :prim_socket.ioctl(sockRef, getRequest)
  end

  def ioctl({:"$socket", sockRef}, getRequest)
      when :atmark === getRequest do
    :prim_socket.ioctl(sockRef, getRequest)
  end

  def ioctl(socket, getRequest)
      when :tcp_info === getRequest do
    ioctl(socket, getRequest, 0)
  end

  def ioctl(socket, getRequest) do
    :erlang.error(:badarg, [socket, getRequest])
  end

  def ioctl({:"$socket", sockRef}, :gifname = getRequest, index)
      when is_integer(index) do
    :prim_socket.ioctl(sockRef, getRequest, index)
  end

  def ioctl({:"$socket", sockRef}, :gifindex = getRequest, name)
      when is_list(name) do
    :prim_socket.ioctl(sockRef, getRequest, name)
  end

  def ioctl({:"$socket", sockRef}, :gifaddr = getRequest, name)
      when is_list(name) do
    :prim_socket.ioctl(sockRef, getRequest, name)
  end

  def ioctl({:"$socket", sockRef}, :gifdstaddr = getRequest, name)
      when is_list(name) do
    :prim_socket.ioctl(sockRef, getRequest, name)
  end

  def ioctl({:"$socket", sockRef}, :gifbrdaddr = getRequest, name)
      when is_list(name) do
    :prim_socket.ioctl(sockRef, getRequest, name)
  end

  def ioctl({:"$socket", sockRef}, :gifnetmask = getRequest, name)
      when is_list(name) do
    :prim_socket.ioctl(sockRef, getRequest, name)
  end

  def ioctl({:"$socket", sockRef}, :gifmtu = getRequest, name)
      when is_list(name) do
    :prim_socket.ioctl(sockRef, getRequest, name)
  end

  def ioctl({:"$socket", sockRef}, :gifhwaddr = getRequest, name)
      when is_list(name) do
    :prim_socket.ioctl(sockRef, getRequest, name)
  end

  def ioctl({:"$socket", sockRef}, :giftxqlen = getRequest, name)
      when is_list(name) do
    :prim_socket.ioctl(sockRef, getRequest, name)
  end

  def ioctl({:"$socket", sockRef}, :gifflags = getRequest, name)
      when is_list(name) do
    :prim_socket.ioctl(sockRef, getRequest, name)
  end

  def ioctl({:"$socket", sockRef}, :gifmap = getRequest, name)
      when is_list(name) do
    :prim_socket.ioctl(sockRef, getRequest, name)
  end

  def ioctl({:"$socket", sockRef}, :tcp_info = getRequest, version)
      when version === 0 do
    :prim_socket.ioctl(sockRef, getRequest, version)
  end

  def ioctl({:"$socket", sockRef}, :rcvall = setRequest, value)
      when value === :off or value === :on or value === :iplevel do
    :prim_socket.ioctl(sockRef, setRequest, value)
  end

  def ioctl({:"$socket", sockRef}, setRequest, value)
      when (setRequest === :rcvall_igmpmcast or setRequest === :rcvall_mcast) and
             (value === :off or value === :on) do
    :prim_socket.ioctl(sockRef, setRequest, value)
  end

  def ioctl(socket, request, arg) do
    :erlang.error(:badarg, [socket, request, arg])
  end

  def ioctl({:"$socket", sockRef}, :sifflags = setRequest, name, flags)
      when is_list(name) and is_map(flags) do
    :prim_socket.ioctl(sockRef, setRequest, name, flags)
  end

  def ioctl({:"$socket", sockRef}, :sifaddr = setRequest, name, addr)
      when is_list(name) and is_map(addr) do
    :prim_socket.ioctl(sockRef, setRequest, name, :prim_socket.enc_sockaddr(addr))
  end

  def ioctl({:"$socket", sockRef}, :sifdstaddr = setRequest, name, dstAddr)
      when is_list(name) and is_map(dstAddr) do
    :prim_socket.ioctl(sockRef, setRequest, name, :prim_socket.enc_sockaddr(dstAddr))
  end

  def ioctl({:"$socket", sockRef}, :sifbrdaddr = setRequest, name, brdAddr)
      when is_list(name) and is_map(brdAddr) do
    :prim_socket.ioctl(sockRef, setRequest, name, :prim_socket.enc_sockaddr(brdAddr))
  end

  def ioctl({:"$socket", sockRef}, :sifnetmask = setRequest, name, netMask)
      when is_list(name) and is_map(netMask) do
    :prim_socket.ioctl(sockRef, setRequest, name, :prim_socket.enc_sockaddr(netMask))
  end

  def ioctl({:"$socket", sockRef}, :sifmtu = setRequest, name, mTU)
      when is_list(name) and is_integer(mTU) do
    :prim_socket.ioctl(sockRef, setRequest, name, mTU)
  end

  def ioctl({:"$socket", sockRef}, :siftxqlen = setRequest, name, qLen)
      when is_list(name) and is_integer(qLen) do
    :prim_socket.ioctl(sockRef, setRequest, name, qLen)
  end

  def ioctl(socket, setRequest, arg1, arg2) do
    :erlang.error(:badarg, [socket, setRequest, arg1, arg2])
  end

  def cancel(
        {:"$socket", sockRef},
        {:select_info, selectTag, selectHandle} = selectInfo
      )
      when is_reference(sockRef) do
    case selectTag do
      {op, _} when is_atom(op) ->
        :ok

      op when is_atom(op) ->
        :ok
    end

    case cancel(sockRef, op, selectHandle) do
      :ok ->
        :ok

      :invalid ->
        {:error, {:invalid, selectInfo}}

      result ->
        result
    end
  end

  def cancel(
        {:"$socket", sockRef},
        {:completion_info, completionTag, completionHandle} = completionInfo
      )
      when is_reference(sockRef) do
    case completionTag do
      {op, _} when is_atom(op) ->
        :ok

      op when is_atom(op) ->
        :ok
    end

    case cancel(sockRef, op, completionHandle) do
      :ok ->
        :ok

      :invalid ->
        {:error, {:invalid, completionInfo}}

      result ->
        result
    end
  end

  def cancel(socket, info) do
    :erlang.error(:badarg, [socket, info])
  end

  defp cancel(sockRef, op, handle) do
    case :prim_socket.cancel(sockRef, op, handle) do
      :select_sent ->
        _ = flush_select_msg(sockRef, handle)
        _ = flush_abort_msg(sockRef, handle)
        :ok

      :not_found ->
        _ = flush_completion_msg(sockRef, handle)
        _ = flush_abort_msg(sockRef, handle)
        :invalid

      result ->
        _ = flush_select_msg(sockRef, handle)
        _ = flush_completion_msg(sockRef, handle)
        _ = flush_abort_msg(sockRef, handle)
        result
    end
  end

  defp flush_select_msg(sockRef, ref) do
    receive do
      {:"$socket", {:"$socket", ^sockRef}, :select, ^ref} ->
        :ok
    after
      0 ->
        :ok
    end
  end

  defp flush_completion_msg(sockRef, ref) do
    receive do
      {:"$socket", {:"$socket", ^sockRef}, :completion, {^ref, result}} ->
        result
    after
      0 ->
        :ok
    end
  end

  defp flush_abort_msg(sockRef, ref) do
    receive do
      {:"$socket", {:"$socket", ^sockRef}, :abort, {^ref, reason}} ->
        reason
    after
      0 ->
        :ok
    end
  end

  defp deadline(timeout) do
    case timeout do
      :nowait ->
        timeout

      :infinity ->
        timeout

      handle when is_reference(handle) ->
        :handle

      0 ->
        :zero

      _ when is_integer(timeout) and 0 < timeout ->
        timestamp() + timeout

      _ ->
        :invalid
    end
  end

  defp timeout(deadline) do
    case deadline do
      :infinity ->
        deadline

      :zero ->
        0

      _ ->
        now = timestamp()

        cond do
          deadline > now ->
            deadline - now

          true ->
            0
        end
    end
  end

  defp timestamp() do
    :erlang.monotonic_time(:milli_seconds)
  end

  defp bincat(<<>>, <<_::binary>> = b) do
    b
  end

  defp bincat(<<_::binary>> = a, <<>>) do
    a
  end

  defp bincat(<<_::binary>> = a, <<_::binary>> = b) do
    <<a::binary, b::binary>>
  end

  defp f(f, a) do
    :lists.flatten(:io_lib.format(f, a))
  end
end
