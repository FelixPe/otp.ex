defmodule :m_gen_sctp do
  use Bitwise
  require Record

  Record.defrecord(:r_sctp_initmsg, :sctp_initmsg,
    num_ostreams: :undefined,
    max_instreams: :undefined,
    max_attempts: :undefined,
    max_init_timeo: :undefined
  )

  Record.defrecord(:r_sctp_sndrcvinfo, :sctp_sndrcvinfo,
    stream: :undefined,
    ssn: :undefined,
    flags: :undefined,
    ppid: :undefined,
    context: :undefined,
    timetolive: :undefined,
    tsn: :undefined,
    cumtsn: :undefined,
    assoc_id: :undefined
  )

  Record.defrecord(:r_sctp_assoc_change, :sctp_assoc_change,
    state: :cant_assoc,
    error: 0,
    outbound_streams: 0,
    inbound_streams: 0,
    assoc_id: 0
  )

  Record.defrecord(:r_sctp_paddr_change, :sctp_paddr_change,
    addr: [0, 0, 0, 0],
    state: :addr_available,
    error: 0,
    assoc_id: 0
  )

  Record.defrecord(:r_sctp_remote_error, :sctp_remote_error, error: 0, assoc_id: 0, data: [])

  Record.defrecord(:r_sctp_send_failed, :sctp_send_failed,
    flags: false,
    error: 0,
    info: :EFE_TODO_NESTED_RECORD,
    assoc_id: 0,
    data: <<>>
  )

  Record.defrecord(:r_sctp_shutdown_event, :sctp_shutdown_event, assoc_id: 0)

  Record.defrecord(:r_sctp_adaptation_event, :sctp_adaptation_event,
    adaptation_ind: 0,
    assoc_id: 0
  )

  Record.defrecord(:r_sctp_pdapi_event, :sctp_pdapi_event,
    indication: :partial_delivery_aborted,
    assoc_id: 0
  )

  Record.defrecord(:r_sctp_rtoinfo, :sctp_rtoinfo,
    assoc_id: :undefined,
    initial: :undefined,
    max: :undefined,
    min: :undefined
  )

  Record.defrecord(:r_sctp_assocparams, :sctp_assocparams,
    assoc_id: :undefined,
    asocmaxrxt: :undefined,
    number_peer_destinations: :undefined,
    peer_rwnd: :undefined,
    local_rwnd: :undefined,
    cookie_life: :undefined
  )

  Record.defrecord(:r_sctp_prim, :sctp_prim,
    assoc_id: :undefined,
    addr: :undefined
  )

  Record.defrecord(:r_sctp_setpeerprim, :sctp_setpeerprim,
    assoc_id: :undefined,
    addr: :undefined
  )

  Record.defrecord(:r_sctp_setadaptation, :sctp_setadaptation, adaptation_ind: :undefined)

  Record.defrecord(:r_sctp_paddrparams, :sctp_paddrparams,
    assoc_id: :undefined,
    address: :undefined,
    hbinterval: :undefined,
    pathmaxrxt: :undefined,
    pathmtu: :undefined,
    sackdelay: :undefined,
    flags: :undefined
  )

  Record.defrecord(:r_sctp_event_subscribe, :sctp_event_subscribe,
    data_io_event: :undefined,
    association_event: :undefined,
    address_event: :undefined,
    send_failure_event: :undefined,
    peer_error_event: :undefined,
    shutdown_event: :undefined,
    partial_delivery_event: :undefined,
    adaptation_layer_event: :undefined,
    authentication_event: :undefined
  )

  Record.defrecord(:r_sctp_assoc_value, :sctp_assoc_value,
    assoc_id: :undefined,
    assoc_value: :undefined
  )

  Record.defrecord(:r_sctp_paddrinfo, :sctp_paddrinfo,
    assoc_id: :undefined,
    address: :undefined,
    state: :undefined,
    cwnd: :undefined,
    srtt: :undefined,
    rto: :undefined,
    mtu: :undefined
  )

  Record.defrecord(:r_sctp_status, :sctp_status,
    assoc_id: :undefined,
    state: :undefined,
    rwnd: :undefined,
    unackdata: :undefined,
    penddata: :undefined,
    instrms: :undefined,
    outstrms: :undefined,
    fragmentation_point: :undefined,
    primary: :undefined
  )

  def open() do
    open([])
  end

  def open(opts0) when is_list(opts0) do
    {mod, opts} = :inet.sctp_module(opts0)

    case mod.open(opts) do
      {:error, :badarg} ->
        :erlang.error(:badarg, [opts])

      {:error, :einval} ->
        :erlang.error(:badarg, [opts])

      result ->
        result
    end
  end

  def open(port) when is_integer(port) do
    open([{:port, port}])
  end

  def open(x) do
    :erlang.error(:badarg, [x])
  end

  def open(port, opts)
      when is_integer(port) and
             is_list(opts) do
    open([{:port, port} | opts])
  end

  def open(port, opts) do
    :erlang.error(:badarg, [port, opts])
  end

  def close(s) when is_port(s) do
    case :inet_db.lookup_socket(s) do
      {:ok, mod} ->
        mod.close(s)

      {:error, :closed} ->
        :ok
    end
  end

  def close(s) do
    :erlang.error(:badarg, [s])
  end

  def listen(s, backlog)
      when (is_port(s) and
              is_boolean(backlog)) or
             (is_port(s) and is_integer(backlog)) do
    case :inet_db.lookup_socket(s) do
      {:ok, mod} ->
        mod.listen(s, backlog)

      error ->
        error
    end
  end

  def listen(s, flag) do
    :erlang.error(:badarg, [s, flag])
  end

  def peeloff(s, r_sctp_assoc_change(assoc_id: assocId)) when is_port(s) do
    peeloff(s, assocId)
  end

  def peeloff(s, assocId)
      when is_port(s) and
             is_integer(assocId) do
    case :inet_db.lookup_socket(s) do
      {:ok, mod} ->
        mod.peeloff(s, assocId)

      error ->
        error
    end
  end

  def connect(s, sockAddr, opts) do
    connect(s, sockAddr, opts, :infinity)
  end

  def connect(s, sockAddr, opts, timeout)
      when is_map(sockAddr) and is_list(opts) do
    case do_connect(s, sockAddr, opts, timeout, true) do
      :badarg ->
        :erlang.error(:badarg, [s, sockAddr, opts, timeout])

      result ->
        result
    end
  end

  def connect(s, addr, port, opts) do
    connect(s, addr, port, opts, :infinity)
  end

  def connect(s, addr, port, opts, timeout) do
    case do_connect(s, addr, port, opts, timeout, true) do
      :badarg ->
        :erlang.error(:badarg, [s, addr, port, opts, timeout])

      result ->
        result
    end
  end

  def connect_init(s, sockAddr, opts) do
    connect_init(s, sockAddr, opts, :infinity)
  end

  def connect_init(s, sockAddr, opts, timeout)
      when is_map(sockAddr) and is_list(opts) do
    case do_connect(s, sockAddr, opts, timeout, false) do
      :badarg ->
        :erlang.error(:badarg, [s, sockAddr, opts, timeout])

      result ->
        result
    end
  end

  def connect_init(s, addr, port, opts) do
    connect_init(s, addr, port, opts, :infinity)
  end

  def connect_init(s, addr, port, opts, timeout) do
    case do_connect(s, addr, port, opts, timeout, false) do
      :badarg ->
        :erlang.error(:badarg, [s, addr, port, opts, timeout])

      result ->
        result
    end
  end

  defp do_connect(s, sockAddr, opts, timeout, connWait)
       when is_port(s) and is_list(opts) do
    case :inet_db.lookup_socket(s) do
      {:ok, mod} ->
        try do
          :inet.start_timer(timeout)
        catch
          :error, :badarg ->
            :badarg
        else
          timer ->
            connectTimer =
              cond do
                connWait == false ->
                  :nowait

                true ->
                  timer
              end

            mod.connect(s, :inet.ensure_sockaddr(sockAddr), opts, connectTimer)
        end

      error ->
        error
    end
  end

  defp do_connect(_S, _SockAddr, _Opts, _Timeout, _ConnWait) do
    :badarg
  end

  defp do_connect(s, addr, service, opts, timeout, connWait)
       when is_port(s) and is_list(opts) do
    case :inet_db.lookup_socket(s) do
      {:ok, mod} ->
        case mod.getserv(service) do
          {:ok, port} ->
            try do
              :inet.start_timer(timeout)
            catch
              :error, :badarg ->
                :badarg
            else
              timer ->
                try do
                  mod.getaddr(addr, timer)
                else
                  {:ok, iP} ->
                    connectTimer =
                      cond do
                        connWait == false ->
                          :nowait

                        true ->
                          timer
                      end

                    mod.connect(s, iP, port, opts, connectTimer)

                  error ->
                    error
                after
                  _ = :inet.stop_timer(timer)
                end
            end

          error ->
            error
        end

      error ->
        error
    end
  end

  defp do_connect(_S, _Addr, _Port, _Opts, _Timeout, _ConnWait) do
    :badarg
  end

  def connectx_init(s, sockAddrs, opts) do
    case do_connectx(s, sockAddrs, opts) do
      :badarg ->
        :erlang.error(:badarg, [s, sockAddrs, opts])

      result ->
        result
    end
  end

  def connectx_init(s, addrs, port, opts) do
    connectx_init(s, addrs, port, opts, :infinity)
  end

  def connectx_init(s, addrs, port, opts, timeout) do
    case do_connectx(s, addrs, port, opts, timeout) do
      :badarg ->
        :erlang.error(:badarg, [s, addrs, port, opts, timeout])

      result ->
        result
    end
  end

  defp do_connectx(s, sockAddrs, opts)
       when is_port(s) and
              is_list(sockAddrs) and is_list(opts) do
    case :inet_db.lookup_socket(s) do
      {:ok, mod} ->
        case ensure_sockaddrs(sockAddrs) do
          {sockAddrs_1, port} ->
            sockAddrs_2 = set_port(sockAddrs_1, port)
            mod.connectx(s, sockAddrs_2, opts)

          error1 ->
            error1
        end

      {:error, _} = error2 ->
        error2
    end
  end

  defp do_connectx(_S, _SockAddrs, _Opts) do
    :badarg
  end

  defp do_connectx(s, addrs, service, opts, timeout)
       when is_port(s) and is_list(addrs) and
              is_list(opts) do
    case :inet_db.lookup_socket(s) do
      {:ok, mod} ->
        case mod.getserv(service) do
          {:ok, port} ->
            try do
              :inet.start_timer(timeout)
            catch
              :error, :badarg ->
                :badarg
            else
              timer ->
                try do
                  case getaddrs(mod, addrs, timer) do
                    iPs when is_list(iPs) ->
                      mod.connectx(s, iPs, port, opts)

                    error1 ->
                      error1
                  end
                after
                  _ = :inet.stop_timer(timer)
                end
            end

          {:error, _} = error2 ->
            error2
        end

      {:error, _} = error3 ->
        error3
    end
  end

  defp do_connectx(_S, _Addrs, _Port, _Opts, _Timeout) do
    :badarg
  end

  defp ensure_sockaddrs(sockAddrs) do
    ensure_sockaddrs(sockAddrs, 0, [])
  end

  defp ensure_sockaddrs([sockAddr | sockAddrs], port, acc) do
    case sockAddr do
      {iP, p} when is_tuple(iP) ->
        ensure_sockaddrs(sockAddrs, port, [sockAddr | acc], p)

      {family, {_, p}}
      when family === :inet or
             family === :inet6 ->
        ensure_sockaddrs(sockAddrs, port, [sockAddr | acc], p)

      %{family: family}
      when family === :inet or
             family === :inet6 ->
        sockAddr_1 = :inet.ensure_sockaddr(sockAddr)
        ensure_sockaddrs(sockAddrs, port, [sockAddr_1 | acc], :maps.get(:port, sockAddr_1, 0))

      _ ->
        :badarg
    end
  end

  defp ensure_sockaddrs([], 0, _) do
    :badarg
  end

  defp ensure_sockaddrs([], port, acc) do
    {:lists.reverse(acc), port}
  end

  defp ensure_sockaddrs(sockAddrs, port, acc, p) do
    cond do
      is_integer(p) ->
        cond do
          0 < p ->
            ensure_sockaddrs(sockAddrs, p, acc)

          p < 0 ->
            :badarg

          true ->
            ensure_sockaddrs(sockAddrs, port, acc)
        end

      true ->
        :badarg
    end
  end

  defp set_port([sockAddr | sockAddrs], port) do
    case sockAddr do
      {iP, p} when is_tuple(iP) ->
        set_port(sockAddrs, port, sockAddr, p, fn ->
          {iP, port}
        end)

      {family, {addr, p}} ->
        set_port(sockAddrs, port, sockAddr, p, fn ->
          {family, {addr, port}}
        end)

      %{port: p} ->
        set_port(sockAddrs, port, sockAddr, p, fn ->
          %{sockAddr | port: port}
        end)
    end
  end

  defp set_port([], _Port) do
    []
  end

  defp set_port(sockAddrs, port, sockAddr, p, newSockAddrFun) do
    [
      case p do
        ^port ->
          sockAddr

        _ ->
          newSockAddrFun.()
      end
      | set_port(sockAddrs, port)
    ]
  end

  defp getaddrs(mod, addrs, timer) do
    getaddrs(mod, addrs, timer, [])
  end

  defp getaddrs(mod, [addr | addrs], timer, acc) do
    case mod.getaddr(addr, timer) do
      {:ok, iP} ->
        getaddrs(mod, addrs, timer, [iP | acc])

      {:error, _} ->
        :badarg
    end
  end

  defp getaddrs(_Mod, [], _Timer, acc) do
    :lists.reverse(acc)
  end

  def eof(s, r_sctp_assoc_change(assoc_id: assocId)) when is_port(s) do
    eof_or_abort(s, assocId, :eof)
  end

  def eof(s, assoc) do
    :erlang.error(:badarg, [s, assoc])
  end

  def abort(s, r_sctp_assoc_change(assoc_id: assocId)) when is_port(s) do
    eof_or_abort(s, assocId, :abort)
  end

  def abort(s, assoc) do
    :erlang.error(:badarg, [s, assoc])
  end

  defp eof_or_abort(s, assocId, action) do
    case :inet_db.lookup_socket(s) do
      {:ok, mod} ->
        mod.sendmsg(s, r_sctp_sndrcvinfo(assoc_id: assocId, flags: [action]), <<>>)

      error ->
        error
    end
  end

  def send(s, r_sctp_sndrcvinfo() = sRI, data) when is_port(s) do
    case :inet_db.lookup_socket(s) do
      {:ok, mod} ->
        mod.sendmsg(s, sRI, data)

      error ->
        error
    end
  end

  def send(s, sRI, data) do
    :erlang.error(:badarg, [s, sRI, data])
  end

  def send(s, r_sctp_assoc_change(assoc_id: assocId), stream, data)
      when is_port(s) and is_integer(stream) do
    case :inet_db.lookup_socket(s) do
      {:ok, mod} ->
        mod.send(s, assocId, stream, data)

      error ->
        error
    end
  end

  def send(s, assocId, stream, data)
      when is_port(s) and
             is_integer(assocId) and
             is_integer(stream) do
    case :inet_db.lookup_socket(s) do
      {:ok, mod} ->
        mod.send(s, assocId, stream, data)

      error ->
        error
    end
  end

  def send(s, assocChange, stream, data) do
    :erlang.error(:badarg, [s, assocChange, stream, data])
  end

  def recv(s) do
    recv(s, :infinity)
  end

  def recv(s, timeout) when is_port(s) do
    case :inet_db.lookup_socket(s) do
      {:ok, mod} ->
        mod.recv(s, timeout)

      error ->
        error
    end
  end

  def recv(s, timeout) do
    :erlang.error(:badarg, [s, timeout])
  end

  def error_string(0) do
    :ok
  end

  def error_string(1) do
    ~c"Invalid Stream Identifier"
  end

  def error_string(2) do
    ~c"Missing Mandatory Parameter"
  end

  def error_string(3) do
    ~c"Stale Cookie Error"
  end

  def error_string(4) do
    ~c"Out of Resource"
  end

  def error_string(5) do
    ~c"Unresolvable Address"
  end

  def error_string(6) do
    ~c"Unrecognized Chunk Type"
  end

  def error_string(7) do
    ~c"Invalid Mandatory Parameter"
  end

  def error_string(8) do
    ~c"Unrecognized Parameters"
  end

  def error_string(9) do
    ~c"No User Data"
  end

  def error_string(10) do
    ~c"Cookie Received While Shutting Down"
  end

  def error_string(11) do
    ~c"Restart of an Association with New Addresses"
  end

  def error_string(12) do
    ~c"User Initiated Abort"
  end

  def error_string(13) do
    ~c"Protocol Violation"
  end

  def error_string(n) when is_integer(n) do
    :unknown_error
  end

  def error_string(x) do
    :erlang.error(:badarg, [x])
  end

  def controlling_process(s, pid) when is_port(s) and is_pid(pid) do
    :inet.udp_controlling_process(s, pid)
  end

  def controlling_process(s, pid) do
    :erlang.error(:badarg, [s, pid])
  end
end
