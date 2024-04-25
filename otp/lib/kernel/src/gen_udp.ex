defmodule :m_gen_udp do
  use Bitwise
  import Kernel, except: [send: 2]
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
  def open(port) do
    open(port, [])
  end

  def open(port, opts0) do
    case (:inet.gen_udp_module(opts0)) do
      {:gen_udp, opts} ->
        open1(port, opts)
      {genUdpMod, opts} ->
        genUdpMod.open(port, opts)
    end
  end

  defp open1(port, opts0) do
    {mod, opts} = :inet.udp_module(opts0)
    {:ok, uP} = mod.getserv(port)
    mod.open(uP, opts)
  end

  def close({:"$inet", genUdpMod, _} = s)
      when is_atom(genUdpMod) do
    genUdpMod.close(s)
  end

  def close(s) do
    :inet.udp_close(s)
  end

  def send({:"$inet", genUdpMod, _} = s, packet)
      when is_atom(genUdpMod) do
    genUdpMod.send(s, packet)
  end

  def send(s, packet) when is_port(s) do
    case (:inet_db.lookup_socket(s)) do
      {:ok, mod} ->
        mod.send(s, packet)
      error ->
        error
    end
  end

  def send({:"$inet", genUdpMod, _} = s, destination, packet)
      when is_atom(genUdpMod) do
    genUdpMod.send(s, destination, packet)
  end

  def send(socket, destination, packet) do
    send(socket, destination, [], packet)
  end

  def send({:"$inet", genUdpMod, _} = s, arg2, arg3, packet)
      when is_atom(genUdpMod) do
    genUdpMod.send(s, arg2, arg3, packet)
  end

  def send(s, %{family: fam} = destination, ancData, packet)
      when is_port(s) and (fam === :inet or fam === :inet6) and is_list(ancData) do
    case (:inet_db.lookup_socket(s)) do
      {:ok, mod} ->
        mod.send(s, :inet.ensure_sockaddr(destination), ancData,
                   packet)
      error ->
        error
    end
  end

  def send(s, {_, _} = destination, portZero = ancData,
           packet)
      when is_port(s) do
    cond do
      portZero === 0 ->
        case (:inet_db.lookup_socket(s)) do
          {:ok, mod} ->
            mod.send(s, destination, [], packet)
          error ->
            error
        end
      is_integer(portZero) ->
        {:error, :einval}
      is_list(ancData) ->
        case (:inet_db.lookup_socket(s)) do
          {:ok, mod} ->
            mod.send(s, destination, ancData, packet)
          error ->
            error
        end
    end
  end

  def send(s, host, port, packet) when is_port(s) do
    send(s, host, port, [], packet)
  end

  def send({:"$inet", genUdpMod, _} = s, host, port, ancData,
           packet)
      when is_atom(genUdpMod) do
    genUdpMod.send(s, host, port, ancData, packet)
  end

  def send(s, host, port, ancData, packet)
      when (is_port(s) and is_list(ancData)) do
    case (:inet_db.lookup_socket(s)) do
      {:ok, mod} ->
        case (mod.getaddr(host)) do
          {:ok, iP} ->
            case (mod.getserv(port)) do
              {:ok, p} ->
                mod.send(s, {iP, p}, ancData, packet)
              {:error, :einval} ->
                exit(:badarg)
              error ->
                error
            end
          {:error, :einval} ->
            exit(:badarg)
          error ->
            error
        end
      error ->
        error
    end
  end

  def recv({:"$inet", genUdpMod, _} = s, len)
      when is_atom(genUdpMod) and is_integer(len) do
    genUdpMod.recv(s, len)
  end

  def recv(s, len) when is_port(s) and is_integer(len) do
    case (:inet_db.lookup_socket(s)) do
      {:ok, mod} ->
        mod.recv(s, len)
      error ->
        error
    end
  end

  def recv({:"$inet", genUdpMod, _} = s, len, time)
      when is_atom(genUdpMod) do
    genUdpMod.recv(s, len, time)
  end

  def recv(s, len, time) when is_port(s) do
    case (:inet_db.lookup_socket(s)) do
      {:ok, mod} ->
        mod.recv(s, len, time)
      error ->
        error
    end
  end

  def connect(s, sockAddr)
      when is_port(s) and is_map(sockAddr) do
    case (:inet_db.lookup_socket(s)) do
      {:ok, mod} ->
        mod.connect(s, :inet.ensure_sockaddr(sockAddr))
      error ->
        error
    end
  end

  def connect({:"$inet", genUdpMod, _} = s, address, port)
      when is_atom(genUdpMod) do
    genUdpMod.connect(s, address, port)
  end

  def connect(s, address, port) when is_port(s) do
    case (:inet_db.lookup_socket(s)) do
      {:ok, mod} ->
        case (mod.getaddr(address)) do
          {:ok, iP} ->
            mod.connect(s, iP, port)
          error ->
            error
        end
      error ->
        error
    end
  end

  def controlling_process({:"$inet", genUdpMod, _} = s, newOwner)
      when is_atom(genUdpMod) do
    genUdpMod.controlling_process(s, newOwner)
  end

  def controlling_process(s, newOwner) do
    :inet.udp_controlling_process(s, newOwner)
  end

  def fdopen(fd, opts0) do
    {mod, opts} = :inet.udp_module(opts0)
    mod.fdopen(fd, opts)
  end

end