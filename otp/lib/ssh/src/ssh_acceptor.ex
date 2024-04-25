defmodule :m_ssh_acceptor do
  use Bitwise
  require Record

  Record.defrecord(:r_address, :address,
    address: :undefined,
    port: :undefined,
    profile: :undefined
  )

  Record.defrecord(:r_ssh, :ssh,
    role: :undefined,
    peer: :undefined,
    local: :undefined,
    c_vsn: :undefined,
    s_vsn: :undefined,
    c_version: :undefined,
    s_version: :undefined,
    c_keyinit: :undefined,
    s_keyinit: :undefined,
    send_ext_info: :undefined,
    recv_ext_info: :undefined,
    kex_strict_negotiated: false,
    algorithms: :undefined,
    send_mac: :none,
    send_mac_key: :undefined,
    send_mac_size: 0,
    recv_mac: :none,
    recv_mac_key: :undefined,
    recv_mac_size: 0,
    encrypt: :none,
    encrypt_cipher: :undefined,
    encrypt_keys: :undefined,
    encrypt_block_size: 8,
    encrypt_ctx: :undefined,
    decrypt: :none,
    decrypt_cipher: :undefined,
    decrypt_keys: :undefined,
    decrypt_block_size: 8,
    decrypt_ctx: :undefined,
    compress: :none,
    compress_ctx: :undefined,
    decompress: :none,
    decompress_ctx: :undefined,
    c_lng: :none,
    s_lng: :none,
    user_ack: true,
    timeout: :infinity,
    shared_secret: :undefined,
    exchanged_hash: :undefined,
    session_id: :undefined,
    opts: [],
    send_sequence: 0,
    recv_sequence: 0,
    keyex_key: :undefined,
    keyex_info: :undefined,
    random_length_padding: 15,
    user: :undefined,
    service: :undefined,
    userauth_quiet_mode: :undefined,
    userauth_methods: :undefined,
    userauth_supported_methods: :undefined,
    userauth_pubkeys: :undefined,
    kb_tries_left: 0,
    userauth_preference: :undefined,
    available_host_keys: :undefined,
    pwdfun_user_state: :undefined,
    authenticated: false
  )

  Record.defrecord(:r_alg, :alg,
    kex: :undefined,
    hkey: :undefined,
    send_mac: :undefined,
    recv_mac: :undefined,
    encrypt: :undefined,
    decrypt: :undefined,
    compress: :undefined,
    decompress: :undefined,
    c_lng: :undefined,
    s_lng: :undefined,
    send_ext_info: :undefined,
    recv_ext_info: :undefined,
    kex_strict_negotiated: false
  )

  Record.defrecord(:r_ssh_pty, :ssh_pty,
    c_version: ~c"",
    term: ~c"",
    width: 80,
    height: 25,
    pixel_width: 1024,
    pixel_height: 768,
    modes: <<>>
  )

  Record.defrecord(:r_circ_buf_entry, :circ_buf_entry,
    module: :undefined,
    line: :undefined,
    function: :undefined,
    pid: self(),
    value: :undefined
  )

  @behaviour :ssh_dbg
  def start_link(systemSup, address, options) do
    :proc_lib.start_link(:ssh_acceptor, :acceptor_init, [self(), systemSup, address, options])
  end

  def listen(port, options) do
    {_, callback, _} =
      :ssh_options.get_value(:user_options, :transport, options, :ssh_acceptor, 49)

    sockOpts = [
      {:active, false},
      {:reuseaddr, true}
      | :ssh_options.get_value(
          :user_options,
          :socket_options,
          options,
          :ssh_acceptor,
          50
        )
    ]

    case callback.listen(port, sockOpts) do
      {:error, :nxdomain} ->
        callback.listen(port, :lists.delete(:inet6, sockOpts))

      {:error, :enetunreach} ->
        callback.listen(port, :lists.delete(:inet6, sockOpts))

      {:error, :eafnosupport} ->
        callback.listen(port, :lists.delete(:inet6, sockOpts))

      other ->
        other
    end
  end

  defp accept(listenSocket, acceptTimeout, options) do
    {_, callback, _} =
      :ssh_options.get_value(:user_options, :transport, options, :ssh_acceptor, 63)

    callback.accept(listenSocket, acceptTimeout)
  end

  defp close(socket, options) do
    {_, callback, _} =
      :ssh_options.get_value(:user_options, :transport, options, :ssh_acceptor, 67)

    callback.close(socket)
  end

  def acceptor_init(
        parent,
        systemSup,
        r_address(address: address, port: port, profile: _Profile),
        opts
      ) do
    acceptTimeout =
      :ssh_options.get_value(
        :internal_options,
        :timeout,
        opts,
        fn ->
          5000
        end,
        :ssh_acceptor,
        76
      )

    case :ssh_options.get_value(
           :internal_options,
           :lsocket,
           opts,
           fn ->
             :undefined
           end,
           :ssh_acceptor,
           77
         ) do
      {lSock, sockOwner} ->
        case :inet.sockname(lSock) do
          {:ok, {_, ^port}} ->
            :proc_lib.init_ack(parent, {:ok, self()})
            request_ownership(lSock, sockOwner)
            acceptor_loop(port, address, opts, lSock, acceptTimeout, systemSup)

          {:error, _Error} ->
            case try_listen(port, opts, 4) do
              {:ok, newLSock} ->
                :proc_lib.init_ack(parent, {:ok, self()})

                opts1 =
                  :ssh_options.delete_key(:internal_options, :lsocket, opts, :ssh_acceptor, 93)

                acceptor_loop(port, address, opts1, newLSock, acceptTimeout, systemSup)

              {:error, error} ->
                :proc_lib.init_fail(parent, {:error, error}, {:exit, :normal})
            end
        end

      :undefined ->
        case listen(port, opts) do
          {:ok, lSock} ->
            :proc_lib.init_ack(parent, {:ok, self()})
            acceptor_loop(port, address, opts, lSock, acceptTimeout, systemSup)

          {:error, error} ->
            :proc_lib.init_fail(parent, {:error, error}, {:exit, :normal})
        end
    end
  end

  defp try_listen(port, opts, ntriesLeft) do
    try_listen(port, opts, 1, ntriesLeft)
  end

  defp try_listen(port, opts, n, nmax) do
    case listen(port, opts) do
      {:error, :eaddrinuse} when n < nmax ->
        :timer.sleep(10 * n)
        try_listen(port, opts, n + 1, nmax)

      other ->
        other
    end
  end

  defp request_ownership(lSock, sockOwner) do
    send(sockOwner, {:request_control, lSock, self()})

    receive do
      {:its_yours, ^lSock} ->
        :ok
    end
  end

  def acceptor_loop(port, address, opts, listenSocket, acceptTimeout, systemSup) do
    try do
      case accept(listenSocket, acceptTimeout, opts) do
        {:ok, socket} ->
          peerName = :inet.peername(socket)

          maxSessions =
            :ssh_options.get_value(:user_options, :max_sessions, opts, :ssh_acceptor, 137)

          numSessions = number_of_connections(systemSup)

          parallelLogin =
            :ssh_options.get_value(:user_options, :parallel_login, opts, :ssh_acceptor, 139)

          case handle_connection(
                 address,
                 port,
                 peerName,
                 opts,
                 socket,
                 maxSessions,
                 numSessions,
                 parallelLogin
               ) do
            {:error, error} ->
              try do
                close(socket, opts)
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end

              handle_error(error, address, port, peerName)

            _ ->
              :ok
          end

        {:error, error} ->
          handle_error(error, address, port, :undefined)
      end
    catch
      class, err ->
        handle_error(
          {:error, {:unhandled, class, err, __STACKTRACE__}},
          address,
          port,
          :undefined
        )
    end

    :ssh_acceptor.acceptor_loop(port, address, opts, listenSocket, acceptTimeout, systemSup)
  end

  defp handle_connection(
         _Address,
         _Port,
         _Peer,
         _Options,
         _Socket,
         maxSessions,
         numSessions,
         _ParallelLogin
       )
       when numSessions >= maxSessions do
    {:error, {:max_sessions, maxSessions}}
  end

  defp handle_connection(
         _Address,
         _Port,
         {:error, error},
         _Options,
         _Socket,
         _MaxSessions,
         _NumSessions,
         _ParallelLogin
       ) do
    {:error, error}
  end

  defp handle_connection(
         address,
         port,
         _Peer,
         options,
         socket,
         _MaxSessions,
         _NumSessions,
         parallelLogin
       )
       when parallelLogin == false do
    handle_connection(address, port, options, socket)
  end

  defp handle_connection(
         address,
         port,
         _Peer,
         options,
         socket,
         _MaxSessions,
         _NumSessions,
         parallelLogin
       )
       when parallelLogin == true do
    ref = make_ref()

    pid =
      spawn_link(fn ->
        :erlang.process_flag(:trap_exit, true)

        receive do
          {:start, ^ref} ->
            handle_connection(address, port, options, socket)
        after
          10000 ->
            {:error, :timeout2}
        end
      end)

    try do
      :gen_tcp.controlling_process(socket, pid)
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end

    send(pid, {:start, ref})
    :ok
  end

  defp handle_connection(address, port, options0, socket) do
    options =
      :ssh_options.put_value(
        :internal_options,
        [{:user_pid, self()}],
        options0,
        :ssh_acceptor,
        189
      )

    :ssh_system_sup.start_subsystem(
      :server,
      r_address(
        address: address,
        port: port,
        profile:
          :ssh_options.get_value(
            :user_options,
            :profile,
            options,
            :ssh_acceptor,
            193
          )
      ),
      socket,
      options
    )
  end

  defp handle_error(reason, toAddress, toPort, {:ok, {fromIP, fromPort}}) do
    handle_error(reason, toAddress, toPort, fromIP, fromPort)
  end

  defp handle_error(reason, toAddress, toPort, _) do
    handle_error(reason, toAddress, toPort, :undefined, :undefined)
  end

  defp handle_error(reason, toAddress, toPort, fromAddress, fromPort) do
    case reason do
      {:max_sessions, maxSessions} ->
        :error_logger.info_report(
          :lists.concat([
            ~c"Ssh login attempt to ",
            :ssh_lib.format_address_port(
              toAddress,
              toPort
            ),
            ~c" from ",
            :ssh_lib.format_address_port(
              fromAddress,
              fromPort
            ),
            ~c" denied due to option max_sessions limits to ",
            maxSessions,
            ~c" sessions."
          ])
        )

      limit when limit == :enfile or limit == :emfile ->
        :error_logger.info_report([
          :erlang.atom_to_list(limit),
          ~c": out of accept sockets on ",
          :ssh_lib.format_address_port(
            toAddress,
            toPort
          ),
          ~c" - retrying"
        ])

        :timer.sleep(200)

      :closed ->
        :error_logger.info_report([
          ~c"The ssh accept socket on ",
          :ssh_lib.format_address_port(
            toAddress,
            toPort
          ),
          ~c"was closed by a third party."
        ])

      :timeout ->
        :ok

      error when is_list(error) ->
        :ok

      error
      when fromAddress !== :undefined and
             fromPort !== :undefined ->
        :error_logger.info_report([
          ~c"Accept failed on ",
          :ssh_lib.format_address_port(
            toAddress,
            toPort
          ),
          ~c" for connect from ",
          :ssh_lib.format_address_port(
            fromAddress,
            fromPort
          ),
          :io_lib.format(~c": ~p", [error])
        ])

      error ->
        :error_logger.info_report([
          ~c"Accept failed on ",
          :ssh_lib.format_address_port(
            toAddress,
            toPort
          ),
          :io_lib.format(~c": ~p", [error])
        ])
    end
  end

  def number_of_connections(sysSupPid) do
    :lists.foldl(
      fn
        {_Ref, _Pid, :supervisor, [:ssh_subsystem_sup]}, n ->
          n + 1

        _, n ->
          n
      end,
      0,
      :supervisor.which_children(sysSupPid)
    )
  end

  def ssh_dbg_trace_points() do
    [:connections, :tcp]
  end

  def ssh_dbg_flags(:tcp) do
    [:c]
  end

  def ssh_dbg_flags(:connections) do
    [:c]
  end

  def ssh_dbg_on(:tcp) do
    :dbg.tp(:ssh_acceptor, :listen, 2, :x)
    :dbg.tpl(:ssh_acceptor, :accept, 3, :x)
    :dbg.tpl(:ssh_acceptor, :close, 2, :x)
  end

  def ssh_dbg_on(:connections) do
    :dbg.tp(:ssh_acceptor, :acceptor_init, 4, :x)
    :dbg.tpl(:ssh_acceptor, :handle_connection, 4, :x)
  end

  def ssh_dbg_off(:tcp) do
    :dbg.ctpg(:ssh_acceptor, :listen, 2)
    :dbg.ctpl(:ssh_acceptor, :accept, 3)
    :dbg.ctpl(:ssh_acceptor, :close, 2)
  end

  def ssh_dbg_off(:connections) do
    :dbg.ctp(:ssh_acceptor, :acceptor_init, 4)
    :dbg.ctp(:ssh_acceptor, :handle_connection, 4)
  end

  def ssh_dbg_format(
        :tcp,
        {:call, {:ssh_acceptor, :listen, [port, _Opts]}},
        stack
      ) do
    {:skip, [{:port, port} | stack]}
  end

  def ssh_dbg_format(
        :tcp,
        {:return_from, {:ssh_acceptor, :listen, 2}, {:ok, sock}},
        [{:port, port} | stack]
      ) do
    {[
       ~c"TCP listener started\n",
       :io_lib.format(~c"Port: ~p~nListeningSocket: ~p~n", [port, sock])
     ], stack}
  end

  def ssh_dbg_format(
        :tcp,
        {:return_from, {:ssh_acceptor, :listen, 2}, result},
        [{:port, port} | stack]
      ) do
    {[~c"TCP listener start ERROR\n", :io_lib.format(~c"Port: ~p~nReturn: ~p~n", [port, result])],
     stack}
  end

  def ssh_dbg_format(
        :tcp,
        {:call, {:ssh_acceptor, :accept, [listenSocket, _AcceptTimeout, _Options]}},
        stack
      ) do
    {:skip, [{:lsock, listenSocket} | stack]}
  end

  def ssh_dbg_format(
        :tcp,
        {:return_from, {:ssh_acceptor, :accept, 3}, {:ok, sock}},
        [{:lsock, listenSocket} | stack]
      ) do
    {[
       ~c"TCP accept\n",
       :io_lib.format(~c"ListenSock: ~p~nNew Socket: ~p~n", [listenSocket, sock])
     ], stack}
  end

  def ssh_dbg_format(
        :tcp,
        {:return_from, {:ssh_acceptor, :accept, 3}, {:error, :timeout}},
        [{:lsock, _ListenSocket} | stack]
      ) do
    {:skip, stack}
  end

  def ssh_dbg_format(
        :tcp,
        {:return_from, {:ssh_acceptor, :accept, 3}, return},
        [{:lsock, listenSocket} | stack]
      ) do
    {[
       ~c"TCP accept returned\n",
       :io_lib.format(~c"ListenSock: ~p~nReturn: ~p~n", [listenSocket, return])
     ], stack}
  end

  def ssh_dbg_format(
        :tcp,
        {:call, {:ssh_acceptor, :close, [socket, _Options]}}
      ) do
    [~c"TCP close listen socket\n", :io_lib.format(~c"Socket: ~p~n", [socket])]
  end

  def ssh_dbg_format(
        :tcp,
        {:return_from, {:ssh_acceptor, :close, 2}, _Return}
      ) do
    :skip
  end

  def ssh_dbg_format(
        :connections,
        {:call, {:ssh_acceptor, :acceptor_init, [_Parent, _SysSup, address, _Opts]}}
      ) do
    [:io_lib.format(~c"Starting LISTENER on ~s\n", [:ssh_lib.format_address(address)])]
  end

  def ssh_dbg_format(
        :connections,
        {:return_from, {:ssh_acceptor, :acceptor_init, 4}, _Ret}
      ) do
    :skip
  end

  def ssh_dbg_format(
        :connections,
        {:call, {:ssh_acceptor, :handle_connection, [_Address, _Port, _Options, _Sock]}}
      ) do
    :skip
  end

  def ssh_dbg_format(
        :connections,
        {:return_from, {:ssh_acceptor, :handle_connection, 4}, {:error, error}}
      ) do
    [~c"Starting connection to server failed:\n", :io_lib.format(~c"Error = ~p", [error])]
  end
end
