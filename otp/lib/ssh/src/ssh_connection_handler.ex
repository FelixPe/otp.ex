defmodule :m_ssh_connection_handler do
  use Bitwise
  @behaviour :gen_statem
  require Record
  Record.defrecord(:r_address, :address, address: :undefined,
                                   port: :undefined, profile: :undefined)
  Record.defrecord(:r_ssh, :ssh, role: :undefined,
                               peer: :undefined, local: :undefined,
                               c_vsn: :undefined, s_vsn: :undefined,
                               c_version: :undefined, s_version: :undefined,
                               c_keyinit: :undefined, s_keyinit: :undefined,
                               send_ext_info: :undefined,
                               recv_ext_info: :undefined,
                               kex_strict_negotiated: false,
                               algorithms: :undefined, send_mac: :none,
                               send_mac_key: :undefined, send_mac_size: 0,
                               recv_mac: :none, recv_mac_key: :undefined,
                               recv_mac_size: 0, encrypt: :none,
                               encrypt_cipher: :undefined,
                               encrypt_keys: :undefined, encrypt_block_size: 8,
                               encrypt_ctx: :undefined, decrypt: :none,
                               decrypt_cipher: :undefined,
                               decrypt_keys: :undefined, decrypt_block_size: 8,
                               decrypt_ctx: :undefined, compress: :none,
                               compress_ctx: :undefined, decompress: :none,
                               decompress_ctx: :undefined, c_lng: :none,
                               s_lng: :none, user_ack: true, timeout: :infinity,
                               shared_secret: :undefined,
                               exchanged_hash: :undefined,
                               session_id: :undefined, opts: [],
                               send_sequence: 0, recv_sequence: 0,
                               keyex_key: :undefined, keyex_info: :undefined,
                               random_length_padding: 15, user: :undefined,
                               service: :undefined,
                               userauth_quiet_mode: :undefined,
                               userauth_methods: :undefined,
                               userauth_supported_methods: :undefined,
                               userauth_pubkeys: :undefined, kb_tries_left: 0,
                               userauth_preference: :undefined,
                               available_host_keys: :undefined,
                               pwdfun_user_state: :undefined,
                               authenticated: false)
  Record.defrecord(:r_alg, :alg, kex: :undefined,
                               hkey: :undefined, send_mac: :undefined,
                               recv_mac: :undefined, encrypt: :undefined,
                               decrypt: :undefined, compress: :undefined,
                               decompress: :undefined, c_lng: :undefined,
                               s_lng: :undefined, send_ext_info: :undefined,
                               recv_ext_info: :undefined,
                               kex_strict_negotiated: false)
  Record.defrecord(:r_ssh_pty, :ssh_pty, c_version: '', term: '',
                                   width: 80, height: 25, pixel_width: 1024,
                                   pixel_height: 768, modes: <<>>)
  Record.defrecord(:r_circ_buf_entry, :circ_buf_entry, module: :undefined,
                                          line: :undefined,
                                          function: :undefined, pid: self(),
                                          value: :undefined)
  Record.defrecord(:r_ssh_msg_disconnect, :ssh_msg_disconnect, code: :undefined,
                                              description: :undefined,
                                              language: :undefined)
  Record.defrecord(:r_ssh_msg_ignore, :ssh_msg_ignore, data: :undefined)
  Record.defrecord(:r_ssh_msg_unimplemented, :ssh_msg_unimplemented, sequence: :undefined)
  Record.defrecord(:r_ssh_msg_debug, :ssh_msg_debug, always_display: :undefined,
                                         message: :undefined,
                                         language: :undefined)
  Record.defrecord(:r_ssh_msg_service_request, :ssh_msg_service_request, name: :undefined)
  Record.defrecord(:r_ssh_msg_service_accept, :ssh_msg_service_accept, name: :undefined)
  Record.defrecord(:r_ssh_msg_ext_info, :ssh_msg_ext_info, nr_extensions: :undefined,
                                            data: :undefined)
  Record.defrecord(:r_ssh_msg_kexinit, :ssh_msg_kexinit, cookie: :undefined,
                                           kex_algorithms: :undefined,
                                           server_host_key_algorithms: :undefined,
                                           encryption_algorithms_client_to_server: :undefined,
                                           encryption_algorithms_server_to_client: :undefined,
                                           mac_algorithms_client_to_server: :undefined,
                                           mac_algorithms_server_to_client: :undefined,
                                           compression_algorithms_client_to_server: :undefined,
                                           compression_algorithms_server_to_client: :undefined,
                                           languages_client_to_server: :undefined,
                                           languages_server_to_client: :undefined,
                                           first_kex_packet_follows: false,
                                           reserved: 0)
  Record.defrecord(:r_ssh_msg_kexdh_init, :ssh_msg_kexdh_init, e: :undefined)
  Record.defrecord(:r_ssh_msg_kexdh_reply, :ssh_msg_kexdh_reply, public_host_key: :undefined,
                                               f: :undefined, h_sig: :undefined)
  Record.defrecord(:r_ssh_msg_newkeys, :ssh_msg_newkeys, [])
  Record.defrecord(:r_ssh_msg_kex_dh_gex_request, :ssh_msg_kex_dh_gex_request, min: :undefined,
                                                      n: :undefined,
                                                      max: :undefined)
  Record.defrecord(:r_ssh_msg_kex_dh_gex_request_old, :ssh_msg_kex_dh_gex_request_old, n: :undefined)
  Record.defrecord(:r_ssh_msg_kex_dh_gex_group, :ssh_msg_kex_dh_gex_group, p: :undefined,
                                                    g: :undefined)
  Record.defrecord(:r_ssh_msg_kex_dh_gex_init, :ssh_msg_kex_dh_gex_init, e: :undefined)
  Record.defrecord(:r_ssh_msg_kex_dh_gex_reply, :ssh_msg_kex_dh_gex_reply, public_host_key: :undefined,
                                                    f: :undefined,
                                                    h_sig: :undefined)
  Record.defrecord(:r_ssh_msg_kex_ecdh_init, :ssh_msg_kex_ecdh_init, q_c: :undefined)
  Record.defrecord(:r_ssh_msg_kex_ecdh_reply, :ssh_msg_kex_ecdh_reply, public_host_key: :undefined,
                                                  q_s: :undefined,
                                                  h_sig: :undefined)
  Record.defrecord(:r_ssh_msg_userauth_request, :ssh_msg_userauth_request, user: :undefined,
                                                    service: :undefined,
                                                    method: :undefined,
                                                    data: :undefined)
  Record.defrecord(:r_ssh_msg_userauth_failure, :ssh_msg_userauth_failure, authentications: :undefined,
                                                    partial_success: :undefined)
  Record.defrecord(:r_ssh_msg_userauth_success, :ssh_msg_userauth_success, [])
  Record.defrecord(:r_ssh_msg_userauth_banner, :ssh_msg_userauth_banner, message: :undefined,
                                                   language: :undefined)
  Record.defrecord(:r_ssh_msg_userauth_passwd_changereq, :ssh_msg_userauth_passwd_changereq, prompt: :undefined,
                                                             language: :undefined)
  Record.defrecord(:r_ssh_msg_userauth_pk_ok, :ssh_msg_userauth_pk_ok, algorithm_name: :undefined,
                                                  key_blob: :undefined)
  Record.defrecord(:r_ssh_msg_userauth_info_request, :ssh_msg_userauth_info_request, name: :undefined,
                                                         instruction: :undefined,
                                                         language_tag: :undefined,
                                                         num_prompts: :undefined,
                                                         data: :undefined)
  Record.defrecord(:r_ssh_msg_userauth_info_response, :ssh_msg_userauth_info_response, num_responses: :undefined,
                                                          data: :undefined)
  Record.defrecord(:r_ssh_msg_global_request, :ssh_msg_global_request, name: :undefined,
                                                  want_reply: :undefined,
                                                  data: :undefined)
  Record.defrecord(:r_ssh_msg_request_success, :ssh_msg_request_success, data: :undefined)
  Record.defrecord(:r_ssh_msg_request_failure, :ssh_msg_request_failure, [])
  Record.defrecord(:r_ssh_msg_channel_open, :ssh_msg_channel_open, channel_type: :undefined,
                                                sender_channel: :undefined,
                                                initial_window_size: :undefined,
                                                maximum_packet_size: :undefined,
                                                data: :undefined)
  Record.defrecord(:r_ssh_msg_channel_open_confirmation, :ssh_msg_channel_open_confirmation, recipient_channel: :undefined,
                                                             sender_channel: :undefined,
                                                             initial_window_size: :undefined,
                                                             maximum_packet_size: :undefined,
                                                             data: :undefined)
  Record.defrecord(:r_ssh_msg_channel_open_failure, :ssh_msg_channel_open_failure, recipient_channel: :undefined,
                                                        reason: :undefined,
                                                        description: :undefined,
                                                        lang: :undefined)
  Record.defrecord(:r_ssh_msg_channel_window_adjust, :ssh_msg_channel_window_adjust, recipient_channel: :undefined,
                                                         bytes_to_add: :undefined)
  Record.defrecord(:r_ssh_msg_channel_data, :ssh_msg_channel_data, recipient_channel: :undefined,
                                                data: :undefined)
  Record.defrecord(:r_ssh_msg_channel_extended_data, :ssh_msg_channel_extended_data, recipient_channel: :undefined,
                                                         data_type_code: :undefined,
                                                         data: :undefined)
  Record.defrecord(:r_ssh_msg_channel_eof, :ssh_msg_channel_eof, recipient_channel: :undefined)
  Record.defrecord(:r_ssh_msg_channel_close, :ssh_msg_channel_close, recipient_channel: :undefined)
  Record.defrecord(:r_ssh_msg_channel_request, :ssh_msg_channel_request, recipient_channel: :undefined,
                                                   request_type: :undefined,
                                                   want_reply: :undefined,
                                                   data: :undefined)
  Record.defrecord(:r_ssh_msg_channel_success, :ssh_msg_channel_success, recipient_channel: :undefined)
  Record.defrecord(:r_ssh_msg_channel_failure, :ssh_msg_channel_failure, recipient_channel: :undefined)
  Record.defrecord(:r_channel, :channel, type: :undefined,
                                   sys: :undefined, user: :undefined,
                                   flow_control: :undefined,
                                   local_id: :undefined,
                                   recv_window_size: :undefined,
                                   recv_window_pending: 0,
                                   recv_packet_size: :undefined,
                                   recv_close: false, remote_id: :undefined,
                                   send_window_size: :undefined,
                                   send_packet_size: :undefined,
                                   sent_close: false, send_buf: [])
  Record.defrecord(:r_connection, :connection, requests: [],
                                      channel_cache: :undefined,
                                      channel_id_seed: :undefined,
                                      cli_spec: :undefined, options: :undefined,
                                      suggest_window_size: :undefined,
                                      suggest_packet_size: :undefined,
                                      exec: :undefined,
                                      sub_system_supervisor: :undefined)
  Record.defrecord(:r_data, :data, starter: :undefined,
                                auth_user: :undefined,
                                connection_state: :undefined,
                                latest_channel_id: 0,
                                transport_protocol: :undefined,
                                transport_cb: :undefined,
                                transport_close_tag: :undefined,
                                ssh_params: :undefined, socket: :undefined,
                                decrypted_data_buffer: <<>>,
                                encrypted_data_buffer: <<>>, aead_data: <<>>,
                                undecrypted_packet_length: :undefined,
                                key_exchange_init_msg: :undefined,
                                last_size_rekey: 0, event_queue: [],
                                inet_initial_recbuf_size: :undefined)
  @behaviour :ssh_dbg
  def start_link(role, address, socket, options) do
    start_link(role, address, :undefined, socket, options)
  end

  def start_link(role, _Address = r_address(), id, socket, options) do
    case (:gen_statem.start_link(:ssh_connection_handler,
                                   [role, socket, options],
                                   [{:spawn_opt,
                                       [{:message_queue_data, :off_heap}]}])) do
      {:ok, pid} when id !== :undefined ->
        send(:ssh_options.get_value(:internal_options,
                                      :user_pid, options,
                                      :ssh_connection_handler,
                                      115), {:new_connection_ref, id, pid})
        {:ok, pid}
      others ->
        others
    end
  end

  def takeover(connPid, :client, socket, options) do
    :erlang.group_leader(:erlang.group_leader(), connPid)
    takeover(connPid, :common, socket, options)
  end

  def takeover(connPid, _, socket, options) do
    {_, callback, _} = :ssh_options.get_value(:user_options,
                                                :transport, options,
                                                :ssh_connection_handler, 128)
    case (callback.controlling_process(socket, connPid)) do
      :ok ->
        :gen_statem.cast(connPid, :socket_control)
        negTimeout = :ssh_options.get_value(:internal_options,
                                              :negotiation_timeout, options,
                                              fn () ->
                                                   :ssh_options.get_value(:user_options,
                                                                            :negotiation_timeout,
                                                                            options,
                                                                            :ssh_connection_handler,
                                                                            134)
                                              end,
                                              :ssh_connection_handler, 134)
        handshake(connPid, :erlang.monitor(:process, connPid),
                    negTimeout)
      {:error, reason} ->
        {:error, reason}
    end
  end

  def stop(connectionHandler) do
    case (call(connectionHandler, :stop)) do
      {:error, :closed} ->
        :ok
      other ->
        other
    end
  end

  def disconnect(code, detailedText, module, line) do
    throw({:keep_state_and_data,
             [{:next_event, :internal,
                 {:send_disconnect, code, detailedText, module, line}}]})
  end

  def open_channel(connectionHandler, channelType,
           channelSpecificData, initialWindowSize, maxPacketSize,
           timeout) do
    call(connectionHandler,
           {:open, self(), channelType, initialWindowSize,
              maxPacketSize, channelSpecificData, timeout})
  end

  def start_channel(connectionHandler, callbackModule, channelId,
           args, exec) do
    {:ok, {subSysSup, role, opts}} = call(connectionHandler,
                                            :get_misc)
    :ssh_subsystem_sup.start_channel(role, subSysSup,
                                       connectionHandler, callbackModule,
                                       channelId, args, exec, opts)
  end

  def handle_direct_tcpip(connectionHandler, listenHost, listenPort,
           connectToHost, connectToPort, timeout) do
    call(connectionHandler,
           {:handle_direct_tcpip, listenHost, listenPort,
              connectToHost, connectToPort, timeout})
  end

  def request(connectionHandler, channelPid, channelId, type,
           true, data, timeout) do
    call(connectionHandler,
           {:request, channelPid, channelId, type, data, timeout})
  end

  def request(connectionHandler, channelPid, channelId, type,
           false, data, _) do
    cast(connectionHandler,
           {:request, channelPid, channelId, type, data})
  end

  def request(connectionHandler, channelId, type, true, data,
           timeout) do
    call(connectionHandler,
           {:request, channelId, type, data, timeout})
  end

  def request(connectionHandler, channelId, type, false, data,
           _) do
    cast(connectionHandler,
           {:request, channelId, type, data})
  end

  def reply_request(connectionHandler, status, channelId) do
    cast(connectionHandler,
           {:reply_request, status, channelId})
  end

  def global_request(connectionHandler, type, true, data, timeout) do
    call(connectionHandler,
           {:global_request, type, data, timeout})
  end

  def global_request(connectionHandler, type, false, data, _) do
    cast(connectionHandler, {:global_request, type, data})
  end

  def send(connectionHandler, channelId, type, data,
           timeout) do
    call(connectionHandler,
           {:data, channelId, type, data, timeout})
  end

  def send_eof(connectionHandler, channelId) do
    call(connectionHandler, {:eof, channelId})
  end

  def info(connectionHandler) do
    info(connectionHandler, :all)
  end

  def info(connectionHandler, channelProcess) do
    call(connectionHandler, {:info, channelProcess})
  end

  def get_print_info(connectionHandler) do
    call(connectionHandler, :get_print_info, 1000)
  end

  def connection_info(connectionHandler, []) do
    connection_info(connectionHandler, conn_info_keys())
  end

  def connection_info(connectionHandler, key) when is_atom(key) do
    case (connection_info(connectionHandler, [key])) do
      [{^key, val}] ->
        {key, val}
      other ->
        other
    end
  end

  def connection_info(connectionHandler, options) do
    call(connectionHandler, {:connection_info, options})
  end

  def channel_info(connectionHandler, channelId, options) do
    call(connectionHandler,
           {:channel_info, channelId, options})
  end

  def adjust_window(connectionHandler, channel, bytes) do
    cast(connectionHandler,
           {:adjust_window, channel, bytes})
  end

  def close(connectionHandler, channelId) do
    case (call(connectionHandler, {:close, channelId})) do
      :ok ->
        :ok
      {:error, :closed} ->
        :ok
    end
  end

  def store(connectionHandler, key, value) do
    cast(connectionHandler, {:store, key, value})
  end

  def retrieve(r_connection(options: opts), key) do
    try do
      :ssh_options.get_value(:internal_options, key, opts,
                               :ssh_connection_handler, 345)
    catch
      :error, {:badkey, ^key} ->
        :undefined
    else
      value ->
        {:ok, value}
    end
  end

  def retrieve(connectionHandler, key) do
    call(connectionHandler, {:retrieve, key})
  end

  def set_sock_opts(connectionRef, socketOptions) do
    try do
      :lists.foldr(fn {name, _Val}, acc ->
                        case (prohibited_sock_option(name)) do
                          true ->
                            [name | acc]
                          false ->
                            acc
                        end
                   end,
                     [], socketOptions)
    catch
      _, _ ->
        {:error, :badarg}
    else
      [] ->
        call(connectionRef, {:set_sock_opts, socketOptions})
      bad ->
        {:error, {:not_allowed, bad}}
    end
  end

  def prohibited_sock_option(:active) do
    true
  end

  def prohibited_sock_option(:deliver) do
    true
  end

  def prohibited_sock_option(:mode) do
    true
  end

  def prohibited_sock_option(:packet) do
    true
  end

  def prohibited_sock_option(_) do
    false
  end

  def get_sock_opts(connectionRef, socketGetOptions) do
    call(connectionRef, {:get_sock_opts, socketGetOptions})
  end

  def renegotiate(connectionHandler) do
    cast(connectionHandler, :force_renegotiate)
  end

  def alg(connectionHandler) do
    call(connectionHandler, :get_alg)
  end

  def init([role, socket, opts]) when role == :client or
                                      role == :server do
    :erlang.process_flag(:trap_exit, true)
    d = r_data(socket: socket,
            ssh_params: r_ssh(role: role, opts: opts))
    {:ok, {:wait_for_socket, role}, d}
  end

  defp init_connection_record(role, socket, opts) do
    {winSz, pktSz} = init_inet_buffers_window(socket)
    c = r_connection(channel_cache: :ssh_client_channel.cache_create(),
            channel_id_seed: 0, suggest_window_size: winSz,
            suggest_packet_size: pktSz, requests: [], options: opts,
            sub_system_supervisor: :ssh_options.get_value(:internal_options,
                                                            :subsystem_sup,
                                                            opts,
                                                            :ssh_connection_handler,
                                                            419))
    case (role) do
      :server ->
        r_connection(c, cli_spec: :ssh_options.get_value(:user_options,
                                                :ssh_cli, opts,
                                                fn () ->
                                                     {:ssh_cli,
                                                        [:ssh_options.get_value(:user_options,
                                                                                  :shell,
                                                                                  opts,
                                                                                  :ssh_connection_handler,
                                                                                  424)]}
                                                end,
                                                :ssh_connection_handler, 424), 
               exec: :ssh_options.get_value(:user_options, :exec, opts,
                                              :ssh_connection_handler, 426))
      :client ->
        c
    end
  end

  def init_ssh_record(role, socket, opts) do
    {:ok, peerAddr} = :inet.peername(socket)
    init_ssh_record(role, socket, peerAddr, opts)
  end

  defp init_ssh_record(role, socket, peerAddr, opts) do
    authMethods = :ssh_options.get_value(:user_options,
                                           :auth_methods, opts,
                                           :ssh_connection_handler, 438)
    s0 = r_ssh(role: role, opts: opts,
             userauth_supported_methods: authMethods,
             available_host_keys: available_hkey_algorithms(role,
                                                              opts),
             random_length_padding: :ssh_options.get_value(:user_options,
                                                             :max_random_length_padding,
                                                             opts,
                                                             :ssh_connection_handler,
                                                             443))
    {vsn, version} = :ssh_transport.versions(role, opts)
    localName = (case (:inet.sockname(socket)) do
                   {:ok, local} ->
                     local
                   _ ->
                     :undefined
                 end)
    case (role) do
      :client ->
        peerName = (case (:ssh_options.get_value(:internal_options,
                                                   :host, opts,
                                                   fn () ->
                                                        :erlang.element(1,
                                                                          peerAddr)
                                                   end,
                                                   :ssh_connection_handler,
                                                   453)) do
                      peerIP when is_tuple(peerIP) ->
                        :inet_parse.ntoa(peerIP)
                      peerName0 when is_atom(peerName0) ->
                        :erlang.atom_to_list(peerName0)
                      peerName0 when is_list(peerName0) ->
                        peerName0
                    end)
        s1 = r_ssh(s0, c_vsn: vsn,  c_version: version, 
                     opts: :ssh_options.put_value(:internal_options,
                                                    {:io_cb,
                                                       case (:ssh_options.get_value(:user_options,
                                                                                      :user_interaction,
                                                                                      opts,
                                                                                      :ssh_connection_handler,
                                                                                      464)) do
                                                         true ->
                                                           :ssh_io
                                                         false ->
                                                           :ssh_no_io
                                                       end},
                                                    opts,
                                                    :ssh_connection_handler,
                                                    468), 
                     userauth_quiet_mode: :ssh_options.get_value(:user_options,
                                                                   :quiet_mode,
                                                                   opts,
                                                                   :ssh_connection_handler,
                                                                   469), 
                     peer: {peerName, peerAddr},  local: localName)
        r_ssh(s1, userauth_pubkeys: for k <- :ssh_options.get_value(:user_options,
                                                                  :pref_public_key_algs,
                                                                  opts,
                                                                  :ssh_connection_handler,
                                                                  473),
                                      is_usable_user_pubkey(k, s1) do
                                  k
                                end)
      :server ->
        r_ssh(s0, s_vsn: vsn,  s_version: version, 
                userauth_methods: :string.tokens(authMethods, ','), 
                kb_tries_left: 3,  peer: {:undefined, peerAddr}, 
                local: localName)
    end
  end

  defp handshake(pid, ref, timeout) do
    receive do
      {^pid, :ssh_connected} ->
        :erlang.demonitor(ref, [:flush])
        {:ok, pid}
      {^pid, {:not_connected, reason}} ->
        :erlang.demonitor(ref, [:flush])
        {:error, reason}
      {:DOWN, ^ref, :process, ^pid, {:shutdown, reason}} ->
        {:error, reason}
      {:DOWN, ^ref, :process, ^pid, reason} ->
        {:error, reason}
      {:EXIT, _, reason} ->
        stop(pid)
        {:error, {:exit, reason}}
    after timeout ->
      :erlang.demonitor(ref, [:flush])
      :ssh_connection_handler.stop(pid)
      {:error, :timeout}
    end
  end

  def handshake(msg, r_data(starter: user)) do
    send(user, {self(), msg})
  end

  defp renegotiation({_, _, reNeg}) do
    reNeg == :renegotiate
  end

  defp renegotiation(_) do
    false
  end

  def callback_mode() do
    [:handle_event_function, :state_enter]
  end

  def handle_event(:cast, :socket_control, {:wait_for_socket, role},
           r_data(socket: socket, ssh_params: r_ssh(opts: opts))) do
    case (:inet.peername(socket)) do
      {:ok, peerAddr} ->
        try do
          {protocol, callback,
             closeTag} = :ssh_options.get_value(:user_options,
                                                  :transport, opts,
                                                  :ssh_connection_handler, 572)
          d = r_data(starter: :ssh_options.get_value(:internal_options,
                                                  :user_pid, opts,
                                                  :ssh_connection_handler, 573),
                  socket: socket, transport_protocol: protocol,
                  transport_cb: callback, transport_close_tag: closeTag,
                  ssh_params: init_ssh_record(role, socket, peerAddr,
                                                opts),
                  connection_state: init_connection_record(role, socket,
                                                             opts))
          nextEvent = {:next_event, :internal, :socket_ready}
          {:next_state, {:hello, role}, d, nextEvent}
        catch
          _, {:error, error} ->
            {:stop, {:error, error}}
          :error, error ->
            {:stop, {:error, error}}
        end
      {:error, error} ->
        {:stop, {:shutdown, error}}
    end
  end

  def handle_event(:internal, :socket_ready,
           {:hello, _} = stateName, r_data(ssh_params: ssh0) = d) do
    vsnMsg = :ssh_transport.hello_version_msg(string_version(ssh0))
    send_bytes(vsnMsg, d)
    case (:inet.getopts(socket = r_data(d, :socket),
                          [:recbuf])) do
      {:ok, [{:recbuf, size}]} ->
        :inet.setopts(socket,
                        [{:packet, :line}, {:active, :once}, {:recbuf, 255},
                                                                 {:nodelay,
                                                                    true}])
        time = :ssh_options.get_value(:user_options,
                                        :hello_timeout, r_ssh(ssh0, :opts),
                                        fn () ->
                                             :infinity
                                        end,
                                        :ssh_connection_handler, 604)
        {:keep_state, r_data(d, inet_initial_recbuf_size: size),
           [{:state_timeout, time, :no_hello_received}]}
      other ->
        call_disconnectfun_and_log_cond('Option return',
                                          :io_lib.format('Unexpected getopts return:~n  ~p', [other]),
                                          :ssh_connection_handler, 609,
                                          stateName, d)
        {:stop,
           {:shutdown, {:unexpected_getopts_return, other}}}
    end
  end

  def handle_event(:internal, {:info_line, _Line},
           {:hello, :client}, d) do
    :inet.setopts(r_data(d, :socket), [{:active, :once}])
    :keep_state_and_data
  end

  def handle_event(:internal, {:info_line, line},
           {:hello, :server} = stateName, d) do
    send_bytes('Protocol mismatch.', d)
    msg = :io_lib.format('Protocol mismatch in version exchange. Client sent info lines.~n~s', [:ssh_dbg.hex_dump(line, 64)])
    call_disconnectfun_and_log_cond('Protocol mismatch.', msg,
                                      :ssh_connection_handler, 626, stateName,
                                      d)
    {:stop, {:shutdown, 'Protocol mismatch in version exchange. Client sent info lines.'}}
  end

  def handle_event(:internal, {:version_exchange, version},
           {:hello, role}, d0) do
    {numVsn,
       strVsn} = :ssh_transport.handle_hello_version(version)
    case (handle_version(numVsn, strVsn,
                           r_data(d0, :ssh_params))) do
      {:ok, ssh1} ->
        :inet.setopts(r_data(d0, :socket),
                        [{:packet, 0}, {:mode, :binary}, {:active, :once},
                                                             {:recbuf,
                                                                r_data(d0, :inet_initial_recbuf_size)}])
        {keyInitMsg, sshPacket,
           ssh} = :ssh_transport.key_exchange_init_msg(ssh1)
        send_bytes(sshPacket, d0)
        d = r_data(d0, ssh_params: ssh, 
                    key_exchange_init_msg: keyInitMsg)
        {:next_state, {:kexinit, role, :init}, d,
           {:change_callback_module, :ssh_fsm_kexinit}}
      :not_supported ->
        {shutdown,
           d} = :ssh_connection_handler.send_disconnect(8,
                                                          :io_lib.format('Offending version is ~p',
                                                                           [:string.chomp(version)]),
                                                          :ssh_connection_handler,
                                                          648, {:hello, role},
                                                          d0)
        {:stop, shutdown, d}
    end
  end

  def handle_event(:state_timeout, :no_hello_received,
           {:hello, _Role} = stateName,
           d0 = r_data(ssh_params: ssh0)) do
    time = :ssh_options.get_value(:user_options,
                                    :hello_timeout, r_ssh(ssh0, :opts),
                                    :ssh_connection_handler, 656)
    {shutdown,
       d} = :ssh_connection_handler.send_disconnect(2,
                                                      :lists.concat(['No HELLO received within ',
                                                                         :ssh_lib.format_time_ms(time)]),
                                                      :ssh_connection_handler,
                                                      659, stateName, d0)
    {:stop, shutdown, d}
  end

  def handle_event(:internal, msg = r_ssh_msg_service_request(name: serviceName),
           stateName = {:service_request, :server}, d0) do
    case (serviceName) do
      'ssh-userauth' ->
        ssh0 = (r_ssh(session_id: sessionId) = r_data(d0, :ssh_params))
        {:ok,
           {reply, ssh}} = :ssh_auth.handle_userauth_request(msg,
                                                               sessionId, ssh0)
        d = send_msg(reply, r_data(d0, ssh_params: ssh))
        {:next_state, {:userauth, :server}, d,
           {:change_callback_module, :ssh_fsm_userauth_server}}
      _ ->
        {shutdown,
           d} = :ssh_connection_handler.send_disconnect(7,
                                                          :io_lib.format('Unknown service: ~p',
                                                                           [serviceName]),
                                                          :ssh_connection_handler,
                                                          677, stateName, d0)
        {:stop, shutdown, d}
    end
  end

  def handle_event(:internal, r_ssh_msg_service_accept(name: 'ssh-userauth'),
           {:service_request, :client},
           r_data(ssh_params: r_ssh(service: 'ssh-userauth') = ssh0) = d0) do
    {msg, ssh} = :ssh_auth.init_userauth_request_msg(ssh0)
    d = send_msg(msg,
                   r_data(d0, ssh_params: ssh,  auth_user: r_ssh(ssh, :user)))
    {:next_state, {:userauth, :client}, d,
       {:change_callback_module, :ssh_fsm_userauth_client}}
  end

  def handle_event(:internal, r_ssh_msg_ext_info(), {:connected, _Role}, d) do
    {:keep_state, d}
  end

  def handle_event(:internal, {r_ssh_msg_kexinit(), _}, {:connected, role}, d0) do
    {keyInitMsg, sshPacket,
       ssh} = :ssh_transport.key_exchange_init_msg(r_data(d0, :ssh_params))
    d = r_data(d0, ssh_params: ssh, 
                key_exchange_init_msg: keyInitMsg)
    send_bytes(sshPacket, d)
    {:next_state, {:kexinit, role, :renegotiate}, d,
       [:postpone, {:change_callback_module,
                      :ssh_fsm_kexinit}]}
  end

  def handle_event(:internal, r_ssh_msg_disconnect(description: desc) = msg, stateName,
           d0) do
    {:disconnect, _,
       repliesCon} = :ssh_connection.handle_msg(msg,
                                                  r_data(d0, :connection_state),
                                                  :erlang.element(2, stateName),
                                                  r_data(d0, :ssh_params))
    {actions, d} = send_replies(repliesCon, d0)
    disconnect_fun('Received disconnect: ' ++ desc, d)
    {:stop_and_reply, {:shutdown, desc}, actions, d}
  end

  def handle_event(:internal, r_ssh_msg_ignore(), {_StateName, _Role, :init},
           r_data(ssh_params: r_ssh(kex_strict_negotiated: true,
                             send_sequence: sendSeq,
                             recv_sequence: recvSeq))) do
    :ssh_connection_handler.disconnect(3,
                                         :io_lib.format('strict KEX violation: unexpected SSH_MSG_IGNORE send_sequence = ~p  recv_sequence = ~p', [sendSeq, recvSeq]),
                                         :ssh_connection_handler, 716)
  end

  def handle_event(:internal, r_ssh_msg_ignore(), _StateName, _) do
    :keep_state_and_data
  end

  def handle_event(:internal, r_ssh_msg_unimplemented(), _StateName, _) do
    :keep_state_and_data
  end

  def handle_event(:cast, r_ssh_msg_debug() = msg, state, d) do
    handle_event(:internal, msg, state, d)
  end

  def handle_event(:internal, r_ssh_msg_debug() = msg, _StateName, d) do
    debug_fun(msg, d)
    :keep_state_and_data
  end

  def handle_event(:internal, {:conn_msg, msg}, stateName,
           r_data(connection_state: connection0,
               event_queue: qev0) = d0) do
    role = :erlang.element(2, stateName)
    rengotation = renegotiation(stateName)
    try do
      :ssh_connection.handle_msg(msg, connection0, role,
                                   r_data(d0, :ssh_params))
    catch
      class, error ->
        {repls,
           d1} = send_replies(:ssh_connection.handle_stop(connection0),
                                d0)
        {shutdown,
           d} = :ssh_connection_handler.send_disconnect(11,
                                                          :io_lib.format('Internal error: ~p:~p',
                                                                           [class,
                                                                                error]),
                                                          :ssh_connection_handler,
                                                          772, stateName, d1)
        {:stop_and_reply, shutdown, repls, d}
    else
      {:disconnect, reason0, repliesConn} ->
        {repls, d} = send_replies(repliesConn, d0)
        case ({reason0, role}) do
          {{_, reason}, :client} when stateName !== {:connected,
                                                       :client} and not
                                                                    rengotation
                                      ->
            handshake({:not_connected, reason}, d)
          _ ->
            :ok
        end
        {:stop_and_reply, {:shutdown, :normal}, repls, d}
      {replies, connection} when is_list(replies) ->
        {repls, d} = (case (stateName) do
                        {:connected, _} ->
                          send_replies(replies,
                                         r_data(d0, connection_state: connection))
                        _ ->
                          {connReplies,
                             nonConnReplies} = :lists.splitwith(&not_connected_filter/1,
                                                                  replies)
                          send_replies(nonConnReplies,
                                         r_data(d0, event_queue: qev0 ++ connReplies))
                      end)
        case ({msg, stateName}) do
          {r_ssh_msg_channel_close(), {:connected, _}} ->
            {:keep_state, d, [cond_set_idle_timer(d) | repls]}
          {r_ssh_msg_channel_success(), _} ->
            update_inet_buffers(r_data(d, :socket))
            {:keep_state, d, repls}
          _ ->
            {:keep_state, d, repls}
        end
    end
  end

  def handle_event(:enter, oldState, {:connected, _} = newState,
           d) do
    init_renegotiate_timers(oldState, newState, d)
  end

  def handle_event(:enter, oldState,
           {:ext_info, _, :renegotiate} = newState, d) do
    init_renegotiate_timers(oldState, newState, d)
  end

  def handle_event(:enter, {:connected, _} = oldState, newState,
           d) do
    pause_renegotiate_timers(oldState, newState, d)
  end

  def handle_event(:cast, :force_renegotiate, stateName, d) do
    handle_event({:timeout, :renegotiate}, :undefined,
                   stateName, d)
  end

  def handle_event({:timeout, :renegotiate}, _, stateName, d0) do
    case (stateName) do
      {:connected, role} ->
        start_rekeying(role, d0)
      {:ext_info, role, :renegotiate} ->
        start_rekeying(role, d0)
      _ ->
        :keep_state_and_data
    end
  end

  def handle_event({:timeout, :check_data_size}, _, stateName,
           d0) do
    case (stateName) do
      {:connected, role} ->
        check_data_rekeying(role, d0)
      _ ->
        :keep_state_and_data
    end
  end

  def handle_event({:call, from}, :get_alg, _, d) do
    r_ssh(algorithms: algs) = r_data(d, :ssh_params)
    {:keep_state_and_data, [{:reply, from, algs}]}
  end

  def handle_event(:cast, _, stateName, _) when not
                                      (:erlang.element(1,
                                                         stateName) == :connected or :erlang.element(1,
                                                                                                       stateName) == :ext_info) do
    {:keep_state_and_data, [:postpone]}
  end

  def handle_event(:cast, {:adjust_window, channelId, bytes},
           stateName, d)
      when :erlang.element(1,
                             stateName) == :connected or :erlang.element(1,
                                                                           stateName) == :ext_info do
    case (:ssh_client_channel.cache_lookup(cache(d),
                                             channelId)) do
      r_channel(recv_window_size: winSize,
          recv_window_pending: pending,
          recv_packet_size: pktSize) = channel
          when winSize - bytes >= 2 * pktSize ->
        :ssh_client_channel.cache_update(cache(d),
                                           r_channel(channel, recv_window_pending: pending + bytes))
        :keep_state_and_data
      r_channel(recv_window_size: winSize,
          recv_window_pending: pending,
          remote_id: id) = channel ->
        :ssh_client_channel.cache_update(cache(d),
                                           r_channel(channel, recv_window_size: winSize + bytes + pending, 
                                                        recv_window_pending: 0))
        msg = :ssh_connection.channel_adjust_window_msg(id,
                                                          bytes + pending)
        {:keep_state, send_msg(msg, d)}
      :undefined ->
        :keep_state_and_data
    end
  end

  def handle_event(:cast, {:reply_request, resp, channelId},
           stateName, d)
      when :erlang.element(1,
                             stateName) == :connected or :erlang.element(1,
                                                                           stateName) == :ext_info do
    case (:ssh_client_channel.cache_lookup(cache(d),
                                             channelId)) do
      r_channel(remote_id: remoteId) when resp == :success or
                                    resp == :failure
                                  ->
        msg = (case (resp) do
                 :success ->
                   :ssh_connection.channel_success_msg(remoteId)
                 :failure ->
                   :ssh_connection.channel_failure_msg(remoteId)
               end)
        update_inet_buffers(r_data(d, :socket))
        {:keep_state, send_msg(msg, d)}
      r_channel() ->
        details = :io_lib.format('Unhandled reply in state ~p:~n~p', [stateName, resp])
        {_Shutdown,
           d1} = :ssh_connection_handler.send_disconnect(2,
                                                           details,
                                                           :ssh_connection_handler,
                                                           861, stateName, d)
        {:keep_state, d1}
      :undefined ->
        :keep_state_and_data
    end
  end

  def handle_event(:cast,
           {:request, channelPid, channelId, type, data},
           stateName, d)
      when :erlang.element(1,
                             stateName) == :connected or :erlang.element(1,
                                                                           stateName) == :ext_info do
    {:keep_state,
       handle_request(channelPid, channelId, type, data, false,
                        :none, d)}
  end

  def handle_event(:cast, {:request, channelId, type, data},
           stateName, d)
      when :erlang.element(1,
                             stateName) == :connected or :erlang.element(1,
                                                                           stateName) == :ext_info do
    {:keep_state,
       handle_request(channelId, type, data, false, :none, d)}
  end

  def handle_event(:cast, {:unknown, data}, stateName, d)
      when :erlang.element(1,
                             stateName) == :connected or :erlang.element(1,
                                                                           stateName) == :ext_info do
    msg = r_ssh_msg_unimplemented(sequence: data)
    {:keep_state, send_msg(msg, d)}
  end

  def handle_event(:cast, {:global_request, type, data}, stateName,
           d)
      when :erlang.element(1,
                             stateName) == :connected or :erlang.element(1,
                                                                           stateName) == :ext_info do
    {:keep_state,
       send_msg(:ssh_connection.request_global_msg(type, false,
                                                     data),
                  d)}
  end

  def handle_event({:call, from}, :get_print_info, stateName, d) do
    reply = (try do
               {:inet.sockname(r_data(d, :socket)),
                  :inet.peername(r_data(d, :socket))}
             catch
               _, _ ->
                 {{'?', 0}, '?'}
             else
               {{:ok, local}, {:ok, remote}} ->
                 {{local, remote}, :io_lib.format('statename=~p', [stateName])}
               _ ->
                 {{'-', 0}, '-'}
             end)
    {:keep_state_and_data, [{:reply, from, reply}]}
  end

  def handle_event({:call, from}, {:connection_info, options}, _,
           d) do
    info = fold_keys(options, &conn_info/2, d)
    {:keep_state_and_data, [{:reply, from, info}]}
  end

  def handle_event({:call, from},
           {:channel_info, channelId, options}, _, d) do
    case (:ssh_client_channel.cache_lookup(cache(d),
                                             channelId)) do
      r_channel() = channel ->
        info = fold_keys(options, &chann_info/2, channel)
        {:keep_state_and_data, [{:reply, from, info}]}
      :undefined ->
        {:keep_state_and_data, [{:reply, from, []}]}
    end
  end

  def handle_event({:call, from}, {:info, :all}, _, d) do
    result = :ssh_client_channel.cache_foldl(fn channel,
                                                  acc ->
                                                  [channel | acc]
                                             end,
                                               [], cache(d))
    {:keep_state_and_data, [{:reply, from, {:ok, result}}]}
  end

  def handle_event({:call, from}, {:info, channelPid}, _, d) do
    result = :ssh_client_channel.cache_foldl(fn channel, acc
                                                    when r_channel(channel, :user) == channelPid
                                                         ->
                                                  [channel | acc]
                                                _, acc ->
                                                  acc
                                             end,
                                               [], cache(d))
    {:keep_state_and_data, [{:reply, from, {:ok, result}}]}
  end

  def handle_event({:call, from}, {:set_sock_opts, socketOptions},
           _StateName, d) do
    result = (try do
                :inet.setopts(r_data(d, :socket), socketOptions)
              catch
                _, _ ->
                  {:error, :badarg}
              end)
    {:keep_state_and_data, [{:reply, from, result}]}
  end

  def handle_event({:call, from},
           {:get_sock_opts, socketGetOptions}, _StateName, d) do
    result = (try do
                :inet.getopts(r_data(d, :socket), socketGetOptions)
              catch
                _, _ ->
                  {:error, :badarg}
              end)
    {:keep_state_and_data, [{:reply, from, result}]}
  end

  def handle_event({:call, from}, :stop, _StateName, d0) do
    {repls,
       d} = send_replies(:ssh_connection.handle_stop(r_data(d0, :connection_state)),
                           d0)
    {:stop_and_reply, :normal,
       [{:reply, from, :ok} | repls], d}
  end

  def handle_event({:call, _}, _, stateName, _) when not
                                           (:erlang.element(1,
                                                              stateName) == :connected or :erlang.element(1,
                                                                                                            stateName) == :ext_info) do
    {:keep_state_and_data, [:postpone]}
  end

  def handle_event({:call, from},
           {:request, channelPid, channelId, type, data, timeout},
           stateName, d0)
      when :erlang.element(1,
                             stateName) == :connected or :erlang.element(1,
                                                                           stateName) == :ext_info do
    case (handle_request(channelPid, channelId, type, data,
                           true, from, d0)) do
      {:error, error} ->
        {:keep_state, d0, {:reply, from, {:error, error}}}
      d ->
        start_channel_request_timer(channelId, from, timeout)
        {:keep_state, d, cond_set_idle_timer(d)}
    end
  end

  def handle_event({:call, from},
           {:request, channelId, type, data, timeout}, stateName,
           d0)
      when :erlang.element(1,
                             stateName) == :connected or :erlang.element(1,
                                                                           stateName) == :ext_info do
    case (handle_request(channelId, type, data, true, from,
                           d0)) do
      {:error, error} ->
        {:keep_state, d0, {:reply, from, {:error, error}}}
      d ->
        start_channel_request_timer(channelId, from, timeout)
        {:keep_state, d, cond_set_idle_timer(d)}
    end
  end

  def handle_event({:call, from},
           {:global_request, 'tcpip-forward' = type,
              {listenHost, listenPort, connectToHost, connectToPort},
              timeout},
           stateName, d0)
      when :erlang.element(1,
                             stateName) == :connected or :erlang.element(1,
                                                                           stateName) == :ext_info do
    id = make_ref()
    data = <<byte_size(listenHost)
             ::
             size(32) - unsigned - big - integer,
               listenHost :: binary,
               listenPort :: size(32) - unsigned - big - integer>>
    fun = fn {:success,
                <<port :: size(32) - unsigned - integer>>},
               c ->
               key = {:tcpip_forward, listenHost, port}
               value = {connectToHost, connectToPort}
               r_connection(c, options: :ssh_options.put_value(:internal_options,
                                                      {key, value},
                                                      r_connection(c, :options),
                                                      :ssh_connection_handler,
                                                      981))
             {:success, <<>>}, c ->
               key = {:tcpip_forward, listenHost, listenPort}
               value = {connectToHost, connectToPort}
               r_connection(c, options: :ssh_options.put_value(:internal_options,
                                                      {key, value},
                                                      r_connection(c, :options),
                                                      :ssh_connection_handler,
                                                      985))
             _, c ->
               c
          end
    d = send_msg(:ssh_connection.request_global_msg(type,
                                                      true, data),
                   add_request(fun, id, from, d0))
    start_channel_request_timer(id, from, timeout)
    {:keep_state, d, cond_set_idle_timer(d)}
  end

  def handle_event({:call, from},
           {:global_request, type, data, timeout}, stateName, d0)
      when :erlang.element(1,
                             stateName) == :connected or :erlang.element(1,
                                                                           stateName) == :ext_info do
    id = make_ref()
    d = send_msg(:ssh_connection.request_global_msg(type,
                                                      true, data),
                   add_request(true, id, from, d0))
    start_channel_request_timer(id, from, timeout)
    {:keep_state, d, cond_set_idle_timer(d)}
  end

  def handle_event({:call, from},
           {:data, channelId, type, data, timeout}, stateName, d0)
      when :erlang.element(1,
                             stateName) == :connected or :erlang.element(1,
                                                                           stateName) == :ext_info do
    {repls,
       d} = send_replies(:ssh_connection.channel_data(channelId,
                                                        type, data,
                                                        r_data(d0, :connection_state),
                                                        from),
                           d0)
    start_channel_request_timer(channelId, from, timeout)
    {:keep_state, d, repls}
  end

  def handle_event({:call, from}, {:eof, channelId}, stateName, d0)
      when :erlang.element(1,
                             stateName) == :connected or :erlang.element(1,
                                                                           stateName) == :ext_info do
    case (:ssh_client_channel.cache_lookup(cache(d0),
                                             channelId)) do
      r_channel(remote_id: id, sent_close: false) ->
        d = send_msg(:ssh_connection.channel_eof_msg(id), d0)
        {:keep_state, d, [{:reply, from, :ok}]}
      _ ->
        {:keep_state, d0, [{:reply, from, {:error, :closed}}]}
    end
  end

  def handle_event({:call, from}, :get_misc, stateName,
           r_data(connection_state: r_connection(options: opts)) = d)
      when :erlang.element(1,
                             stateName) == :connected or :erlang.element(1,
                                                                           stateName) == :ext_info do
    subSysSup = :ssh_options.get_value(:internal_options,
                                         :subsystem_sup, opts,
                                         :ssh_connection_handler, 1020)
    reply = {:ok,
               {subSysSup, :erlang.element(2, stateName), opts}}
    {:keep_state, d, [{:reply, from, reply}]}
  end

  def handle_event({:call, from},
           {:open, channelPid, type, initialWindowSize,
              maxPacketSize, data, timeout},
           stateName, d0 = r_data(connection_state: c))
      when :erlang.element(1,
                             stateName) == :connected or :erlang.element(1,
                                                                           stateName) == :ext_info do
    :erlang.monitor(:process, channelPid)
    {channelId, d1} = new_channel_id(d0)
    winSz = (case (initialWindowSize) do
               :undefined ->
                 r_connection(c, :suggest_window_size)
               _ ->
                 initialWindowSize
             end)
    pktSz = (case (maxPacketSize) do
               :undefined ->
                 r_connection(c, :suggest_packet_size)
               _ ->
                 maxPacketSize
             end)
    d2 = send_msg(:ssh_connection.channel_open_msg(type,
                                                     channelId, winSz, pktSz,
                                                     data),
                    d1)
    :ssh_client_channel.cache_update(cache(d2),
                                       r_channel(type: type, sys: 'none', user: channelPid,
                                           local_id: channelId,
                                           recv_window_size: winSz,
                                           recv_packet_size: pktSz,
                                           send_buf: :queue.new()))
    d = add_request(true, channelId, from, d2)
    start_channel_request_timer(channelId, from, timeout)
    {:keep_state, d, cond_set_idle_timer(d)}
  end

  def handle_event({:call, from}, {:send_window, channelId},
           stateName, d)
      when :erlang.element(1,
                             stateName) == :connected or :erlang.element(1,
                                                                           stateName) == :ext_info do
    reply = (case (:ssh_client_channel.cache_lookup(cache(d),
                                                      channelId)) do
               r_channel(send_window_size: winSize,
                   send_packet_size: packsize) ->
                 {:ok, {winSize, packsize}}
               :undefined ->
                 {:error, :einval}
             end)
    {:keep_state_and_data, [{:reply, from, reply}]}
  end

  def handle_event({:call, from}, {:recv_window, channelId},
           stateName, d)
      when :erlang.element(1,
                             stateName) == :connected or :erlang.element(1,
                                                                           stateName) == :ext_info do
    reply = (case (:ssh_client_channel.cache_lookup(cache(d),
                                                      channelId)) do
               r_channel(recv_window_size: winSize,
                   recv_packet_size: packsize) ->
                 {:ok, {winSize, packsize}}
               :undefined ->
                 {:error, :einval}
             end)
    {:keep_state_and_data, [{:reply, from, reply}]}
  end

  def handle_event({:call, from}, {:close, channelId}, stateName,
           d0)
      when :erlang.element(1,
                             stateName) == :connected or :erlang.element(1,
                                                                           stateName) == :ext_info do
    case (:ssh_client_channel.cache_lookup(cache(d0),
                                             channelId)) do
      r_channel(remote_id: id) = channel ->
        d1 = send_msg(:ssh_connection.channel_close_msg(id), d0)
        :ssh_client_channel.cache_update(cache(d1),
                                           r_channel(channel, sent_close: true))
        {:keep_state, d1,
           [cond_set_idle_timer(d1), {:reply, from, :ok}]}
      :undefined ->
        {:keep_state_and_data, [{:reply, from, :ok}]}
    end
  end

  def handle_event(:cast, {:store, key, value}, _StateName,
           r_data(connection_state: c0) = d) do
    c = r_connection(c0, options: :ssh_options.put_value(:internal_options,
                                                {key, value}, r_connection(c0, :options),
                                                :ssh_connection_handler, 1087))
    {:keep_state, r_data(d, connection_state: c)}
  end

  def handle_event({:call, from}, {:retrieve, key}, _StateName,
           r_data(connection_state: c)) do
    case (retrieve(c, key)) do
      {:ok, value} ->
        {:keep_state_and_data, [{:reply, from, {:ok, value}}]}
      _ ->
        {:keep_state_and_data, [{:reply, from, :undefined}]}
    end
  end

  def handle_event(:info, {proto, sock, info}, {:hello, _},
           r_data(socket: sock, transport_protocol: proto)) do
    case (info) do
      'SSH-' ++ _ ->
        {:keep_state_and_data,
           [{:next_event, :internal, {:version_exchange, info}}]}
      _ ->
        {:keep_state_and_data,
           [{:next_event, :internal, {:info_line, info}}]}
    end
  end

  def handle_event(:info, {proto, sock, newData}, stateName,
           d0 = r_data(socket: sock, transport_protocol: proto,
                    ssh_params: sshParams)) do
    try do
      :ssh_transport.handle_packet_part(r_data(d0, :decrypted_data_buffer),
                                          <<r_data(d0, :encrypted_data_buffer)
                                            ::
                                            binary,
                                              newData :: binary>>,
                                          r_data(d0, :aead_data),
                                          r_data(d0, :undecrypted_packet_length),
                                          r_data(d0, :ssh_params))
    catch
      c, e ->
        maxLogItemLen = :ssh_options.get_value(:user_options,
                                                 :max_log_item_len,
                                                 r_ssh(sshParams, :opts),
                                                 :ssh_connection_handler, 1194)
        {shutdown,
           d} = :ssh_connection_handler.send_disconnect(2,
                                                          :io_lib.format('Bad packet: Couldn\'t decrypt~n~p:~p~n~P',
                                                                           [c,
                                                                                e,
                                                                                    __STACKTRACE__,
                                                                                        maxLogItemLen]),
                                                          :ssh_connection_handler,
                                                          1198, stateName, d0)
        {:stop, shutdown, d}
    else
      {:packet_decrypted, decryptedBytes, encryptedDataRest,
         ssh1} ->
        d1 = r_data(d0, ssh_params: r_ssh(ssh1, recv_sequence: :ssh_transport.next_seqnum(r_ssh(ssh1, :recv_sequence))), 
                     decrypted_data_buffer: <<>>, 
                     undecrypted_packet_length: :undefined, 
                     aead_data: <<>>, 
                     encrypted_data_buffer: encryptedDataRest)
        try do
          :ssh_message.decode(set_kex_overload_prefix(decryptedBytes,
                                                        d1))
        catch
          c, e ->
            maxLogItemLen = :ssh_options.get_value(:user_options,
                                                     :max_log_item_len,
                                                     r_ssh(sshParams, :opts),
                                                     :ssh_connection_handler,
                                                     1159)
            {shutdown,
               d} = :ssh_connection_handler.send_disconnect(2,
                                                              :io_lib.format('Bad packet: Decrypted, but can\'t decode~n~p:~p~n~P',
                                                                               [c,
                                                                                    e,
                                                                                        __STACKTRACE__,
                                                                                            maxLogItemLen]),
                                                              :ssh_connection_handler,
                                                              1163, stateName,
                                                              d1)
            {:stop, shutdown, d}
        else
          r_ssh_msg_kexinit() = msg ->
            {:keep_state, d1,
               [{:next_event, :internal, :prepare_next_packet},
                    {:next_event, :internal, {msg, decryptedBytes}}]}
          r_ssh_msg_global_request() = msg ->
            {:keep_state, d1,
               [{:next_event, :internal, :prepare_next_packet},
                    {:next_event, :internal, {:conn_msg, msg}}]}
          r_ssh_msg_request_success() = msg ->
            {:keep_state, d1,
               [{:next_event, :internal, :prepare_next_packet},
                    {:next_event, :internal, {:conn_msg, msg}}]}
          r_ssh_msg_request_failure() = msg ->
            {:keep_state, d1,
               [{:next_event, :internal, :prepare_next_packet},
                    {:next_event, :internal, {:conn_msg, msg}}]}
          r_ssh_msg_channel_open() = msg ->
            {:keep_state, d1,
               [{{:timeout, :max_initial_idle_time}, :cancel},
                    {:next_event, :internal, :prepare_next_packet},
                        {:next_event, :internal, {:conn_msg, msg}}]}
          r_ssh_msg_channel_open_confirmation() = msg ->
            {:keep_state, d1,
               [{:next_event, :internal, :prepare_next_packet},
                    {:next_event, :internal, {:conn_msg, msg}}]}
          r_ssh_msg_channel_open_failure() = msg ->
            {:keep_state, d1,
               [{:next_event, :internal, :prepare_next_packet},
                    {:next_event, :internal, {:conn_msg, msg}}]}
          r_ssh_msg_channel_window_adjust() = msg ->
            {:keep_state, d1,
               [{:next_event, :internal, :prepare_next_packet},
                    {:next_event, :internal, {:conn_msg, msg}}]}
          r_ssh_msg_channel_data() = msg ->
            {:keep_state, d1,
               [{:next_event, :internal, :prepare_next_packet},
                    {:next_event, :internal, {:conn_msg, msg}}]}
          r_ssh_msg_channel_extended_data() = msg ->
            {:keep_state, d1,
               [{:next_event, :internal, :prepare_next_packet},
                    {:next_event, :internal, {:conn_msg, msg}}]}
          r_ssh_msg_channel_eof() = msg ->
            {:keep_state, d1,
               [{:next_event, :internal, :prepare_next_packet},
                    {:next_event, :internal, {:conn_msg, msg}}]}
          r_ssh_msg_channel_close() = msg ->
            {:keep_state, d1,
               [{:next_event, :internal, :prepare_next_packet},
                    {:next_event, :internal, {:conn_msg, msg}}]}
          r_ssh_msg_channel_request() = msg ->
            {:keep_state, d1,
               [{:next_event, :internal, :prepare_next_packet},
                    {:next_event, :internal, {:conn_msg, msg}}]}
          r_ssh_msg_channel_failure() = msg ->
            {:keep_state, d1,
               [{:next_event, :internal, :prepare_next_packet},
                    {:next_event, :internal, {:conn_msg, msg}}]}
          r_ssh_msg_channel_success() = msg ->
            {:keep_state, d1,
               [{:next_event, :internal, :prepare_next_packet},
                    {:next_event, :internal, {:conn_msg, msg}}]}
          msg ->
            {:keep_state, d1,
               [{:next_event, :internal, :prepare_next_packet},
                    {:next_event, :internal, msg}]}
        end
      {:get_more, decryptedBytes, encryptedDataRest, aeadData,
         remainingSshPacketLen, ssh1} ->
        :inet.setopts(sock, [{:active, :once}])
        {:keep_state,
           r_data(d0, encrypted_data_buffer: encryptedDataRest, 
                   decrypted_data_buffer: decryptedBytes, 
                   undecrypted_packet_length: remainingSshPacketLen, 
                   aead_data: aeadData,  ssh_params: ssh1)}
      {:bad_mac, ssh1} ->
        {shutdown,
           d} = :ssh_connection_handler.send_disconnect(2, 'Bad packet: bad mac',
                                                          :ssh_connection_handler,
                                                          1181, stateName,
                                                          r_data(d0, ssh_params: ssh1))
        {:stop, shutdown, d}
      {:error, {:exceeds_max_size, packetLen}} ->
        {shutdown,
           d} = :ssh_connection_handler.send_disconnect(2,
                                                          :io_lib.format('Bad packet: Size (~p bytes) exceeds max size',
                                                                           [packetLen]),
                                                          :ssh_connection_handler,
                                                          1189, stateName, d0)
        {:stop, shutdown, d}
    end
  end

  def handle_event(:internal, :prepare_next_packet, _StateName,
           d) do
    enough = :erlang.max(8,
                           r_ssh(r_data(d, :ssh_params), :decrypt_block_size))
    case (byte_size(r_data(d, :encrypted_data_buffer))) do
      sz when sz >= enough ->
        send(self(), {r_data(d, :transport_protocol), r_data(d, :socket),
                        <<>>})
      _ ->
        :ok
    end
    :inet.setopts(r_data(d, :socket), [{:active, :once}])
    :keep_state_and_data
  end

  def handle_event(:info, {closeTag, socket}, _StateName,
           d0 = r_data(socket: socket, transport_close_tag: closeTag,
                    connection_state: c0)) do
    {repls,
       d} = send_replies(:ssh_connection.handle_stop(c0), d0)
    disconnect_fun('Received a transport close', d)
    {:stop_and_reply, {:shutdown, 'Connection closed'}, repls, d}
  end

  def handle_event(:info, {:timeout, {_, from} = request}, _,
           r_data(connection_state: r_connection(requests: requests) = c0) = d) do
    case (:lists.member(request, requests)) do
      true ->
        c = r_connection(c0, requests: :lists.delete(request, requests))
        {:keep_state, r_data(d, connection_state: c),
           [{:reply, from, {:error, :timeout}}]}
      false ->
        :keep_state_and_data
    end
  end

  def handle_event(:info,
           {:DOWN, _Ref, :process, channelPid, _Reason}, _, d) do
    cache = cache(d)
    :ssh_client_channel.cache_foldl(fn r_channel(user: u,
                                           local_id: id),
                                         acc
                                           when u == channelPid ->
                                         :ssh_client_channel.cache_delete(cache,
                                                                            id)
                                         acc
                                       _, acc ->
                                         acc
                                    end,
                                      [], cache)
    {:keep_state, d, cond_set_idle_timer(d)}
  end

  def handle_event({:timeout, :idle_time}, _Data, _StateName, d) do
    case (:ssh_client_channel.cache_info(:num_entries,
                                           cache(d))) do
      0 ->
        {:stop, {:shutdown, 'Timeout'}}
      _ ->
        :keep_state_and_data
    end
  end

  def handle_event({:timeout, :max_initial_idle_time}, _Data,
           _StateName, _D) do
    {:stop, {:shutdown, 'Timeout'}}
  end

  def handle_event(:info, {:EXIT, _Sup, reason}, stateName, _D) do
    role = :erlang.element(2, stateName)
    cond do
      role == :client ->
        {:stop, {:shutdown, reason}}
      reason == :normal ->
        :keep_state_and_data
      true ->
        {:stop, {:shutdown, reason}}
    end
  end

  def handle_event(:info, :check_cache, _, d) do
    {:keep_state, d, cond_set_idle_timer(d)}
  end

  def handle_event(:info,
           {:fwd_connect_received, sock, chId, chanCB}, stateName,
           r_data(connection_state: connection)) do
    r_connection(options: options, channel_cache: cache,
        sub_system_supervisor: subSysSup) = connection
    channel = :ssh_client_channel.cache_lookup(cache, chId)
    {:ok,
       pid} = :ssh_subsystem_sup.start_channel(:erlang.element(2,
                                                                 stateName),
                                                 subSysSup, self(), chanCB,
                                                 chId, [sock], :undefined,
                                                 options)
    :ssh_client_channel.cache_update(cache,
                                       r_channel(channel, user: pid))
    :gen_tcp.controlling_process(sock, pid)
    :inet.setopts(sock, [{:active, :once}])
    :keep_state_and_data
  end

  def handle_event({:call, from},
           {:handle_direct_tcpip, listenHost, listenPort,
              connectToHost, connectToPort, _Timeout},
           _StateName,
           r_data(connection_state: r_connection(sub_system_supervisor: subSysSup))) do
    case (:ssh_tcpip_forward_acceptor.supervised_start(:ssh_subsystem_sup.tcpip_fwd_supervisor(subSysSup),
                                                         {listenHost,
                                                            listenPort},
                                                         {connectToHost,
                                                            connectToPort},
                                                         'direct-tcpip',
                                                         :ssh_tcpip_forward_client,
                                                         self())) do
      {:ok, lPort} ->
        {:keep_state_and_data, [{:reply, from, {:ok, lPort}}]}
      {:error, error} ->
        {:keep_state_and_data,
           [{:reply, from, {:error, error}}]}
    end
  end

  def handle_event(:info, unexpectedMessage, stateName,
           d = r_data(ssh_params: ssh)) do
    case (unexpected_fun(unexpectedMessage, d)) do
      :report ->
        msg = :lists.flatten(:io_lib.format('*** SSH: Unexpected message \'~p\' received in state \'~p\'\nRole: ~p\nPeer: ~p\nLocal Address: ~p\n',
                                              [unexpectedMessage, stateName,
                                                                      r_ssh(ssh, :role),
                                                                          r_ssh(ssh, :peer),
                                                                              :ssh_options.get_value(:internal_options,
                                                                                                       :address,
                                                                                                       r_ssh(ssh, :opts),
                                                                                                       fn () ->
                                                                                                            :undefined
                                                                                                       end,
                                                                                                       :ssh_connection_handler,
                                                                                                       1321)]))
        :error_logger.info_report(msg)
        :keep_state_and_data
      :skip ->
        :keep_state_and_data
      other ->
        msg = :lists.flatten(:io_lib.format('*** SSH: Call to fun in \'unexpectedfun\' failed:~nReturn: ~p\nMessage: ~p\nRole: ~p\nPeer: ~p\nLocal Address: ~p\n',
                                              [other, unexpectedMessage,
                                                          r_ssh(ssh, :role),
                                                              r_ssh(ssh, :peer),
                                                                  :ssh_options.get_value(:internal_options,
                                                                                           :address,
                                                                                           r_ssh(ssh, :opts),
                                                                                           fn () ->
                                                                                                :undefined
                                                                                           end,
                                                                                           :ssh_connection_handler,
                                                                                           1341)]))
        :error_logger.error_report(msg)
        :keep_state_and_data
    end
  end

  def handle_event(:internal,
           {:send_disconnect, code, detailedText, module, line},
           stateName, d0) do
    {shutdown, d} = send_disconnect(code, detailedText,
                                      module, line, stateName, d0)
    {:stop, shutdown, d}
  end

  def handle_event(:enter, _OldState, state, d) do
    {:next_state, state, d}
  end

  def handle_event(_Type, _Msg, {:ext_info, role, _ReNegFlag}, d) do
    {:next_state, {:connected, role}, d, [:postpone]}
  end

  def handle_event(type, ev, stateName, d0) do
    details = (case ((try do
                       :erlang.atom_to_list(:erlang.element(1, ev))
                     catch
                       :error, e -> {:EXIT, {e, __STACKTRACE__}}
                       :exit, e -> {:EXIT, e}
                       e -> e
                     end)) do
                 'ssh_msg_' ++ _ when type == :internal ->
                   :lists.flatten(:io_lib.format('Message ~p in wrong state (~p)',
                                                   [:erlang.element(1, ev),
                                                        stateName]))
                 _ ->
                   :io_lib.format('Unhandled event in state ~p and type ~p:~n~p', [stateName, type, ev])
               end)
    {shutdown,
       d} = :ssh_connection_handler.send_disconnect(2, details,
                                                      :ssh_connection_handler,
                                                      1370, stateName, d0)
    {:stop, shutdown, d}
  end

  def terminate(_, {:wait_for_socket, _}, _) do
    :ok
  end

  def terminate(:normal, _StateName, d) do
    close_transport(d)
  end

  def terminate({:shutdown, _R}, _StateName, d) do
    close_transport(d)
  end

  def terminate(:shutdown, _StateName, d0) do
    d = send_msg(r_ssh_msg_disconnect(code: 11, description: 'Terminated (shutdown) by supervisor'), d0)
    close_transport(d)
  end

  def terminate(reason, stateName, d0) do
    log(:error, d0, reason)
    {_ShutdownReason,
       d} = :ssh_connection_handler.send_disconnect(11, 'Internal error',
                                                      :io_lib.format('Reason: ~p',
                                                                       [reason]),
                                                      :ssh_connection_handler,
                                                      1406, stateName, d0)
    close_transport(d)
  end

  def format_status(a, b) do
    try do
      format_status0(a, b)
    catch
      _, _ ->
        '????'
    end
  end

  defp format_status0(:normal, [_PDict, _StateName, d]) do
    [{:data, [{'State', d}]}]
  end

  defp format_status0(:terminate, [_, _StateName, d]) do
    [{:data, [{'State', clean(d)}]}]
  end

  defp clean(r_data() = r) do
    fmt_stat_rec(Keyword.keys(r_data(r_data())), r,
                   [:decrypted_data_buffer, :encrypted_data_buffer,
                                                :key_exchange_init_msg,
                                                    :user_passwords, :opts,
                                                                         :inet_initial_recbuf_size])
  end

  defp clean(r_ssh() = r) do
    fmt_stat_rec(Keyword.keys(r_ssh(r_ssh())), r,
                   [:c_keyinit, :s_keyinit, :send_mac_key, :send_mac_size,
                                                               :recv_mac_key,
                                                                   :recv_mac_size,
                                                                       :encrypt_keys,
                                                                           :encrypt_ctx,
                                                                               :decrypt_keys,
                                                                                   :decrypt_ctx,
                                                                                       :compress_ctx,
                                                                                           :decompress_ctx,
                                                                                               :shared_secret,
                                                                                                   :exchanged_hash,
                                                                                                       :session_id,
                                                                                                           :keyex_key,
                                                                                                               :keyex_info,
                                                                                                                   :available_host_keys])
  end

  defp clean(r_connection() = r) do
    fmt_stat_rec(Keyword.keys(r_connection(r_connection())), r, [])
  end

  defp clean(l) when is_list(l) do
    :lists.map(&clean/1, l)
  end

  defp clean(t) when is_tuple(t) do
    :erlang.list_to_tuple(clean(:erlang.tuple_to_list(t)))
  end

  defp clean(x) do
    :ssh_options.no_sensitive(:filter, x)
  end

  defp fmt_stat_rec(fieldNames, rec, exclude) do
    values = tl(:erlang.tuple_to_list(rec))
    :erlang.list_to_tuple([:erlang.element(1, rec) |
                               :lists.map(fn {k, v} ->
                                               case (:lists.member(k,
                                                                     exclude)) do
                                                 true ->
                                                   :"****"
                                                 false ->
                                                   clean(v)
                                               end
                                          end,
                                            :lists.zip(fieldNames, values))])
  end

  def code_change(_OldVsn, stateName, state, _Extra) do
    {:ok, stateName, state}
  end

  defp close_transport(r_data(transport_cb: transport, socket: socket)) do
    (try do
      transport.close(socket)
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end)
    :ok
  end

  def available_hkey_algorithms(:client, options) do
    case (available_hkey_algos(options)) do
      [] ->
        :erlang.error({:shutdown, 'No public key algs'})
      algs ->
        for a <- algs do
          :erlang.atom_to_list(a)
        end
    end
  end

  def available_hkey_algorithms(:server, options) do
    case (for a <- available_hkey_algos(options),
                is_usable_host_key(a, options) do
            a
          end) do
      [] ->
        :erlang.error({:shutdown, 'No host key available'})
      algs ->
        for a <- algs do
          :erlang.atom_to_list(a)
        end
    end
  end

  defp available_hkey_algos(options) do
    supAlgos = :ssh_transport.supported_algorithms(:public_key)
    hKeys = :proplists.get_value(:public_key,
                                   :ssh_options.get_value(:user_options,
                                                            :preferred_algorithms,
                                                            options,
                                                            :ssh_connection_handler,
                                                            1521))
    nonSupported = hKeys -- supAlgos
    availableAndSupported = hKeys -- nonSupported
    availableAndSupported
  end

  def send_msg(msg, state = r_data(ssh_params: ssh0))
      when is_tuple(msg) do
    {bytes, ssh} = :ssh_transport.ssh_packet(msg, ssh0)
    send_bytes(bytes, state)
    r_data(state, ssh_params: ssh)
  end

  def send_bytes('', _D) do
    :ok
  end

  def send_bytes(bytes,
           r_data(socket: socket, transport_cb: transport)) do
    _ = transport.send(socket, bytes)
    :ok
  end

  defp handle_version({2, 0} = numVsn, strVsn, ssh0) do
    ssh = counterpart_versions(numVsn, strVsn, ssh0)
    {:ok, ssh}
  end

  defp handle_version(_, _, _) do
    :not_supported
  end

  defp string_version(r_ssh(role: :client, c_version: vsn)) do
    vsn
  end

  defp string_version(r_ssh(role: :server, s_version: vsn)) do
    vsn
  end

  defp cast(fsmPid, event) do
    :gen_statem.cast(fsmPid, event)
  end

  defp call(fsmPid, event) do
    call(fsmPid, event, :infinity)
  end

  defp call(fsmPid, event, timeout) do
    try do
      :gen_statem.call(fsmPid, event, timeout)
    catch
      :exit, {:noproc, _R} ->
        {:error, :closed}
      :exit, {:normal, _R} ->
        {:error, :closed}
      :exit, {{:shutdown, _R}, _} ->
        {:error, :closed}
      :exit, {:shutdown, _R} ->
        {:error, :closed}
    else
      {:closed, _R} ->
        {:error, :closed}
      {:killed, _R} ->
        {:error, :closed}
      result ->
        result
    end
  end

  defp set_kex_overload_prefix(msg = <<op
                  ::
                  size(8) - unsigned - big - integer,
                    _ :: binary>>,
            r_data(ssh_params: sshParams))
      when op == 30 or op == 31 do
    case ((try do
            :erlang.atom_to_list(kex(sshParams))
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      'ecdh-sha2-' ++ _ ->
        <<"ecdh", msg :: binary>>
      'curve25519-' ++ _ ->
        <<"ecdh", msg :: binary>>
      'curve448-' ++ _ ->
        <<"ecdh", msg :: binary>>
      'diffie-hellman-group-exchange-' ++ _ ->
        <<"dh_gex", msg :: binary>>
      'diffie-hellman-group' ++ _ ->
        <<"dh", msg :: binary>>
      _ ->
        msg
    end
  end

  defp set_kex_overload_prefix(msg, _) do
    msg
  end

  defp kex(r_ssh(algorithms: r_alg(kex: kex))) do
    kex
  end

  defp kex(_) do
    :undefined
  end

  defp cache(r_data(connection_state: c)) do
    r_connection(c, :channel_cache)
  end

  def handle_ssh_msg_ext_info(r_ssh_msg_ext_info(),
           d = r_data(ssh_params: r_ssh(recv_ext_info: false))) do
    d
  end

  def handle_ssh_msg_ext_info(r_ssh_msg_ext_info(data: data), d0) do
    :lists.foldl(&ext_info/2, d0, data)
  end

  defp ext_info({'server-sig-algs', sigAlgsStr},
            d0 = r_data(ssh_params: r_ssh(role: :client,
                                   userauth_pubkeys: clientSigAlgs) = ssh0)) do
    sigAlgs = (for astr <- :string.tokens(sigAlgsStr, ','),
                     a <- (try do
                             [:erlang.list_to_existing_atom(astr)]
                           catch
                             _, _ ->
                               []
                           end) do
                 a
               end)
    commonAlgs = (for a <- sigAlgs,
                        :lists.member(a, clientSigAlgs) do
                    a
                  end)
    r_data(d0, ssh_params: r_ssh(ssh0, userauth_pubkeys: commonAlgs ++ clientSigAlgs -- commonAlgs))
  end

  defp ext_info(_, d0) do
    d0
  end

  defp is_usable_user_pubkey(alg, ssh) do
    try do
      :ssh_auth.get_public_key(alg, ssh)
    catch
      _, _ ->
        false
    else
      {:ok, _} ->
        true
      _ ->
        false
    end
  end

  defp is_usable_host_key(alg, opts) do
    try do
      :ssh_transport.get_host_key(alg, opts)
    catch
      _, _ ->
        false
    else
      _PrivHostKey ->
        true
    end
  end

  defp handle_request(channelPid, channelId, type, data, wantReply,
            from, d) do
    case (:ssh_client_channel.cache_lookup(cache(d),
                                             channelId)) do
      r_channel(remote_id: id, sent_close: false) = channel ->
        update_sys(cache(d), channel, type, channelPid)
        send_msg(:ssh_connection.channel_request_msg(id, type,
                                                       wantReply, data),
                   add_request(wantReply, channelId, from, d))
      _ when wantReply == true ->
        {:error, :closed}
      _ ->
        d
    end
  end

  defp handle_request(channelId, type, data, wantReply, from, d) do
    case (:ssh_client_channel.cache_lookup(cache(d),
                                             channelId)) do
      r_channel(remote_id: id, sent_close: false) ->
        send_msg(:ssh_connection.channel_request_msg(id, type,
                                                       wantReply, data),
                   add_request(wantReply, channelId, from, d))
      _ when wantReply == true ->
        {:error, :closed}
      _ ->
        d
    end
  end

  defp update_sys(cache, channel, type, channelPid) do
    :ssh_client_channel.cache_update(cache,
                                       r_channel(channel, sys: type,  user: channelPid))
  end

  defp add_request(false, _ChannelId, _From, state) do
    state
  end

  defp add_request(true, channelId, from,
            r_data(connection_state: r_connection(requests: requests0) = connection) = state) do
    requests = [{channelId, from} | requests0]
    r_data(state, connection_state: r_connection(connection, requests: requests))
  end

  defp add_request(fun, channelId, from,
            r_data(connection_state: r_connection(requests: requests0) = connection) = state)
      when is_function(fun) do
    requests = [{channelId, from, fun} | requests0]
    r_data(state, connection_state: r_connection(connection, requests: requests))
  end

  defp new_channel_id(r_data(connection_state: r_connection(channel_id_seed: id) = connection) = state) do
    {id,
       r_data(state, connection_state: r_connection(connection, channel_id_seed: id + 1))}
  end

  defp start_rekeying(role, d0) do
    {keyInitMsg, sshPacket,
       ssh} = :ssh_transport.key_exchange_init_msg(r_data(d0, :ssh_params))
    send_bytes(sshPacket, d0)
    d = r_data(d0, ssh_params: ssh, 
                key_exchange_init_msg: keyInitMsg)
    {:next_state, {:kexinit, role, :renegotiate}, d,
       {:change_callback_module, :ssh_fsm_kexinit}}
  end

  defp init_renegotiate_timers(_OldState, newState, d) do
    {rekeyTimeout,
       _MaxSent} = :ssh_options.get_value(:user_options,
                                            :rekey_limit,
                                            r_ssh(r_data(d, :ssh_params), :opts),
                                            :ssh_connection_handler, 1731)
    {:next_state, newState, d,
       [{{:timeout, :renegotiate}, rekeyTimeout, :none},
            {{:timeout, :check_data_size}, 60000, :none}]}
  end

  defp pause_renegotiate_timers(_OldState, newState, d) do
    {:next_state, newState, d,
       [{{:timeout, :renegotiate}, :infinity, :none},
            {{:timeout, :check_data_size}, :infinity, :none}]}
  end

  defp check_data_rekeying(role, d) do
    case (:inet.getstat(r_data(d, :socket), [:send_oct])) do
      {:ok, [{:send_oct, socketSentTotal}]} ->
        sentSinceRekey = socketSentTotal - r_data(d, :last_size_rekey)
        {_RekeyTimeout,
           maxSent} = :ssh_options.get_value(:user_options,
                                               :rekey_limit,
                                               r_ssh(r_data(d, :ssh_params), :opts),
                                               :ssh_connection_handler, 1744)
        case (check_data_rekeying_dbg(sentSinceRekey,
                                        maxSent)) do
          true ->
            start_rekeying(role,
                             r_data(d, last_size_rekey: socketSentTotal))
          _ ->
            {:keep_state, d,
               {{:timeout, :check_data_size}, 60000, :none}}
        end
      {:error, _} ->
        {:keep_state, d,
           {{:timeout, :check_data_size}, 60000, :none}}
    end
  end

  defp check_data_rekeying_dbg(sentSinceRekey, maxSent) do
    sentSinceRekey >= maxSent
  end

  def send_disconnect(code, detailedText, module, line, stateName,
           d) do
    send_disconnect(code, default_text(code), detailedText,
                      module, line, stateName, d)
  end

  def send_disconnect(code, reason, detailedText, module, line,
           stateName, d0) do
    msg = r_ssh_msg_disconnect(code: code, description: reason)
    d = send_msg(msg, d0)
    logMsg = :io_lib.format('Disconnects with code = ~p [RFC4253 11.1]: ~s', [code, reason])
    call_disconnectfun_and_log_cond(logMsg, detailedText,
                                      module, line, stateName, d)
    {{:shutdown, reason}, d}
  end

  defp call_disconnectfun_and_log_cond(logMsg, detailedText, module, line, stateName,
            d) do
    case (disconnect_fun(logMsg, d)) do
      :void ->
        log(:info, d, '~s~nState = ~p~nModule = ~p, Line = ~p.~nDetails:~n  ~s~n',
              [logMsg, stateName, module, line, detailedText])
      _ ->
        :ok
    end
  end

  defp default_text(1) do
    'Host not allowed to connect'
  end

  defp default_text(2) do
    'Protocol error'
  end

  defp default_text(3) do
    'Key exchange failed'
  end

  defp default_text(4) do
    'Reserved'
  end

  defp default_text(5) do
    'Mac error'
  end

  defp default_text(6) do
    'Compression error'
  end

  defp default_text(7) do
    'Service not available'
  end

  defp default_text(8) do
    'Protocol version not supported'
  end

  defp default_text(9) do
    'Host key not verifiable'
  end

  defp default_text(10) do
    'Connection lost'
  end

  defp default_text(11) do
    'By application'
  end

  defp default_text(12) do
    'Too many connections'
  end

  defp default_text(13) do
    'Auth cancelled by user'
  end

  defp default_text(14) do
    'Unable to connect using the available authentication methods'
  end

  defp default_text(15) do
    'Illegal user name'
  end

  defp counterpart_versions(numVsn, strVsn, r_ssh(role: :server) = ssh) do
    r_ssh(ssh, c_vsn: numVsn,  c_version: strVsn)
  end

  defp counterpart_versions(numVsn, strVsn, r_ssh(role: :client) = ssh) do
    r_ssh(ssh, s_vsn: numVsn,  s_version: strVsn)
  end

  defp conn_info_keys() do
    [:client_version, :server_version, :peer, :user,
                                                  :sockname, :options,
                                                                 :algorithms,
                                                                     :channels]
  end

  defp conn_info(:client_version, r_data(ssh_params: s)) do
    {r_ssh(s, :c_vsn), r_ssh(s, :c_version)}
  end

  defp conn_info(:server_version, r_data(ssh_params: s)) do
    {r_ssh(s, :s_vsn), r_ssh(s, :s_version)}
  end

  defp conn_info(:peer, r_data(ssh_params: s)) do
    r_ssh(s, :peer)
  end

  defp conn_info(:user, d) do
    r_data(d, :auth_user)
  end

  defp conn_info(:sockname, r_data(ssh_params: s)) do
    r_ssh(s, :local)
  end

  defp conn_info(:options, r_data(ssh_params: r_ssh(opts: opts))) do
    :lists.sort(:maps.to_list(:ssh_options.keep_set_options(:client,
                                                              :ssh_options.keep_user_options(:client,
                                                                                               opts))))
  end

  defp conn_info(:algorithms, r_data(ssh_params: r_ssh(algorithms: a))) do
    conn_info_alg(a)
  end

  defp conn_info(:channels, d) do
    try do
      conn_info_chans(:ets.tab2list(cache(d)))
    catch
      _, _ ->
        :undefined
    end
  end

  defp conn_info(:socket, d) do
    r_data(d, :socket)
  end

  defp conn_info(:chan_ids, d) do
    :ssh_client_channel.cache_foldl(fn r_channel(local_id: id),
                                         acc ->
                                         [id | acc]
                                    end,
                                      [], cache(d))
  end

  defp conn_info_chans(chs) do
    fs = Keyword.keys(r_channel(r_channel()))
    for (ch = r_channel()) <- chs do
      :lists.zip(fs, tl(:erlang.tuple_to_list(ch)))
    end
  end

  defp conn_info_alg(algTup) do
    [:alg | vs] = :erlang.tuple_to_list(algTup)
    fs = Keyword.keys(r_alg(r_alg()))
    for {k, v} <- :lists.zip(fs, vs),
          :lists.member(k,
                          [:kex, :hkey, :encrypt, :decrypt, :send_mac,
                                                                :recv_mac,
                                                                    :compress,
                                                                        :decompress,
                                                                            :send_ext_info,
                                                                                :recv_ext_info]) do
      {k, v}
    end
  end

  defp chann_info(:recv_window, c) do
    {{:win_size, r_channel(c, :recv_window_size)},
       {:packet_size, r_channel(c, :recv_packet_size)}}
  end

  defp chann_info(:send_window, c) do
    {{:win_size, r_channel(c, :send_window_size)},
       {:packet_size, r_channel(c, :send_packet_size)}}
  end

  defp chann_info(:pid, c) do
    r_channel(c, :user)
  end

  defp fold_keys(keys, fun, extra) do
    :lists.foldr(fn key, acc ->
                      try do
                        fun.(key, extra)
                      catch
                        _, _ ->
                          acc
                      else
                        value ->
                          [{key, value} | acc]
                      end
                 end,
                   [], keys)
  end

  defp log(tag, d, format, args) do
    log(tag, d, :io_lib.format(format, args))
  end

  defp log(tag, d, reason) do
    case (:erlang.atom_to_list(tag)) do
      'error' ->
        do_log(:error_msg, reason, d)
      'warning' ->
        do_log(:warning_msg, reason, d)
      'info' ->
        do_log(:info_msg, reason, d)
    end
  end

  defp do_log(f, reason0, r_data(ssh_params: s)) do
    reason1 = :string.chomp(assure_string(reason0))
    reason = limit_size(reason1,
                          :ssh_options.get_value(:user_options,
                                                   :max_log_item_len,
                                                   r_ssh(s, :opts),
                                                   :ssh_connection_handler,
                                                   1902))
    case (s) do
      r_ssh(role: role) when role == :server or role == :client ->
        {peerRole, peerVersion} = (case (role) do
                                     :server ->
                                       {'Peer client', r_ssh(s, :c_version)}
                                     :client ->
                                       {'Peer server', r_ssh(s, :s_version)}
                                   end)
        apply(:error_logger, f,
                ['Erlang SSH ~p version: ~s ~s.~nAddress: ~s~n~s version: ~p~nPeer address: ~s~n~s~n', [role, ssh_log_version(), crypto_log_info(),
                                                  :ssh_lib.format_address_port(r_ssh(s, :local)),
                                                      peerRole, peerVersion,
                                                                    :ssh_lib.format_address_port(:erlang.element(2,
                                                                                                                   r_ssh(s, :peer))),
                                                                        reason]])
      _ ->
        apply(:error_logger, f,
                ['Erlang SSH ~s ~s.~n~s~n', [ssh_log_version(), crypto_log_info(), reason]])
    end
  end

  defp assure_string(s) do
    try do
      :io_lib.format('~s', [s])
    catch
      _, _ ->
        :io_lib.format('~p', [s])
    else
      formatted ->
        formatted
    end
  end

  defp limit_size(s, maxLen) when is_integer(maxLen) do
    limit_size(s, :lists.flatlength(s), maxLen)
  end

  defp limit_size(s, _) do
    s
  end

  defp limit_size(s, len, maxLen) when len <= maxLen do
    s
  end

  defp limit_size(s, len, maxLen) when len <= maxLen + 5 do
    s
  end

  defp limit_size(s, len, maxLen) when len > maxLen do
    :io_lib.format('~s ... (~w bytes skipped)',
                     [:string.substr(:lists.flatten(s), 1, maxLen),
                          len - maxLen])
  end

  defp crypto_log_info() do
    try do
      [{_, _, cI}] = :crypto.info_lib()
      case (:crypto.info_fips()) do
        :enabled ->
          <<"(", cI :: binary, ". FIPS enabled)">>
        :not_enabled ->
          <<"(", cI :: binary, ". FIPS available but not enabled)">>
        _ ->
          <<"(", cI :: binary, ")">>
      end
    catch
      _, _ ->
        ''
    end
  end

  defp ssh_log_version() do
    case (:application.get_key(:ssh, :vsn)) do
      {:ok, vsn} ->
        vsn
      :undefined ->
        ''
    end
  end

  defp not_connected_filter({:connection_reply, _Data}) do
    true
  end

  defp not_connected_filter(_) do
    false
  end

  defp send_replies({repls, c = r_connection()}, d) when is_list(repls) do
    send_replies(repls, r_data(d, connection_state: c))
  end

  defp send_replies(repls, state) do
    :lists.foldl(&get_repl/2, {[], state}, repls)
  end

  defp get_repl({:connection_reply, msg}, {callRepls, s}) do
    cond do
      elem(msg, 0) === :ssh_msg_channel_success ->
        update_inet_buffers(r_data(s, :socket))
      true ->
        :ok
    end
    {callRepls, send_msg(msg, s)}
  end

  defp get_repl({:channel_data, :undefined, _Data}, acc) do
    acc
  end

  defp get_repl({:channel_data, pid, data}, acc) do
    send(pid, {:ssh_cm, self(), data})
    acc
  end

  defp get_repl({:channel_request_reply, from, data},
            {callRepls, s}) do
    {[{:reply, from, data} | callRepls], s}
  end

  defp get_repl({:flow_control, cache, channel, from, msg},
            {callRepls, s}) do
    :ssh_client_channel.cache_update(cache,
                                       r_channel(channel, flow_control: :undefined))
    {[{:reply, from, msg} | callRepls], s}
  end

  defp get_repl({:flow_control, from, msg}, {callRepls, s}) do
    {[{:reply, from, msg} | callRepls], s}
  end

  defp get_repl(x, acc) do
    exit({:get_repl, x, acc})
  end

  defp disconnect_fun(reason, d) do
    (try do
      (:ssh_options.get_value(:user_options, :disconnectfun,
                                r_ssh(r_data(d, :ssh_params), :opts),
                                :ssh_connection_handler, 2011)).(reason)
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end)
  end

  defp unexpected_fun(unexpectedMessage,
            r_data(ssh_params: r_ssh(peer: {_, peer})) = d) do
    (try do
      (:ssh_options.get_value(:user_options, :unexpectedfun,
                                r_ssh(r_data(d, :ssh_params), :opts),
                                :ssh_connection_handler,
                                2014)).(unexpectedMessage, peer)
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end)
  end

  defp debug_fun(r_ssh_msg_debug(always_display: display, message: dbgMsg,
              language: lang),
            d) do
    (try do
      (:ssh_options.get_value(:user_options,
                                :ssh_msg_debug_fun, r_ssh(r_data(d, :ssh_params), :opts),
                                :ssh_connection_handler, 2020)).(self(),
                                                                   display,
                                                                   dbgMsg, lang)
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end)
  end

  defp cond_set_idle_timer(d) do
    case (:ssh_client_channel.cache_info(:num_entries,
                                           cache(d))) do
      0 ->
        {{:timeout, :idle_time},
           :ssh_options.get_value(:user_options, :idle_time,
                                    r_ssh(r_data(d, :ssh_params), :opts),
                                    :ssh_connection_handler, 2029),
           :none}
      _ ->
        {{:timeout, :idle_time}, :infinity, :none}
    end
  end

  defp start_channel_request_timer(_, _, :infinity) do
    :ok
  end

  defp start_channel_request_timer(channel, from, time) do
    :erlang.send_after(time, self(),
                         {:timeout, {channel, from}})
  end

  defp init_inet_buffers_window(socket) do
    update_inet_buffers(socket)
    {:ok, sockOpts} = :inet.getopts(socket,
                                      [:buffer, :recbuf])
    winSz = :proplists.get_value(:recbuf, sockOpts,
                                   10 * 65536)
    pktSz = min(:proplists.get_value(:buffer, sockOpts,
                                       65536),
                  65536)
    {winSz, pktSz}
  end

  defp update_inet_buffers(socket) do
    try do
      {:ok, bufSzs0} = :inet.getopts(socket,
                                       [:sndbuf, :recbuf])
      minVal = 655360
      for {tag, val} <- bufSzs0, val < minVal do
        {tag, minVal}
      end
    catch
      _, _ ->
        :ok
    else
      [] ->
        :ok
      newOpts ->
        :inet.setopts(socket, newOpts)
        :ok
    end
  end

  def ssh_dbg_trace_points() do
    [:terminate, :disconnect, :connections,
                                  :connection_events, :renegotiation, :tcp,
                                                                          :connection_handshake]
  end

  def ssh_dbg_flags(:connections) do
    [:c | ssh_dbg_flags(:terminate)]
  end

  def ssh_dbg_flags(:renegotiation) do
    [:c]
  end

  def ssh_dbg_flags(:connection_events) do
    [:c]
  end

  def ssh_dbg_flags(:connection_handshake) do
    [:c]
  end

  def ssh_dbg_flags(:terminate) do
    [:c]
  end

  def ssh_dbg_flags(:tcp) do
    [:c]
  end

  def ssh_dbg_flags(:disconnect) do
    [:c]
  end

  def ssh_dbg_on(:connections) do
    :dbg.tp(:ssh_connection_handler, :init, 1, :x)
    ssh_dbg_on(:terminate)
  end

  def ssh_dbg_on(:connection_events) do
    :dbg.tp(:ssh_connection_handler, :handle_event, 4, :x)
  end

  def ssh_dbg_on(:connection_handshake) do
    :dbg.tpl(:ssh_connection_handler, :handshake, 3, :x)
  end

  def ssh_dbg_on(:renegotiation) do
    :dbg.tpl(:ssh_connection_handler,
               :init_renegotiate_timers, 3, :x)
    :dbg.tpl(:ssh_connection_handler,
               :pause_renegotiate_timers, 3, :x)
    :dbg.tpl(:ssh_connection_handler,
               :check_data_rekeying_dbg, 2, :x)
    :dbg.tpl(:ssh_connection_handler, :start_rekeying, 2,
               :x)
    :dbg.tp(:ssh_connection_handler, :renegotiate, 1, :x)
  end

  def ssh_dbg_on(:terminate) do
    :dbg.tp(:ssh_connection_handler, :terminate, 3, :x)
  end

  def ssh_dbg_on(:tcp) do
    :dbg.tp(:ssh_connection_handler, :handle_event, 4,
              [{[:info, {:tcp, :_, :_}, :_, :_], [], []}, {[:info,
                                                                {:tcp_error, :_,
                                                                   :_},
                                                                    :_, :_],
                                                             [], []},
                                                              {[:info,
                                                                    {:tcp_closed,
                                                                       :_},
                                                                        :_, :_],
                                                                 [], []}])
    :dbg.tp(:ssh_connection_handler, :send_bytes, 2, :x)
    :dbg.tpl(:ssh_connection_handler, :close_transport, 1,
               :x)
  end

  def ssh_dbg_on(:disconnect) do
    :dbg.tpl(:ssh_connection_handler, :send_disconnect, 7,
               :x)
  end

  def ssh_dbg_off(:disconnect) do
    :dbg.ctpl(:ssh_connection_handler, :send_disconnect, 7)
  end

  def ssh_dbg_off(:terminate) do
    :dbg.ctpg(:ssh_connection_handler, :terminate, 3)
  end

  def ssh_dbg_off(:tcp) do
    :dbg.ctpg(:ssh_connection_handler, :handle_event, 4)
    :dbg.ctpl(:ssh_connection_handler, :send_bytes, 2)
    :dbg.ctpl(:ssh_connection_handler, :close_transport, 1)
  end

  def ssh_dbg_off(:renegotiation) do
    :dbg.ctpl(:ssh_connection_handler,
                :init_renegotiate_timers, 3)
    :dbg.ctpl(:ssh_connection_handler,
                :pause_renegotiate_timers, 3)
    :dbg.ctpl(:ssh_connection_handler,
                :check_data_rekeying_dbg, 2)
    :dbg.ctpl(:ssh_connection_handler, :start_rekeying, 2)
    :dbg.ctpg(:ssh_connection_handler, :renegotiate, 1)
  end

  def ssh_dbg_off(:connection_events) do
    :dbg.ctpg(:ssh_connection_handler, :handle_event, 4)
  end

  def ssh_dbg_off(:connection_handshake) do
    :dbg.ctpl(:ssh_connection_handler, :handshake, 3)
  end

  def ssh_dbg_off(:connections) do
    :dbg.ctpg(:ssh_connection_handler, :init, 1)
    ssh_dbg_off(:terminate)
  end

  def ssh_dbg_format(:connections,
           {:call,
              {:ssh_connection_handler, :init,
                 [[role, sock, opts]]}}) do
    defaultOpts = :ssh_options.handle_options(role, [])
    excludedKeys = [:internal_options, :user_options]
    nonDefaultOpts = :maps.filter(fn k, v ->
                                       case (:lists.member(k, excludedKeys)) do
                                         true ->
                                           false
                                         false ->
                                           v !== ((try do
                                                    :maps.get(k, defaultOpts)
                                                  catch
                                                    :error, e -> {:EXIT, {e, __STACKTRACE__}}
                                                    :exit, e -> {:EXIT, e}
                                                    e -> e
                                                  end))
                                       end
                                  end,
                                    opts)
    {:ok, {iPp, portp}} = :inet.peername(sock)
    {:ok, {iPs, ports}} = :inet.sockname(sock)
    [:io_lib.format('Starting ~p connection:\n', [role]), :io_lib.format('Socket = ~p, Peer = ~s, Local = ~s,~nNon-default options:~n~p',
                                                 [sock,
                                                      :ssh_lib.format_address_port(iPp,
                                                                                     portp),
                                                          :ssh_lib.format_address_port(iPs,
                                                                                         ports),
                                                              nonDefaultOpts])]
  end

  def ssh_dbg_format(:connections, f) do
    ssh_dbg_format(:terminate, f)
  end

  def ssh_dbg_format(:connection_events,
           {:call,
              {:ssh_connection_handler, :handle_event,
                 [eventType, eventContent, state, _Data]}}) do
    ['Connection event\n', :io_lib.format('EventType: ~p~nEventContent: ~p~nState: ~p~n', [eventType, eventContent, state])]
  end

  def ssh_dbg_format(:connection_events,
           {:return_from,
              {:ssh_connection_handler, :handle_event, 4}, ret}) do
    ['Connection event result\n', :io_lib.format('~p~n',
                         [:ssh_dbg.reduce_state(ret, r_data())])]
  end

  def ssh_dbg_format(:tcp,
           {:call,
              {:ssh_connection_handler, :handle_event,
                 [:info, {:tcp, sock, tcpData}, state, _Data]}}) do
    ['TCP stream data arrived\n', :io_lib.format('State: ~p~nSocket: ~p~nTcpData:~n~s',
                         [state, sock, :ssh_dbg.hex_dump(tcpData,
                                                           [{:max_bytes,
                                                               48}])])]
  end

  def ssh_dbg_format(:tcp,
           {:call,
              {:ssh_connection_handler, :handle_event,
                 [:info, {:tcp_error, sock, msg}, state, _Data]}}) do
    ['TCP stream data ERROR arrived\n', :io_lib.format('State: ~p~nSocket: ~p~nErrorMsg:~p~n', [state, sock, msg])]
  end

  def ssh_dbg_format(:tcp,
           {:call,
              {:ssh_connection_handler, :handle_event,
                 [:info, {:tcp_closed, sock}, state, _Data]}}) do
    ['TCP stream closed\n', :io_lib.format('State: ~p~nSocket: ~p~n', [state, sock])]
  end

  def ssh_dbg_format(:tcp,
           {:return_from,
              {:ssh_connection_handler, :handle_event, 4}, _Ret}) do
    :skip
  end

  def ssh_dbg_format(:tcp,
           {:call,
              {:ssh_connection_handler, :send_bytes, ['', _D]}}) do
    :skip
  end

  def ssh_dbg_format(:tcp,
           {:call,
              {:ssh_connection_handler, :send_bytes,
                 [tcpData, r_data(socket: sock)]}}) do
    ['TCP send stream data\n', :io_lib.format('Socket: ~p~nTcpData:~n~s',
                         [sock, :ssh_dbg.hex_dump(tcpData,
                                                    [{:max_bytes, 48}])])]
  end

  def ssh_dbg_format(:tcp,
           {:return_from,
              {:ssh_connection_handler, :send_bytes, 2}, _R}) do
    :skip
  end

  def ssh_dbg_format(:tcp,
           {:call,
              {:ssh_connection_handler, :close_transport,
                 [r_data(socket: sock)]}}) do
    ['TCP close stream\n', :io_lib.format('Socket: ~p~n', [sock])]
  end

  def ssh_dbg_format(:tcp,
           {:return_from,
              {:ssh_connection_handler, :close_transport, 1}, _R}) do
    :skip
  end

  def ssh_dbg_format(:renegotiation,
           {:call,
              {:ssh_connection_handler, :init_renegotiate_timers,
                 [oldState, newState, d]}}) do
    ['Renegotiation: start timer (init_renegotiate_timers)\n', :io_lib.format('State: ~p  -->  ~p~nrekey_limit: ~p ({ms,bytes})~ncheck_data_size: ~p (ms)~n',
                         [oldState, newState,
                                        :ssh_options.get_value(:user_options,
                                                                 :rekey_limit,
                                                                 r_ssh(r_data(d, :ssh_params), :opts),
                                                                 :ssh_connection_handler,
                                                                 2200),
                                            60000])]
  end

  def ssh_dbg_format(:renegotiation,
           {:return_from,
              {:ssh_connection_handler, :init_renegotiate_timers, 3},
              _Ret}) do
    :skip
  end

  def ssh_dbg_format(:renegotiation,
           {:call,
              {:ssh_connection_handler, :renegotiate,
                 [connectionHandler]}}) do
    ['Renegotiation: renegotiation forced\n', :io_lib.format('~p:renegotiate(~p) called~n',
                         [:ssh_connection_handler, connectionHandler])]
  end

  def ssh_dbg_format(:renegotiation,
           {:return_from,
              {:ssh_connection_handler, :renegotiate, 1}, _Ret}) do
    :skip
  end

  def ssh_dbg_format(:renegotiation,
           {:call,
              {:ssh_connection_handler, :pause_renegotiate_timers,
                 [oldState, newState, _D]}}) do
    ['Renegotiation: pause timers\n', :io_lib.format('State: ~p  -->  ~p~n', [oldState, newState])]
  end

  def ssh_dbg_format(:renegotiation,
           {:return_from,
              {:ssh_connection_handler, :pause_renegotiate_timers, 3},
              _Ret}) do
    :skip
  end

  def ssh_dbg_format(:renegotiation,
           {:call,
              {:ssh_connection_handler, :start_rekeying,
                 [_Role, _D]}}) do
    ['Renegotiation: start rekeying\n']
  end

  def ssh_dbg_format(:renegotiation,
           {:return_from,
              {:ssh_connection_handler, :start_rekeying, 2}, _Ret}) do
    :skip
  end

  def ssh_dbg_format(:renegotiation,
           {:call,
              {:ssh_connection_handler, :check_data_rekeying_dbg,
                 [sentSinceRekey, maxSent]}}) do
    ['Renegotiation: check size of data sent\n', :io_lib.format('TotalSentSinceRekey: ~p~nMaxBeforeRekey: ~p~nStartRekey: ~p~n',
                         [sentSinceRekey, maxSent, sentSinceRekey >= maxSent])]
  end

  def ssh_dbg_format(:renegotiation,
           {:return_from,
              {:ssh_connection_handler, :check_data_rekeying_dbg, 2},
              _Ret}) do
    :skip
  end

  def ssh_dbg_format(:terminate,
           {:call,
              {:ssh_connection_handler, :terminate,
                 [reason, stateName, d]}}) do
    extraInfo = (try do
                   {conn_info(:peer, d), conn_info(:user, d),
                      conn_info(:sockname, d)}
                 catch
                   _, _ ->
                     ''
                 else
                   {{_, {iPp, portp}}, usr, {iPs, ports}}
                       when (is_tuple(iPp) and is_tuple(iPs) and
                               is_integer(portp) and is_integer(ports))
                            ->
                     :io_lib.format('Peer=~s:~p, Local=~s:~p, User=~p',
                                      [:inet.ntoa(iPp), portp, :inet.ntoa(iPs),
                                                                   ports, usr])
                   {peer, usr, sockname} ->
                     :io_lib.format('Peer=~p, Local=~p, User=~p', [peer, sockname, usr])
                 end)
    cond do
      reason == :normal or reason == :shutdown or
        :erlang.element(1, reason) == :shutdown ->
        ['Connection Terminating:\n', :io_lib.format('Reason: ~p, StateName: ~p~n~s', [reason, stateName, extraInfo])]
      true ->
        ['Connection Terminating:\n', :io_lib.format('Reason: ~p, StateName: ~p~n~s~nStateData = ~p',
                             [reason, stateName, extraInfo, clean(d)])]
    end
  end

  def ssh_dbg_format(:renegotiation,
           {:return_from, {:ssh_connection_handler, :terminate, 3},
              _Ret}) do
    :skip
  end

  def ssh_dbg_format(:disconnect,
           {:call,
              {:ssh_connection_handler, :send_disconnect,
                 [code, reason, detailedText, module, line, stateName,
                                                                _D]}}) do
    ['Disconnecting:\n', :io_lib.format(' Module = ~p, Line = ~p, StateName = ~p,~n Code = ~p, Reason = ~p,~n DetailedText =~n ~p',
                         [module, line, stateName, code, reason,
                                                             :lists.flatten(detailedText)])]
  end

  def ssh_dbg_format(:renegotiation,
           {:return_from,
              {:ssh_connection_handler, :send_disconnect, 7},
              _Ret}) do
    :skip
  end

  def ssh_dbg_format(:connection_handshake,
           {:call,
              {:ssh_connection_handler, :handshake,
                 [pid, ref, timeout]}},
           stack) do
    {['Connection handshake\n', :io_lib.format('Connection Child: ~p~nReg: ~p~nTimeout: ~p~n', [pid, ref, timeout])],
       [pid | stack]}
  end

  def ssh_dbg_format(:connection_handshake,
           {tag, {:ssh_connection_handler, :handshake, 3}, ret},
           [pid | stack]) do
    {[:lists.flatten(:io_lib.format('Connection handshake result ~p\n', [tag])),
          :io_lib.format('Connection Child: ~p~nRet: ~p~n', [pid, ret])],
       stack}
  end

end