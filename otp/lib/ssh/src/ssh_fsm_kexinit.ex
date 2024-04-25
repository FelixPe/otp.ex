defmodule :m_ssh_fsm_kexinit do
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

  Record.defrecord(:r_ssh_msg_disconnect, :ssh_msg_disconnect,
    code: :undefined,
    description: :undefined,
    language: :undefined
  )

  Record.defrecord(:r_ssh_msg_ignore, :ssh_msg_ignore, data: :undefined)
  Record.defrecord(:r_ssh_msg_unimplemented, :ssh_msg_unimplemented, sequence: :undefined)

  Record.defrecord(:r_ssh_msg_debug, :ssh_msg_debug,
    always_display: :undefined,
    message: :undefined,
    language: :undefined
  )

  Record.defrecord(:r_ssh_msg_service_request, :ssh_msg_service_request, name: :undefined)
  Record.defrecord(:r_ssh_msg_service_accept, :ssh_msg_service_accept, name: :undefined)

  Record.defrecord(:r_ssh_msg_ext_info, :ssh_msg_ext_info,
    nr_extensions: :undefined,
    data: :undefined
  )

  Record.defrecord(:r_ssh_msg_kexinit, :ssh_msg_kexinit,
    cookie: :undefined,
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
    reserved: 0
  )

  Record.defrecord(:r_ssh_msg_kexdh_init, :ssh_msg_kexdh_init, e: :undefined)

  Record.defrecord(:r_ssh_msg_kexdh_reply, :ssh_msg_kexdh_reply,
    public_host_key: :undefined,
    f: :undefined,
    h_sig: :undefined
  )

  Record.defrecord(:r_ssh_msg_newkeys, :ssh_msg_newkeys, [])

  Record.defrecord(:r_ssh_msg_kex_dh_gex_request, :ssh_msg_kex_dh_gex_request,
    min: :undefined,
    n: :undefined,
    max: :undefined
  )

  Record.defrecord(:r_ssh_msg_kex_dh_gex_request_old, :ssh_msg_kex_dh_gex_request_old,
    n: :undefined
  )

  Record.defrecord(:r_ssh_msg_kex_dh_gex_group, :ssh_msg_kex_dh_gex_group,
    p: :undefined,
    g: :undefined
  )

  Record.defrecord(:r_ssh_msg_kex_dh_gex_init, :ssh_msg_kex_dh_gex_init, e: :undefined)

  Record.defrecord(:r_ssh_msg_kex_dh_gex_reply, :ssh_msg_kex_dh_gex_reply,
    public_host_key: :undefined,
    f: :undefined,
    h_sig: :undefined
  )

  Record.defrecord(:r_ssh_msg_kex_ecdh_init, :ssh_msg_kex_ecdh_init, q_c: :undefined)

  Record.defrecord(:r_ssh_msg_kex_ecdh_reply, :ssh_msg_kex_ecdh_reply,
    public_host_key: :undefined,
    q_s: :undefined,
    h_sig: :undefined
  )

  Record.defrecord(:r_ssh_msg_userauth_request, :ssh_msg_userauth_request,
    user: :undefined,
    service: :undefined,
    method: :undefined,
    data: :undefined
  )

  Record.defrecord(:r_ssh_msg_userauth_failure, :ssh_msg_userauth_failure,
    authentications: :undefined,
    partial_success: :undefined
  )

  Record.defrecord(:r_ssh_msg_userauth_success, :ssh_msg_userauth_success, [])

  Record.defrecord(:r_ssh_msg_userauth_banner, :ssh_msg_userauth_banner,
    message: :undefined,
    language: :undefined
  )

  Record.defrecord(:r_ssh_msg_userauth_passwd_changereq, :ssh_msg_userauth_passwd_changereq,
    prompt: :undefined,
    language: :undefined
  )

  Record.defrecord(:r_ssh_msg_userauth_pk_ok, :ssh_msg_userauth_pk_ok,
    algorithm_name: :undefined,
    key_blob: :undefined
  )

  Record.defrecord(:r_ssh_msg_userauth_info_request, :ssh_msg_userauth_info_request,
    name: :undefined,
    instruction: :undefined,
    language_tag: :undefined,
    num_prompts: :undefined,
    data: :undefined
  )

  Record.defrecord(:r_ssh_msg_userauth_info_response, :ssh_msg_userauth_info_response,
    num_responses: :undefined,
    data: :undefined
  )

  Record.defrecord(:r_ssh_msg_global_request, :ssh_msg_global_request,
    name: :undefined,
    want_reply: :undefined,
    data: :undefined
  )

  Record.defrecord(:r_ssh_msg_request_success, :ssh_msg_request_success, data: :undefined)
  Record.defrecord(:r_ssh_msg_request_failure, :ssh_msg_request_failure, [])

  Record.defrecord(:r_ssh_msg_channel_open, :ssh_msg_channel_open,
    channel_type: :undefined,
    sender_channel: :undefined,
    initial_window_size: :undefined,
    maximum_packet_size: :undefined,
    data: :undefined
  )

  Record.defrecord(:r_ssh_msg_channel_open_confirmation, :ssh_msg_channel_open_confirmation,
    recipient_channel: :undefined,
    sender_channel: :undefined,
    initial_window_size: :undefined,
    maximum_packet_size: :undefined,
    data: :undefined
  )

  Record.defrecord(:r_ssh_msg_channel_open_failure, :ssh_msg_channel_open_failure,
    recipient_channel: :undefined,
    reason: :undefined,
    description: :undefined,
    lang: :undefined
  )

  Record.defrecord(:r_ssh_msg_channel_window_adjust, :ssh_msg_channel_window_adjust,
    recipient_channel: :undefined,
    bytes_to_add: :undefined
  )

  Record.defrecord(:r_ssh_msg_channel_data, :ssh_msg_channel_data,
    recipient_channel: :undefined,
    data: :undefined
  )

  Record.defrecord(:r_ssh_msg_channel_extended_data, :ssh_msg_channel_extended_data,
    recipient_channel: :undefined,
    data_type_code: :undefined,
    data: :undefined
  )

  Record.defrecord(:r_ssh_msg_channel_eof, :ssh_msg_channel_eof, recipient_channel: :undefined)

  Record.defrecord(:r_ssh_msg_channel_close, :ssh_msg_channel_close,
    recipient_channel: :undefined
  )

  Record.defrecord(:r_ssh_msg_channel_request, :ssh_msg_channel_request,
    recipient_channel: :undefined,
    request_type: :undefined,
    want_reply: :undefined,
    data: :undefined
  )

  Record.defrecord(:r_ssh_msg_channel_success, :ssh_msg_channel_success,
    recipient_channel: :undefined
  )

  Record.defrecord(:r_ssh_msg_channel_failure, :ssh_msg_channel_failure,
    recipient_channel: :undefined
  )

  Record.defrecord(:r_channel, :channel,
    type: :undefined,
    sys: :undefined,
    user: :undefined,
    flow_control: :undefined,
    local_id: :undefined,
    recv_window_size: :undefined,
    recv_window_pending: 0,
    recv_packet_size: :undefined,
    recv_close: false,
    remote_id: :undefined,
    send_window_size: :undefined,
    send_packet_size: :undefined,
    sent_close: false,
    send_buf: []
  )

  Record.defrecord(:r_connection, :connection,
    requests: [],
    channel_cache: :undefined,
    channel_id_seed: :undefined,
    cli_spec: :undefined,
    options: :undefined,
    suggest_window_size: :undefined,
    suggest_packet_size: :undefined,
    exec: :undefined,
    sub_system_supervisor: :undefined
  )

  Record.defrecord(:r_data, :data,
    starter: :undefined,
    auth_user: :undefined,
    connection_state: :undefined,
    latest_channel_id: 0,
    transport_protocol: :undefined,
    transport_cb: :undefined,
    transport_close_tag: :undefined,
    ssh_params: :undefined,
    socket: :undefined,
    decrypted_data_buffer: <<>>,
    encrypted_data_buffer: <<>>,
    aead_data: <<>>,
    undecrypted_packet_length: :undefined,
    key_exchange_init_msg: :undefined,
    last_size_rekey: 0,
    event_queue: [],
    inet_initial_recbuf_size: :undefined
  )

  def callback_mode() do
    [:handle_event_function, :state_enter]
  end

  def handle_event(
        :internal,
        {r_ssh_msg_kexinit() = kex, payload},
        {:kexinit, role, reNeg},
        d = r_data(key_exchange_init_msg: ownKex)
      ) do
    ssh1 = :ssh_transport.key_init(peer_role(role), r_data(d, :ssh_params), payload)

    ssh =
      case :ssh_transport.handle_kexinit_msg(kex, ownKex, ssh1, reNeg) do
        {:ok, nextKexMsg, ssh2} when role == :client ->
          :ssh_connection_handler.send_bytes(nextKexMsg, d)
          ssh2

        {:ok, ssh2} when role == :server ->
          ssh2
      end

    {:next_state, {:key_exchange, role, reNeg}, r_data(d, ssh_params: ssh)}
  end

  def handle_event(:internal, r_ssh_msg_kexdh_init() = msg, {:key_exchange, :server, reNeg}, d) do
    {:ok, kexdhReply, ssh1} =
      :ssh_transport.handle_kexdh_init(
        msg,
        r_data(d, :ssh_params)
      )

    :ssh_connection_handler.send_bytes(kexdhReply, d)
    {:ok, newKeys, ssh2} = :ssh_transport.new_keys_message(ssh1)
    :ssh_connection_handler.send_bytes(newKeys, d)
    {:ok, extInfo, ssh} = :ssh_transport.ext_info_message(ssh2)
    :ssh_connection_handler.send_bytes(extInfo, d)
    {:next_state, {:new_keys, :server, reNeg}, r_data(d, ssh_params: ssh)}
  end

  def handle_event(:internal, r_ssh_msg_kexdh_reply() = msg, {:key_exchange, :client, reNeg}, d) do
    {:ok, newKeys, ssh1} =
      :ssh_transport.handle_kexdh_reply(
        msg,
        r_data(d, :ssh_params)
      )

    :ssh_connection_handler.send_bytes(newKeys, d)
    {:ok, extInfo, ssh} = :ssh_transport.ext_info_message(ssh1)
    :ssh_connection_handler.send_bytes(extInfo, d)
    {:next_state, {:new_keys, :client, reNeg}, r_data(d, ssh_params: ssh)}
  end

  def handle_event(
        :internal,
        r_ssh_msg_kex_dh_gex_request() = msg,
        {:key_exchange, :server, reNeg},
        d
      ) do
    {:ok, gexGroup, ssh1} =
      :ssh_transport.handle_kex_dh_gex_request(
        msg,
        r_data(d, :ssh_params)
      )

    :ssh_connection_handler.send_bytes(gexGroup, d)
    ssh = :ssh_transport.parallell_gen_key(ssh1)
    {:next_state, {:key_exchange_dh_gex_init, :server, reNeg}, r_data(d, ssh_params: ssh)}
  end

  def handle_event(
        :internal,
        r_ssh_msg_kex_dh_gex_request_old() = msg,
        {:key_exchange, :server, reNeg},
        d
      ) do
    {:ok, gexGroup, ssh1} =
      :ssh_transport.handle_kex_dh_gex_request(
        msg,
        r_data(d, :ssh_params)
      )

    :ssh_connection_handler.send_bytes(gexGroup, d)
    ssh = :ssh_transport.parallell_gen_key(ssh1)
    {:next_state, {:key_exchange_dh_gex_init, :server, reNeg}, r_data(d, ssh_params: ssh)}
  end

  def handle_event(
        :internal,
        r_ssh_msg_kex_dh_gex_group() = msg,
        {:key_exchange, :client, reNeg},
        d
      ) do
    {:ok, kexGexInit, ssh} =
      :ssh_transport.handle_kex_dh_gex_group(
        msg,
        r_data(d, :ssh_params)
      )

    :ssh_connection_handler.send_bytes(kexGexInit, d)
    {:next_state, {:key_exchange_dh_gex_reply, :client, reNeg}, r_data(d, ssh_params: ssh)}
  end

  def handle_event(:internal, r_ssh_msg_kex_ecdh_init() = msg, {:key_exchange, :server, reNeg}, d) do
    {:ok, kexEcdhReply, ssh1} =
      :ssh_transport.handle_kex_ecdh_init(
        msg,
        r_data(d, :ssh_params)
      )

    :ssh_connection_handler.send_bytes(kexEcdhReply, d)
    {:ok, newKeys, ssh2} = :ssh_transport.new_keys_message(ssh1)
    :ssh_connection_handler.send_bytes(newKeys, d)
    {:ok, extInfo, ssh} = :ssh_transport.ext_info_message(ssh2)
    :ssh_connection_handler.send_bytes(extInfo, d)
    {:next_state, {:new_keys, :server, reNeg}, r_data(d, ssh_params: ssh)}
  end

  def handle_event(
        :internal,
        r_ssh_msg_kex_ecdh_reply() = msg,
        {:key_exchange, :client, reNeg},
        d
      ) do
    {:ok, newKeys, ssh1} =
      :ssh_transport.handle_kex_ecdh_reply(
        msg,
        r_data(d, :ssh_params)
      )

    :ssh_connection_handler.send_bytes(newKeys, d)
    {:ok, extInfo, ssh} = :ssh_transport.ext_info_message(ssh1)
    :ssh_connection_handler.send_bytes(extInfo, d)
    {:next_state, {:new_keys, :client, reNeg}, r_data(d, ssh_params: ssh)}
  end

  def handle_event(
        :internal,
        r_ssh_msg_kex_dh_gex_init() = msg,
        {:key_exchange_dh_gex_init, :server, reNeg},
        d
      ) do
    {:ok, kexGexReply, ssh1} =
      :ssh_transport.handle_kex_dh_gex_init(
        msg,
        r_data(d, :ssh_params)
      )

    :ssh_connection_handler.send_bytes(kexGexReply, d)
    {:ok, newKeys, ssh2} = :ssh_transport.new_keys_message(ssh1)
    :ssh_connection_handler.send_bytes(newKeys, d)
    {:ok, extInfo, ssh} = :ssh_transport.ext_info_message(ssh2)
    :ssh_connection_handler.send_bytes(extInfo, d)
    {:next_state, {:new_keys, :server, reNeg}, r_data(d, ssh_params: ssh)}
  end

  def handle_event(
        :internal,
        r_ssh_msg_kex_dh_gex_reply() = msg,
        {:key_exchange_dh_gex_reply, :client, reNeg},
        d
      ) do
    {:ok, newKeys, ssh1} =
      :ssh_transport.handle_kex_dh_gex_reply(
        msg,
        r_data(d, :ssh_params)
      )

    :ssh_connection_handler.send_bytes(newKeys, d)
    {:ok, extInfo, ssh} = :ssh_transport.ext_info_message(ssh1)
    :ssh_connection_handler.send_bytes(extInfo, d)
    {:next_state, {:new_keys, :client, reNeg}, r_data(d, ssh_params: ssh)}
  end

  def handle_event(:internal, r_ssh_msg_newkeys() = msg, {:new_keys, :client, :init}, d0) do
    {:ok, ssh1} =
      :ssh_transport.handle_new_keys(
        msg,
        r_data(d0, :ssh_params)
      )

    {msgReq, ssh} = :ssh_auth.service_request_msg(ssh1)

    d =
      :ssh_connection_handler.send_msg(
        msgReq,
        r_data(d0, ssh_params: ssh)
      )

    {:next_state, {:ext_info, :client, :init}, d}
  end

  def handle_event(:internal, r_ssh_msg_newkeys() = msg, {:new_keys, :server, :init}, d) do
    {:ok, ssh} =
      :ssh_transport.handle_new_keys(
        msg,
        r_data(d, :ssh_params)
      )

    {:next_state, {:ext_info, :server, :init}, r_data(d, ssh_params: ssh)}
  end

  def handle_event(:internal, r_ssh_msg_newkeys() = msg, {:new_keys, role, :renegotiate}, d) do
    {:ok, ssh} =
      :ssh_transport.handle_new_keys(
        msg,
        r_data(d, :ssh_params)
      )

    {:next_state, {:ext_info, role, :renegotiate}, r_data(d, ssh_params: ssh)}
  end

  def handle_event(:internal, r_ssh_msg_ext_info() = msg, {:ext_info, role, :init}, d0) do
    d =
      :ssh_connection_handler.handle_ssh_msg_ext_info(
        msg,
        d0
      )

    {:next_state, {:service_request, role}, d, {:change_callback_module, :ssh_connection_handler}}
  end

  def handle_event(:internal, r_ssh_msg_ext_info() = msg, {:ext_info, role, :renegotiate}, d0) do
    d =
      :ssh_connection_handler.handle_ssh_msg_ext_info(
        msg,
        d0
      )

    {:next_state, {:connected, role}, d, {:change_callback_module, :ssh_connection_handler}}
  end

  def handle_event(:internal, r_ssh_msg_newkeys() = msg, {:ext_info, _Role, :renegotiate}, d) do
    {:ok, ssh} =
      :ssh_transport.handle_new_keys(
        msg,
        r_data(d, :ssh_params)
      )

    {:keep_state, r_data(d, ssh_params: ssh)}
  end

  def handle_event(:internal, msg, {:ext_info, role, :init}, d)
      when is_tuple(msg) do
    {:next_state, {:service_request, role}, d,
     [:postpone, {:change_callback_module, :ssh_connection_handler}]}
  end

  def handle_event(:internal, msg, {:ext_info, role, :renegotiate}, d)
      when is_tuple(msg) do
    {:next_state, {:connected, role}, d,
     [:postpone, {:change_callback_module, :ssh_connection_handler}]}
  end

  def handle_event(type, event, stateName, d) do
    :ssh_connection_handler.handle_event(type, event, stateName, d)
  end

  def format_status(a, b) do
    :ssh_connection_handler.format_status(a, b)
  end

  def terminate(reason, stateName, d) do
    :ssh_connection_handler.terminate(reason, stateName, d)
  end

  def code_change(_OldVsn, stateName, state, _Extra) do
    {:ok, stateName, state}
  end

  defp peer_role(:client) do
    :server
  end

  defp peer_role(:server) do
    :client
  end
end
