defmodule :m_ssh_info do
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

  def print() do
    print(&:io.format/2)
  end

  def print(f) when is_function(f, 2) do
    f.(~c"~s", [string()])
  end

  def print(file) when is_list(file) do
    {:ok, d} = :file.open(file, [:write])
    print(d)
    :file.close(d)
  end

  def print(d) do
    :io.format(d, ~c"~s", [string()])
  end

  def string() do
    try do
      :supervisor.which_children(:ssh_sup)
    catch
      _, _ ->
        :io_lib.format(~c"Ssh not found~n", [])
    else
      _ ->
        [
          :io_lib.nl(),
          print_general(),
          :io_lib.nl(),
          underline(~c"Client(s)", ?-),
          print_sups(:client, :sshc_sup),
          :io_lib.nl(),
          underline(
            ~c"Daemon(s)",
            ?-
          ),
          print_sups(
            :server,
            :sshd_sup
          ),
          :io_lib.nl()
        ]
    end
  end

  defp print_general() do
    {_Name, slogan, ver} = :lists.keyfind(:ssh, 1, :application.which_applications())

    [
      underline(:io_lib.format(~c"~s  ~s", [slogan, ver]), ?=),
      :io_lib.format(:"This printout is generated ~s. ~n", [datetime()])
    ]
  end

  defp print_sups(role, startPid) do
    walk_tree(role, get_subs_tree(startPid))
  end

  defp get_subs_tree(startPid) do
    :lists.foldl(
      fn
        {id, _, :worker, _} = c, acc ->
          [{c, chspec(startPid, id)} | acc]

        {id, pid, :supervisor, _} = c, acc ->
          [{c, chspec(startPid, id), get_subs_tree(pid)} | acc]
      end,
      [],
      children(startPid)
    )
  end

  defp chspec(sup, id) do
    try do
      :supervisor.get_childspec(sup, id)
    catch
      _, _ ->
        :undefined
    else
      {:ok, spec} ->
        spec

      {:error, _} ->
        :undefined
    end
  end

  defp walk_tree(role, tree) do
    walk_tree(role, tree, _Indent = 0 + 4)
  end

  defp walk_tree(role, [{{_, _, :supervisor, _}, _, _} = h | t], indent) do
    [
      :io_lib.format(:"~s", [format_sup(role, h, indent)])
      | walk_tree(role, t, indent)
    ]
  end

  defp walk_tree(role, [{{_, _, :worker, _}, _} = h | t], indent) do
    [
      :io_lib.format(:"~s", [format_wrk(role, h, indent)])
      | walk_tree(role, t, indent)
    ]
  end

  defp walk_tree(_Role, [], _) do
    ~c""
  end

  defp format_sup(
         :server,
         {{{:ssh_system_sup, localAddress}, pid, :supervisor, [:ssh_system_sup]}, _Spec,
          [
            {{{:ssh_acceptor_sup, address}, accSupPid, :supervisor, [:ssh_acceptor_sup]},
             _AccSupSpec,
             [{{{:ssh_acceptor_sup, address}, accPid, :worker, [:ssh_acceptor]}, _AccSpec}]}
            | children
          ]},
         indent
       ) do
    [
      indent(indent),
      :io_lib.format(
        ~c"Local listen: ~s, Daemon_ref = ~s~n~ssys_sup=~s, acc_sup=~s, acc=~s~n",
        [
          format_address(localAddress),
          print_pid(pid),
          indent(indent),
          print_pid(pid),
          print_pid(accSupPid),
          print_pid(accPid)
        ]
      ),
      walk_tree(:server, children, indent + 4),
      :io_lib.nl()
    ]
  end

  defp format_sup(
         :server,
         {{{:ssh_system_sup, localAddress}, pid, :supervisor, [:ssh_system_sup]}, _Spec,
          children},
         indent
       ) do
    [
      indent(indent),
      :io_lib.format(
        ~c"Local listen: none (was: ~s), Daemon_ref = ~s~n~ssys_sup=~s~n",
        [format_address(localAddress), print_pid(pid), indent(indent), print_pid(pid)]
      ),
      walk_tree(:server, children, indent + 4),
      :io_lib.nl()
    ]
  end

  defp format_sup(
         :client,
         {{{:ssh_system_sup, localAddress}, pid, :supervisor, [:ssh_system_sup]}, _Spec,
          children},
         indent
       ) do
    [
      indent(indent),
      :io_lib.format(
        ~c"Local:  ~s sys_sup=~s~n",
        [format_address(localAddress), print_pid(pid)]
      ),
      walk_tree(:client, children, indent + 4),
      :io_lib.nl()
    ]
  end

  defp format_sup(
         role,
         {{ref, subSysSup, :supervisor, [:ssh_subsystem_sup]}, _SubSysSpec,
          [
            {{:connection, connPid, :worker, [:ssh_connection_handler]}, _ConnSpec}
            | children
          ]},
         indent
       )
       when is_reference(ref) do
    [
      :io_lib.format(
        ~c"~sRemote: ~s (Version: ~s)~n~sConnectionRef=~s, subsys_sup=~s~n",
        [
          indent(indent),
          peer_addr(connPid),
          peer_version(
            role,
            connPid
          ),
          indent(indent),
          print_pid(connPid),
          print_pid(subSysSup)
        ]
      ),
      walk_tree(
        role,
        for {h, _, cs} <- children do
          {h, {:connref, connPid}, cs}
        end,
        indent + 4
      ),
      :io_lib.nl()
    ]
  end

  defp format_sup(
         role,
         {{:channel_sup, pid, :supervisor, [:ssh_channel_sup]}, {:connref, connPid}, children},
         indent
       ) do
    [
      indent(indent),
      case children do
        [] ->
          :io_lib.format(~c"No open channels (chan_sup=~s).~n", [print_pid(pid)])

        _ ->
          cinfo =
            try do
              {:ok, l} = :ssh_connection_handler.info(connPid)
              l
            catch
              _, _ ->
                []
            end

          [
            :io_lib.format(~c"Open channels (chan_sup=~s):~n", [print_pid(pid)]),
            walk_tree(
              role,
              for {chH = {_, chPid, _, _}, _} <- children do
                {chH,
                 :lists.keyfind(
                   chPid,
                   r_channel(:user),
                   cinfo
                 )}
              end,
              indent + 4
            )
          ]
      end
    ]
  end

  defp format_sup(
         role,
         {{:tcpip_forward_acceptor_sup, pid, :supervisor, [:ssh_tcpip_forward_acceptor_sup]},
          {:connref, _ConnPid}, children},
         indent
       ) do
    [
      indent(indent),
      case children do
        [] ->
          :io_lib.format(~c"TCP/IP forwarding not started (fwd_sup=~s)~n", [print_pid(pid)])

        _ ->
          [
            :io_lib.format(~c"TCP/IP forwarding (fwd_sup=~s):~n", [print_pid(pid)]),
            walk_tree(
              role,
              children,
              indent + 4
            )
          ]
      end
    ]
  end

  defp format_sup(role, {h, spec, children}, indent) do
    [
      indent(indent),
      :io_lib.format(
        ~c"?: ~200p ~s ~n",
        [h, print_spec(spec)]
      ),
      walk_tree(role, children, indent + 4)
    ]
  end

  defp format_wrk(
         _Role,
         {{{:ssh_acceptor_sup, address}, pid, :worker, [:ssh_acceptor]}, _Spec},
         indent
       ) do
    [
      indent(indent),
      :io_lib.format(
        ~c"acceptor: ~s ~s~n",
        [format_address(address), print_pid(pid)]
      )
    ]
  end

  defp format_wrk(
         _Role,
         {{{from, to}, pid, :worker, [:ssh_tcpip_forward_acceptor]}, _Spec},
         indent
       ) do
    :io_lib.format(
      ~c"~sssh_tcpip_forward_acceptor ~s From: ~s, To: ~s~n",
      [indent(indent), print_pid(pid), format_address(from), format_address(to)]
    )
  end

  defp format_wrk(_Role, {{ref, pid, :worker, [cb]}, c}, indent)
       when is_reference(ref) do
    str =
      try do
        :io_lib.format(
          ~c"~p: (remote ~p)~s~s",
          [
            r_channel(c, :local_id),
            r_channel(c, :remote_id),
            if_true(
              r_channel(c, :sent_close),
              ~c" sent_close"
            ),
            if_true(
              r_channel(c, :recv_close),
              ~c" recv_close"
            )
          ]
        )
      catch
        _, _ ->
          ~c"?:"
      end

    chCb =
      try do
        case cb do
          :ssh_server_channel ->
            :io_lib.format(~c" ~s", [cb.get_print_info(pid, :channel_cb)])

          :ssh_client_channel ->
            :io_lib.format(~c" ~s", [cb.get_print_info(pid, :channel_cb)])

          _ ->
            ~c""
        end
      catch
        _, _ ->
          ~c""
      end

    [
      indent(indent),
      :io_lib.format(
        ~c"ch ~s ~p~s ~s~n",
        [str, cb, chCb, print_pid(pid)]
      )
    ]
  end

  defp format_wrk(_Role, {h, spec}, indent) do
    [
      indent(indent),
      :io_lib.format(
        ~c"?: ~200p ~s~n",
        [h, print_spec(spec)]
      )
    ]
  end

  defp if_true(true, str) do
    str
  end

  defp if_true(_, _) do
    ~c""
  end

  defp peer_version(role, pid) do
    try do
      key =
        case role do
          :client ->
            :server_version

          :server ->
            :client_version
        end

      [{^key, {{_, _}, v}}] =
        :ssh_connection_handler.connection_info(
          pid,
          [key]
        )

      v
    catch
      _, _ ->
        ~c"?"
    end
  end

  defp peer_addr(pid) do
    try do
      [{:peer, {_, addrPort}}] =
        :ssh_connection_handler.connection_info(
          pid,
          [:peer]
        )

      :ssh_lib.format_address_port(addrPort)
    catch
      _, _ ->
        ~c"?"
    end
  end

  defp format_address(r_address(address: addr, port: port, profile: prof)) do
    :io_lib.format(
      ~c"~s (profile ~p)",
      [:ssh_lib.format_address_port({addr, port}), prof]
    )
  end

  defp format_address(a) do
    :io_lib.format(~c"~p", [a])
  end

  defp print_pid(pid) do
    :io_lib.format(~c"~p~s", [pid, dead_or_alive(pid)])
  end

  defp dead_or_alive(name) when is_atom(name) do
    case :erlang.whereis(name) do
      :undefined ->
        ~c" **UNDEFINED**"

      pid ->
        dead_or_alive(pid)
    end
  end

  defp dead_or_alive(pid) when is_pid(pid) do
    case :erlang.process_info(pid, :message_queue_len) do
      :undefined ->
        ~c" ***DEAD***"

      {:message_queue_len, n} when n > 10 ->
        :io_lib.format(~c" ***msg_queue_len: ~p***", [n])

      {:message_queue_len, n} when n > 0 ->
        :io_lib.format(~c" (msg_queue_len: ~p)", [n])

      _ ->
        ~c""
    end
  end

  defp indent(i) do
    :io_lib.format(:"~*c", [i, ?\s])
  end

  defp children(pid) do
    parent = self()

    helper =
      spawn(fn ->
        send(parent, {self(), :supervisor.which_children(pid)})
      end)

    receive do
      {^helper, l} when is_list(l) ->
        l
    after
      2000 ->
        try do
          :erlang.exit(helper, :kill)
        catch
          :error, e -> {:EXIT, {e, __STACKTRACE__}}
          :exit, e -> {:EXIT, e}
          e -> e
        end

        []
    end
  end

  defp print_spec(_Spec) do
    ~c""
  end

  defp underline(str, lineChar) do
    :io_lib.format(
      :"~s~n~*c~n",
      [str, :lists.flatlength(str), lineChar]
    )
  end

  defp datetime() do
    {{yYYY, mM, dD}, {h, m, s}} = :calendar.now_to_universal_time(:erlang.timestamp())

    :lists.flatten(
      :io_lib.format(
        :"~4w-~2..0w-~2..0w ~2..0w:~2..0w:~2..0w UTC",
        [yYYY, mM, dD, h, m, s]
      )
    )
  end
end
