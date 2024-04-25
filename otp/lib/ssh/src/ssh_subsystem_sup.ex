defmodule :m_ssh_subsystem_sup do
  use Bitwise
  @behaviour :supervisor
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
  def start_link(role, address = r_address(), id, socket, options) do
    case (:supervisor.start_link(:ssh_subsystem_sup,
                                   [role, address, id, socket, options])) do
      {:error,
         {:shutdown, {:failed_to_start_child, _, error}}} ->
        {:error, error}
      other ->
        other
    end
  end

  def start_channel(role, supPid, connRef, callback, id, args, exec,
           opts) do
    channelSup = channel_supervisor(supPid)
    :ssh_channel_sup.start_child(role, channelSup, connRef,
                                   callback, id, args, exec, opts)
  end

  def tcpip_fwd_supervisor(subSysSup) do
    find_child(:tcpip_forward_acceptor_sup, subSysSup)
  end

  def init([role, address, id, socket, options]) do
    subSysSup = self()
    supFlags = %{strategy: :one_for_all,
                   auto_shutdown: :any_significant, intensity: 0,
                   period: 3600}
    childSpecs = [%{id: :connection, restart: :temporary,
                      type: :worker, significant: true,
                      start:
                      {:ssh_connection_handler, :start_link,
                         [role, address, id, socket,
                                                 :ssh_options.put_value(:internal_options,
                                                                          [{:subsystem_sup,
                                                                              subSysSup}],
                                                                          options,
                                                                          :ssh_subsystem_sup,
                                                                          77)]}},
                      %{id: :channel_sup, restart: :temporary,
                          type: :supervisor,
                          start: {:ssh_channel_sup, :start_link, [options]}},
                          %{id: :tcpip_forward_acceptor_sup,
                              restart: :temporary, type: :supervisor,
                              start:
                              {:ssh_tcpip_forward_acceptor_sup, :start_link,
                                 []}}]
    {:ok, {supFlags, childSpecs}}
  end

  defp channel_supervisor(subSysSup) do
    find_child(:channel_sup, subSysSup)
  end

  defp find_child(id, sup) when is_pid(sup) do
    try do
      {^id, pid, _, _} = :lists.keyfind(id, 1,
                                          :supervisor.which_children(sup))
      pid
    catch
      :exit, {:no_proc, _} ->
        {:error, :no_proc}
      _, _ ->
        {:error, {:id_not_found, :ssh_subsystem_sup, id}}
    end
  end

end