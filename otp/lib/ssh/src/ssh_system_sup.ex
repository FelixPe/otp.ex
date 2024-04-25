defmodule :m_ssh_system_sup do
  use Bitwise
  @behaviour :supervisor
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

  def start_system(role, address0, options) do
    case find_system_sup(role, address0) do
      {:ok, {sysPid, address}} when role === :server ->
        restart_acceptor(sysPid, address, options)

      {:ok, {sysPid, _}} ->
        {:ok, sysPid}

      {:error, :not_found} ->
        :supervisor.start_child(
          sup(role),
          %{
            id: {:ssh_system_sup, address0},
            start: {:ssh_system_sup, :start_link, [role, address0, options]},
            restart: :temporary,
            type: :supervisor
          }
        )
    end
  end

  def stop_system(role, sysSup) when is_pid(sysSup) do
    case :lists.keyfind(sysSup, 2, :supervisor.which_children(sup(role))) do
      {{:ssh_system_sup, id}, ^sysSup, _, _} ->
        stop_system(role, id)

      false ->
        :undefined
    end
  end

  def stop_system(role, id) do
    :supervisor.terminate_child(
      sup(role),
      {:ssh_system_sup, id}
    )
  end

  def stop_listener(systemSup) when is_pid(systemSup) do
    {id, _, _, _} = lookup(:ssh_acceptor_sup, systemSup)
    :supervisor.terminate_child(systemSup, id)
    :supervisor.delete_child(systemSup, id)
  end

  def get_daemon_listen_address(systemSup) do
    try do
      lookup(:ssh_acceptor_sup, systemSup)
    catch
      _, _ ->
        {:error, :not_found}
    else
      {{:ssh_acceptor_sup, address}, _, _, _} ->
        {:ok, address}

      _ ->
        {:error, :not_found}
    end
  end

  def start_subsystem(role, address = r_address(), socket, options0) do
    options =
      :ssh_options.put_value(
        :internal_options,
        [{:user_pid, self()}],
        options0,
        :ssh_system_sup,
        100
      )

    id = make_ref()

    case get_system_sup(role, address, options) do
      {:ok, sysPid} ->
        case :supervisor.start_child(
               sysPid,
               %{
                 id: id,
                 start: {:ssh_subsystem_sup, :start_link, [role, address, id, socket, options]},
                 restart: :temporary,
                 significant: true,
                 type: :supervisor
               }
             ) do
          {:ok, _SubSysPid} ->
            try do
              receive do
                {:new_connection_ref, ^id, connPid} ->
                  :ssh_connection_handler.takeover(connPid, role, socket, options)
              after
                10000 ->
                  :erlang.error(:timeout)
              end
            catch
              :error, {:badmatch, {:error, error}} ->
                {:error, error}

              :error, :timeout ->
                :supervisor.terminate_child(sysPid, id)
                {:error, :connection_start_timeout}
            end

          others ->
            others
        end

      others ->
        others
    end
  end

  def start_link(role, address, options) do
    :supervisor.start_link(
      :ssh_system_sup,
      [role, address, options]
    )
  end

  def addresses(
        role,
        r_address(address: address, port: port, profile: profile)
      ) do
    for {{:ssh_system_sup, a}, sysSup, :supervisor, _} <- :supervisor.which_children(sup(role)),
        address == :any or r_address(a, :address) == address,
        port == :any or r_address(a, :port) == port,
        profile == :any or r_address(a, :profile) == profile do
      {sysSup, a}
    end
  end

  def get_acceptor_options(sysPid) do
    case get_daemon_listen_address(sysPid) do
      {:ok, address} ->
        get_options(sysPid, address)

      {:error, error} ->
        {:error, error}
    end
  end

  def replace_acceptor_options(sysPid, newOpts) do
    case get_daemon_listen_address(sysPid) do
      {:ok, address} ->
        try do
          stop_listener(sysPid)
        catch
          :error, _ ->
            restart_acceptor(sysPid, address, newOpts)
        else
          :ok ->
            restart_acceptor(sysPid, address, newOpts)
        end

      {:error, error} ->
        {:error, error}
    end
  end

  def init([role, address, options]) do
    supFlags = %{
      strategy: :one_for_one,
      auto_shutdown: :all_significant,
      intensity: 0,
      period: 3600
    }

    childSpecs =
      case {role, is_socket_server(options)} do
        {:server, false} ->
          [acceptor_sup_child_spec(_SysSup = self(), address, options)]

        _ ->
          []
      end

    {:ok, {supFlags, childSpecs}}
  end

  def get_options(sup, address = r_address()) do
    try do
      {:ok, %{start: {:ssh_acceptor_sup, :start_link, [_, _, options]}}} =
        :supervisor.get_childspec(
          sup,
          {:ssh_acceptor_sup, address}
        )

      {:ok, options}
    catch
      _, _ ->
        {:error, :not_found}
    end
  end

  defp acceptor_sup_child_spec(sysSup, address, options) do
    %{
      id: {:ssh_acceptor_sup, address},
      start: {:ssh_acceptor_sup, :start_link, [sysSup, address, options]},
      restart: :transient,
      significant: true,
      type: :supervisor
    }
  end

  defp lookup(supModule, systemSup) do
    :lists.keyfind([supModule], 4, :supervisor.which_children(systemSup))
  end

  defp get_system_sup(role, address0, options) do
    case find_system_sup(role, address0) do
      {:ok, {sysPid, _Address}} ->
        {:ok, sysPid}

      {:error, :not_found} ->
        start_system(role, address0, options)

      {:error, error} ->
        {:error, error}
    end
  end

  defp find_system_sup(role, address0) do
    case addresses(role, address0) do
      [{sysSupPid, address}] ->
        {:ok, {sysSupPid, address}}

      [] ->
        {:error, :not_found}

      [_, _ | _] ->
        {:error, :ambiguous}
    end
  end

  defp sup(:client) do
    :sshc_sup
  end

  defp sup(:server) do
    :sshd_sup
  end

  defp is_socket_server(options) do
    :undefined !==
      :ssh_options.get_value(
        :internal_options,
        :connected_socket,
        options,
        fn ->
          :undefined
        end,
        :ssh_system_sup,
        251
      )
  end

  defp restart_acceptor(sysPid, address, options) do
    case lookup(:ssh_acceptor_sup, sysPid) do
      {_, _, :supervisor, _} ->
        {:error, :eaddrinuse}

      false ->
        childSpec = acceptor_sup_child_spec(sysPid, address, options)

        case :supervisor.start_child(sysPid, childSpec) do
          {:ok, _ChildPid} ->
            {:ok, sysPid}

          {:ok, _ChildPid, _Info} ->
            {:ok, sysPid}

          {:error, error} ->
            {:error, error}
        end
    end
  end
end
