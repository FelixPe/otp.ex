defmodule :m_tls_server_sup do
  use Bitwise
  @behaviour :supervisor
  def start_link() do
    :supervisor.start_link({:local, :tls_server_sup}, :tls_server_sup, [])
  end

  def init([]) do
    childSpecs = [
      listen_options_tracker_child_spec(),
      tls_server_session_child_spec(),
      ssl_server_session_child_spec(),
      ssl_upgrade_server_session_child_spec()
    ]

    supFlags = %{strategy: :one_for_all, intensity: 10, period: 3600}
    {:ok, {supFlags, childSpecs}}
  end

  defp listen_options_tracker_child_spec() do
    %{
      id: :ssl_listen_tracker_sup,
      start: {:ssl_listen_tracker_sup, :start_link, []},
      restart: :permanent,
      shutdown: 4000,
      modules: [:ssl_listen_tracker_sup],
      type: :supervisor
    }
  end

  defp tls_server_session_child_spec() do
    %{
      id: :tls_server_session_ticket,
      start: {:tls_server_session_ticket_sup, :start_link, []},
      restart: :permanent,
      shutdown: 4000,
      modules: [:tls_server_session_ticket_sup],
      type: :supervisor
    }
  end

  defp ssl_server_session_child_spec() do
    %{
      id: :ssl_server_session_cache_sup,
      start: {:ssl_server_session_cache_sup, :start_link, []},
      restart: :permanent,
      shutdown: 4000,
      modules: [:ssl_server_session_cache_sup],
      type: :supervisor
    }
  end

  defp ssl_upgrade_server_session_child_spec() do
    %{
      id: :ssl_upgrade_server_session_cache_sup,
      start: {:ssl_upgrade_server_session_cache_sup, :start_link, []},
      restart: :permanent,
      shutdown: 4000,
      modules: [:ssl_upgrade_server_session_cache_sup],
      type: :supervisor
    }
  end
end
