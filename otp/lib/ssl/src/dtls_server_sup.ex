defmodule :m_dtls_server_sup do
  use Bitwise
  @behaviour :supervisor
  def start_link() do
    :supervisor.start_link({:local, :dtls_server_sup}, :dtls_server_sup, [])
  end

  def init([]) do
    supFlags = %{strategy: :one_for_all, intensity: 10, period: 3600}
    childSpecs = [dtls_listeners_spec(), ssl_server_session_child_spec()]
    {:ok, {supFlags, childSpecs}}
  end

  defp dtls_listeners_spec() do
    %{
      id: :dtls_listener_sup,
      start: {:dtls_listener_sup, :start_link, []},
      restart: :permanent,
      shutdown: 4000,
      modules: [:dtls_listener_sup],
      type: :supervisor
    }
  end

  defp ssl_server_session_child_spec() do
    %{
      id: :dtls_server_session_cache_sup,
      start: {:dtls_server_session_cache_sup, :start_link, []},
      restart: :permanent,
      shutdown: 4000,
      modules: [:dtls_server_session_cache_sup],
      type: :supervisor
    }
  end
end
