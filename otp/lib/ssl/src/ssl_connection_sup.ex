defmodule :m_ssl_connection_sup do
  use Bitwise
  @behaviour :supervisor
  def start_link() do
    :supervisor.start_link({:local, :ssl_connection_sup},
                             :ssl_connection_sup, [])
  end

  def init([]) do
    childSpecs = [tls_sup_child_spec(),
                      dtls_sup_child_spec()]
    supFlags = %{strategy: :one_for_one, intensity: 10,
                   period: 3600}
    {:ok, {supFlags, childSpecs}}
  end

  defp tls_sup_child_spec() do
    %{id: :tls_sup, start: {:tls_sup, :start_link, []},
        restart: :permanent, shutdown: 4000,
        modules: [:tls_sup], type: :supervisor}
  end

  defp dtls_sup_child_spec() do
    %{id: :dtls_sup, start: {:dtls_sup, :start_link, []},
        restart: :permanent, shutdown: 4000,
        modules: [:dtls_sup], type: :supervisor}
  end

end