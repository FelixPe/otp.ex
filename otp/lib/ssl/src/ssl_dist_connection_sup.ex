defmodule :m_ssl_dist_connection_sup do
  use Bitwise
  @behaviour :supervisor
  def start_link() do
    :supervisor.start_link({:local,
                              :ssl_dist_connection_sup},
                             :ssl_dist_connection_sup, [])
  end

  def init([]) do
    supFlags = %{strategy: :one_for_one, intensity: 10,
                   period: 3600}
    childSpecs = [tls_sup_child_spec()]
    {:ok, {supFlags, childSpecs}}
  end

  defp tls_sup_child_spec() do
    %{id: :tls_dist_sup,
        start: {:tls_dist_sup, :start_link, []},
        restart: :permanent, shutdown: 4000,
        modules: [:tls_dist_sup], type: :supervisor}
  end

end