defmodule :m_tls_dist_sup do
  use Bitwise
  @behaviour :supervisor
  def start_link() do
    :supervisor.start_link({:local, :tls_dist_sup}, :tls_dist_sup, [])
  end

  def init([]) do
    supFlags = %{strategy: :one_for_one, intensity: 10, period: 3600}
    childSpecs = [tls_connection_child_spec(), server_instance_child_spec()]
    {:ok, {supFlags, childSpecs}}
  end

  defp tls_connection_child_spec() do
    %{
      id: :dist_tls_connection_sup,
      start: {:tls_connection_sup, :start_link_dist, []},
      restart: :permanent,
      shutdown: 4000,
      modules: [:tls_connection_sup],
      type: :supervisor
    }
  end

  defp server_instance_child_spec() do
    %{
      id: :tls_dist_server_sup,
      start: {:tls_dist_server_sup, :start_link, []},
      restart: :permanent,
      shutdown: 4000,
      modules: [:tls_dist_server_sup],
      type: :supervisor
    }
  end
end
