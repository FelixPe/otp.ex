defmodule :m_tls_sup do
  use Bitwise
  @behaviour :supervisor
  def start_link() do
    :supervisor.start_link({:local, :tls_sup}, :tls_sup, [])
  end

  def init([]) do
    childSpecs = [tls_connection_child_spec(),
                      server_instance_child_spec()]
    supFlags = %{strategy: :one_for_one, intensity: 10,
                   period: 3600}
    {:ok, {supFlags, childSpecs}}
  end

  defp tls_connection_child_spec() do
    %{id: :tls_connection_sup,
        start: {:tls_connection_sup, :start_link, []},
        restart: :permanent, shutdown: 4000,
        modules: [:tls_connection_sup], type: :supervisor}
  end

  defp server_instance_child_spec() do
    %{id: :tls_server_sup,
        start: {:tls_server_sup, :start_link, []},
        restart: :permanent, shutdown: 4000,
        modules: [:tls_server_sup], type: :supervisor}
  end

end