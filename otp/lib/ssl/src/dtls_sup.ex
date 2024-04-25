defmodule :m_dtls_sup do
  use Bitwise
  @behaviour :supervisor
  def start_link() do
    :supervisor.start_link({:local, :dtls_sup}, :dtls_sup,
                             [])
  end

  def init([]) do
    supFlags = %{strategy: :one_for_one, intensity: 10,
                   period: 3600}
    children = [dtls_connection_child_spec(),
                    server_instance_child_spec()]
    {:ok, {supFlags, children}}
  end

  defp dtls_connection_child_spec() do
    %{id: :dtls_connection_sup,
        start: {:dtls_connection_sup, :start_link, []},
        restart: :permanent, shutdown: 4000,
        modules: [:dtls_connection_sup], type: :supervisor}
  end

  defp server_instance_child_spec() do
    %{id: :dtls_server_sup,
        start: {:dtls_server_sup, :start_link, []},
        restart: :permanent, shutdown: 4000,
        modules: [:dtls_server_sup], type: :supervisor}
  end

end