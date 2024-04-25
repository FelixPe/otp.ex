defmodule :m_ssl_sup do
  use Bitwise
  @behaviour :supervisor
  def start_link() do
    :supervisor.start_link({:local, :ssl_sup}, :ssl_sup, [])
  end

  def init([]) do
    supFlags = %{strategy: :rest_for_one, intensity: 10, period: 3600}
    childSpecs = [ssl_admin_child_spec(), ssl_connection_sup()]
    {:ok, {supFlags, childSpecs}}
  end

  defp ssl_admin_child_spec() do
    %{
      id: :ssl_admin_sup,
      start: {:ssl_admin_sup, :start_link, []},
      restart: :permanent,
      shutdown: 4000,
      modules: [:ssl_admin_sup],
      type: :supervisor
    }
  end

  defp ssl_connection_sup() do
    %{
      id: :ssl_connection_sup,
      start: {:ssl_connection_sup, :start_link, []},
      restart: :permanent,
      shutdown: 4000,
      modules: [:ssl_connection_sup],
      type: :supervisor
    }
  end
end
