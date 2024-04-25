defmodule :m_ssl_dist_admin_sup do
  use Bitwise
  @behaviour :supervisor
  def start_link() do
    :supervisor.start_link({:local, :ssl_dist_admin_sup}, :ssl_dist_admin_sup, [])
  end

  def init([]) do
    childSpecs = [pem_cache_child_spec(), session_and_cert_manager_child_spec()]
    supFlags = %{strategy: :rest_for_one, intensity: 10, period: 3600}
    {:ok, {supFlags, childSpecs}}
  end

  defp pem_cache_child_spec() do
    %{
      id: :ssl_pem_cache_dist,
      start: {:ssl_pem_cache, :start_link_dist, [[]]},
      restart: :permanent,
      shutdown: 4000,
      modules: [:ssl_pem_cache],
      type: :worker
    }
  end

  defp session_and_cert_manager_child_spec() do
    opts = :ssl_admin_sup.manager_opts()

    %{
      id: :ssl_dist_manager,
      start: {:ssl_manager, :start_link_dist, [opts]},
      restart: :permanent,
      shutdown: 4000,
      modules: [:ssl_manager],
      type: :worker
    }
  end
end
