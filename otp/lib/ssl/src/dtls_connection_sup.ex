defmodule :m_dtls_connection_sup do
  use Bitwise
  @behaviour :supervisor
  def start_link() do
    :supervisor.start_link({:local, :dtls_connection_sup},
                             :dtls_connection_sup, [])
  end

  def start_link_dist() do
    :supervisor.start_link({:local,
                              :dtls_connection_sup_dist},
                             :dtls_connection_sup, [])
  end

  def start_child(args) do
    :supervisor.start_child(:dtls_connection_sup, args)
  end

  def start_child_dist(args) do
    :supervisor.start_child(:dtls_connection_sup_dist, args)
  end

  def init(_) do
    supFlags = %{strategy: :simple_one_for_one,
                   intensity: 0, period: 3600}
    childSpecs = [%{id: :undefined,
                      start: {:ssl_gen_statem, :start_link, []},
                      restart: :temporary, shutdown: 4000,
                      modules: [:ssl_gen_statem, :dtls_connection],
                      type: :worker}]
    {:ok, {supFlags, childSpecs}}
  end

end