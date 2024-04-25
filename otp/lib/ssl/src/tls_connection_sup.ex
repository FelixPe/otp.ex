defmodule :m_tls_connection_sup do
  use Bitwise
  @behaviour :supervisor
  def start_link() do
    :supervisor.start_link({:local, :tls_connection_sup}, :tls_connection_sup, [])
  end

  def start_link_dist() do
    :supervisor.start_link({:local, :tls_dist_connection_sup}, :tls_connection_sup, [])
  end

  def start_child(args) do
    :supervisor.start_child(:tls_connection_sup, args)
  end

  def start_child_dist(args) do
    :supervisor.start_child(:tls_dist_connection_sup, args)
  end

  def init(_) do
    supFlags = %{strategy: :simple_one_for_one, intensity: 0, period: 3600}

    childSpecs = [
      %{
        id: :undefined,
        restart: :temporary,
        type: :supervisor,
        start: {:tls_dyn_connection_sup, :start_link, []}
      }
    ]

    {:ok, {supFlags, childSpecs}}
  end
end
