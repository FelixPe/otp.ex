defmodule :m_ssl_listen_tracker_sup do
  use Bitwise
  @behaviour :supervisor
  def start_link() do
    :supervisor.start_link({:local, tracker_name(:normal)}, :ssl_listen_tracker_sup, [])
  end

  def start_link_dist() do
    :supervisor.start_link({:local, tracker_name(:dist)}, :ssl_listen_tracker_sup, [])
  end

  def start_child(args) do
    :supervisor.start_child(tracker_name(:normal), args)
  end

  def start_child_dist(args) do
    :supervisor.start_child(tracker_name(:dist), args)
  end

  def init(_) do
    supFlags = %{strategy: :simple_one_for_one, intensity: 0, period: 3600}

    childSpecs = [
      %{
        id: :undefined,
        start: {:tls_socket, :start_link, []},
        restart: :temporary,
        shutdown: 4000,
        modules: [:tls_socket],
        type: :worker
      }
    ]

    {:ok, {supFlags, childSpecs}}
  end

  defp tracker_name(:normal) do
    :ssl_listen_tracker_sup
  end

  defp tracker_name(:dist) do
    :erlang.list_to_atom(:erlang.atom_to_list(:ssl_listen_tracker_sup) ++ ~c"_dist")
  end
end
