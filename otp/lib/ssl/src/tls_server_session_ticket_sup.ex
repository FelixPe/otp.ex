defmodule :m_tls_server_session_ticket_sup do
  use Bitwise
  @behaviour :supervisor
  def start_link() do
    :supervisor.start_link({:local, sup_name(:normal)}, :tls_server_session_ticket_sup, [])
  end

  def start_link_dist() do
    :supervisor.start_link({:local, sup_name(:dist)}, :tls_server_session_ticket_sup, [])
  end

  def start_child(args) do
    :supervisor.start_child(sup_name(:normal), args)
  end

  def start_child_dist(args) do
    :supervisor.start_child(sup_name(:dist), args)
  end

  def sup_name(:normal) do
    :tls_server_session_ticket_sup
  end

  def sup_name(:dist) do
    :erlang.list_to_atom(:erlang.atom_to_list(:tls_server_session_ticket_sup) ++ ~c"_dist")
  end

  def init(_) do
    supFlags = %{strategy: :simple_one_for_one, intensity: 0, period: 3600}

    childSpecs = [
      %{
        id: :undefined,
        start: {:tls_server_session_ticket, :start_link, []},
        restart: :transient,
        shutdown: 4000,
        modules: [:tls_server_session_ticket],
        type: :worker
      }
    ]

    {:ok, {supFlags, childSpecs}}
  end
end
