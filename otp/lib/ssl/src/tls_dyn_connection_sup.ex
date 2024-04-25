defmodule :m_tls_dyn_connection_sup do
  use Bitwise
  @behaviour :supervisor
  def start_link() do
    :supervisor.start_link(:tls_dyn_connection_sup, [])
  end

  def start_child(sup, :sender, args) do
    :supervisor.start_child(sup, sender(args))
  end

  def start_child(sup, :receiver, args) do
    :supervisor.start_child(sup, receiver(args))
  end

  def init(_) do
    supFlags = %{strategy: :one_for_all,
                   auto_shutdown: :any_significant, intensity: 0,
                   period: 3600}
    childSpecs = []
    {:ok, {supFlags, childSpecs}}
  end

  defp sender(args) do
    %{id: :sender, restart: :temporary, type: :worker,
        start: {:tls_sender, :start_link, args},
        modules: [:tls_sender]}
  end

  defp receiver(args) do
    %{id: :receiver, restart: :temporary, type: :worker,
        significant: true,
        start: {:ssl_gen_statem, :start_link, args},
        modules:
        [:ssl_gen_statem, :tls_connection, :tls_gen_connection,
                                               :tls_client_connection_1_3,
                                                   :tls_server_connection_1_3,
                                                       :tls_gen_connection_1_3]}
  end

end