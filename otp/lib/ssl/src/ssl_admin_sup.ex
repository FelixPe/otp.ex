defmodule :m_ssl_admin_sup do
  use Bitwise
  @behaviour :supervisor
  def start_link() do
    :supervisor.start_link({:local, :ssl_admin_sup},
                             :ssl_admin_sup, [])
  end

  def init([]) do
    supFlags = %{strategy: :rest_for_one, intensity: 10,
                   period: 3600}
    childSpecs = [pem_cache_child_spec(),
                      session_and_cert_manager_child_spec(),
                          ticket_store_spec()]
    {:ok, {supFlags, childSpecs}}
  end

  def manager_opts() do
    cbOpts = (case (:application.get_env(:ssl,
                                           :session_cb)) do
                {:ok, cb} when is_atom(cb) ->
                  initArgs = session_cb_init_args()
                  [{:session_cb, cb}, {:session_cb_init_args, initArgs}]
                _ ->
                  []
              end)
    case (:application.get_env(:ssl, :session_lifetime)) do
      {:ok, time} when is_integer(time) ->
        [{:session_lifetime, time} | cbOpts]
      _ ->
        cbOpts
    end
  end

  defp pem_cache_child_spec() do
    %{id: :ssl_pem_cache,
        start: {:ssl_pem_cache, :start_link, [[]]},
        restart: :permanent, shutdown: 4000,
        modules: [:ssl_pem_cache], type: :worker}
  end

  defp session_and_cert_manager_child_spec() do
    opts = manager_opts()
    %{id: :ssl_manager,
        start: {:ssl_manager, :start_link, [opts]},
        restart: :permanent, shutdown: 4000,
        modules: [:ssl_manager], type: :worker}
  end

  defp ticket_store_spec() do
    size = client_session_ticket_store_size()
    lifetime = client_session_ticket_lifetime()
    %{id: :tls_client_ticket_store,
        start:
        {:tls_client_ticket_store, :start_link,
           [size, lifetime]},
        restart: :permanent, shutdown: 4000,
        modules: [:tls_client_ticket_store], type: :worker}
  end

  defp session_cb_init_args() do
    case (:application.get_env(:ssl,
                                 :session_cb_init_args)) do
      {:ok, args} when is_list(args) ->
        args
      _ ->
        []
    end
  end

  defp client_session_ticket_store_size() do
    case (:application.get_env(:ssl,
                                 :client_session_ticket_store_size)) do
      {:ok, size} when is_integer(size) and size > 0 ->
        size
      _ ->
        1000
    end
  end

  defp client_session_ticket_lifetime() do
    case (:application.get_env(:ssl,
                                 :client_session_ticket_lifetime)) do
      {:ok, size} when is_integer(size) and size > 0 ->
        size
      _ ->
        7200
    end
  end

end