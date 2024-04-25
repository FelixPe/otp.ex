defmodule :m_application do
  use Bitwise
  def load(application) do
    load1(application, [])
  end

  def load(application, distNodes) do
    load1(application, distNodes)
  end

  defp load1(application, distNodes) do
    case (:application_controller.load_application(application)) do
      :ok when distNodes !== [] ->
        appName = get_appl_name(application)
        case (:dist_ac.load_application(appName, distNodes)) do
          :ok ->
            :ok
          {:error, r} ->
            :application_controller.unload_application(appName)
            {:error, r}
        end
      else__ ->
        else__
    end
  end

  def unload(application) do
    :application_controller.unload_application(application)
  end

  def ensure_all_started(application) do
    ensure_all_started(application, :temporary, :serial)
  end

  def ensure_all_started(application, type) do
    ensure_all_started(application, type, :serial)
  end

  def ensure_all_started(application, type, mode)
      when is_atom(application) do
    ensure_all_started([application], type, mode)
  end

  def ensure_all_started(applications, type, mode)
      when is_list(applications) do
    opts = %{type: type, mode: mode}
    case (enqueue_or_start(applications, [], %{}, [], [],
                             opts)) do
      {:ok, dAG, _Pending, started} when mode === :concurrent
                                         ->
        reqIDs = :gen_server.reqids_new()
        concurrent_dag_start(:maps.to_list(dAG), reqIDs, [],
                               started, type)
      {:ok, dAG, _Pending, started} when mode === :serial ->
        0 = map_size(dAG)
        {:ok, :lists.reverse(started)}
      {:error, appReason, started} ->
        _ = (for name <- started do
               stop(name)
             end)
        {:error, appReason}
    end
  end

  defp enqueue_or_start([app | apps], optional, dAG, pending, started,
            opts)
      when :erlang.is_map_key(app, dAG) do
    enqueue_or_start(apps, optional, dAG, [app | pending],
                       started, opts)
  end

  defp enqueue_or_start([app | apps], optional, dAG, pending, started,
            opts)
      when is_atom(app) do
    case (:application_controller.is_running(app)) do
      false ->
        case (ensure_loaded(app)) do
          {:ok, name} ->
            case (enqueue_or_start_app(name, app, dAG, pending,
                                         started, opts)) do
              {:ok, newDAG, newPending, newStarted} ->
                enqueue_or_start(apps, optional, newDAG, newPending,
                                   newStarted, opts)
              errorAppReasonStarted ->
                errorAppReasonStarted
            end
          {:error, {'no such file or directory', _} = reason} ->
            case (:lists.member(app, optional)) do
              true ->
                enqueue_or_start(apps, optional, dAG, pending, started,
                                   opts)
              false ->
                {:error, {app, reason}, started}
            end
          {:error, reason} ->
            {:error, {app, reason}, started}
        end
      true ->
        enqueue_or_start(apps, optional, dAG, pending, started,
                           opts)
    end
  end

  defp enqueue_or_start([], _Optional, dAG, pending, started, _Opts) do
    {:ok, dAG, pending, started}
  end

  defp enqueue_or_start_app(name, app, dAG, pending, started, opts) do
    %{type: type, mode: mode} = opts
    {:ok, childApps} = get_key(name, :applications)
    {:ok, optionalApps} = get_key(name,
                                    :optional_applications)
    {:ok, mod} = get_key(name, :mod)
    case (enqueue_or_start(childApps, optionalApps, dAG, [],
                             started, opts)) do
      {:ok, newDAG, newPending, newStarted}
          when (newPending === [] and
                  mode === :serial or mod === [])
               ->
        case (:application_controller.start_application(app,
                                                          type)) do
          :ok ->
            {:ok, newDAG, pending, [app | newStarted]}
          {:error, {:already_started, ^app}} ->
            {:ok, newDAG, pending, newStarted}
          {:error, reason} ->
            {:error, {app, reason}, newStarted}
        end
      {:ok, newDAG, newPending, newStarted} ->
        {:ok, Map.put(newDAG, app, newPending), [app | pending],
           newStarted}
      errorAppReasonStarted ->
        errorAppReasonStarted
    end
  end

  defp concurrent_dag_start([], reqIDs, _Done, started, _Type) do
    wait_all_enqueued(reqIDs, started, false)
  end

  defp concurrent_dag_start(pending0, reqIDs0, done, started0, type) do
    {pending1, reqIDs1} = enqueue_dag_leaves(pending0,
                                               reqIDs0, [], done, type)
    case (wait_one_enqueued(reqIDs1, started0)) do
      {:ok, app, reqIDs2, started1} ->
        concurrent_dag_start(pending1, reqIDs2, [app], started1,
                               type)
      {:error, appReason, reqIDs2} ->
        wait_all_enqueued(reqIDs2, started0, appReason)
    end
  end

  defp enqueue_dag_leaves([{app, children} | rest], reqIDs, acc, done,
            type) do
    case (children -- done) do
      [] ->
        req = :application_controller.start_application_request(app,
                                                                  type)
        newReqIDs = :gen_server.reqids_add(req, app, reqIDs)
        enqueue_dag_leaves(rest, newReqIDs, acc, done, type)
      newChildren ->
        newAcc = [{app, newChildren} | acc]
        enqueue_dag_leaves(rest, reqIDs, newAcc, done, type)
    end
  end

  defp enqueue_dag_leaves([], reqIDs, acc, _Done, _Type) do
    {acc, reqIDs}
  end

  defp wait_one_enqueued(reqIDs0, started) do
    case (:gen_server.wait_response(reqIDs0, :infinity,
                                      true)) do
      {{:reply, :ok}, app, reqIDs1} ->
        {:ok, app, reqIDs1, [app | started]}
      {{:reply, {:error, {:already_started, app}}}, app,
         reqIDs1} ->
        {:ok, app, reqIDs1, started}
      {{:reply, {:error, reason}}, app, reqIDs1} ->
        {:error, {app, reason}, reqIDs1}
      {{:error, {reason, _Ref}}, _App, _ReqIDs1} ->
        exit(reason)
      :no_request ->
        exit(:deadlock)
    end
  end

  defp wait_all_enqueued(reqIDs0, started0, lastAppReason) do
    case (:gen_server.reqids_size(reqIDs0)) do
      0 when lastAppReason === false ->
        {:ok, :lists.reverse(started0)}
      0 ->
        _ = (for app <- started0 do
               stop(app)
             end)
        {:error, lastAppReason}
      _ ->
        case (wait_one_enqueued(reqIDs0, started0)) do
          {:ok, _App, reqIDs1, started1} ->
            wait_all_enqueued(reqIDs1, started1, lastAppReason)
          {:error, newAppReason, reqIDs1} ->
            wait_all_enqueued(reqIDs1, started0, newAppReason)
        end
    end
  end

  def start(application) do
    start(application, :temporary)
  end

  def start(application, restartType) do
    case (ensure_loaded(application)) do
      {:ok, name} ->
        :application_controller.start_application(name,
                                                    restartType)
      error ->
        error
    end
  end

  defp ensure_loaded(application) do
    case (load(application)) do
      :ok ->
        {:ok, get_appl_name(application)}
      {:error, {:already_loaded, name}} ->
        {:ok, name}
      error ->
        error
    end
  end

  def ensure_started(application) do
    ensure_started(application, :temporary)
  end

  def ensure_started(application, restartType) do
    case (start(application, restartType)) do
      :ok ->
        :ok
      {:error, {:already_started, ^application}} ->
        :ok
      error ->
        error
    end
  end

  def start_boot(application) do
    start_boot(application, :temporary)
  end

  def start_boot(application, restartType) do
    :application_controller.start_boot_application(application,
                                                     restartType)
  end

  def takeover(application, restartType) do
    :dist_ac.takeover_application(application, restartType)
  end

  def permit(application, bool) do
    case (bool) do
      true ->
        :ok
      false ->
        :ok
      bad ->
        exit({:badarg,
                {:application, :permit, [application, bad]}})
    end
    case (:application_controller.permit_application(application,
                                                       bool)) do
      :distributed_application ->
        :dist_ac.permit_application(application, bool)
      {:distributed_application, :only_loaded} ->
        :dist_ac.permit_only_loaded_application(application,
                                                  bool)
      localResult ->
        localResult
    end
  end

  def stop(application) do
    :application_controller.stop_application(application)
  end

  def which_applications() do
    :application_controller.which_applications()
  end

  def which_applications(:infinity) do
    :application_controller.which_applications(:infinity)
  end

  def which_applications(timeout) when (is_integer(timeout) and
                          timeout >= 0) do
    :application_controller.which_applications(timeout)
  end

  def loaded_applications() do
    :application_controller.loaded_applications()
  end

  def info() do
    :application_controller.info()
  end

  def set_env(config) when is_list(config) do
    set_env(config, [])
  end

  def set_env(config, opts) when (is_list(config) and
                               is_list(opts)) do
    case (:application_controller.set_env(config, opts)) do
      :ok ->
        :ok
      {:error, msg} ->
        :erlang.error({:badarg, msg}, [config, opts])
    end
  end

  def set_env(application, key, val) do
    :application_controller.set_env(application, key, val)
  end

  def set_env(application, key, val, :infinity) do
    set_env(application, key, val, [{:timeout, :infinity}])
  end

  def set_env(application, key, val, timeout)
      when (is_integer(timeout) and timeout >= 0) do
    set_env(application, key, val, [{:timeout, timeout}])
  end

  def set_env(application, key, val, opts)
      when is_list(opts) do
    :application_controller.set_env(application, key, val,
                                      opts)
  end

  def unset_env(application, key) do
    :application_controller.unset_env(application, key)
  end

  def unset_env(application, key, :infinity) do
    unset_env(application, key, [{:timeout, :infinity}])
  end

  def unset_env(application, key, timeout)
      when (is_integer(timeout) and timeout >= 0) do
    unset_env(application, key, [{:timeout, timeout}])
  end

  def unset_env(application, key, opts) when is_list(opts) do
    :application_controller.unset_env(application, key,
                                        opts)
  end

  def get_env(key) do
    :application_controller.get_pid_env(:erlang.group_leader(),
                                          key)
  end

  def get_env(application, key) do
    :application_controller.get_env(application, key)
  end

  def get_env(application, key, default) do
    :application_controller.get_env(application, key,
                                      default)
  end

  def get_all_env() do
    :application_controller.get_pid_all_env(:erlang.group_leader())
  end

  def get_all_env(application) do
    :application_controller.get_all_env(application)
  end

  def get_key(key) do
    :application_controller.get_pid_key(:erlang.group_leader(),
                                          key)
  end

  def get_key(application, key) do
    :application_controller.get_key(application, key)
  end

  def get_all_key() do
    :application_controller.get_pid_all_key(:erlang.group_leader())
  end

  def get_all_key(application) do
    :application_controller.get_all_key(application)
  end

  def get_application() do
    :application_controller.get_application(:erlang.group_leader())
  end

  def get_application(pid) when is_pid(pid) do
    case (:erlang.process_info(pid, :group_leader)) do
      {:group_leader, gl} ->
        :application_controller.get_application(gl)
      :undefined ->
        :undefined
    end
  end

  def get_application(module) when is_atom(module) do
    :application_controller.get_application_module(module)
  end

  def get_supervisor(application) when is_atom(application) do
    case (:application_controller.get_master(application)) do
      :undefined ->
        :undefined
      master ->
        case (:application_master.get_child(master)) do
          {root, _App} ->
            {:ok, root}
          :error ->
            :undefined
        end
    end
  end

  def start_type() do
    :application_controller.start_type(:erlang.group_leader())
  end

  defp get_appl_name(name) when is_atom(name) do
    name
  end

  defp get_appl_name({:application, name, _}) when is_atom(name) do
    name
  end

end