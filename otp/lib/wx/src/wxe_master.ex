defmodule :m_wxe_master do
  use Bitwise
  @behaviour :gen_server
  require Record
  Record.defrecord(:r_state, :state, subscribers: [], msgs: [])
  Record.defrecord(:r_wx_ref, :wx_ref, ref: :undefined,
                                  type: :undefined, state: [])
  Record.defrecord(:r_wx_env, :wx_env, ref: :undefined,
                                  sv: :undefined, debug: 0)
  Record.defrecord(:r_wx_mem, :wx_mem, bin: :undefined,
                                  size: :undefined)
  Record.defrecord(:r_evh, :evh, et: :null, id: - 1,
                               lastId: - 1, cb: 0, skip: :undefined,
                               userdata: [], handler: :undefined)
  def start(silentStart) do
    :gen_server.start({:local, :wxe_master}, :wxe_master,
                        [silentStart], [])
  end

  def init_env(silentStart) do
    case (:erlang.whereis(:wxe_master)) do
      :undefined ->
        case (start(silentStart)) do
          {:ok, pid} ->
            pid
          {:error, {:already_started, pid}} ->
            pid
          {:error, {reason, stack}} ->
            :erlang.raise(:error, reason, stack)
        end
      pid ->
        pid
    end
    :gen_server.call(:wxe_master, :init_env, :infinity)
    :wxe_util.make_env()
  end

  def init_opengl() do
    case (:erlang.get(:wx_init_opengl)) do
      true ->
        {:ok, 'already  initialized'}
      _ ->
        opaque = :gl.lookup_func(:functions)
        debug = :gl.lookup_func(:function_names)
        {:ok, :wxe_util.init_opengl(opaque, debug)}
    end
  end

  def fetch_msgs() do
    :gen_server.call(:wxe_master, :fetch_msgs, :infinity)
  end

  def init([silentStart]) do
    :erlang.group_leader(:erlang.whereis(:init), self())
    case ((try do
            :erlang.system_info(:smp_support)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      true ->
        :ok
      _ ->
        :wxe_util.opt_error_log(silentStart, 'WX ERROR: SMP emulator required', [])
        :erlang.error({:error, :not_smp})
    end
    :erlang.process_flag(:trap_exit, true)
    case (:wxe_util.init_nif(silentStart)) do
      :ok ->
        :ok
      {:error, {reason, string}} = err ->
        :wxe_util.opt_error_log(silentStart, 'WX ERROR: Could not load library: ~p~n~s',
                                  [reason, string])
        :erlang.error(err)
    end
    try do
      spawn_link(fn () ->
                      debug_ping()
                 end)
      :wxe_util.setup_consts()
      {:ok, r_state()}
    catch
      _, error ->
        str = :io_lib.format('Error: ~p @ ~p~n', [error, __STACKTRACE__])
        :logger.log(:error, str, %{domain: [:wx]})
        :erlang.error({:error, {error, 'Could not initiate graphics'}})
    end
  end

  def handle_call(:init_env, _From, state) do
    {:reply, :ok, state}
  end

  def handle_call(:fetch_msgs, _From, state = r_state(msgs: msgs)) do
    newFiles = (for {type, data} <- :lists.reverse(msgs),
                      type == :new_file do
                  data
                end)
    {:reply, newFiles, r_state(state, msgs: [])}
  end

  def handle_call(:subscribe_msgs, {pid, _Tag},
           state = r_state(subscribers: subs)) do
    :erlang.monitor(:process, pid)
    :lists.foreach(fn msg ->
                        send(pid, msg)
                   end,
                     :lists.reverse(r_state(state, :msgs)))
    {:reply, :ok,
       r_state(state, subscribers: [pid | subs],  msgs: [])}
  end

  def handle_call(_Request, _From, state) do
    reply = :ok
    {:reply, reply, state}
  end

  def handle_cast(_Msg, state) do
    {:noreply, state}
  end

  def handle_info({:wxe_driver, :error, msg}, state) do
    :logger.log(:error, 'wx: ~s', [msg], %{domain: [:wx]})
    {:noreply, state}
  end

  def handle_info({:wxe_driver, :internal_error, msg}, state) do
    :logger.log(:error, 'wx: ~s', [msg], %{domain: [:wx]})
    {:noreply, state}
  end

  def handle_info({:wxe_driver, :debug, msg}, state) do
    :logger.log(:notice, 'wx: ~s', [msg], %{domain: [:wx]})
    {:noreply, state}
  end

  def handle_info({:wxe_driver, cmd, file},
           state = r_state(subscribers: subs, msgs: msgs))
      when cmd === :open_file or cmd === :new_file or
             cmd === :print_file or cmd === :open_url or
             cmd === :reopen_app do
    :lists.foreach(fn pid ->
                        send(pid, {cmd, file})
                   end,
                     subs)
    {:noreply, r_state(state, msgs: [{cmd, file} | msgs])}
  end

  def handle_info({:DOWN, _Ref, :process, pid, _Info}, state) do
    subs = r_state(state, :subscribers) -- [pid]
    {:noreply, r_state(state, subscribers: subs)}
  end

  def handle_info(info, state) do
    :logger.log(:notice, 'wx: Unexpected Msg: ~p', [info],
                  %{domain: [:wx], line: 189, file: 'wxe_master'})
    {:noreply, state}
  end

  def terminate(_Reason, _State) do
    :erlang.display({:wxe_master, :killed,
                       :erlang.process_info(self(), :trap_exit), _Reason})
    :ok
  end

  def code_change(_OldVsn, state, _Extra) do
    {:ok, state}
  end

  defp debug_ping() do
    :timer.sleep(1 * 333)
    :wxe_util.debug_ping()
    debug_ping()
  end

end