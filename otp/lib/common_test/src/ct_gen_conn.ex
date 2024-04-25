defmodule :m_ct_gen_conn do
  use Bitwise
  @behaviour :gen_server
  require Record
  Record.defrecord(:r_gen_opts, :gen_opts, callback: :undefined,
                                    name: :undefined, address: :undefined,
                                    init_data: :undefined, reconnect: true,
                                    forward: false, use_existing: true,
                                    old: false, conn_pid: :undefined,
                                    cb_state: :undefined,
                                    ct_util_server: :undefined)
  def start(address, initData, callbackMod, opts)
      when is_list(opts) do
    do_start(address, initData, callbackMod, opts)
  end

  def start(name, address, initData, callbackMod) do
    do_start(address, initData, callbackMod,
               [{:name, name}, {:old, true}])
  end

  def stop(handle) do
    call(handle, :stop, 5000)
  end

  def get_conn_pid(handle) do
    call(handle, :get_conn_pid)
  end

  def log(heading, format, args) do
    log(:log, [heading, format, args])
  end

  def start_log(heading) do
    log(:start_log, [heading])
  end

  def cont_log(format, args) do
    log(:cont_log, [format, args])
  end

  def cont_log_no_timestamp(format, args) do
    log(:cont_log_no_timestamp, [format, args])
  end

  def end_log() do
    log(:end_log, [])
  end

  def do_within_time(fun, tmo) do
    do_within_time(fun, tmo, :erlang.get(:silent),
                     :erlang.get(:conn_pid))
  end

  defp do_within_time(fun, tmo, silent, :undefined) do
    do_within_time(fun, tmo, silent, self())
  end

  defp do_within_time(fun, tmo, silent, connPid) do
    mRef = :erlang.monitor(:process, connPid)
    pid = spawn_link(fn () ->
                          :ct_util.mark_process()
                          :erlang.put(:silent, silent)
                          exit({mRef, fun.()})
                     end)
    down(pid, mRef, tmo, :failure)
  end

  defp down(pid, mRef, tmo, reason) do
    receive do
      {:EXIT, ^pid, t} ->
        :infinity == tmo or :erlang.demonitor(mRef, [:flush])
        rc(mRef, t, reason)
      {:DOWN, ^mRef, :process, _, _} ->
        down(pid, mRef, :connection_closed)
    after tmo ->
      :erlang.demonitor(mRef, [:flush])
      down(pid, mRef, :timeout)
    end
  end

  defp down(pid, mRef, reason) do
    :erlang.exit(pid, :kill)
    down(pid, mRef, :infinity, reason)
  end

  defp rc(ref, {ref, rC}, _Reason) do
    rC
  end

  defp rc(_, reason, :failure) do
    {:error, reason}
  end

  defp rc(_, _, reason) do
    {:error, reason}
  end

  defp do_start(address, initData, callbackMod, optsList) do
    r_gen_opts(name: name) = (opts = make_opts(optsList,
                                        r_gen_opts(callback: callbackMod,
                                            address: address,
                                            init_data: initData)))
    case (:ct_util.does_connection_exist(name, address,
                                           callbackMod)) do
      {:ok, _Pid} = ok when r_gen_opts(opts, :use_existing) ->
        log('ct_gen_conn:start', 'Using existing connection!\n', [])
        ok
      {:ok, pid} when not r_gen_opts(opts, :use_existing) ->
        {:error, {:connection_exists, pid}}
      false ->
        do_start(opts)
    end
  end

  defp do_start(opts) do
    try do
      :gen_server.start(:ct_gen_conn, opts, [])
    catch
      :exit, reason ->
        log('ct_gen_conn:start', 'Connection process died: ~tp\n', [reason])
        {:error, {:connection_process_died, reason}}
    else
      {:ok, _} = ok ->
        ok
      {:error, reason} ->
        {:error, rc(reason)}
    end
  end

  defp rc({:shutdown, reason}) do
    reason
  end

  defp rc(t) do
    t
  end

  def make_opts(opts) do
    make_opts(opts, r_gen_opts())
  end

  defp make_opts(opts, r_gen_opts() = rec) do
    :lists.foldl(&opt/2, rec, opts)
  end

  defp opt({:name, name}, rec) do
    r_gen_opts(rec, name: name)
  end

  defp opt({:reconnect, bool}, rec) do
    r_gen_opts(rec, reconnect: bool)
  end

  defp opt({:forward_messages, bool}, rec) do
    r_gen_opts(rec, forward: bool)
  end

  defp opt({:use_existing_connection, bool}, rec) do
    r_gen_opts(rec, use_existing: bool)
  end

  defp opt({:old, bool}, rec) do
    r_gen_opts(rec, old: bool)
  end

  def call(pid, msg) do
    call(pid, msg, :infinity)
  end

  def call(pid, msg, :infinity = tmo) do
    gen_call(pid, msg, tmo)
  end

  def call(pid, msg, tmo) do
    {_, mRef} = spawn_monitor(fn () ->
                                   exit(gen_call(pid, msg, tmo))
                              end)
    receive do
      {:DOWN, ^mRef, :process, _, rC} ->
        rC
    end
  end

  defp gen_call(pid, msg, tmo) do
    try do
      :gen_server.call(pid, msg, tmo)
    catch
      :exit, reason ->
        {:error, {:process_down, pid, rc(pid, reason)}}
    else
      t ->
        retry(pid, t, tmo)
    end
  end

  defp retry(pid, {:retry, _} = t, tmo) do
    gen_call(pid, t, tmo)
  end

  defp retry(_, t, _) do
    t
  end

  defp rc(pid, {reason, {:gen_server, :call, _}}) do
    rc(pid, reason)
  end

  defp rc(pid, :timeout) do
    log('ct_gen_conn', 'Connection process ~w not responding. Killing now!', [pid])
    :erlang.exit(pid, :kill)
    :forced_termination
  end

  defp rc(_, reason) do
    rc(reason)
  end

  def return(from, result) do
    :gen_server.reply(from, result)
  end

  def init(r_gen_opts(callback: mod, name: name, address: addr,
             init_data: initData) = opts) do
    :erlang.process_flag(:trap_exit, true)
    :ct_util.mark_process()
    :erlang.put(:silent, false)
    try do
      mod.init(name, addr, initData)
    catch
      c, reason when c != :error ->
        {:stop, {:shutdown, reason}}
    else
      {:ok, connPid, state} when is_pid(connPid) ->
        :erlang.link(connPid)
        :erlang.put(:conn_pid, connPid)
        srvPid = :erlang.whereis(:ct_util_server)
        :erlang.link(srvPid)
        :ct_util.register_connection(name, addr, mod, self())
        {:ok,
           r_gen_opts(opts, conn_pid: connPid,  cb_state: state, 
                     ct_util_server: srvPid)}
      {:error, reason} ->
        {:stop, {:shutdown, reason}}
    end
  end

  def handle_call(:get_conn_pid, _From, r_gen_opts(conn_pid: pid) = opts) do
    {:reply, pid, opts}
  end

  def handle_call(:stop, _From, opts) do
    {:stop, :normal, :ok, opts}
  end

  def handle_call({:retry, {error, _Name, connPid, _Msg}}, _From,
           r_gen_opts(conn_pid: connPid) = opts) do
    {:reply, error_rc(error), opts}
  end

  def handle_call({:retry, {_Error, _Name, _CPid, msg}}, _From,
           r_gen_opts(callback: mod, cb_state: state) = opts) do
    log('Rerunning command', 'Connection reestablished. Rerunning command...', [])
    {reply, newState} = mod.handle_msg(msg, state)
    {:reply, reply, r_gen_opts(opts, cb_state: newState)}
  end

  def handle_call(msg, _From,
           r_gen_opts(old: true, callback: mod, cb_state: state) = opts) do
    {reply, newState} = mod.handle_msg(msg, state)
    {:reply, reply, r_gen_opts(opts, cb_state: newState)}
  end

  def handle_call(msg, from,
           r_gen_opts(callback: mod, cb_state: state) = opts) do
    case (mod.handle_msg(msg, from, state)) do
      {:reply, reply, newState} ->
        {:reply, reply, r_gen_opts(opts, cb_state: newState)}
      {:noreply, newState} ->
        {:noreply, r_gen_opts(opts, cb_state: newState)}
      {:stop, reply, newState} ->
        {:stop, :normal, reply, r_gen_opts(opts, cb_state: newState)}
    end
  end

  def handle_cast(_, opts) do
    {:noreply, opts}
  end

  def handle_info({:EXIT, pid, reason},
           r_gen_opts(reconnect: true, conn_pid: pid,
               address: addr) = opts) do
    log('Connection down!\nOpening new!', 'Reason: ~tp\nAddress: ~tp\n', [reason, addr])
    case (reconnect(opts)) do
      {:ok, newPid, newState} ->
        :erlang.link(newPid)
        :erlang.put(:conn_pid, newPid)
        {:noreply,
           r_gen_opts(opts, conn_pid: newPid,  cb_state: newState)}
      error ->
        log('Reconnect failed. Giving up!', 'Reason: ~tp\n', [error])
        {:stop, :normal, opts}
    end
  end

  def handle_info({:EXIT, pid, reason},
           r_gen_opts(reconnect: false, conn_pid: pid) = opts) do
    log('Connection closed!', 'Reason: ~tp\n', [reason])
    {:stop, :normal, opts}
  end

  def handle_info({:EXIT, pid, reason},
           r_gen_opts(ct_util_server: pid) = opts) do
    {:stop, {:shutdown, reason}, opts}
  end

  def handle_info(msg,
           r_gen_opts(forward: true, callback: mod,
               cb_state: state) = opts) do
    case (mod.handle_msg(msg, state)) do
      {:noreply, newState} ->
        {:noreply, r_gen_opts(opts, cb_state: newState)}
      {:stop, newState} ->
        {:stop, :normal, r_gen_opts(opts, cb_state: newState)}
    end
  end

  def handle_info(_, r_gen_opts() = opts) do
    {:noreply, opts}
  end

  def code_change(_Vsn, state, _Extra) do
    {:ok, state}
  end

  def terminate(:normal,
           r_gen_opts(callback: mod, conn_pid: pid, cb_state: state)) do
    :ct_util.unregister_connection(self())
    :erlang.unlink(pid)
    mod.terminate(pid, state)
  end

  def terminate(_, r_gen_opts()) do
    :ok
  end

  defp error_rc({:error, _} = t) do
    t
  end

  defp error_rc(reason) do
    {:error, reason}
  end

  defp reconnect(r_gen_opts(callback: mod, address: addr,
              cb_state: state)) do
    mod.reconnect(addr, state)
  end

  defp log(func, args) do
    case (:erlang.get(:silent)) do
      true when not false ->
        :ok
      _ ->
        apply(:ct_logs, func, args)
    end
  end

end