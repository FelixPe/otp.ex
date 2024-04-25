defmodule :m_timer do
  use Bitwise

  def apply_after(0, m, f, a)
      when is_atom(m) and is_atom(f) and
             is_list(a) do
    _ = do_apply({m, f, a}, false)
    {:ok, {:instant, make_ref()}}
  end

  def apply_after(time, m, f, a)
      when is_integer(time) and
             time >= 0 and is_atom(m) and is_atom(f) and
             is_list(a) do
    req(:apply_once, {system_time(), time, {m, f, a}})
  end

  def apply_after(_Time, _M, _F, _A) do
    {:error, :badarg}
  end

  def send_after(0, pidOrRegName, message)
      when is_pid(pidOrRegName) or is_atom(pidOrRegName) do
    send(pidOrRegName, message)
    {:ok, {:instant, make_ref()}}
  end

  def send_after(0, {regName, node} = dest, message)
      when is_atom(regName) and is_atom(node) do
    send(dest, message)
    {:ok, {:instant, make_ref()}}
  end

  def send_after(time, pid, message)
      when is_integer(time) and
             time >= 0 and is_pid(pid) and
             node(pid) === node() do
    tRef = :erlang.send_after(time, pid, message)
    {:ok, {:send_local, tRef}}
  end

  def send_after(time, pid, message) when is_pid(pid) do
    apply_after(time, :timer, :send, [pid, message])
  end

  def send_after(time, regName, message) when is_atom(regName) do
    apply_after(time, :timer, :send, [regName, message])
  end

  def send_after(time, {regName, node} = dest, message)
      when is_atom(regName) and is_atom(node) do
    apply_after(time, :timer, :send, [dest, message])
  end

  def send_after(_Time, _PidOrRegName, _Message) do
    {:error, :badarg}
  end

  def send_after(time, message) do
    send_after(time, self(), message)
  end

  def exit_after(time, pid, reason) do
    apply_after(time, :erlang, :exit, [pid, reason])
  end

  def exit_after(time, reason) do
    exit_after(time, self(), reason)
  end

  def kill_after(time, pid) do
    exit_after(time, pid, :kill)
  end

  def kill_after(time) do
    exit_after(time, self(), :kill)
  end

  def apply_interval(time, m, f, a)
      when is_integer(time) and
             time >= 0 and is_atom(m) and is_atom(f) and
             is_list(a) do
    req(
      :apply_interval,
      {system_time(), time, self(), {m, f, a}}
    )
  end

  def apply_interval(_Time, _M, _F, _A) do
    {:error, :badarg}
  end

  def apply_repeatedly(time, m, f, a)
      when is_integer(time) and
             time >= 0 and is_atom(m) and is_atom(f) and
             is_list(a) do
    req(
      :apply_repeatedly,
      {system_time(), time, self(), {m, f, a}}
    )
  end

  def apply_repeatedly(_Time, _M, _F, _A) do
    {:error, :badarg}
  end

  def send_interval(time, pid, message)
      when is_integer(time) and
             time >= 0 and is_pid(pid) do
    req(
      :apply_interval,
      {system_time(), time, pid, {:timer, :send, [pid, message]}}
    )
  end

  def send_interval(time, regName, message)
      when is_integer(time) and time >= 0 and
             is_atom(regName) do
    req(
      :apply_interval,
      {system_time(), time, regName, {:timer, :send, [regName, message]}}
    )
  end

  def send_interval(time, dest = {regName, node}, message)
      when is_integer(time) and time >= 0 and
             is_atom(regName) and is_atom(node) do
    req(
      :apply_interval,
      {system_time(), time, dest, {:timer, :send, [dest, message]}}
    )
  end

  def send_interval(_Time, _Pid, _Message) do
    {:error, :badarg}
  end

  def send_interval(time, message) do
    send_interval(time, self(), message)
  end

  def cancel({:instant, ref}) when is_reference(ref) do
    {:ok, :cancel}
  end

  def cancel({:send_local, ref}) when is_reference(ref) do
    _ = :erlang.cancel_timer(ref)
    {:ok, :cancel}
  end

  def cancel({:once, ref} = tRef) when is_reference(ref) do
    req(:cancel, tRef)
  end

  def cancel({:interval, ref} = tRef)
      when is_reference(ref) do
    req(:cancel, tRef)
  end

  def cancel(_TRef) do
    {:error, :badarg}
  end

  def sleep(t) when is_integer(t) and t > 4_294_967_295 do
    receive do
    after
      4_294_967_295 ->
        sleep(t - 4_294_967_295)
    end
  end

  def sleep(t) do
    receive do
    after
      t ->
        :ok
    end
  end

  def tc(f) do
    tc(f, :microsecond)
  end

  def tc(f, a) when is_list(a) do
    tc(f, a, :microsecond)
  end

  def tc(f, timeUnit) do
    t1 = :erlang.monotonic_time()
    val = f.()
    t2 = :erlang.monotonic_time()
    time = :erlang.convert_time_unit(t2 - t1, :native, timeUnit)
    {time, val}
  end

  def tc(m, f, a) when is_list(a) do
    tc(m, f, a, :microsecond)
  end

  def tc(f, a, timeUnit) do
    t1 = :erlang.monotonic_time()
    val = apply(f, a)
    t2 = :erlang.monotonic_time()
    time = :erlang.convert_time_unit(t2 - t1, :native, timeUnit)
    {time, val}
  end

  def tc(m, f, a, timeUnit) do
    t1 = :erlang.monotonic_time()
    val = apply(m, f, a)
    t2 = :erlang.monotonic_time()
    time = :erlang.convert_time_unit(t2 - t1, :native, timeUnit)
    {time, val}
  end

  def now_diff({a2, b2, c2}, {a1, b1, c1}) do
    ((a2 - a1) * 1_000_000 + b2 - b1) * 1_000_000 + c2 - c1
  end

  def seconds(seconds) do
    1000 * seconds
  end

  def minutes(minutes) do
    1000 * 60 * minutes
  end

  def hours(hours) do
    1000 * 60 * 60 * hours
  end

  def hms(h, m, s) do
    hours(h) + minutes(m) + seconds(s)
  end

  def start() do
    {:ok, _Pid} = do_start()
    :ok
  end

  defp do_start() do
    case :supervisor.start_child(
           :kernel_sup,
           %{
             id: :timer_server,
             start: {:timer, :start_link, []},
             restart: :permanent,
             shutdown: 1000,
             type: :worker,
             modules: [:timer]
           }
         ) do
      {:ok, pid} ->
        {:ok, pid}

      {:ok, pid, _} ->
        {:ok, pid}

      {:error, {:already_started, pid}} ->
        {:ok, pid}

      {:error, :already_present} ->
        case :supervisor.restart_child(
               :kernel_sup,
               :timer_server
             ) do
          {:ok, pid} ->
            {:ok, pid}

          {:error, {:already_started, pid}} ->
            {:ok, pid}
        end

      error ->
        error
    end
  end

  def start_link() do
    :gen_server.start_link({:local, :timer_server}, :timer, [], [])
  end

  def init([]) do
    :erlang.process_flag(:trap_exit, true)
    tab = :ets.new(:timer, [])
    {:ok, tab}
  end

  defp req(req, arg) do
    try do
      maybe_req(req, arg)
    catch
      :exit, {:noproc, _} ->
        {:ok, _Pid} = do_start()
        maybe_req(req, arg)
    end
  end

  defp maybe_req(req, arg) do
    :gen_server.call(:timer_server, {req, arg}, :infinity)
  end

  def handle_call({:apply_once, {started, time, mFA}}, _From, tab) do
    timeout = started + time

    reply =
      try do
        :erlang.start_timer(timeout, self(), {:apply_once, mFA}, [{:abs, true}])
      catch
        :error, :badarg ->
          {:error, :badarg}
      else
        sRef ->
          :ets.insert(tab, {sRef})
          {:ok, {:once, sRef}}
      end

    {:reply, reply, tab}
  end

  def handle_call({:apply_interval, {started, time, pid, mFA}}, _From, tab) do
    {tRef, tPid, tag} = start_interval_loop(started, time, pid, mFA, false)
    :ets.insert(tab, {tRef, tPid, tag})
    {:reply, {:ok, {:interval, tRef}}, tab}
  end

  def handle_call({:apply_repeatedly, {started, time, pid, mFA}}, _From, tab) do
    {tRef, tPid, tag} = start_interval_loop(started, time, pid, mFA, true)
    :ets.insert(tab, {tRef, tPid, tag})
    {:reply, {:ok, {:interval, tRef}}, tab}
  end

  def handle_call({:cancel, {:once, tRef}}, _From, tab) do
    _ = remove_timer(tRef, tab)
    {:reply, {:ok, :cancel}, tab}
  end

  def handle_call({:cancel, {:interval, tRef}}, _From, tab) do
    _ =
      case remove_timer(tRef, tab) do
        true ->
          :erlang.demonitor(tRef, [:flush])

        false ->
          :ok
      end

    {:reply, {:ok, :cancel}, tab}
  end

  def handle_call(_Req, _From, tab) do
    {:noreply, tab}
  end

  def handle_info({:timeout, tRef, {:apply_once, mFA}}, tab) do
    _ =
      case :ets.take(tab, tRef) do
        [{^tRef}] ->
          do_apply(mFA, false)

        [] ->
          :ok
      end

    {:noreply, tab}
  end

  def handle_info({:DOWN, tRef, :process, _Pid, _Reason}, tab) do
    _ = remove_timer(tRef, tab)
    {:noreply, tab}
  end

  def handle_info(_Req, tab) do
    {:noreply, tab}
  end

  def handle_cast(_Req, tab) do
    {:noreply, tab}
  end

  def terminate(_Reason, :undefined) do
    :ok
  end

  def terminate(reason, tab) do
    _ =
      :ets.foldl(
        fn
          {tRef}, acc ->
            _ = cancel_timer(tRef)
            acc

          {_TRef, tPid, tag}, acc ->
            send(tPid, {:cancel, tag})
            acc
        end,
        :undefined,
        tab
      )

    true = :ets.delete(tab)
    terminate(reason, :undefined)
  end

  def code_change(_OldVsn, tab, _Extra) do
    {:ok, tab}
  end

  defp start_interval_loop(started, time, targetPid, mFA, waitComplete) do
    tag = make_ref()
    timeServerPid = self()

    {tPid, tRef} =
      spawn_monitor(fn ->
        timeServerRef =
          :erlang.monitor(
            :process,
            timeServerPid
          )

        targetRef =
          :erlang.monitor(
            :process,
            targetPid
          )

        timerRef =
          schedule_interval_timer(
            started,
            time,
            mFA
          )

        _ = interval_loop(timeServerRef, targetRef, tag, waitComplete, timerRef)
      end)

    {tRef, tPid, tag}
  end

  defp interval_loop(timerServerMon, targetMon, tag, waitComplete, timerRef0) do
    receive do
      {:cancel, ^tag} ->
        :ok = cancel_timer(timerRef0)

      {:DOWN, ^timerServerMon, :process, _, _} ->
        :ok = cancel_timer(timerRef0)

      {:DOWN, ^targetMon, :process, _, _} ->
        :ok = cancel_timer(timerRef0)

      {:timeout, ^timerRef0, {:apply_interval, curTimeout, time, mFA}} ->
        case do_apply(mFA, waitComplete) do
          {:ok, {:spawn, actionMon}} ->
            receive do
              {:cancel, ^tag} ->
                :ok

              {:DOWN, ^timerServerMon, :process, _, _} ->
                :ok

              {:DOWN, ^targetMon, :process, _, _} ->
                :ok

              {:DOWN, ^actionMon, :process, _, _} ->
                timerRef1 = schedule_interval_timer(curTimeout, time, mFA)
                interval_loop(timerServerMon, targetMon, tag, waitComplete, timerRef1)
            end

          _ ->
            timerRef1 = schedule_interval_timer(curTimeout, time, mFA)
            interval_loop(timerServerMon, targetMon, tag, waitComplete, timerRef1)
        end
    end
  end

  defp schedule_interval_timer(curTimeout, time, mFA) do
    nextTimeout = curTimeout + time

    case nextTimeout <= system_time() do
      true ->
        timerRef = make_ref()
        send(self(), {:timeout, timerRef, {:apply_interval, nextTimeout, time, mFA}})
        timerRef

      false ->
        :erlang.start_timer(nextTimeout, self(), {:apply_interval, nextTimeout, time, mFA}, [
          {:abs, true}
        ])
    end
  end

  defp remove_timer(tRef, tab) do
    case :ets.take(tab, tRef) do
      [{^tRef}] ->
        :ok = cancel_timer(tRef)
        true

      [{^tRef, tPid, tag}] ->
        send(tPid, {:cancel, tag})
        true

      [] ->
        false
    end
  end

  defp cancel_timer(tRef) do
    :erlang.cancel_timer(
      tRef,
      [{:async, true}, {:info, false}]
    )
  end

  defp do_apply({:timer, :send, a}, _) do
    try do
      send(a)
    catch
      _, _ ->
        :error
    else
      _ ->
        {:ok, :send}
    end
  end

  defp do_apply({:erlang, :exit, [name, reason]}, _) do
    try do
      :erlang.exit(get_pid(name), reason)
    catch
      _, _ ->
        :error
    else
      _ ->
        {:ok, :exit}
    end
  end

  defp do_apply({m, f, a}, false) do
    try do
      spawn(m, f, a)
    catch
      :error, :badarg ->
        :error
    else
      _ ->
        {:ok, :spawn}
    end
  end

  defp do_apply({m, f, a}, true) do
    try do
      spawn_monitor(m, f, a)
    catch
      :error, :badarg ->
        :error
    else
      {_, ref} ->
        {:ok, {:spawn, ref}}
    end
  end

  defp system_time() do
    div(:erlang.monotonic_time(:microsecond) + 999, 1000)
  end

  defp send([pid, msg]) do
    send(pid, msg)
  end

  defp get_pid(name) when is_pid(name) do
    name
  end

  defp get_pid(:undefined) do
    :undefined
  end

  defp get_pid(name) when is_atom(name) do
    get_pid(:erlang.whereis(name))
  end

  defp get_pid(_) do
    :undefined
  end
end
