defmodule :m_dialyzer_timing do
  use Bitwise

  def init(active) do
    case active do
      true ->
        :io.format(~c"\n")

        spawn_link(fn ->
          loop(:erlang.monotonic_time(), 0, ~c"")
        end)

      :debug ->
        :io.format(~c"\n")

        spawn_link(fn ->
          debug_loop(~c"")
        end)

      false ->
        :none
    end
  end

  defp loop(lastNow, size, unit) do
    receive do
      {:stamp, msg, now} ->
        :io.format(~c"    ~-10s (+~4.2fs):", [msg, diff(now, lastNow)])
        loop(now, 0, ~c"")

      {:stamp, now} ->
        sizeStr =
          case size do
            0 ->
              ~c""

            _ ->
              data = :io_lib.format(~c"~p ~s", [size, unit])
              :io_lib.format(~c" (~12s)", [data])
          end

        :io.format(~c"~7.2fs~s\n", [diff(now, lastNow), sizeStr])
        loop(now, 0, ~c"")

      {:size, newSize, newUnit} ->
        loop(lastNow, newSize, newUnit)

      {pid, :stop, now} ->
        :io.format(~c"    ~-9s (+~5.2fs)\n", [~c"", diff(now, lastNow)])
        send(pid, :ok)

      {pid, :stop} ->
        send(pid, :ok)
    end
  end

  defp debug_loop(phase) do
    receive do
      message ->
        {runtime, _} = :erlang.statistics(:wall_clock)
        procs = :erlang.system_info(:process_count)
        procMem = :erlang.memory(:total)
        status = :io_lib.format(~c"~12w ~6w ~20w", [runtime, procs, procMem])

        case message do
          {:stamp, msg, _Now} ->
            :io.format(~c"~s ~s_start\n", [status, msg])
            debug_loop(msg)

          {:stamp, _Now} ->
            :io.format(~c"~s ~s_stop\n", [status, phase])
            debug_loop(~c"")

          {pid, :stop, _Now} ->
            send(pid, :ok)

          {pid, :stop} ->
            send(pid, :ok)

          _ ->
            debug_loop(phase)
        end
    after
      50 ->
        {runtime, _} = :erlang.statistics(:wall_clock)
        procs = :erlang.system_info(:process_count)
        procMem = :erlang.memory(:total)
        status = :io_lib.format(~c"~12w ~6w ~20w", [runtime, procs, procMem])
        :io.format(~c"~s\n", [status])
        debug_loop(phase)
    end
  end

  def start_stamp(:none, _) do
    :ok
  end

  def start_stamp(pid, msg) do
    send(pid, {:stamp, msg, :erlang.monotonic_time()})
    :ok
  end

  def end_stamp(:none) do
    :ok
  end

  def end_stamp(pid) do
    send(pid, {:stamp, :erlang.monotonic_time()})
    :ok
  end

  def send_size_info(:none, _, _) do
    :ok
  end

  def send_size_info(pid, size, unit) do
    send(pid, {:size, size, unit})
    :ok
  end

  def stop(:none) do
    :ok
  end

  def stop(pid) do
    send(pid, {self(), :stop, :erlang.monotonic_time()})

    receive do
      :ok ->
        :ok
    end
  end

  defp diff(t2, t1) do
    (t2 - t1) / :erlang.convert_time_unit(1, :seconds, :native)
  end
end
