defmodule :m_logger_simple_h do
  use Bitwise
  def adding_handler(%{id: :simple} = config) do
    me = self()
    case (:erlang.whereis(:logger_simple_h)) do
      :undefined ->
        {pid, ref} = :erlang.spawn_opt(fn () ->
                                            init(me)
                                       end,
                                         [:link, :monitor, {:message_queue_data,
                                                              :off_heap}])
        receive do
          {:DOWN, ^ref, :process, ^pid, reason} ->
            {:error, reason}
          {^pid, :started} ->
            :erlang.demonitor(ref)
            {:ok, config}
        end
      _ ->
        {:error,
           {:handler_process_name_already_exists,
              :logger_simple_h}}
    end
  end

  def removing_handler(%{id: :simple}) do
    case (:erlang.whereis(:logger_simple_h)) do
      :undefined ->
        :ok
      pid ->
        ref = :erlang.monitor(:process, pid)
        send(pid, :stop)
        receive do
          {:DOWN, ^ref, :process, ^pid, _} ->
            :ok
        end
    end
  end

  def log(%{meta:
           %{error_logger: %{tag: :info_report, type: type}}},
           _Config)
      when type !== :std_info do
    :ok
  end

  def log(%{msg: _, meta: %{time: _} = m} = log,
           _Config) do
    _ = (case (:erlang.whereis(:logger_simple_h)) do
           :undefined ->
             case (:maps.get(:internal_log_event, m, false)) do
               false ->
                 do_log(:simple,
                          %{level: :error,
                              msg:
                              {:report, {:error, :simple_handler_process_dead}},
                              meta: %{time: :logger.timestamp()}})
               true ->
                 :ok
             end
             do_log(:simple, log)
           _ ->
             send(:logger_simple_h, {:log, log})
         end)
    :ok
  end

  def log(_, _) do
    :ok
  end

  defp init(starter) do
    :erlang.register(:logger_simple_h, self())
    send(starter, {self(), :started})
    loop(:rich, %{buffer_size: 10, dropped: 0, buffer: []})
  end

  defp loop(mode, buffer) do
    receive do
      :stop ->
        case (:logger.get_handler_config(:default)) do
          {:ok, _} ->
            replay_buffer(buffer)
          _ ->
            :ok
        end
        :erlang.unlink(:erlang.whereis(:logger))
        :ok
      {:log, %{msg: _, meta: %{time: _}} = log} ->
        newMode = do_log(mode, log)
        loop(newMode, update_buffer(buffer, log))
      _ ->
        loop(mode, buffer)
    end
  end

  defp update_buffer(%{buffer_size: 0, dropped: d} = buffer, _Log) do
    Map.put(buffer, :dropped, d + 1)
  end

  defp update_buffer(%{buffer_size: s, buffer: b} = buffer, log) do
    Map.merge(buffer, %{buffer_size: s - 1,
                          buffer: [log | b]})
  end

  defp replay_buffer(%{dropped: d, buffer: buffer}) do
    :lists.foreach(fn f
                   %{msg: {tag, msg}} = l when tag === :string or
                                                 tag === :report
                                               ->
                     f.(%{l | msg: msg})
                   %{level: level, msg: msg, meta: mD} ->
                     :logger.log(level, msg, mD)
                   end,
                     :lists.reverse(buffer, drop_msg(d)))
  end

  defp drop_msg(0) do
    []
  end

  defp drop_msg(n) do
    [%{level: :info, msg: {'Simple handler buffer full, dropped ~w messages', [n]},
         meta: %{time: :logger.timestamp()}}]
  end

  defp do_log(:simple, log) do
    display_log(log)
    :simple
  end

  defp do_log(:rich = mode, log) do
    {pid, ref} = spawn_monitor(fn () ->
                                    str = :logger_formatter.format(log,
                                                                     %{legacy_header:
                                                                       true,
                                                                         single_line:
                                                                         false,
                                                                         depth:
                                                                         :unlimited,
                                                                         time_offset:
                                                                         ''})
                                    :erlang.display_string(:stdout,
                                                             :lists.flatten(:unicode.characters_to_list(str)))
                               end)
    receive do
      {:DOWN, ^ref, _, _, :normal} ->
        mode
      {:DOWN, ^ref, _, _, _Else} ->
        display_log(log)
        mode
    after 300 ->
      :erlang.exit(pid, :kill)
      receive do
        {:DOWN, ^ref, _, _, :normal} ->
          mode
        {:DOWN, ^ref, _, _, _Else} ->
          display_log(log)
          :simple
      end
    end
  end

  defp display_log(%{msg: {:report, report},
              meta: %{time: t, error_logger: %{type: type}}}) do
    display_date(t)
    display_report(type, report)
  end

  defp display_log(%{msg: msg, meta: %{time: t}}) do
    display_date(t)
    display(msg)
  end

  defp display_date(timestamp) when is_integer(timestamp) do
    micro = rem(timestamp, 1000000)
    sec = div(timestamp, 1000000)
    {{y, mo, d},
       {h, mi,
          s}} = :erlang.universaltime_to_localtime(:erlang.posixtime_to_universaltime(sec))
    :erlang.display_string(:stdout,
                             :erlang.integer_to_list(y) ++ '-' ++ pad(mo,
                                                                      2) ++ '-' ++ pad(d,
                                                                                       2) ++ ' ' ++ pad(h,
                                                                                                        2) ++ ':' ++ pad(mi,
                                                                                                                         2) ++ ':' ++ pad(s,
                                                                                                                                          2) ++ '.' ++ pad(micro,
                                                                                                                                                           6) ++ ' ')
  end

  defp pad(int, size) when is_integer(int) do
    pad(:erlang.integer_to_list(int), size)
  end

  defp pad(str, size) when length(str) == size do
    str
  end

  defp pad(str, size) do
    pad([?0 | str], size)
  end

  defp display({:string, chardata}) do
    try do
      :unicode.characters_to_list(chardata)
    catch
      _, _ ->
        :erlang.display(chardata)
    else
      string ->
        :erlang.display_string(:stdout, string)
        :erlang.display_string(:stdout, '\n')
    end
  end

  defp display({:report, report}) when is_map(report) do
    display_report(:maps.to_list(report))
  end

  defp display({:report, report}) do
    display_report(report)
  end

  defp display({f, a}) when (is_list(f) and is_list(a)) do
    :erlang.display_string(:stdout, f ++ '\n')
    for arg <- a do
      (
        :erlang.display_string(:stdout, '\t')
        :erlang.display(arg)
      )
    end
    :ok
  end

  defp display_report(atom, a) when is_atom(atom) do
    columnWidth = 20
    atomString = :erlang.atom_to_list(atom)
    atomLength = length(atomString)
    padding = :lists.duplicate(columnWidth - atomLength,
                                 ?\s)
    :erlang.display_string(:stdout, atomString ++ padding)
    display_report(a)
  end

  defp display_report(f, a) do
    :erlang.display({f, a})
  end

  defp display_report(%{report: report}) do
    display_report(report)
  end

  defp display_report([a, []]) do
    display_report(a)
  end

  defp display_report(a = [_ | _]) do
    case (:lists.all(fn {key, _Value} ->
                          is_atom(key)
                        _ ->
                          false
                     end,
                       a)) do
      true ->
        :erlang.display_string(:stdout, '\n')
        :lists.foreach(fn {key, value} ->
                            :erlang.display_string(:stdout,
                                                     '    ' ++ :erlang.atom_to_list(key) ++ ': ')
                            :erlang.display(value)
                       end,
                         a)
      false ->
        :erlang.display(a)
    end
  end

  defp display_report(a) do
    :erlang.display(a)
  end

end