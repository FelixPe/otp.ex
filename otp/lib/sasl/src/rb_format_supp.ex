defmodule :m_rb_format_supp do
  use Bitwise

  def print(date, report, device) do
    line = 79
    {_Time, rep} = report

    case rep do
      {:error_report, _GL, {pid, :crash_report, crashReport}} ->
        header = format_h(line, ~c"CRASH REPORT", pid, date)

        :format_lib_supp.print_info(device, line, [
          {:header, header}
          | format_c(crashReport)
        ])

        true

      {:error_report, _GL, {pid, :supervisor_report, supReport}} ->
        header = format_h(line, ~c"SUPERVISOR REPORT", pid, date)
        :format_lib_supp.print_info(device, line, [{:header, header} | format_s(supReport)])
        true

      {:error_report, _GL, {pid, _Type, report1}} ->
        header = format_h(line, ~c"ERROR REPORT", pid, date)
        :format_lib_supp.print_info(device, line, [{:header, header}, {:data, report1}])
        true

      {:info_report, _GL, {pid, :progress, supProgress}} ->
        header = format_h(line, ~c"PROGRESS REPORT", pid, date)

        :format_lib_supp.print_info(device, line, [
          {:header, header}
          | format_p(supProgress)
        ])

      {:info_report, _GL, {pid, _Type, report1}} ->
        header = format_h(line, ~c"INFO REPORT", pid, date)
        :format_lib_supp.print_info(device, line, [{:header, header}, {:data, report1}])
        true

      {:warning_report, _GL, {pid, _Type, report1}} ->
        header = format_h(line, ~c"WARNING REPORT", pid, date)
        :format_lib_supp.print_info(device, line, [{:header, header}, {:data, report1}])
        true

      {:error, _GL, {pid, format, args}} ->
        header = format_h(line, ~c"ERROR REPORT", pid, date)
        :format_lib_supp.print_info(device, line, [{:header, header}])
        :io.format(device, format, args)

      {:info_msg, _GL, {pid, format, args}} ->
        header = format_h(line, ~c"INFO REPORT", pid, date)
        :format_lib_supp.print_info(device, line, [{:header, header}])
        :io.format(device, format, args)

      {:warning_msg, _GL, {pid, format, args}} ->
        header = format_h(line, ~c"WARNING REPORT", pid, date)
        :format_lib_supp.print_info(device, line, [{:header, header}])
        :io.format(device, format, args)

      {type, _GL, typeReport} ->
        modifier = :misc_supp.modifier(device)
        :io.format(device, ~c"~nInfo type <~" ++ modifier ++ ~c"w> ~s~n", [type, date])
        :io.format(device, ~c"~" ++ modifier ++ ~c"p", [typeReport])

      _ ->
        modifier = :misc_supp.modifier(device)
        :io.format(~c"~nPrinting info of unknown type... ~s~n", [date])
        :io.format(device, ~c"~" ++ modifier ++ ~c"p", [report])
    end
  end

  defp format_h(line, header, pid, date) do
    nHeader =
      :lists.flatten(
        :io_lib.format(
          ~c"~s  ~w",
          [header, pid]
        )
      )

    dateLen = :string.length(date)
    headerLen = line - dateLen
    format = :lists.concat([~c"~-", headerLen, ~c"s~", dateLen, ~c"s"])
    :io_lib.format(format, [nHeader, date])
  end

  defp format_c([ownReport, linkReport]) do
    [{:items, {~c"Crashing process", ownReport}}, format_neighbours(linkReport)]
  end

  defp format_neighbours([data | rest]) do
    [
      {:newline, 1},
      {:items, {~c"Neighbour process", data}}
      | format_neighbours(rest)
    ]
  end

  defp format_neighbours([]) do
    []
  end

  defp format_s(data) do
    superName = get_opt(:supervisor, data)
    errorContext = get_opt(:errorContext, data)
    reason = get_opt(:reason, data)
    childInfo = get_opt(:offender, data)

    [
      {:data, [{~c"Reporting supervisor", superName}]},
      {:newline, 1},
      {:items,
       {~c"Child process",
        [
          {:errorContext, errorContext},
          {:reason, reason}
          | :lists.map(
              fn cI ->
                transform_mfa(cI)
              end,
              childInfo
            )
        ]}}
    ]
  end

  defp transform_mfa({:mfa, value}) do
    {:start_function, value}
  end

  defp transform_mfa(x) do
    x
  end

  defp format_p(data) do
    [{:data, data}]
  end

  defp get_opt(key, list) do
    case :lists.keysearch(key, 1, list) do
      {:value, {_Key, val}} ->
        val

      _ ->
        :undefined
    end
  end
end
