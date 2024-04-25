defmodule :m_sasl_report do
  use Bitwise

  def format_report(fd, what, report) do
    io_report(:io_lib, fd, what, report)
  end

  def write_report(fd, what, report) do
    io_report(:io, fd, what, report)
  end

  defp io_report(iO, fd, what, {time, {:error_report, _GL, {pid, type, report}}}) do
    case is_my_error_report(what, type) do
      true ->
        head = write_head(type, time, pid)
        write_report2(iO, fd, head, type, report)

      _ ->
        true
    end
  end

  defp io_report(iO, fd, what, {time, {:info_report, _GL, {pid, type, report}}}) do
    case is_my_info_report(what, type) do
      true ->
        head = write_head(type, time, pid)
        write_report2(iO, fd, head, type, report)

      _ ->
        true
    end
  end

  defp io_report(_IO, _Fd, _, _) do
    false
  end

  defp is_my_error_report(:all, type) do
    is_my_error_report(type)
  end

  defp is_my_error_report(:error, type) do
    is_my_error_report(type)
  end

  defp is_my_error_report(_, _Type) do
    false
  end

  defp is_my_error_report(:supervisor_report) do
    true
  end

  defp is_my_error_report(:crash_report) do
    true
  end

  defp is_my_error_report(_) do
    false
  end

  defp is_my_info_report(:all, type) do
    is_my_info_report(type)
  end

  defp is_my_info_report(:progress, type) do
    is_my_info_report(type)
  end

  defp is_my_info_report(_, _Type) do
    false
  end

  defp is_my_info_report(:progress) do
    true
  end

  defp is_my_info_report(_) do
    false
  end

  defp write_report2(iO, fd, head, :supervisor_report, report) do
    name = sup_get(:supervisor, report)
    context = sup_get(:errorContext, report)
    reason = sup_get(:reason, report)
    offender = sup_get(:offender, report)
    enc = encoding(fd)

    {fmtString, args} =
      supervisor_format(
        [name, context, reason, offender],
        enc
      )

    string = :io_lib.format(fmtString, args)
    write_report_action(iO, fd, head, string)
  end

  defp write_report2(iO, fd, head, :progress, report) do
    encoding = encoding(fd)
    depth = :error_logger.get_format_depth()
    string = format_key_val(report, encoding, depth)
    write_report_action(iO, fd, head, string)
  end

  defp write_report2(iO, fd, head, :crash_report, report) do
    encoding = encoding(fd)
    depth = :error_logger.get_format_depth()
    string = :proc_lib.format(report, encoding, depth)
    write_report_action(iO, fd, head, string)
  end

  defp supervisor_format(args0, encoding) do
    {p, tl} = p(encoding, :error_logger.get_format_depth())
    [a, b, c, d] = args0
    args = [a | tl] ++ [b | tl] ++ [c | tl] ++ [d | tl]

    {~c"     Supervisor: ~" ++
       p ++
       ~c"\n     Context:    ~" ++
       p ++ ~c"\n     Reason:     ~80.18" ++ p ++ ~c"\n     Offender:   ~80.18" ++ p ++ ~c"\n~n",
     args}
  end

  defp write_report_action(iO, fd, head, string) do
    s = [head | string]

    case iO do
      :io ->
        :io.put_chars(fd, s)

      :io_lib ->
        s
    end
  end

  defp format_key_val(rep, encoding, depth) do
    {p, tl} = p(encoding, depth)
    format_key_val1(rep, p, tl)
  end

  defp format_key_val1([{tag, data} | rep], p, tl) do
    :io_lib.format(
      ~c"    ~16w: ~" ++ p ++ ~c"\n",
      [tag, data | tl]
    ) ++ format_key_val1(rep, p, tl)
  end

  defp format_key_val1(_, _, _) do
    []
  end

  defp p(encoding, depth) do
    {letter, tl} =
      case depth do
        :unlimited ->
          {~c"p", []}

        _ ->
          {~c"P", [depth]}
      end

    p = modifier(encoding) ++ letter
    {p, tl}
  end

  defp encoding(iO) do
    case :lists.keyfind(:encoding, 1, :io.getopts(iO)) do
      false ->
        :latin1

      {:encoding, enc} ->
        enc
    end
  end

  defp modifier(:latin1) do
    ~c""
  end

  defp modifier(_) do
    ~c"t"
  end

  defp sup_get(tag, report) do
    case :lists.keysearch(tag, 1, report) do
      {:value, {_, value}} ->
        value

      _ ->
        ~c""
    end
  end

  defp maybe_utc(time) do
    case :application.get_env(:sasl, :utc_log) do
      {:ok, true} ->
        case :calendar.local_time_to_universal_time_dst(time) do
          [uTC] ->
            {:utc, uTC}

          [uTC1, _UTC2] ->
            {:utc, uTC1}

          [] ->
            time
        end

      _ ->
        time
    end
  end

  defp write_head(:supervisor_report, time, pid) do
    write_head1(~c"SUPERVISOR REPORT", maybe_utc(time), pid)
  end

  defp write_head(:crash_report, time, pid) do
    write_head1(~c"CRASH REPORT", maybe_utc(time), pid)
  end

  defp write_head(:progress, time, pid) do
    write_head1(~c"PROGRESS REPORT", maybe_utc(time), pid)
  end

  defp write_head1(type, {:utc, {{y, mo, d}, {h, mi, s}}}, pid)
       when node(pid) != node() do
    :io_lib.format(
      ~c"~n=~s==== ~p-~s-~p::~s:~s:~s UTC (~p) ===~n",
      [type, d, month(mo), y, t(h), t(mi), t(s), node(pid)]
    )
  end

  defp write_head1(type, {:utc, {{y, mo, d}, {h, mi, s}}}, _) do
    :io_lib.format(
      ~c"~n=~s==== ~p-~s-~p::~s:~s:~s UTC ===~n",
      [type, d, month(mo), y, t(h), t(mi), t(s)]
    )
  end

  defp write_head1(type, {{y, mo, d}, {h, mi, s}}, pid)
       when node(pid) != node() do
    :io_lib.format(
      ~c"~n=~s==== ~p-~s-~p::~s:~s:~s (~p) ===~n",
      [type, d, month(mo), y, t(h), t(mi), t(s), node(pid)]
    )
  end

  defp write_head1(type, {{y, mo, d}, {h, mi, s}}, _) do
    :io_lib.format(
      ~c"~n=~s==== ~p-~s-~p::~s:~s:~s ===~n",
      [type, d, month(mo), y, t(h), t(mi), t(s)]
    )
  end

  defp t(x) when is_integer(x) do
    t1(:erlang.integer_to_list(x))
  end

  defp t(_) do
    ~c""
  end

  defp t1([x]) do
    [?0, x]
  end

  defp t1(x) do
    x
  end

  defp month(1) do
    ~c"Jan"
  end

  defp month(2) do
    ~c"Feb"
  end

  defp month(3) do
    ~c"Mar"
  end

  defp month(4) do
    ~c"Apr"
  end

  defp month(5) do
    ~c"May"
  end

  defp month(6) do
    ~c"Jun"
  end

  defp month(7) do
    ~c"Jul"
  end

  defp month(8) do
    ~c"Aug"
  end

  defp month(9) do
    ~c"Sep"
  end

  defp month(10) do
    ~c"Oct"
  end

  defp month(11) do
    ~c"Nov"
  end

  defp month(12) do
    ~c"Dec"
  end
end
