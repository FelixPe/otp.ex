defmodule :m_error_logger_file_h do
  use Bitwise
  @behaviour :gen_event
  require Record

  Record.defrecord(:r_st, :st,
    fd: :undefined,
    filename: :undefined,
    prev_handler: :undefined,
    depth: :unlimited
  )

  def init({file, {:error_logger, buf}}) do
    case init(file, :error_logger) do
      {:ok, state} ->
        write_events(state, buf)
        {:ok, state}

      error ->
        error
    end
  end

  def init(file) do
    init(file, [])
  end

  defp init(file, prevHandler) do
    :erlang.process_flag(:trap_exit, true)

    case :file.open(file, [:write, {:encoding, :utf8}]) do
      {:ok, fd} ->
        depth = :error_logger.get_format_depth()
        state = r_st(fd: fd, filename: file, prev_handler: prevHandler, depth: depth)
        {:ok, state}

      error ->
        error
    end
  end

  def handle_event({_Type, gL, _Msg}, state)
      when node(gL) !== node() do
    {:ok, state}
  end

  def handle_event(event, state) do
    write_event(state, event)
    {:ok, state}
  end

  def handle_info(
        {:EXIT, fd, _Reason},
        r_st(fd: fd, prev_handler: prevHandler)
      ) do
    case prevHandler do
      [] ->
        :remove_handler

      _ ->
        {:swap_handler, :install_prev, [], prevHandler, :go_back}
    end
  end

  def handle_info(_, state) do
    {:ok, state}
  end

  def handle_call(:filename, r_st(filename: file) = state) do
    {:ok, file, state}
  end

  def handle_call(_Query, state) do
    {:ok, {:error, :bad_query}, state}
  end

  def terminate(_Reason, r_st(fd: fd)) do
    :file.close(fd)
  end

  def code_change(_OldVsn, state, _Extra) do
    {:ok, state}
  end

  defp write_events(state, [ev | es]) do
    write_events(state, es)
    write_event(state, ev)
  end

  defp write_events(_State, []) do
    :ok
  end

  defp write_event(r_st(fd: fd) = state, event) do
    case parse_event(event) do
      :ignore ->
        :ok

      {head, pid, formatList} ->
        time = :erlang.universaltime()
        header = header(time, head)
        body = format_body(state, formatList)

        atNode =
          cond do
            node(pid) !== node() ->
              [~c"** at node ", :erlang.atom_to_list(node(pid)), ~c" **\n"]

            true ->
              []
          end

        :io.put_chars(fd, [header, atNode, body])
    end
  end

  defp format_body(state, [{format, args} | t]) do
    s =
      try do
        format(state, format, args)
      catch
        _, _ ->
          format(state, ~c"ERROR: ~tp - ~tp\n", [format, args])
      else
        s0 ->
          s0
      end

    [s | format_body(state, t)]
  end

  defp format_body(_State, []) do
    []
  end

  defp format(r_st(depth: :unlimited), format, args) do
    :io_lib.format(format, args)
  end

  defp format(r_st(depth: depth), format0, args) do
    format1 = :io_lib.scan_format(format0, args)
    format = limit_format(format1, depth)
    :io_lib.build_text(format)
  end

  defp limit_format([%{control_char: c0} = m0 | t], depth)
       when c0 === ?p or c0 === ?w do
    c = c0 - (?a - ?A)
    %{args: args} = m0
    m = %{m0 | control_char: c, args: args ++ [depth]}
    [m | limit_format(t, depth)]
  end

  defp limit_format([h | t], depth) do
    [h | limit_format(t, depth)]
  end

  defp limit_format([], _) do
    []
  end

  defp parse_event({:error, _GL, {pid, format, args}}) do
    {~c"ERROR REPORT", pid, [{format, args}]}
  end

  defp parse_event({:info_msg, _GL, {pid, format, args}}) do
    {~c"INFO REPORT", pid, [{format, args}]}
  end

  defp parse_event({:warning_msg, _GL, {pid, format, args}}) do
    {~c"WARNING REPORT", pid, [{format, args}]}
  end

  defp parse_event({:error_report, _GL, {pid, :std_error, args}}) do
    {~c"ERROR REPORT", pid, format_term(args)}
  end

  defp parse_event({:info_report, _GL, {pid, :std_info, args}}) do
    {~c"INFO REPORT", pid, format_term(args)}
  end

  defp parse_event({:warning_report, _GL, {pid, :std_warning, args}}) do
    {~c"WARNING REPORT", pid, format_term(args)}
  end

  defp parse_event(_) do
    :ignore
  end

  defp format_term(term) when is_list(term) do
    case string_p(:lists.flatten(term)) do
      true ->
        [{~c"~ts\n", [term]}]

      false ->
        format_term_list(term)
    end
  end

  defp format_term(term) do
    [{~c"~tp\n", [term]}]
  end

  defp format_term_list([{tag, data} | t]) do
    [{~c"    ~tp: ~tp\n", [tag, data]} | format_term_list(t)]
  end

  defp format_term_list([data | t]) do
    [{~c"    ~tp\n", [data]} | format_term_list(t)]
  end

  defp format_term_list([]) do
    []
  end

  defp string_p([]) do
    false
  end

  defp string_p(flatList) do
    :io_lib.printable_list(flatList)
  end

  defp get_utc_config() do
    case :application.get_env(:sasl, :utc_log) do
      {:ok, val} ->
        val

      :undefined ->
        case :application.get_env(:stdlib, :utc_log) do
          {:ok, val} ->
            val

          :undefined ->
            false
        end
    end
  end

  defp header(time, title) do
    case get_utc_config() do
      true ->
        header(time, title, ~c"UTC ")

      _ ->
        header(:calendar.universal_time_to_local_time(time), title, ~c"")
    end
  end

  defp header({{y, mo, d}, {h, mi, s}}, title, uTC) do
    :io_lib.format(
      ~c"~n=~ts==== ~p-~s-~p::~s:~s:~s ~s===~n",
      [title, d, month(mo), y, t(h), t(mi), t(s), uTC]
    )
  end

  defp t(x) when is_integer(x) do
    t1(:erlang.integer_to_list(x))
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
