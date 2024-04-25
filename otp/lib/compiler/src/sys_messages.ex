defmodule :m_sys_messages do
  use Bitwise

  def format_messages(f, p, [{:none, mod, e} | es], opts) do
    m = {:none, :io_lib.format(~c"~ts: ~s~ts\n", [f, p, mod.format_error(e)])}
    [m | format_messages(f, p, es, opts)]
  end

  def format_messages(f, p, [{loc, mod, e} | es], opts) do
    startLoc = loc
    endLoc = startLoc
    src = quote_source(f, startLoc, endLoc, opts)

    msg =
      :io_lib.format(
        ~c"~ts:~ts: ~s~ts\n~ts",
        [f, fmt_pos(startLoc), p, mod.format_error(e), src]
      )

    pos = startLoc
    [{{f, pos}, msg} | format_messages(f, p, es, opts)]
  end

  def format_messages(_, _, [], _Opts) do
    []
  end

  def list_errors(f, [{:none, mod, e} | es], opts) do
    :io.fwrite(~c"~ts: ~ts\n", [f, mod.format_error(e)])
    list_errors(f, es, opts)
  end

  def list_errors(f, [{loc, mod, e} | es], opts) do
    startLoc = loc
    endLoc = startLoc
    src = quote_source(f, startLoc, endLoc, opts)

    :io.fwrite(
      ~c"~ts:~ts: ~ts\n~ts",
      [f, fmt_pos(startLoc), mod.format_error(e), src]
    )

    list_errors(f, es, opts)
  end

  def list_errors(_F, [], _Opts) do
    :ok
  end

  defp fmt_pos({line, col}) do
    :io_lib.format(~c"~w:~w", [line, col])
  end

  defp fmt_pos(line) do
    :io_lib.format(~c"~w", [line])
  end

  defp quote_source(file, startLoc, endLoc, opts) do
    case :proplists.get_bool(:brief, opts) do
      true ->
        ~c""

      false ->
        quote_source_1(file, startLoc, endLoc)
    end
  end

  defp quote_source_1(file, line, loc2) when is_integer(line) do
    quote_source_1(file, {line, 1}, loc2)
  end

  defp quote_source_1(file, loc1, line) when is_integer(line) do
    quote_source_1(file, loc1, {line, -1})
  end

  defp quote_source_1(file, {startLine, startCol}, {endLine, endCol}) do
    case :file.read_file(file) do
      {:ok, bin} ->
        enc =
          case :epp.read_encoding_from_binary(bin) do
            :none ->
              :epp.default_encoding()

            enc0 ->
              enc0
          end

        ctx =
          cond do
            startLine === endLine ->
              0

            true ->
              1
          end

        case seek_line(bin, 1, startLine - ctx) do
          {:ok, bin1} ->
            quote_source_2(bin1, enc, startLine, startCol, endLine, endCol, ctx)

          :error ->
            ~c""
        end

      {:error, _} ->
        ~c""
    end
  end

  defp quote_source_2(bin, enc, startLine, startCol, endLine, endCol, ctx) do
    case take_lines(bin, enc, startLine - ctx, endLine + ctx) do
      [] ->
        ~c""

      lines ->
        lines1 =
          case length(lines) <= 4 + ctx do
            true ->
              lines

            false ->
              before = :lists.sublist(lines, 2 + ctx)

              after__ =
                :lists.reverse(
                  :lists.sublist(
                    :lists.reverse(lines),
                    1 + ctx
                  )
                )

              before ++ [{0, ~c"..."}] ++ after__
          end

        lines2 = decorate(lines1, startLine, startCol, endLine, endCol)

        [
          for {l, text} <- lines2 do
            fmt_line(l, text)
          end,
          ?\n
        ]
    end
  end

  defp line_prefix() do
    ~c"% "
  end

  defp fmt_line(l, text) do
    {lineText, lineTextLength} = line_to_txt(l)

    [
      line_prefix(),
      :io_lib.format(
        ~c"~*.ts| ",
        [lineTextLength, lineText]
      ),
      text,
      ~c"\n"
    ]
  end

  defp line_to_txt(l) do
    lineText = :erlang.integer_to_list(abs(l))
    length = max(4, length(lineText))

    cond do
      l < 0 ->
        {~c"", length}

      true ->
        {lineText, length}
    end
  end

  defp decorate([{line, text} = l | ls], startLine, startCol, endLine, endCol)
       when line === startLine and endLine === startLine do
    s = underline(text, startCol, endCol)
    decorate(s, l, ls, startLine, startCol, endLine, endCol)
  end

  defp decorate([{line, text} = l | ls], startLine, startCol, endLine, endCol)
       when line === startLine do
    s = underline(text, startCol, :string.length(text) + 1)
    decorate(s, l, ls, startLine, startCol, endLine, endCol)
  end

  defp decorate([{_Line, _Text} = l | ls], startLine, startCol, endLine, endCol) do
    [l | decorate(ls, startLine, startCol, endLine, endCol)]
  end

  defp decorate([], _StartLine, _StartCol, _EndLine, _EndCol) do
    []
  end

  defp decorate(~c"", l, ls, startLine, startCol, endLine, endCol) do
    [l | decorate(ls, startLine, startCol, endLine, endCol)]
  end

  defp decorate(text, {line, _} = l, ls, startLine, startCol, endLine, endCol) do
    [l, {-line, text} | decorate(ls, startLine, startCol, endLine, endCol)]
  end

  defp underline(_Text, start, end__) when end__ < start do
    ~c""
  end

  defp underline(text, start, start) do
    underline(text, start, start + 1)
  end

  defp underline(text, start, end__) do
    underline(text, start, end__, 1)
  end

  defp underline([?\t | text], start, end__, n) when n < start do
    [?\t | underline(text, start, end__, n + 1)]
  end

  defp underline([_ | text], start, end__, n) when n < start do
    [?\s | underline(text, start, end__, n + 1)]
  end

  defp underline(_Text, _Start, end__, n) do
    underline_1(n, end__)
  end

  defp underline_1(n, end__) when n < end__ do
    [?^ | underline_1(n + 1, end__)]
  end

  defp underline_1(_N, _End) do
    ~c""
  end

  defp seek_line(bin, l, l) do
    {:ok, bin}
  end

  defp seek_line(<<?\n, rest::binary>>, n, l) do
    seek_line(rest, n + 1, l)
  end

  defp seek_line(<<?\r, ?\n, rest::binary>>, n, l) do
    seek_line(rest, n + 1, l)
  end

  defp seek_line(<<_, rest::binary>>, n, l) do
    seek_line(rest, n, l)
  end

  defp seek_line(<<>>, _, _) do
    :error
  end

  defp take_lines(<<>>, _Enc, _Here, _To) do
    []
  end

  defp take_lines(bin, enc, here, to) when here <= to do
    {text, rest} = take_line(bin, <<>>)
    [{here, text_to_string(text, enc)} | take_lines(rest, enc, here + 1, to)]
  end

  defp take_lines(_Bin, _Enc, _Here, _To) do
    []
  end

  defp text_to_string(text, enc) do
    case :unicode.characters_to_list(text, enc) do
      string when is_list(string) ->
        string

      {:error, string, _Rest} ->
        string

      {:incomplete, string, _Rest} ->
        string
    end
  end

  defp take_line(<<?\n, rest::binary>>, ack) do
    {ack, rest}
  end

  defp take_line(<<?\r, ?\n, rest::binary>>, ack) do
    {ack, rest}
  end

  defp take_line(<<b, rest::binary>>, ack) do
    take_line(rest, <<ack::binary, b>>)
  end

  defp take_line(<<>>, ack) do
    {ack, <<>>}
  end
end
