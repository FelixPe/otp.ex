defmodule :m_yeccscan do
  use Bitwise
  def scan(inport) do
    scan(inport, :"", {1, 1})
  end

  def scan(inport, prompt, location1) do
    case ((try do
            :io.scan_erl_form(inport, prompt, location1,
                                [:text, :return])
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      {:eof, location2} ->
        {:eof, location2}
      {:ok, tokens, location2} ->
        lexedTokens = lex(tokens)
        parsableTokens = (for token <- lexedTokens,
                                :erlang.element(1, token) !== :white_space,
                                :erlang.element(1, token) !== :comment do
                            token
                          end)
        case (parsableTokens) do
          [] ->
            scan(inport, prompt, location2)
          _ ->
            {:ok, lexedTokens, parsableTokens, location2}
        end
      {:error, reason} ->
        {:error, reason}
      {:error, descriptor, location2} ->
        {:error, descriptor, location2}
      {:EXIT, why} ->
        :io.format(:"yeccscan: Error scanning input line ~s~n", [pos(location1)])
        exit(why)
    end
  end

  defp pos({line, col}) do
    :io_lib.format('~w:~w', [line, col])
  end

  defp pos(line) do
    :io_lib.format('~w', [line])
  end

  defp lex([]) do
    []
  end

  defp lex([token | tokens]) do
    case (token) do
      {:dot, location} ->
        [{:dot, location} | lex(tokens)]
      {:":", location} ->
        [{:":", location} | lex(tokens)]
      {:"->", location} ->
        [{:"->", location} | lex(tokens)]
      {category, location, symbol} ->
        [{category, location, symbol} | lex(tokens)]
      {other, location} ->
        cat = (case (:erl_scan.reserved_word(other)) do
                 true ->
                   :reserved_word
                 false ->
                   :reserved_symbol
               end)
        [{cat, location, other} | lex(tokens)]
    end
  end

end