defmodule :m_edlin do
  use Bitwise
  import :lists, only: [reverse: 1, reverse: 2]

  def init() do
    :erlang.put(:key_map, :edlin_key.get_key_map())
    :erlang.put(:kill_buffer, [])
  end

  def init(pid) do
    init()

    copiedKillBuf =
      case :erlang.process_info(
             pid,
             :dictionary
           ) do
        {:dictionary, dict} ->
          case :proplists.get_value(:kill_buffer, dict) do
            :undefined ->
              []

            buf ->
              buf
          end

        :undefined ->
          []
      end

    :erlang.put(:kill_buffer, copiedKillBuf)
  end

  def start(pbs) do
    start(pbs, {:normal, :none})
  end

  def start(pbs, {_, {_, []}, []} = cont) do
    {:more_chars, {:line, pbs, cont, {:normal, :none}},
     [{:insert_chars, :unicode, multi_line_prompt(pbs)}]}
  end

  def start(pbs, {_, {_, _}, _} = cont) do
    {:more_chars, {:line, pbs, cont, {:normal, :none}}, redraw(pbs, cont, [])}
  end

  def start(pbs, editState) do
    {:more_chars, {:line, pbs, {[], {[], []}, []}, editState},
     [:new_prompt, {:insert_chars, :unicode, pbs}]}
  end

  def keymap() do
    :erlang.get(:key_map)
  end

  def edit_line(cs, {:line, p, l, {:blink, n_Rs}}) do
    edit(cs, p, l, {:normal, :none}, n_Rs)
  end

  def edit_line(cs, {:line, p, l, m}) do
    edit(cs, p, l, m, [])
  end

  def edit_line1(cs, {:line, p, l, {:blink, n_Rs}}) do
    edit(cs, p, l, {:normal, :none}, n_Rs)
  end

  def edit_line1(
        cs,
        {:line, p, {b, {[], []}, a}, {:normal, :none}}
      ) do
    [
      currentLine
      | lines
    ] =
      for line <- reverse(:string.split(cs, ~c"\n", :all)) do
        :string.to_graphemes(line)
      end

    cont = {lines ++ b, {reverse(currentLine), []}, a}
    rs = redraw(p, cont, [])
    {:more_chars, {:line, p, cont, {:normal, :none}}, [:delete_line | rs]}
  end

  def edit_line1(cs, {:line, p, l, m}) do
    edit(cs, p, l, m, [])
  end

  defp edit([c | cs], p, line, {:blink, _}, [_ | rs]) do
    edit([c | cs], p, line, {:normal, :none}, rs)
  end

  defp edit([], p, l, {:blink, n}, rs) do
    {:blink, {:line, p, l, {:blink, n}}, reverse(rs)}
  end

  defp edit([], p, l, editState, rs) do
    {:more_chars, {:line, p, l, editState}, reverse(rs)}
  end

  defp edit(:eof, _, {_, {bef, aft0}, lA} = l, _, rs) do
    aft1 =
      case lA do
        [last | _] ->
          last

        _ ->
          aft0
      end

    {:done, l, [],
     reverse(
       rs,
       [{:move_combo, -cp_len(bef), length(lA), cp_len(aft1)}]
     )}
  end

  defp edit(buf, p, {lB, {bef, aft}, lA} = multiLine, {shellMode, escapePrefix}, rs0) do
    case :edlin_key.get_valid_escape_key(
           buf,
           escapePrefix
         ) do
      {:escape_prefix, escapePrefix1} ->
        case shellMode do
          :tab_expand ->
            edit(buf, p, multiLine, {:normal, :none}, rs0)

          _ ->
            edit([], p, multiLine, {shellMode, escapePrefix1}, rs0)
        end

      {:invalid, _I, rest} ->
        edit(rest, p, multiLine, {shellMode, :none}, rs0)

      {:insert, c1, cs2} ->
        op =
          case shellMode do
            :normal when c1 === ?) ->
              {:blink, ?), ?(}

            :normal when c1 === ?] ->
              {:blink, ?], ?[}

            :normal when c1 === ?} ->
              {:blink, ?}, ?{}

            :normal ->
              {:insert, c1}

            :search when ?\s <= c1 ->
              {:insert_search, c1}

            :search ->
              :search_quit

            :tab_expand ->
              :tab_expand_quit
          end

        case op do
          :tab_expand_quit ->
            edit(buf, p, multiLine, {:normal, :none}, rs0)

          :search_quit ->
            {:search_quit, cs2, {:line, p, multiLine, {:normal, :none}}, reverse(rs0)}

          _ ->
            case do_op(op, multiLine, rs0) do
              {:blink, n, multiLine1, rs} ->
                edit(cs2, p, multiLine1, {:blink, n}, rs)

              {:redraw, multiLine1, rs} ->
                edit(cs2, p, multiLine1, {shellMode, :none}, redraw(p, multiLine1, rs))

              {multiLine1, rs} ->
                edit(cs2, p, multiLine1, {shellMode, :none}, rs)
            end
        end

      {:key, key, cs} ->
        keyMap = :erlang.get(:key_map)

        value =
          case :maps.find(
                 key,
                 :maps.get(shellMode, keyMap)
               ) do
            :error ->
              case :maps.find(
                     :default,
                     :maps.get(shellMode, keyMap)
                   ) do
                :error ->
                  :none

                {:ok, value0} ->
                  value0
              end

            {:ok, value0} ->
              value0
          end

        case value do
          :none ->
            edit(cs, p, multiLine, {:normal, :none}, rs0)

          :search ->
            {:search, cs, {:line, p, multiLine, {:normal, :none}}, reverse(rs0)}

          :search_found ->
            {:search_found, cs, {:line, p, multiLine, {:normal, :none}}, reverse(rs0)}

          :search_cancel ->
            {:search_cancel, cs, {:line, p, multiLine, {:normal, :none}}, reverse(rs0)}

          :search_quit ->
            {:search_quit, cs, {:line, p, multiLine, {:normal, :none}}, reverse(rs0)}

          :open_editor ->
            {:open_editor, cs, {:line, p, multiLine, {:normal, :none}}, reverse(rs0)}

          :history_up ->
            {:history_up, cs, {:line, p, multiLine, {:normal, :none}}, reverse(rs0)}

          :history_down ->
            {:history_down, cs, {:line, p, multiLine, {:normal, :none}}, reverse(rs0)}

          :new_line ->
            multiLine1 = {[:lists.reverse(bef) | lB], {[], aft}, lA}
            edit(cs, p, multiLine1, {:normal, :none}, reverse(redraw(p, multiLine1, rs0)))

          :new_line_finish ->
            {{lB1, {bef1, []}, []}, rs1} = do_op(:end_of_expression, multiLine, rs0)

            {:done, {[:lists.reverse(bef1) | lB1], {[], []}, []}, cs,
             reverse(rs1, [{:insert_chars, :unicode, ~c"\n"}])}

          :redraw_line ->
            rs1 = erase_line(rs0)
            rs = redraw(p, multiLine, rs1)
            edit(cs, p, multiLine, {:normal, :none}, rs)

          :clear ->
            rs = redraw(p, multiLine, [:clear | rs0])
            edit(cs, p, multiLine, {:normal, :none}, rs)

          :tab_expand ->
            {:expand, chars_before(multiLine), cs, {:line, p, multiLine, {:tab_expand, :none}},
             reverse(rs0)}

          :tab_expand_full ->
            {:expand_full, chars_before(multiLine), cs,
             {:line, p, multiLine, {:tab_expand, :none}}, reverse(rs0)}

          :tab_expand_quit ->
            edit(buf, p, multiLine, {:normal, :none}, rs0)

          op ->
            op1 =
              case shellMode do
                :search ->
                  {:search, op}

                _ ->
                  op
              end

            case do_op(op1, multiLine, rs0) do
              {:blink, n, multiLine1, rs} ->
                edit(cs, p, multiLine1, {:blink, n}, rs)

              {:redraw, multiLine1, rs} ->
                edit(cs, p, multiLine1, {:normal, :none}, redraw(p, multiLine1, rs))

              {multiLine1, rs} ->
                edit(cs, p, multiLine1, {shellMode, :none}, rs)
            end
        end
    end
  end

  defp do_op({:insert, c}, {lB, {[], []}, lA}, rs) do
    {{lB, {[c], []}, lA}, [{:insert_chars, :unicode, [c]} | rs]}
  end

  defp do_op({:insert, c}, {lB, {[bef | bef0], []}, lA}, rs) do
    case :string.to_graphemes([bef, c]) do
      [gC] ->
        {{lB, {[gC | bef0], []}, lA}, [{:insert_chars, :unicode, [c]} | rs]}

      _ ->
        {{lB, {[c, bef | bef0], []}, lA}, [{:insert_chars, :unicode, [c]} | rs]}
    end
  end

  defp do_op({:insert, c}, {lB, {[], aft}, lA}, rs) do
    {{lB, {[c], aft}, lA}, [{:insert_chars, :unicode, [c]} | rs]}
  end

  defp do_op({:insert, c}, {lB, {[bef | bef0], aft}, lA}, rs) do
    case :string.to_graphemes([bef, c]) do
      [gC] ->
        {{lB, {[gC | bef0], aft}, lA}, [{:insert_chars, :unicode, [c]} | rs]}

      _ ->
        {{lB, {[c, bef | bef0], aft}, lA}, [{:insert_chars, :unicode, [c]} | rs]}
    end
  end

  defp do_op({:insert_search, c}, {lB, {bef, []}, lA}, rs) do
    {{lB, {[c | bef], []}, lA},
     [
       {:insert_chars, :unicode, [c]},
       :delete_after_cursor
       | rs
     ]}
  end

  defp do_op({:insert_search, c}, {lB, {bef, _Aft}, lA}, rs) do
    {{lB, {[c | bef], []}, lA},
     [
       {:insert_chars, :unicode, [c]},
       :delete_after_cursor
       | rs
     ], :search}
  end

  defp do_op({:search, :backward_delete_char}, {lB, {[_ | bef], aft}, lA}, rs) do
    offset = cp_len(aft) + 1

    {{lB, {bef, aft}, lA},
     [
       {:insert_chars, :unicode, aft},
       {:delete_chars, -offset}
       | rs
     ]}
  end

  defp do_op({:search, :backward_delete_char}, {lB, {[], aft}, lA}, rs) do
    {{lB, {[], aft}, lA},
     [
       {:insert_chars, :unicode, aft},
       {:delete_chars, -cp_len(aft)}
       | rs
     ]}
  end

  defp do_op({:search, :skip_up}, {_, {bef, aft}, _}, rs) do
    offset = cp_len(aft)

    {{[], {[18 | bef], aft}, []},
     [
       {:insert_chars, :unicode, aft},
       {:delete_chars, -offset}
       | rs
     ]}
  end

  defp do_op({:search, :skip_down}, {_, {bef, aft}, _LA}, rs) do
    offset = cp_len(aft)

    {{[], {[19 | bef], aft}, []},
     [
       {:insert_chars, :unicode, aft},
       {:delete_chars, -offset}
       | rs
     ]}
  end

  defp do_op({:blink, c, m}, {_, {[?$, ?$ | _], _}, _} = multiLine, rs) do
    blink(over_paren(chars_before(multiLine), c, m), c, multiLine, rs)
  end

  defp do_op({:blink, c, _}, {_, {[?$ | _], _}, _} = multiLine, rs) do
    do_op({:insert, c}, multiLine, rs)
  end

  defp do_op({:blink, c, m}, multiLine, rs) do
    blink(over_paren(chars_before(multiLine), c, m), c, multiLine, rs)
  end

  defp do_op(:auto_blink, multiLine, rs) do
    blink(over_paren_auto(chars_before(multiLine)), multiLine, rs)
  end

  defp do_op(:forward_delete_char, {lB, {bef, []}, [nextLine | lA]}, rs) do
    newLine = {lB, {bef, nextLine}, lA}
    {:redraw, newLine, rs}
  end

  defp do_op(:forward_delete_char, {lB, {bef, [gC | aft]}, lA}, rs) do
    {{lB, {bef, aft}, lA}, [{:delete_chars, gc_len(gC)} | rs]}
  end

  defp do_op(:backward_delete_char, {[prevLine | lB], {[], aft}, lA}, rs) do
    newLine = {lB, {:lists.reverse(prevLine), aft}, lA}
    {:redraw, newLine, rs}
  end

  defp do_op(:backward_delete_char, {lB, {[gC | bef], aft}, lA}, rs) do
    {{lB, {bef, aft}, lA}, [{:delete_chars, -gc_len(gC)} | rs]}
  end

  defp do_op(:forward_delete_word, {lB, {bef, []}, [nextLine | lA]}, rs) do
    newLine = {lB, {bef, nextLine}, lA}
    {:redraw, newLine, rs}
  end

  defp do_op(:forward_delete_word, {lB, {bef, aft0}, lA}, rs) do
    {aft1, kill0, n0} = over_non_word(aft0, [], 0)
    {aft, kill, n} = over_word(aft1, kill0, n0)
    :erlang.put(:kill_buffer, reverse(kill))
    {{lB, {bef, aft}, lA}, [{:delete_chars, n} | rs]}
  end

  defp do_op(:backward_delete_word, {[prevLine | lB], {[], aft}, lA}, rs) do
    newLine = {lB, {:lists.reverse(prevLine), aft}, lA}
    {:redraw, newLine, rs}
  end

  defp do_op(:backward_delete_word, {lB, {bef0, aft}, lA}, rs) do
    {bef1, kill0, n0} = over_non_word(bef0, [], 0)
    {bef, kill, n} = over_word(bef1, kill0, n0)
    :erlang.put(:kill_buffer, kill)
    {{lB, {bef, aft}, lA}, [{:delete_chars, -n} | rs]}
  end

  defp do_op(:transpose_char, {lB, {[c1, c2 | bef], []}, lA}, rs) do
    len = gc_len(c1) + gc_len(c2)

    {{lB, {[c2, c1 | bef], []}, lA},
     [
       {:insert_chars_over, :unicode, [c1, c2]},
       {:move_rel, -len}
       | rs
     ]}
  end

  defp do_op(:transpose_char, {lB, {[c2 | bef], [c1 | aft]}, lA}, rs) do
    len = gc_len(c2)

    {{lB, {[c2, c1 | bef], aft}, lA},
     [
       {:insert_chars_over, :unicode, [c1, c2]},
       {:move_rel, -len}
       | rs
     ]}
  end

  defp do_op(:transpose_word, {lB, {bef0, aft0}, lA}, rs) do
    {aft1, word2A, n0} = over_word(aft0, [], 0)

    {bef, transposedWords, aft, n} =
      case n0 do
        0 ->
          {aft2, nonWord, n1} = over_non_word(aft1, [], 0)

          case n1 do
            0 ->
              {bef1, word2B, b0} = over_word(bef0, [], 0)
              {bef2, nonWordB, b1} = over_non_word(bef1, [], b0)
              {bef3, word1, b2} = over_word(bef2, [], b1)
              {bef3, word2B ++ nonWordB ++ word1, aft0, b2}

            _ ->
              {aft3, word2, n2} = over_word(aft2, [], n1)

              case n2 do
                0 ->
                  {bef1, word2B, b0} = over_word(bef0, [], 0)

                  {bef2, nonWordB, b1} =
                    over_non_word(
                      bef1,
                      [],
                      b0
                    )

                  {bef3, word1, b2} = over_word(bef2, [], b1)
                  {bef3, word2B ++ nonWordB ++ word1, aft0, b2}

                _ ->
                  {bef1, nonWord2, b0} =
                    over_non_word(
                      bef0,
                      [],
                      0
                    )

                  {bef2, word1, b1} = over_word(bef1, [], b0)
                  {bef2, reverse(word2) ++ nonWord2 ++ reverse(nonWord) ++ word1, aft3, b1}
              end
          end

        _ ->
          {bef1, word2B, b0} =
            over_word(
              bef0,
              [],
              0
            )

          {bef2, nonWord, b1} = over_non_word(bef1, [], b0)

          {bef3, word1, b2} =
            over_word(
              bef2,
              [],
              b1
            )

          {bef3, word2B ++ reverse(word2A) ++ nonWord ++ word1, aft1, b2}
      end

    {{lB, {reverse(transposedWords) ++ bef, aft}, lA},
     [{:insert_chars_over, :unicode, transposedWords}, {:move_rel, -n} | rs]}
  end

  defp do_op(:kill_word, {lB, {bef, aft0}, lA}, rs) do
    {aft1, kill0, n0} = over_non_word(aft0, [], 0)
    {aft, kill, n} = over_word(aft1, kill0, n0)
    :erlang.put(:kill_buffer, reverse(kill))
    {{lB, {bef, aft}, lA}, [{:delete_chars, n} | rs]}
  end

  defp do_op(:backward_kill_word, {lB, {bef0, aft}, lA}, rs) do
    {bef1, kill0, n0} = over_non_word(bef0, [], 0)
    {bef, kill, n} = over_word(bef1, kill0, n0)
    :erlang.put(:kill_buffer, kill)
    {{lB, {bef, aft}, lA}, [{:delete_chars, -n} | rs]}
  end

  defp do_op(:kill_line, {lB, {bef, aft}, lA}, rs) do
    :erlang.put(:kill_buffer, aft)
    {{lB, {bef, []}, lA}, [{:delete_chars, cp_len(aft)} | rs]}
  end

  defp do_op(:clear_line, _, rs) do
    {:redraw, {[], {[], []}, []}, rs}
  end

  defp do_op(:yank, {lB, {bef, []}, lA}, rs) do
    kill = :erlang.get(:kill_buffer)
    {{lB, {reverse(kill, bef), []}, lA}, [{:insert_chars, :unicode, kill} | rs]}
  end

  defp do_op(:yank, {lB, {bef, aft}, lA}, rs) do
    kill = :erlang.get(:kill_buffer)
    {{lB, {reverse(kill, bef), aft}, lA}, [{:insert_chars, :unicode, kill} | rs]}
  end

  defp do_op(:forward_line, {_, _, []} = multiLine, rs) do
    {multiLine, rs}
  end

  defp do_op(:forward_line, {lB, {bef, aft}, [aL | lA]}, rs) do
    cL = :lists.reverse(bef, aft)
    cursorPos = min(length(bef), length(aL))
    {bef1, aft1} = :lists.split(cursorPos, aL)

    {{[cL | lB], {:lists.reverse(bef1), aft1}, lA},
     [{:move_combo, -cp_len(bef), 1, cp_len(bef1)} | rs]}
  end

  defp do_op(:backward_line, {[], _, _} = multiLine, rs) do
    {multiLine, rs}
  end

  defp do_op(:backward_line, {[bL | lB], {bef, aft}, lA}, rs) do
    cL = :lists.reverse(bef, aft)
    cursorPos = min(length(bef), length(bL))
    {bef1, aft1} = :lists.split(cursorPos, bL)

    {{lB, {:lists.reverse(bef1), aft1}, [cL | lA]},
     [{:move_combo, -cp_len(bef), -1, cp_len(bef1)} | rs]}
  end

  defp do_op(:forward_char, {lB, {bef, []}, [aL | lA]}, rs) do
    {{[:lists.reverse(bef) | lB], {[], :string.to_graphemes(aL)}, lA},
     [{:move_combo, -cp_len(bef), 1, 0} | rs]}
  end

  defp do_op(:forward_char, {lB, {bef, [c | aft]}, lA}, rs) do
    {{lB, {[c | bef], aft}, lA}, [{:move_rel, gc_len(c)} | rs]}
  end

  defp do_op(:backward_char, {[bL | lB], {[], aft}, lA}, rs) do
    {{lB, {:lists.reverse(:string.to_graphemes(bL)), []}, [aft | lA]},
     [{:move_combo, 0, -1, cp_len(bL)} | rs]}
  end

  defp do_op(:backward_char, {lB, {[c | bef], aft}, lA}, rs) do
    {{lB, {bef, [c | aft]}, lA}, [{:move_rel, -gc_len(c)} | rs]}
  end

  defp do_op(:forward_word, {lB, {bef0, []}, [nextLine | lA]}, rs) do
    {{[reverse(bef0) | lB], {[], nextLine}, lA}, [{:move_combo, -cp_len(bef0), 1, 0} | rs]}
  end

  defp do_op(:forward_word, {lB, {bef0, aft0}, lA}, rs) do
    {aft1, bef1, n0} = over_non_word(aft0, bef0, 0)
    {aft, bef, n} = over_word(aft1, bef1, n0)
    {{lB, {bef, aft}, lA}, [{:move_rel, n} | rs]}
  end

  defp do_op(:backward_word, {[prevLine | lB], {[], aft0}, lA}, rs) do
    {{lB, {reverse(prevLine), []}, [aft0 | lA]}, [{:move_combo, 0, -1, cp_len(prevLine)} | rs]}
  end

  defp do_op(:backward_word, {lB, {bef0, aft0}, lA}, rs) do
    {bef1, aft1, n0} = over_non_word(bef0, aft0, 0)
    {bef, aft, n} = over_word(bef1, aft1, n0)
    {{lB, {bef, aft}, lA}, [{:move_rel, -n} | rs]}
  end

  defp do_op(:beginning_of_expression, {[], {[], aft}, lA}, rs) do
    {{[], {[], aft}, lA}, rs}
  end

  defp do_op(:beginning_of_expression, {lB, {bef, aft}, lA}, rs) do
    [
      first
      | rest
    ] = :lists.reverse(lB) ++ [:lists.reverse(bef, aft)]

    {{[], {[], first}, rest ++ lA}, [{:move_combo, -cp_len(bef), -length(lB), 0} | rs]}
  end

  defp do_op(:end_of_expression, {lB, {bef, []}, []}, rs) do
    {{lB, {bef, []}, []}, rs}
  end

  defp do_op(:end_of_expression, {lB, {bef, aft}, lA}, rs) do
    [
      last
      | rest
    ] = :lists.reverse(lA) ++ [:lists.reverse(bef, aft)]

    {{rest ++ lB, {:lists.reverse(last), []}, []},
     [
       {:move_combo, -cp_len(bef), length(lA), cp_len(last)}
       | rs
     ]}
  end

  defp do_op(:beginning_of_line, {lB, {[_ | _] = bef, aft}, lA}, rs) do
    {{lB, {[], reverse(bef, aft)}, lA}, [{:move_rel, -cp_len(bef)} | rs]}
  end

  defp do_op(:beginning_of_line, {lB, {[], aft}, lA}, rs) do
    {{lB, {[], aft}, lA}, rs}
  end

  defp do_op(:end_of_line, {lB, {bef, [_ | _] = aft}, lA}, rs) do
    {{lB, {reverse(aft, bef), []}, lA}, [{:move_rel, cp_len(aft)} | rs]}
  end

  defp do_op(:end_of_line, {lB, {bef, []}, lA}, rs) do
    {{lB, {bef, []}, lA}, rs}
  end

  defp do_op(:backward_kill_line, {lB, {bef, aft}, lA}, rs) do
    :erlang.put(:kill_buffer, reverse(bef))
    {{lB, {[], aft}, lA}, [{:delete_chars, -cp_len(bef)} | rs]}
  end

  defp do_op(:beep, {lB, {bef, aft}, lA}, rs) do
    {{lB, {bef, aft}, lA}, [:beep | rs]}
  end

  defp do_op(_, {lB, {bef, aft}, lA}, rs) do
    {{lB, {bef, aft}, lA}, [:beep | rs]}
  end

  defp blink(:beep, c, {lB, {bef, aft}, lA}, rs) do
    {{lB, {[c | bef], aft}, lA}, [:beep, {:insert_chars, :unicode, [c]} | rs]}
  end

  defp blink({n, r}, c, multiLine, rs) do
    blink({n, r, c}, multiLine, rs)
  end

  defp blink(:beep, {lB, {bef, aft}, lA}, rs) do
    {{lB, {bef, aft}, lA}, [:beep | rs]}
  end

  defp blink({n, 0, paren}, {lB, {bef, aft}, lA}, rs) do
    moveBackToParen = {:move_rel, -n - 1}
    moveForwardToParen = {:move_rel, n + 1}

    {:blink, [moveForwardToParen], {lB, {[paren | bef], aft}, lA},
     [
       moveBackToParen,
       {:insert_chars, :unicode, [paren]}
       | rs
     ]}
  end

  defp blink({n, r, paren}, {lB, {bef, aft}, lA}, rs) do
    lengthToClosingParen = cp_len([paren | bef])
    lengthOpeningParen = cp_len(:lists.nth(r, lB)) - n - 1
    moveToOpeningParen = {:move_combo, -lengthToClosingParen, -r, lengthOpeningParen}
    moveToClosingParen = {:move_combo, -lengthOpeningParen, r, lengthToClosingParen + 1}

    {:blink, [moveToClosingParen], {lB, {[paren | bef], aft}, lA},
     [
       moveToOpeningParen,
       {:insert_chars, :unicode, [paren]}
       | rs
     ]}
  end

  def over_word(cs, stack, n) do
    l =
      length(
        for ?' <- cs do
          1
        end
      )

    case rem(l, 2) do
      0 ->
        over_word1(cs, stack, n)

      1 ->
        until_quote(cs, stack, n)
    end
  end

  defp until_quote([?' | cs], stack, n) do
    {cs, [?' | stack], n + 1}
  end

  defp until_quote([c | cs], stack, n) do
    until_quote(cs, [c | stack], n + gc_len(c))
  end

  defp over_word1([?' = c | cs], stack, n) do
    until_quote(cs, [c | stack], n + 1)
  end

  defp over_word1(cs, stack, n) do
    over_word2(cs, stack, n)
  end

  defp over_word2([c | cs], stack, n) do
    case word_char(c) do
      true ->
        over_word2(cs, [c | stack], n + gc_len(c))

      false ->
        {[c | cs], stack, n}
    end
  end

  defp over_word2([], stack, n) when is_integer(n) do
    {[], stack, n}
  end

  defp over_non_word([c | cs], stack, n) do
    case word_char(c) do
      true ->
        {[c | cs], stack, n}

      false ->
        over_non_word(cs, [c | stack], n + gc_len(c))
    end
  end

  defp over_non_word([], stack, n) do
    {[], stack, n}
  end

  defp over_paren(chars, paren, match) do
    over_paren(chars, paren, match, 1, 1, 0, [])
  end

  defp over_paren([c, ?$, ?$ | cs], paren, match, d, n, r, l) do
    over_paren([c | cs], paren, match, d, n + 2, r, l)
  end

  defp over_paren([gC, ?$ | cs], paren, match, d, n, r, l) do
    over_paren(cs, paren, match, d, n + 1 + gc_len(gC), r, l)
  end

  defp over_paren([?\n | cs], paren, match, d, _N, r, l) do
    over_paren(cs, paren, match, d, 0, r + 1, l)
  end

  defp over_paren([match | _], _Paren, match, 1, n, r, _) do
    {n, r}
  end

  defp over_paren([match | cs], paren, match, d, n, r, [match | l]) do
    over_paren(cs, paren, match, d - 1, n + 1, r, l)
  end

  defp over_paren([paren | cs], paren, match, d, n, r, l) do
    over_paren(cs, paren, match, d + 1, n + 1, r, [match | l])
  end

  defp over_paren([?) | cs], paren, match, d, n, r, l) do
    over_paren(cs, paren, match, d, n + 1, r, [?( | l])
  end

  defp over_paren([?] | cs], paren, match, d, n, r, l) do
    over_paren(cs, paren, match, d, n + 1, r, [?[ | l])
  end

  defp over_paren([?} | cs], paren, match, d, n, r, l) do
    over_paren(cs, paren, match, d, n + 1, r, [?{ | l])
  end

  defp over_paren([?( | cs], paren, match, d, n, r, [?( | l]) do
    over_paren(cs, paren, match, d, n + 1, r, l)
  end

  defp over_paren([?[ | cs], paren, match, d, n, r, [?[ | l]) do
    over_paren(cs, paren, match, d, n + 1, r, l)
  end

  defp over_paren([?{ | cs], paren, match, d, n, r, [?{ | l]) do
    over_paren(cs, paren, match, d, n + 1, r, l)
  end

  defp over_paren([?( | _], _, _, _, _, _, _) do
    :beep
  end

  defp over_paren([?[ | _], _, _, _, _, _, _) do
    :beep
  end

  defp over_paren([?{ | _], _, _, _, _, _, _) do
    :beep
  end

  defp over_paren([gC | cs], paren, match, d, n, r, l) do
    over_paren(cs, paren, match, d, n + gc_len(gC), r, l)
  end

  defp over_paren([], _, _, _, _, _, _) do
    :beep
  end

  defp over_paren_auto(chars) do
    over_paren_auto(chars, 1, 1, 0, [])
  end

  defp over_paren_auto([c, ?$, ?$ | cs], d, n, r, l) do
    over_paren_auto([c | cs], d, n + 2, r, l)
  end

  defp over_paren_auto([gC, ?$ | cs], d, n, r, l) do
    over_paren_auto(cs, d, n + 1 + gc_len(gC), r, l)
  end

  defp over_paren_auto([?\n | cs], d, _N, r, l) do
    over_paren_auto(cs, d, 0, r + 1, l)
  end

  defp over_paren_auto([?( | _], _, n, r, []) do
    {n, r, ?)}
  end

  defp over_paren_auto([?[ | _], _, n, r, []) do
    {n, r, ?]}
  end

  defp over_paren_auto([?{ | _], _, n, r, []) do
    {n, r, ?}}
  end

  defp over_paren_auto([?) | cs], d, n, r, l) do
    over_paren_auto(cs, d, n + 1, r, [?( | l])
  end

  defp over_paren_auto([?] | cs], d, n, r, l) do
    over_paren_auto(cs, d, n + 1, r, [?[ | l])
  end

  defp over_paren_auto([?} | cs], d, n, r, l) do
    over_paren_auto(cs, d, n + 1, r, [?{ | l])
  end

  defp over_paren_auto([?( | cs], d, n, r, [?( | l]) do
    over_paren_auto(cs, d, n + 1, r, l)
  end

  defp over_paren_auto([?[ | cs], d, n, r, [?[ | l]) do
    over_paren_auto(cs, d, n + 1, r, l)
  end

  defp over_paren_auto([?{ | cs], d, n, r, [?{ | l]) do
    over_paren_auto(cs, d, n + 1, r, l)
  end

  defp over_paren_auto([gC | cs], d, n, r, l) do
    over_paren_auto(cs, d, n + gc_len(gC), r, l)
  end

  defp over_paren_auto([], _, _, _, _) do
    :beep
  end

  def erase_line() do
    [:delete_line]
  end

  def erase_inp({:line, _, l, _}) do
    reverse(erase([], l, []))
  end

  defp erase_line(rs) do
    [:delete_line | rs]
  end

  defp erase(pbs, {_, {bef, aft}, _}, rs) do
    [{:delete_chars, -cp_len(pbs) - cp_len(bef)}, {:delete_chars, cp_len(aft)} | rs]
  end

  def redraw_line({:line, pbs, l, _}) do
    redraw(pbs, l, [])
  end

  defp multi_line_prompt(pbs) do
    case :application.get_env(:stdlib, :shell_multiline_prompt, :default) do
      :default ->
        default_multiline_prompt(pbs)

      {m, f} when is_atom(m) and is_atom(f) ->
        case (try do
                apply(m, f, [pbs])
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end) do
          prompt when is_list(prompt) ->
            prompt

          _ ->
            :application.set_env(:stdlib, :shell_multiline_prompt, :default)
            :io.format(~c"Invalid call: ~p:~p/1~n", [m, f])
            default_multiline_prompt(pbs)
        end

      prompt when is_list(prompt) ->
        :lists.duplicate(
          max(
            0,
            :prim_tty.npwcwidthstring(pbs) - :prim_tty.npwcwidthstring(prompt)
          ),
          ?\s
        ) ++ prompt

      prompt ->
        :application.set_env(:stdlib, :shell_multiline_prompt, :default)
        :io.format(~c"Invalid multiline prompt: ~p~n", [prompt])
        default_multiline_prompt(pbs)
    end
  end

  defp default_multiline_prompt(pbs) do
    :lists.duplicate(
      max(
        0,
        :prim_tty.npwcwidthstring(pbs) - 3
      ),
      ?\s
    ) ++ ~c".. "
  end

  def inverted_space_prompt(pbs) do
    ~c"\e[7m" ++
      :lists.duplicate(
        :prim_tty.npwcwidthstring(pbs) - 1,
        ?\s
      ) ++ ~c"\e[27m "
  end

  defp redraw(pbs, {_, {_, _}, _} = l, rs) do
    [{:redraw_prompt, pbs, multi_line_prompt(pbs), l} | rs]
  end

  defp chars_before({[], {bef, _}, _}) do
    bef
  end

  defp chars_before({lB, {bef, _}, _}) do
    :lists.flatten(
      :lists.join(
        ?\n,
        [
          bef
          | for line <- lB do
              reverse(line)
            end
        ]
      )
    )
  end

  def length_before({:line, pbs, {_, {bef, _Aft}, _}, _}) do
    cp_len(pbs) + cp_len(bef)
  end

  def length_after({:line, _, {_, {_Bef, aft}, _}, _}) do
    cp_len(aft)
  end

  def prompt({:line, pbs, _, _}) do
    pbs
  end

  def current_chars({:line, _, multiLine, _}) do
    current_line(multiLine)
  end

  def current_line({:line, _, multiLine, _}) do
    current_line(multiLine) ++ ~c"\n"
  end

  def current_line({linesBefore, {before, after__}, linesAfter}) do
    currentLine = :lists.reverse(before, after__)

    :unicode.characters_to_list(
      :lists.flatten(
        :lists.filter(
          fn x ->
            x != []
          end,
          :lists.join(
            ?\n,
            :lists.reverse(linesBefore) ++ [currentLine] ++ linesAfter
          )
        )
      )
    )
  end

  defp gc_len(cP) when is_integer(cP) do
    1
  end

  defp gc_len(cPs) when is_list(cPs) do
    length(cPs)
  end

  defp cp_len(str) do
    cp_len(str, 0)
  end

  defp cp_len([gC | r], len) do
    cp_len(r, len + gc_len(gC))
  end

  defp cp_len([], len) do
    len
  end
end
