defmodule :m_edlin_key do
  use Bitwise
  import :lists, only: [reverse: 1, reverse: 2]
  def get_key_map() do
    keyMap = :application.get_env(:stdlib, :shell_keymap,
                                    :none)
    case (keyMap) do
      :none ->
        key_map()
      _ ->
        merge(keyMap)
    end
  end

  def get_valid_escape_key([], {:csi, [_] = acc} = _Mode) do
    {:key, '\e[' ++ acc, []}
  end

  def get_valid_escape_key([], res) do
    case (res) do
      {atom, acc, rest} ->
        case (atom) do
          :finished ->
            {:key, acc, rest}
          :invalid ->
            {:invalid, acc, rest}
        end
      {atom, acc} ->
        case (atom) do
          :finished ->
            {:key, acc, []}
          :invalid ->
            {:invalid, acc, []}
          :csi ->
            {:mode, {:csi, acc}}
        end
      :meta ->
        {:escape_prefix, :meta}
      :meta_o ->
        {:key, '\eO', []}
      :meta_meta ->
        {:escape_prefix, :meta_meta}
      :meta_csi ->
        {:escape_prefix, :meta_csi}
      :meta_left_sq_bracket ->
        {:escape_prefix, :meta_left_sq_bracket}
    end
  end

  def get_valid_escape_key([c | rest], :none) do
    case (c) do
      ?\e ->
        get_valid_escape_key(rest, :meta)
      ^c when (?\0 <= c and c <= 31) or c === 31 ->
        {:key, [c], rest}
      _ ->
        {:insert, c, rest}
    end
  end

  def get_valid_escape_key([c | rest], :meta) do
    case (c) do
      ?\e ->
        get_valid_escape_key(rest, :meta_meta)
      ?O ->
        get_valid_escape_key(rest, :meta_o)
      ?[ ->
        get_valid_escape_key(rest, :meta_left_sq_bracket)
      _ when (?! <= c and c <= ?~) ->
        get_valid_escape_key(rest, {:finished, '\e' ++ [c]})
      _ when (?\0 <= c and c <= 31) or c === 31 ->
        get_valid_escape_key(rest, {:finished, '\e' ++ [c]})
      _ ->
        get_valid_escape_key(rest, {:invalid, '\e' ++ [c]})
    end
  end

  def get_valid_escape_key([c | rest], :meta_meta) do
    case (c) do
      ?[ ->
        get_valid_escape_key(rest, :meta_csi)
      _ when (?! <= c and c <= ?~) ->
        get_valid_escape_key(rest, {:finished, '\e\e' ++ [c]})
      _ ->
        get_valid_escape_key(rest, {:invalid, '\e\e' ++ [c]})
    end
  end

  def get_valid_escape_key([c | rest], :meta_o) do
    case (c) do
      _ when (?! <= c and c <= ?~) ->
        get_valid_escape_key(rest, {:finished, '\eO' ++ [c]})
      _ ->
        get_valid_escape_key(rest, {:invalid, '\eO' ++ [c]})
    end
  end

  def get_valid_escape_key([c | rest], :meta_csi) do
    case (c) do
      _ when (?! <= c and c <= ?~) ->
        get_valid_escape_key(rest, {:finished, '\e\e[' ++ [c]})
      _ ->
        get_valid_escape_key(rest, {:invalid, '\e[' ++ [c]})
    end
  end

  def get_valid_escape_key([c | rest], :meta_left_sq_bracket) do
    case (c) do
      _ when (?0 <= c and c <= ?9) ->
        get_valid_escape_key(rest, {:csi, [c]})
      _ when (?a <= c and c <= ?z) or (?A <= c and c <= ?Z) ->
        get_valid_escape_key(rest, {:finished, '\e[' ++ [c]})
      _ ->
        get_valid_escape_key(rest, {:invalid, '\e[' ++ [c]})
    end
  end

  def get_valid_escape_key([c | rest], {:csi, [?; | acc]}) do
    case (c) do
      _ when (?0 <= c and c <= ?9) ->
        get_valid_escape_key(rest, {:csi, [c, ?; | acc]})
      _ ->
        get_valid_escape_key(rest,
                               {:invalid, '\e[' ++ reverse([?; | acc]) ++ [c]})
    end
  end

  def get_valid_escape_key([c | rest], {:csi, acc}) do
    case (c) do
      ?~ ->
        get_valid_escape_key(rest,
                               {:finished, '\e[' ++ reverse([?~ | acc])})
      ?; ->
        get_valid_escape_key(rest, {:csi, [?; | acc]})
      _ when (?0 <= c and c <= ?9) ->
        get_valid_escape_key(rest, {:csi, [c | acc]})
      ?m ->
        {:invalid, '\e[' ++ reverse([?m | acc]), [?m | rest]}
      _ when (?! <= c and c <= ?~) ->
        get_valid_escape_key(rest,
                               {:finished, '\e[' ++ reverse([c | acc])})
    end
  end

  def get_valid_escape_key([c | rest], {:finished, acc}) do
    case (c) do
      ?~ ->
        get_valid_escape_key([], {:finished, acc ++ [c], rest})
      _ ->
        get_valid_escape_key([], {:finished, acc, [c | rest]})
    end
  end

  def get_valid_escape_key(rest, {:invalid, acc}) do
    {:invalid, acc, rest}
  end

  def get_valid_escape_key(rest, acc) do
    {:invalid, acc, rest}
  end

  defp merge(keyMap) do
    merge(keyMap, [:normal, :search, :tab_expand],
            key_map())
  end

  defp merge(_, [], keyMap) do
    keyMap
  end

  defp merge(inputKeyMap, [mode | shellModes], keyMap) do
    inputKeyMapModeValidated = :maps.filtermap(fn key, value
                                                      when (is_list(key) and
                                                              is_atom(value))
                                                           ->
                                                    try do
                                                      {:key, ^key,
                                                         []} = get_valid_escape_key(key,
                                                                                      :none)
                                                      case (:lists.member(value,
                                                                            valid_functions())) do
                                                        true ->
                                                          {true, value}
                                                        false ->
                                                          :io.format(:standard_error,
                                                                       'Invalid function ~p in entry {~p,~p}~n',
                                                                       [value,
                                                                            key,
                                                                                value])
                                                          false
                                                      end
                                                    catch
                                                      _, _ ->
                                                        :io.format(:standard_error,
                                                                     'Invalid key ~p in entry {~p,~p}~n',
                                                                     [key, key,
                                                                               value])
                                                        false
                                                    end
                                                  :default, value ->
                                                    case (:lists.member(value,
                                                                          valid_functions())) do
                                                      true ->
                                                        {true, value}
                                                      false ->
                                                        :io.format(:standard_error,
                                                                     'Invalid function ~p in entry {default,~p}~n',
                                                                     [value,
                                                                          value])
                                                        false
                                                    end
                                                  key, value ->
                                                    :io.format(:standard_error,
                                                                 'Invalid entry {~p,~p}~n',
                                                                 [key, value])
                                                    false
                                               end,
                                                 :maps.get(mode, inputKeyMap,
                                                             %{}))
    keyMap1 = Map.put(keyMap, mode,
                                :maps.merge(:maps.get(mode, keyMap),
                                              inputKeyMapModeValidated))
    merge(inputKeyMap, shellModes, keyMap1)
  end

  defp key_map() do
    %{normal: normal_map(),
        search:
        %{'\022' => :skip_up, '\023' => :skip_down, '\eC' => :search_cancel,
            '\ec' => :search_cancel, '\n' => :search_found,
            '\r' => :search_found, '\b' => :backward_delete_char,
            '\037' => :backward_delete_char, default: :search_quit},
        tab_expand:
        %{'\t' => :tab_expand_full, default: :tab_expand_quit}}
  end

  defp normal_map() do
    %{'\n' => :new_line_finish, '\r' => :new_line_finish,
        '\e\n' => :new_line, '\e\r' => :new_line, '\t' => :tab_expand,
        '\001' => :beginning_of_line, '\002' => :backward_char,
        '\004' => :forward_delete_char, '\005' => :end_of_line,
        '\006' => :forward_char, '\b' => :backward_delete_char,
        '\v' => :kill_line, '\f' => :clear, '\016' => :history_down,
        '\017' => :open_editor, '\020' => :history_up, '\022' => :search,
        '\024' => :transpose_char, '\025' => :backward_kill_line,
        '\027' => :backward_kill_word, '\031' => :yank, '\035' => :auto_blink,
        '\eB' => :backward_word, '\eb' => :backward_word,
        '\ec' => :clear_line, '\eD' => :kill_word, '\ed' => :kill_word,
        '\eF' => :forward_word, '\ef' => :forward_word,
        '\eL' => :redraw_line, '\el' => :redraw_line, '\eo' => :open_editor,
        '\eT' => :transpose_word, '\et' => :transpose_word,
        '\e<' => :beginning_of_expression, '\e>' => :end_of_expression,
        '\037' => :backward_delete_char, '\e\037' => :backward_kill_word,
        '\e[3~' => :forward_delete_char, '\e[3;5~' => :forward_delete_word,
        '\e[H' => :beginning_of_line, '\eOH' => :beginning_of_line,
        '\e[F' => :end_of_line, '\eOF' => :end_of_line, '\eOA' => :history_up,
        '\e[A' => :history_up, '\e[1;3A' => :backward_line,
        '\e[1;5A' => :backward_line, '\e[1;4A' => :beginning_of_expression,
        '\eOB' => :history_down, '\e[B' => :history_down,
        '\e[1;3B' => :forward_line, '\e[1;5B' => :forward_line,
        '\e[1;4B' => :end_of_expression, '\eOD' => :backward_char,
        '\e[D' => :backward_char, '\e[3D' => :backward_word,
        '\e[1;3D' => :backward_word, '\e[5D' => :backward_word,
        '\e[1;5D' => :backward_word, '\eOC' => :forward_char,
        '\e[C' => :forward_char, '\e[3C' => :forward_word,
        '\e[1;3C' => :forward_word, '\e[5C' => :forward_word,
        '\e[1;5C' => :forward_word, default: :none}
  end

  defp valid_functions() do
    [:auto_blink, :backward_char, :backward_delete_char,
                                      :backward_delete_word,
                                          :backward_kill_line,
                                              :backward_kill_word,
                                                  :backward_line,
                                                      :backward_word,
                                                          :beginning_of_expression,
                                                              :beginning_of_line,
                                                                  :clear,
                                                                      :clear_line,
                                                                          :end_of_expression,
                                                                              :end_of_line,
                                                                                  :forward_char,
                                                                                      :forward_delete_char,
                                                                                          :forward_delete_word,
                                                                                              :forward_line,
                                                                                                  :forward_word,
                                                                                                      :history_down,
                                                                                                          :history_up,
                                                                                                              :kill_line,
                                                                                                                  :kill_word,
                                                                                                                      :new_line_finish,
                                                                                                                          :new_line,
                                                                                                                              :none,
                                                                                                                                  :open_editor,
                                                                                                                                      :redraw_line,
                                                                                                                                          :search_cancel,
                                                                                                                                              :search_found,
                                                                                                                                                  :search_quit,
                                                                                                                                                      :search,
                                                                                                                                                          :skip_down,
                                                                                                                                                              :skip_up,
                                                                                                                                                                  :tab_expand_full,
                                                                                                                                                                      :tab_expand_quit,
                                                                                                                                                                          :tab_expand,
                                                                                                                                                                              :transpose_char,
                                                                                                                                                                                  :transpose_word,
                                                                                                                                                                                      :yank]
  end

end