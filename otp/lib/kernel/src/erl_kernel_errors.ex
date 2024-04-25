defmodule :m_erl_kernel_errors do
  use Bitwise
  def format_error(_Reason, [{m, f, as, info} | _]) do
    errorInfoMap = :proplists.get_value(:error_info, info,
                                          %{})
    cause = :maps.get(:cause, errorInfoMap, :none)
    res = (case (m) do
             :erl_ddll ->
               format_erl_ddll_error(f, as, cause)
             :os ->
               format_os_error(f, as, cause)
             _ ->
               []
           end)
    format_error_map(res, 1, %{})
  end

  defp format_erl_ddll_error(_, _, _) do
    []
  end

  defp format_os_error(:cmd, _, {:open_port, reason}) do
    [{:general, maybe_posix_message(reason)}]
  end

  defp format_os_error(:cmd, [_], _) do
    [:not_charlist]
  end

  defp format_os_error(:cmd, [_, _], cause) do
    case (cause) do
      :badopt ->
        [[], :not_map]
      _ ->
        [:not_charlist]
    end
  end

  defp format_os_error(:getenv, [name | _], _) do
    [must_be_env_var_name(name)]
  end

  defp format_os_error(:perf_counter, [_], _) do
    [:invalid_time_unit]
  end

  defp format_os_error(:putenv, [name, value], _) do
    [must_be_env_var_name(name),
         must_be_env_var_value(value)]
  end

  defp format_os_error(:set_signal, [signal, _Option], cause) do
    case (cause) do
      :badopt ->
        [must_be_atom(signal, []), :invalid_signal_option]
      _ ->
        [must_be_atom(signal, :invalid_signal_name)]
    end
  end

  defp format_os_error(:system_time, [_], _) do
    [:invalid_time_unit]
  end

  defp format_os_error(:unsetenv, [name], _) do
    [must_be_env_var_name(name)]
  end

  defp format_os_error(_, _, _) do
    []
  end

  defp maybe_posix_message(reason) do
    case (:erl_posix_msg.message(reason)) do
      'unknown POSIX error' ++ _ ->
        :io_lib.format('open_port failed with reason: ~tp', [reason])
      posixStr ->
        :io_lib.format('~ts (~tp)', [posixStr, reason])
    end
  end

  defp must_be_atom(term, default) when is_atom(term) do
    default
  end

  defp must_be_atom(_, _) do
    :not_atom
  end

  defp must_be_env_var_name(term) do
    case (must_be_env_charlist(term)) do
      {:ok, flatList0} ->
        flatList = (case ({flatList0, :os.type()}) do
                      {'=' ++ flatList1, {:win32, _}} ->
                        flatList1
                      {_, _} ->
                        flatList0
                    end)
        case (:lists.member(?=, flatList)) do
          true ->
            :eq_in_list
          false ->
            []
        end
      error ->
        error
    end
  end

  defp must_be_env_var_value(term) do
    case (must_be_env_charlist(term)) do
      {:ok, _} ->
        []
      error ->
        error
    end
  end

  defp must_be_env_charlist(term) when is_list(term) do
    try do
      :lists.flatten(term)
    catch
      :error, _ ->
        :not_proper_list
    else
      flatList ->
        case (:lists.all(&is_integer/1, flatList)) do
          true ->
            enc = :file.native_name_encoding()
            case (:unicode.characters_to_list(flatList, enc)) do
              l when is_list(l) ->
                case (:lists.member(0, flatList)) do
                  true ->
                    :zero_in_list
                  false ->
                    {:ok, flatList}
                end
              {:error, _, _} ->
                :invalid_characters
            end
          false ->
            :not_charlist
        end
    end
  end

  defp must_be_env_charlist(_) do
    :not_list
  end

  defp format_error_map(['' | es], argNum, map) do
    format_error_map(es, argNum + 1, map)
  end

  defp format_error_map([{:general, e} | es], argNum, map) do
    format_error_map(es, argNum,
                       Map.put(map, :general, expand_error(e)))
  end

  defp format_error_map([e | es], argNum, map) do
    format_error_map(es, argNum + 1,
                       Map.put(map, argNum, expand_error(e)))
  end

  defp format_error_map([], _, map) do
    map
  end

  defp expand_error(:eq_in_list) do
    "\"=\" characters is not allowed in environment variable names"
  end

  defp expand_error(:zero_in_list) do
    "\"\\0\" characters is not allowed in environment variable names or values"
  end

  defp expand_error(:invalid_characters) do
    "invalid characters"
  end

  defp expand_error(:invalid_signal_name) do
    "invalid signal name"
  end

  defp expand_error(:invalid_signal_option) do
    "invalid signal handling option"
  end

  defp expand_error(:invalid_time_unit) do
    "invalid time unit"
  end

  defp expand_error(:not_atom) do
    "not an atom"
  end

  defp expand_error(:not_charlist) do
    "not a list of characters"
  end

  defp expand_error(:not_list) do
    "not a list"
  end

  defp expand_error(:not_map) do
    "not a map"
  end

  defp expand_error(:not_proper_list) do
    "not a proper list"
  end

  defp expand_error(other) do
    other
  end

end