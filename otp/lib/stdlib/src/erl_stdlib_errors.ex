defmodule :m_erl_stdlib_errors do
  use Bitwise
  def format_error(_Reason, [{m, f, as, info} | _]) do
    errorInfoMap = :proplists.get_value(:error_info, info,
                                          %{})
    cause = :maps.get(:cause, errorInfoMap, :none)
    res = (case (m) do
             :binary ->
               format_binary_error(f, as, cause)
             :ets ->
               format_ets_error(f, as, cause)
             :lists ->
               format_lists_error(f, as)
             :maps ->
               format_maps_error(f, as)
             :math ->
               format_math_error(f, as)
             :re ->
               format_re_error(f, as, cause)
             :unicode ->
               format_unicode_error(f, as)
             :io ->
               format_io_error(f, as, cause)
             _ ->
               []
           end)
    format_error_map(res, 1, %{})
  end

  defp format_binary_error(:at, [subject, pos], _) do
    [must_be_binary(subject), must_be_position(pos)]
  end

  defp format_binary_error(:bin_to_list, [subject], _) do
    [must_be_binary(subject)]
  end

  defp format_binary_error(:bin_to_list, args, cause) do
    format_binary_error(:part, args, cause)
  end

  defp format_binary_error(:compile_pattern, [_], _) do
    ["not a valid pattern"]
  end

  defp format_binary_error(:copy, [subject], _) do
    [must_be_binary(subject)]
  end

  defp format_binary_error(:copy, [subject, n], _) do
    [must_be_binary(subject), must_be_non_neg_integer(n)]
  end

  defp format_binary_error(:decode_unsigned, [subject], _) do
    [must_be_binary(subject)]
  end

  defp format_binary_error(:decode_unsigned, [subject, endianness], _) do
    [must_be_binary(subject),
         must_be_endianness(endianness)]
  end

  defp format_binary_error(:encode_unsigned, [subject], _) do
    [must_be_non_neg_integer(subject)]
  end

  defp format_binary_error(:encode_unsigned, [subject, endianness], _) do
    [must_be_non_neg_integer(subject),
         must_be_endianness(endianness)]
  end

  defp format_binary_error(:encode_hex, [subject], _) do
    [must_be_binary(subject)]
  end

  defp format_binary_error(:encode_hex, [subject, case__], _) do
    [must_be_binary(subject), must_be_hex_case(case__)]
  end

  defp format_binary_error(:decode_hex, [subject], _) do
    cond do
      is_binary(subject) ->
        cond do
          rem(byte_size(subject), 2) === 1 ->
            ["must contain an even number of bytes"]
          true ->
            ["must only contain hex digits 0-9, A-F, and a-f"]
        end
      true ->
        [must_be_binary(subject)]
    end
  end

  defp format_binary_error(:unhex, [subject], _) do
    [<<subject :: binary, " is not a valid hex">>]
  end

  defp format_binary_error(:first, [subject], _) do
    [case (subject) do
       <<>> ->
         :empty_binary
       _ ->
         must_be_binary(subject)
     end]
  end

  defp format_binary_error(:last, [subject], _) do
    [case (subject) do
       <<>> ->
         :empty_binary
       _ ->
         must_be_binary(subject)
     end]
  end

  defp format_binary_error(:list_to_bin, [_], _) do
    [:not_iodata]
  end

  defp format_binary_error(:longest_common_prefix, [_], _) do
    [:bad_binary_list]
  end

  defp format_binary_error(:longest_common_suffix, [_], _) do
    [:bad_binary_list]
  end

  defp format_binary_error(:match, [subject, pattern], _) do
    [must_be_binary(subject), must_be_pattern(pattern)]
  end

  defp format_binary_error(:match, [subject, pattern, options], _) do
    case ([must_be_binary(subject),
               must_be_pattern(pattern)]) do
      [[], []] ->
        case (options) do
          [{:scope, {start, len}}] when (is_integer(start) and
                                           is_integer(len))
                                        ->
            [[], [], "specified part is not wholly inside binary"]
          _ ->
            [[], [], :bad_options]
        end
      errors ->
        errors
    end
  end

  defp format_binary_error(:matches, args, cause) do
    format_binary_error(:match, args, cause)
  end

  defp format_binary_error(:part = name, [subject, posLen], cause) do
    case (posLen) do
      {pos, len} when (is_integer(pos) and is_integer(len)) ->
        case (format_binary_error(name, [subject, pos, len],
                                    cause)) do
          [arg1, [], []] ->
            [arg1]
          [arg1, _, _] ->
            [arg1, :range]
        end
      _ ->
        [must_be_binary(subject), "not a valid {Pos,Length} tuple"]
    end
  end

  defp format_binary_error(:part, [subject, pos, len], _) do
    case ([must_be_binary(subject), must_be_position(pos),
                                        must_be_integer(len)]) do
      [[], [], []] ->
        arg2 = (cond do
                  pos > byte_size(subject) ->
                    :range
                  true ->
                    []
                end)
        case (arg2) do
          [] ->
            [[], [], :range]
          :range ->
            [[], arg2]
        end
      errors ->
        errors
    end
  end

  defp format_binary_error(:referenced_byte_size, [subject], _) do
    [must_be_binary(subject)]
  end

  defp format_binary_error(:split, [subject, pattern], _) do
    [must_be_binary(subject), must_be_pattern(pattern)]
  end

  defp format_binary_error(:split, [subject, pattern, _Options], _) do
    case ([must_be_binary(subject),
               must_be_pattern(pattern)]) do
      [[], []] ->
        [[], [], :bad_options]
      errors ->
        errors
    end
  end

  defp format_binary_error(:replace, [subject, pattern, replacement], _) do
    [must_be_binary(subject), must_be_pattern(pattern),
                                  must_be_binary(replacement)]
  end

  defp format_binary_error(:replace,
            [subject, pattern, replacement, _Options], cause) do
    errors = format_binary_error(:replace,
                                   [subject, pattern, replacement], cause)
    case (cause) do
      :badopt ->
        errors ++ [:bad_options]
      _ ->
        case (errors) do
          [[], [], []] ->
            [[], [], [], :bad_options]
          _ ->
            errors
        end
    end
  end

  defp format_lists_error(:keyfind, [_Key, pos, list]) do
    posError = (cond do
                  is_integer(pos) ->
                    cond do
                      pos < 1 ->
                        :range
                      true ->
                        []
                    end
                  true ->
                    :not_integer
                end)
    [[], posError, must_be_list(list)]
  end

  defp format_lists_error(:keymember, args) do
    format_lists_error(:keyfind, args)
  end

  defp format_lists_error(:keysearch, args) do
    format_lists_error(:keyfind, args)
  end

  defp format_lists_error(:member, [_Key, list]) do
    [[], must_be_list(list)]
  end

  defp format_lists_error(:reverse, [list, _Acc]) do
    [must_be_list(list)]
  end

  defp format_lists_error(:seq, [first, last, inc]) do
    case ([must_be_integer(first), must_be_integer(last),
                                       must_be_integer(inc)]) do
      [[], [], []] ->
        incError = (cond do
                      inc <= 0 and first - inc <= last ->
                        "not a positive increment"
                      inc >= 0 and first - inc >= last ->
                        "not a negative increment"
                    end)
        [[], [], incError]
      errors ->
        errors
    end
  end

  defp format_maps_error(:filter, args) do
    format_maps_error(:map, args)
  end

  defp format_maps_error(:filtermap, args) do
    format_maps_error(:map, args)
  end

  defp format_maps_error(:foreach, args) do
    format_maps_error(:map, args)
  end

  defp format_maps_error(:find, _Args) do
    [[], :not_map]
  end

  defp format_maps_error(:fold, [pred, _Init, map]) do
    [must_be_fun(pred, 3), [], must_be_map_or_iter(map)]
  end

  defp format_maps_error(:from_keys, [list, _]) do
    [must_be_list(list)]
  end

  defp format_maps_error(:from_list, [list]) do
    [must_be_list(list)]
  end

  defp format_maps_error(:get, [_Key, map]) do
    cond do
      is_map(map) ->
        ["not present in map"]
      true ->
        [[], :not_map]
    end
  end

  defp format_maps_error(:groups_from_list, [fun, list]) do
    [must_be_fun(fun, 1), must_be_list(list)]
  end

  defp format_maps_error(:groups_from_list, [fun1, fun2, list]) do
    [must_be_fun(fun1, 1), must_be_fun(fun2, 1),
                               must_be_list(list)]
  end

  defp format_maps_error(:get, [_, _, _]) do
    [[], :not_map]
  end

  defp format_maps_error(:intersect, [map1, map2]) do
    [must_be_map(map1), must_be_map(map2)]
  end

  defp format_maps_error(:intersect_with, [combiner, map1, map2]) do
    [must_be_fun(combiner, 3), must_be_map(map1),
                                   must_be_map(map2)]
  end

  defp format_maps_error(:is_key, _Args) do
    [[], :not_map]
  end

  defp format_maps_error(:iterator, [map]) do
    [must_be_map(map)]
  end

  defp format_maps_error(:iterator, [map, order]) do
    [must_be_map(map), must_be_map_iterator_order(order)]
  end

  defp format_maps_error(:keys, _Args) do
    [:not_map]
  end

  defp format_maps_error(:map, [pred, map]) do
    [must_be_fun(pred, 2), must_be_map_or_iter(map)]
  end

  defp format_maps_error(:merge, [map1, map2]) do
    [must_be_map(map1), must_be_map(map2)]
  end

  defp format_maps_error(:merge_with, [combiner, map1, map2]) do
    [must_be_fun(combiner, 3), must_be_map(map1),
                                   must_be_map(map2)]
  end

  defp format_maps_error(:next, _Args) do
    [:bad_iterator]
  end

  defp format_maps_error(:put, _Args) do
    [[], [], :not_map]
  end

  defp format_maps_error(:remove, _Args) do
    [[], :not_map]
  end

  defp format_maps_error(:size, _Args) do
    [:not_map]
  end

  defp format_maps_error(:take, _Args) do
    [[], :not_map]
  end

  defp format_maps_error(:to_list, _Args) do
    [:not_map_or_iterator]
  end

  defp format_maps_error(:update, _Args) do
    [[], [], :not_map]
  end

  defp format_maps_error(:update_with, [_Key, fun, map]) do
    [[], must_be_fun(fun, 1), must_be_map(map)]
  end

  defp format_maps_error(:update_with, [_Key, fun, _Init, map]) do
    [[], must_be_fun(fun, 1), [], must_be_map(map)]
  end

  defp format_maps_error(:values, _Args) do
    [:not_map]
  end

  defp format_maps_error(:with, [list, map]) do
    [must_be_list(list), must_be_map(map)]
  end

  defp format_maps_error(:without, [list, map]) do
    [must_be_list(list), must_be_map(map)]
  end

  defp format_math_error(:acos, args) do
    maybe_domain_error(args)
  end

  defp format_math_error(:acosh, args) do
    maybe_domain_error(args)
  end

  defp format_math_error(:asin, args) do
    maybe_domain_error(args)
  end

  defp format_math_error(:atanh, args) do
    maybe_domain_error(args)
  end

  defp format_math_error(:log, args) do
    maybe_domain_error(args)
  end

  defp format_math_error(:log2, args) do
    maybe_domain_error(args)
  end

  defp format_math_error(:log10, args) do
    maybe_domain_error(args)
  end

  defp format_math_error(:sqrt, args) do
    maybe_domain_error(args)
  end

  defp format_math_error(:fmod, [arg1, arg2]) do
    case ([must_be_number(arg1), must_be_number(arg2)]) do
      [[], []] ->
        cond do
          arg2 == 0 ->
            [[], :domain_error]
          true ->
            []
        end
      error ->
        error
    end
  end

  defp format_math_error(_, [arg]) do
    [must_be_number(arg)]
  end

  defp format_math_error(_, [arg1, arg2]) do
    [must_be_number(arg1), must_be_number(arg2)]
  end

  defp maybe_domain_error([arg]) do
    case (must_be_number(arg)) do
      [] ->
        [:domain_error]
      error ->
        [error]
    end
  end

  defp format_re_error(:compile, [_], _) do
    [:not_iodata]
  end

  defp format_re_error(:compile, [re, _Options], cause) do
    reError = (try do
                 :re.compile(re)
               catch
                 _, _ ->
                   :not_iodata
               else
                 {:ok, _} ->
                   []
                 {:error, reason} ->
                   {:bad_regexp, reason}
               end)
    case (cause) do
      :badopt ->
        [reError, :bad_options]
      _ ->
        [reError]
    end
  end

  defp format_re_error(:inspect, [compiledRE, item], _) do
    reError = (try do
                 :re.inspect(compiledRE, :namelist)
               catch
                 :error, _ ->
                   :not_compiled_regexp
               else
                 _ ->
                   []
               end)
    cond do
      reError === [] or not is_atom(item) ->
        [reError, "not a valid item"]
      true ->
        [reError]
    end
  end

  defp format_re_error(:replace, [subject, rE, replacement], _) do
    [must_be_iodata(subject), must_be_regexp(rE),
                                  must_be_re_replacement(replacement)]
  end

  defp format_re_error(:replace, [subject, rE, replacement, _Options],
            cause) do
    errors = [must_be_iodata(subject), must_be_regexp(rE),
                                           must_be_re_replacement(replacement)]
    case (cause) do
      :badopt ->
        errors ++ [:bad_options]
      _ ->
        errors
    end
  end

  defp format_re_error(:run, [subject, rE], _) do
    [must_be_iodata(subject), must_be_regexp(rE)]
  end

  defp format_re_error(:run, [subject, rE, _Options], cause) do
    errors = [must_be_iodata(subject), must_be_regexp(rE)]
    case (cause) do
      :badopt ->
        errors ++ [:bad_options]
      _ ->
        errors
    end
  end

  defp format_re_error(:split, [subject, rE], _) do
    [must_be_iodata(subject), must_be_regexp(rE)]
  end

  defp format_re_error(:split, [subject, rE, _Options], cause) do
    errors = [must_be_iodata(subject), must_be_regexp(rE)]
    case (cause) do
      :badopt ->
        errors ++ [:bad_options]
      _ ->
        errors
    end
  end

  defp format_unicode_error(:characters_to_binary, [_]) do
    [:bad_char_data]
  end

  defp format_unicode_error(:characters_to_binary, [chars, inEnc]) do
    [unicode_char_data(chars), unicode_encoding(inEnc)]
  end

  defp format_unicode_error(:characters_to_binary,
            [chars, inEnc, outEnc]) do
    [unicode_char_data(chars), unicode_encoding(inEnc),
                                   unicode_encoding(outEnc)]
  end

  defp format_unicode_error(:characters_to_list, args) do
    format_unicode_error(:characters_to_binary, args)
  end

  defp format_unicode_error(:characters_to_nfc_binary, [_]) do
    [:bad_char_data]
  end

  defp format_unicode_error(:characters_to_nfc_list, [_]) do
    [:bad_char_data]
  end

  defp format_unicode_error(:characters_to_nfd_binary, [_]) do
    [:bad_char_data]
  end

  defp format_unicode_error(:characters_to_nfd_list, [_]) do
    [:bad_char_data]
  end

  defp format_unicode_error(:characters_to_nfkc_binary, [_]) do
    [:bad_char_data]
  end

  defp format_unicode_error(:characters_to_nfkc_list, [_]) do
    [:bad_char_data]
  end

  defp format_unicode_error(:characters_to_nfkd_binary, [_]) do
    [:bad_char_data]
  end

  defp format_unicode_error(:characters_to_nfkd_list, [_]) do
    [:bad_char_data]
  end

  defp unicode_char_data(chars) do
    try do
      :unicode.characters_to_binary(chars)
    catch
      :error, _ ->
        :bad_char_data
    else
      {:error, _, _} ->
        :bad_char_data
      {:incomplete, _, _} ->
        :bad_char_data
      _ ->
        []
    end
  end

  defp unicode_encoding(enc) do
    try do
      :unicode.characters_to_binary("a", enc)
    catch
      :error, _ ->
        :bad_encoding
    else
      _ ->
        []
    end
  end

  defp format_io_error(:fwrite, args, cause) do
    format_io_error(:format, args, cause)
  end

  defp format_io_error(:format = fn__, [_Io, _Fmt, _Args] = args,
            cause) do
    format_io_error(fn__, args, cause, true)
  end

  defp format_io_error(:put_chars = fn__, [_Io, _Chars] = args,
            cause) do
    format_io_error(fn__, args, cause, true)
  end

  defp format_io_error(:put_chars = fn__,
            [_Io, _Encoding, _Chars] = args, cause) do
    format_io_error(fn__, args, cause, true)
  end

  defp format_io_error(:nl = fn__, [_Io] = args, cause) do
    format_io_error(fn__, args, cause, true)
  end

  defp format_io_error(:write = fn__, [_Io, _Term] = args, cause) do
    format_io_error(fn__, args, cause, true)
  end

  defp format_io_error(fn__, args, cause) do
    format_io_error(fn__, args, cause, false)
  end

  defp format_io_error(_, _, {:io, :arguments}, true) do
    [:device_arguments]
  end

  defp format_io_error(_, _, {:io, :arguments}, false) do
    [{:general, :device_arguments}]
  end

  defp format_io_error(_, _, {:io, :calling_self}, true) do
    [:calling_self]
  end

  defp format_io_error(_, _, {:io, :calling_self}, false) do
    [{:general, :calling_self}]
  end

  defp format_io_error(_, _, {:io, :terminated}, true) do
    [:device_terminated]
  end

  defp format_io_error(_, _, {:io, :terminated}, false) do
    [{:general, :device_terminated}]
  end

  defp format_io_error(fn__, args, {:device, cause}, hasDevice) do
    format_io_error_cause(fn__, args, cause, hasDevice)
  end

  defp format_io_error_cause(_, _, {:no_translation, in__, out}, true) do
    [{:no_translation, in__, out}]
  end

  defp format_io_error_cause(_, _, {:no_translation, in__, out}, false) do
    [{:general, {:no_translation, in__, out}}]
  end

  defp format_io_error_cause(:format, args, cause, hasDevice) do
    case (maybe_posix_message(cause, hasDevice)) do
      :unknown ->
        cond do
          hasDevice ->
            [[]] ++ check_io_format(tl(args), cause)
          not hasDevice ->
            check_io_format(args, cause)
        end
      posixError ->
        posixError
    end
  end

  defp format_io_error_cause(:put_chars, args, cause, hasDevice) do
    data = (cond do
              hasDevice ->
                hd(tl(args))
              not hasDevice ->
                hd(args)
            end)
    case (maybe_posix_message(cause, hasDevice)) do
      :unknown ->
        (for _ <- [:EFE_DUMMY_GEN], hasDevice do
           []
         end) ++ (case (unicode_char_data(data)) do
                    [] ->
                      [{:general, {:unknown_error, cause}}]
                    invalidData ->
                      [invalidData]
                  end)
      posixError ->
        posixError ++ [unicode_char_data(data)]
    end
  end

  defp format_io_error_cause(fn__, _Args, cause, hasDevice)
      when fn__ === :write or fn__ === :nl do
    case (maybe_posix_message(cause, hasDevice)) do
      :unknown ->
        [{:general, {:unknown_error, cause}}]
      posixError ->
        posixError
    end
  end

  defp format_io_error_cause(_, _, _, _HasDevice) do
    []
  end

  defp maybe_posix_message(cause, hasDevice) do
    case (:erl_posix_msg.message(cause)) do
      'unknown POSIX error' ++ _ ->
        :unknown
      posixStr when hasDevice ->
        [:io_lib.format('~ts (~tp)', [posixStr, cause])]
      posixStr when not hasDevice ->
        [{:general, :io_lib.format('~ts (~tp)', [posixStr, cause])}]
    end
  end

  defp check_io_format([fmt], cause) do
    check_io_format([fmt, []], cause)
  end

  defp check_io_format([fmt, args], cause) do
    case (is_io_format(fmt)) do
      false ->
        [:invalid_format,
             must_be_list(args)] ++ (case (:erlang.and(:erlang.or(is_pid(fmt),
                                                                    is_atom(fmt)),
                                                         is_io_format(args))) do
                                       true ->
                                         [{:general, :missing_argument_list}]
                                       false ->
                                         []
                                     end)
      _ when not is_list(args) ->
        [[], must_be_list(args)]
      true ->
        case (:erl_lint.check_format_string(fmt)) do
          {:error, s} ->
            [:io_lib.format('format string invalid (~ts)', [s])]
          {:ok, argTypes} when length(argTypes) !== length(args)
                               ->
            ["wrong number of arguments"] ++ (for _ <- [:EFE_DUMMY_GEN], is_atom(fmt) do
                      {:general, :missing_argument_list}
                    end)
          {:ok, argTypes} ->
            case (check_io_arguments(argTypes, args)) do
              [] when cause === :format ->
                [:format_failed]
              [] ->
                try do
                  :io_lib.format(fmt, args)
                catch
                  _, _ ->
                    [:format_failed]
                else
                  _ ->
                    [{:general, {:unknown_error, cause}}]
                end
              argErrors ->
                argErrors
            end
        end
    end
  end

  defp is_io_format(fmt) when is_list(fmt) do
    try do
      :lists.all(&:erlang.is_integer/1, fmt)
    catch
      _, _ ->
        false
    else
      res ->
        res
    end
  end

  defp is_io_format(fmt) when is_atom(fmt) or is_binary(fmt) do
    true
  end

  defp is_io_format(_Fmt) do
    false
  end

  defp check_io_arguments(types, args) do
    case (check_io_arguments(types, args, 1)) do
      [] ->
        []
      checks ->
        [[], :lists.join('\n', checks)]
    end
  end

  defp check_io_arguments([], [], _No) do
    []
  end

  defp check_io_arguments([type | typeT], [arg | argT], no) do
    case (type) do
      :float when is_float(arg) ->
        check_io_arguments(typeT, argT, no + 1)
      :int when is_integer(arg) ->
        check_io_arguments(typeT, argT, no + 1)
      :term ->
        check_io_arguments(typeT, argT, no + 1)
      :string when is_atom(arg) or is_binary(arg) ->
        check_io_arguments(typeT, argT, no + 1)
      :string when is_list(arg) ->
        try do
          :unicode.characters_to_binary(arg)
        catch
          _, _ ->
            [:io_lib.format('element ~B must be of type ~p', [no, :string]) |
                 check_io_arguments(typeT, argT, no + 1)]
        else
          _ ->
            check_io_arguments(typeT, argT, no + 1)
        end
      :int ->
        [:io_lib.format('element ~B must be of type ~p', [no, :integer]) |
             check_io_arguments(typeT, argT, no + 1)]
      _ when type === :float or type === :string ->
        [:io_lib.format('element ~B must be of type ~p', [no, type]) |
             check_io_arguments(typeT, argT, no + 1)]
    end
  end

  defp format_ets_error(:delete_object, args, cause) do
    format_object(args, cause)
  end

  defp format_ets_error(:give_away, [_Tab, pid, _Gift] = args, cause) do
    tabCause = format_cause(args, cause)
    case (cause) do
      :owner ->
        [tabCause, :already_owner]
      :not_owner ->
        [tabCause, :not_owner]
      _ ->
        [tabCause, case ({is_pid(pid), tabCause}) do
                     {true, ''} ->
                       :dead_process
                     {false, _} ->
                       :not_pid
                     _ ->
                       ''
                   end]
    end
  end

  defp format_ets_error(:info, args, cause) do
    format_default(:bad_info_item, args, cause)
  end

  defp format_ets_error(:insert, args, cause) do
    format_objects(args, cause)
  end

  defp format_ets_error(:insert_new, args, cause) do
    format_objects(args, cause)
  end

  defp format_ets_error(:lookup_element, [_, _, pos] = args, cause) do
    tabCause = format_cause(args, cause)
    posCause = format_non_negative_integer(pos)
    case (cause) do
      :badkey ->
        [tabCause, :bad_key, posCause]
      _ ->
        case ({tabCause, posCause}) do
          {'', ''} ->
            ['', '', "position is greater than the size of the object"]
          {_, _} ->
            [tabCause, '', posCause]
        end
    end
  end

  defp format_ets_error(:lookup_element, [tab, key, pos, _Default],
            cause) do
    format_ets_error(:lookup_element, [tab, key, pos],
                       cause)
  end

  defp format_ets_error(:match, [_], _Cause) do
    [:bad_continuation]
  end

  defp format_ets_error(:match, [_, _, _] = args, cause) do
    format_limit(args, cause)
  end

  defp format_ets_error(:match_object, [_], _Cause) do
    [:bad_continuation]
  end

  defp format_ets_error(:match_object, [_, _, _] = args, cause) do
    format_limit(args, cause)
  end

  defp format_ets_error(:match_spec_compile, [_], _Cause) do
    [:bad_matchspec]
  end

  defp format_ets_error(:next, args, cause) do
    format_default(:bad_key, args, cause)
  end

  defp format_ets_error(:new, [name, options], cause) do
    nameError = (cond do
                   is_atom(name) ->
                     []
                   true ->
                     :not_atom
                 end)
    optsError = must_be_list(options)
    case ({nameError, optsError, cause}) do
      {[], [], :already_exists} ->
        [:name_already_exists, []]
      {[], [], _} ->
        [[], :bad_options]
      {_, _, _} ->
        [nameError, optsError]
    end
  end

  defp format_ets_error(:prev, args, cause) do
    format_default(:bad_key, args, cause)
  end

  defp format_ets_error(:rename, [_, newName] = args, cause) do
    case ([format_cause(args, cause), cond do
                                        is_atom(newName) ->
                                          ''
                                        true ->
                                          :bad_table_name
                                      end]) do
      ['', ''] ->
        ['', :name_already_exists]
      result ->
        result
    end
  end

  defp format_ets_error(:safe_fixtable, args, cause) do
    format_default(:bad_boolean, args, cause)
  end

  defp format_ets_error(:select, [_], _Cause) do
    [:bad_continuation]
  end

  defp format_ets_error(:select, [_, _] = args, cause) do
    format_default(:bad_matchspec, args, cause)
  end

  defp format_ets_error(:select, [_, _, _] = args, cause) do
    format_ms_limit(args, cause)
  end

  defp format_ets_error(:select_count, [_, _] = args, cause) do
    format_default(:bad_matchspec, args, cause)
  end

  defp format_ets_error(:select_count, [_, _, _] = args, cause) do
    format_ms_limit(args, cause)
  end

  defp format_ets_error(:internal_select_delete, args, cause) do
    format_default(:bad_matchspec, args, cause)
  end

  defp format_ets_error(:select_replace, args, cause) do
    format_default(:bad_matchspec, args, cause)
  end

  defp format_ets_error(:select_reverse, [_], _Cause) do
    [:bad_continuation]
  end

  defp format_ets_error(:select_reverse, [_, _] = args, cause) do
    format_default(:bad_matchspec, args, cause)
  end

  defp format_ets_error(:select_reverse, [_, _, _] = args, cause) do
    format_ms_limit(args, cause)
  end

  defp format_ets_error(:setopts, args, cause) do
    format_default(:bad_options, args, cause)
  end

  defp format_ets_error(:slot, args, cause) do
    format_default(:range, args, cause)
  end

  defp format_ets_error(:update_counter, [_, _, updateOp] = args,
            cause) do
    tabCause = format_cause(args, cause)
    case (cause) do
      :badkey ->
        [tabCause, :bad_key, format_update_op(updateOp)]
      :keypos ->
        [tabCause, '', :same_as_keypos]
      :position ->
        [tabCause, '', :update_op_range]
      :none ->
        case (is_update_op_top(updateOp)) do
          false ->
            [tabCause, '', :bad_update_op]
          true ->
            [tabCause, '', :counter_not_integer]
        end
      _ ->
        [tabCause, '', format_update_op(updateOp)]
    end
  end

  defp format_ets_error(:update_counter,
            [_, _, updateOp, default] = args, cause) do
    case (format_cause(args, cause)) do
      tabCause when tabCause !== [] ->
        [tabCause]
      '' ->
        tupleCause = format_tuple(default)
        case (cause) do
          :badkey ->
            ['', :bad_key, format_update_op(updateOp) | tupleCause]
          :keypos ->
            ['', '', :same_as_keypos | tupleCause]
          :position ->
            ['', '', :update_op_range]
          _ ->
            case ({format_update_op(updateOp), tupleCause}) do
              {'', ['']} ->
                ['', '', :counter_not_integer]
              {updateOpCause, _} ->
                ['', '', updateOpCause | tupleCause]
            end
        end
    end
  end

  defp format_ets_error(:update_element, [_, _, elementSpec] = args,
            cause) do
    tabCause = format_cause(args, cause)
    [tabCause, '' | case (cause) do
                     :keypos ->
                       [:same_as_keypos]
                     _ ->
                       case (is_element_spec_top(elementSpec)) do
                         true ->
                           case (tabCause) do
                             [] ->
                               [:range]
                             _ ->
                               []
                           end
                         false ->
                           ["is not a valid element specification"]
                       end
                   end]
  end

  defp format_ets_error(:whereis, _Args, _Cause) do
    [:bad_table_name]
  end

  defp format_ets_error(_, args, cause) do
    [format_cause(args, cause)]
  end

  defp format_default(default, args, cause) do
    case (format_cause(args, cause)) do
      '' ->
        ['', default]
      error ->
        [error]
    end
  end

  defp is_element_spec_top(list) when is_list(list) do
    :lists.all(&is_element_spec/1, list)
  end

  defp is_element_spec_top(other) do
    is_element_spec(other)
  end

  defp is_element_spec({pos, _Value}) when (is_integer(pos) and
                                 pos > 0) do
    true
  end

  defp is_element_spec(_) do
    false
  end

  defp format_ms_limit([_, ms, _] = args, cause) do
    [tab, [], limit] = format_limit(args, cause)
    case (is_match_spec(ms)) do
      true ->
        [tab, '', limit]
      false ->
        [tab, :bad_matchspec, limit]
    end
  end

  defp format_limit([_, _, limit] = args, cause) do
    [format_cause(args, cause), '',
                                    format_non_negative_integer(limit)]
  end

  defp format_non_negative_integer(n) do
    cond do
      not is_integer(n) ->
        :not_integer
      n < 1 ->
        :range
      true ->
        ''
    end
  end

  defp format_object([_, object | _] = args, cause) do
    [format_cause(args, cause) | format_tuple(object)]
  end

  defp format_tuple(term) do
    cond do
      tuple_size(term) > 0 ->
        ['']
      is_tuple(term) ->
        [:empty_tuple]
      true ->
        [:not_tuple]
    end
  end

  defp format_objects([_, term | _] = args, cause) do
    [format_cause(args, cause) | cond do
                                   tuple_size(term) > 0 ->
                                     []
                                   is_tuple(term) ->
                                     [:empty_tuple]
                                   is_list(term) ->
                                     try do
                                       :lists.all(fn t ->
                                                       tuple_size(t) > 0
                                                  end,
                                                    term)
                                     catch
                                       _, _ ->
                                         [:not_tuple_or_list]
                                     else
                                       true ->
                                         []
                                       false ->
                                         [:not_tuple_or_list]
                                     end
                                   true ->
                                     [:not_tuple]
                                 end]
  end

  defp format_cause(args, cause) do
    case (cause) do
      :none ->
        ''
      :type ->
        case (args) do
          [ref | _] when is_reference(ref) ->
            "not a valid table identifier"
          _ ->
            "not an atom or a table identifier"
        end
      :id ->
        "the table identifier does not refer to an existing ETS table"
      :access ->
        "the table identifier refers to an ETS table with insufficient access rights"
      :table_type ->
        "the table identifier refers to an ETS table of a type not supported by this operation"
      :badkey ->
        ''
      :keypos ->
        ''
      :position ->
        ''
      :owner ->
        ''
      :not_owner ->
        ''
    end
  end

  defp is_match_spec(term) do
    :ets.is_compiled_ms(term) or (try do
                                    :ets.match_spec_compile(term)
                                  catch
                                    :error, :badarg ->
                                      false
                                  else
                                    _ ->
                                      true
                                  end)
  end

  defp format_update_op(updateOp) do
    case (is_update_op_top(updateOp)) do
      true ->
        ''
      false ->
        :bad_update_op
    end
  end

  defp is_update_op_top(list) when is_list(list) do
    :lists.all(&is_update_op/1, list)
  end

  defp is_update_op_top(op) do
    is_update_op(op)
  end

  defp is_update_op({pos, incr}) when (is_integer(pos) and
                               is_integer(incr)) do
    true
  end

  defp is_update_op({pos, incr, threshold, setValue})
      when (is_integer(pos) and is_integer(incr) and
              is_integer(threshold) and is_integer(setValue)) do
    true
  end

  defp is_update_op(incr) do
    is_integer(incr)
  end

  defp is_iodata(<<_ :: binary>>) do
    true
  end

  defp is_iodata(term) when is_list(term) do
    try do
      :erlang.iolist_size(term)
    catch
      :error, _ ->
        false
    else
      _ ->
        true
    end
  end

  defp is_iodata(_) do
    false
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

  defp must_be_binary(bin) do
    must_be_binary(bin, [])
  end

  defp must_be_binary(bin, error) when is_binary(bin) do
    error
  end

  defp must_be_binary(bin, _Error) when is_bitstring(bin) do
    :bitstring
  end

  defp must_be_binary(_, _) do
    :not_binary
  end

  defp must_be_hex_case(:uppercase) do
    []
  end

  defp must_be_hex_case(:lowercase) do
    []
  end

  defp must_be_hex_case(_) do
    :bad_hex_case
  end

  defp must_be_endianness(:little) do
    []
  end

  defp must_be_endianness(:big) do
    []
  end

  defp must_be_endianness(_) do
    :bad_endianness
  end

  defp must_be_fun(f, arity) when is_function(f, arity) do
    []
  end

  defp must_be_fun(_, arity) do
    {:not_fun, arity}
  end

  defp must_be_integer(n) when is_integer(n) do
    []
  end

  defp must_be_integer(_) do
    :not_integer
  end

  defp must_be_integer(n, min, max, default) when is_integer(n) do
    cond do
      (min <= n and n <= max) ->
        default
      true ->
        :range
    end
  end

  defp must_be_integer(_, _, _, _) do
    :not_integer
  end

  defp must_be_integer(n, min, max) do
    must_be_integer(n, min, max, [])
  end

  defp must_be_non_neg_integer(n) do
    must_be_integer(n, 0, :infinity)
  end

  defp must_be_iodata(term) do
    case (is_iodata(term)) do
      true ->
        []
      false ->
        :not_iodata
    end
  end

  defp must_be_list(list) when is_list(list) do
    try do
      length(list)
    catch
      :error, :badarg ->
        :not_proper_list
    else
      _ ->
        []
    end
  end

  defp must_be_list(_) do
    :not_list
  end

  defp must_be_map(%{}) do
    []
  end

  defp must_be_map(_) do
    :not_map
  end

  defp must_be_map_iterator_order(:undefined) do
    []
  end

  defp must_be_map_iterator_order(:ordered) do
    []
  end

  defp must_be_map_iterator_order(cmpFun) when is_function(cmpFun, 2) do
    []
  end

  defp must_be_map_iterator_order(_) do
    :not_map_iterator_order
  end

  defp must_be_map_or_iter(map) when is_map(map) do
    []
  end

  defp must_be_map_or_iter(iter) do
    case (:maps.is_iterator_valid(iter)) do
      true ->
        []
      false ->
        :not_map_or_iterator
    end
  end

  defp must_be_number(n) do
    cond do
      is_number(n) ->
        []
      true ->
        :not_number
    end
  end

  defp must_be_pattern(p) do
    try do
      :binary.match("a", p)
    catch
      :error, :badarg ->
        :bad_binary_pattern
    else
      _ ->
        []
    end
  end

  defp must_be_position(pos) when (is_integer(pos) and pos >= 0) do
    []
  end

  defp must_be_position(pos) when is_integer(pos) do
    :range
  end

  defp must_be_position(_) do
    :not_integer
  end

  defp must_be_regexp(term) do
    try do
      :re.compile(term)
    catch
      :error, _ ->
        try do
          :re.run('', term)
        catch
          :error, _ ->
            :not_regexp
        else
          _ ->
            []
        end
    else
      {:ok, _} ->
        []
      {:error, reason} ->
        {:bad_regexp, reason}
    end
  end

  defp must_be_re_replacement(r) when is_function(r, 1) do
    []
  end

  defp must_be_re_replacement(r) do
    case (is_iodata(r)) do
      true ->
        []
      false ->
        :bad_replacement
    end
  end

  defp expand_error(:already_owner) do
    "the process is already the owner of the table"
  end

  defp expand_error(:bad_boolean) do
    "not a boolean value"
  end

  defp expand_error(:bad_binary_list) do
    "not a flat list of binaries"
  end

  defp expand_error(:bad_char_data) do
    "not valid character data (an iodata term)"
  end

  defp expand_error(:bad_binary_pattern) do
    "not a valid pattern"
  end

  defp expand_error(:bad_continuation) do
    "invalid continuation"
  end

  defp expand_error(:bad_encoding) do
    "not a valid encoding"
  end

  defp expand_error(:bad_endianness) do
    "must be 'big' or 'little'"
  end

  defp expand_error(:bad_info_item) do
    "not a valid info item"
  end

  defp expand_error(:bad_iterator) do
    "not a valid iterator"
  end

  defp expand_error(:bad_key) do
    "not a key that exists in the table"
  end

  defp expand_error(:bad_matchspec) do
    "not a valid match specification"
  end

  defp expand_error(:bad_options) do
    "invalid options"
  end

  defp expand_error(:bad_replacement) do
    "not a valid replacement"
  end

  defp expand_error(:bad_table_name) do
    "invalid table name (must be an atom)"
  end

  defp expand_error(:bad_update_op) do
    "not a valid update operation"
  end

  defp expand_error(:bitstring) do
    "is a bitstring (expected a binary)"
  end

  defp expand_error(:calling_self) do
    "the device is not allowed to be the current process"
  end

  defp expand_error(:counter_not_integer) do
    "the value in the given position, in the object, is not an integer"
  end

  defp expand_error(:dead_process) do
    "the pid refers to a terminated process"
  end

  defp expand_error(:device_arguments) do
    "the device does not exist"
  end

  defp expand_error(:device_terminated) do
    "the device has terminated"
  end

  defp expand_error(:domain_error) do
    "is outside the domain for this function"
  end

  defp expand_error(:empty_binary) do
    "a zero-sized binary is not allowed"
  end

  defp expand_error(:empty_tuple) do
    "is an empty tuple"
  end

  defp expand_error(:format_failed) do
    "failed to format string"
  end

  defp expand_error(:invalid_format) do
    "not a valid format string"
  end

  defp expand_error(:missing_argument_list) do
    "possibly missing argument list"
  end

  defp expand_error(:name_already_exists) do
    "table name already exists"
  end

  defp expand_error({:no_translation, in__, out}) do
    :unicode.characters_to_binary(:io_lib.format('device failed to transcode string from ~p to ~p',
                                                   [in__, out]))
  end

  defp expand_error(:not_atom) do
    "not an atom"
  end

  defp expand_error(:not_binary) do
    "not a binary"
  end

  defp expand_error(:bad_hex_case) do
    "not 'uppercase' or 'lowercase'"
  end

  defp expand_error(:not_compiled_regexp) do
    "not a compiled regular expression"
  end

  defp expand_error(:not_iodata) do
    "not an iodata term"
  end

  defp expand_error({:not_fun, 1}) do
    "not a fun that takes one argument"
  end

  defp expand_error({:not_fun, 2}) do
    "not a fun that takes two arguments"
  end

  defp expand_error({:not_fun, 3}) do
    "not a fun that takes three arguments"
  end

  defp expand_error(:not_integer) do
    "not an integer"
  end

  defp expand_error(:not_list) do
    "not a list"
  end

  defp expand_error(:not_map_iterator_order) do
    "not 'undefined', 'ordered', or a fun that takes two arguments"
  end

  defp expand_error(:not_map_or_iterator) do
    "not a map or an iterator"
  end

  defp expand_error(:not_number) do
    "not a number"
  end

  defp expand_error(:not_proper_list) do
    "not a proper list"
  end

  defp expand_error(:not_map) do
    "not a map"
  end

  defp expand_error(:not_owner) do
    "the current process is not the owner"
  end

  defp expand_error(:not_pid) do
    "not a pid"
  end

  defp expand_error(:not_regexp) do
    "neither an iodata term nor a compiled regular expression"
  end

  defp expand_error({:bad_regexp, {reason, column}}) do
    :unicode.characters_to_binary(:io_lib.format('could not parse regular expression~n~ts on character ~p',
                                                   [reason, column]))
  end

  defp expand_error(:not_tuple) do
    "not a tuple"
  end

  defp expand_error(:not_tuple_or_list) do
    "not a non-empty tuple or a list of non-empty tuples"
  end

  defp expand_error(:range) do
    "out of range"
  end

  defp expand_error(:same_as_keypos) do
    "the position is the same as the key position"
  end

  defp expand_error({:unknown_error, cause}) do
    :unicode.characters_to_binary(:io_lib.format('unknown error: ~tp',
                                                   [cause]))
  end

  defp expand_error(:update_op_range) do
    "the position in the update operation is out of range"
  end

  defp expand_error(other) do
    other
  end

end