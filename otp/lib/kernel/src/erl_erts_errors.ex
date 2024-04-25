defmodule :m_erl_erts_errors do
  use Bitwise

  def format_error(reason, [{m, f, as, info} | _]) do
    errorInfoMap = :proplists.get_value(:error_info, info, %{})
    cause = :maps.get(:cause, errorInfoMap, :none)

    res =
      case m do
        :erlang ->
          format_erlang_error(f, as, reason, cause)

        :atomics ->
          format_atomics_error(f, as, reason, cause)

        :counters ->
          format_counters_error(f, as, reason, cause)

        :persistent_term ->
          format_pt_error(f, as)

        _ ->
          []
      end

    format_error_map(res, 1, %{})
  end

  def format_bs_fail(reason, [{_, _, _, info} | _]) do
    errorInfoMap = :proplists.get_value(:error_info, info, %{})

    case errorInfoMap do
      %{cause: {segment0, type, error, value}} ->
        segment1 = :maps.get(:override_segment_position, errorInfoMap, segment0)
        prettyPrinter = :maps.get(:pretty_printer, errorInfoMap, &possibly_truncated/1)
        str0 = do_format_bs_fail(reason, type, error, value, prettyPrinter)
        str1 = :io_lib.format(~c"segment ~p of type '~ts': ~ts", [segment1, type, str0])
        str = :erlang.iolist_to_binary(str1)
        %{general: str, reason: "construction of binary failed"}

      %{} ->
        %{}
    end
  end

  defp format_atomics_error(:new, [size, options], reason, cause) do
    case reason do
      :system_limit ->
        ["atomics array size reached a system limit", must_be_list(options)]

      :badarg ->
        case cause do
          :badopt ->
            sizeError = must_be_pos_int(size)
            [sizeError, must_be_list(options, :bad_option)]

          _ ->
            [must_be_pos_int(size)]
        end
    end
  end

  defp format_atomics_error(name, args, _, _) do
    format_atomics_error(name, args)
  end

  defp format_atomics_error(:add, args) do
    do_atomics_operation(args)
  end

  defp format_atomics_error(:add_get, args) do
    do_atomics_operation(args)
  end

  defp format_atomics_error(
         :compare_exchange,
         [ref, index, expected, desired]
       ) do
    try do
      :atomics.info(ref)
    catch
      :error, :badarg ->
        [:bad_atomics_ref, must_be_pos_int(index), must_be_int(expected), must_be_int(desired)]
    else
      %{min: min, max: max, size: maxIndex} ->
        [
          [],
          must_be_int(index, 1, maxIndex),
          must_be_int(expected, min, max),
          must_be_int(desired, min, max)
        ]
    end
  end

  defp format_atomics_error(:exchange, args) do
    do_atomics_operation(args)
  end

  defp format_atomics_error(:get, [ref, index]) do
    do_atomics_operation([ref, index, 0])
  end

  defp format_atomics_error(:info, [_]) do
    [:bad_atomics_ref]
  end

  defp format_atomics_error(:put, args) do
    do_atomics_operation(args)
  end

  defp format_atomics_error(:sub, args) do
    do_atomics_operation(args)
  end

  defp format_atomics_error(:sub_get, args) do
    do_atomics_operation(args)
  end

  defp format_atomics_error(_, _) do
    []
  end

  defp do_atomics_operation([ref, index, value]) do
    try do
      :atomics.info(ref)
    catch
      :error, :badarg ->
        [:bad_atomics_ref, must_be_pos_int(index), must_be_int(value)]
    else
      %{min: min, max: max, size: maxIndex} ->
        [[], must_be_int(index, 1, maxIndex), must_be_int(value, min, max)]
    end
  end

  defp format_counters_error(:new, [size, options], reason, cause) do
    case reason do
      :system_limit ->
        ["counters array size reached a system limit", must_be_list(options)]

      :badarg ->
        case cause do
          :badopt ->
            sizeError = must_be_pos_int(size)
            [sizeError, must_be_list(options, :bad_option)]

          _ ->
            [must_be_pos_int(size)]
        end
    end
  end

  defp format_counters_error(name, args, _, _) do
    format_counters_error(name, args)
  end

  defp format_counters_error(:add, args) do
    do_counters_operation(args)
  end

  defp format_counters_error(:get, [ref, index]) do
    do_counters_operation([ref, index, 0])
  end

  defp format_counters_error(:info, [_]) do
    [:bad_counters_ref]
  end

  defp format_counters_error(:put, args) do
    do_counters_operation(args)
  end

  defp format_counters_error(:sub, args) do
    do_counters_operation(args)
  end

  defp do_counters_operation([ref, index, value]) do
    try do
      :counters.info(ref)
    catch
      :error, :badarg ->
        [:bad_counters_ref, must_be_pos_int(index), must_be_int(value)]
    else
      %{size: maxIndex} ->
        case must_be_int(index, 1, maxIndex) do
          [] when is_integer(value) ->
            [[], [], :range]

          [] ->
            [[], [], :not_integer]

          indexError ->
            [[], indexError]
        end
    end
  end

  defp format_pt_error(:get, [_]) do
    ["no persistent term stored with this key"]
  end

  defp format_erlang_error(_, _, :system_limit, _) do
    []
  end

  defp format_erlang_error(f, as, _, cause) do
    format_erlang_error(f, as, cause)
  end

  defp format_erlang_error(:abs, [_], _) do
    [:not_number]
  end

  defp format_erlang_error(:adler32, [_], _) do
    [:not_iodata]
  end

  defp format_erlang_error(:adler32, [int, data], _) do
    [must_be_adler32(int), must_be_iodata(data)]
  end

  defp format_erlang_error(:adler32_combine, [first, second, size], _) do
    [must_be_adler32(first), must_be_adler32(second), must_be_size(size)]
  end

  defp format_erlang_error(:alias, [options], _) do
    [must_be_list(options, :bad_option)]
  end

  defp format_erlang_error(:append, [_, _], _) do
    [:not_list]
  end

  defp format_erlang_error(:apply, [mod, name, arity], _) do
    must_be_mf_args(mod, name, arity)
  end

  defp format_erlang_error(:atom_to_binary, [_], _) do
    [:not_atom]
  end

  defp format_erlang_error(:atom_to_binary, [atom, encoding], _) do
    [
      cond do
        not is_atom(atom) ->
          :not_atom

        encoding === :latin1 ->
          "contains a character not expressible in latin1"

        true ->
          []
      end,
      case :lists.member(
             encoding,
             [:latin1, :unicode, :utf8]
           ) do
        true ->
          []

        false ->
          "is an invalid encoding option"
      end
    ]
  end

  defp format_erlang_error(:atom_to_list, [_], _) do
    [:not_atom]
  end

  defp format_erlang_error(:append_element, [_, _], _) do
    [:not_tuple]
  end

  defp format_erlang_error(:bit_size, [_], _) do
    [:not_bitstring]
  end

  defp format_erlang_error(:binary_part, [bin, posLen], cause) do
    case posLen do
      {pos, len} when is_integer(pos) and is_integer(len) ->
        case format_erlang_error(:binary_part, [bin, pos, len], cause) do
          [arg1, [], []] ->
            [arg1]

          [arg1, _, _] ->
            [arg1, :range]
        end

      _ ->
        [must_be_binary(bin), "not a valid {Pos,Length} tuple"]
    end
  end

  defp format_erlang_error(:binary_part, [bin, pos, len], _) do
    case [must_be_binary(bin), must_be_non_neg_int(pos), must_be_int(len)] do
      [[], [], []] ->
        arg2 =
          cond do
            pos > byte_size(bin) ->
              :range

            true ->
              []
          end

        case arg2 do
          [] ->
            [[], [], :range]

          :range ->
            [[], arg2]
        end

      errors ->
        errors
    end
  end

  defp format_erlang_error(:binary_to_atom = bif, [bin], cause) do
    format_erlang_error(bif, [bin, :utf8], cause)
  end

  defp format_erlang_error(:binary_to_atom, [bin, enc], _) do
    defaultError = []
    do_binary_to_atom(bin, enc, defaultError)
  end

  defp format_erlang_error(:binary_to_existing_atom = bif, [bin], cause) do
    format_erlang_error(bif, [bin, :utf8], cause)
  end

  defp format_erlang_error(:binary_to_existing_atom, [bin, enc], _) do
    do_binary_to_atom(bin, enc, :non_existing_atom)
  end

  defp format_erlang_error(:binary_to_float, [bin], _) do
    [must_be_binary(bin, {:not_encodable, "a float"})]
  end

  defp format_erlang_error(:binary_to_integer, [bin], _) do
    [must_be_binary(bin, {:not_encodable, "an integer"})]
  end

  defp format_erlang_error(:binary_to_integer, [bin, base], _) do
    case must_be_base(base) do
      [] ->
        [must_be_binary(bin, {:not_encodable, "an integer"})]

      badBase ->
        [must_be_binary(bin, []), badBase]
    end
  end

  defp format_erlang_error(:binary_to_list, [_], _) do
    [:not_binary]
  end

  defp format_erlang_error(:binary_to_list, [bin, start, stop], _) do
    case [must_be_binary(bin), must_be_pos_int(start), must_be_pos_int(stop)] do
      [[], [], []] ->
        cond do
          start > stop ->
            [[], "start position greater than stop position"]

          true ->
            [
              [],
              cond do
                start > byte_size(bin) ->
                  :range

                true ->
                  []
              end,
              cond do
                stop > byte_size(bin) ->
                  :range

                true ->
                  []
              end
            ]
        end

      errors ->
        errors
    end
  end

  defp format_erlang_error(:binary_to_term, [bin], _) do
    [must_be_binary(bin, :bad_ext_term)]
  end

  defp format_erlang_error(:binary_to_term, [bin, options], cause) do
    arg1 = must_be_binary(bin)

    arg2 =
      case cause do
        :badopt ->
          must_be_list(options, :bad_option)

        _ ->
          []
      end

    case {arg1, arg2} do
      {[], []} ->
        case :lists.member(:safe, options) do
          true ->
            [:bad_or_unsafe_ext_term]

          false ->
            [:bad_ext_term]
        end

      {_, _} ->
        [arg1, arg2]
    end
  end

  defp format_erlang_error(:bitstring_to_list, [_], _) do
    [:not_bitstring]
  end

  defp format_erlang_error(:bump_reductions, [int], _) do
    [must_be_non_neg_int(int)]
  end

  defp format_erlang_error(:byte_size, [_], _) do
    [:not_bitstring]
  end

  defp format_erlang_error(:cancel_timer, [_], _) do
    [:not_ref]
  end

  defp format_erlang_error(:cancel_timer, [ref, options], _) do
    arg1 = must_be_ref(ref)
    [arg1, maybe_option_list_error(options, arg1)]
  end

  defp format_erlang_error(:ceil, [_], _) do
    [:not_number]
  end

  defp format_erlang_error(:check_old_code, [_], _) do
    [:not_atom]
  end

  defp format_erlang_error(:check_process_code, [pid, module], _) do
    [must_be_local_pid(pid), must_be_atom(module)]
  end

  defp format_erlang_error(:check_process_code, [pid, module, _Options], cause) do
    format_erlang_error(:check_process_code, [pid, module], cause) ++
      [
        case cause do
          :bad_option ->
            :bad_option

          _ ->
            []
        end
      ]
  end

  defp format_erlang_error(:convert_time_unit, [time, fromUnit, toUnit], _) do
    [must_be_int(time), must_be_time_unit(fromUnit), must_be_time_unit(toUnit)]
  end

  defp format_erlang_error(:crc32, args, cause) do
    format_erlang_error(:adler32, args, cause)
  end

  defp format_erlang_error(:crc32_combine, args, cause) do
    format_erlang_error(:adler32_combine, args, cause)
  end

  defp format_erlang_error(:decode_packet, [_, bin, options], cause) do
    arg2 = must_be_binary(bin)
    arg3 = maybe_option_list_error(options, arg2)

    case cause do
      :badopt ->
        ["invalid packet type", arg2, arg3]

      :none ->
        [[], arg2, arg3]
    end
  end

  defp format_erlang_error(:delete_element, args, cause) do
    format_erlang_error(:element, args, cause)
  end

  defp format_erlang_error(:delete_module, [_], _) do
    [:not_atom]
  end

  defp format_erlang_error(:demonitor, [_], _) do
    [:not_ref]
  end

  defp format_erlang_error(:demonitor, [ref, options], _) do
    arg1 = must_be_ref(ref)
    [arg1, maybe_option_list_error(options, arg1)]
  end

  defp format_erlang_error(:display_string, [_], :none) do
    [:not_string]
  end

  defp format_erlang_error(:display_string, [_], cause) do
    maybe_posix_message(cause, false)
  end

  defp format_erlang_error(:display_string, [device, _], :none) do
    case :lists.member(
           device,
           [:stdin, :stdout, :stderr]
         ) do
      true ->
        [[], :not_string]

      false ->
        [:not_device, []]
    end
  end

  defp format_erlang_error(:display_string, [_, _], cause) do
    maybe_posix_message(cause, true)
  end

  defp format_erlang_error(:element, [index, tuple], _) do
    [
      cond do
        not is_integer(index) ->
          :not_integer

        index <= 0 or index > tuple_size(tuple) ->
          :range

        true ->
          []
      end,
      must_be_tuple(tuple)
    ]
  end

  defp format_erlang_error(:exit, [_, _], _) do
    [:not_pid]
  end

  defp format_erlang_error(:exit_signal, [_, _], _) do
    [:not_pid]
  end

  defp format_erlang_error(:external_size, [_Term, options], _) do
    [[], must_be_option_list(options)]
  end

  defp format_erlang_error(:float, [_], _) do
    [:not_number]
  end

  defp format_erlang_error(:float_to_binary, [_], _) do
    [:not_float]
  end

  defp format_erlang_error(:float_to_binary, [float, options], _) do
    arg1 = must_be_float(float)
    [arg1, maybe_option_list_error(options, arg1)]
  end

  defp format_erlang_error(:float_to_list, [_], _) do
    [:not_float]
  end

  defp format_erlang_error(:float_to_list, [float, options], _) do
    arg1 = must_be_float(float)
    [arg1, maybe_option_list_error(options, arg1)]
  end

  defp format_erlang_error(:floor, [_], _) do
    [:not_number]
  end

  defp format_erlang_error(:function_exported, [m, f, a], _) do
    [must_be_atom(m), must_be_atom(f), must_be_non_neg_int(a)]
  end

  defp format_erlang_error(:fun_info, [_], _) do
    [:not_fun]
  end

  defp format_erlang_error(:fun_info, [fun, _], _) do
    arg1 =
      cond do
        is_function(fun) ->
          []

        true ->
          :not_fun
      end

    case arg1 do
      [] ->
        [[], "invalid item"]

      _ ->
        [arg1]
    end
  end

  defp format_erlang_error(:fun_info_mfa, [_], _) do
    [:not_fun]
  end

  defp format_erlang_error(:fun_to_list, [_], _) do
    [:not_fun]
  end

  defp format_erlang_error(:garbage_collect, [pid], _) do
    [must_be_local_pid(pid)]
  end

  defp format_erlang_error(:garbage_collect, [pid, _], cause) do
    [
      must_be_local_pid(pid),
      case cause do
        :bad_option ->
          :bad_option

        _ ->
          []
      end
    ]
  end

  defp format_erlang_error(:get_cookie, [node], _) do
    [must_be_atom(node)]
  end

  defp format_erlang_error(:group_leader, [pid1, pid2], _) do
    [must_be_pid(pid1), must_be_pid(pid2)]
  end

  defp format_erlang_error(:halt, [_], _) do
    [:bad_status]
  end

  defp format_erlang_error(:halt, [_Status, options], cause) do
    case cause do
      :badopt ->
        [[], must_be_list(options, :bad_option)]

      :none ->
        [:bad_status]
    end
  end

  defp format_erlang_error(:hibernate, [m, f, a], _) do
    must_be_mf_args(m, f, a)
  end

  defp format_erlang_error(:hd, [_], _) do
    [:not_cons]
  end

  defp format_erlang_error(:insert_element, [index, tuple, _], cause) do
    format_erlang_error(:element, [index, tuple], cause)
  end

  defp format_erlang_error(:integer_to_binary, [_], _) do
    [:not_integer]
  end

  defp format_erlang_error(:integer_to_binary, args, cause) do
    format_erlang_error(:integer_to_list, args, cause)
  end

  defp format_erlang_error(:integer_to_list, [_], _) do
    [:not_integer]
  end

  defp format_erlang_error(:integer_to_list, [int, base], _) do
    [
      cond do
        is_integer(int) ->
          []

        true ->
          :not_integer
      end,
      must_be_base(base)
    ]
  end

  defp format_erlang_error(:iolist_size, [_], _) do
    [:not_iodata]
  end

  defp format_erlang_error(:iolist_to_binary, [_], _) do
    [:not_iodata]
  end

  defp format_erlang_error(:iolist_to_iovec, [_], _) do
    [:not_iodata]
  end

  defp format_erlang_error(:is_builtin, [m, f, a], _) do
    must_be_mf_arity(m, f, a)
  end

  defp format_erlang_error(:is_function, [_, arity], _) do
    [
      [],
      cond do
        is_integer(arity) ->
          :range

        true ->
          :not_integer
      end
    ]
  end

  defp format_erlang_error(:is_map_key, [_, _], _) do
    [[], :not_map]
  end

  defp format_erlang_error(:is_process_alive, [_], _) do
    [:not_pid]
  end

  defp format_erlang_error(:is_record, [_, _], _) do
    [:not_atom]
  end

  defp format_erlang_error(:is_record, [_, tag, size], _) do
    [[], must_be_atom(tag), must_be_int(size)]
  end

  defp format_erlang_error(:length, [_], _) do
    [:not_list]
  end

  defp format_erlang_error(:link, [pid], _) do
    cond do
      is_pid(pid) ->
        [:dead_process]

      true ->
        [:not_pid]
    end
  end

  defp format_erlang_error(:list_to_atom, [list], _) do
    [must_be_list(list, :not_string)]
  end

  defp format_erlang_error(:list_to_existing_atom, [list], _) do
    case is_flat_char_list(list) do
      false ->
        [must_be_list(list, :not_string)]

      true ->
        [:non_existing_atom]
    end
  end

  defp format_erlang_error(:list_to_binary, [_], _) do
    [:not_iolist]
  end

  defp format_erlang_error(:list_to_bitstring, [_], _) do
    ["not a bitstring list"]
  end

  defp format_erlang_error(:list_to_float, [list], _) do
    list_to_something(list, [{:not_encodable, "a float"}])
  end

  defp format_erlang_error(:list_to_integer, [list], _) do
    list_to_something(list, [{:not_encodable, "an integer"}])
  end

  defp format_erlang_error(:list_to_integer, [list, base], _) do
    case must_be_base(base) do
      [] ->
        [must_be_list(list, {:not_encodable, "an integer"})]

      badBase ->
        [must_be_list(list, []), badBase]
    end
  end

  defp format_erlang_error(:list_to_pid, [list], _) do
    list_to_something(list, [{:not_encodable, "a pid"}])
  end

  defp format_erlang_error(:list_to_port, [list], _) do
    list_to_something(list, [{:not_encodable, "a port"}])
  end

  defp format_erlang_error(:list_to_ref, [list], _) do
    list_to_something(list, [{:not_encodable, "a reference"}])
  end

  defp format_erlang_error(:list_to_tuple, [_], _) do
    [:not_list]
  end

  defp format_erlang_error(:load_module, [module, code], _) do
    [must_be_atom(module), must_be_binary(code)]
  end

  defp format_erlang_error(:localtime_to_universaltime, [time], _) do
    [must_be_localtime(time)]
  end

  defp format_erlang_error(:localtime_to_universaltime, [time, bool], _) do
    [must_be_localtime(time), must_be_isdst(bool)]
  end

  defp format_erlang_error(:load_nif, [_, _], _) do
    [:bad_path]
  end

  defp format_erlang_error(:make_fun, [mod, name, arity], _) do
    [must_be_atom(mod), must_be_atom(name), must_be_non_neg_int(arity)]
  end

  defp format_erlang_error(:make_tuple, [_, _], _) do
    [:range]
  end

  defp format_erlang_error(:make_tuple, [arity, _Value, initList], _) do
    arg1 = must_be_non_neg_int(arity)
    [arg1, [], maybe_option_list_error(initList, arg1)]
  end

  defp format_erlang_error(:map_size, [_], _) do
    [:not_map]
  end

  defp format_erlang_error(:map_get, [_Key, map], _) do
    cond do
      is_map(map) ->
        ["not present in map"]

      true ->
        [[], :not_map]
    end
  end

  defp format_erlang_error(:match_spec_test, [_Subject, _Ms, type], _) do
    case type do
      :trace ->
        [:not_list]

      :table ->
        [:not_tuple]

      _ ->
        [[], [], "invalid type for match spec"]
    end
  end

  defp format_erlang_error(:md5, [_], _) do
    [:not_iodata]
  end

  defp format_erlang_error(:md5_final, [context], _) do
    [check_md5_context(context)]
  end

  defp format_erlang_error(:md5_update, [context, data], _) do
    [
      check_md5_context(context),
      try do
        :erlang.iolist_size(data)
      catch
        :error, :badarg ->
          :not_iodata
      else
        _ ->
          []
      end
    ]
  end

  defp format_erlang_error(:memory, [options], _) do
    cond do
      length(options) >= 0 ->
        [:bad_option]

      is_atom(options) ->
        ["invalid memory type option"]

      true ->
        ["not an atom or a list of atoms"]
    end
  end

  defp format_erlang_error(:module_loaded, [_], _) do
    [:not_atom]
  end

  defp format_erlang_error(:monitor, [type, item], cause) do
    case cause do
      :badtype ->
        ["invalid monitor type"]

      :none ->
        case type do
          :port ->
            [[], must_be_local_port(item)]

          :process ->
            [[], must_be_pid(item)]
        end
    end
  end

  defp format_erlang_error(:monitor, [type, item, options], cause) do
    itemError =
      case type do
        :port ->
          must_be_local_port(item)

        :process ->
          must_be_pid(item)

        _ ->
          []
      end

    case cause do
      :badopt ->
        [[], itemError, must_be_list(options, :bad_option)]

      :badtype ->
        ["invalid monitor type"]

      :none ->
        [[], itemError]
    end
  end

  defp format_erlang_error(:monitor_node, [node, flag], _) do
    [must_be_atom(node), must_be_boolean(flag)]
  end

  defp format_erlang_error(:monitor_node, [node, flag, options], cause) do
    arg3 =
      case cause do
        :badopt ->
          :bad_option

        _ ->
          []
      end

    case format_erlang_error(:monitor_node, [node, flag], cause) do
      [[], []] ->
        [[], [], must_be_list(options, arg3)]

      errors ->
        errors ++ [must_be_list(options, arg3)]
    end
  end

  defp format_erlang_error(:monotonic_time, [_], _) do
    [:bad_time_unit]
  end

  defp format_erlang_error(:node, [_], _) do
    [:not_pid]
  end

  defp format_erlang_error(:nodes, [nTVal], _) when is_atom(nTVal) do
    ["not a valid node type"]
  end

  defp format_erlang_error(:nodes, [nTVal], _) when is_list(nTVal) do
    ["not a list of valid node types"]
  end

  defp format_erlang_error(:nodes, [_NTVal], _) do
    ["not a valid node type or list of valid node types"]
  end

  defp format_erlang_error(:nodes, [nTVal, opts], _) do
    validNodeTypes = [:this, :connected, :visible, :hidden, :known]

    [
      cond do
        is_atom(nTVal) ->
          case :lists.member(nTVal, validNodeTypes) do
            true ->
              []

            false ->
              "not a valid node type"
          end

        is_list(nTVal) ->
          try do
            :lists.foreach(
              fn nT ->
                case :lists.member(nT, validNodeTypes) do
                  true ->
                    []

                  false ->
                    throw(:invalid)
                end
              end,
              nTVal
            )

            []
          catch
            :invalid ->
              "not a list of valid node types"
          end

        true ->
          "not a valid node type or list of valid node types"
      end,
      cond do
        is_map(opts) ->
          try do
            :maps.foreach(
              fn
                :connection_id, bool
                when is_boolean(bool) ->
                  :ok

                :node_type, bool when is_boolean(bool) ->
                  :ok

                _, _ ->
                  throw(:invalid)
              end,
              opts
            )

            []
          catch
            :invalid ->
              "invalid options in map"
          end

        true ->
          :not_map
      end
    ]
  end

  defp format_erlang_error(:open_port, [name, settings], cause) do
    case cause do
      :badopt ->
        [must_be_tuple(name), :bad_option]

      _ when is_tuple(name) ->
        case :lists.keysearch(:args, 1, settings) do
          {:value, _}
          when :erlang.element(
                 1,
                 name
               ) !== :spawn_executable ->
            ["must be spawn_executable"]

          _ ->
            ["invalid port name"]
        end

      _ ->
        must_be_tuple(name)
    end
  end

  defp format_erlang_error(:phash, [_, n], _) do
    [must_be_pos_int(n)]
  end

  defp format_erlang_error(:phash2, [_, n], _) do
    [must_be_pos_int(n)]
  end

  defp format_erlang_error(:posixtime_to_universaltime, [_], _) do
    [:not_integer]
  end

  defp format_erlang_error(:pid_to_list, [_], _) do
    [:not_pid]
  end

  defp format_erlang_error(:port_call, [port, operation, _Data], _) do
    [must_be_local_port(port), must_be_operation(operation)]
  end

  defp format_erlang_error(:port_close, [port], _) do
    [must_be_local_port(port)]
  end

  defp format_erlang_error(:port_command, [port, command], _) do
    [must_be_local_port(port), must_be_iodata(command)]
  end

  defp format_erlang_error(:port_command, [port, command, options], cause) do
    case cause do
      :badopt ->
        [must_be_local_port(port), must_be_iodata(command), must_be_list(options, :bad_option)]

      _ ->
        [must_be_local_port(port), must_be_iodata(command)]
    end
  end

  defp format_erlang_error(:port_connect, [port, pid], _) do
    [must_be_local_port(port), must_be_local_pid(pid)]
  end

  defp format_erlang_error(:port_control, [port, operation, data], _) do
    [must_be_local_port(port), must_be_operation(operation), must_be_iodata(data)]
  end

  defp format_erlang_error(:port_info, [port], _) do
    [must_be_local_port(port)]
  end

  defp format_erlang_error(:port_info, [port, _], cause) do
    case cause do
      :badtype ->
        [must_be_local_port(port)]

      _ ->
        [must_be_local_port(port), :bad_option]
    end
  end

  defp format_erlang_error(:port_to_list, [_], _) do
    [:not_port]
  end

  defp format_erlang_error(:prepare_loading, [module, code], _) do
    [must_be_atom(module), must_be_binary(code)]
  end

  defp format_erlang_error(:process_display, [pid, _], cause) do
    case cause do
      :badopt ->
        [must_be_local_pid(pid), "invalid value"]

      _ ->
        [must_be_local_pid(pid, :dead_process)]
    end
  end

  defp format_erlang_error(:process_flag, [_, _], cause) do
    case cause do
      :badopt ->
        ["invalid process flag"]

      _ ->
        [[], "invalid value for this process flag"]
    end
  end

  defp format_erlang_error(:process_flag, [pid, option, _], cause) do
    optionError =
      case option do
        :save_calls ->
          []

        _ ->
          "invalid process flag"
      end

    case cause do
      :badtype ->
        [must_be_local_pid(pid, :dead_process), optionError]

      _ ->
        case {must_be_local_pid(pid), optionError} do
          {[], []} ->
            [[], [], "invalid value for process flag 'save_calls'"]

          {pidError, _} ->
            [pidError, optionError]
        end
    end
  end

  defp format_erlang_error(:process_info, [pid], _) do
    [must_be_local_pid(pid)]
  end

  defp format_erlang_error(:process_info, [pid, _What], _) do
    arg1 = must_be_local_pid(pid)

    case arg1 do
      [] ->
        [[], "invalid item or item list"]

      _ ->
        [arg1]
    end
  end

  defp format_erlang_error(:purge_module, [module], _) do
    [must_be_atom(module)]
  end

  defp format_erlang_error(:read_timer, [_], _) do
    [:not_ref]
  end

  defp format_erlang_error(:read_timer, [ref, options], _) do
    arg1 = must_be_ref(ref)
    [arg1, maybe_option_list_error(options, arg1)]
  end

  defp format_erlang_error(:ref_to_list, [_], _) do
    [:not_ref]
  end

  defp format_erlang_error(:register, [name, pidOrPort], cause) do
    case cause do
      :registered_name ->
        [[], "this process or port already has a name"]

      :notalive ->
        [[], :dead_process]

      _ ->
        errors = [
          cond do
            name === :undefined ->
              "'undefined' is not a valid name"

            is_atom(name) ->
              []

            true ->
              :not_atom
          end,
          cond do
            is_pid(pidOrPort) and node(pidOrPort) !== node() ->
              :not_local_pid

            is_port(pidOrPort) and node(pidOrPort) !== node() ->
              :not_local_port

            is_pid(pidOrPort) ->
              []

            is_port(pidOrPort) ->
              []

            true ->
              "not a pid or port"
          end
        ]

        case errors do
          [[], []] ->
            ["name is in use"]

          [_, _] ->
            errors
        end
    end
  end

  defp format_erlang_error(:resume_process, [pid], _) do
    [must_be_local_pid(pid, "process is not suspended or is not alive")]
  end

  defp format_erlang_error(:round, [_], _) do
    [:not_number]
  end

  defp format_erlang_error(:send, [_, _], _) do
    [:bad_destination]
  end

  defp format_erlang_error(:send, [_, _, options], cause) do
    case cause do
      :badopt ->
        [[], [], must_be_list(options, :bad_option)]

      _ ->
        [:bad_destination]
    end
  end

  defp format_erlang_error(:send_after, args, cause) do
    format_erlang_error(:start_timer, args, cause)
  end

  defp format_erlang_error(:send_nosuspend, [_, _], _) do
    [:bad_destination]
  end

  defp format_erlang_error(:send_nosuspend, [_, _, options], cause) do
    case cause do
      :badopt ->
        [[], [], must_be_list(options, :bad_option)]

      _ ->
        [:bad_destination]
    end
  end

  defp format_erlang_error(:set_cookie, [cookie], _) do
    [must_be_atom(cookie)]
  end

  defp format_erlang_error(:set_cookie, [node, cookie], _) do
    [must_be_live_node(node), must_be_atom(cookie)]
  end

  defp format_erlang_error(:setelement, [index, tuple, _], cause) do
    format_erlang_error(:element, [index, tuple], cause)
  end

  defp format_erlang_error(:size, [_], _) do
    ["not tuple or binary"]
  end

  defp format_erlang_error(:spawn, [_], _) do
    [:not_fun]
  end

  defp format_erlang_error(:spawn, [n, f], _) do
    must_be_node_fun(n, f)
  end

  defp format_erlang_error(:spawn, [m, f, a], _) do
    must_be_mf_args(m, f, a)
  end

  defp format_erlang_error(:spawn, [n, m, f, a], _) do
    must_be_node_mf_args(n, m, f, a)
  end

  defp format_erlang_error(:spawn_link, [_], _) do
    [:not_fun]
  end

  defp format_erlang_error(:spawn_link, [n, f], _) do
    must_be_node_fun(n, f)
  end

  defp format_erlang_error(:spawn_link, [m, f, a], _) do
    must_be_mf_args(m, f, a)
  end

  defp format_erlang_error(:spawn_link, [n, m, f, a], _) do
    must_be_node_mf_args(n, m, f, a)
  end

  defp format_erlang_error(:spawn_monitor, [_], _) do
    [:not_fun]
  end

  defp format_erlang_error(:spawn_monitor, [n, f], _) do
    must_be_node_fun(n, f)
  end

  defp format_erlang_error(:spawn_monitor, [m, f, a], _) do
    must_be_mf_args(m, f, a)
  end

  defp format_erlang_error(:spawn_monitor, [n, m, f, a], _) do
    must_be_node_mf_args(n, m, f, a)
  end

  defp format_erlang_error(:spawn_opt, [fun, options], cause) do
    [
      must_be_fun(fun),
      case cause do
        :badopt ->
          must_be_list(options, "invalid spawn option")

        :none ->
          []
      end
    ]
  end

  defp format_erlang_error(:spawn_opt, [node, fun, options], cause) do
    [
      must_be_atom(node),
      must_be_fun(fun),
      case cause do
        :badopt ->
          must_be_list(options, "invalid spawn option")

        :none ->
          []
      end
    ]
  end

  defp format_erlang_error(:spawn_opt, [m, f, a, options], cause) do
    must_be_mf_args(m, f, a) ++
      [
        case cause do
          :badopt ->
            must_be_list(options, "invalid spawn option")

          :none ->
            []
        end
      ]
  end

  defp format_erlang_error(:spawn_opt, [n, m, f, a, options], cause) do
    must_be_node_mf_args(n, m, f, a) ++
      [
        case cause do
          :badopt ->
            must_be_list(options, "invalid spawn option")

          :none ->
            []
        end
      ]
  end

  defp format_erlang_error(:spawn_request, [_], _) do
    [:not_fun]
  end

  defp format_erlang_error(:spawn_request, [fun, _Options], cause)
       when is_function(fun) do
    case cause do
      :badopt ->
        [[], :bad_option]

      _ ->
        []
    end
  end

  defp format_erlang_error(:spawn_request, [_Node, fun], _)
       when is_function(fun) do
    [:not_atom]
  end

  defp format_erlang_error(:spawn_request, [node, _BadFun], _)
       when is_atom(node) do
    [[], :not_fun]
  end

  defp format_erlang_error(:spawn_request, [_, _], _) do
    ["not a fun or an atom"]
  end

  defp format_erlang_error(:spawn_request, [n, f, o], cause)
       when is_function(f) do
    case cause do
      :badopt ->
        [must_be_atom(n), [], must_be_list(o, :bad_option)]

      _ ->
        [must_be_atom(n), [], must_be_list(o, [])]
    end
  end

  defp format_erlang_error(:spawn_request, [n, f, o], cause)
       when is_function(f) do
    case cause do
      :badopt ->
        [must_be_atom(n), [], must_be_option_list(o)]

      _ ->
        nodeError = must_be_atom(n)
        [nodeError, [], maybe_option_list_error(o, nodeError)]
    end
  end

  defp format_erlang_error(:spawn_request, [m, f, a], _) do
    must_be_mf_args(m, f, a)
  end

  defp format_erlang_error(:spawn_request, [n, m, f, a], _)
       when is_atom(f) do
    must_be_node_mf_args(n, m, f, a)
  end

  defp format_erlang_error(:spawn_request, [m, f, a, _Opts], cause) do
    case cause do
      :badopt ->
        must_be_mf_args(m, f, a) ++ [:bad_option]

      _ ->
        must_be_mf_args(m, f, a)
    end
  end

  defp format_erlang_error(:spawn_request, [n, m, f, a, _Opts], cause) do
    case cause do
      :badopt ->
        must_be_node_mf_args(n, m, f, a) ++ [:bad_option]

      _ ->
        must_be_node_mf_args(n, m, f, a)
    end
  end

  defp format_erlang_error(:spawn_request_abandon, [_], _) do
    [:not_ref]
  end

  defp format_erlang_error(:split_binary, [bin, pos], _) do
    case [must_be_binary(bin), must_be_non_neg_int(pos)] do
      [[], []] ->
        cond do
          pos > byte_size(bin) ->
            [[], :range]

          true ->
            []
        end

      errors ->
        errors
    end
  end

  defp format_erlang_error(:start_timer, [time, process, _], cause) do
    [
      must_be_time(time, cause),
      cond do
        is_pid(process) and
            node(process) !== node() ->
          :not_local_pid

        (is_pid(process) and
           node(process) === node()) or
            is_atom(process) ->
          []

        true ->
          "not a pid or an atom"
      end
    ]
  end

  defp format_erlang_error(:start_timer, [a1, a2, a3, options], cause) do
    format_erlang_error(:start_timer, [a1, a2, a3], cause) ++
      [
        case cause do
          :badopt ->
            must_be_list(options, :bad_option)

          _ ->
            must_be_list(options, [])
        end
      ]
  end

  defp format_erlang_error(:subtract, [a, b], _) do
    [must_be_list(a), must_be_list(b)]
  end

  defp format_erlang_error(:suspend_process, [pid], _) do
    [
      cond do
        pid === self() ->
          :self_not_allowed

        true ->
          must_be_local_pid(pid, :dead_process)
      end
    ]
  end

  defp format_erlang_error(:suspend_process, [pid, options], cause) do
    case cause do
      :badopt ->
        [
          must_be_local_pid(pid, []),
          must_be_list(
            options,
            :bad_option
          )
        ]

      _ ->
        [
          cond do
            pid === self() ->
              :self_not_allowed

            true ->
              must_be_local_pid(pid, :dead_process)
          end
        ]
    end
  end

  defp format_erlang_error(:system_flag, [_, _], cause) do
    case cause do
      :badopt ->
        ["invalid system flag"]

      :none ->
        [[], "invalid value for this system flag"]
    end
  end

  defp format_erlang_error(:system_info, [_], _) do
    ["invalid system info item"]
  end

  defp format_erlang_error(:system_monitor, [_], _) do
    ["invalid system monitor item"]
  end

  defp format_erlang_error(:system_monitor, [pid, options], _) do
    cond do
      is_pid(pid) and node(pid) === node() ->
        [[], must_be_list(options, "invalid system monitor option")]

      is_pid(pid) ->
        [:not_local_pid, must_be_list(options)]

      true ->
        [:not_pid, must_be_list(options)]
    end
  end

  defp format_erlang_error(:system_profile, [_, _], _) do
    []
  end

  defp format_erlang_error(:system_time, [_], _) do
    [:bad_time_unit]
  end

  defp format_erlang_error(:statistics, [_], _) do
    ["invalid statistics item"]
  end

  defp format_erlang_error(:term_to_binary, [_, options], _) do
    [[], must_be_option_list(options)]
  end

  defp format_erlang_error(:term_to_iovec, [_, options], _) do
    [[], must_be_option_list(options)]
  end

  defp format_erlang_error(:time_offset, [_], _) do
    [:bad_time_unit]
  end

  defp format_erlang_error(:trace, [pidOrPort, how, options], cause) do
    pidOrPortError =
      cond do
        is_pid(pidOrPort) and node(pidOrPort) !== node() ->
          :not_local_pid

        is_port(pidOrPort) and node(pidOrPort) !== node() ->
          :not_local_port

        true ->
          []
      end

    howError = must_be_boolean(how)

    case cause do
      :badopt ->
        [pidOrPortError, howError, must_be_option_list(options)]

      _ ->
        case {howError, pidOrPortError} do
          {[], []} ->
            ["invalid spec for pid or port"]

          _ ->
            [pidOrPortError, howError, []]
        end
    end
  end

  defp format_erlang_error(:trace_pattern = f, [_, _] = args, cause) do
    [err1, err2 | _] = format_erlang_error(f, args ++ [[]], cause)
    [err1, err2]
  end

  defp format_erlang_error(:trace_pattern, [_, _, options], cause) do
    case cause do
      :badopt ->
        [[], [], must_be_option_list(options)]

      :match_spec ->
        [
          [],
          :bad_match_spec,
          maybe_option_list_error(
            options,
            :bad_match_spec
          )
        ]

      :call_count ->
        [[], [], "a match spec is not allowed in combination with these options"]

      _ ->
        ["invalid MFA specification", [], []]
    end
  end

  defp format_erlang_error(:trace_delivered, [pid], _) do
    cond do
      is_pid(pid) and node(pid) !== :node ->
        [:not_local_pid]

      true ->
        ["not a pid or 'all'"]
    end
  end

  defp format_erlang_error(:tuple_size, [_], _) do
    [:not_tuple]
  end

  defp format_erlang_error(:tl, [_], _) do
    [:not_cons]
  end

  defp format_erlang_error(:trace_info, [tracee, _], cause) do
    case cause do
      :badopt ->
        cond do
          is_pid(tracee) and node(tracee) !== node() ->
            [:not_local_pid]

          is_port(tracee) and node(tracee) !== node() ->
            [:not_local_port]

          true ->
            ["not a valid tracee specification"]
        end

      :none ->
        [[], "invalid trace item"]
    end
  end

  defp format_erlang_error(:trunc, [_], _) do
    [:not_number]
  end

  defp format_erlang_error(:tuple_to_list, [_], _) do
    [:not_tuple]
  end

  defp format_erlang_error(:unalias, [_], _) do
    [:not_ref]
  end

  defp format_erlang_error(:unlink, [_], _) do
    [:not_pid]
  end

  defp format_erlang_error(:unique_integer, [modifiers], _) do
    [must_be_list(modifiers, "invalid modifier")]
  end

  defp format_erlang_error(:universaltime_to_localtime, [_], _) do
    [:bad_universaltime]
  end

  defp format_erlang_error(:universaltime_to_posixtime, [_], _) do
    [:bad_universaltime]
  end

  defp format_erlang_error(:unregister, [_], _) do
    [:not_pid]
  end

  defp format_erlang_error(:whereis, [_], _) do
    [:not_atom]
  end

  defp format_erlang_error(_, _, _) do
    []
  end

  defp do_format_bs_fail(:system_limit, :binary, :binary, :size, _PrettyPrinter) do
    :io_lib.format("the size of the binary/bitstring is too large (exceeding ~p bits)", [
      1 <<< (31 - 1)
    ])
  end

  defp do_format_bs_fail(:system_limit, _Type, :size, value, _PrettyPrinter) do
    :io_lib.format("the size ~p is too large", [value])
  end

  defp do_format_bs_fail(:badarg, type, info, value, prettyPrinter) do
    do_format_bs_fail(type, info, value, prettyPrinter)
  end

  defp do_format_bs_fail(:float, :invalid, value, _PrettyPrinter) do
    :io_lib.format("expected one of the supported sizes 16, 32, or 64 but got: ~p", [value])
  end

  defp do_format_bs_fail(:float, :no_float, value, prettyPrinter) do
    :io_lib.format("the value ~ts is outside the range expressible as a float", [
      prettyPrinter.(value)
    ])
  end

  defp do_format_bs_fail(:binary, :unit, value, prettyPrinter) do
    :io_lib.format("the size of the value ~ts is not a multiple of the unit for the segment", [
      prettyPrinter.(value)
    ])
  end

  defp do_format_bs_fail(_Type, :short, value, prettyPrinter) do
    :io_lib.format("the value ~ts is shorter than the size of the segment", [
      prettyPrinter.(value)
    ])
  end

  defp do_format_bs_fail(_Type, :size, value, prettyPrinter) do
    :io_lib.format("expected a non-negative integer as size but got: ~ts", [prettyPrinter.(value)])
  end

  defp do_format_bs_fail(type, :type, value, prettyPrinter) do
    f =
      <<"expected a",
        case type do
          :binary ->
            " binary"

          :float ->
            " float or an integer"

          :integer ->
            "n integer"

          _ ->
            <<" non-negative integer encodable as ", :erlang.atom_to_binary(type)::binary>>
        end::binary, " but got: ~ts">>

    :io_lib.format(f, [prettyPrinter.(value)])
  end

  defp possibly_truncated(int) when is_integer(int) do
    bin = :erlang.integer_to_binary(int)

    case byte_size(bin) do
      size when size < 48 ->
        bin

      size ->
        <<prefix::size(12)-binary, _::size(size - 24)-binary, suffix::binary>> = bin
        [prefix, "...", suffix]
    end
  end

  defp possibly_truncated(bin) when is_bitstring(bin) do
    case byte_size(bin) do
      size when size < 16 ->
        :io_lib.format(~c"~p", [bin])

      size ->
        <<prefix0::size(8)-binary, _::size(size - 10)-binary, suffix0::bitstring>> = bin

        prefix1 =
          :erlang.iolist_to_binary(
            :io_lib.format(
              ~c"~w",
              [prefix0]
            )
          )

        <<prefix::size(byte_size(prefix1) - 2)-binary, _::binary>> = prefix1

        <<_::size(2)-unit(8), suffix::binary>> =
          :erlang.iolist_to_binary(
            :io_lib.format(
              ~c"~w",
              [suffix0]
            )
          )

        [prefix, "...,", suffix]
    end
  end

  defp possibly_truncated(value) do
    :io_lib.format(~c"~P", [value, 20])
  end

  defp list_to_something(list, error) do
    try do
      length(list)
    catch
      :error, :badarg ->
        [:not_list]
    else
      _ ->
        error
    end
  end

  defp must_be_adler32(n) do
    cond do
      is_integer(n) ->
        cond do
          0 <= n and n < 1 <<< 32 ->
            []

          true ->
            :range
        end

      true ->
        :not_integer
    end
  end

  defp must_be_atom(a) when is_atom(a) do
    []
  end

  defp must_be_atom(_) do
    :not_atom
  end

  defp must_be_live_node(:nonode@nohost) do
    :not_live_node
  end

  defp must_be_live_node(a) when is_atom(a) do
    []
  end

  defp must_be_live_node(_) do
    :not_atom
  end

  defp must_be_base(n)
       when is_integer(n) and 2 <= n and
              n <= 36 do
    []
  end

  defp must_be_base(_) do
    :bad_base
  end

  defp must_be_boolean(b) when is_boolean(b) do
    []
  end

  defp must_be_boolean(_) do
    :bad_boolean
  end

  defp must_be_fun(f) when is_function(f) do
    []
  end

  defp must_be_fun(_) do
    :not_fun
  end

  defp must_be_isdst(:undefined) do
    []
  end

  defp must_be_isdst(b) when is_boolean(b) do
    []
  end

  defp must_be_isdst(_) do
    :bad_isdst
  end

  defp must_be_binary(bin) do
    must_be_binary(bin, [])
  end

  defp must_be_binary(bin, error) when is_binary(bin) do
    error
  end

  defp must_be_binary(_, _) do
    :not_binary
  end

  defp must_be_float(float) when is_float(float) do
    []
  end

  defp must_be_float(_) do
    :not_float
  end

  defp must_be_iodata(data) do
    try do
      :erlang.iolist_size(data)
    catch
      :error, :badarg ->
        :not_iodata
    else
      _ ->
        []
    end
  end

  defp must_be_list(list) do
    must_be_list(list, [])
  end

  defp must_be_list(list, error) when is_list(list) do
    try do
      length(list)
    catch
      :error, :badarg ->
        :not_proper_list
    else
      _ ->
        error
    end
  end

  defp must_be_list(_, _) do
    :not_list
  end

  defp must_be_localtime(time) do
    try do
      :erlang.localtime_to_universaltime(time)
    catch
      :error, :badarg ->
        :bad_localtime
    else
      _ ->
        []
    end
  end

  defp must_be_mf_args(m, f, a) do
    [must_be_atom(m), must_be_atom(f), must_be_list(a)]
  end

  defp must_be_mf_arity(m, f, a) do
    [must_be_atom(m), must_be_atom(f), must_be_non_neg_int(a)]
  end

  defp must_be_node_mf_args(n, m, f, a) do
    [must_be_atom(n) | must_be_mf_args(m, f, a)]
  end

  defp must_be_node_fun(n, f) do
    [
      must_be_atom(n)
      | cond do
          is_function(f) ->
            []

          true ->
            [:not_fun]
        end
    ]
  end

  defp must_be_int(n) when is_integer(n) do
    []
  end

  defp must_be_int(_) do
    :not_integer
  end

  defp must_be_int(n, min, max) do
    must_be_int(n, min, max, [])
  end

  defp must_be_int(n, min, max, default) when is_integer(n) do
    cond do
      min <= n and n <= max ->
        default

      true ->
        :range
    end
  end

  defp must_be_int(_, _, _, _) do
    :not_integer
  end

  defp must_be_non_neg_int(n) do
    must_be_int(n, 0, :infinity)
  end

  defp must_be_pos_int(n) do
    must_be_int(n, 1, :infinity)
  end

  defp must_be_operation(operation) do
    must_be_int(operation, 0, 1 <<< (32 - 1), [])
  end

  defp must_be_option_list(options) do
    case must_be_list(options) do
      [] ->
        :bad_option

      error ->
        error
    end
  end

  defp maybe_option_list_error(options, previousError) do
    case {previousError, must_be_list(options)} do
      {[], []} ->
        :bad_option

      {_, arg2} ->
        arg2
    end
  end

  defp must_be_pid(pid) do
    must_be_pid(pid, [])
  end

  defp must_be_pid(pid, error) when is_pid(pid) do
    error
  end

  defp must_be_pid(_, _) do
    :not_pid
  end

  defp must_be_local_pid(pid) do
    must_be_local_pid(pid, [])
  end

  defp must_be_local_pid(pid, _Error)
       when is_pid(pid) and
              node(pid) !== node() do
    :not_local_pid
  end

  defp must_be_local_pid(pid, error) when is_pid(pid) do
    error
  end

  defp must_be_local_pid(_Pid, _Error) do
    :not_pid
  end

  defp must_be_local_port(term) do
    must_be_local_port(term, [])
  end

  defp must_be_local_port(port, _Error)
       when is_port(port) and
              node(port) !== node() do
    :not_local_port
  end

  defp must_be_local_port(port, error)
       when is_port(port) or
              is_atom(port) do
    error
  end

  defp must_be_local_port(_, _) do
    :not_port
  end

  defp must_be_ref(ref) when is_reference(ref) do
    []
  end

  defp must_be_ref(_) do
    :not_ref
  end

  defp must_be_size(n) when is_integer(n) do
    cond do
      n < 0 ->
        :range

      true ->
        []
    end
  end

  defp must_be_size(_) do
    :not_integer
  end

  defp must_be_time(time, cause) do
    case must_be_non_neg_int(time) do
      [] ->
        case cause do
          :time ->
            :beyond_end_time

          _ ->
            []
        end

      error ->
        error
    end
  end

  defp must_be_time_unit(unit) do
    try do
      :erlang.convert_time_unit(1, :native, unit)
    catch
      :error, _ ->
        :bad_time_unit
    else
      _ ->
        []
    end
  end

  defp must_be_tuple(term) do
    must_be_tuple(term, [])
  end

  defp must_be_tuple(tuple, error) when is_tuple(tuple) do
    error
  end

  defp must_be_tuple(_, _) do
    :not_tuple
  end

  defp check_md5_context(context) when is_binary(context) do
    case byte_size(:erlang.md5_init()) === byte_size(context) do
      true ->
        []

      false ->
        "invalid MD5 context"
    end
  end

  defp check_md5_context(_) do
    :not_binary
  end

  defp do_binary_to_atom(bin, enc0, defaultError) do
    enc =
      case enc0 do
        :latin1 ->
          :latin1

        :unicode ->
          :unicode

        :utf8 ->
          :unicode

        _ ->
          :invalid
      end

    case enc do
      :latin1 ->
        [must_be_binary(bin, defaultError)]

      :unicode ->
        cond do
          is_binary(bin) ->
            case :unicode.characters_to_list(bin, enc) do
              charList when is_list(charList) ->
                [:non_existing_atom]

              _ ->
                [:bad_unicode]
            end

          true ->
            [:not_binary]
        end

      :invalid ->
        [must_be_binary(bin), :bad_encode_option]
    end
  end

  defp is_flat_char_list([h | t]) do
    try do
      <<h::utf8>>
    catch
      :error, :badarg ->
        false
    else
      _ ->
        is_flat_char_list(t)
    end
  end

  defp is_flat_char_list([]) do
    true
  end

  defp is_flat_char_list(_) do
    false
  end

  defp maybe_posix_message(cause, hasDevice) do
    case :erl_posix_msg.message(cause) do
      ~c"unknown POSIX error" ++ _ ->
        :unknown

      posixStr when hasDevice ->
        [
          :unicode.characters_to_binary(
            :io_lib.format(
              ~c"~ts (~tp)",
              [posixStr, cause]
            )
          )
        ]

      posixStr when not hasDevice ->
        [
          {:general,
           :unicode.characters_to_binary(
             :io_lib.format(
               ~c"~ts (~tp)",
               [posixStr, cause]
             )
           )}
        ]
    end
  end

  defp format_error_map([~c"" | es], argNum, map) do
    format_error_map(es, argNum + 1, map)
  end

  defp format_error_map([{:general, e} | es], argNum, map) do
    format_error_map(es, argNum, Map.put(map, :general, expand_error(e)))
  end

  defp format_error_map([e | es], argNum, map) do
    format_error_map(es, argNum + 1, Map.put(map, argNum, expand_error(e)))
  end

  defp format_error_map([], _, map) do
    map
  end

  defp expand_error(:bad_atomics_ref) do
    "invalid atomics reference"
  end

  defp expand_error(:bad_base) do
    "not an integer in the range 2 through 36"
  end

  defp expand_error(:bad_boolean) do
    "not a boolean ('true' or 'false')"
  end

  defp expand_error(:bad_counters_ref) do
    "invalid atomics reference"
  end

  defp expand_error(:bad_destination) do
    "invalid destination"
  end

  defp expand_error(:bad_encode_option) do
    "not one of the atoms: latin1, utf8, or unicode"
  end

  defp expand_error(:bad_ext_term) do
    "invalid external representation of a term"
  end

  defp expand_error(:bad_or_unsafe_ext_term) do
    "invalid or unsafe external representation of a term"
  end

  defp expand_error(:bad_isdst) do
    "not 'true', 'false', or 'undefined'"
  end

  defp expand_error(:bad_localtime) do
    "not a valid local time"
  end

  defp expand_error(:bad_match_spec) do
    "invalid match specification"
  end

  defp expand_error(:bad_option) do
    "invalid option in list"
  end

  defp expand_error(:bad_path) do
    "not a valid path name"
  end

  defp expand_error(:bad_status) do
    "invalid status"
  end

  defp expand_error(:bad_time_unit) do
    "invalid time unit"
  end

  defp expand_error(:bad_unicode) do
    "invalid UTF8 encoding"
  end

  defp expand_error(:bad_universaltime) do
    "not a valid universal time"
  end

  defp expand_error(:beyond_end_time) do
    "exceeds the maximum supported time value"
  end

  defp expand_error(:dead_process) do
    "the pid does not refer to an existing process"
  end

  defp expand_error({:not_encodable, type}) do
    ["not a textual representation of ", type]
  end

  defp expand_error(:non_existing_atom) do
    "not an already existing atom"
  end

  defp expand_error(:not_atom) do
    "not an atom"
  end

  defp expand_error(:not_binary) do
    "not a binary"
  end

  defp expand_error(:not_bitstring) do
    "not a bitstring"
  end

  defp expand_error(:not_cons) do
    "not a nonempty list"
  end

  defp expand_error(:not_float) do
    "not a float"
  end

  defp expand_error(:not_fun) do
    "not a fun"
  end

  defp expand_error(:not_integer) do
    "not an integer"
  end

  defp expand_error(:not_iodata) do
    "not an iodata term"
  end

  defp expand_error(:not_iolist) do
    "not an iolist term"
  end

  defp expand_error(:not_list) do
    "not a list"
  end

  defp expand_error(:not_live_node) do
    "the node name is not part of a distributed system"
  end

  defp expand_error(:not_local_pid) do
    "not a local pid"
  end

  defp expand_error(:not_local_port) do
    "not a local port"
  end

  defp expand_error(:not_proper_list) do
    "not a proper list"
  end

  defp expand_error(:not_map) do
    "not a map"
  end

  defp expand_error(:not_number) do
    "not a number"
  end

  defp expand_error(:not_pid) do
    "not a pid"
  end

  defp expand_error(:not_port) do
    "not a port"
  end

  defp expand_error(:not_ref) do
    "not a reference"
  end

  defp expand_error(:not_string) do
    "not a list of characters"
  end

  defp expand_error(:not_device) do
    "not a valid device type"
  end

  defp expand_error(:not_tuple) do
    "not a tuple"
  end

  defp expand_error(:range) do
    "out of range"
  end

  defp expand_error(:self_not_allowed) do
    "the pid refers to the current process"
  end

  defp expand_error(e) when is_binary(e) do
    e
  end
end
