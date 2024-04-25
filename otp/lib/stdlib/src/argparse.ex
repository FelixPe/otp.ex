defmodule :m_argparse do
  use Bitwise
  @author "maximfca@gmail.com"
  def validate(command) do
    validate(command, %{})
  end

  def validate(command, options) do
    prog = executable(options)
    is_list(prog) or :erlang.error(:badarg,
                                     [command, options],
                                     [{:error_info, %{cause: %{2 => "progname is not valid"}}}])
    prefixes = :maps.from_list(for p <- :maps.get(:prefixes,
                                                    options, [?-]) do
                                 {p, true}
                               end)
    _ = validate_command([{prog, command}], prefixes)
    prog
  end

  def parse(args, command) do
    parse(args, command, %{})
  end

  def parse(args, command, options) do
    prog = validate(command, options)
    prefixes = :maps.from_list(for p <- :maps.get(:prefixes,
                                                    options, [?-]) do
                                 {p, true}
                               end)
    try do
      parse_impl(args,
                   merge_arguments(prog, command,
                                     init_parser(prefixes, command, options)))
    catch
      reason ->
        {:error, reason}
    end
  end

  def help(command) do
    help(command, %{})
  end

  def help(command, options) do
    prog = validate(command, options)
    format_help({prog, command}, options)
  end

  def run(args, command, options) do
    try do
      parse(args, command, options)
    catch
      :error, reason ->
        :io.format(:erl_error.format_exception(:error, reason,
                                                 __STACKTRACE__))
        :erlang.halt(1)
    else
      {:ok, argMap, path, subCmd} ->
        handle(command, argMap, tl(path), subCmd)
      {:error, reason} ->
        :io.format('error: ~ts~n', [:argparse.format_error(reason)])
        :io.format('~ts',
                     [:argparse.help(command,
                                       Map.put(options, :command,
                                                          tl(:erlang.element(1,
                                                                               reason))))])
        :erlang.halt(1)
    end
  end

  def format_error({path, :undefined, :undefined, details}) do
    :io_lib.format('~ts: ~ts', [format_path(path), details])
  end

  def format_error({path, :undefined, actual, details}) do
    :io_lib.format('~ts: unknown argument: ~ts~ts', [format_path(path), actual, details])
  end

  def format_error({path, %{name: name}, :undefined, details}) do
    :io_lib.format('~ts: required argument missing: ~ts~ts', [format_path(path), name, details])
  end

  def format_error({path, %{name: name}, value, details}) do
    :io_lib.format('~ts: invalid argument for ~ts: ~ts ~ts',
                     [format_path(path), name, value, details])
  end

  def format_error({:argparse, :command, path, field, reason},
           [{_M, _F, [cmd], info} | _]) do
    %{cause: cause} = :proplists.get_value(:error_info,
                                             info, %{})
    Map.merge(cause, %{general: "command specification is invalid",
                         1 => :io_lib.format('~tp', [cmd]),
                         reason:
                         :io_lib.format('command "~ts": invalid field \'~ts\', reason: ~ts', [format_path(path), field, reason])})
  end

  def format_error({:argparse, :argument, path, field, reason},
           [{_M, _F, [arg], info} | _]) do
    %{cause: cause} = :proplists.get_value(:error_info,
                                             info, %{})
    argName = :maps.get(:name, arg, '')
    Map.merge(cause, %{general: 'argument specification is invalid',
                         1 => :io_lib.format('~tp', [arg]),
                         reason:
                         :io_lib.format('command "~ts", argument \'~ts\', invalid field \'~ts\': ~ts',
                                          [format_path(path), argName, field,
                                                                           reason])})
  end

  require Record
  Record.defrecord(:r_eos, :eos, prefixes: :undefined,
                               argmap: %{}, commands: [], current: :undefined,
                               pos: [], short: %{}, long: %{}, no_digits: true,
                               default: :undefined)
  defp init_parser(prefixes, cmd, options) do
    r_eos(prefixes: prefixes, current: cmd,
        default: :maps.find(:default, options))
  end

  defp match_long(arg, longOpts) do
    case (:maps.find(arg, longOpts)) do
      {:ok, option} ->
        {:ok, option}
      :error ->
        case (:string.split(arg, '=')) do
          [maybeLong, value] ->
            case (:maps.find(maybeLong, longOpts)) do
              {:ok, option} ->
                {:ok, option, value}
              :error ->
                :nomatch
            end
          _ ->
            :nomatch
        end
    end
  end

  defp parse_impl([[prefix | name] | tail],
            r_eos(prefixes: pref) = eos)
      when :erlang.is_map_key(prefix, pref) do
    case (match_long(name, r_eos(eos, :long))) do
      {:ok, option} ->
        consume(tail, option, eos)
      {:ok, option, value} ->
        consume([value | tail], option, eos)
      :nomatch ->
        case (name) do
          [flag] when :erlang.is_map_key(flag, r_eos(eos, :short)) ->
            consume(tail, :maps.get(flag, r_eos(eos, :short)), eos)
          [flag | rest] when :erlang.is_map_key(flag,
                                                  r_eos(eos, :short))
                             ->
            case (abbreviated(name, [], r_eos(eos, :short))) do
              false ->
                consume([rest | tail], :maps.get(flag, r_eos(eos, :short)),
                          eos)
              expanded ->
                parse_impl((for e <- expanded do
                              [prefix, e]
                            end) ++ tail,
                             eos)
            end
          maybeNegative when (prefix === ?- and
                                r_eos(eos, :no_digits))
                             ->
            case (is_digits(maybeNegative)) do
              true ->
                parse_positional([prefix | name], tail, eos)
              false ->
                catch_all_positional([[prefix | name] | tail], eos)
            end
          _Unknown ->
            catch_all_positional([[prefix | name] | tail], eos)
        end
    end
  end

  defp parse_impl([positional | tail],
            r_eos(current: %{commands: subCommands}) = eos) do
    case (:maps.find(positional, subCommands)) do
      :error ->
        parse_positional(positional, tail, eos)
      {:ok, subCmd} ->
        parse_impl(tail,
                     merge_arguments(positional, subCmd, eos))
    end
  end

  defp parse_impl([positional | tail], eos) do
    parse_positional(positional, tail, eos)
  end

  defp parse_impl([],
            r_eos(argmap: argMap0, commands: commands, current: current,
                pos: pos, default: def__) = eos) do
    map_size(:maps.get(:commands, current, %{})) > 0 and not
                                                         :erlang.is_map_key(:handler,
                                                                              current) and throw({commands,
                                                                                                    :undefined,
                                                                                                    :undefined,
                                                                                                    "subcommand expected"})
    argMap1 = fold_args_map(commands, true, argMap0, pos,
                              def__)
    argMap2 = fold_args_map(commands, false, argMap1,
                              :maps.values(r_eos(eos, :short)), def__)
    argMap3 = fold_args_map(commands, false, argMap2,
                              :maps.values(r_eos(eos, :long)), def__)
    {:ok, argMap3, r_eos(eos, :commands), r_eos(eos, :current)}
  end

  defp fold_args_map(commands, req, argMap, args, globalDefault) do
    :lists.foldl(fn %{name: name}, acc
                        when :erlang.is_map_key(name, acc) ->
                      acc
                    %{required: true} = opt, _Acc ->
                      throw({commands, opt, :undefined, <<>>})
                    %{name: name, required: false, default: default}, acc ->
                      Map.put(acc, name, default)
                    %{name: name, required: false}, acc ->
                      try_global_default(name, acc, globalDefault)
                    %{name: name, default: default}, acc when req === true
                                                              ->
                      Map.put(acc, name, default)
                    opt, _Acc when req === true ->
                      throw({commands, opt, :undefined, <<>>})
                    %{name: name, default: default}, acc ->
                      Map.put(acc, name, default)
                    %{name: name}, acc ->
                      try_global_default(name, acc, globalDefault)
                 end,
                   argMap, args)
  end

  defp try_global_default(_Name, acc, :error) do
    acc
  end

  defp try_global_default(name, acc, {:ok, term}) do
    Map.put(acc, name, term)
  end

  defp catch_all_positional(tail, r_eos(pos: [%{nargs: :all} = opt]) = eos) do
    action([], tail,
             Map.put(opt, :type,
                            {:list, :maps.get(:type, opt, :string)}),
             eos)
  end

  defp catch_all_positional(tail,
            r_eos(argmap: args,
                pos: [%{name: name, default: default, required: false} |
                          pos]) = eos) do
    catch_all_positional(tail,
                           r_eos(eos, argmap: Map.put(args, name, default), 
                                    pos: pos))
  end

  defp catch_all_positional(tail,
            r_eos(pos: [%{required: false} | pos]) = eos) do
    catch_all_positional(tail, r_eos(eos, pos: pos))
  end

  defp catch_all_positional([arg | _Tail], r_eos(commands: commands)) do
    throw({commands, :undefined, arg, <<>>})
  end

  defp parse_positional(arg, _Tail, r_eos(pos: [], commands: commands)) do
    throw({commands, :undefined, arg, <<>>})
  end

  defp parse_positional(arg, tail, r_eos(pos: pos) = eos) do
    consume([arg | tail], hd(pos), eos)
  end

  defp merge_arguments(cmdName, %{arguments: args} = subCmd, eos) do
    add_args(args,
               r_eos(eos, current: subCmd, 
                        commands: r_eos(eos, :commands) ++ [cmdName]))
  end

  defp merge_arguments(cmdName, subCmd, eos) do
    r_eos(eos, current: subCmd, 
             commands: r_eos(eos, :commands) ++ [cmdName])
  end

  defp add_args([], eos) do
    eos
  end

  defp add_args([%{short: s, long: l} = option | tail],
            r_eos(short: short, long: long) = eos) do
    noDigits = no_digits(r_eos(eos, :no_digits),
                           r_eos(eos, :prefixes), s, l)
    add_args(tail,
               r_eos(eos, short: Map.put(short, s, option), 
                        long: Map.put(long, l, option),  no_digits: noDigits))
  end

  defp add_args([%{short: s} = option | tail],
            r_eos(short: short) = eos) do
    noDigits = no_digits(r_eos(eos, :no_digits),
                           r_eos(eos, :prefixes), s, 0)
    add_args(tail,
               r_eos(eos, short: Map.put(short, s, option), 
                        no_digits: noDigits))
  end

  defp add_args([%{long: l} = option | tail],
            r_eos(long: long) = eos) do
    noDigits = no_digits(r_eos(eos, :no_digits),
                           r_eos(eos, :prefixes), 0, l)
    add_args(tail,
               r_eos(eos, long: Map.put(long, l, option), 
                        no_digits: noDigits))
  end

  defp add_args([posOpt | tail], r_eos(pos: pos) = eos) do
    add_args(tail, r_eos(eos, pos: pos ++ [posOpt]))
  end

  defp no_digits(false, _, _, _) do
    false
  end

  defp no_digits(true, prefixes, _, _) when not
                                     :erlang.is_map_key(?-, prefixes) do
    true
  end

  defp no_digits(true, _, short, _) when (short >= ?0 and
                                     short <= ?9) do
    false
  end

  defp no_digits(true, _, _, long) do
    not is_digits(long)
  end

  defp requires_argument(%{nargs: {:maybe, _Term}}) do
    false
  end

  defp requires_argument(%{nargs: :maybe}) do
    false
  end

  defp requires_argument(%{nargs: _Any}) do
    true
  end

  defp requires_argument(opt) do
    case (:maps.get(:action, opt, :store)) do
      :store ->
        :maps.get(:type, opt, :string) !== :boolean
      :append ->
        :maps.get(:type, opt, :string) !== :boolean
      _ ->
        false
    end
  end

  defp abbreviated([last], acc, allShort)
      when :erlang.is_map_key(last, allShort) do
    :lists.reverse([last | acc])
  end

  defp abbreviated([_], _Acc, _Eos) do
    false
  end

  defp abbreviated([flag | tail], acc, allShort) do
    case (:maps.find(flag, allShort)) do
      :error ->
        false
      {:ok, opt} ->
        case (requires_argument(opt)) do
          true ->
            false
          false ->
            abbreviated(tail, [flag | acc], allShort)
        end
    end
  end

  defp consume(tail, %{nargs: count} = opt, eos)
      when is_integer(count) do
    {consumed, remain} = split_to_option(tail, count, eos,
                                           [])
    length(consumed) < count and throw({r_eos(eos, :commands),
                                          opt, tail,
                                          :io_lib.format('expected ~b, found ~b argument(s)',
                                                           [count,
                                                                length(consumed)])})
    action(remain, consumed,
             Map.put(opt, :type,
                            {:list, :maps.get(:type, opt, :string)}),
             eos)
  end

  defp consume(tail, %{nargs: :all} = opt, eos) do
    action([], tail,
             Map.put(opt, :type,
                            {:list, :maps.get(:type, opt, :string)}),
             eos)
  end

  defp consume(tail, %{nargs: :nonempty_list} = opt, eos) do
    {consumed, remains} = split_to_option(tail, - 1, eos,
                                            [])
    consumed === [] and throw({r_eos(eos, :commands), opt, tail,
                                 "expected argument"})
    action(remains, consumed,
             Map.put(opt, :type,
                            {:list, :maps.get(:type, opt, :string)}),
             eos)
  end

  defp consume(tail, %{nargs: :list} = opt, eos) do
    {consumed, remains} = split_to_option(tail, - 1, eos,
                                            [])
    action(remains, consumed,
             Map.put(opt, :type,
                            {:list, :maps.get(:type, opt, :string)}),
             eos)
  end

  defp consume(['true' | tail], %{type: :boolean} = opt, eos) do
    action(tail, true, Map.put(opt, :type, :raw), eos)
  end

  defp consume(['false' | tail], %{type: :boolean} = opt, eos) do
    action(tail, false, Map.put(opt, :type, :raw), eos)
  end

  defp consume(tail, %{type: :boolean} = opt, eos) do
    action(tail, :undefined, opt, eos)
  end

  defp consume(tail, %{nargs: :maybe} = opt, eos) do
    case (split_to_option(tail, 1, eos, [])) do
      {[], _} ->
        action(tail, default(opt), Map.put(opt, :type, :raw),
                 eos)
      {[consumed], remains} ->
        action(remains, consumed, opt, eos)
    end
  end

  defp consume(tail, %{nargs: {:maybe, const}} = opt, eos) do
    case (split_to_option(tail, 1, eos, [])) do
      {[], _} ->
        action(tail, const, opt, eos)
      {[consumed], remains} ->
        action(remains, consumed, opt, eos)
    end
  end

  defp consume(tail, %{action: :count} = opt, eos) do
    action(tail, :undefined, opt, eos)
  end

  defp consume(tail, %{action: {act, _Const}} = opt, eos)
      when act === :store or act === :append do
    action(tail, :undefined, opt, eos)
  end

  defp consume([[prefix | _] = argValue | tail], opt, eos)
      when (:erlang.is_map_key(:short,
                                 opt) or :erlang.is_map_key(:long, opt) and
              :erlang.is_map_key(prefix, r_eos(eos, :prefixes))) do
    case (r_eos(eos, :no_digits) and is_digits(argValue)) do
      true ->
        action(tail, argValue, opt, eos)
      false ->
        throw({r_eos(eos, :commands), opt, :undefined, "expected argument"})
    end
  end

  defp consume([argValue | tail], opt, eos) do
    action(tail, argValue, opt, eos)
  end

  defp consume([], opt, eos) do
    throw({r_eos(eos, :commands), opt, :undefined, "expected argument"})
  end

  defp split_to_option([], _, _Eos, acc) do
    {:lists.reverse(acc), []}
  end

  defp split_to_option(tail, 0, _Eos, acc) do
    {:lists.reverse(acc), tail}
  end

  defp split_to_option([[prefix | _] = maybeNumber | tail] = all, left,
            r_eos(no_digits: true, prefixes: prefixes) = eos, acc)
      when :erlang.is_map_key(prefix, prefixes) do
    case (is_digits(maybeNumber)) do
      true ->
        split_to_option(tail, left - 1, eos,
                          [maybeNumber | acc])
      false ->
        {:lists.reverse(acc), all}
    end
  end

  defp split_to_option([[prefix | _] | _] = all, _Left,
            r_eos(no_digits: false, prefixes: prefixes), acc)
      when :erlang.is_map_key(prefix, prefixes) do
    {:lists.reverse(acc), all}
  end

  defp split_to_option([head | tail], left, opts, acc) do
    split_to_option(tail, left - 1, opts, [head | acc])
  end

  defp action(tail, argValue,
            %{name: argName, action: :store} = opt,
            r_eos(argmap: argMap) = eos) do
    value = convert_type(:maps.get(:type, opt, :string),
                           argValue, opt, eos)
    continue_parser(tail, opt,
                      r_eos(eos, argmap: Map.put(argMap, argName, value)))
  end

  defp action(tail, :undefined,
            %{name: argName, action: {:store, value}} = opt,
            r_eos(argmap: argMap) = eos) do
    continue_parser(tail, opt,
                      r_eos(eos, argmap: Map.put(argMap, argName, value)))
  end

  defp action(tail, argValue,
            %{name: argName, action: :append} = opt,
            r_eos(argmap: argMap) = eos) do
    value = convert_type(:maps.get(:type, opt, :string),
                           argValue, opt, eos)
    continue_parser(tail, opt,
                      r_eos(eos, argmap: Map.put(argMap, argName,
                                                       :maps.get(argName,
                                                                   argMap,
                                                                   []) ++ [value])))
  end

  defp action(tail, :undefined,
            %{name: argName, action: {:append, value}} = opt,
            r_eos(argmap: argMap) = eos) do
    continue_parser(tail, opt,
                      r_eos(eos, argmap: Map.put(argMap, argName,
                                                       :maps.get(argName,
                                                                   argMap,
                                                                   []) ++ [value])))
  end

  defp action(tail, argValue,
            %{name: argName, action: :extend} = opt,
            r_eos(argmap: argMap) = eos) do
    value = convert_type(:maps.get(:type, opt, :string),
                           argValue, opt, eos)
    extended = :maps.get(argName, argMap, []) ++ value
    continue_parser(tail, opt,
                      r_eos(eos, argmap: Map.put(argMap, argName, extended)))
  end

  defp action(tail, _, %{name: argName, action: :count} = opt,
            r_eos(argmap: argMap) = eos) do
    continue_parser(tail, opt,
                      r_eos(eos, argmap: Map.put(argMap, argName,
                                                       :maps.get(argName,
                                                                   argMap,
                                                                   0) + 1)))
  end

  defp action(tail, argValue, %{name: argName} = opt,
            r_eos(argmap: argMap) = eos) do
    value = convert_type(:maps.get(:type, opt, :string),
                           argValue, opt, eos)
    continue_parser(tail, opt,
                      r_eos(eos, argmap: Map.put(argMap, argName, value)))
  end

  defp continue_parser(tail, opt, eos) when :erlang.is_map_key(:short,
                                                    opt) or :erlang.is_map_key(:long,
                                                                                 opt) do
    parse_impl(tail, eos)
  end

  defp continue_parser(tail, %{nargs: list}, eos)
      when list === :list or list === :nonempty_list do
    parse_impl(tail, eos)
  end

  defp continue_parser(tail, _Opt, eos) do
    parse_impl(tail, r_eos(eos, pos: tl(r_eos(eos, :pos))))
  end

  defp convert_type({:list, type}, arg, opt, eos) do
    for var <- arg do
      convert_type(type, var, opt, eos)
    end
  end

  defp convert_type(:raw, arg, _Opt, _Eos) do
    arg
  end

  defp convert_type(:string, arg, _Opt, _Eos) do
    arg
  end

  defp convert_type({:string, choices}, arg, opt, eos)
      when (is_list(choices) and is_list(hd(choices))) do
    :lists.member(arg, choices) or throw({r_eos(eos, :commands),
                                            opt, arg, "is not one of the choices"})
    arg
  end

  defp convert_type({:string, re}, arg, opt, eos) do
    case (:re.run(arg, re)) do
      {:match, _X} ->
        arg
      _ ->
        throw({r_eos(eos, :commands), opt, arg, "does not match"})
    end
  end

  defp convert_type({:string, re, reOpt}, arg, opt, eos) do
    case (:re.run(arg, re, reOpt)) do
      :match ->
        arg
      {:match, _} ->
        arg
      _ ->
        throw({r_eos(eos, :commands), opt, arg, "does not match"})
    end
  end

  defp convert_type(:integer, arg, opt, eos) do
    get_int(arg, opt, eos)
  end

  defp convert_type({:integer, opts}, arg, opt, eos) do
    minimax(get_int(arg, opt, eos), opts, eos, opt, arg)
  end

  defp convert_type(:boolean, 'true', _Opt, _Eos) do
    true
  end

  defp convert_type(:boolean, :undefined, _Opt, _Eos) do
    true
  end

  defp convert_type(:boolean, 'false', _Opt, _Eos) do
    false
  end

  defp convert_type(:boolean, arg, opt, eos) do
    throw({r_eos(eos, :commands), opt, arg, "is not a boolean"})
  end

  defp convert_type(:binary, arg, _Opt, _Eos) do
    :unicode.characters_to_binary(arg)
  end

  defp convert_type({:binary, choices}, arg, opt, eos)
      when (is_list(choices) and is_binary(hd(choices))) do
    conv = :unicode.characters_to_binary(arg)
    :lists.member(conv,
                    choices) or throw({r_eos(eos, :commands), opt, arg, "is not one of the choices"})
    conv
  end

  defp convert_type({:binary, re}, arg, opt, eos) do
    case (:re.run(arg, re)) do
      {:match, _X} ->
        :unicode.characters_to_binary(arg)
      _ ->
        throw({r_eos(eos, :commands), opt, arg, "does not match"})
    end
  end

  defp convert_type({:binary, re, reOpt}, arg, opt, eos) do
    case (:re.run(arg, re, reOpt)) do
      :match ->
        :unicode.characters_to_binary(arg)
      {:match, _} ->
        :unicode.characters_to_binary(arg)
      _ ->
        throw({r_eos(eos, :commands), opt, arg, "does not match"})
    end
  end

  defp convert_type(:float, arg, opt, eos) do
    get_float(arg, opt, eos)
  end

  defp convert_type({:float, opts}, arg, opt, eos) do
    minimax(get_float(arg, opt, eos), opts, eos, opt, arg)
  end

  defp convert_type(:atom, arg, opt, eos) do
    try do
      :erlang.list_to_existing_atom(arg)
    catch
      :error, :badarg ->
        throw({r_eos(eos, :commands), opt, arg, "is not an existing atom"})
    end
  end

  defp convert_type({:atom, :unsafe}, arg, _Opt, _Eos) do
    :erlang.list_to_atom(arg)
  end

  defp convert_type({:atom, choices}, arg, opt, eos) do
    try do
      atom = :erlang.list_to_existing_atom(arg)
      :lists.member(atom,
                      choices) or throw({r_eos(eos, :commands), opt, arg, "is not one of the choices"})
      atom
    catch
      :error, :badarg ->
        throw({r_eos(eos, :commands), opt, arg, "is not an existing atom"})
    end
  end

  defp convert_type({:custom, fun}, arg, opt, eos) do
    try do
      fun.(arg)
    catch
      :error, :badarg ->
        throw({r_eos(eos, :commands), opt, arg, "failed validation"})
    end
  end

  defp minimax(var, [], _Eos, _Opt, _Orig) do
    var
  end

  defp minimax(var, [{:min, min} | _], eos, opt, orig)
      when var < min do
    throw({r_eos(eos, :commands), opt, orig, "is less than accepted minimum"})
  end

  defp minimax(var, [{:max, max} | _], eos, opt, orig)
      when var > max do
    throw({r_eos(eos, :commands), opt, orig, "is greater than accepted maximum"})
  end

  defp minimax(var, [num | tail], eos, opt, orig)
      when is_number(num) do
    :lists.member(var,
                    [num | tail]) or throw({r_eos(eos, :commands), opt, orig,
                                              "is not one of the choices"})
    var
  end

  defp minimax(var, [_ | tail], eos, opt, orig) do
    minimax(var, tail, eos, opt, orig)
  end

  defp get_int(arg, opt, eos) do
    case (:string.to_integer(arg)) do
      {int, []} ->
        int
      _ ->
        throw({r_eos(eos, :commands), opt, arg, "is not an integer"})
    end
  end

  defp get_float(arg, opt, eos) do
    case (:string.to_float(arg)) do
      {float, []} ->
        float
      _ ->
        case (:string.to_integer(arg)) do
          {int, []} ->
            int
          _ ->
            throw({r_eos(eos, :commands), opt, arg, "is not a number"})
        end
    end
  end

  defp is_digits(string) do
    case (:string.to_integer(string)) do
      {_Int, []} ->
        true
      {_, _} ->
        case (:string.to_float(string)) do
          {_Float, []} ->
            true
          {_, _} ->
            false
        end
    end
  end

  defp default(%{default: default}) do
    default
  end

  defp default(%{type: :boolean}) do
    true
  end

  defp default(%{type: :integer}) do
    0
  end

  defp default(%{type: :float}) do
    0.0
  end

  defp default(%{type: :string}) do
    ''
  end

  defp default(%{type: :binary}) do
    ""
  end

  defp default(%{type: :atom}) do
    :undefined
  end

  defp default(_) do
    :undefined
  end

  defp format_path(commands) do
    :lists.join(' ', commands)
  end

  defp executable(%{progname: prog}) when is_atom(prog) do
    :erlang.atom_to_list(prog)
  end

  defp executable(%{progname: prog}) when is_binary(prog) do
    :erlang.binary_to_list(prog)
  end

  defp executable(%{progname: prog}) do
    prog
  end

  defp executable(_) do
    {:ok, [[prog]]} = :init.get_argument(:progname)
    prog
  end

  defp validate_command([{name, cmd} | _] = path, prefixes) do
    is_list(name) and not
                      :erlang.is_map_key(hd(name),
                                           prefixes) or :erlang.error({:argparse,
                                                                         :command,
                                                                         clean_path(tl(path)),
                                                                         :commands,
                                                                         "command name must be a string not starting with option prefix"},
                                                                        [cmd],
                                                                        [{:error_info,
                                                                            %{cause:
                                                                              %{}}}])
    is_map(cmd) or :erlang.error({:argparse, :command,
                                    clean_path(path), :commands, "expected command()"},
                                   [cmd], [{:error_info, %{cause: %{}}}])
    is_valid_command_help(:maps.get(:help, cmd,
                                      [])) or :erlang.error({:argparse,
                                                               :command,
                                                               clean_path(path),
                                                               :help, "must be a printable unicode list, or a command help template"},
                                                              [cmd],
                                                              [{:error_info,
                                                                  %{cause:
                                                                    %{}}}])
    is_map(:maps.get(:commands, cmd,
                       %{})) or :erlang.error({:argparse, :command,
                                                 clean_path(path), :commands,
                                                 "expected map of \#{string() => command()}"},
                                                [cmd],
                                                [{:error_info, %{cause: %{}}}])
    case (:maps.get(:handler, cmd, :optional)) do
      :optional ->
        :ok
      {mod, modFun} when (is_atom(mod) and is_atom(modFun)) ->
        :ok
      {mod, modFun, _} when (is_atom(mod) and is_atom(modFun))
                            ->
        :ok
      {fun, _} when is_function(fun) ->
        :ok
      fun when is_function(fun, 1) ->
        :ok
      _ ->
        :erlang.error({:argparse, :command, clean_path(path),
                         :handler, "handler must be a valid callback, or an atom 'optional'"},
                        [cmd], [{:error_info, %{cause: %{}}}])
    end
    cmd1 = (case (:maps.find(:arguments, cmd)) do
              :error ->
                cmd
              {:ok, opts} when not is_list(opts) ->
                :erlang.error({:argparse, :command, clean_path(path),
                                 :arguments, "expected a list, [argument()]"},
                                [cmd], [{:error_info, %{cause: %{}}}])
              {:ok, opts} ->
                Map.put(cmd, :arguments,
                               for opt <- opts do
                                 validate_option(path, opt)
                               end)
            end)
    :lists.foldl(fn {_, %{arguments: opts}}, acc ->
                      :lists.foldl(fn %{short: short, name: oName} = arg,
                                        {allS, allL} ->
                                        :erlang.is_map_key(short,
                                                             allS) and :erlang.error({:argparse,
                                                                                        :argument,
                                                                                        clean_path(path),
                                                                                        :short,
                                                                                        'short conflicting with previously defined short for ' ++ :erlang.atom_to_list(:maps.get(short,
                                                                                                                              allS))},
                                                                                       [arg],
                                                                                       [{:error_info,
                                                                                           %{cause:
                                                                                             %{}}}])
                                        {Map.put(allS, short, oName), allL}
                                      %{long: long, name: oName} = arg,
                                        {allS, allL} ->
                                        :erlang.is_map_key(long,
                                                             allL) and :erlang.error({:argparse,
                                                                                        :argument,
                                                                                        clean_path(path),
                                                                                        :long,
                                                                                        'long conflicting with previously defined long for ' ++ :erlang.atom_to_list(:maps.get(long,
                                                                                                                              allL))},
                                                                                       [arg],
                                                                                       [{:error_info,
                                                                                           %{cause:
                                                                                             %{}}}])
                                        {allS, Map.put(allL, long, oName)}
                                      _, accIn ->
                                        accIn
                                   end,
                                     acc, opts)
                    _, acc ->
                      acc
                 end,
                   {%{}, %{}}, path)
    case (:maps.find(:commands, cmd1)) do
      :error ->
        {name, cmd1}
      {:ok, sub} ->
        {name,
           Map.put(cmd1, :commands,
                           :maps.map(fn k, v ->
                                          {^k, updated} = validate_command([{k,
                                                                               v} |
                                                                                path],
                                                                             prefixes)
                                          updated
                                     end,
                                       sub))}
    end
  end

  defp validate_option(path, %{name: name} = arg) when is_atom(name) or
                                            is_list(name) or is_binary(name) do
    is_valid_option_help(:maps.get(:help, arg,
                                     [])) or :erlang.error({:argparse,
                                                              :argument,
                                                              clean_path(path),
                                                              :help, "must be a string or valid help template"},
                                                             [arg],
                                                             [{:error_info,
                                                                 %{cause:
                                                                   %{}}}])
    :io_lib.printable_unicode_list(:maps.get(:long, arg,
                                               [])) or :erlang.error({:argparse,
                                                                        :argument,
                                                                        clean_path(path),
                                                                        :long,
                                                                        "must be a printable string"},
                                                                       [arg],
                                                                       [{:error_info,
                                                                           %{cause:
                                                                             %{}}}])
    is_boolean(:maps.get(:required, arg,
                           true)) or :erlang.error({:argparse, :argument,
                                                      clean_path(path),
                                                      :required, "must be a boolean"},
                                                     [arg],
                                                     [{:error_info,
                                                         %{cause: %{}}}])
    :io_lib.printable_unicode_list([:maps.get(:short, arg,
                                                ?a)]) or :erlang.error({:argparse,
                                                                          :argument,
                                                                          clean_path(path),
                                                                          :short,
                                                                          "must be a printable character"},
                                                                         [arg],
                                                                         [{:error_info,
                                                                             %{cause:
                                                                               %{}}}])
    opt1 = maybe_validate(:action, arg, &validate_action/3,
                            path)
    opt2 = maybe_validate(:type, opt1, &validate_type/3,
                            path)
    maybe_validate(:nargs, opt2, &validate_args/3, path)
  end

  defp validate_option(path, arg) do
    :erlang.error({:argparse, :argument, clean_path(path),
                     :name, "argument must be a map containing 'name' field"},
                    [arg], [{:error_info, %{cause: %{}}}])
  end

  defp maybe_validate(key, map, fun, path)
      when :erlang.is_map_key(key, map) do
    :maps.put(key, fun.(:maps.get(key, map), path, map),
                map)
  end

  defp maybe_validate(_Key, map, _Fun, _Path) do
    map
  end

  defp validate_action(:store, _Path, _Opt) do
    :store
  end

  defp validate_action({:store, term}, _Path, _Opt) do
    {:store, term}
  end

  defp validate_action(:append, _Path, _Opt) do
    :append
  end

  defp validate_action({:append, term}, _Path, _Opt) do
    {:append, term}
  end

  defp validate_action(:count, _Path, _Opt) do
    :count
  end

  defp validate_action(:extend, _Path, %{nargs: nargs})
      when nargs === :list or nargs === :nonempty_list or
             nargs === :all or is_integer(nargs) do
    :extend
  end

  defp validate_action(:extend, _Path, %{type: {:custom, _}}) do
    :extend
  end

  defp validate_action(:extend, path, arg) do
    :erlang.error({:argparse, :argument, clean_path(path),
                     :action, "extend action works only with lists"},
                    [arg], [{:error_info, %{cause: %{}}}])
  end

  defp validate_action(_Action, path, arg) do
    :erlang.error({:argparse, :argument, clean_path(path),
                     :action, "unsupported"},
                    [arg], [{:error_info, %{cause: %{}}}])
  end

  defp validate_type(simple, _Path, _Opt) when simple === :boolean or
                                      simple === :integer or
                                      simple === :float or simple === :string or
                                      simple === :binary or simple === :atom or
                                      simple === {:atom, :unsafe} do
    simple
  end

  defp validate_type({:custom, fun}, _Path, _Opt)
      when is_function(fun, 1) do
    {:custom, fun}
  end

  defp validate_type({:float, opts}, path, arg) do
    for {kind, val} <- opts,
          kind !== :min and kind !== :max or not is_float(val) do
      :erlang.error({:argparse, :argument, clean_path(path),
                       :type, "invalid validator"},
                      [arg], [{:error_info, %{cause: %{}}}])
    end
    {:float, opts}
  end

  defp validate_type({:integer, opts}, path, arg) do
    for {kind, val} <- opts,
          kind !== :min and kind !== :max or not
                                             is_integer(val) do
      :erlang.error({:argparse, :argument, clean_path(path),
                       :type, "invalid validator"},
                      [arg], [{:error_info, %{cause: %{}}}])
    end
    {:integer, opts}
  end

  defp validate_type({:atom, choices} = valid, path, arg)
      when is_list(choices) do
    for c <- choices, not is_atom(c) do
      :erlang.error({:argparse, :argument, clean_path(path),
                       :type, "unsupported"},
                      [arg], [{:error_info, %{cause: %{}}}])
    end
    valid
  end

  defp validate_type({:string, re} = valid, _Path, _Opt)
      when is_list(re) do
    valid
  end

  defp validate_type({:string, re, l} = valid, _Path, _Opt)
      when (is_list(re) and is_list(l)) do
    valid
  end

  defp validate_type({:binary, re} = valid, _Path, _Opt)
      when is_binary(re) do
    valid
  end

  defp validate_type({:binary, choices} = valid, _Path, _Opt)
      when (is_list(choices) and is_binary(hd(choices))) do
    valid
  end

  defp validate_type({:binary, re, l} = valid, _Path, _Opt)
      when (is_binary(re) and is_list(l)) do
    valid
  end

  defp validate_type(_Type, path, arg) do
    :erlang.error({:argparse, :argument, clean_path(path),
                     :type, "unsupported"},
                    [arg], [{:error_info, %{cause: %{}}}])
  end

  defp validate_args(n, _Path, _Opt) when (is_integer(n) and
                                  n >= 1) do
    n
  end

  defp validate_args(simple, _Path, _Opt) when simple === :all or
                                      simple === :list or simple === :maybe or
                                      simple === :nonempty_list do
    simple
  end

  defp validate_args({:maybe, term}, _Path, _Opt) do
    {:maybe, term}
  end

  defp validate_args(_Nargs, path, arg) do
    :erlang.error({:argparse, :argument, clean_path(path),
                     :nargs, "unsupported"},
                    [arg], [{:error_info, %{cause: %{}}}])
  end

  defp clean_path(path) do
    {cmds, _} = :lists.unzip(path)
    :lists.reverse(cmds)
  end

  defp is_valid_option_help(:hidden) do
    true
  end

  defp is_valid_option_help(help) when is_list(help) or is_binary(help) do
    true
  end

  defp is_valid_option_help({short, desc})
      when (is_list(short) or is_binary(short) and
              is_list(desc)) do
    :lists.all(fn :type ->
                    true
                  :default ->
                    true
                  s when is_list(s) or is_binary(s) ->
                    true
                  _ ->
                    false
               end,
                 desc)
  end

  defp is_valid_option_help({short, desc})
      when (is_list(short) or is_binary(short) and
              is_function(desc, 0)) do
    true
  end

  defp is_valid_option_help(_) do
    false
  end

  defp is_valid_command_help(:hidden) do
    true
  end

  defp is_valid_command_help(help) when is_binary(help) do
    true
  end

  defp is_valid_command_help(help) when is_list(help) do
    case (:io_lib.printable_unicode_list(help)) do
      true ->
        true
      false ->
        :lists.all(fn atom when atom === :usage or
                                  atom === :commands or atom === :arguments or
                                  atom === :options
                                ->
                        true
                      bin when is_binary(bin) ->
                        true
                      str ->
                        :io_lib.printable_unicode_list(str)
                   end,
                     help)
    end
  end

  defp is_valid_command_help(_) do
    false
  end

  defp format_help({progName, root}, format) do
    prefix = hd(:maps.get(:prefixes, format, [?-]))
    nested = :maps.get(:command, format, [])
    {_CmdName, cmd, allArgs} = collect_options(progName,
                                                 root, nested, [])
    {_, longest, flags, opts, args, optL,
       posL} = :lists.foldl(&format_opt_help/2,
                              {prefix, 0, '', [], [], [], []}, allArgs)
    immediate = :maps.get(:commands, cmd, %{})
    {long, subs} = :maps.fold(fn _Name, %{help: :hidden},
                                   {long, subAcc} ->
                                   {long, subAcc}
                                 name, sub, {long, subAcc} ->
                                   help = :maps.get(:help, sub, '')
                                   {max(long, :string.length(name)),
                                      [{name, help} | subAcc]}
                              end,
                                {longest, []},
                                :maps.iterator(immediate, :ordered))
    shortCmd0 = (case (map_size(immediate)) do
                   0 ->
                     []
                   small when small < 4 ->
                     keys = :lists.sort(:maps.keys(immediate))
                     ['{' ++ :lists.append(:lists.join('|', keys)) ++ '}']
                   _Largs ->
                     ['<command>']
                 end)
    shortCmd = (cond do
                  nested === [] ->
                    shortCmd0
                  true ->
                    [:lists.append(:lists.join(' ', nested)) | shortCmd0]
                end)
    flagsForm = (cond do
                   flags === [] ->
                     []
                   true ->
                     [:unicode.characters_to_list(:io_lib.format('[~tc~ts]',
                                                                   [prefix,
                                                                        flags]))]
                 end)
    usage = [progName, shortCmd, flagsForm, opts, args]
    template0 = :maps.get(:help, root, '')
    template = (case (template0 === '' or :io_lib.printable_unicode_list(template0)) do
                  true ->
                    nL = [:io_lib.nl()]
                    template1 = ['Usage:' ++ nL, :usage, nL]
                    template2 = maybe_add('~n', template0, template0 ++ nL,
                                            template1)
                    template3 = maybe_add('~nSubcommands:~n', subs, :commands, template2)
                    template4 = maybe_add('~nArguments:~n', posL, :arguments, template3)
                    maybe_add('~nOptional arguments:~n', optL, :options, template4)
                  false ->
                    template0
                end)
    parts = %{usage: usage, commands: {long, subs},
                arguments: {longest, posL}, options: {longest, optL}}
    width = :maps.get(:columns, format, 80)
    :lists.append(for part <- template do
                    format_width(:maps.find(part, parts), part, width)
                  end)
  end

  defp collect_options(cmdName, command, [], args) do
    {cmdName, command,
       args ++ :maps.get(:arguments, command, [])}
  end

  defp collect_options(cmdName, command, [cmd | tail], args) do
    sub = :maps.get(:commands, command)
    subCmd = :maps.get(cmd, sub)
    collect_options(cmdName ++ ' ' ++ cmd, subCmd, tail,
                      args ++ :maps.get(:arguments, command, []))
  end

  defp maybe_add(_ToAdd, [], _Element, template) do
    template
  end

  defp maybe_add(toAdd, _List, element, template) do
    template ++ [:io_lib.format(toAdd, []), element]
  end

  defp format_width(:error, part, width) do
    wrap_text(part, 0, width)
  end

  defp format_width({:ok,
             [progName, shortCmd, flagsForm, opts, args]},
            :usage, width) do
    words = shortCmd ++ flagsForm ++ opts ++ args
    cond do
      words === [] ->
        :io_lib.format('  ~ts', [progName])
      true ->
        indent = :string.length(progName)
        wrapped = wordwrap(words, width - indent, 0, [], [])
        pad = :lists.append(:lists.duplicate(indent + 3, ' '))
        argLines = :lists.join([:io_lib.nl() | pad], wrapped)
        :io_lib.format('  ~ts~ts', [progName, argLines])
    end
  end

  defp format_width({:ok, {len, texts}}, _Part, width) do
    subFormat = :io_lib.format('  ~~-~bts ~~ts~n', [len])
    for {n, d} <- :lists.reverse(texts) do
      :io_lib.format(subFormat,
                       [n, wrap_text(d, len + 3, width)])
    end
  end

  defp wrap_text(text, indent, width) do
    nL = :io_lib.nl()
    lines = :string.split(text, nL, :all)
    paragraphs = :lists.append(for l <- lines do
                                 wrap_line(l, width, indent)
                               end)
    pad = :lists.append(:lists.duplicate(indent, ' '))
    :lists.join([nL | pad], paragraphs)
  end

  defp wrap_line([], _Width, _Indent) do
    [[]]
  end

  defp wrap_line(line, width, indent) do
    [first | tail] = :string.split(line, ' ', :all)
    wordwrap(tail, width - indent, :string.length(first),
               first, [])
  end

  defp wordwrap([], _Max, _Len, [], lines) do
    :lists.reverse(lines)
  end

  defp wordwrap([], _Max, _Len, line, lines) do
    :lists.reverse([line | lines])
  end

  defp wordwrap([word | tail], max, len, line, lines) do
    wordLen = :string.length(word)
    case (len + 1 + wordLen > max) do
      true ->
        wordwrap(tail, max, wordLen, word, [line | lines])
      false ->
        wordwrap(tail, max, wordLen + 1 + len, [line, " ", word],
                   lines)
    end
  end

  defp format_opt_help(%{help: :hidden}, acc) do
    acc
  end

  defp format_opt_help(opt,
            {prefix, longest, flags, opts, args, optL, posL})
      when :erlang.is_map_key(:short,
                                opt) or :erlang.is_map_key(:long, opt) do
    desc = format_description(opt)
    requiresArg = requires_argument(opt)
    nonOption = :maps.get(:required, opt, false) === true
    {name0, maybeOpt0} = (case (:maps.find(:long, opt)) do
                            :error ->
                              {'', []}
                            {:ok, long} when (nonOption and requiresArg) ->
                              fN = [prefix | long]
                              {fN, [format_required(true, [fN, ' '], opt)]}
                            {:ok, long} when requiresArg ->
                              fN = [prefix | long]
                              {fN, [format_required(false, [fN, ' '], opt)]}
                            {:ok, long} when nonOption ->
                              fN = [prefix | long]
                              {fN, [fN]}
                            {:ok, long} ->
                              fN = [prefix | long]
                              {fN, [:io_lib.format('[~ts]', [fN])]}
                          end)
    {name, maybeFlag, maybeOpt1} = (case (:maps.find(:short,
                                                       opt)) do
                                      :error ->
                                        {name0, [], maybeOpt0}
                                      {:ok, short} when requiresArg ->
                                        sN = [prefix, short]
                                        {maybe_concat(sN, name0), [],
                                           [format_required(nonOption, [sN, ' '],
                                                              opt) |
                                                maybeOpt0]}
                                      {:ok, short} ->
                                        {maybe_concat([prefix, short], name0),
                                           [short], maybeOpt0}
                                    end)
    maybeOpt2 = (case (:maps.find(:help, opt)) do
                   {:ok, {str, _}} ->
                     [str]
                   _ ->
                     maybeOpt1
                 end)
    nameLen = :string.length(name)
    capped = min(24, nameLen)
    {prefix, max(capped, longest), flags ++ maybeFlag,
       opts ++ maybeOpt2, args, [{name, desc} | optL], posL}
  end

  defp format_opt_help(%{name: name} = opt,
            {prefix, longest, flags, opts, args, optL, posL}) do
    desc = format_description(opt)
    lName = :io_lib.format('~ts', [name])
    lPos = (case (:maps.find(:help, opt)) do
              {:ok, {str, _}} ->
                str
              _ ->
                format_required(:maps.get(:required, opt, true), '', opt)
            end)
    {prefix, max(longest, :string.length(lName)), flags,
       opts, args ++ [lPos], optL, [{lName, desc} | posL]}
  end

  defp format_description(%{help: {_Short, fun}}) when is_function(fun,
                                                     0) do
    fun.()
  end

  defp format_description(%{help: {_Short, desc}} = opt) do
    :lists.map(fn :type ->
                    format_type(opt)
                  :default ->
                    format_default(opt)
                  string ->
                    string
               end,
                 desc)
  end

  defp format_description(%{name: name} = opt) do
    nameStr = :maps.get(:help, opt,
                          :io_lib.format('~ts', [name]))
    case ({nameStr, format_type(opt),
             format_default(opt)}) do
      {'', '', type} ->
        type
      {'', default, ''} ->
        default
      {desc, '', ''} ->
        desc
      {desc, '', default} ->
        [desc, ' , default: ', default]
      {desc, type, ''} ->
        [desc, ' (', type, ')']
      {'', type, default} ->
        [type, ', default: ', default]
      {desc, type, default} ->
        [desc, ' (', type, '), default: ', default]
    end
  end

  defp maybe_concat(no, []) do
    no
  end

  defp maybe_concat(no, l) do
    [no, ', ', l]
  end

  defp format_required(true, extra, %{name: name} = opt) do
    :io_lib.format('~ts<~ts>~ts', [extra, name, format_nargs(opt)])
  end

  defp format_required(false, extra, %{name: name} = opt) do
    :io_lib.format('[~ts<~ts>~ts]', [extra, name, format_nargs(opt)])
  end

  defp format_nargs(%{nargs: dots}) when dots === :list or
                                 dots === :all or dots === :nonempty_list do
    '...'
  end

  defp format_nargs(_) do
    ''
  end

  defp format_type(%{type: {:integer, choices}})
      when (is_list(choices) and is_integer(hd(choices))) do
    :io_lib.format('choice: ~s',
                     [:lists.join(', ',
                                    for c <- choices do
                                      :erlang.integer_to_list(c)
                                    end)])
  end

  defp format_type(%{type: {:float, choices}})
      when (is_list(choices) and is_number(hd(choices))) do
    :io_lib.format('choice: ~s',
                     [:lists.join(', ',
                                    for c <- choices do
                                      :io_lib.format('~g', [c])
                                    end)])
  end

  defp format_type(%{type: {num, valid}}) when num === :integer or
                                        num === :float do
    case ({:proplists.get_value(:min, valid),
             :proplists.get_value(:max, valid)}) do
      {:undefined, :undefined} ->
        :io_lib.format('~s', [format_type(%{type: num})])
      {min, :undefined} ->
        :io_lib.format('~s >= ~tp', [format_type(%{type: num}), min])
      {:undefined, max} ->
        :io_lib.format('~s <= ~tp', [format_type(%{type: num}), max])
      {min, max} ->
        :io_lib.format('~tp <= ~s <= ~tp', [min, format_type(%{type: num}), max])
    end
  end

  defp format_type(%{type: {:string, re, _}}) when (is_list(re) and
                                             not is_list(hd(re))) do
    :io_lib.format('string re: ~ts', [re])
  end

  defp format_type(%{type: {:string, re}}) when (is_list(re) and
                                          not is_list(hd(re))) do
    :io_lib.format('string re: ~ts', [re])
  end

  defp format_type(%{type: {:binary, re}}) when is_binary(re) do
    :io_lib.format('binary re: ~ts', [re])
  end

  defp format_type(%{type: {:binary, re, _}}) when is_binary(re) do
    :io_lib.format('binary re: ~ts', [re])
  end

  defp format_type(%{type: {strBin, choices}})
      when (strBin === :string or strBin === :binary and
              is_list(choices)) do
    :io_lib.format('choice: ~ts', [:lists.join(', ', choices)])
  end

  defp format_type(%{type: :atom}) do
    'existing atom'
  end

  defp format_type(%{type: {:atom, :unsafe}}) do
    'atom'
  end

  defp format_type(%{type: {:atom, choices}}) do
    :io_lib.format('choice: ~ts',
                     [:lists.join(', ',
                                    for c <- choices do
                                      :erlang.atom_to_list(c)
                                    end)])
  end

  defp format_type(%{type: :boolean}) do
    ''
  end

  defp format_type(%{type: :integer}) do
    'int'
  end

  defp format_type(%{type: type}) when is_atom(type) do
    :io_lib.format('~ts', [type])
  end

  defp format_type(_Opt) do
    ''
  end

  defp format_default(%{default: def__}) when is_list(def__) or
                                    is_binary(def__) or is_atom(def__) do
    :io_lib.format('~ts', [def__])
  end

  defp format_default(%{default: def__}) do
    :io_lib.format('~tp', [def__])
  end

  defp format_default(_) do
    ''
  end

  defp handle(cmdMap, argMap, path,
            %{handler: {mod, modFun, default}}) do
    argList = arg_map_to_arg_list(cmdMap, path, argMap,
                                    default)
    :erlang.apply(mod, modFun, argList)
  end

  defp handle(_CmdMap, argMap, _Path,
            %{handler: {mod, modFun}})
      when (is_atom(mod) and is_atom(modFun)) do
    apply(mod, modFun, [argMap])
  end

  defp handle(cmdMap, argMap, path,
            %{handler: {fun, default}})
      when is_function(fun) do
    argList = arg_map_to_arg_list(cmdMap, path, argMap,
                                    default)
    :erlang.apply(fun, argList)
  end

  defp handle(_CmdMap, argMap, _Path, %{handler: handler})
      when is_function(handler, 1) do
    handler.(argMap)
  end

  defp arg_map_to_arg_list(command, path, argMap, default) do
    allArgs = collect_arguments(command, path, [])
    for %{name: arg} <- allArgs do
      :maps.get(arg, argMap, default)
    end
  end

  defp collect_arguments(command, [], acc) do
    acc ++ :maps.get(:arguments, command, [])
  end

  defp collect_arguments(command, [h | tail], acc) do
    args = :maps.get(:arguments, command, [])
    next = :maps.get(h, :maps.get(:commands, command, h))
    collect_arguments(next, tail, acc ++ args)
  end

end