defmodule :m_edlin_expand do
  use Bitwise
  require Record

  Record.defrecord(:r_docs_v1, :docs_v1,
    anno: :undefined,
    beam_language: :erlang,
    format: "application/erlang+html",
    module_doc: :undefined,
    metadata: %{otp_doc_vsn: {1, 0, 0}},
    docs: :undefined
  )

  Record.defrecord(:r_docs_v1_entry, :docs_v1_entry,
    kind_name_arity: :undefined,
    anno: :undefined,
    signature: :undefined,
    doc: :undefined,
    metadata: :undefined
  )

  Record.defrecord(:r_shell_state, :shell_state, bindings: [], records: [], functions: [])

  def expand(bef0) do
    expand(bef0, [{:legacy_output, true}])
  end

  def expand(bef0, opts) do
    shellState =
      try do
        :shell.get_state()
      catch
        _, _ ->
          r_shell_state(bindings: [], records: [], functions: [])
      end

    expand(bef0, opts, shellState)
  end

  def expand(bef0, opts, r_shell_state(bindings: bs, records: rT, functions: fT)) do
    legacyOutput = :proplists.get_value(:legacy_output, opts, false)
    {_Bef1, word} = over_word(bef0)

    {res, expansion, matches} =
      case :edlin_context.get_context(bef0) do
        {:string} ->
          expand_string(bef0)

        {:binding} ->
          expand_binding(word, bs)

        {:term} ->
          expand_module_function(bef0, fT)

        {:term, _, {_, unfinished}} ->
          expand_module_function(:lists.reverse(unfinished), fT)

        {:error, _Column} ->
          {:no, [], []}

        {:function} ->
          expand_module_function(bef0, fT)

        {:fun_} ->
          expand_module_function(bef0, fT)

        {:fun_, mod} ->
          expand_function_name(mod, word, ~c"/", fT)

        {:fun_, mod, fun} ->
          arities =
            for a <- get_arities(mod, fun) do
              :erlang.integer_to_list(a)
            end

          match(word, arities, ~c"")

        {:new_fun, _ArgsString} ->
          {:no, [], []}

        {:function, mod, fun, args, unfinished, nesting} ->
          mod2 =
            case mod do
              ~c"user_defined" ->
                ~c"shell_default"

              _ ->
                mod
            end

          funExpansion = expand_function_type(mod2, fun, args, unfinished, nesting, fT)

          case word do
            [] ->
              funExpansion

            _ ->
              moduleOrBifs = expand_helper(fT, :module, word, ~c":")

              functions =
                case args !== [] and :lists.last(args) do
                  {:atom, maybeMod} ->
                    expand_function_name(maybeMod, word, ~c"", fT)

                  _ ->
                    {:no, [], []}
                end

              fold_results([funExpansion] ++ moduleOrBifs ++ [functions])
          end

        {:map, binding, keys} ->
          expand_map(word, bs, binding, keys)

        {:map_or_record} ->
          {[?# | bef2], _} = over_word(bef0)
          {_, var} = over_word(bef2)

          case bs do
            [] ->
              expand_record(word, rT)

            _ ->
              case :proplists.get_value(
                     :erlang.list_to_atom(var),
                     bs
                   ) do
                :undefined ->
                  expand_record(word, rT)

                map when is_map(map) ->
                  {:yes, ~c"{", []}

                recordTuple
                when is_tuple(recordTuple) and
                       tuple_size(recordTuple) > 0 ->
                  atom = :erlang.element(1, recordTuple)

                  case is_atom(atom) and :lists.keysearch(atom, 1, rT) do
                    {:value, {^atom, _}} ->
                      match(word, [atom], ~c"{")

                    _ ->
                      {:no, [], []}
                  end

                _ ->
                  {:no, [], []}
              end
          end

        {:record} ->
          expand_record(word, rT)

        {:record, record, fields, fieldToComplete, args, unfinished, nestings} ->
          recordExpansion =
            expand_record_fields(
              fieldToComplete,
              unfinished,
              record,
              fields,
              rT,
              args,
              nestings,
              fT
            )

          case word do
            [] ->
              recordExpansion

            _ ->
              moduleOrBifs = expand_helper(fT, :module, word, ~c":")
              fold_results([recordExpansion] ++ moduleOrBifs)
          end

        _ ->
          {:no, [], []}
      end

    matches1 =
      case {res, number_matches(matches)} do
        {:yes, 1} ->
          []

        _ ->
          matches
      end

    case legacyOutput do
      true ->
        {res, expansion, to_legacy_format(matches1)}

      false ->
        {res, expansion, matches1}
    end
  end

  defp expand_map(_, [], _, _) do
    {:no, [], []}
  end

  defp expand_map(word, bs, binding, keys) do
    case :proplists.get_value(
           :erlang.list_to_atom(binding),
           bs
         ) do
      map when is_map(map) ->
        k1 = :sets.from_list(:maps.keys(map))

        k2 =
          :sets.subtract(
            k1,
            :sets.from_list(
              for k <- keys do
                :erlang.list_to_atom(k)
              end
            )
          )

        match(word, :sets.to_list(k2), ~c"=>")

      _ ->
        {:no, [], []}
    end
  end

  def over_word(bef) do
    {bef1, _, _} = over_white(bef, [], 0)
    {bef2, word, _} = :edlin.over_word(bef1, [], 0)
    {bef2, word}
  end

  defp expand_binding(prefix, bindings) do
    alts =
      for {k, _} <- bindings do
        strip_quotes(k)
      end

    case match(prefix, alts, ~c"") do
      {_Res, _Expansion, []} = m ->
        m

      {res, expansion, matches} ->
        {res, expansion, [%{title: ~c"bindings", elems: matches, options: [:highlight_all]}]}
    end
  end

  defp expand_record(prefix, rT) do
    alts =
      for {name, _} <- rT do
        name
      end

    case match(prefix, alts, ~c"{") do
      {_Res, _Expansion, []} = m ->
        m

      {res, expansion, matches} ->
        {res, expansion, [%{title: ~c"records", elems: matches, options: [:highlight_all]}]}
    end
  end

  defp expand_record_fields(fieldToComplete, word, record, fields, rT, _Args, nestings, fT) do
    record2 = :erlang.list_to_atom(record)

    fieldSet2 =
      :sets.from_list(
        for f <- fields do
          :erlang.list_to_atom(f)
        end
      )

    fieldToComplete2 = :erlang.list_to_atom(fieldToComplete)

    word1 =
      case word do
        {_, word2} ->
          word2

        [] ->
          []
      end

    case (for {record3, recordSpec} <- rT,
              record2 === record3 do
            recordSpec
          end) do
      [recordType | _] ->
        case :sets.is_element(fieldToComplete2, fieldSet2) do
          true ->
            expand_record_field_content(fieldToComplete2, recordType, word1, nestings, fT)

          false ->
            expand_record_field_name(record2, fieldSet2, recordType, word1)
        end

      _ ->
        {:no, [], []}
    end
  end

  defp expand_record_field_name(record, fields, recordType, word) do
    recordFieldsList =
      extract_record_fields(
        record,
        recordType
      )

    recordFieldsSet = :sets.from_list(recordFieldsList)
    recordFields = :sets.subtract(recordFieldsSet, fields)
    alts = :sets.to_list(recordFields)

    case match(word, alts, ~c"=") do
      {_Res, _Expansion, []} = m ->
        m

      {res, expansion, matches} ->
        {res, expansion, [%{title: ~c"fields", elems: matches, options: [:highlight_all]}]}
    end
  end

  defp expand_record_field_content(
         field,
         {:attribute, _, :record, {_Record, fieldTypes}},
         word,
         nestings,
         fT
       ) do
    fieldTypesFiltered =
      for {:typed_record_field, {:record_field, _, {_, _, f}}, type1} <- fieldTypes,
          f == field do
        type1
      end ++
        for {:typed_record_field, {:record_field, _, {_, _, f}, _}, type1} <- fieldTypes,
            f == field do
          type1
        end

    case fieldTypesFiltered do
      [] ->
        {:no, [], []}

      [type] ->
        t = :edlin_type_suggestion.type_tree(:erlang, type, nestings, fT)
        types = :edlin_type_suggestion.get_types([], t, nestings)

        case nestings do
          [] ->
            atoms = :edlin_type_suggestion.get_atoms([], t, nestings)

            case {word, match(word, atoms, ~c", ")} do
              {[], {_Res, _Expansion, _}} ->
                {_Res, _Expansion,
                 [%{title: ~c"types", elems: types, options: [{:hide, :title}]}]}

              {_, {_Res, _Expansion, []} = m} ->
                m

              {_, {res, expansion, matches}} ->
                {res, expansion,
                 [%{title: ~c"matches", elems: matches, options: [:highlight_all]}]}
            end

          _ ->
            expand_nesting_content(t, [], nestings, %{
              title: ~c"types",
              elems: types,
              options: [{:hide, :title}]
            })
        end
    end
  end

  defp match_arguments({:function, {{:parameters, ps}, _}, cs}, as) do
    match_arguments1(ps, cs, as)
  end

  defp match_arguments({{:parameters, ps}, _}, as) do
    match_arguments1(ps, [], as)
  end

  def match_arguments1(_, _, []) do
    true
  end

  def match_arguments1([_ | ps], cs, [{:parenthesis, _} | as]) do
    match_arguments1(ps, cs, as)
  end

  def match_arguments1([_ | ps], cs, [{:operation, _} | as]) do
    match_arguments1(ps, cs, as)
  end

  def match_arguments1([_ | ps], cs, [{:keyword, _} | as]) do
    match_arguments1(ps, cs, as)
  end

  def match_arguments1([_ | ps], cs, [{:var, _} | as]) do
    match_arguments1(ps, cs, as)
  end

  def match_arguments1([_ | ps], cs, [{:call, _} | as]) do
    match_arguments1(ps, cs, as)
  end

  def match_arguments1([_ | ps], cs, [{:fun_, _} | as]) do
    match_arguments1(ps, cs, as)
  end

  def match_arguments1([p | ps], cs, [{:atom, [?' | _] = string} | as]) do
    case :edlin_context.odd_quotes(
           ?',
           :lists.reverse(string)
         ) do
      true ->
        false

      _ ->
        case is_type(p, cs, string) do
          true ->
            match_arguments1(ps, cs, as)

          false ->
            false
        end
    end
  end

  def match_arguments1([p | ps], cs, [{_, string} | as]) do
    case is_type(p, cs, string) do
      true ->
        match_arguments1(ps, cs, as)

      false ->
        false
    end
  end

  def is_type(type, cs, string) do
    {:ok, a, _} = :erl_scan.string(string ++ ~c".")

    types =
      for t <- :edlin_type_suggestion.get_types(cs, type, [], [:no_print]) do
        t
      end

    try do
      {:ok, term} = :erl_parse.parse_term(a)

      case term do
        atom when is_atom(atom) ->
          atoms = :edlin_type_suggestion.get_atoms(cs, type, [])

          :lists.member(
            to_list(atom),
            atoms
          ) or
            :lists.member(
              :erlang.atom_to_list(atom),
              atoms
            ) or
            find_type(
              types,
              [:atom, :node, :module, :fun]
            )

        tuple when is_tuple(tuple) ->
          find_type(types, [:tuple])

        map when is_map(map) ->
          find_type(types, [:map])

        binary when is_binary(binary) ->
          find_type(types, [:binary])

        float when is_float(float) ->
          find_type(types, [:float])

        integer when is_integer(integer) ->
          check_integer_type(types, integer)

        list when is_list(list) and length(list) > 0 ->
          find_type(
            types,
            [:list, :string, :nonempty_list, :maybe_improper_list, :nonempty_improper_list]
          )

        list when is_list(list) ->
          find_type(types, [:list, :string, :maybe_improper_list])
      end
    catch
      _, _ ->
        b =
          for x <- a do
            (fn
               {:var, anno, _} ->
                 {:atom, anno, :var}

               token ->
                 token
             end).(x)
          end

        try do
          {:ok, term2} = :erl_parse.parse_term(b)

          case term2 do
            tuple2 when is_tuple(tuple2) ->
              find_type(types, [:tuple])

            map2 when is_map(map2) ->
              find_type(types, [:map])

            binary2 when is_binary(binary2) ->
              find_type(types, [:binary])

            list2 when is_list(list2) and length(list2) > 0 ->
              find_type(
                types,
                [:list, :string, :nonempty_list, :maybe_improper_list, :nonempty_improper_list]
              )

            list2 when is_list(list2) ->
              find_type(types, [:list, :string, :maybe_improper_list])
          end
        catch
          _, _ ->
            case a do
              [{:"#", _}, {:var, _, :Port}, {:<, _}, {:float, _, _}, {:>, _}, {:dot, _}] ->
                find_type(types, [:port])

              [
                {:"#", _},
                {:var, _, :Ref},
                {:<, _},
                {:float, _, _},
                {:., _},
                {:float, _, _},
                {:>, _},
                {:dot, _}
              ] ->
                find_type(types, [:reference])

              [{:fun, _}, {:"(", _} | _] ->
                find_type(types, [:parameters, :function, :fun])

              [
                {:"#", _},
                {:var, _, :Fun},
                {:<, _},
                {:atom, _, :erl_eval},
                {:., _},
                {:float, _, _},
                {:>, _}
              ] ->
                find_type(types, [:parameters, :function, :fun])

              [{:<, _}, {:float, _, _}, {:., _}, {:integer, _, _}, {:>, _}, {:dot, _}] ->
                find_type(types, [:pid])

              [{:"#", _}, {:atom, _, recordName}, {:"{", _} | _] ->
                find_type(types, [{:record, recordName}])

              _ ->
                false
            end
        end
    end
  end

  defp find_type([], _) do
    false
  end

  defp find_type([:any | _], _) do
    true
  end

  defp find_type([{:type, :any, []} | _], _) do
    true
  end

  defp find_type([{{:parameters, _}, _} | types], validTypes) do
    case :lists.member(:parameters, validTypes) do
      true ->
        true

      false ->
        find_type(types, validTypes)
    end
  end

  defp find_type([{:record, _} = type | types], validTypes) do
    case :lists.member(type, validTypes) do
      true ->
        true

      false ->
        find_type(types, validTypes)
    end
  end

  defp find_type([{type, _} | types], validTypes) do
    case :lists.member(type, validTypes) do
      true ->
        true

      false ->
        find_type(types, validTypes)
    end
  end

  defp find_type([{:type, type, _} | types], validTypes) do
    case :lists.member(type, validTypes) do
      true ->
        true

      false ->
        find_type(types, validTypes)
    end
  end

  defp find_type([{:type, type, _, :any} | types], validTypes) do
    case :lists.member(type, validTypes) do
      true ->
        true

      false ->
        find_type(types, validTypes)
    end
  end

  defp find_type([_ | types], validTypes) do
    find_type(types, validTypes)
  end

  defp in_range(_, []) do
    false
  end

  defp in_range(
         integer,
         [
           {:type, :range, [{:integer, start}, {:integer, end__}]}
           | _
         ]
       )
       when start <= integer and integer <= end__ do
    true
  end

  defp in_range(integer, [_ | types]) do
    in_range(integer, types)
  end

  defp check_integer_type(types, integer) when integer == 0 do
    find_type(
      types,
      [:integer, :non_neg_integer, :arity]
    ) or in_range(integer, types)
  end

  defp check_integer_type(types, integer) when integer < 0 do
    find_type(
      types,
      [:integer, :neg_integer]
    ) or in_range(integer, types)
  end

  defp check_integer_type(types, integer) when integer > 0 do
    find_type(
      types,
      [:integer, :non_neg_integer, :pos_integer]
    ) or in_range(integer, types)
  end

  defp add_to_last_nesting(term, nesting) do
    last = :lists.last(nesting)
    list = :lists.droplast(nesting)

    case last do
      {:tuple, args, u} ->
        list ++ [{:tuple, args ++ [term], u}]

      {:list, args, u} ->
        list ++ [{:list, args ++ [term], u}]

      {:map, f, fs, args, u} ->
        list ++ [{:map, f, fs, args ++ [term], u}]
    end
  end

  defp expand_function_parameter_type(mod, mFA, funType, args, unfinished, nestings, fT) do
    typeTree = :edlin_type_suggestion.type_tree(mod, funType, nestings, fT)

    {parameters, constraints1} =
      case typeTree do
        {:function, {{:parameters, parameters1}, _}, constraints} ->
          {parameters1, constraints}

        {{:parameters, parameters1}, _} = _F ->
          {parameters1, []}
      end

    case match_arguments(typeTree, args) do
      false ->
        {:no, [], []}

      true when parameters == [] ->
        {:yes, ~c")", [%{title: mFA, elems: [~c")"], options: []}]}

      true ->
        parameter = :lists.nth(length(args) + 1, parameters)

        {t, _Name} =
          case parameter do
            atom when is_atom(atom) ->
              {atom, :erlang.atom_to_list(atom)}

            {:var, name1} = t1 ->
              {t1, :erlang.atom_to_list(name1)}

            {:ann_type, {:var, name1}, t1} ->
              {t1, :erlang.atom_to_list(name1)}

            t1 ->
              {t1, :edlin_type_suggestion.print_type(t1, [], [{:first_only, true}])}
          end

        ts = :edlin_type_suggestion.get_types(constraints1, t, nestings)

        types =
          case ts do
            [] ->
              []

            _ ->
              sectionTypes =
                for %{} = s <- ts do
                  s
                end

              types1 =
                case (for {_, _} = e <- ts do
                        e
                      end) do
                  [] ->
                    sectionTypes

                  elems ->
                    case sectionTypes do
                      [] ->
                        elems

                      sT ->
                        [
                          %{title: ~c"simple types", elems: elems, options: [{:hide, :title}]}
                          | sT
                        ]
                    end
                end

              [%{title: ~c"types", elems: types1, options: [{:hide, :title}]}]
          end

        case nestings do
          [] ->
            case unfinished do
              [] ->
                case t do
                  atom1 when is_atom(atom1) ->
                    cC =
                      case length(args) + 1 < length(parameters) do
                        true ->
                          ~c", "

                        false ->
                          ~c")"
                      end

                    {res, expansion, matches} = match([], [atom1], cC)

                    case matches do
                      [] ->
                        {:no, [], []}

                      _ ->
                        {res, expansion,
                         [
                           %{
                             title: mFA,
                             elems: [],
                             options: [{:highlight_param, length(args) + 1}]
                           }
                         ]}
                    end

                  _ when types == [] ->
                    {:no, [], []}

                  _ ->
                    {:no, [],
                     [
                       %{
                         title: mFA,
                         elems: types,
                         options: [{:highlight_param, length(args) + 1}]
                       }
                     ]}
                end

              {_, word} when is_atom(t) ->
                cC =
                  case length(args) + 1 < length(parameters) do
                    true ->
                      ~c", "

                    false ->
                      ~c")"
                  end

                {res, expansion, matches} = match(word, [t], cC)

                case matches do
                  [] ->
                    {:no, [], []}

                  _ ->
                    {res, expansion,
                     [%{title: mFA, elems: [], options: [{:highlight_param, length(args) + 1}]}]}
                end

              {_, word} ->
                {res, expansion, matches} =
                  (
                    cC =
                      case length(args) + 1 < length(parameters) do
                        true ->
                          ~c", "

                        false ->
                          ~c")"
                      end

                    atoms1 =
                      :edlin_type_suggestion.get_atoms(
                        constraints1,
                        t,
                        nestings
                      )

                    match(word, atoms1, cC)
                  )

                match1 =
                  case matches do
                    [] ->
                      []

                    _ ->
                      atoms = [%{title: ~c"atoms", elems: matches, options: [{:hide, :title}]}]

                      [
                        %{
                          title: mFA,
                          elems: atoms,
                          options: [{:highlight_param, length(args) + 1}]
                        }
                      ]
                  end

                {res, expansion, match1}
            end

          _ ->
            expand_nesting_content(t, constraints1, nestings, %{
              title: mFA,
              elems: types,
              options: [{:highlight_param, length(args) + 1}]
            })
        end
    end
  end

  defp expand_nesting_content(t, constraints, nestings, section) do
    {nestingType, unfinishedNestingArg, _NestingArgs} =
      case :lists.last(nestings) do
        {:tuple, nestingArgs1, unfinished1} ->
          {:tuple, unfinished1, nestingArgs1}

        {:list, nestingArgs1, unfinished1} ->
          {:list, unfinished1, nestingArgs1}

        {:map, _, _, nestingArgs1, unfinished1} ->
          {:map, unfinished1, nestingArgs1}
      end

    types =
      for ts <-
            :edlin_type_suggestion.get_types(
              constraints,
              t,
              :lists.droplast(nestings),
              [:no_print]
            ) do
        ts
      end

    case unfinishedNestingArg do
      [] ->
        case find_type(types, [nestingType]) do
          true ->
            nestings2 = add_to_last_nesting({:var, ~c"Var"}, nestings)
            nestingArities = :edlin_type_suggestion.get_arity(constraints, t, nestings2)

            fold_results(
              for nestingArity <- nestingArities do
                case nestingArity do
                  :none ->
                    {:no, [], []}

                  _ ->
                    {:no, [], [section]}
                end
              end
            )

          false ->
            {:no, [], []}
        end

      {_, word} ->
        atoms1 = :edlin_type_suggestion.get_atoms(constraints, t, nestings)
        {res1, expansion1, matches1} = match(word, atoms1, ~c"")

        {res, expansion, matches} =
          case matches1 do
            [] ->
              nestings2 =
                add_to_last_nesting(
                  unfinishedNestingArg,
                  nestings
                )

              nestingArities =
                :edlin_type_suggestion.get_arity(
                  constraints,
                  t,
                  nestings2
                )

              fold_results(
                for nestingArity <- nestingArities do
                  case nestingArity do
                    :none ->
                      {:no, [], []}

                    _ ->
                      {:no, [], []}
                  end
                end
              )

            [{word2, _}] ->
              nestings2 =
                add_to_last_nesting(
                  {:atom, word2},
                  nestings
                )

              nestingArities =
                :edlin_type_suggestion.get_arity(
                  constraints,
                  t,
                  nestings2
                )

              fold_results(
                for nestingArity <- nestingArities do
                  case nestingArity do
                    :none ->
                      {:no, [], []}

                    _ ->
                      {res1, expansion1, matches1}
                  end
                end
              )

            _ ->
              {res1, expansion1, matches1}
          end

        match1 =
          case matches do
            [] ->
              []

            _ ->
              atoms = [%{title: ~c"atoms", elems: matches, options: [{:hide, :title}]}]
              [%{section | elems: atoms}]
          end

        {res, expansion, match1}
    end
  end

  defp extract_record_fields(
         record,
         {:attribute, _, :record, {record, fields}}
       ) do
    for x <-
          (for f <- fields do
             extract_record_field(f)
           end),
        x != [] do
      x
    end
  end

  defp extract_record_fields(_, _) do
    :error
  end

  defp extract_record_field({:typed_record_field, {_, _, {:atom, _, field}}, _}) do
    field
  end

  defp extract_record_field({:typed_record_field, {_, _, {:atom, _, field}, _}, _}) do
    field
  end

  defp extract_record_field({:record_field, _, {:atom, _, field}, _}) do
    field
  end

  defp extract_record_field({:record_field, _, {:atom, _, field}}) do
    field
  end

  defp extract_record_field(_) do
    []
  end

  defp fold_results([]) do
    {:no, [], []}
  end

  defp fold_results([r | results]) do
    :lists.foldl(&fold_completion_result/2, r, results)
  end

  defp fold_completion_result(
         {:yes, cmp1, matches1},
         {:yes, cmp2, matches2}
       ) do
    {_, cmp} = longest_common_head([cmp1, cmp2])

    case cmp do
      [] ->
        {:no, [], :ordsets.union([matches1, matches2])}

      _ ->
        {:yes, cmp, :ordsets.union([matches1, matches2])}
    end
  end

  defp fold_completion_result({:yes, cmp, matches}, {:no, [], []}) do
    {:yes, cmp, matches}
  end

  defp fold_completion_result({:no, [], []}, {:yes, cmp, matches}) do
    {:yes, cmp, matches}
  end

  defp fold_completion_result({_, _, matches1}, {_, [], matches2}) do
    {:no, [], :ordsets.union([matches1, matches2])}
  end

  defp fold_completion_result(a, b) do
    fold_completion_result(b, a)
  end

  defp expand_filepath(pathPrefix, word) do
    path =
      case pathPrefix do
        [?/ | _] ->
          pathPrefix

        _ ->
          {:ok, cwd} = :file.get_cwd()
          cwd ++ ~c"/" ++ pathPrefix
      end

    showHidden =
      case word do
        ~c"." ++ _ ->
          true

        _ ->
          false
      end

    entries =
      case :file.list_dir(path) do
        {:ok, e} ->
          :lists.map(
            fn x ->
              case :filelib.is_dir(path ++ ~c"/" ++ x) do
                true ->
                  x ++ ~c"/"

                false ->
                  x
              end
            end,
            [~c".." | e]
          )

        _ ->
          []
      end

    entriesFiltered =
      for file <- entries,
          (case file do
             [?. | _] ->
               showHidden

             _ ->
               true
           end) do
        file
      end

    case match(word, entriesFiltered, []) do
      {:yes, cmp, [match]} ->
        case :filelib.is_dir(path ++ ~c"/" ++ word ++ cmp) do
          true ->
            {:yes, cmp, [match]}

          false ->
            {:yes, cmp ++ ~c"\"", [match]}
        end

      x ->
        x
    end
  end

  defp shell(fun) do
    case :shell.local_func(:erlang.list_to_atom(fun)) do
      true ->
        ~c"shell"

      false ->
        ~c"user_defined"
    end
  end

  def shell_default_or_bif(fun) do
    case :lists.member(
           :erlang.list_to_atom(fun),
           for {e, _} <- get_exports(:shell_default) do
             e
           end
         ) do
      true ->
        ~c"shell_default"

      _ ->
        bif(fun)
    end
  end

  def bif(fun) do
    case :lists.member(
           :erlang.list_to_atom(fun),
           for {e, a} <- get_exports(:erlang),
               :erl_internal.bif(e, a) do
             e
           end
         ) do
      true ->
        ~c"erlang"

      _ ->
        shell(fun)
    end
  end

  defp expand_string(bef0) do
    case over_filepath(bef0, []) do
      {_, filepath} ->
        {path, file} = split_at_last_slash(filepath)
        expand_filepath(path, file)

      _ ->
        {:no, [], []}
    end
  end

  defp over_filepath([], _) do
    :none
  end

  defp over_filepath([?", ?\\ | bef1], filepath) do
    over_filepath(bef1, [?" | filepath])
  end

  defp over_filepath([?" | bef1], filepath) do
    {bef1, filepath}
  end

  defp over_filepath([?\s, ?\\ | bef1], filepath) do
    over_filepath(bef1, [?\s | filepath])
  end

  defp over_filepath([?\s | _], _) do
    :none
  end

  defp over_filepath([c | bef1], filepath) do
    over_filepath(bef1, [c | filepath])
  end

  defp split_at_last_slash(filepath) do
    {file, path} =
      :lists.splitwith(
        fn x ->
          x != ?/
        end,
        :lists.reverse(filepath)
      )

    {:lists.reverse(path), :lists.reverse(file)}
  end

  defp print_function_head(modStr, funStr, arity) do
    :lists.flatten(modStr ++ ~c":" ++ funStr ++ ~c"/" ++ :erlang.integer_to_list(arity))
  end

  defp print_function_head(modStr, funStr, funType, fT) do
    :lists.flatten(print_function_head_from_type(modStr, funStr, funType, fT))
  end

  defp print_function_head1(mod, fun, par, _Ret) do
    mod ++
      ~c":" ++
      fun ++
      ~c"(" ++
      :lists.join(
        ~c", ",
        for {_N, p} <- :lists.enumerate(par) do
          case p do
            atom when is_atom(atom) ->
              :erlang.atom_to_list(atom)

            {:var, v} ->
              :erlang.atom_to_list(v)

            {:ann_type, {:var, v}, _T} ->
              :erlang.atom_to_list(v)

            t ->
              :edlin_type_suggestion.print_type(
                t,
                [],
                [{:first_only, true}]
              )
          end
        end
      ) ++ ~c")"
  end

  defp print_function_head_from_type(mod, fun, funType, fT) do
    case :edlin_type_suggestion.type_tree(:erlang.list_to_atom(mod), funType, [], fT) do
      {:function, {{:parameters, parameters}, {:return, return}}, _} ->
        print_function_head1(mod, fun, parameters, return)

      {{:parameters, parameters}, {:return, return}} ->
        print_function_head1(mod, fun, parameters, return)
    end
  end

  defp expand_module_function(bef0, fT) do
    {bef1, word, _} = :edlin.over_word(bef0, [], 0)

    case over_white(bef1, [], 0) do
      {[?, | bef2], _White, _Nwh} ->
        {bef3, _White1, _Nwh1} = over_white(bef2, [], 0)
        {bef4, mod, _Nm} = :edlin.over_word(bef3, [], 0)

        case expand_function(bef4) do
          :help ->
            expand_function_name(mod, word, ~c", ", fT)

          :help_type ->
            expand_type_name(mod, word, ~c", ")

          _ ->
            fold_results(expand_helper(fT, :module, word, ~c":"))
        end

      {[?: | bef2], _White, _Nwh} ->
        {bef3, _White1, _Nwh1} = over_white(bef2, [], 0)
        {_, mod, _Nm} = :edlin.over_word(bef3, [], 0)
        expand_function_name(mod, word, ~c"(", fT)

      {[cC, n_Esc | _], _White, _Nwh}
      when cC === ?] or cC === ?) or cC === ?> or cC === ?} or cC === ?" or
             (cC === ?' and
                n_Esc !== ?$ and n_Esc !== ?-) ->
        {:no, [], []}

      {[], _, _} ->
        case word do
          [] ->
            {:no, [], []}

          _ ->
            fold_results(expand_helper(fT, :all, word, ~c":"))
        end

      {_, _, _} ->
        case word do
          [] ->
            {:no, [], []}

          _ ->
            typeOfExpand = expand_function(bef1)

            completeChar =
              case typeOfExpand do
                :help ->
                  ~c", "

                :help_type ->
                  ~c", "

                _ ->
                  ~c":"
              end

            fold_results(expand_helper(fT, typeOfExpand, word, completeChar))
        end
    end
  end

  defp expand_keyword(word) do
    keywords = [
      ~c"begin",
      ~c"case",
      ~c"of",
      ~c"receive",
      ~c"after",
      ~c"maybe",
      ~c"try",
      ~c"catch",
      ~c"throw",
      ~c"if",
      ~c"fun",
      ~c"when",
      ~c"end"
    ]

    {res, expansion, matches} = match(word, keywords, ~c"")

    case matches do
      [] ->
        {:no, [], []}

      [{^word, _}] ->
        {:no, [], []}

      _ ->
        {res, expansion, [%{title: ~c"keywords", elems: matches, options: [:highlight_all]}]}
    end
  end

  defp expand_helper(_, :help, word, completeChar) do
    [expand_module_name(word, completeChar)]
  end

  defp expand_helper(_, :help_type, word, completeChar) do
    [expand_module_name(word, completeChar)]
  end

  defp expand_helper(fT, :all, word, completeChar) do
    [
      expand_module_name(word, completeChar),
      expand_bifs(word),
      expand_shell_default(word),
      expand_user_defined_functions(fT, word),
      expand_keyword(word)
    ]
  end

  defp expand_helper(fT, _, word, completeChar) do
    [
      expand_module_name(word, completeChar),
      expand_bifs(word),
      expand_user_defined_functions(
        fT,
        word
      ),
      expand_keyword(word)
    ]
  end

  defp expand_function(~c"(" ++ str) do
    case :edlin.over_word(str, [], 0) do
      {_, ~c"h", _} ->
        :help

      {_, ~c"ht", _} ->
        :help_type

      _ ->
        :module
    end
  end

  defp expand_function(_) do
    :module
  end

  defp expand_bifs(prefix) do
    alts =
      for {e, a} = eA <- get_exports(:erlang),
          :erl_internal.bif(e, a) do
        eA
      end

    cC = ~c"("

    case match(prefix, alts, cC) do
      {_Res, _Expansion, []} = m ->
        m

      {res, expansion, matches} ->
        {res, expansion, [%{title: ~c"bifs", elems: matches, options: [:highlight_all]}]}
    end
  end

  defp expand_shell_default(prefix) do
    alts = get_exports(:shell_default) ++ :shell.local_func()
    cC = ~c"("

    case match(prefix, alts, cC) do
      {_Res, _Expansion, []} = m ->
        m

      {res, expansion, matches} ->
        {res, expansion, [%{title: ~c"commands", elems: matches, options: [:highlight_all]}]}
    end
  end

  defp expand_user_defined_functions(fT, prefix) do
    alts =
      for {{:function, {_, name, arity}}, _} <- fT do
        {name, arity}
      end

    cC = ~c"("

    case match(prefix, alts, cC) do
      {_Res, _Expansion, []} = m ->
        m

      {res, expansion, matches} ->
        {res, expansion, [%{title: ~c"user_defined", elems: matches, options: [:highlight_all]}]}
    end
  end

  defp expand_module_name(~c"", _) do
    {:no, [], []}
  end

  defp expand_module_name(prefix, cC) do
    alts =
      for {m, _, _} <- :code.all_available() do
        {:erlang.list_to_atom(m), ~c""}
      end

    case match(prefix, alts, cC) do
      {_Res, _Expansion, []} = m ->
        m

      {res, expansion, matches} ->
        {res, expansion, [%{title: ~c"modules", elems: matches, options: [:highlight_all]}]}
    end
  end

  defp get_arities(~c"shell_default" = modStr, funcStr, fT) do
    {:ok, func} = to_atom(funcStr)

    case (for {{:function, {_, fun, a}}, _} <- fT,
              fun === func do
            a
          end) do
      [] ->
        get_arities(modStr, funcStr)

      arities ->
        arities
    end
  end

  defp get_arities(modStr, funcStr, _) do
    get_arities(modStr, funcStr)
  end

  defp get_arities(modStr, funcStr) do
    case to_atom(modStr) do
      {:ok, mod} ->
        exports = get_exports(mod)

        :lists.sort(
          for {h, a} <- exports,
              :string.equal(funcStr, flat_write(h)) do
            a
          end
        )

      :error ->
        []
    end
  end

  def get_exports(mod) do
    case :erlang.module_loaded(mod) do
      true ->
        mod.module_info(:exports)

      false ->
        case :beam_lib.chunks(:code.which(mod), [:exports]) do
          {:ok, {^mod, [{:exports, e}]}} ->
            e

          _ ->
            []
        end
    end
  end

  defp expand_function_name(modStr, funcPrefix, completeChar, fT) do
    case to_atom(modStr) do
      {:ok, mod} ->
        extra =
          case mod do
            :shell_default ->
              for {{:function, {_, name, arity}}, _} <- fT do
                {name, arity}
              end

            _ ->
              []
          end

        exports = get_exports(mod) ++ extra
        {res, expansion, matches} = result = match(funcPrefix, exports, completeChar)

        case matches do
          [] ->
            result

          _ ->
            {res, expansion, [%{title: ~c"functions", elems: matches, options: [:highlight_all]}]}
        end

      :error ->
        {:no, [], []}
    end
  end

  defp get_module_types(mod) do
    case :code.get_doc(mod, %{sources: [:debug_info]}) do
      {:ok, r_docs_v1(docs: docs)} ->
        for {{:type, t, a}, _Anno, _Sig, _Doc, _Meta} <- docs do
          {t, a}
        end

      _ ->
        {:no, [], []}
    end
  end

  defp expand_type_name(modStr, typePrefix, completeChar) do
    case to_atom(modStr) do
      {:ok, mod} ->
        case get_module_types(mod) do
          {:no, [], []} ->
            {:no, [], []}

          types ->
            {res, expansion, matches} = result = match(typePrefix, types, completeChar)

            case matches do
              [] ->
                result

              _ ->
                {res, expansion, [%{title: ~c"types", elems: matches, options: [:highlight_all]}]}
            end
        end

      :error ->
        {:no, [], []}
    end
  end

  defp to_atom(str) do
    case :erl_scan.string(str) do
      {:ok, [{:atom, _, a}], _} ->
        {:ok, a}

      _ ->
        :error
    end
  end

  defp to_list(atom) do
    :io_lib.write_atom(atom)
  end

  defp strip_quotes(atom) do
    for c <- :erlang.atom_to_list(atom), c != ?' do
      c
    end
  end

  defp match_preprocess_alt({_, _} = alt) do
    alt
  end

  defp match_preprocess_alt(x) do
    {x, ~c""}
  end

  defp match(prefix, alts, extra0) do
    alts2 =
      for a <- alts do
        match_preprocess_alt(a)
      end

    len = :string.length(prefix)

    matches =
      :lists.sort(
        for {h, a} <- alts2,
            :lists.prefix(prefix, s = flat_write(h)) do
          {s, a}
        end
      )

    matches2 =
      :lists.usort(
        case extra0 do
          [] ->
            for {s, _} <- matches do
              {s, []}
            end

          _ ->
            for {s, _} <- matches do
              {s, [{:ending, extra0}]}
            end
        end
      )

    case longest_common_head(
           for {n, _} <- matches do
             n
           end
         ) do
      {:partial, []} ->
        {:no, [], matches2}

      {:partial, str} ->
        case :string.slice(str, len) do
          [] ->
            {:yes, [], matches2}

          remain ->
            {:yes, remain, matches2}
        end

      {:complete, str} ->
        extra =
          case {extra0, matches} do
            {~c"/", [{^str, n}]} when is_integer(n) ->
              ~c"/" ++ :erlang.integer_to_list(n)

            {~c"(", [{^str, 0}]} ->
              ~c"()"

            {_, _} ->
              extra0
          end

        {:yes, :string.slice(str, len) ++ extra, :ordsets.from_list(matches2)}

      :no ->
        {:no, [], []}
    end
  end

  defp flat_write(t) when is_atom(t) do
    :lists.flatten(:io_lib.fwrite(~c"~tw", [t]))
  end

  defp flat_write(s) do
    s
  end

  defp special_sort1([c | a], b)
       when c == ?{ or c == ?. or
              c == ?# do
    special_sort1(a, b)
  end

  defp special_sort1(a, [c | b])
       when c == ?{ or c == ?. or
              c == ?# do
    special_sort1(a, b)
  end

  defp special_sort1(a, b) do
    :string.lowercase(a) <= :string.lowercase(b)
  end

  defp special_sort(%{title: a}, %{title: b}) do
    special_sort1(a, b)
  end

  defp special_sort(%{}, {}) do
    :error
  end

  defp special_sort({}, %{}) do
    :error
  end

  defp special_sort({a, _}, {b, _}) do
    special_sort1(a, b)
  end

  defp special_sort(a, b) do
    special_sort1(a, b)
  end

  defp to_legacy_format([]) do
    []
  end

  defp to_legacy_format([%{title: title} | rest])
       when title === ~c"commands" or
              title === ~c"bifs" do
    to_legacy_format(rest)
  end

  defp to_legacy_format([%{title: title, elems: elems} | rest])
       when title === ~c"modules" or title === ~c"functions" or title === ~c"bindings" or
              (title === ~c"user_defined" and title === ~c"records") or title === ~c"fields" or
              title === ~c"types" or title === ~c"atoms" or title === ~c"matches" or
              title === ~c"keywords" or title === ~c"typespecs" do
    elems1 = to_legacy_format(elems)
    elems1 ++ to_legacy_format(rest)
  end

  defp to_legacy_format([%{title: title, elems: _Elems} | rest]) do
    [title] ++ to_legacy_format(rest)
  end

  defp to_legacy_format([{val, _} | rest]) do
    [{val, ~c""}] ++ to_legacy_format(rest)
  end

  def format_matches([], _LineWidth) do
    []
  end

  def format_matches([%{} | _] = fF, lineWidth) do
    groups =
      :maps.groups_from_list(
        fn %{title: title, elems: t, options: opts} ->
          separator =
            :proplists.get_value(
              :separator,
              opts,
              ~c"\n"
            )

          case :lists.last(
                 :string.split(
                   title ++ separator,
                   ~c"\n",
                   :all
                 )
               ) do
            [] ->
              format_section_matches(
                t,
                lineWidth
              )

            chars ->
              len = length(chars)

              format_section_matches(
                t,
                lineWidth,
                len
              )
          end
        end,
        fn f ->
          format_title(f, lineWidth)
        end,
        fF
      )

    s =
      :lists.flatten(
        for {matches, f} <-
              :lists.sort(
                fn {_, a}, {_, b} ->
                  a <= b
                end,
                :maps.to_list(groups)
              ) do
          :lists.join(~c"", f) ++ matches
        end
      )

    :lists.flatten(:string.trim(s, :trailing) ++ ~c"\n")
  end

  def format_matches(elems, lineWidth) do
    s = format_section_matches1(elems, lineWidth, 0)
    :lists.flatten(:string.trim(s, :trailing) ++ ~c"\n")
  end

  defp format_title(%{title: mFA, options: options}, _LineWidth) do
    case :proplists.get_value(:hide, options) do
      :title ->
        ~c""

      _ ->
        separator = :proplists.get_value(:separator, options, ~c"\n")

        highlightAll =
          :proplists.is_defined(
            :highlight_all,
            options
          )

        case highlightAll do
          true ->
            ~c"\e[;1;4m" ++ mFA ++ ~c"\e[0m" ++ separator

          _ ->
            highlightParam = :proplists.get_value(:highlight_param, options, false)

            mFA2 =
              case highlightParam do
                false ->
                  mFA

                _ ->
                  previousParams = highlightParam - 1
                  tuplePattern = ~c"(?:\\{[^\\}]+\\})"
                  atomVarPattern = ~c"(?:\\w+)"

                  typePattern =
                    ~c"(?:(?:" ++
                      atomVarPattern ++
                      ~c":)?(?:" ++ atomVarPattern ++ ~c"\\(\\))(?:\\s[><=]+\\s\\d+)?)"

                  simplePatterns =
                    ~c"(?:" ++
                      tuplePattern ++ ~c"|" ++ typePattern ++ ~c"|" ++ atomVarPattern ++ ~c")"

                  unionPattern =
                    ~c"(?:" ++ simplePatterns ++ ~c"(?:\\s\\|\\s" ++ simplePatterns ++ ~c")*)"

                  funPattern =
                    ~c"(?:fun\\(\\(" ++
                      unionPattern ++ ~c"\\)\\s*->\\s*" ++ unionPattern ++ ~c"\\))"

                  argPattern3 = ~c"(?:" ++ funPattern ++ ~c"|" ++ unionPattern ++ ~c")"

                  prevArgs =
                    ~c"(?:" ++
                      argPattern3 ++
                      ~c",\\s){" ++ :erlang.integer_to_list(previousParams) ++ ~c"}"

                  functionHeadStart = ~c"^([^\\(]+\\(" ++ prevArgs ++ ~c")"
                  highlightArg = ~c"(" ++ argPattern3 ++ ~c")"
                  nextArgs = ~c"(?:,\\s" ++ argPattern3 ++ ~c")*"
                  functionHeadEnd = ~c"(" ++ nextArgs ++ ~c"\\)(?:.*))$"

                  :re.replace(
                    mFA,
                    functionHeadStart ++ highlightArg ++ functionHeadEnd,
                    ~c"\\1\e[;1;4m\\2\e[0m\\3",
                    [:global, {:return, :list}, :unicode]
                  )
              end

            highlight = :proplists.get_value(:highlight, options, false)

            case highlight do
              false ->
                mFA2

              _ ->
                :re.replace(mFA2, ~c"(\\Q" ++ highlight ++ ~c"\\E)", ~c"\e[;1;4m\\1\e[0m", [
                  :global,
                  {:return, :list},
                  :unicode
                ])
            end ++ separator
        end
    end
  end

  defp format_title(_Elems, _LineWidth) do
    ~c""
  end

  defp format_section_matches(lS, lineWidth) do
    format_section_matches(lS, lineWidth, 0)
  end

  defp format_section_matches([], _, _) do
    ~c"\n"
  end

  defp format_section_matches([%{} | _] = fF, lineWidth, acc) do
    groups =
      :maps.groups_from_list(
        fn %{title: title, elems: t, options: opts} ->
          separator =
            :proplists.get_value(
              :separator,
              opts,
              ~c"\n"
            )

          case :lists.last(
                 :string.split(
                   title ++ separator,
                   ~c"\n",
                   :trailing
                 )
               ) do
            [] ->
              format_section_matches(
                t,
                lineWidth
              )

            chars ->
              len = :string.length(chars)

              format_section_matches(
                t,
                lineWidth,
                len + acc
              )
          end
        end,
        fn f ->
          format_title(f, lineWidth)
        end,
        fF
      )

    :lists.flatten(
      for {matches, f} <-
            :lists.sort(
              fn {_, a}, {_, b} ->
                a <= b
              end,
              :maps.to_list(groups)
            ) do
        :lists.join(~c"", f) ++ matches
      end
    )
  end

  defp format_section_matches(elems, lineWidth, acc) do
    format_section_matches1(elems, lineWidth, acc)
  end

  defp format_section_matches1([], _, _) do
    []
  end

  defp format_section_matches1(lS, lineWidth, len) do
    l0 = :lists.sort(&special_sort/2, :ordsets.to_list(lS))
    l = :lists.uniq(l0)

    opt =
      case len == 0 do
        true ->
          []

        false ->
          [{:title, len}]
      end

    s1 = format_col(opt ++ l, field_width(opt ++ l, lineWidth), len, [], lineWidth, opt)

    s2 =
      :lists.map(
        fn line ->
          case :string.length(line) do
            len1 when len1 > lineWidth ->
              :string.sub_string(line, 1, lineWidth - 4) ++ ~c"...\n"

            _ ->
              line
          end
        end,
        s1
      )

    :lists.flatten(:string.trim(s2, :trailing) ++ ~c"\n")
  end

  defp format_col(x, width, len, acc, lL, opt)
       when width + len > lL do
    format_col(x, width, 0, [~c"\n" | acc], lL, opt)
  end

  defp format_col([{:title, titleLen} | t], width, len, acc0, lL, opt) do
    acc = [:io_lib.format(~c"~-*ts", [width - titleLen, ~c""]) | acc0]
    format_col(t, width, len + width, acc, lL, opt)
  end

  defp format_col([a | t], width, len, acc0, lL, _Opt) do
    {h0, r} = format_val(a)
    hmax = lL - :string.length(r)

    {h, _} =
      case :string.length(h0) > hmax do
        true ->
          {:io_lib.format(~c"~-*ts", [hmax - 3, h0]) ++ ~c"...", true}

        false ->
          {h0, false}
      end

    acc = [:io_lib.format(~c"~-*ts", [width, h ++ r]) | acc0]
    format_col(t, width, len + width, acc, lL, [])
  end

  defp format_col([], _, _, acc, _LL, _Opt) do
    :lists.reverse(acc)
  end

  defp format_val({h, l}) when is_list(l) do
    {h, :proplists.get_value(:ending, l, ~c"")}
  end

  defp format_val({h, i}) when is_integer(i) do
    {h, ~c"/" ++ :erlang.integer_to_list(i)}
  end

  defp format_val({h, _}) do
    {h, ~c""}
  end

  defp format_val(h) do
    {h, ~c""}
  end

  defp field_width(l, lL) do
    field_width(l, 0, lL)
  end

  defp field_width([{:title, len} | t], w, lL) do
    case len do
      l when l > w ->
        field_width(t, l, lL)

      _ ->
        field_width(t, w, lL)
    end
  end

  defp field_width([h | t], w, lL) do
    {h1, ending} = format_val(h)

    case :string.length(h1 ++ ending) do
      l when l > w ->
        field_width(t, l, lL)

      _ ->
        field_width(t, w, lL)
    end
  end

  defp field_width([], w, lL) when w < lL do
    w + 4
  end

  defp field_width([], _, lL) do
    lL
  end

  def number_matches([%{elems: matches} | t]) do
    number_matches(matches) + number_matches(t)
  end

  def number_matches([_ | t]) do
    1 + number_matches(t)
  end

  def number_matches([]) do
    0
  end

  defp longest_common_head([]) do
    :no
  end

  defp longest_common_head(lL) do
    longest_common_head(lL, [])
  end

  defp longest_common_head([[] | _], l) do
    {:partial, :lists.reverse(l)}
  end

  defp longest_common_head(lL, l) do
    case same_head(lL) do
      true ->
        [[h | _] | _] = lL
        lL1 = all_tails(lL)

        case all_nil(lL1) do
          false ->
            longest_common_head(lL1, [h | l])

          true ->
            {:complete, :lists.reverse([h | l])}
        end

      false ->
        {:partial, :lists.reverse(l)}
    end
  end

  defp same_head([[h | _] | t1]) do
    same_head(h, t1)
  end

  defp same_head(h, [[h | _] | t]) do
    same_head(h, t)
  end

  defp same_head(_, []) do
    true
  end

  defp same_head(_, _) do
    false
  end

  defp all_tails(lL) do
    all_tails(lL, [])
  end

  defp all_tails([[_ | t] | t1], l) do
    all_tails(t1, [t | l])
  end

  defp all_tails([], l) do
    l
  end

  defp all_nil([]) do
    true
  end

  defp all_nil([[] | rest]) do
    all_nil(rest)
  end

  defp all_nil(_) do
    false
  end

  defp over_white([?\s | cs], stack, n) do
    over_white(cs, [?\s | stack], n + 1)
  end

  defp over_white([?\t | cs], stack, n) do
    over_white(cs, [?\t | stack], n + 1)
  end

  defp over_white(cs, stack, n) when is_list(cs) do
    {cs, stack, n}
  end
end
