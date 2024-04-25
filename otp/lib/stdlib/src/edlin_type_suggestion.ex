defmodule :m_edlin_type_suggestion do
  use Bitwise
  require Record
  Record.defrecord(:r_docs_v1, :docs_v1, anno: :undefined,
                                   beam_language: :erlang, format: "application/erlang+html",
                                   module_doc: :undefined,
                                   metadata: %{otp_doc_vsn: {1, 0, 0}},
                                   docs: :undefined)
  Record.defrecord(:r_docs_v1_entry, :docs_v1_entry, kind_name_arity: :undefined,
                                         anno: :undefined,
                                         signature: :undefined, doc: :undefined,
                                         metadata: :undefined)
  def type_tree(mod, funType, nestings, fT) do
    case (:erlang.get({:type_traverser, mod, funType,
                         nestings})) do
      :undefined ->
        res = type_traverser_cache(mod, funType, %{},
                                     length(nestings) + 1, fT)
        :erlang.put({:type_traverser, mod, funType, nestings},
                      res)
        res
      res ->
        res
    end
  end

  defp type_traverser_cache(mod, t, visited, level, fT) do
    case (:erlang.get({mod, t, level})) do
      :undefined ->
        res = type_traverser(mod, t, visited, level, fT)
        :erlang.put({mod, t, level}, res)
        res
      res ->
        res
    end
  end

  defp type_traverser(mod,
            {:type, _, :bounded_fun, [fun, constraints]}, visited,
            level, fT) do
    cl = (for x <- constraints do
            type_traverser(mod, x, visited, level, fT)
          end)
    f = type_traverser(mod, fun, visited, level, fT)
    {:function, f, cl}
  end

  defp type_traverser(mod, {:type, _, :fun, [product, return]},
            visited, level, fT) do
    p = type_traverser(mod, product, visited, level, fT)
    r = type_traverser(mod, return, visited, level, fT)
    {p, {:return, r}}
  end

  defp type_traverser(mod, {:type, _, :product, childs}, visited,
            level, fT) do
    cl = (for x <- childs do
            type_traverser(mod, x, visited, level, fT)
          end)
    {:parameters, cl}
  end

  defp type_traverser(mod,
            {:type, _, :constraint,
               [{:atom, _, :is_subtype}, [type1, type2]]},
            visited, level, fT) do
    {:constraint,
       type_traverser(mod, type1, visited, level, fT),
       type_traverser(mod, type2, visited, level, fT)}
  end

  defp type_traverser(_, {:var, _, name}, _Visited, _Level, _FT) do
    {:var, name}
  end

  defp type_traverser(_Mod, {:type, _, :map, :any}, _Visited, _Level,
            _FT) do
    {:type, :map, []}
  end

  defp type_traverser(mod, {:type, _, :map, params}, visited, level,
            fT) do
    {:map,
       for x <- params do
         type_traverser(mod, x, visited, level - 1, fT)
       end}
  end

  defp type_traverser(mod,
            {:type, _, :map_field_exact, [type1, type2]}, visited,
            level, fT) do
    {:map_field_exact,
       type_traverser(mod, type1, visited, level, fT),
       type_traverser(mod, type2, visited, level, fT)}
  end

  defp type_traverser(mod,
            {:type, _, :map_field_assoc, [type1, type2]}, visited,
            level, fT) do
    {:map_field_assoc,
       type_traverser(mod, type1, visited, level, fT),
       type_traverser(mod, type2, visited, level, fT)}
  end

  defp type_traverser(_Mod, {:atom, _, atom}, _Visited, _Level, _FT)
      when is_atom(atom) do
    atom
  end

  defp type_traverser(mod, {:op, _, op, type}, visited, level, fT) do
    {:op, op, type_traverser(mod, type, visited, level, fT)}
  end

  defp type_traverser(mod, {:op, _, op, type1, type2}, visited, level,
            fT) do
    {:op, op,
       type_traverser(mod, type1, visited, level, fT),
       type_traverser(mod, type2, visited, level, fT)}
  end

  defp type_traverser(_Mod, {:integer, _, int}, _Visited, _Level,
            _FT) do
    {:integer, int}
  end

  defp type_traverser(mod, {:type, _, :list, [childType]}, visited,
            level, fT) do
    {:list,
       type_traverser(mod, childType, visited, level - 1, fT)}
  end

  defp type_traverser(_Mod, {:type, _, :tuple, :any}, _Visited,
            _Level, _FT) do
    {:type, :tuple, []}
  end

  defp type_traverser(mod, {:type, _, :tuple, childTypes}, visited,
            level, fT) do
    {:tuple,
       for x <- childTypes do
         type_traverser(mod, x, visited, level - 1, fT)
       end}
  end

  defp type_traverser(mod, {:type, _, :union, childTypes}, visited,
            level, fT) do
    childs = (for x <- childTypes do
                type_traverser(mod, x, visited, level, fT)
              end)
    childsFiltered = (for x <- childs, x != :undefined do
                        x
                      end)
    {unionChilds, nonUnionChilds} = :lists.partition(fn x ->
                                                          case (x) do
                                                            {:union, _} ->
                                                              true
                                                            _ ->
                                                              false
                                                          end
                                                     end,
                                                       childsFiltered)
    childsFlattened = :lists.flatten(for {:union,
                                            t} <- unionChilds do
                                       t
                                     end) ++ nonUnionChilds
    {:union, childsFlattened}
  end

  defp type_traverser(mod, {:ann_type, _, [t1, t2]}, visited, level,
            fT) do
    {:ann_type, type_traverser(mod, t1, visited, level, fT),
       type_traverser(mod, t2, visited, level, fT)}
  end

  defp type_traverser(mod, {:user_type, _, name, params} = t, visited,
            level, fT)
      when 0 >= level do
    case (:maps.is_key(strip_anno(t), visited)) do
      false ->
        {:type, mod, name,
           for p <- params do
             type_traverser(mod, p,
                              Map.put(visited, strip_anno(t), true), 0, fT)
           end}
      true ->
        {:type, mod, name, []}
    end
  end

  defp type_traverser(_,
            {:remote_type, _,
               [{_, _, mod}, {_, _, name}, params]} = t,
            visited, level, fT)
      when 0 >= level do
    case (:maps.is_key(strip_anno(t), visited)) do
      false ->
        {:type, mod, name,
           for p <- params do
             type_traverser(mod, p,
                              Map.put(visited, strip_anno(t), true), 0, fT)
           end}
      true ->
        {:type, mod, name, []}
    end
  end

  defp type_traverser(mod, {:user_type, _, name, params} = t, visited,
            1 = level, fT) do
    case (:maps.is_key(strip_anno(t), visited)) do
      false ->
        case (:erlang.get({strip_anno(t), 1})) do
          :undefined ->
            res = (case (lookup_type(mod, name, length(params),
                                       fT)) do
                     :hidden ->
                       {:type, mod, name,
                          for p <- params do
                            type_traverser(mod, p,
                                             Map.put(visited, strip_anno(t),
                                                                true),
                                             level, fT)
                          end}
                     type ->
                       {:user_type, mod, name,
                          for p <- params do
                            type_traverser(mod, p,
                                             Map.put(visited, strip_anno(t),
                                                                true),
                                             level, fT)
                          end,
                          type_traverser(mod, type,
                                           Map.put(visited, strip_anno(t),
                                                              true),
                                           level, fT)}
                   end)
            :erlang.put({strip_anno(t), 1}, res)
            res
          res ->
            res
        end
      true ->
        {:type, mod, name, []}
    end
  end

  defp type_traverser(_,
            {:remote_type, _,
               [{_, _, mod}, {_, _, name}, params]} = t,
            visited, 1 = level, fT) do
    case (:maps.is_key(strip_anno(t), visited)) do
      false ->
        case (:erlang.get({strip_anno(t), 1})) do
          :undefined ->
            res = (case (lookup_type(mod, name, length(params),
                                       fT)) do
                     :hidden ->
                       {:type, mod, name,
                          for p <- params do
                            type_traverser(mod, p,
                                             Map.put(visited, strip_anno(t),
                                                                true),
                                             level, fT)
                          end}
                     type ->
                       {:user_type, mod, name,
                          for p <- params do
                            type_traverser(mod, p,
                                             Map.put(visited, strip_anno(t),
                                                                true),
                                             level, fT)
                          end,
                          type_traverser(mod, type,
                                           Map.put(visited, strip_anno(t),
                                                              true),
                                           level, fT)}
                   end)
            :erlang.put({strip_anno(t), 1}, res)
            res
          res ->
            res
        end
      true ->
        {:type, mod, name, []}
    end
  end

  defp type_traverser(mod, {:user_type, _, name, params} = t, visited,
            level, fT) do
    case (:maps.is_key(strip_anno(t), visited)) do
      false ->
        case (:erlang.get({strip_anno(t), level})) do
          :undefined ->
            res = (case (lookup_type(mod, name, length(params),
                                       fT)) do
                     :hidden ->
                       {:type, mod, name,
                          for p <- params do
                            type_traverser(mod, p,
                                             Map.put(visited, strip_anno(t),
                                                                true),
                                             level, fT)
                          end}
                     type ->
                       type_traverser(mod, type,
                                        Map.put(visited, strip_anno(t), true),
                                        level, fT)
                   end)
            :erlang.put({strip_anno(t), level}, res)
            res
          res ->
            res
        end
      true ->
        {:type, mod, name, []}
    end
  end

  defp type_traverser(_,
            {:remote_type, _,
               [{_, _, mod}, {_, _, name}, params]} = t,
            visited, level, fT) do
    case (:maps.is_key(strip_anno(t), visited)) do
      false ->
        case (:erlang.get({strip_anno(t), level})) do
          :undefined ->
            res = (case (lookup_type(mod, name, length(params),
                                       fT)) do
                     :hidden ->
                       {:type, mod, name,
                          for p <- params do
                            type_traverser(mod, p,
                                             Map.put(visited, strip_anno(t),
                                                                true),
                                             level, fT)
                          end}
                     type ->
                       type_traverser(mod, type,
                                        Map.put(visited, strip_anno(t), true),
                                        level, fT)
                   end)
            :erlang.put({strip_anno(t), level}, res)
            res
          res ->
            res
        end
      true ->
        {:type, mod, name, []}
    end
  end

  defp type_traverser(_, {:type, _, :record, [{:atom, _, record}]},
            _Visited, _Level, _FT) do
    {:record, record}
  end

  defp type_traverser(_, {:type, _, name, :any}, _, _, _) do
    {:type, name, []}
  end

  defp type_traverser(_, {:type, _, :term}, _, _, _) do
    {:type, :any, []}
  end

  defp type_traverser(_, {:type, _, name}, _, _, _) do
    {:type, name, []}
  end

  defp type_traverser(_, {:type, _, :term, _}, _, _, _) do
    {:type, :any, []}
  end

  defp type_traverser(_, {:type, _, name, params} = t, visited, level,
            fT) do
    case (:maps.is_key(strip_anno(t), visited)) do
      false ->
        case (:erlang.get({strip_anno(t), 1})) do
          :undefined ->
            res = (case (lookup_type(:erlang, name, length(params),
                                       fT)) do
                     :hidden ->
                       {:type, name,
                          for p <- params do
                            type_traverser(:erlang, p,
                                             Map.put(visited, strip_anno(t),
                                                                true),
                                             level, fT)
                          end}
                     type ->
                       type_traverser(:erlang, type,
                                        Map.put(visited, strip_anno(t), true),
                                        level, fT)
                   end)
            :erlang.put({strip_anno(t), 1}, res)
            res
          res ->
            res
        end
      true ->
        {:type, name, []}
    end
  end

  defp strip_anno({a, _, b}) do
    {a, b}
  end

  defp strip_anno({a, _, b, c}) do
    {a, b, c}
  end

  defp simplified_type(:erlang, :binary, 0) do
    {:type, :undefined, :binary, []}
  end

  defp simplified_type(:erlang, :char, 0) do
    {:type, :undefined, :char, []}
  end

  defp simplified_type(:erlang, :iolist, 0) do
    {:type, :undefined, :iolist, []}
  end

  defp simplified_type(:erlang, :string, 0) do
    {:type, :undefined, :string, []}
  end

  defp simplified_type(:unicode, :chardata, 0) do
    {:type, :erlang, :string, []}
  end

  defp simplified_type(:file, :filename_all, 0) do
    {:type, :erlang, :string, []}
  end

  defp simplified_type(:file, :filename, 0) do
    {:type, :erlang, :string, []}
  end

  defp simplified_type(:file, :name_all, 0) do
    {:type, :erlang, :string, []}
  end

  defp simplified_type(:file, :name, 0) do
    {:type, :erlang, :string, []}
  end

  defp simplified_type(_Module, _TypeName, _Arity) do
    :none
  end

  defp lookup_type(mod, type, arity, fT) do
    case (simplified_type(mod, type, arity)) do
      :none ->
        case (:code.get_doc(mod, %{sources: [:debug_info]})) do
          {:ok, r_docs_v1(docs: docs)} ->
            fnFunctions = :lists.filter(fn {{:type, t, a}, _Anno,
                                              _Sig, _Doc, _Meta} ->
                                             t === type and a === arity
                                           _ ->
                                             false
                                        end,
                                          docs)
            case (fnFunctions) do
              [] ->
                case (for {{:type, type2},
                             {:attribute, _, :type, {_, typeAST, _}}} <- fT,
                            type2 === type do
                        typeAST
                      end) do
                  [] ->
                    :hidden
                  [singleTypeAST] ->
                    singleTypeAST
                end
              [{_, _, _, _,
                  %{signature:
                    [{:attribute, _, :type, {_, typeAST, _}}]}}] ->
                typeAST
            end
          _ ->
            case (for {{:type, type2},
                         {:attribute, _, :type, {_, typeAST, _}}} <- fT,
                        type2 === type do
                    typeAST
                  end) do
              [] ->
                :hidden
              [singleTypeAST] ->
                singleTypeAST
            end
        end
      t ->
        t
    end
  end

  def get_function_type(mod, fun, arity, fT) do
    case (:code.get_doc(mod, %{sources: [:debug_info]})) do
      {:ok, r_docs_v1(docs: docs)} ->
        r = :lists.flatten(for {{:function, f, a}, _Anno, _Sig,
                                  _Doc,
                                  %{signature:
                                    [{:attribute, _, :spec,
                                        {_, funTypes}}]}} <- docs,
                                 f === fun, a === arity do
                             funTypes
                           end)
        case ({mod, r}) do
          {:shell_default, []} ->
            :lists.flatten(for {{:function_type,
                                   {:shell_default, f, a}},
                                  {:attribute, _, :spec, {_, funTypes}}} <- fT,
                                 f === fun, a === arity do
                             funTypes
                           end)
          _ ->
            r
        end
      _ when mod === :shell_default ->
        :lists.flatten(for {{:function_type,
                               {:shell_default, f, a}},
                              {:attribute, _, :spec, {_, funTypes}}} <- fT,
                             f === fun, a === arity do
                         funTypes
                       end)
      _ ->
        []
    end
  end

  def get_arity(constraints, type, nestings) do
    case (get_arity1(type, constraints, nestings)) do
      list when is_list(list) ->
        list
      val ->
        [val]
    end
  end

  defp get_arity1({:var, _Var} = c, constraints, nestings) do
    case (get_constraint(c, constraints)) do
      {:constraint, _, t} ->
        get_arity1(t, constraints, nestings)
      _ ->
        :none
    end
  end

  defp get_arity1({:list, _T}, _Constraints, [{:list, _, _}]) do
    99
  end

  defp get_arity1({:list, t}, constraints,
            [{:list, _, _} | nestings]) do
    get_arity1(t, constraints, nestings)
  end

  defp get_arity1({:tuple, lT}, constraints, [{:tuple, args, _}])
      when length(lT) >= length(args) do
    case (:edlin_expand.match_arguments1(lT, constraints,
                                           args)) do
      true ->
        length(lT)
      false ->
        :none
    end
  end

  defp get_arity1({:tuple, lT}, constraints,
            [{:tuple, args, _} | nestings])
      when length(lT) >= length(args) + 1 do
    case (:edlin_expand.match_arguments1(lT, constraints,
                                           args)) do
      true ->
        get_arity1(:lists.nth(length(args) + 1, lT),
                     constraints, nestings)
      false ->
        :none
    end
  end

  defp get_arity1({:map, types}, _Constraints,
            [{:map, _Keys, [], _, _}]) do
    length(types)
  end

  defp get_arity1({:map, types}, _Constraints,
            [{:map, _Keys, _Key, _, _}]) do
    length(types)
  end

  defp get_arity1({:map, types}, constraints,
            [{:map, keys, [], _, _} | nestings]) do
    :lists.flatten(for ({_, key, _} = t) <- types,
                         not :lists.member(:erlang.atom_to_list(key), keys) do
                     get_arity1(t, constraints, nestings)
                   end)
  end

  defp get_arity1({:map, types}, constraints,
            [{:map, _Keys, key, _, _} | nestings]) do
    case (for {_, k, v} <- types,
                k === :erlang.list_to_atom(key) do
            v
          end) do
      [] ->
        :none
      [type] ->
        get_arity1(type, constraints, nestings)
    end
  end

  defp get_arity1({:map_field_assoc, k, _V}, c, nestings) do
    get_arity1(k, c, nestings)
  end

  defp get_arity1({:map_field_exact, k, _V}, c, nestings) do
    get_arity1(k, c, nestings)
  end

  defp get_arity1({:union, types}, constraints, nestings) do
    arities = (for t <- types do
                 get_arity1(t, constraints, nestings)
               end)
    for x <- :lists.flatten(arities), x != :none do
      x
    end
  end

  defp get_arity1({:ann_type, _Var, type}, constraints,
            nestings) do
    get_arity1(type, constraints, nestings)
  end

  defp get_arity1({:user_type, _, _, _, type}, constraints,
            nestings) do
    get_arity1(type, constraints, nestings)
  end

  defp get_arity1(_, _, _) do
    :none
  end

  def get_atoms(constraints, type, nestings) do
    case (get_atoms1(type, constraints, nestings)) do
      list when is_list(list) ->
        for atom <- list do
          :io_lib.write_atom(atom)
        end
      atom when is_atom(atom) ->
        [:io_lib.write_atom(atom)]
    end
  end

  defp get_atoms1({:var, _Var} = c, constraints, nestings) do
    case (get_constraint(c, constraints)) do
      {:constraint, _, t} ->
        get_atoms1(t, constraints, nestings)
      _ ->
        []
    end
  end

  defp get_atoms1({:list, t}, constraints,
            [{:list, _, _} | nestings]) do
    get_atoms1(t, constraints, nestings)
  end

  defp get_atoms1({:tuple, lT}, constraints,
            [{:tuple, args, _} | nestings])
      when length(lT) >= length(args) + 1 do
    case (:edlin_expand.match_arguments1(lT, constraints,
                                           args)) do
      true ->
        get_atoms1(:lists.nth(length(args) + 1, lT),
                     constraints, nestings)
      false ->
        []
    end
  end

  defp get_atoms1({:map, types}, constraints,
            [{:map, keys, [], _, _} | nestings]) do
    :lists.flatten(for ({_, key, _} = t) <- types,
                         not :lists.member(:erlang.atom_to_list(key), keys) do
                     get_atoms1(t, constraints, nestings)
                   end)
  end

  defp get_atoms1({:map, types}, constraints,
            [{:map, _Keys, key, _, _} | nestings]) do
    case (for {_, k, v} <- types,
                k === :erlang.list_to_atom(key) do
            v
          end) do
      [] ->
        []
      [type] ->
        get_atoms1(type, constraints, nestings)
    end
  end

  defp get_atoms1({:map_field_assoc, k, _V}, c, nestings) do
    get_atoms1(k, c, nestings)
  end

  defp get_atoms1({:map_field_exact, k, _V}, c, nestings) do
    get_atoms1(k, c, nestings)
  end

  defp get_atoms1({:union, types}, constraints, nestings) do
    atoms = (for t <- types do
               get_atoms1(t, constraints, nestings)
             end)
    for x <- :lists.flatten(atoms), x != [] do
      x
    end
  end

  defp get_atoms1(atom, _Constraints, []) when is_atom(atom) do
    atom
  end

  defp get_atoms1({:user_type, _, _, _, type}, constraints,
            nestings) do
    get_atoms1(type, constraints, nestings)
  end

  defp get_atoms1(_, _, _) do
    []
  end

  def get_types(constraints, t, nestings) do
    get_types(constraints, t, nestings, [])
  end

  def get_types(constraints, t, nestings, options) do
    maxUserTypeExpansions = 1
    case (get_types1(t, constraints, nestings,
                       maxUserTypeExpansions, options)) do
      [] ->
        []
      [_ | _] = types ->
        for type <- types, type != [] do
          type
        end
      type ->
        [type]
    end
  end

  defp get_types1({:var, _Var} = c, constraints, nestings,
            maxUserTypeExpansions, options) do
    case (get_constraint(c, constraints)) do
      {:constraint, _, t} ->
        get_types1(t, constraints, nestings,
                     maxUserTypeExpansions, options)
      _ ->
        []
    end
  end

  defp get_types1({:union, types}, cs, nestings,
            maxUserTypeExpansions, options) do
    :lists.flatten(for t <- types do
                     get_types1(t, cs, nestings, maxUserTypeExpansions,
                                  options)
                   end)
  end

  defp get_types1({:list, t}, cs, [{:list, _Args, _} | nestings],
            maxUserTypeExpansions, options) do
    get_types1(t, cs, nestings, maxUserTypeExpansions,
                 options)
  end

  defp get_types1({:tuple, lT}, cs,
            [{:tuple, args, _} | nestings], maxUserTypeExpansions,
            options)
      when length(lT) >= length(args) + 1 do
    case (:edlin_expand.match_arguments1(lT, cs, args)) do
      true ->
        get_types1(:lists.nth(length(args) + 1, lT), cs,
                     nestings, maxUserTypeExpansions, options)
      false ->
        []
    end
  end

  defp get_types1({:map, types}, cs,
            [{:map, keys, [], _Args, _} | nestings],
            maxUserTypeExpansions, options) do
    :lists.flatten(for ({_, key, _} = t) <- types,
                         not :lists.member(:erlang.atom_to_list(key), keys) do
                     get_types1(t, cs, nestings, maxUserTypeExpansions,
                                  options)
                   end)
  end

  defp get_types1({:map, types}, cs,
            [{:map, _, key, _Args, _} | nestings],
            maxUserTypeExpansions, options) do
    case (for {_, k, v} <- types,
                k === :erlang.list_to_atom(key) do
            v
          end) do
      [] ->
        []
      [type] ->
        get_types1(type, cs, nestings, maxUserTypeExpansions,
                     options)
    end
  end

  defp get_types1({:user_type, _Mod, _Name, _Params, type}, cs,
            nestings, maxUserTypeExpansions, [:no_print] = options)
      when maxUserTypeExpansions > 0 do
    :lists.flatten([get_types1(type, cs, nestings,
                                 maxUserTypeExpansions - 1, options)])
  end

  defp get_types1({:user_type, _, _, _, type}, cs, nestings, 0,
            [:no_print] = options) do
    get_types1(type, cs, nestings, 0, options)
  end

  defp get_types1({:ann_type, _Var, t}, cs, nestings,
            maxUserTypeExpansions, [:no_print]) do
    get_types1(t, cs, nestings, maxUserTypeExpansions,
                 [:no_print])
  end

  defp get_types1({:ann_type, _Var, _T} = type, cs, [],
            _MaxUserTypeExpansions, []) do
    {print_type(type, cs), ''}
  end

  defp get_types1({:ann_type, _Var, t}, cs, nestings,
            maxUserTypeExpansions, []) do
    get_types1(t, cs, nestings, maxUserTypeExpansions, [])
  end

  defp get_types1(type, _Cs, [], _, [:no_print]) do
    type
  end

  defp get_types1({:user_type, mod, name, params, type}, cs,
            nestings, maxUserTypeExpansions, [])
      when maxUserTypeExpansions > 0 do
    title = print_type({:type, mod, name, params}, cs, [])
    elems = :lists.flatten([get_types1(type, cs, nestings,
                                         maxUserTypeExpansions - 1, [])])
    %{title: title, elems: elems,
        options: [{:separator, ' :: '}, {:highlight_all}]}
  end

  defp get_types1({:user_type, _, _, _, type}, cs, nestings, 0,
            []) do
    get_types1(type, cs, nestings, 0, [])
  end

  defp get_types1(type, cs, [], _, []) do
    {print_type(type, cs), ''}
  end

  defp get_types1(_, _, _, _, _) do
    []
  end

  defp get_constraint(type, constraints) do
    case (for ({:constraint, t, _} = x) <- constraints,
                t == type do
            x
          end) do
      [c | _] ->
        c
      [] ->
        []
    end
  end

  defp print_type(type, constraints) do
    :lists.flatten(print_type(type, constraints, [], []))
  end

  def print_type(type, constraints, options) do
    :lists.flatten(print_type(type, constraints, [],
                                options))
  end

  defp print_type({:var, name} = var, constraints, visited,
            options) do
    case (:lists.member(var, visited)) do
      true ->
        :erlang.atom_to_list(name)
      false ->
        case (get_constraint(var, constraints)) do
          {:constraint, _, t2} ->
            print_type(t2, constraints, [var | visited], options)
          _ ->
            :erlang.atom_to_list(name)
        end
    end
  end

  defp print_type(atom, _Cs, _V, _) when is_atom(atom) do
    :io_lib.write_atom(atom)
  end

  defp print_type({{:parameters, ps}, {:return, r}}, cs, v,
            options) do
    'fun((' ++ :lists.join(', ',
                       for x <- ps do
                         print_type(x, cs, v, options)
                       end) ++ ') -> ' ++ print_type(r, cs, v, options) ++ ')'
  end

  defp print_type({:list, type}, cs, v, options) do
    '[' ++ print_type(type, cs, v, options) ++ ']'
  end

  defp print_type({:tuple, types}, cs, v, options)
      when is_list(types) do
    types1 = (for x <- types do
                print_type(x, cs, v, options)
              end)
    case (types1) do
      [] ->
        '{}'
      _ ->
        '{' ++ :lists.nth(1, types1) ++ ', ...}'
    end
  end

  defp print_type({:ann_type, var, type}, cs, v, options) do
    print_type(var, cs, v, options) ++ ' :: ' ++ print_type(type,
                                                         cs, v, options)
  end

  defp print_type({:map, types}, cs, v, options) do
    types1 = (for x <- types do
                print_type(x, cs, v, options)
              end)
    '\#{' ++ :lists.join(', ', types1) ++ '}'
  end

  defp print_type({:map_field_assoc, type1, type2}, cs, v,
            options) do
    print_type(type1, cs, v,
                 options) ++ '=>' ++ print_type(type2, cs, v, options)
  end

  defp print_type({:map_field_exact, type1, type2}, cs, v,
            options) do
    print_type(type1, cs, v,
                 options) ++ ':=' ++ print_type(type2, cs, v, options)
  end

  defp print_type({:integer, int}, _Cs, _V, _) do
    :erlang.integer_to_list(int)
  end

  defp print_type({:op, op, type}, cs, v, options) do
    'op (' ++ :erlang.atom_to_list(op) ++ ' ' ++ print_type(type,
                                                       cs, v, options) ++ ')'
  end

  defp print_type({:op, op, type1, type2}, cs, v, options) do
    'op (' ++ print_type(type1, cs, v,
                      options) ++ ' ' ++ :erlang.atom_to_list(op) ++ ' ' ++ print_type(type2,
                                                                                     cs,
                                                                                     v,
                                                                                     options) ++ ')'
  end

  defp print_type({:record, record}, _Cs, _V, _) do
    '#' ++ :erlang.atom_to_list(record)
  end

  defp print_type({:type, :range,
             [{:integer, int1}, {:integer, int2}]},
            _Cs, _V, _) do
    :erlang.integer_to_list(int1) ++ '..' ++ :erlang.integer_to_list(int2)
  end

  defp print_type({:type, :non_neg_integer, []}, _Cs, _V, _) do
    'integer() >= 0'
  end

  defp print_type({:type, :neg_integer, []}, _Cs, _V, _) do
    'integer() < 0'
  end

  defp print_type({:type, :pos_integer, []}, _Cs, _V, _) do
    'integer() > 0'
  end

  defp print_type({:type, name, []}, _Cs, _V, _) do
    :erlang.atom_to_list(name) ++ '()'
  end

  defp print_type({:type, name, params}, _Cs, _V, _) do
    :erlang.atom_to_list(name) ++ '(' ++ :lists.join(', ',
                                                     for p <- params do
                                                       extract_param(p)
                                                     end) ++ ')'
  end

  defp print_type({:union, types}, cs, v, options) do
    :lists.join(' | ',
                  for x <- types do
                    print_type(x, cs, v, options)
                  end)
  end

  defp print_type({:type, mod, name, params}, _Cs, _V, _) do
    :erlang.atom_to_list(mod) ++ ':' ++ :erlang.atom_to_list(name) ++ '(' ++ :lists.join(', ',
                                                                                       for p <- params do
                                                                                         extract_param(p)
                                                                                       end) ++ ')'
  end

  defp print_type({:user_type, mod, name, params, type}, cs, v,
            options) do
    first = :proplists.get_value(:first_only, options,
                                   false)
    case (first) do
      true ->
        print_type({:type, mod, name, params}, cs, v, options)
      _ ->
        print_type({:type, mod, name, params}, cs, v,
                     options) ++ ' :: ' ++ print_type(type, cs, v, options)
    end
  end

  defp print_type(_, _, _, _) do
    :erlang.atom_to_list(:unknown)
  end

  defp extract_param({:var, var}) do
    :erlang.atom_to_list(var)
  end

  defp extract_param({:integer, value}) do
    :io_lib.format('~p', [value])
  end

  defp extract_param({:type, type, _}) do
    :io_lib.format('~p', [type])
  end

  defp extract_param(t) do
    print_type(t, [])
  end

end