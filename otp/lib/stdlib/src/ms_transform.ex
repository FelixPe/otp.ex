defmodule :m_ms_transform do
  use Bitwise
  def format_error({50, name}) do
    :lists.flatten(:io_lib.format('variable ~p shadowed in ms_transform fun head', [name]))
  end

  def format_error(1) do
    'Parameter of ets/dbg:fun2ms/1 is not a literal fun'
  end

  def format_error(2) do
    'ets:fun2ms requires fun with single variable or tuple parameter'
  end

  def format_error(3) do
    'dbg:fun2ms requires fun with single variable or list parameter'
  end

  def format_error(4) do
    'in fun head, only matching (=) on toplevel can be translated into match_spec'
  end

  def format_error(5) do
    'fun with semicolon (;) in guard cannot be translated into match_spec'
  end

  def format_error(16) do
    'fun with guard matching (\'=\' in guard) is illegal as match_spec as well'
  end

  def format_error({17, name, arithy}) do
    :lists.flatten(:io_lib.format('fun containing the local function call \'~tw/~w\' (called in guard) cannot be translated into match_spec', [name, arithy]))
  end

  def format_error({22, module, name, arithy}) do
    :lists.flatten(:io_lib.format('fun containing the remote function call \'~w:~tw/~w\' (called in guard) cannot be translated into match_spec',
                                    [module, name, arithy]))
  end

  def format_error({18, str}) do
    :lists.flatten(:io_lib.format('the language element ~ts (in guard) cannot be translated into match_spec', [str]))
  end

  def format_error({23, var}) do
    :lists.flatten(:io_lib.format('bit syntax construction with variable ~w (in guard) cannot be translated into match_spec', [var]))
  end

  def format_error({24, operator}) do
    :lists.flatten(:io_lib.format('the operator ~w is not allowed in guards', [operator]))
  end

  def format_error(116) do
    'fun with body matching (\'=\' in body) is illegal as match_spec'
  end

  def format_error({117, name, arithy}) do
    :lists.flatten(:io_lib.format('fun containing the local function call \'~tw/~w\' (called in body) cannot be translated into match_spec', [name, arithy]))
  end

  def format_error({122, module, name, arithy}) do
    :lists.flatten(:io_lib.format('fun containing the remote function call \'~w:~tw/~w\' (called in body) cannot be translated into match_spec',
                                    [module, name, arithy]))
  end

  def format_error({118, str}) do
    :lists.flatten(:io_lib.format('the language element ~ts (in body) cannot be translated into match_spec', [str]))
  end

  def format_error({123, var}) do
    :lists.flatten(:io_lib.format('bit syntax construction with variable ~w (in body) cannot be translated into match_spec', [var]))
  end

  def format_error({124, operator}) do
    :lists.flatten(:io_lib.format('the operator ~w is not allowed in function bodies', [operator]))
  end

  def format_error({6, str}) do
    :lists.flatten(:io_lib.format('the variable ~s is unbound, cannot translate into match_spec', [str]))
  end

  def format_error({7, name}) do
    :lists.flatten(:io_lib.format('fun head contains unknown record type ~tw', [name]))
  end

  def format_error({8, rName, fName}) do
    :lists.flatten(:io_lib.format('fun head contains reference to unknown field ~tw in record type ~tw', [fName, rName]))
  end

  def format_error({9, rName, fName}) do
    :lists.flatten(:io_lib.format('fun head contains already defined field ~tw in record type ~tw', [fName, rName]))
  end

  def format_error({10, atom}) do
    :lists.flatten(:io_lib.format('fun head contains atom ~w, which conflics with reserved atoms in match_spec heads', [atom]))
  end

  def format_error({11, atom}) do
    :lists.flatten(:io_lib.format('fun head contains bit syntax matching of variable ~w, which cannot be translated into match_spec', [atom]))
  end

  def format_error({20, name}) do
    :lists.flatten(:io_lib.format('fun guard contains unknown record type ~tw', [name]))
  end

  def format_error({19, rName, fName}) do
    :lists.flatten(:io_lib.format('fun guard contains reference to unknown field ~tw in record type ~tw', [fName, rName]))
  end

  def format_error({21, rName, fName}) do
    :lists.flatten(:io_lib.format('fun guard contains already defined field ~tw in record type ~tw', [fName, rName]))
  end

  def format_error({120, name}) do
    :lists.flatten(:io_lib.format('fun body contains unknown record type ~tw', [name]))
  end

  def format_error({119, rName, fName}) do
    :lists.flatten(:io_lib.format('fun body contains reference to unknown field ~tw in record type ~tw', [fName, rName]))
  end

  def format_error({121, rName, fName}) do
    :lists.flatten(:io_lib.format('fun body contains already defined field ~tw in record type ~tw', [fName, rName]))
  end

  def format_error(else__) do
    :lists.flatten(:io_lib.format('Unknown error code ~tw', [else__]))
  end

  def parse_transform_info() do
    %{error_location: :column}
  end

  def transform_from_shell(dialect, clauses, boundEnvironment) do
    saveFilename = setup_filename()
    case ((try do
            ms_clause_list(1, clauses, dialect, :gb_sets.new())
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      {:EXIT, reason} ->
        cleanup_filename(saveFilename)
        exit(reason)
      {:error, annoOrUnknown, r} ->
        {:error,
           [{cleanup_filename(saveFilename),
               [{location(annoOrUnknown), :ms_transform, r}]}],
           []}
      else__ ->
        case ((try do
                fixup_environment(else__, boundEnvironment)
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end)) do
          {:error, annoOrUnknown1, r1} ->
            {:error,
               [{cleanup_filename(saveFilename),
                   [{location(annoOrUnknown1), :ms_transform, r1}]}],
               []}
          else1 ->
            ret = normalise(else1)
            cleanup_filename(saveFilename)
            ret
        end
    end
  end

  def parse_transform(forms, _Options) do
    saveFilename = setup_filename()
    case ((try do
            forms(forms)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      {:EXIT, reason} ->
        cleanup_filename(saveFilename)
        exit(reason)
      {:error, annoOrUnknown, r} ->
        {:error,
           [{cleanup_filename(saveFilename),
               [{location(annoOrUnknown), :ms_transform, r}]}],
           []}
      else__ ->
        case (get_warnings()) do
          [] ->
            cleanup_filename(saveFilename)
            else__
          wL ->
            fName = cleanup_filename(saveFilename)
            wList = (for {l, r} <- wL do
                       {fName, [{l, :ms_transform, r}]}
                     end)
            {:warning, else__, wList}
        end
    end
  end

  defp location(:unknown) do
    :none
  end

  defp location(anno) do
    :erl_anno.location(anno)
  end

  defp get_warnings() do
    case (:erlang.get(:warnings)) do
      :undefined ->
        []
      else__ ->
        else__
    end
  end

  defp add_warning(location, r) do
    :erlang.put(:warnings, [{location, r} | get_warnings()])
  end

  defp setup_filename() do
    {:erlang.erase(:filename), :erlang.erase(:records),
       :erlang.erase(:warnings)}
  end

  defp put_filename(name) do
    :erlang.put(:filename, name)
  end

  defp put_records(r) do
    :erlang.put(:records, r)
    :ok
  end

  defp get_records() do
    case (:erlang.get(:records)) do
      :undefined ->
        []
      else__ ->
        else__
    end
  end

  defp get_record(rName) do
    case (:lists.keyfind(rName, 1, get_records())) do
      {^rName, fieldList} ->
        :erlang.put(:records_replaced_by_tuples,
                      [rName | :erlang.get(:records_replaced_by_tuples)])
        fieldList
      false ->
        :not_found
    end
  end

  defp cleanup_filename({old, oldRec, oldWarnings}) do
    ret = (case (:erlang.erase(:filename)) do
             :undefined ->
               'TOP_LEVEL'
             x ->
               x
           end)
    case (oldRec) do
      :undefined ->
        :erlang.erase(:records)
      rec ->
        :erlang.put(:records, rec)
    end
    case (oldWarnings) do
      :undefined ->
        :erlang.erase(:warnings)
      warn ->
        :erlang.put(:warnings, warn)
    end
    case (old) do
      :undefined ->
        ret
      y ->
        :erlang.put(:filename, y)
        ret
    end
  end

  defp add_record_definition({name, fieldList}) do
    {keyList, _} = :lists.foldl(fn f, {l, c} ->
                                     {[record_field(f, c) | l], c + 1}
                                end,
                                  {[], 2}, fieldList)
    put_records([{name, keyList} | get_records()])
  end

  defp record_field({:record_field, _, {:atom, anno0, fieldName}},
            c) do
    {fieldName, c, {:atom, anno0, :undefined}}
  end

  defp record_field({:record_field, _, {:atom, _, fieldName},
             def__},
            c) do
    {fieldName, c, def__}
  end

  defp record_field({:typed_record_field, field, _Type}, c) do
    record_field(field, c)
  end

  defp forms(forms0) do
    :erlang.put(:records_replaced_by_tuples, [])
    try do
      forms = (for f <- forms0 do
                 form(f)
               end)
      case (:erlang.get(:records_replaced_by_tuples)) do
        [] ->
          forms
        rNames ->
          noWarn = {:nowarn_unused_record, [:lists.usort(rNames)]}
          [{:attribute, :erl_anno.new(0), :compile,
              noWarn}] ++ forms
      end
    after
      :erlang.erase(:records_replaced_by_tuples)
    end
  end

  defp form({:attribute, _, :file, {filename, _}} = form) do
    put_filename(filename)
    form
  end

  defp form({:attribute, _, :record, definition} = form) do
    add_record_definition(definition)
    form
  end

  defp form({:function, anno, name0, arity0, clauses0}) do
    {name, arity, clauses} = function(name0, arity0,
                                        clauses0)
    {:function, anno, name, arity, clauses}
  end

  defp form(anyOther) do
    anyOther
  end

  defp function(name, arity, clauses0) do
    clauses1 = clauses(clauses0)
    {name, arity, clauses1}
  end

  defp clauses([c0 | cs]) do
    c1 = clause(c0, :gb_sets.new())
    c2 = clauses(cs)
    [c1 | c2]
  end

  defp clauses([]) do
    []
  end

  defp clause({:clause, anno, h0, g0, b0}, bound) do
    {h1, bound1} = copy(h0, bound)
    {b1, _Bound2} = copy(b0, bound1)
    {:clause, anno, h1, g0, b1}
  end

  defp copy({:call, anno,
             {:remote, _Anno2, {:atom, _Anno3, :ets},
                {:atom, _Anno4, :fun2ms}},
             as0},
            bound) do
    {transform_call(:ets, anno, as0, bound), bound}
  end

  defp copy({:call, anno,
             {:remote, _Anno2, {:atom, _Anno3, :dbg},
                {:atom, _Anno4, :fun2ms}},
             as0},
            bound) do
    {transform_call(:dbg, anno, as0, bound), bound}
  end

  defp copy({:match, anno, a, b}, bound) do
    {b1, bound1} = copy(b, bound)
    {a1, bound2} = copy(a, bound)
    {{:match, anno, a1, b1}, :gb_sets.union(bound1, bound2)}
  end

  defp copy({:var, _Anno, :_} = varDef, bound) do
    {varDef, bound}
  end

  defp copy({:var, _Anno, name} = varDef, bound) do
    bound1 = :gb_sets.add(name, bound)
    {varDef, bound1}
  end

  defp copy({:fun, anno, {:clauses, clauses}}, bound) do
    {newClauses, _IgnoredBindings} = copy_list(clauses,
                                                 bound)
    {{:fun, anno, {:clauses, newClauses}}, bound}
  end

  defp copy({:named_fun, anno, name, clauses}, bound) do
    bound1 = (case (name) do
                :_ ->
                  bound
                ^name ->
                  :gb_sets.add(name, bound)
              end)
    {newClauses, _IgnoredBindings} = copy_list(clauses,
                                                 bound1)
    {{:named_fun, anno, name, newClauses}, bound}
  end

  defp copy({:case, anno, of, clausesList}, bound) do
    {newOf, newBind0} = copy(of, bound)
    {newClausesList,
       newBindings} = copy_case_clauses(clausesList, newBind0,
                                          [])
    {{:case, anno, newOf, newClausesList}, newBindings}
  end

  defp copy(t, bound) when is_tuple(t) do
    {l, bound1} = copy_list(:erlang.tuple_to_list(t), bound)
    {:erlang.list_to_tuple(l), bound1}
  end

  defp copy(l, bound) when is_list(l) do
    copy_list(l, bound)
  end

  defp copy(anyOther, bound) do
    {anyOther, bound}
  end

  defp copy_case_clauses([], bound, addSets) do
    reallyAdded = :gb_sets.intersection(addSets)
    {[], :gb_sets.union(bound, reallyAdded)}
  end

  defp copy_case_clauses([{:clause, anno, match, guard, clauses} | t],
            bound, addSets) do
    {newMatch, matchBinds} = copy(match, bound)
    {newGuard, guardBinds} = copy(guard, matchBinds)
    {newClauses, allBinds} = copy(clauses, guardBinds)
    addedBinds = :gb_sets.subtract(allBinds, bound)
    {newTail, exportedBindings} = copy_case_clauses(t,
                                                      bound,
                                                      [addedBinds | addSets])
    {[{:clause, anno, newMatch, newGuard, newClauses} |
          newTail],
       exportedBindings}
  end

  defp copy_list([h | t], bound) do
    {c1, bound1} = copy(h, bound)
    {c2, bound2} = copy_list(t, bound1)
    {[c1 | c2], bound2}
  end

  defp copy_list([], bound) do
    {[], bound}
  end

  defp transform_call(type, _Anno,
            [{:fun, anno2, {:clauses, clauseList}}], bound) do
    ms_clause_list(anno2, clauseList, type, bound)
  end

  defp transform_call(_Type, anno, _NoAbstractFun, _) do
    throw({:error, anno, 1})
  end

  defp ms_clause_expand({:clause, anno, parameters, guard = [_, _ | _],
             body}) do
    for x <- guard do
      {:clause, anno, parameters, [x], body}
    end
  end

  defp ms_clause_expand(_Other) do
    false
  end

  defp ms_clause_list(anno, [h | t], type, bound) do
    case (ms_clause_expand(h)) do
      newHead when is_list(newHead) ->
        ms_clause_list(anno, newHead ++ t, type, bound)
      false ->
        {:cons, anno, ms_clause(h, type, bound),
           ms_clause_list(anno, t, type, bound)}
    end
  end

  defp ms_clause_list(anno, [], _, _) do
    {nil, anno}
  end

  defp ms_clause({:clause, anno, parameters, guards, body}, type,
            bound) do
    check_type(anno, parameters, type)
    {mSHead, bindings} = transform_head(parameters, bound)
    mSGuards = transform_guards(anno, guards, bindings)
    mSBody = transform_body(anno, body, bindings)
    {:tuple, anno, [mSHead, mSGuards, mSBody]}
  end

  defp check_type(_, [{:var, _, _}], _) do
    :ok
  end

  defp check_type(_, [{:tuple, _, _}], :ets) do
    :ok
  end

  defp check_type(_, [{:record, _, _, _}], :ets) do
    :ok
  end

  defp check_type(_, [{:cons, _, _, _}], :dbg) do
    :ok
  end

  defp check_type(_, [{nil, _}], :dbg) do
    :ok
  end

  defp check_type(anno0, [{:match, _, {:var, _, _}, x}], any) do
    check_type(anno0, [x], any)
  end

  defp check_type(anno0, [{:match, _, x, {:var, _, _}}], any) do
    check_type(anno0, [x], any)
  end

  defp check_type(anno, _Type, :ets) do
    throw({:error, anno, 2})
  end

  defp check_type(anno, _, :dbg) do
    throw({:error, anno, 3})
  end

  require Record
  Record.defrecord(:r_tgd, :tgd, b: :undefined, p: :undefined,
                               eb: :undefined)
  defp transform_guards(anno, [], _Bindings) do
    {nil, anno}
  end

  defp transform_guards(anno, [g], bindings) do
    b = r_tgd(b: bindings, p: :guard, eb: 0)
    tg0(anno, g, b)
  end

  defp transform_guards(anno, _, _) do
    throw({:error, anno, 5})
  end

  defp transform_body(anno, body, bindings) do
    b = r_tgd(b: bindings, p: :body, eb: 100)
    tg0(anno, body, b)
  end

  defp guard_top_trans({:call, anno0, {:atom, anno1, oldTest},
             params}) do
    case (old_bool_test(oldTest, length(params))) do
      :undefined ->
        {:call, anno0, {:atom, anno1, oldTest}, params}
      trans ->
        {:call, anno0, {:atom, anno1, trans}, params}
    end
  end

  defp guard_top_trans(else__) do
    else__
  end

  defp tg0(anno, [], _) do
    {nil, anno}
  end

  defp tg0(anno, [h0 | t], b) when r_tgd(b, :p) === :guard do
    h = guard_top_trans(h0)
    {:cons, anno, tg(h, b), tg0(anno, t, b)}
  end

  defp tg0(anno, [h | t], b) do
    {:cons, anno, tg(h, b), tg0(anno, t, b)}
  end

  defp tg({:match, anno, _, _}, b) do
    throw({:error, anno, 16 + r_tgd(b, :eb)})
  end

  defp tg({:op, anno, operator, o1, o2} = expr, b) do
    case (:erl_eval.partial_eval(expr)) do
      ^expr ->
        {:tuple, anno,
           [{:atom, anno, operator}, tg(o1, b), tg(o2, b)]}
      value ->
        value
    end
  end

  defp tg({:op, anno, operator, o1} = expr, b) do
    case (:erl_eval.partial_eval(expr)) do
      ^expr ->
        {:tuple, anno, [{:atom, anno, operator}, tg(o1, b)]}
      value ->
        value
    end
  end

  defp tg({:call, _Anno, {:atom, anno2, :bindings}, []},
            _B) do
    {:atom, anno2, :"$*"}
  end

  defp tg({:call, _Anno, {:atom, anno2, :object}, []},
            _B) do
    {:atom, anno2, :"$_"}
  end

  defp tg({:call, anno, {:atom, _, :is_record} = call,
             [object, {:atom, anno3, rName} = r]},
            b) do
    mSObject = tg(object, b)
    case (get_record(rName)) do
      fieldList when is_list(fieldList) ->
        rSize = length(fieldList) + 1
        {:tuple, anno,
           [call, mSObject, r, {:integer, anno3, rSize}]}
      :not_found ->
        throw({:error, anno3, {20 + r_tgd(b, :eb), rName}})
    end
  end

  defp tg({:call, anno, {:atom, anno2, funName},
             paraList},
            b) do
    case (is_ms_function(funName, length(paraList),
                           r_tgd(b, :p))) do
      true ->
        {:tuple, anno,
           [{:atom, anno2, funName} | :lists.map(fn x ->
                                                      tg(x, b)
                                                 end,
                                                   paraList)]}
      _ ->
        throw({:error, anno,
                 {17 + r_tgd(b, :eb), funName, length(paraList)}})
    end
  end

  defp tg({:call, anno,
             {:remote, _, {:atom, _, :erlang},
                {:atom, anno2, funName}},
             paraList},
            b) do
    l = length(paraList)
    case (is_imported_from_erlang(funName, l, r_tgd(b, :p))) do
      true ->
        case (is_operator(funName, l, r_tgd(b, :p))) do
          false ->
            tg({:call, anno, {:atom, anno2, funName}, paraList}, b)
          true ->
            tg(:erlang.list_to_tuple([:op, anno2, funName |
                                                      paraList]),
                 b)
        end
      _ ->
        throw({:error, anno,
                 {22 + r_tgd(b, :eb), :erlang, funName, length(paraList)}})
    end
  end

  defp tg({:call, anno,
             {:remote, _, {:atom, _, moduleName},
                {:atom, _, funName}},
             paraList},
            b) do
    throw({:error, anno,
             {22 + r_tgd(b, :eb), moduleName, funName,
                length(paraList)}})
  end

  defp tg({:cons, anno, h, t}, b) do
    {:cons, anno, tg(h, b), tg(t, b)}
  end

  defp tg({nil, anno}, _B) do
    {nil, anno}
  end

  defp tg({:tuple, anno, l}, b) do
    {:tuple, anno,
       [{:tuple, anno,
           :lists.map(fn x ->
                           tg(x, b)
                      end,
                        l)}]}
  end

  defp tg({:integer, anno, i}, _) do
    {:integer, anno, i}
  end

  defp tg({:char, anno, c}, _) do
    {:char, anno, c}
  end

  defp tg({:float, anno, f}, _) do
    {:float, anno, f}
  end

  defp tg({:atom, anno, a}, _) do
    case (:erlang.atom_to_list(a)) do
      [?$ | _] ->
        {:tuple, anno,
           [{:atom, anno, :const}, {:atom, anno, a}]}
      _ ->
        {:atom, anno, a}
    end
  end

  defp tg({:string, anno, s}, _) do
    {:string, anno, s}
  end

  defp tg({:var, anno, varName}, b) do
    case (lkup_bind(varName, r_tgd(b, :b))) do
      :undefined ->
        {:tuple, anno,
           [{:atom, anno, :const}, {:var, anno, varName}]}
      atomName ->
        {:atom, anno, atomName}
    end
  end

  defp tg({:record_field, anno, object, rName,
             {:atom, _Anno1, keyName}},
            b) do
    case (get_record(rName)) do
      fieldList when is_list(fieldList) ->
        case (:lists.keysearch(keyName, 1, fieldList)) do
          {:value, {^keyName, position, _}} ->
            newObject = tg(object, b)
            {:tuple, anno,
               [{:atom, anno, :element}, {:integer, anno, position},
                                             newObject]}
          _ ->
            throw({:error, anno, {19 + r_tgd(b, :eb), rName, keyName}})
        end
      :not_found ->
        throw({:error, anno, {20 + r_tgd(b, :eb), rName}})
    end
  end

  defp tg({:record, anno, rName, rFields}, b) do
    keyList0 = :lists.foldl(fn {:record_field, _,
                                  {:atom, _, key}, value},
                                 l ->
                                 nV = tg(value, b)
                                 [{key, nV} | l]
                               {:record_field, _, {:var, _, :_}, value}, l ->
                                 nV = tg(value, b)
                                 [{{:default}, nV} | l]
                               _, _ ->
                                 throw({:error, anno, {20 + r_tgd(b, :eb), rName}})
                            end,
                              [], rFields)
    defValue = (case (:lists.keysearch({:default}, 1,
                                         keyList0)) do
                  {:value, {{:default}, overriddenDefValue}} ->
                    {true, overriddenDefValue}
                  _ ->
                    false
                end)
    keyList = :lists.keydelete({:default}, 1, keyList0)
    case (:lists.keysearch({:default}, 1, keyList)) do
      {:value, {{:default}, _}} ->
        throw({:error, anno, {21 + r_tgd(b, :eb), rName, :_}})
      _ ->
        :ok
    end
    case (get_record(rName)) do
      fieldList0 when is_list(fieldList0) ->
        fieldList1 = :lists.foldl(fn {fN, _, def__}, acc ->
                                       el = (case (:lists.keysearch(fN, 1,
                                                                      keyList)) do
                                               {:value, {^fN, x0}} ->
                                                 x0
                                               _ ->
                                                 case (defValue) do
                                                   {true, overridden} ->
                                                     overridden
                                                   false ->
                                                     def__
                                                 end
                                             end)
                                       [el | acc]
                                  end,
                                    [], fieldList0)
        check_multi_field(rName, anno, keyList, 21 + r_tgd(b, :eb))
        check_undef_field(rName, anno, keyList, fieldList0,
                            19 + r_tgd(b, :eb))
        {:tuple, anno,
           [{:tuple, anno, [{:atom, anno, rName} | fieldList1]}]}
      :not_found ->
        throw({:error, anno, {20 + r_tgd(b, :eb), rName}})
    end
  end

  defp tg({:record_index, anno, rName,
             {:atom, anno2, keyName}},
            b) do
    case (get_record(rName)) do
      fieldList when is_list(fieldList) ->
        case (:lists.keysearch(keyName, 1, fieldList)) do
          {:value, {^keyName, position, _}} ->
            {:integer, anno2, position}
          _ ->
            throw({:error, anno2, {19 + r_tgd(b, :eb), rName, keyName}})
        end
      :not_found ->
        throw({:error, anno, {20 + r_tgd(b, :eb), rName}})
    end
  end

  defp tg({:record, anno, {:var, anno2, _VName} = aVName,
             rName, rFields},
            b) do
    mSVName = tg(aVName, b)
    keyList = :lists.foldl(fn {:record_field, _,
                                 {:atom, _, key}, value},
                                l ->
                                nV = tg(value, b)
                                [{key, nV} | l]
                              _, _ ->
                                throw({:error, anno, 7})
                           end,
                             [], rFields)
    case (get_record(rName)) do
      fieldList0 when is_list(fieldList0) ->
        fieldList1 = :lists.foldl(fn {fN, pos, _}, acc ->
                                       el = (case (:lists.keysearch(fN, 1,
                                                                      keyList)) do
                                               {:value, {^fN, x0}} ->
                                                 x0
                                               _ ->
                                                 {:tuple, anno2,
                                                    [{:atom, anno2, :element},
                                                         {:integer, anno2, pos},
                                                             mSVName]}
                                             end)
                                       [el | acc]
                                  end,
                                    [], fieldList0)
        check_multi_field(rName, anno, keyList, 21 + r_tgd(b, :eb))
        check_undef_field(rName, anno, keyList, fieldList0,
                            19 + r_tgd(b, :eb))
        {:tuple, anno,
           [{:tuple, anno, [{:atom, anno, rName} | fieldList1]}]}
      :not_found ->
        throw({:error, anno, {20 + r_tgd(b, :eb), rName}})
    end
  end

  defp tg({:bin_element, _Anno0, {:var, anno, a}, _,
             _} = whole,
            b) do
    case (lkup_bind(a, r_tgd(b, :b))) do
      :undefined ->
        whole
      _AtomName ->
        throw({:error, anno, {23 + r_tgd(b, :eb), a}})
    end
  end

  defp tg(:default, _B) do
    :default
  end

  defp tg({:bin_element, anno, x, y, z}, b) do
    {:bin_element, anno, tg(x, b), tg(y, b), z}
  end

  defp tg({:bin, anno, list}, b) do
    {:bin, anno,
       for x <- list do
         tg(x, b)
       end}
  end

  defp tg({:map_field_assoc, anno, field, value}, b) do
    {:map_field_assoc, anno, tg(field, b), tg(value, b)}
  end

  defp tg({:map, anno, list}, b) do
    {:map, anno,
       for x <- list do
         tg(x, b)
       end}
  end

  defp tg(t, b) when (is_tuple(t) and
                        tuple_size(t) >= 2) do
    element = :erlang.element(1, t)
    anno = :erlang.element(2, t)
    throw({:error, anno,
             {18 + r_tgd(b, :eb), translate_language_element(element)}})
  end

  defp tg(other, b) do
    element = :io_lib.format('unknown element ~tw', [other])
    throw({:error, :erl_anno.new(0),
             {18 + r_tgd(b, :eb), element}})
  end

  defp transform_head([v], outerBound) do
    bind = cre_bind()
    {newV, newBind} = toplevel_head_match(v, bind,
                                            outerBound)
    th(newV, newBind, outerBound)
  end

  defp toplevel_head_match({:match, _, {:var, anno, vName}, expr}, b,
            oB) do
    warn_var_clash(anno, vName, oB)
    {expr, new_bind({vName, :"$_"}, b)}
  end

  defp toplevel_head_match({:match, _, expr, {:var, anno, vName}}, b,
            oB) do
    warn_var_clash(anno, vName, oB)
    {expr, new_bind({vName, :"$_"}, b)}
  end

  defp toplevel_head_match(other, b, _OB) do
    {other, b}
  end

  defp th({:record, anno, rName, rFields}, b, oB) do
    {keyList0, newB} = :lists.foldl(fn {:record_field, _,
                                          {:atom, _, key}, value},
                                         {l, b0} ->
                                         {nV, b1} = th(value, b0, oB)
                                         {[{key, nV} | l], b1}
                                       {:record_field, _, {:var, _, :_}, value},
                                         {l, b0} ->
                                         {nV, b1} = th(value, b0, oB)
                                         {[{{:default}, nV} | l], b1}
                                       _, _ ->
                                         throw({:error, anno, {7, rName}})
                                    end,
                                      {[], b}, rFields)
    defValue = (case (:lists.keysearch({:default}, 1,
                                         keyList0)) do
                  {:value, {{:default}, overriddenDefValue}} ->
                    overriddenDefValue
                  _ ->
                    {:atom, anno, :_}
                end)
    keyList = :lists.keydelete({:default}, 1, keyList0)
    case (:lists.keysearch({:default}, 1, keyList)) do
      {:value, {{:default}, _}} ->
        throw({:error, anno, {9, rName, :_}})
      _ ->
        :ok
    end
    case (get_record(rName)) do
      fieldList0 when is_list(fieldList0) ->
        fieldList1 = :lists.foldl(fn {fN, _, _}, acc ->
                                       el = (case (:lists.keysearch(fN, 1,
                                                                      keyList)) do
                                               {:value, {^fN, x0}} ->
                                                 x0
                                               _ ->
                                                 defValue
                                             end)
                                       [el | acc]
                                  end,
                                    [], fieldList0)
        check_multi_field(rName, anno, keyList, 9)
        check_undef_field(rName, anno, keyList, fieldList0, 8)
        {{:tuple, anno, [{:atom, anno, rName} | fieldList1]},
           newB}
      :not_found ->
        throw({:error, anno, {7, rName}})
    end
  end

  defp th({:match, anno, _, _}, _, _) do
    throw({:error, anno, 4})
  end

  defp th({:atom, anno, a}, b, _OB) do
    case (:erlang.atom_to_list(a)) do
      [?$ | nL] ->
        case ((try do
                :erlang.list_to_integer(nL)
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end)) do
          n when is_integer(n) ->
            throw({:error, anno, {10, a}})
          _ ->
            {{:atom, anno, a}, b}
        end
      _ ->
        {{:atom, anno, a}, b}
    end
  end

  defp th({:bin_element, _Anno0, {:var, anno, a}, _, _},
            _, _) do
    throw({:error, anno, {11, a}})
  end

  defp th({:var, anno, name}, b, oB) do
    warn_var_clash(anno, name, oB)
    case (lkup_bind(name, b)) do
      :undefined ->
        newB = new_bind(name, b)
        {{:atom, anno, lkup_bind(name, newB)}, newB}
      trans ->
        {{:atom, anno, trans}, b}
    end
  end

  defp th({:map_field_exact, anno, field, value}, b,
            oB) do
    {[nField, nValue], nB} = th([field, value], b, oB)
    {{:map_field_assoc, anno, nField, nValue}, nB}
  end

  defp th([h | t], b, oB) do
    {nH, nB} = th(h, b, oB)
    {nT, nNB} = th(t, nB, oB)
    {[nH | nT], nNB}
  end

  defp th(t, b, oB) when is_tuple(t) do
    {l, nB} = th(:erlang.tuple_to_list(t), b, oB)
    {:erlang.list_to_tuple(l), nB}
  end

  defp th(nonstruct, b, _OB) do
    {nonstruct, b}
  end

  defp warn_var_clash(anno, name, outerBound) do
    case (:gb_sets.is_member(name, outerBound)) do
      true ->
        location = :erl_anno.location(anno)
        add_warning(location, {50, name})
      _ ->
        :ok
    end
  end

  defp check_multi_field(_, _, [], _) do
    :ok
  end

  defp check_multi_field(rName, anno, [{key, _} | t], errCode) do
    case (:lists.keymember(key, 1, t)) do
      true ->
        throw({:error, anno, {errCode, rName, key}})
      false ->
        check_multi_field(rName, anno, t, errCode)
    end
  end

  defp check_undef_field(_, _, [], _, _) do
    :ok
  end

  defp check_undef_field(rName, anno, [{key, _} | t], fieldList,
            errCode) do
    case (:lists.keymember(key, 1, fieldList)) do
      true ->
        check_undef_field(rName, anno, t, fieldList, errCode)
      false ->
        throw({:error, anno, {errCode, rName, key}})
    end
  end

  defp cre_bind() do
    {1, [{:_, :_}]}
  end

  defp lkup_bind(name, {_, list}) do
    case (:lists.keysearch(name, 1, list)) do
      {:value, {^name, trans}} ->
        trans
      _ ->
        :undefined
    end
  end

  defp new_bind({name, trans}, {next, l}) do
    {next, [{name, trans} | l]}
  end

  defp new_bind(name, {next, l}) do
    trans = :erlang.list_to_atom([?$ |
                                      :erlang.integer_to_list(next)])
    {next + 1, [{name, trans} | l]}
  end

  defp translate_language_element(atom) do
    transtab = [{:lc, 'list comprehension'}, {:bc, 'binary comprehension'}, {:block, 'begin/end block'}, {:if, 'if'},
                                                     {:case, 'case'}, {:receive, 'receive'},
                                                                     {:try, 'try'},
                                                                         {:catch,
                                                                            'catch'},
                                                                             {:match,
                                                                                'match (=)'},
                                                                                 {:remote,
                                                                                    'external function call'}]
    case (:lists.keysearch(atom, 1, transtab)) do
      {:value, {^atom, string}} ->
        string
      _ ->
        :erlang.atom_to_list(atom)
    end
  end

  defp old_bool_test(:atom, 1) do
    :is_atom
  end

  defp old_bool_test(:float, 1) do
    :is_float
  end

  defp old_bool_test(:integer, 1) do
    :is_integer
  end

  defp old_bool_test(:list, 1) do
    :is_list
  end

  defp old_bool_test(:number, 1) do
    :is_number
  end

  defp old_bool_test(:pid, 1) do
    :is_pid
  end

  defp old_bool_test(:port, 1) do
    :is_port
  end

  defp old_bool_test(:reference, 1) do
    :is_reference
  end

  defp old_bool_test(:tuple, 1) do
    :is_tuple
  end

  defp old_bool_test(:binary, 1) do
    :is_binary
  end

  defp old_bool_test(:function, 1) do
    :is_function
  end

  defp old_bool_test(:record, 2) do
    :is_record
  end

  defp old_bool_test(_, _) do
    :undefined
  end

  defp bool_test(:is_atom, 1) do
    true
  end

  defp bool_test(:is_float, 1) do
    true
  end

  defp bool_test(:is_integer, 1) do
    true
  end

  defp bool_test(:is_list, 1) do
    true
  end

  defp bool_test(:is_number, 1) do
    true
  end

  defp bool_test(:is_pid, 1) do
    true
  end

  defp bool_test(:is_port, 1) do
    true
  end

  defp bool_test(:is_reference, 1) do
    true
  end

  defp bool_test(:is_tuple, 1) do
    true
  end

  defp bool_test(:is_map, 1) do
    true
  end

  defp bool_test(:is_map_key, 2) do
    true
  end

  defp bool_test(:is_binary, 1) do
    true
  end

  defp bool_test(:is_function, 1) do
    true
  end

  defp bool_test(:is_record, 2) do
    true
  end

  defp bool_test(:is_seq_trace, 0) do
    true
  end

  defp bool_test(_, _) do
    false
  end

  defp real_guard_function(:abs, 1) do
    true
  end

  defp real_guard_function(:element, 2) do
    true
  end

  defp real_guard_function(:hd, 1) do
    true
  end

  defp real_guard_function(:length, 1) do
    true
  end

  defp real_guard_function(:max, 2) do
    true
  end

  defp real_guard_function(:min, 2) do
    true
  end

  defp real_guard_function(:node, 0) do
    true
  end

  defp real_guard_function(:node, 1) do
    true
  end

  defp real_guard_function(:round, 1) do
    true
  end

  defp real_guard_function(:size, 1) do
    true
  end

  defp real_guard_function(:bit_size, 1) do
    true
  end

  defp real_guard_function(:byte_size, 1) do
    true
  end

  defp real_guard_function(:map_size, 1) do
    true
  end

  defp real_guard_function(:map_get, 2) do
    true
  end

  defp real_guard_function(:binary_part, 2) do
    true
  end

  defp real_guard_function(:binary_part, 3) do
    true
  end

  defp real_guard_function(:tl, 1) do
    true
  end

  defp real_guard_function(:trunc, 1) do
    true
  end

  defp real_guard_function(:self, 0) do
    true
  end

  defp real_guard_function(:float, 1) do
    true
  end

  defp real_guard_function(_, _) do
    false
  end

  defp pseudo_guard_function(:get_tcw, 0) do
    true
  end

  defp pseudo_guard_function(_, _) do
    false
  end

  defp guard_function(x, a) do
    :erlang.or(real_guard_function(x, a),
                 pseudo_guard_function(x, a))
  end

  defp action_function(:set_seq_token, 2) do
    true
  end

  defp action_function(:get_seq_token, 0) do
    true
  end

  defp action_function(:message, 1) do
    true
  end

  defp action_function(:return_trace, 0) do
    true
  end

  defp action_function(:exception_trace, 0) do
    true
  end

  defp action_function(:process_dump, 0) do
    true
  end

  defp action_function(:enable_trace, 1) do
    true
  end

  defp action_function(:enable_trace, 2) do
    true
  end

  defp action_function(:disable_trace, 1) do
    true
  end

  defp action_function(:disable_trace, 2) do
    true
  end

  defp action_function(:display, 1) do
    true
  end

  defp action_function(:caller, 0) do
    true
  end

  defp action_function(:set_tcw, 1) do
    true
  end

  defp action_function(:silent, 1) do
    true
  end

  defp action_function(:trace, 2) do
    true
  end

  defp action_function(:trace, 3) do
    true
  end

  defp action_function(:caller_line, 0) do
    true
  end

  defp action_function(:current_stacktrace, 0) do
    true
  end

  defp action_function(:current_stacktrace, 1) do
    true
  end

  defp action_function(_, _) do
    false
  end

  defp bool_operator(:and, 2) do
    true
  end

  defp bool_operator(:or, 2) do
    true
  end

  defp bool_operator(:xor, 2) do
    true
  end

  defp bool_operator(:not, 1) do
    true
  end

  defp bool_operator(:andalso, 2) do
    true
  end

  defp bool_operator(:orelse, 2) do
    true
  end

  defp bool_operator(_, _) do
    false
  end

  defp arith_operator(:"+", 1) do
    true
  end

  defp arith_operator(:"+", 2) do
    true
  end

  defp arith_operator(:-, 1) do
    true
  end

  defp arith_operator(:-, 2) do
    true
  end

  defp arith_operator(:"*", 2) do
    true
  end

  defp arith_operator(:"/", 2) do
    true
  end

  defp arith_operator(:div, 2) do
    true
  end

  defp arith_operator(:rem, 2) do
    true
  end

  defp arith_operator(:band, 2) do
    true
  end

  defp arith_operator(:bor, 2) do
    true
  end

  defp arith_operator(:bxor, 2) do
    true
  end

  defp arith_operator(:bnot, 1) do
    true
  end

  defp arith_operator(:bsl, 2) do
    true
  end

  defp arith_operator(:bsr, 2) do
    true
  end

  defp arith_operator(_, _) do
    false
  end

  defp cmp_operator(:">", 2) do
    true
  end

  defp cmp_operator(:">=", 2) do
    true
  end

  defp cmp_operator(:"<", 2) do
    true
  end

  defp cmp_operator(:"=<", 2) do
    true
  end

  defp cmp_operator(:"==", 2) do
    true
  end

  defp cmp_operator(:"=:=", 2) do
    true
  end

  defp cmp_operator(:"/=", 2) do
    true
  end

  defp cmp_operator(:"=/=", 2) do
    true
  end

  defp cmp_operator(_, _) do
    false
  end

  defp is_operator(x, a, _) do
    :erlang.or(:erlang.or(bool_operator(x, a),
                            arith_operator(x, a)),
                 cmp_operator(x, a))
  end

  defp is_imported_from_erlang(x, a, _) do
    :erlang.or(:erlang.or(:erlang.or(:erlang.or(real_guard_function(x,
                                                                      a),
                                                  bool_test(x, a)),
                                       bool_operator(x, a)),
                            arith_operator(x, a)),
                 cmp_operator(x, a))
  end

  defp is_ms_function(x, a, :body) do
    :erlang.or(:erlang.or(action_function(x, a),
                            guard_function(x, a)),
                 bool_test(x, a))
  end

  defp is_ms_function(x, a, :guard) do
    :erlang.or(guard_function(x, a), bool_test(x, a))
  end

  defp fixup_environment(l, b) when is_list(l) do
    :lists.map(fn x ->
                    fixup_environment(x, b)
               end,
                 l)
  end

  defp fixup_environment({:var, anno, name}, b) do
    case (:lists.keysearch(name, 1, b)) do
      {:value, {^name, value}} ->
        freeze(anno, value)
      _ ->
        throw({:error, anno, {6, :erlang.atom_to_list(name)}})
    end
  end

  defp fixup_environment(t, b) when is_tuple(t) do
    :erlang.list_to_tuple(:lists.map(fn x ->
                                          fixup_environment(x, b)
                                     end,
                                       :erlang.tuple_to_list(t)))
  end

  defp fixup_environment(other, _B) do
    other
  end

  defp freeze(anno, term) do
    {:frozen, anno, term}
  end

  defp normalise({:frozen, _, term}) do
    term
  end

  defp normalise({:char, _, c}) do
    c
  end

  defp normalise({:integer, _, i}) do
    i
  end

  defp normalise({:float, _, f}) do
    f
  end

  defp normalise({:atom, _, a}) do
    a
  end

  defp normalise({:string, _, s}) do
    s
  end

  defp normalise({nil, _}) do
    []
  end

  defp normalise({:bin, _, fs}) do
    {:value, b, _} = :eval_bits.expr_grp(fs, [],
                                           fn e, _ ->
                                                {:value, normalise(e), []}
                                           end)
    b
  end

  defp normalise({:cons, _, head, tail}) do
    [normalise(head) | normalise(tail)]
  end

  defp normalise({:op, _, :"++", a, b}) do
    normalise(a) ++ normalise(b)
  end

  defp normalise({:tuple, _, args}) do
    :erlang.list_to_tuple(normalise_list(args))
  end

  defp normalise({:map, _, pairs}) do
    :maps.from_list(:lists.map(fn {:map_field_assoc, _, k,
                                     v} ->
                                    {normalise(k), normalise(v)}
                               end,
                                 pairs))
  end

  defp normalise({:op, _, :"+", {:char, _, i}}) do
    i
  end

  defp normalise({:op, _, :"+", {:integer, _, i}}) do
    i
  end

  defp normalise({:op, _, :"+", {:float, _, f}}) do
    f
  end

  defp normalise({:op, _, :-, {:char, _, i}}) do
    - i
  end

  defp normalise({:op, _, :-, {:integer, _, i}}) do
    - i
  end

  defp normalise({:op, _, :-, {:float, _, f}}) do
    - f
  end

  defp normalise_list([h | t]) do
    [normalise(h) | normalise_list(t)]
  end

  defp normalise_list([]) do
    []
  end

end