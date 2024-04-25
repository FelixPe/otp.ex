defmodule :m_beam_ssa_private_append do
  use Bitwise
  import :lists, only: [foldl: 3, foldr: 3, keysort: 2,
                          map: 2, reverse: 1]
  require Record
  Record.defrecord(:r_b_module, :b_module, anno: %{},
                                    name: :undefined, exports: :undefined,
                                    attributes: :undefined, body: :undefined)
  Record.defrecord(:r_b_function, :b_function, anno: %{},
                                      args: :undefined, bs: :undefined,
                                      cnt: :undefined)
  Record.defrecord(:r_b_blk, :b_blk, anno: %{}, is: :undefined,
                                 last: :undefined)
  Record.defrecord(:r_b_set, :b_set, anno: %{}, dst: :none,
                                 op: :undefined, args: [])
  Record.defrecord(:r_b_ret, :b_ret, anno: %{}, arg: :undefined)
  Record.defrecord(:r_b_br, :b_br, anno: %{}, bool: :undefined,
                                succ: :undefined, fail: :undefined)
  Record.defrecord(:r_b_switch, :b_switch, anno: %{},
                                    arg: :undefined, fail: :undefined,
                                    list: :undefined)
  Record.defrecord(:r_b_var, :b_var, name: :undefined)
  Record.defrecord(:r_b_literal, :b_literal, val: :undefined)
  Record.defrecord(:r_b_remote, :b_remote, mod: :undefined,
                                    name: :undefined, arity: :undefined)
  Record.defrecord(:r_b_local, :b_local, name: :undefined,
                                   arity: :undefined)
  Record.defrecord(:r_func_info, :func_info, in: :ordsets.new(),
                                     out: :ordsets.new(), exported: true,
                                     arg_types: [], succ_types: [])
  Record.defrecord(:r_opt_st, :opt_st, ssa: :undefined,
                                  args: :undefined, cnt: :undefined,
                                  anno: :undefined)
  Record.defrecord(:r_t_atom, :t_atom, elements: :any)
  Record.defrecord(:r_t_bitstring, :t_bitstring, size_unit: 1,
                                       appendable: false)
  Record.defrecord(:r_t_bs_context, :t_bs_context, tail_unit: 1)
  Record.defrecord(:r_t_bs_matchable, :t_bs_matchable, tail_unit: 1)
  Record.defrecord(:r_t_float, :t_float, elements: :any)
  Record.defrecord(:r_t_fun, :t_fun, arity: :any, target: :any,
                                 type: :any)
  Record.defrecord(:r_t_integer, :t_integer, elements: :any)
  Record.defrecord(:r_t_number, :t_number, elements: :any)
  Record.defrecord(:r_t_map, :t_map, super_key: :any,
                                 super_value: :any)
  Record.defrecord(:r_t_cons, :t_cons, type: :any,
                                  terminator: :any)
  Record.defrecord(:r_t_list, :t_list, type: :any,
                                  terminator: :any)
  Record.defrecord(:r_t_tuple, :t_tuple, size: 0, exact: false,
                                   elements: %{})
  Record.defrecord(:r_t_union, :t_union, atom: :none, list: :none,
                                   number: :none, tuple_set: :none,
                                   other: :none)
  def opt(stMap, funcDb) do
    funs = (for f <- :maps.keys(stMap),
                  :erlang.is_map_key(f, funcDb), not is_nif(f, stMap) do
              f
            end)
    private_append(funs, stMap, funcDb)
  end

  defp private_append(funs, stMap0, funcDb) do
    appends = :maps.fold(fn fun, as, acc ->
                              (for a <- as do
                                 {fun, a}
                               end) ++ acc
                         end,
                           [], find_appends(funs, stMap0, %{}))
    defs = find_defs(appends, stMap0, funcDb)
    stMap = patch_appends(defs, appends, stMap0)
    {stMap, funcDb}
  end

  defp find_appends([f | funs], stMap, found0) do
    r_opt_st(ssa: linear) = :erlang.map_get(f, stMap)
    found = find_appends_blk(linear, f, found0)
    find_appends(funs, stMap, found)
  end

  defp find_appends([], _, found) do
    found
  end

  defp find_appends_blk([{_Lbl, r_b_blk(is: is)} | linear], fun, found0) do
    found = find_appends_is(is, fun, found0)
    find_appends_blk(linear, fun, found)
  end

  defp find_appends_blk([], _, found) do
    found
  end

  defp find_appends_is([r_b_set(dst: dst, op: :bs_create_bin,
               args: [r_b_literal(val: :append), _, lit = r_b_literal(val: <<>>) | _]) |
               is],
            fun, found0) do
    alreadyFound = :maps.get(fun, found0, [])
    found = Map.put(found0, fun,
                              [{:append, dst, lit} | alreadyFound])
    find_appends_is(is, fun, found)
  end

  defp find_appends_is([r_b_set(dst: dst, op: :bs_create_bin,
               args: [r_b_literal(val: :append), segmentInfo, var | _],
               anno: %{first_fragment_dies: dies} = anno) |
               is],
            fun, found0) do
    case (dies and is_unique(var,
                               anno) and is_appendable(anno, segmentInfo)) do
      true ->
        alreadyFound = :maps.get(fun, found0, [])
        found = Map.put(found0, fun,
                                  [{:append, dst, var} | alreadyFound])
        find_appends_is(is, fun, found)
      false ->
        find_appends_is(is, fun, found0)
    end
  end

  defp find_appends_is([_ | is], fun, found) do
    find_appends_is(is, fun, found)
  end

  defp find_appends_is([], _, found) do
    found
  end

  defp is_unique(var, anno) do
    :ordsets.is_element(var, :maps.get(:unique, anno, []))
  end

  defp is_appendable(anno, r_b_literal(val: [segmentUnit | _]))
      when is_integer(segmentUnit) do
    case (anno) do
      %{arg_types:
        %{2 => r_t_bitstring(appendable: true, size_unit: sizeUnit)}} ->
        rem(sizeUnit, segmentUnit) == 0
      _ ->
        false
    end
  end

  Record.defrecord(:r_def_st, :def_st, funcdb: :undefined,
                                  stmap: :undefined, defsdb: %{}, literals: %{},
                                  valuesdb: %{})
  defp find_defs(as, stMap, funcDb) do
    find_defs_1(as, r_def_st(funcdb: funcDb, stmap: stMap))
  end

  defp find_defs_1([{fun, {:append, dst, _Arg}} | work],
            defSt0 = r_def_st(stmap: stMap)) do
    %{^fun => r_opt_st(ssa: sSA, args: args)} = stMap
    {defsInFun, defSt} = defs_in_fun(fun, args, sSA, defSt0)
    valuesInFun = values_in_fun(fun, defSt)
    :skip
    track_value_in_fun([{dst, :self}], fun, work, defsInFun,
                         valuesInFun, defSt)
  end

  defp find_defs_1([{fun,
              {:track_call_argument, callee, element, idx}} |
               work],
            defSt0 = r_def_st(stmap: stMap)) do
    %{^fun => r_opt_st(ssa: sSA, args: args)} = stMap
    :skip
    {defsInFun, defSt1} = defs_in_fun(fun, args, sSA,
                                        defSt0)
    valuesInFun = values_in_fun(fun, defSt1)
    {vars, defSt} = get_call_arguments(callee, element, idx,
                                         defsInFun, fun, defSt1)
    :skip
    track_value_in_fun(vars, fun, work, defsInFun,
                         valuesInFun, defSt)
  end

  defp find_defs_1([{fun, {:track_result, element}} | work],
            defSt0 = r_def_st(stmap: stMap)) do
    %{^fun => r_opt_st(ssa: sSA, args: args)} = stMap
    {defsInFun, defSt1} = defs_in_fun(fun, args, sSA,
                                        defSt0)
    valuesInFun = values_in_fun(fun, defSt0)
    :skip
    {results, defSt} = get_results(sSA, element, fun,
                                     defSt1)
    :skip
    track_value_in_fun(results, fun, work, defsInFun,
                         valuesInFun, defSt)
  end

  defp find_defs_1([], defSt) do
    r_def_st(defSt, :literals)
  end

  defp get_results(sSA, element, fun, defSt) do
    get_results(sSA, [], element, fun, defSt)
  end

  defp get_results([{_, r_b_blk(last: r_b_ret(arg: r_b_var() = v))} | rest], acc,
            element, fun, defSt) do
    get_results(rest, [{v, element} | acc], element, fun,
                  defSt)
  end

  defp get_results([{lbl, r_b_blk(last: r_b_ret(arg: r_b_literal(val: lit)))} | rest],
            acc, element, fun, defSt0) do
    continue = (case (element) do
                  {:tuple_element, _, _} ->
                    is_tuple(lit)
                  :self ->
                    is_bitstring(lit)
                  {:hd, _} ->
                    is_list(lit) and lit !== []
                end)
    defSt = (cond do
               continue ->
                 add_literal(fun, {:ret, lbl, element}, defSt0)
               true ->
                 defSt0
             end)
    get_results(rest, acc, element, fun, defSt)
  end

  defp get_results([_ | rest], acc, element, fun, defSt) do
    get_results(rest, acc, element, fun, defSt)
  end

  defp get_results([], acc, _, _Fun, defSt) do
    {acc, defSt}
  end

  defp track_value_in_fun([{r_b_var() = v, element} | rest], fun, work, defs,
            valuesInFun, defSt0)
      when :erlang.is_map_key({v, element}, valuesInFun) do
    :skip
    track_value_in_fun(rest, fun, work, defs, valuesInFun,
                         defSt0)
  end

  defp track_value_in_fun([{r_b_var() = v, element} | rest], fun, work0, defs,
            valuesInFun0, defSt0 = r_def_st()) do
    :skip
    valuesInFun = Map.put(valuesInFun0, {v, element},
                                          :visited)
    case (defs) do
      %{^v => r_b_set(dst: ^v, op: op, args: args)} ->
        case ({op, args, element}) do
          {:bs_create_bin, [r_b_literal(val: :append), _, arg | _],
             :self} ->
            track_value_in_fun([{arg, :self} | rest], fun, work0,
                                 defs, valuesInFun, defSt0)
          {:bs_create_bin, [r_b_literal(val: :private_append), _, _ | _],
             :self} ->
            track_value_in_fun(rest, fun, work0, defs, valuesInFun,
                                 defSt0)
          {:bs_init_writable, _, :self} ->
            track_value_in_fun(rest, fun, work0, defs, valuesInFun,
                                 defSt0)
          {:call, [r_b_local() = callee | _Args], _} ->
            track_value_into_call(callee, element, fun, rest, work0,
                                    defs, valuesInFun, defSt0)
          {:call,
             [r_b_remote(mod: r_b_literal(val: :erlang), name: r_b_literal(val: :error),
                  arity: 1) |
                  _Args],
             _} ->
            track_value_in_fun(rest, fun, work0, defs, valuesInFun,
                                 defSt0)
          {:get_hd, [list], _} ->
            track_value_in_fun([{list, {:hd, element}} | rest], fun,
                                 work0, defs, valuesInFun, defSt0)
          {:get_tuple_element, [r_b_var() = tuple, r_b_literal(val: idx)], _} ->
            track_value_in_fun([{tuple,
                                   {:tuple_element, idx, element}} |
                                    rest],
                                 fun, work0, defs, valuesInFun, defSt0)
          {:phi, _, _} ->
            {toExplore, defSt} = handle_phi(fun, v, args, element,
                                              defSt0)
            track_value_in_fun(toExplore ++ rest, fun, work0, defs,
                                 valuesInFun, defSt)
          {:put_tuple, _, _} when element !== :self ->
            track_put_tuple(args, element, rest, fun, v, work0,
                              defs, valuesInFun, defSt0)
          {:put_list, _, _} when element !== :self ->
            track_put_list(args, element, rest, fun, v, work0, defs,
                             valuesInFun, defSt0)
          {_, _, _} ->
            track_value_in_fun(rest, fun, work0, defs, valuesInFun,
                                 defSt0)
        end
      %{^v => {:arg, idx}} ->
        track_value_into_caller(element, idx, rest, fun, work0,
                                  defs, valuesInFun, defSt0)
    end
  end

  defp track_value_in_fun([{r_b_literal(), _} | rest], fun, work, defs, valuesInFun,
            defSt) do
    track_value_in_fun(rest, fun, work, defs, valuesInFun,
                         defSt)
  end

  defp track_value_in_fun([], fun, work, _Defs, valuesInFun,
            defSt0 = r_def_st(valuesdb: valuesDb0)) do
    defSt = r_def_st(defSt0, valuesdb: Map.put(valuesDb0, fun,
                                                     valuesInFun))
    find_defs_1(work, defSt)
  end

  defp track_value_into_call(callee, element, callerFun, callerWork,
            globalWork0, callerDefs, callerValuesInFun, defSt0) do
    globalWork = [{callee, {:track_result, element}} |
                      globalWork0]
    track_value_in_fun(callerWork, callerFun, globalWork,
                         callerDefs, callerValuesInFun, defSt0)
  end

  defp track_value_into_caller(element, argIdx, calledFunWorklist, calledFun,
            globalWorklist0, calledFunDefs, calledFunValues,
            defSt0 = r_def_st(funcdb: funcDb, stmap: stMap)) do
    r_func_info(in: callers) = :erlang.map_get(calledFun, funcDb)
    :skip
    work = (for caller <- callers,
                  :erlang.is_map_key(caller, stMap) do
              {caller,
                 {:track_call_argument, calledFun, element, argIdx}}
            end)
    globalWorklist = work ++ globalWorklist0
    track_value_in_fun(calledFunWorklist, calledFun,
                         globalWorklist, calledFunDefs, calledFunValues, defSt0)
  end

  defp track_put_tuple(fieldVars, {:tuple_element, idx, element}, work,
            fun, dst, globalWork, defs, valuesInFun, defSt0) do
    case (:lists.nth(idx + 1, fieldVars)) do
      toTrack = r_b_var() ->
        track_value_in_fun([{toTrack, element} | work], fun,
                             globalWork, defs, valuesInFun, defSt0)
      r_b_literal(val: lit) ->
        defSt = add_literal(fun,
                              {:opargs, dst, idx, lit, element}, defSt0)
        track_value_in_fun(work, fun, globalWork, defs,
                             valuesInFun, defSt)
    end
  end

  defp track_put_tuple(_FieldVars, {:hd, _}, work, fun, _Dst,
            globalWork, defs, valuesInFun, defSt) do
    track_value_in_fun(work, fun, globalWork, defs,
                         valuesInFun, defSt)
  end

  defp track_put_list([hd, _Tl], {:hd, element}, work, fun, dst,
            globalWork, defs, valuesInFun, defSt0) do
    case (hd) do
      r_b_var() ->
        track_value_in_fun([{hd, element} | work], fun,
                             globalWork, defs, valuesInFun, defSt0)
      r_b_literal(val: lit) ->
        defSt = add_literal(fun,
                              {:opargs, dst, 0, lit, element}, defSt0)
        track_value_in_fun(work, fun, globalWork, defs,
                             valuesInFun, defSt)
    end
  end

  defp track_put_list([_Hd, _Tl], {:tuple_element, _, _}, work, fun,
            _Dst, globalWork, defs, valuesInFun, defSt) do
    track_value_in_fun(work, fun, globalWork, defs,
                         valuesInFun, defSt)
  end

  defp get_call_arguments(callee, element, idx, defs, fun, defSt0) do
    :maps.fold(fn _,
                    r_b_set(dst: dst, op: :call, args: [target | args]),
                    {acc, defSt}
                      when callee === target ->
                    {values, defSt1} = gca(args, element, idx, fun, dst,
                                             defSt)
                    {values ++ acc, defSt1}
                  _, _, acc ->
                    acc
               end,
                 {[], defSt0}, defs)
  end

  defp gca(args, element, idx, fun, dst, defSt) do
    gca(args, 0, element, idx, fun, dst, defSt)
  end

  defp gca([r_b_var() = v | _], i, element, i, _Fun, _Dst,
            defSt) do
    {[{v, element}], defSt}
  end

  defp gca([r_b_literal(val: lit) | _], i, :self, i, _Fun, _Dst,
            defSt)
      when not is_bitstring(lit) do
    {[], defSt}
  end

  defp gca([r_b_literal(val: lit) | _], i, element, i, fun, dst,
            defSt) do
    {[],
       add_literal(fun, {:opargs, dst, i + 1, lit, element},
                     defSt)}
  end

  defp gca([_ | args], i, element, idx, fun, dst, defSt) do
    gca(args, i + 1, element, idx, fun, dst, defSt)
  end

  defp handle_phi(fun, dst, args, element, defSt0) do
    foldl(fn {r_b_literal(val: lit), lbl}, {acc, defStAcc0} ->
               defStAcc = add_literal(fun,
                                        {:phi, dst, lbl, lit, element},
                                        defStAcc0)
               {acc, defStAcc}
             {v = r_b_var(), _Lbl}, {acc, defStAcc} ->
               {[{v, element} | acc], defStAcc}
          end,
            {[], defSt0}, args)
  end

  defp defs_in_fun(fun, args, sSA, defSt = r_def_st(defsdb: defsDb)) do
    case (defsDb) do
      %{^fun => defs} ->
        {defs, defSt}
      %{} ->
        blockMap = :maps.from_list(sSA)
        labels = :maps.keys(blockMap)
        defs0 = :beam_ssa.definitions(labels, blockMap)
        {defs, _} = foldl(fn arg, {acc, idx} ->
                               {Map.put(acc, arg, {:arg, idx}), idx + 1}
                          end,
                            {defs0, 0}, args)
        {defs, r_def_st(defSt, defsdb: Map.put(defsDb, fun, defs))}
    end
  end

  defp values_in_fun(fun, r_def_st(valuesdb: valuesDb)) do
    :maps.get(fun, valuesDb, %{})
  end

  defp add_literal(fun, litInfo, defSt = r_def_st(literals: ls)) do
    old = :maps.get(fun, ls, [])
    r_def_st(defSt, literals: Map.put(ls, fun, [litInfo | old]))
  end

  defp patch_appends(bins, appends, stMap0) do
    :skip
    :skip
    patches = foldl(fn {fun, append}, acc ->
                         Map.put(acc, fun, [append | :maps.get(fun, acc, [])])
                    end,
                      bins, appends)
    :skip
    :maps.fold(fn fun, ps, stMapAcc ->
                    optSt = (r_opt_st(ssa: sSA0, cnt: cnt0) = :erlang.map_get(fun,
                                                                         stMapAcc))
                    {sSA, cnt} = patch_appends_f(sSA0, cnt0, ps)
                    Map.put(stMapAcc, fun, r_opt_st(optSt, ssa: sSA,  cnt: cnt))
               end,
                 stMap0, patches)
  end

  defp patch_appends_f(sSA0, cnt0, patches) do
    :skip
    :skip
    pD = foldl(fn p, acc ->
                    case (p) do
                      {:opargs, dst, _, _, _} ->
                        :ok
                      {:append, dst, _} ->
                        :ok
                      {:phi, dst, _, _, _} ->
                        :ok
                      {:ret, dst, _} ->
                        :ok
                    end
                    set = :ordsets.add_element(p, :maps.get(dst, acc, []))
                    Map.put(acc, dst, set)
               end,
                 %{}, patches)
    :skip
    patch_appends_f(sSA0, cnt0, pD, [], [])
  end

  defp patch_appends_f([{lbl, blk = r_b_blk(is: is0, last: last0)} | rest],
            cnt0, pD0, acc0, blockAdditions0) do
    {last, extra, cnt2, pD} = (case (pD0) do
                                 %{^lbl => patches} ->
                                   {last1, extra0,
                                      cnt1} = patch_appends_ret(last0, patches,
                                                                  cnt0)
                                   {last1, reverse(extra0), cnt1,
                                      :maps.remove(lbl, pD0)}
                                 %{} ->
                                   {last0, [], cnt0, pD0}
                               end)
    {is, cnt, blockAdditions} = patch_appends_is(is0, pD,
                                                   cnt2, [], [])
    acc = [{lbl, r_b_blk(blk, is: is ++ extra,  last: last)} |
               acc0]
    patch_appends_f(rest, cnt, pD, acc,
                      blockAdditions ++ blockAdditions0)
  end

  defp patch_appends_f([], cnt, _PD, acc, blockAdditions) do
    :skip
    linear = insert_block_additions(acc,
                                      :maps.from_list(blockAdditions), [])
    :skip
    {linear, cnt}
  end

  defp patch_appends_is([i0 = r_b_set(dst: dst) | rest], pD0, cnt0, acc,
            blockAdditions0)
      when :erlang.is_map_key(dst, pD0) do
    %{^dst => patches} = pD0
    pD = :maps.remove(dst, pD0)
    extractOpargs = fn {:opargs, d, idx, lit, element}
                           when dst === d ->
                         {idx, lit, element}
                    end
    case (patches) do
      [{:opargs, ^dst, _, _, _} | _] ->
        ps = keysort(1, map(extractOpargs, patches))
        {is, cnt} = patch_opargs(i0, ps, cnt0)
        patch_appends_is(rest, pD, cnt, is ++ acc,
                           blockAdditions0)
      [{:append, ^dst, r_b_literal(val: <<>>) = lit}] ->
        r_b_set(op: :bs_create_bin, dst: ^dst, args: args0) = i0
        [r_b_literal(val: :append), segInfo, ^lit | otherArgs] = args0
        {v, cnt} = new_var(cnt0)
        init = r_b_set(op: :bs_init_writable, dst: v,
                   args: [r_b_literal(val: 256)])
        i = r_b_set(i0, args: [r_b_literal(val: :private_append), segInfo, v |
                                                               otherArgs])
        patch_appends_is(rest, pD, cnt, [i, init | acc],
                           blockAdditions0)
      [{:append, ^dst, _}] ->
        r_b_set(op: :bs_create_bin, dst: ^dst, args: args0) = i0
        [r_b_literal(val: :append) | otherArgs] = args0
        i = r_b_set(i0, args: [r_b_literal(val: :private_append) | otherArgs])
        patch_appends_is(rest, pD, cnt0, [i | acc],
                           blockAdditions0)
      [{:phi, ^dst, _, _, _} | _] ->
        {i, extra, cnt} = patch_phi(i0, patches, cnt0)
        patch_appends_is(rest, pD, cnt, [i | acc],
                           extra ++ blockAdditions0)
    end
  end

  defp patch_appends_is([i | rest], pD, cnt, acc, blockAdditions) do
    patch_appends_is(rest, pD, cnt, [i | acc],
                       blockAdditions)
  end

  defp patch_appends_is([], _, cnt, acc, blockAdditions) do
    {reverse(acc), cnt, blockAdditions}
  end

  defp patch_appends_ret(last = r_b_ret(arg: r_b_literal(val: lit)), patches, cnt0)
      when is_list(lit) or is_tuple(lit) do
    ps = keysort(1,
                   for {:ret, _, e} <- patches do
                     e
                   end)
    :skip
    {v, extra, cnt} = patch_literal_term(lit, ps, cnt0)
    {r_b_ret(last, arg: v), extra, cnt}
  end

  defp patch_appends_ret(last = r_b_ret(arg: r_b_literal(val: lit)),
            [{:ret, _, element}], cnt0) do
    :skip
    {v, extra, cnt} = patch_literal_term(lit, element, cnt0)
    {r_b_ret(last, arg: v), extra, cnt}
  end

  defp patch_opargs(i0 = r_b_set(args: args), patches0, cnt0) do
    :skip
    patches = merge_arg_patches(patches0)
    {patchedArgs, is, cnt} = patch_opargs(args, patches, 0,
                                            [], [], cnt0)
    {[r_b_set(i0, args: reverse(patchedArgs)) | is], cnt}
  end

  defp patch_opargs([r_b_literal(val: lit) | args],
            [{idx, lit, element} | patches], idx, patchedArgs, is,
            cnt0) do
    :skip
    {arg, extra, cnt} = patch_literal_term(lit, element,
                                             cnt0)
    patch_opargs(args, patches, idx + 1,
                   [arg | patchedArgs], extra ++ is, cnt)
  end

  defp patch_opargs([arg | args], patches, idx, patchedArgs, is,
            cnt) do
    :skip
    patch_opargs(args, patches, idx + 1,
                   [arg | patchedArgs], is, cnt)
  end

  defp patch_opargs([], [], _, patchedArgs, is, cnt) do
    {patchedArgs, is, cnt}
  end

  defp merge_arg_patches([{idx, lit, p0}, {idx, lit, p1} | patches]) do
    p = (case ({p0, p1}) do
           {{:tuple_element, i0, e0}, {:tuple_element, i1, e1}} ->
             {:tuple_elements, [{i0, e0}, {i1, e1}]}
           {{:tuple_elements, es}, {:tuple_element, i, e}} ->
             {:tuple_elements, [{i, e} | es]}
           {_, _} ->
             [p0 | merge_arg_patches([p1 | patches])]
         end)
    merge_arg_patches([{idx, lit, p} | patches])
  end

  defp merge_arg_patches([p | patches]) do
    [p | merge_arg_patches(patches)]
  end

  defp merge_arg_patches([]) do
    []
  end

  defp patch_phi(i0 = r_b_set(op: :phi, args: args0), patches, cnt0) do
    l2P = foldl(fn phi = {:phi, _, lbl, _, _}, acc ->
                     Map.put(acc, lbl, phi)
                end,
                  %{}, patches)
    {args, extra, cnt} = foldr(fn arg0 = {_, lbl},
                                    {argsAcc, extraAcc, cntAcc} ->
                                    case (l2P) do
                                      %{^lbl
                                        =>
                                        {:phi, _, ^lbl, lit, element}} ->
                                        {arg, extra,
                                           cnt1} = patch_literal_term(lit,
                                                                        element,
                                                                        cntAcc)
                                        {[{arg, lbl} | argsAcc],
                                           [{lbl, extra} | extraAcc], cnt1}
                                      _ ->
                                        {[arg0 | argsAcc], extraAcc, cntAcc}
                                    end
                               end,
                                 {[], [], cnt0}, args0)
    i = r_b_set(i0, op: :phi,  args: args)
    {i, extra, cnt}
  end

  defp patch_literal_term(tuple, {:tuple_elements, elems}, cnt) do
    es = (for {i, e} <- keysort(1, elems) do
            {:tuple_element, i, e}
          end)
    patch_literal_tuple(tuple, es, cnt)
  end

  defp patch_literal_term(tuple, elements0, cnt) when is_tuple(tuple) do
    elements = (cond do
                  is_list(elements0) ->
                    elements0
                  true ->
                    [elements0]
                end)
    patch_literal_tuple(tuple, elements, cnt)
  end

  defp patch_literal_term(<<>>, :self, cnt0) do
    {v, cnt} = new_var(cnt0)
    i = r_b_set(op: :bs_init_writable, dst: v,
            args: [r_b_literal(val: 256)])
    {v, [i], cnt}
  end

  defp patch_literal_term(lit, :self, cnt) do
    {r_b_literal(val: lit), [], cnt}
  end

  defp patch_literal_term([h0 | t0], {:hd, element}, cnt0) do
    {h, extra, cnt1} = patch_literal_term(h0, element, cnt0)
    {t, [], ^cnt1} = patch_literal_term(t0, [], cnt1)
    {dst, cnt} = new_var(cnt1)
    i = r_b_set(op: :put_list, dst: dst, args: [h, t])
    {dst, [i | extra], cnt}
  end

  defp patch_literal_term([_ | _] = pair, elems, cnt)
      when is_list(elems) do
    [elem] = (for ({:hd, _} = e) <- elems do
                e
              end)
    patch_literal_term(pair, elem, cnt)
  end

  defp patch_literal_term(lit, [], cnt) do
    {r_b_literal(val: lit), [], cnt}
  end

  defp patch_literal_tuple(tuple, elements0, cnt) do
    :skip
    elements = (for ({:tuple_element, _,
                        _} = e) <- elements0 do
                  e
                end)
    patch_literal_tuple(:erlang.tuple_to_list(tuple),
                          elements, [], [], 0, cnt)
  end

  defp patch_literal_tuple([lit | litElements],
            [{:tuple_element, idx, element} | elements], patched,
            extra, idx, cnt0) do
    :skip
    {v, exs, cnt} = patch_literal_term(lit, element, cnt0)
    patch_literal_tuple(litElements, elements,
                          [v | patched], exs ++ extra, idx + 1, cnt)
  end

  defp patch_literal_tuple([lit | litElements], patches, patched, extra,
            idx, cnt) do
    :skip
    {t, [], ^cnt} = patch_literal_term(lit, [], cnt)
    patch_literal_tuple(litElements, patches, [t | patched],
                          extra, idx + 1, cnt)
  end

  defp patch_literal_tuple([], [], patched, extra, _, cnt0) do
    {v, cnt} = new_var(cnt0)
    i = r_b_set(op: :put_tuple, dst: v, args: reverse(patched))
    {v, [i | extra], cnt}
  end

  defp new_var(count) do
    {r_b_var(name: {:alias_opt, count}), count + 1}
  end

  defp insert_block_additions([blk0 = {l, b = r_b_blk(is: is0)} | revLinear],
            lbl2Addition, acc) do
    blk = (case (lbl2Addition) do
             %{^l => additions} ->
               is = is0 ++ reverse(additions)
               {l, r_b_blk(b, is: is)}
             _ ->
               blk0
           end)
    insert_block_additions(revLinear, lbl2Addition,
                             [blk | acc])
  end

  defp insert_block_additions([], _, acc) do
    acc
  end

  defp is_nif(f, stMap) do
    r_opt_st(ssa: [{0, r_b_blk(is: is)} | _]) = :erlang.map_get(f, stMap)
    case (is) do
      [r_b_set(op: :nif_start) | _] ->
        true
      _ ->
        false
    end
  end

end