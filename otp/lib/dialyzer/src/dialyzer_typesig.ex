defmodule :m_dialyzer_typesig do
  use Bitwise
  import :erl_types, only: [t_any: 0, t_atom: 0,
                              t_atom_vals: 1, t_binary: 0, t_bitstr: 0,
                              t_bitstr: 2, t_bitstr_concat: 1, t_boolean: 0,
                              t_collect_var_names: 1, t_cons: 2, t_cons_hd: 1,
                              t_cons_tl: 1, t_float: 0, t_from_range: 2,
                              t_from_term: 1, t_fun: 0, t_fun: 2, t_fun_args: 1,
                              t_fun_range: 1, t_has_var: 1, t_inf: 2,
                              t_integer: 0, t_is_any: 1, t_is_any_atom: 2,
                              t_is_atom: 1, t_is_cons: 1, t_is_equal: 2,
                              t_is_float: 1, t_is_fun: 1, t_is_impossible: 1,
                              t_is_integer: 1, t_is_list: 1, t_is_nil: 1,
                              t_is_none: 1, t_is_number: 1, t_is_singleton: 1,
                              t_is_subtype: 2, t_limit: 2, t_list: 0, t_list: 1,
                              t_list_elements: 1, t_map: 0, t_map: 1,
                              t_map_get: 2, t_map_put: 2,
                              t_maybe_improper_list: 0, t_module: 0,
                              t_non_neg_integer: 0, t_none: 0,
                              t_nonempty_list: 1, t_number: 0, t_number_vals: 1,
                              t_pid: 0, t_port: 0, t_product: 1, t_reference: 0,
                              t_subst: 2, t_subtract: 2, t_subtract_list: 2,
                              t_sup: 1, t_sup: 2, t_timeout: 0, t_tuple: 0,
                              t_tuple: 1, t_unify_table_only: 2, t_unit: 0,
                              t_var: 1, t_var_name: 1]
  require Record
  Record.defrecord(:r_plt_info, :plt_info, files: :undefined,
                                    mod_deps: :dict.new())
  Record.defrecord(:r_iplt_info, :iplt_info, files: :undefined,
                                     mod_deps: :dict.new(), warning_map: :none,
                                     legal_warnings: :none)
  Record.defrecord(:r_plt, :plt, info: :undefined,
                               types: :undefined, contracts: :undefined,
                               callbacks: :undefined,
                               exported_types: :undefined)
  Record.defrecord(:r_analysis, :analysis, analysis_pid: :undefined,
                                    type: :succ_typings, defines: [],
                                    doc_plt: :undefined, files: [],
                                    include_dirs: [], start_from: :byte_code,
                                    plt: :undefined, use_contracts: true,
                                    behaviours_chk: false, timing: false,
                                    timing_server: :none, callgraph_file: '',
                                    mod_deps_file: '', solvers: :undefined)
  Record.defrecord(:r_options, :options, files: [], files_rec: [],
                                   warning_files: [], warning_files_rec: [],
                                   analysis_type: :succ_typings, timing: false,
                                   defines: [], from: :byte_code,
                                   get_warnings: :maybe, init_plts: [],
                                   include_dirs: [], output_plt: :none,
                                   legal_warnings: :ordsets.new(),
                                   report_mode: :normal, erlang_mode: false,
                                   use_contracts: true, output_file: :none,
                                   output_format: :formatted,
                                   filename_opt: :basename, indent_opt: true,
                                   callgraph_file: '', mod_deps_file: '',
                                   check_plt: true, error_location: :column,
                                   metrics_file: :none,
                                   module_lookup_file: :none, solvers: [])
  Record.defrecord(:r_contract, :contract, contracts: [], args: [],
                                    forms: [])
  Record.defrecord(:r_fun_var, :fun_var, "fun": :undefined,
                                   deps: :undefined, origin: :undefined)
  Record.defrecord(:r_constraint, :constraint, lhs: :undefined,
                                      op: :undefined, rhs: :undefined,
                                      deps: :undefined)
  Record.defrecord(:r_constraint_list, :constraint_list, type: :undefined,
                                           list: :undefined, deps: :undefined,
                                           masks: :undefined, id: :undefined)
  Record.defrecord(:r_constraint_ref, :constraint_ref, id: :undefined,
                                          deps: :undefined)
  Record.defrecord(:r_state, :state, callgraph: :undefined,
                                 cserver: :undefined, cs: [], cmap: :maps.new(),
                                 fun_map: :maps.new(), fun_arities: :maps.new(),
                                 in_match: false, in_guard: false,
                                 module: :undefined, name_map: :maps.new(),
                                 next_label: 0, self_rec: :undefined,
                                 plt: :undefined, prop_types: %{},
                                 mod_records: [], scc: [], mfas: :undefined,
                                 solvers: [])
  def analyze_scc(sCC, nextLabel, callGraph, cServer, plt,
           propTypes, solvers0) do
    solvers = solvers(solvers0)
    state1 = new_state(sCC, nextLabel, callGraph, cServer,
                         plt, propTypes, solvers)
    defSet = add_def_list(:maps.values(r_state(state1, :name_map)),
                            :sets.new([{:version, 2}]))
    state2 = traverse_scc(sCC, cServer, defSet, state1)
    state3 = state__finalize(state2)
    funs = state__scc(state3)
    pp_constrs_scc(funs, state3)
    constraints_to_dot_scc(funs, state3)
    t = solve(funs, state3)
    :orddict.from_list(:maps.to_list(t))
  end

  defp solvers([]) do
    [:v2]
  end

  defp solvers(solvers) do
    solvers
  end

  defp traverse_scc([{m, _, _} = mFA | left], codeserver, defSet,
            accState) do
    tmpState1 = state__set_module(accState, m)
    def__ = :dialyzer_codeserver.lookup_mfa_code(mFA,
                                                   codeserver)
    dummyLetrec = :cerl.c_letrec([def__],
                                   :cerl.c_atom(:foo))
    tmpState2 = state__new_constraint_context(tmpState1)
    {newAccState, _} = traverse(dummyLetrec, defSet,
                                  tmpState2)
    traverse_scc(left, codeserver, defSet, newAccState)
  end

  defp traverse_scc([], _Codeserver, _DefSet, accState) do
    accState
  end

  defp traverse_list(trees, definedVars, state) do
    traverse_list(trees, definedVars, state, [])
  end

  defp traverse_list([tree | tail], definedVars, state, acc) do
    {state1, var} = traverse(tree, definedVars, state)
    traverse_list(tail, definedVars, state1, [var | acc])
  end

  defp traverse_list([], _DefinedVars, state, acc) do
    {state, :lists.reverse(acc)}
  end

  defp add_def(var, set) do
    :sets.add_element(:cerl_trees.get_label(var), set)
  end

  defp add_def_list([h | t], set) do
    add_def_list(t, add_def(h, set))
  end

  defp add_def_list([], set) do
    set
  end

  defp add_def_from_tree(t, definedVars) do
    :cerl_trees.fold(fn x, set ->
                          case (:cerl.is_c_var(x)) do
                            true ->
                              add_def(x, set)
                            false ->
                              set
                          end
                     end,
                       definedVars, t)
  end

  defp add_def_from_tree_list([h | t], definedVars) do
    add_def_from_tree_list(t,
                             add_def_from_tree(h, definedVars))
  end

  defp add_def_from_tree_list([], definedVars) do
    definedVars
  end

  defp is_def(var, set) do
    :sets.is_element(:cerl_trees.get_label(var), set)
  end

  defp handle_try(tree, definedVars, state) do
    arg = :cerl.try_arg(tree)
    vars = :cerl.try_vars(tree)
    eVars = :cerl.try_evars(tree)
    body = :cerl.try_body(tree)
    handler = :cerl.try_handler(tree)
    state1 = state__new_constraint_context(state)
    {argBodyState, bodyVar} = (try do
                                 {state2, argVar} = traverse(arg, definedVars,
                                                               state1)
                                 definedVars1 = add_def_list(vars, definedVars)
                                 {state3, bodyVar1} = traverse(body,
                                                                 definedVars1,
                                                                 state2)
                                 state4 = state__store_conj(t_product(mk_var_list(vars)),
                                                              :eq, argVar,
                                                              state3)
                                 {state4, bodyVar1}
                               catch
                                 :error ->
                                   {state1, t_none()}
                               end)
    state6 = state__new_constraint_context(argBodyState)
    {handlerState, handlerVar} = (try do
                                    definedVars2 = add_def_list(for x <- eVars,
                                                                      :cerl.is_c_var(x) do
                                                                  x
                                                                end,
                                                                  definedVars)
                                    traverse(handler, definedVars2, state6)
                                  catch
                                    :error ->
                                      {state6, t_none()}
                                  end)
    argBodyCs = state__cs(argBodyState)
    handlerCs = state__cs(handlerState)
    treeVar = mk_var(tree)
    oldCs = state__cs(state)
    case (state__is_in_guard(state)) do
      true ->
        conj1 = mk_conj_constraint_list([argBodyCs,
                                             mk_constraint(bodyVar, :eq,
                                                             treeVar)])
        disj = mk_disj_constraint_list([conj1,
                                            mk_constraint(handlerVar, :eq,
                                                            treeVar)])
        newState1 = state__new_constraint_context(handlerState)
        conj2 = mk_conj_constraint_list([oldCs, disj])
        newState2 = state__store_conj(conj2, newState1)
        {newState2, treeVar}
      false ->
        {newCs, returnVar} = (case ({t_is_none(bodyVar),
                                       t_is_none(handlerVar)}) do
                                {false, false} ->
                                  conj1 = mk_conj_constraint_list([argBodyCs,
                                                                       mk_constraint(treeVar,
                                                                                       :eq,
                                                                                       bodyVar)])
                                  conj2 = mk_conj_constraint_list([handlerCs,
                                                                       mk_constraint(treeVar,
                                                                                       :eq,
                                                                                       handlerVar)])
                                  disj = mk_disj_constraint_list([conj1, conj2])
                                  {disj, treeVar}
                                {false, true} ->
                                  {mk_conj_constraint_list([argBodyCs,
                                                                mk_constraint(treeVar,
                                                                                :eq,
                                                                                bodyVar)]),
                                     bodyVar}
                                {true, false} ->
                                  {mk_conj_constraint_list([handlerCs,
                                                                mk_constraint(treeVar,
                                                                                :eq,
                                                                                handlerVar)]),
                                     handlerVar}
                                {true, true} ->
                                  :ok
                                  throw(:error)
                              end)
        conj = mk_conj_constraint_list([oldCs, newCs])
        newState1 = state__new_constraint_context(handlerState)
        newState2 = state__store_conj(conj, newState1)
        {newState2, returnVar}
    end
  end

  defp handle_call(call, definedVars, state) do
    args = :cerl.call_args(call)
    mod = :cerl.call_module(call)
    fun = :cerl.call_name(call)
    dst = mk_var(call)
    case (:cerl.is_c_atom(mod) and :cerl.is_c_atom(fun)) do
      true ->
        m = :cerl.atom_val(mod)
        f = :cerl.atom_val(fun)
        a = length(args)
        mFA = {m, f, a}
        {state1, argVars} = traverse_list(args, definedVars,
                                            state)
        case (state__lookup_rec_var_in_scope(mFA, state)) do
          :error ->
            case (get_bif_constr(mFA, dst, argVars, state1)) do
              :none ->
                {get_plt_constr(mFA, dst, argVars, state1), dst}
              c ->
                {state__store_conj(c, state1), dst}
            end
          {:ok, var} ->
            :ok
            label = :cerl_trees.get_label(call)
            apply = :cerl.ann_c_apply([{:label, label}], var, args)
            traverse(apply, definedVars, state)
        end
      false ->
        {state1, mF} = traverse_list([mod, fun], definedVars,
                                       state)
        {state__store_conj_lists(mF, :sub,
                                   [t_module(), t_atom()], state1),
           dst}
    end
  end

  defp get_plt_constr(mFA, dst, argVars, state) do
    plt = state__plt(state)
    pltRes = :dialyzer_plt.lookup(plt, mFA)
    sCCMFAs = r_state(state, :mfas)
    contract = (case (:lists.member(mFA, sCCMFAs)) do
                  true ->
                    :none
                  false ->
                    :dialyzer_plt.lookup_contract(plt, mFA)
                end)
    case (contract) do
      :none ->
        case (pltRes) do
          :none ->
            state
          {:value, {pltRetType, pltArgTypes}} ->
            state__store_conj_lists([dst | argVars], :sub,
                                      [pltRetType | pltArgTypes], state)
        end
      {:value, r_contract(args: genArgs) = c} ->
        {retType, argCs} = (case (pltRes) do
                              :none ->
                                {mk_fun_var(fn map ->
                                                 argTypes = lookup_type_list(argVars,
                                                                               map)
                                                 get_contract_return(c,
                                                                       argTypes)
                                            end,
                                              argVars),
                                   genArgs}
                              {:value, {pltRetType, pltArgTypes}} ->
                                {mk_fun_var(fn map ->
                                                 argTypes = lookup_type_list(argVars,
                                                                               map)
                                                 cRet = get_contract_return(c,
                                                                              argTypes)
                                                 t_inf(cRet, pltRetType)
                                            end,
                                              argVars),
                                   for {x, y} <- :lists.zip(genArgs,
                                                              pltArgTypes) do
                                     t_inf(x, y)
                                   end}
                            end)
        state__store_conj_lists([dst | argVars], :sub,
                                  [retType | argCs], state)
    end
  end

  defp get_contract_return(c, argTypes) do
    :dialyzer_contracts.get_contract_return(c, argTypes)
  end

  defp handle_clauses(clauses, topVar, arg, definedVars, state) do
    subtrTypeList = (cond do
                       length(clauses) > 15 ->
                         :overflow
                       true ->
                         []
                     end)
    {state1, cList} = handle_clauses_1(clauses, topVar, arg,
                                         definedVars, state, subtrTypeList, [])
    {newCs, newState} = (cond do
                           cList === [] ->
                             throw(:error)
                           true ->
                             {cList, state1}
                         end)
    oldCs = state__cs(state)
    newCList = mk_disj_constraint_list(newCs)
    finalState = state__new_constraint_context(newState)
    {state__store_conj_list([oldCs, newCList], finalState),
       topVar}
  end

  defp handle_clauses_1([clause | tail], topVar, arg, definedVars,
            state, subtrTypes, acc) do
    state0 = state__new_constraint_context(state)
    pats = :cerl.clause_pats(clause)
    guard = :cerl.clause_guard(clause)
    body = :cerl.clause_body(clause)
    newSubtrTypes = (case (subtrTypes) do
                       :overflow ->
                         :overflow
                       _ ->
                         :ordsets.add_element(get_safe_underapprox(pats, guard),
                                                subtrTypes)
                     end)
    try do
      definedVars1 = add_def_from_tree_list(pats, definedVars)
      state1 = state__set_in_match(state0, true)
      {state2, patVars} = traverse_list(pats, definedVars1,
                                          state1)
      s = state__store_conj(arg, :eq, t_product(patVars),
                              state2)
      state3 = (case (subtrTypes) do
                  :overflow ->
                    s
                  _ ->
                    subtrPatVar = mk_fun_var(fn map ->
                                                  tmpType = lookup_type(arg,
                                                                          map)
                                                  t_subtract_list(tmpType,
                                                                    subtrTypes)
                                             end,
                                               [arg])
                    state__store_conj(arg, :sub, subtrPatVar, s)
                end)
      state4 = handle_guard(guard, definedVars1, state3)
      {state5, bodyVar} = traverse(body, definedVars1,
                                     state__set_in_match(state4, false))
      state6 = state__store_conj(topVar, :eq, bodyVar, state5)
      cs = state__cs(state6)
      handle_clauses_1(tail, topVar, arg, definedVars, state6,
                         newSubtrTypes, [cs | acc])
    catch
      :error ->
        handle_clauses_1(tail, topVar, arg, definedVars, state,
                           newSubtrTypes, acc)
    end
  end

  defp handle_clauses_1([], _TopVar, _Arg, _DefinedVars, state,
            _SubtrType, acc) do
    {state__new_constraint_context(state), acc}
  end

  def get_safe_underapprox(pats, guard) do
    try do
      map1 = :cerl_trees.fold(fn x, acc ->
                                   case (:cerl.is_c_var(x)) do
                                     true ->
                                       :maps.put(:cerl_trees.get_label(x),
                                                   t_any(), acc)
                                     false ->
                                       acc
                                   end
                              end,
                                :maps.new(), :cerl.c_values(pats))
      {type, map2} = get_underapprox_from_guard(guard, map1)
      map3 = (case (t_is_none(t_inf(t_from_term(true),
                                      type))) do
                true ->
                  throw(:dont_know)
                false ->
                  case (:cerl.is_c_var(guard)) do
                    false ->
                      map2
                    true ->
                      :maps.put(:cerl_trees.get_label(guard),
                                  t_from_term(true), map2)
                  end
              end)
      {ts, _Map4} = get_safe_underapprox_1(pats, [], map3)
      t_product(ts)
    catch
      :dont_know ->
        t_none()
    end
  end

  defp get_underapprox_from_guard(tree, map) do
    true__ = t_from_term(true)
    case (:cerl.type(tree)) do
      :call ->
        case ({:cerl.concrete(:cerl.call_module(tree)),
                 :cerl.concrete(:cerl.call_name(tree)),
                 length(:cerl.call_args(tree))}) do
          {:erlang, :is_function, 2} ->
            [fun, arity] = :cerl.call_args(tree)
            case (:cerl.is_c_int(arity)) do
              false ->
                throw(:dont_know)
              true ->
                {funType, map1} = get_underapprox_from_guard(fun, map)
                inf = t_inf(funType,
                              t_fun(:cerl.int_val(arity), t_any()))
                case (t_is_none(inf)) do
                  true ->
                    throw(:dont_know)
                  false ->
                    {true__,
                       :maps.put(:cerl_trees.get_label(fun), inf, map1)}
                end
            end
          mFA ->
            case (get_type_test(mFA)) do
              {:ok, type} ->
                [arg0] = :cerl.call_args(tree)
                arg = :cerl.fold_literal(arg0)
                {argType, map1} = get_underapprox_from_guard(arg, map)
                inf = t_inf(type, argType)
                case (t_is_none(inf)) do
                  true ->
                    throw(:dont_know)
                  false ->
                    case (:cerl.is_literal(arg)) do
                      true ->
                        {true__, map1}
                      false ->
                        {true__,
                           :maps.put(:cerl_trees.get_label(arg), inf, map1)}
                    end
                end
              :error ->
                case (mFA) do
                  {:erlang, :"=:=", 2} ->
                    throw(:dont_know)
                  {:erlang, :"==", 2} ->
                    throw(:dont_know)
                  {:erlang, :and, 2} ->
                    [arg1_0, arg2_0] = :cerl.call_args(tree)
                    arg1 = :cerl.fold_literal(arg1_0)
                    arg2 = :cerl.fold_literal(arg2_0)
                    case ((:cerl.is_c_var(arg1) or :cerl.is_literal(arg1)) and (:cerl.is_c_var(arg2) or :cerl.is_literal(arg2))) do
                      true ->
                        {arg1Type, _} = get_underapprox_from_guard(arg1, map)
                        {arg2Type, _} = get_underapprox_from_guard(arg2, map)
                        case (t_is_equal(true__,
                                           arg1Type) and t_is_equal(true__,
                                                                      arg2Type)) do
                          true ->
                            {true__, map}
                          false ->
                            throw(:dont_know)
                        end
                      false ->
                        throw(:dont_know)
                    end
                  {:erlang, :or, 2} ->
                    throw(:dont_know)
                  _ ->
                    throw(:dont_know)
                end
            end
        end
      :var ->
        type = (case (:maps.find(:cerl_trees.get_label(tree),
                                   map)) do
                  :error ->
                    throw(:dont_know)
                  {:ok, t} ->
                    t
                end)
        {type, map}
      :literal ->
        case (:cerl.unfold_literal(tree)) do
          ^tree ->
            type = (case (:cerl.concrete(tree)) do
                      int when is_integer(int) ->
                        t_from_term(int)
                      atom when is_atom(atom) ->
                        t_from_term(atom)
                      _Other ->
                        throw(:dont_know)
                    end)
            {type, map}
          otherTree ->
            get_underapprox_from_guard(otherTree, map)
        end
      _ ->
        throw(:dont_know)
    end
  end

  defp get_type_test({:erlang, :is_atom, 1}) do
    {:ok, t_atom()}
  end

  defp get_type_test({:erlang, :is_boolean, 1}) do
    {:ok, t_boolean()}
  end

  defp get_type_test({:erlang, :is_binary, 1}) do
    {:ok, t_binary()}
  end

  defp get_type_test({:erlang, :is_bitstring, 1}) do
    {:ok, t_bitstr()}
  end

  defp get_type_test({:erlang, :is_float, 1}) do
    {:ok, t_float()}
  end

  defp get_type_test({:erlang, :is_function, 1}) do
    {:ok, t_fun()}
  end

  defp get_type_test({:erlang, :is_integer, 1}) do
    {:ok, t_integer()}
  end

  defp get_type_test({:erlang, :is_list, 1}) do
    {:ok, t_list()}
  end

  defp get_type_test({:erlang, :is_map, 1}) do
    {:ok, t_map()}
  end

  defp get_type_test({:erlang, :is_number, 1}) do
    {:ok, t_number()}
  end

  defp get_type_test({:erlang, :is_pid, 1}) do
    {:ok, t_pid()}
  end

  defp get_type_test({:erlang, :is_port, 1}) do
    {:ok, t_port()}
  end

  defp get_type_test({:erlang, :is_reference, 1}) do
    {:ok, t_reference()}
  end

  defp get_type_test({:erlang, :is_tuple, 1}) do
    {:ok, t_tuple()}
  end

  defp get_type_test({m, f, a}) when (is_atom(m) and is_atom(f) and
                             is_integer(a)) do
    :error
  end

  defp bitstr_constr(sizeType, unitVal) do
    bitstr_constr(sizeType, unitVal, :construct)
  end

  defp bitstr_constr(sizeType, unitVal, constructOrMatch) do
    unit = (case (constructOrMatch) do
              :construct ->
                0
              :match ->
                1
            end)
    fn map ->
         tmpSizeType = lookup_type(sizeType, map)
         case (t_is_integer(tmpSizeType) and t_is_subtype(tmpSizeType,
                                                            t_non_neg_integer())) do
           true ->
             case (t_number_vals(tmpSizeType)) do
               [oneSize] ->
                 t_bitstr(unit, oneSize * unitVal)
               _ ->
                 minSize = :erl_types.number_min(tmpSizeType)
                 t_bitstr(unitVal, minSize * unitVal)
             end
           false ->
             t_bitstr(unitVal, 0)
         end
    end
  end

  defp bitstr_val_constr(sizeType, unitVal, flags) do
    fn map ->
         tmpSizeType = lookup_type(sizeType, map)
         case (t_is_integer(tmpSizeType) and t_is_subtype(tmpSizeType,
                                                            t_non_neg_integer())) do
           true ->
             case (:erl_types.number_max(tmpSizeType)) do
               n when (is_integer(n) and n < 128) ->
                 totalSizeVal = n * unitVal
                 {rangeMin, rangeMax} = (case (:lists.member(:signed,
                                                               flags)) do
                                           true ->
                                             {- (1 <<< (totalSizeVal - 1)),
                                                1 <<< (totalSizeVal - 1) - 1}
                                           false ->
                                             {0, 1 <<< totalSizeVal - 1}
                                         end)
                 t_from_range(rangeMin, rangeMax)
               _ ->
                 t_integer()
             end
           false ->
             t_integer()
         end
    end
  end

  defp get_safe_underapprox_1([pat0 | left], acc, map) do
    pat = :dialyzer_utils.refold_pattern(pat0)
    case (:cerl.type(pat)) do
      :alias ->
        aPat = :cerl.alias_pat(pat)
        aVar = :cerl.alias_var(pat)
        {[varType], map1} = get_safe_underapprox_1([aVar], [],
                                                     map)
        {[patType], map2} = get_safe_underapprox_1([aPat], [],
                                                     map1)
        inf = t_inf(varType, patType)
        case (t_is_none(inf)) do
          true ->
            throw(:dont_know)
          false ->
            map3 = :maps.put(:cerl_trees.get_label(aVar), inf, map2)
            get_safe_underapprox_1(left, [inf | acc], map3)
        end
      :binary ->
        throw(:dont_know)
      :cons ->
        {[hd, tl],
           map1} = get_safe_underapprox_1([:cerl.cons_hd(pat),
                                               :cerl.cons_tl(pat)],
                                            [], map)
        case (t_is_any(tl)) do
          true ->
            get_safe_underapprox_1(left,
                                     [t_nonempty_list(hd) | acc], map1)
          false ->
            throw(:dont_know)
        end
      :literal ->
        case (:cerl.unfold_literal(pat)) do
          ^pat ->
            type = (case (:cerl.concrete(pat)) do
                      int when is_integer(int) ->
                        t_from_term(int)
                      atom when is_atom(atom) ->
                        t_from_term(atom)
                      [] ->
                        t_from_term([])
                      _Other ->
                        throw(:dont_know)
                    end)
            get_safe_underapprox_1(left, [type | acc], map)
          otherPat ->
            get_safe_underapprox_1([otherPat | left], acc, map)
        end
      :tuple ->
        es = :cerl.tuple_es(pat)
        {ts, map1} = get_safe_underapprox_1(es, [], map)
        type = t_tuple(ts)
        get_safe_underapprox_1(left, [type | acc], map1)
      :map ->
        true = %{} === :cerl.concrete(:cerl.map_arg(pat))
        true = :lists.all(fn p ->
                               :cerl.is_literal(op = :cerl.map_pair_op(p)) and :exact === :cerl.concrete(op)
                          end,
                            :cerl.map_es(pat))
        keyTrees = :lists.map(&:cerl.map_pair_key/1,
                                :cerl.map_es(pat))
        valTrees = :lists.map(&:cerl.map_pair_val/1,
                                :cerl.map_es(pat))
        keys = get_safe_overapprox(keyTrees)
        {vals, map1} = get_safe_underapprox_1(valTrees, [], map)
        case (:lists.all(&:erl_types.t_is_singleton/1, keys)) do
          false ->
            throw(:dont_know)
          true ->
            :ok
        end
        sortedPairs = :lists.sort(:lists.zip(keys, vals))
        squashDuplicates = fn squashDuplicates
                           [{k, first}, {k, second} | list] ->
                             case (t_is_none(inf = t_inf(first, second))) do
                               true ->
                                 throw(:dont_know)
                               false ->
                                 [{k, inf} | squashDuplicates.(list)]
                             end
                           [good | rest] ->
                             [good | squashDuplicates.(rest)]
                           [] ->
                             []
                           end
        type = t_map(squashDuplicates.(sortedPairs))
        get_safe_underapprox_1(left, [type | acc], map1)
      :values ->
        es = :cerl.values_es(pat)
        {ts, map1} = get_safe_underapprox_1(es, [], map)
        type = t_product(ts)
        get_safe_underapprox_1(left, [type | acc], map1)
      :var ->
        case (:maps.find(:cerl_trees.get_label(pat), map)) do
          :error ->
            throw(:dont_know)
          {:ok, varType} ->
            get_safe_underapprox_1(left, [varType | acc], map)
        end
    end
  end

  defp get_safe_underapprox_1([], acc, map) do
    {:lists.reverse(acc), map}
  end

  defp get_safe_overapprox(pats) do
    :lists.map(&get_safe_overapprox_1/1, pats)
  end

  defp get_safe_overapprox_1(pat) do
    case (:cerl.is_literal(lit = :cerl.fold_literal(pat))) do
      true ->
        t_from_term(:cerl.concrete(lit))
      false ->
        t_any()
    end
  end

  defp handle_guard(guard, definedVars, state) do
    true__ = t_from_term(true)
    state1 = state__set_in_guard(state, true)
    state2 = state__new_constraint_context(state1)
    {state3, return} = traverse(guard, definedVars, state2)
    state4 = state__store_conj(return, :eq, true__, state3)
    cs = state__cs(state4)
    newCs = mk_disj_norm_form(cs)
    oldCs = state__cs(state)
    state5 = state__set_in_guard(state4,
                                   state__is_in_guard(state))
    state6 = state__new_constraint_context(state5)
    state__store_conj(mk_conj_constraint_list([oldCs,
                                                   newCs]),
                        state6)
  end

  defp get_bif_constr({:erlang, op, 2}, dst, args = [arg1, arg2],
            _State)
      when op === :"+" or op === :- or op === :"*" do
    returnType = mk_fun_var(fn map ->
                                 tmpArgTypes = lookup_type_list(args, map)
                                 bif_return(:erlang, op, 2, tmpArgTypes)
                            end,
                              args)
    argFun = fn a, pos ->
                  f = fn map ->
                           dstType = lookup_type(dst, map)
                           aType = lookup_type(a, map)
                           case (t_is_integer(dstType)) do
                             true ->
                               case (t_is_integer(aType)) do
                                 true ->
                                   eval_inv_arith(op, pos, dstType, aType)
                                 false ->
                                   t_integer()
                               end
                             false ->
                               case (t_is_float(dstType)) do
                                 true ->
                                   case (t_is_integer(aType)) do
                                     true ->
                                       t_float()
                                     false ->
                                       t_number()
                                   end
                                 false ->
                                   t_number()
                               end
                           end
                      end
                  mk_fun_var(f, [dst, a])
             end
    arg1FunVar = argFun.(arg2, 2)
    arg2FunVar = argFun.(arg1, 1)
    mk_conj_constraint_list([mk_constraint(dst, :sub,
                                             returnType),
                                 mk_constraint(arg1, :sub, arg1FunVar),
                                     mk_constraint(arg2, :sub, arg2FunVar)])
  end

  defp get_bif_constr({:erlang, op, 2}, dst, [arg1, arg2] = args,
            _State)
      when op === :"<" or op === :"=<" or op === :">" or op === :">=" do
    argFun = fn localArg1, localArg2, localOp ->
                  fn map ->
                       dstType = lookup_type(dst, map)
                       isTrue = t_is_any_atom(true, dstType)
                       isFalse = t_is_any_atom(false, dstType)
                       case (isTrue or isFalse) do
                         true ->
                           arg1Type = lookup_type(localArg1, map)
                           arg2Type = lookup_type(localArg2, map)
                           case (t_is_integer(arg1Type) and t_is_integer(arg2Type)) do
                             true ->
                               max1 = :erl_types.number_max(arg1Type)
                               min1 = :erl_types.number_min(arg1Type)
                               max2 = :erl_types.number_max(arg2Type)
                               min2 = :erl_types.number_min(arg2Type)
                               case (localOp) do
                                 :"=<" ->
                                   cond do
                                     isTrue ->
                                       t_from_range(min1, max2)
                                     isFalse ->
                                       t_from_range(range_inc(min2), max1)
                                   end
                                 :"<" ->
                                   cond do
                                     isTrue ->
                                       t_from_range(min1, range_dec(max2))
                                     isFalse ->
                                       t_from_range(min2, max1)
                                   end
                                 :">=" ->
                                   cond do
                                     isTrue ->
                                       t_from_range(min2, max1)
                                     isFalse ->
                                       t_from_range(min1, range_dec(max2))
                                   end
                                 :">" ->
                                   cond do
                                     isTrue ->
                                       t_from_range(range_inc(min2), max1)
                                     isFalse ->
                                       t_from_range(min1, max2)
                                   end
                               end
                             false ->
                               t_any()
                           end
                         false ->
                           t_any()
                       end
                  end
             end
    {arg1Fun, arg2Fun} = (case (op) do
                            :"<" ->
                              {argFun.(arg1, arg2, :"<"), argFun.(arg2, arg1, :">=")}
                            :"=<" ->
                              {argFun.(arg1, arg2, :"=<"), argFun.(arg2, arg1, :">=")}
                            :">" ->
                              {argFun.(arg1, arg2, :">"), argFun.(arg2, arg1, :"<")}
                            :">=" ->
                              {argFun.(arg1, arg2, :">="), argFun.(arg2, arg1, :"=<")}
                          end)
    dstArgs = [dst, arg1, arg2]
    arg1Var = mk_fun_var(arg1Fun, dstArgs)
    arg2Var = mk_fun_var(arg2Fun, dstArgs)
    dstVar = mk_fun_var(fn map ->
                             tmpArgTypes = lookup_type_list(args, map)
                             bif_return(:erlang, op, 2, tmpArgTypes)
                        end,
                          args)
    mk_conj_constraint_list([mk_constraint(dst, :sub,
                                             dstVar),
                                 mk_constraint(arg1, :sub, arg1Var),
                                     mk_constraint(arg2, :sub, arg2Var)])
  end

  defp get_bif_constr({:erlang, :"++", 2}, dst, [hd, tl] = args,
            _State) do
    hdFun = fn map ->
                 dstType = lookup_type(dst, map)
                 case (t_is_cons(dstType)) do
                   true ->
                     t_list(t_cons_hd(dstType))
                   false ->
                     case (t_is_list(dstType)) do
                       true ->
                         case (t_is_nil(dstType)) do
                           true ->
                             dstType
                           false ->
                             t_list(t_list_elements(dstType))
                         end
                       false ->
                         t_list()
                     end
                 end
            end
    tlFun = fn map ->
                 dstType = lookup_type(dst, map)
                 case (t_is_cons(dstType)) do
                   true ->
                     t_sup(t_cons_tl(dstType), dstType)
                   false ->
                     case (t_is_list(dstType)) do
                       true ->
                         case (t_is_nil(dstType)) do
                           true ->
                             dstType
                           false ->
                             t_list(t_list_elements(dstType))
                         end
                       false ->
                         t_any()
                     end
                 end
            end
    dstL = [dst]
    hdVar = mk_fun_var(hdFun, dstL)
    tlVar = mk_fun_var(tlFun, dstL)
    argTypes = :erl_bif_types.arg_types(:erlang, :"++", 2)
    returnType = mk_fun_var(fn map ->
                                 tmpArgTypes = lookup_type_list(args, map)
                                 bif_return(:erlang, :"++", 2, tmpArgTypes)
                            end,
                              args)
    cs = mk_constraints(args, :sub, argTypes)
    mk_conj_constraint_list([mk_constraint(dst, :sub,
                                             returnType),
                                 mk_constraint(hd, :sub, hdVar),
                                     mk_constraint(tl, :sub, tlVar) | cs])
  end

  defp get_bif_constr({:erlang, :is_atom, 1}, dst, [arg], state) do
    get_bif_test_constr(dst, arg, t_atom(), state)
  end

  defp get_bif_constr({:erlang, :is_binary, 1}, dst, [arg], state) do
    get_bif_test_constr(dst, arg, t_binary(), state)
  end

  defp get_bif_constr({:erlang, :is_bitstring, 1}, dst, [arg],
            state) do
    get_bif_test_constr(dst, arg, t_bitstr(), state)
  end

  defp get_bif_constr({:erlang, :is_boolean, 1}, dst, [arg], state) do
    get_bif_test_constr(dst, arg, t_boolean(), state)
  end

  defp get_bif_constr({:erlang, :is_float, 1}, dst, [arg], state) do
    get_bif_test_constr(dst, arg, t_float(), state)
  end

  defp get_bif_constr({:erlang, :is_function, 1}, dst, [arg],
            state) do
    get_bif_test_constr(dst, arg, t_fun(), state)
  end

  defp get_bif_constr({:erlang, :is_function, 2}, dst, [fun, arity],
            _State) do
    argFun = fn map ->
                  dstType = lookup_type(dst, map)
                  case (t_is_any_atom(true, dstType)) do
                    true ->
                      arityType = lookup_type(arity, map)
                      case (t_number_vals(arityType)) do
                        :unknown ->
                          t_fun()
                        vals ->
                          t_sup(for x <- vals do
                                  t_fun(x, t_any())
                                end)
                      end
                    false ->
                      t_any()
                  end
             end
    argV = mk_fun_var(argFun, [dst, arity])
    mk_conj_constraint_list([mk_constraint(dst, :sub,
                                             t_boolean()),
                                 mk_constraint(arity, :sub, t_integer()),
                                     mk_constraint(fun, :sub, argV)])
  end

  defp get_bif_constr({:erlang, :is_integer, 1}, dst, [arg], state) do
    get_bif_test_constr(dst, arg, t_integer(), state)
  end

  defp get_bif_constr({:erlang, :is_list, 1}, dst, [arg], state) do
    get_bif_test_constr(dst, arg, t_maybe_improper_list(),
                          state)
  end

  defp get_bif_constr({:erlang, :is_map, 1}, dst, [arg], state) do
    get_bif_test_constr(dst, arg, t_map(), state)
  end

  defp get_bif_constr({:erlang, :is_number, 1}, dst, [arg], state) do
    get_bif_test_constr(dst, arg, t_number(), state)
  end

  defp get_bif_constr({:erlang, :is_pid, 1}, dst, [arg], state) do
    get_bif_test_constr(dst, arg, t_pid(), state)
  end

  defp get_bif_constr({:erlang, :is_port, 1}, dst, [arg], state) do
    get_bif_test_constr(dst, arg, t_port(), state)
  end

  defp get_bif_constr({:erlang, :is_reference, 1}, dst, [arg],
            state) do
    get_bif_test_constr(dst, arg, t_reference(), state)
  end

  defp get_bif_constr({:erlang, :is_record, 2}, dst,
            [var, tag] = args, _State) do
    argFun = fn map ->
                  case (t_is_any_atom(true, lookup_type(dst, map))) do
                    true ->
                      t_tuple()
                    false ->
                      t_any()
                  end
             end
    argV = mk_fun_var(argFun, [dst])
    dstFun = fn map ->
                  tmpArgTypes = lookup_type_list(args, map)
                  bif_return(:erlang, :is_record, 2, tmpArgTypes)
             end
    dstV = mk_fun_var(dstFun, args)
    mk_conj_constraint_list([mk_constraint(dst, :sub, dstV),
                                 mk_constraint(tag, :sub, t_atom()),
                                     mk_constraint(var, :sub, argV)])
  end

  defp get_bif_constr({:erlang, :is_record, 3}, dst,
            [var, tag, arity] = args, state) do
    argFun = fn map ->
                  case (t_is_any_atom(true, lookup_type(dst, map))) do
                    true ->
                      arityType = lookup_type(arity, map)
                      case (t_is_integer(arityType)) do
                        true ->
                          case (t_number_vals(arityType)) do
                            [arityVal] ->
                              tagType = lookup_type(tag, map)
                              case (t_is_atom(tagType)) do
                                true ->
                                  anyElems = :lists.duplicate(arityVal - 1,
                                                                t_any())
                                  genRecord = t_tuple([tagType | anyElems])
                                  case (t_atom_vals(tagType)) do
                                    [tagVal] ->
                                      case (lookup_record(state, tagVal,
                                                            arityVal - 1)) do
                                        {:ok, type, _NewState} ->
                                          type
                                        {:error, _NewState} ->
                                          genRecord
                                      end
                                    _ ->
                                      genRecord
                                  end
                                false ->
                                  t_tuple(arityVal)
                              end
                            _ ->
                              t_tuple()
                          end
                        false ->
                          t_tuple()
                      end
                    false ->
                      t_any()
                  end
             end
    argV = mk_fun_var(argFun, [tag, arity, dst])
    dstFun = fn map ->
                  [tmpVar, tmpTag, tmpArity] = lookup_type_list(args, map)
                  tmpArgTypes = [tmpVar, tmpTag, tmpArity]
                  bif_return(:erlang, :is_record, 3, tmpArgTypes)
             end
    dstV = mk_fun_var(dstFun, args)
    mk_conj_constraint_list([mk_constraint(dst, :sub, dstV),
                                 mk_constraint(arity, :sub, t_integer()),
                                     mk_constraint(tag, :sub, t_atom()),
                                         mk_constraint(var, :sub, argV)])
  end

  defp get_bif_constr({:erlang, :is_tuple, 1}, dst, [arg], state) do
    get_bif_test_constr(dst, arg, t_tuple(), state)
  end

  defp get_bif_constr({:erlang, :and, 2}, dst, [arg1, arg2] = args,
            _State) do
    true__ = t_from_term(true)
    false__ = t_from_term(false)
    argFun = fn var ->
                  fn map ->
                       dstType = lookup_type(dst, map)
                       case (t_is_any_atom(true, dstType)) do
                         true ->
                           true__
                         false ->
                           case (t_is_any_atom(false, dstType)) do
                             true ->
                               case (t_is_any_atom(true,
                                                     lookup_type(var, map))) do
                                 true ->
                                   false__
                                 false ->
                                   t_boolean()
                               end
                             false ->
                               t_boolean()
                           end
                       end
                  end
             end
    dstFun = fn map ->
                  arg1Type = lookup_type(arg1, map)
                  case (t_is_any_atom(false, arg1Type)) do
                    true ->
                      false__
                    false ->
                      arg2Type = lookup_type(arg2, map)
                      case (t_is_any_atom(false, arg2Type)) do
                        true ->
                          false__
                        false ->
                          case (t_is_any_atom(true,
                                                arg1Type) and t_is_any_atom(true,
                                                                              arg2Type)) do
                            true ->
                              true__
                            false ->
                              t_boolean()
                          end
                      end
                  end
             end
    argV1 = mk_fun_var(argFun.(arg2), [arg2, dst])
    argV2 = mk_fun_var(argFun.(arg1), [arg1, dst])
    dstV = mk_fun_var(dstFun, args)
    mk_conj_constraint_list([mk_constraint(dst, :sub, dstV),
                                 mk_constraint(arg1, :sub, argV1),
                                     mk_constraint(arg2, :sub, argV2)])
  end

  defp get_bif_constr({:erlang, :or, 2}, dst, [arg1, arg2] = args,
            _State) do
    true__ = t_from_term(true)
    false__ = t_from_term(false)
    argFun = fn var ->
                  fn map ->
                       dstType = lookup_type(dst, map)
                       case (t_is_any_atom(false, dstType)) do
                         true ->
                           false__
                         false ->
                           case (t_is_any_atom(true, dstType)) do
                             true ->
                               case (t_is_any_atom(false,
                                                     lookup_type(var, map))) do
                                 true ->
                                   true__
                                 false ->
                                   t_boolean()
                               end
                             false ->
                               t_boolean()
                           end
                       end
                  end
             end
    dstFun = fn map ->
                  arg1Type = lookup_type(arg1, map)
                  case (t_is_any_atom(true, arg1Type)) do
                    true ->
                      true__
                    false ->
                      arg2Type = lookup_type(arg2, map)
                      case (t_is_any_atom(true, arg2Type)) do
                        true ->
                          true__
                        false ->
                          case (t_is_any_atom(false,
                                                arg1Type) and t_is_any_atom(false,
                                                                              arg2Type)) do
                            true ->
                              false__
                            false ->
                              t_boolean()
                          end
                      end
                  end
             end
    argV1 = mk_fun_var(argFun.(arg2), [arg2, dst])
    argV2 = mk_fun_var(argFun.(arg1), [arg1, dst])
    dstV = mk_fun_var(dstFun, args)
    f = fn a ->
             try do
               [mk_constraint(a, :sub, true__)]
             catch
               :error ->
                 []
             end
        end
    constrs = f.(arg1) ++ f.(arg2)
    disj = mk_disj_constraint_list([mk_constraint(dst, :sub,
                                                    false__) |
                                        constrs])
    mk_conj_constraint_list([mk_constraint(dst, :sub, dstV),
                                 mk_constraint(arg1, :sub, argV1),
                                     mk_constraint(arg2, :sub, argV2), disj])
  end

  defp get_bif_constr({:erlang, :not, 1}, dst, [arg] = args,
            _State) do
    true__ = t_from_term(true)
    false__ = t_from_term(false)
    fun = fn var ->
               fn map ->
                    type = lookup_type(var, map)
                    case (t_is_any_atom(true, type)) do
                      true ->
                        false__
                      false ->
                        case (t_is_any_atom(false, type)) do
                          true ->
                            true__
                          false ->
                            t_boolean()
                        end
                    end
               end
          end
    argV = mk_fun_var(fun.(dst), [dst])
    dstV = mk_fun_var(fun.(arg), args)
    mk_conj_constraint_list([mk_constraint(arg, :sub, argV),
                                 mk_constraint(dst, :sub, dstV)])
  end

  defp get_bif_constr({:erlang, :"=:=", 2}, dst, [arg1, arg2] = args,
            _State) do
    argFun = fn self, otherVar ->
                  fn map ->
                       dstType = lookup_type(dst, map)
                       otherVarType = lookup_type(otherVar, map)
                       case (t_is_any_atom(true, dstType)) do
                         true ->
                           otherVarType
                         false ->
                           case (t_is_any_atom(false, dstType)) do
                             true ->
                               case (is_singleton_type(otherVarType)) do
                                 true ->
                                   t_subtract(lookup_type(self, map),
                                                otherVarType)
                                 false ->
                                   t_any()
                               end
                             false ->
                               t_any()
                           end
                       end
                  end
             end
    dstFun = fn map ->
                  argType1 = lookup_type(arg1, map)
                  argType2 = lookup_type(arg2, map)
                  case (t_is_none(t_inf(argType1, argType2))) do
                    true ->
                      t_from_term(false)
                    false ->
                      t_boolean()
                  end
             end
    dstArgs = [dst, arg1, arg2]
    argV1 = mk_fun_var(argFun.(arg1, arg2), dstArgs)
    argV2 = mk_fun_var(argFun.(arg2, arg1), dstArgs)
    dstV = mk_fun_var(dstFun, args)
    mk_conj_constraint_list([mk_constraint(dst, :sub, dstV),
                                 mk_constraint(arg1, :sub, argV1),
                                     mk_constraint(arg2, :sub, argV2)])
  end

  defp get_bif_constr({:erlang, :"==", 2}, dst, [arg1, arg2] = args,
            _State) do
    dstFun = fn map ->
                  tmpArgTypes = lookup_type_list(args, map)
                  bif_return(:erlang, :"==", 2, tmpArgTypes)
             end
    argFun = fn var, self ->
                  fn map ->
                       varType = lookup_type(var, map)
                       dstType = lookup_type(dst, map)
                       case (is_singleton_non_number_type(varType)) do
                         true ->
                           case (t_is_any_atom(true, dstType)) do
                             true ->
                               varType
                             false ->
                               case (t_is_any_atom(false, dstType)) do
                                 true ->
                                   t_subtract(lookup_type(self, map), varType)
                                 false ->
                                   t_any()
                               end
                           end
                         false ->
                           case (t_is_any_atom(true, dstType)) do
                             true ->
                               case (t_is_number(varType)) do
                                 true ->
                                   t_number()
                                 false ->
                                   case (t_is_atom(varType)) do
                                     true ->
                                       varType
                                     false ->
                                       t_any()
                                   end
                               end
                             false ->
                               t_any()
                           end
                       end
                  end
             end
    dstV = mk_fun_var(dstFun, args)
    argL = [arg1, arg2, dst]
    argV1 = mk_fun_var(argFun.(arg2, arg1), argL)
    argV2 = mk_fun_var(argFun.(arg1, arg2), argL)
    mk_conj_constraint_list([mk_constraint(dst, :sub, dstV),
                                 mk_constraint(arg1, :sub, argV1),
                                     mk_constraint(arg2, :sub, argV2)])
  end

  defp get_bif_constr({:erlang, :element, 2} = _BIF, dst, args,
            r_state(cs: constrs)) do
    genType = :erl_bif_types.type(:erlang, :element, 2)
    case (t_is_none(genType)) do
      true ->
        :ok
        throw(:error)
      false ->
        fun = fn map ->
                   aTs2 = lookup_type_list(args, map)
                   bif_return(:erlang, :element, 2, aTs2)
              end
        returnType = mk_fun_var(fun, args)
        argTypes = :erl_bif_types.arg_types(:erlang, :element,
                                              2)
        cs = mk_constraints(args, :sub, argTypes)
        newCs = (case (find_element(args, constrs)) do
                   :unknown ->
                     cs
                   elem ->
                     [mk_constraint(dst, :eq, elem) | cs]
                 end)
        mk_conj_constraint_list([mk_constraint(dst, :sub,
                                                 returnType) |
                                     newCs])
    end
  end

  defp get_bif_constr({m, f, a} = _BIF, dst, args, _State) do
    genType = :erl_bif_types.type(m, f, a)
    case (t_is_none(genType)) do
      true ->
        :ok
        throw(:error)
      false ->
        returnType = mk_fun_var(fn map ->
                                     tmpArgTypes = lookup_type_list(args, map)
                                     bif_return(m, f, a, tmpArgTypes)
                                end,
                                  args)
        case (:erl_bif_types.is_known(m, f, a)) do
          false ->
            case (t_is_any(genType)) do
              true ->
                :none
              false ->
                mk_constraint(dst, :sub, returnType)
            end
          true ->
            argTypes = :erl_bif_types.arg_types(m, f, a)
            cs = mk_constraints(args, :sub, argTypes)
            mk_conj_constraint_list([mk_constraint(dst, :sub,
                                                     returnType) |
                                         cs])
        end
    end
  end

  defp eval_inv_arith(:"+", _Pos, dst, arg) do
    bif_return(:erlang, :-, 2, [dst, arg])
  end

  defp eval_inv_arith(:"*", _Pos, dst, arg) do
    zero = t_from_term(0)
    case (t_is_none(t_inf(arg, zero))) do
      false ->
        t_integer()
      true ->
        tmpRet = bif_return(:erlang, :div, 2, [dst, arg])
        case (t_is_subtype(zero, dst)) do
          false ->
            t_subtract(tmpRet, zero)
          true ->
            tmpRet
        end
    end
  end

  defp eval_inv_arith(:-, 1, dst, arg) do
    bif_return(:erlang, :-, 2, [arg, dst])
  end

  defp eval_inv_arith(:-, 2, dst, arg) do
    bif_return(:erlang, :"+", 2, [arg, dst])
  end

  defp range_inc(:neg_inf) do
    :neg_inf
  end

  defp range_inc(:pos_inf) do
    :pos_inf
  end

  defp range_inc(int) when is_integer(int) do
    int + 1
  end

  defp range_dec(:neg_inf) do
    :neg_inf
  end

  defp range_dec(:pos_inf) do
    :pos_inf
  end

  defp range_dec(int) when is_integer(int) do
    int - 1
  end

  defp get_bif_test_constr(dst, arg, type, _State) do
    argFun = fn map ->
                  dstType = lookup_type(dst, map)
                  case (t_is_any_atom(true, dstType)) do
                    true ->
                      type
                    false ->
                      t_any()
                  end
             end
    argV = mk_fun_var(argFun, [dst])
    dstFun = fn map ->
                  argType = lookup_type(arg, map)
                  case (t_is_none(t_inf(argType, type))) do
                    true ->
                      t_from_term(false)
                    false ->
                      case (t_is_subtype(argType, type)) do
                        true ->
                          t_from_term(true)
                        false ->
                          t_boolean()
                      end
                  end
             end
    dstV = mk_fun_var(dstFun, [arg])
    mk_conj_constraint_list([mk_constraint(dst, :sub, dstV),
                                 mk_constraint(arg, :sub, argV)])
  end

  defp solve([fun], state) do
    :ok
    solve_fun(fun, %{}, state)
  end

  defp solve([_ | _] = sCC, state) do
    :ok
    users = comp_users(sCC, state)
    solve_scc(sCC, %{}, state, users, _ToSolve = sCC, false)
  end

  defp comp_users(sCC, state) do
    vars0 = (for fun <- sCC do
               {fun, state__get_rec_var(fun, state)}
             end)
    vars = :lists.sort(for {_, {:ok, var}} <- vars0 do
                         t_var_name(var)
                       end)
    family(for f <- sCC,
                 v <- :ordsets.intersection(get_deps(state__get_cs(f,
                                                                     state)),
                                              vars) do
             {t_var(v), f}
           end)
  end

  defp solve_fun(fun, funMap, state) do
    newMap = solve(fun, funMap, state)
    newType = lookup_type(fun, newMap)
    newFunMap1 = (case (state__get_rec_var(fun, state)) do
                    :error ->
                      funMap
                    {:ok, var} ->
                      enter_type(var, newType, funMap)
                  end)
    enter_type(fun, newType, newFunMap1)
  end

  defp solve_scc(sCC, map, state, users, toSolve, tryingUnit) do
    vars0 = (for fun <- sCC do
               {fun, state__get_rec_var(fun, state)}
             end)
    vars = (for {_, {:ok, var}} <- vars0 do
              var
            end)
    funs = (for {fun, {:ok, _}} <- vars0 do
              fun
            end)
    types = unsafe_lookup_type_list(funs, map)
    recTypes = (for type <- types do
                  t_limit(type, 4)
                end)
    cleanMap = :lists.foldl(fn fun, accFunMap ->
                                 erase_type(t_var_name(fun), accFunMap)
                            end,
                              map, toSolve)
    map1 = enter_type_lists(vars, recTypes, cleanMap)
    :ok
    solveFun = fn x, y ->
                    scc_fold_fun(x, y, state)
               end
    map2 = :lists.foldl(solveFun, map1, toSolve)
    updated = updated_vars_only(vars, map, map2)
    case (updated === []) do
      true ->
        :ok
        newTypes = unsafe_lookup_type_list(funs, map2)
        case (:erl_types.any_none(for t <- newTypes do
                                    t_fun_range(t)
                                  end) and tryingUnit === false) do
          true ->
            unitTypes = (for t <- newTypes do
                           case (t_is_none(t_fun_range(t))) do
                             false ->
                               t
                             true ->
                               t_fun(t_fun_args(t), t_unit())
                           end
                         end)
            map3 = enter_type_lists(funs, unitTypes, map2)
            solve_scc(sCC, map3, state, users, sCC, true)
          false ->
            map2
        end
      false ->
        :ok
        toSolve1 = affected(updated, users)
        solve_scc(sCC, map2, state, users, toSolve1, tryingUnit)
    end
  end

  defp affected(updated, users) do
    :lists.umerge(for v <- updated do
                    case (:lists.keyfind(v, 1, users)) do
                      {^v, vs} ->
                        vs
                      false ->
                        []
                    end
                  end)
  end

  defp scc_fold_fun(f, funMap, state) do
    map = solve(f, funMap, state)
    newType0 = unsafe_lookup_type(f, map)
    newType = t_limit(newType0, 4)
    newFunMap = (case (state__get_rec_var(f, state)) do
                   {:ok, r} ->
                     enter_type(r, newType, enter_type(f, newType, funMap))
                   :error ->
                     enter_type(f, newType, funMap)
                 end)
    :ok
    newFunMap
  end

  defp solve(fun, funMap, state) do
    {:ok, map} = v2_solve_ref(fun, funMap, state)
    map
  end

  Record.defrecord(:r_v2_state, :v2_state, constr_data: :maps.new(),
                                    state: :undefined)
  defp v2_solve_ref(fun, map, state) do
    v2State = r_v2_state(state: state)
    {:ok, newMap, _, _} = v2_solve_reference(fun, map,
                                               v2State)
    {:ok, newMap}
  end

  defp v2_solve(r_constraint() = c, map, v2State) do
    case (solve_one_c(c, map)) do
      :error ->
        report_failed_constraint(c, map)
        {:error, v2State}
      {:ok, {newMap, u}} ->
        {:ok, newMap, v2State, u}
    end
  end

  defp v2_solve(r_constraint_list(type: :disj) = c, map, v2State) do
    v2_solve_disjunct(c, map, v2State)
  end

  defp v2_solve(r_constraint_list(type: :conj) = c, map, v2State) do
    v2_solve_conjunct(c, map, v2State)
  end

  defp v2_solve(r_constraint_ref(id: id), map, v2State) do
    v2_solve_reference(id, map, v2State)
  end

  defp v2_solve_reference(id, map, v2State0) do
    :ok
    :ok
    pp_constr_data('solve_ref', v2State0)
    map1 = restore_local_map(v2State0, id, map)
    state = r_v2_state(v2State0, :state)
    cs = state__get_cs(id, state)
    res = (case (state__is_self_rec(id, state)) do
             true ->
               v2_solve_self_recursive(cs, map1, id, t_none(),
                                         v2State0)
             false ->
               v2_solve(cs, map1, v2State0)
           end)
    {funType, v2State} = (case (res) do
                            {:error, v2State1} ->
                              :ok
                              arity = state__fun_arity(id, state)
                              funType0 = (case (state__prop_domain(t_var_name(id),
                                                                     state)) do
                                            :error ->
                                              t_fun(arity, t_none())
                                            {:ok, dom} ->
                                              t_fun(dom, t_none())
                                          end)
                              {funType0, v2State1}
                            {:ok, resMap, v2State1, resU} ->
                              :ok
                              funType0 = lookup_type(id, resMap)
                              v2State2 = save_local_map(v2State1, id, resU,
                                                          resMap)
                              {funType0, v2State2}
                          end)
    :ok
    {newMap0, u0} = enter_var_type(id, funType, map)
    case (state__get_rec_var(id, state)) do
      {:ok, var} ->
        {:ok, {newMap, u}} = refine_bindings([{var, funType}],
                                               newMap0, u0)
        {:ok, newMap, v2State, u}
      :error ->
        {:ok, newMap0, v2State, u0}
    end
  end

  defp v2_solve_self_recursive(cs, map, id, recType0, v2State0) do
    :ok
    state = r_v2_state(v2State0, :state)
    {:ok, recVar} = state__get_rec_var(id, state)
    :ok
    recType = t_limit(recType0, 4)
    {map1, u0} = enter_var_type(recVar, recType, map)
    v2State1 = save_updated_vars1(v2State0, cs, u0)
    case (v2_solve(cs, map1, v2State1)) do
      {:error, _V2State} = error ->
        case (t_is_none(recType0)) do
          true ->
            arity = state__fun_arity(id, state)
            newRecType = t_fun(:lists.duplicate(arity, t_any()),
                                 t_unit())
            v2_solve_self_recursive(cs, map, id, newRecType,
                                      v2State0)
          false ->
            error
        end
      {:ok, newMap, v2State, u} ->
        :ok
        newRecType = unsafe_lookup_type(id, newMap)
        case (is_equal(newRecType, recType0)) do
          true ->
            {newMap2, u1} = enter_var_type(recVar, newRecType,
                                             newMap)
            {:ok, newMap2, v2State, :lists.umerge(u, u1)}
          false ->
            v2_solve_self_recursive(cs, map, id, newRecType,
                                      v2State0)
        end
    end
  end

  defp enter_var_type(var, type, map0) do
    {map, vs} = enter_type2(var, type, map0)
    {map,
       for v <- vs do
         t_var_name(v)
       end}
  end

  defp v2_solve_disjunct(disj, map, v2State0) do
    r_constraint_list(type: :disj, id: _Id, list: cs, masks: masks) = disj
    :ok
    :ok
    pp_constr_data('disjunct', v2State0)
    case (get_flags(v2State0, disj)) do
      {v2State1, :failed_list} ->
        {:error, v2State1}
      {v2State1, flags} when flags !== [] ->
        {:ok, v2State, eval, uL, mapL0, uneval,
           failed} = v2_solve_disj(flags, cs, 1, map, v2State1, [],
                                     [], [], [], false)
        :ok
        cond do
          (eval === [] and uneval === []) ->
            {:error, failed_list(disj, v2State0)}
          true ->
            {is0, unIds} = :lists.unzip(uneval)
            mapL = (for id <- unIds do
                      restore_local_map(v2State, id, map)
                    end) ++ mapL0
            u0 = (case (failed) do
                    false ->
                      :lists.umerge(uL)
                    true ->
                      constrained_keys(mapL)
                  end)
            cond do
              u0 === [] ->
                {:ok, map, v2State, []}
              true ->
                notFailed = :lists.umerge(is0, eval)
                u1 = (for v <- u0,
                            var_occurs_everywhere(v, masks, notFailed) do
                        v
                      end)
                newMap = join_maps(u1, mapL, map)
                :ok
                u = updated_vars_only(u1, map, newMap)
                :ok
                {:ok, newMap, v2State, u}
            end
        end
    end
  end

  defp var_occurs_everywhere(v, masks, notFailed) do
    :ordsets.is_subset(notFailed, get_mask(v, masks))
  end

  defp v2_solve_disj([i | is], [c | cs], i, map0, v2State0, uL, mapL,
            eval, uneval, failed0) do
    id = r_constraint_list(c, :id)
    map1 = restore_local_map(v2State0, id, map0)
    case (v2_solve(c, map1, v2State0)) do
      {:error, v2State} ->
        :ok
        failed = failed0 or not is_failed_list(c, v2State0)
        v2_solve_disj(is, cs, i + 1, map0, v2State, uL, mapL,
                        eval, uneval, failed)
      {:ok, map, v2State1, u} ->
        :ok
        v2State = save_local_map(v2State1, id, u, map)
        :ok
        v2_solve_disj(is, cs, i + 1, map0, v2State, [u | uL],
                        [map | mapL], [i | eval], uneval, failed0)
    end
  end

  defp v2_solve_disj([], [], _I, _Map, v2State, uL, mapL, eval,
            uneval, failed) do
    {:ok, v2State, :lists.reverse(eval), uL, mapL,
       :lists.reverse(uneval), failed}
  end

  defp v2_solve_disj([:every_i], cs, i, map, v2State, uL, mapL, eval,
            uneval, failed) do
    newIs = (case (cs) do
               [] ->
                 []
               _ ->
                 [i, :every_i]
             end)
    v2_solve_disj(newIs, cs, i, map, v2State, uL, mapL,
                    eval, uneval, failed)
  end

  defp v2_solve_disj(is, [c | cs], i, map, v2State, uL, mapL, eval,
            uneval0, failed) do
    uneval = (for _ <- [:EFE_DUMMY_GEN],
                    not is_failed_list(c, v2State) do
                {i, r_constraint_list(c, :id)}
              end) ++ uneval0
    v2_solve_disj(is, cs, i + 1, map, v2State, uL, mapL,
                    eval, uneval, failed)
  end

  defp save_local_map(r_v2_state(constr_data: conData0) = v2State, id, u,
            map) do
    :ok
    {part0, []} = :maps.get(id, conData0, {%{}, []})
    :ok
    part = :maps.merge(part0, :maps.with(u, map))
    :ok
    conData = Map.put(conData0, id, {part, []})
    r_v2_state(v2State, constr_data: conData)
  end

  defp restore_local_map(r_v2_state(constr_data: conData), id, map0) do
    case (conData) do
      %{^id => {part0, u}} when map_size(part0) !== 0 ->
        :ok
        :ok
        part = :maps.without(u, part0)
        :ok
        map = :maps.merge(map0, part)
        :ok
        map
      %{} ->
        map0
    end
  end

  defp v2_solve_conjunct(conj, map, v2State0) do
    r_constraint_list(type: :conj, list: cs) = conj
    :ok
    isFlat = (case (cs) do
                [r_constraint() | _] ->
                  true
                _ ->
                  false
              end)
    case (get_flags(v2State0, conj)) do
      {v2State, :failed_list} ->
        {:error, v2State}
      {v2State, flags} ->
        v2_solve_conj(flags, cs, 1, map, conj, isFlat, v2State,
                        [], [], [], map, flags)
    end
  end

  defp v2_solve_conj([i | is], [cs | tail], i, map0, conj, isFlat,
            v2State0, uL, newFs0, varsUp, lastMap, lastFlags) do
    :ok
    true = isFlat === elem(cs, 0) === :constraint
    pp_constr_data('conj', v2State0)
    case (v2_solve(cs, map0, v2State0)) do
      {:error, v2State1} ->
        {:error, failed_list(conj, v2State1)}
      {:ok, map, v2State1, []} ->
        v2_solve_conj(is, tail, i + 1, map, conj, isFlat,
                        v2State1, uL, newFs0, varsUp, lastMap, lastFlags)
      {:ok, map, v2State1, u} when isFlat ->
        mask = :lists.umerge(for v <- u do
                               get_mask(v, r_constraint_list(conj, :masks))
                             end)
        {is1, newF} = add_mask_to_flags(is, mask, i, [])
        newFs = [newF | newFs0]
        v2_solve_conj(is1, tail, i + 1, map, conj, isFlat,
                        v2State1, [u | uL], newFs, varsUp, lastMap, lastFlags)
      {:ok, map, v2State1, u} ->
        r_constraint_list(masks: masks, list: allCs) = conj
        m = :lists.keydelete(i, 1, vars_per_child(u, masks))
        {v2State2, newF0} = save_updated_vars_list(allCs, m,
                                                     v2State1)
        {newF, f} = :lists.splitwith(fn j ->
                                          j < i
                                     end,
                                       newF0)
        is1 = umerge_mask(is, f)
        newFs = [newF | newFs0]
        v2_solve_conj(is1, tail, i + 1, map, conj, isFlat,
                        v2State2, [u | uL], newFs, varsUp, lastMap, lastFlags)
    end
  end

  defp v2_solve_conj([], _Cs, _I, map, conj, isFlat, v2State, uL,
            newFs, varsUp, lastMap, lastFlags) do
    u = :lists.umerge(uL)
    case (:lists.umerge(newFs)) do
      [] ->
        :ok
        {:ok, map, v2State, :lists.umerge([u | varsUp])}
      newFlags when (newFlags === lastFlags and
                       map === lastMap)
                    ->
        report_detected_loop(conj)
        {:ok, map, v2State, :lists.umerge([u | varsUp])}
      newFlags ->
        :ok
        r_constraint_list(type: :conj, list: cs) = conj
        v2_solve_conj(newFlags, cs, 1, map, conj, isFlat,
                        v2State, [], [], [u | varsUp], map, newFlags)
    end
  end

  defp v2_solve_conj([:every_i], cs, i, map, conj, isFlat, v2State,
            uL, newFs, varsUp, lastMap, lastFlags) do
    newIs = (case (cs) do
               [] ->
                 []
               _ ->
                 [i, :every_i]
             end)
    v2_solve_conj(newIs, cs, i, map, conj, isFlat, v2State,
                    uL, newFs, varsUp, lastMap, lastFlags)
  end

  defp v2_solve_conj(is, [_ | tail], i, map, conj, isFlat, v2State,
            uL, newFs, varsUp, lastMap, lastFlags) do
    v2_solve_conj(is, tail, i + 1, map, conj, isFlat,
                    v2State, uL, newFs, varsUp, lastMap, lastFlags)
  end

  defp report_detected_loop(_) do
    :ok
  end

  defp add_mask_to_flags(flags, [im | m], i, l) when i > im do
    add_mask_to_flags(flags, m, i, [im | l])
  end

  defp add_mask_to_flags(flags, [_ | m], _I, l) do
    {umerge_mask(flags, m), :lists.reverse(l)}
  end

  defp umerge_mask([:every_i] = is, _F) do
    is
  end

  defp umerge_mask(is, f) do
    :lists.umerge(is, f)
  end

  defp get_mask(v, masks) do
    case (masks) do
      %{^v => m} ->
        m
      %{} ->
        []
    end
  end

  defp get_flags(r_v2_state(constr_data: conData0) = v2State0, c) do
    r_constraint_list(id: id, list: cs, masks: masks) = c
    case (conData0) do
      %{^id => {part, u}} ->
        true = u !== []
        :ok
        conData = Map.put(conData0, id, {part, []})
        v2State = r_v2_state(v2State0, constr_data: conData)
        save_updated_vars_list(cs, vars_per_child(u, masks),
                                 v2State)
      %{^id => :failed} ->
        {v2State0, :failed_list}
      %{} ->
        :ok
        conData = Map.put(conData0, id, {%{}, []})
        v2State = r_v2_state(v2State0, constr_data: conData)
        {v2State, [:every_i]}
    end
  end

  defp vars_per_child(u, masks) do
    family(for v <- :lists.usort(u),
                 i <- get_mask(v, masks) do
             {i, v}
           end)
  end

  defp save_updated_vars_list(cs, iU, v2State) do
    save_updated_vars_list1(cs, iU, v2State, 1, [])
  end

  defp save_updated_vars_list1([c | cs], [{i, u} | iU], v2State0, i, is) do
    v2State = save_updated_vars(c, u, v2State0)
    save_updated_vars_list1(cs, iU, v2State, i + 1,
                              [i | is])
  end

  defp save_updated_vars_list1([], [], v2State, _I, is) do
    {v2State, :lists.reverse(is)}
  end

  defp save_updated_vars_list1([_ | cs], iU, v2State, i, is) do
    save_updated_vars_list1(cs, iU, v2State, i + 1, is)
  end

  defp save_updated_vars(r_constraint(), _, v2State) do
    v2State
  end

  defp save_updated_vars(r_constraint_list() = c, u, v2State0) do
    save_updated_vars1(v2State0, c, u)
  end

  defp save_updated_vars(r_constraint_ref(id: id), u, v2State) do
    cs = state__get_cs(id, r_v2_state(v2State, :state))
    save_updated_vars(cs, u, v2State)
  end

  defp save_updated_vars1(r_v2_state(constr_data: conData0) = v2State, r_constraint_list(id: id),
            u) do
    case (conData0) do
      %{^id => {part, u0}} ->
        conData = Map.put(conData0, id, {part, u ++ u0})
        r_v2_state(v2State, constr_data: conData)
      %{} ->
        v2State
    end
  end

  defp pp_constr_data(_Tag, _V2State) do
    :ok
  end

  defp failed_list(r_constraint_list(id: id), r_v2_state(constr_data: d0) = v2State) do
    :ok
    d = Map.put(d0, id, :failed)
    r_v2_state(v2State, constr_data: d)
  end

  defp is_failed_list(r_constraint_list(id: id), r_v2_state(constr_data: d)) do
    case (d) do
      %{^id => :failed} ->
        true
      %{} ->
        false
    end
  end

  defp solve_one_c(r_constraint(lhs: lhs, rhs: rhs, op: op), map) do
    lhsType = lookup_type(lhs, map)
    rhsType = lookup_type(rhs, map)
    inf = t_inf(lhsType, rhsType)
    :ok
    case (t_is_none(inf)) do
      true ->
        :error
      false ->
        case (op) do
          :sub ->
            solve_subtype(lhs, inf, map)
          :eq ->
            case (solve_subtype(lhs, inf, map)) do
              :error ->
                :error
              {:ok, {map1, u1}} ->
                case (solve_subtype(rhs, inf, map1)) do
                  :error ->
                    :error
                  {:ok, {map2, u2}} ->
                    {:ok, {map2, :lists.umerge(u1, u2)}}
                end
            end
        end
    end
  end

  defp solve_subtype(type, inf, map) do
    try do
      t_unify_table_only(type, inf)
    catch
      {:mismatch, _T1, _T2} ->
        :ok
        :error
    else
      bindings ->
        refine_bindings(:maps.to_list(bindings), map, [])
    end
  end

  defp refine_bindings([{key, val} | tail], map, u0) do
    :ok
    case (t_is_equal(val, t_any())) do
      true ->
        refine_bindings(tail, :maps.remove(key, map), u0)
      false ->
        limitedVal = t_limit(val, 5)
        case (map) do
          %{^key => old} ->
            limitedInf = t_inf(old, limitedVal)
            case (t_is_none(limitedInf)) do
              true ->
                :error
              false ->
                case (t_is_equal(old, limitedInf)) do
                  true ->
                    refine_bindings(tail, map, u0)
                  false ->
                    u = :ordsets.add_element(key, u0)
                    refine_bindings(tail, Map.put(map, key, limitedInf), u)
                end
            end
          %{} ->
            u = :ordsets.add_element(key, u0)
            refine_bindings(tail, Map.put(map, key, limitedVal), u)
        end
    end
  end

  defp refine_bindings([], map, u) do
    {:ok, {map, u}}
  end

  defp report_failed_constraint(_C, _Map) do
    :ok
  end

  defp constrained_keys(maps) do
    :lists.foldl(fn tmpMap, accKeys ->
                      for key <- accKeys, :maps.is_key(key, tmpMap) do
                        key
                      end
                 end,
                   :maps.keys(hd(maps)), tl(maps))
  end

  defp join_maps([key | left], maps = [map | mapsLeft],
            accMap) do
    newType = join_one_key(key, mapsLeft,
                             lookup_type(key, map))
    newAccMap = enter_type(key, newType, accMap)
    join_maps(left, maps, newAccMap)
  end

  defp join_maps([], _Maps, accMap) do
    accMap
  end

  defp join_one_key(key, [map | maps], type) do
    case (t_is_any(type)) do
      true ->
        type
      false ->
        newType = lookup_type(key, map)
        case (is_equal(newType, type)) do
          true ->
            join_one_key(key, maps, type)
          false ->
            join_one_key(key, maps, t_sup(newType, type))
        end
    end
  end

  defp join_one_key(_Key, [], type) do
    type
  end

  defp enter_type(key, val, map) when is_integer(key) do
    :ok
    case (is_equal(val, t_any())) do
      true ->
        erase_type(key, map)
      false ->
        limitedVal = t_limit(val, 5)
        case (is_equal(limitedVal, val)) do
          true ->
            :ok
          false ->
            :ok
        end
        case (:maps.find(key, map)) do
          {:ok, value} ->
            case (is_equal(value, limitedVal)) do
              true ->
                map
              false ->
                map_store(key, limitedVal, map)
            end
          :error ->
            map_store(key, limitedVal, map)
        end
    end
  end

  defp enter_type(key, val, map) do
    keyName = t_var_name(key)
    enter_type(keyName, val, map)
  end

  defp enter_type_lists([key | keyTail], [val | valTail], map) do
    map1 = enter_type(key, val, map)
    enter_type_lists(keyTail, valTail, map1)
  end

  defp enter_type_lists([], [], map) do
    map
  end

  defp enter_type2(key, val, map) do
    map1 = enter_type(key, val, map)
    {map1,
       for _ <- [:EFE_DUMMY_GEN],
             not is_same(key, map, map1) do
         key
       end}
  end

  defp map_store(key, val, map) do
    :ok
    :maps.put(key, val, map)
  end

  defp erase_type(key, map) do
    :maps.remove(key, map)
  end

  defp lookup_type_list(list, map) do
    for x <- list do
      lookup_type(x, map)
    end
  end

  defp unsafe_lookup_type(key, map) do
    case (:maps.find(t_var_name(key), map)) do
      {:ok, type} ->
        type
      :error ->
        t_none()
    end
  end

  defp unsafe_lookup_type_list(list, map) do
    for x <- list do
      unsafe_lookup_type(x, map)
    end
  end

  defp lookup_type(r_fun_var("fun": fun), map) do
    fun.(map)
  end

  defp lookup_type(key, map) when is_integer(key) do
    case (map) do
      %{^key => val} ->
        val
      %{} ->
        t_any()
    end
  end

  defp lookup_type(key, map) do
    t_subst(key, map)
  end

  defp mk_var(var) do
    case (:cerl.is_literal(var)) do
      true ->
        var
      false ->
        case (:cerl.is_c_values(var)) do
          true ->
            t_product(mk_var_no_lit_list(:cerl.values_es(var)))
          false ->
            t_var(:cerl_trees.get_label(var))
        end
    end
  end

  defp mk_var_list(list) do
    for x <- list do
      mk_var(x)
    end
  end

  defp mk_var_no_lit(var) do
    case (:cerl.is_literal(var)) do
      true ->
        t_from_term(:cerl.concrete(var))
      false ->
        mk_var(var)
    end
  end

  defp mk_var_no_lit_list(list) do
    for x <- list do
      mk_var_no_lit(x)
    end
  end

  defp updated_vars_only(u, oldMap, newMap) do
    for v <- u, not is_same(v, oldMap, newMap) do
      v
    end
  end

  defp is_same(key, map1, map2) do
    is_equal(lookup_type(key, map1), lookup_type(key, map2))
  end

  defp is_equal(type1, type2) do
    t_is_equal(type1, type2)
  end

  defp new_state(mFAs, nextLabel, callGraph, cServer, plt,
            propTypes0, solvers) do
    list_SCC = (for mFA <- mFAs do
                  (
                    {var,
                       label} = :dialyzer_codeserver.lookup_mfa_var_label(mFA,
                                                                            cServer)
                    {{mFA, var}, t_var(label)}
                  )
                end)
    {list, sCC} = :lists.unzip(list_SCC)
    nameMap = :maps.from_list(list)
    selfRec = (case (sCC) do
                 [oneF] ->
                   label = t_var_name(oneF)
                   case (:dialyzer_callgraph.is_self_rec(label,
                                                           callGraph)) do
                     true ->
                       oneF
                     false ->
                       false
                   end
                 _Many ->
                   false
               end)
    propTypes = :maps.from_list(propTypes0)
    r_state(callgraph: callGraph, name_map: nameMap,
        next_label: nextLabel, prop_types: propTypes, plt: plt,
        scc: :ordsets.from_list(sCC), mfas: mFAs,
        self_rec: selfRec, solvers: solvers, cserver: cServer)
  end

  defp state__set_module(state, module) do
    r_state(state, module: module)
  end

  defp state__set_in_match(state, bool) do
    r_state(state, in_match: bool)
  end

  defp state__is_in_match(r_state(in_match: bool)) do
    bool
  end

  defp state__set_in_guard(state, bool) do
    r_state(state, in_guard: bool)
  end

  defp state__is_in_guard(r_state(in_guard: bool)) do
    bool
  end

  defp state__get_fun_prototype(op, arity, state) do
    case (t_is_fun(op)) do
      true ->
        {state, op}
      false ->
        {state1, [ret | args]} = state__mk_vars(arity + 1,
                                                  state)
        fun = t_fun(args, ret)
        {state1, fun}
    end
  end

  defp state__lookup_rec_var_in_scope(mFA, r_state(name_map: nameMap)) do
    :maps.find(mFA, nameMap)
  end

  defp state__store_fun_arity(tree, r_state(fun_arities: map) = state) do
    arity = length(:cerl.fun_vars(tree))
    id = mk_var(tree)
    r_state(state, fun_arities: :maps.put(id, arity, map))
  end

  defp state__fun_arity(id, r_state(fun_arities: map)) do
    :maps.get(id, map)
  end

  defp state__lookup_undef_var(tree, r_state(callgraph: cG, plt: plt)) do
    label = :cerl_trees.get_label(tree)
    case (:dialyzer_callgraph.lookup_rec_var(label, cG)) do
      :error ->
        :error
      {:ok, mFA} ->
        case (:dialyzer_plt.lookup(plt, mFA)) do
          :none ->
            :error
          {:value, {retType, argTypes}} ->
            {:ok, t_fun(argTypes, retType)}
        end
    end
  end

  defp state__lookup_apply(tree, r_state(callgraph: callgraph)) do
    apply = :cerl_trees.get_label(tree)
    case (:dialyzer_callgraph.lookup_call_site(apply,
                                                 callgraph)) do
      :error ->
        :unknown
      {:ok, list} ->
        case (:lists.member(:external, list)) do
          true ->
            :unknown
          false ->
            list
        end
    end
  end

  defp get_apply_constr(funLabels, dst, argTypes,
            r_state(callgraph: cG) = state) do
    mFAs = (for label <- funLabels do
              :dialyzer_callgraph.lookup_name(label, cG)
            end)
    case (:lists.member(:error, mFAs)) do
      true ->
        :error
      false ->
        constrs0 = (for {:ok, mFA} <- mFAs do
                      (
                        state1 = state__new_constraint_context(state)
                        try do
                          get_plt_constr(mFA, dst, argTypes, state1)
                        catch
                          :error ->
                            :error
                        else
                          state2 ->
                            state__cs(state2)
                        end
                      )
                    end)
        case (for c <- constrs0, c !== :error do
                c
              end) do
          [] ->
            throw(:error)
          constrs ->
            applyConstr = mk_disj_constraint_list(constrs)
            {:ok, state__store_conj(applyConstr, state)}
        end
    end
  end

  defp state__scc(r_state(scc: sCC)) do
    sCC
  end

  defp state__add_fun_to_scc(fun, r_state(scc: sCC) = state) do
    r_state(state, scc: :ordsets.add_element(fun, sCC))
  end

  defp state__plt(r_state(plt: pLT)) do
    pLT
  end

  defp state__new_constraint_context(state) do
    r_state(state, cs: [])
  end

  defp state__prop_domain(funLabel, r_state(prop_types: propTypes)) do
    case (propTypes) do
      %{^funLabel => funType} ->
        {:ok, t_fun_args(funType)}
      %{} ->
        :error
    end
  end

  defp state__add_prop_constrs(tree, r_state(prop_types: propTypes) = state) do
    label = :cerl_trees.get_label(tree)
    case (propTypes) do
      %{^label => funType} ->
        case (t_fun_args(funType)) do
          :unknown ->
            state
          argTypes ->
            case (:erl_types.any_none(argTypes)) do
              true ->
                state
              false ->
                :ok
                funVar = mk_var(tree)
                state__store_conj(funVar, :sub, funType, state)
            end
        end
      %{} ->
        state
    end
  end

  defp state__cs(r_state(cs: cs)) do
    mk_conj_constraint_list(cs)
  end

  defp state__store_conj(c, r_state(cs: cs) = state) do
    r_state(state, cs: [c | cs])
  end

  defp state__store_conj_list([h | t], state) do
    state1 = state__store_conj(h, state)
    state__store_conj_list(t, state1)
  end

  defp state__store_conj_list([], state) do
    state
  end

  defp state__store_conj(lhs, op, rhs, r_state(cs: cs) = state) do
    r_state(state, cs: [mk_constraint(lhs, op, rhs) | cs])
  end

  defp state__store_conj_lists(list1, op, list2, state) do
    {newList1, newList2} = strip_of_any_constrs(list1,
                                                  list2)
    state__store_conj_lists_1(newList1, op, newList2, state)
  end

  defp strip_of_any_constrs(list1, list2) do
    strip_of_any_constrs(list1, list2, [], [])
  end

  defp strip_of_any_constrs([t1 | left1], [t2 | left2], acc1, acc2) do
    case (t_is_any(t1) or constraint_opnd_is_any(t2)) do
      true ->
        strip_of_any_constrs(left1, left2, acc1, acc2)
      false ->
        strip_of_any_constrs(left1, left2, [t1 | acc1],
                               [t2 | acc2])
    end
  end

  defp strip_of_any_constrs([], [], acc1, acc2) do
    {acc1, acc2}
  end

  defp state__store_conj_lists_1([arg1 | arg1Tail], op, [arg2 | arg2Tail],
            state) do
    state1 = state__store_conj(arg1, op, arg2, state)
    state__store_conj_lists_1(arg1Tail, op, arg2Tail,
                                state1)
  end

  defp state__store_conj_lists_1([], _Op, [], state) do
    state
  end

  defp state__mk_var(r_state(next_label: nL) = state) do
    {r_state(state, next_label: nL + 1), t_var(nL)}
  end

  defp state__mk_vars(n, r_state(next_label: nL) = state) do
    newLabel = nL + n
    vars = (for x <- :lists.seq(nL, newLabel - 1) do
              t_var(x)
            end)
    {r_state(state, next_label: newLabel), vars}
  end

  defp state__store_constrs(id, cs, r_state(cmap: map) = state) do
    newMap = :maps.put(id, cs, map)
    r_state(state, cmap: newMap)
  end

  defp state__get_cs(var, r_state(cmap: map)) do
    :maps.get(var, map)
  end

  defp state__is_self_rec(fun, r_state(self_rec: selfRec)) do
    not (selfRec === false) and is_equal(fun, selfRec)
  end

  defp state__store_funs(vars0, funs0, r_state(fun_map: map) = state) do
    debug_make_name_map(vars0, funs0)
    vars = mk_var_list(vars0)
    funs = mk_var_list(funs0)
    newMap = :lists.foldl(fn {var, fun}, mP ->
                               :maps.put(fun, var, mP)
                          end,
                            map, :lists.zip(vars, funs))
    r_state(state, fun_map: newMap)
  end

  defp state__get_rec_var(fun, r_state(fun_map: map)) do
    :maps.find(fun, map)
  end

  defp state__finalize(state) do
    state1 = state__new_constraint_context(state)
    state2 = enumerate_constraints(state1)
    order_fun_constraints(state2)
  end

  defp mk_constraint(lhs, op, rhs) do
    case (t_is_any(lhs) or constraint_opnd_is_any(rhs)) do
      false ->
        deps = find_constraint_deps([lhs, rhs])
        c = mk_constraint_1(lhs, op, rhs, deps)
        case (deps === []) do
          true ->
            case (solve_one_c(c, %{})) do
              :error ->
                throw(:error)
              _R ->
                c
            end
          false ->
            c
        end
      true ->
        mk_constraint_any(op)
    end
  end

  defp mk_constraint_any(op) do
    mk_constraint_1(t_any(), op, t_any(), [])
  end

  defp constraint_opnd_is_any(r_fun_var()) do
    false
  end

  defp constraint_opnd_is_any(type) do
    t_is_any(type)
  end

  defp mk_fun_var(fun, types) do
    deps = t_collect_var_names(t_product(types))
    r_fun_var("fun": fun, deps: deps)
  end

  defp get_deps(r_constraint(deps: d)) do
    d
  end

  defp get_deps(r_constraint_list(deps: d)) do
    d
  end

  defp get_deps(r_constraint_ref(deps: d)) do
    d
  end

  defp find_constraint_deps(list) do
    find_constraint_deps(list, [])
  end

  defp find_constraint_deps([r_fun_var(deps: deps) | tail], acc) do
    find_constraint_deps(tail, :ordsets.union(deps, acc))
  end

  defp find_constraint_deps([type | tail], acc0) do
    acc = :ordsets.union(t_collect_var_names(type), acc0)
    find_constraint_deps(tail, acc)
  end

  defp find_constraint_deps([], acc) do
    acc
  end

  defp mk_constraint_1(lhs, :eq, rhs, deps) when lhs < rhs do
    r_constraint(lhs: lhs, op: :eq, rhs: rhs, deps: deps)
  end

  defp mk_constraint_1(lhs, :eq, rhs, deps) do
    r_constraint(lhs: rhs, op: :eq, rhs: lhs, deps: deps)
  end

  defp mk_constraint_1(lhs, op, rhs, deps) do
    r_constraint(lhs: lhs, op: op, rhs: rhs, deps: deps)
  end

  defp mk_constraints([lhs | lhsTail], op, [rhs | rhsTail]) do
    [mk_constraint(lhs, op, rhs) | mk_constraints(lhsTail,
                                                    op, rhsTail)]
  end

  defp mk_constraints([], _Op, []) do
    []
  end

  defp mk_constraint_ref(id, deps) do
    ds = :ordsets.del_element(t_var_name(id), deps)
    r_constraint_ref(id: id, deps: ds)
  end

  defp mk_constraint_list(type, list) do
    list1 = :ordsets.from_list(lift_lists(type, list))
    case (type) do
      :conj ->
        list2 = :ordsets.filter(fn x ->
                                     get_deps(x) !== []
                                end,
                                  list1)
        mk_constraint_list_cont(type, list2)
      :disj ->
        case (:lists.any(fn x ->
                              get_deps(x) === []
                         end,
                           list1)) do
          true ->
            mk_constraint_list_cont(type, [mk_constraint_any(:eq)])
          false ->
            mk_constraint_list_cont(type, list1)
        end
    end
  end

  defp mk_constraint_list_cont(type, list) do
    deps = calculate_deps(list)
    case (deps === []) do
      true ->
        r_constraint_list(type: :conj, list: [mk_constraint_any(:eq)], deps: [])
      false ->
        r_constraint_list(type: type, list: list, deps: deps)
    end
  end

  defp lift_lists(type, list) do
    lift_lists(type, list, [])
  end

  defp lift_lists(type, [r_constraint_list(type: type, list: list) | tail],
            acc) do
    lift_lists(type, tail, list ++ acc)
  end

  defp lift_lists(type, [c | tail], acc) do
    lift_lists(type, tail, [c | acc])
  end

  defp lift_lists(_Type, [], acc) do
    acc
  end

  defp update_constraint_list(cL, list) do
    r_constraint_list(cL, list: list)
  end

  defp mk_disj_norm_form(r_constraint_list() = cL) do
    try do
      list1 = expand_to_conjunctions(cL)
      mk_disj_constraint_list(list1)
    catch
      :too_many_disj ->
        cL
    end
  end

  defp expand_to_conjunctions(r_constraint_list(type: :conj, list: list)) do
    list1 = (for c <- list, is_simple_constraint(c) do
               c
             end)
    list2 = (for (r_constraint_list() = c) <- list do
               expand_to_conjunctions(c)
             end)
    case (list2 === []) do
      true ->
        [mk_conj_constraint_list(list1)]
      false ->
        case (list2) do
          [justOneList] ->
            for l <- justOneList do
              mk_conj_constraint_list([l | list1])
            end
          _ ->
            combine_conj_lists(list2, list1)
        end
    end
  end

  defp expand_to_conjunctions(r_constraint_list(type: :disj, list: list)) do
    cond do
      length(list) > 28 ->
        throw(:too_many_disj)
      true ->
        :ok
    end
    list1 = (for c <- list, is_simple_constraint(c) do
               c
             end)
    [] = (for (r_constraint() = c) <- list1 do
            c
          end)
    expanded = :lists.append(for (r_constraint_list() = c) <- list do
                               expand_to_conjunctions(c)
                             end)
    returnList = expanded ++ list1
    cond do
      length(returnList) > 28 ->
        throw(:too_many_disj)
      true ->
        returnList
    end
  end

  defp is_simple_constraint(r_constraint()) do
    true
  end

  defp is_simple_constraint(r_constraint_ref()) do
    true
  end

  defp is_simple_constraint(r_constraint_list()) do
    false
  end

  defp combine_conj_lists([list1, list2 | left], prefix) do
    newList = (for l1 <- list1, l2 <- list2 do
                 mk_conj_constraint_list([l1, l2])
               end)
    cond do
      length(newList) > 28 ->
        throw(:too_many_disj)
      true ->
        :ok
    end
    combine_conj_lists([newList | left], prefix)
  end

  defp combine_conj_lists([list], prefix) do
    for l <- list do
      mk_conj_constraint_list([mk_conj_constraint_list(prefix),
                                   l])
    end
  end

  defp calculate_deps(list) do
    calculate_deps(list, [])
  end

  defp calculate_deps([h | tail], acc) do
    deps = get_deps(h)
    calculate_deps(tail, [deps | acc])
  end

  defp calculate_deps([], []) do
    []
  end

  defp calculate_deps([], [l]) do
    l
  end

  defp calculate_deps([], acc) do
    :lists.umerge(acc)
  end

  defp mk_conj_constraint_list(list) do
    mk_constraint_list(:conj, list)
  end

  defp mk_disj_constraint_list([notReallyAList]) do
    notReallyAList
  end

  defp mk_disj_constraint_list(list) do
    list1 = (for c <- list do
               wrap_simple_constr(c)
             end)
    mk_constraint_list(:disj, list1)
  end

  defp wrap_simple_constr(r_constraint() = c) do
    mk_conj_constraint_list([c])
  end

  defp wrap_simple_constr(r_constraint_list() = c) do
    c
  end

  defp wrap_simple_constr(r_constraint_ref() = c) do
    c
  end

  defp enumerate_constraints(state) do
    cs = (for id <- state__scc(state) do
            mk_constraint_ref(id,
                                get_deps(state__get_cs(id, state)))
          end)
    {_, _, newState} = enumerate_constraints(cs, 0, [],
                                               state)
    newState
  end

  defp enumerate_constraints([r_constraint_ref(id: id) = c | tail], n, acc, state) do
    cs = state__get_cs(id, state)
    {[newCs], newN, newState1} = enumerate_constraints([cs],
                                                         n, [], state)
    newState2 = state__store_constrs(id, newCs, newState1)
    enumerate_constraints(tail, newN + 1, [c | acc],
                            newState2)
  end

  defp enumerate_constraints([r_constraint_list(type: :conj, list: list) = c | tail], n, acc,
            state) do
    {flat, deep} = :lists.partition(fn r_constraint() ->
                                         true
                                       r_constraint_list() ->
                                         false
                                       r_constraint_ref() ->
                                         false
                                    end,
                                      list)
    {newFlat, n1, state1} = enumerate_constraints(flat, n,
                                                    [], state)
    {newDeep, n2, state2} = enumerate_constraints(deep, n1,
                                                    [], state1)
    {newList, n3} = (cond do
                       newFlat === [] ->
                         {newDeep, n2}
                       newDeep === [] ->
                         {newFlat, n2}
                       true ->
                         tmpCList = mk_conj_constraint_list(newFlat)
                         {[r_constraint_list(tmpCList, id: {:list, n2}) | newDeep], n2 + 1}
                     end)
    newAcc = [r_constraint_list(c, list: newList,  id: {:list, n3}) | acc]
    enumerate_constraints(tail, n3 + 1, newAcc, state2)
  end

  defp enumerate_constraints([r_constraint_list(list: list, type: :disj) = c | tail], n, acc,
            state) do
    {newList, newN, newState} = enumerate_constraints(list,
                                                        n, [], state)
    newAcc = [r_constraint_list(c, list: newList,  id: {:list, newN}) | acc]
    enumerate_constraints(tail, newN + 1, newAcc, newState)
  end

  defp enumerate_constraints([r_constraint() = c | tail], n, acc, state) do
    enumerate_constraints(tail, n, [c | acc], state)
  end

  defp enumerate_constraints([], n, acc, state) do
    {:lists.reverse(acc), n, state}
  end

  defp order_fun_constraints(state) do
    cs = (for id <- state__scc(state) do
            mk_constraint_ref(id,
                                get_deps(state__get_cs(id, state)))
          end)
    order_fun_constraints(cs, state)
  end

  defp order_fun_constraints([r_constraint_ref(id: id) | tail], state) do
    cs = state__get_cs(id, state)
    {[cs1], state1} = order_fun_constraints([cs], [], [],
                                              state)
    newCs = r_constraint_list(cs1, deps: r_constraint_list(cs, :deps))
    newState = state__store_constrs(id, newCs, state1)
    order_fun_constraints(tail, newState)
  end

  defp order_fun_constraints([], state) do
    state
  end

  defp order_fun_constraints([r_constraint_ref() = c | tail], funs, acc, state) do
    order_fun_constraints(tail, [c | funs], acc, state)
  end

  defp order_fun_constraints([r_constraint_list(list: list, type: type,
               masks: oldMasks) = c |
               tail],
            funs, acc, state) do
    case (oldMasks) do
      :undefined ->
        {newList, newState} = (case (type) do
                                 :conj ->
                                   order_fun_constraints(list, [], [], state)
                                 :disj ->
                                   foldFun = fn x, accState ->
                                                  {[newX],
                                                     newAccState} = order_fun_constraints([x],
                                                                                            [],
                                                                                            [],
                                                                                            accState)
                                                  {newX, newAccState}
                                             end
                                   :lists.mapfoldl(foldFun, state, list)
                               end)
        newList2 = reset_deps(newList, state)
        c1 = update_constraint_list(c, newList2)
        masks = calculate_masks(newList, 1, [])
        newAcc = [update_masks(c1, masks) | acc]
        order_fun_constraints(tail, funs, newAcc, newState)
      m when is_map(m) ->
        order_fun_constraints(tail, funs, [c | acc], state)
    end
  end

  defp order_fun_constraints([r_constraint() = c | tail], funs, acc, state) do
    order_fun_constraints(tail, funs, [c | acc], state)
  end

  defp order_fun_constraints([], funs, acc, state) do
    newState = order_fun_constraints(funs, state)
    {:lists.reverse(acc) ++ funs, newState}
  end

  defp update_masks(c, masks) do
    r_constraint_list(c, masks: masks)
  end

  defp reset_deps(constrList, r_state(solvers: solvers)) do
    case (:lists.member(:v1, solvers)) do
      true ->
        constrList
      false ->
        for constr <- constrList do
          reset_deps(constr)
        end
    end
  end

  defp reset_deps(r_constraint() = c) do
    r_constraint(c, deps: [])
  end

  defp reset_deps(r_constraint_list() = c) do
    r_constraint_list(c, deps: [])
  end

  defp reset_deps(r_constraint_ref() = c) do
    r_constraint_ref(c, deps: [])
  end

  defp calculate_masks([c | cs], i, l0) do
    calculate_masks(cs, i + 1,
                      (for v <- get_deps(c) do
                         {v, i}
                       end) ++ l0)
  end

  defp calculate_masks([], _I, l) do
    m = family(l)
    :maps.from_list(m)
  end

  defp bif_return(m, f, a, xs) do
    :erl_bif_types.type(m, f, a, xs)
  end

  defp is_singleton_non_number_type(type) do
    case (t_is_number(type)) do
      true ->
        false
      false ->
        is_singleton_type(type)
    end
  end

  defp is_singleton_type(type) do
    case (t_is_atom(type)) do
      true ->
        case (t_atom_vals(type)) do
          :unknown ->
            false
          [_] ->
            true
          [_ | _] ->
            false
        end
      false ->
        case (t_is_integer(type)) do
          true ->
            case (t_number_vals(type)) do
              :unknown ->
                false
              [_] ->
                true
              [_ | _] ->
                false
            end
          false ->
            t_is_nil(type)
        end
    end
  end

  defp find_element(args, cs) do
    [pos, tuple] = args
    case (t_is_number(pos)) do
      true ->
        case (:erl_types.t_number_vals(pos)) do
          :unknown ->
            :unknown
          [i] ->
            case (find_constraint(tuple, cs)) do
              :unknown ->
                :unknown
              r_constraint(lhs: exTuple) ->
                case (:erl_types.t_is_tuple(exTuple)) do
                  true ->
                    elems = :erl_types.t_tuple_args(exTuple)
                    elem = :lists.nth(i, elems)
                    case (:erl_types.t_is_var(elem)) do
                      true ->
                        elem
                      false ->
                        :unknown
                    end
                  false ->
                    :unknown
                end
            end
          _ ->
            :unknown
        end
      false ->
        :unknown
    end
  end

  defp find_constraint(_Tuple, []) do
    :unknown
  end

  defp find_constraint(tuple, [r_constraint(op: :eq, rhs: tuple) = c | _]) do
    c
  end

  defp find_constraint(tuple, [r_constraint_list(list: list) | cs]) do
    find_constraint(tuple, list ++ cs)
  end

  defp find_constraint(tuple, [_ | cs]) do
    find_constraint(tuple, cs)
  end

  defp is_foldable(tree, state) do
    :dialyzer_utils.is_foldable(tree,
                                  state__is_in_match(state))
  end

  defp lookup_record(state, tag, arity) do
    r_state(module: m, mod_records: modRecs,
        cserver: cServer) = state
    {state1, rec} = (case (:lists.keyfind(m, 1, modRecs)) do
                       {^m, rec0} ->
                         {state, rec0}
                       false ->
                         rec0 = :dialyzer_codeserver.lookup_mod_records(m,
                                                                          cServer)
                         newModRecs = [{m, rec0} | modRecs]
                         {r_state(state, mod_records: newModRecs), rec0}
                     end)
    case (:erl_types.lookup_record(tag, arity, rec)) do
      {:ok, fields} ->
        recType = t_tuple([t_from_term(tag) | for {_FieldName,
                                                     _Abstr,
                                                     fieldType} <- fields do
                                                fieldType
                                              end])
        {:ok, recType, state1}
      :error ->
        {:error, state1}
    end
  end

  defp is_literal_record(tree) do
    ann = :cerl.get_ann(tree)
    :lists.member(:record, ann)
  end

  defp family(l) do
    :dialyzer_utils.family(l)
  end

  defp debug_make_name_map(_Vars, _Funs) do
    :ok
  end

  defp pp_constrs_scc(_SCC, _State) do
    :ok
  end

  defp constraints_to_dot_scc(_SCC, _State) do
    :ok
  end

end