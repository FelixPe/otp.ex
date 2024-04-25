defmodule :m_dialyzer_succ_typings do
  use Bitwise
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
  Record.defrecord(:r_st, :st, callgraph: :undefined,
                              codeserver: :undefined, timing_server: :undefined,
                              solvers: :undefined, plt: :undefined)
  def analyze_callgraph(callgraph, plt, codeserver, timingServer,
           solvers) do
    _ = get_success_typings(callgraph, plt, codeserver,
                              timingServer, solvers)
    plt
  end

  def get_warnings(callgraph, plt, docPlt, codeserver, timingServer,
           solvers) do
    initState = get_success_typings(callgraph, plt,
                                      codeserver, timingServer, solvers)
    mods = :dialyzer_callgraph.modules(r_st(initState, :callgraph))
    cWarns = :dialyzer_contracts.get_invalid_contract_warnings(mods,
                                                                 codeserver,
                                                                 plt)
    modWarns = ((
                  :dialyzer_timing.start_stamp(timingServer, 'warning')
                  _T = get_warnings_from_modules(mods, initState, docPlt)
                  :dialyzer_timing.end_stamp(timingServer)
                  _T
                ))
    {postprocess_warnings(cWarns ++ modWarns, codeserver),
       plt, docPlt}
  end

  def find_succ_types_for_scc(sCC0, {codeserver, callgraph, plt, solvers}) do
    sCC = (for ({_, _, _} = mFA) <- sCC0 do
             mFA
           end)
    label = :dialyzer_codeserver.get_next_core_label(codeserver)
    f = fn mFA ->
             {_Var, fun} = :dialyzer_codeserver.lookup_mfa_code(mFA,
                                                                  codeserver)
             collect_fun_info(fun)
        end
    allFuns = :lists.flatmap(f, sCC)
    propTypes = get_fun_types_from_plt(allFuns, callgraph,
                                         plt)
    funTypes = :dialyzer_typesig.analyze_scc(sCC, label,
                                               callgraph, codeserver, plt,
                                               propTypes, solvers)
    allFunKeys = (for {x, _} <- allFuns do
                    x
                  end)
    set = :sofs.set(allFunKeys, [:id])
    binRel = :sofs.from_external(funTypes, [{:id, :type}])
    filteredFunTypes = :sofs.to_external(:sofs.restriction(binRel,
                                                             set))
    funMFAContracts = get_contracts(filteredFunTypes,
                                      callgraph, codeserver)
    modOpaques = get_module_opaques(funMFAContracts,
                                      codeserver)
    decoratedFunTypes = decorate_succ_typings(funMFAContracts,
                                                modOpaques)
    contracts = :orddict.from_list(for {_,
                                          {mFA, contract}} <- funMFAContracts do
                                     {mFA, contract}
                                   end)
    pltContracts = :dialyzer_contracts.check_contracts(contracts,
                                                         callgraph,
                                                         decoratedFunTypes,
                                                         modOpaques)
    debug_pp_functions('SCC', filteredFunTypes,
                         decoratedFunTypes, callgraph)
    newPltContracts = (for ({mFA, _C} = mC) <- pltContracts,
                             not :dialyzer_plt.is_contract(plt, mFA) do
                         mC
                       end)
    _ = insert_into_plt(decoratedFunTypes, callgraph, plt)
    _ = :dialyzer_plt.insert_contract_list(plt,
                                             newPltContracts)
    case (newPltContracts === [] and reached_fixpoint_strict(propTypes,
                                                               decoratedFunTypes)) do
      true ->
        []
      false ->
        :ok
        allFunKeys
    end
  end

  def refine_one_module(m, {codeServer, callgraph, plt, _Solvers}) do
    modCode = :dialyzer_codeserver.lookup_mod_code(m,
                                                     codeServer)
    allFuns = collect_fun_info(modCode)
    funTypes = get_fun_types_from_plt(allFuns, callgraph,
                                        plt)
    records = :dialyzer_codeserver.lookup_mod_records(m,
                                                        codeServer)
    newFunTypes = :dialyzer_dataflow.get_fun_types(modCode,
                                                     plt, callgraph, codeServer,
                                                     records)
    funMFAContracts = get_contracts(newFunTypes, callgraph,
                                      codeServer)
    modOpaques = get_module_opaques(funMFAContracts,
                                      codeServer)
    decoratedFunTypes = decorate_succ_typings(funMFAContracts,
                                                modOpaques)
    debug_pp_functions('Refine', newFunTypes, decoratedFunTypes,
                         callgraph)
    case (updated_types(funTypes, decoratedFunTypes)) do
      [] ->
        []
      [_ | _] = notFixpoint ->
        :ok
        _ = insert_into_plt(notFixpoint, callgraph, plt)
        for {funLbl, _Type} <- notFixpoint do
          funLbl
        end
    end
  end

  def collect_warnings(m, {codeserver, callgraph, plt, docPlt}) do
    modCode = :dialyzer_codeserver.lookup_mod_code(m,
                                                     codeserver)
    contracts = :dialyzer_codeserver.lookup_mod_contracts(m,
                                                            codeserver)
    allFuns = collect_fun_info(modCode)
    warnings1 = :dialyzer_contracts.contracts_without_fun(contracts,
                                                            allFuns, callgraph)
    attrs = :cerl.module_attrs(modCode)
    records = :dialyzer_codeserver.lookup_mod_records(m,
                                                        codeserver)
    {warnings2,
       funTypes} = :dialyzer_dataflow.get_warnings(modCode,
                                                     plt, callgraph, codeserver,
                                                     records)
    warnings3 = :dialyzer_behaviours.check_callbacks(m,
                                                       attrs, records, plt,
                                                       codeserver)
    ^docPlt = insert_into_doc_plt(funTypes, callgraph,
                                    docPlt)
    :lists.flatten([warnings1, warnings2, warnings3])
  end

  def find_depends_on(sCC, {_Codeserver, callgraph, _Plt, _Solvers}) do
    :dialyzer_callgraph.get_depends_on(sCC, callgraph)
  end

  def add_to_result(labels, result,
           {_Codeserver, callgraph, _Plt, _Solver}) do
    (for label <- labels do
       lookup_name(label, callgraph)
     end) ++ result
  end

  defp get_success_typings(callgraph, plt, codeserver, timingServer,
            solvers) do
    {labelledSCCs, callgraph1} = ((
                                    :dialyzer_timing.start_stamp(timingServer,
                                                                   'order')
                                    _T = :dialyzer_callgraph.finalize(callgraph)
                                    :dialyzer_timing.end_stamp(timingServer)
                                    _T
                                  ))
    state = r_st(callgraph: callgraph1, plt: plt,
                codeserver: codeserver, timing_server: timingServer,
                solvers: solvers)
    get_refined_success_typings(labelledSCCs, state)
  end

  defp get_refined_success_typings(labelledSCCs,
            r_st(callgraph: callgraph,
                timing_server: timingServer) = state) do
    case (find_succ_typings(labelledSCCs, state)) do
      [] ->
        state
      notFixpoint1 ->
        {modulePostorder, modCallgraph} = ((
                                             :dialyzer_timing.start_stamp(timingServer,
                                                                            'order')
                                             _C1 = :dialyzer_callgraph.module_postorder_from_funs(notFixpoint1,
                                                                                                    callgraph)
                                             :dialyzer_timing.end_stamp(timingServer)
                                             _C1
                                           ))
        modState = r_st(state, callgraph: modCallgraph)
        case (refine_succ_typings(modulePostorder, modState)) do
          [] ->
            modState
          notFixpoint2 ->
            {newLabelledSCCs, callgraph2} = ((
                                               :dialyzer_timing.start_stamp(timingServer,
                                                                              'order')
                                               _C2 = :dialyzer_callgraph.reset_from_funs(notFixpoint2,
                                                                                           modCallgraph)
                                               :dialyzer_timing.end_stamp(timingServer)
                                               _C2
                                             ))
            newState = r_st(modState, callgraph: callgraph2)
            get_refined_success_typings(newLabelledSCCs, newState)
        end
    end
  end

  defp find_succ_typings(labelledSCCs, state) do
    {init, timing} = init_pass_data(state)
    updated = ((
                 :dialyzer_timing.start_stamp(timing, 'typesig')
                 _T = :dialyzer_coordinator.parallel_job(:typesig,
                                                           labelledSCCs, init,
                                                           timing)
                 :dialyzer_timing.end_stamp(timing)
                 _T
               ))
    :ok
    updated
  end

  defp refine_succ_typings(modules, state) do
    {init, timing} = init_pass_data(state)
    updated = ((
                 :dialyzer_timing.start_stamp(timing, 'refine')
                 _T = :dialyzer_coordinator.parallel_job(:dataflow,
                                                           modules, init,
                                                           timing)
                 :dialyzer_timing.end_stamp(timing)
                 _T
               ))
    :ok
    updated
  end

  defp init_pass_data(r_st(codeserver: codeserver, callgraph: callgraph,
              plt: plt, timing_server: timing, solvers: solvers)) do
    init = {codeserver, callgraph, plt, solvers}
    {init, timing}
  end

  defp get_warnings_from_modules(mods, state, docPlt) do
    r_st(callgraph: callgraph, codeserver: codeserver,
        plt: plt, timing_server: timingServer) = state
    init = {codeserver, callgraph, plt, docPlt}
    :dialyzer_coordinator.parallel_job(:warnings, mods,
                                         init, timingServer)
  end

  defp postprocess_warnings(rawWarnings, codeserver) do
    pred = fn {:warn_contract_range, _, _} ->
                true
              _ ->
                false
           end
    {cRWarns, nonCRWarns} = :lists.partition(pred,
                                               rawWarnings)
    postprocess_dataflow_warns(cRWarns, codeserver,
                                 nonCRWarns, [])
  end

  defp postprocess_dataflow_warns([], _Callgraph, wAcc, acc) do
    :lists.reverse(acc, wAcc)
  end

  defp postprocess_dataflow_warns([{:warn_contract_range, warningInfo, msg} |
               rest],
            codeserver, wAcc, acc) do
    {callF, callL, _CallMFA} = warningInfo
    {:contract_range,
       [contract, m, f, a, argStrings, cRet]} = msg
    case (:dialyzer_codeserver.lookup_mfa_contract({m, f,
                                                      a},
                                                     codeserver)) do
      {:ok, {{contrF, contrL}, _C, _X}} ->
        case (callF === contrF) do
          true ->
            newMsg = {:contract_range,
                        [contract, m, f, argStrings, callL, cRet]}
            warningInfo2 = {contrF, contrL, {m, f, a}}
            w = {:warn_contract_range, warningInfo2, newMsg}
            filter = fn {:warn_contract_types, wI, _}
                            when wI === warningInfo2 ->
                          false
                        _ ->
                          true
                     end
            filterWAcc = :lists.filter(filter, wAcc)
            postprocess_dataflow_warns(rest, codeserver, filterWAcc,
                                         [w | acc])
          false ->
            postprocess_dataflow_warns(rest, codeserver, wAcc, acc)
        end
      :error ->
        newMsg = {:contract_range,
                    [contract, m, f, argStrings, callL, cRet]}
        w = {:warn_contract_range, warningInfo, newMsg}
        postprocess_dataflow_warns(rest, codeserver, wAcc,
                                     [w | acc])
    end
  end

  defp reached_fixpoint_strict([{key, type1} | types1],
            [{key, type2} | types2]) do
    case (is_failed_or_not_called_fun(type2)) do
      true ->
        reached_fixpoint_strict(types1, types2)
      false ->
        limitedType1 = :erl_types.t_limit(type1, 4)
        limitedType2 = :erl_types.t_limit(type2, 4)
        :erl_types.t_is_equal(limitedType1,
                                limitedType2) and reached_fixpoint_strict(types1,
                                                                            types2)
    end
  end

  defp reached_fixpoint_strict([{key1, _} | types1], [{key2, _} | _] = types2)
      when key1 < key2 do
    reached_fixpoint_strict(types1, types2)
  end

  defp reached_fixpoint_strict([], []) do
    true
  end

  defp updated_types(oldTypes, newTypes) do
    updated_types_1(oldTypes, newTypes, [])
  end

  defp updated_types_1([{key, type1} | types1],
            [{key, type2} | types2], acc) do
    case (is_failed_or_not_called_fun(type2)) do
      true ->
        updated_types_1(types1, types2, acc)
      false ->
        limitedType1 = :erl_types.t_limit(type1, 4)
        limitedType2 = :erl_types.t_limit(type2, 4)
        case (:erl_types.t_is_subtype(limitedType1,
                                        limitedType2)) do
          true ->
            updated_types_1(types1, types2, acc)
          false ->
            :ok
            updated_types_1(types1, types2, [{key, type2} | acc])
        end
    end
  end

  defp updated_types_1([], [], acc) do
    acc
  end

  defp is_failed_or_not_called_fun(type) do
    :erl_types.any_none([:erl_types.t_fun_range(type) |
                             :erl_types.t_fun_args(type)])
  end

  defp get_contracts(funTypes, callgraph, codeserver) do
    f = fn {label, _Type} = labelType, acc ->
             case (:dialyzer_callgraph.lookup_name(label,
                                                     callgraph)) do
               {:ok, mFA} ->
                 case (:dialyzer_codeserver.lookup_mfa_contract(mFA,
                                                                  codeserver)) do
                   {:ok, {_FileLocation, contract, _Xtra}} ->
                     [{labelType, {mFA, contract}} | acc]
                   :error ->
                     [{labelType, :no} | acc]
                 end
               :error ->
                 [{labelType, :no} | acc]
             end
        end
    :lists.foldl(f, [], funTypes)
  end

  defp get_module_opaques(contracts, codeserver) do
    opaqueModules = :ordsets.from_list(for {_LabelType,
                                              {{m, _, _}, _Con}} <- contracts do
                                         m
                                       end)
    for m <- opaqueModules do
      {m, lookup_opaques(m, codeserver)}
    end
  end

  defp decorate_succ_typings(funTypesContracts, modOpaques) do
    f = fn {{label, type}, {{m, _, _}, contract}}, acc ->
             case (:lists.keyfind(m, 1, modOpaques)) do
               {^m, []} ->
                 [{label, type} | acc]
               {^m, opaques} ->
                 args = :dialyzer_contracts.get_contract_args(contract)
                 ret = :dialyzer_contracts.get_contract_return(contract)
                 c = :erl_types.t_fun(args, ret)
                 r = :erl_types.t_decorate_with_opaque(type, c, opaques)
                 [{label, r} | acc]
             end
           {labelType, :no}, acc ->
             [labelType | acc]
        end
    :orddict.from_list(:lists.foldl(f, [],
                                      funTypesContracts))
  end

  defp lookup_opaques(module, codeserver) do
    records = :dialyzer_codeserver.lookup_mod_records(module,
                                                        codeserver)
    :erl_types.t_opaque_from_records(records)
  end

  defp get_fun_types_from_plt(funList, callgraph, plt) do
    get_fun_types_from_plt(funList, callgraph, plt, [])
  end

  defp get_fun_types_from_plt([{funLabel, arity} | left], callgraph, plt,
            map) do
    type = lookup_fun_type(funLabel, arity, callgraph, plt)
    get_fun_types_from_plt(left, callgraph, plt,
                             [{funLabel, type} | map])
  end

  defp get_fun_types_from_plt([], _Callgraph, _Plt, map) do
    :orddict.from_list(map)
  end

  defp collect_fun_info(tree) do
    fun = fn subTree, acc ->
               case (:cerl.is_c_fun(subTree)) do
                 true ->
                   [{:cerl_trees.get_label(subTree),
                       :cerl.fun_arity(subTree)} |
                        acc]
                 false ->
                   acc
               end
          end
    :cerl_trees.fold(fun, [], tree)
  end

  defp lookup_fun_type(label, arity, callgraph, plt) do
    iD = lookup_name(label, callgraph)
    case (:dialyzer_plt.lookup(plt, iD)) do
      :none ->
        :erl_types.t_fun(arity, :erl_types.t_any())
      {:value, {retT, argT}} ->
        :erl_types.t_fun(argT, retT)
    end
  end

  defp insert_into_doc_plt(_FunTypes, _Callgraph, :undefined) do
    :undefined
  end

  defp insert_into_doc_plt(funTypes, callgraph, docPlt) do
    succTypes = format_succ_types(funTypes, callgraph)
    :dialyzer_plt.insert_list(docPlt, succTypes)
  end

  defp insert_into_plt(succTypes0, callgraph, plt) do
    succTypes = format_succ_types(succTypes0, callgraph)
    debug_pp_succ_typings(succTypes)
    :dialyzer_plt.insert_list(plt, succTypes)
  end

  defp format_succ_types(succTypes, callgraph) do
    format_succ_types(succTypes, callgraph, [])
  end

  defp format_succ_types([{label, type0} | left], callgraph, acc) do
    type = :erl_types.t_limit(type0, 4 + 1)
    id = lookup_name(label, callgraph)
    newTuple = {id,
                  {:erl_types.t_fun_range(type),
                     :erl_types.t_fun_args(type)}}
    format_succ_types(left, callgraph, [newTuple | acc])
  end

  defp format_succ_types([], _Callgraph, acc) do
    acc
  end

  defp lookup_name(f, cG) do
    case (:dialyzer_callgraph.lookup_name(f, cG)) do
      :error ->
        f
      {:ok, name} ->
        name
    end
  end

  defp debug_pp_succ_typings(_) do
    :ok
  end

  defp debug_pp_functions(_, _, _, _) do
    :ok
  end

end