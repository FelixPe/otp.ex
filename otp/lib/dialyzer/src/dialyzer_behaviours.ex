defmodule :m_dialyzer_behaviours do
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
  Record.defrecord(:r_state, :state, plt: :undefined,
                                 codeserver: :undefined, filename: :undefined,
                                 behlines: :undefined, records: :undefined)
  def check_callbacks(module, attrs, records, plt, codeserver) do
    {behaviours, behLines} = get_behaviours(attrs)
    case (behaviours) do
      [] ->
        []
      _ ->
        mFA = {module, :module_info, 0}
        {_Var, code} = :dialyzer_codeserver.lookup_mfa_code(mFA,
                                                              codeserver)
        file = get_file(codeserver, module, :cerl.get_ann(code))
        state = r_state(plt: plt, filename: file, behlines: behLines,
                    codeserver: codeserver, records: records)
        warnings = get_warnings(module, behaviours, state)
        for w <- warnings do
          add_tag_warning_info(module, w, state)
        end
    end
  end

  def get_behaviours(attrs) do
    behaviourListsAndLocation = (for {l1, l2} <- attrs,
                                       :cerl.is_literal(l1),
                                       :cerl.is_literal(l2),
                                       :cerl.concrete(l1) === :behaviour or :cerl.concrete(l1) === :behavior do
                                   {:cerl.concrete(l2), hd(:cerl.get_ann(l2))}
                                 end)
    behaviours = :lists.append(for {behs,
                                      _} <- behaviourListsAndLocation do
                                 behs
                               end)
    behLocations = (for {l1,
                           l} <- behaviourListsAndLocation,
                          b <- l1 do
                      {b, l}
                    end)
    {behaviours, behLocations}
  end

  defp get_warnings(module, behaviours, state) do
    get_warnings(module, behaviours, state, [])
  end

  defp get_warnings(_, [], _, acc) do
    acc
  end

  defp get_warnings(module, [behaviour | rest], state, acc) do
    newAcc = check_behaviour(module, behaviour, state, acc)
    get_warnings(module, rest, state, newAcc)
  end

  defp check_behaviour(module, behaviour, r_state(plt: plt) = state, acc) do
    case (:dialyzer_plt.lookup_callbacks(plt, behaviour)) do
      :none ->
        [{:callback_info_missing, [behaviour]} | acc]
      {:value, callbacks} ->
        check_all_callbacks(module, behaviour, callbacks, state,
                              acc)
    end
  end

  defp check_all_callbacks(_Module, _Behaviour, [], _State, acc) do
    acc
  end

  defp check_all_callbacks(module, behaviour, [cb | rest],
            r_state(plt: plt, codeserver: codeserver) = state, acc0) do
    {{^behaviour, function, arity},
       {{_BehFile, _BehLocation}, callback, xtra}} = cb
    cbMFA = {module, function, arity}
    acc1 = (case (:dialyzer_plt.lookup(plt, cbMFA)) do
              :none ->
                case (:lists.member(:optional_callback, xtra)) do
                  true ->
                    acc0
                  false ->
                    [{:callback_missing, [behaviour, function, arity]} |
                         acc0]
                end
              {:value, retArgTypes} ->
                case (:dialyzer_codeserver.is_exported(cbMFA,
                                                         codeserver)) do
                  true ->
                    check_callback(retArgTypes, cbMFA, behaviour, callback,
                                     state, acc0)
                  false ->
                    case (:lists.member(:optional_callback, xtra)) do
                      true ->
                        acc0
                      false ->
                        [{:callback_not_exported,
                            [behaviour, function, arity]} |
                             acc0]
                    end
                end
            end)
    check_all_callbacks(module, behaviour, rest, state,
                          acc1)
  end

  defp check_callback(retArgTypes, cbMFA, behaviour, callback,
            r_state(plt: _Plt, codeserver: codeserver, records: records),
            acc0) do
    {_Module, function, arity} = cbMFA
    cbReturnType = :dialyzer_contracts.get_contract_return(callback)
    cbArgTypes = :dialyzer_contracts.get_contract_args(callback)
    {returnType, argTypes} = retArgTypes
    acc1 = (case (not
                  :erl_types.t_is_none(returnType) and :erl_types.t_is_none(:erl_types.t_inf(returnType,
                                                                                               cbReturnType))) do
              false ->
                acc0
              true ->
                [{:callback_type_mismatch,
                    [behaviour, function, arity,
                                              :erl_types.t_to_string(returnType,
                                                                       records),
                                                  :erl_types.t_to_string(cbReturnType,
                                                                           records)]} |
                     acc0]
            end)
    acc2 = (case (:erl_types.any_none(:erl_types.t_inf_lists(argTypes,
                                                               cbArgTypes))) do
              false ->
                acc1
              true ->
                find_mismatching_args(:type, argTypes, cbArgTypes,
                                        behaviour, function, arity, records, 1,
                                        acc1)
            end)
    case (:dialyzer_codeserver.lookup_mfa_contract(cbMFA,
                                                     codeserver)) do
      :error ->
        acc2
      {:ok, {{file, location}, contract, _Xtra}} ->
        specReturnType0 = :dialyzer_contracts.get_contract_return(contract)
        specArgTypes0 = :dialyzer_contracts.get_contract_args(contract)
        specReturnType = :erl_types.subst_all_vars_to_any(specReturnType0)
        specArgTypes = (for argT0 <- specArgTypes0 do
                          :erl_types.subst_all_vars_to_any(argT0)
                        end)
        acc3 = (case (not
                      :erl_types.t_is_none(specReturnType) and :erl_types.t_is_none(:erl_types.t_inf(specReturnType,
                                                                                                       cbReturnType))) do
                  false ->
                    acc2
                  true ->
                    extraType = :erl_types.t_subtract(specReturnType,
                                                        cbReturnType)
                    [{:callback_spec_type_mismatch,
                        [file, location, behaviour, function, arity,
                                                                  :erl_types.t_to_string(extraType,
                                                                                           records),
                                                                      :erl_types.t_to_string(cbReturnType,
                                                                                               records)]} |
                         acc2]
                end)
        case (:erl_types.any_none(:erl_types.t_inf_lists(specArgTypes,
                                                           cbArgTypes))) do
          false ->
            acc3
          true ->
            find_mismatching_args({:spec, file, location},
                                    specArgTypes, cbArgTypes, behaviour,
                                    function, arity, records, 1, acc3)
        end
    end
  end

  defp find_mismatching_args(_, [], [], _Beh, _Function, _Arity, _Records,
            _N, acc) do
    acc
  end

  defp find_mismatching_args(kind, [type | rest], [cbType | cbRest],
            behaviour, function, arity, records, n, acc) do
    case (:erl_types.t_is_none(:erl_types.t_inf(type,
                                                  cbType))) do
      false ->
        find_mismatching_args(kind, rest, cbRest, behaviour,
                                function, arity, records, n + 1, acc)
      true ->
        info = [behaviour, function, arity, n,
                                                :erl_types.t_to_string(type,
                                                                         records),
                                                    :erl_types.t_to_string(cbType,
                                                                             records)]
        newAcc = [case (kind) do
                    :type ->
                      {:callback_arg_type_mismatch, info}
                    {:spec, file, location} ->
                      {:callback_spec_arg_type_mismatch,
                         [file, location | info]}
                  end |
                      acc]
        find_mismatching_args(kind, rest, cbRest, behaviour,
                                function, arity, records, n + 1, newAcc)
    end
  end

  defp add_tag_warning_info(module, {tag, [b | _R]} = warn, state)
      when tag === :callback_missing or
             tag === :callback_info_missing do
    {^b, location} = :lists.keyfind(b, 1,
                                      r_state(state, :behlines))
    category = (case (tag) do
                  :callback_missing ->
                    :warn_behaviour
                  :callback_info_missing ->
                    :warn_undefined_callbacks
                end)
    {category, {r_state(state, :filename), location, module},
       warn}
  end

  defp add_tag_warning_info(module, {tag, [file, location | r]}, _State)
      when tag === :callback_spec_type_mismatch or
             tag === :callback_spec_arg_type_mismatch do
    {:warn_behaviour, {file, location, module}, {tag, r}}
  end

  defp add_tag_warning_info(module, {_Tag, [_B, fun, arity | _R]} = warn,
            state) do
    {_A,
       funCode} = :dialyzer_codeserver.lookup_mfa_code({module,
                                                          fun, arity},
                                                         r_state(state, :codeserver))
    anns = :cerl.get_ann(funCode)
    file = get_file(r_state(state, :codeserver), module, anns)
    warningInfo = {file, get_location(funCode),
                     {module, fun, arity}}
    {:warn_behaviour, warningInfo, warn}
  end

  defp get_location(tree) do
    :dialyzer_utils.get_location(tree, - 1)
  end

  defp get_file(codeserver, module, [{:file, fakeFile} | _]) do
    :dialyzer_codeserver.translate_fake_file(codeserver,
                                               module, fakeFile)
  end

  defp get_file(codeserver, module, [_ | tail]) do
    get_file(codeserver, module, tail)
  end

end