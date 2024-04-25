defmodule :m_dialyzer_dataflow do
  use Bitwise

  import :erl_types,
    only: [
      any_none: 1,
      t_any: 0,
      t_atom: 0,
      t_atom: 1,
      t_atom_vals: 1,
      t_atom_vals: 2,
      t_binary: 0,
      t_bitstr: 0,
      t_bitstr: 2,
      t_bitstr_concat: 1,
      t_bitstr_match: 2,
      t_boolean: 0,
      t_cons: 0,
      t_cons: 2,
      t_cons_hd: 2,
      t_cons_tl: 2,
      t_contains_opaque: 2,
      t_find_opaque_mismatch: 3,
      t_float: 0,
      t_from_range: 2,
      t_from_term: 1,
      t_fun: 0,
      t_fun: 2,
      t_fun_args: 1,
      t_fun_args: 2,
      t_fun_range: 1,
      t_fun_range: 2,
      t_inf: 2,
      t_inf: 3,
      t_inf_lists: 2,
      t_inf_lists: 3,
      t_integer: 0,
      t_integers: 1,
      t_is_any: 1,
      t_is_any_atom: 3,
      t_is_atom: 1,
      t_is_atom: 2,
      t_is_boolean: 2,
      t_is_equal: 2,
      t_is_impossible: 1,
      t_is_integer: 2,
      t_is_list: 1,
      t_is_nil: 2,
      t_is_none: 1,
      t_is_number: 2,
      t_is_pid: 2,
      t_is_port: 2,
      t_is_reference: 2,
      t_is_singleton: 2,
      t_is_subtype: 2,
      t_is_unit: 1,
      t_limit: 2,
      t_list: 0,
      t_list_elements: 2,
      t_map: 0,
      t_map: 1,
      t_maybe_improper_list: 0,
      t_module: 0,
      t_non_neg_integer: 0,
      t_none: 0,
      t_number: 0,
      t_number_vals: 2,
      t_pid: 0,
      t_port: 0,
      t_product: 1,
      t_reference: 0,
      t_subtract: 2,
      t_sup: 1,
      t_sup: 2,
      t_to_string: 2,
      t_to_tlist: 1,
      t_tuple: 0,
      t_tuple: 1,
      t_tuple_args: 1,
      t_tuple_args: 2,
      t_tuple_subtypes: 2,
      t_unit: 0,
      t_unopaque: 2
    ]

  require Record

  Record.defrecord(:r_plt_info, :plt_info,
    files: :undefined,
    mod_deps: :dict.new()
  )

  Record.defrecord(:r_iplt_info, :iplt_info,
    files: :undefined,
    mod_deps: :dict.new(),
    warning_map: :none,
    legal_warnings: :none
  )

  Record.defrecord(:r_plt, :plt,
    info: :undefined,
    types: :undefined,
    contracts: :undefined,
    callbacks: :undefined,
    exported_types: :undefined
  )

  Record.defrecord(:r_analysis, :analysis,
    analysis_pid: :undefined,
    type: :succ_typings,
    defines: [],
    doc_plt: :undefined,
    files: [],
    include_dirs: [],
    start_from: :byte_code,
    plt: :undefined,
    use_contracts: true,
    behaviours_chk: false,
    timing: false,
    timing_server: :none,
    callgraph_file: ~c"",
    mod_deps_file: ~c"",
    solvers: :undefined
  )

  Record.defrecord(:r_options, :options,
    files: [],
    files_rec: [],
    warning_files: [],
    warning_files_rec: [],
    analysis_type: :succ_typings,
    timing: false,
    defines: [],
    from: :byte_code,
    get_warnings: :maybe,
    init_plts: [],
    include_dirs: [],
    output_plt: :none,
    legal_warnings: :ordsets.new(),
    report_mode: :normal,
    erlang_mode: false,
    use_contracts: true,
    output_file: :none,
    output_format: :formatted,
    filename_opt: :basename,
    indent_opt: true,
    callgraph_file: ~c"",
    mod_deps_file: ~c"",
    check_plt: true,
    error_location: :column,
    metrics_file: :none,
    module_lookup_file: :none,
    solvers: []
  )

  Record.defrecord(:r_contract, :contract, contracts: [], args: [], forms: [])

  Record.defrecord(:r_state, :state,
    callgraph: :undefined,
    codeserver: :undefined,
    envs: :undefined,
    fun_tab: :undefined,
    fun_homes: :undefined,
    reachable_funs: :undefined,
    plt: :undefined,
    opaques: :undefined,
    records: :dict.new(),
    tree_map: :undefined,
    warning_mode: false,
    warnings: [],
    work: :undefined,
    module: :undefined,
    curr_fun: :undefined
  )

  Record.defrecord(:r_map, :map,
    map: :maps.new(),
    subst: :maps.new(),
    modified: [],
    modified_stack: [],
    ref: :undefined
  )

  def get_warnings(tree, plt, callgraph, codeserver, records) do
    state1 = analyze_module(tree, plt, callgraph, codeserver, records, true)

    state2 =
      state__renew_warnings(
        state__get_warnings(state1),
        state1
      )

    {r_state(state2, :warnings), state__all_fun_types(state2)}
  end

  def get_fun_types(tree, plt, callgraph, codeserver, records) do
    state = analyze_module(tree, plt, callgraph, codeserver, records, false)
    state__all_fun_types(state)
  end

  defp analyze_module(tree, plt, callgraph, codeserver, records, getWarnings) do
    debug_pp(tree, false)
    module = :cerl.atom_val(:cerl.module_name(tree))
    topFun = :cerl.ann_c_fun([{:label, :top}], [], tree)
    state = state__new(callgraph, codeserver, topFun, plt, module, records)
    state1 = analyze_loop(state)

    case getWarnings do
      true ->
        state2 = state__set_warning_mode(state1)
        analyze_loop(state2)

      false ->
        state1
    end
  end

  defp analyze_loop(state) do
    case state__get_work(state) do
      :none ->
        state__set_curr_fun(:undefined, state)

      {fun, newState0} ->
        newState1 =
          state__set_curr_fun(
            get_label(fun),
            newState0
          )

        {argTypes, isCalled} =
          state__get_args_and_status(
            fun,
            newState1
          )

        case not isCalled do
          true ->
            :ok
            analyze_loop(newState1)

          false ->
            case state__fun_env(fun, newState1) do
              :none ->
                :ok
                analyze_loop(newState1)

              map ->
                :ok
                vars = :cerl.fun_vars(fun)
                map1 = enter_type_lists(vars, argTypes, map)
                body = :cerl.fun_body(fun)
                {newState2, _Map2, bodyType} = traverse(body, map1, newState1)
                :ok
                newState3 = state__update_fun_entry(fun, argTypes, bodyType, newState2)
                :ok
                analyze_loop(newState3)
            end
        end
    end
  end

  defp traverse(tree, map, state) do
    :ok

    case :cerl.type(tree) do
      :alias ->
        traverse(:cerl.alias_pat(tree), map, state)

      :apply ->
        handle_apply(tree, map, state)

      :binary ->
        segs = :cerl.binary_segments(tree)
        {state1, map1, segTypes} = traverse_list(segs, map, state)
        {state1, map1, t_bitstr_concat(segTypes)}

      :bitstr ->
        handle_bitstr(tree, map, state)

      :call ->
        handle_call(tree, map, state)

      :case ->
        handle_case(tree, map, state)

      :catch ->
        {state1, _Map1, _} = traverse(:cerl.catch_body(tree), map, state)
        {state1, map, t_any()}

      :cons ->
        handle_cons(tree, map, state)

      :fun ->
        type = state__fun_type(tree, state)

        case state__warning_mode(state) do
          true ->
            {state, map, type}

          false ->
            funLbl = get_label(tree)
            state2 = state__add_work(funLbl, state)
            state3 = state__update_fun_env(tree, map, state2)
            state4 = state__add_reachable(funLbl, state3)
            {state4, map, type}
        end

      :let ->
        handle_let(tree, map, state)

      :letrec ->
        defs = :cerl.letrec_defs(tree)
        body = :cerl.letrec_body(tree)

        foldFun = fn {var, fun}, {accState, accMap} ->
          {newAccState, newAccMap0, funType} =
            traverse(
              fun,
              accMap,
              accState
            )

          newAccMap = enter_type(var, funType, newAccMap0)
          {newAccState, newAccMap}
        end

        {state1, map1} = :lists.foldl(foldFun, {state, map}, defs)
        traverse(body, map1, state1)

      :literal ->
        type = literal_type(tree)
        {state, map, type}

      :primop ->
        handle_primop(tree, map, state)

      :seq ->
        arg = :cerl.seq_arg(tree)
        body = :cerl.seq_body(tree)
        {state1, map1, argType} = sMA = traverse(arg, map, state)

        case t_is_impossible(argType) do
          true ->
            sMA

          false ->
            state2 = maybe_warn_unmatched_return(arg, argType, state1)
            traverse(body, map1, state2)
        end

      :try ->
        handle_try(tree, map, state)

      :tuple ->
        handle_tuple(tree, map, state)

      :map ->
        handle_map(tree, map, state)

      :values ->
        elements = :cerl.values_es(tree)
        {state1, map1, esType} = traverse_list(elements, map, state)
        type = t_product(esType)
        {state1, map1, type}

      :var ->
        :ok

        case state__lookup_type_for_letrec(tree, state) do
          :error ->
            lType = lookup_type(tree, map)
            {state, map, lType}

          {:ok, type} ->
            {state, map, type}
        end

      other ->
        :erlang.error({:"Unsupported type", other})
    end
  end

  defp traverse_list(trees, map, state) do
    traverse_list(trees, map, state, [])
  end

  defp traverse_list([tree | tail], map, state, acc) do
    {state1, map1, type} = traverse(tree, map, state)
    traverse_list(tail, map1, state1, [type | acc])
  end

  defp traverse_list([], map, state, acc) do
    {state, map, :lists.reverse(acc)}
  end

  defp maybe_warn_unmatched_return(arg, argType, state) do
    case state__warning_mode(state) do
      false ->
        state

      true ->
        case t_is_any(argType) or
               t_is_simple(
                 argType,
                 state
               ) or is_call_to_send(arg) or
               is_lc_simple_list(
                 arg,
                 argType,
                 state
               ) do
          true ->
            state

          false ->
            state__add_warning(
              state,
              :warn_umatched_return,
              arg,
              {:unmatched_return, [format_type(argType, state)]}
            )
        end
    end
  end

  defp handle_apply(tree, map, state) do
    args = :cerl.apply_args(tree)
    op = :cerl.apply_op(tree)
    {state0, map1, argTypes} = traverse_list(args, map, state)
    {state1, map2, opType} = traverse(op, map1, state0)

    case any_none(argTypes) do
      true ->
        {state1, map2, t_none()}

      false ->
        funList =
          case state__lookup_call_site(
                 tree,
                 state
               ) do
            :error ->
              [:external]

            {:ok, list} ->
              list
          end

        funInfoList =
          for fun <- funList do
            {:local, state__fun_info(fun, state)}
          end

        case handle_apply_or_call(funInfoList, args, argTypes, map2, tree, state1) do
          {:had_external, state2} ->
            arity = length(args)
            opType1 = t_inf(opType, t_fun(arity, t_any()))

            case t_is_none(opType1) do
              true ->
                msg = {:fun_app_no_fun, [format_cerl(op), format_type(opType, state2), arity]}
                state3 = state__add_warning(state2, :warn_failing_call, tree, msg)
                {state3, map2, t_none()}

              false ->
                newArgs =
                  t_inf_lists(
                    argTypes,
                    t_fun_args(opType1, :universe)
                  )

                case any_none(newArgs) do
                  true ->
                    enumNewArgs =
                      :lists.zip(
                        :lists.seq(1, length(newArgs)),
                        newArgs
                      )

                    argNs =
                      for {arg, type} <- enumNewArgs,
                          t_is_none(type) do
                        arg
                      end

                    msg =
                      {:fun_app_args,
                       [argNs, format_args(args, argTypes, state), format_type(opType, state)]}

                    argTree = select_arg(argNs, args, tree)
                    state3 = state__add_warning(state2, :warn_failing_call, argTree, msg)
                    {state3, enter_type(op, opType1, map2), t_none()}

                  false ->
                    map3 = enter_type_lists(args, newArgs, map2)
                    range0 = t_fun_range(opType1, :universe)

                    range =
                      case t_is_unit(range0) do
                        true ->
                          t_none()

                        false ->
                          range0
                      end

                    {state2, enter_type(op, opType1, map3), range}
                end
            end

          normal ->
            normal
        end
    end
  end

  defp handle_apply_or_call(funInfoList, args, argTypes, map, tree, state) do
    none = t_none()

    handle_apply_or_call(
      funInfoList,
      args,
      argTypes,
      map,
      tree,
      state,
      for _ <- argTypes do
        none
      end,
      none,
      false,
      {:none, []}
    )
  end

  defp handle_apply_or_call(
         [{:local, :external} | left],
         args,
         argTypes,
         map,
         tree,
         state,
         _AccArgTypes,
         _AccRet,
         _HadExternal,
         warns
       ) do
    {howMany, _} = warns

    newHowMany =
      case howMany do
        :none ->
          :one

        _ ->
          :many
      end

    newWarns = {newHowMany, []}

    handle_apply_or_call(
      left,
      args,
      argTypes,
      map,
      tree,
      state,
      argTypes,
      t_any(),
      true,
      newWarns
    )
  end

  defp handle_apply_or_call(
         [
           {typeOfApply, {fun, sig, contr, localRet}}
           | left
         ],
         args,
         argTypes,
         map,
         tree,
         r_state(opaques: opaques) = state,
         accArgTypes,
         accRet,
         hadExternal,
         warns
       ) do
    any = t_any()

    anyArgs =
      for _ <- args do
        any
      end

    genSig =
      {anyArgs,
       fn _ ->
         t_any()
       end}

    {cArgs, cRange} =
      case contr do
        {:value, r_contract(args: as) = c} ->
          {as,
           fn funArgs ->
             :dialyzer_contracts.get_contract_return(
               c,
               funArgs
             )
           end}

        :none ->
          genSig
      end

    {bifArgs, bifRange} =
      case typeOfApply do
        :remote ->
          {m, f, a} = fun

          case :erl_bif_types.is_known(m, f, a) do
            true ->
              bArgs = :erl_bif_types.arg_types(m, f, a)

              bRange = fn funArgs ->
                :erl_bif_types.type(m, f, a, funArgs, opaques)
              end

              {bArgs, bRange}

            false ->
              genSig
          end

        :local ->
          genSig
      end

    {sigArgs, sigRange} =
      case sig do
        {:value, {sR, sA}} ->
          {sA, sR}

        :none ->
          {anyArgs, t_any()}
      end

    :ok
    :ok
    :ok
    :ok
    :ok
    :ok
    newArgsSig = t_inf_lists(sigArgs, argTypes, opaques)
    :ok
    :ok
    newArgsContract = t_inf_lists(cArgs, argTypes, opaques)
    :ok
    newArgsBif = t_inf_lists(bifArgs, argTypes, opaques)
    :ok
    newArgTypes0 = t_inf_lists(newArgsSig, newArgsContract)
    newArgTypes = t_inf_lists(newArgTypes0, newArgsBif, opaques)
    :ok
    :ok
    bifRet = bifRange.(newArgTypes)
    contrRet = cRange.(newArgTypes)
    retWithoutContr = t_inf(sigRange, bifRet)
    retWithoutLocal = t_inf(contrRet, retWithoutContr)
    :ok
    :ok
    :ok
    :ok
    :ok
    :ok
    failedConj = any_none([retWithoutLocal | newArgTypes])
    isFailBif = t_is_none(bifRange.(bifArgs))
    isFailSig = t_is_none(sigRange)
    :ok
    :ok
    :ok

    state2 =
      case failedConj and not (isFailBif or isFailSig) do
        true ->
          case t_is_none(retWithoutLocal) and not t_is_none(retWithoutContr) and
                 not any_none(newArgTypes) do
            true ->
              {:value, c1} = contr
              contract = :dialyzer_contracts.contract_to_string(c1)
              {m1, f1, a1} = state__lookup_name(fun, state)
              argStrings = format_args(args, argTypes, state)
              cRet = :erl_types.t_to_string(retWithoutContr)
              msg = {:contract_range, [contract, m1, f1, a1, argStrings, cRet]}
              state__add_warning(state, :warn_contract_range, tree, msg)

            false ->
              failedSig = any_none(newArgsSig)

              failedContract =
                any_none([
                  cRange.(newArgsContract)
                  | newArgsContract
                ])

              failedBif =
                any_none([
                  bifRange.(newArgsBif)
                  | newArgsBif
                ])

              infSig =
                t_inf(
                  t_fun(sigArgs, sigRange),
                  t_fun(bifArgs, bifRange.(bifArgs))
                )

              failReason = apply_fail_reason(failedSig, failedBif, failedContract)

              msg =
                get_apply_fail_msg(
                  fun,
                  args,
                  argTypes,
                  newArgTypes,
                  infSig,
                  contr,
                  cArgs,
                  state,
                  failReason,
                  opaques
                )

              warnType =
                case msg do
                  {:call, _} ->
                    :warn_failing_call

                  {:apply, _} ->
                    :warn_failing_call

                  {:call_with_opaque, _} ->
                    :warn_opaque

                  {:call_without_opaque, _} ->
                    :warn_opaque

                  {:opaque_type_test, _} ->
                    :warn_opaque
                end

              locTree =
                case msg do
                  {:call, [_M, _F, _ASs, aNs | _]} ->
                    select_arg(aNs, args, tree)

                  {:apply, [_ASs, aNs | _]} ->
                    select_arg(aNs, args, tree)

                  {:call_with_opaque, [_M, _F, _ASs, aNs, _EAs_]} ->
                    select_arg(aNs, args, tree)

                  {:call_without_opaque, [_M, _F, _ASs, [{n, _T, _TS} | _]]} ->
                    select_arg([n], args, tree)

                  {:opaque_type_test, _} ->
                    tree
                end

              frc = {:erlang, :is_record, 3} === state__lookup_name(fun, state)
              state__add_warning(state, warnType, locTree, msg, frc)
          end

        false ->
          state
      end

    state3 =
      case typeOfApply do
        :local ->
          case state__is_escaping(fun, state2) do
            true ->
              state2

            false ->
              forwardArgs =
                for x <- argTypes do
                  t_limit(x, 3)
                end

              forward_args(fun, forwardArgs, state2)
          end

        :remote ->
          add_bif_warnings(fun, newArgTypes, tree, state2)
      end

    newAccArgTypes =
      case failedConj do
        true ->
          accArgTypes

        false ->
          for {x, y} <- :lists.zip(newArgTypes, accArgTypes) do
            t_sup(x, y)
          end
      end

    totalRet =
      case t_is_none(localRet) and t_is_unit(retWithoutLocal) do
        true ->
          retWithoutLocal

        false ->
          t_inf(retWithoutLocal, localRet)
      end

    newAccRet = t_sup(accRet, totalRet)
    :ok
    {newWarnings, state4} = state__remove_added_warnings(state, state3)
    {howMany, oldWarnings} = warns

    newWarns =
      case howMany do
        :none ->
          {:one, newWarnings}

        _ ->
          case oldWarnings === [] do
            true ->
              {:many, []}

            false ->
              case newWarnings === [] do
                true ->
                  {:many, []}

                false ->
                  {:many, newWarnings ++ oldWarnings}
              end
          end
      end

    handle_apply_or_call(
      left,
      args,
      argTypes,
      map,
      tree,
      state4,
      newAccArgTypes,
      newAccRet,
      hadExternal,
      newWarns
    )
  end

  defp handle_apply_or_call(
         [],
         args,
         _ArgTypes,
         map,
         _Tree,
         state,
         accArgTypes,
         accRet,
         hadExternal,
         {_, warnings}
       ) do
    state1 = state__add_warnings(warnings, state)

    case hadExternal do
      false ->
        newMap = enter_type_lists(args, accArgTypes, map)
        {state1, newMap, accRet}

      true ->
        {:had_external, state1}
    end
  end

  defp apply_fail_reason(failedSig, failedBif, failedContract) do
    cond do
      (failedSig or failedBif) and not failedContract ->
        :only_sig

      failedContract and not (failedSig or failedBif) ->
        :only_contract

      true ->
        :both
    end
  end

  defp get_apply_fail_msg(
         fun,
         args,
         argTypes,
         newArgTypes,
         sig,
         contract,
         contrArgs,
         state,
         failReason,
         opaques
       ) do
    argStrings = format_args(args, argTypes, state)

    contractInfo =
      case contract do
        {:value, r_contract() = c} ->
          {:dialyzer_contracts.is_overloaded(c), :dialyzer_contracts.contract_to_string(c)}

        :none ->
          {false, :none}
      end

    enumArgTypes =
      :lists.zip(
        :lists.seq(
          1,
          length(newArgTypes)
        ),
        newArgTypes
      )

    argNs =
      for {arg, type} <- enumArgTypes,
          t_is_none(type) do
        arg
      end

    case state__lookup_name(fun, state) do
      {m, f, a} ->
        case is_opaque_type_test_problem(fun, args, newArgTypes, state) do
          {:yes, arg, argType} ->
            {:opaque_type_test,
             [
               :erlang.atom_to_list(f),
               argStrings,
               format_arg(arg),
               format_type(
                 argType,
                 state
               )
             ]}

          :no ->
            sigArgs = t_fun_args(sig)
            badOpaque = opaque_problems([sigArgs, contrArgs], argTypes, opaques, argNs)

            case :lists.keyfind(:decl, 1, badOpaque) do
              {:decl, badArgs} ->
                expectedTriples =
                  case failReason do
                    :only_sig ->
                      expected_arg_triples(badArgs, sigArgs, state)

                    _ ->
                      expected_arg_triples(badArgs, contrArgs, state)
                  end

                {:call_without_opaque, [m, f, argStrings, expectedTriples]}

              false ->
                case :lists.keyfind(:use, 1, badOpaque) do
                  {:use, badArgs} ->
                    expectedArgs =
                      case failReason do
                        :only_sig ->
                          sigArgs

                        _ ->
                          contrArgs
                      end

                    {:call_with_opaque, [m, f, argStrings, badArgs, expectedArgs]}

                  false ->
                    case :erl_bif_types.opaque_args(m, f, a, argTypes, opaques) do
                      [] ->
                        {:call,
                         [
                           m,
                           f,
                           argStrings,
                           argNs,
                           failReason,
                           format_sig_args(
                             sig,
                             state
                           ),
                           format_type(
                             t_fun_range(sig),
                             state
                           ),
                           contractInfo
                         ]}

                      ns ->
                        {:call_with_opaque, [m, f, argStrings, ns, contrArgs]}
                    end
                end
            end
        end

      label when is_integer(label) ->
        {:apply,
         [
           argStrings,
           argNs,
           failReason,
           format_sig_args(
             sig,
             state
           ),
           format_type(
             t_fun_range(sig),
             state
           ),
           contractInfo
         ]}
    end
  end

  defp opaque_problems(contractOrSigList, argTypes, opaques, argNs) do
    argElementList = find_unknown(contractOrSigList, argTypes, opaques, argNs)

    f = fn
      1 ->
        :decl

      2 ->
        :use
    end

    for elementI <-
          :lists.usort(
            for {_, eI} <- argElementList do
              eI
            end
          ) do
      {f.(elementI),
       :lists.usort(
         for {argN, eI} <- argElementList,
             eI === elementI do
           argN
         end
       )}
    end
  end

  defp find_unknown(contractOrSigList, argTypes, opaques, noneArgNs) do
    argNs = :lists.seq(1, length(argTypes))

    for contractOrSig <- contractOrSigList,
        {e1, e2, argN} <- :lists.zip3(contractOrSig, argTypes, argNs),
        :lists.member(argN, noneArgNs),
        elementI <- :erl_types.t_find_unknown_opaque(e1, e2, opaques) do
      {argN, elementI}
    end
  end

  defp is_opaque_type_test_problem(fun, args, argTypes, state) do
    case fun do
      {:erlang, fN, 2} when fN === :is_function ->
        type_test_opaque_arg(args, argTypes, r_state(state, :opaques))

      {:erlang, fN, 1} ->
        case t_is_any(type_test_type(fN, 1)) do
          true ->
            :no

          false ->
            type_test_opaque_arg(args, argTypes, r_state(state, :opaques))
        end

      _ ->
        :no
    end
  end

  defp type_test_opaque_arg([], [], _Opaques) do
    :no
  end

  defp type_test_opaque_arg([arg | args], [argType | argTypes], opaques) do
    case :erl_types.t_has_opaque_subtype(
           argType,
           opaques
         ) do
      true ->
        {:yes, arg, argType}

      false ->
        type_test_opaque_arg(args, argTypes, opaques)
    end
  end

  defp expected_arg_triples(argNs, argTypes, state) do
    for n <- argNs do
      arg = :lists.nth(n, argTypes)
      {n, arg, format_type(arg, state)}
    end
  end

  defp add_bif_warnings({:erlang, op, 2}, [t1, t2] = ts, tree, state)
       when op === :"=:=" or op === :== do
    opaques = r_state(state, :opaques)
    inf = t_inf(t1, t2, opaques)

    case t_is_none(inf) and not any_none(ts) and not is_int_float_eq_comp(t1, op, t2, opaques) do
      true ->
        case :erl_types.t_find_unknown_opaque(t1, t2, opaques) do
          [] ->
            args = comp_format_args([], t1, op, t2, state)
            state__add_warning(state, :warn_matching, tree, {:exact_eq, args})

          ns ->
            args = comp_format_args(ns, t1, op, t2, state)
            state__add_warning(state, :warn_opaque, tree, {:opaque_eq, args})
        end

      false ->
        state
    end
  end

  defp add_bif_warnings({:erlang, op, 2}, [t1, t2] = ts, tree, state)
       when op === :"=/=" or op === :"/=" do
    opaques = r_state(state, :opaques)

    case not any_none(ts) and not is_int_float_eq_comp(t1, op, t2, opaques) do
      true ->
        case :erl_types.t_find_unknown_opaque(t1, t2, opaques) do
          [] ->
            state

          ns ->
            args = comp_format_args(ns, t1, op, t2, state)
            state__add_warning(state, :warn_opaque, tree, {:opaque_neq, args})
        end

      false ->
        state
    end
  end

  defp add_bif_warnings(_, _, _, state) do
    state
  end

  defp is_int_float_eq_comp(t1, op, t2, opaques) do
    (op === :== or op === :"/=") and
      ((:erl_types.t_is_float(
          t1,
          opaques
        ) and
          t_is_integer(
            t2,
            opaques
          )) or
         (t_is_integer(
            t1,
            opaques
          ) and
            :erl_types.t_is_float(
              t2,
              opaques
            )))
  end

  defp comp_format_args([1 | _], t1, op, t2, state) do
    [format_type(t2, state), op, format_type(t1, state)]
  end

  defp comp_format_args(_, t1, op, t2, state) do
    [format_type(t1, state), op, format_type(t2, state)]
  end

  defp handle_bitstr(tree, map, state) do
    size = :cerl.bitstr_size(tree)
    val = :cerl.bitstr_val(tree)
    bitstrType = :cerl.concrete(:cerl.bitstr_type(tree))
    {state1, map1, sizeType0} = traverse(size, map, state)
    {state2, map2, valType0} = traverse(val, map1, state1)

    case :cerl.bitstr_bitsize(tree) do
      bitSz when bitSz === :all or bitSz === :utf ->
        valType =
          case bitSz do
            :all ->
              true = bitstrType === :binary
              t_inf(valType0, t_bitstr())

            :utf ->
              true =
                :lists.member(
                  bitstrType,
                  [:utf8, :utf16, :utf32]
                )

              t_inf(valType0, t_integer())
          end

        map3 = enter_type(val, valType, map2)

        case t_is_none(valType) do
          true ->
            msg =
              {:bin_construction,
               [~c"value", format_cerl(val), format_cerl(tree), format_type(valType0, state2)]}

            state3 = state__add_warning(state2, :warn_bin_construction, val, msg)
            {state3, map3, t_none()}

          false ->
            {state2, map3, t_bitstr()}
        end

      bitSz when is_integer(bitSz) or bitSz === :any ->
        sizeType = t_inf(sizeType0, t_non_neg_integer())

        valType =
          case bitstrType do
            :binary ->
              t_inf(valType0, t_bitstr())

            :float ->
              t_inf(valType0, t_number())

            :integer ->
              t_inf(valType0, t_integer())
          end

        case any_none([sizeType, valType]) do
          true ->
            {msg, offending} =
              case t_is_none(sizeType) do
                true ->
                  {{:bin_construction,
                    [
                      ~c"size",
                      format_cerl(size),
                      format_cerl(tree),
                      format_type(
                        sizeType0,
                        state2
                      )
                    ]}, size}

                false ->
                  {{:bin_construction,
                    [
                      ~c"value",
                      format_cerl(val),
                      format_cerl(tree),
                      format_type(
                        valType0,
                        state2
                      )
                    ]}, val}
              end

            state3 = state__add_warning(state2, :warn_bin_construction, offending, msg)
            {state3, map2, t_none()}

          false ->
            unitVal = :cerl.concrete(:cerl.bitstr_unit(tree))
            opaques = r_state(state2, :opaques)
            numberVals = t_number_vals(sizeType, opaques)

            {state3, type} =
              case t_contains_opaque(
                     sizeType,
                     opaques
                   ) do
                true ->
                  msg = {:opaque_size, [format_type(sizeType, state2), format_cerl(size)]}
                  {state__add_warning(state2, :warn_opaque, size, msg), t_none()}

                false ->
                  case numberVals do
                    [oneSize] ->
                      {state2, t_bitstr(0, oneSize * unitVal)}

                    :unknown ->
                      {state2, t_bitstr()}

                    _ ->
                      minSize =
                        :erl_types.number_min(
                          sizeType,
                          opaques
                        )

                      {state2, t_bitstr(unitVal, unitVal * minSize)}
                  end
              end

            map3 = enter_type_lists([val, size, tree], [valType, sizeType, type], map2)
            {state3, map3, type}
        end
    end
  end

  defp handle_call(tree, map, state) do
    m = :cerl.call_module(tree)
    f = :cerl.call_name(tree)
    args = :cerl.call_args(tree)
    mFAList = [m, f | args]
    {state1, map1, [mType0, fType0 | as]} = traverse_list(mFAList, map, state)
    opaques = r_state(state, :opaques)
    mType = t_inf(t_module(), mType0, opaques)
    fType = t_inf(t_atom(), fType0, opaques)
    map2 = enter_type_lists([m, f], [mType, fType], map1)
    mOpaque = t_is_none(mType) and not t_is_none(mType0)
    fOpaque = t_is_none(fType) and not t_is_none(fType0)

    case any_none([mType, fType | as]) do
      true ->
        state2 =
          cond do
            mOpaque ->
              mS = format_cerl(m)

              case t_is_none(t_inf(t_module(), mType0)) do
                true ->
                  msg =
                    {:app_call,
                     [
                       mS,
                       format_cerl(f),
                       format_args(args, as, state1),
                       mS,
                       format_type(
                         t_module(),
                         state1
                       ),
                       format_type(
                         mType0,
                         state1
                       )
                     ]}

                  state__add_warning(state1, :warn_failing_call, m, msg)

                false ->
                  msg =
                    {:opaque_call,
                     [
                       mS,
                       format_cerl(f),
                       format_args(args, as, state1),
                       mS,
                       format_type(
                         mType0,
                         state1
                       )
                     ]}

                  state__add_warning(state1, :warn_failing_call, m, msg)
              end

            fOpaque ->
              fS = format_cerl(f)

              case t_is_none(t_inf(t_atom(), fType0)) do
                true ->
                  msg =
                    {:app_call,
                     [
                       format_cerl(m),
                       fS,
                       format_args(args, as, state1),
                       fS,
                       format_type(
                         t_atom(),
                         state1
                       ),
                       format_type(
                         fType0,
                         state1
                       )
                     ]}

                  state__add_warning(state1, :warn_failing_call, f, msg)

                false ->
                  msg =
                    {:opaque_call,
                     [
                       format_cerl(m),
                       fS,
                       format_args(args, as, state1),
                       fS,
                       format_type(
                         fType0,
                         state1
                       )
                     ]}

                  state__add_warning(state1, :warn_failing_call, f, msg)
              end

            true ->
              state1
          end

        {state2, map2, t_none()}

      false ->
        case t_is_atom(mType) do
          true ->
            case {t_atom_vals(mType), t_atom_vals(fType)} do
              {[mAtom], [fAtom]} ->
                funInfo = [
                  {:remote,
                   state__fun_info(
                     {mAtom, fAtom, length(args)},
                     state1
                   )}
                ]

                handle_apply_or_call(funInfo, args, as, map2, tree, state1)

              {_MAtoms, _FAtoms} ->
                {state1, map2, t_any()}
            end

          false ->
            {state1, map2, t_any()}
        end
    end
  end

  defp handle_case(tree, map, state) do
    arg = :cerl.case_arg(tree)
    clauses = :cerl.case_clauses(tree)
    {state1, map1, argType} = sMA = traverse(arg, map, state)

    case t_is_impossible(argType) do
      true ->
        sMA

      false ->
        map2 = join_maps_begin(map1)
        {mapList, state3, type, warns} = handle_clauses(clauses, arg, argType, map2, state1)
        doForce = not is_compiler_generated(:cerl.get_ann(tree)) or t_is_none(type)

        state4 =
          :lists.foldl(
            fn {t, r, m, f}, s ->
              state__add_warning(s, t, r, m, f and doForce)
            end,
            state3,
            warns
          )

        map3 = join_maps_end(mapList, map2)
        debug_pp_map(map3)
        {state4, map3, type}
    end
  end

  defp handle_cons(tree, map, state) do
    hd = :cerl.cons_hd(tree)
    tl = :cerl.cons_tl(tree)
    {state1, map1, hdType} = traverse(hd, map, state)
    {state2, map2, tlType} = traverse(tl, map1, state1)

    state3 =
      case t_is_none(t_inf(tlType, t_list(), r_state(state2, :opaques))) do
        true ->
          msg = {:improper_list_constr, [format_type(tlType, state2)]}
          state__add_warning(state2, :warn_non_proper_list, tree, msg)

        false ->
          state2
      end

    type = t_cons(hdType, tlType)
    {state3, map2, type}
  end

  defp handle_let(tree, map, state) do
    arg = :cerl.let_arg(tree)
    vars = :cerl.let_vars(tree)

    {map0, state0} =
      case :cerl.is_c_var(arg) do
        true ->
          [var] = vars
          {enter_subst(var, arg, map), state}

        false ->
          {map, state}
      end

    body = :cerl.let_body(tree)
    {state1, map1, argTypes} = sMA = traverse(arg, map0, state0)

    case t_is_impossible(argTypes) do
      true ->
        sMA

      false ->
        map2 = enter_type_lists(vars, t_to_tlist(argTypes), map1)
        traverse(body, map2, state1)
    end
  end

  defp handle_primop(tree, map, state) do
    case :cerl.atom_val(:cerl.primop_name(tree)) do
      :match_fail ->
        {state, map, t_none()}

      :raise ->
        {state, map, t_none()}

      :bs_init_writable ->
        {state, map, t_from_term(<<>>)}

      :build_stacktrace ->
        {state, map, :erl_bif_types.type(:erlang, :build_stacktrace, 0)}

      :dialyzer_unknown ->
        {state, map, t_any()}

      :recv_peek_message ->
        {state, map, t_product([t_boolean(), t_any()])}

      :recv_wait_timeout ->
        [arg] = :cerl.primop_args(tree)
        {state1, map1, timeoutType} = traverse(arg, map, state)
        opaques = r_state(state1, :opaques)

        case t_is_atom(
               timeoutType,
               opaques
             ) and
               t_atom_vals(
                 timeoutType,
                 opaques
               ) === [:infinity] do
          true ->
            {state1, map1, t_boolean()}

          false ->
            {state1, map1, t_boolean()}
        end

      :remove_message ->
        {state, map, t_any()}

      :nif_start ->
        {state, map, t_any()}

      other ->
        :erlang.error({:"Unsupported primop", other})
    end
  end

  defp handle_try(tree, map, state) do
    arg = :cerl.try_arg(tree)
    eVars = :cerl.try_evars(tree)
    vars = :cerl.try_vars(tree)
    body = :cerl.try_body(tree)
    handler = :cerl.try_handler(tree)
    {state1, map1, argType} = sMA = traverse(arg, map, state)
    typeList = t_to_tlist(argType)

    cond do
      length(vars) !== length(typeList) ->
        sMA

      true ->
        map2 = mark_as_fresh(vars, map1)

        {succState, succMap, succType} =
          case bind_pat_vars(vars, typeList, map2, state1) do
            {:error, _, _, _, _} ->
              {state1, map__new(), t_none()}

            {succMap1, varTypes} ->
              succMap2 =
                case bind_pat_vars_reverse(
                       [arg],
                       [t_product(varTypes)],
                       succMap1,
                       state1
                     ) do
                  {:error, _, _, _, _} ->
                    succMap1

                  {sM, _} ->
                    sM
                end

              traverse(body, succMap2, state1)
          end

        excMap1 = mark_as_fresh(eVars, map)
        {state2, excMap2, handlerType} = traverse(handler, excMap1, succState)
        tryType = t_sup(succType, handlerType)
        {state2, join_maps([excMap2, succMap], map1), tryType}
    end
  end

  defp handle_map(tree, map, state) do
    pairs = :cerl.map_es(tree)
    arg = :cerl.map_arg(tree)
    {state1, map1, argType} = traverse(arg, map, state)
    argType1 = t_inf(t_map(), argType)

    case t_is_impossible(argType1) do
      true ->
        {state1, map1, argType1}

      false ->
        {state2, map2, typePairs, exactKeys} =
          traverse_map_pairs(pairs, map1, state1, t_none(), [], [])

        insertPair = fn
          {kV, :assoc, _}, acc ->
            :erl_types.t_map_put(kV, acc)

          {kV, :exact, kVTree}, acc ->
            case t_is_none(
                   t =
                     :erl_types.t_map_update(
                       kV,
                       acc
                     )
                 ) do
              true ->
                throw({:none, acc, kV, kVTree})

              false ->
                t
            end
        end

        try do
          :lists.foldl(insertPair, argType1, typePairs)
        catch
          {:none, mapType, {k, _}, kVTree} ->
            msg2 = {:map_update, [format_type(mapType, state2), format_type(k, state2)]}
            {state__add_warning(state2, :warn_map_construction, kVTree, msg2), map2, t_none()}
        else
          resT ->
            bindT =
              t_map(
                for k <- exactKeys do
                  {k, t_any()}
                end
              )

            case bind_pat_vars_reverse([arg], [bindT], map2, state2) do
              {:error, _, _, _, _} ->
                {state2, map2, resT}

              {map3, _} ->
                {state2, map3, resT}
            end
        end
    end
  end

  defp traverse_map_pairs([], map, state, _ShadowKeys, pairAcc, keyAcc) do
    {state, map, :lists.reverse(pairAcc), keyAcc}
  end

  defp traverse_map_pairs([pair | pairs], map, state, shadowKeys, pairAcc, keyAcc) do
    key = :cerl.map_pair_key(pair)
    val = :cerl.map_pair_val(pair)
    op = :cerl.map_pair_op(pair)
    {state1, map1, [k, v]} = traverse_list([key, val], map, state)

    keyAcc1 =
      case :cerl.is_literal(op) and :cerl.concrete(op) === :exact and
             t_is_singleton(
               k,
               r_state(state, :opaques)
             ) and
             t_is_none(
               t_inf(
                 shadowKeys,
                 k
               )
             ) do
        true ->
          [k | keyAcc]

        false ->
          keyAcc
      end

    traverse_map_pairs(
      pairs,
      map1,
      state1,
      t_sup(k, shadowKeys),
      [{{k, v}, :cerl.concrete(op), pair} | pairAcc],
      keyAcc1
    )
  end

  defp handle_tuple(tree, map, state) do
    elements = :cerl.tuple_es(tree)
    {state1, map1, esType} = traverse_list(elements, map, state)
    tupleType = t_tuple(esType)

    case t_is_none(tupleType) do
      true ->
        {state1, map1, t_none()}

      false ->
        case elements do
          [tag | left] ->
            case :cerl.is_c_atom(tag) and is_literal_record(tree) do
              true ->
                tagVal = :cerl.atom_val(tag)

                case state__lookup_record(tagVal, length(left), state1) do
                  :error ->
                    {state1, map1, tupleType}

                  {:ok, recType, fieldNames} ->
                    infTupleType = t_inf(recType, tupleType)

                    case t_is_none(infTupleType) do
                      true ->
                        recC = format_type(tupleType, state1)
                        {fieldPosList, fieldDiffs} = format_field_diffs(tupleType, state1)
                        msg = {:record_constr, [recC, fieldDiffs]}
                        locTree = :lists.nth(hd(fieldPosList), left)
                        state2 = state__add_warning(state1, :warn_matching, locTree, msg)
                        {state2, map1, t_none()}

                      false ->
                        case bind_pat_vars(elements, t_tuple_args(recType), map1, state1) do
                          {:error, :bind, errorPat, errorType, _} ->
                            msg =
                              {:record_constr,
                               [
                                 tagVal,
                                 format_patterns(errorPat),
                                 format_type(
                                   errorType,
                                   state1
                                 )
                               ]}

                            locTree = hd(errorPat)
                            state2 = state__add_warning(state1, :warn_matching, locTree, msg)
                            {state2, map1, t_none()}

                          {:error, :opaque, errorPat, errorType, opaqueType} ->
                            opaqueStr = format_type(opaqueType, state1)
                            name = field_name(elements, errorPat, fieldNames)

                            msg =
                              {:opaque_match,
                               [
                                 ~c"record field" ++
                                   name ++
                                   ~c" declared to be of type " ++
                                   format_type(
                                     errorType,
                                     state1
                                   ),
                                 opaqueStr,
                                 opaqueStr
                               ]}

                            locTree = hd(errorPat)
                            state2 = state__add_warning(state1, :warn_opaque, locTree, msg)
                            {state2, map1, t_none()}

                          {:error, :record, errorPat, errorType, _} ->
                            msg =
                              {:record_match,
                               [format_patterns(errorPat), format_type(errorType, state1)]}

                            state2 = state__add_warning(state1, :warn_matching, tree, msg)
                            {state2, map1, t_none()}

                          {map2, eTypes} ->
                            {state1, map2, t_tuple(eTypes)}
                        end
                    end
                end

              false ->
                {state1, map1, t_tuple(esType)}
            end

          [] ->
            {state1, map1, t_tuple([])}
        end
    end
  end

  defp field_name(elements, errorPat, fieldNames) do
    try do
      [pat] = errorPat

      take =
        :lists.takewhile(
          fn x ->
            x !== pat
          end,
          elements
        )

      ~c" " ++ format_atom(:lists.nth(length(take), fieldNames))
    catch
      _, _ ->
        ~c""
    end
  end

  defp handle_clauses(cs, arg, argType, map, state) do
    handle_clauses(cs, arg, argType, argType, map, state, [], [], [])
  end

  defp handle_clauses([c | cs], arg, argType, origArgType, mapIn, state, caseTypes, acc, warnAcc0) do
    {state1, clauseMap, bodyType, newArgType, warnAcc} =
      do_clause(c, arg, argType, origArgType, mapIn, state, warnAcc0)

    case t_is_none(bodyType) do
      true ->
        handle_clauses(cs, arg, newArgType, origArgType, mapIn, state1, caseTypes, acc, warnAcc)

      false ->
        handle_clauses(
          cs,
          arg,
          newArgType,
          origArgType,
          mapIn,
          state1,
          [bodyType | caseTypes],
          [clauseMap | acc],
          warnAcc
        )
    end
  end

  defp handle_clauses([], _Arg, _ArgType, _OrigArgType, _MapIn, state, caseTypes, acc, warnAcc) do
    {:lists.reverse(acc), state, t_sup(caseTypes), warnAcc}
  end

  defp do_clause(c, arg, argType, origArgType, map, state, warns) do
    pats = :cerl.clause_pats(c)
    map0 = mark_as_fresh(pats, map)
    map1 = bind_subst(arg, pats, map0)

    bindRes =
      case t_is_none(argType) do
        true ->
          {:error, :maybe_covered, origArgType, :ignore, :ignore}

        false ->
          argTypes = get_arg_list(argType, pats)
          bind_pat_vars(pats, argTypes, map1, state)
      end

    case bindRes do
      {:error, _ErrorType, _NewPats, _Type, _OpaqueTerm} ->
        :ok

        newWarns =
          case state__warning_mode(state) do
            false ->
              warns

            true ->
              warn = clause_error(state, map1, bindRes, c, pats, argType)
              [warn | warns]
          end

        {state, map, t_none(), argType, newWarns}

      {map2, patTypes} ->
        map3 =
          case bind_pat_vars_reverse([arg], [t_product(patTypes)], map2, state) do
            {:error, _, _, _, _} ->
              map2

            {newMap, _} ->
              newMap
          end

        guard = :cerl.clause_guard(c)

        genType =
          :dialyzer_typesig.get_safe_underapprox(
            pats,
            guard
          )

        newArgType =
          t_subtract(
            t_product(t_to_tlist(argType)),
            genType
          )

        case bind_guard(guard, map3, state) do
          {:error, reason} ->
            :ok
            warn = clause_guard_error(state, reason, c, pats, argType)
            {state, map, t_none(), newArgType, [warn | warns]}

          map4 ->
            body = :cerl.clause_body(c)
            {retState, retMap, bodyType} = traverse(body, map4, state)
            {retState, retMap, bodyType, newArgType, warns}
        end
    end
  end

  defp clause_error(state, map, {:error, :maybe_covered, origArgType, _, _}, c, pats, _) do
    origArgTypes = get_arg_list(origArgType, pats)

    msg =
      case bind_pat_vars(pats, origArgTypes, map, state) do
        {_, _} ->
          patString = format_patterns(pats)
          argTypeString = format_type(origArgType, state)
          {:pattern_match_cov, [patString, argTypeString]}

        {:error, errorType, _, _, opaqueTerm} ->
          failed_msg(state, errorType, pats, origArgType, pats, origArgType, opaqueTerm)
      end

    force = false
    clause_error_warning(msg, force, c)
  end

  defp clause_error(state, _Map, bindRes, c, pats, argType) do
    force = not is_lc_default_clause(c)
    {:error, errorType, newPats, newType, opaqueTerm} = bindRes
    msg = failed_msg(state, errorType, pats, argType, newPats, newType, opaqueTerm)
    clause_error_warning(msg, force, c)
  end

  defp failed_msg(state, errorType, pats, type, newPats, newType, opaqueTerm) do
    case errorType do
      :bind ->
        {:pattern_match, [format_patterns(pats), format_type(type, state)]}

      :record ->
        {:record_match, [format_patterns(newPats), format_type(newType, state)]}

      :opaque ->
        {:opaque_match,
         [format_patterns(newPats), format_type(newType, state), format_type(opaqueTerm, state)]}
    end
  end

  defp clause_error_warning(msg, force, c) do
    {warn_type(msg), c, msg, force}
  end

  defp warn_type({tag, _}) do
    case tag do
      :guard_fail ->
        :warn_matching

      :neg_guard_fail ->
        :warn_matching

      :opaque_guard ->
        :warn_opaque

      :opaque_match ->
        :warn_opaque

      :pattern_match ->
        :warn_matching

      :pattern_match_cov ->
        :warn_matching

      :record_match ->
        :warn_matching
    end
  end

  defp get_arg_list(argTypes, pats) do
    case t_is_any(argTypes) do
      true ->
        for _ <- pats do
          argTypes
        end

      false ->
        t_to_tlist(argTypes)
    end
  end

  defp is_lc_default_clause(c) do
    case is_compiler_generated(:cerl.get_ann(c)) do
      false ->
        false

      true ->
        case :cerl.clause_pats(c) do
          [pat] ->
            :cerl.is_c_cons(pat) and :cerl.is_c_var(:cerl.cons_hd(pat)) and
              :cerl.is_c_var(:cerl.cons_tl(pat)) and does_guard_succeed(c)

          [pat0, pat1] ->
            :cerl.is_c_cons(pat0) and :cerl.is_c_var(:cerl.cons_hd(pat0)) and
              :cerl.is_c_var(:cerl.cons_tl(pat0)) and :cerl.is_c_var(pat1) and
              does_guard_succeed(c)

          _ ->
            false
        end
    end
  end

  defp does_guard_succeed(c) do
    guard = :cerl.clause_guard(c)
    :cerl.is_literal(guard) and :cerl.concrete(guard) === true
  end

  defp clause_guard_error(state, reason, c, pats, argType) do
    case reason do
      :none ->
        msg =
          case pats do
            [] ->
              {:guard_fail, []}

            [_ | _] ->
              patString = format_patterns(pats)
              {:guard_fail_pat, [patString, format_type(argType, state)]}
          end

        {:warn_matching, c, msg, false}

      {failGuard, msg} ->
        case is_compiler_generated(:cerl.get_ann(failGuard)) do
          false ->
            {warn_type(msg), failGuard, msg, false}

          true ->
            {:warn_matching, c, msg, false}
        end
    end
  end

  defp bind_subst(arg, pats, map) do
    case :cerl.type(arg) do
      :values ->
        bind_subst_list(:cerl.values_es(arg), pats, map)

      :var ->
        [pat] = pats
        enter_subst(arg, pat, map)

      _ ->
        map
    end
  end

  defp bind_subst_list([arg | argLeft], [pat | patLeft], map) do
    newMap =
      case {:cerl.type(arg), :cerl.type(pat)} do
        {:var, :var} ->
          enter_subst(arg, pat, map)

        {:var, :alias} ->
          enter_subst(arg, :cerl.alias_pat(pat), map)

        {:literal, :literal} ->
          map

        {t, t} ->
          bind_subst_list(
            :lists.flatten(:cerl.subtrees(arg)),
            :lists.flatten(:cerl.subtrees(pat)),
            map
          )

        _ ->
          map
      end

    bind_subst_list(argLeft, patLeft, newMap)
  end

  defp bind_subst_list([], [], map) do
    map
  end

  defp bind_pat_vars(pats, types, map, state) do
    bind_pat_vars(pats, types, map, state, false)
  end

  defp bind_pat_vars_reverse(pats, types, map, state) do
    bind_pat_vars(pats, types, map, state, true)
  end

  defp bind_pat_vars(pats, types, map, state, rev) do
    try do
      do_bind_pat_vars(pats, types, map, state, rev, [])
    catch
      error ->
        error
    end
  end

  defp do_bind_pat_vars([pat | pats], [type | types], map, state, rev, acc) do
    :ok
    opaques = r_state(state, :opaques)

    {newMap, typeOut} =
      case :cerl.type(pat) do
        :alias ->
          aliasPat = :dialyzer_utils.refold_pattern(:cerl.alias_pat(pat))
          var = :cerl.alias_var(pat)
          map1 = enter_subst(var, aliasPat, map)
          {map2, [patType]} = do_bind_pat_vars([aliasPat], [type], map1, state, rev, [])
          {enter_type(var, patType, map2), patType}

        :binary ->
          case rev do
            true ->
              {map, t_bitstr()}

            false ->
              binType = bind_checked_inf(pat, t_bitstr(), type, opaques)
              segs = :cerl.binary_segments(pat)
              {map1, segTypes} = bind_bin_segs(segs, binType, map, state)
              {map1, t_bitstr_concat(segTypes)}
          end

        :cons ->
          cons = bind_checked_inf(pat, t_cons(), type, opaques)

          {map1, [hdType, tlType]} =
            do_bind_pat_vars(
              [:cerl.cons_hd(pat), :cerl.cons_tl(pat)],
              [
                t_cons_hd(
                  cons,
                  opaques
                ),
                t_cons_tl(
                  cons,
                  opaques
                )
              ],
              map,
              state,
              rev,
              []
            )

          {map1, t_cons(hdType, tlType)}

        :literal ->
          pat0 = :dialyzer_utils.refold_pattern(pat)

          case :cerl.is_literal(pat0) do
            true ->
              literalType = bind_checked_inf(pat, literal_type(pat), type, opaques)
              {map, literalType}

            false ->
              {map1, [patType]} = do_bind_pat_vars([pat0], [type], map, state, rev, [])
              {map1, patType}
          end

        :map ->
          bind_map(pat, type, map, state, opaques, rev)

        :tuple ->
          bind_tuple(pat, type, map, state, opaques, rev)

        :values ->
          es = :cerl.values_es(pat)
          {map1, esTypes} = do_bind_pat_vars(es, t_to_tlist(type), map, state, rev, [])
          {map1, t_product(esTypes)}

        :var ->
          varType1 =
            case state__lookup_type_for_letrec(
                   pat,
                   state
                 ) do
              :error ->
                lookup_type(pat, map)

              {:ok, recType} ->
                recType
            end

          varType2 = bind_checked_inf(pat, varType1, type, opaques)
          map1 = enter_type(pat, varType2, map)
          {map1, varType2}

        _Other ->
          :ok
          ^rev = true
          bind_error([pat], type, t_none(), :bind)
      end

    do_bind_pat_vars(pats, types, newMap, state, rev, [typeOut | acc])
  end

  defp do_bind_pat_vars([], [], map, _State, _Rev, acc) do
    {map, :lists.reverse(acc)}
  end

  defp bind_map(pat, type, map, state, opaques, rev) do
    mapT = bind_checked_inf(pat, t_map(), type, opaques)

    case rev do
      true ->
        {map, mapT}

      false ->
        foldFun = fn pair, {mapAcc, listAcc} ->
          :exact = :cerl.concrete(:cerl.map_pair_op(pair))
          key = :cerl.map_pair_key(pair)

          keyType =
            case :cerl.type(key) do
              :var ->
                case state__lookup_type_for_letrec(
                       key,
                       state
                     ) do
                  :error ->
                    lookup_type(key, mapAcc)

                  {:ok, recType} ->
                    recType
                end

              :literal ->
                literal_type(key)
            end

          bind = :erl_types.t_map_get(keyType, mapT)

          {mapAcc1, [valType]} =
            do_bind_pat_vars([:cerl.map_pair_val(pair)], [bind], mapAcc, state, rev, [])

          case t_is_singleton(keyType, opaques) do
            true ->
              {mapAcc1, [{keyType, valType} | listAcc]}

            false ->
              {mapAcc1, listAcc}
          end
        end

        {map1, pairs} = :lists.foldl(foldFun, {map, []}, :cerl.map_es(pat))
        {map1, t_inf(mapT, t_map(pairs))}
    end
  end

  defp bind_tuple(pat, type, map, state, opaques, rev) do
    es = :cerl.tuple_es(pat)

    {isTypedRecord, prototype} =
      case es do
        [] ->
          {false, t_tuple([])}

        [tag | tags] ->
          case :cerl.is_c_atom(tag) and is_literal_record(pat) do
            true ->
              any = t_any()

              [_Head | anyTail] =
                for _ <- es do
                  any
                end

              tagAtomVal = :cerl.atom_val(tag)

              untypedRecord =
                t_tuple([
                  t_atom(tagAtomVal)
                  | anyTail
                ])

              case state__lookup_record(
                     tagAtomVal,
                     length(tags),
                     state
                   ) do
                :error ->
                  {false, untypedRecord}

                {:ok, record, _FieldNames} ->
                  {not t_is_equal(
                     record,
                     untypedRecord
                   ), record}
              end

            false ->
              {false, t_tuple(length(es))}
          end
      end

    tuple = bind_checked_inf(pat, prototype, type, opaques)
    subTuples = t_tuple_subtypes(tuple, opaques)
    mapJ = join_maps_begin(map)

    results =
      for subTuple <- subTuples do
        bind_pat_vars(es, t_tuple_args(subTuple, opaques), mapJ, state, rev)
      end

    case :lists.keyfind(:opaque, 2, results) do
      {:error, :opaque, _PatList, _Type, opaque} ->
        bind_error([pat], tuple, opaque, :opaque)

      false ->
        case (for {m, _} <- results, m !== :error do
                m
              end) do
          [] ->
            case isTypedRecord do
              true ->
                bind_error([pat], tuple, prototype, :record)

              false ->
                bind_error([pat], tuple, t_none(), :bind)
            end

          maps ->
            map1 = join_maps_end(maps, mapJ)

            tupleType =
              t_sup(
                for {m, esTypes} <- results,
                    m !== :error do
                  t_tuple(esTypes)
                end
              )

            {map1, tupleType}
        end
    end
  end

  defp bind_bin_segs(binSegs, binType, map, state) do
    bind_bin_segs(binSegs, binType, [], map, state)
  end

  defp bind_bin_segs([seg | segs], binType, acc, map, state) do
    val = :cerl.bitstr_val(seg)
    segType = :cerl.concrete(:cerl.bitstr_type(seg))
    unitVal = :cerl.concrete(:cerl.bitstr_unit(seg))
    size = :cerl.bitstr_size(seg)

    case bitstr_bitsize_type(size) do
      {:literal, :all} ->
        :binary = segType
        [] = segs
        t = t_inf(t_bitstr(unitVal, 0), binType)
        {map1, [type]} = do_bind_pat_vars([val], [t], map, state, false, [])

        type1 =
          remove_local_opaque_types(
            type,
            r_state(state, :opaques)
          )

        bind_bin_segs(segs, t_bitstr(0, 0), [type1 | acc], map1, state)

      sizeType
      when segType === :utf8 or segType === :utf16 or
             segType === :utf32 ->
        {:literal, :undefined} = sizeType
        {map1, [_]} = do_bind_pat_vars([val], [t_integer()], map, state, false, [])
        type = t_binary()
        bind_bin_segs(segs, binType, [type | acc], map1, state)

      {:literal, n} when not is_integer(n) or n < 0 ->
        bind_error([seg], binType, t_none(), :bind)

      _ ->
        {map1, [sizeType]} =
          do_bind_pat_vars([size], [t_non_neg_integer()], map, state, false, [])

        opaques = r_state(state, :opaques)
        numberVals = t_number_vals(sizeType, opaques)

        case t_contains_opaque(sizeType, opaques) do
          true ->
            bind_error([seg], sizeType, t_none(), :opaque)

          false ->
            :ok
        end

        type =
          case numberVals do
            [oneSize] ->
              t_bitstr(0, unitVal * oneSize)

            _ ->
              minSize = :erl_types.number_min(sizeType, opaques)
              t_bitstr(unitVal, unitVal * minSize)
          end

        valConstr =
          case segType do
            :binary ->
              type

            :float ->
              t_float()

            :integer ->
              case numberVals do
                :unknown ->
                  t_integer()

                list ->
                  sizeVal = :lists.max(list)
                  flags = :cerl.concrete(:cerl.bitstr_flags(seg))
                  n = sizeVal * unitVal

                  case n >= 128 do
                    true ->
                      case :lists.member(:signed, flags) do
                        true ->
                          t_from_range(:neg_inf, :pos_inf)

                        false ->
                          t_from_range(0, :pos_inf)
                      end

                    false ->
                      case :lists.member(:signed, flags) do
                        true ->
                          t_from_range(
                            -(1 <<< (n - 1)),
                            1 <<< (n - 1 - 1)
                          )

                        false ->
                          t_from_range(0, 1 <<< (n - 1))
                      end
                  end
              end
          end

        {map2, [_]} = do_bind_pat_vars([val], [valConstr], map1, state, false, [])
        newBinType = t_bitstr_match(type, binType)

        case t_is_none(newBinType) do
          true ->
            bind_error([seg], binType, t_none(), :bind)

          false ->
            bind_bin_segs(segs, newBinType, [type | acc], map2, state)
        end
    end
  end

  defp bind_bin_segs([], _BinType, acc, map, _State) do
    {map, :lists.reverse(acc)}
  end

  defp bitstr_bitsize_type(size) do
    case :cerl.is_literal(size) do
      true ->
        {:literal, :cerl.concrete(size)}

      false ->
        :variable
    end
  end

  defp bind_checked_inf(pat, expectedType, type, opaques) do
    inf = t_inf(expectedType, type, opaques)

    case t_is_impossible(inf) do
      true ->
        case t_find_opaque_mismatch(expectedType, type, opaques) do
          {:ok, t1, t2} ->
            bind_error([pat], t1, t2, :opaque)

          :error ->
            bind_error([pat], type, inf, :bind)
        end

      false ->
        inf
    end
  end

  defp bind_error(pats, type, opaqueType, error0) do
    error =
      case {error0, pats} do
        {:bind, [pat]} ->
          case is_literal_record(pat) do
            true ->
              :record

            false ->
              error0
          end

        _ ->
          error0
      end

    throw({:error, error, pats, type, opaqueType})
  end

  defp bind_guard(guard, map, state) do
    try do
      bind_guard(guard, map, :maps.new(), :pos, state)
    catch
      {:fail, warning} ->
        {:error, warning}

      {:fatal_fail, warning} ->
        {:error, warning}
    else
      {map1, _Type} ->
        map1
    end
  end

  defp bind_guard(guard, map, env, eval, state) do
    :ok

    case :cerl.type(guard) do
      :binary ->
        {map, t_binary()}

      :case ->
        arg = :cerl.case_arg(guard)
        clauses = :cerl.case_clauses(guard)
        bind_guard_case_clauses(arg, clauses, map, env, eval, state)

      :cons ->
        hd = :cerl.cons_hd(guard)
        tl = :cerl.cons_tl(guard)
        {map1, hdType} = bind_guard(hd, map, env, :dont_know, state)
        {map2, tlType} = bind_guard(tl, map1, env, :dont_know, state)
        {map2, t_cons(hdType, tlType)}

      :literal ->
        {map, literal_type(guard)}

      :try ->
        arg = :cerl.try_arg(guard)
        [var] = :cerl.try_vars(guard)
        eVars = :cerl.try_evars(guard)
        map1 = join_maps_begin(map)
        map2 = mark_as_fresh(eVars, map1)

        {{handlerMap, handlerType}, handlerE} =
          try do
            {bind_guard(:cerl.try_handler(guard), map2, env, eval, state), :none}
          catch
            hE ->
              {{map2, t_none()}, hE}
          end

        bodyEnv = :maps.put(get_label(var), arg, env)

        case t_is_none(guard_eval_inf(eval, handlerType)) do
          true ->
            bind_guard(:cerl.try_body(guard), map, bodyEnv, eval, state)

          false ->
            {{bodyMap, bodyType}, bodyE} =
              try do
                {bind_guard(:cerl.try_body(guard), map1, bodyEnv, eval, state), :none}
              catch
                bE ->
                  {{map1, t_none()}, bE}
              end

            map3 = join_maps_end([bodyMap, handlerMap], map1)

            case t_is_none(sup = t_sup(bodyType, handlerType)) do
              true ->
                fatality =
                  case {bodyE, handlerE} do
                    {{:fatal_fail, _}, _} ->
                      :fatal_fail

                    {_, {:fatal_fail, _}} ->
                      :fatal_fail

                    _ ->
                      :fail
                  end

                throw(
                  {fatality,
                   case {bodyE, handlerE} do
                     {{_, rsn}, _} when rsn !== :none ->
                       rsn

                     {_, {_, rsn}} ->
                       rsn

                     _ ->
                       :none
                   end}
                )

              false ->
                {map3, sup}
            end
        end

      :tuple ->
        es0 = :cerl.tuple_es(guard)
        {map1, es} = bind_guard_list(es0, map, env, :dont_know, state)
        {map1, t_tuple(es)}

      :map ->
        case eval do
          :dont_know ->
            handle_guard_map(guard, map, env, state)

          _PosOrNeg ->
            {map, t_none()}
        end

      :let ->
        arg = :cerl.let_arg(guard)
        [var] = :cerl.let_vars(guard)
        newEnv = :maps.put(get_label(var), arg, env)
        bind_guard(:cerl.let_body(guard), map, newEnv, eval, state)

      :values ->
        es = :cerl.values_es(guard)

        list =
          for v <- es do
            bind_guard(v, map, env, :dont_know, state)
          end

        type =
          t_product(
            for {_, t} <- list do
              t
            end
          )

        {map, type}

      :var ->
        :ok
        guardLabel = get_label(guard)

        case env do
          %{^guardLabel => tree} ->
            :ok
            {map1, type} = bind_guard(tree, map, env, eval, state)
            {enter_type(guard, type, map1), type}

          %{} ->
            :ok
            type = lookup_type(guard, map)
            inf = guard_eval_inf(eval, type)
            {enter_type(guard, inf, map), inf}
        end

      :call ->
        handle_guard_call(guard, map, env, eval, state)
    end
  end

  defp handle_guard_call(guard, map, env, eval, state) do
    mFA =
      {:cerl.atom_val(:cerl.call_module(guard)), :cerl.atom_val(:cerl.call_name(guard)),
       :cerl.call_arity(guard)}

    case mFA do
      {:erlang, :is_function, 2} ->
        handle_guard_is_function(guard, map, env, eval, state)

      {:erlang, f, 3}
      when f === :internal_is_record or
             f === :is_record ->
        handle_guard_is_record(guard, map, env, eval, state)

      {:erlang, :"=:=", 2} ->
        handle_guard_eqeq(guard, map, env, eval, state)

      {:erlang, :==, 2} ->
        handle_guard_eq(guard, map, env, eval, state)

      {:erlang, :and, 2} ->
        handle_guard_and(guard, map, env, eval, state)

      {:erlang, :or, 2} ->
        handle_guard_or(guard, map, env, eval, state)

      {:erlang, :not, 1} ->
        handle_guard_not(guard, map, env, eval, state)

      {:erlang, comp, 2}
      when comp === :< or comp === :"=<" or
             comp === :> or comp === :>= ->
        handle_guard_comp(guard, comp, map, env, eval, state)

      {:erlang, f, a} ->
        typeTestType = type_test_type(f, a)

        case t_is_any(typeTestType) do
          true ->
            handle_guard_gen_fun(mFA, guard, map, env, eval, state)

          false ->
            handle_guard_type_test(guard, typeTestType, map, env, eval, state)
        end
    end
  end

  defp handle_guard_gen_fun({m, f, a}, guard, map, env, eval, state) do
    args = :cerl.call_args(guard)
    {map1, as} = bind_guard_list(args, map, env, :dont_know, state)
    opaques = r_state(state, :opaques)
    bifRet = :erl_bif_types.type(m, f, a, as, opaques)

    case t_is_none(bifRet) do
      true ->
        case t_is_none(:erl_bif_types.type(m, f, a)) do
          true ->
            signal_guard_fail(eval, guard, as, state)

          false ->
            signal_guard_fatal_fail(eval, guard, as, state)
        end

      false ->
        bifArgs = bif_args(m, f, a)
        map2 = enter_type_lists(args, t_inf_lists(bifArgs, as, opaques), map1)
        ret = guard_eval_inf(eval, bifRet)

        case t_is_none(ret) do
          true ->
            case eval === :pos do
              true ->
                signal_guard_fail(eval, guard, as, state)

              false ->
                throw({:fail, :none})
            end

          false ->
            {map2, ret}
        end
    end
  end

  defp handle_guard_type_test(guard, typeTestType, map, env, eval, state) do
    [arg] = :cerl.call_args(guard)
    {map1, argType} = bind_guard(arg, map, env, :dont_know, state)

    case bind_type_test(eval, typeTestType, argType, state) do
      :error ->
        :ok
        signal_guard_fail(eval, guard, [argType], state)

      {:ok, newArgType, ret} ->
        :ok
        {enter_type(arg, newArgType, map1), ret}
    end
  end

  defp bind_type_test(eval, type, argType, state) do
    case eval do
      :pos ->
        inf = t_inf(type, argType, r_state(state, :opaques))

        case t_is_none(inf) do
          true ->
            :error

          false ->
            {:ok, inf, t_atom(true)}
        end

      :neg ->
        sub = t_subtract(argType, type)

        case t_is_none(sub) do
          true ->
            :error

          false ->
            {:ok, sub, t_atom(false)}
        end

      :dont_know ->
        {:ok, argType, t_boolean()}
    end
  end

  defp type_test_type(typeTest, 1) do
    case typeTest do
      :is_atom ->
        t_atom()

      :is_boolean ->
        t_boolean()

      :is_binary ->
        t_binary()

      :is_bitstring ->
        t_bitstr()

      :is_float ->
        t_float()

      :is_function ->
        t_fun()

      :is_integer ->
        t_integer()

      :is_list ->
        t_maybe_improper_list()

      :is_map ->
        t_map()

      :is_number ->
        t_number()

      :is_pid ->
        t_pid()

      :is_port ->
        t_port()

      :is_reference ->
        t_reference()

      :is_tuple ->
        t_tuple()

      _ ->
        t_any()
    end
  end

  defp type_test_type(_, _) do
    t_any()
  end

  defp handle_guard_comp(guard, comp, map, env, eval, state) do
    args = :cerl.call_args(guard)
    [arg1, arg2] = args
    {map1, argTypes} = bind_guard_list(args, map, env, :dont_know, state)
    opaques = r_state(state, :opaques)
    [type1, type2] = argTypes
    isInt1 = t_is_integer(type1, opaques)
    isInt2 = t_is_integer(type2, opaques)

    case {type(arg1), type(arg2)} do
      {{:literal, lit1}, {:literal, lit2}} ->
        case apply(:erlang, comp, [:cerl.concrete(lit1), :cerl.concrete(lit2)]) do
          true when eval === :pos ->
            {map, t_atom(true)}

          true when eval === :dont_know ->
            {map, t_atom(true)}

          true when eval === :neg ->
            {map, t_atom(true)}

          false when eval === :pos ->
            signal_guard_fail(eval, guard, argTypes, state)

          false when eval === :dont_know ->
            {map, t_atom(false)}

          false when eval === :neg ->
            {map, t_atom(false)}
        end

      {{:literal, lit1}, :var}
      when isInt1 and isInt2 and
             eval === :pos ->
        case bind_comp_literal_var(lit1, arg2, type2, comp, map1, opaques) do
          :error ->
            signal_guard_fail(eval, guard, argTypes, state)

          {:ok, newMap} ->
            {newMap, t_atom(true)}
        end

      {:var, {:literal, lit2}}
      when isInt1 and isInt2 and
             eval === :pos ->
        case bind_comp_literal_var(lit2, arg1, type1, invert_comp(comp), map1, opaques) do
          :error ->
            signal_guard_fail(eval, guard, argTypes, state)

          {:ok, newMap} ->
            {newMap, t_atom(true)}
        end

      {_, _} ->
        handle_guard_gen_fun({:erlang, comp, 2}, guard, map, env, eval, state)
    end
  end

  defp invert_comp(:"=<") do
    :>=
  end

  defp invert_comp(:<) do
    :>
  end

  defp invert_comp(:>=) do
    :"=<"
  end

  defp invert_comp(:>) do
    :<
  end

  defp bind_comp_literal_var(lit, var, varType, compOp, map, opaques) do
    litVal = :cerl.concrete(lit)

    newVarType =
      case t_number_vals(varType, opaques) do
        :unknown ->
          range =
            case compOp do
              :"=<" ->
                t_from_range(litVal, :pos_inf)

              :< ->
                t_from_range(litVal + 1, :pos_inf)

              :>= ->
                t_from_range(:neg_inf, litVal)

              :> ->
                t_from_range(:neg_inf, litVal - 1)
            end

          t_inf(range, varType, opaques)

        numberVals ->
          newNumberVals =
            for x <- numberVals,
                apply(:erlang, compOp, [litVal, x]) do
              x
            end

          t_integers(newNumberVals)
      end

    case t_is_none(newVarType) do
      true ->
        :error

      false ->
        {:ok, enter_type(var, newVarType, map)}
    end
  end

  defp handle_guard_is_function(guard, map, env, eval, state) do
    args = :cerl.call_args(guard)
    {map1, argTypes0} = bind_guard_list(args, map, env, :dont_know, state)
    [funType0, arityType0] = argTypes0
    opaques = r_state(state, :opaques)
    arityType = t_inf(arityType0, t_integer(), opaques)

    case t_is_none(arityType) do
      true ->
        signal_guard_fail(eval, guard, argTypes0, state)

      false ->
        funTypeConstr =
          case t_number_vals(
                 arityType,
                 r_state(state, :opaques)
               ) do
            :unknown ->
              t_fun()

            vals ->
              t_sup(
                for x <- vals do
                  t_fun(
                    :lists.duplicate(x, t_any()),
                    t_any()
                  )
                end
              )
          end

        funType = t_inf(funType0, funTypeConstr, opaques)

        case t_is_none(funType) do
          true ->
            case eval do
              :pos ->
                signal_guard_fail(eval, guard, argTypes0, state)

              :neg ->
                {map1, t_atom(false)}

              :dont_know ->
                {map1, t_atom(false)}
            end

          false ->
            case eval do
              :pos ->
                {enter_type_lists(args, [funType, arityType], map1), t_atom(true)}

              :neg ->
                {map1, t_atom(false)}

              :dont_know ->
                {map1, t_boolean()}
            end
        end
    end
  end

  defp handle_guard_is_record(guard, map, env, eval, state) do
    args = :cerl.call_args(guard)
    [rec, tag0, arity0] = args
    tag = :cerl.atom_val(tag0)
    arity = :cerl.int_val(arity0)
    {map1, recType} = bind_guard(rec, map, env, :dont_know, state)
    arityMin1 = arity - 1
    opaques = r_state(state, :opaques)

    tuple =
      t_tuple([
        t_atom(tag)
        | :lists.duplicate(arityMin1, t_any())
      ])

    case t_is_none(t_inf(tuple, recType, opaques)) do
      true ->
        case :erl_types.t_has_opaque_subtype(
               recType,
               opaques
             ) do
          true ->
            signal_guard_fail(eval, guard, [recType, t_from_term(tag), t_from_term(arity)], state)

          false ->
            case eval do
              :pos ->
                signal_guard_fail(
                  eval,
                  guard,
                  [recType, t_from_term(tag), t_from_term(arity)],
                  state
                )

              :neg ->
                {map1, t_atom(false)}

              :dont_know ->
                {map1, t_atom(false)}
            end
        end

      false ->
        tupleType =
          case state__lookup_record(tag, arityMin1, state) do
            :error ->
              tuple

            {:ok, prototype, _FieldNames} ->
              prototype
          end

        type = t_inf(tupleType, recType, r_state(state, :opaques))

        case t_is_none(type) do
          true ->
            fArgs = ~c"record " ++ format_type(recType, state)
            msg = {:record_matching, [fArgs, tag]}
            throw({:fail, {guard, msg}})

          false ->
            case eval do
              :pos ->
                {enter_type(rec, type, map1), t_atom(true)}

              :neg ->
                {map1, t_atom(false)}

              :dont_know ->
                {map1, t_boolean()}
            end
        end
    end
  end

  defp handle_guard_eq(guard, map, env, eval, state) do
    [arg1, arg2] = :cerl.call_args(guard)

    case {type(arg1), type(arg2)} do
      {{:literal, lit1}, {:literal, lit2}} ->
        case :cerl.concrete(lit1) === :cerl.concrete(lit2) do
          true ->
            cond do
              eval === :pos ->
                {map, t_atom(true)}

              eval === :neg ->
                argTypes = [t_from_term(:cerl.concrete(lit1)), t_from_term(:cerl.concrete(lit2))]
                signal_guard_fail(eval, guard, argTypes, state)

              eval === :dont_know ->
                {map, t_atom(true)}
            end

          false ->
            cond do
              eval === :neg ->
                {map, t_atom(false)}

              eval === :dont_know ->
                {map, t_atom(false)}

              eval === :pos ->
                argTypes = [t_from_term(:cerl.concrete(lit1)), t_from_term(:cerl.concrete(lit2))]
                signal_guard_fail(eval, guard, argTypes, state)
            end
        end

      {{:literal, lit1}, _} when eval === :pos ->
        case :cerl.concrete(lit1) do
          atom when is_atom(atom) ->
            bind_eqeq_guard_lit_other(guard, lit1, arg2, map, env, state)

          [] ->
            bind_eqeq_guard_lit_other(guard, lit1, arg2, map, env, state)

          _ ->
            bind_eq_guard(guard, lit1, arg2, map, env, eval, state)
        end

      {_, {:literal, lit2}} when eval === :pos ->
        case :cerl.concrete(lit2) do
          atom when is_atom(atom) ->
            bind_eqeq_guard_lit_other(guard, lit2, arg1, map, env, state)

          [] ->
            bind_eqeq_guard_lit_other(guard, lit2, arg1, map, env, state)

          _ ->
            bind_eq_guard(guard, arg1, lit2, map, env, eval, state)
        end

      {_, _} ->
        bind_eq_guard(guard, arg1, arg2, map, env, eval, state)
    end
  end

  defp bind_eq_guard(guard, arg1, arg2, map, env, eval, state) do
    {map1, type1} = bind_guard(arg1, map, env, :dont_know, state)
    {map2, type2} = bind_guard(arg2, map1, env, :dont_know, state)
    opaques = r_state(state, :opaques)

    case t_is_nil(type1, opaques) or
           t_is_nil(
             type2,
             opaques
           ) or
           t_is_atom(
             type1,
             opaques
           ) or
           t_is_atom(
             type2,
             opaques
           ) do
      true ->
        bind_eqeq_guard(guard, arg1, arg2, map, env, eval, state)

      false ->
        opArgs = :erl_types.t_find_unknown_opaque(type1, type2, opaques)

        case opArgs === [] do
          true ->
            {map2, guard_eval_inf(eval, t_boolean())}

          false ->
            signal_guard_fail(eval, guard, [type1, type2], state)
        end
    end
  end

  defp handle_guard_eqeq(guard, map, env, eval, state) do
    [arg1, arg2] = :cerl.call_args(guard)

    case {type(arg1), type(arg2)} do
      {{:literal, lit1}, {:literal, lit2}} ->
        case :cerl.concrete(lit1) === :cerl.concrete(lit2) do
          true ->
            cond do
              eval === :neg ->
                argTypes = [t_from_term(:cerl.concrete(lit1)), t_from_term(:cerl.concrete(lit2))]
                signal_guard_fail(eval, guard, argTypes, state)

              eval === :pos ->
                {map, t_atom(true)}

              eval === :dont_know ->
                {map, t_atom(true)}
            end

          false ->
            cond do
              eval === :neg ->
                {map, t_atom(false)}

              eval === :dont_know ->
                {map, t_atom(false)}

              eval === :pos ->
                argTypes = [t_from_term(:cerl.concrete(lit1)), t_from_term(:cerl.concrete(lit2))]
                signal_guard_fail(eval, guard, argTypes, state)
            end
        end

      {{:literal, lit1}, _} when eval === :pos ->
        bind_eqeq_guard_lit_other(guard, lit1, arg2, map, env, state)

      {_, {:literal, lit2}} when eval === :pos ->
        bind_eqeq_guard_lit_other(guard, lit2, arg1, map, env, state)

      {_, _} ->
        bind_eqeq_guard(guard, arg1, arg2, map, env, eval, state)
    end
  end

  defp bind_eqeq_guard(guard, arg1, arg2, map, env, eval, state) do
    {map1, type1} = bind_guard(arg1, map, env, :dont_know, state)
    {map2, type2} = bind_guard(arg2, map1, env, :dont_know, state)
    :ok
    opaques = r_state(state, :opaques)
    inf = t_inf(type1, type2, opaques)

    case t_is_none(inf) do
      true ->
        opArgs = :erl_types.t_find_unknown_opaque(type1, type2, opaques)

        case opArgs === [] do
          true ->
            case eval do
              :neg ->
                {map2, t_atom(false)}

              :dont_know ->
                {map2, t_atom(false)}

              :pos ->
                signal_guard_fail(eval, guard, [type1, type2], state)
            end

          false ->
            signal_guard_fail(eval, guard, [type1, type2], state)
        end

      false ->
        case eval do
          :pos ->
            case {:cerl.type(arg1), :cerl.type(arg2)} do
              {:var, :var} ->
                map3 = enter_subst(arg1, arg2, map2)
                map4 = enter_type(arg2, inf, map3)
                {map4, t_atom(true)}

              {:var, _} ->
                map3 = enter_type(arg1, inf, map2)
                {map3, t_atom(true)}

              {_, :var} ->
                map3 = enter_type(arg2, inf, map2)
                {map3, t_atom(true)}

              {_, _} ->
                {map2, t_atom(true)}
            end

          :neg ->
            {map2, t_atom(false)}

          :dont_know ->
            {map2, t_boolean()}
        end
    end
  end

  defp bind_eqeq_guard_lit_other(guard, arg1, arg2, map, env, state) do
    eval = :dont_know
    opaques = r_state(state, :opaques)

    case :cerl.concrete(arg1) do
      true ->
        {_, type} = mT = bind_guard(arg2, map, env, :pos, state)

        case t_is_any_atom(true, type, opaques) do
          true ->
            mT

          false ->
            {_, type0} = bind_guard(arg2, map, env, eval, state)
            signal_guard_fail(eval, guard, [type0, t_atom(true)], state)
        end

      false ->
        {map1, type} = bind_guard(arg2, map, env, :neg, state)

        case t_is_any_atom(false, type, opaques) do
          true ->
            {map1, t_atom(true)}

          false ->
            {_, type0} = bind_guard(arg2, map, env, eval, state)
            signal_guard_fail(eval, guard, [type0, t_atom(false)], state)
        end

      term ->
        litType = t_from_term(term)
        {map1, type} = bind_guard(arg2, map, env, eval, state)

        case t_is_subtype(litType, type) do
          false ->
            signal_guard_fail(eval, guard, [type, litType], state)

          true ->
            case :cerl.is_c_var(arg2) do
              true ->
                {enter_type(arg2, litType, map1), t_atom(true)}

              false ->
                {map1, t_atom(true)}
            end
        end
    end
  end

  defp handle_guard_and(guard, map, env, eval, state) do
    [arg1, arg2] = :cerl.call_args(guard)
    opaques = r_state(state, :opaques)

    case eval do
      :pos ->
        {map1, type1} = bind_guard(arg1, map, env, eval, state)

        case t_is_any_atom(true, type1, opaques) do
          false ->
            signal_guard_fail(eval, guard, [type1, t_any()], state)

          true ->
            {map2, type2} = bind_guard(arg2, map1, env, eval, state)

            case t_is_any_atom(true, type2, opaques) do
              false ->
                signal_guard_fail(eval, guard, [type1, type2], state)

              true ->
                {map2, t_atom(true)}
            end
        end

      :neg ->
        mapJ = join_maps_begin(map)

        {map1, type1} =
          try do
            bind_guard(arg1, mapJ, env, :neg, state)
          catch
            {:fail, _} ->
              bind_guard(arg2, mapJ, env, :pos, state)
          end

        {map2, type2} =
          try do
            bind_guard(arg2, mapJ, env, :neg, state)
          catch
            {:fail, _} ->
              bind_guard(arg1, mapJ, env, :pos, state)
          end

        case t_is_any_atom(false, type1, opaques) or t_is_any_atom(false, type2, opaques) do
          true ->
            {join_maps_end([map1, map2], mapJ), t_atom(false)}

          false ->
            signal_guard_fail(eval, guard, [type1, type2], state)
        end

      :dont_know ->
        mapJ = join_maps_begin(map)
        {map1, type1} = bind_guard(arg1, mapJ, env, :dont_know, state)
        {map2, type2} = bind_guard(arg2, mapJ, env, :dont_know, state)
        bool1 = t_inf(type1, t_boolean())
        bool2 = t_inf(type2, t_boolean())

        case t_is_none(bool1) or t_is_none(bool2) do
          true ->
            throw({:fatal_fail, :none})

          false ->
            newMap = join_maps_end([map1, map2], mapJ)

            newType =
              case {t_atom_vals(bool1, opaques), t_atom_vals(bool2, opaques)} do
                {[true], [true]} ->
                  t_atom(true)

                {[false], _} ->
                  t_atom(false)

                {_, [false]} ->
                  t_atom(false)

                {:unknown, _} ->
                  signal_guard_fail(eval, guard, [type1, type2], state)

                {_, :unknown} ->
                  signal_guard_fail(eval, guard, [type1, type2], state)

                {_, _} ->
                  t_boolean()
              end

            {newMap, newType}
        end
    end
  end

  defp handle_guard_or(guard, map, env, eval, state) do
    [arg1, arg2] = :cerl.call_args(guard)
    opaques = r_state(state, :opaques)

    case eval do
      :pos ->
        mapJ = join_maps_begin(map)

        {map1, bool1} =
          try do
            bind_guard(arg1, mapJ, env, :pos, state)
          catch
            {:fail, _} ->
              bind_guard(arg1, mapJ, env, :dont_know, state)
          end

        {map2, bool2} =
          try do
            bind_guard(arg2, mapJ, env, :pos, state)
          catch
            {:fail, _} ->
              bind_guard(arg2, mapJ, env, :dont_know, state)
          end

        case (t_is_any_atom(true, bool1, opaques) and
                t_is_boolean(
                  bool2,
                  opaques
                )) or
               (t_is_any_atom(
                  true,
                  bool2,
                  opaques
                ) and
                  t_is_boolean(
                    bool1,
                    opaques
                  )) do
          true ->
            {join_maps_end([map1, map2], mapJ), t_atom(true)}

          false ->
            signal_guard_fail(eval, guard, [bool1, bool2], state)
        end

      :neg ->
        {map1, type1} = bind_guard(arg1, map, env, :neg, state)

        case t_is_any_atom(false, type1, opaques) do
          false ->
            signal_guard_fail(eval, guard, [type1, t_any()], state)

          true ->
            {map2, type2} = bind_guard(arg2, map1, env, :neg, state)

            case t_is_any_atom(false, type2, opaques) do
              false ->
                signal_guard_fail(eval, guard, [type1, type2], state)

              true ->
                {map2, t_atom(false)}
            end
        end

      :dont_know ->
        mapJ = join_maps_begin(map)
        {map1, type1} = bind_guard(arg1, mapJ, env, :dont_know, state)
        {map2, type2} = bind_guard(arg2, mapJ, env, :dont_know, state)
        bool1 = t_inf(type1, t_boolean())
        bool2 = t_inf(type2, t_boolean())

        case t_is_none(bool1) or t_is_none(bool2) do
          true ->
            throw({:fatal_fail, :none})

          false ->
            newMap = join_maps_end([map1, map2], mapJ)

            newType =
              case {t_atom_vals(bool1, opaques), t_atom_vals(bool2, opaques)} do
                {[false], [false]} ->
                  t_atom(false)

                {[true], _} ->
                  t_atom(true)

                {_, [true]} ->
                  t_atom(true)

                {:unknown, _} ->
                  signal_guard_fail(eval, guard, [type1, type2], state)

                {_, :unknown} ->
                  signal_guard_fail(eval, guard, [type1, type2], state)

                {_, _} ->
                  t_boolean()
              end

            {newMap, newType}
        end
    end
  end

  defp handle_guard_not(guard, map, env, eval, state) do
    [arg] = :cerl.call_args(guard)
    opaques = r_state(state, :opaques)

    case eval do
      :neg ->
        {map1, type} = bind_guard(arg, map, env, :pos, state)

        case t_is_any_atom(true, type, opaques) do
          true ->
            {map1, t_atom(false)}

          false ->
            {_, type0} = bind_guard(arg, map, env, eval, state)
            signal_guard_fail(eval, guard, [type0], state)
        end

      :pos ->
        {map1, type} = bind_guard(arg, map, env, :neg, state)

        case t_is_any_atom(false, type, opaques) do
          true ->
            {map1, t_atom(true)}

          false ->
            {_, type0} = bind_guard(arg, map, env, eval, state)
            signal_guard_fail(eval, guard, [type0], state)
        end

      :dont_know ->
        {map1, type} = bind_guard(arg, map, env, :dont_know, state)
        bool = t_inf(type, t_boolean())

        case t_is_none(bool) do
          true ->
            throw({:fatal_fail, :none})

          false ->
            case t_atom_vals(bool, opaques) do
              [true] ->
                {map1, t_atom(false)}

              [false] ->
                {map1, t_atom(true)}

              [_, _] ->
                {map1, bool}

              :unknown ->
                signal_guard_fail(eval, guard, [type], state)
            end
        end
    end
  end

  defp bind_guard_list(guards, map, env, eval, state) do
    bind_guard_list(guards, map, env, eval, state, [])
  end

  defp bind_guard_list([g | gs], map, env, eval, state, acc) do
    {map1, t} = bind_guard(g, map, env, eval, state)
    bind_guard_list(gs, map1, env, eval, state, [t | acc])
  end

  defp bind_guard_list([], map, _Env, _Eval, _State, acc) do
    {map, :lists.reverse(acc)}
  end

  defp handle_guard_map(guard, map, env, state) do
    pairs = :cerl.map_es(guard)
    arg = :cerl.map_arg(guard)
    {map1, argType0} = bind_guard(arg, map, env, :dont_know, state)
    argType1 = t_inf(t_map(), argType0)

    case t_is_impossible(argType1) do
      true ->
        {map1, t_none()}

      false ->
        {map2, typePairs} = bind_guard_map_pairs(pairs, map1, env, state, [])

        {map2,
         :lists.foldl(
           fn
             {kV, :assoc}, acc ->
               :erl_types.t_map_put(kV, acc)

             {kV, :exact}, acc ->
               :erl_types.t_map_update(kV, acc)
           end,
           argType1,
           typePairs
         )}
    end
  end

  defp bind_guard_map_pairs([], map, _Env, _State, pairAcc) do
    {map, :lists.reverse(pairAcc)}
  end

  defp bind_guard_map_pairs([pair | pairs], map, env, state, pairAcc) do
    key = :cerl.map_pair_key(pair)
    val = :cerl.map_pair_val(pair)
    op = :cerl.map_pair_op(pair)
    {map1, [k, v]} = bind_guard_list([key, val], map, env, :dont_know, state)
    bind_guard_map_pairs(pairs, map1, env, state, [{{k, v}, :cerl.concrete(op)} | pairAcc])
  end

  defp guard_eval_inf(eval, type) do
    constr =
      case eval do
        :pos ->
          t_atom(true)

        :neg ->
          t_atom(false)

        :dont_know ->
          type
      end

    t_inf(constr, type)
  end

  defp signal_guard_fail(eval, guard, argTypes, state) do
    signal_guard_failure(eval, guard, argTypes, :fail, state)
  end

  defp signal_guard_fatal_fail(eval, guard, argTypes, state) do
    signal_guard_failure(eval, guard, argTypes, :fatal_fail, state)
  end

  defp signal_guard_failure(eval, guard, argTypes, tag, state) do
    args = :cerl.call_args(guard)
    f = :cerl.atom_val(:cerl.call_name(guard))
    {m, ^f, a} = mFA = {:cerl.atom_val(:cerl.call_module(guard)), f, length(args)}
    opaques = r_state(state, :opaques)

    {kind, xInfo} =
      case :erl_bif_types.opaque_args(m, f, a, argTypes, opaques) do
        [] ->
          {case eval do
             :neg ->
               :neg_guard_fail

             :pos ->
               :guard_fail

             :dont_know ->
               :guard_fail
           end, []}

        ns ->
          {:opaque_guard, [ns]}
      end

    fArgs =
      case is_infix_op(mFA) do
        true ->
          [argType1, argType2] = argTypes
          [arg1, arg2] = args

          [
            format_args_1([arg1], [argType1], state),
            :erlang.atom_to_list(f),
            format_args_1(
              [arg2],
              [argType2],
              state
            )
          ] ++ xInfo

        false ->
          [f, format_args(args, argTypes, state)]
      end

    msg = {kind, fArgs}

    locTree =
      case xInfo do
        [] ->
          guard

        [ns1] ->
          select_arg(ns1, args, guard)
      end

    throw({tag, {locTree, msg}})
  end

  defp is_infix_op({:erlang, f, 2}) do
    :erl_internal.comp_op(f, 2)
  end

  defp is_infix_op({_, _, _}) do
    false
  end

  defp bif_args(m, f, a) do
    case :erl_bif_types.arg_types(m, f, a) do
      :unknown ->
        :lists.duplicate(a, t_any())

      list ->
        list
    end
  end

  defp bind_guard_case_clauses(arg, clauses, map0, env, eval, state) do
    clauses1 = filter_fail_clauses(clauses)
    map = join_maps_begin(map0)
    {genMap, genArgType} = bind_guard(arg, map, env, :dont_know, state)

    bind_guard_case_clauses(
      genArgType,
      genMap,
      arg,
      clauses1,
      map,
      env,
      eval,
      t_none(),
      [],
      [],
      state
    )
  end

  defp filter_fail_clauses([clause | left]) do
    case :cerl.clause_pats(clause) === [] do
      true ->
        body = :cerl.clause_body(clause)

        case (:cerl.is_literal(body) and :cerl.concrete(body) === :fail) or
               (:cerl.is_c_primop(body) and
                  :cerl.atom_val(:cerl.primop_name(body)) === :match_fail) do
          true ->
            filter_fail_clauses(left)

          false ->
            [clause | filter_fail_clauses(left)]
        end

      false ->
        [clause | filter_fail_clauses(left)]
    end
  end

  defp filter_fail_clauses([]) do
    []
  end

  defp bind_guard_case_clauses(
         genArgType,
         genMap,
         argExpr,
         [clause | left],
         map,
         env,
         eval,
         accType,
         accMaps,
         throws,
         state
       ) do
    pats = :cerl.clause_pats(clause)

    {newMap0, argType} =
      case pats do
        [pat] ->
          case :cerl.is_literal(pat) do
            true ->
              try do
                case :cerl.concrete(pat) do
                  true ->
                    bind_guard(argExpr, map, env, :pos, state)

                  false ->
                    bind_guard(argExpr, map, env, :neg, state)

                  _ ->
                    {genMap, genArgType}
                end
              catch
                {:fail, _} ->
                  {:none, genArgType}
              end

            false ->
              {genMap, genArgType}
          end

        _ ->
          {genMap, genArgType}
      end

    newMap1 =
      case pats === [] do
        true ->
          newMap0

        false ->
          case t_is_none(argType) do
            true ->
              :none

            false ->
              argTypes =
                case t_is_any(argType) do
                  true ->
                    any = t_any()

                    for _ <- pats do
                      any
                    end

                  false ->
                    t_to_tlist(argType)
                end

              case bind_pat_vars(pats, argTypes, newMap0, state) do
                {:error, _, _, _, _} ->
                  :none

                {patMap, _PatTypes} ->
                  patMap
              end
          end
      end

    guard = :cerl.clause_guard(clause)

    genPatType =
      :dialyzer_typesig.get_safe_underapprox(
        pats,
        guard
      )

    newGenArgType = t_subtract(genArgType, genPatType)

    case newMap1 === :none or t_is_none(genArgType) do
      true ->
        bind_guard_case_clauses(
          newGenArgType,
          genMap,
          argExpr,
          left,
          map,
          env,
          eval,
          accType,
          accMaps,
          throws,
          state
        )

      false ->
        {newAccType, newAccMaps, newThrows} =
          try do
            {newMap2, guardType} =
              bind_guard(
                guard,
                newMap1,
                env,
                :pos,
                state
              )

            case t_is_none(
                   t_inf(
                     t_atom(true),
                     guardType
                   )
                 ) do
              true ->
                throw({:fail, :none})

              false ->
                :ok
            end

            {newMap3, cType} =
              bind_guard(
                :cerl.clause_body(clause),
                newMap2,
                env,
                eval,
                state
              )

            opaques = r_state(state, :opaques)

            case eval do
              :pos ->
                case t_is_any_atom(
                       true,
                       cType,
                       opaques
                     ) do
                  true ->
                    :ok

                  false ->
                    throw({:fail, :none})
                end

              :neg ->
                case t_is_any_atom(
                       false,
                       cType,
                       opaques
                     ) do
                  true ->
                    :ok

                  false ->
                    throw({:fail, :none})
                end

              :dont_know ->
                :ok
            end

            {t_sup(accType, cType), [newMap3 | accMaps], throws}
          catch
            {:fail, reason} ->
              throws1 =
                case reason do
                  :none ->
                    throws

                  _ ->
                    throws ++ [reason]
                end

              {accType, accMaps, throws1}
          end

        bind_guard_case_clauses(
          newGenArgType,
          genMap,
          argExpr,
          left,
          map,
          env,
          eval,
          newAccType,
          newAccMaps,
          newThrows,
          state
        )
    end
  end

  defp bind_guard_case_clauses(
         _GenArgType,
         _GenMap,
         _ArgExpr,
         [],
         map,
         _Env,
         _Eval,
         accType,
         accMaps,
         throws,
         _State
       ) do
    case t_is_none(accType) do
      true ->
        case throws do
          [throw | _] ->
            throw({:fail, throw})

          [] ->
            throw({:fail, :none})
        end

      false ->
        {join_maps_end(accMaps, map), accType}
    end
  end

  defp map__new() do
    r_map()
  end

  defp join_maps_begin(r_map(modified: m, modified_stack: s, ref: ref) = map) do
    r_map(map, ref: make_ref(), modified: [], modified_stack: [{m, ref} | s])
  end

  defp join_maps_end(maps, mapOut) do
    r_map(ref: ref, modified_stack: [{m1, r1} | s]) = mapOut

    true =
      :lists.all(
        fn m ->
          r_map(m, :ref) === ref
        end,
        maps
      )

    keys0 =
      :lists.usort(
        :lists.append(
          for m <- maps do
            r_map(m, :modified)
          end
        )
      )

    r_map(map: map, subst: subst) = mapOut

    keys =
      for key <- keys0,
          :maps.is_key(key, map) or :maps.is_key(key, subst) do
        key
      end

    out =
      case maps do
        [] ->
          join_maps(maps, mapOut)

        _ ->
          join_maps(keys, maps, mapOut)
      end

    debug_join_check(maps, mapOut, out)
    r_map(out, ref: r1, modified: r_map(out, :modified) ++ m1, modified_stack: s)
  end

  defp join_maps(maps, mapOut) do
    r_map(map: map, subst: subst) = mapOut
    keys = :ordsets.from_list(:maps.keys(map) ++ :maps.keys(subst))
    join_maps(keys, maps, mapOut)
  end

  defp join_maps(keys, maps, mapOut) do
    kTs = join_maps_collect(keys, maps, mapOut)

    :lists.foldl(
      fn {k, t}, m ->
        enter_type(k, t, m)
      end,
      mapOut,
      kTs
    )
  end

  defp join_maps_collect([key | left], maps, mapOut) do
    type = join_maps_one_key(maps, key, t_none())

    case t_is_equal(lookup_type(key, mapOut), type) do
      true ->
        join_maps_collect(left, maps, mapOut)

      false ->
        [{key, type} | join_maps_collect(left, maps, mapOut)]
    end
  end

  defp join_maps_collect([], _Maps, _MapOut) do
    []
  end

  defp join_maps_one_key([map | left], key, accType) do
    case t_is_any(accType) do
      true ->
        accType

      false ->
        join_maps_one_key(left, key, t_sup(lookup_type(key, map), accType))
    end
  end

  defp join_maps_one_key([], _Key, accType) do
    accType
  end

  defp debug_join_check(_Maps, _MapOut, _Out) do
    :ok
  end

  defp enter_type_lists([key | keyTail], [val | valTail], map) do
    map1 = enter_type(key, val, map)
    enter_type_lists(keyTail, valTail, map1)
  end

  defp enter_type_lists([], [], map) do
    map
  end

  defp enter_type(key, val, mS) do
    case :cerl.is_literal(key) do
      true ->
        mS

      false ->
        case :cerl.is_c_values(key) do
          true ->
            keys = :cerl.values_es(key)

            case t_is_any(val) or t_is_none(val) do
              true ->
                enter_type_lists(
                  keys,
                  for _ <- keys do
                    val
                  end,
                  mS
                )

              false ->
                enter_type_lists(keys, t_to_tlist(val), mS)
            end

          false ->
            r_map(map: map, subst: subst) = mS
            keyLabel = get_label(key)

            case subst do
              %{^keyLabel => newKey} ->
                :ok
                enter_type(newKey, val, mS)

              %{} ->
                :ok

                case map do
                  %{^keyLabel => value} ->
                    case :erl_types.t_is_equal(val, value) do
                      true ->
                        mS

                      false ->
                        store_map(keyLabel, val, mS)
                    end

                  %{} ->
                    store_map(keyLabel, val, mS)
                end
            end
        end
    end
  end

  defp store_map(key, val, r_map(map: map, ref: :undefined) = mapRec) do
    r_map(mapRec, map: :maps.put(key, val, map))
  end

  defp store_map(key, val, r_map(map: map, modified: mod) = mapRec) do
    r_map(mapRec,
      map: Map.put(map, key, val),
      modified: [key | mod]
    )
  end

  defp enter_subst(key, val0, r_map(subst: subst) = mS) do
    keyLabel = get_label(key)
    val = :dialyzer_utils.refold_pattern(val0)

    case :cerl.is_literal(val) do
      true ->
        store_map(keyLabel, literal_type(val), mS)

      false ->
        case :cerl.is_c_var(val) do
          false ->
            mS

          true ->
            valLabel = get_label(val)

            case subst do
              %{^valLabel => newVal} ->
                enter_subst(key, newVal, mS)

              %{} ->
                cond do
                  keyLabel === valLabel ->
                    mS

                  true ->
                    :ok
                    store_subst(keyLabel, valLabel, mS)
                end
            end
        end
    end
  end

  defp store_subst(key, val, r_map(subst: s, ref: :undefined) = map) do
    r_map(map, subst: :maps.put(key, val, s))
  end

  defp store_subst(key, val, r_map(subst: s, modified: mod) = map) do
    r_map(map,
      subst: Map.put(s, key, val),
      modified: [key | mod]
    )
  end

  defp lookup_type(key, r_map(map: map, subst: subst)) do
    lookup(key, map, subst, t_none())
  end

  defp lookup(key, map, subst, anyNone) do
    case :cerl.is_literal(key) do
      true ->
        literal_type(key)

      false ->
        label = get_label(key)

        case subst do
          %{^label => newKey} ->
            lookup(newKey, map, subst, anyNone)

          %{} ->
            case map do
              %{^label => val} ->
                val

              %{} ->
                anyNone
            end
        end
    end
  end

  defp lookup_fun_sig(fun, callgraph, plt) do
    mFAorLabel =
      case :dialyzer_callgraph.lookup_name(
             fun,
             callgraph
           ) do
        :error ->
          fun

        {:ok, mFA} ->
          mFA
      end

    :dialyzer_plt.lookup(plt, mFAorLabel)
  end

  defp literal_type(lit) do
    t_from_term(:cerl.concrete(lit))
  end

  defp mark_as_fresh([tree | left], map) do
    subTrees1 = :lists.append(:cerl.subtrees(tree))

    {subTrees2, map1} =
      case :cerl.type(tree) do
        :bitstr ->
          {subTrees1 -- [:cerl.bitstr_size(tree)], map}

        :map_pair ->
          {subTrees1 -- [:cerl.map_pair_key(tree)], map}

        :var ->
          {subTrees1, enter_type(tree, t_any(), map)}

        _ ->
          {subTrees1, map}
      end

    mark_as_fresh(subTrees2 ++ left, map1)
  end

  defp mark_as_fresh([], map) do
    map
  end

  defp debug_pp_map(_Map) do
    :ok
  end

  defp get_label(l) when is_integer(l) do
    l
  end

  defp get_label(t) do
    :cerl_trees.get_label(t)
  end

  defp t_is_simple(argType, state) do
    opaques = r_state(state, :opaques)

    t_is_atom(argType, opaques) or
      t_is_number(
        argType,
        opaques
      ) or
      t_is_port(
        argType,
        opaques
      ) or
      t_is_pid(
        argType,
        opaques
      ) or
      t_is_reference(
        argType,
        opaques
      ) or
      t_is_nil(
        argType,
        opaques
      )
  end

  defp remove_local_opaque_types(type, opaques) do
    t_unopaque(type, opaques)
  end

  defp is_call_to_send(tree) do
    case :cerl.is_c_call(tree) do
      false ->
        false

      true ->
        mod = :cerl.call_module(tree)
        name = :cerl.call_name(tree)
        arity = :cerl.call_arity(tree)

        :cerl.is_c_atom(mod) and :cerl.is_c_atom(name) and is_send(:cerl.atom_val(name)) and
          :cerl.atom_val(mod) === :erlang and arity === 2
    end
  end

  defp is_send(:!) do
    true
  end

  defp is_send(:send) do
    true
  end

  defp is_send(_) do
    false
  end

  defp is_lc_simple_list(tree, treeType, state) do
    opaques = r_state(state, :opaques)
    ann = :cerl.get_ann(tree)

    :lists.member(
      :list_comprehension,
      ann
    ) and t_is_list(treeType) and
      t_is_simple(
        t_list_elements(
          treeType,
          opaques
        ),
        state
      )
  end

  defp state__new(callgraph, codeserver, tree, plt, module, records) do
    opaques = :erl_types.t_opaque_from_records(records)
    {treeMap, funHomes} = build_tree_map(tree, callgraph)
    funs = :dict.fetch_keys(treeMap)
    funTab = init_fun_tab(funs, :dict.new(), treeMap, callgraph, plt)

    exportedFunctions =
      for fun <- funs -- [:top],
          :dialyzer_callgraph.is_escaping(fun, callgraph),
          :dialyzer_callgraph.lookup_name(
            fun,
            callgraph
          ) !== :error do
        fun
      end

    work = init_work(exportedFunctions)

    env =
      :lists.foldl(
        fn fun, env ->
          :dict.store(fun, map__new(), env)
        end,
        :dict.new(),
        funs
      )

    r_state(
      callgraph: callgraph,
      codeserver: codeserver,
      envs: env,
      fun_tab: funTab,
      fun_homes: funHomes,
      opaques: opaques,
      plt: plt,
      records: records,
      warning_mode: false,
      warnings: [],
      work: work,
      tree_map: treeMap,
      module: module,
      reachable_funs: :sets.new([{:version, 2}])
    )
  end

  defp state__warning_mode(r_state(warning_mode: wM)) do
    wM
  end

  defp state__set_warning_mode(
         r_state(
           tree_map: treeMap,
           fun_tab: funTab,
           callgraph: callgraph,
           reachable_funs: reachableFuns
         ) = state
       ) do
    :ok
    funs = :dict.fetch_keys(treeMap)

    work =
      for fun <- funs -- [:top],
          :dialyzer_callgraph.lookup_name(
            fun,
            callgraph
          ) !== :error or
            :sets.is_element(
              fun,
              reachableFuns
            ) do
        fun
      end

    r_state(state, work: init_work(work), fun_tab: funTab, warning_mode: true)
  end

  defp state__renew_warnings(warnings, state) do
    r_state(state, warnings: warnings)
  end

  defp state__add_warning(state, tag, tree, msg) do
    state__add_warning(state, tag, tree, msg, false)
  end

  defp state__add_warning(r_state(warning_mode: false) = state, _, _, _, _) do
    state
  end

  defp state__add_warning(
         r_state(
           warnings: warnings,
           warning_mode: true
         ) = state,
         tag,
         tree,
         msg,
         force
       ) do
    ann = :cerl.get_ann(tree)

    case force do
      true ->
        warningInfo = {get_file(ann, state), get_location(tree), r_state(state, :curr_fun)}
        warn = {tag, warningInfo, msg}
        :ok
        r_state(state, warnings: [warn | warnings])

      false ->
        case is_compiler_generated(ann) do
          true ->
            state

          false ->
            warningInfo = {get_file(ann, state), get_location(tree), r_state(state, :curr_fun)}
            warn = {tag, warningInfo, msg}

            case tag do
              :warn_contract_range ->
                :ok

              _ ->
                :ok
            end

            r_state(state, warnings: [warn | warnings])
        end
    end
  end

  defp state__remove_added_warnings(oldState, newState) do
    r_state(warnings: oldWarnings) = oldState
    r_state(warnings: newWarnings) = newState

    case newWarnings === oldWarnings do
      true ->
        {[], newState}

      false ->
        {newWarnings -- oldWarnings, r_state(newState, warnings: oldWarnings)}
    end
  end

  defp state__add_warnings(warns, r_state(warnings: warnings) = state) do
    r_state(state, warnings: warns ++ warnings)
  end

  defp state__set_curr_fun(:undefined, state) do
    r_state(state, curr_fun: :undefined)
  end

  defp state__set_curr_fun(funLbl, state) do
    r_state(state, curr_fun: find_function(funLbl, state))
  end

  defp state__get_warnings(
         r_state(
           tree_map: treeMap,
           fun_tab: funTab,
           callgraph: callgraph,
           plt: plt,
           reachable_funs: reachableFuns
         ) = state
       ) do
    foldFun = fn
      {:top, _}, accState ->
        accState

      {funLbl, fun}, accState ->
        accState1 = state__set_curr_fun(funLbl, accState)

        {notCalled, ret} =
          case :dict.fetch(
                 get_label(fun),
                 funTab
               ) do
            {:not_handled, {_Args0, ret0}} ->
              {true, ret0}

            {_Args0, ret0} ->
              {false, ret0}
          end

        case notCalled do
          true ->
            case :dialyzer_callgraph.lookup_name(
                   funLbl,
                   callgraph
                 ) do
              :error ->
                accState1

              {:ok, {_M, f, a}} ->
                msg = {:unused_fun, [f, a]}
                state__add_warning(accState1, :warn_not_called, fun, msg)
            end

          false ->
            {name, contract} =
              case :dialyzer_callgraph.lookup_name(
                     funLbl,
                     callgraph
                   ) do
                :error ->
                  {[], :none}

                {:ok, {_M, f, a} = mFA} ->
                  {[f, a],
                   :dialyzer_plt.lookup_contract(
                     plt,
                     mFA
                   )}
              end

            case t_is_none(ret) do
              true ->
                warn =
                  case contract do
                    :none ->
                      not parent_allows_this(funLbl, accState1)

                    {:value, c} ->
                      genRet = :dialyzer_contracts.get_contract_return(c)
                      not t_is_unit(genRet)
                  end

                case warn and
                       (:dialyzer_callgraph.lookup_name(
                          funLbl,
                          callgraph
                        ) !== :error or
                          :sets.is_element(
                            funLbl,
                            reachableFuns
                          )) do
                  true ->
                    case classify_returns(fun) do
                      :no_match ->
                        msg = {:no_return, [:no_match | name]}
                        state__add_warning(accState1, :warn_return_no_exit, fun, msg)

                      :only_explicit ->
                        msg = {:no_return, [:only_explicit | name]}
                        state__add_warning(accState1, :warn_return_only_exit, fun, msg)

                      :only_normal ->
                        msg = {:no_return, [:only_normal | name]}
                        state__add_warning(accState1, :warn_return_no_exit, fun, msg)

                      :both ->
                        msg = {:no_return, [:both | name]}
                        state__add_warning(accState1, :warn_return_no_exit, fun, msg)
                    end

                  false ->
                    accState
                end

              false ->
                accState
            end
        end
    end

    r_state(warnings: warn) = :lists.foldl(foldFun, state, :dict.to_list(treeMap))
    warn
  end

  defp state__is_escaping(fun, r_state(callgraph: callgraph)) do
    :dialyzer_callgraph.is_escaping(fun, callgraph)
  end

  defp state__lookup_type_for_letrec(var, r_state(callgraph: callgraph) = state) do
    label = get_label(var)

    case :dialyzer_callgraph.lookup_letrec(
           label,
           callgraph
         ) do
      :error ->
        :error

      {:ok, funLabel} ->
        {:ok, state__fun_type(funLabel, state)}
    end
  end

  defp state__lookup_name({_, _, _} = mFA, r_state()) do
    mFA
  end

  defp state__lookup_name(:top, r_state()) do
    :top
  end

  defp state__lookup_name(fun, r_state(callgraph: callgraph)) do
    case :dialyzer_callgraph.lookup_name(
           fun,
           callgraph
         ) do
      {:ok, mFA} ->
        mFA

      :error ->
        fun
    end
  end

  defp state__lookup_record(tag, arity, r_state(records: records)) do
    case :erl_types.lookup_record(tag, arity, records) do
      {:ok, fields} ->
        recType =
          t_tuple([
            t_atom(tag)
            | for {_FieldName, _Abstr, fieldType} <- fields do
                fieldType
              end
          ])

        fieldNames =
          for {fieldName, _Abstr, _FieldType} <- fields do
            fieldName
          end

        {:ok, recType, fieldNames}

      :error ->
        :error
    end
  end

  defp state__get_args_and_status(tree, r_state(fun_tab: funTab)) do
    fun = get_label(tree)

    case :dict.find(fun, funTab) do
      {:ok, {:not_handled, {argTypes, _}}} ->
        {argTypes, false}

      {:ok, {argTypes, _}} ->
        {argTypes, true}
    end
  end

  defp state__add_reachable(
         funLbl,
         r_state(reachable_funs: reachableFuns) = state
       ) do
    newReachableFuns =
      :sets.add_element(
        funLbl,
        reachableFuns
      )

    r_state(state, reachable_funs: newReachableFuns)
  end

  defp build_tree_map(tree, callgraph) do
    fun = fn t, {dict, homes, funLbls} = acc ->
      case :cerl.is_c_fun(t) do
        true ->
          funLbl = get_label(t)
          dict1 = :dict.store(funLbl, t, dict)

          case (try do
                  :dialyzer_callgraph.lookup_name(funLbl, callgraph)
                catch
                  :error, e -> {:EXIT, {e, __STACKTRACE__}}
                  :exit, e -> {:EXIT, e}
                  e -> e
                end) do
            {:ok, mFA} ->
              f2 = fn lbl, dict0 ->
                :dict.store(lbl, mFA, dict0)
              end

              homes1 = :lists.foldl(f2, homes, [funLbl | funLbls])
              {dict1, homes1, []}

            _ ->
              {dict1, homes, [funLbl | funLbls]}
          end

        false ->
          acc
      end
    end

    dict0 = :dict.new()
    {dict, homes, _} = :cerl_trees.fold(fun, {dict0, dict0, []}, tree)
    {dict, homes}
  end

  defp init_fun_tab([:top | left], dict, treeMap, callgraph, plt) do
    newDict = :dict.store(:top, {[], t_none()}, dict)
    init_fun_tab(left, newDict, treeMap, callgraph, plt)
  end

  defp init_fun_tab([fun | left], dict, treeMap, callgraph, plt) do
    arity = :cerl.fun_arity(:dict.fetch(fun, treeMap))

    funEntry =
      case :dialyzer_callgraph.is_escaping(
             fun,
             callgraph
           ) do
        true ->
          args = :lists.duplicate(arity, t_any())

          case lookup_fun_sig(fun, callgraph, plt) do
            :none ->
              {args, t_unit()}

            {:value, {retType, _}} ->
              case t_is_none(retType) do
                true ->
                  {args, t_none()}

                false ->
                  {args, t_unit()}
              end
          end

        false ->
          {:not_handled, {:lists.duplicate(arity, t_none()), t_unit()}}
      end

    newDict = :dict.store(fun, funEntry, dict)
    init_fun_tab(left, newDict, treeMap, callgraph, plt)
  end

  defp init_fun_tab([], dict, _TreeMap, _Callgraph, _Plt) do
    :ok
    dict
  end

  defp state__update_fun_env(tree, map, r_state(envs: envs) = state) do
    newEnvs = :dict.store(get_label(tree), map, envs)
    r_state(state, envs: newEnvs)
  end

  defp state__fun_env(tree, r_state(envs: envs)) do
    fun = get_label(tree)

    case :dict.find(fun, envs) do
      :error ->
        :none

      {:ok, map} ->
        map
    end
  end

  defp state__clean_not_called(r_state(fun_tab: funTab) = state) do
    newFunTab =
      :dict.map(
        fn
          :top, entry ->
            entry

          _Fun, {:not_handled, {args, _}} ->
            {args, t_none()}

          _Fun, entry ->
            entry
        end,
        funTab
      )

    r_state(state, fun_tab: newFunTab)
  end

  defp state__all_fun_types(state) do
    r_state(fun_tab: funTab) = state__clean_not_called(state)
    tab1 = :dict.erase(:top, funTab)

    list =
      for {fun, {args, ret}} <- :dict.to_list(tab1) do
        {fun, t_fun(args, ret)}
      end

    :orddict.from_list(list)
  end

  defp state__fun_type(fun, r_state(fun_tab: funTab)) do
    label =
      cond do
        is_integer(fun) ->
          fun

        true ->
          get_label(fun)
      end

    entry = :dict.find(label, funTab)
    :ok

    case entry do
      {:ok, {:not_handled, {a, r}}} ->
        t_fun(a, r)

      {:ok, {a, r}} ->
        t_fun(a, r)
    end
  end

  defp state__update_fun_entry(
         tree,
         argTypes,
         out0,
         r_state(fun_tab: funTab, callgraph: cG, plt: plt) = state
       ) do
    fun = get_label(tree)

    out1 =
      cond do
        fun === :top ->
          out0

        true ->
          case lookup_fun_sig(fun, cG, plt) do
            {:value, {sigRet, _}} ->
              t_inf(sigRet, out0)

            :none ->
              out0
          end
      end

    out = t_limit(out1, 3)
    {:ok, {oldArgTypes, oldOut}} = :dict.find(fun, funTab)

    sameArgs =
      :lists.all(
        fn {a, b} ->
          :erl_types.t_is_equal(a, b)
        end,
        :lists.zip(oldArgTypes, argTypes)
      )

    sameOut = t_is_equal(oldOut, out)

    cond do
      sameArgs and sameOut ->
        :ok
        state

      true ->
        newEntry = {oldArgTypes, out}
        :ok
        newFunTab = :dict.store(fun, newEntry, funTab)
        state1 = r_state(state, fun_tab: newFunTab)
        state__add_work_from_fun(tree, state1)
    end
  end

  defp state__add_work_from_fun(_Tree, r_state(warning_mode: true) = state) do
    state
  end

  defp state__add_work_from_fun(
         tree,
         r_state(callgraph: callgraph, tree_map: treeMap) = state
       ) do
    case get_label(tree) do
      :top ->
        state

      label when is_integer(label) ->
        case :dialyzer_callgraph.in_neighbours(
               label,
               callgraph
             ) do
          :none ->
            state

          mFAList ->
            labelList =
              for mFA <- mFAList do
                :dialyzer_callgraph.lookup_label(mFA, callgraph)
              end

            filteredList =
              for {:ok, l} <- labelList,
                  :dict.is_key(l, treeMap) do
                l
              end

            :ok

            :lists.foldl(
              fn l, accState ->
                state__add_work(l, accState)
              end,
              state,
              filteredList
            )
        end
    end
  end

  defp state__add_work(:external, state) do
    state
  end

  defp state__add_work(:top, state) do
    state
  end

  defp state__add_work(fun, r_state(work: work) = state) do
    newWork = add_work(fun, work)
    r_state(state, work: newWork)
  end

  defp state__get_work(r_state(work: work, tree_map: treeMap) = state) do
    case get_work(work) do
      :none ->
        :none

      {fun, newWork} ->
        {:dict.fetch(fun, treeMap), r_state(state, work: newWork)}
    end
  end

  defp state__lookup_call_site(tree, r_state(callgraph: callgraph)) do
    label = get_label(tree)
    :dialyzer_callgraph.lookup_call_site(label, callgraph)
  end

  defp state__fun_info(:external, r_state()) do
    :external
  end

  defp state__fun_info({_, _, _} = mFA, r_state(plt: pLT)) do
    {mFA, :dialyzer_plt.lookup(pLT, mFA), :dialyzer_plt.lookup_contract(pLT, mFA), t_any()}
  end

  defp state__fun_info(
         fun,
         r_state(callgraph: cG, fun_tab: funTab, plt: pLT)
       ) do
    {sig, contract} =
      case :dialyzer_callgraph.lookup_name(
             fun,
             cG
           ) do
        :error ->
          {:dialyzer_plt.lookup(pLT, fun), :none}

        {:ok, mFA} ->
          {:dialyzer_plt.lookup(pLT, mFA), :dialyzer_plt.lookup_contract(pLT, mFA)}
      end

    localRet =
      case :dict.fetch(fun, funTab) do
        {:not_handled, {_Args, ret}} ->
          ret

        {_Args, ret} ->
          ret
      end

    :ok
    {fun, sig, contract, localRet}
  end

  defp forward_args(fun, argTypes, r_state(work: work, fun_tab: funTab) = state) do
    {newArgTypes, oldOut, fixpoint} =
      case :dict.find(
             fun,
             funTab
           ) do
        {:ok, {:not_handled, {_OldArgTypesAreNone, oldOut0}}} ->
          {argTypes, oldOut0, false}

        {:ok, {oldArgTypes0, oldOut0}} ->
          newArgTypes0 =
            for {x, y} <-
                  :lists.zip(
                    argTypes,
                    oldArgTypes0
                  ) do
              t_sup(x, y)
            end

          {newArgTypes0, oldOut0,
           t_is_equal(
             t_product(newArgTypes0),
             t_product(oldArgTypes0)
           )}
      end

    case fixpoint do
      true ->
        state

      false ->
        newWork = add_work(fun, work)
        :ok
        newFunTab = :dict.store(fun, {newArgTypes, oldOut}, funTab)
        r_state(state, work: newWork, fun_tab: newFunTab)
    end
  end

  defp state__translate_file(fakeFile, state) do
    r_state(codeserver: codeServer, module: module) = state
    :dialyzer_codeserver.translate_fake_file(codeServer, module, fakeFile)
  end

  defp init_work(list) do
    {list, [], :sets.from_list(list, [{:version, 2}])}
  end

  defp get_work({[], [], _Set}) do
    :none
  end

  defp get_work({[h | t], rev, set}) do
    {h, {t, rev, :sets.del_element(h, set)}}
  end

  defp get_work({[], rev, set}) do
    get_work({:lists.reverse(rev), [], set})
  end

  defp add_work(new, {list, rev, set} = work) do
    case :sets.is_element(new, set) do
      true ->
        work

      false ->
        {list, [new | rev], :sets.add_element(new, set)}
    end
  end

  defp get_location(tree) do
    :dialyzer_utils.get_location(tree, 1)
  end

  defp select_arg([], _Args, tree) do
    tree
  end

  defp select_arg([argN | _], args, _Tree) do
    :lists.nth(argN, args)
  end

  defp get_file([], _State) do
    []
  end

  defp get_file([{:file, fakeFile} | _], state) do
    state__translate_file(fakeFile, state)
  end

  defp get_file([_ | tail], state) do
    get_file(tail, state)
  end

  defp is_compiler_generated(ann) do
    :dialyzer_utils.is_compiler_generated(ann)
  end

  defp is_literal_record(tree) do
    ann = :cerl.get_ann(tree)
    :lists.member(:record, ann)
  end

  def format_args([], [], _State) do
    ~c"()"
  end

  def format_args(argList0, typeList, state) do
    argList = fold_literals(argList0)
    ~c"(" ++ format_args_1(argList, typeList, state) ++ ~c")"
  end

  defp format_args_1([arg], [type], state) do
    format_arg_1(arg, type, state)
  end

  defp format_args_1([arg | args], [type | types], state) do
    format_arg_1(arg, type, state) ++ ~c"," ++ format_args_1(args, types, state)
  end

  defp format_arg_1(arg, type, state) do
    case :cerl.is_literal(arg) do
      true ->
        format_cerl(arg)

      false ->
        format_arg(arg) ++ format_type(type, state)
    end
  end

  defp format_arg(arg) do
    default = ~c""

    case :cerl.is_c_var(arg) do
      true ->
        case :cerl.var_name(arg) do
          atom when is_atom(atom) ->
            case :erlang.atom_to_list(atom) do
              ~c"@" ++ _ ->
                default

              ~c"cor" ++ _ ->
                default

              ~c"rec" ++ _ ->
                default

              name ->
                name ++ ~c"::"
            end

          _What ->
            default
        end

      false ->
        default
    end
  end

  defp format_type(type, r_state(records: r)) do
    t_to_string(type, r)
  end

  defp format_field_diffs(recConstruction, r_state(records: r)) do
    :erl_types.record_field_diffs_to_string(
      recConstruction,
      r
    )
  end

  defp format_sig_args(type, r_state(opaques: opaques) = state) do
    sigArgs = t_fun_args(type, opaques)

    case sigArgs do
      [] ->
        ~c"()"

      [sArg | sArgs] ->
        :lists.flatten(
          ~c"(" ++
            format_type(
              sArg,
              state
            ) ++
            for t <- sArgs do
              ~c"," ++
                format_type(
                  t,
                  state
                )
            end ++ ~c")"
        )
    end
  end

  defp format_cerl(tree) do
    :cerl_prettypr.format(
      :cerl.set_ann(tree, []),
      [{:hook, :dialyzer_utils.pp_hook()}, {:noann, true}, {:paper, 100_000}, {:ribbon, 100_000}]
    )
  end

  defp format_patterns(pats0) do
    pats = fold_literals(pats0)
    newPats = map_pats(:cerl.c_values(pats))
    string = format_cerl(newPats)

    case pats do
      [posVar] ->
        case :cerl.is_c_var(posVar) and :cerl.var_name(posVar) !== :"" do
          true ->
            ~c"variable " ++ string

          false ->
            ~c"pattern " ++ string
        end

      _ ->
        ~c"pattern " ++ string
    end
  end

  defp map_pats(pats) do
    fun = fn tree ->
      case :cerl.is_c_var(tree) do
        true ->
          case :cerl.var_name(tree) do
            atom when is_atom(atom) ->
              case :erlang.atom_to_list(atom) do
                ~c"@" ++ _ ->
                  :cerl.c_var(:"")

                ~c"cor" ++ _ ->
                  :cerl.c_var(:"")

                ~c"rec" ++ _ ->
                  :cerl.c_var(:"")

                _ ->
                  :cerl.set_ann(tree, [])
              end

            _What ->
              :cerl.c_var(:"")
          end

        false ->
          :cerl.set_ann(tree, [])
      end
    end

    :cerl_trees.map(fun, pats)
  end

  defp fold_literals(treeList) do
    for tree <- treeList do
      :cerl.fold_literal(tree)
    end
  end

  defp format_atom(a) do
    format_cerl(:cerl.c_atom(a))
  end

  defp type(tree) do
    folded = :cerl.fold_literal(tree)

    case :cerl.type(folded) do
      :literal ->
        {:literal, folded}

      type ->
        type
    end
  end

  defp is_literal(tree) do
    folded = :cerl.fold_literal(tree)

    case :cerl.is_literal(folded) do
      true ->
        {:yes, folded}

      false ->
        :no
    end
  end

  defp parent_allows_this(
         funLbl,
         r_state(callgraph: callgraph, plt: plt) = state
       ) do
    case state__is_escaping(funLbl, state) do
      false ->
        false

      true ->
        case state__lookup_name(funLbl, state) do
          {_M, _F, _A} ->
            false

          _ ->
            case :dialyzer_callgraph.in_neighbours(
                   funLbl,
                   callgraph
                 ) do
              [parent] ->
                case state__lookup_name(parent, state) do
                  {_M, _F, _A} = pMFA ->
                    case :dialyzer_plt.lookup_contract(plt, pMFA) do
                      :none ->
                        false

                      {:value, c} ->
                        genRet = :dialyzer_contracts.get_contract_return(c)

                        case :erl_types.t_is_fun(genRet) do
                          false ->
                            false

                          true ->
                            t_is_unit(t_fun_range(genRet))
                        end
                    end

                  _ ->
                    false
                end

              _ ->
                false
            end
        end
    end
  end

  defp find_function({_, _, _} = mFA, _State) do
    mFA
  end

  defp find_function(:top, _State) do
    :top
  end

  defp find_function(funLbl, r_state(fun_homes: homes)) do
    :dict.fetch(funLbl, homes)
  end

  defp classify_returns(tree) do
    case find_terminals(:cerl.fun_body(tree)) do
      {false, false} ->
        :no_match

      {true, false} ->
        :only_explicit

      {false, true} ->
        :only_normal

      {true, true} ->
        :both
    end
  end

  defp find_terminals(tree) do
    case :cerl.type(tree) do
      :apply ->
        {false, true}

      :binary ->
        {false, true}

      :bitstr ->
        {false, true}

      :call ->
        m0 = :cerl.call_module(tree)
        f0 = :cerl.call_name(tree)
        a = length(:cerl.call_args(tree))

        case {is_literal(m0), is_literal(f0)} do
          {{:yes, litM}, {:yes, litF}} ->
            m = :cerl.concrete(litM)
            f = :cerl.concrete(litF)

            case :erl_bif_types.is_known(m, f, a) and
                   t_is_none(
                     :erl_bif_types.type(
                       m,
                       f,
                       a
                     )
                   ) do
              true ->
                {true, false}

              false ->
                {false, true}
            end

          _ ->
            {true, true}
        end

      :case ->
        case :cerl.case_clauses(tree) do
          [] ->
            case :lists.member(
                   :receive_timeout,
                   :cerl.get_ann(tree)
                 ) do
              true ->
                {false, true}

              false ->
                {false, false}
            end

          [_ | _] ->
            find_terminals_list(:cerl.case_clauses(tree))
        end

      :catch ->
        find_terminals(:cerl.catch_body(tree))

      :clause ->
        find_terminals(:cerl.clause_body(tree))

      :cons ->
        {false, true}

      :fun ->
        {false, true}

      :let ->
        find_terminals(:cerl.let_body(tree))

      :letrec ->
        find_terminals(:cerl.letrec_body(tree))

      :literal ->
        {false, true}

      :map ->
        {false, true}

      :primop ->
        {false, false}

      :receive ->
        timeout = :cerl.receive_timeout(tree)
        clauses = :cerl.receive_clauses(tree)

        case :cerl.is_literal(timeout) and :cerl.concrete(timeout) === :infinity do
          true ->
            cond do
              clauses === [] ->
                {false, true}

              true ->
                find_terminals_list(clauses)
            end

          false ->
            find_terminals_list([
              :cerl.receive_action(tree)
              | clauses
            ])
        end

      :seq ->
        find_terminals(:cerl.seq_body(tree))

      :try ->
        find_terminals_list([:cerl.try_handler(tree), :cerl.try_body(tree)])

      :tuple ->
        {false, true}

      :values ->
        {false, true}

      :var ->
        {false, true}
    end
  end

  defp find_terminals_list(list) do
    find_terminals_list(list, false, false)
  end

  defp find_terminals_list([tree | left], explicit1, normal1) do
    {explicit2, normal2} = find_terminals(tree)

    case {:erlang.or(explicit1, explicit2), :erlang.or(normal1, normal2)} do
      {true, true} = ans ->
        ans

      {newExplicit, newNormal} ->
        find_terminals_list(left, newExplicit, newNormal)
    end
  end

  defp find_terminals_list([], explicit, normal) do
    {explicit, normal}
  end

  defp debug_pp(_Tree, _UseHook) do
    :ok
  end
end
