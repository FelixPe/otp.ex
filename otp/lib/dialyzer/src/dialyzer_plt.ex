defmodule :m_dialyzer_plt do
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
  def new() do
    [eTSInfo, eTSContracts] = (for name <- [:plt_info,
                                                :plt_contracts] do
                                 :ets.new(name, [:public])
                               end)
    [eTSTypes, eTSCallbacks,
                   eTSExpTypes] = (for name <- [:plt_types, :plt_callbacks,
                                                                :plt_exported_types] do
                                     :ets.new(name, [:compressed, :public])
                                   end)
    r_plt(info: eTSInfo, types: eTSTypes,
        contracts: eTSContracts, callbacks: eTSCallbacks,
        exported_types: eTSExpTypes)
  end

  def delete_module(r_plt(info: info, types: types, contracts: contracts,
             callbacks: callbacks, exported_types: expTypes),
           mod) do
    r_plt(info: table_delete_module(info, mod),
        types: table_delete_module2(types, mod),
        contracts: table_delete_module(contracts, mod),
        callbacks: table_delete_module2(callbacks, mod),
        exported_types: table_delete_module1(expTypes, mod))
  end

  def delete_list(r_plt(info: info, contracts: contracts) = plt,
           list) do
    r_plt(plt, info: ets_table_delete_list(info, list), 
             contracts: ets_table_delete_list(contracts, list))
  end

  def insert_contract_list(r_plt(contracts: contracts) = pLT, list) do
    true = :ets.insert(contracts, list)
    pLT
  end

  def insert_callbacks(r_plt(callbacks: callbacks) = plt, codeserver) do
    callbacksList = :dialyzer_codeserver.get_callbacks(codeserver)
    callbacksByModule = (for m <- :lists.usort(for {{m, _,
                                                       _},
                                                      _} <- callbacksList do
                                                 m
                                               end) do
                           {m,
                              for ({{m1, _, _}, _} = cb) <- callbacksList,
                                    m1 === m do
                                cb
                              end}
                         end)
    true = :ets.insert(callbacks, callbacksByModule)
    plt
  end

  def is_contract(r_plt(contracts: eTSContracts), {m, f, _} = mFA)
      when (is_atom(m) and is_atom(f)) do
    :ets.member(eTSContracts, mFA)
  end

  def lookup_contract(r_plt(contracts: eTSContracts), {m, f, _} = mFA)
      when (is_atom(m) and is_atom(f)) do
    ets_table_lookup(eTSContracts, mFA)
  end

  def lookup_callbacks(r_plt(callbacks: eTSCallbacks), mod)
      when is_atom(mod) do
    ets_table_lookup(eTSCallbacks, mod)
  end

  def insert_list(r_plt(info: info) = pLT, list) do
    true = :ets.insert(info, list)
    pLT
  end

  def lookup(plt, {m, f, _} = mFA) when (is_atom(m) and
                                       is_atom(f)) do
    lookup_1(plt, mFA)
  end

  def lookup(plt, label) when is_integer(label) do
    lookup_1(plt, label)
  end

  defp lookup_1(r_plt(info: info), mFAorLabel) do
    ets_table_lookup(info, mFAorLabel)
  end

  def insert_types(pLT, records) do
    :ok = :dialyzer_utils.ets_move(records, r_plt(pLT, :types))
    pLT
  end

  def insert_exported_types(pLT, expTypes) do
    :ok = :dialyzer_utils.ets_move(expTypes,
                                     r_plt(pLT, :exported_types))
    pLT
  end

  def get_module_types(r_plt(types: types), m) when is_atom(m) do
    ets_table_lookup(types, m)
  end

  def get_exported_types(r_plt(exported_types: eTSExpTypes)) do
    :sets.from_list(for {e} <- table_to_list(eTSExpTypes) do
                      e
                    end)
  end

  def lookup_module(r_plt(info: info), m) when is_atom(m) do
    table_lookup_module(info, m)
  end

  def all_modules(r_plt(info: info, contracts: cs)) do
    :sets.union(table_all_modules(info),
                  table_all_modules(cs))
  end

  def contains_mfa(r_plt(info: info, contracts: contracts), mFA) do
    :ets.member(info, mFA) or :ets.member(contracts, mFA)
  end

  def merge_plts(list) do
    {infoList, typesList, expTypesList, contractsList,
       callbacksList} = group_fields(list)
    r_plt(info: table_merge(infoList),
        types: table_merge(typesList),
        exported_types: sets_merge(expTypesList),
        contracts: table_merge(contractsList),
        callbacks: table_merge(callbacksList))
  end

  defp group_fields(list) do
    infoList = (for r_plt(info: info) <- list do
                  info
                end)
    typesList = (for r_plt(types: types) <- list do
                   types
                 end)
    expTypesList = (for r_plt(exported_types: expTypes) <- list do
                      expTypes
                    end)
    contractsList = (for r_plt(contracts: contracts) <- list do
                       contracts
                     end)
    callbacksList = (for r_plt(callbacks: callbacks) <- list do
                       callbacks
                     end)
    {infoList, typesList, expTypesList, contractsList,
       callbacksList}
  end

  def delete(r_plt(info: eTSInfo, types: eTSTypes,
             contracts: eTSContracts, callbacks: eTSCallbacks,
             exported_types: eTSExpTypes)) do
    true = :ets.delete(eTSContracts)
    true = :ets.delete(eTSTypes)
    true = :ets.delete(eTSInfo)
    true = :ets.delete(eTSCallbacks)
    true = :ets.delete(eTSExpTypes)
    :ok
  end

  def get_specs(r_plt(info: info)) do
    l = :lists.sort(for {{_, _, _} = mFA,
                           val} <- table_to_list(info) do
                      {mFA, val}
                    end)
    :lists.flatten(create_specs(l, []))
  end

  def get_specs(r_plt(info: info), m, f, a) when (is_atom(m) and
                                         is_atom(f)) do
    mFA = {m, f, a}
    case (ets_table_lookup(info, mFA)) do
      :none ->
        :none
      {:value, val} ->
        :lists.flatten(create_specs([{mFA, val}], []))
    end
  end

  defp create_specs([{{m, f, _A}, {ret, args}} | left], m) do
    [:io_lib.format('-spec ~tw(~ts) -> ~ts\n',
                      [f, expand_args(args), :erl_types.t_to_string(ret)]) |
         create_specs(left, m)]
  end

  defp create_specs(list = [{{m, _F, _A}, {_Ret, _Args}} | _],
            _M) do
    [:io_lib.format('\n\n%% ------- Module: ~w -------\n\n', [m]) | create_specs(list, m)]
  end

  defp create_specs([], _) do
    []
  end

  defp expand_args([]) do
    []
  end

  defp expand_args([argType]) do
    case (:erl_types.t_is_any(argType)) do
      true ->
        ['_']
      false ->
        [:erl_types.t_to_string(argType)]
    end
  end

  defp expand_args([argType | left]) do
    [(case (:erl_types.t_is_any(argType)) do
        true ->
          '_'
        false ->
          :erl_types.t_to_string(argType)
      end) ++ ',' |
         expand_args(left)]
  end

  defp table_to_list(plt) do
    :ets.tab2list(plt)
  end

  defp table_delete_module(tab, mod) do
    mS = :ets.fun2ms(fn {{m, _F, _A}, _Val} ->
                          m === mod
                        {_, _} ->
                          false
                     end)
    _NumDeleted = :ets.select_delete(tab, mS)
    tab
  end

  defp table_delete_module1(tab, mod) do
    mS = :ets.fun2ms(fn {{m, _F, _A}} ->
                          m === mod
                     end)
    _NumDeleted = :ets.select_delete(tab, mS)
    tab
  end

  defp table_delete_module2(tab, mod) do
    true = :ets.delete(tab, mod)
    tab
  end

  defp ets_table_delete_list(tab, [h | t]) do
    :ets.delete(tab, h)
    ets_table_delete_list(tab, t)
  end

  defp ets_table_delete_list(tab, []) do
    tab
  end

  defp ets_table_lookup(plt, obj) do
    try do
      :ets.lookup_element(plt, obj, 2)
    catch
      _, _ ->
        :none
    else
      val ->
        {:value, val}
    end
  end

  defp table_lookup_module(tab, mod) do
    mS = :ets.fun2ms(fn {{m, f, a}, v} when m === mod ->
                          {{m, f, a}, v}
                     end)
    list = (for {mFA, v} <- :ets.select(tab, mS) do
              (
                {v1, v2} = v
                {mFA, v1, v2}
              )
            end)
    case (list === []) do
      true ->
        :none
      false ->
        {:value, list}
    end
  end

  defp table_all_modules(tab) do
    ks = :ets.match(tab, {:"$1", :_}, 100)
    all_mods(ks, :sets.new())
  end

  defp all_mods(:"$end_of_table", s) do
    s
  end

  defp all_mods({listsOfKeys, cont}, s) do
    s1 = :lists.foldl(fn [{m, _F, _A}], s0 ->
                           :sets.add_element(m, s0)
                      end,
                        s, listsOfKeys)
    all_mods(:ets.match(cont), s1)
  end

  defp table_merge([h | t]) do
    table_merge(t, h)
  end

  defp table_merge([], acc) do
    acc
  end

  defp table_merge([plt | plts], acc) do
    newAcc = merge_tables(plt, acc)
    table_merge(plts, newAcc)
  end

  defp sets_merge([h | t]) do
    sets_merge(t, h)
  end

  defp sets_merge([], acc) do
    acc
  end

  defp sets_merge([plt | plts], acc) do
    newAcc = merge_tables(plt, acc)
    sets_merge(plts, newAcc)
  end

  defp merge_tables(t1, t2) do
    tab_merge(:ets.first(t1), t1, t2)
  end

  defp tab_merge(:"$end_of_table", t1, t2) do
    case (:ets.first(t1)) do
      :"$end_of_table" ->
        true = :ets.delete(t1)
        t2
      key ->
        tab_merge(key, t1, t2)
    end
  end

  defp tab_merge(k1, t1, t2) do
    vs = :ets.lookup(t1, k1)
    nextK1 = :ets.next(t1, k1)
    true = :ets.delete(t1, k1)
    true = :ets.insert(t2, vs)
    tab_merge(nextK1, t1, t2)
  end

  def get_all_contracts(r_plt(contracts: eTSContracts)) do
    :maps.from_list(:ets.tab2list(eTSContracts))
  end

  def get_all_types(r_plt(types: eTSTypes)) do
    types = :ets.tab2list(eTSTypes)
    :maps.from_list(types)
  end

  def plt_kind(fileName) do
    case (:filelib.is_regular(fileName)) do
      true ->
        case (:dialyzer_iplt.is_iplt(fileName)) do
          true ->
            :iplt
          false ->
            case (:dialyzer_cplt.is_cplt(fileName)) do
              true ->
                :cplt
              false ->
                :bad_file
            end
        end
      false ->
        :no_file
    end
  end

end