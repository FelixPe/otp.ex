defmodule :m_dialyzer_callgraph do
  use Bitwise
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

  Record.defrecord(:r_callgraph, :callgraph,
    digraph: :digraph.new(),
    active_digraph: :undefined,
    esc: :undefined,
    letrec_map: :undefined,
    name_map: :undefined,
    rev_name_map: :undefined,
    rec_var_map: :undefined,
    self_rec: :undefined,
    calls: :undefined
  )

  def new() do
    [eTSEsc, eTSNameMap, eTSRevNameMap, eTSRecVarMap, eTSLetrecMap, eTSSelfRec, eTSCalls] =
      for n <- [
            :callgraph_esc,
            :callgraph_name_map,
            :callgraph_rev_name_map,
            :callgraph_rec_var_map,
            :callgraph_letrec_map,
            :callgraph_self_rec,
            :callgraph_calls
          ] do
        :ets.new(
          n,
          [:public, {:read_concurrency, true}]
        )
      end

    r_callgraph(
      esc: eTSEsc,
      letrec_map: eTSLetrecMap,
      name_map: eTSNameMap,
      rev_name_map: eTSRevNameMap,
      rec_var_map: eTSRecVarMap,
      self_rec: eTSSelfRec,
      calls: eTSCalls
    )
  end

  def delete(r_callgraph(digraph: digraph)) do
    digraph_delete(digraph)
  end

  def all_nodes(r_callgraph(digraph: dG)) do
    digraph_vertices(dG)
  end

  def lookup_rec_var(label, r_callgraph(rec_var_map: recVarMap))
      when is_integer(label) do
    ets_lookup_dict(label, recVarMap)
  end

  def lookup_letrec(label, r_callgraph(letrec_map: letrecMap))
      when is_integer(label) do
    ets_lookup_dict(label, letrecMap)
  end

  def lookup_call_site(label, r_callgraph(calls: calls)) when is_integer(label) do
    ets_lookup_dict(label, calls)
  end

  def lookup_name(label, r_callgraph(name_map: nameMap))
      when is_integer(label) do
    ets_lookup_dict(label, nameMap)
  end

  def lookup_label({_, _, _} = mFA, r_callgraph(rev_name_map: revNameMap)) do
    ets_lookup_dict(mFA, revNameMap)
  end

  def lookup_label(label, r_callgraph()) when is_integer(label) do
    {:ok, label}
  end

  def in_neighbours(label, r_callgraph(digraph: digraph) = cG)
      when is_integer(label) do
    name =
      case lookup_name(label, cG) do
        {:ok, val} ->
          val

        :error ->
          label
      end

    digraph_in_neighbours(name, digraph)
  end

  def in_neighbours({_, _, _} = mFA, r_callgraph(digraph: digraph)) do
    digraph_in_neighbours(mFA, digraph)
  end

  def is_self_rec(mfaOrLabel, r_callgraph(self_rec: selfRecs)) do
    ets_lookup_set(mfaOrLabel, selfRecs)
  end

  def is_escaping(label, r_callgraph(esc: esc)) when is_integer(label) do
    ets_lookup_set(label, esc)
  end

  def add_edges([], _CG) do
    :ok
  end

  def add_edges(edges, r_callgraph(digraph: digraph)) do
    digraph_add_edges(edges, digraph)
  end

  def add_edges(edges, mFAs, r_callgraph(digraph: dG) = cG) do
    digraph_confirm_vertices(mFAs, dG)
    add_edges(edges, cG)
  end

  def remove_external(r_callgraph(digraph: dG) = cG) do
    {^dG, external} = digraph_remove_external(dG)
    {cG, external}
  end

  def non_local_calls(r_callgraph(digraph: dG)) do
    edges = digraph_edges(dG)
    find_non_local_calls(edges, :sets.new([{:version, 2}]))
  end

  defp find_non_local_calls([{{m, _, _}, {m, _, _}} | left], set) do
    find_non_local_calls(left, set)
  end

  defp find_non_local_calls([{{m1, _, _}, {m2, _, _}} = edge | left], set)
       when m1 !== m2 do
    find_non_local_calls(left, :sets.add_element(edge, set))
  end

  defp find_non_local_calls([{{_, _, _}, label} | left], set)
       when is_integer(label) do
    find_non_local_calls(left, set)
  end

  defp find_non_local_calls([{label, {_, _, _}} | left], set)
       when is_integer(label) do
    find_non_local_calls(left, set)
  end

  defp find_non_local_calls([{label1, label2} | left], set)
       when is_integer(label1) and is_integer(label2) do
    find_non_local_calls(left, set)
  end

  defp find_non_local_calls([], set) do
    :sets.to_list(set)
  end

  def get_depends_on(sCC, r_callgraph(active_digraph: {:e, out})) do
    case ets_lookup_dict(sCC, out) do
      :error ->
        []

      {:ok, val} ->
        val
    end
  end

  def get_depends_on(sCC, r_callgraph(active_digraph: {:d, dG})) do
    :digraph.out_neighbours(dG, sCC)
  end

  def modules(r_callgraph(digraph: dG)) do
    :ordsets.from_list(
      for {m, _F, _A} <- digraph_vertices(dG) do
        m
      end
    )
  end

  defp module_postorder(r_callgraph(digraph: dG)) do
    edges = :lists.foldl(&edge_fold/2, :sets.new([{:version, 2}]), digraph_edges(dG))

    modules =
      :ordsets.from_list(
        for {m, _F, _A} <- digraph_vertices(dG) do
          m
        end
      )

    mDG = :digraph.new([:acyclic])
    digraph_confirm_vertices(modules, mDG)

    foreach = fn {m1, m2} ->
      _ = :digraph.add_edge(mDG, m1, m2)
    end

    :lists.foreach(foreach, :sets.to_list(edges))
    {:lists.reverse(:digraph_utils.topsort(mDG)), {:d, mDG}}
  end

  defp edge_fold({{m1, _, _}, {m2, _, _}}, set) do
    case m1 !== m2 do
      true ->
        :sets.add_element({m1, m2}, set)

      false ->
        set
    end
  end

  defp edge_fold(_, set) do
    set
  end

  def module_call_deps(r_callgraph(digraph: dG)) do
    edges = :lists.foldl(&edge_fold/2, :sets.new([{:version, 2}]), digraph_edges(dG))

    modules =
      :ordsets.from_list(
        for {m, _F, _A} <- digraph_vertices(dG) do
          m
        end
      )

    mDG = :digraph.new()
    digraph_confirm_vertices(modules, mDG)

    foreach = fn {m1, m2} ->
      check_add_edge(mDG, m1, m2)
    end

    :lists.foreach(foreach, :sets.to_list(edges))

    deps =
      for n <- modules do
        {n, :ordsets.from_list(:digraph.in_neighbours(mDG, n))}
      end

    digraph_delete(mDG)
    :dict.from_list(deps)
  end

  def merge_module_deps(left, right) do
    :dict.merge(
      fn _Mod, l, r ->
        :gb_sets.to_list(
          :gb_sets.union(
            :gb_sets.from_list(l),
            :gb_sets.from_list(r)
          )
        )
      end,
      left,
      right
    )
  end

  def strip_module_deps(modDeps, stripSet) do
    filterFun1 = fn val ->
      not :sets.is_element(val, stripSet)
    end

    mapFun = fn _Key, valSet ->
      :ordsets.filter(filterFun1, valSet)
    end

    modDeps1 = :dict.map(mapFun, modDeps)

    filterFun2 = fn _Key, valSet ->
      valSet !== []
    end

    :dict.filter(filterFun2, modDeps1)
  end

  def finalize(r_callgraph(digraph: dG) = cG) do
    {activeDG, labelledPostorder} = condensation(dG)
    {labelledPostorder, r_callgraph(cG, active_digraph: activeDG)}
  end

  def reset_from_funs(
        funs,
        r_callgraph(digraph: dG, active_digraph: aDG) = cG
      ) do
    active_digraph_delete(aDG)
    subGraph = digraph_reaching_subgraph(funs, dG)
    {newActiveDG, labelledPostorder} = condensation(subGraph)
    digraph_delete(subGraph)
    {labelledPostorder, r_callgraph(cG, active_digraph: newActiveDG)}
  end

  def module_postorder_from_funs(
        funs,
        r_callgraph(digraph: dG, active_digraph: aDG) = cG
      ) do
    active_digraph_delete(aDG)
    subGraph = digraph_reaching_subgraph(funs, dG)
    {pO, active} = module_postorder(r_callgraph(cG, digraph: subGraph))
    digraph_delete(subGraph)
    {pO, r_callgraph(cG, active_digraph: active)}
  end

  defp ets_lookup_dict(key, table) do
    case :ets.lookup_element(table, key, 2, :error) do
      :error ->
        :error

      val ->
        {:ok, val}
    end
  end

  defp ets_lookup_set(key, table) do
    :ets.member(table, key)
  end

  def scan_core_tree(
        tree,
        r_callgraph(
          calls: eTSCalls,
          esc: eTSEsc,
          letrec_map: eTSLetrecMap,
          name_map: eTSNameMap,
          rec_var_map: eTSRecVarMap,
          rev_name_map: eTSRevNameMap,
          self_rec: eTSSelfRec
        )
      ) do
    build_maps(tree, eTSRecVarMap, eTSNameMap, eTSRevNameMap, eTSLetrecMap)
    {deps0, escapingFuns, calls, letrecs} = :dialyzer_dep.analyze(tree)
    true = :ets.insert(eTSCalls, :dict.to_list(calls))
    true = :ets.insert(eTSLetrecMap, :dict.to_list(letrecs))

    true =
      :ets.insert(
        eTSEsc,
        for e <- escapingFuns do
          {e}
        end
      )

    labelEdges = get_edges_from_deps(deps0)

    selfRecs0 =
      :lists.foldl(
        fn
          {key, key}, acc ->
            case ets_lookup_dict(key, eTSNameMap) do
              :error ->
                [key | acc]

              {:ok, name} ->
                [key, name | acc]
            end

          _, acc ->
            acc
        end,
        [],
        labelEdges
      )

    true =
      :ets.insert(
        eTSSelfRec,
        for s <- selfRecs0 do
          {s}
        end
      )

    namedEdges1 = name_edges(labelEdges, eTSNameMap)
    namedEdges2 = scan_core_funs(tree)

    names1 =
      :lists.append(
        for {x, y} <- namedEdges1 do
          [x, y]
        end
      )

    names2 = :ordsets.from_list(names1)
    names3 = :ordsets.del_element(:top, names2)

    newNamedEdges2 =
      for {from, to} = e <- namedEdges2, from !== :top, to !== :top do
        e
      end

    newNamedEdges1 =
      for {from, to} = e <- namedEdges1, from !== :top, to !== :top do
        e
      end

    namedEdges3 = newNamedEdges1 ++ newNamedEdges2
    {names3, namedEdges3}
  end

  defp build_maps(tree, eTSRecVarMap, eTSNameMap, eTSRevNameMap, eTSLetrecMap) do
    defs = :cerl.module_defs(tree)
    mod = :cerl.atom_val(:cerl.module_name(tree))

    fun = fn {var, function} ->
      funName = :cerl.fname_id(var)
      arity = :cerl.fname_arity(var)
      mFA = {mod, funName, arity}
      funLabel = get_label(function)
      varLabel = get_label(var)
      true = :ets.insert(eTSLetrecMap, {varLabel, funLabel})
      true = :ets.insert(eTSNameMap, {funLabel, mFA})
      true = :ets.insert(eTSRevNameMap, {mFA, funLabel})
      true = :ets.insert(eTSRecVarMap, {varLabel, mFA})
    end

    :lists.foreach(fun, defs)
  end

  defp get_edges_from_deps(deps) do
    edges =
      :dict.fold(
        fn
          :external, _Set, acc ->
            acc

          caller, set, acc ->
            [
              for callee <- set, callee !== :external do
                {caller, callee}
              end
              | acc
            ]
        end,
        [],
        deps
      )

    :lists.flatten(edges)
  end

  defp name_edges(edges, eTSNameMap) do
    mapFun = fn x ->
      case ets_lookup_dict(x, eTSNameMap) do
        :error ->
          x

        {:ok, mFA} ->
          mFA
      end
    end

    name_edges(edges, mapFun, [])
  end

  defp name_edges([{from, to} | left], mapFun, acc) do
    newFrom = mapFun.(from)
    newTo = mapFun.(to)
    name_edges(left, mapFun, [{newFrom, newTo} | acc])
  end

  defp name_edges([], _MapFun, acc) do
    acc
  end

  defp scan_core_funs(tree) do
    defs = :cerl.module_defs(tree)
    mod = :cerl.atom_val(:cerl.module_name(tree))

    deepEdges =
      :lists.foldl(
        fn {var, function}, edges ->
          funName = :cerl.fname_id(var)
          arity = :cerl.fname_arity(var)
          mFA = {mod, funName, arity}
          [scan_one_core_fun(function, mFA) | edges]
        end,
        [],
        defs
      )

    :lists.flatten(deepEdges)
  end

  defp scan_one_core_fun(topTree, funName) do
    foldFun = fn tree, acc ->
      case :cerl.type(tree) do
        :call ->
          calleeM = :cerl.call_module(tree)
          calleeF = :cerl.call_name(tree)
          calleeArgs = :cerl.call_args(tree)
          a = length(calleeArgs)

          case :cerl.is_c_atom(calleeM) and :cerl.is_c_atom(calleeF) do
            true ->
              m = :cerl.atom_val(calleeM)
              f = :cerl.atom_val(calleeF)

              case :erl_bif_types.is_known(m, f, a) do
                true ->
                  case {m, f, a} do
                    {:erlang, :make_fun, 3} ->
                      [cA1, cA2, cA3] = calleeArgs

                      case :cerl.is_c_atom(cA1) and :cerl.is_c_atom(cA2) and :cerl.is_c_int(cA3) do
                        true ->
                          mM = :cerl.atom_val(cA1)
                          fF = :cerl.atom_val(cA2)
                          aA = :cerl.int_val(cA3)

                          case :erl_bif_types.is_known(mM, fF, aA) do
                            true ->
                              acc

                            false ->
                              [{funName, {mM, fF, aA}} | acc]
                          end

                        false ->
                          acc
                      end

                    _ ->
                      acc
                  end

                false ->
                  [{funName, {m, f, a}} | acc]
              end

            false ->
              acc
          end

        _ ->
          acc
      end
    end

    :cerl_trees.fold(foldFun, [], topTree)
  end

  defp get_label(t) do
    case :cerl.get_ann(t) do
      [{:label, l} | _] when is_integer(l) ->
        l

      _ ->
        :erlang.error({:missing_label, t})
    end
  end

  defp digraph_add_edges([{from, to} | left], dG) do
    digraph_add_edge(from, to, dG)
    digraph_add_edges(left, dG)
  end

  defp digraph_add_edges([], _DG) do
    :ok
  end

  defp digraph_add_edge(from, to, dG) do
    case :digraph.vertex(dG, from) do
      false ->
        :digraph.add_vertex(dG, from)

      {^from, _} ->
        :ok
    end

    case :digraph.vertex(dG, to) do
      false ->
        :digraph.add_vertex(dG, to)

      {^to, _} ->
        :ok
    end

    check_add_edge(dG, {from, to}, from, to, [])
    :ok
  end

  defp check_add_edge(g, v1, v2) do
    case :digraph.add_edge(g, v1, v2) do
      {:error, error} ->
        exit({:add_edge, v1, v2, error})

      _Edge ->
        :ok
    end
  end

  defp check_add_edge(g, e, v1, v2, l) do
    case :digraph.add_edge(g, e, v1, v2, l) do
      {:error, error} ->
        exit({:add_edge, e, v1, v2, l, error})

      _Edge ->
        :ok
    end
  end

  defp digraph_confirm_vertices([mFA | left], dG) do
    :digraph.add_vertex(dG, mFA, :confirmed)
    digraph_confirm_vertices(left, dG)
  end

  defp digraph_confirm_vertices([], _DG) do
    :ok
  end

  defp digraph_remove_external(dG) do
    vertices = :digraph.vertices(dG)
    unconfirmed = remove_unconfirmed(vertices, dG)
    {dG, unconfirmed}
  end

  defp remove_unconfirmed(vertices, dG) do
    remove_unconfirmed(vertices, dG, [])
  end

  defp remove_unconfirmed([v | left], dG, unconfirmed) do
    case :digraph.vertex(dG, v) do
      {^v, :confirmed} ->
        remove_unconfirmed(left, dG, unconfirmed)

      {^v, []} ->
        remove_unconfirmed(left, dG, [v | unconfirmed])
    end
  end

  defp remove_unconfirmed([], dG, unconfirmed) do
    badCalls =
      :lists.append(
        for v <- unconfirmed do
          :digraph.in_edges(dG, v)
        end
      )

    badCallsSorted = :lists.keysort(1, badCalls)
    :digraph.del_vertices(dG, unconfirmed)
    badCallsSorted
  end

  defp digraph_delete(dG) do
    :digraph.delete(dG)
  end

  defp active_digraph_delete({:d, dG}) do
    :digraph.delete(dG)
  end

  defp active_digraph_delete({:e, out}) do
    :ets.delete(out)
  end

  defp digraph_edges(dG) do
    :digraph.edges(dG)
  end

  defp digraph_vertices(dG) do
    :digraph.vertices(dG)
  end

  defp digraph_in_neighbours(v, dG) do
    case :digraph.in_neighbours(dG, v) do
      [] ->
        :none

      list ->
        list
    end
  end

  defp digraph_reaching_subgraph(funs, dG) do
    vertices = :digraph_utils.reaching(funs, dG)
    :digraph_utils.subgraph(dG, vertices)
  end

  def mod_deps_to_dot(modDeps, file) do
    depEdges =
      :lists.flatten(
        for {mod, modulesDependingOnIt} <- :dict.to_list(modDeps) do
          for moduleDependingOnIt <- modulesDependingOnIt do
            {mod, moduleDependingOnIt}
          end
        end
      )

    :dialyzer_dot.translate_list(depEdges, file, ~c"mod_deps")
  end

  def mod_deps_to_ps(modDeps, file, args) do
    dotFile = :filename.rootname(file) ++ ~c".dot"
    mod_deps_to_dot(modDeps, dotFile)
    command = :io_lib.format(~c"dot -Tps ~ts -o ~ts ~ts", [args, file, dotFile])
    _ = :os.cmd(command)
    :ok
  end

  def to_dot(r_callgraph(digraph: dG, esc: esc) = cG, file) do
    fun = fn l ->
      case lookup_name(l, cG) do
        :error ->
          l

        {:ok, name} ->
          name
      end
    end

    escaping =
      for l <-
            (for {e} <- :ets.tab2list(esc) do
               e
             end),
          l !== :external do
        {fun.(l), {:color, :red}}
      end

    vertices = digraph_edges(dG)
    :dialyzer_dot.translate_list(vertices, file, ~c"CG", escaping)
  end

  def to_ps(r_callgraph() = cG, file, args) do
    dot_File = :filename.rootname(file) ++ ~c".dot"
    to_dot(cG, dot_File)
    command = :io_lib.format(~c"dot -Tps ~ts -o ~ts ~ts", [args, file, dot_File])
    _ = :os.cmd(command)
    :ok
  end

  defp condensation(g) do
    outETS =
      :ets.new(
        :callgraph_label_deps_out,
        [{:read_concurrency, true}]
      )

    sCCs = :digraph_utils.strong_components(g)
    ints = :lists.seq(1, length(sCCs))
    intToSCC = :lists.zip(ints, sCCs)
    intScc = :sofs.relation(intToSCC, [{:int, :scc}])

    c2V =
      :sofs.relation(
        for sC <- sCCs, v <- sC do
          {sC, v}
        end,
        [{:scc, :v}]
      )

    i2V = :sofs.relative_product(intScc, c2V)
    es = :sofs.relation(:digraph.edges(g), [{:v, :v}])
    r1 = :sofs.relative_product(i2V, es)
    r2 = :sofs.relative_product(i2V, :sofs.converse(r1))
    r2Strict = :sofs.strict_relation(r2)
    out = :sofs.relation_to_family(:sofs.converse(r2Strict))
    :ets.insert(outETS, :sofs.to_external(out))
    dG = :sofs.family_to_digraph(out)

    :lists.foreach(
      fn i ->
        :digraph.add_vertex(dG, i)
      end,
      ints
    )

    sCCInts0 = :digraph_utils.topsort(dG)
    :digraph.delete(dG)
    sCCInts = :lists.reverse(sCCInts0)
    intToSCCMap = :maps.from_list(intToSCC)

    labelledPostorder =
      for i <- sCCInts do
        {i, :maps.get(i, intToSCCMap)}
      end

    {{:e, outETS}, labelledPostorder}
  end
end
