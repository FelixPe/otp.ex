defmodule :m_beam_ssa_recv do
  use Bitwise
  import :lists, only: [foldl: 3, member: 2, search: 2]
  require Record

  Record.defrecord(:r_b_module, :b_module,
    anno: %{},
    name: :undefined,
    exports: :undefined,
    attributes: :undefined,
    body: :undefined
  )

  Record.defrecord(:r_b_function, :b_function,
    anno: %{},
    args: :undefined,
    bs: :undefined,
    cnt: :undefined
  )

  Record.defrecord(:r_b_blk, :b_blk, anno: %{}, is: :undefined, last: :undefined)
  Record.defrecord(:r_b_set, :b_set, anno: %{}, dst: :none, op: :undefined, args: [])
  Record.defrecord(:r_b_ret, :b_ret, anno: %{}, arg: :undefined)

  Record.defrecord(:r_b_br, :b_br,
    anno: %{},
    bool: :undefined,
    succ: :undefined,
    fail: :undefined
  )

  Record.defrecord(:r_b_switch, :b_switch,
    anno: %{},
    arg: :undefined,
    fail: :undefined,
    list: :undefined
  )

  Record.defrecord(:r_b_var, :b_var, name: :undefined)
  Record.defrecord(:r_b_literal, :b_literal, val: :undefined)
  Record.defrecord(:r_b_remote, :b_remote, mod: :undefined, name: :undefined, arity: :undefined)

  Record.defrecord(:r_b_local, :b_local,
    name: :undefined,
    arity: :undefined
  )

  def format_error(optInfo) do
    format_opt_info(optInfo)
  end

  Record.defrecord(:r_scan, :scan,
    graph: :beam_digraph.new(),
    module: :undefined,
    recv_candidates: %{},
    ref_candidates: %{}
  )

  def module(r_b_module() = mod0, opts) do
    case scan(mod0) do
      r_scan() = scan ->
        {markers, uses, clears} = plan(scan)
        true = markers !== %{} === (uses !== %{})
        true = clears === %{} or markers !== %{}
        mod = optimize(mod0, markers, uses, clears)

        ws =
          case :proplists.get_bool(
                 :recv_opt_info,
                 opts
               ) do
            true ->
              collect_opt_info(mod)

            false ->
              []
          end

        {:ok, mod, ws}

      :none ->
        {:ok, mod0, []}
    end
  end

  defp scan(r_b_module(body: fs)) do
    case scan_peek_message(fs) do
      [_ | _] = rs0 ->
        rs = :maps.from_list(rs0)

        modMap =
          foldl(
            fn r_b_function(bs: blocks, args: args) = f, acc ->
              funcId = get_func_id(f)
              rets = scan_rets(blocks)
              Map.put(acc, funcId, {blocks, args, rets})
            end,
            %{},
            fs
          )

        foldl(
          fn f, scan0 ->
            funcId = get_func_id(f)
            scan = scan_add_vertex({funcId, 0}, scan0)
            scan_function(funcId, f, scan)
          end,
          r_scan(module: modMap, recv_candidates: rs),
          fs
        )

      [] ->
        :none
    end
  end

  defp scan_peek_message([r_b_function(bs: bs) = f | fs]) do
    case scan_peek_message_bs(:maps.to_list(bs)) do
      [] ->
        scan_peek_message(fs)

      [_ | _] = rs ->
        funcId = get_func_id(f)
        [{funcId, rs} | scan_peek_message(fs)]
    end
  end

  defp scan_peek_message([]) do
    []
  end

  defp scan_rets(blocks) do
    rets =
      :maps.fold(
        fn
          _K, r_b_blk(last: r_b_ret(arg: r_b_var() = retVal)), acc ->
            :gb_sets.add_element(retVal, acc)

          _K, _V, acc ->
            acc
        end,
        :gb_sets.new(),
        blocks
      )

    :gb_sets.to_list(rets)
  end

  defp scan_peek_message_bs([{lbl, blk} | bs]) do
    case blk do
      r_b_blk(is: [r_b_set(op: :peek_message) = i | _]) ->
        [{lbl, i} | scan_peek_message_bs(bs)]

      r_b_blk() ->
        scan_peek_message_bs(bs)
    end
  end

  defp scan_peek_message_bs([]) do
    []
  end

  defp get_func_id(r_b_function(anno: anno)) do
    {_, name, arity} = :maps.get(:func_info, anno)
    r_b_local(name: r_b_literal(val: name), arity: arity)
  end

  defp scan_function(funcId, r_b_function(bs: blocks), state) do
    scan_bs(:beam_ssa.rpo(blocks), blocks, funcId, state)
  end

  defp scan_bs([lbl | lbls], blocks, funcId, state0) do
    r_b_blk(is: is) = blk = :erlang.map_get(lbl, blocks)
    state = scan_is(is, blk, lbl, blocks, funcId, state0)
    scan_bs(lbls, blocks, funcId, state)
  end

  defp scan_bs([], _Blocks, _FuncId, state) do
    state
  end

  defp scan_is([r_b_set(op: {:succeeded, :body})], blk, lbl, _Blocks, funcId, state) do
    r_b_br(bool: r_b_var(), succ: succ) = r_b_blk(blk, :last)
    scan_add_edge({funcId, lbl}, {funcId, succ}, state)
  end

  defp scan_is([r_b_set(op: :new_try_tag, dst: dst)], blk, lbl, _Blocks, funcId, state) do
    r_b_br(bool: ^dst, succ: succ) = r_b_blk(blk, :last)
    scan_add_edge({funcId, lbl}, {funcId, succ}, state)
  end

  defp scan_is(
         [
           r_b_set(op: :call, dst: dst, args: [r_b_remote() | _]) = call,
           r_b_set(op: {:succeeded, :body})
         ],
         r_b_blk(last: r_b_br(succ: succ)),
         lbl,
         blocks,
         funcId,
         state0
       ) do
    case blocks do
      %{^succ => r_b_blk(is: [], last: r_b_ret(arg: ^dst))} ->
        si_remote_call(call, lbl, succ, blocks, funcId, state0)

      %{} ->
        state = si_remote_call(call, lbl, succ, blocks, funcId, state0)
        scan_add_edge({funcId, lbl}, {funcId, succ}, state)
    end
  end

  defp scan_is(
         [r_b_set(op: :call, args: [r_b_remote() | _]) = call | is],
         blk,
         lbl,
         blocks,
         funcId,
         state0
       ) do
    state = si_remote_call(call, lbl, lbl, blocks, funcId, state0)
    scan_is(is, blk, lbl, blocks, funcId, state)
  end

  defp scan_is(
         [
           r_b_set(op: :call, dst: dst, args: [r_b_local() | _]) = call,
           r_b_set(op: {:succeeded, :body}, args: [dst])
         ],
         r_b_blk(last: r_b_br(succ: succ)),
         lbl,
         blocks,
         funcId,
         state0
       ) do
    case blocks do
      %{^succ => r_b_blk(is: [], last: r_b_ret(arg: ^dst))} ->
        scan_add_call(call, lbl, succ, funcId, state0)

      %{} ->
        state = scan_add_call(call, lbl, succ, funcId, state0)
        scan_add_edge({funcId, lbl}, {funcId, succ}, state)
    end
  end

  defp scan_is([_I | is], blk, lbl, blocks, funcId, state) do
    scan_is(is, blk, lbl, blocks, funcId, state)
  end

  defp scan_is([], r_b_blk(last: r_b_ret()), lbl, _Blocks, funcId, state) do
    scan_add_edge({funcId, lbl}, {funcId, -1}, state)
  end

  defp scan_is([], blk, lbl, _Blocks, funcId, state) do
    foldl(
      fn succ, acc ->
        scan_add_edge({funcId, lbl}, {funcId, succ}, acc)
      end,
      state,
      :beam_ssa.successors(blk)
    )
  end

  defp scan_add_call(call, callLbl, succLbl, caller, r_scan(module: modMap) = state0) do
    r_b_set(dst: dst, args: [r_b_local() = callee | args]) = call
    %{^callee => {_Blocks, params, rets}} = modMap
    {callTranslation, callInverse} = scan_translate_call(args, params, %{}, %{})

    state =
      scan_add_edge({caller, callLbl}, {callee, 0}, {callTranslation, callInverse, args}, state0)

    {retTranslation, retInverse} = scan_translate_return(rets, dst, callTranslation)
    scan_add_edge({callee, -1}, {caller, succLbl}, {retTranslation, retInverse, params}, state)
  end

  defp scan_translate_call([arg | args], [param | params], argToParams, paramToArgs) do
    scan_translate_call(
      args,
      params,
      Map.put(argToParams, arg, param),
      Map.put(paramToArgs, param, arg)
    )
  end

  defp scan_translate_call([], [], argToParams, paramToArgs) do
    {argToParams, paramToArgs}
  end

  defp scan_translate_return(rets, dst, callerToCallee0) do
    callerToCallee = Map.put(callerToCallee0, dst, rets)
    calleeToCaller = scan_translate_return_1(rets, dst, %{})
    {calleeToCaller, callerToCallee}
  end

  defp scan_translate_return_1([ret | rets], dst, calleeToCaller) do
    scan_translate_return_1(rets, dst, Map.put(calleeToCaller, ret, dst))
  end

  defp scan_translate_return_1([], _Dst, calleeToCaller) do
    calleeToCaller
  end

  defp scan_add_edge(from, to, state) do
    scan_add_edge(from, to, :branch, state)
  end

  defp scan_add_edge(from, to, label, state0) do
    state =
      scan_add_vertex(
        to,
        scan_add_vertex(from, state0)
      )

    graph = :beam_digraph.add_edge(r_scan(state, :graph), from, to, label)
    r_scan(state, graph: graph)
  end

  defp scan_add_vertex(vertex, r_scan(graph: graph0) = state) do
    case :beam_digraph.has_vertex(graph0, vertex) do
      true ->
        state

      false ->
        graph = :beam_digraph.add_vertex(graph0, vertex)
        r_scan(state, graph: graph)
    end
  end

  defp si_remote_call(
         r_b_set(anno: anno, dst: dst, args: args) = call,
         calledAt,
         validAfter,
         blocks,
         funcId,
         state
       ) do
    case si_remote_call_1(dst, args, validAfter, blocks) do
      {:makes_ref, extractedAt, ref} ->
        r_scan(ref_candidates: candidates0) = state
        makeRefs0 = :maps.get(funcId, candidates0, [])
        makeRef = {anno, calledAt, dst, extractedAt, ref}
        candidates = Map.put(candidates0, funcId, [makeRef | makeRefs0])
        r_scan(state, ref_candidates: candidates)

      :uses_ref ->
        r_scan(recv_candidates: candidates0) = state
        useRefs0 = :maps.get(funcId, candidates0, [])
        useRef = {calledAt, call}
        candidates = Map.put(candidates0, funcId, [useRef | useRefs0])
        r_scan(state, recv_candidates: candidates)

      :no ->
        state
    end
  end

  defp si_remote_call_1(dst, [callee | args], lbl, blocks) do
    mFA =
      case callee do
        r_b_remote(mod: r_b_literal(val: mod), name: r_b_literal(val: func), arity: arity) ->
          {mod, func, arity}

        _ ->
          :none
      end

    case mFA do
      {:erlang, :alias, a}
      when is_integer(a) and 0 <= a and
             a <= 1 ->
        {:makes_ref, lbl, dst}

      {:erlang, :demonitor, 2} ->
        case args do
          [_MRef, r_b_literal(val: [:flush])] ->
            :uses_ref

          [_MRef, _Options] ->
            :no
        end

      {:erlang, :make_ref, 0} ->
        {:makes_ref, lbl, dst}

      {:erlang, :monitor, a}
      when is_integer(a) and
             2 <= a and a <= 3 ->
        {:makes_ref, lbl, dst}

      {:erlang, :spawn_monitor, a}
      when is_integer(a) and
             1 <= a and a <= 4 ->
        rPO = :beam_ssa.rpo([lbl], blocks)
        si_ref_in_tuple(rPO, blocks, dst)

      {:erlang, :spawn_request, a}
      when is_integer(a) and
             1 <= a and a <= 5 ->
        {:makes_ref, lbl, dst}

      _ ->
        :no
    end
  end

  defp si_ref_in_tuple([lbl | lbls], blocks, tuple) do
    r_b_blk(is: is) = :erlang.map_get(lbl, blocks)

    case si_ref_in_tuple_is(is, tuple) do
      {:yes, ref} ->
        {:makes_ref, lbl, ref}

      :no ->
        si_ref_in_tuple(lbls, blocks, tuple)
    end
  end

  defp si_ref_in_tuple([], _Blocks, _Tuple) do
    :no
  end

  defp si_ref_in_tuple_is(
         [
           r_b_set(op: :get_tuple_element, dst: ref, args: [r_b_var() = tuple, pos])
           | is
         ],
         tuple
       ) do
    case pos do
      r_b_literal(val: 1) ->
        {:yes, ref}

      _ ->
        si_ref_in_tuple_is(is, tuple)
    end
  end

  defp si_ref_in_tuple_is([_I | is], tuple) do
    si_ref_in_tuple_is(is, tuple)
  end

  defp si_ref_in_tuple_is([], _Tuple) do
    :no
  end

  defp plan(scan) do
    r_scan(
      ref_candidates: refCandidates,
      recv_candidates: receiveCandidates,
      module: modMap,
      graph: graph
    ) = scan

    refMap0 = propagate_references(refCandidates, graph)
    uses = plan_uses(receiveCandidates, refMap0, modMap)
    refMap = intersect_uses(uses, refMap0, graph)
    markers = plan_markers(refCandidates, refMap)
    clears = plan_clears(refMap, graph)
    {markers, uses, clears}
  end

  defp propagate_references(candidates, g) do
    roots =
      :maps.fold(
        fn funcId, makeRefs, acc ->
          for makeRef <- makeRefs do
            {_, _, _, extractedAt, ref} = makeRef
            vertex = {funcId, extractedAt}
            {vertex, ref}
          end ++ acc
        end,
        [],
        candidates
      )

    propagate_references_1(roots, g, %{})
  end

  defp propagate_references_1([{vertex, ref} | vRefs], g, acc0) do
    refs = :maps.get(vertex, acc0, :sets.new([{:version, 2}]))

    acc =
      case :sets.is_element(ref, refs) do
        true ->
          acc0

        false ->
          acc1 = Map.put(acc0, vertex, :sets.add_element(ref, refs))

          next =
            pr_successors(
              :beam_digraph.out_edges(g, vertex),
              ref
            )

          propagate_references_1(next, g, acc1)
      end

    propagate_references_1(vRefs, g, acc)
  end

  defp propagate_references_1([], _G, acc) do
    acc
  end

  defp pr_successors([{_From, to, :branch} | edges], ref) do
    [{to, ref} | pr_successors(edges, ref)]
  end

  defp pr_successors(
         [
           {{_, fromLbl}, to, {translation, _Inverse, args}}
           | edges
         ],
         ref
       ) do
    case translation do
      %{^ref => r_b_var() = param} ->
        case fromLbl !== -1 or not member(ref, args) do
          true ->
            [{to, param} | pr_successors(edges, ref)]

          false ->
            pr_successors(edges, ref)
        end

      %{} ->
        pr_successors(edges, ref)
    end
  end

  defp pr_successors([], _Ref) do
    []
  end

  defp plan_uses(candidates, refMap, modMap) do
    :maps.fold(
      fn funcId, receives, acc ->
        %{^funcId => {blocks, _Params, _Rets}} = modMap

        case plan_uses_1(receives, funcId, blocks, refMap) do
          [_ | _] = uses ->
            Map.put(acc, funcId, uses)

          [] ->
            acc
        end
      end,
      %{},
      candidates
    )
  end

  defp plan_uses_1([{lbl, i} | receives], funcId, blocks, refMap) do
    case refMap do
      %{{^funcId, ^lbl} => refs} ->
        case search(
               fn ref ->
                 pu_is_ref_used(i, ref, lbl, blocks)
               end,
               :sets.to_list(refs)
             ) do
          {:value, ref} ->
            use = {lbl, i, ref}
            [use | plan_uses_1(receives, funcId, blocks, refMap)]

          false ->
            plan_uses_1(receives, funcId, blocks, refMap)
        end

      %{} ->
        plan_uses_1(receives, funcId, blocks, refMap)
    end
  end

  defp plan_uses_1([], _FuncId, _Blocks, _RefMap) do
    []
  end

  defp pu_is_ref_used(r_b_set(op: :call, args: [callee | args]), ref, _Lbl, _Blocks) do
    mFA =
      case callee do
        r_b_remote(mod: r_b_literal(val: mod), name: r_b_literal(val: func), arity: arity) ->
          {mod, func, arity}

        _ ->
          :none
      end

    case mFA do
      {:erlang, :demonitor, 2} ->
        [mRef | _] = args
        mRef === ref

      _ ->
        false
    end
  end

  defp pu_is_ref_used(r_b_set(op: :peek_message, dst: msg) = i, ref, lbl, blocks) do
    r_b_blk(is: [^i | _]) = blk = :erlang.map_get(lbl, blocks)
    vs = %{msg => :message, ref => :ref, ref: ref, ref_matched: false}

    case pu_is_ref_used_last(blk, vs, blocks) do
      :used ->
        true

      :not_used ->
        false

      :done ->
        false
    end
  end

  defp pu_is_ref_used_last(r_b_blk(last: last) = blk, vs, blocks) do
    succVs =
      case last do
        r_b_br(bool: r_b_var() = bool, succ: succ, fail: fail) ->
          case vs do
            %{^bool => {:is_ref, matched}} ->
              [{succ, %{vs | ref_matched: matched}}, {fail, %{vs | ref_matched: not matched}}]

            %{} ->
              [{succ, vs}, {fail, vs}]
          end

        _ ->
          for succ <- :beam_ssa.successors(blk) do
            {succ, vs}
          end
      end

    [_ | _] = succVs
    pu_ref_used_in(succVs, blocks)
  end

  defp pu_ref_used_in([{l, vs0} | ls], blocks) do
    case pu_is_ref_used_in_1(l, vs0, blocks) do
      :not_used ->
        :not_used

      :used ->
        case pu_ref_used_in(ls, blocks) do
          :done ->
            :used

          result ->
            result
        end

      :done ->
        pu_ref_used_in(ls, blocks)
    end
  end

  defp pu_ref_used_in([], _) do
    :done
  end

  defp pu_is_ref_used_in_1(l, vs0, blocks) do
    r_b_blk(is: is) = blk = :erlang.map_get(l, blocks)

    case pu_is_ref_used_is(is, vs0) do
      %{} = vs ->
        pu_is_ref_used_last(blk, vs, blocks)

      result ->
        result
    end
  end

  defp pu_is_ref_used_is(
         [
           r_b_set(op: {:bif, bif}, args: args, dst: dst) = i
           | is
         ],
         vs0
       ) do
    cond do
      bif === :"=:=" or bif === :== ->
        case pu_is_ref_msg_comparison(args, vs0) do
          true ->
            vs = Map.put(vs0, dst, {:is_ref, true})
            pu_is_ref_used_is(is, vs)

          false ->
            pu_is_ref_used_is(is, vs0)
        end

      true ->
        vs = pu_update_vars(i, vs0)
        pu_is_ref_used_is(is, vs)
    end
  end

  defp pu_is_ref_used_is([r_b_set(op: :remove_message) | _], vs) do
    case vs do
      %{ref_matched: true} ->
        :used

      %{ref_matched: false} ->
        :not_used
    end
  end

  defp pu_is_ref_used_is([r_b_set(op: :recv_next) | _], _Vs) do
    :done
  end

  defp pu_is_ref_used_is([r_b_set(op: :wait_timeout) | _], _Vs) do
    :done
  end

  defp pu_is_ref_used_is([r_b_set() = i | is], vs0) do
    true = :beam_ssa.no_side_effect(i)
    vs = pu_update_vars(i, vs0)
    pu_is_ref_used_is(is, vs)
  end

  defp pu_is_ref_used_is([], vs) do
    vs
  end

  defp pu_update_vars(r_b_set(args: args, dst: dst), vs) do
    vars =
      for r_b_var() = v <- args do
        v
      end

    all =
      :lists.all(
        fn var ->
          case vs do
            %{^var => :message} ->
              true

            %{} ->
              false
          end
        end,
        vars
      )

    case {vars, all} do
      {[_ | _], true} ->
        Map.put(vs, dst, :message)

      {_, _} ->
        vs
    end
  end

  defp pu_is_ref_msg_comparison([r_b_var() = v1, r_b_var() = v2], vs) do
    case vs do
      %{^v1 => :ref, ^v2 => :message} ->
        true

      %{^v1 => :message, ^v2 => :ref} ->
        true

      %{} ->
        false
    end
  end

  defp pu_is_ref_msg_comparison(_, _) do
    false
  end

  defp intersect_uses(usageMap, refMap, graph) do
    roots =
      :maps.fold(
        fn funcId, uses, acc ->
          for {lbl, _I, ref} <- uses do
            vertex = {funcId, lbl}
            {vertex, ref}
          end ++ acc
        end,
        [],
        usageMap
      )

    intersect_uses_1(roots, refMap, graph, %{})
  end

  defp intersect_uses_1([{vertex, ref} | vs], refMap, graph, acc0) do
    possibleRefs = :maps.get(vertex, refMap, :sets.new([{:version, 2}]))
    activeRefs0 = :maps.get(vertex, acc0, :sets.new([{:version, 2}]))

    acc =
      case {:sets.is_element(ref, possibleRefs), :sets.is_element(ref, activeRefs0)} do
        {true, false} ->
          edges = :beam_digraph.in_edges(graph, vertex)
          next = iu_predecessors(edges, ref)
          activeRefs = :sets.add_element(ref, activeRefs0)
          intersect_uses_1(next, refMap, graph, Map.put(acc0, vertex, activeRefs))

        {false, _} ->
          acc0

        {_, true} ->
          acc0
      end

    intersect_uses_1(vs, refMap, graph, acc)
  end

  defp intersect_uses_1([], _RefMap, _Graph, acc) do
    acc
  end

  defp iu_predecessors([{from, _To, :branch} | edges], ref) do
    [{from, ref} | iu_predecessors(edges, ref)]
  end

  defp iu_predecessors(
         [
           {from, _To, {_Translation, inverse, _Args}}
           | edges
         ],
         ref
       ) do
    case inverse do
      %{^ref => r_b_var() = arg} ->
        [{from, arg} | iu_predecessors(edges, ref)]

      %{^ref => [_ | _] = rets} ->
        for ret <- rets do
          {from, ret}
        end ++ iu_predecessors(edges, ref)

      %{} ->
        iu_predecessors(edges, ref)
    end
  end

  defp iu_predecessors([], _Ref) do
    []
  end

  defp plan_markers(candidates, usageMap) do
    :maps.fold(
      fn funcId, makeRefs, acc ->
        case plan_markers_1(makeRefs, funcId, usageMap) do
          [_ | _] = marks ->
            Map.put(acc, funcId, marks)

          [] ->
            acc
        end
      end,
      %{},
      candidates
    )
  end

  defp plan_markers_1(makeRefs0, funcId, usageMap) do
    for {_, _, _, extractedAt, ref} = marker <- makeRefs0,
        (case usageMap do
           %{{^funcId, ^extractedAt} => refs} ->
             :sets.is_element(ref, refs)

           %{} ->
             false
         end) do
      marker
    end
  end

  defp plan_clears(usageMap, graph) do
    :maps.fold(
      fn {funcId, _} = vertex, activeRefs, acc ->
        edges = :beam_digraph.out_edges(graph, vertex)

        case plan_clears_1(edges, activeRefs, usageMap) do
          [_ | _] = clears ->
            clears0 = :maps.get(funcId, acc, [])
            Map.put(acc, funcId, clears ++ clears0)

          [] ->
            acc
        end
      end,
      %{},
      usageMap
    )
  end

  defp plan_clears_1([{from, to, :branch} | edges], activeRefs, usageMap) do
    toRefs = :maps.get(to, usageMap, :sets.new([{:version, 2}]))
    refs = :sets.subtract(activeRefs, toRefs)
    {funcId, fromLbl} = from
    {^funcId, toLbl} = to

    clears =
      for ref <- :sets.to_list(refs) do
        {fromLbl, toLbl, ref}
      end

    clears ++ plan_clears_1(edges, activeRefs, usageMap)
  end

  defp plan_clears_1([{_From, _To, {_, _, _}} | edges], activeRefs, usageMap) do
    plan_clears_1(edges, activeRefs, usageMap)
  end

  defp plan_clears_1([], _ActiveRefs, _UsageMap) do
    []
  end

  defp optimize(r_b_module(body: fs0) = mod, markers, uses, clears) do
    fs =
      for f <- fs0 do
        optimize_1(f, markers, uses, clears)
      end

    r_b_module(mod, body: fs)
  end

  defp optimize_1(r_b_function(bs: blocks0, cnt: count0) = f, markers, uses, clears) do
    funcId = get_func_id(f)
    {blocks1, count1} = insert_markers(:maps.get(funcId, markers, []), blocks0, count0)
    {blocks2, count2} = insert_uses(:maps.get(funcId, uses, []), blocks1, count1)
    {blocks, count} = insert_clears(:maps.get(funcId, clears, []), blocks2, count2)
    r_b_function(f, bs: blocks, cnt: count)
  end

  defp insert_markers(
         [
           {anno, createdAt, dst, extractedAt, ref}
           | markers
         ],
         blocks0,
         count0
       ) do
    {markerVar, blocks1, count1} = insert_reserve(createdAt, dst, anno, blocks0, count0)
    {blocks, count} = insert_bind(extractedAt, ref, markerVar, blocks1, count1)
    insert_markers(markers, blocks, count)
  end

  defp insert_markers([], blocks, count) do
    {blocks, count}
  end

  defp insert_reserve(lbl, dst, anno, blocks0, count0) do
    %{^lbl => r_b_blk(is: is0) = blk} = blocks0
    var = r_b_var(name: {:"@ssa_recv_marker", count0})
    count = count0 + 1
    reserve = r_b_set(anno: anno, op: :recv_marker_reserve, args: [], dst: var)
    is = insert_reserve_is(is0, reserve, dst)
    blocks = %{blocks0 | lbl => r_b_blk(blk, is: is)}
    {var, blocks, count}
  end

  defp insert_reserve_is([r_b_set(dst: var) | _] = is, reserve, var) do
    [reserve | is]
  end

  defp insert_reserve_is([i | is], reserve, var) do
    [i | insert_reserve_is(is, reserve, var)]
  end

  defp insert_bind(lbl, ref, marker, blocks0, count0) do
    %{^lbl => r_b_blk(is: is0, last: last) = blk} = blocks0
    ignored = r_b_var(name: {:"@ssa_ignored", count0})
    count = count0 + 1
    bind = r_b_set(op: :recv_marker_bind, args: [marker, ref], dst: ignored)
    is = insert_bind_is(is0, bind, last)
    blocks = %{blocks0 | lbl => r_b_blk(blk, is: is)}
    {blocks, count}
  end

  defp insert_bind_is([r_b_set(), r_b_set(op: {:succeeded, _})] = is, bind, _Last) do
    [bind | is]
  end

  defp insert_bind_is([r_b_set(op: :call, dst: ret)] = is, bind, r_b_ret(arg: ret)) do
    [bind | is]
  end

  defp insert_bind_is([r_b_set(op: :new_try_tag)] = is, bind, _Last) do
    [bind | is]
  end

  defp insert_bind_is([r_b_set(op: op) = i | is], bind, last) do
    true = op !== :bs_put
    [i | insert_bind_is(is, bind, last)]
  end

  defp insert_bind_is([], bind, _Last) do
    [bind]
  end

  defp insert_uses([{_Lbl, r_b_set(op: :call), _Ref} | uses], blocks, count) do
    insert_uses(uses, blocks, count)
  end

  defp insert_uses(
         [
           {lbl, r_b_set(op: :peek_message) = peek0, ref}
           | uses
         ],
         blocks0,
         count
       ) do
    %{^lbl => r_b_blk(is: is0) = blk} = blocks0
    [^peek0 | is] = is0
    peek = r_b_set(peek0, args: [ref])
    blocks = %{blocks0 | lbl => r_b_blk(blk, is: [peek | is])}
    insert_uses(uses, blocks, count)
  end

  defp insert_uses([], blocks, count) do
    {blocks, count}
  end

  defp insert_clears(clears0, blocks0, count0) do
    {insertions, count} = insert_clears_1(clears0, count0, [])
    :beam_ssa.insert_on_edges(insertions, blocks0, count)
  end

  defp insert_clears_1([{from, to, ref} | clears], count0, acc) do
    ignored = r_b_var(name: {:"@ssa_ignored", count0})
    count = count0 + 1
    clear = r_b_set(op: :recv_marker_clear, args: [ref], dst: ignored)
    insert_clears_1(clears, count, [{from, to, [clear]} | acc])
  end

  defp insert_clears_1([], count, acc) do
    {acc, count}
  end

  defp collect_opt_info(r_b_module(body: fs)) do
    coi_1(fs, [])
  end

  defp coi_1([r_b_function(args: args, bs: blocks) = f | fs], acc0) do
    lbls = :beam_ssa.rpo(blocks)
    where = :beam_ssa.get_anno(:location, f, [])

    {defs, _} =
      foldl(
        fn var, {defs0, index0} ->
          defs = Map.put(defs0, var, {:parameter, index0})
          index = index0 + 1
          {defs, index}
        end,
        {%{}, 1},
        args
      )

    acc = coi_bs(lbls, blocks, where, defs, acc0)
    coi_1(fs, acc)
  end

  defp coi_1([], acc) do
    acc
  end

  defp coi_bs([lbl | lbls], blocks, where, defs0, ws0) do
    %{^lbl => r_b_blk(is: is, last: last)} = blocks
    {defs, ws} = coi_is(is, last, blocks, where, defs0, ws0)
    coi_bs(lbls, blocks, where, defs, ws)
  end

  defp coi_bs([], _Blocks, _Where, _Defs, ws) do
    ws
  end

  defp coi_is(
         [
           r_b_set(anno: anno, op: :peek_message, args: [r_b_var()] = args)
           | is
         ],
         last,
         blocks,
         where,
         defs,
         ws
       ) do
    [creation] = coi_creations(args, blocks, defs)
    warning = make_warning({:used_receive_marker, creation}, anno, where)
    coi_is(is, last, blocks, where, defs, [warning | ws])
  end

  defp coi_is(
         [
           r_b_set(anno: anno, op: :peek_message, args: [r_b_literal()])
           | is
         ],
         last,
         blocks,
         where,
         defs,
         ws
       ) do
    r_b_br(succ: nextMsg) = last
    %{^nextMsg => r_b_blk(is: nextIs)} = blocks

    info =
      case nextIs do
        [r_b_set(op: :remove_message) | _] ->
          :matches_any_message

        _ ->
          :unoptimized_selective_receive
      end

    warning = make_warning(info, anno, where)
    coi_is(is, last, blocks, where, defs, [warning | ws])
  end

  defp coi_is([r_b_set(anno: anno, op: :recv_marker_reserve) | is], last, blocks, where, defs, ws) do
    warning = make_warning(:reserved_receive_marker, anno, where)
    coi_is(is, last, blocks, where, defs, [warning | ws])
  end

  defp coi_is(
         [
           r_b_set(anno: anno, op: :call, dst: dst, args: [r_b_local() | args]) = i
           | is
         ],
         last,
         blocks,
         where,
         defs0,
         ws0
       ) do
    defs = Map.put(defs0, dst, i)

    ws =
      for r_b_set() = creation <- coi_creations(args, blocks, defs) do
        make_warning({:passed_marker, creation}, anno, where)
      end ++ ws0

    coi_is(is, last, blocks, where, defs, ws)
  end

  defp coi_is([r_b_set(dst: dst) = i | is], last, blocks, where, defs0, ws) do
    defs = Map.put(defs0, dst, i)
    coi_is(is, last, blocks, where, defs, ws)
  end

  defp coi_is([], _Last, _Blocks, _Where, defs, ws) do
    {defs, ws}
  end

  defp coi_creations([var | vars], blocks, defs) do
    case defs do
      %{^var => r_b_set(op: :call, dst: dst, args: args) = call} ->
        case si_remote_call_1(dst, args, 0, blocks) do
          {:makes_ref, _, _} ->
            [call | coi_creations(vars, blocks, defs)]

          _ ->
            coi_creations(vars, blocks, defs)
        end

      %{^var => r_b_set(op: :get_tuple_element, args: [tuple | _])} ->
        coi_creations([tuple | vars], blocks, defs)

      %{^var => {:parameter, _} = parameter} ->
        [parameter | coi_creations(vars, blocks, defs)]

      %{} ->
        coi_creations(vars, blocks, defs)
    end
  end

  defp coi_creations([], _Blocks, _Defs) do
    []
  end

  defp make_warning(term, anno, where) do
    {file, line} =
      case :maps.get(:location, anno, where) do
        {_, _} = location ->
          location

        _ ->
          {~c"no_file", :none}
      end

    {file, [{line, :beam_ssa_recv, term}]}
  end

  defp format_opt_info(:matches_any_message) do
    ~c"INFO: receive matches any message, this is always fast"
  end

  defp format_opt_info({:passed_marker, creation}) do
    :io_lib.format(~c"INFO: passing reference ~ts", [format_ref_creation(creation)])
  end

  defp format_opt_info({:used_receive_marker, creation}) do
    :io_lib.format(~c"OPTIMIZED: all clauses match reference ~ts", [format_ref_creation(creation)])
  end

  defp format_opt_info(:reserved_receive_marker) do
    ~c"OPTIMIZED: reference used to mark a message queue position"
  end

  defp format_opt_info(:unoptimized_selective_receive) do
    ~c"NOT OPTIMIZED: all clauses do not match a suitable reference"
  end

  defp format_ref_creation({:parameter, index}) do
    :io_lib.format(~c"in function parameter ~w", [index])
  end

  defp format_ref_creation(r_b_set(op: :call, anno: anno, args: [callee | _])) do
    r_b_remote(name: r_b_literal(val: f), arity: a) = callee
    {file, line} = :maps.get(:location, anno, {~c"", 1})
    :io_lib.format(~c"created by ~p/~p at ~ts:~w", [f, a, file, line])
  end
end
