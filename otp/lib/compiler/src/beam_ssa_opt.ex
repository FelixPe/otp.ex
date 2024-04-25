defmodule :m_beam_ssa_opt do
  use Bitwise

  import :lists,
    only: [
      all: 2,
      append: 1,
      droplast: 1,
      duplicate: 2,
      flatten: 1,
      foldl: 3,
      keyfind: 3,
      last: 1,
      mapfoldl: 3,
      member: 2,
      partition: 2,
      reverse: 1,
      reverse: 2,
      sort: 1,
      splitwith: 2,
      takewhile: 2,
      unzip: 1
    ]

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

  Record.defrecord(:r_func_info, :func_info,
    in: :ordsets.new(),
    out: :ordsets.new(),
    exported: true,
    arg_types: [],
    succ_types: []
  )

  Record.defrecord(:r_opt_st, :opt_st,
    ssa: :undefined,
    args: :undefined,
    cnt: :undefined,
    anno: :undefined
  )

  def module(module, opts) do
    funcDb =
      case :proplists.get_value(:no_module_opt, opts, false) do
        false ->
          build_func_db(module)

        true ->
          %{}
      end

    stMap0 = build_st_map(module)
    order = get_call_order_po(stMap0, funcDb)

    phases = [
      {:once, order, prologue_passes(opts)},
      {:module, module_passes(opts)},
      {:fixpoint, order, repeated_passes(opts)},
      {:once, order, early_epilogue_passes(opts)},
      {:module, epilogue_module_passes(opts)},
      {:once, order, late_epilogue_passes(opts)}
    ]

    stMap = run_phases(phases, stMap0, funcDb)
    {:ok, finish(module, stMap)}
  end

  defp run_phases([{:module, passes} | phases], stMap0, funcDb0) do
    {stMap, funcDb} =
      :compile.run_sub_passes(
        passes,
        {stMap0, funcDb0}
      )

    run_phases(phases, stMap, funcDb)
  end

  defp run_phases([{:once, funcIds0, passes} | phases], stMap0, funcDb0) do
    funcIds = skip_removed(funcIds0, stMap0)
    {stMap, funcDb} = phase(funcIds, passes, stMap0, funcDb0)
    run_phases(phases, stMap, funcDb)
  end

  defp run_phases([{:fixpoint, funcIds0, passes} | phases], stMap0, funcDb0) do
    funcIds = skip_removed(funcIds0, stMap0)
    revFuncIds = reverse(funcIds)
    order = {funcIds, revFuncIds}
    {stMap, funcDb} = fixpoint(revFuncIds, order, passes, stMap0, funcDb0, 16)
    run_phases(phases, stMap, funcDb)
  end

  defp run_phases([], stMap, _FuncDb) do
    stMap
  end

  defp skip_removed(funcIds, stMap) do
    for f <- funcIds, :erlang.is_map_key(f, stMap) do
      f
    end
  end

  defp fixpoint(_FuncIds, _Order, _Passes, stMap, funcDb, 0) do
    {stMap, funcDb}
  end

  defp fixpoint(funcIds0, order0, passes, stMap0, funcDb0, n)
       when is_map(stMap0) do
    {stMap, funcDb} = phase(funcIds0, passes, stMap0, funcDb0)
    repeat = changed(funcIds0, funcDb0, funcDb, stMap0, stMap)

    case :sets.is_empty(repeat) do
      true ->
        {stMap, funcDb}

      false ->
        {orderA, orderB} = order0
        order = {orderB, orderA}

        funcIds =
          for id <- orderA,
              :sets.is_element(id, repeat) do
            id
          end

        fixpoint(funcIds, order, passes, stMap, funcDb, n - 1)
    end
  end

  defp phase([funcId | ids], ps, stMap, funcDb0) do
    try do
      :compile.run_sub_passes(
        ps,
        {:erlang.map_get(funcId, stMap), funcDb0}
      )
    catch
      class, error ->
        r_b_local(name: r_b_literal(val: name), arity: arity) = funcId
        :io.fwrite(~c"Function: ~w/~w\n", [name, arity])
        :erlang.raise(class, error, __STACKTRACE__)
    else
      {st, funcDb} ->
        phase(ids, ps, Map.put(stMap, funcId, st), funcDb)
    end
  end

  defp phase([], _Ps, stMap, funcDb) do
    {stMap, funcDb}
  end

  defp changed(prevIds, funcDb0, funcDb, stMap0, stMap) do
    emptySet = :sets.new([{:version, 2}])
    changed0 = changed_types(prevIds, funcDb0, funcDb, emptySet, emptySet)

    foldl(
      fn id, changed ->
        case :sets.is_element(id, changed) do
          true ->
            changed

          false ->
            case {:erlang.map_get(id, stMap0), :erlang.map_get(id, stMap)} do
              {same, same} ->
                changed

              {_, _} ->
                :sets.add_element(id, changed)
            end
        end
      end,
      changed0,
      prevIds
    )
  end

  defp changed_types([id | ids], fdb0, fdb, in0, out0) do
    case {fdb0, fdb} do
      {%{^id => r_func_info(arg_types: aTs0, succ_types: sT0)},
       %{^id => r_func_info(arg_types: aTs, succ_types: sT)}} ->
        in__ =
          case sT0 === sT do
            true ->
              in0

            false ->
              changed_types_1([id], r_func_info(:in), fdb, in0)
          end

        out =
          case aTs0 === aTs do
            true ->
              out0

            false ->
              changed_types_1([id], r_func_info(:out), fdb, out0)
          end

        changed_types(ids, fdb0, fdb, in__, out)

      _ ->
        changed_types(ids, fdb0, fdb, in0, out0)
    end
  end

  defp changed_types([], _Fdb0, _Fdb, in__, out) do
    :sets.union(in__, out)
  end

  defp changed_types_1([id | ids], direction, fdb, seen0) do
    case :sets.is_element(id, seen0) do
      true ->
        changed_types_1(ids, direction, fdb, seen0)

      false ->
        case fdb do
          %{^id => funcInfo} ->
            next = :erlang.element(direction, funcInfo)
            seen1 = :sets.add_element(id, seen0)
            seen2 = changed_types_1(next, direction, fdb, seen1)
            changed_types_1(ids, direction, fdb, seen2)

          %{} ->
            changed_types_1(ids, direction, fdb, seen0)
        end
    end
  end

  defp changed_types_1([], _, _, seen) do
    seen
  end

  defp get_func_id(f) do
    {_Mod, name, arity} = :beam_ssa.get_anno(:func_info, f)
    r_b_local(name: r_b_literal(val: name), arity: arity)
  end

  defp build_st_map(r_b_module(body: fs)) do
    build_st_map_1(fs, %{})
  end

  defp build_st_map_1([f | fs], map) do
    r_b_function(anno: anno, args: args, cnt: counter, bs: bs) = f
    st = r_opt_st(anno: anno, args: args, cnt: counter, ssa: bs)
    build_st_map_1(fs, Map.put(map, get_func_id(f), st))
  end

  defp build_st_map_1([], map) do
    map
  end

  defp finish(r_b_module(body: fs0) = module, stMap) do
    r_b_module(module, body: finish_1(fs0, stMap))
  end

  defp finish_1([f0 | fs], stMap) do
    funcId = get_func_id(f0)

    case stMap do
      %{^funcId => r_opt_st(anno: anno, cnt: counter, ssa: blocks)} ->
        f = r_b_function(f0, anno: anno, bs: blocks, cnt: counter)
        [f | finish_1(fs, stMap)]

      %{} ->
        finish_1(fs, stMap)
    end
  end

  defp finish_1([], _StMap) do
    []
  end

  defp prologue_passes(opts) do
    ps = [
      {:ssa_opt_split_blocks, &ssa_opt_split_blocks/1},
      {:ssa_opt_coalesce_phis, &ssa_opt_coalesce_phis/1},
      {:ssa_opt_tail_phis, &ssa_opt_tail_phis/1},
      {:ssa_opt_element, &ssa_opt_element/1},
      {:ssa_opt_linearize, &ssa_opt_linearize/1},
      {:ssa_opt_tuple_size, &ssa_opt_tuple_size/1},
      {:ssa_opt_record, &ssa_opt_record/1},
      {:ssa_opt_update_tuple, &ssa_opt_update_tuple/1},
      {:ssa_opt_cse, &ssa_opt_cse/1},
      {:ssa_opt_live, &ssa_opt_live/1}
    ]

    passes_1(ps, opts)
  end

  defp module_passes(opts) do
    ps0 = [
      {:ssa_opt_bc_size,
       fn {stMap, funcDb} ->
         {:beam_ssa_bc_size.opt(stMap), funcDb}
       end},
      {:ssa_opt_type_start,
       fn {stMap, funcDb} ->
         :beam_ssa_type.opt_start(stMap, funcDb)
       end}
    ]

    passes_1(ps0, opts)
  end

  defp repeated_passes(opts) do
    ps = [
      {:ssa_opt_live, &ssa_opt_live/1},
      {:ssa_opt_ne, &ssa_opt_ne/1},
      {:ssa_opt_bs_create_bin, &ssa_opt_bs_create_bin/1},
      {:ssa_opt_dead, &ssa_opt_dead/1},
      {:ssa_opt_cse, &ssa_opt_cse/1},
      {:ssa_opt_tail_phis, &ssa_opt_tail_phis/1},
      {:ssa_opt_sink, &ssa_opt_sink/1},
      {:ssa_opt_tuple_size, &ssa_opt_tuple_size/1},
      {:ssa_opt_record, &ssa_opt_record/1},
      {:ssa_opt_try, &ssa_opt_try/1},
      {:ssa_opt_type_continue, &ssa_opt_type_continue/1}
    ]

    passes_1(ps, opts)
  end

  defp epilogue_module_passes(opts) do
    ps0 = [
      {:ssa_opt_alias,
       fn {stMap, funcDb} ->
         :beam_ssa_alias.opt(stMap, funcDb)
       end},
      {:ssa_opt_private_append,
       fn {stMap, funcDb} ->
         :beam_ssa_private_append.opt(stMap, funcDb)
       end}
    ]

    passes_1(ps0, opts)
  end

  defp early_epilogue_passes(opts) do
    ps = [
      {:ssa_opt_type_finish, &ssa_opt_type_finish/1},
      {:ssa_opt_float, &ssa_opt_float/1},
      {:ssa_opt_sw, &ssa_opt_sw/1}
    ]

    passes_1(ps, opts)
  end

  defp late_epilogue_passes(opts) do
    ps = [
      {:ssa_opt_live, &ssa_opt_live/1},
      {:ssa_opt_bsm, &ssa_opt_bsm/1},
      {:ssa_opt_bsm_shortcut, &ssa_opt_bsm_shortcut/1},
      {:ssa_opt_sink, &ssa_opt_sink/1},
      {:ssa_opt_blockify, &ssa_opt_blockify/1},
      {:ssa_opt_redundant_br, &ssa_opt_redundant_br/1},
      {:ssa_opt_merge_blocks, &ssa_opt_merge_blocks/1},
      {:ssa_opt_bs_ensure, &ssa_opt_bs_ensure/1},
      {:ssa_opt_try, &ssa_opt_try/1},
      {:ssa_opt_get_tuple_element, &ssa_opt_get_tuple_element/1},
      {:ssa_opt_tail_literals, &ssa_opt_tail_literals/1},
      {:ssa_opt_trim_unreachable, &ssa_opt_trim_unreachable/1},
      {:ssa_opt_unfold_literals, &ssa_opt_unfold_literals/1},
      {:ssa_opt_ranges, &ssa_opt_ranges/1}
    ]

    passes_1(ps, opts)
  end

  defp passes_1(ps, opts0) do
    negations =
      for {n, _} <- ps do
        {:erlang.list_to_atom(~c"no_" ++ :erlang.atom_to_list(n)), n}
      end

    expansions = [{:no_bs_match, [:no_ssa_opt_bs_ensure, :no_bs_match]}]

    opts =
      :proplists.normalize(
        opts0,
        [{:expand, expansions}, {:negations, negations}]
      )

    for {name, _} = p <- ps do
      case :proplists.get_value(name, opts, true) do
        true ->
          p

        false ->
          {noName, ^name} = keyfind(name, 2, negations)

          {noName,
           fn s ->
             s
           end}
      end
    end
  end

  defp build_func_db(r_b_module(body: fs, attributes: attr, exports: exports0)) do
    exports = fdb_exports(attr, exports0)

    try do
      fdb_fs(fs, exports, %{})
    catch
      :load_nif ->
        %{}
    end
  end

  defp fdb_exports([{:on_load, l} | attrs], exports) do
    fdb_exports(attrs, flatten(l) ++ exports)
  end

  defp fdb_exports([_Attr | attrs], exports) do
    fdb_exports(attrs, exports)
  end

  defp fdb_exports([], exports) do
    :gb_sets.from_list(exports)
  end

  defp fdb_fs([r_b_function(args: args, bs: bs) = f | fs], exports, funcDb0) do
    id = get_func_id(f)
    r_b_local(name: r_b_literal(val: name), arity: arity) = id
    exported = :gb_sets.is_element({name, arity}, exports)
    argTypes = duplicate(length(args), %{})

    funcDb1 =
      case funcDb0 do
        %{^id => info} ->
          %{funcDb0 | id => r_func_info(info, exported: exported, arg_types: argTypes)}

        %{} ->
          Map.put(
            funcDb0,
            id,
            r_func_info(
              exported: exported,
              arg_types: argTypes
            )
          )
      end

    rPO = :beam_ssa.rpo(bs)

    funcDb =
      :beam_ssa.fold_blocks(
        fn _L, r_b_blk(is: is), funcDb ->
          fdb_is(is, id, funcDb)
        end,
        rPO,
        funcDb1,
        bs
      )

    fdb_fs(fs, exports, funcDb)
  end

  defp fdb_fs([], _Exports, funcDb) do
    funcDb
  end

  defp fdb_is([r_b_set(op: :call, args: [r_b_local() = callee | _]) | is], caller, funcDb) do
    fdb_is(is, caller, fdb_update(caller, callee, funcDb))
  end

  defp fdb_is(
         [
           r_b_set(
             op: :call,
             args: [
               r_b_remote(mod: r_b_literal(val: :erlang), name: r_b_literal(val: :load_nif)),
               _Path,
               _LoadInfo
             ]
           )
           | _Is
         ],
         _Caller,
         _FuncDb
       ) do
    throw(:load_nif)
  end

  defp fdb_is([r_b_set(op: makeFun, args: [r_b_local() = callee | _]) | is], caller, funcDb)
       when makeFun === :make_fun or
              makeFun === :old_make_fun do
    fdb_is(is, caller, fdb_update(caller, callee, funcDb))
  end

  defp fdb_is([_ | is], caller, funcDb) do
    fdb_is(is, caller, funcDb)
  end

  defp fdb_is([], _Caller, funcDb) do
    funcDb
  end

  defp fdb_update(caller, callee, funcDb) do
    callerVertex = :maps.get(caller, funcDb, r_func_info())
    calleeVertex = :maps.get(callee, funcDb, r_func_info())

    calls =
      :ordsets.add_element(
        callee,
        r_func_info(callerVertex, :out)
      )

    calledBy =
      :ordsets.add_element(
        caller,
        r_func_info(calleeVertex, :in)
      )

    Map.merge(funcDb, %{
      caller => r_func_info(callerVertex, out: calls),
      callee => r_func_info(calleeVertex, in: calledBy)
    })
  end

  defp get_call_order_po(stMap, funcDb) when is_map(funcDb) do
    order = gco_po(funcDb)

    order ++
      sort(
        for k <- :maps.keys(stMap),
            not :erlang.is_map_key(k, funcDb) do
          k
        end
      )
  end

  defp gco_po(funcDb) do
    all = sort(:maps.keys(funcDb))
    {rPO, _} = gco_rpo(all, funcDb, :sets.new([{:version, 2}]), [])
    reverse(rPO)
  end

  defp gco_rpo([id | ids], funcDb, seen0, acc0) do
    case :sets.is_element(id, seen0) do
      true ->
        gco_rpo(ids, funcDb, seen0, acc0)

      false ->
        r_func_info(out: successors) = :erlang.map_get(id, funcDb)
        seen1 = :sets.add_element(id, seen0)
        {acc, seen} = gco_rpo(successors, funcDb, seen1, acc0)
        gco_rpo(ids, funcDb, seen, [id | acc])
    end
  end

  defp gco_rpo([], _, seen, acc) do
    {acc, seen}
  end

  defp ssa_opt_dead({r_opt_st(ssa: linear) = st, funcDb}) do
    {r_opt_st(st, ssa: :beam_ssa_dead.opt(linear)), funcDb}
  end

  defp ssa_opt_linearize({r_opt_st(ssa: blocks) = st, funcDb}) do
    {r_opt_st(st, ssa: :beam_ssa.linearize(blocks)), funcDb}
  end

  defp ssa_opt_type_continue({r_opt_st(ssa: linear0, args: args, anno: anno) = st0, funcDb0}) do
    {linear, funcDb} = :beam_ssa_type.opt_continue(linear0, args, anno, funcDb0)
    {r_opt_st(st0, ssa: linear), funcDb}
  end

  defp ssa_opt_type_finish({r_opt_st(args: args, anno: anno0) = st0, funcDb0}) do
    {anno, funcDb} = :beam_ssa_type.opt_finish(args, anno0, funcDb0)
    {r_opt_st(st0, anno: anno), funcDb}
  end

  defp ssa_opt_blockify({r_opt_st(ssa: linear) = st, funcDb}) do
    {r_opt_st(st, ssa: :maps.from_list(linear)), funcDb}
  end

  defp ssa_opt_trim_unreachable({r_opt_st(ssa: blocks) = st, funcDb}) do
    {r_opt_st(st, ssa: :beam_ssa.trim_unreachable(blocks)), funcDb}
  end

  defp ssa_opt_merge_blocks({r_opt_st(ssa: blocks0) = st, funcDb}) do
    rPO = :beam_ssa.rpo(blocks0)
    blocks = :beam_ssa.merge_blocks(rPO, blocks0)
    {r_opt_st(st, ssa: blocks), funcDb}
  end

  defp ssa_opt_ranges({r_opt_st(ssa: blocks) = st, funcDb}) do
    {r_opt_st(st, ssa: :beam_ssa_type.opt_ranges(blocks)), funcDb}
  end

  defp ssa_opt_split_blocks({r_opt_st(ssa: blocks0, cnt: count0) = st, funcDb}) do
    p = fn
      r_b_set(op: {:bif, :element}) ->
        true

      r_b_set(op: :call) ->
        true

      r_b_set(op: :bs_init_writable) ->
        true

      r_b_set(op: :make_fun) ->
        true

      r_b_set(op: :old_make_fun) ->
        true

      _ ->
        false
    end

    rPO = :beam_ssa.rpo(blocks0)
    {blocks, count} = :beam_ssa.split_blocks(rPO, p, blocks0, count0)
    {r_opt_st(st, ssa: blocks, cnt: count), funcDb}
  end

  defp ssa_opt_coalesce_phis({r_opt_st(ssa: blocks0) = st, funcDb})
       when is_map(blocks0) do
    ls = :beam_ssa.rpo(blocks0)
    blocks = c_phis_1(ls, blocks0)
    {r_opt_st(st, ssa: blocks), funcDb}
  end

  defp c_phis_1([l | ls], blocks0) do
    case :erlang.map_get(l, blocks0) do
      r_b_blk(is: [r_b_set(op: :phi) | _]) = blk ->
        blocks = c_phis_2(l, blk, blocks0)
        c_phis_1(ls, blocks)

      r_b_blk() ->
        c_phis_1(ls, blocks0)
    end
  end

  defp c_phis_1([], blocks) do
    blocks
  end

  defp c_phis_2(l, r_b_blk(is: is0) = blk0, blocks0) do
    case c_phis_args(is0, blocks0) do
      :none ->
        blocks0

      {_, _, preds} = info ->
        is = c_rewrite_phis(is0, info)
        blk = r_b_blk(blk0, is: is)
        blocks = %{blocks0 | l => blk}
        c_fix_branches(preds, l, blocks)
    end
  end

  defp c_phis_args([r_b_set(op: :phi, args: args0) | is], blocks) do
    case c_phis_args_1(args0, blocks) do
      :none ->
        c_phis_args(is, blocks)

      res ->
        res
    end
  end

  defp c_phis_args(_, _Blocks) do
    :none
  end

  defp c_phis_args_1([{var, pred} | as], blocks) do
    case c_get_pred_vars(var, pred, blocks) do
      :none ->
        c_phis_args_1(as, blocks)

      result ->
        result
    end
  end

  defp c_phis_args_1([], _Blocks) do
    :none
  end

  defp c_get_pred_vars(var, pred, blocks) do
    case :erlang.map_get(pred, blocks) do
      r_b_blk(is: [r_b_set(op: :phi, dst: ^var, args: args)]) ->
        {var, pred, args}

      r_b_blk() ->
        :none
    end
  end

  defp c_rewrite_phis([r_b_set(op: :phi, args: args0) = i | is], info) do
    args = c_rewrite_phi(args0, info)
    [r_b_set(i, args: args) | c_rewrite_phis(is, info)]
  end

  defp c_rewrite_phis(is, _Info) do
    is
  end

  defp c_rewrite_phi([{var, pred} | as], {var, pred, values}) do
    values ++ as
  end

  defp c_rewrite_phi([{value, pred} | as], {_, pred, values}) do
    for {_, p} <- values do
      {value, p}
    end ++ as
  end

  defp c_rewrite_phi([a | as], info) do
    [a | c_rewrite_phi(as, info)]
  end

  defp c_rewrite_phi([], _Info) do
    []
  end

  defp c_fix_branches([{_, pred} | as], l, blocks0) do
    r_b_blk(last: last0) = blk0 = :erlang.map_get(pred, blocks0)
    r_b_br(bool: r_b_literal(val: true)) = last0
    last = r_b_br(last0, bool: r_b_literal(val: true), succ: l, fail: l)
    blk = r_b_blk(blk0, last: last)
    blocks = %{blocks0 | pred => blk}
    c_fix_branches(as, l, blocks)
  end

  defp c_fix_branches([], _, blocks) do
    blocks
  end

  defp ssa_opt_tail_phis({r_opt_st(ssa: sSA0, cnt: count0) = st, funcDb}) do
    {sSA, count} = opt_tail_phis(sSA0, count0)
    {r_opt_st(st, ssa: sSA, cnt: count), funcDb}
  end

  defp opt_tail_phis(blocks, count) when is_map(blocks) do
    opt_tail_phis(:maps.values(blocks), blocks, count)
  end

  defp opt_tail_phis(linear0, count0) when is_list(linear0) do
    blocks0 = :maps.from_list(linear0)
    {blocks, count} = opt_tail_phis(blocks0, count0)
    {:beam_ssa.linearize(blocks), count}
  end

  defp opt_tail_phis([r_b_blk(is: is0, last: last) | bs], blocks0, count0) do
    case {is0, last} do
      {[r_b_set(op: :phi, args: [_, _ | _]) | _], r_b_ret(arg: r_b_var()) = ret} ->
        {phis, is} =
          splitwith(
            fn r_b_set(op: op) ->
              op === :phi
            end,
            is0
          )

        case suitable_tail_ops(is) do
          true ->
            {blocks, count} = opt_tail_phi(phis, is, ret, blocks0, count0)
            opt_tail_phis(bs, blocks, count)

          false ->
            opt_tail_phis(bs, blocks0, count0)
        end

      {_, _} ->
        opt_tail_phis(bs, blocks0, count0)
    end
  end

  defp opt_tail_phis([], blocks, count) do
    {blocks, count}
  end

  defp opt_tail_phi(phis0, is, ret, blocks0, count0) do
    phis = rel2fam(reduce_phis(phis0))

    {blocks, count, cost} =
      foldl(
        fn phiArg, acc ->
          opt_tail_phi_arg(phiArg, is, ret, acc)
        end,
        {blocks0, count0, 0},
        phis
      )

    maxCost = length(phis) * 3 + 2

    cond do
      cost <= maxCost ->
        {blocks, count}

      true ->
        {blocks0, count0}
    end
  end

  defp reduce_phis([r_b_set(dst: phiDst, args: phiArgs) | is]) do
    for {val, l} <- phiArgs do
      {l, {phiDst, val}}
    end ++ reduce_phis(is)
  end

  defp reduce_phis([]) do
    []
  end

  defp opt_tail_phi_arg({predL, sub0}, is0, ret0, {blocks0, count0, cost0}) do
    blk0 = :erlang.map_get(predL, blocks0)
    r_b_blk(is: isPrefix, last: r_b_br(succ: next, fail: next)) = blk0
    sub1 = :maps.from_list(sub0)
    {is1, count, sub} = new_names(is0, sub1, count0, [])

    is2 =
      for i <- is1 do
        sub(i, sub)
      end

    cost = build_cost(is2, cost0)
    is = isPrefix ++ is2
    ret = sub(ret0, sub)
    blk = r_b_blk(blk0, is: is, last: ret)
    blocks = %{blocks0 | predL => blk}
    {blocks, count, cost}
  end

  defp new_names([r_b_set(dst: dst) = i | is], sub0, count0, acc) do
    {newDst, count} = new_var(dst, count0)
    sub = Map.put(sub0, dst, newDst)
    new_names(is, sub, count, [r_b_set(i, dst: newDst) | acc])
  end

  defp new_names([], sub, count, acc) do
    {reverse(acc), count, sub}
  end

  defp suitable_tail_ops(is) do
    all(
      fn r_b_set(op: op) ->
        is_suitable_tail_op(op)
      end,
      is
    )
  end

  defp is_suitable_tail_op({:bif, _}) do
    true
  end

  defp is_suitable_tail_op(:put_list) do
    true
  end

  defp is_suitable_tail_op(:put_tuple) do
    true
  end

  defp is_suitable_tail_op(_) do
    false
  end

  defp build_cost([r_b_set(op: :put_list, args: args) | is], cost) do
    case are_all_literals(args) do
      true ->
        build_cost(is, cost)

      false ->
        build_cost(is, cost + 1)
    end
  end

  defp build_cost([r_b_set(op: :put_tuple, args: args) | is], cost) do
    case are_all_literals(args) do
      true ->
        build_cost(is, cost)

      false ->
        build_cost(is, cost + length(args) + 1)
    end
  end

  defp build_cost([r_b_set(op: {:bif, _}, args: args) | is], cost) do
    case are_all_literals(args) do
      true ->
        build_cost(is, cost)

      false ->
        build_cost(is, cost + 1)
    end
  end

  defp build_cost([], cost) do
    cost
  end

  defp are_all_literals(args) do
    all(
      fn
        r_b_literal() ->
          true

        _ ->
          false
      end,
      args
    )
  end

  defp ssa_opt_element({r_opt_st(ssa: blocks) = st, funcDb}) do
    getEls = collect_element_calls(:beam_ssa.linearize(blocks))
    chains = collect_chains(getEls, [])
    {r_opt_st(st, ssa: swap_element_calls(chains, blocks)), funcDb}
  end

  defp collect_element_calls([{l, r_b_blk(is: is0, last: last)} | bs]) do
    case {is0, last} do
      {[
         r_b_set(
           op: {:bif, :element},
           dst: element,
           args: [r_b_literal(val: n), r_b_var() = tuple]
         ),
         r_b_set(op: {:succeeded, :guard}, dst: bool, args: [element])
       ], r_b_br(bool: bool, succ: succ, fail: fail)} ->
        info = {l, succ, {tuple, fail}, n}
        [info | collect_element_calls(bs)]

      {_, _} ->
        collect_element_calls(bs)
    end
  end

  defp collect_element_calls([]) do
    []
  end

  defp collect_chains(
         [{this, _, v, _} = el | els],
         [{_, this, v, _} | _] = chain
       ) do
    collect_chains(els, [el | chain])
  end

  defp collect_chains([el | els], [_, _ | _] = chain) do
    [chain | collect_chains(els, [el])]
  end

  defp collect_chains([el | els], _Chain) do
    collect_chains(els, [el])
  end

  defp collect_chains([], [_, _ | _] = chain) do
    [chain]
  end

  defp collect_chains([], _) do
    []
  end

  defp swap_element_calls(
         [[{l, _, _, n} | _] = chain | chains],
         blocks0
       ) do
    blocks = swap_element_calls_1(chain, {n, l}, blocks0)
    swap_element_calls(chains, blocks)
  end

  defp swap_element_calls([], blocks) do
    blocks
  end

  defp swap_element_calls_1([{l1, _, _, n1}], {n2, l2}, blocks)
       when n2 > n1 do
    %{^l1 => blk1, ^l2 => blk2} = blocks
    [r_b_set(dst: dst1) = getEl1, succ1] = r_b_blk(blk1, :is)
    [r_b_set(dst: dst2) = getEl2, succ2] = r_b_blk(blk2, :is)
    is1 = [getEl2, r_b_set(succ1, args: [dst2])]
    is2 = [getEl1, r_b_set(succ2, args: [dst1])]
    %{blocks | l1 => r_b_blk(blk1, is: is1), l2 => r_b_blk(blk2, is: is2)}
  end

  defp swap_element_calls_1([{l, _, _, n1} | els], {n2, _}, blocks)
       when n1 > n2 do
    swap_element_calls_1(els, {n2, l}, blocks)
  end

  defp swap_element_calls_1([_ | els], highest, blocks) do
    swap_element_calls_1(els, highest, blocks)
  end

  defp swap_element_calls_1([], _, blocks) do
    blocks
  end

  defp ssa_opt_record({r_opt_st(ssa: linear) = st, funcDb}) do
    blocks = :maps.from_list(linear)
    {r_opt_st(st, ssa: record_opt(linear, blocks)), funcDb}
  end

  defp record_opt(
         [{l, r_b_blk(is: is0, last: last) = blk0} | bs],
         blocks
       ) do
    is = record_opt_is(is0, last, blocks)
    blk = r_b_blk(blk0, is: is)
    [{l, blk} | record_opt(bs, blocks)]
  end

  defp record_opt([], _Blocks) do
    []
  end

  defp record_opt_is(
         [r_b_set(op: {:bif, :is_tuple}, dst: bool, args: [tuple]) = set],
         last,
         blocks
       ) do
    case is_tagged_tuple(tuple, bool, last, blocks) do
      {:yes, size, tag} ->
        args = [tuple, size, tag]
        [r_b_set(set, op: :is_tagged_tuple, args: args)]

      :no ->
        [set]
    end
  end

  defp record_opt_is([i | is] = is0, r_b_br(bool: bool) = last, blocks) do
    case is_tagged_tuple_1(is0, last, blocks) do
      {:yes, _Fail, tuple, arity, tag} ->
        args = [tuple, arity, tag]
        [r_b_set(i, op: :is_tagged_tuple, dst: bool, args: args)]

      :no ->
        [i | record_opt_is(is, last, blocks)]
    end
  end

  defp record_opt_is([i | is], last, blocks) do
    [i | record_opt_is(is, last, blocks)]
  end

  defp record_opt_is([], _Last, _Blocks) do
    []
  end

  defp is_tagged_tuple(
         r_b_var() = tuple,
         bool,
         r_b_br(bool: bool, succ: succ, fail: fail),
         blocks
       ) do
    r_b_blk(is: is, last: last) = :erlang.map_get(succ, blocks)

    case is_tagged_tuple_1(is, last, blocks) do
      {:yes, ^fail, ^tuple, arity, tag} ->
        {:yes, arity, tag}

      _ ->
        :no
    end
  end

  defp is_tagged_tuple(_, _, _, _) do
    :no
  end

  defp is_tagged_tuple_1(is, last, blocks) do
    case {is, last} do
      {[
         r_b_set(op: {:bif, :tuple_size}, dst: arityVar, args: [r_b_var() = tuple]),
         r_b_set(
           op: {:bif, :"=:="},
           dst: bool,
           args: [arityVar, r_b_literal(val: arityVal) = arity]
         )
       ], r_b_br(bool: bool, succ: succ, fail: fail)}
      when is_integer(arityVal) ->
        succBlk = :erlang.map_get(succ, blocks)

        case is_tagged_tuple_2(succBlk, tuple, fail) do
          :no ->
            :no

          {:yes, tag} ->
            {:yes, fail, tuple, arity, tag}
        end

      _ ->
        :no
    end
  end

  defp is_tagged_tuple_2(
         r_b_blk(
           is: is,
           last: r_b_br(bool: r_b_var() = bool, fail: fail)
         ),
         tuple,
         fail
       ) do
    is_tagged_tuple_3(is, bool, tuple)
  end

  defp is_tagged_tuple_2(r_b_blk(), _, _) do
    :no
  end

  defp is_tagged_tuple_3(
         [
           r_b_set(
             op: :get_tuple_element,
             dst: tagVar,
             args: [r_b_var() = tuple, r_b_literal(val: 0)]
           )
           | is
         ],
         bool,
         tuple
       ) do
    is_tagged_tuple_4(is, bool, tagVar)
  end

  defp is_tagged_tuple_3([_ | is], bool, tuple) do
    is_tagged_tuple_3(is, bool, tuple)
  end

  defp is_tagged_tuple_3([], _, _) do
    :no
  end

  defp is_tagged_tuple_4(
         [
           r_b_set(
             op: {:bif, :"=:="},
             dst: bool,
             args: [r_b_var() = tagVar, r_b_literal(val: tagVal) = tag]
           )
         ],
         bool,
         tagVar
       )
       when is_atom(tagVal) do
    {:yes, tag}
  end

  defp is_tagged_tuple_4([_ | is], bool, tagVar) do
    is_tagged_tuple_4(is, bool, tagVar)
  end

  defp is_tagged_tuple_4([], _, _) do
    :no
  end

  defp ssa_opt_update_tuple({r_opt_st(ssa: linear0) = st, funcDb}) do
    {r_opt_st(st, ssa: update_tuple_opt(linear0, %{})), funcDb}
  end

  defp update_tuple_opt([{l, r_b_blk(is: is0) = b} | bs], setOps0) do
    {is, setOps} = update_tuple_opt_is(is0, setOps0, [])
    [{l, r_b_blk(b, is: is)} | update_tuple_opt(bs, setOps)]
  end

  defp update_tuple_opt([], _SetOps) do
    []
  end

  defp update_tuple_opt_is(
         [
           r_b_set(
             op: :call,
             dst: dst,
             args: [
               r_b_remote(
                 mod: r_b_literal(val: :erlang),
                 name: r_b_literal(val: :setelement)
               ),
               r_b_literal(val: n) = index,
               src,
               value
             ]
           ) = i0
           | is
         ],
         setOps0,
         acc
       )
       when is_integer(n) and n >= 1 do
    setOps1 = Map.put(setOps0, dst, {src, index, value})
    setOps = :maps.remove(value, setOps1)
    args = update_tuple_merge(src, setOps, [index, value], :sets.new([{:version, 2}]))
    i = r_b_set(i0, op: :update_tuple, dst: dst, args: args)
    update_tuple_opt_is(is, setOps, [i | acc])
  end

  defp update_tuple_opt_is([r_b_set(op: op) = i | is], setOps0, acc) do
    case {op, :beam_ssa.clobbers_xregs(i)} do
      {_, true} ->
        update_tuple_opt_is(is, %{}, [i | acc])

      {{:succeeded, _}, false} ->
        update_tuple_opt_is(is, setOps0, [i | acc])

      {_, false} ->
        setOps = :maps.without(:beam_ssa.used(i), setOps0)
        update_tuple_opt_is(is, setOps, [i | acc])
    end
  end

  defp update_tuple_opt_is([], setOps, acc) do
    {reverse(acc), setOps}
  end

  defp update_tuple_merge(src, setOps, updates0, seen0) do
    case setOps do
      %{^src => {ancestor, index, value}} ->
        updates =
          case :sets.is_element(index, seen0) do
            false ->
              [index, value | updates0]

            true ->
              updates0
          end

        seen = :sets.add_element(index, seen0)
        update_tuple_merge(ancestor, setOps, updates, seen)

      %{} ->
        [src | updates0]
    end
  end

  defp ssa_opt_cse({r_opt_st(ssa: linear) = st, funcDb}) do
    m = %{0 => %{}, 1 => %{}}
    {r_opt_st(st, ssa: cse(linear, %{}, m)), funcDb}
  end

  defp cse([{l, r_b_blk(is: is0, last: last0) = blk} | bs], sub0, m0) do
    es0 = :erlang.map_get(l, m0)
    {is1, es, sub} = cse_is(is0, es0, sub0, [])
    last = sub(last0, sub)
    m = cse_successors(is1, blk, es, m0)
    is = reverse(is1)
    [{l, r_b_blk(blk, is: is, last: last)} | cse(bs, sub, m)]
  end

  defp cse([], _, _) do
    []
  end

  defp cse_successors_1([l | ls], es0, m) do
    case m do
      %{^l => es1} when map_size(es1) === 0 ->
        cse_successors_1(ls, es0, m)

      %{^l => es1} ->
        es = cse_intersection(es0, es1)
        cse_successors_1(ls, es0, %{m | l => es})

      %{} ->
        cse_successors_1(ls, es0, Map.put(m, l, es0))
    end
  end

  defp cse_successors_1([], _, m) do
    m
  end

  defp cse_intersection(m1, m2) do
    cond do
      map_size(m1) < map_size(m2) ->
        cse_intersection_1(:maps.to_list(m1), m2, m1)

      true ->
        cse_intersection_1(:maps.to_list(m2), m1, m2)
    end
  end

  defp cse_intersection_1([{key, value} | kVs], m, result) do
    case m do
      %{^key => ^value} ->
        cse_intersection_1(kVs, m, result)

      %{} ->
        cse_intersection_1(kVs, m, :maps.remove(key, result))
    end
  end

  defp cse_intersection_1([], _, result) do
    result
  end

  defp cse_is(
         [
           r_b_set(op: {:succeeded, _}, dst: bool, args: [src]) = i0
           | is
         ],
         es,
         sub0,
         acc
       ) do
    i = sub(i0, sub0)

    case i do
      r_b_set(args: [^src]) ->
        cse_is(is, es, sub0, [i | acc])

      r_b_set() ->
        sub = Map.put(sub0, bool, r_b_literal(val: true))
        cse_is(is, es, sub, acc)
    end
  end

  defp cse_is(
         [
           r_b_set(op: :put_map, dst: dst, args: [_Kind, map | _]) = i0
           | is
         ],
         es0,
         sub0,
         acc
       ) do
    i1 = sub(i0, sub0)
    {:ok, exprKey} = cse_expr(i1)

    case es0 do
      %{^exprKey => prevPutMap} ->
        sub = Map.put(sub0, dst, prevPutMap)
        cse_is(is, es0, sub, acc)

      %{^map => putMap} ->
        case combine_put_maps(putMap, i1) do
          :none ->
            es1 = Map.put(es0, exprKey, dst)
            es = cse_add_inferred_exprs(i1, es1)
            cse_is(is, es, sub0, [i1 | acc])

          i ->
            es1 = Map.put(es0, exprKey, dst)
            es = cse_add_inferred_exprs(i1, es1)
            cse_is(is, es, sub0, [i | acc])
        end

      %{} ->
        es1 = Map.put(es0, exprKey, dst)
        es = cse_add_inferred_exprs(i1, es1)
        cse_is(is, es, sub0, [i1 | acc])
    end
  end

  defp cse_is([r_b_set(dst: dst) = i0 | is], es0, sub0, acc) do
    i = sub(i0, sub0)

    case :beam_ssa.clobbers_xregs(i) do
      true ->
        cse_is(is, %{}, sub0, [i | acc])

      false ->
        case cse_expr(i) do
          :none ->
            cse_is(is, es0, sub0, [i | acc])

          {:ok, exprKey} ->
            case es0 do
              %{^exprKey => src} ->
                sub = Map.put(sub0, dst, src)
                cse_is(is, es0, sub, acc)

              %{} ->
                es1 = Map.put(es0, exprKey, dst)
                es = cse_add_inferred_exprs(i, es1)
                cse_is(is, es, sub0, [i | acc])
            end
        end
    end
  end

  defp cse_is([], es, sub, acc) do
    {acc, es, sub}
  end

  defp cse_add_inferred_exprs(
         r_b_set(op: :put_list, dst: list, args: [hd, tl]),
         es
       ) do
    Map.merge(es, %{{:get_hd, [list]} => hd, {:get_tl, [list]} => tl})
  end

  defp cse_add_inferred_exprs(
         r_b_set(op: :put_tuple, dst: tuple, args: [e1, e2 | _]),
         es
       ) do
    Map.merge(es, %{
      {:get_tuple_element, [tuple, r_b_literal(val: 0)]} => e1,
      {:get_tuple_element, [tuple, r_b_literal(val: 1)]} => e2
    })
  end

  defp cse_add_inferred_exprs(
         r_b_set(op: {:bif, :element}, dst: e, args: [r_b_literal(val: n), tuple]),
         es
       )
       when is_integer(n) do
    Map.put(es, {:get_tuple_element, [tuple, r_b_literal(val: n - 1)]}, e)
  end

  defp cse_add_inferred_exprs(
         r_b_set(op: {:bif, :hd}, dst: hd, args: [list]),
         es
       ) do
    Map.put(es, {:get_hd, [list]}, hd)
  end

  defp cse_add_inferred_exprs(
         r_b_set(op: {:bif, :tl}, dst: tl, args: [list]),
         es
       ) do
    Map.put(es, {:get_tl, [list]}, tl)
  end

  defp cse_add_inferred_exprs(
         r_b_set(op: {:bif, :map_get}, dst: value, args: [key, map]),
         es
       ) do
    Map.put(es, {:get_map_element, [map, key]}, value)
  end

  defp cse_add_inferred_exprs(
         r_b_set(op: :put_map, dst: map, args: [_, _ | args]) = i,
         es0
       ) do
    es = cse_add_map_get(args, map, es0)
    Map.put(es, map, i)
  end

  defp cse_add_inferred_exprs(_, es) do
    es
  end

  defp cse_add_map_get([key, value | t], map, es0) do
    es = Map.put(es0, {:get_map_element, [map, key]}, value)
    cse_add_map_get(t, map, es)
  end

  defp cse_add_map_get([], _, es) do
    es
  end

  defp cse_expr(r_b_set(op: op, args: args) = i) do
    case cse_suitable(i) do
      true ->
        {:ok, {op, args}}

      false ->
        :none
    end
  end

  defp cse_suitable(r_b_set(op: :get_hd)) do
    true
  end

  defp cse_suitable(r_b_set(op: :get_tl)) do
    true
  end

  defp cse_suitable(r_b_set(op: :put_list)) do
    true
  end

  defp cse_suitable(r_b_set(op: :get_tuple_element)) do
    true
  end

  defp cse_suitable(r_b_set(op: :put_tuple)) do
    true
  end

  defp cse_suitable(r_b_set(op: :get_map_element)) do
    true
  end

  defp cse_suitable(r_b_set(op: :put_map)) do
    true
  end

  defp cse_suitable(r_b_set(op: {:bif, :tuple_size})) do
    false
  end

  defp cse_suitable(r_b_set(anno: anno, op: {:bif, name}, args: args)) do
    arity = length(args)

    not (:erlang.is_map_key(
           :float_op,
           anno
         ) or
           :erl_internal.new_type_test(
             name,
             arity
           ) or
           :erl_internal.comp_op(
             name,
             arity
           ) or
           :erl_internal.bool_op(
             name,
             arity
           ))
  end

  defp cse_suitable(r_b_set()) do
    false
  end

  defp combine_put_maps(
         r_b_set(
           dst: prev,
           args: [r_b_literal(val: :assoc), map | args1]
         ),
         r_b_set(args: [r_b_literal(val: :assoc), prev | args2]) = i
       ) do
    case are_map_keys_literals(args1) and are_map_keys_literals(args2) do
      true ->
        args = combine_put_map_args(args1, args2)
        r_b_set(i, args: [r_b_literal(val: :assoc), map | args])

      false ->
        :none
    end
  end

  defp combine_put_maps(r_b_set(), r_b_set()) do
    :none
  end

  defp combine_put_map_args(args1, args2) do
    keys =
      :sets.from_list(
        get_map_keys(args2),
        [{:version, 2}]
      )

    combine_put_map_args_1(args1, args2, keys)
  end

  defp combine_put_map_args_1([key, value | t], tail, keys) do
    case :sets.is_element(key, keys) do
      true ->
        combine_put_map_args_1(t, tail, keys)

      false ->
        [key, value | combine_put_map_args_1(t, tail, keys)]
    end
  end

  defp combine_put_map_args_1([], tail, _Keys) do
    tail
  end

  defp get_map_keys([key, _ | t]) do
    [key | get_map_keys(t)]
  end

  defp get_map_keys([]) do
    []
  end

  defp are_map_keys_literals([r_b_literal(), _Value | args]) do
    are_map_keys_literals(args)
  end

  defp are_map_keys_literals([r_b_var() | _]) do
    false
  end

  defp are_map_keys_literals([]) do
    true
  end

  Record.defrecord(:r_fs, :fs,
    regs: %{},
    non_guards: :undefined,
    bs: :undefined,
    preds: :undefined
  )

  defp ssa_opt_float({r_opt_st(ssa: linear0, cnt: count0) = st, funcDb}) do
    nonGuards = non_guards(linear0)
    blocks = :maps.from_list(linear0)
    preds = :beam_ssa.predecessors(blocks)
    fs = r_fs(non_guards: nonGuards, bs: blocks, preds: preds)
    {linear, count} = float_opt(linear0, count0, fs)
    {r_opt_st(st, ssa: linear, cnt: count), funcDb}
  end

  defp float_can_optimize_blk(
         r_b_blk(last: r_b_br(bool: r_b_var(), fail: f)),
         r_fs(non_guards: nonGuards)
       ) do
    :gb_sets.is_member(f, nonGuards)
  end

  defp float_can_optimize_blk(r_b_blk(), r_fs()) do
    false
  end

  defp float_opt([{l, blk} | bs0], count0, fs) do
    case float_can_optimize_blk(blk, fs) do
      true ->
        float_opt_1(l, blk, bs0, count0, fs)

      false ->
        {bs, count} = float_opt(bs0, count0, fs)
        {[{l, blk} | bs], count}
    end
  end

  defp float_opt([], count, _Fs) do
    {[], count}
  end

  defp float_opt_1(l, r_b_blk(is: is0) = blk0, bs0, count0, fs0) do
    case float_opt_is(is0, fs0, count0, []) do
      {is1, fs1, count1} ->
        {flush, blk, fs, count2} = float_maybe_flush(blk0, fs1, count1)
        {blks, count3} = float_fixup_conv(l, is1, blk, count2)
        {bs, count} = float_opt(bs0, count3, fs)
        {blks ++ flush ++ bs, count}

      :none ->
        {bs, count} = float_opt(bs0, count0, fs0)
        {[{l, blk0} | bs], count}
    end
  end

  defp float_fixup_conv(l, is, blk, count0) do
    split = float_split_conv(is, blk)
    {blks, count} = float_number(split, l, count0)
    r_b_blk(last: r_b_br(bool: r_b_var(), fail: fail)) = blk
    float_conv(blks, fail, count)
  end

  defp float_split_conv(is0, blk) do
    br = r_b_br(bool: r_b_literal(val: true), succ: 0, fail: 0)

    case splitwith(
           fn r_b_set(op: op) ->
             op !== {:float, :convert}
           end,
           is0
         ) do
      {is, []} ->
        [r_b_blk(blk, is: is)]

      {[_ | _] = is1, [r_b_set(op: {:float, :convert}) = conv | is2]} ->
        [
          r_b_blk(is: is1, last: br),
          r_b_blk(is: [conv], last: br)
          | float_split_conv(is2, blk)
        ]

      {[], [r_b_set(op: {:float, :convert}) = conv | is1]} ->
        [r_b_blk(is: [conv], last: br) | float_split_conv(is1, blk)]
    end
  end

  defp float_number(bs0, firstL, count0) do
    {[{_, firstBlk} | bs], count} =
      float_number(
        bs0,
        count0
      )

    {[{firstL, firstBlk} | bs], count}
  end

  defp float_number([b], count) do
    {[{count, b}], count}
  end

  defp float_number([b | bs0], count0) do
    next = count0 + 1
    {bs, count} = float_number(bs0, next)
    br = r_b_br(bool: r_b_literal(val: true), succ: next, fail: next)
    {[{count0, r_b_blk(b, last: br)} | bs], count}
  end

  defp float_conv([{l, r_b_blk(is: is0, last: last) = blk0} | bs0], fail, count0) do
    case is0 do
      [r_b_set(op: {:float, :convert}) = conv] ->
        {bool, count1} = new_var(:"@ssa_bool", count0)
        succeeded = r_b_set(op: {:succeeded, :body}, dst: bool, args: [r_b_set(conv, :dst)])
        is = [conv, succeeded]
        br = r_b_br(last, bool: bool, fail: fail)
        blk = r_b_blk(blk0, is: is, last: br)
        {bs, count} = float_conv(bs0, fail, count1)
        {[{l, blk} | bs], count}

      [_ | _] ->
        {bs, count} = float_conv(bs0, fail, count0)
        {[{l, blk0} | bs], count}
    end
  end

  defp float_conv([], _, count) do
    {[], count}
  end

  defp float_maybe_flush(blk0, fs0, count0) do
    r_b_blk(last: r_b_br(bool: r_b_var(), succ: succ) = br) = blk0

    case float_safe_to_skip_flush(succ, fs0) do
      true ->
        {[], blk0, fs0, count0}

      false ->
        flushL = count0
        count = count0 + 1
        blk = r_b_blk(blk0, last: r_b_br(br, succ: flushL))
        flushIs = float_flush_regs(fs0)
        flushBr = r_b_br(bool: r_b_literal(val: true), succ: succ, fail: succ)
        flushBlk = r_b_blk(is: flushIs, last: flushBr)
        fs = r_fs(fs0, regs: %{})
        flushBs = [{flushL, flushBlk}]
        {flushBs, blk, fs, count}
    end
  end

  defp float_safe_to_skip_flush(l, r_fs(bs: blocks, preds: preds) = fs) do
    r_b_blk(is: is) = blk = :erlang.map_get(l, blocks)

    case preds do
      %{^l => [_]} ->
        float_can_optimize_blk(
          blk,
          fs
        ) and float_optimizable_is(is)

      %{} ->
        false
    end
  end

  defp float_optimizable_is([r_b_set(anno: %{float_op: _}) | _]) do
    true
  end

  defp float_optimizable_is([r_b_set(op: :get_tuple_element) | is]) do
    float_optimizable_is(is)
  end

  defp float_optimizable_is(_) do
    false
  end

  defp float_opt_is(
         [r_b_set(op: {:succeeded, _}, args: [src]) = i0],
         r_fs(regs: rs) = fs,
         count,
         acc
       ) do
    case rs do
      %{^src => fr} ->
        i = r_b_set(i0, args: [fr])
        {reverse(acc, [i]), fs, count}

      %{} ->
        :none
    end
  end

  defp float_opt_is([r_b_set(anno: anno0) = i0 | is0], fs0, count0, acc) do
    case anno0 do
      %{float_op: fTypes} ->
        argTypes0 = :maps.get(:arg_types, anno0, %{})
        argTypes = float_arg_types(fTypes, 0, argTypes0)
        anno1 = :maps.remove(:float_op, anno0)
        anno = :maps.remove(:arg_types, anno1)
        i1 = r_b_set(i0, anno: anno)
        {is, fs, count} = float_make_op(i1, fTypes, argTypes, fs0, count0)
        float_opt_is(is0, fs, count, reverse(is, acc))

      %{} ->
        float_opt_is(is0, fs0, count0, [i0 | acc])
    end
  end

  defp float_opt_is([], _Fs, _Count, _Acc) do
    :none
  end

  defp float_arg_types([_ | as], index, argTypes) do
    case argTypes do
      %{^index => argType} ->
        [argType | float_arg_types(as, index + 1, argTypes)]

      %{} ->
        [:any | float_arg_types(as, index + 1, argTypes)]
    end
  end

  defp float_arg_types([], _, _) do
    []
  end

  defp float_make_op(
         r_b_set(op: {:bif, op}, dst: dst, args: as0, anno: anno) = i0,
         ts,
         argTypes,
         r_fs(regs: rs0) = fs,
         count0
       ) do
    {as1, rs1, count1} = float_load(as0, ts, argTypes, anno, rs0, count0, [])
    {as, is0} = unzip(as1)
    {frDst, count2} = new_var(:"@fr", count1)
    i = r_b_set(i0, op: {:float, op}, dst: frDst, args: as)
    rs = Map.put(rs1, dst, frDst)
    is = append(is0) ++ [i]
    {is, r_fs(fs, regs: rs), count2}
  end

  defp float_load([a | as], [t | ts], [aT | aTs], anno, rs0, count0, acc) do
    {load, rs, count} = float_reg_arg(a, t, aT, anno, rs0, count0)
    float_load(as, ts, aTs, anno, rs, count, [load | acc])
  end

  defp float_load([], [], [], _Anno, rs, count, acc) do
    {reverse(acc), rs, count}
  end

  defp float_reg_arg(a, t, aT, anno0, rs, count0) do
    case rs do
      %{^a => fr} ->
        {{fr, []}, rs, count0}

      %{} ->
        {dst, count} = new_var(:"@fr_copy", count0)
        i0 = float_load_reg(t, a, dst)

        anno =
          case aT do
            :any ->
              anno0

            _ ->
              Map.put(anno0, :arg_types, %{0 => aT})
          end

        i = r_b_set(i0, anno: anno)
        {{dst, [i]}, Map.put(rs, a, dst), count}
    end
  end

  defp float_load_reg(:convert, r_b_var() = src, dst) do
    r_b_set(op: {:float, :convert}, dst: dst, args: [src])
  end

  defp float_load_reg(:convert, r_b_literal(val: val) = src, dst) do
    try do
      :erlang.float(val)
    catch
      :error, _ ->
        r_b_set(op: {:float, :convert}, dst: dst, args: [src])
    else
      f ->
        r_b_set(op: {:float, :put}, dst: dst, args: [r_b_literal(val: f)])
    end
  end

  defp float_load_reg(:float, src, dst) do
    r_b_set(op: {:float, :put}, dst: dst, args: [src])
  end

  defp float_flush_regs(r_fs(regs: rs)) do
    :maps.fold(
      fn
        _, r_b_var(name: {:"@fr_copy", _}), acc ->
          acc

        dst, fr, acc ->
          [r_b_set(op: {:float, :get}, dst: dst, args: [fr]) | acc]
      end,
      [],
      rs
    )
  end

  defp ssa_opt_live({r_opt_st(ssa: linear0) = st, funcDb}) do
    revLinear = reverse(linear0)
    blocks0 = :maps.from_list(revLinear)
    blocks = live_opt(revLinear, %{}, blocks0)
    linear = :beam_ssa.linearize(blocks)
    {r_opt_st(st, ssa: linear), funcDb}
  end

  defp live_opt([{l, blk0} | bs], liveMap0, blocks) do
    blk1 = :beam_ssa_share.block(blk0, blocks)
    successors = :beam_ssa.successors(blk1)
    live0 = live_opt_succ(successors, l, liveMap0, :sets.new([{:version, 2}]))
    {blk, live} = live_opt_blk(blk1, live0)
    liveMap = live_opt_phis(r_b_blk(blk, :is), l, live, liveMap0)
    live_opt(bs, liveMap, %{blocks | l => blk})
  end

  defp live_opt([], _, acc) do
    acc
  end

  defp live_opt_succ([s | ss], l, liveMap, live0) do
    case liveMap do
      %{{^s, ^l} => live} ->
        live_opt_succ(ss, l, liveMap, :sets.union(live0, live))

      %{^s => live} ->
        live_opt_succ(ss, l, liveMap, :sets.union(live0, live))

      %{} ->
        live_opt_succ(ss, l, liveMap, live0)
    end
  end

  defp live_opt_succ([], _, _, acc) do
    acc
  end

  defp live_opt_blk(r_b_blk(is: is0, last: last) = blk, live0) do
    live1 = list_set_union(:beam_ssa.used(last), live0)
    {is, live} = live_opt_is(reverse(is0), live1, [])
    {r_b_blk(blk, is: is), live}
  end

  defp live_opt_is([r_b_set(op: :phi, dst: dst) = i | is], live0, acc) do
    live = :sets.del_element(dst, live0)

    case :sets.is_element(dst, live0) do
      true ->
        live_opt_is(is, live, [i | acc])

      false ->
        live_opt_is(is, live, acc)
    end
  end

  defp live_opt_is(
         [
           r_b_set(op: {:succeeded, :guard}, dst: succDst, args: [dst]) = succI,
           r_b_set(op: op, dst: dst) = i0 | is
         ],
         live0,
         acc
       ) do
    case {:sets.is_element(succDst, live0), :sets.is_element(dst, live0)} do
      {true, true} ->
        live = :sets.del_element(succDst, live0)
        live_opt_is([i0 | is], live, [succI | acc])

      {true, false} ->
        case op do
          {:bif, :not} ->
            i = r_b_set(i0, op: {:bif, :is_boolean}, dst: succDst)
            live_opt_is([i | is], live0, acc)

          {:bif, :tuple_size} ->
            i = r_b_set(i0, op: {:bif, :is_tuple}, dst: succDst)
            live_opt_is([i | is], live0, acc)

          :get_map_element ->
            i = r_b_set(i0, op: :has_map_field, dst: succDst)
            live_opt_is([i | is], live0, acc)

          _ ->
            live1 = :sets.del_element(succDst, live0)
            live = :sets.add_element(dst, live1)
            live_opt_is([i0 | is], live, [succI | acc])
        end

      {false, true} ->
        live_opt_is([i0 | is], live0, acc)

      {false, false} ->
        live_opt_is(is, live0, acc)
    end
  end

  defp live_opt_is([r_b_set(dst: dst) = i | is], live0, acc) do
    case :sets.is_element(dst, live0) do
      true ->
        live1 = list_set_union(:beam_ssa.used(i), live0)
        live = :sets.del_element(dst, live1)
        live_opt_is(is, live, [i | acc])

      false ->
        case :beam_ssa.no_side_effect(i) do
          true ->
            live_opt_is(is, live0, acc)

          false ->
            live = list_set_union(:beam_ssa.used(i), live0)
            live_opt_is(is, live, [i | acc])
        end
    end
  end

  defp live_opt_is([], live, acc) do
    {acc, live}
  end

  defp ssa_opt_try({r_opt_st(ssa: sSA0, cnt: count0) = st, funcDb}) do
    {count, sSA} = opt_try(sSA0, count0)
    {r_opt_st(st, ssa: sSA, cnt: count), funcDb}
  end

  defp opt_try(blocks, count0) when is_map(blocks) do
    {count, linear} =
      opt_try(
        :beam_ssa.linearize(blocks),
        count0
      )

    {count, :maps.from_list(linear)}
  end

  defp opt_try(linear, count0) when is_list(linear) do
    {count, shrunk} = shrink_try(linear, count0, [])
    reduced = reduce_try(shrunk, [])
    emptySet = :sets.new([{:version, 2}])
    trimmed = trim_try(reduced, emptySet, emptySet, [])
    {count, trimmed}
  end

  defp shrink_try(
         [
           {tryLbl0,
            r_b_blk(
              is: [r_b_set(op: :new_try_tag, dst: dst)],
              last: r_b_br(bool: dst, succ: succLbl)
            ) = tryBlk},
           {succLbl, r_b_blk(is: succIs0, last: succLast) = succBlk0}
           | bs
         ],
         count0,
         acc0
       ) do
    {hoistIs, succIs} = hoist_try_is(succIs0, succLast, dst, [])
    hoistLbl = tryLbl0
    tryLbl = count0
    count = count0 + 1

    hoistBlk =
      r_b_blk(
        is: hoistIs,
        last: r_b_br(bool: r_b_literal(val: true), succ: tryLbl, fail: tryLbl)
      )

    succBlk = r_b_blk(succBlk0, is: succIs)
    acc = [{tryLbl, tryBlk}, {hoistLbl, hoistBlk} | acc0]
    shrink_try([{succLbl, succBlk} | bs], count, acc)
  end

  defp shrink_try([{l, r_b_blk(is: is) = blk0} | bs], count, acc) do
    blk = r_b_blk(blk0, is: sink_try_is(is))
    shrink_try(bs, count, [{l, blk} | acc])
  end

  defp shrink_try([], count, acc) do
    {count, reverse(acc)}
  end

  defp hoist_try_is(
         [
           r_b_set(dst: dst),
           r_b_set(
             op: {:succeeded, _},
             args: [dst]
           )
         ] = is,
         r_b_br(),
         _TryTag,
         hoistIs
       ) do
    {reverse(hoistIs), is}
  end

  defp hoist_try_is([r_b_set(dst: dst)] = is, r_b_br(bool: dst), _TryTag, hoistIs) do
    {reverse(hoistIs), is}
  end

  defp hoist_try_is(
         [
           r_b_set(op: :kill_try_tag, args: [tryTag]) = kill
           | rest
         ],
         last,
         tryTag,
         hoistIs0
       ) do
    {hoistIs, is} = hoist_try_is(rest, last, tryTag, [])
    {reverse(hoistIs0, hoistIs), [kill | is]}
  end

  defp hoist_try_is([r_b_set() = i | is], last, tryTag, hoistIs) do
    hoist_try_is(is, last, tryTag, [i | hoistIs])
  end

  defp hoist_try_is([], _Last, _TryTag, hoistIs) do
    {reverse(hoistIs), []}
  end

  defp sink_try_is([r_b_set(op: :landingpad) | _] = is) do
    is
  end

  defp sink_try_is([r_b_set(op: :phi) = phi | is]) do
    [phi | sink_try_is(is)]
  end

  defp sink_try_is(is) do
    sink_try_is_1(is, [])
  end

  defp sink_try_is_1([r_b_set(op: :kill_try_tag) = kill | is], acc) do
    [kill | reverse(acc, is)]
  end

  defp sink_try_is_1([i | is], acc) do
    case is_safe_sink_try(i) do
      true ->
        sink_try_is_1(is, [i | acc])

      false ->
        reverse(acc, [i | is])
    end
  end

  defp sink_try_is_1([], acc) do
    reverse(acc)
  end

  defp is_safe_sink_try(r_b_set(op: op) = i) do
    case op do
      :bs_extract ->
        false

      _ ->
        :beam_ssa.no_side_effect(i)
    end
  end

  defp reduce_try(
         [
           {l, r_b_blk(is: [r_b_set(op: :new_try_tag)], last: last) = blk0}
           | bs0
         ],
         acc
       ) do
    r_b_br(succ: succ, fail: fail) = last
    ws = :sets.from_list([succ, fail], [{:version, 2}])

    try do
      do_reduce_try(bs0, ws)
    catch
      :not_possible ->
        reduce_try(bs0, [{l, blk0} | acc])
    else
      bs ->
        blk =
          r_b_blk(blk0,
            is: [],
            last: r_b_br(bool: r_b_literal(val: true), succ: succ, fail: succ)
          )

        reduce_try(bs, [{l, blk} | acc])
    end
  end

  defp reduce_try([{l, blk} | bs], acc) do
    reduce_try(bs, [{l, blk} | acc])
  end

  defp reduce_try([], acc) do
    acc
  end

  defp do_reduce_try([{l, blk} | bs] = bs0, ws0) do
    case :sets.is_element(l, ws0) do
      false ->
        case :sets.is_empty(ws0) do
          true ->
            bs0

          false ->
            [{l, blk} | do_reduce_try(bs, ws0)]
        end

      true ->
        ws1 = :sets.del_element(l, ws0)
        r_b_blk(is: is0) = blk

        case reduce_try_is(is0, []) do
          {:safe, is} ->
            successors = :beam_ssa.successors(blk)
            ws = list_set_union(successors, ws1)
            [{l, r_b_blk(blk, is: is)} | do_reduce_try(bs, ws)]

          :unsafe ->
            throw(:not_possible)

          {:done, is} ->
            [{l, r_b_blk(blk, is: is)} | do_reduce_try(bs, ws1)]
        end
    end
  end

  defp do_reduce_try([], ws) do
    true = :sets.is_empty(ws)
    []
  end

  defp reduce_try_is([r_b_set(op: :kill_try_tag) | is], acc) do
    {:done, reverse(acc, is)}
  end

  defp reduce_try_is([r_b_set(op: :extract) | _], _Acc) do
    :unsafe
  end

  defp reduce_try_is([r_b_set(op: :landingpad) | is], acc) do
    reduce_try_is(is, acc)
  end

  defp reduce_try_is([r_b_set(op: {:succeeded, :body}) = i0 | is], acc) do
    i = r_b_set(i0, op: {:succeeded, :guard})
    reduce_try_is(is, [i | acc])
  end

  defp reduce_try_is([r_b_set(op: op) = i | is], acc) do
    isSafe =
      case op do
        :phi ->
          true

        _ ->
          :beam_ssa.no_side_effect(i)
      end

    case isSafe do
      true ->
        reduce_try_is(is, [i | acc])

      false ->
        :unsafe
    end
  end

  defp reduce_try_is([], acc) do
    {:safe, reverse(acc)}
  end

  defp trim_try(
         [
           {l, r_b_blk(is: [r_b_set(op: :landingpad) | _]) = blk}
           | bs
         ],
         unreachable0,
         killed,
         acc
       ) do
    unreachable1 = :sets.add_element(l, unreachable0)
    successors = :sets.from_list(:beam_ssa.successors(blk))
    unreachable = :sets.subtract(unreachable1, successors)
    trim_try(bs, unreachable, killed, [{l, blk} | acc])
  end

  defp trim_try([{l, r_b_blk(last: r_b_ret()) = blk} | bs], unreachable, killed, acc) do
    trim_try(bs, unreachable, killed, [{l, blk} | acc])
  end

  defp trim_try([{l, blk0} | bs], unreachable0, killed0, acc) do
    case :sets.is_empty(unreachable0) do
      true ->
        trim_try(bs, unreachable0, killed0, [{l, blk0} | acc])

      false ->
        r_b_blk(is: is0, last: last0) = blk0

        case reverse(is0) do
          [r_b_set(op: :new_try_tag, dst: tag) | is] ->
            r_b_br(succ: succLbl, fail: padLbl) = last0
            unreachable = :sets.del_element(padLbl, unreachable0)

            case :sets.is_element(padLbl, unreachable0) do
              true ->
                blk =
                  r_b_blk(blk0,
                    is: reverse(is),
                    last: r_b_br(bool: r_b_literal(val: true), succ: succLbl, fail: succLbl)
                  )

                killed = :sets.add_element(tag, killed0)
                trim_try(bs, unreachable, killed, [{l, blk} | acc])

              false ->
                trim_try(bs, unreachable, killed0, [{l, blk0} | acc])
            end

          _ ->
            successors = :sets.from_list(:beam_ssa.successors(blk0))
            unreachable = :sets.subtract(unreachable0, successors)
            trim_try(bs, unreachable, killed0, [{l, blk0} | acc])
        end
    end
  end

  defp trim_try([], _Unreachable, killed, acc0) do
    case :sets.is_empty(killed) do
      true ->
        acc0

      false ->
        for {l, r_b_blk(is: is0) = blk} <- acc0 do
          {l, r_b_blk(blk, is: trim_try_is(is0, killed))}
        end
    end
  end

  defp trim_try_is(
         [
           r_b_set(op: :phi, dst: catchEndVal) = phi,
           r_b_set(op: :catch_end, dst: dst, args: [tag, catchEndVal]) = catch__
           | is
         ],
         killed
       ) do
    case :sets.is_element(tag, killed) do
      true ->
        [r_b_set(phi, dst: dst) | trim_try_is(is, killed)]

      false ->
        [phi, catch__ | trim_try_is(is, killed)]
    end
  end

  defp trim_try_is(
         [r_b_set(op: :kill_try_tag, args: [tag]) = i | is],
         killed
       ) do
    case :sets.is_element(tag, killed) do
      true ->
        trim_try_is(is, killed)

      false ->
        [i | trim_try_is(is, killed)]
    end
  end

  defp trim_try_is([i | is], killed) do
    [i | trim_try_is(is, killed)]
  end

  defp trim_try_is([], _Killed) do
    []
  end

  defp ssa_opt_bsm({r_opt_st(ssa: linear0) = st, funcDb}) do
    extracted0 = bsm_extracted(linear0)
    extracted = :sets.from_list(extracted0, [{:version, 2}])
    linear1 = bsm_skip(linear0, extracted)
    linear = bsm_coalesce_skips(linear1, %{})
    {r_opt_st(st, ssa: linear), funcDb}
  end

  defp bsm_skip([{l, r_b_blk(is: is0) = blk} | bs0], extracted) do
    bs = bsm_skip(bs0, extracted)
    is = bsm_skip_is(is0, extracted)
    [{l, r_b_blk(blk, is: is)} | bs]
  end

  defp bsm_skip([], _) do
    []
  end

  defp bsm_skip_is([i0 | is], extracted) do
    case i0 do
      r_b_set(
        anno: anno0,
        op: :bs_match,
        dst: ctx,
        args: [r_b_literal(val: t) = type, prevCtx | args0]
      )
      when t !== :float and t !== :string and t !== :skip ->
        i =
          case :sets.is_element(ctx, extracted) do
            true ->
              i0

            false ->
              args = [r_b_literal(val: :skip), prevCtx, type | args0]
              anno = :maps.remove(:arg_types, anno0)
              r_b_set(i0, anno: anno, args: args)
          end

        [i | is]

      r_b_set() ->
        [i0 | bsm_skip_is(is, extracted)]
    end
  end

  defp bsm_skip_is([], _) do
    []
  end

  defp bsm_extracted([{_, r_b_blk(is: is)} | bs]) do
    case is do
      [r_b_set(op: :bs_extract, args: [ctx]) | _] ->
        [ctx | bsm_extracted(bs)]

      _ ->
        bsm_extracted(bs)
    end
  end

  defp bsm_extracted([]) do
    []
  end

  defp bsm_coalesce_skips([{l, blk0} | bs0], renames0) do
    case coalesce_skips({l, blk0}, bs0, renames0) do
      :not_possible ->
        [{l, blk0} | bsm_coalesce_skips(bs0, renames0)]

      {bs, renames} ->
        bsm_coalesce_skips(bs, renames)
    end
  end

  defp bsm_coalesce_skips([], _Renames) do
    []
  end

  defp coalesce_skips(
         {l,
          r_b_blk(
            is: [r_b_set(op: :bs_extract) = extract | is0],
            last: last0
          ) = blk0},
         bs0,
         renames0
       ) do
    case coalesce_skips_is(is0, last0, bs0, renames0) do
      :not_possible ->
        :not_possible

      {is, last, bs, renames} ->
        blk = r_b_blk(blk0, is: [extract | is], last: last)
        {[{l, blk} | bs], renames}
    end
  end

  defp coalesce_skips({l, r_b_blk(is: is0, last: last0) = blk0}, bs0, renames0) do
    case coalesce_skips_is(is0, last0, bs0, renames0) do
      :not_possible ->
        :not_possible

      {is, last, bs, renames} ->
        blk = r_b_blk(blk0, is: is, last: last)
        {[{l, blk} | bs], renames}
    end
  end

  defp coalesce_skips_is(
         [
           r_b_set(
             op: :bs_match,
             args: [
               r_b_literal(val: :skip),
               ctx0,
               type,
               flags,
               r_b_literal(val: size0),
               r_b_literal(val: unit0)
             ],
             dst: prevCtx
           ) = skip0,
           r_b_set(op: {:succeeded, :guard})
         ],
         r_b_br(succ: l2, fail: fail) = br0,
         bs0,
         renames0
       )
       when is_integer(size0) do
    case bs0 do
      [
        {^l2,
         r_b_blk(
           is: [
             r_b_set(
               op: :bs_match,
               dst: skipDst,
               args: [
                 r_b_literal(val: :skip),
                 ^prevCtx,
                 _,
                 _,
                 r_b_literal(val: size1),
                 r_b_literal(val: unit1)
               ]
             ),
             r_b_set(op: {:succeeded, :guard}) = succeeded
           ],
           last: r_b_br(fail: ^fail) = br
         )}
        | bs
      ]
      when is_integer(size1) ->
        oldCtx = :maps.get(ctx0, renames0, ctx0)
        skipBits = size0 * unit0 + size1 * unit1

        skip =
          r_b_set(skip0,
            dst: skipDst,
            args: [
              r_b_literal(val: :skip),
              oldCtx,
              type,
              flags,
              r_b_literal(val: skipBits),
              r_b_literal(val: 1)
            ]
          )

        is = [skip, succeeded]
        renames = Map.put(renames0, prevCtx, ctx0)
        {is, br, bs, renames}

      [
        {^l2,
         r_b_blk(
           is: [
             r_b_set(
               op: :bs_test_tail,
               args: [^prevCtx, r_b_literal(val: tailSkip)]
             )
           ],
           last: r_b_br(succ: nextSucc, fail: ^fail)
         )}
        | bs
      ] ->
        oldCtx = :maps.get(ctx0, renames0, ctx0)
        skipBits = size0 * unit0

        testTail =
          r_b_set(skip0,
            op: :bs_test_tail,
            args: [oldCtx, r_b_literal(val: skipBits + tailSkip)]
          )

        br = r_b_br(br0, bool: r_b_set(testTail, :dst), succ: nextSucc)
        is = [testTail]
        renames = Map.put(renames0, prevCtx, ctx0)
        {is, br, bs, renames}

      _ ->
        :not_possible
    end
  end

  defp coalesce_skips_is(_, _, _, _) do
    :not_possible
  end

  defp ssa_opt_bsm_shortcut({r_opt_st(ssa: linear0) = st, funcDb}) do
    positions = bsm_positions(linear0, %{})

    case map_size(positions) do
      0 ->
        {st, funcDb}

      _ ->
        linear = bsm_shortcut(linear0, positions)
        ssa_opt_live({r_opt_st(st, ssa: linear), funcDb})
    end
  end

  defp bsm_positions([{l, r_b_blk(is: is, last: last)} | bs], posMap0) do
    posMap = bsm_positions_is(is, posMap0)

    case {is, last} do
      {[r_b_set(op: :bs_test_tail, dst: bool, args: [ctx, r_b_literal(val: bits0)])],
       r_b_br(bool: bool, fail: fail)} ->
        bits = bits0 + :erlang.map_get(ctx, posMap0)
        bsm_positions(bs, Map.put(posMap, l, {bits, fail}))

      {_, _} ->
        bsm_positions(bs, posMap)
    end
  end

  defp bsm_positions([], posMap) do
    posMap
  end

  defp bsm_positions_is(
         [r_b_set(op: :bs_start_match, dst: new) | is],
         posMap0
       ) do
    posMap = Map.put(posMap0, new, 0)
    bsm_positions_is(is, posMap)
  end

  defp bsm_positions_is(
         [r_b_set(op: :bs_match, dst: new, args: args) | is],
         posMap0
       ) do
    [_, old | _] = args
    %{^old => bits0} = posMap0
    bits = bsm_update_bits(args, bits0)
    posMap = Map.put(posMap0, new, bits)
    bsm_positions_is(is, posMap)
  end

  defp bsm_positions_is([_ | is], posMap) do
    bsm_positions_is(is, posMap)
  end

  defp bsm_positions_is([], posMap) do
    posMap
  end

  defp bsm_update_bits([r_b_literal(val: :string), _, r_b_literal(val: string)], bits) do
    bits + bit_size(string)
  end

  defp bsm_update_bits([r_b_literal(val: :utf8) | _], bits) do
    bits + 8
  end

  defp bsm_update_bits([r_b_literal(val: :utf16) | _], bits) do
    bits + 16
  end

  defp bsm_update_bits([r_b_literal(val: :utf32) | _], bits) do
    bits + 32
  end

  defp bsm_update_bits([_, _, _, r_b_literal(val: sz), r_b_literal(val: u)], bits)
       when is_integer(sz) do
    bits + sz * u
  end

  defp bsm_update_bits(_, bits) do
    bits
  end

  defp bsm_shortcut(
         [{l, r_b_blk(is: is, last: last0) = blk} | bs],
         posMap0
       ) do
    case {is, last0} do
      {[
         r_b_set(op: :bs_match, dst: new, args: [_, old | _]),
         r_b_set(op: {:succeeded, :guard}, dst: bool, args: [new])
       ], r_b_br(bool: bool, fail: fail)} ->
        case posMap0 do
          %{^old => bits, ^fail => {tailBits, nextFail}}
          when bits > tailBits ->
            last = r_b_br(last0, fail: nextFail)
            [{l, r_b_blk(blk, last: last)} | bsm_shortcut(bs, posMap0)]

          %{} ->
            [{l, blk} | bsm_shortcut(bs, posMap0)]
        end

      {[r_b_set(op: :bs_test_tail, dst: bool, args: [old, r_b_literal(val: tailBits)])],
       r_b_br(bool: bool, succ: succ, fail: fail)} ->
        case posMap0 do
          %{{:bs_test_tail, ^old, ^l} => actualTailBits} ->
            last1 =
              cond do
                tailBits === actualTailBits ->
                  r_b_br(last0, fail: succ)

                true ->
                  r_b_br(last0, succ: fail)
              end

            last = :beam_ssa.normalize(last1)
            [{l, r_b_blk(blk, last: last)} | bsm_shortcut(bs, posMap0)]

          %{} ->
            posMap = Map.put(posMap0, {:bs_test_tail, old, succ}, tailBits)
            [{l, blk} | bsm_shortcut(bs, posMap)]
        end

      {_, _} ->
        [{l, blk} | bsm_shortcut(bs, posMap0)]
    end
  end

  defp bsm_shortcut([], _PosMap) do
    []
  end

  defp ssa_opt_bs_create_bin({r_opt_st(ssa: linear0) = st, funcDb}) do
    linear = opt_create_bin_fs(linear0)
    {r_opt_st(st, ssa: linear), funcDb}
  end

  defp opt_create_bin_fs([{l, r_b_blk(is: is0) = blk0} | bs]) do
    is = opt_create_bin_is(is0)
    blk = r_b_blk(blk0, is: is)
    [{l, blk} | opt_create_bin_fs(bs)]
  end

  defp opt_create_bin_fs([]) do
    []
  end

  defp opt_create_bin_is([
         r_b_set(op: :bs_create_bin, args: args0) = i0
         | is
       ]) do
    args = opt_create_bin_args(args0)
    i = r_b_set(i0, args: args)
    [i | opt_create_bin_is(is)]
  end

  defp opt_create_bin_is([i | is]) do
    [i | opt_create_bin_is(is)]
  end

  defp opt_create_bin_is([]) do
    []
  end

  defp opt_create_bin_args([
         r_b_literal(val: :binary),
         r_b_literal(val: [1 | _]),
         r_b_literal(val: bin0),
         r_b_literal(val: :all),
         r_b_literal(val: :binary),
         r_b_literal(
           val: [
             1
             | _
           ]
         ),
         r_b_literal(val: bin1),
         r_b_literal(val: :all)
         | args0
       ])
       when is_bitstring(bin0) and is_bitstring(bin1) do
    bin = <<bin0::bitstring, bin1::bitstring>>

    args = [
      r_b_literal(val: :binary),
      r_b_literal(val: [1]),
      r_b_literal(val: bin),
      r_b_literal(val: :all) | args0
    ]

    opt_create_bin_args(args)
  end

  defp opt_create_bin_args([
         r_b_literal(val: type) = type0,
         r_b_literal(val: uFs) = uFs0,
         val,
         size | args0
       ]) do
    [unit | flags] = uFs

    case opt_create_bin_arg(type, unit, uFs, val, size) do
      :not_possible ->
        [type0, uFs0, val, size | opt_create_bin_args(args0)]

      [bin] when is_bitstring(bin) ->
        args = [
          r_b_literal(val: :binary),
          r_b_literal(val: [1]),
          r_b_literal(val: bin),
          r_b_literal(val: :all) | args0
        ]

        opt_create_bin_args(args)

      [{:int, int, intSize}, bin] when is_bitstring(bin) ->
        args = [
          r_b_literal(val: :integer),
          r_b_literal(val: [1 | flags]),
          r_b_literal(val: int),
          r_b_literal(val: intSize),
          r_b_literal(val: :binary),
          r_b_literal(val: [1]),
          r_b_literal(val: bin),
          r_b_literal(val: :all)
          | args0
        ]

        opt_create_bin_args(args)
    end
  end

  defp opt_create_bin_args([]) do
    []
  end

  defp opt_create_bin_arg(:binary, unit, _Flags, r_b_literal(val: val), r_b_literal(val: :all))
       when unit !== 1 and rem(bit_size(val), unit) === 0 do
    [val]
  end

  defp opt_create_bin_arg(type, unit, flags, r_b_literal(val: val), r_b_literal(val: size))
       when is_integer(size) and is_integer(unit) do
    effectiveSize = size * unit

    cond do
      effectiveSize > 1 <<< 24 ->
        :not_possible

      effectiveSize > 0 and effectiveSize <= 1 <<< 24 ->
        case {type, opt_create_bin_endian(flags)} do
          {:integer, :big} when is_integer(val) ->
            cond do
              effectiveSize < 64 ->
                [<<val::size(effectiveSize)>>]

              true ->
                opt_bs_put_split_int(val, effectiveSize)
            end

          {:integer, :little}
          when is_integer(val) and
                 effectiveSize < 128 ->
            <<int::size(effectiveSize)>> = <<val::size(effectiveSize)-little>>

            opt_create_bin_arg(
              type,
              1,
              [],
              r_b_literal(val: int),
              r_b_literal(val: effectiveSize)
            )

          {:binary, _} when is_bitstring(val) ->
            case val do
              <<bitstring::size(effectiveSize)-bits, _::bits>> ->
                [bitstring]

              _ ->
                :not_possible
            end

          {:float, endian} ->
            try do
              case endian do
                :big ->
                  [<<val::size(effectiveSize)-big-float-unit(1)>>]

                :little ->
                  [<<val::size(effectiveSize)-little-float-unit(1)>>]
              end
            catch
              :error, _ ->
                :not_possible
            end

          {_, _} ->
            :not_possible
        end

      true ->
        :not_possible
    end
  end

  defp opt_create_bin_arg(_, _, _, _, _) do
    :not_possible
  end

  defp opt_create_bin_endian([:little = e | _]) do
    e
  end

  defp opt_create_bin_endian([:native = e | _]) do
    e
  end

  defp opt_create_bin_endian([_ | fs]) do
    opt_create_bin_endian(fs)
  end

  defp opt_create_bin_endian([]) do
    :big
  end

  defp opt_bs_put_split_int(int, size) do
    pos = opt_bs_put_split_int_1(int, 0, size - 1)
    upperSize = size - pos

    cond do
      pos === 0 ->
        :not_possible

      upperSize < 64 ->
        [<<int::size(size)>>]

      true ->
        [{:int, int >>> pos, upperSize}, <<int::size(pos)>>]
    end
  end

  defp opt_bs_put_split_int_1(_Int, l, r) when l > r do
    8 * div(l + 7, 8)
  end

  defp opt_bs_put_split_int_1(int, l, r) do
    mid = div(l + r, 2)

    case int >>> mid do
      upper when upper === 0 or upper === -1 ->
        opt_bs_put_split_int_1(int, l, mid - 1)

      _ ->
        opt_bs_put_split_int_1(int, mid + 1, r)
    end
  end

  defp ssa_opt_tuple_size({r_opt_st(ssa: linear0, cnt: count0) = st, funcDb}) do
    nonGuards = non_guards(linear0)
    {linear, count} = opt_tup_size(linear0, nonGuards, count0, [])
    {r_opt_st(st, ssa: linear, cnt: count), funcDb}
  end

  defp opt_tup_size([{l, r_b_blk(is: is, last: last) = blk} | bs], nonGuards, count0, acc0) do
    case {is, last} do
      {[r_b_set(op: {:bif, :"=:="}, dst: bool, args: [r_b_var() = tup, r_b_literal(val: arity)])],
       r_b_br(bool: bool)}
      when is_integer(arity) and arity >= 0 ->
        {acc, count} = opt_tup_size_1(tup, l, nonGuards, count0, acc0)
        opt_tup_size(bs, nonGuards, count, [{l, blk} | acc])

      {_, _} ->
        opt_tup_size(bs, nonGuards, count0, [{l, blk} | acc0])
    end
  end

  defp opt_tup_size([], _NonGuards, count, acc) do
    {reverse(acc), count}
  end

  defp opt_tup_size_1(size, eqL, nonGuards, count0, [{l, blk0} | acc]) do
    r_b_blk(is: is0, last: last) = blk0

    case last do
      r_b_br(bool: bool, succ: ^eqL, fail: fail) ->
        case :gb_sets.is_member(fail, nonGuards) do
          true ->
            {[{l, blk0} | acc], count0}

          false ->
            case opt_tup_size_is(is0, bool, size, []) do
              :none ->
                {[{l, blk0} | acc], count0}

              {preIs, tupleSizeIs, tuple} ->
                opt_tup_size_2(preIs, tupleSizeIs, l, eqL, tuple, fail, count0, acc)
            end
        end

      _ ->
        {[{l, blk0} | acc], count0}
    end
  end

  defp opt_tup_size_1(_, _, _, count, acc) do
    {acc, count}
  end

  defp opt_tup_size_2(preIs, tupleSizeIs, preL, eqL, tuple, fail, count0, acc) do
    isTupleL = count0
    tupleSizeL = count0 + 1
    bool = r_b_var(name: {:"@ssa_bool", count0 + 2})
    count = count0 + 3
    true__ = r_b_literal(val: true)
    preBr = r_b_br(bool: true__, succ: isTupleL, fail: isTupleL)
    preBlk = r_b_blk(is: preIs, last: preBr)
    isTupleIs = [r_b_set(op: {:bif, :is_tuple}, dst: bool, args: [tuple])]
    isTupleBr = r_b_br(bool: bool, succ: tupleSizeL, fail: fail)
    isTupleBlk = r_b_blk(is: isTupleIs, last: isTupleBr)
    tupleSizeBr = r_b_br(bool: true__, succ: eqL, fail: eqL)
    tupleSizeBlk = r_b_blk(is: tupleSizeIs, last: tupleSizeBr)
    {[{tupleSizeL, tupleSizeBlk}, {isTupleL, isTupleBlk}, {preL, preBlk} | acc], count}
  end

  defp opt_tup_size_is(
         [
           r_b_set(op: {:bif, :tuple_size}, dst: size, args: [tuple]) = i,
           r_b_set(op: {:succeeded, _}, dst: bool, args: [size])
         ],
         bool,
         size,
         acc
       ) do
    {reverse(acc), [i], tuple}
  end

  defp opt_tup_size_is([i | is], bool, size, acc) do
    opt_tup_size_is(is, bool, size, [i | acc])
  end

  defp opt_tup_size_is([], _, _, _Acc) do
    :none
  end

  defp ssa_opt_sw({r_opt_st(ssa: linear0, cnt: count0) = st, funcDb}) do
    {linear, count} = opt_sw(linear0, count0, [])
    {r_opt_st(st, ssa: linear, cnt: count), funcDb}
  end

  defp opt_sw([{l, r_b_blk(is: is, last: r_b_switch() = sw0) = blk0} | bs], count0, acc) do
    case sw0 do
      r_b_switch(arg: arg, fail: fail, list: [{lit, lbl}]) ->
        {bool, count} = new_var(:"@ssa_bool", count0)
        isEq = r_b_set(op: {:bif, :"=:="}, dst: bool, args: [arg, lit])
        br = r_b_br(bool: bool, succ: lbl, fail: fail)
        blk = r_b_blk(blk0, is: is ++ [isEq], last: br)
        opt_sw(bs, count, [{l, blk} | acc])

      r_b_switch(
        arg: arg,
        fail: fail,
        list: [{r_b_literal(val: b1), lbl}, {r_b_literal(val: b2), lbl}]
      )
      when b1 === not b2 ->
        {bool, count} = new_var(:"@ssa_bool", count0)
        isBool = r_b_set(op: {:bif, :is_boolean}, dst: bool, args: [arg])
        br = r_b_br(bool: bool, succ: lbl, fail: fail)
        blk = r_b_blk(blk0, is: is ++ [isBool], last: br)
        opt_sw(bs, count, [{l, blk} | acc])

      _ ->
        opt_sw(bs, count0, [{l, blk0} | acc])
    end
  end

  defp opt_sw([{l, r_b_blk() = blk} | bs], count, acc) do
    opt_sw(bs, count, [{l, blk} | acc])
  end

  defp opt_sw([], count, acc) do
    {reverse(acc), count}
  end

  defp ssa_opt_ne({r_opt_st(ssa: linear0) = st, funcDb}) do
    linear = opt_ne(linear0, {:uses, linear0})
    {r_opt_st(st, ssa: linear), funcDb}
  end

  defp opt_ne(
         [
           {l,
            r_b_blk(
              is: [_ | _] = is0,
              last: r_b_br(bool: r_b_var() = bool)
            ) = blk0}
           | bs
         ],
         uses0
       ) do
    case last(is0) do
      r_b_set(op: {:bif, :"=/="}, dst: ^bool) = i0 ->
        i = r_b_set(i0, op: {:bif, :"=:="})
        {blk, uses} = opt_ne_replace(i, blk0, uses0)
        [{l, blk} | opt_ne(bs, uses)]

      r_b_set(op: {:bif, :"/="}, dst: ^bool) = i0 ->
        i = r_b_set(i0, op: {:bif, :==})
        {blk, uses} = opt_ne_replace(i, blk0, uses0)
        [{l, blk} | opt_ne(bs, uses)]

      _ ->
        [{l, blk0} | opt_ne(bs, uses0)]
    end
  end

  defp opt_ne([{l, blk} | bs], uses) do
    [{l, blk} | opt_ne(bs, uses)]
  end

  defp opt_ne([], _Uses) do
    []
  end

  defp opt_ne_replace(
         r_b_set(dst: bool) = i,
         r_b_blk(is: is0, last: r_b_br(succ: succ, fail: fail) = br0) = blk,
         uses0
       ) do
    case opt_ne_single_use(bool, uses0) do
      {true, uses} ->
        is = replace_last(is0, i)
        br = r_b_br(br0, succ: fail, fail: succ)
        {r_b_blk(blk, is: is, last: br), uses}

      {false, uses} ->
        {blk, uses}
    end
  end

  defp replace_last([_], repl) do
    [repl]
  end

  defp replace_last([i | is], repl) do
    [i | replace_last(is, repl)]
  end

  defp opt_ne_single_use(var, {:uses, linear}) do
    blocks = :maps.from_list(linear)
    rPO = :beam_ssa.rpo(blocks)
    uses = :beam_ssa.uses(rPO, blocks)
    opt_ne_single_use(var, uses)
  end

  defp opt_ne_single_use(var, uses) when is_map(uses) do
    {case uses do
       %{^var => [_]} ->
         true

       %{^var => [_ | _]} ->
         false
     end, uses}
  end

  defp ssa_opt_sink({r_opt_st(ssa: linear) = st, funcDb}) do
    case def_blocks(linear) do
      [] ->
        {st, funcDb}

      [_ | _] = defs0 ->
        defs = :maps.from_list(defs0)
        {do_ssa_opt_sink(defs, st), funcDb}
    end
  end

  defp do_ssa_opt_sink(defs, r_opt_st(ssa: linear) = st) when is_map(defs) do
    used = used_blocks(linear, defs, [])
    blocks0 = :maps.from_list(linear)
    rPO = :beam_ssa.rpo(blocks0)
    preds = :beam_ssa.predecessors(blocks0)

    {dom, numbering} =
      :beam_ssa.dominators_from_predecessors(
        rPO,
        preds
      )

    unsuitable = unsuitable(linear, blocks0, preds)
    defLocs0 = new_def_locations(used, defs, dom, numbering, unsuitable)
    ps = partition_deflocs(defLocs0, defs, blocks0)
    defLocs1 = filter_deflocs(ps, preds, blocks0)
    defLocs = sort(defLocs1)

    blocks =
      foldl(
        fn {v, {from, to}}, a ->
          move_defs(v, from, to, a)
        end,
        blocks0,
        defLocs
      )

    r_opt_st(st, ssa: :beam_ssa.linearize(blocks))
  end

  defp def_blocks([{l, r_b_blk(is: is)} | bs]) do
    def_blocks_is(is, l, def_blocks(bs))
  end

  defp def_blocks([]) do
    []
  end

  defp def_blocks_is(
         [
           r_b_set(op: :get_tuple_element, args: [tuple, _], dst: dst)
           | is
         ],
         l,
         acc
       ) do
    def_blocks_is(is, l, [{dst, {l, tuple}} | acc])
  end

  defp def_blocks_is([_ | is], l, acc) do
    def_blocks_is(is, l, acc)
  end

  defp def_blocks_is([], _, acc) do
    acc
  end

  defp used_blocks([{l, blk} | bs], def__, acc0) do
    used = :beam_ssa.used(blk)

    acc =
      for v <- used, :maps.is_key(v, def__) do
        {v, l}
      end ++ acc0

    used_blocks(bs, def__, acc)
  end

  defp used_blocks([], _Def, acc) do
    rel2fam(acc)
  end

  defp partition_deflocs(defLoc, _Defs, blocks) do
    {blkNums0, _} =
      mapfoldl(
        fn l, n ->
          {{l, n}, n + 1}
        end,
        0,
        :beam_ssa.rpo(blocks)
      )

    blkNums = :maps.from_list(blkNums0)

    s =
      for {v, tuple, {from, to}} <- defLoc do
        {tuple, {:erlang.map_get(to, blkNums), {v, {from, to}}}}
      end

    f = rel2fam(s)
    partition_deflocs_1(f, blocks)
  end

  defp partition_deflocs_1([{tuple, defLocs0} | t], blocks) do
    defLocs1 =
      for {_, dL} <- defLocs0 do
        dL
      end

    defLocs = partition_dl(defLocs1, blocks)

    for dL <- defLocs do
      {tuple, dL}
    end ++ partition_deflocs_1(t, blocks)
  end

  defp partition_deflocs_1([], _) do
    []
  end

  defp partition_dl([_] = defLoc, _Blocks) do
    [defLoc]
  end

  defp partition_dl([{_, {_, first}} | _] = defLoc0, blocks) do
    rPO = :beam_ssa.rpo([first], blocks)
    {p, defLoc} = partition_dl_1(defLoc0, rPO, [])
    [p | partition_dl(defLoc, blocks)]
  end

  defp partition_dl([], _Blocks) do
    []
  end

  defp partition_dl_1([{_, {_, l}} = dL | dLs], [l | _] = ls, acc) do
    partition_dl_1(dLs, ls, [dL | acc])
  end

  defp partition_dl_1([_ | _] = dLs, [_ | ls], acc) do
    partition_dl_1(dLs, ls, acc)
  end

  defp partition_dl_1([], _, acc) do
    {reverse(acc), []}
  end

  defp partition_dl_1([_ | _] = dLs, [], acc) do
    {reverse(acc), dLs}
  end

  defp filter_gc_deflocs(defLocGC, tuple, first, preds, blocks) do
    case defLocGC do
      [] ->
        []

      [{_, {_, {from, to}}}] ->
        case is_on_stack(first, tuple, blocks) do
          true ->
            defLocGC

          false ->
            case will_gc(from, to, preds, blocks, false) do
              false ->
                defLocGC

              true ->
                []
            end
        end

      [_, _ | _] ->
        defLocGC
    end
  end

  defp find_paths_to_check([{_, {_, to}} = move | t], first) do
    [{{first, to}, move} | find_paths_to_check(t, first)]
  end

  defp find_paths_to_check([], _First) do
    []
  end

  defp will_gc(from, to, preds, blocks, all) do
    between = :beam_ssa.between(from, to, preds, blocks)
    will_gc_1(between, to, blocks, all, %{from => false})
  end

  defp will_gc_1([to | _], to, _Blocks, _All, willGC) do
    :erlang.map_get(to, willGC)
  end

  defp will_gc_1([l | ls], to, blocks, all, willGC0) do
    r_b_blk(is: is) = blk = :erlang.map_get(l, blocks)
    gC = :erlang.map_get(l, willGC0) or will_gc_is(is, all)
    willGC = gc_update_successors(blk, gC, willGC0)
    will_gc_1(ls, to, blocks, all, willGC)
  end

  defp will_gc_is([r_b_set(op: :call, args: args) | is], false) do
    case args do
      [r_b_remote(mod: r_b_literal(val: :erlang)) | _] ->
        will_gc_is(is, false)

      [_ | _] ->
        true
    end
  end

  defp will_gc_is([_ | is], false) do
    will_gc_is(is, false)
  end

  defp will_gc_is([i | is], all) do
    :beam_ssa.clobbers_xregs(i) or will_gc_is(is, all)
  end

  defp will_gc_is([], _All) do
    false
  end

  defp is_on_stack(from, var, blocks) do
    is_on_stack(:beam_ssa.rpo([from], blocks), var, blocks, %{from => false})
  end

  defp is_on_stack([l | ls], var, blocks, willGC0) do
    r_b_blk(is: is) = blk = :erlang.map_get(l, blocks)
    gC0 = :erlang.map_get(l, willGC0)

    case is_on_stack_is(is, var, gC0) do
      {:done, gC} ->
        gC

      gC ->
        willGC = gc_update_successors(blk, gC, willGC0)
        is_on_stack(ls, var, blocks, willGC)
    end
  end

  defp is_on_stack([], _Var, _, _) do
    false
  end

  defp is_on_stack_is([r_b_set(op: :get_tuple_element) | is], var, gC) do
    is_on_stack_is(is, var, gC)
  end

  defp is_on_stack_is([i | is], var, gC0) do
    case gC0 and member(var, :beam_ssa.used(i)) do
      true ->
        {:done, gC0}

      false ->
        gC = gC0 or :beam_ssa.clobbers_xregs(i)
        is_on_stack_is(is, var, gC)
    end
  end

  defp is_on_stack_is([], _, gC) do
    gC
  end

  defp gc_update_successors(blk, gC, willGC) do
    foldl(
      fn l, acc ->
        case acc do
          %{^l => true} ->
            acc

          %{^l => false} when gC === false ->
            acc

          %{} ->
            Map.put(acc, l, gC)
        end
      end,
      willGC,
      :beam_ssa.successors(blk)
    )
  end

  defp unsuitable(linear, blocks, predecessors)
       when is_map(blocks) and is_map(predecessors) do
    unsuitable0 = unsuitable_1(linear)
    unsuitable1 = unsuitable_recv(linear, blocks, predecessors)
    :gb_sets.from_list(unsuitable0 ++ unsuitable1)
  end

  defp unsuitable_1([{l, r_b_blk(is: [r_b_set(op: op) = i | _])} | bs]) do
    unsuitable =
      case op do
        :bs_extract ->
          true

        :bs_match ->
          true

        {:float, _} ->
          true

        :landingpad ->
          true

        _ ->
          :beam_ssa.is_loop_header(i)
      end

    case unsuitable do
      true ->
        [l | unsuitable_1(bs)]

      false ->
        unsuitable_1(bs)
    end
  end

  defp unsuitable_1([{_, r_b_blk()} | bs]) do
    unsuitable_1(bs)
  end

  defp unsuitable_1([]) do
    []
  end

  defp unsuitable_recv([{l, r_b_blk(is: [r_b_set(op: op) | _])} | bs], blocks, predecessors) do
    ls =
      case op do
        :remove_message ->
          unsuitable_loop(l, blocks, predecessors)

        :recv_next ->
          unsuitable_loop(l, blocks, predecessors)

        _ ->
          []
      end

    ls ++ unsuitable_recv(bs, blocks, predecessors)
  end

  defp unsuitable_recv([_ | bs], blocks, predecessors) do
    unsuitable_recv(bs, blocks, predecessors)
  end

  defp unsuitable_recv([], _, _) do
    []
  end

  defp unsuitable_loop(l, blocks, predecessors) do
    unsuitable_loop(l, blocks, predecessors, [])
  end

  defp unsuitable_loop(l, blocks, predecessors, acc) do
    ps = :erlang.map_get(l, predecessors)
    unsuitable_loop_1(ps, blocks, predecessors, acc)
  end

  defp unsuitable_loop_1([p | ps], blocks, predecessors, acc0) do
    case is_loop_header(p, blocks) do
      true ->
        unsuitable_loop_1(ps, blocks, predecessors, acc0)

      false ->
        case :ordsets.is_element(p, acc0) do
          false ->
            acc1 = :ordsets.add_element(p, acc0)
            acc = unsuitable_loop(p, blocks, predecessors, acc1)
            unsuitable_loop_1(ps, blocks, predecessors, acc)

          true ->
            unsuitable_loop_1(ps, blocks, predecessors, acc0)
        end
    end
  end

  defp unsuitable_loop_1([], _, _, acc) do
    acc
  end

  defp is_loop_header(l, blocks) do
    case :erlang.map_get(l, blocks) do
      r_b_blk(is: [i | _]) ->
        :beam_ssa.is_loop_header(i)

      r_b_blk() ->
        false
    end
  end

  defp new_def_locations([{v, usedIn} | vs], defs, dom, numbering, unsuitable) do
    {defIn, tuple} = :erlang.map_get(v, defs)
    common = common_dominator(usedIn, dom, numbering, unsuitable)

    sink =
      case member(
             common,
             :erlang.map_get(defIn, dom)
           ) do
        true ->
          {v, tuple, {defIn, defIn}}

        false ->
          {v, tuple, {defIn, common}}
      end

    [sink | new_def_locations(vs, defs, dom, numbering, unsuitable)]
  end

  defp new_def_locations([], _, _, _, _) do
    []
  end

  defp common_dominator(ls0, dom, numbering, unsuitable) do
    [common | _] = :beam_ssa.common_dominators(ls0, dom, numbering)

    case :gb_sets.is_member(common, unsuitable) do
      true ->
        [^common, oneUp | _] = :erlang.map_get(common, dom)
        common_dominator([oneUp], dom, numbering, unsuitable)

      false ->
        common
    end
  end

  defp move_defs(v, from, to, blocks) do
    %{^from => fromBlk0, ^to => toBlk0} = blocks
    {def__, fromBlk} = remove_def(v, fromBlk0)

    try do
      insert_def(v, def__, toBlk0)
    catch
      :not_possible ->
        blocks
    else
      toBlk ->
        %{blocks | from => fromBlk, to => toBlk}
    end
  end

  defp remove_def(v, r_b_blk(is: is0) = blk) do
    {def__, is} = remove_def_is(is0, v, [])
    {def__, r_b_blk(blk, is: is)}
  end

  defp remove_def_is([r_b_set(dst: dst) = def__ | is], dst, acc) do
    {def__, reverse(acc, is)}
  end

  defp remove_def_is([i | is], dst, acc) do
    remove_def_is(is, dst, [i | acc])
  end

  defp insert_def(v, def__, r_b_blk(is: is0) = blk) do
    is = insert_def_is(is0, v, def__)
    r_b_blk(blk, is: is)
  end

  defp insert_def_is([r_b_set(op: :phi) = i | is], v, def__) do
    case member(v, :beam_ssa.used(i)) do
      true ->
        throw(:not_possible)

      false ->
        [i | insert_def_is(is, v, def__)]
    end
  end

  defp insert_def_is([r_b_set(op: op) = i | is] = is0, v, def__) do
    action0 =
      case op do
        :call ->
          :beyond

        :catch_end ->
          :beyond

        :wait_timeout ->
          :beyond

        _ ->
          :here
      end

    action =
      case is do
        [r_b_set(op: {:succeeded, _}) | _] ->
          :here

        _ ->
          action0
      end

    case action do
      :beyond ->
        case member(v, :beam_ssa.used(i)) do
          true ->
            [def__ | is0]

          false ->
            [i | insert_def_is(is, v, def__)]
        end

      :here ->
        [def__ | is0]
    end
  end

  defp insert_def_is([], _V, def__) do
    [def__]
  end

  defp ssa_opt_get_tuple_element({r_opt_st(ssa: blocks0) = st, funcDb}) do
    blocks =
      opt_get_tuple_element(
        :maps.to_list(blocks0),
        blocks0
      )

    {r_opt_st(st, ssa: blocks), funcDb}
  end

  defp opt_get_tuple_element([{l, r_b_blk(is: is0) = blk0} | bs], blocks) do
    case opt_get_tuple_element_is(is0, false, []) do
      {:yes, is} ->
        blk = r_b_blk(blk0, is: is)
        opt_get_tuple_element(bs, %{blocks | l => blk})

      :no ->
        opt_get_tuple_element(bs, blocks)
    end
  end

  defp opt_get_tuple_element([], blocks) do
    blocks
  end

  defp opt_get_tuple_element_is(
         [
           r_b_set(
             op: :get_tuple_element,
             args: [r_b_var() = src, _]
           ) = i0
           | is0
         ],
         _AnyChange,
         acc
       ) do
    {getIs0, is} = collect_get_tuple_element(is0, src, [i0])

    getIs1 =
      sort(
        for r_b_set(args: [_, pos]) = i <- getIs0 do
          {pos, i}
        end
      )

    getIs =
      for {_, i} <- getIs1 do
        i
      end

    opt_get_tuple_element_is(is, true, reverse(getIs, acc))
  end

  defp opt_get_tuple_element_is([i | is], anyChange, acc) do
    opt_get_tuple_element_is(is, anyChange, [i | acc])
  end

  defp opt_get_tuple_element_is([], anyChange, acc) do
    case anyChange do
      true ->
        {:yes, reverse(acc)}

      false ->
        :no
    end
  end

  defp collect_get_tuple_element(
         [
           r_b_set(op: :get_tuple_element, args: [src, _]) = i
           | is
         ],
         src,
         acc
       ) do
    collect_get_tuple_element(is, src, [i | acc])
  end

  defp collect_get_tuple_element(is, _Src, acc) do
    {acc, is}
  end

  defp ssa_opt_unfold_literals({st, funcDb}) do
    r_opt_st(ssa: blocks0, args: args, anno: anno) = st
    true = is_map(blocks0)
    paramInfo = :maps.get(:parameter_info, anno, %{})
    litMap = collect_arg_literals(args, paramInfo, 0, %{})

    case map_size(litMap) do
      0 ->
        {st, funcDb}

      _ ->
        safeMap = %{0 => true}
        blocks = unfold_literals(:beam_ssa.rpo(blocks0), litMap, safeMap, blocks0)
        {r_opt_st(st, ssa: blocks), funcDb}
    end
  end

  defp collect_arg_literals([v | vs], info, x, acc0) do
    case info do
      %{^v => varInfo} ->
        type = :proplists.get_value(:type, varInfo, :any)

        case :beam_types.get_singleton_value(type) do
          {:ok, val} ->
            f = fn vars ->
              [{x, v} | vars]
            end

            acc = :maps.update_with(val, f, [{x, v}], acc0)
            collect_arg_literals(vs, info, x + 1, acc)

          :error ->
            collect_arg_literals(vs, info, x + 1, acc0)
        end

      %{} ->
        collect_arg_literals(vs, info, x + 1, acc0)
    end
  end

  defp collect_arg_literals([], _Info, _X, acc) do
    acc
  end

  defp unfold_literals([1 | ls], litMap, safeMap, blocks) do
    unfold_literals(ls, litMap, safeMap, blocks)
  end

  defp unfold_literals([l | ls], litMap, safeMap0, blocks0) do
    {blocks, safe} =
      case :erlang.map_get(l, safeMap0) do
        false ->
          {blocks0, false}

        true ->
          r_b_blk(is: is0) = blk = :erlang.map_get(l, blocks0)
          {is, safe0} = unfold_lit_is(is0, litMap, [])
          {%{blocks0 | l => r_b_blk(blk, is: is)}, safe0}
      end

    successors = :beam_ssa.successors(l, blocks)
    safeMap = unfold_update_succ(successors, safe, safeMap0)
    unfold_literals(ls, litMap, safeMap, blocks)
  end

  defp unfold_literals([], _, _, blocks) do
    blocks
  end

  defp unfold_update_succ([s | ss], safe, safeMap0) do
    f = fn prev ->
      :erlang.and(prev, safe)
    end

    safeMap = :maps.update_with(s, f, safe, safeMap0)
    unfold_update_succ(ss, safe, safeMap)
  end

  defp unfold_update_succ([], _, safeMap) do
    safeMap
  end

  defp unfold_lit_is(
         [
           r_b_set(
             op: :match_fail,
             args: [r_b_literal(val: :function_clause) | args0]
           ) = i0
           | is
         ],
         litMap,
         acc
       ) do
    args = unfold_call_args(args0, litMap, 0)
    i = r_b_set(i0, args: [r_b_literal(val: :function_clause) | args])
    {reverse(acc, [i | is]), false}
  end

  defp unfold_lit_is([r_b_set(op: op, args: args0) = i0 | is], litMap, acc) do
    unfold =
      case op do
        :call ->
          true

        :old_make_fun ->
          true

        _ ->
          false
      end

    i =
      case unfold do
        true ->
          args = unfold_call_args(args0, litMap, -1)
          r_b_set(i0, args: args)

        false ->
          i0
      end

    case :beam_ssa.clobbers_xregs(i) do
      true ->
        {reverse(acc, [i | is]), false}

      false ->
        unfold_lit_is(is, litMap, [i | acc])
    end
  end

  defp unfold_lit_is([], _LitMap, acc) do
    {reverse(acc), true}
  end

  defp unfold_call_args([a0 | as], litMap, x) do
    a = unfold_arg(a0, litMap, x)
    [a | unfold_call_args(as, litMap, x + 1)]
  end

  defp unfold_call_args([], _, _) do
    []
  end

  defp unfold_arg(r_b_literal(val: val) = lit, litMap, x) do
    case litMap do
      %{^val => vars} ->
        case keyfind(x, 1, vars) do
          false ->
            lit

          {^x, var} ->
            var
        end

      %{} ->
        lit
    end
  end

  defp unfold_arg(expr, _LitMap, _X) do
    expr
  end

  defp ssa_opt_tail_literals({st, funcDb}) do
    r_opt_st(cnt: count0, ssa: blocks0) = st
    true = is_map(blocks0)
    {count, blocks} = opt_tail_literals(:beam_ssa.rpo(blocks0), count0, blocks0)
    {r_opt_st(st, cnt: count, ssa: blocks), funcDb}
  end

  defp opt_tail_literals([l | ls], count, blocks0) do
    r_b_blk(is: is0, last: last) =
      blk0 =
      :erlang.map_get(
        l,
        blocks0
      )

    case is_tail_literal(is0, last, blocks0) do
      {:yes, var} ->
        retBlk = r_b_blk(is: [], last: r_b_ret(arg: var))
        retLbl = count
        blk = r_b_blk(blk0, last: r_b_br(last, succ: retLbl))
        blocks = Map.put(%{blocks0 | l => blk}, retLbl, retBlk)
        opt_tail_literals(ls, count + 1, blocks)

      :no ->
        opt_tail_literals(ls, count, blocks0)
    end
  end

  defp opt_tail_literals([], count, blocks) do
    {count, blocks}
  end

  defp is_tail_literal(
         [r_b_set(op: :call, dst: dst) = call, r_b_set(op: {:succeeded, :body}, dst: bool)],
         r_b_br(bool: r_b_var() = bool, succ: succ),
         blocks
       ) do
    case blocks do
      %{^succ => r_b_blk(is: [], last: r_b_ret(arg: r_b_literal(val: val)))} ->
        type = :beam_ssa.get_anno(:result_type, call, :any)

        case :beam_types.get_singleton_value(type) do
          {:ok, ^val} ->
            {:yes, dst}

          _ ->
            :no
        end

      %{} ->
        :no
    end
  end

  defp is_tail_literal([_ | is], r_b_br() = last, blocks) do
    is_tail_literal(is, last, blocks)
  end

  defp is_tail_literal(_Is, _Last, _Blocks) do
    :no
  end

  defp ssa_opt_redundant_br({r_opt_st(ssa: blocks0) = st, funcDb})
       when is_map(blocks0) do
    blocks = redundant_br(:beam_ssa.rpo(blocks0), blocks0)
    {r_opt_st(st, ssa: blocks), funcDb}
  end

  defp redundant_br([l | ls], blocks0) do
    blk0 = :erlang.map_get(l, blocks0)

    case blk0 do
      r_b_blk(
        is: is,
        last: r_b_br(bool: r_b_var() = bool, succ: succ, fail: fail)
      ) ->
        case blocks0 do
          %{
            ^succ => r_b_blk(is: [], last: r_b_ret(arg: r_b_literal(val: true))),
            ^fail => r_b_blk(is: [], last: r_b_ret(arg: r_b_literal(val: false)))
          } ->
            case redundant_br_safe_bool(is, bool) do
              true ->
                blk = r_b_blk(blk0, last: r_b_ret(arg: bool))
                blocks = Map.put(blocks0, l, blk)
                redundant_br(ls, blocks)

              false ->
                redundant_br(ls, blocks0)
            end

          %{
            ^succ => r_b_blk(is: [], last: r_b_br(succ: phiL, fail: phiL)),
            ^fail => r_b_blk(is: [], last: r_b_br(succ: phiL, fail: phiL))
          } ->
            case redundant_br_safe_bool(is, bool) do
              true ->
                blocks = redundant_br_phi(l, blk0, phiL, blocks0)
                redundant_br(ls, blocks)

              false ->
                redundant_br(ls, blocks0)
            end

          %{
            ^succ => r_b_blk(is: [], last: r_b_ret(arg: other)),
            ^fail => r_b_blk(is: [], last: r_b_ret(arg: var))
          }
          when is !== [] ->
            case last(is) do
              r_b_set(op: {:bif, :"=:="}, args: [^var, ^other]) ->
                blk = r_b_blk(blk0, is: droplast(is), last: r_b_ret(arg: var))
                blocks = Map.put(blocks0, l, blk)
                redundant_br(ls, blocks)

              r_b_set() ->
                redundant_br(ls, blocks0)
            end

          %{} ->
            redundant_br(ls, blocks0)
        end

      _ ->
        redundant_br(ls, blocks0)
    end
  end

  defp redundant_br([], blocks) do
    blocks
  end

  defp redundant_br_phi(l, blk0, phiL, blocks) do
    r_b_blk(is: is0) = phiBlk0 = :erlang.map_get(phiL, blocks)

    case is0 do
      [r_b_set(op: :phi), r_b_set(op: :phi) | _] ->
        blocks

      [r_b_set(op: :phi, args: phiArgs0) = i0 | is] ->
        r_b_blk(last: r_b_br(succ: succ, fail: fail)) = blk0
        boolPhiArgs = [{r_b_literal(val: false), fail}, {r_b_literal(val: true), succ}]
        phiArgs1 = :ordsets.from_list(phiArgs0)

        case :ordsets.is_subset(boolPhiArgs, phiArgs1) do
          true ->
            r_b_blk(last: r_b_br(bool: bool)) = blk0
            phiArgs = :ordsets.add_element({bool, l}, phiArgs1)
            i = r_b_set(i0, args: phiArgs)
            phiBlk = r_b_blk(phiBlk0, is: [i | is])
            br = r_b_br(bool: r_b_literal(val: true), succ: phiL, fail: phiL)
            blk = r_b_blk(blk0, last: br)
            %{blocks | l => blk, phiL => phiBlk}

          false ->
            blocks
        end
    end
  end

  defp redundant_br_safe_bool([], _Bool) do
    true
  end

  defp redundant_br_safe_bool(is, bool) do
    case last(is) do
      r_b_set(op: {:bif, _}) ->
        true

      r_b_set(op: :has_map_field) ->
        true

      r_b_set(dst: dst) ->
        dst !== bool
    end
  end

  defp ssa_opt_bs_ensure({r_opt_st(ssa: blocks0, cnt: count0) = st, funcDb})
       when is_map(blocks0) do
    rPO = :beam_ssa.rpo(blocks0)
    seen = :sets.new([{:version, 2}])
    {blocks, count} = ssa_opt_bs_ensure(rPO, seen, count0, blocks0)
    {r_opt_st(st, ssa: blocks, cnt: count), funcDb}
  end

  defp ssa_opt_bs_ensure([l | ls], seen0, count0, blocks0) do
    case :sets.is_element(l, seen0) do
      true ->
        ssa_opt_bs_ensure(ls, seen0, count0, blocks0)

      false ->
        case is_bs_match_blk(l, blocks0) do
          :no ->
            ssa_opt_bs_ensure(ls, seen0, count0, blocks0)

          {:yes, size0, r_b_br(succ: succ, fail: fail)} ->
            {size, blocks1, seen} = ssa_opt_bs_ensure_collect(succ, fail, blocks0, seen0, size0)
            blocks2 = annotate_match(l, blocks1)
            {blocks, count} = build_bs_ensure_match(l, size, count0, blocks2)
            ssa_opt_bs_ensure(ls, seen, count, blocks)
        end
    end
  end

  defp ssa_opt_bs_ensure([], _Seen, count, blocks) do
    {blocks, count}
  end

  defp ssa_opt_bs_ensure_collect(l, fail, blocks0, seen0, acc0) do
    case is_bs_match_blk(l, blocks0) do
      :no ->
        {acc0, blocks0, seen0}

      {:yes, size, r_b_br(succ: succ, fail: ^fail)} ->
        case update_size(size, acc0) do
          :no ->
            {acc0, blocks0, seen0}

          acc ->
            seen = :sets.add_element(l, seen0)
            blocks = annotate_match(l, blocks0)
            ssa_opt_bs_ensure_collect(succ, fail, blocks, seen, acc)
        end

      {:yes, _, _} ->
        {acc0, blocks0, seen0}
    end
  end

  defp annotate_match(l, blocks) do
    r_b_blk(is: is0) = blk0 = :erlang.map_get(l, blocks)

    is =
      for i <- is0 do
        case i do
          r_b_set(op: :bs_match) ->
            :beam_ssa.add_anno(:ensured, true, i)

          r_b_set() ->
            i
        end
      end

    blk = r_b_blk(blk0, is: is)
    %{blocks | l => blk}
  end

  defp update_size(
         {{prevCtx, newCtx}, size, unit},
         {{_, prevCtx}, sum, unit0}
       ) do
    {{prevCtx, newCtx}, sum + size, max(unit, unit0)}
  end

  defp update_size(_, _) do
    :no
  end

  defp is_bs_match_blk(l, blocks) do
    blk = :erlang.map_get(l, blocks)

    case blk do
      r_b_blk(is: is, last: r_b_br(bool: r_b_var()) = last) ->
        case is_bs_match_is(is) do
          :no ->
            :no

          {:yes, ctxSizeUnit} ->
            {:yes, ctxSizeUnit, last}
        end

      r_b_blk() ->
        :no
    end
  end

  defp is_bs_match_is([
         r_b_set(op: :bs_match, dst: dst) = i,
         r_b_set(op: {:succeeded, :guard}, args: [dst])
       ]) do
    case is_viable_match(i) do
      :no ->
        :no

      {:yes, {ctx, size, unit}} when size >>> 24 === 0 ->
        {:yes, {{ctx, dst}, size, unit}}

      {:yes, _} ->
        :no
    end
  end

  defp is_bs_match_is([_ | is]) do
    is_bs_match_is(is)
  end

  defp is_bs_match_is([]) do
    :no
  end

  defp is_viable_match(r_b_set(op: :bs_match, args: args)) do
    case args do
      [r_b_literal(val: :binary), ctx, _, r_b_literal(val: :all), r_b_literal(val: u)]
      when is_integer(u) and 1 <= u and u <= 256 ->
        {:yes, {ctx, 0, u}}

      [r_b_literal(val: :binary), ctx, _, r_b_literal(val: size), r_b_literal(val: u)]
      when is_integer(size) ->
        {:yes, {ctx, size * u, 1}}

      [r_b_literal(val: :integer), ctx, _, r_b_literal(val: size), r_b_literal(val: u)]
      when is_integer(size) ->
        {:yes, {ctx, size * u, 1}}

      [r_b_literal(val: :skip), ctx, _, _, r_b_literal(val: :all), r_b_literal(val: u)] ->
        {:yes, {ctx, 0, u}}

      [r_b_literal(val: :skip), ctx, _, _, r_b_literal(val: size), r_b_literal(val: u)]
      when is_integer(size) ->
        {:yes, {ctx, size * u, 1}}

      [r_b_literal(val: :string), ctx, r_b_literal(val: str)]
      when bit_size(str) <= 64 ->
        {:yes, {ctx, bit_size(str), 1}}

      _ ->
        :no
    end
  end

  defp build_bs_ensure_match(l, {_, size, unit}, count0, blocks0) do
    bsMatchL = count0
    count1 = count0 + 1
    {newCtx, count2} = new_var(:"@context", count1)
    {succBool, count} = new_var(:"@ssa_bool", count2)
    bsMatchBlk0 = :erlang.map_get(l, blocks0)
    r_b_blk(is: matchIs, last: r_b_br(fail: fail)) = bsMatchBlk0

    {prefix, suffix0} =
      splitwith(
        fn r_b_set(op: op) ->
          op !== :bs_match
        end,
        matchIs
      )

    [bsMatch0 | suffix1] = suffix0
    r_b_set(args: [type, _Ctx | args]) = bsMatch0
    bsMatch = r_b_set(bsMatch0, args: [type, newCtx | args])
    suffix = [bsMatch | suffix1]
    bsMatchBlk = r_b_blk(bsMatchBlk0, is: suffix)
    r_b_set(args: [_, ctx | _]) = keyfind(:bs_match, r_b_set(:op), matchIs)

    is =
      prefix ++
        [
          r_b_set(
            op: :bs_ensure,
            dst: newCtx,
            args: [ctx, r_b_literal(val: size), r_b_literal(val: unit)]
          ),
          r_b_set(op: {:succeeded, :guard}, dst: succBool, args: [newCtx])
        ]

    blk =
      r_b_blk(
        is: is,
        last: r_b_br(bool: succBool, succ: bsMatchL, fail: fail)
      )

    blocks = Map.put(%{blocks0 | l => blk}, bsMatchL, bsMatchBlk)
    {blocks, count}
  end

  defp list_set_union([], set) do
    set
  end

  defp list_set_union([e], set) do
    :sets.add_element(e, set)
  end

  defp list_set_union(list, set) do
    :sets.union(:sets.from_list(list, [{:version, 2}]), set)
  end

  defp non_guards(linear) do
    :gb_sets.from_list(non_guards_1(linear))
  end

  defp non_guards_1([{l, r_b_blk(is: is)} | bs]) do
    case is do
      [r_b_set(op: :landingpad) | _] ->
        [l | non_guards_1(bs)]

      _ ->
        non_guards_1(bs)
    end
  end

  defp non_guards_1([]) do
    [1]
  end

  defp rel2fam(s0) do
    s1 = :sofs.relation(s0)
    s = :sofs.rel2fam(s1)
    :sofs.to_external(s)
  end

  defp sub(i, sub) do
    :beam_ssa.normalize(sub_1(i, sub))
  end

  defp sub_1(r_b_set(op: :phi, args: args) = i, sub) do
    r_b_set(i,
      args:
        for {a, p} <- args do
          {sub_arg(a, sub), p}
        end
    )
  end

  defp sub_1(r_b_set(args: args) = i, sub) do
    r_b_set(i,
      args:
        for a <- args do
          sub_arg(a, sub)
        end
    )
  end

  defp sub_1(r_b_br(bool: r_b_var() = old) = br, sub) do
    new = sub_arg(old, sub)
    r_b_br(br, bool: new)
  end

  defp sub_1(r_b_switch(arg: r_b_var() = old) = sw, sub) do
    new = sub_arg(old, sub)
    r_b_switch(sw, arg: new)
  end

  defp sub_1(r_b_ret(arg: r_b_var() = old) = ret, sub) do
    new = sub_arg(old, sub)
    r_b_ret(ret, arg: new)
  end

  defp sub_1(last, _) do
    last
  end

  defp sub_arg(r_b_remote(mod: mod, name: name) = rem, sub) do
    r_b_remote(rem,
      mod: sub_arg(mod, sub),
      name: sub_arg(name, sub)
    )
  end

  defp sub_arg(old, sub) do
    case sub do
      %{^old => new} ->
        new

      %{} ->
        old
    end
  end

  defp new_var(r_b_var(name: {base, n}), count) do
    true = is_integer(n)
    {r_b_var(name: {base, count}), count + 1}
  end

  defp new_var(r_b_var(name: base), count) do
    {r_b_var(name: {base, count}), count + 1}
  end

  defp new_var(base, count) when is_atom(base) do
    {r_b_var(name: {base, count}), count + 1}
  end
end
