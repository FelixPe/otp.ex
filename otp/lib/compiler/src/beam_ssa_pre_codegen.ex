defmodule :m_beam_ssa_pre_codegen do
  use Bitwise

  import :lists,
    only: [
      all: 2,
      any: 2,
      append: 1,
      duplicate: 2,
      foldl: 3,
      last: 1,
      member: 2,
      partition: 2,
      reverse: 1,
      reverse: 2,
      seq: 2,
      sort: 1,
      sort: 2,
      usort: 1,
      zip: 2
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

  Record.defrecord(:r_t_atom, :t_atom, elements: :any)

  Record.defrecord(:r_t_bitstring, :t_bitstring,
    size_unit: 1,
    appendable: false
  )

  Record.defrecord(:r_t_bs_context, :t_bs_context, tail_unit: 1)
  Record.defrecord(:r_t_bs_matchable, :t_bs_matchable, tail_unit: 1)
  Record.defrecord(:r_t_float, :t_float, elements: :any)
  Record.defrecord(:r_t_fun, :t_fun, arity: :any, target: :any, type: :any)
  Record.defrecord(:r_t_integer, :t_integer, elements: :any)
  Record.defrecord(:r_t_number, :t_number, elements: :any)

  Record.defrecord(:r_t_map, :t_map,
    super_key: :any,
    super_value: :any
  )

  Record.defrecord(:r_t_cons, :t_cons,
    type: :any,
    terminator: :any
  )

  Record.defrecord(:r_t_list, :t_list,
    type: :any,
    terminator: :any
  )

  Record.defrecord(:r_t_tuple, :t_tuple, size: 0, exact: false, elements: %{})

  Record.defrecord(:r_t_union, :t_union,
    atom: :none,
    list: :none,
    number: :none,
    tuple_set: :none,
    other: :none
  )

  Record.defrecord(:r_tr, :tr, r: :undefined, t: :undefined)

  def module(r_b_module(body: fs0) = module, opts) do
    ps = passes(opts)
    fs1 = functions(fs0, ps)
    fs = create_fc_stubs(fs1, module)
    {:ok, r_b_module(module, body: fs)}
  end

  defp functions([f | fs], ps) do
    [function(f, ps) | functions(fs, ps)]
  end

  defp functions([], _Ps) do
    []
  end

  Record.defrecord(:r_st, :st,
    ssa: :undefined,
    args: :undefined,
    cnt: :undefined,
    frames: [],
    intervals: [],
    res: [],
    regs: %{},
    extra_annos: [],
    location: :undefined
  )

  defp passes(opts) do
    addPrecgAnnos = :proplists.get_bool(:dprecg, opts)

    ps = [
      {:assert_no_critical_edges, &assert_no_critical_edges/1},
      {:fix_bs, &fix_bs/1},
      {:sanitize, &sanitize/1},
      {:expand_match_fail, &expand_match_fail/1},
      {:expand_update_tuple, &expand_update_tuple/1},
      {:place_frames, &place_frames/1},
      {:fix_receives, &fix_receives/1},
      {:find_yregs, &find_yregs/1},
      {:reserve_yregs, &reserve_yregs/1},
      {:copy_retval, &copy_retval/1},
      {:opt_get_list, &opt_get_list/1},
      {:number_instructions, &number_instructions/1},
      {:live_intervals, &live_intervals/1},
      {:reserve_regs, &reserve_regs/1},
      case addPrecgAnnos do
        false ->
          :ignore

        true ->
          {:save_live_intervals, &save_live_intervals/1}
      end,
      {:linear_scan, &linear_scan/1},
      {:frame_size, &frame_size/1},
      {:turn_yregs, &turn_yregs/1},
      {:assert_no_critical_edges, &assert_no_critical_edges/1}
    ]

    for p <- ps, p !== :ignore do
      p
    end
  end

  defp function(
         r_b_function(anno: anno, args: args, bs: blocks0, cnt: count0) = f0,
         ps
       ) do
    try do
      location = :maps.get(:location, anno, :none)
      st0 = r_st(ssa: blocks0, args: args, cnt: count0, location: location)
      st = :compile.run_sub_passes(ps, st0)
      r_st(ssa: blocks, cnt: count, regs: regs, extra_annos: extraAnnos) = st
      f1 = add_extra_annos(f0, extraAnnos)
      f = :beam_ssa.add_anno(:registers, regs, f1)
      r_b_function(f, bs: blocks, cnt: count)
    catch
      class, error ->
        %{func_info: {_, name, arity}} = anno
        :io.fwrite(~c"Function: ~w/~w\n", [name, arity])
        :erlang.raise(class, error, __STACKTRACE__)
    end
  end

  defp save_live_intervals(r_st(intervals: intervals) = st) do
    r_st(st, extra_annos: [{:live_intervals, intervals}])
  end

  defp add_extra_annos(f, annos) do
    foldl(
      fn {name, value}, acc ->
        :beam_ssa.add_anno(name, value, acc)
      end,
      f,
      annos
    )
  end

  defp assert_no_critical_edges(r_st(ssa: blocks) = st) do
    f = &assert_no_ces/3
    rPO = :beam_ssa.rpo(blocks)
    :beam_ssa.fold_blocks(f, rPO, blocks, blocks)
    st
  end

  defp assert_no_ces(
         _,
         r_b_blk(is: [r_b_set(op: :phi, args: [_, _] = phis) | _]),
         blocks
       ) do
    true =
      all(
        fn {_, p} ->
          length(:beam_ssa.successors(p, blocks)) === 1
        end,
        phis
      )

    blocks
  end

  defp assert_no_ces(_, _, blocks) do
    blocks
  end

  defp fix_bs(r_st(ssa: blocks, cnt: count0) = st) do
    f = fn
      r_b_set(op: :bs_start_match, dst: dst), a ->
        Map.put(a, dst, {:context, dst})

      r_b_set(op: :bs_ensure, dst: dst, args: [parentCtx | _]), a ->
        Map.put(a, dst, parentCtx)

      r_b_set(op: :bs_match, dst: dst, args: [_, parentCtx | _]), a ->
        Map.put(a, dst, parentCtx)

      _, a ->
        a
    end

    rPO = :beam_ssa.rpo(blocks)
    ctxChain = :beam_ssa.fold_instrs(f, rPO, %{}, blocks)

    case map_size(ctxChain) do
      0 ->
        st

      _ ->
        linear0 = :beam_ssa.linearize(blocks)
        {linear1, count} = bs_pos_bsm3(linear0, ctxChain, count0)
        linear = bs_instrs(linear1, ctxChain, [])
        r_st(st, ssa: :maps.from_list(linear), cnt: count)
    end
  end

  defp bs_pos_bsm3(linear0, ctxChain, count0) do
    rs0 = bs_restores(linear0, ctxChain, %{}, %{})
    rs = :maps.values(rs0)
    s0 = :sofs.relation(rs, [{:context, :save_point}])
    s1 = :sofs.relation_to_family(s0)
    s = :sofs.to_external(s1)
    {savePoints, count1} = make_bs_pos_dict(s, count0, [])
    {gets, count2} = make_bs_getpos_map(rs, savePoints, count1, [])
    {sets, count} = make_bs_setpos_map(:maps.to_list(rs0), savePoints, count2, [])
    {bs_insert_bsm3(linear0, gets, sets), count}
  end

  defp make_bs_getpos_map([{ctx, save} = ps | t], savePoints, count, acc) do
    savePoint = get_savepoint(ps, savePoints)
    i = r_b_set(op: :bs_get_position, dst: savePoint, args: [ctx])
    make_bs_getpos_map(t, savePoints, count + 1, [{save, i} | acc])
  end

  defp make_bs_getpos_map([], _, count, acc) do
    {:maps.from_list(acc), count}
  end

  defp make_bs_setpos_map([{bef, {ctx, _} = ps} | t], savePoints, count, acc) do
    ignored = r_b_var(name: {:"@ssa_ignored", count})
    args = [ctx, get_savepoint(ps, savePoints)]
    i = r_b_set(op: :bs_set_position, dst: ignored, args: args)
    make_bs_setpos_map(t, savePoints, count + 1, [{bef, i} | acc])
  end

  defp make_bs_setpos_map([], _, count, acc) do
    {:maps.from_list(acc), count}
  end

  defp get_savepoint({_, _} = ps, savePoints) do
    name = {:"@ssa_bs_position", :erlang.map_get(ps, savePoints)}
    r_b_var(name: name)
  end

  defp make_bs_pos_dict([{ctx, pts} | t], count0, acc0) do
    {acc, count} = make_bs_pos_dict_1(pts, ctx, count0, acc0)
    make_bs_pos_dict(t, count, acc)
  end

  defp make_bs_pos_dict([], count, acc) do
    {:maps.from_list(acc), count}
  end

  defp make_bs_pos_dict_1([h | t], ctx, i, acc) do
    make_bs_pos_dict_1(t, ctx, i + 1, [{{ctx, h}, i} | acc])
  end

  defp make_bs_pos_dict_1([], ctx, i, acc) do
    {[{ctx, i} | acc], i}
  end

  defp bs_restores([{l, r_b_blk(is: is, last: last)} | bs], ctxChain, d0, rs0) do
    inPos = :maps.get(l, d0, %{})
    {succPos, failPos, rs} = bs_restores_is(is, ctxChain, inPos, inPos, rs0)
    d = bs_update_successors(last, succPos, failPos, d0)
    bs_restores(bs, ctxChain, d, rs)
  end

  defp bs_restores([], _, _, rs) do
    rs
  end

  defp bs_update_successors(r_b_br(succ: succ, fail: fail), sPos, fPos, d) do
    join_positions([{succ, sPos}, {fail, fPos}], d)
  end

  defp bs_update_successors(r_b_switch(fail: fail, list: list), sPos, fPos, d) do
    ^sPos = fPos

    update =
      for {_, l} <- list do
        {l, sPos}
      end ++ [{fail, sPos}]

    join_positions(update, d)
  end

  defp bs_update_successors(r_b_ret(), sPos, fPos, d) do
    ^sPos = fPos
    d
  end

  defp join_positions([{l, mapPos0} | t], d) do
    case d do
      %{^l => ^mapPos0} ->
        join_positions(t, d)

      %{^l => mapPos1} ->
        mapPos = join_positions_1(mapPos0, mapPos1)
        join_positions(t, %{d | l => mapPos})

      %{} ->
        join_positions(t, Map.put(d, l, mapPos0))
    end
  end

  defp join_positions([], d) do
    d
  end

  defp join_positions_1(lHS, rHS) do
    cond do
      map_size(lHS) < map_size(rHS) ->
        join_positions_2(:maps.keys(lHS), rHS, lHS)

      true ->
        join_positions_2(:maps.keys(rHS), lHS, rHS)
    end
  end

  defp join_positions_2([v | vs], bigger, smaller) do
    case {bigger, smaller} do
      {%{^v => same}, %{^v => same}} ->
        join_positions_2(vs, bigger, smaller)

      {%{^v => _}, %{^v => _}} ->
        join_positions_2(vs, bigger, %{smaller | v => :unknown})

      {%{}, %{^v => _}} ->
        join_positions_2(vs, bigger, :maps.remove(v, smaller))
    end
  end

  defp join_positions_2([], _Bigger, smaller) do
    smaller
  end

  defp bs_restores_is([r_b_set(op: :bs_start_match, dst: start) | is], ctxChain, sPos0, _FPos, rs) do
    fPos = sPos0
    sPos = Map.put(sPos0, start, start)
    bs_restores_is(is, ctxChain, sPos, fPos, rs)
  end

  defp bs_restores_is(
         [
           r_b_set(op: :bs_ensure, dst: newPos, args: args)
           | is
         ],
         ctxChain,
         sPos0,
         _FPos,
         rs0
       ) do
    start = bs_subst_ctx(newPos, ctxChain)
    [fromPos, r_b_literal(val: bits) | _] = args

    case sPos0 do
      %{^start => ^fromPos} ->
        sPos =
          case bits do
            0 ->
              sPos0

            _ ->
              %{sPos0 | start => newPos}
          end

        fPos = sPos0
        bs_restores_is(is, ctxChain, sPos, fPos, rs0)

      %{} ->
        sPos = %{sPos0 | start => newPos}
        fPos = %{sPos0 | start => fromPos}
        rs = Map.put(rs0, newPos, {start, fromPos})
        bs_restores_is(is, ctxChain, sPos, fPos, rs)
    end
  end

  defp bs_restores_is(
         [
           r_b_set(anno: %{ensured: _}, op: :bs_match, dst: newPos, args: args)
           | is
         ],
         ctxChain,
         sPos0,
         _FPos,
         rs
       ) do
    start = bs_subst_ctx(newPos, ctxChain)

    case args do
      [r_b_literal(val: :skip), _FromPos, _Type, _Flags, r_b_literal(val: :all), _] ->
        sPos = fPos = sPos0
        bs_restores_is(is, ctxChain, sPos, fPos, rs)

      [_, fromPos | _] ->
        sPos = %{sPos0 | start => newPos}
        fPos = %{sPos0 | start => fromPos}
        bs_restores_is(is, ctxChain, sPos, fPos, rs)
    end
  end

  defp bs_restores_is(
         [
           r_b_set(op: :bs_match, dst: newPos, args: args) = i
           | is
         ],
         ctxChain,
         sPos0,
         _FPos,
         rs0
       ) do
    start = bs_subst_ctx(newPos, ctxChain)
    [_, fromPos | _] = args

    case sPos0 do
      %{^start => ^fromPos} ->
        sPos =
          case bs_match_type(i) do
            :plain ->
              %{sPos0 | start => newPos}

            _ ->
              sPos0
          end

        fPos = sPos0
        bs_restores_is(is, ctxChain, sPos, fPos, rs0)

      %{^start => _} ->
        case bs_match_type(i) do
          :none ->
            fPos = sPos0
            bs_restores_is(is, ctxChain, sPos0, fPos, rs0)

          :test_unit ->
            sPos = %{sPos0 | start => fromPos}
            fPos = sPos
            rs = Map.put(rs0, newPos, {start, fromPos})
            bs_restores_is(is, ctxChain, sPos, fPos, rs)

          :plain ->
            sPos = %{sPos0 | start => newPos}
            fPos = %{sPos0 | start => fromPos}
            rs = Map.put(rs0, newPos, {start, fromPos})
            bs_restores_is(is, ctxChain, sPos, fPos, rs)
        end
    end
  end

  defp bs_restores_is(
         [r_b_set(op: :bs_extract, args: [fromPos | _]) | is],
         ctxChain,
         sPos,
         _FPos,
         rs
       ) do
    start = bs_subst_ctx(fromPos, ctxChain)
    %{^start => ^fromPos} = sPos
    fPos = sPos
    bs_restores_is(is, ctxChain, sPos, fPos, rs)
  end

  defp bs_restores_is(
         [r_b_set(op: :call, dst: dst, args: args) | is],
         ctxChain,
         sPos0,
         _FPos,
         rs0
       ) do
    {sPos1, rs} = bs_restore_args(args, sPos0, ctxChain, dst, rs0)
    sPos = bs_invalidate_pos(args, sPos1, ctxChain)
    fPos = sPos
    bs_restores_is(is, ctxChain, sPos, fPos, rs)
  end

  defp bs_restores_is([r_b_set(op: op, dst: dst, args: args) | is], ctxChain, sPos0, _FPos, rs0)
       when op === :bs_test_tail or op === :bs_get_tail do
    {sPos, rs} = bs_restore_args(args, sPos0, ctxChain, dst, rs0)
    fPos = sPos
    bs_restores_is(is, ctxChain, sPos, fPos, rs)
  end

  defp bs_restores_is([r_b_set(op: {:succeeded, :guard}, args: [arg])], ctxChain, sPos, fPos0, rs) do
    ctx = bs_subst_ctx(arg, ctxChain)

    fPos =
      case sPos do
        %{^ctx => _} ->
          fPos0

        %{} ->
          sPos
      end

    {sPos, fPos, rs}
  end

  defp bs_restores_is([_ | is], ctxChain, sPos, _FPos, rs) do
    fPos = sPos
    bs_restores_is(is, ctxChain, sPos, fPos, rs)
  end

  defp bs_restores_is([], _CtxChain, sPos, _FPos, rs) do
    fPos = sPos
    {sPos, fPos, rs}
  end

  defp bs_match_type(
         r_b_set(
           args: [
             r_b_literal(val: :skip),
             _Ctx,
             r_b_literal(val: :binary),
             _Flags,
             r_b_literal(val: :all),
             r_b_literal(val: u)
           ]
         )
       ) do
    case u do
      1 ->
        :none

      _ ->
        :test_unit
    end
  end

  defp bs_match_type(_) do
    :plain
  end

  defp bs_invalidate_pos([r_b_var() = arg | args], pos0, ctxChain) do
    start = bs_subst_ctx(arg, ctxChain)

    case pos0 do
      %{^start => _} ->
        pos = %{pos0 | start => :unknown}
        bs_invalidate_pos(args, pos, ctxChain)

      %{} ->
        bs_invalidate_pos(args, pos0, ctxChain)
    end
  end

  defp bs_invalidate_pos([_ | args], pos, ctxChain) do
    bs_invalidate_pos(args, pos, ctxChain)
  end

  defp bs_invalidate_pos([], pos, _CtxChain) do
    pos
  end

  defp bs_restore_args([r_b_var() = arg | args], pos0, ctxChain, dst, rs0) do
    start = bs_subst_ctx(arg, ctxChain)

    case pos0 do
      %{^start => ^arg} ->
        bs_restore_args(args, pos0, ctxChain, dst, rs0)

      %{^start => _} ->
        pos = %{pos0 | start => arg}
        rs = Map.put(rs0, dst, {start, arg})
        bs_restore_args(args, pos, ctxChain, dst, rs)

      %{} ->
        bs_restore_args(args, pos0, ctxChain, dst, rs0)
    end
  end

  defp bs_restore_args([_ | args], pos, ctxChain, dst, rs) do
    bs_restore_args(args, pos, ctxChain, dst, rs)
  end

  defp bs_restore_args([], pos, _CtxChain, _Dst, rs) do
    {pos, rs}
  end

  defp bs_insert_bsm3(blocks, saves, restores) do
    bs_insert_1(blocks, [], saves, restores)
  end

  defp bs_insert_1([{l, r_b_blk(is: is0) = blk} | bs], deferred0, saves, restores) do
    is1 = bs_insert_deferred(is0, deferred0)
    {is, deferred} = bs_insert_is(is1, saves, restores, [])
    [{l, r_b_blk(blk, is: is)} | bs_insert_1(bs, deferred, saves, restores)]
  end

  defp bs_insert_1([], [], _, _) do
    []
  end

  defp bs_insert_deferred([r_b_set(op: :bs_extract) = i | is], deferred) do
    [i | bs_insert_deferred(is, deferred)]
  end

  defp bs_insert_deferred(is, deferred) do
    deferred ++ is
  end

  defp bs_insert_is([r_b_set(dst: dst) = i | is], saves, restores, acc0) do
    pre =
      case restores do
        %{^dst => r} ->
          [r]

        %{} ->
          []
      end

    post =
      case saves do
        %{^dst => s} ->
          [s]

        %{} ->
          []
      end

    acc = [i | pre] ++ acc0

    case is do
      [r_b_set(op: {:succeeded, _}, args: [^dst])] ->
        {reverse(acc, is), post}

      _ ->
        bs_insert_is(is, saves, restores, post ++ acc)
    end
  end

  defp bs_insert_is([], _, _, acc) do
    {reverse(acc), []}
  end

  defp bs_instrs([{l, r_b_blk(is: is0) = blk} | bs], ctxChain, acc0) do
    case bs_instrs_is(is0, ctxChain, []) do
      [r_b_set(op: :bs_extract, dst: dst, args: [ctx]) | is] ->
        acc = bs_combine(dst, ctx, acc0)
        bs_instrs(bs, ctxChain, [{l, r_b_blk(blk, is: is)} | acc])

      is ->
        bs_instrs(bs, ctxChain, [{l, r_b_blk(blk, is: is)} | acc0])
    end
  end

  defp bs_instrs([], _, acc) do
    bs_rewrite_skip(acc)
  end

  defp bs_rewrite_skip([{l, r_b_blk(is: is0, last: last0) = blk} | bs]) do
    case bs_rewrite_skip_is(is0, []) do
      :no ->
        [{l, blk} | bs_rewrite_skip(bs)]

      {:yes, is} ->
        r_b_br(succ: succ) = last0
        last = :beam_ssa.normalize(r_b_br(last0, fail: succ))
        [{l, r_b_blk(blk, is: is, last: last)} | bs_rewrite_skip(bs)]
    end
  end

  defp bs_rewrite_skip([]) do
    []
  end

  defp bs_rewrite_skip_is(
         [r_b_set(anno: %{ensured: true}, op: :bs_skip) = i0, r_b_set(op: {:succeeded, :guard})],
         acc
       ) do
    i = r_b_set(i0, op: :bs_checked_skip)
    {:yes, reverse(acc, [i])}
  end

  defp bs_rewrite_skip_is([i | is], acc) do
    bs_rewrite_skip_is(is, [i | acc])
  end

  defp bs_rewrite_skip_is([], _Acc) do
    :no
  end

  defp bs_instrs_is([r_b_set(op: {:succeeded, _}) = i | is], ctxChain, acc) do
    bs_instrs_is(is, ctxChain, [i | acc])
  end

  defp bs_instrs_is([r_b_set(anno: anno0, op: op, args: args0) = i0 | is], ctxChain, acc) do
    args =
      for a <- args0 do
        bs_subst_ctx(a, ctxChain)
      end

    i1 = r_b_set(i0, args: args)

    i =
      case {op, args} do
        {:bs_match, [r_b_literal(val: :skip), ctx, type | as]} ->
          anno =
            case anno0 do
              %{arg_types: %{4 => sizeType}} ->
                %{anno0 | arg_types: %{3 => sizeType}}

              %{} ->
                anno0
            end

          r_b_set(i1, anno: anno, op: :bs_skip, args: [type, ctx | as])

        {:bs_match, [r_b_literal(val: :string), ctx | as]} ->
          r_b_set(i1, op: :bs_match_string, args: [ctx | as])

        {_, _} ->
          i1
      end

    bs_instrs_is(is, ctxChain, [i | acc])
  end

  defp bs_instrs_is([], _, acc) do
    reverse(acc)
  end

  defp bs_combine(dst, ctx, [{l, r_b_blk(is: is0) = blk} | acc]) do
    [
      r_b_set() = succeeded,
      r_b_set(anno: anno, op: :bs_match, args: [type, _ | as]) = bsMatch
      | is1
    ] = reverse(is0)

    cond do
      :erlang.is_map_key(:ensured, anno) ->
        is =
          reverse(
            is1,
            [r_b_set(bsMatch, op: :bs_checked_get, dst: dst, args: [type, ctx | as])]
          )

        r_b_blk(last: r_b_br(succ: succ) = br0) = blk
        br = :beam_ssa.normalize(r_b_br(br0, fail: succ))
        [{l, r_b_blk(blk, is: is, last: br)} | acc]

      true ->
        is =
          reverse(
            is1,
            [
              r_b_set(bsMatch, op: :bs_get, dst: dst, args: [type, ctx | as]),
              r_b_set(succeeded, args: [dst])
            ]
          )

        [{l, r_b_blk(blk, is: is)} | acc]
    end
  end

  defp bs_subst_ctx(r_b_var() = var, ctxChain) do
    case ctxChain do
      %{^var => {:context, ctx}} ->
        ctx

      %{^var => parentCtx} ->
        bs_subst_ctx(parentCtx, ctxChain)

      %{} ->
        var
    end
  end

  defp bs_subst_ctx(other, _CtxChain) do
    other
  end

  defp sanitize(r_st(ssa: blocks0, cnt: count0) = st) do
    ls = :beam_ssa.rpo(blocks0)
    {blocks, count} = sanitize(ls, blocks0, count0, %{}, %{0 => :reachable})
    r_st(st, ssa: blocks, cnt: count)
  end

  defp sanitize([l | ls], inBlocks, count0, values0, blocks0) do
    case :erlang.is_map_key(l, blocks0) do
      false ->
        sanitize(ls, inBlocks, count0, values0, blocks0)

      true ->
        r_b_blk(is: is0, last: last0) =
          blk0 =
          :erlang.map_get(
            l,
            inBlocks
          )

        case sanitize_is(is0, last0, inBlocks, blocks0, count0, values0, false, []) do
          :no_change ->
            blk = sanitize_last(blk0, values0)
            blocks1 = %{blocks0 | l => blk}
            blocks = sanitize_reachable(blk, blocks1)
            sanitize(ls, inBlocks, count0, values0, blocks)

          {is, last, count, values} ->
            blk1 = r_b_blk(blk0, is: is, last: last)
            blk = sanitize_last(blk1, values)
            blocks1 = %{blocks0 | l => blk}
            blocks = sanitize_reachable(blk, blocks1)
            sanitize(ls, inBlocks, count, values, blocks)
        end
    end
  end

  defp sanitize([], _InBlocks, count, _Values, blocks) do
    {blocks, count}
  end

  defp sanitize_reachable(blk, blocks) do
    foldl(
      fn
        s, a when :erlang.is_map_key(s, a) ->
          a

        s, a ->
          Map.put(a, s, :reachable)
      end,
      blocks,
      :beam_ssa.successors(blk)
    )
  end

  defp sanitize_is(
         [
           r_b_set(op: :get_map_element, args: args0) = i0
           | is
         ],
         last,
         inBlocks,
         blocks,
         count0,
         values,
         changed,
         acc
       ) do
    case sanitize_args(args0, values) do
      [r_b_literal() = map, key] ->
        {mapVar, count} = new_var(:"@ssa_map", count0)
        i = r_b_set(i0, args: [mapVar, key])
        copy = r_b_set(op: :copy, dst: mapVar, args: [map])
        sanitize_is(is, last, inBlocks, blocks, count, values, true, [i, copy | acc])

      [_, _] = ^args0 ->
        sanitize_is(is, last, inBlocks, blocks, count0, values, changed, [i0 | acc])

      [_, _] = args ->
        i = r_b_set(i0, args: args)
        sanitize_is(is, last, inBlocks, blocks, count0, values, true, [i | acc])
    end
  end

  defp sanitize_is(
         [
           r_b_set(op: :call, dst: callDst) = call,
           r_b_set(op: {:succeeded, :body}, dst: succDst, args: [callDst]) = succ
         ],
         r_b_br(bool: succDst, succ: succLbl, fail: 1) = last0,
         inBlocks,
         blocks,
         count,
         values,
         changed,
         acc
       ) do
    case inBlocks do
      %{^succLbl => r_b_blk(is: [], last: r_b_ret(arg: ^callDst) = last)} ->
        do_sanitize_is(call, [], last, inBlocks, blocks, count, values, true, acc)

      %{} ->
        do_sanitize_is(call, [succ], last0, inBlocks, blocks, count, values, changed, acc)
    end
  end

  defp sanitize_is(
         [
           r_b_set(op: op, dst: dst) = fail,
           r_b_set(
             op: {:succeeded, :body},
             args: [dst]
           )
         ],
         r_b_br(fail: 1),
         inBlocks,
         blocks,
         count,
         values,
         _Changed,
         acc
       )
       when op === :match_fail or op === :resume do
    last = r_b_ret(arg: dst)
    do_sanitize_is(fail, [], last, inBlocks, blocks, count, values, true, acc)
  end

  defp sanitize_is(
         [
           r_b_set(op: :match_fail, dst: raiseDst),
           r_b_set(op: {:succeeded, :guard}, dst: succDst, args: [raiseDst])
         ],
         r_b_br(bool: succDst) = last0,
         inBlocks,
         blocks,
         count,
         values,
         _Changed,
         acc
       ) do
    last = :beam_ssa.normalize(r_b_br(last0, bool: r_b_literal(val: false)))
    sanitize_is([], last, inBlocks, blocks, count, values, true, acc)
  end

  defp sanitize_is(
         [r_b_set(op: {:succeeded, _Kind}, dst: dst, args: [arg0]) = i0],
         r_b_br(bool: dst) = last,
         _InBlocks,
         _Blocks,
         count,
         values,
         _Changed,
         acc
       ) do
    case sanitize_arg(arg0, values) do
      r_b_var() = arg ->
        i = r_b_set(i0, op: :succeeded, args: [arg])
        {reverse(acc, [i]), last, count, values}

      r_b_literal() ->
        value = r_b_literal(val: true)
        {reverse(acc), last, count, Map.put(values, dst, value)}
    end
  end

  defp sanitize_is(
         [r_b_set(op: {:succeeded, kind}, args: [arg0]) | is],
         last,
         inBlocks,
         blocks,
         count,
         values,
         _Changed,
         acc
       ) do
    [] = is
    r_b_br(succ: same, fail: same) = last

    cond do
      same === 1 ->
        :body = kind
        arg = sanitize_arg(arg0, values)
        sanitize_is(is, r_b_ret(arg: arg), inBlocks, blocks, count, values, true, acc)

      same !== 1 ->
        true = kind === :guard or kind === :body
        sanitize_is(is, last, inBlocks, blocks, count, values, true, acc)
    end
  end

  defp sanitize_is(
         [r_b_set(op: :bs_test_tail) = i],
         last,
         inBlocks,
         blocks,
         count,
         values,
         changed,
         acc
       ) do
    case last do
      r_b_br(succ: same, fail: same) ->
        sanitize_is([], last, inBlocks, blocks, count, values, true, acc)

      _ ->
        do_sanitize_is(i, [], last, inBlocks, blocks, count, values, changed, acc)
    end
  end

  defp sanitize_is(
         [r_b_set(op: :bs_get, args: args0) = i0 | is],
         last,
         inBlocks,
         blocks,
         count,
         values,
         changed,
         acc
       ) do
    case {args0, sanitize_args(args0, values)} do
      {[_, _, _, r_b_var(), _], [type, val, flags, r_b_literal(val: :all), unit]} ->
        args = [type, val, flags, r_b_literal(val: :bad_size), unit]
        i = r_b_set(i0, args: args)
        sanitize_is(is, last, inBlocks, blocks, count, values, true, [i | acc])

      {_, args} ->
        i = r_b_set(i0, args: args)
        sanitize_is(is, last, inBlocks, blocks, count, values, changed, [i | acc])
    end
  end

  defp sanitize_is([r_b_set() = i | is], last, inBlocks, blocks, count, values, changed, acc) do
    do_sanitize_is(i, is, last, inBlocks, blocks, count, values, changed, acc)
  end

  defp sanitize_is([], last, _InBlocks, _Blocks, count, values, changed, acc) do
    case changed do
      true ->
        {reverse(acc), last, count, values}

      false ->
        :no_change
    end
  end

  defp do_sanitize_is(
         r_b_set(op: op, dst: dst, args: args0) = i0,
         is,
         last,
         inBlocks,
         blocks,
         count,
         values,
         changed0,
         acc
       ) do
    args = sanitize_args(args0, values)

    case sanitize_instr(op, args, i0, blocks) do
      {:subst, subst} ->
        sanitize_is(is, last, inBlocks, blocks, count, Map.put(values, dst, subst), true, acc)

      {:ok, i} ->
        sanitize_is(is, last, inBlocks, blocks, count, values, true, [i | acc])

      :ok ->
        i = r_b_set(i0, args: args)
        changed = changed0 or args !== args0
        sanitize_is(is, last, inBlocks, blocks, count, values, changed, [i | acc])
    end
  end

  defp sanitize_last(r_b_blk(last: last0) = blk, values) do
    last =
      case last0 do
        r_b_br(bool: r_b_literal()) ->
          last0

        r_b_br(bool: bool) ->
          :beam_ssa.normalize(
            r_b_br(last0,
              bool:
                sanitize_arg(
                  bool,
                  values
                )
            )
          )

        r_b_ret(arg: arg) ->
          r_b_ret(last0, arg: sanitize_arg(arg, values))

        r_b_switch(arg: arg) ->
          :beam_ssa.normalize(
            r_b_switch(last0,
              arg:
                sanitize_arg(
                  arg,
                  values
                )
            )
          )
      end

    cond do
      last !== last0 ->
        r_b_blk(blk, last: last)

      true ->
        blk
    end
  end

  defp sanitize_args(args, values) do
    for arg <- args do
      sanitize_arg(arg, values)
    end
  end

  defp sanitize_arg(r_b_remote(mod: mod0, name: name0) = remote, values) do
    mod = sanitize_arg(mod0, values)
    name = sanitize_arg(name0, values)
    r_b_remote(remote, mod: mod, name: name)
  end

  defp sanitize_arg({r_b_var() = var, l}, values) do
    {sanitize_arg(var, values), l}
  end

  defp sanitize_arg(r_b_var() = var, values) do
    case values do
      %{^var => new} ->
        new

      %{} ->
        var
    end
  end

  defp sanitize_arg(arg, _Values) do
    arg
  end

  defp sanitize_instr(:phi, phiArgs0, i, blocks) do
    phiArgs =
      for {v, l} <- phiArgs0,
          :erlang.is_map_key(l, blocks) do
        {v, l}
      end

    case phi_all_same(phiArgs) do
      true ->
        [{subst, _} | _] = phiArgs
        {:subst, subst}

      false ->
        {:ok, r_b_set(i, args: phiArgs)}
    end
  end

  defp sanitize_instr(op, args, i, _Blocks) do
    sanitize_instr(op, args, i)
  end

  defp sanitize_instr({:bif, bif}, [r_b_literal(val: lit)], _I) do
    case :erl_bifs.is_pure(:erlang, bif, 1) do
      false ->
        :ok

      true ->
        try do
          {:subst, r_b_literal(val: apply(:erlang, bif, [lit]))}
        catch
          :error, _ ->
            :ok
        end
    end
  end

  defp sanitize_instr({:bif, bif}, [r_b_literal(val: lit1), r_b_literal(val: lit2)], _I) do
    true = :erl_bifs.is_pure(:erlang, bif, 2)

    try do
      {:subst, r_b_literal(val: apply(:erlang, bif, [lit1, lit2]))}
    catch
      :error, _ ->
        :ok
    end
  end

  defp sanitize_instr(:bs_match, args, i) do
    {:ok, r_b_set(i, op: :bs_get, args: args)}
  end

  defp sanitize_instr(:get_hd, [r_b_literal(val: [hd | _])], _I) do
    {:subst, r_b_literal(val: hd)}
  end

  defp sanitize_instr(:get_tl, [r_b_literal(val: [_ | tl])], _I) do
    {:subst, r_b_literal(val: tl)}
  end

  defp sanitize_instr(:get_tuple_element, [r_b_literal(val: t), r_b_literal(val: i)], _I)
       when i < tuple_size(t) do
    {:subst, r_b_literal(val: :erlang.element(i + 1, t))}
  end

  defp sanitize_instr(:is_nonempty_list, [r_b_literal(val: term)], _I) do
    lit =
      case term do
        [_ | _] ->
          true

        _ ->
          false
      end

    {:subst, r_b_literal(val: lit)}
  end

  defp sanitize_instr(
         :is_tagged_tuple,
         [r_b_literal(val: tuple), r_b_literal(val: arity), r_b_literal(val: tag)],
         _I
       )
       when is_integer(arity) and is_atom(tag) do
    cond do
      tuple_size(tuple) === arity and
          :erlang.element(1, tuple) === tag ->
        {:subst, r_b_literal(val: true)}

      true ->
        {:subst, r_b_literal(val: false)}
    end
  end

  defp sanitize_instr(:succeeded, [r_b_literal()], _I) do
    {:subst, r_b_literal(val: true)}
  end

  defp sanitize_instr(_, _, _) do
    :ok
  end

  defp phi_all_same([{arg, _From} | phis]) do
    phi_all_same_1(phis, arg)
  end

  defp phi_all_same_1([{arg, _From} | phis], arg) do
    phi_all_same_1(phis, arg)
  end

  defp phi_all_same_1([], _Arg) do
    true
  end

  defp phi_all_same_1(_Phis, _Arg) do
    false
  end

  defp expand_match_fail(r_st(ssa: blocks0, cnt: count0, args: args, location: location) = st) do
    bs = :maps.to_list(blocks0)
    {blocks, count} = expand_mf_bs(bs, length(args), location, blocks0, count0)
    r_st(st, ssa: blocks, cnt: count)
  end

  defp expand_mf_bs([{l, r_b_blk(is: is0) = blk} | bs], arity, location, blocks0, count0) do
    case expand_mf_is(is0, arity, location, count0, []) do
      :none ->
        expand_mf_bs(bs, arity, location, blocks0, count0)

      {is, count} ->
        blocks = %{blocks0 | l => r_b_blk(blk, is: is)}
        expand_mf_bs(bs, arity, location, blocks, count)
    end
  end

  defp expand_mf_bs([], _Arity, _Location, blocks, count) do
    {blocks, count}
  end

  defp expand_mf_is(
         [
           r_b_set(op: :match_fail, anno: anno, args: [r_b_literal(val: :function_clause) | args]) =
             i0
           | is
         ],
         arity,
         location,
         count0,
         acc
       ) do
    case anno do
      %{location: ^location} when length(args) === arity ->
        :none

      %{inlined: {name, inlinedArity}}
      when length(args) === inlinedArity ->
        target = r_b_local(name: r_b_literal(val: name), arity: inlinedArity)
        i = r_b_set(i0, op: :call, args: [target | args])
        {reverse(acc, [i | is]), count0}
    end
  end

  defp expand_mf_is([r_b_set(op: :match_fail) = i | is], _Arity, _Location, count, acc) do
    expand_mf_instr(i, is, count, acc)
  end

  defp expand_mf_is([i | is], arity, location, count, acc) do
    expand_mf_is(is, arity, location, count, [i | acc])
  end

  defp expand_mf_is(_, _, _, _, _) do
    :none
  end

  defp expand_mf_instr(
         r_b_set(args: [r_b_literal(val: :case_clause) | args]) = i0,
         is,
         count,
         acc
       ) do
    i = r_b_set(i0, args: [r_b_literal(val: :case_end) | args])
    {reverse(acc, [i | is]), count}
  end

  defp expand_mf_instr(r_b_set(args: [r_b_literal(val: :if_clause) | args]) = i0, is, count, acc) do
    i = r_b_set(i0, args: [r_b_literal(val: :if_end) | args])
    {reverse(acc, [i | is]), count}
  end

  defp expand_mf_instr(r_b_set(args: [r_b_literal(val: :try_clause) | args]) = i0, is, count, acc) do
    i = r_b_set(i0, args: [r_b_literal(val: :try_case_end) | args])
    {reverse(acc, [i | is]), count}
  end

  defp expand_mf_instr(r_b_set(args: [r_b_literal(val: :badmatch) | _Args]) = i, is, count, acc) do
    {reverse(acc, [i | is]), count}
  end

  defp expand_mf_instr(r_b_set(args: [r_b_literal(val: :badrecord) | _Args]) = i, is, count, acc) do
    {reverse(acc, [i | is]), count}
  end

  defp expand_mf_instr(r_b_set(args: [r_b_literal() | _] = args) = i0, is, count0, acc) do
    {tuple, count} = new_var(:"@match_fail", count0)
    put = r_b_set(op: :put_tuple, dst: tuple, args: args)

    call =
      r_b_set(i0,
        op: :call,
        args: [
          r_b_remote(mod: r_b_literal(val: :erlang), name: r_b_literal(val: :error), arity: 1),
          tuple
        ]
      )

    {reverse(acc, [put, call | is]), count}
  end

  defp create_fc_stubs(fs, r_b_module(name: mod)) do
    stubs0 = usort(find_fc_errors(fs, []))

    stubs =
      for {{name, arity}, location} <- stubs0 do
        seq = seq(0, arity - 1)

        args =
          for v <- seq do
            r_b_var(name: v)
          end

        xRegs =
          for v <- seq do
            {:x, v}
          end

        ret = r_b_var(name: :"@ssa_ret")

        regs =
          :maps.from_list([
            {ret, {:x, 0}}
            | zip(
                args,
                xRegs
              )
          ])

        anno = %{
          func_info: {mod, name, arity},
          location: location,
          parameter_info: %{},
          registers: regs
        }

        fc = r_b_set(op: :match_fail, dst: ret, args: [r_b_literal(val: :function_clause) | args])
        blk = r_b_blk(is: [fc], last: r_b_ret(arg: ret))
        r_b_function(anno: anno, args: args, bs: %{0 => blk}, cnt: 1)
      end

    fs ++ stubs
  end

  defp find_fc_errors([r_b_function(bs: blocks) | fs], acc0) do
    f = fn
      r_b_set(anno: anno, op: :call, args: [r_b_local() | _]), a ->
        case anno do
          %{inlined: fA} ->
            [{fA, :maps.get(:location, anno, [])} | a]

          %{} ->
            a
        end

      _, a ->
        a
    end

    acc = :beam_ssa.fold_instrs(f, :maps.keys(blocks), acc0, blocks)
    find_fc_errors(fs, acc)
  end

  defp find_fc_errors([], acc) do
    acc
  end

  defp expand_update_tuple(r_st(ssa: blocks0, cnt: count0) = st) do
    linear0 = :beam_ssa.linearize(blocks0)
    {linear, count} = expand_update_tuple_1(linear0, count0, [])
    blocks = :maps.from_list(linear)
    r_st(st, ssa: blocks, cnt: count)
  end

  defp expand_update_tuple_1([{l, r_b_blk(is: is0) = b0} | bs], count0, acc0) do
    case expand_update_tuple_is(is0, count0, []) do
      {is, count} ->
        expand_update_tuple_1(bs, count, [{l, r_b_blk(b0, is: is)} | acc0])

      {is, nextIs, count1} ->
        r_b_blk(last: br) = b0
        r_b_br(succ: succ) = br
        nextL = count1
        count = count1 + 1
        nextBr = r_b_br(bool: r_b_literal(val: true), succ: succ, fail: succ)
        nextB = r_b_blk(is: nextIs, last: nextBr)
        b = r_b_blk(b0, is: is, last: r_b_br(br, succ: nextL))
        acc = [{nextL, nextB}, {l, b} | acc0]
        expand_update_tuple_1(bs, count, acc)
    end
  end

  defp expand_update_tuple_1([], count, acc) do
    {acc, count}
  end

  defp expand_update_tuple_is(
         [
           r_b_set(op: :update_tuple, args: [src | args]) = i0
           | is
         ],
         count0,
         acc
       ) do
    {setElement, sets, count} = expand_update_tuple_list(args, i0, src, count0)

    case {sets, is} do
      {[_ | _], [r_b_set(op: :succeeded)]} ->
        {reverse(acc, [setElement | is]), reverse(sets), count}

      {_, _} ->
        expand_update_tuple_is(is, count, sets ++ [setElement | acc])
    end
  end

  defp expand_update_tuple_is([i | is], count, acc) do
    expand_update_tuple_is(is, count, [i | acc])
  end

  defp expand_update_tuple_is([], count, acc) do
    {reverse(acc), count}
  end

  defp expand_update_tuple_list(args, i0, src, count0) do
    [index, value | rest] = sort_update_tuple(args, [])

    i =
      r_b_set(i0,
        op: :call,
        args: [
          r_b_remote(
            mod: r_b_literal(val: :erlang),
            name: r_b_literal(val: :setelement),
            arity: 3
          ),
          index,
          src,
          value
        ]
      )

    {sets, count} = expand_update_tuple_list_1(rest, r_b_set(i, :dst), count0, [])
    {i, sets, count}
  end

  defp expand_update_tuple_list_1([], _Src, count, acc) do
    {acc, count}
  end

  defp expand_update_tuple_list_1([index0, value | updates], src, count0, acc) do
    index = r_b_literal(val: r_b_literal(index0, :val) - 1)
    {dst, count} = new_var(:"@ssa_dummy", count0)
    setOp = r_b_set(op: :set_tuple_element, dst: dst, args: [value, src, index])
    expand_update_tuple_list_1(updates, src, count, [setOp | acc])
  end

  defp sort_update_tuple([_Index, _Value] = args, []) do
    args
  end

  defp sort_update_tuple([r_b_literal() = index, value | updates], acc) do
    sort_update_tuple(updates, [{index, value} | acc])
  end

  defp sort_update_tuple([], acc) do
    append(
      for {index, value} <- sort(&(:erlang.unquote(:>=) / 2), acc) do
        [index, value]
      end
    )
  end

  defp place_frames(r_st(ssa: blocks) = st) do
    ls = :beam_ssa.rpo(blocks)
    {doms, _} = :beam_ssa.dominators(ls, blocks)
    tried = :gb_sets.empty()
    frames0 = []
    {frames, _} = place_frames_1(ls, blocks, doms, tried, frames0)
    r_st(st, frames: frames)
  end

  defp place_frames_1([l | ls], blocks, doms, tried0, frames0) do
    blk = :erlang.map_get(l, blocks)

    case need_frame(blk) do
      true ->
        {frames, tried} = do_place_frame(l, blocks, doms, tried0, frames0)
        place_frames_1(ls, blocks, doms, tried, frames)

      false ->
        try do
          place_frames_1(ls, blocks, doms, tried0, frames0)
        catch
          {:need_frame, for, tried1} = reason ->
            case is_dominated_by(for, l, doms) do
              true ->
                {frames, tried} = do_place_frame(l, blocks, doms, tried1, frames0)
                place_frames_1(ls, blocks, doms, tried, frames)

              false ->
                throw(reason)
            end
        end
    end
  end

  defp place_frames_1([], _, _, tried, frames) do
    {frames, tried}
  end

  defp do_place_frame(l, blocks, doms, tried0, frames) do
    case :gb_sets.is_element(l, tried0) do
      true ->
        {frames, tried0}

      false ->
        tried = :gb_sets.insert(l, tried0)

        case place_frame_here(l, blocks, doms, frames) do
          :yes ->
            {[l | frames], tried}

          :no ->
            {frames, tried}

          :ancestor ->
            throw({:need_frame, l, tried})
        end
    end
  end

  defp place_frame_here(l, blocks, doms, frames) do
    b0 =
      any(
        fn domBy ->
          is_dominated_by(l, domBy, doms)
        end,
        frames
      )

    case b0 do
      true ->
        :no

      false ->
        descendants = :beam_ssa.rpo([l], blocks)
        phiPredecessors = phi_predecessors(l, blocks)
        mustDominate = :ordsets.from_list(phiPredecessors ++ descendants)

        dominates =
          all(
            fn
              1 ->
                true

              bl ->
                is_dominated_by(bl, l, doms)
            end,
            mustDominate
          )

        isLoopHeader = is_loop_header(l, blocks)

        case dominates and not isLoopHeader do
          true ->
            :yes

          false ->
            :ancestor
        end
    end
  end

  defp phi_predecessors(l, blocks) do
    r_b_blk(is: is) = :erlang.map_get(l, blocks)

    for r_b_set(op: :phi, args: args) <- is, {_, p} <- args do
      p
    end
  end

  defp is_dominated_by(l, domBy, doms) do
    dominatedBy = :erlang.map_get(l, doms)
    member(domBy, dominatedBy)
  end

  defp need_frame(r_b_blk(is: is, last: r_b_ret(arg: ret))) do
    need_frame_1(is, {:return, ret})
  end

  defp need_frame(r_b_blk(is: is)) do
    need_frame_1(is, :body)
  end

  defp need_frame_1(
         [r_b_set(op: :old_make_fun, dst: fun) | is],
         {:return, ret} = context
       ) do
    case need_frame_1(is, context) do
      true ->
        true

      false ->
        defs =
          :ordsets.from_list(
            for r_b_set(dst: dst) <- is do
              dst
            end
          )

        blk = r_b_blk(is: is, last: r_b_ret(arg: ret))
        used = :ordsets.subtract(:beam_ssa.used(blk), defs)

        case used do
          [] ->
            false

          [^fun] ->
            false

          [_ | _] ->
            true
        end
    end
  end

  defp need_frame_1([r_b_set(op: :new_try_tag) | _], _) do
    true
  end

  defp need_frame_1(
         [r_b_set(op: :call, dst: val)] = is,
         {:return, ret}
       ) do
    cond do
      val === ret ->
        need_frame_1(is, :tail)

      true ->
        need_frame_1(is, :body)
    end
  end

  defp need_frame_1(
         [r_b_set(op: :call, args: [func | _]) | is],
         context
       ) do
    case func do
      r_b_remote(mod: r_b_literal(val: mod), name: r_b_literal(val: name), arity: arity)
      when is_atom(mod) and is_atom(name) ->
        context === :body or is !== [] or is_trap_bif(mod, name, arity)

      r_b_remote() ->
        true

      r_b_local() ->
        context === :body or is !== []

      _ ->
        true
    end
  end

  defp need_frame_1([i | is], context) do
    :beam_ssa.clobbers_xregs(i) or need_frame_1(is, context)
  end

  defp need_frame_1([], _) do
    false
  end

  defp is_trap_bif(:erlang, :!, 2) do
    true
  end

  defp is_trap_bif(:erlang, :link, 1) do
    true
  end

  defp is_trap_bif(:erlang, :unlink, 1) do
    true
  end

  defp is_trap_bif(:erlang, :monitor_node, 2) do
    true
  end

  defp is_trap_bif(:erlang, :group_leader, 2) do
    true
  end

  defp is_trap_bif(:erlang, :exit, 2) do
    true
  end

  defp is_trap_bif(_, _, _) do
    false
  end

  defp fix_receives(r_st(ssa: blocks0, cnt: count0) = st) do
    {blocks, count} = fix_receives_1(:maps.to_list(blocks0), blocks0, count0)
    r_st(st, ssa: blocks, cnt: count)
  end

  defp fix_receives_1([{l, blk} | ls], blocks0, count0) do
    case blk do
      r_b_blk(is: [r_b_set(op: :peek_message) | _]) ->
        rm0 = find_rm_blocks(l, blocks0)
        {rm, blocks1, count1} = split_rm_blocks(rm0, blocks0, count0, [])
        loopExit = find_loop_exit(rm, blocks1)
        rPO = :beam_ssa.rpo([l], blocks1)
        defs0 = :beam_ssa.def(rPO, blocks1)
        commonUsed = recv_common(defs0, loopExit, blocks1)
        {blocks2, count2} = recv_crit_edges(rm, loopExit, blocks1, count1)
        {blocks3, count3} = recv_fix_common(commonUsed, loopExit, rm, blocks2, count2)
        defs = :ordsets.subtract(defs0, commonUsed)
        {blocks, count} = fix_receive(rm, defs, blocks3, count3)
        fix_receives_1(ls, blocks, count)

      r_b_blk() ->
        fix_receives_1(ls, blocks0, count0)
    end
  end

  defp fix_receives_1([], blocks, count) do
    {blocks, count}
  end

  defp split_rm_blocks([l | ls], blocks0, count0, acc) do
    r_b_blk(is: is) = :erlang.map_get(l, blocks0)

    case need_split(is) do
      false ->
        split_rm_blocks(ls, blocks0, count0, [l | acc])

      true ->
        p = fn r_b_set(op: op) ->
          op === :remove_message
        end

        next = count0
        {blocks, count} = :beam_ssa.split_blocks([l], p, blocks0, count0)
        true = count0 !== count
        split_rm_blocks(ls, blocks, count, [next | acc])
    end
  end

  defp split_rm_blocks([], blocks, count, acc) do
    {reverse(acc), blocks, count}
  end

  defp need_split([r_b_set(op: op) | t]) do
    case op do
      :get_tuple_element ->
        need_split(t)

      :recv_marker_clear ->
        need_split(t)

      :remove_message ->
        false

      _ ->
        true
    end
  end

  defp recv_common(_Defs, :none, _Blocks) do
    []
  end

  defp recv_common(defs, exit, blocks) do
    rPO = :beam_ssa.rpo([exit], blocks)
    {exitDefs, exitUnused} = :beam_ssa.def_unused(rPO, defs, blocks)
    def__ = :ordsets.subtract(defs, exitDefs)
    :ordsets.subtract(def__, exitUnused)
  end

  defp recv_crit_edges(_Rms, :none, blocks0, count0) do
    {blocks0, count0}
  end

  defp recv_crit_edges(rms, exit, blocks0, count0) do
    ls = :beam_ssa.rpo(rms, blocks0)
    rce_insert_edges(ls, exit, count0, blocks0)
  end

  defp rce_insert_edges([l | ls], exit, count0, blocks0) do
    successors =
      :beam_ssa.successors(
        :erlang.map_get(
          l,
          blocks0
        )
      )

    case member(exit, successors) do
      true when successors !== [exit] ->
        {blocks, count} = rce_insert_edge(l, exit, count0, blocks0)
        rce_insert_edges(ls, exit, count, blocks)

      _ ->
        rce_insert_edges(ls, exit, count0, blocks0)
    end
  end

  defp rce_insert_edges([], _Exit, count, blocks) do
    {blocks, count}
  end

  defp rce_insert_edge(l, exit, count, blocks0) do
    r_b_blk(last: last0) =
      fromBlk0 =
      :erlang.map_get(
        l,
        blocks0
      )

    toExit = r_b_br(bool: r_b_literal(val: true), succ: exit, fail: exit)
    fromBlk = r_b_blk(fromBlk0, last: rce_reroute_terminator(last0, exit, count))
    edgeBlk = r_b_blk(anno: %{}, is: [], last: toExit)
    blocks = Map.merge(blocks0, %{count => edgeBlk, l => fromBlk})
    {blocks, count + 1}
  end

  defp rce_reroute_terminator(r_b_br(succ: exit) = last, exit, new) do
    rce_reroute_terminator(r_b_br(last, succ: new), exit, new)
  end

  defp rce_reroute_terminator(r_b_br(fail: exit) = last, exit, new) do
    rce_reroute_terminator(r_b_br(last, fail: new), exit, new)
  end

  defp rce_reroute_terminator(r_b_br() = last, _Exit, _New) do
    last
  end

  defp rce_reroute_terminator(r_b_switch(fail: exit) = last, exit, new) do
    rce_reroute_terminator(r_b_switch(last, fail: new), exit, new)
  end

  defp rce_reroute_terminator(r_b_switch(list: list0) = last, exit, new) do
    list =
      for {arg, lbl} <- list0 do
        cond do
          lbl === exit ->
            {arg, new}

          lbl !== exit ->
            {arg, lbl}
        end
      end

    r_b_switch(last, list: list)
  end

  defp recv_fix_common([msg0 | t], exit, rm, blocks0, count0) do
    {msg, count1} = new_var(:"@recv", count0)
    rPO = :beam_ssa.rpo([exit], blocks0)
    blocks1 = :beam_ssa.rename_vars(%{msg0 => msg}, rPO, blocks0)
    n = length(rm)
    {msgVars, count} = new_vars(duplicate(n, :"@recv"), count1)
    phiArgs = fix_exit_phi_args(msgVars, rm, exit, blocks1)
    phi = r_b_set(op: :phi, dst: msg, args: phiArgs)
    exitBlk0 = :erlang.map_get(exit, blocks1)
    exitBlk = r_b_blk(exitBlk0, is: [phi | r_b_blk(exitBlk0, :is)])
    blocks2 = %{blocks1 | exit => exitBlk}
    blocks = recv_fix_common_1(msgVars, rm, msg0, blocks2)
    recv_fix_common(t, exit, rm, blocks, count)
  end

  defp recv_fix_common([], _, _, blocks, count) do
    {blocks, count}
  end

  defp recv_fix_common_1([v | vs], [rm | rms], msg, blocks0) do
    ren = %{msg => v}
    rPO = :beam_ssa.rpo([rm], blocks0)
    blocks1 = :beam_ssa.rename_vars(ren, rPO, blocks0)
    r_b_blk(is: is0) = blk0 = :erlang.map_get(rm, blocks1)
    copy = r_b_set(op: :copy, dst: v, args: [msg])
    is = [copy | is0]
    blk = r_b_blk(blk0, is: is)
    blocks = %{blocks1 | rm => blk}
    recv_fix_common_1(vs, rms, msg, blocks)
  end

  defp recv_fix_common_1([], [], _Msg, blocks) do
    blocks
  end

  defp fix_exit_phi_args([v | vs], [rm | rms], exit, blocks) do
    path = :beam_ssa.rpo([rm], blocks)
    preds = exit_predecessors(path, exit, blocks)

    for pred <- preds do
      {v, pred}
    end ++ fix_exit_phi_args(vs, rms, exit, blocks)
  end

  defp fix_exit_phi_args([], [], _, _) do
    []
  end

  defp exit_predecessors([l | ls], exit, blocks) do
    blk = :erlang.map_get(l, blocks)

    case member(exit, :beam_ssa.successors(blk)) do
      true ->
        [l | exit_predecessors(ls, exit, blocks)]

      false ->
        exit_predecessors(ls, exit, blocks)
    end
  end

  defp exit_predecessors([], _Exit, _Blocks) do
    []
  end

  defp fix_receive([l | ls], defs, blocks0, count0) do
    rPO = :beam_ssa.rpo([l], blocks0)
    {rmDefs, unused} = :beam_ssa.def_unused(rPO, defs, blocks0)
    def__ = :ordsets.subtract(defs, rmDefs)
    used = :ordsets.subtract(def__, unused)

    {newVars, count} =
      new_vars(
        for r_b_var(name: base) <- used do
          base
        end,
        count0
      )

    ren = zip(used, newVars)
    blocks1 = :beam_ssa.rename_vars(ren, rPO, blocks0)
    r_b_blk(is: is0) = blk1 = :erlang.map_get(l, blocks1)

    is =
      for {old, new} <- ren do
        r_b_set(op: :copy, dst: new, args: [old])
      end ++ is0

    blk = r_b_blk(blk1, is: is)
    blocks = %{blocks1 | l => blk}
    fix_receive(ls, defs, blocks, count)
  end

  defp fix_receive([], _Defs, blocks, count) do
    {blocks, count}
  end

  defp find_loop_exit([_, _ | _] = rmBlocks, blocks) do
    rPO = :beam_ssa.rpo(blocks)
    {dominators, _} = :beam_ssa.dominators(rPO, blocks)
    rmSet = :sets.from_list(rmBlocks, [{:version, 2}])
    rmRPO = :beam_ssa.rpo(rmBlocks, blocks)
    find_loop_exit_1(rmRPO, rmSet, dominators, blocks)
  end

  defp find_loop_exit(_, _) do
    :none
  end

  defp find_loop_exit_1([1 | ls], rmSet, dominators, blocks) do
    find_loop_exit_1(ls, rmSet, dominators, blocks)
  end

  defp find_loop_exit_1([l | ls0], rmSet, dominators, blocks) do
    domBy = :erlang.map_get(l, dominators)

    case any(
           fn e ->
             :sets.is_element(e, rmSet)
           end,
           domBy
         ) do
      true ->
        find_loop_exit_1(ls0, rmSet, dominators, blocks)

      false ->
        case :erlang.map_get(l, blocks) do
          r_b_blk(is: [r_b_set(op: :landingpad) | _]) ->
            ls = ls0 -- :beam_ssa.rpo([l], blocks)
            find_loop_exit_1(ls, rmSet, dominators, blocks)

          r_b_blk() ->
            l
        end
    end
  end

  defp find_loop_exit_1([], _, _, _) do
    :none
  end

  defp find_rm_blocks(l, blocks) do
    seen = :gb_sets.singleton(l)
    blk = :erlang.map_get(l, blocks)
    succ = :beam_ssa.successors(blk)
    find_rm_blocks_1(succ, seen, blocks)
  end

  defp find_rm_blocks_1([l | ls], seen0, blocks) do
    case :gb_sets.is_member(l, seen0) do
      true ->
        find_rm_blocks_1(ls, seen0, blocks)

      false ->
        seen = :gb_sets.insert(l, seen0)
        blk = :erlang.map_get(l, blocks)

        case find_rm_act(r_b_blk(blk, :is)) do
          :prune ->
            find_rm_blocks_1(ls, seen, blocks)

          :continue ->
            succ = :beam_ssa.successors(blk)
            find_rm_blocks_1(succ ++ ls, seen, blocks)

          :found ->
            [l | find_rm_blocks_1(ls, seen, blocks)]
        end
    end
  end

  defp find_rm_blocks_1([], _, _) do
    []
  end

  defp find_rm_act([r_b_set(op: op) | is]) do
    case op do
      :remove_message ->
        :found

      :peek_message ->
        :prune

      :recv_next ->
        :prune

      :wait_timeout ->
        :prune

      _ ->
        find_rm_act(is)
    end
  end

  defp find_rm_act([]) do
    :continue
  end

  Record.defrecord(:r_dk, :dk, d: :undefined, k: :undefined)

  defp find_yregs(r_st(frames: []) = st) do
    st
  end

  defp find_yregs(r_st(frames: [_ | _] = frames, args: args, ssa: blocks0) = st) do
    frameDefs =
      find_defs(
        frames,
        blocks0,
        for r_b_var() = v <- args do
          v
        end
      )

    blocks = find_yregs_1(frameDefs, blocks0)
    r_st(st, ssa: blocks)
  end

  defp find_yregs_1([{f, defs} | fs], blocks0) do
    dK = r_dk(d: defs, k: :sets.new([{:version, 2}]))
    d0 = %{f => dK, 1 => r_dk(dK, d: [])}
    ls = :beam_ssa.rpo([f], blocks0)
    yregs0 = :sets.new([{:version, 2}])
    yregs = find_yregs_2(ls, blocks0, d0, yregs0)
    blk0 = :erlang.map_get(f, blocks0)
    blk = :beam_ssa.add_anno(:yregs, yregs, blk0)
    blocks = %{blocks0 | f => blk}
    find_yregs_1(fs, blocks)
  end

  defp find_yregs_1([], blocks) do
    blocks
  end

  defp find_yregs_2([l | ls], blocks0, d0, yregs0) do
    blk0 = :erlang.map_get(l, blocks0)
    r_b_blk(is: is, last: last) = blk0
    ys0 = :erlang.map_get(l, d0)
    {yregs1, ys} = find_yregs_is(is, ys0, yregs0)
    yregs = find_yregs_terminator(last, ys, yregs1)
    successors = :beam_ssa.successors(blk0)
    d = find_update_succ(successors, ys, d0)
    find_yregs_2(ls, blocks0, d, yregs)
  end

  defp find_yregs_2([], _Blocks, _D, yregs) do
    yregs
  end

  defp find_defs(frames, blocks, defs) do
    seen = :gb_sets.empty()
    framesSet = :gb_sets.from_list(frames)
    {frameDefs, _} = find_defs_1([0], blocks, framesSet, seen, defs, [])
    frameDefs
  end

  defp find_defs_1([l | ls], blocks, frames, seen0, defs0, acc0) do
    case :gb_sets.is_member(l, frames) do
      true ->
        orderedDefs = :ordsets.from_list(defs0)
        find_defs_1(ls, blocks, frames, seen0, defs0, [{l, orderedDefs} | acc0])

      false ->
        case :gb_sets.is_member(l, seen0) do
          true ->
            find_defs_1(ls, blocks, frames, seen0, defs0, acc0)

          false ->
            seen1 = :gb_sets.insert(l, seen0)
            {acc, seen} = find_defs_1(ls, blocks, frames, seen1, defs0, acc0)
            r_b_blk(is: is) = blk = :erlang.map_get(l, blocks)
            defs = find_defs_is(is, defs0)
            successors = :beam_ssa.successors(blk)
            find_defs_1(successors, blocks, frames, seen, defs, acc)
        end
    end
  end

  defp find_defs_1([], _, _, seen, _, acc) do
    {acc, seen}
  end

  defp find_defs_is([r_b_set(dst: dst) | is], acc) do
    find_defs_is(is, [dst | acc])
  end

  defp find_defs_is([], acc) do
    acc
  end

  defp find_update_succ([1 | ss], dK, d) do
    find_update_succ(ss, dK, d)
  end

  defp find_update_succ([s | ss], r_dk(d: defs0, k: killed0) = dK0, d0) do
    case d0 do
      %{^s => r_dk(d: defs1, k: killed1)} ->
        defs = :ordsets.intersection(defs0, defs1)
        killed = :sets.union(killed0, killed1)
        dK = r_dk(d: defs, k: killed)
        d = %{d0 | s => dK}
        find_update_succ(ss, dK0, d)

      %{} ->
        d = Map.put(d0, s, dK0)
        find_update_succ(ss, dK0, d)
    end
  end

  defp find_update_succ([], _, d) do
    d
  end

  defp find_yregs_is([r_b_set(dst: dst) = i | is], r_dk(d: defs0, k: killed0) = ys, yregs0) do
    yregs1 = intersect_used(i, killed0)
    yregs = :sets.union(yregs0, yregs1)

    case :beam_ssa.clobbers_xregs(i) do
      false ->
        defs = :ordsets.add_element(dst, defs0)
        find_yregs_is(is, r_dk(ys, d: defs), yregs)

      true ->
        killed =
          :sets.union(
            :sets.from_list(
              defs0,
              [{:version, 2}]
            ),
            killed0
          )

        defs = [dst]
        find_yregs_is(is, r_dk(ys, d: defs, k: killed), yregs)
    end
  end

  defp find_yregs_is([], ys, yregs) do
    {yregs, ys}
  end

  defp find_yregs_terminator(terminator, r_dk(k: killed), yregs0) do
    yregs = intersect_used(terminator, killed)
    :sets.union(yregs0, yregs)
  end

  defp intersect_used(r_b_br(bool: r_b_var() = v), set) do
    intersect_used_keep_singleton(v, set)
  end

  defp intersect_used(r_b_ret(arg: r_b_var() = v), set) do
    intersect_used_keep_singleton(v, set)
  end

  defp intersect_used(r_b_set(op: :phi, args: args), set) do
    :sets.from_list(
      for {r_b_var() = v, _} <- args,
          :sets.is_element(v, set) do
        v
      end,
      [{:version, 2}]
    )
  end

  defp intersect_used(r_b_set(args: args), set) do
    :sets.from_list(
      intersect_used_keep(
        used_args(args),
        set
      ),
      [{:version, 2}]
    )
  end

  defp intersect_used(r_b_switch(arg: r_b_var() = v), set) do
    intersect_used_keep_singleton(v, set)
  end

  defp intersect_used(_, _) do
    :sets.new([{:version, 2}])
  end

  defp intersect_used_keep_singleton(v, set) do
    case :sets.is_element(v, set) do
      true ->
        :sets.from_list([v], [{:version, 2}])

      false ->
        :sets.new([{:version, 2}])
    end
  end

  defp intersect_used_keep(vs, set) do
    for v <- vs, :sets.is_element(v, set) do
      v
    end
  end

  defp used_args([r_b_var() = v | as]) do
    [v | used_args(as)]
  end

  defp used_args([r_b_remote(mod: mod, name: name) | as]) do
    used_args([mod, name | as])
  end

  defp used_args([_ | as]) do
    used_args(as)
  end

  defp used_args([]) do
    []
  end

  defp copy_retval(r_st(frames: frames, ssa: blocks0, cnt: count0) = st) do
    {blocks, count} = copy_retval_1(frames, blocks0, count0)
    r_st(st, ssa: blocks, cnt: count)
  end

  defp copy_retval_1([f | fs], blocks0, count0) do
    r_b_blk(anno: %{yregs: yregs0}, is: is) =
      :erlang.map_get(
        f,
        blocks0
      )

    yregs = collect_yregs(is, yregs0)
    ls = :beam_ssa.rpo([f], blocks0)
    {blocks, count} = copy_retval_2(ls, yregs, :none, blocks0, count0)
    copy_retval_1(fs, blocks, count)
  end

  defp copy_retval_1([], blocks, count) do
    {blocks, count}
  end

  defp collect_yregs(
         [r_b_set(op: :copy, dst: y, args: [r_b_var() = x]) | is],
         yregs0
       ) do
    true = :sets.is_element(x, yregs0)

    yregs =
      :sets.add_element(
        y,
        :sets.del_element(x, yregs0)
      )

    collect_yregs(is, yregs)
  end

  defp collect_yregs([r_b_set() | is], yregs) do
    collect_yregs(is, yregs)
  end

  defp collect_yregs([], yregs) do
    yregs
  end

  defp copy_retval_2([l | ls], yregs, copy0, blocks0, count0) do
    r_b_blk(is: is0, last: last) =
      blk =
      :erlang.map_get(
        l,
        blocks0
      )

    rC =
      case {last, ls} do
        {r_b_br(succ: succ, fail: 1), [succ | _]} ->
          true

        {_, _} ->
          false
      end

    case copy_retval_is(is0, rC, yregs, copy0, count0, []) do
      {is, count} ->
        case copy0 === :none and count0 === count do
          true ->
            copy_retval_2(ls, yregs, :none, blocks0, count0)

          false ->
            blocks = Map.put(blocks0, l, r_b_blk(blk, is: is))
            copy_retval_2(ls, yregs, :none, blocks, count)
        end

      {is, count, copy} ->
        blocks = Map.put(blocks0, l, r_b_blk(blk, is: is))
        copy_retval_2(ls, yregs, copy, blocks, count)
    end
  end

  defp copy_retval_2([], _Yregs, :none, blocks, count) do
    {blocks, count}
  end

  defp copy_retval_is([r_b_set(op: op) = i0], false, yregs, copy, count0, acc0)
       when op === :call or op === :old_make_fun do
    {i, count, acc} = place_retval_copy(i0, yregs, copy, count0, acc0)
    {reverse(acc, [i]), count}
  end

  defp copy_retval_is([r_b_set()] = is, false, _Yregs, copy, count, acc) do
    {reverse(acc, acc_copy(is, copy)), count}
  end

  defp copy_retval_is([r_b_set(), r_b_set(op: :succeeded)] = is, false, _Yregs, copy, count, acc) do
    {reverse(acc, acc_copy(is, copy)), count}
  end

  defp copy_retval_is(
         [
           r_b_set(op: op, dst: r_b_var(name: retName) = dst) = i0
           | is
         ],
         rC,
         yregs,
         copy0,
         count0,
         acc0
       )
       when op === :call or op === :old_make_fun do
    {i1, count1, acc} = place_retval_copy(i0, yregs, copy0, count0, acc0)

    case :sets.is_element(dst, yregs) do
      true ->
        {newVar, count} = new_var(retName, count1)
        copy = r_b_set(op: :copy, dst: dst, args: [newVar])
        i = r_b_set(i1, dst: newVar)
        copy_retval_is(is, rC, yregs, copy, count, [i | acc])

      false ->
        copy_retval_is(is, rC, yregs, :none, count1, [i1 | acc])
    end
  end

  defp copy_retval_is([r_b_set(args: args0) = i0 | is], rC, yregs, copy, count, acc) do
    i = r_b_set(i0, args: copy_sub_args(args0, copy))

    case :beam_ssa.clobbers_xregs(i) do
      true ->
        copy_retval_is(is, rC, yregs, :none, count, [i | acc_copy(acc, copy)])

      false ->
        copy_retval_is(is, rC, yregs, copy, count, [i | acc])
    end
  end

  defp copy_retval_is([], rC, _, copy, count, acc) do
    case {copy, rC} do
      {:none, _} ->
        {reverse(acc), count}

      {r_b_set(), true} ->
        {reverse(acc), count, copy}

      {r_b_set(), false} ->
        {reverse(acc, [copy]), count}
    end
  end

  defp place_retval_copy(i, _Yregs, :none, count, acc) do
    {i, count, acc}
  end

  defp place_retval_copy(r_b_set(args: [f | args0]) = i0, yregs0, retCopy, count0, acc0) do
    r_b_set(dst: avoid) = retCopy
    yregs = :sets.del_element(avoid, yregs0)
    {args, acc1, count} = copy_func_args(args0, yregs, acc0, count0)
    i = r_b_set(i0, args: [f | args])
    acc = [retCopy | acc1]
    {i, count, acc}
  end

  defp copy_func_args(args, yregs, acc, count) do
    copy_func_args_1(reverse(args), yregs, acc, [], count)
  end

  defp copy_func_args_1([r_b_var(name: aName) = a | as], yregs, instrAcc, argAcc, count0) do
    case :sets.is_element(a, yregs) do
      true ->
        {newVar, count} = new_var(aName, count0)
        copy = r_b_set(op: :copy, dst: newVar, args: [a])
        copy_func_args_1(as, yregs, [copy | instrAcc], [newVar | argAcc], count)

      false ->
        copy_func_args_1(as, yregs, instrAcc, [a | argAcc], count0)
    end
  end

  defp copy_func_args_1([a | as], yregs, instrAcc, argAcc, count) do
    copy_func_args_1(as, yregs, instrAcc, [a | argAcc], count)
  end

  defp copy_func_args_1([], _Yregs, instrAcc, argAcc, count) do
    {argAcc, instrAcc, count}
  end

  defp acc_copy(acc, :none) do
    acc
  end

  defp acc_copy(acc, r_b_set() = copy) do
    [copy | acc]
  end

  defp copy_sub_args(args, :none) do
    args
  end

  defp copy_sub_args(args, r_b_set(dst: dst, args: [src])) do
    for a <- args do
      sub_arg(a, dst, src)
    end
  end

  defp sub_arg(old, old, new) do
    new
  end

  defp sub_arg(old, _, _) do
    old
  end

  defp opt_get_list(r_st(ssa: blocks, res: res) = st) do
    resMap = :maps.from_list(res)
    ls = :beam_ssa.rpo(blocks)
    r_st(st, ssa: opt_get_list_1(ls, resMap, blocks))
  end

  defp opt_get_list_1([l | ls], res, blocks0) do
    r_b_blk(is: is0) = blk = :erlang.map_get(l, blocks0)

    case opt_get_list_is(is0, res, [], false) do
      :no ->
        opt_get_list_1(ls, res, blocks0)

      {:yes, is} ->
        blocks = %{blocks0 | l => r_b_blk(blk, is: is)}
        opt_get_list_1(ls, res, blocks)
    end
  end

  defp opt_get_list_1([], _, blocks) do
    blocks
  end

  defp opt_get_list_is(
         [
           r_b_set(op: :get_hd, dst: hd, args: [cons]) = getHd,
           r_b_set(op: :get_tl, dst: tl, args: [cons]) = getTl | is
         ],
         res,
         acc,
         changed
       ) do
    case res do
      %{^hd => {:y, _}} ->
        opt_get_list_is([getTl | is], res, [getHd | acc], changed)

      %{^tl => {:y, _}} ->
        opt_get_list_is([getHd | is], res, [getTl | acc], true)

      %{} ->
        opt_get_list_is([getTl | is], res, [getHd | acc], changed)
    end
  end

  defp opt_get_list_is([i | is], res, acc, changed) do
    opt_get_list_is(is, res, [i | acc], changed)
  end

  defp opt_get_list_is([], _Res, acc, changed) do
    case changed do
      true ->
        {:yes, reverse(acc)}

      false ->
        :no
    end
  end

  defp number_instructions(r_st(ssa: blocks0) = st) do
    ls = :beam_ssa.rpo(blocks0)
    r_st(st, ssa: number_is_1(ls, 1, blocks0))
  end

  defp number_is_1([l | ls], n0, blocks0) do
    r_b_blk(is: is0, last: last0) =
      bl0 =
      :erlang.map_get(
        l,
        blocks0
      )

    {is, n1} = number_is_2(is0, n0, [])
    last = :beam_ssa.add_anno(:n, n1, last0)
    n = n1 + 2
    bl = r_b_blk(bl0, is: is, last: last)
    blocks = %{blocks0 | l => bl}
    number_is_1(ls, n, blocks)
  end

  defp number_is_1([], _, blocks) do
    blocks
  end

  defp number_is_2([r_b_set(op: :phi) = i | is], n, acc) do
    number_is_2(is, n, [i | acc])
  end

  defp number_is_2([i0 | is], n, acc) do
    i = :beam_ssa.add_anno(:n, n, i0)
    number_is_2(is, n + 2, [i | acc])
  end

  defp number_is_2([], n, acc) do
    {reverse(acc), n}
  end

  defp live_intervals(r_st(args: args, ssa: blocks) = st) do
    pO = reverse(:beam_ssa.rpo(blocks))
    intervals0 = live_interval_blk(pO, blocks, %{}, %{})

    intervals1 =
      add_ranges(
        for r_b_var() = v <- args do
          {v, {0, 1}}
        end,
        intervals0
      )

    intervals = :maps.to_list(intervals1)
    r_st(st, intervals: intervals)
  end

  defp live_interval_blk([l | ls], blocks, liveMap0, intervals0) do
    blk = :erlang.map_get(l, blocks)
    successors = :beam_ssa.successors(blk)
    live1 = live_in_successors(successors, l, blocks, liveMap0)
    r_b_blk(is: is, last: last) = blk
    firstNumber = first_number(is, last)
    defaultRange = {firstNumber, 1 + :beam_ssa.get_anno(:n, last)}

    ranges0 =
      for v <- live1 do
        {v, defaultRange}
      end

    case {is, last} do
      {[], r_b_br(bool: r_b_literal(val: true))} ->
        intervals = add_ranges(ranges0, intervals0)
        liveMap = Map.put(liveMap0, l, live1)
        live_interval_blk(ls, blocks, liveMap, intervals)

      {_, _} ->
        ranges1 = :gb_trees.from_orddict(ranges0)
        ranges2 = live_interval_last(last, firstNumber, ranges1)
        ranges3 = live_interval_blk_is(is, firstNumber, ranges2)
        ranges = :gb_trees.to_list(ranges3)
        intervals = add_ranges(ranges, intervals0)

        live =
          for {v, {from, _To}} <- ranges,
              from <= firstNumber do
            v
          end

        liveMap = Map.put(liveMap0, l, live)
        live_interval_blk(ls, blocks, liveMap, intervals)
    end
  end

  defp live_interval_blk([], _Blocks, _LiveMap, intervals) do
    intervals
  end

  defp live_interval_last(i, firstNumber, ranges) do
    n = :beam_ssa.get_anno(:n, i)
    used = :beam_ssa.used(i)
    update_used(used, firstNumber, n, ranges)
  end

  defp live_interval_blk_is([r_b_set(op: :phi, dst: dst) | is], firstNumber, acc0) do
    acc = live_interval_blk_is(is, firstNumber, acc0)

    case :gb_trees.is_defined(dst, acc) do
      true ->
        update_def(dst, firstNumber, acc)

      false ->
        :gb_trees.insert(dst, {firstNumber, firstNumber}, acc)
    end
  end

  defp live_interval_blk_is([r_b_set(args: args, dst: dst) = i | is], firstNumber, acc0) do
    acc1 = live_interval_blk_is(is, firstNumber, acc0)
    n = :beam_ssa.get_anno(:n, i)
    used = used_args(args)
    acc = update_used(used, firstNumber, n, acc1)
    update_def(dst, n, acc)
  end

  defp live_interval_blk_is([], _FirstNumber, acc) do
    acc
  end

  defp update_def(v, n, ranges) do
    case :gb_trees.lookup(v, ranges) do
      {:value, {_From, to}} ->
        :gb_trees.update(v, {n, to}, ranges)

      :none ->
        :gb_trees.insert(v, {n, n}, ranges)
    end
  end

  defp update_used([v | vs], first, n, ranges) do
    case :gb_trees.is_defined(v, ranges) do
      true ->
        update_used(vs, first, n, ranges)

      false ->
        update_used(vs, first, n, :gb_trees.insert(v, {first, n}, ranges))
    end
  end

  defp update_used([], _First, _N, ranges) do
    ranges
  end

  defp add_ranges([{v, {a, n} = range} | t], map) do
    case map do
      %{^v => [{^n, z} | ranges]} ->
        add_ranges(t, %{map | v => [{a, z} | ranges]})

      %{^v => [{^a, ^n} | _]} ->
        add_ranges(t, map)

      %{^v => ranges} ->
        add_ranges(t, %{map | v => [range | ranges]})

      %{} ->
        add_ranges(t, Map.put(map, v, [range]))
    end
  end

  defp add_ranges([], map) do
    map
  end

  defp first_number([r_b_set(op: :phi) | is], last) do
    first_number(is, last)
  end

  defp first_number([i | _], _) do
    :beam_ssa.get_anno(:n, i) - 1
  end

  defp first_number([], last) do
    :beam_ssa.get_anno(:n, last) - 1
  end

  defp live_in_successors(ls, pred, blocks, liveMap) do
    live_in_successors(ls, pred, blocks, liveMap, [])
  end

  defp live_in_successors([l | ls], pred, blocks, liveMap, live0) do
    live1 = :ordsets.union(live0, get_live(l, liveMap))
    r_b_blk(is: is) = :erlang.map_get(l, blocks)
    live = live_in_phis(is, pred, live1)
    live_in_successors(ls, pred, blocks, liveMap, live)
  end

  defp live_in_successors([], _, _, _, live) do
    live
  end

  defp get_live(l, liveMap) do
    case liveMap do
      %{^l => live} ->
        live

      %{} ->
        []
    end
  end

  defp live_in_phis([r_b_set(op: :phi, dst: killed, args: args) | is], pred, live0) do
    used =
      for {r_b_var() = v, l} <- args, l === pred do
        v
      end

    live1 = :ordsets.union(used, live0)
    live = :ordsets.del_element(killed, live1)
    live_in_phis(is, pred, live)
  end

  defp live_in_phis(_, _, live) do
    live
  end

  defp reserve_yregs(r_st(frames: frames) = st0) do
    foldl(&reserve_yregs_1/2, st0, frames)
  end

  defp reserve_yregs_1(
         l,
         r_st(ssa: blocks0, cnt: count0, res: res0) = st
       ) do
    blk = :erlang.map_get(l, blocks0)

    yregs =
      :ordsets.from_list(
        :sets.to_list(
          :beam_ssa.get_anno(
            :yregs,
            blk
          )
        )
      )

    rPO = :beam_ssa.rpo([l], blocks0)
    {def__, unused} = :beam_ssa.def_unused(rPO, yregs, blocks0)
    usedYregs = :ordsets.subtract(yregs, unused)
    defBefore = :ordsets.subtract(usedYregs, def__)
    {beforeVars, blocks, count} = rename_vars(defBefore, l, rPO, blocks0, count0)
    insideVars = :ordsets.subtract(usedYregs, defBefore)
    resTryTags0 = reserve_try_tags(l, blocks)

    resTryTags =
      for {v, reg} <- resTryTags0 do
        {v, {reg, count}}
      end

    vars = beforeVars ++ insideVars

    res =
      for v <- vars do
        {v, {:y, count}}
      end ++ resTryTags ++ res0

    r_st(st, res: res, ssa: blocks, cnt: count + 1)
  end

  defp reserve_try_tags(l, blocks) do
    seen = :gb_sets.empty()
    {res0, _} = reserve_try_tags_1([l], blocks, seen, %{})

    res1 =
      for m <- :maps.values(res0) do
        :maps.to_list(m)
      end

    res =
      for {v, y} <- append(res1) do
        {v, {:y, y}}
      end

    :ordsets.from_list(res)
  end

  defp reserve_try_tags_1([l | ls], blocks, seen0, actMap0) do
    case :gb_sets.is_element(l, seen0) do
      true ->
        reserve_try_tags_1(ls, blocks, seen0, actMap0)

      false ->
        seen1 = :gb_sets.insert(l, seen0)
        r_b_blk(is: is) = blk = :erlang.map_get(l, blocks)
        active0 = get_active(l, actMap0)
        active = reserve_try_tags_is(is, active0)
        successors = :beam_ssa.successors(blk)
        actMap1 = update_act_map(successors, active, actMap0)
        {actMap, seen} = reserve_try_tags_1(ls, blocks, seen1, actMap1)
        reserve_try_tags_1(successors, blocks, seen, actMap)
    end
  end

  defp reserve_try_tags_1([], _Blocks, seen, actMap) do
    {actMap, seen}
  end

  defp get_active(l, actMap) do
    case actMap do
      %{^l => active} ->
        active

      %{} ->
        %{}
    end
  end

  defp reserve_try_tags_is([r_b_set(op: :new_try_tag, dst: v) | is], active) do
    n = map_size(active)
    reserve_try_tags_is(is, Map.put(active, v, n))
  end

  defp reserve_try_tags_is(
         [r_b_set(op: :kill_try_tag, args: [tag]) | is],
         active
       ) do
    reserve_try_tags_is(is, :maps.remove(tag, active))
  end

  defp reserve_try_tags_is([_ | is], active) do
    reserve_try_tags_is(is, active)
  end

  defp reserve_try_tags_is([], active) do
    active
  end

  defp update_act_map([l | ls], active0, actMap0) do
    case actMap0 do
      %{^l => active1} ->
        actMap = Map.put(actMap0, l, :maps.merge(active0, active1))
        update_act_map(ls, active0, actMap)

      %{} ->
        actMap = Map.put(actMap0, l, active0)
        update_act_map(ls, active0, actMap)
    end
  end

  defp update_act_map([], _, actMap) do
    actMap
  end

  defp rename_vars([], _, _, blocks, count) do
    {[], blocks, count}
  end

  defp rename_vars(vs, l, rPO, blocks0, count0) do
    {newVars, count} =
      new_vars(
        for r_b_var(name: base) <- vs do
          base
        end,
        count0
      )

    ren = zip(vs, newVars)
    blocks1 = :beam_ssa.rename_vars(ren, rPO, blocks0)
    r_b_blk(is: is0) = blk0 = :erlang.map_get(l, blocks1)

    copyIs =
      for {old, new} <- ren do
        r_b_set(op: :copy, dst: new, args: [old])
      end

    is = insert_after_phis(is0, copyIs)
    blk = r_b_blk(blk0, is: is)
    blocks = %{blocks1 | l => blk}
    {newVars, blocks, count}
  end

  defp insert_after_phis([r_b_set(op: :phi) = i | is], insertIs) do
    [i | insert_after_phis(is, insertIs)]
  end

  defp insert_after_phis(is, insertIs) do
    insertIs ++ is
  end

  defp frame_size(r_st(frames: frames, regs: regs, ssa: blocks0) = st) do
    blocks =
      foldl(
        fn l, blks ->
          frame_size_1(l, regs, blks)
        end,
        blocks0,
        frames
      )

    r_st(st, ssa: blocks)
  end

  defp frame_size_1(l, regs, blocks0) do
    rPO = :beam_ssa.rpo([l], blocks0)
    def__ = :beam_ssa.def(rPO, blocks0)

    yregs0 =
      for v <- def__,
          is_yreg(:erlang.map_get(v, regs)) do
        :erlang.map_get(v, regs)
      end

    yregs = :ordsets.from_list(yregs0)
    frameSize = length(:ordsets.from_list(yregs))

    cond do
      frameSize !== 0 ->
        [{:y, 0} | _] = yregs
        {:y, last} = last(yregs)
        ^last = frameSize - 1
        :ok

      true ->
        :ok
    end

    blk0 = :erlang.map_get(l, blocks0)
    blk = :beam_ssa.add_anno(:frame_size, frameSize, blk0)
    blocks = %{blocks0 | l => blk}
    reachable = :beam_ssa.rpo([l], blocks)
    frame_deallocate(reachable, frameSize, blocks)
  end

  defp frame_deallocate([l | ls], size, blocks0) do
    blk0 = :erlang.map_get(l, blocks0)

    blk =
      case blk0 do
        r_b_blk(last: r_b_ret() = ret0) ->
          ret = :beam_ssa.add_anno(:deallocate, size, ret0)
          r_b_blk(blk0, last: ret)

        r_b_blk() ->
          blk0
      end

    blocks = %{blocks0 | l => blk}
    frame_deallocate(ls, size, blocks)
  end

  defp frame_deallocate([], _, blocks) do
    blocks
  end

  defp turn_yregs(r_st(frames: frames, regs: regs0, ssa: blocks) = st) do
    regs1 =
      foldl(
        fn l, a ->
          blk = :erlang.map_get(l, blocks)
          frameSize = :beam_ssa.get_anno(:frame_size, blk)
          rPO = :beam_ssa.rpo([l], blocks)
          def__ = :beam_ssa.def(rPO, blocks)
          [turn_yregs_1(def__, frameSize, regs0) | a]
        end,
        [],
        frames
      )

    regs =
      :maps.merge(
        regs0,
        :maps.from_list(append(regs1))
      )

    r_st(st, regs: regs)
  end

  defp turn_yregs_1(def__, frameSize, regs) do
    yregs0 =
      for v <- def__,
          is_yreg(:erlang.map_get(v, regs)) do
        {:erlang.map_get(v, regs), v}
      end

    yregs1 = rel2fam(yregs0)
    ^frameSize = length(yregs1)

    yregs2 =
      for {{:y, y}, vs} <- yregs1 do
        {{:y, frameSize - y - 1}, vs}
      end

    r0 = :sofs.family(yregs2)
    r1 = :sofs.family_to_relation(r0)
    r = :sofs.converse(r1)
    :sofs.to_external(r)
  end

  defp reserve_regs(r_st(args: args, ssa: blocks, intervals: intervals, res: res0) = st) do
    res1 = reserve_arg_regs(args, 0, res0)
    rPO = :beam_ssa.rpo(blocks)
    res2 = reserve_zregs(rPO, blocks, intervals, res1)
    res3 = reserve_fregs(rPO, blocks, res2)
    res = :maps.from_list(res3)
    r_st(st, res: reserve_xregs(rPO, blocks, res))
  end

  defp reserve_arg_regs([r_b_var() = arg | is], n, acc) do
    reserve_arg_regs(is, n + 1, [{arg, {:x, n}} | acc])
  end

  defp reserve_arg_regs([], _, acc) do
    acc
  end

  defp reserve_zregs(rPO, blocks, intervals, res) do
    shortLived0 =
      for {v, [{start, end__}]} <- intervals,
          start + 2 === end__ do
        v
      end

    shortLived =
      :sets.from_list(
        shortLived0,
        [{:version, 2}]
      )

    f = fn _, r_b_blk(is: is, last: last), a ->
      reserve_zreg(is, last, shortLived, a)
    end

    :beam_ssa.fold_blocks(f, rPO, res, blocks)
  end

  defp reserve_zreg(
         [
           r_b_set(op: {:bif, :tuple_size}, dst: dst),
           r_b_set(op: {:bif, :"=:="}, args: [dst, val], dst: bool)
         ],
         last,
         shortLived,
         a
       ) do
    case {val, last} do
      {r_b_literal(val: arity), r_b_br(bool: ^bool)} when arity >>> 32 === 0 ->
        reserve_test_zreg(dst, shortLived, a)

      {_, _} ->
        a
    end
  end

  defp reserve_zreg(
         [r_b_set(op: {:bif, :tuple_size}, dst: dst)],
         r_b_switch(arg: dst),
         shortLived,
         a
       ) do
    reserve_test_zreg(dst, shortLived, a)
  end

  defp reserve_zreg([r_b_set(op: op, dst: dst)], r_b_br(bool: dst), shortLived, a) do
    case use_zreg(op) do
      :yes ->
        [{dst, :z} | a]

      :no ->
        a

      :maybe ->
        reserve_test_zreg(dst, shortLived, a)
    end
  end

  defp reserve_zreg([r_b_set(op: op, dst: dst) | is], last, shortLived, a) do
    case use_zreg(op) do
      :yes ->
        reserve_zreg(is, last, shortLived, [{dst, :z} | a])

      _Other ->
        reserve_zreg(is, last, shortLived, a)
    end
  end

  defp reserve_zreg([], _, _, a) do
    a
  end

  defp use_zreg(:bs_checked_skip) do
    :yes
  end

  defp use_zreg(:bs_ensure) do
    :yes
  end

  defp use_zreg(:bs_match_string) do
    :yes
  end

  defp use_zreg(:bs_set_position) do
    :yes
  end

  defp use_zreg(:kill_try_tag) do
    :yes
  end

  defp use_zreg(:landingpad) do
    :yes
  end

  defp use_zreg(:recv_marker_bind) do
    :yes
  end

  defp use_zreg(:recv_marker_clear) do
    :yes
  end

  defp use_zreg(:remove_message) do
    :yes
  end

  defp use_zreg(:set_tuple_element) do
    :yes
  end

  defp use_zreg(:succeeded) do
    :yes
  end

  defp use_zreg(:wait_timeout) do
    :yes
  end

  defp use_zreg(:call) do
    :no
  end

  defp use_zreg({:bif, :element}) do
    :no
  end

  defp use_zreg({:bif, :is_map_key}) do
    :no
  end

  defp use_zreg({:bif, :is_record}) do
    :no
  end

  defp use_zreg({:bif, :map_get}) do
    :no
  end

  defp use_zreg({:bif, :xor}) do
    :no
  end

  defp use_zreg(:get_hd) do
    :no
  end

  defp use_zreg(:get_tl) do
    :no
  end

  defp use_zreg(:get_tuple_element) do
    :no
  end

  defp use_zreg(_) do
    :maybe
  end

  defp reserve_test_zreg(r_b_var() = v, shortLived, a) do
    case :sets.is_element(v, shortLived) do
      true ->
        [{v, :z} | a]

      false ->
        a
    end
  end

  defp reserve_fregs(rPO, blocks, res) do
    f = fn _, r_b_blk(is: is), a ->
      reserve_freg(is, a)
    end

    :beam_ssa.fold_blocks(f, rPO, res, blocks)
  end

  defp reserve_freg([r_b_set(op: {:float, op}, dst: v) | is], res) do
    case op do
      :get ->
        reserve_freg(is, res)

      _ ->
        reserve_freg(is, [{v, :fr} | res])
    end
  end

  defp reserve_freg([_ | is], res) do
    reserve_freg(is, res)
  end

  defp reserve_freg([], res) do
    res
  end

  defp reserve_xregs(rPO, blocks, res) do
    ls = reverse(rPO)
    reserve_xregs(ls, blocks, %{}, res)
  end

  defp reserve_xregs([l | ls], blocks, xsMap0, res0) do
    r_b_blk(anno: anno, is: is0, last: last) =
      :erlang.map_get(
        l,
        blocks
      )

    xs0 = reserve_terminator(l, is0, last, blocks, xsMap0, res0)
    is1 = reverse(is0)
    is2 = res_place_gc_instrs(is1, [])
    is = res_place_allocate(anno, is2)
    {res, xs} = reserve_xregs_is(is, res0, xs0, [])
    xsMap = Map.put(xsMap0, l, xs)
    reserve_xregs(ls, blocks, xsMap, res)
  end

  defp reserve_xregs([], _, _, res) do
    res
  end

  defp res_place_gc_instrs([r_b_set(op: :phi) = i | is], acc) do
    res_place_gc_instrs(is, [i | acc])
  end

  defp res_place_gc_instrs([r_b_set(op: op) = i | is], acc)
       when op === :call or
              op === :old_make_fun do
    case acc do
      [] ->
        res_place_gc_instrs(is, [i | acc])

      [gC | _] when gC === :gc or gC === :test_heap ->
        res_place_gc_instrs(is, [i, :gc | acc])

      [_ | _] ->
        res_place_gc_instrs(is, [i, :gc | acc])
    end
  end

  defp res_place_gc_instrs([r_b_set(op: op, args: args) = i | is], acc0) do
    case :beam_ssa_codegen.classify_heap_need(op, args) do
      :neutral ->
        case acc0 do
          [:test_heap | acc] ->
            res_place_gc_instrs(is, [:test_heap, i | acc])

          acc ->
            res_place_gc_instrs(is, [i | acc])
        end

      {:put, _} ->
        res_place_gc_instrs(is, res_place_test_heap(i, acc0))

      {:put_fun, _} ->
        res_place_gc_instrs(is, res_place_test_heap(i, acc0))

      :put_float ->
        res_place_gc_instrs(is, res_place_test_heap(i, acc0))

      :gc ->
        res_place_gc_instrs(is, [:gc, i | acc0])
    end
  end

  defp res_place_gc_instrs([], acc) do
    res_place_gc_instrs_rev(acc, [])
  end

  defp res_place_test_heap(i, acc) do
    case acc do
      [:test_heap | ^acc] ->
        [:test_heap, i | acc]

      _ ->
        [:test_heap, i | acc]
    end
  end

  defp res_place_gc_instrs_rev([:test_heap | is], [:gc | _] = acc) do
    res_place_gc_instrs_rev(is, acc)
  end

  defp res_place_gc_instrs_rev([:test_heap | is], acc) do
    res_place_gc_instrs_rev(is, [:gc | acc])
  end

  defp res_place_gc_instrs_rev([:gc | is], [:gc | _] = acc) do
    res_place_gc_instrs_rev(is, acc)
  end

  defp res_place_gc_instrs_rev([i | is], acc) do
    res_place_gc_instrs_rev(is, [i | acc])
  end

  defp res_place_gc_instrs_rev([], acc) do
    acc
  end

  defp res_place_allocate(%{yregs: _}, is) do
    is ++ [:gc]
  end

  defp res_place_allocate(%{}, is) do
    is
  end

  defp reserve_xregs_is([:gc | is], res, xs0, used) do
    xs = res_xregs_prune(xs0, used, res)
    reserve_xregs_is(is, res, xs, used)
  end

  defp reserve_xregs_is([r_b_set(op: op, dst: dst, args: args) = i | is], res0, xs0, used0) do
    res = reserve_xreg(dst, xs0, res0)
    used1 = :ordsets.union(used0, :beam_ssa.used(i))
    used = :ordsets.del_element(dst, used1)

    case op do
      :call ->
        xs = reserve_call_args(tl(args))
        reserve_xregs_is(is, res, xs, used)

      :old_make_fun ->
        xs = reserve_call_args(tl(args))
        reserve_xregs_is(is, res, xs, used)

      _ ->
        reserve_xregs_is(is, res, xs0, used)
    end
  end

  defp reserve_xregs_is([], res, xs, _Used) do
    {res, xs}
  end

  defp reserve_terminator(
         l,
         is,
         r_b_br(bool: r_b_var(), succ: succ, fail: fail),
         blocks,
         xsMap,
         res
       )
       when succ !== fail and fail !== 1 do
    %{^succ => succBlk, ^fail => failBlk} = blocks

    case {succBlk, failBlk} do
      {r_b_blk(is: [], last: r_b_br(succ: phiL, fail: phiL)),
       r_b_blk(is: [], last: r_b_br(succ: phiL, fail: phiL))} ->
        %{^phiL => r_b_blk(is: phiIs)} = blocks
        xs = res_xregs_from_phi(phiIs, succ, res, %{})
        res_xregs_from_phi(phiIs, fail, res, xs)

      {_, _} when is !== [] ->
        case last(is) do
          r_b_set(op: :succeeded, args: [arg]) ->
            br = r_b_br(bool: r_b_literal(val: true), succ: succ, fail: succ)

            case reserve_terminator(l, [], br, blocks, xsMap, res) do
              %{^arg => reg} ->
                %{arg => reg}

              %{} ->
                %{}
            end

          r_b_set(op: :new_try_tag) ->
            reserve_terminator_1(l, succ, is, blocks, xsMap, res)

          _ ->
            %{}
        end

      {_, _} ->
        %{}
    end
  end

  defp reserve_terminator(l, is, r_b_br(bool: bool, succ: succ, fail: fail), blocks, xsMap, res) do
    case {bool, fail} do
      {_, 1} ->
        reserve_terminator_1(l, succ, is, blocks, xsMap, res)

      {r_b_literal(val: true), _} ->
        reserve_terminator_1(l, succ, is, blocks, xsMap, res)

      {_, _} ->
        %{}
    end
  end

  defp reserve_terminator(_, _, _, _, _, _) do
    %{}
  end

  defp reserve_terminator_1(l, succ, _Is, blocks, xsMap, res) do
    case {blocks, xsMap} do
      {%{^succ => r_b_blk(is: [r_b_set(op: :phi) | _] = phiIs)}, %{}} ->
        res_xregs_from_phi(phiIs, l, res, %{})

      {%{}, %{^succ => xs}} ->
        xs

      {%{}, %{}} ->
        %{}
    end
  end

  defp res_xregs_from_phi([r_b_set(op: :phi, dst: dst, args: args) | is], pred, res, acc) do
    case (for {r_b_var() = v, l} <- args, l === pred do
            v
          end) do
      [] ->
        res_xregs_from_phi(is, pred, res, acc)

      [v] ->
        case res do
          %{^dst => {:prefer, reg}} ->
            res_xregs_from_phi(is, pred, res, Map.put(acc, v, reg))

          %{^dst => _} ->
            res_xregs_from_phi(is, pred, res, acc)
        end
    end
  end

  defp res_xregs_from_phi(_, _, _, acc) do
    acc
  end

  defp reserve_call_args(args) do
    reserve_call_args(args, 0, %{})
  end

  defp reserve_call_args([r_b_var() = var | as], x, xs) do
    reserve_call_args(as, x + 1, Map.put(xs, var, {:x, x}))
  end

  defp reserve_call_args([r_b_literal() | as], x, xs) do
    reserve_call_args(as, x + 1, Map.put(xs, {:x, x}, :hole))
  end

  defp reserve_call_args([], _, xs) do
    xs
  end

  defp reserve_xreg(v, xs, res) do
    case res do
      %{^v => _} ->
        res

      %{} ->
        case xs do
          %{^v => x} ->
            Map.put(res, v, {:prefer, x})

          %{} ->
            Map.put(res, v, :x)
        end
    end
  end

  Record.defrecord(:r_i, :i, sort: 1, reg: :none, pool: :x, var: :EFE_TODO_NESTED_RECORD, rs: [])

  Record.defrecord(:r_l, :l,
    cur: :EFE_TODO_NESTED_RECORD,
    unhandled_res: [],
    unhandled_any: [],
    active: [],
    inactive: [],
    free: %{},
    regs: []
  )

  defp linear_scan(r_st(intervals: intervals0, res: res) = st0) do
    st = r_st(st0, intervals: [], res: [])
    free = init_free(:maps.to_list(res))

    intervals1 =
      for int <- intervals0 do
        init_interval(int, res)
      end

    intervals = sort(intervals1)

    isReserved = fn r_i(reg: reg) ->
      case reg do
        :none ->
          false

        {:prefer, {_, _}} ->
          false

        {_, _} ->
          true
      end
    end

    {unhandledRes, unhandled} =
      partition(
        isReserved,
        intervals
      )

    l = r_l(unhandled_res: unhandledRes, unhandled_any: unhandled, free: free)
    r_l(regs: regs) = do_linear(l)
    r_st(st, regs: :maps.from_list(regs))
  end

  defp init_interval({v, [{start, _} | _] = rs}, res) do
    info = :erlang.map_get(v, res)

    pool =
      case info do
        {:prefer, {:x, _}} ->
          :x

        :x ->
          :x

        {:x, _} ->
          :x

        {:y, uniq} ->
          uniq

        {{:y, _}, uniq} ->
          uniq

        :z ->
          :z

        :fr ->
          :fr
      end

    reg =
      case info do
        {:prefer, {:x, _}} ->
          info

        {:x, _} ->
          info

        {{:y, _} = y, _} ->
          y

        _ ->
          :none
      end

    r_i(sort: start, var: v, reg: reg, pool: pool, rs: rs)
  end

  defp init_free_1([{_, {:prefer, {:x, _} = reg}} | res]) do
    [{:x, reg} | init_free_1(res)]
  end

  defp init_free_1([{_, {:x, _} = reg} | res]) do
    [{:x, reg} | init_free_1(res)]
  end

  defp init_free_1([{_, {:y, uniq}} | res]) do
    [{uniq, {:y, 0}} | init_free_1(res)]
  end

  defp init_free_1([{_, {{:y, _} = reg, uniq}} | res]) do
    [{uniq, reg} | init_free_1(res)]
  end

  defp init_free_1([{_, :z} | res]) do
    [{:z, {:z, 0}} | init_free_1(res)]
  end

  defp init_free_1([{_, :fr} | res]) do
    [{:fr, {:fr, 0}} | init_free_1(res)]
  end

  defp init_free_1([{_, :x} | res]) do
    init_free_1(res)
  end

  defp init_free_1([]) do
    []
  end

  defp init_xregs([{:x, n}, {:x, m} | is]) when n + 1 === m do
    [{:x, n} | init_xregs([{:x, m} | is])]
  end

  defp init_xregs([{:x, n} | [{:x, _} | _] = is]) do
    [{:x, n} | init_xregs([{:x, n + 1} | is])]
  end

  defp init_xregs([{:x, _}] = is) do
    is
  end

  defp do_linear(l0) do
    case set_next_current(l0) do
      :done ->
        l0

      l1 ->
        l2 = expire_active(l1)
        l3 = check_inactive(l2)
        available = collect_available(l3)
        l4 = select_register(available, l3)
        l = make_cur_active(l4)
        do_linear(l)
    end
  end

  defp set_next_current(
         r_l(
           unhandled_res: [cur1 | t1],
           unhandled_any: [cur2 | t2]
         ) = l
       ) do
    case {cur1, cur2} do
      {r_i(sort: n1), r_i(sort: n2)} when n1 < n2 ->
        r_l(l, cur: cur1, unhandled_res: t1)

      {_, _} ->
        r_l(l, cur: cur2, unhandled_any: t2)
    end
  end

  defp set_next_current(
         r_l(
           unhandled_res: [],
           unhandled_any: [cur | t]
         ) = l
       ) do
    r_l(l, cur: cur, unhandled_any: t)
  end

  defp set_next_current(
         r_l(
           unhandled_res: [cur | t],
           unhandled_any: []
         ) = l
       ) do
    r_l(l, cur: cur, unhandled_res: t)
  end

  defp set_next_current(r_l(unhandled_res: [], unhandled_any: [])) do
    :done
  end

  defp expire_active(r_l(cur: r_i(sort: curBegin), active: act0) = l0) do
    {act, l} = expire_active(act0, curBegin, l0, [])
    r_l(l, active: act)
  end

  defp expire_active([r_i(reg: reg, rs: rs0) = i | is], curBegin, l0, acc) do
    {_, _} = reg

    case overlap_status(rs0, curBegin) do
      :ends_before_cur ->
        l = free_reg(i, l0)
        expire_active(is, curBegin, l, acc)

      :overlapping ->
        expire_active(is, curBegin, l0, [i | acc])

      :not_overlapping ->
        rs = strip_before_current(rs0, curBegin)
        l1 = free_reg(i, l0)
        l = r_l(l1, inactive: [r_i(i, rs: rs) | r_l(l1, :inactive)])
        expire_active(is, curBegin, l, acc)
    end
  end

  defp expire_active([], _CurBegin, l, acc) do
    {acc, l}
  end

  defp check_inactive(
         r_l(
           cur: r_i(sort: curBegin),
           inactive: inAct0
         ) = l0
       ) do
    {inAct, l} = check_inactive(inAct0, curBegin, l0, [])
    r_l(l, inactive: inAct)
  end

  defp check_inactive([r_i(rs: rs0) = i | is], curBegin, l0, acc) do
    case overlap_status(rs0, curBegin) do
      :ends_before_cur ->
        check_inactive(is, curBegin, l0, acc)

      :not_overlapping ->
        check_inactive(is, curBegin, l0, [i | acc])

      :overlapping ->
        rs = strip_before_current(rs0, curBegin)
        l1 = r_l(l0, active: [r_i(i, rs: rs) | r_l(l0, :active)])
        l = reserve_reg(i, l1)
        check_inactive(is, curBegin, l, acc)
    end
  end

  defp check_inactive([], _CurBegin, l, acc) do
    {acc, l}
  end

  defp strip_before_current([{_, e} | rs], curBegin) when e <= curBegin do
    strip_before_current(rs, curBegin)
  end

  defp strip_before_current(rs, _CurBegin) do
    rs
  end

  defp collect_available(r_l(cur: r_i(reg: {:prefer, {_, _} = prefer}) = i) = l) do
    avail = collect_available(r_l(l, cur: r_i(i, reg: :none)))

    case member(prefer, avail) do
      true ->
        [prefer]

      false ->
        avail
    end
  end

  defp collect_available(r_l(cur: r_i(reg: {_, _} = reservedReg))) do
    [reservedReg]
  end

  defp collect_available(r_l(unhandled_res: unhandled, cur: cur) = l) do
    free = get_pool(cur, l)
    collect_available(unhandled, cur, free)
  end

  defp collect_available([r_i(pool: pool1) | is], r_i(pool: pool2) = cur, free)
       when pool1 !== pool2 do
    collect_available(is, cur, free)
  end

  defp collect_available([r_i(reg: {_, _} = reg) = i | is], cur, free0) do
    case overlaps(i, cur) do
      true ->
        free = :ordsets.del_element(reg, free0)
        collect_available(is, cur, free)

      false ->
        collect_available(is, cur, free0)
    end
  end

  defp collect_available([], _, free) do
    free
  end

  defp select_register(
         [{_, _} = reg | _],
         r_l(cur: cur0, regs: regs) = l
       ) do
    cur = r_i(cur0, reg: reg)

    reserve_reg(
      cur,
      r_l(l, cur: cur, regs: [{r_i(cur, :var), reg} | regs])
    )
  end

  defp select_register([], r_l(cur: cur0, regs: regs) = l0) do
    {reg, l1} = get_next_free(cur0, l0)
    cur = r_i(cur0, reg: reg)
    l = r_l(l1, cur: cur, regs: [{r_i(cur, :var), reg} | regs])
    reserve_reg(cur, l)
  end

  defp make_cur_active(r_l(cur: cur, active: act) = l) do
    r_l(l, active: [cur | act])
  end

  defp overlaps(r_i(rs: rs1), r_i(rs: rs2)) do
    are_overlapping(rs1, rs2)
  end

  defp overlap_status([{s, e}], curBegin) do
    cond do
      e <= curBegin ->
        :ends_before_cur

      curBegin < s ->
        :not_overlapping

      true ->
        :overlapping
    end
  end

  defp overlap_status([{s, e} | rs], curBegin) do
    cond do
      e <= curBegin ->
        overlap_status(rs, curBegin)

      s <= curBegin ->
        :overlapping

      true ->
        :not_overlapping
    end
  end

  defp reserve_reg(r_i(reg: {_, _} = reg) = i, l) do
    freeRegs0 = get_pool(i, l)
    freeRegs = :ordsets.del_element(reg, freeRegs0)
    update_pool(i, freeRegs, l)
  end

  defp free_reg(r_i(reg: {_, _} = reg) = i, l) do
    freeRegs0 = get_pool(i, l)
    freeRegs = :ordsets.add_element(reg, freeRegs0)
    update_pool(i, freeRegs, l)
  end

  defp get_pool(r_i(pool: pool), r_l(free: free)) do
    :erlang.map_get(pool, free)
  end

  defp update_pool(r_i(pool: pool), new, r_l(free: free0) = l) do
    free = %{free0 | pool => new}
    r_l(l, free: free)
  end

  defp get_next_free(r_i(pool: pool), r_l(free: free0) = l0) do
    k = {:next, pool}
    n = :erlang.map_get(k, free0)
    free = %{free0 | k => n + 1}
    l = r_l(l0, free: free)

    cond do
      is_integer(pool) ->
        {{:y, n}, l}

      is_atom(pool) ->
        {{pool, n}, l}
    end
  end

  defp are_overlapping([r | rs1], rs2) do
    case are_overlapping_1(r, rs2) do
      true ->
        true

      false ->
        are_overlapping(rs1, rs2)
    end
  end

  defp are_overlapping([], _) do
    false
  end

  defp are_overlapping_1({_S1, e1}, [{s2, _E2} | _]) when e1 < s2 do
    false
  end

  defp are_overlapping_1({s1, e1} = r, [{s2, e2} | rs]) do
    (s2 < e1 and e2 > s1) or are_overlapping_1(r, rs)
  end

  defp are_overlapping_1({_, _}, []) do
    false
  end

  defp is_loop_header(l, blocks) do
    case :erlang.map_get(l, blocks) do
      r_b_blk(is: [i | _]) ->
        :beam_ssa.is_loop_header(i)

      r_b_blk() ->
        false
    end
  end

  defp rel2fam(s0) do
    s1 = :sofs.relation(s0)
    s = :sofs.rel2fam(s1)
    :sofs.to_external(s)
  end

  defp is_yreg({:y, _}) do
    true
  end

  defp is_yreg({:x, _}) do
    false
  end

  defp is_yreg({:z, _}) do
    false
  end

  defp is_yreg({:fr, _}) do
    false
  end

  defp new_vars([base | vs0], count0) do
    {v, count1} = new_var(base, count0)
    {vs, count} = new_vars(vs0, count1)
    {[v | vs], count}
  end

  defp new_vars([], count) do
    {[], count}
  end

  defp new_var({base, int}, count) do
    true = is_integer(int)
    {r_b_var(name: {base, count}), count + 1}
  end

  defp new_var(base, count) do
    {r_b_var(name: {base, count}), count + 1}
  end
end
