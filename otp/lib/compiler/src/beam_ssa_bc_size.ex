defmodule :m_beam_ssa_bc_size do
  use Bitwise
  import :lists, only: [any: 2, member: 2, reverse: 1,
                          sort: 1]
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
  def opt(stMap) when is_map(stMap) do
    opt(:maps.keys(stMap), stMap)
  end

  defp opt([id | ids], stMap0) do
    stMap = opt_function(id, stMap0)
    opt(ids, stMap)
  end

  defp opt([], stMap) do
    stMap
  end

  defp opt_function(id, stMap) do
    r_opt_st(anno: anno, ssa: linear0,
        cnt: count0) = (optSt0 = :erlang.map_get(id, stMap))
    paramInfo = :maps.get(:parameter_info, anno, %{})
    try do
      opt_blks(linear0, paramInfo, stMap, :unchanged, count0,
                 [])
    catch
      class, error ->
        r_b_local(name: r_b_literal(val: name), arity: arity) = id
        :io.fwrite('Function: ~w/~w\n', [name, arity])
        :erlang.raise(class, error, __STACKTRACE__)
    else
      {linear, count} ->
        optSt = r_opt_st(optSt0, ssa: linear,  cnt: count)
        %{stMap | id => optSt}
      :none ->
        stMap
    end
  end

  defp opt_blks([{l, r_b_blk(is: is) = blk} | blks], paramInfo, stMap,
            anyChange, count0, acc0) do
    case (is) do
      [r_b_set(op: :bs_init_writable, dst: dst)] ->
        bs = %{st_map: stMap, dst => {:writable, r_b_literal(val: 0)},
                 seen: :sets.new([{:version, 2}])}
        try do
          opt_writable(bs, l, blk, blks, paramInfo, count0, acc0)
        catch
          :not_possible ->
            opt_blks(blks, paramInfo, stMap, anyChange, count0,
                       [{l, blk} | acc0])
        else
          {acc, count} ->
            opt_blks(blks, paramInfo, stMap, :changed, count, acc)
        end
      _ ->
        opt_blks(blks, paramInfo, stMap, anyChange, count0,
                   [{l, blk} | acc0])
    end
  end

  defp opt_blks([], _ParamInfo, _StMap, :changed, count, acc) do
    {reverse(acc), count}
  end

  defp opt_blks([], _ParamInfo, _StMap, :unchanged, _Count,
            _Acc) do
    :none
  end

  defp ensure_not_match_context(r_b_set(anno: anno, args: [_ | args]), paramInfo) do
    case (:maps.get(:bsm_info, anno, [])) do
      :context_reused ->
        throw(:not_possible)
      _ ->
        case (any(fn v ->
                       member(:accepts_match_context,
                                :maps.get(v, paramInfo, []))
                  end,
                    args)) do
          true ->
            throw(:not_possible)
          false ->
            :ok
        end
    end
  end

  defp call_size_func(r_b_set(anno: anno, op: :call, args: [name | args],
              dst: dst),
            bs) do
    stMap = :erlang.map_get(:st_map, bs)
    case (stMap) do
      %{^name => r_opt_st(ssa: linear, args: params)} ->
        newBs0 = setup_call_bs(params, args, bs, %{})
        case (any(fn {:writable, _} ->
                       true
                     _ ->
                       false
                  end,
                    :maps.values(newBs0))) do
          false ->
            Map.put(bs, dst, :any)
          true ->
            seen0 = :erlang.map_get(:seen, bs)
            case (:sets.is_element(name, seen0)) do
              true ->
                throw(:not_possible)
              false ->
                seen = :sets.add_element(name, seen0)
                newBs = Map.merge(newBs0, %{name => :self,
                                              st_map: stMap, seen: seen})
                map0 = %{0 => newBs}
                result = calc_size(linear, map0)
                Map.put(bs, dst, result)
            end
        end
      %{} ->
        case (name) do
          r_b_remote(mod: r_b_literal(val: :erlang), name: r_b_literal(val: :error),
              arity: 1) ->
            capture_anno(anno, dst, args,
                           Map.put(bs, dst, :exception))
          _ ->
            Map.put(bs, dst, :any)
        end
    end
  end

  defp capture_anno(anno, dst, [errorTerm], bs) do
    case (get_value(errorTerm, bs)) do
      {:tuple, elements} ->
        ts = (for e <- elements do
                get_value(e, bs)
              end)
        capture_anno_1(anno, dst, ts, bs)
      _ ->
        bs
    end
  end

  defp capture_anno_1(anno, dst, [{:nil_or_bad, generator} | _],
            bs) do
    Map.put(bs, dst, {:generator_anno, {generator, anno}})
  end

  defp capture_anno_1(anno, dst, [{:arg, generator} | _], bs) do
    Map.put(bs, dst, {:generator_anno, {generator, anno}})
  end

  defp capture_anno_1(anno, dst, [_ | t], bs) do
    capture_anno_1(anno, dst, t, bs)
  end

  defp capture_anno_1(_, _, [], bs) do
    bs
  end

  defp setup_call_bs([v | vs], [a0 | as], oldBs, newBs) do
    a = (case (get_value(a0, oldBs)) do
           r_b_literal() = lit ->
             {:arg, lit}
           {:writable, r_b_literal(val: 0)} = wr ->
             wr
           {:arg, _} = arg ->
             arg
           _ ->
             :any
         end)
    setup_call_bs(vs, as, oldBs, Map.put(newBs, v, a))
  end

  defp setup_call_bs([], [], %{}, newBs) do
    newBs
  end

  defp calc_size([{l, r_b_blk(is: is, last: last)} | blks], map0) do
    case (:maps.take(l, map0)) do
      {bs0, map1} when is_map(bs0) ->
        bs1 = calc_size_is(is, bs0)
        map2 = update_successors(last, bs1, map1)
        case (get_ret(last, bs1)) do
          :none ->
            calc_size(blks, map2)
          ret ->
            map = Map.put(map2, l, ret)
            calc_size(blks, map)
        end
      :error ->
        calc_size(blks, map0)
    end
  end

  defp calc_size([], map) do
    case (sort(:maps.values(map))) do
      [{:call, _} = call, {:generator_anno, genAnno}] ->
        {call, genAnno}
      _ ->
        throw(:not_possible)
    end
  end

  defp get_ret(r_b_ret(arg: arg), bs) do
    case (get_value(arg, bs)) do
      :exception ->
        :none
      {:writable, r_b_literal(val: 0)} ->
        :none
      {:generator_anno, _} = genAnno ->
        genAnno
      ret ->
        ret
    end
  end

  defp get_ret(_, _) do
    :none
  end

  defp update_successors(r_b_br(bool: bool, succ: succ, fail: fail), bs0,
            map0) do
    case (get_value(bool, bs0)) do
      r_b_literal(val: true) ->
        update_successor(succ, bs0, map0)
      r_b_literal(val: false) ->
        update_successor(fail, bs0, map0)
      {:succeeded, var} ->
        map = update_successor(succ, bs0, map0)
        update_successor(fail, :maps.remove(var, bs0), map)
      {:if, var, trueType, falseType} ->
        bs = :maps.remove(bool, bs0)
        case (var) do
          r_b_var() ->
            map = update_successor(succ, Map.put(bs, var, trueType),
                                     map0)
            update_successor(fail, Map.put(bs, var, falseType), map)
          r_b_literal() ->
            bs
        end
      :any ->
        map = update_successor(succ,
                                 %{bs0 | bool => r_b_literal(val: true)}, map0)
        update_successor(fail, %{bs0 | bool => r_b_literal(val: false)},
                           map)
    end
  end

  defp update_successors(r_b_switch(), _Bs, _Map) do
    throw(:not_possible)
  end

  defp update_successors(r_b_ret(), _Bs, map) do
    map
  end

  defp update_successor(1, _Bs, map) do
    map
  end

  defp update_successor(l, bs, map) do
    case (map) do
      %{^l => oldBs} ->
        %{map | l => join_bs(oldBs, bs)}
      %{} ->
        Map.put(map, l, bs)
    end
  end

  defp calc_size_is([i | is], bs0) do
    bs = calc_size_instr(i, bs0)
    calc_size_is(is, bs)
  end

  defp calc_size_is([], bs) do
    bs
  end

  defp calc_size_instr(r_b_set(op: :bs_create_bin,
              args: [r_b_literal(val: :private_append), _, writable, _ | args],
              dst: dst),
            bs) do
    case (calc_create_bin_size(args, bs)) do
      {:expr, expr} ->
        update_writable(dst, writable, expr, bs)
      :any ->
        Map.put(bs, dst, :any)
    end
  end

  defp calc_size_instr(r_b_set(op: :bs_match,
              args: [_Type, ctx, _Flags, size, unit], dst: dst),
            bs) do
    case (get_arg_value(size, bs)) do
      :none ->
        Map.put(bs, dst, :any)
      val ->
        update_match(dst, ctx,
                       {{:safe, {:bif, :"*"}}, [val, unit]}, bs)
    end
  end

  defp calc_size_instr(r_b_set(op: :bs_start_match,
              args: [r_b_literal(val: :new), arg], dst: dst),
            bs) do
    case (get_arg_value(arg, bs)) do
      :none ->
        Map.put(bs, dst, :any)
      val ->
        Map.put(bs, dst,
                      {:match, {{:bif, :bit_size}, [val]}, r_b_literal(val: 0)})
    end
  end

  defp calc_size_instr(r_b_set(op: :call, args: [name | args], dst: dst) = i,
            bs) do
    cond do
      :erlang.is_map_key(name, bs) ->
        result0 = (for a <- args do
                     get_value(a, bs)
                   end)
        result = (for val <- result0, val !== :any do
                    val
                  end)
        Map.put(bs, dst, {:call, result})
      true ->
        call_size_func(i, bs)
    end
  end

  defp calc_size_instr(r_b_set(op: :get_tl, args: [ctx], dst: dst), bs) do
    update_match(dst, ctx, r_b_literal(val: 1), bs)
  end

  defp calc_size_instr(r_b_set(op: :is_nonempty_list, args: [arg], dst: dst),
            bs) do
    case (get_arg_value(arg, bs)) do
      :none ->
        Map.put(bs, dst, :any)
      val ->
        numElements = {{:bif, :length}, [val]}
        match = {:match, numElements, r_b_literal(val: 0)}
        noMatch = {:nil_or_bad, val}
        Map.put(bs, dst, {:if, arg, match, noMatch})
    end
  end

  defp calc_size_instr(r_b_set(op: :put_tuple, args: args, dst: dst), bs) do
    Map.put(bs, dst, {:tuple, args})
  end

  defp calc_size_instr(r_b_set(op: {:succeeded, _}, args: [arg], dst: dst),
            bs) do
    Map.put(bs, dst, {:succeeded, arg})
  end

  defp calc_size_instr(r_b_set(dst: dst), bs) do
    Map.put(bs, dst, :any)
  end

  defp calc_create_bin_size(args, bs) do
    calc_create_bin_size(args, bs, r_b_literal(val: 0))
  end

  defp calc_create_bin_size([_, r_b_literal(val: [0 | _]), _, _ | _], _Bs, _Acc) do
    :any
  end

  defp calc_create_bin_size([_, r_b_literal(val: [u | _]), _, size | t], bs, acc0)
      when is_integer(u) do
    case (get_value(size, bs)) do
      r_b_literal(val: val) when is_integer(val) ->
        acc = {{:bif, :"+"}, [acc0, r_b_literal(val: u * val)]}
        calc_create_bin_size(t, bs, acc)
      {:arg, var} ->
        acc = {{:bif, :"+"},
                 [acc0, {{:bif, :"*"}, [var, r_b_literal(val: u)]}]}
        calc_create_bin_size(t, bs, acc)
      _ ->
        :any
    end
  end

  defp calc_create_bin_size([], _Bs, acc) do
    {:expr, acc}
  end

  defp update_writable(dst, writable, expr, bs) do
    case (get_value(writable, bs)) do
      {:writable, r_b_literal(val: 0)} ->
        Map.put(bs, dst, {:writable, expr})
      _ ->
        Map.put(bs, dst, :any)
    end
  end

  defp update_match(dst, ctx, increment, bs) do
    case (get_value(ctx, bs)) do
      {:match, numElements, offset0} ->
        offset = {{:bif, :"+"}, [offset0, increment]}
        Map.put(bs, dst, {:match, numElements, offset})
      _ ->
        Map.put(bs, dst, :any)
    end
  end

  defp get_arg_value(r_b_literal() = lit, _Bs) do
    lit
  end

  defp get_arg_value(name, bs) do
    case (bs) do
      %{^name => {:arg, val}} ->
        val
      %{} ->
        :none
    end
  end

  defp get_value(name, bs) do
    case (bs) do
      %{^name => value} ->
        value
      %{} ->
        name
    end
  end

  defp join_bs(lHS, rHS) do
    cond do
      map_size(lHS) < map_size(rHS) ->
        join_bs_1(:maps.keys(lHS), rHS, lHS)
      true ->
        join_bs_1(:maps.keys(rHS), lHS, rHS)
    end
  end

  defp join_bs_1([v | vs], bigger, smaller) do
    case ({bigger, smaller}) do
      {%{^v => same}, %{^v => same}} ->
        join_bs_1(vs, bigger, smaller)
      {%{^v => _LHS}, %{^v => _RHS}} ->
        join_bs_1(vs, bigger, %{smaller | v => :any})
      {%{}, %{^v => _}} ->
        join_bs_1(vs, bigger, :maps.remove(v, smaller))
    end
  end

  defp join_bs_1([], _Bigger, smaller) do
    smaller
  end

  defp make_expr_tree({{:call, alloc0}, genAnno}) do
    {alloc1, annos} = make_expr_tree_list(alloc0, :none,
                                            :none, [genAnno])
    alloc2 = opt_expr(alloc1)
    alloc = round_up_to_byte_size(alloc2)
    {alloc, :maps.from_list(annos)}
  end

  defp make_expr_tree(_) do
    throw(:not_possible)
  end

  defp make_expr_tree_list([{{:call, list}, genAnno} | t], match, :none,
            annos0) do
    {buildSize, annos} = make_expr_tree_list(list, :none,
                                               :none, [genAnno | annos0])
    make_expr_tree_list(t, match, buildSize, annos)
  end

  defp make_expr_tree_list([{:match, numItems, n} | t], :none, buildSize,
            annos) do
    make_expr_tree_list(t, {numItems, n}, buildSize, annos)
  end

  defp make_expr_tree_list([{:writable, buildSize} | t], match, :none,
            annos) do
    make_expr_tree_list(t, match, buildSize, annos)
  end

  defp make_expr_tree_list([_ | t], match, buildSize, annos) do
    make_expr_tree_list(t, match, buildSize, annos)
  end

  defp make_expr_tree_list([], match, buildSize, annos)
      when (match !== :none and buildSize !== :none) do
    {numItems, n} = match
    expr = {{:bif, :"*"},
              [{{:safe, {:bif, :div}}, [numItems, n]}, buildSize]}
    {expr, annos}
  end

  defp make_expr_tree_list([], _, _, annos) do
    {:none, annos}
  end

  defp round_up_to_byte_size(alloc0) do
    alloc = (case (divisible_by_eight(alloc0)) do
               true ->
                 alloc0
               false ->
                 {{:bif, :"+"}, [alloc0, r_b_literal(val: 7)]}
             end)
    opt_expr({{:bif, :div}, [alloc, r_b_literal(val: 8)]})
  end

  defp divisible_by_eight({{:bif, :"*"}, [expr1, expr2]}) do
    divisible_by_eight(expr1) or divisible_by_eight(expr2)
  end

  defp divisible_by_eight(r_b_literal(val: val)) when rem(val, 8) === 0 do
    true
  end

  defp divisible_by_eight(_) do
    false
  end

  defp opt_expr({op, args0}) do
    args = opt_expr_args(args0)
    case (literal_expr_args(args, [])) do
      :none ->
        opt_expr_1(op, args)
      litArgs ->
        bif = (case (op) do
                 {:safe, {:bif, bif0}} ->
                   bif0
                 {:bif, bif0} ->
                   bif0
               end)
        try do
          apply(:erlang, bif, litArgs)
        catch
          :error, _ ->
            opt_expr_1(op, args)
        else
          result ->
            r_b_literal(val: result)
        end
    end
  end

  defp opt_expr(:none) do
    :none
  end

  defp opt_expr_1({:safe, {:bif, :div}} = op, args) do
    case (args) do
      [int, r_b_literal(val: 1)] ->
        int
      [_Int, r_b_literal(val: n)] when n > 1 ->
        opt_expr_1({:bif, :div}, args)
      [_, _] ->
        {op, args}
    end
  end

  defp opt_expr_1({:bif, :div} = op,
            [numerator, r_b_literal(val: denominator)] = args) do
    try do
      opt_expr_div(numerator, denominator)
    catch
      :not_possible ->
        try do
          denominator &&& (denominator - 1)
        catch
          _, _ ->
            {op, args}
        else
          0 ->
            shift = round(:math.log2(denominator))
            {{:bif, :bsr}, [numerator, r_b_literal(val: shift)]}
          _ ->
            {op, args}
        end
    end
  end

  defp opt_expr_1({:bif, :"*"},
            [{{:safe, _}, _}, r_b_literal(val: 0) = zero]) do
    zero
  end

  defp opt_expr_1({:bif, :"*"}, [factor, r_b_literal(val: 1)]) do
    factor
  end

  defp opt_expr_1(op, args) do
    {op, args}
  end

  defp opt_expr_div({{:bif, :"*"}, [a, b]}, denominator) do
    case (b) do
      r_b_literal(val: factor) when rem(factor, denominator) === 0 ->
        {{:bif, :"*"}, [a, r_b_literal(val: div(factor, denominator))]}
      _ ->
        {{:bif, :"*"}, [a, opt_expr_div(b, denominator)]}
    end
  end

  defp opt_expr_div(_, _) do
    throw(:not_possible)
  end

  defp opt_expr_args([a0 | as]) do
    a = (case (a0) do
           r_b_literal() ->
             a0
           r_b_var() ->
             a0
           _ ->
             opt_expr(a0)
         end)
    [a | opt_expr_args(as)]
  end

  defp opt_expr_args([]) do
    []
  end

  defp literal_expr_args([r_b_literal(val: val) | as], acc) do
    literal_expr_args(as, [val | acc])
  end

  defp literal_expr_args([_ | _], _) do
    :none
  end

  defp literal_expr_args([], acc) do
    reverse(acc)
  end

  defp cg_size_calc(expr, l, r_b_blk(is: is0) = blk0, callLast, annos,
            count0, acc0) do
    [initWr] = is0
    failBlk0 = []
    {acc1, alloc, nextBlk, failBlk,
       count} = cg_size_calc_1(l, expr, annos, callLast,
                                 failBlk0, count0, acc0)
    is = [r_b_set(initWr, args: [alloc])]
    blk = r_b_blk(blk0, is: is)
    acc = [{nextBlk, blk} | failBlk ++ acc1]
    {acc, count}
  end

  defp cg_size_calc_1(l, r_b_literal() = alloc, _Annos, _CallLast, failBlk,
            count, acc) do
    {acc, alloc, l, failBlk, count}
  end

  defp cg_size_calc_1(l0, {op0, args0}, annos, callLast, failBlk0,
            count0, acc0) do
    {args, acc1, l, failBlk1,
       count1} = cg_atomic_args(args0, l0, annos, callLast,
                                  failBlk0, count0, acc0, [])
    {badGenL, failBlk, count2} = cg_bad_generator(args,
                                                    annos, callLast, failBlk1,
                                                    count1)
    {dst, count3} = new_var(:"@ssa_tmp", count2)
    case (op0) do
      {:safe, op} ->
        {opDst, count4} = new_var(:"@ssa_size", count3)
        {[opSuccL, opFailL, phiL, nextL],
           count5} = new_blocks(4, count4)
        i = r_b_set(op: op, args: args, dst: opDst)
        {blk, count} = cg_succeeded(i, opSuccL, opFailL, count5)
        jumpBlk = r_b_blk(is: [], last: cg_br(phiL))
        phiIs = [r_b_set(op: :phi,
                     args: [{opDst, opSuccL}, {r_b_literal(val: 0), opFailL}],
                     dst: dst)]
        phiBlk = r_b_blk(is: phiIs, last: cg_br(nextL))
        acc = [{phiL, phiBlk}, {opSuccL, jumpBlk}, {opFailL,
                                                      jumpBlk},
                                                       {l, blk} | acc1]
        {acc, dst, nextL, failBlk, count}
      _ ->
        {nextBlkL, count4} = new_block(count3)
        i = r_b_set(op: op0, args: args, dst: dst)
        {succBlk, count} = cg_succeeded(i, nextBlkL, badGenL,
                                          count4)
        acc = [{l, succBlk} | acc1]
        {acc, dst, nextBlkL, failBlk, count}
    end
  end

  defp cg_bad_generator([arg | _], annos, callLast, failBlk, count) do
    case (annos) do
      %{^arg => anno} ->
        cg_bad_generator_1(anno, arg, callLast, failBlk, count)
      %{} ->
        case (failBlk) do
          [{l, _} | _] ->
            {l, failBlk, count}
          [] ->
            cg_bad_generator_1(%{}, arg, callLast, failBlk, count)
        end
    end
  end

  defp cg_bad_generator_1(anno, arg, callLast, failBlk, count0) do
    {l, count1} = new_block(count0)
    {tupleDst, count2} = new_var(:"@ssa_tuple", count1)
    {succDst, count3} = new_var(:"@ssa_bool", count2)
    {ret, count4} = new_var(:"@ssa_ret", count3)
    mFA = r_b_remote(mod: r_b_literal(val: :erlang), name: r_b_literal(val: :error),
              arity: 1)
    tupleI = r_b_set(op: :put_tuple,
                 args: [r_b_literal(val: :bad_generator), arg], dst: tupleDst)
    callI = r_b_set(anno: anno, op: :call, args: [mFA, tupleDst],
                dst: ret)
    succI = r_b_set(op: {:succeeded, :body}, args: [ret],
                dst: succDst)
    is = [tupleI, callI, succI]
    r_b_br(fail: failLbl) = callLast
    last = r_b_br(bool: succDst, succ: failLbl, fail: failLbl)
    blk = r_b_blk(is: is, last: last)
    {l, [{l, blk} | failBlk], count4}
  end

  defp cg_succeeded(r_b_set(dst: opDst) = i, succ, fail, count0) do
    {bool, count} = new_var(:"@ssa_bool", count0)
    succI = r_b_set(op: {:succeeded, :guard}, args: [opDst],
                dst: bool)
    blk = r_b_blk(is: [i, succI],
              last: r_b_br(bool: bool, succ: succ, fail: fail))
    {blk, count}
  end

  defp cg_br(target) do
    r_b_br(bool: r_b_literal(val: true), succ: target, fail: target)
  end

  defp cg_atomic_args([a | as], l, annos, callLast, failBlk0, count0,
            blkAcc0, acc) do
    case (a) do
      r_b_literal() ->
        cg_atomic_args(as, l, annos, callLast, failBlk0, count0,
                         blkAcc0, [a | acc])
      r_b_var() ->
        cg_atomic_args(as, l, annos, callLast, failBlk0, count0,
                         blkAcc0, [a | acc])
      :none ->
        throw(:not_possible)
      _ ->
        {blkAcc, var, nextBlk, failBlk,
           count} = cg_size_calc_1(l, a, annos, callLast, failBlk0,
                                     count0, blkAcc0)
        cg_atomic_args(as, nextBlk, annos, callLast, failBlk,
                         count, blkAcc, [var | acc])
    end
  end

  defp cg_atomic_args([], nextBlk, _Annos, _CallLast, failBlk, count,
            blkAcc, acc) do
    {reverse(acc), blkAcc, nextBlk, failBlk, count}
  end

  defp new_var(base, count) do
    {r_b_var(name: {base, count}), count + 1}
  end

  defp new_blocks(n, count) do
    new_blocks(n, count, [])
  end

  defp new_blocks(0, count, acc) do
    {acc, count}
  end

  defp new_blocks(n, count, acc) do
    new_blocks(n - 1, count + 1, [count | acc])
  end

  defp new_block(count) do
    {count, count + 1}
  end

end