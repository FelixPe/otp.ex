defmodule :m_beam_trim do
  use Bitwise
  import :lists, only: [any: 2, reverse: 1, reverse: 2,
                          seq: 2, sort: 1]
  require Record
  Record.defrecord(:r_t_atom, :t_atom, elements: :any)
  Record.defrecord(:r_t_bitstring, :t_bitstring, size_unit: 1,
                                       appendable: false)
  Record.defrecord(:r_t_bs_context, :t_bs_context, tail_unit: 1)
  Record.defrecord(:r_t_bs_matchable, :t_bs_matchable, tail_unit: 1)
  Record.defrecord(:r_t_float, :t_float, elements: :any)
  Record.defrecord(:r_t_fun, :t_fun, arity: :any, target: :any,
                                 type: :any)
  Record.defrecord(:r_t_integer, :t_integer, elements: :any)
  Record.defrecord(:r_t_number, :t_number, elements: :any)
  Record.defrecord(:r_t_map, :t_map, super_key: :any,
                                 super_value: :any)
  Record.defrecord(:r_t_cons, :t_cons, type: :any,
                                  terminator: :any)
  Record.defrecord(:r_t_list, :t_list, type: :any,
                                  terminator: :any)
  Record.defrecord(:r_t_tuple, :t_tuple, size: 0, exact: false,
                                   elements: %{})
  Record.defrecord(:r_t_union, :t_union, atom: :none, list: :none,
                                   number: :none, tuple_set: :none,
                                   other: :none)
  Record.defrecord(:r_tr, :tr, r: :undefined, t: :undefined)
  Record.defrecord(:r_st, :st, safe: :undefined,
                              fsz: :undefined)
  def module({mod, exp, attr, fs0, lc}, _Opts) do
    fs = (for f <- fs0 do
            function(f)
          end)
    {:ok, {mod, exp, attr, fs, lc}}
  end

  defp function({:function, name, arity, cLabel, is0}) do
    try do
      st = r_st(safe: safe_labels(is0, []), fsz: 0)
      usage = :none
      is = trim(is0, usage, st)
      {:function, name, arity, cLabel, is}
    catch
      class, error ->
        :io.fwrite('Function: ~w/~w\n', [name, arity])
        :erlang.raise(class, error, __STACKTRACE__)
    end
  end

  defp trim([{:init_yregs, _} = i | is], :none, st0) do
    case (usage(is, st0)) do
      :none ->
        [i | trim(is, :none, st0)]
      {frameSize, us} ->
        st = r_st(st0, fsz: frameSize)
        trim([i | is], us, st)
    end
  end

  defp trim([{:init_yregs, {:list, killed}} = i | is0],
            [u | us], st) do
    frameSize = r_st(st, :fsz)
    layout = frame_layout(frameSize, killed, u)
    isNotRecursive = is_not_recursive(is0)
    case (trim_recipe(layout, isNotRecursive, u)) do
      :none ->
        [i | trim(is0, us, st)]
      r ->
        {trimInstr, remap} = expand_recipe(r, frameSize)
        is = remap(is0, remap)
        trimInstr ++ trim(is, :none, st)
    end
  end

  defp trim([i | is], [_ | us], st) do
    [i | trim(is, us, st)]
  end

  defp trim([i | is], :none, st) do
    [i | trim(is, :none, st)]
  end

  defp trim([i | is], [], st) do
    [i | trim(is, :none, st)]
  end

  defp trim([], _, _) do
    []
  end

  defp is_not_recursive([{:call_ext, _, ext} | _]) do
    case (ext) do
      {:extfunc, m, f, a} ->
        :erl_bifs.is_pure(m, f, a)
      _ ->
        false
    end
  end

  defp is_not_recursive([{:block, _} | is]) do
    is_not_recursive(is)
  end

  defp is_not_recursive([{:line, _} | is]) do
    is_not_recursive(is)
  end

  defp is_not_recursive(_) do
    false
  end

  defp trim_recipe(layout, isNotRecursive, {us, ns}) do
    usedRegs = :ordsets.union(us, ns)
    recipes = construct_recipes(layout, 0, [], [])
    numOrigKills = length(for ({:kill, _} = i) <- layout do
                            i
                          end)
    isTooExpensive = is_too_expensive_fun(isNotRecursive)
    rs = (for r <- recipes, is_recipe_viable(r, usedRegs),
                not is_too_expensive(r, numOrigKills, isTooExpensive) do
            r
          end)
    case (rs) do
      [] ->
        :none
      [r | _] ->
        r
    end
  end

  defp construct_recipes([{:kill, {:y, trim0}} | ks], trim0, moves,
            acc) do
    trim = trim0 + 1
    recipe = {ks, trim, moves}
    construct_recipes(ks, trim, moves, [recipe | acc])
  end

  defp construct_recipes([{:dead, {:y, trim0}} | ks], trim0, moves,
            acc) do
    trim = trim0 + 1
    recipe = {ks, trim, moves}
    construct_recipes(ks, trim, moves, [recipe | acc])
  end

  defp construct_recipes([{:live, {:y, trim0} = src} | ks0], trim0,
            moves0, acc) do
    case (take_last_dead(ks0)) do
      :none ->
        acc
      {dst, ks} ->
        trim = trim0 + 1
        moves = [{:move, src, dst} | moves0]
        recipe = {ks, trim, moves}
        construct_recipes(ks, trim, moves, [recipe | acc])
    end
  end

  defp construct_recipes(_, _, _, acc) do
    acc
  end

  defp take_last_dead(l) do
    take_last_dead_1(reverse(l))
  end

  defp take_last_dead_1([{:live, _} | is]) do
    take_last_dead_1(is)
  end

  defp take_last_dead_1([{:kill, reg} | is]) do
    {reg, reverse(is)}
  end

  defp take_last_dead_1([{:dead, reg} | is]) do
    {reg, reverse(is)}
  end

  defp take_last_dead_1(_) do
    :none
  end

  defp is_too_expensive({ks, _, moves}, numOrigKills, isTooExpensive) do
    numKills = num_kills(ks, 0)
    numMoves = length(moves)
    isTooExpensive.(numKills, numMoves, numOrigKills)
  end

  defp num_kills([{:kill, _} | t], acc) do
    num_kills(t, acc + 1)
  end

  defp num_kills([_ | t], acc) do
    num_kills(t, acc)
  end

  defp num_kills([], acc) do
    acc
  end

  defp is_too_expensive_fun(true) do
    fn numKills, numMoves, numOrigKills ->
         penalty = (cond do
                      numMoves !== 0 ->
                        1
                      true ->
                        0
                    end)
         1 + penalty + numKills + numMoves > numOrigKills
    end
  end

  defp is_too_expensive_fun(false) do
    fn numKills, numMoves, numOrigKills ->
         numKills + numMoves > numOrigKills
    end
  end

  defp is_recipe_viable({_, trim, moves}, usedRegs) do
    moved = :ordsets.from_list(for {:move, src,
                                      _} <- moves do
                                 src
                               end)
    illegal = :ordsets.from_list(for {:move, _,
                                        dst} <- moves do
                                   dst
                                 end)
    eliminated = (for n <- seq(0, trim - 1) do
                    {:y, n}
                  end)
    usedEliminated = :ordsets.intersection(eliminated,
                                             usedRegs)
    case (:ordsets.is_subset(usedEliminated,
                               moved) and :ordsets.is_disjoint(illegal,
                                                                 usedRegs)) do
      true ->
        ^usedEliminated = moved
        true
      _ ->
        false
    end
  end

  defp remap([{:"%", comment} = i0 | is], remap) do
    case (comment) do
      {:var_info, {:y, _} = var, type} ->
        i = {:"%", {:var_info, remap_arg(var, remap), type}}
        [i | remap(is, remap)]
      _ ->
        [i0 | remap(is, remap)]
    end
  end

  defp remap([{:block, bl0} | is], remap) do
    bl = remap_block(bl0, remap)
    i = {:block, bl}
    [i | remap(is, remap)]
  end

  defp remap([{:bs_create_bin, fail, alloc, live, unit, dst0,
              {:list, ss0}} |
               is],
            remap) do
    dst = remap_arg(dst0, remap)
    ss = remap_args(ss0, remap)
    i = {:bs_create_bin, fail, alloc, live, unit, dst,
           {:list, ss}}
    [i | remap(is, remap)]
  end

  defp remap([{:bs_get_tail, src, dst, live} | is], remap) do
    i = {:bs_get_tail, remap_arg(src, remap),
           remap_arg(dst, remap), live}
    [i | remap(is, remap)]
  end

  defp remap([{:bs_start_match4, fail, live, src, dst} | is],
            remap) do
    i = {:bs_start_match4, fail, live,
           remap_arg(src, remap), remap_arg(dst, remap)}
    [i | remap(is, remap)]
  end

  defp remap([{:bs_set_position, src1, src2} | is], remap) do
    i = {:bs_set_position, remap_arg(src1, remap),
           remap_arg(src2, remap)}
    [i | remap(is, remap)]
  end

  defp remap([{:call_fun, _} = i | is], remap) do
    [i | remap(is, remap)]
  end

  defp remap([{:call_fun2, tag, arity, func} = i | is],
            remap) do
    ^i = {:call_fun2, tag, arity, remap_arg(func, remap)}
    [i | remap(is, remap)]
  end

  defp remap([{:call, _, _} = i | is], remap) do
    [i | remap(is, remap)]
  end

  defp remap([{:call_ext, _, _} = i | is], remap) do
    [i | remap(is, remap)]
  end

  defp remap([{:apply, _} = i | is], remap) do
    [i | remap(is, remap)]
  end

  defp remap([{:bif, name, fail, ss, d} | is], remap) do
    i = {:bif, name, fail, remap_args(ss, remap),
           remap_arg(d, remap)}
    [i | remap(is, remap)]
  end

  defp remap([{:gc_bif, name, fail, live, ss, d} | is],
            remap) do
    i = {:gc_bif, name, fail, live, remap_args(ss, remap),
           remap_arg(d, remap)}
    [i | remap(is, remap)]
  end

  defp remap([{:get_map_elements, fail, m, {:list, l0}} |
               is],
            remap) do
    l = remap_args(l0, remap)
    i = {:get_map_elements, fail, remap_arg(m, remap),
           {:list, l}}
    [i | remap(is, remap)]
  end

  defp remap([{:init_yregs, {:list, yregs0}} | is], remap) do
    yregs = sort(remap_args(yregs0, remap))
    i = {:init_yregs, {:list, yregs}}
    [i | remap(is, remap)]
  end

  defp remap([{:make_fun3, f, index, oldUniq, dst0,
              {:list, env0}} |
               is],
            remap) do
    env = remap_args(env0, remap)
    dst = remap_arg(dst0, remap)
    i = {:make_fun3, f, index, oldUniq, dst, {:list, env}}
    [i | remap(is, remap)]
  end

  defp remap([{:update_record, hint, size, src0, dst0,
              {:list, updates0}} |
               is],
            remap) do
    updates = remap_args(updates0, remap)
    src = remap_arg(src0, remap)
    dst = remap_arg(dst0, remap)
    i = {:update_record, hint, size, src, dst,
           {:list, updates}}
    [i | remap(is, remap)]
  end

  defp remap([{:deallocate, n} | is], {trim, _} = remap) do
    i = {:deallocate, n - trim}
    [i | remap(is, remap)]
  end

  defp remap([{:recv_marker_clear, ref} | is], remap) do
    i = {:recv_marker_clear, remap_arg(ref, remap)}
    [i | remap(is, remap)]
  end

  defp remap([{:recv_marker_reserve, mark} | is], remap) do
    i = {:recv_marker_reserve, remap_arg(mark, remap)}
    [i | remap(is, remap)]
  end

  defp remap([{:swap, reg1, reg2} | is], remap) do
    i = {:swap, remap_arg(reg1, remap),
           remap_arg(reg2, remap)}
    [i | remap(is, remap)]
  end

  defp remap([{:test, name, fail, ss} | is], remap) do
    i = {:test, name, fail, remap_args(ss, remap)}
    [i | remap(is, remap)]
  end

  defp remap([{:test, name, fail, live, ss, dst} | is],
            remap) do
    i = {:test, name, fail, live, remap_args(ss, remap),
           remap_arg(dst, remap)}
    [i | remap(is, remap)]
  end

  defp remap([:return | _] = is, _) do
    is
  end

  defp remap([{:line, _} = i | is], remap) do
    [i | remap(is, remap)]
  end

  defp remap_block([{:set, [{:x, _}] = ds, ss0, info} | is],
            remap) do
    ss = remap_args(ss0, remap)
    [{:set, ds, ss, info} | remap_block(is, remap)]
  end

  defp remap_block([{:set, ds0, ss0, info} | is], remap) do
    ds = remap_args(ds0, remap)
    ss = remap_args(ss0, remap)
    [{:set, ds, ss, info} | remap_block(is, remap)]
  end

  defp remap_block([], _) do
    []
  end

  defp remap_args(args, {trim, map}) do
    for arg <- args do
      remap_arg(arg, trim, map)
    end
  end

  defp remap_arg(arg, {trim, map}) do
    remap_arg(arg, trim, map)
  end

  defp remap_arg(arg, trim, map) do
    case (arg) do
      {:y, y} when y < trim ->
        {:y, :erlang.map_get(y, map)}
      {:y, y} ->
        {:y, y - trim}
      r_tr(r: {:y, y}, t: type) when y < trim ->
        r_tr(r: {:y, :erlang.map_get(y, map)}, t: type)
      r_tr(r: {:y, y}, t: type) ->
        r_tr(r: {:y, y - trim}, t: type)
      other ->
        other
    end
  end

  defp safe_labels([{:label, l} | is], acc) do
    case (is_safe_label(is)) do
      true ->
        safe_labels(is, [l | acc])
      false ->
        safe_labels(is, acc)
    end
  end

  defp safe_labels([_ | is], acc) do
    safe_labels(is, acc)
  end

  defp safe_labels([], acc) do
    :sets.from_list(acc, [{:version, 2}])
  end

  defp is_safe_label([{:"%", _} | is]) do
    is_safe_label(is)
  end

  defp is_safe_label([{:line, _} | is]) do
    is_safe_label(is)
  end

  defp is_safe_label([{:badmatch, {tag, _}} | _]) do
    tag !== :y
  end

  defp is_safe_label([{:case_end, {tag, _}} | _]) do
    tag !== :y
  end

  defp is_safe_label([{:try_case_end, {tag, _}} | _]) do
    tag !== :y
  end

  defp is_safe_label([:if_end | _]) do
    true
  end

  defp is_safe_label([{:badrecord, {tag, _}} | _]) do
    tag !== :y
  end

  defp is_safe_label([{:block, bl} | is]) do
    is_safe_label_block(bl) and is_safe_label(is)
  end

  defp is_safe_label([{:call_ext, _, {:extfunc, m, f, a}} | _]) do
    :erl_bifs.is_exit_bif(m, f, a)
  end

  defp is_safe_label(_) do
    false
  end

  defp is_safe_label_block([{:set, ds, ss, _} | is]) do
    isYreg = fn r_tr(r: {:y, _}) ->
                  true
                {:y, _} ->
                  true
                _ ->
                  false
             end
    not
    (any(isYreg, ss) or any(isYreg,
                              ds)) and is_safe_label_block(is)
  end

  defp is_safe_label_block([]) do
    true
  end

  defp frame_layout(n, killed, {u, _}) do
    dead0 = (for r <- seq(0, n - 1) do
               {:y, r}
             end)
    dead = :ordsets.subtract(dead0,
                               :ordsets.union(u, killed))
    is = [for r <- u do
            {r, {:live, r}}
          end,
              for r <- dead do
                {r, {:dead, r}}
              end,
                  for r <- killed do
                    {r, {:kill, r}}
                  end]
    for {_, i} <- :lists.merge(is) do
      i
    end
  end

  defp usage(is0, st) do
    is = usage_1(is0, [])
    do_usage(is, st)
  end

  defp usage_1([{:label, _} | _], acc) do
    acc
  end

  defp usage_1([i | is], acc) do
    usage_1(is, [i | acc])
  end

  defp usage_1([], acc) do
    acc
  end

  defp do_usage(is0, r_st(safe: safe)) do
    case (is0) do
      [:return, {:deallocate, n} | is] ->
        regs = []
        case (do_usage(is, safe, regs, [], [])) do
          :none ->
            :none
          us ->
            {n, us}
        end
      _ ->
        :none
    end
  end

  defp do_usage([{:"%", _} | is], safe, regs, ns, acc) do
    u = {regs, ns}
    do_usage(is, safe, regs, ns, [u | acc])
  end

  defp do_usage([{:apply, _} | is], safe, regs, ns, acc) do
    u = {regs, ns}
    do_usage(is, safe, regs, ns, [u | acc])
  end

  defp do_usage([{:block, blk} | is], safe, regs0, ns0, acc) do
    {regs, ns} = (u = do_usage_blk(blk, regs0, ns0))
    do_usage(is, safe, regs, ns, [u | acc])
  end

  defp do_usage([{:bs_create_bin, fail, _, _, _, dst,
              {:list, args}} |
               is],
            safe, regs0, ns0, acc) do
    case (is_safe_branch(fail, safe)) do
      true ->
        regs1 = :ordsets.del_element(dst, regs0)
        regs = :ordsets.union(regs1, yregs(args))
        ns = :ordsets.union(yregs([dst]), ns0)
        u = {regs, ns}
        do_usage(is, safe, regs, ns, [u | acc])
      false ->
        :none
    end
  end

  defp do_usage([{:bs_get_tail, src, dst, _} | is], safe, regs0,
            ns0, acc) do
    regs1 = :ordsets.del_element(dst, regs0)
    regs = :ordsets.union(regs1, yregs([src]))
    ns = :ordsets.union(yregs([dst]), ns0)
    u = {regs, ns}
    do_usage(is, safe, regs, ns, [u | acc])
  end

  defp do_usage([{:bs_set_position, src1, src2} | is], safe,
            regs0, ns, acc) do
    regs = :ordsets.union(regs0, yregs([src1, src2]))
    u = {regs, ns}
    do_usage(is, safe, regs, ns, [u | acc])
  end

  defp do_usage([{:bs_start_match4, fail, _Live, src, dst} |
               is],
            safe, regs0, ns, acc) do
    case (fail === {:atom, :no_fail} or fail === {:atom,
                                                    :resume} or is_safe_branch(fail,
                                                                                 safe)) do
      true ->
        regs = :ordsets.union(regs0, yregs([src, dst]))
        u = {regs, ns}
        do_usage(is, safe, regs, ns, [u | acc])
      false ->
        :none
    end
  end

  defp do_usage([{:call, _, _} | is], safe, regs, ns, acc) do
    u = {regs, ns}
    do_usage(is, safe, regs, ns, [u | acc])
  end

  defp do_usage([{:call_ext, _, _} | is], safe, regs, ns,
            acc) do
    u = {regs, ns}
    do_usage(is, safe, regs, ns, [u | acc])
  end

  defp do_usage([{:call_fun, _} | is], safe, regs, ns, acc) do
    u = {regs, ns}
    do_usage(is, safe, regs, ns, [u | acc])
  end

  defp do_usage([{:call_fun2, _, _, ss} | is], safe, regs0, ns,
            acc) do
    regs = :ordsets.union(regs0, yregs([ss]))
    u = {regs, ns}
    do_usage(is, safe, regs, ns, [u | acc])
  end

  defp do_usage([{:bif, _, fail, ss, dst} | is], safe, regs0,
            ns0, acc) do
    case (is_safe_branch(fail, safe)) do
      true ->
        regs1 = :ordsets.del_element(dst, regs0)
        regs = :ordsets.union(regs1, yregs(ss))
        ns = :ordsets.union(yregs([dst]), ns0)
        u = {regs, ns}
        do_usage(is, safe, regs, ns, [u | acc])
      false ->
        :none
    end
  end

  defp do_usage([{:gc_bif, _, fail, _, ss, dst} | is], safe,
            regs0, ns0, acc) do
    case (is_safe_branch(fail, safe)) do
      true ->
        regs1 = :ordsets.del_element(dst, regs0)
        regs = :ordsets.union(regs1, yregs(ss))
        ns = :ordsets.union(yregs([dst]), ns0)
        u = {regs, ns}
        do_usage(is, safe, regs, ns, [u | acc])
      false ->
        :none
    end
  end

  defp do_usage([{:get_map_elements, fail, s, {:list, list}} |
               is],
            safe, regs0, ns0, acc) do
    case (is_safe_branch(fail, safe)) do
      true ->
        {ss, ds1} = :beam_utils.split_even(list)
        ds = yregs(ds1)
        regs1 = :ordsets.subtract(regs0, ds)
        regs = :ordsets.union(regs1, yregs([s | ss]))
        ns = :ordsets.union(ns0, ds)
        u = {regs, ns}
        do_usage(is, safe, regs, ns, [u | acc])
      false ->
        :none
    end
  end

  defp do_usage([{:init_yregs, {:list, ds}} | is], safe, regs0,
            ns0, acc) do
    regs = :ordsets.subtract(regs0, ds)
    ns = :ordsets.union(ns0, ds)
    u = {regs, ns}
    do_usage(is, safe, regs, ns, [u | acc])
  end

  defp do_usage([{:make_fun3, _, _, _, dst, {:list, ss}} | is],
            safe, regs0, ns0, acc) do
    regs1 = :ordsets.del_element(dst, regs0)
    regs = :ordsets.union(regs1, yregs(ss))
    ns = :ordsets.union(yregs([dst]), ns0)
    u = {regs, ns}
    do_usage(is, safe, regs, ns, [u | acc])
  end

  defp do_usage([{:update_record, _, _, src, dst, {:list, ss}} |
               is],
            safe, regs0, ns0, acc) do
    regs1 = :ordsets.del_element(dst, regs0)
    regs = :ordsets.union(regs1, yregs([src | ss]))
    ns = :ordsets.union(yregs([dst]), ns0)
    u = {regs, ns}
    do_usage(is, safe, regs, ns, [u | acc])
  end

  defp do_usage([{:line, _} | is], safe, regs, ns, acc) do
    u = {regs, ns}
    do_usage(is, safe, regs, ns, [u | acc])
  end

  defp do_usage([{:recv_marker_clear, src} | is], safe, regs0,
            ns, acc) do
    regs = :ordsets.union(regs0, yregs([src]))
    u = {regs, ns}
    do_usage(is, safe, regs, ns, [u | acc])
  end

  defp do_usage([{:recv_marker_reserve, src} | is], safe, regs0,
            ns, acc) do
    regs = :ordsets.union(regs0, yregs([src]))
    u = {regs, ns}
    do_usage(is, safe, regs, ns, [u | acc])
  end

  defp do_usage([{:swap, r1, r2} | is], safe, regs0, ns0,
            acc) do
    ds = yregs([r1, r2])
    regs = :ordsets.union(regs0, ds)
    ns = :ordsets.union(ns0, ds)
    u = {regs, ns}
    do_usage(is, safe, regs, ns, [u | acc])
  end

  defp do_usage([{:test, _, fail, ss} | is], safe, regs0, ns,
            acc) do
    case (is_safe_branch(fail, safe)) do
      true ->
        regs = :ordsets.union(regs0, yregs(ss))
        u = {regs, ns}
        do_usage(is, safe, regs, ns, [u | acc])
      false ->
        :none
    end
  end

  defp do_usage([{:test, _, fail, _, ss, dst} | is], safe,
            regs0, ns0, acc) do
    case (is_safe_branch(fail, safe)) do
      true ->
        regs1 = :ordsets.del_element(dst, regs0)
        regs = :ordsets.union(regs1, yregs(ss))
        ns = :ordsets.union(yregs([dst]), ns0)
        u = {regs, ns}
        do_usage(is, safe, regs, ns, [u | acc])
      false ->
        :none
    end
  end

  defp do_usage([_I | _], _, _, _, _) do
    :none
  end

  defp do_usage([], _Safe, _Regs, _Ns, acc) do
    acc
  end

  defp do_usage_blk([{:set, ds0, ss, _} | is], regs0, ns0) do
    ds = yregs(ds0)
    {regs1, ns1} = do_usage_blk(is, regs0, ns0)
    regs2 = :ordsets.subtract(regs1, ds)
    regs = :ordsets.union(regs2, yregs(ss))
    ns = :ordsets.union(ns1, ds)
    {regs, ns}
  end

  defp do_usage_blk([], regs, ns) do
    {regs, ns}
  end

  defp is_safe_branch({:f, 0}, _Safe) do
    true
  end

  defp is_safe_branch({:f, l}, safe) do
    :sets.is_element(l, safe)
  end

  defp yregs(rs) do
    :ordsets.from_list(yregs_1(rs))
  end

  defp yregs_1([{:y, _} = y | rs]) do
    [y | yregs_1(rs)]
  end

  defp yregs_1([{:tr, {:y, _} = y, _} | rs]) do
    [y | yregs_1(rs)]
  end

  defp yregs_1([_ | rs]) do
    yregs_1(rs)
  end

  defp yregs_1([]) do
    []
  end

end