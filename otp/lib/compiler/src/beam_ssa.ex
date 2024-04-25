defmodule :m_beam_ssa do
  use Bitwise
  import :lists, only: [foldl: 3, mapfoldl: 3, member: 2, reverse: 1, sort: 1]
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

  def add_anno(key, val, r_b_function(anno: anno) = bl) do
    r_b_function(bl, anno: Map.put(anno, key, val))
  end

  def add_anno(key, val, r_b_blk(anno: anno) = bl) do
    r_b_blk(bl, anno: Map.put(anno, key, val))
  end

  def add_anno(key, val, r_b_set(anno: anno) = bl) do
    r_b_set(bl, anno: Map.put(anno, key, val))
  end

  def add_anno(key, val, r_b_br(anno: anno) = bl) do
    r_b_br(bl, anno: Map.put(anno, key, val))
  end

  def add_anno(key, val, r_b_ret(anno: anno) = bl) do
    r_b_ret(bl, anno: Map.put(anno, key, val))
  end

  def add_anno(key, val, r_b_switch(anno: anno) = bl) do
    r_b_switch(bl, anno: Map.put(anno, key, val))
  end

  def get_anno(key, construct) do
    :erlang.map_get(key, get_anno(construct))
  end

  def get_anno(key, construct, default) do
    :maps.get(key, get_anno(construct), default)
  end

  defp get_anno(r_b_function(anno: anno)) do
    anno
  end

  defp get_anno(r_b_blk(anno: anno)) do
    anno
  end

  defp get_anno(r_b_set(anno: anno)) do
    anno
  end

  defp get_anno(r_b_br(anno: anno)) do
    anno
  end

  defp get_anno(r_b_ret(anno: anno)) do
    anno
  end

  defp get_anno(r_b_switch(anno: anno)) do
    anno
  end

  def clobbers_xregs(r_b_set(op: op)) do
    case op do
      :bs_init_writable ->
        true

      :build_stacktrace ->
        true

      :call ->
        true

      :landingpad ->
        true

      :old_make_fun ->
        true

      :peek_message ->
        true

      :raw_raise ->
        true

      :wait_timeout ->
        true

      _ ->
        false
    end
  end

  def no_side_effect(r_b_set(op: op)) do
    case op do
      {:bif, _} ->
        true

      {:float, :get} ->
        true

      :bs_create_bin ->
        true

      :bs_init_writable ->
        true

      :bs_extract ->
        true

      :bs_match ->
        true

      :bs_start_match ->
        true

      :bs_test_tail ->
        true

      :bs_get_tail ->
        true

      :build_stacktrace ->
        true

      :extract ->
        true

      :get_hd ->
        true

      :get_tl ->
        true

      :get_map_element ->
        true

      :get_tuple_element ->
        true

      :has_map_field ->
        true

      :is_nonempty_list ->
        true

      :is_tagged_tuple ->
        true

      :make_fun ->
        true

      :match_fail ->
        true

      :phi ->
        true

      :put_map ->
        true

      :put_list ->
        true

      :put_tuple ->
        true

      :raw_raise ->
        true

      {:succeeded, :guard} ->
        true

      :update_record ->
        true

      :update_tuple ->
        true

      _ ->
        false
    end
  end

  def insert_on_edges(insertions, blocks, count) when is_map(blocks) do
    insert_on_edges_1(sort(insertions), blocks, count)
  end

  defp insert_on_edges_1([{_, 1, _} | _], _, _) do
    :erlang.error(:unsafe_edge)
  end

  defp insert_on_edges_1([{from, to, isA}, {from, to, isB} | insertions], blocks, count) do
    insert_on_edges_1([{from, to, isA ++ isB} | insertions], blocks, count)
  end

  defp insert_on_edges_1([{from, to, is} | insertions], blocks0, count0) do
    r_b_blk(last: fromLast0) =
      fromBlk0 =
      :erlang.map_get(
        from,
        blocks0
      )

    r_b_blk(is: toIs0) = toBlk0 = :erlang.map_get(to, blocks0)
    edgeLbl = count0
    count = count0 + 1
    fromLast = insert_on_edges_reroute(fromLast0, to, edgeLbl)
    fromBlk = r_b_blk(fromBlk0, last: fromLast)
    {edgeIs0, toIs} = insert_on_edges_is(toIs0, from, edgeLbl, [])
    edgeIs = edgeIs0 ++ is
    br = r_b_br(bool: r_b_literal(val: true), succ: to, fail: to)
    edgeBlk = r_b_blk(is: edgeIs, last: br)
    toBlk = r_b_blk(toBlk0, is: toIs)
    blocks1 = Map.put(%{blocks0 | from => fromBlk, to => toBlk}, edgeLbl, edgeBlk)
    blocks = update_phi_labels([to], from, edgeLbl, blocks1)
    insert_on_edges_1(insertions, blocks, count)
  end

  defp insert_on_edges_1([], blocks, count) do
    {blocks, count}
  end

  defp insert_on_edges_reroute(r_b_switch(fail: fail0, list: list0) = sw, old, new) do
    fail = rename_label(fail0, old, new)

    list =
      for {value, dst} <- list0 do
        {value, rename_label(dst, old, new)}
      end

    r_b_switch(sw, fail: fail, list: list)
  end

  defp insert_on_edges_reroute(r_b_br(succ: succ0, fail: fail0) = br, old, new) do
    succ = rename_label(succ0, old, new)
    fail = rename_label(fail0, old, new)
    r_b_br(br, succ: succ, fail: fail)
  end

  defp insert_on_edges_is([r_b_set(op: :bs_extract) = i | is], fromLbl, edgeLbl, edgeIs) do
    insert_on_edges_is(is, fromLbl, edgeLbl, [i | edgeIs])
  end

  defp insert_on_edges_is(toIs0, fromLbl, edgeLbl, edgeIs) do
    case toIs0 do
      [r_b_set(op: :landingpad) | _] ->
        :erlang.error(:unsafe_edge)

      _ ->
        toIs = update_phi_labels_is(toIs0, fromLbl, edgeLbl)
        {reverse(edgeIs), toIs}
    end
  end

  def is_loop_header(r_b_set(op: :wait_timeout, args: [args])) do
    case args do
      r_b_literal(val: 0) ->
        false

      _ ->
        true
    end
  end

  def is_loop_header(r_b_set(op: op)) do
    op === :peek_message
  end

  def successors(r_b_blk(last: terminator)) do
    case terminator do
      r_b_br(bool: r_b_literal(val: true), succ: succ) ->
        [succ]

      r_b_br(bool: r_b_literal(val: false), fail: fail) ->
        [fail]

      r_b_br(succ: succ, fail: fail) ->
        [fail, succ]

      r_b_switch(fail: fail, list: list) ->
        [
          fail
          | for {_, l} <- list do
              l
            end
        ]

      r_b_ret() ->
        []
    end
  end

  def normalize(r_b_set(anno: anno0, op: {:bif, bif}, args: args) = set) do
    case {is_commutative(bif), args} do
      {true, [r_b_literal() = lit, r_b_var() = var]} ->
        anno =
          case anno0 do
            %{arg_types: argTypes0} ->
              case argTypes0 do
                %{1 => type} ->
                  Map.put(anno0, :arg_types, %{0 => type})

                %{} ->
                  Map.put(anno0, :arg_types, %{})
              end

            %{} ->
              anno0
          end

        r_b_set(set, anno: anno, args: [var, lit])

      {_, _} ->
        set
    end
  end

  def normalize(r_b_set() = set) do
    set
  end

  def normalize(r_b_br() = br) do
    case br do
      r_b_br(bool: bool, succ: same, fail: same) ->
        case bool do
          r_b_literal(val: true) ->
            br

          _ ->
            r_b_br(br, bool: r_b_literal(val: true))
        end

      r_b_br(bool: r_b_literal(val: true), succ: succ) ->
        r_b_br(br, fail: succ)

      r_b_br(bool: r_b_literal(val: false), fail: fail) ->
        r_b_br(br, bool: r_b_literal(val: true), succ: fail)

      r_b_br() ->
        br
    end
  end

  def normalize(r_b_switch(arg: arg, fail: fail, list: list) = sw) do
    case arg do
      r_b_literal() ->
        normalize_switch(arg, list, fail)

      r_b_var() when list === [] ->
        r_b_br(bool: r_b_literal(val: true), succ: fail, fail: fail)

      r_b_var() ->
        r_b_switch(sw, list: sort(list))
    end
  end

  def normalize(r_b_ret() = ret) do
    ret
  end

  defp normalize_switch(val, [{val, l} | _], _Fail) do
    r_b_br(bool: r_b_literal(val: true), succ: l, fail: l)
  end

  defp normalize_switch(val, [_ | t], fail) do
    normalize_switch(val, t, fail)
  end

  defp normalize_switch(_Val, [], fail) do
    r_b_br(bool: r_b_literal(val: true), succ: fail, fail: fail)
  end

  def successors(l, blocks) do
    successors(:erlang.map_get(l, blocks))
  end

  def def(ls, blocks) when is_map(blocks) do
    blks =
      for l <- ls do
        :erlang.map_get(l, blocks)
      end

    def_1(blks, [])
  end

  def def_unused(ls, unused, blocks) when is_map(blocks) do
    blks =
      for l <- ls do
        :erlang.map_get(l, blocks)
      end

    preds = :sets.from_list(ls, [{:version, 2}])
    def_unused_1(blks, preds, [], unused)
  end

  def dominators(labels, blocks) when is_map(blocks) do
    preds = predecessors(blocks)
    dominators_from_predecessors(labels, preds)
  end

  def dominators_from_predecessors(top0, preds) when is_map(preds) do
    df = :maps.from_list(number(top0, 0))

    [{0, []} | top] =
      for l <- top0 do
        {l, :erlang.map_get(l, preds)}
      end

    acc = %{0 => [0]}
    {dominators_1(top, df, acc), df}
  end

  def common_dominators(ls, dom, numbering) when is_map(dom) do
    doms =
      for l <- ls do
        :erlang.map_get(l, dom)
      end

    dom_intersection(doms, numbering)
  end

  def fold_instrs(fun, labels, acc0, blocks) when is_map(blocks) do
    fold_instrs_1(labels, fun, blocks, acc0)
  end

  def mapfold_blocks(fun, labels, acc, blocks) when is_map(blocks) do
    foldl(
      fn lbl, a ->
        mapfold_blocks_1(fun, lbl, a)
      end,
      {blocks, acc},
      labels
    )
  end

  defp mapfold_blocks_1(fun, lbl, {blocks0, acc0}) do
    block0 = :erlang.map_get(lbl, blocks0)
    {block, acc} = fun.(lbl, block0, acc0)
    blocks = %{blocks0 | lbl => block}
    {blocks, acc}
  end

  def mapfold_instrs(fun, labels, acc0, blocks) when is_map(blocks) do
    mapfold_instrs_1(labels, fun, blocks, acc0)
  end

  def flatmapfold_instrs(fun, labels, acc0, blocks) when is_map(blocks) do
    flatmapfold_instrs_1(labels, fun, blocks, acc0)
  end

  def fold_blocks(fun, labels, acc0, blocks) when is_map(blocks) do
    fold_blocks_1(labels, fun, blocks, acc0)
  end

  def linearize(blocks) when is_map(blocks) do
    seen = :sets.new([{:version, 2}])
    {linear0, _} = linearize_1([0], blocks, seen, [])
    linear = fix_phis(linear0, %{})
    linear
  end

  def rpo(blocks) do
    rpo([0], blocks)
  end

  def rpo(from, blocks) when is_map(blocks) do
    seen = :sets.new([{:version, 2}])
    {ls, _} = rpo_1(from, blocks, seen, [])
    ls
  end

  def between(from, to, preds, blocks)
      when is_map(preds) and
             is_map(blocks) do
    filter = between_make_filter([to], preds, :sets.from_list([from], [{:version, 2}]))
    {paths, _} = between_rpo([from], blocks, filter, [])
    paths
  end

  def rename_vars(rename, labels, blocks) when is_list(rename) do
    rename_vars(:maps.from_list(rename), labels, blocks)
  end

  def rename_vars(rename, labels, blocks)
      when is_map(rename) and
             is_map(blocks) do
    preds = :sets.from_list(labels, [{:version, 2}])

    f = fn
      r_b_set(op: :phi, args: args0) = set ->
        args = rename_phi_vars(args0, preds, rename)
        normalize(r_b_set(set, args: args))

      r_b_set(args: args0) = set ->
        args =
          for a <- args0 do
            rename_var(a, rename)
          end

        normalize(r_b_set(set, args: args))

      r_b_switch(arg: bool) = sw ->
        normalize(r_b_switch(sw, arg: rename_var(bool, rename)))

      r_b_br(bool: bool) = br ->
        normalize(r_b_br(br, bool: rename_var(bool, rename)))

      r_b_ret(arg: arg) = ret ->
        normalize(r_b_ret(ret, arg: rename_var(arg, rename)))
    end

    map_instrs_1(labels, f, blocks)
  end

  def split_blocks(ls, p, blocks, count) when is_map(blocks) do
    split_blocks_1(ls, p, blocks, count)
  end

  def trim_unreachable(blocks) when is_map(blocks) do
    :maps.from_list(linearize(blocks))
  end

  def trim_unreachable([_ | _] = blocks) do
    trim_unreachable_1(
      blocks,
      :sets.from_list([0], [{:version, 2}])
    )
  end

  def used(r_b_blk(is: is, last: last)) do
    used_1([last | is], :ordsets.new())
  end

  def used(r_b_br(bool: r_b_var() = v)) do
    [v]
  end

  def used(r_b_ret(arg: r_b_var() = v)) do
    [v]
  end

  def used(r_b_set(op: :phi, args: args)) do
    :ordsets.from_list(
      for {r_b_var() = v, _} <- args do
        v
      end
    )
  end

  def used(r_b_set(args: args)) do
    :ordsets.from_list(used_args(args))
  end

  def used(r_b_switch(arg: r_b_var() = v)) do
    [v]
  end

  def used(_) do
    []
  end

  def definitions(labels, blocks) do
    fold_instrs(
      fn
        r_b_set(dst: var) = i, acc ->
          Map.put(acc, var, i)

        _Terminator, acc ->
          acc
      end,
      labels,
      %{},
      blocks
    )
  end

  def uses(labels, blocks) when is_map(blocks) do
    fold_blocks(&fold_uses_block/3, labels, %{}, blocks)
  end

  defp fold_uses_block(lbl, r_b_blk(is: is, last: last), useMap0) do
    f = fn i, useMap ->
      foldl(
        fn var, acc ->
          uses0 = :maps.get(var, acc, [])
          uses = [{lbl, i} | uses0]
          :maps.put(var, uses, acc)
        end,
        useMap,
        used(i)
      )
    end

    f.(last, foldl(f, useMap0, is))
  end

  def merge_blocks(labels, blocks) do
    preds = predecessors(blocks)
    merge_blocks_1(labels, preds, blocks)
  end

  defp is_commutative(:and) do
    true
  end

  defp is_commutative(:or) do
    true
  end

  defp is_commutative(:xor) do
    true
  end

  defp is_commutative(:band) do
    true
  end

  defp is_commutative(:bor) do
    true
  end

  defp is_commutative(:bxor) do
    true
  end

  defp is_commutative(:+) do
    true
  end

  defp is_commutative(:*) do
    true
  end

  defp is_commutative(:"=:=") do
    true
  end

  defp is_commutative(:==) do
    true
  end

  defp is_commutative(:"=/=") do
    true
  end

  defp is_commutative(:"/=") do
    true
  end

  defp is_commutative(_) do
    false
  end

  defp def_unused_1([r_b_blk(is: is, last: last) | bs], preds, def0, unused0) do
    unused1 = :ordsets.subtract(unused0, used(last))
    {def__, unused} = def_unused_is(is, preds, def0, unused1)
    def_unused_1(bs, preds, def__, unused)
  end

  defp def_unused_1([], _Preds, def__, unused) do
    {:ordsets.from_list(def__), unused}
  end

  defp def_unused_is([r_b_set(op: :phi, dst: dst, args: args) | is], preds, def0, unused0) do
    def__ = [dst | def0]

    unused1 =
      for {r_b_var() = v, l} <- args,
          :sets.is_element(l, preds) do
        v
      end

    unused =
      :ordsets.subtract(
        unused0,
        :ordsets.from_list(unused1)
      )

    def_unused_is(is, preds, def__, unused)
  end

  defp def_unused_is([r_b_set(dst: dst) = i | is], preds, def0, unused0) do
    def__ = [dst | def0]
    unused = :ordsets.subtract(unused0, used(i))
    def_unused_is(is, preds, def__, unused)
  end

  defp def_unused_is([], _Preds, def__, unused) do
    {def__, unused}
  end

  defp def_1([r_b_blk(is: is) | bs], def0) do
    def__ = def_is(is, def0)
    def_1(bs, def__)
  end

  defp def_1([], def__) do
    :ordsets.from_list(def__)
  end

  defp def_is([r_b_set(dst: dst) | is], def__) do
    def_is(is, [dst | def__])
  end

  defp def_is([], def__) do
    def__
  end

  defp dominators_1([{l, preds} | ls], df, doms) do
    domPreds =
      for p <- preds,
          :erlang.is_map_key(p, doms) do
        :erlang.map_get(p, doms)
      end

    dom = [l | dom_intersection(domPreds, df)]
    dominators_1(ls, df, Map.put(doms, l, dom))
  end

  defp dominators_1([], _Df, doms) do
    doms
  end

  defp dom_intersection([s], _Df) do
    s
  end

  defp dom_intersection([s | ss], df) do
    dom_intersection(s, ss, df)
  end

  defp dom_intersection([0] = s, [_ | _], _Df) do
    s
  end

  defp dom_intersection(s1, [s2 | ss], df) do
    dom_intersection(dom_intersection_1(s1, s2, df), ss, df)
  end

  defp dom_intersection(s, [], _Df) do
    s
  end

  defp dom_intersection_1([e1 | es1] = set1, [e2 | es2] = set2, df) do
    %{^e1 => df1, ^e2 => df2} = df

    cond do
      df1 > df2 ->
        dom_intersection_2(es1, set2, df, df2)

      df2 > df1 ->
        dom_intersection_2(es2, set1, df, df1)

      true ->
        set1
    end
  end

  defp dom_intersection_2([e1 | es1] = set1, [_ | es2] = set2, df, df2) do
    %{^e1 => df1} = df

    cond do
      df1 > df2 ->
        dom_intersection_2(es1, set2, df, df2)

      df2 > df1 ->
        dom_intersection_2(es2, set1, df, df1)

      true ->
        set1
    end
  end

  defp number([l | ls], n) do
    [{l, n} | number(ls, n + 1)]
  end

  defp number([], _) do
    []
  end

  defp fold_blocks_1([l | ls], fun, blocks, acc0) do
    block = :erlang.map_get(l, blocks)
    acc = fun.(l, block, acc0)
    fold_blocks_1(ls, fun, blocks, acc)
  end

  defp fold_blocks_1([], _, _, acc) do
    acc
  end

  defp fold_instrs_1([l | ls], fun, blocks, acc0) do
    r_b_blk(is: is, last: last) = :erlang.map_get(l, blocks)
    acc1 = foldl(fun, acc0, is)
    acc = fun.(last, acc1)
    fold_instrs_1(ls, fun, blocks, acc)
  end

  defp fold_instrs_1([], _, _, acc) do
    acc
  end

  defp mapfold_instrs_1([l | ls], fun, blocks0, acc0) do
    r_b_blk(is: is0, last: last0) =
      block0 =
      :erlang.map_get(
        l,
        blocks0
      )

    {is, acc1} = mapfoldl(fun, acc0, is0)
    {last, acc} = fun.(last0, acc1)
    block = r_b_blk(block0, is: is, last: last)
    blocks = %{blocks0 | l => block}
    mapfold_instrs_1(ls, fun, blocks, acc)
  end

  defp mapfold_instrs_1([], _, blocks, acc) do
    {blocks, acc}
  end

  defp flatmapfold_instrs_1([l | ls], fun, blocks0, acc0) do
    r_b_blk(is: is0, last: last0) =
      block0 =
      :erlang.map_get(
        l,
        blocks0
      )

    {is, acc1} = flatmapfoldl(fun, acc0, is0)
    {[last], acc} = fun.(last0, acc1)
    block = r_b_blk(block0, is: is, last: last)
    blocks = %{blocks0 | l => block}
    flatmapfold_instrs_1(ls, fun, blocks, acc)
  end

  defp flatmapfold_instrs_1([], _, blocks, acc) do
    {blocks, acc}
  end

  defp linearize_1([l | ls], blocks, seen0, acc0) do
    case :sets.is_element(l, seen0) do
      true ->
        linearize_1(ls, blocks, seen0, acc0)

      false ->
        seen1 = :sets.add_element(l, seen0)
        block = :erlang.map_get(l, blocks)
        successors = successors(block)
        {acc, seen} = linearize_1(successors, blocks, seen1, acc0)
        linearize_1(ls, blocks, seen, [{l, block} | acc])
    end
  end

  defp linearize_1([], _, seen, acc) do
    {acc, seen}
  end

  defp fix_phis([{l, blk0} | bs], s) do
    blk =
      case blk0 do
        r_b_blk(is: [r_b_set(op: :phi) | _] = is0) ->
          is = fix_phis_1(is0, l, s)
          r_b_blk(blk0, is: is)

        r_b_blk() ->
          blk0
      end

    successors = successors(blk)
    [{l, blk} | fix_phis(bs, Map.put(s, l, successors))]
  end

  defp fix_phis([], _) do
    []
  end

  defp fix_phis_1([r_b_set(op: :phi, args: args0) = i | is], l, s) do
    args =
      for {val, pred} <- args0,
          is_successor(l, pred, s) do
        {val, pred}
      end

    [r_b_set(i, args: args) | fix_phis_1(is, l, s)]
  end

  defp fix_phis_1(is, _, _) do
    is
  end

  defp is_successor(l, pred, s) do
    case s do
      %{^pred => successors} ->
        member(l, successors)

      %{} ->
        false
    end
  end

  defp trim_unreachable_1([{l, blk0} | bs], seen0) do
    blk = trim_phis(blk0, seen0)

    case :sets.is_element(l, seen0) do
      false ->
        trim_unreachable_1(bs, seen0)

      true ->
        case successors(blk) do
          [] ->
            [{l, blk} | trim_unreachable_1(bs, seen0)]

          [next] ->
            seen = :sets.add_element(next, seen0)
            [{l, blk} | trim_unreachable_1(bs, seen)]

          [_ | _] = successors ->
            seen =
              :sets.union(
                seen0,
                :sets.from_list(successors, [{:version, 2}])
              )

            [{l, blk} | trim_unreachable_1(bs, seen)]
        end
    end
  end

  defp trim_unreachable_1([], _) do
    []
  end

  defp trim_phis(r_b_blk(is: [r_b_set(op: :phi) | _] = is0) = blk, seen) do
    is = trim_phis_1(is0, seen)
    r_b_blk(blk, is: is)
  end

  defp trim_phis(blk, _Seen) do
    blk
  end

  defp trim_phis_1([r_b_set(op: :phi, args: args0) = i | is], seen) do
    args =
      for {_, l} = p <- args0,
          :sets.is_element(l, seen) do
        p
      end

    [r_b_set(i, args: args) | trim_phis_1(is, seen)]
  end

  defp trim_phis_1(is, _Seen) do
    is
  end

  defp between_make_filter([l | ls], preds, acc0) do
    case :sets.is_element(l, acc0) do
      true ->
        between_make_filter(ls, preds, acc0)

      false ->
        next = :erlang.map_get(l, preds)
        acc1 = :sets.add_element(l, acc0)
        acc = between_make_filter(next, preds, acc1)
        between_make_filter(ls, preds, acc)
    end
  end

  defp between_make_filter([], _Preds, acc) do
    acc
  end

  defp between_rpo([l | ls], blocks, filter0, acc0) do
    case :sets.is_element(l, filter0) do
      true ->
        block = :erlang.map_get(l, blocks)
        filter1 = :sets.del_element(l, filter0)
        successors = successors(block)
        {acc, filter} = between_rpo(successors, blocks, filter1, acc0)
        between_rpo(ls, blocks, filter, [l | acc])

      false ->
        between_rpo(ls, blocks, filter0, acc0)
    end
  end

  defp between_rpo([], _, filter, acc) do
    {acc, filter}
  end

  defp rpo_1([l | ls], blocks, seen0, acc0) do
    case :sets.is_element(l, seen0) do
      true ->
        rpo_1(ls, blocks, seen0, acc0)

      false ->
        block = :erlang.map_get(l, blocks)
        seen1 = :sets.add_element(l, seen0)
        successors = successors(block)
        {acc, seen} = rpo_1(successors, blocks, seen1, acc0)
        rpo_1(ls, blocks, seen, [l | acc])
    end
  end

  defp rpo_1([], _, seen, acc) do
    {acc, seen}
  end

  defp rename_var(r_b_var() = old, rename) do
    case rename do
      %{^old => new} ->
        new

      %{} ->
        old
    end
  end

  defp rename_var(r_b_remote(mod: mod0, name: name0) = remote, rename) do
    mod = rename_var(mod0, rename)
    name = rename_var(name0, rename)
    r_b_remote(remote, mod: mod, name: name)
  end

  defp rename_var(old, _) do
    old
  end

  defp rename_phi_vars([{var, l} | as], preds, ren) do
    case :sets.is_element(l, preds) do
      true ->
        [{rename_var(var, ren), l} | rename_phi_vars(as, preds, ren)]

      false ->
        [{var, l} | rename_phi_vars(as, preds, ren)]
    end
  end

  defp rename_phi_vars([], _, _) do
    []
  end

  defp map_instrs_1([l | ls], fun, blocks0) do
    r_b_blk(is: is0, last: last0) =
      blk0 =
      :erlang.map_get(
        l,
        blocks0
      )

    is =
      for i <- is0 do
        fun.(i)
      end

    last = fun.(last0)
    blk = r_b_blk(blk0, is: is, last: last)
    blocks = %{blocks0 | l => blk}
    map_instrs_1(ls, fun, blocks)
  end

  defp map_instrs_1([], _, blocks) do
    blocks
  end

  defp flatmapfoldl(f, accu0, [hd | tail]) do
    {r, accu1} = f.(hd, accu0)
    {rs, accu2} = flatmapfoldl(f, accu1, tail)
    {r ++ rs, accu2}
  end

  defp flatmapfoldl(_, accu, []) do
    {[], accu}
  end

  defp split_blocks_1([l | ls], p, blocks0, count0) do
    r_b_blk(is: is0) = blk = :erlang.map_get(l, blocks0)

    case split_blocks_is(is0, p, []) do
      {:yes, bef, aft} ->
        newLbl = count0
        count = count0 + 1
        br = r_b_br(bool: r_b_literal(val: true), succ: newLbl, fail: newLbl)
        befBlk = r_b_blk(blk, is: bef, last: br)
        newBlk = r_b_blk(blk, is: aft)
        blocks1 = Map.put(%{blocks0 | l => befBlk}, newLbl, newBlk)
        successors = successors(newBlk)
        blocks = update_phi_labels(successors, l, newLbl, blocks1)
        split_blocks_1([newLbl | ls], p, blocks, count)

      :no ->
        split_blocks_1(ls, p, blocks0, count0)
    end
  end

  defp split_blocks_1([], _, blocks, count) do
    {blocks, count}
  end

  defp split_blocks_is([i | is], p, []) do
    split_blocks_is(is, p, [i])
  end

  defp split_blocks_is([i | is], p, acc) do
    case p.(i) do
      true ->
        {:yes, reverse(acc), [i | is]}

      false ->
        split_blocks_is(is, p, [i | acc])
    end
  end

  defp split_blocks_is([], _, _) do
    :no
  end

  defp update_phi_labels_is([r_b_set(op: :phi, args: args0) = i0 | is], old, new) do
    args =
      for {arg, lbl} <- args0 do
        {arg, rename_label(lbl, old, new)}
      end

    i = r_b_set(i0, args: args)
    [i | update_phi_labels_is(is, old, new)]
  end

  defp update_phi_labels_is(is, _, _) do
    is
  end

  defp rename_label(old, old, new) do
    new
  end

  defp rename_label(lbl, _Old, _New) do
    lbl
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

  defp used_1([h | t], used0) do
    used = :ordsets.union(used(h), used0)
    used_1(t, used)
  end

  defp used_1([], used) do
    used
  end

  defp merge_blocks_1([l | ls], preds0, blocks0) do
    case preds0 do
      %{^l => [p]} ->
        %{^p => blk0, ^l => blk1} = blocks0

        case is_merge_allowed(l, blk0, blk1) do
          true ->
            r_b_blk(is: is0) = blk0
            r_b_blk(is: is1) = blk1
            verify_merge_is(is1)
            is = merge_fix_succeeded(is0 ++ is1, blk1)
            blk = r_b_blk(blk1, is: is)
            blocks1 = :maps.remove(l, blocks0)
            blocks2 = %{blocks1 | p => blk}
            successors = successors(blk)
            blocks = update_phi_labels(successors, l, p, blocks2)
            preds = merge_update_preds(successors, l, p, preds0)
            merge_blocks_1(ls, preds, blocks)

          false ->
            merge_blocks_1(ls, preds0, blocks0)
        end

      %{} ->
        merge_blocks_1(ls, preds0, blocks0)
    end
  end

  defp merge_blocks_1([], _Preds, blocks) do
    blocks
  end

  defp merge_update_preds([l | ls], from, to, preds0) do
    case preds0 do
      %{^l => [p]} ->
        preds = %{preds0 | l => [rename_label(p, from, to)]}
        merge_update_preds(ls, from, to, preds)

      %{} ->
        merge_update_preds(ls, from, to, preds0)
    end
  end

  defp merge_update_preds([], _, _, preds) do
    preds
  end

  defp merge_fix_succeeded(is, r_b_blk(last: r_b_br(succ: succ, fail: fail)))
       when succ !== fail do
    is
  end

  defp merge_fix_succeeded([_ | _] = is0, r_b_blk()) do
    case reverse(is0) do
      [
        r_b_set(op: {:succeeded, :guard}, args: [dst]),
        r_b_set(dst: dst)
        | is
      ] ->
        reverse(is)

      _ ->
        is0
    end
  end

  defp merge_fix_succeeded(is, _Blk) do
    is
  end

  defp verify_merge_is([r_b_set(op: op) | _]) do
    true = op !== :phi
  end

  defp verify_merge_is(_) do
    :ok
  end

  defp is_merge_allowed(1, r_b_blk(), r_b_blk()) do
    false
  end

  defp is_merge_allowed(_L, r_b_blk(is: [r_b_set(op: :landingpad) | _]), r_b_blk()) do
    false
  end

  defp is_merge_allowed(_L, r_b_blk(), r_b_blk(is: [r_b_set(op: :landingpad) | _])) do
    false
  end

  defp is_merge_allowed(l, r_b_blk() = blk1, r_b_blk(is: [r_b_set() = i | _]) = blk2) do
    not is_loop_header(i) and is_merge_allowed_1(l, blk1, blk2)
  end

  defp is_merge_allowed(l, blk1, blk2) do
    is_merge_allowed_1(l, blk1, blk2)
  end

  defp is_merge_allowed_1(l, r_b_blk(last: r_b_br()) = blk, r_b_blk(is: is)) do
    case successors(blk) do
      [^l] ->
        case is do
          [r_b_set(op: :phi, args: [_]) | _] ->
            false

          _ ->
            true
        end

      [_ | _] ->
        false
    end
  end

  defp is_merge_allowed_1(_, r_b_blk(last: r_b_switch()), r_b_blk()) do
    false
  end

  defp update_phi_labels([l | ls], old, new, blocks0) do
    case blocks0 do
      %{^l => r_b_blk(is: [r_b_set(op: :phi) | _] = is0) = blk0} ->
        is = update_phi_labels_is(is0, old, new)
        blk = r_b_blk(blk0, is: is)
        blocks = %{blocks0 | l => blk}
        update_phi_labels(ls, old, new, blocks)

      %{^l => r_b_blk()} ->
        update_phi_labels(ls, old, new, blocks0)
    end
  end

  defp update_phi_labels([], _, _, blocks) do
    blocks
  end
end
