defmodule :m_sets do
  use Bitwise
  require Record
  Record.defrecord(:r_set, :set, size: 0, n: 16, maxn: 16,
                               bso: div(16, 2), exp_size: 16 * 5,
                               con_size: 16 * 3, empty: :undefined,
                               segs: :undefined)
  def new() do
    empty = mk_seg(16)
    r_set(empty: empty, segs: {empty})
  end

  def new([{:version, 2}]) do
    %{}
  end

  def new(opts) do
    case (:proplists.get_value(:version, opts, 1)) do
      1 ->
        new()
      2 ->
        new([{:version, 2}])
    end
  end

  def from_list(ls) do
    :lists.foldl(fn e, s ->
                      add_element(e, s)
                 end,
                   new(), ls)
  end

  def from_list(ls, [{:version, 2}]) do
    :maps.from_keys(ls, [])
  end

  def from_list(ls, opts) do
    case (:proplists.get_value(:version, opts, 1)) do
      1 ->
        from_list(ls)
      2 ->
        from_list(ls, [{:version, 2}])
    end
  end

  def is_set(%{}) do
    true
  end

  def is_set(r_set()) do
    true
  end

  def is_set(_) do
    false
  end

  def size(%{} = s) do
    map_size(s)
  end

  def size(r_set(size: size)) do
    size
  end

  def is_empty(%{} = s) do
    map_size(s) === 0
  end

  def is_empty(r_set(size: size)) do
    size === 0
  end

  def to_list(%{} = s) do
    :maps.keys(s)
  end

  def to_list(r_set() = s) do
    fold(fn elem, list ->
              [elem | list]
         end,
           [], s)
  end

  def is_element(e, %{} = s) do
    case (s) do
      %{^e => _} ->
        true
      _ ->
        false
    end
  end

  def is_element(e, r_set() = s) do
    slot = get_slot(s, e)
    bkt = get_bucket(s, slot)
    :lists.member(e, bkt)
  end

  def add_element(e, %{} = s) do
    Map.put(s, e, [])
  end

  def add_element(e, r_set() = s0) do
    slot = get_slot(s0, e)
    bkt = get_bucket(s0, slot)
    case (:lists.member(e, bkt)) do
      true ->
        s0
      false ->
        s1 = update_bucket(s0, slot, [e | bkt])
        maybe_expand(s1)
    end
  end

  def del_element(e, %{} = s) do
    :maps.remove(e, s)
  end

  def del_element(e, r_set() = s0) do
    slot = get_slot(s0, e)
    bkt = get_bucket(s0, slot)
    case (:lists.member(e, bkt)) do
      false ->
        s0
      true ->
        s1 = update_bucket(s0, slot, :lists.delete(e, bkt))
        maybe_contract(s1, 1)
    end
  end

  defp update_bucket(set, slot, newBucket) do
    segI = div(slot - 1, 16) + 1
    bktI = rem(slot - 1, 16) + 1
    segs = r_set(set, :segs)
    seg = :erlang.element(segI, segs)
    r_set(set, segs: :erlang.setelement(segI, segs,
                                      :erlang.setelement(bktI, seg, newBucket)))
  end

  def union(%{} = s1, %{} = s2) do
    :maps.merge(s1, s2)
  end

  def union(s1, s2) do
    case (:erlang.size(s1) < :erlang.size(s2)) do
      true ->
        fold(fn e, s ->
                  add_element(e, s)
             end,
               s2, s1)
      false ->
        fold(fn e, s ->
                  add_element(e, s)
             end,
               s1, s2)
    end
  end

  def union([s1, s2 | ss]) do
    union1(union(s1, s2), ss)
  end

  def union([s]) do
    s
  end

  def union([]) do
    new()
  end

  defp union1(s1, [s2 | ss]) do
    union1(union(s1, s2), ss)
  end

  defp union1(s1, []) do
    s1
  end

  def intersection(%{} = s1, %{} = s2) do
    case (map_size(s1) < map_size(s2)) do
      true ->
        next = :maps.next(:maps.iterator(s1))
        intersection_heuristic(next, [], [],
                                 floor(map_size(s1) * 0.75), s1, s2)
      false ->
        next = :maps.next(:maps.iterator(s2))
        intersection_heuristic(next, [], [],
                                 floor(map_size(s2) * 0.75), s2, s1)
    end
  end

  def intersection(s1, s2) do
    case (:erlang.size(s1) < :erlang.size(s2)) do
      true ->
        filter(fn e ->
                    is_element(e, s2)
               end,
                 s1)
      false ->
        filter(fn e ->
                    is_element(e, s1)
               end,
                 s2)
    end
  end

  defp intersection_heuristic(next, _Keep, delete, 0, acc, reference) do
    intersection_decided(next, remove_keys(delete, acc),
                           reference)
  end

  defp intersection_heuristic({key, _Value, iterator}, keep, delete,
            keepCount, acc, reference) do
    next = :maps.next(iterator)
    case (reference) do
      %{^key => _} ->
        intersection_heuristic(next, [key | keep], delete,
                                 keepCount - 1, acc, reference)
      _ ->
        intersection_heuristic(next, keep, [key | delete],
                                 keepCount, acc, reference)
    end
  end

  defp intersection_heuristic(:none, keep, _Delete, _Count, _Acc,
            _Reference) do
    :maps.from_keys(keep, [])
  end

  defp intersection_decided({key, _Value, iterator}, acc0, reference) do
    acc1 = (case (reference) do
              %{^key => _} ->
                acc0
              %{} ->
                :maps.remove(key, acc0)
            end)
    intersection_decided(:maps.next(iterator), acc1,
                           reference)
  end

  defp intersection_decided(:none, acc, _Reference) do
    acc
  end

  defp remove_keys([k | ks], map) do
    remove_keys(ks, :maps.remove(k, map))
  end

  defp remove_keys([], map) do
    map
  end

  def intersection([s1, s2 | ss]) do
    intersection1(intersection(s1, s2), ss)
  end

  def intersection([s]) do
    s
  end

  defp intersection1(s1, [s2 | ss]) do
    intersection1(intersection(s1, s2), ss)
  end

  defp intersection1(s1, []) do
    s1
  end

  def is_disjoint(%{} = s1, %{} = s2) do
    cond do
      map_size(s1) < map_size(s2) ->
        is_disjoint_1(s2, :maps.iterator(s1))
      true ->
        is_disjoint_1(s1, :maps.iterator(s2))
    end
  end

  def is_disjoint(s1, s2) do
    case (:erlang.size(s1) < :erlang.size(s2)) do
      true ->
        fold(fn _, false ->
                  false
                e, true ->
                  not is_element(e, s2)
             end,
               true, s1)
      false ->
        fold(fn _, false ->
                  false
                e, true ->
                  not is_element(e, s1)
             end,
               true, s2)
    end
  end

  defp is_disjoint_1(set, iter) do
    case (:maps.next(iter)) do
      {k, _, nextIter} ->
        case (set) do
          %{^k => _} ->
            false
          %{} ->
            is_disjoint_1(set, nextIter)
        end
      :none ->
        true
    end
  end

  def subtract(%{} = lHS, %{} = rHS) do
    lSize = map_size(lHS)
    rSize = map_size(rHS)
    case (rSize <= div(lSize, 4)) do
      true ->
        next = :maps.next(:maps.iterator(rHS))
        subtract_decided(next, lHS, rHS)
      false ->
        keepThreshold = div(lSize * 3, 4)
        next = :maps.next(:maps.iterator(lHS))
        subtract_heuristic(next, [], [], keepThreshold, lHS,
                             rHS)
    end
  end

  def subtract(lHS, rHS) do
    filter(fn e ->
                not is_element(e, rHS)
           end,
             lHS)
  end

  defp subtract_heuristic(next, _Keep, delete, 0, acc, reference) do
    subtract_decided(next, remove_keys(delete, acc),
                       reference)
  end

  defp subtract_heuristic({key, _Value, iterator}, keep, delete,
            keepCount, acc, reference) do
    next = :maps.next(iterator)
    case (reference) do
      %{^key => _} ->
        subtract_heuristic(next, keep, [key | delete],
                             keepCount, acc, reference)
      _ ->
        subtract_heuristic(next, [key | keep], delete,
                             keepCount - 1, acc, reference)
    end
  end

  defp subtract_heuristic(:none, keep, _Delete, _Count, _Acc,
            _Reference) do
    :maps.from_keys(keep, [])
  end

  defp subtract_decided({key, _Value, iterator}, acc, reference) do
    case (reference) do
      %{^key => _} ->
        subtract_decided(:maps.next(iterator),
                           :maps.remove(key, acc), reference)
      _ ->
        subtract_decided(:maps.next(iterator), acc, reference)
    end
  end

  defp subtract_decided(:none, acc, _Reference) do
    acc
  end

  def is_subset(%{} = s1, %{} = s2) do
    cond do
      map_size(s1) > map_size(s2) ->
        false
      true ->
        is_subset_1(s2, :maps.iterator(s1))
    end
  end

  def is_subset(s1, s2) do
    fold(fn e, sub ->
              sub and is_element(e, s2)
         end,
           true, s1)
  end

  defp is_subset_1(set, iter) do
    case (:maps.next(iter)) do
      {k, _, nextIter} ->
        case (set) do
          %{^k => _} ->
            is_subset_1(set, nextIter)
          %{} ->
            false
        end
      :none ->
        true
    end
  end

  def fold(f, acc, %{} = d) when is_function(f, 2) do
    fold_1(f, acc, :maps.iterator(d))
  end

  def fold(f, acc, r_set() = d) when is_function(f, 2) do
    fold_set(f, acc, d)
  end

  defp fold_1(fun, acc, iter) do
    case (:maps.next(iter)) do
      {k, _, nextIter} ->
        fold_1(fun, fun.(k, acc), nextIter)
      :none ->
        acc
    end
  end

  defp get_slot(t, key) do
    h = :erlang.phash(key, r_set(t, :maxn))
    cond do
      h > r_set(t, :n) ->
        h - r_set(t, :bso)
      true ->
        h
    end
  end

  defp get_bucket(t, slot) do
    get_bucket_s(r_set(t, :segs), slot)
  end

  defp fold_set(f, acc, d) do
    segs = r_set(d, :segs)
    fold_segs(f, acc, segs, tuple_size(segs))
  end

  defp fold_segs(f, acc, segs, i) when i >= 1 do
    seg = :erlang.element(i, segs)
    fold_segs(f, fold_seg(f, acc, seg, tuple_size(seg)),
                segs, i - 1)
  end

  defp fold_segs(_, acc, _, _) do
    acc
  end

  defp fold_seg(f, acc, seg, i) when i >= 1 do
    fold_seg(f,
               fold_bucket(f, acc, :erlang.element(i, seg)), seg,
               i - 1)
  end

  defp fold_seg(_, acc, _, _) do
    acc
  end

  defp fold_bucket(f, acc, [e | bkt]) do
    fold_bucket(f, f.(e, acc), bkt)
  end

  defp fold_bucket(_, acc, []) do
    acc
  end

  defp filter_set(f, d) do
    segs0 = :erlang.tuple_to_list(r_set(d, :segs))
    {segs1, fc} = filter_seg_list(f, segs0, [], 0)
    maybe_contract(r_set(d, segs: :erlang.list_to_tuple(segs1)),
                     fc)
  end

  defp filter_seg_list(f, [seg | segs], fss, fc0) do
    bkts0 = :erlang.tuple_to_list(seg)
    {bkts1, fc1} = filter_bkt_list(f, bkts0, [], fc0)
    filter_seg_list(f, segs,
                      [:erlang.list_to_tuple(bkts1) | fss], fc1)
  end

  defp filter_seg_list(_, [], fss, fc) do
    {:lists.reverse(fss, []), fc}
  end

  defp filter_bkt_list(f, [bkt0 | bkts], fbs, fc0) do
    {bkt1, fc1} = filter_bucket(f, bkt0, [], fc0)
    filter_bkt_list(f, bkts, [bkt1 | fbs], fc1)
  end

  defp filter_bkt_list(_, [], fbs, fc) do
    {:lists.reverse(fbs), fc}
  end

  defp filter_bucket(f, [e | bkt], fb, fc) do
    case (f.(e)) do
      true ->
        filter_bucket(f, bkt, [e | fb], fc)
      false ->
        filter_bucket(f, bkt, fb, fc + 1)
    end
  end

  defp filter_bucket(_, [], fb, fc) do
    {fb, fc}
  end

  defp get_bucket_s(segs, slot) do
    segI = div(slot - 1, 16) + 1
    bktI = rem(slot - 1, 16) + 1
    :erlang.element(bktI, :erlang.element(segI, segs))
  end

  defp put_bucket_s(segs, slot, bkt) do
    segI = div(slot - 1, 16) + 1
    bktI = rem(slot - 1, 16) + 1
    seg = :erlang.setelement(bktI,
                               :erlang.element(segI, segs), bkt)
    :erlang.setelement(segI, segs, seg)
  end

  defp maybe_expand(t0) when r_set(t0, :size) + 1 > r_set(t0, :exp_size) do
    t = maybe_expand_segs(t0)
    n = r_set(t, :n) + 1
    segs0 = r_set(t, :segs)
    slot1 = n - r_set(t, :bso)
    b = get_bucket_s(segs0, slot1)
    slot2 = n
    {b1, b2} = rehash(b, slot1, slot2, r_set(t, :maxn))
    segs1 = put_bucket_s(segs0, slot1, b1)
    segs2 = put_bucket_s(segs1, slot2, b2)
    r_set(t, size: r_set(t, :size) + 1,  n: n,  exp_size: n * 5, 
           con_size: n * 3,  segs: segs2)
  end

  defp maybe_expand(t) do
    r_set(t, size: r_set(t, :size) + 1)
  end

  defp maybe_expand_segs(t) when r_set(t, :n) === r_set(t, :maxn) do
    r_set(t, maxn: 2 * r_set(t, :maxn),  bso: 2 * r_set(t, :bso), 
           segs: expand_segs(r_set(t, :segs), r_set(t, :empty)))
  end

  defp maybe_expand_segs(t) do
    t
  end

  defp maybe_contract(t, dc)
      when (r_set(t, :size) - dc < r_set(t, :con_size) and
              r_set(t, :n) > 16) do
    n = r_set(t, :n)
    slot1 = n - r_set(t, :bso)
    segs0 = r_set(t, :segs)
    b1 = get_bucket_s(segs0, slot1)
    slot2 = n
    b2 = get_bucket_s(segs0, slot2)
    segs1 = put_bucket_s(segs0, slot1, b1 ++ b2)
    segs2 = put_bucket_s(segs1, slot2, [])
    n1 = n - 1
    maybe_contract_segs(r_set(t, size: r_set(t, :size) - dc, 
                               n: n1,  exp_size: n1 * 5,  con_size: n1 * 3, 
                               segs: segs2))
  end

  defp maybe_contract(t, dc) do
    r_set(t, size: r_set(t, :size) - dc)
  end

  defp maybe_contract_segs(t) when r_set(t, :n) === r_set(t, :bso) do
    r_set(t, maxn: div(r_set(t, :maxn), 2), 
           bso: div(r_set(t, :bso), 2), 
           segs: contract_segs(r_set(t, :segs)))
  end

  defp maybe_contract_segs(t) do
    t
  end

  defp rehash([e | t], slot1, slot2, maxN) do
    {l1, l2} = rehash(t, slot1, slot2, maxN)
    case (:erlang.phash(e, maxN)) do
      ^slot1 ->
        {[e | l1], l2}
      ^slot2 ->
        {l1, [e | l2]}
    end
  end

  defp rehash([], _, _, _) do
    {[], []}
  end

  defp mk_seg(16) do
    {[], [], [], [], [], [], [], [], [], [], [], [], [], [],
       [], []}
  end

  defp expand_segs({b1}, empty) do
    {b1, empty}
  end

  defp expand_segs({b1, b2}, empty) do
    {b1, b2, empty, empty}
  end

  defp expand_segs({b1, b2, b3, b4}, empty) do
    {b1, b2, b3, b4, empty, empty, empty, empty}
  end

  defp expand_segs({b1, b2, b3, b4, b5, b6, b7, b8}, empty) do
    {b1, b2, b3, b4, b5, b6, b7, b8, empty, empty, empty,
       empty, empty, empty, empty, empty}
  end

  defp expand_segs({b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11,
             b12, b13, b14, b15, b16},
            empty) do
    {b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13,
       b14, b15, b16, empty, empty, empty, empty, empty, empty,
       empty, empty, empty, empty, empty, empty, empty, empty,
       empty, empty}
  end

  defp expand_segs(segs, empty) do
    :erlang.list_to_tuple(:erlang.tuple_to_list(segs) ++ :lists.duplicate(tuple_size(segs),
                                                                            empty))
  end

  defp contract_segs({b1, _}) do
    {b1}
  end

  defp contract_segs({b1, b2, _, _}) do
    {b1, b2}
  end

  defp contract_segs({b1, b2, b3, b4, _, _, _, _}) do
    {b1, b2, b3, b4}
  end

  defp contract_segs({b1, b2, b3, b4, b5, b6, b7, b8, _, _, _, _, _,
             _, _, _}) do
    {b1, b2, b3, b4, b5, b6, b7, b8}
  end

  defp contract_segs({b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11,
             b12, b13, b14, b15, b16, _, _, _, _, _, _, _, _, _, _,
             _, _, _, _, _, _}) do
    {b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13,
       b14, b15, b16}
  end

  defp contract_segs(segs) do
    ss = div(tuple_size(segs), 2)
    :erlang.list_to_tuple(:lists.sublist(:erlang.tuple_to_list(segs),
                                           1, ss))
  end

end