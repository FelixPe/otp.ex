defmodule :m_maps do
  use Bitwise

  def get(_, _) do
    :erlang.nif_error(:undef)
  end

  def find(_, _) do
    :erlang.nif_error(:undef)
  end

  def from_list(_) do
    :erlang.nif_error(:undef)
  end

  def from_keys(_, _) do
    :erlang.nif_error(:undef)
  end

  def intersect(map1, map2)
      when is_map(map1) and
             is_map(map2) do
    case map_size(map1) <= map_size(map2) do
      true ->
        intersect_with_small_map_first(&intersect_combiner_v2/3, map1, map2)

      false ->
        intersect_with_small_map_first(&intersect_combiner_v1/3, map2, map1)
    end
  end

  def intersect(map1, map2) do
    error_with_info(
      error_type_two_maps(map1, map2),
      [map1, map2]
    )
  end

  defp intersect_combiner_v1(_K, v1, _V2) do
    v1
  end

  defp intersect_combiner_v2(_K, _V1, v2) do
    v2
  end

  def intersect_with(combiner, map1, map2)
      when is_map(map1) and
             is_map(map2) and
             is_function(combiner, 3) do
    case map_size(map1) <= map_size(map2) do
      true ->
        intersect_with_small_map_first(combiner, map1, map2)

      false ->
        rCombiner = fn k, v1, v2 ->
          combiner.(k, v2, v1)
        end

        intersect_with_small_map_first(rCombiner, map2, map1)
    end
  end

  def intersect_with(combiner, map1, map2) do
    error_with_info(
      error_type_merge_intersect(map1, map2, combiner),
      [combiner, map1, map2]
    )
  end

  defp intersect_with_small_map_first(combiner, smallMap, bigMap) do
    next = :maps.next(:maps.iterator(smallMap))
    intersect_with_iterate(next, [], bigMap, combiner)
  end

  defp intersect_with_iterate({k, v1, iterator}, keep, bigMap, combiner) do
    next = :maps.next(iterator)

    case bigMap do
      %{^k => v2} ->
        v = combiner.(k, v1, v2)
        intersect_with_iterate(next, [{k, v} | keep], bigMap, combiner)

      _ ->
        intersect_with_iterate(next, keep, bigMap, combiner)
    end
  end

  defp intersect_with_iterate(:none, keep, _BigMap2, _Combiner) do
    :maps.from_list(keep)
  end

  def is_key(_, _) do
    :erlang.nif_error(:undef)
  end

  def keys(_) do
    :erlang.nif_error(:undef)
  end

  def merge(_, _) do
    :erlang.nif_error(:undef)
  end

  def merge_with(combiner, map1, map2)
      when is_map(map1) and
             is_map(map2) and
             is_function(combiner, 3) do
    case map_size(map1) > map_size(map2) do
      true ->
        iterator = :maps.iterator(map2)
        merge_with_1(:maps.next(iterator), map1, map2, combiner)

      false ->
        iterator = :maps.iterator(map1)

        merge_with_1(:maps.next(iterator), map2, map1, fn k, v1, v2 ->
          combiner.(k, v2, v1)
        end)
    end
  end

  def merge_with(combiner, map1, map2) do
    error_with_info(
      error_type_merge_intersect(map1, map2, combiner),
      [combiner, map1, map2]
    )
  end

  defp merge_with_1({k, v2, iterator}, map1, map2, combiner) do
    case map1 do
      %{^k => v1} ->
        newMap1 = %{map1 | k => combiner.(k, v1, v2)}
        merge_with_1(:maps.next(iterator), newMap1, map2, combiner)

      %{} ->
        merge_with_1(:maps.next(iterator), :maps.put(k, v2, map1), map2, combiner)
    end
  end

  defp merge_with_1(:none, result, _, _) do
    result
  end

  def put(_, _, _) do
    :erlang.nif_error(:undef)
  end

  def remove(_, _) do
    :erlang.nif_error(:undef)
  end

  def take(_, _) do
    :erlang.nif_error(:undef)
  end

  def to_list(map) when is_map(map) do
    to_list_internal(:erts_internal.map_next(0, map, []))
  end

  def to_list(iter) do
    try do
      to_list_from_iterator(next(iter))
    catch
      :error, _ ->
        error_with_info({:badmap, iter}, [iter])
    end
  end

  defp to_list_from_iterator({key, value, nextIter}) do
    [{key, value} | to_list_from_iterator(next(nextIter))]
  end

  defp to_list_from_iterator(:none) do
    []
  end

  defp to_list_internal([iter, map | acc]) when is_integer(iter) do
    to_list_internal(:erts_internal.map_next(iter, map, acc))
  end

  defp to_list_internal(acc) do
    acc
  end

  def update(_, _, _) do
    :erlang.nif_error(:undef)
  end

  def values(_) do
    :erlang.nif_error(:undef)
  end

  def new() do
    %{}
  end

  def update_with(key, fun, map)
      when is_function(fun, 1) and
             is_map(map) do
    case map do
      %{^key => value} ->
        %{map | key => fun.(value)}

      %{} ->
        :erlang.error({:badkey, key}, [key, fun, map])
    end
  end

  def update_with(key, fun, map) do
    error_with_info(error_type(map), [key, fun, map])
  end

  def update_with(key, fun, init, map)
      when is_function(
             fun,
             1
           ) and
             is_map(map) do
    case map do
      %{^key => value} ->
        %{map | key => fun.(value)}

      %{} ->
        Map.put(map, key, init)
    end
  end

  def update_with(key, fun, init, map) do
    error_with_info(error_type(map), [key, fun, init, map])
  end

  def get(key, map, default) when is_map(map) do
    case map do
      %{^key => value} ->
        value

      %{} ->
        default
    end
  end

  def get(key, map, default) do
    error_with_info({:badmap, map}, [key, map, default])
  end

  def filter(pred, map)
      when is_map(map) and
             is_function(pred, 2) do
    :maps.from_list(filter_1(pred, next(iterator(map)), :undefined))
  end

  def filter(pred, iter) when is_function(pred, 2) do
    errorTag = make_ref()

    try do
      filter_1(pred, try_next(iter, errorTag), errorTag)
    catch
      :error, ^errorTag ->
        error_with_info({:badmap, iter}, [pred, iter])
    else
      result ->
        :maps.from_list(result)
    end
  end

  def filter(pred, map) do
    badarg_with_info([pred, map])
  end

  defp filter_1(pred, {k, v, iter}, errorTag) do
    case pred.(k, v) do
      true ->
        [{k, v} | filter_1(pred, try_next(iter, errorTag), errorTag)]

      false ->
        filter_1(pred, try_next(iter, errorTag), errorTag)
    end
  end

  defp filter_1(_Pred, :none, _ErrorTag) do
    []
  end

  def filtermap(fun, map)
      when is_map(map) and
             is_function(fun, 2) do
    :maps.from_list(filtermap_1(fun, next(iterator(map)), :undefined))
  end

  def filtermap(fun, iter) when is_function(fun, 2) do
    errorTag = make_ref()

    try do
      filtermap_1(fun, try_next(iter, errorTag), errorTag)
    catch
      :error, ^errorTag ->
        error_with_info({:badmap, iter}, [fun, iter])
    else
      result ->
        :maps.from_list(result)
    end
  end

  def filtermap(fun, map) do
    badarg_with_info([fun, map])
  end

  defp filtermap_1(fun, {k, v, iter}, errorTag) do
    case fun.(k, v) do
      true ->
        [{k, v} | filtermap_1(fun, try_next(iter, errorTag), errorTag)]

      {true, newV} ->
        [{k, newV} | filtermap_1(fun, try_next(iter, errorTag), errorTag)]

      false ->
        filtermap_1(fun, try_next(iter, errorTag), errorTag)
    end
  end

  defp filtermap_1(_Fun, :none, _ErrorTag) do
    []
  end

  def foreach(fun, map)
      when is_map(map) and
             is_function(fun, 2) do
    foreach_1(fun, next(iterator(map)), :undefined)
  end

  def foreach(fun, iter) when is_function(fun, 2) do
    errorTag = make_ref()

    try do
      foreach_1(fun, try_next(iter, errorTag), errorTag)
    catch
      :error, ^errorTag ->
        error_with_info({:badmap, iter}, [fun, iter])
    end
  end

  def foreach(fun, map) do
    badarg_with_info([fun, map])
  end

  defp foreach_1(fun, {k, v, iter}, errorTag) do
    fun.(k, v)
    foreach_1(fun, try_next(iter, errorTag), errorTag)
  end

  defp foreach_1(_Fun, :none, _ErrorTag) do
    :ok
  end

  def fold(fun, init, map)
      when is_map(map) and
             is_function(fun, 3) do
    fold_1(fun, init, next(iterator(map)), :undefined)
  end

  def fold(fun, init, iter) when is_function(fun, 3) do
    errorTag = make_ref()

    try do
      fold_1(fun, init, try_next(iter, errorTag), errorTag)
    catch
      :error, ^errorTag ->
        error_with_info({:badmap, iter}, [fun, init, iter])
    end
  end

  def fold(fun, init, map) do
    badarg_with_info([fun, init, map])
  end

  defp fold_1(fun, acc, {k, v, iter}, errorTag) do
    fold_1(fun, fun.(k, v, acc), try_next(iter, errorTag), errorTag)
  end

  defp fold_1(_Fun, acc, :none, _ErrorTag) do
    acc
  end

  def map(fun, map)
      when is_map(map) and
             is_function(fun, 2) do
    :maps.from_list(map_1(fun, next(iterator(map)), :undefined))
  end

  def map(fun, iter) when is_function(fun, 2) do
    errorTag = make_ref()

    try do
      map_1(fun, try_next(iter, errorTag), errorTag)
    catch
      :error, ^errorTag ->
        error_with_info({:badmap, iter}, [fun, iter])
    else
      result ->
        :maps.from_list(result)
    end
  end

  def map(fun, map) do
    badarg_with_info([fun, map])
  end

  defp map_1(fun, {k, v, iter}, errorTag) do
    [{k, fun.(k, v)} | map_1(fun, try_next(iter, errorTag), errorTag)]
  end

  defp map_1(_Fun, :none, _ErrorTag) do
    []
  end

  def size(map) do
    try do
      map_size(map)
    catch
      _, _ ->
        error_with_info({:badmap, map}, [map])
    end
  end

  def iterator(m) when is_map(m) do
    iterator(m, :undefined)
  end

  def iterator(m) do
    error_with_info({:badmap, m}, [m])
  end

  def iterator(m, :undefined) when is_map(m) do
    [0 | m]
  end

  def iterator(m, :ordered) when is_map(m) do
    cmpFun = fn a, b ->
      :erts_internal.cmp_term(a, b) <= 0
    end

    keys = :lists.sort(cmpFun, :maps.keys(m))
    [keys | m]
  end

  def iterator(m, :reversed) when is_map(m) do
    cmpFun = fn a, b ->
      :erts_internal.cmp_term(b, a) <= 0
    end

    keys = :lists.sort(cmpFun, :maps.keys(m))
    [keys | m]
  end

  def iterator(m, cmpFun)
      when is_map(m) and
             is_function(cmpFun, 2) do
    keys = :lists.sort(cmpFun, :maps.keys(m))
    [keys | m]
  end

  def iterator(m, order) do
    badarg_with_info([m, order])
  end

  def next({k, v, i}) do
    {k, v, i}
  end

  def next([path | map] = iterator)
      when is_integer(path) or
             (is_list(path) and
                is_map(map)) do
    try do
      :erts_internal.map_next(path, map, :iterator)
    catch
      :error, :badarg ->
        badarg_with_info([iterator])
    else
      result ->
        result
    end
  end

  def next(:none) do
    :none
  end

  def next(iter) do
    badarg_with_info([iter])
  end

  def without(ks, m) when is_list(ks) and is_map(m) do
    :lists.foldl(&:maps.remove/2, m, ks)
  end

  def without(ks, m) do
    error_with_info(error_type(m), [ks, m])
  end

  def with(ks, map1) when is_list(ks) and is_map(map1) do
    :maps.from_list(with_1(ks, map1))
  end

  def with(ks, m) do
    error_with_info(error_type(m), [ks, m])
  end

  defp with_1([k | ks], map) do
    case map do
      %{^k => v} ->
        [{k, v} | with_1(ks, map)]

      %{} ->
        with_1(ks, map)
    end
  end

  defp with_1([], _Map) do
    []
  end

  def groups_from_list(fun, list0) when is_function(fun, 1) do
    try do
      :lists.reverse(list0)
    catch
      :error, _ ->
        badarg_with_info([fun, list0])
    else
      list ->
        groups_from_list_1(fun, list, %{})
    end
  end

  def groups_from_list(fun, list) do
    badarg_with_info([fun, list])
  end

  defp groups_from_list_1(fun, [h | tail], acc) do
    k = fun.(h)

    newAcc =
      case acc do
        %{^k => vs} ->
          %{acc | k => [h | vs]}

        %{} ->
          Map.put(acc, k, [h])
      end

    groups_from_list_1(fun, tail, newAcc)
  end

  defp groups_from_list_1(_Fun, [], acc) do
    acc
  end

  def groups_from_list(fun, valueFun, list0)
      when is_function(
             fun,
             1
           ) and
             is_function(valueFun, 1) do
    try do
      :lists.reverse(list0)
    catch
      :error, _ ->
        badarg_with_info([fun, valueFun, list0])
    else
      list ->
        groups_from_list_2(fun, valueFun, list, %{})
    end
  end

  def groups_from_list(fun, valueFun, list) do
    badarg_with_info([fun, valueFun, list])
  end

  defp groups_from_list_2(fun, valueFun, [h | tail], acc) do
    k = fun.(h)
    v = valueFun.(h)

    newAcc =
      case acc do
        %{^k => vs} ->
          %{acc | k => [v | vs]}

        %{} ->
          Map.put(acc, k, [v])
      end

    groups_from_list_2(fun, valueFun, tail, newAcc)
  end

  defp groups_from_list_2(_Fun, _ValueFun, [], acc) do
    acc
  end

  defp error_type(m) when is_map(m) do
    :badarg
  end

  defp error_type(v) do
    {:badmap, v}
  end

  defp error_type_two_maps(m1, m2) when is_map(m1) do
    {:badmap, m2}
  end

  defp error_type_two_maps(m1, _M2) do
    {:badmap, m1}
  end

  defp error_type_merge_intersect(m1, m2, combiner)
       when is_function(
              combiner,
              3
            ) do
    error_type_two_maps(m1, m2)
  end

  defp error_type_merge_intersect(_M1, _M2, _Combiner) do
    :badarg
  end

  defp badarg_with_info(args) do
    :erlang.error(:badarg, args, [{:error_info, %{module: :erl_stdlib_errors}}])
  end

  defp error_with_info(reason, args) do
    :erlang.error(reason, args, [{:error_info, %{module: :erl_stdlib_errors}}])
  end

  def is_iterator_valid(iter) do
    try do
      is_iterator_valid_1(iter)
    catch
      :error, :badarg ->
        false
    end
  end

  defp is_iterator_valid_1(:none) do
    true
  end

  defp is_iterator_valid_1({_, _, next}) do
    is_iterator_valid_1(next(next))
  end

  defp is_iterator_valid_1(iter) do
    _ = next(iter)
    true
  end

  defp try_next({_, _, _} = kVI, _ErrorTag) do
    kVI
  end

  defp try_next(:none, _ErrorTag) do
    :none
  end

  defp try_next(iter, :undefined) do
    next(iter)
  end

  defp try_next(iter, errorTag) do
    try do
      next(iter)
    catch
      :error, :badarg ->
        :erlang.error(errorTag)
    end
  end
end
