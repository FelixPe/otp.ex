defmodule :m_erl_types do
  use Bitwise
  import Kernel, except: [max: 2, min: 2]
  require Record
  Record.defrecord(:r_c, :c, tag: :undefined, elements: [],
                             qualifier: :unknown)
  Record.defrecord(:r_int_set, :int_set, set: :undefined)
  Record.defrecord(:r_int_rng, :int_rng, from: :undefined,
                                   to: :undefined)
  Record.defrecord(:r_opaque, :opaque, mod: :undefined,
                                  name: :undefined, arity: 0,
                                  struct: :undefined)
  def t_any() do
    :any
  end

  def t_is_any(type) do
    do_opaque(type, :universe, &is_any/1)
  end

  defp is_any(:any) do
    true
  end

  defp is_any(_) do
    false
  end

  def t_none() do
    :none
  end

  def t_is_none(:none) do
    true
  end

  def t_is_none(_) do
    false
  end

  defp t_opaque(mod, name, args, struct) do
    o = r_opaque(mod: mod, name: name, arity: length(args),
            struct: struct)
    r_c(tag: :opaque, elements: set_singleton(o))
  end

  def t_is_opaque(r_c(tag: :opaque, elements: _) = type, opaques) do
    not is_opaque_type(type, opaques)
  end

  def t_is_opaque(_Type, _Opaques) do
    false
  end

  def t_is_opaque(r_c(tag: :opaque, elements: _)) do
    true
  end

  def t_is_opaque(_) do
    false
  end

  def t_has_opaque_subtype(type, opaques) do
    do_opaque(type, opaques, &has_opaque_subtype/1)
  end

  defp has_opaque_subtype(r_c(tag: :union, elements: ts)) do
    :lists.any(&t_is_opaque/1, ts)
  end

  defp has_opaque_subtype(t) do
    t_is_opaque(t)
  end

  def t_opaque_structure(r_c(tag: :opaque, elements: elements)) do
    t_sup(for r_opaque(struct: struct) <- elements do
            struct
          end)
  end

  def t_contains_opaque(type) do
    t_contains_opaque(type, [])
  end

  def t_contains_opaque(:any, _Opaques) do
    false
  end

  def t_contains_opaque(:none, _Opaques) do
    false
  end

  def t_contains_opaque(:unit, _Opaques) do
    false
  end

  def t_contains_opaque(r_c(tag: :atom, elements: _Set), _Opaques) do
    false
  end

  def t_contains_opaque(r_c(tag: :binary, elements: {_Unit, _Base}),
           _Opaques) do
    false
  end

  def t_contains_opaque(r_c(tag: :number, elements: :any,
             qualifier: :float),
           _Opaques) do
    false
  end

  def t_contains_opaque(r_c(tag: :function, elements: {domain, range}),
           opaques) do
    t_contains_opaque(domain,
                        opaques) or t_contains_opaque(range, opaques)
  end

  def t_contains_opaque(r_c(tag: :identifier, elements: _Types),
           _Opaques) do
    false
  end

  def t_contains_opaque(r_c(tag: :number,
             elements: r_int_rng(from: _From, to: _To), qualifier: :integer),
           _Opaques) do
    false
  end

  def t_contains_opaque(r_c(tag: :number, elements: r_int_set(set: _Set),
             qualifier: :integer),
           _Opaques) do
    false
  end

  def t_contains_opaque(r_c(tag: :number, elements: _Types,
             qualifier: :integer),
           _Opaques) do
    false
  end

  def t_contains_opaque(r_c(tag: :list, elements: {type, r_c(tag: nil)},
             qualifier: _),
           opaques) do
    t_contains_opaque(type, opaques)
  end

  def t_contains_opaque(r_c(tag: :list, elements: {type, tail},
             qualifier: _),
           opaques) do
    t_contains_opaque(type,
                        opaques) or t_contains_opaque(tail, opaques)
  end

  def t_contains_opaque(r_c(tag: :map, elements: {_, _, _}) = map,
           opaques) do
    list_contains_opaque(map_all_types(map), opaques)
  end

  def t_contains_opaque(r_c(tag: nil), _Opaques) do
    false
  end

  def t_contains_opaque(r_c(tag: :number, elements: _Set, qualifier: _Tag),
           _Opaques) do
    false
  end

  def t_contains_opaque(r_c(tag: :opaque, elements: _) = t, opaques) do
    not
    is_opaque_type(t,
                     opaques) or t_contains_opaque(t_opaque_structure(t))
  end

  def t_contains_opaque(r_c(tag: :product, elements: types), opaques) do
    list_contains_opaque(types, opaques)
  end

  def t_contains_opaque(r_c(tag: :tuple, elements: :any,
             qualifier: {_, _}),
           _Opaques) do
    false
  end

  def t_contains_opaque(r_c(tag: :tuple, elements: types,
             qualifier: {_, _}),
           opaques) do
    list_contains_opaque(types, opaques)
  end

  def t_contains_opaque(r_c(tag: :tuple_set, elements: _Set) = t,
           opaques) do
    list_contains_opaque(t_tuple_subtypes(t), opaques)
  end

  def t_contains_opaque(r_c(tag: :union, elements: list), opaques) do
    list_contains_opaque(list, opaques)
  end

  def t_contains_opaque(r_c(tag: :var, elements: _Id), _Opaques) do
    false
  end

  defp list_contains_opaque([h | t], opaques) do
    t_contains_opaque(h, opaques) or list_contains_opaque(t,
                                                            opaques)
  end

  defp list_contains_opaque([], _Opaques) do
    false
  end

  def t_find_opaque_mismatch(t1, t2, opaques) do
    try do
      t_find_opaque_mismatch(t1, t2, t2, opaques)
    catch
      :error ->
        :error
    end
  end

  defp t_find_opaque_mismatch(:any, _Type, _TopType, _Opaques) do
    :error
  end

  defp t_find_opaque_mismatch(:none, _Type, _TopType, _Opaques) do
    throw(:error)
  end

  defp t_find_opaque_mismatch(r_c(tag: :list, elements: {t1, tl1},
              qualifier: _),
            r_c(tag: :list, elements: {t2, tl2}, qualifier: _),
            topType, opaques) do
    t_find_opaque_mismatch_ordlists([t1, tl1], [t2, tl2],
                                      topType, opaques)
  end

  defp t_find_opaque_mismatch(t1, r_c(tag: :opaque, elements: _) = t2, topType,
            opaques) do
    case (is_opaque_type(t2, opaques)) do
      false ->
        case (t_is_opaque(t1) and compatible_opaque_types(t1,
                                                            t2) !== []) do
          true ->
            :error
          false ->
            {:ok, topType, t2}
        end
      true ->
        t_find_opaque_mismatch(t1, t_opaque_structure(t2),
                                 topType, opaques)
    end
  end

  defp t_find_opaque_mismatch(r_c(tag: :opaque, elements: _) = t1, t2, topType,
            opaques) do
    case (is_opaque_type(t1, opaques)) do
      false ->
        case (t_is_opaque(t2) and compatible_opaque_types(t1,
                                                            t2) !== []) do
          true ->
            :error
          false ->
            {:ok, topType, t1}
        end
      true ->
        t_find_opaque_mismatch(t_opaque_structure(t1), t2,
                                 topType, opaques)
    end
  end

  defp t_find_opaque_mismatch(r_c(tag: :product, elements: t1),
            r_c(tag: :product, elements: t2), topType, opaques) do
    t_find_opaque_mismatch_ordlists(t1, t2, topType,
                                      opaques)
  end

  defp t_find_opaque_mismatch(r_c(tag: :tuple, elements: t1,
              qualifier: {arity, _}),
            r_c(tag: :tuple, elements: t2, qualifier: {arity, _}),
            topType, opaques) do
    t_find_opaque_mismatch_ordlists(t1, t2, topType,
                                      opaques)
  end

  defp t_find_opaque_mismatch(r_c(tag: :tuple, elements: _,
              qualifier: {_, _}) = t1,
            r_c(tag: :tuple_set, elements: _) = t2, topType,
            opaques) do
    tuples1 = t_tuple_subtypes(t1)
    tuples2 = t_tuple_subtypes(t2)
    t_find_opaque_mismatch_lists(tuples1, tuples2, topType,
                                   opaques)
  end

  defp t_find_opaque_mismatch(t1, r_c(tag: :union, elements: u2), topType,
            opaques) do
    t_find_opaque_mismatch_lists([t1], u2, topType, opaques)
  end

  defp t_find_opaque_mismatch(t1, t2, _TopType, opaques) do
    case (t_is_none(t_inf(t1, t2, opaques))) do
      false ->
        :error
      true ->
        throw(:error)
    end
  end

  defp t_find_opaque_mismatch_ordlists(l1, l2, topType, opaques) when (is_list(l1) and
                                            is_list(l2)) do
    list = :lists.zipwith(fn t1, t2 ->
                               t_find_opaque_mismatch(t1, t2, topType, opaques)
                          end,
                            l1, l2)
    t_find_opaque_mismatch_list(list)
  end

  defp t_find_opaque_mismatch_ordlists(_, _, _TopType, _Opaques) do
    :error
  end

  defp t_find_opaque_mismatch_lists(l1, l2, _TopType, opaques) when (is_list(l1) and
                                             is_list(l2)) do
    list = (for t1 <- l1, t2 <- l2 do
              try do
                t_find_opaque_mismatch(t1, t2, t2, opaques)
              catch
                :error ->
                  :error
              end
            end)
    t_find_opaque_mismatch_list(list)
  end

  defp t_find_opaque_mismatch_lists(_, _, _TopType, _Opaques) do
    :error
  end

  defp t_find_opaque_mismatch_list([]) do
    throw(:error)
  end

  defp t_find_opaque_mismatch_list([h | t]) do
    case (h) do
      {:ok, _T1, _T2} ->
        h
      :error ->
        t_find_opaque_mismatch_list(t)
    end
  end

  def t_find_unknown_opaque(_T1, _T2, :universe) do
    []
  end

  def t_find_unknown_opaque(t1, t2, opaques) do
    try do
      t_inf(t1, t2, {:match, opaques})
    catch
      {:pos, ns} ->
        ns
    else
      _ ->
        []
    end
  end

  def t_decorate_with_opaque(t1, t2, opaques) do
    case (opaques === [] or t_is_equal(t1, t2) or not
                                                  t_contains_opaque(t2)) do
      true ->
        t1
      false ->
        t = t_inf(t1, t2)
        case (t_contains_opaque(t)) do
          false ->
            t1
          true ->
            r = decorate(t1, t, opaques)
            :ok
            r
        end
    end
  end

  defp decorate(type, :none, _Opaques) do
    type
  end

  defp decorate(r_c(tag: :function, elements: {domain, range}),
            r_c(tag: :function, elements: {d, r}), opaques) do
    r_c(tag: :function,
        elements: {decorate(domain, d, opaques),
                     decorate(range, r, opaques)})
  end

  defp decorate(r_c(tag: :list, elements: {types, tail},
              qualifier: size),
            r_c(tag: :list, elements: {ts, tl}, qualifier: _Sz),
            opaques) do
    r_c(tag: :list,
        elements: {decorate(types, ts, opaques),
                     decorate(tail, tl, opaques)},
        qualifier: size)
  end

  defp decorate(r_c(tag: :product, elements: types),
            r_c(tag: :product, elements: ts), opaques) do
    r_c(tag: :product,
        elements: list_decorate(types, ts, opaques))
  end

  defp decorate(r_c(tag: :tuple, elements: _,
              qualifier: {_, _}) = t,
            r_c(tag: :tuple, elements: :any, qualifier: {_, _}),
            _Opaques) do
    t
  end

  defp decorate(r_c(tag: :tuple, elements: :any,
              qualifier: {_, _}) = t,
            r_c(tag: :tuple, elements: _, qualifier: {_, _}),
            _Opaques) do
    t
  end

  defp decorate(r_c(tag: :tuple, elements: types,
              qualifier: {arity, tag}),
            r_c(tag: :tuple, elements: ts, qualifier: {arity, _}),
            opaques) do
    r_c(tag: :tuple,
        elements: list_decorate(types, ts, opaques),
        qualifier: {arity, tag})
  end

  defp decorate(r_c(tag: :tuple_set, elements: list),
            r_c(tag: :tuple, elements: _, qualifier: {arity, _}) = t,
            opaques) do
    decorate_tuple_sets(list, [{arity, [t]}], opaques)
  end

  defp decorate(r_c(tag: :tuple_set, elements: list),
            r_c(tag: :tuple_set, elements: l), opaques) do
    decorate_tuple_sets(list, l, opaques)
  end

  defp decorate(r_c(tag: :union, elements: list), t, opaques)
      when t !== :any do
    r_c(tag: :union, elements: l) = force_union(t)
    union_decorate(list, l, opaques)
  end

  defp decorate(t, r_c(tag: :union, elements: l), opaques)
      when t !== :any do
    r_c(tag: :union, elements: list) = force_union(t)
    union_decorate(list, l, opaques)
  end

  defp decorate(type, r_c(tag: :opaque, elements: _) = t,
            opaques) do
    decorate_with_opaque(type, t, opaques)
  end

  defp decorate(type, _T, _Opaques) do
    type
  end

  defp decorate_with_opaque(type, r_c(tag: :opaque, elements: set2),
            opaques) do
    case (decoration(set2, type, opaques, [], false)) do
      {[], false} ->
        type
      {list, all} when list !== [] ->
        newType = sup_opaque(list)
        case (all) do
          true ->
            newType
          false ->
            t_sup(newType, type)
        end
    end
  end

  defp decoration([r_opaque(struct: s) = opaque | opaqueTypes], type,
            opaques, newOpaqueTypes0, all) do
    isOpaque = is_opaque_type2(opaque, opaques)
    i = t_inf(type, s)
    case (not isOpaque or t_is_none(i)) do
      true ->
        decoration(opaqueTypes, type, opaques, newOpaqueTypes0,
                     all)
      false ->
        newI = decorate(i, s, opaques)
        newOpaque = combine(newI, [opaque])
        newAll = all or t_is_equal(i, type)
        newOpaqueTypes = newOpaque ++ newOpaqueTypes0
        decoration(opaqueTypes, type, opaques, newOpaqueTypes,
                     newAll)
    end
  end

  defp decoration([], _Type, _Opaques, newOpaqueTypes, all) do
    {newOpaqueTypes, all}
  end

  defp list_decorate(list, l, opaques) do
    for {elem, e} <- :lists.zip(list, l) do
      decorate(elem, e, opaques)
    end
  end

  defp union_decorate(u1, u2, opaques) do
    union = union_decorate(u1, u2, opaques, 0, [])
    [a, b, f, i, l, n, t, _, map] = u1
    [_, _, _, _, _, _, _, opaque, _] = u2
    list = [a, b, f, i, l, n, t, map]
    decList = (for e <- list, not t_is_none(e),
                     not t_is_none(dec = decorate(e, opaque, opaques)) do
                 dec
               end)
    t_sup([union | decList])
  end

  defp union_decorate([:none | left1], [_ | left2], opaques, n,
            acc) do
    union_decorate(left1, left2, opaques, n, [:none | acc])
  end

  defp union_decorate([t1 | left1], [:none | left2], opaques, n,
            acc) do
    union_decorate(left1, left2, opaques, n + 1, [t1 | acc])
  end

  defp union_decorate([t1 | left1], [t2 | left2], opaques, n, acc) do
    union_decorate(left1, left2, opaques, n + 1,
                     [decorate(t1, t2, opaques) | acc])
  end

  defp union_decorate([], [], _Opaques, n, acc) do
    cond do
      n === 0 ->
        :none
      n === 1 ->
        [type] = (for t <- acc, t !== :none do
                    t
                  end)
        type
      n >= 2 ->
        r_c(tag: :union, elements: :lists.reverse(acc))
    end
  end

  defp decorate_tuple_sets(list, l, opaques) do
    decorate_tuple_sets(list, l, opaques, [])
  end

  defp decorate_tuple_sets([{arity, tuples} | list], [{arity, ts} | l],
            opaques, acc) do
    decTs = decorate_tuples_in_sets(tuples, ts, opaques)
    decorate_tuple_sets(list, l, opaques,
                          [{arity, decTs} | acc])
  end

  defp decorate_tuple_sets([arTup | list], l, opaques, acc) do
    decorate_tuple_sets(list, l, opaques, [arTup | acc])
  end

  defp decorate_tuple_sets([], _L, _Opaques, acc) do
    r_c(tag: :tuple_set, elements: :lists.reverse(acc))
  end

  defp decorate_tuples_in_sets([r_c(tag: :tuple, elements: elements,
               qualifier: {_, :any})],
            ts, opaques) do
    newList = (for r_c(tag: :tuple, elements: es,
                       qualifier: {_, _}) <- ts do
                 list_decorate(elements, es, opaques)
               end)
    case (t_sup(for es <- newList do
                  t_tuple(es)
                end)) do
      r_c(tag: :tuple_set, elements: [{_Arity, tuples}]) ->
        tuples
      r_c(tag: :tuple, elements: _,
          qualifier: {_, _}) = tuple ->
        [tuple]
    end
  end

  defp decorate_tuples_in_sets(tuples, ts, opaques) do
    decorate_tuples_in_sets(tuples, ts, opaques, [])
  end

  defp decorate_tuples_in_sets([r_c(tag: :tuple, elements: elements,
               qualifier: {arity, tag1}) = t1 |
               tuples] = l1,
            [r_c(tag: :tuple, elements: es,
                 qualifier: {arity, tag2}) |
                 ts] = l2,
            opaques, acc) do
    cond do
      tag1 < tag2 ->
        decorate_tuples_in_sets(tuples, l2, opaques, [t1 | acc])
      tag1 > tag2 ->
        decorate_tuples_in_sets(l1, ts, opaques, acc)
      tag1 == tag2 ->
        newElements = list_decorate(elements, es, opaques)
        newAcc = [r_c(tag: :tuple, elements: newElements,
                      qualifier: {arity, tag1}) |
                      acc]
        decorate_tuples_in_sets(tuples, ts, opaques, newAcc)
    end
  end

  defp decorate_tuples_in_sets([t1 | tuples], l2, opaques, acc) do
    decorate_tuples_in_sets(tuples, l2, opaques, [t1 | acc])
  end

  defp decorate_tuples_in_sets([], _L, _Opaques, acc) do
    :lists.reverse(acc)
  end

  def t_unit() do
    :unit
  end

  def t_is_unit(:unit) do
    true
  end

  def t_is_unit(_) do
    false
  end

  def t_is_impossible(:none) do
    true
  end

  def t_is_impossible(:unit) do
    true
  end

  def t_is_impossible(_) do
    false
  end

  def t_is_none_or_unit(t) do
    t_is_impossible(t)
  end

  def t_atom() do
    r_c(tag: :atom, elements: :any)
  end

  def t_atom(a) when is_atom(a) do
    r_c(tag: :atom, elements: set_singleton(a))
  end

  def t_atoms(list) when is_list(list) do
    t_sup(for a <- list do
            t_atom(a)
          end)
  end

  def t_atom_vals(type) do
    t_atom_vals(type, :universe)
  end

  def t_atom_vals(type, opaques) do
    do_opaque(type, opaques, &atom_vals/1)
  end

  defp atom_vals(r_c(tag: :atom, elements: :any)) do
    :unknown
  end

  defp atom_vals(r_c(tag: :atom, elements: set)) do
    set
  end

  defp atom_vals(r_c(tag: :opaque, elements: _)) do
    :unknown
  end

  defp atom_vals(other) do
    r_c(tag: :atom, elements: _) = (atm = t_inf(t_atom(),
                                                other))
    atom_vals(atm)
  end

  def t_is_atom(type) do
    t_is_atom(type, :universe)
  end

  def t_is_atom(type, opaques) do
    do_opaque(type, opaques, &is_atom1/1)
  end

  defp is_atom1(r_c(tag: :atom, elements: _)) do
    true
  end

  defp is_atom1(_) do
    false
  end

  def t_is_any_atom(atom, someAtomsType) do
    t_is_any_atom(atom, someAtomsType, :universe)
  end

  def t_is_any_atom(atom, someAtomsType, opaques) do
    do_opaque(someAtomsType, opaques,
                fn atomsType ->
                     is_any_atom(atom, atomsType)
                end)
  end

  defp is_any_atom(atom, r_c(tag: :atom, elements: :any))
      when is_atom(atom) do
    false
  end

  defp is_any_atom(atom, r_c(tag: :atom, elements: set))
      when is_atom(atom) do
    set_is_singleton(atom, set)
  end

  defp is_any_atom(atom, _) when is_atom(atom) do
    false
  end

  def t_is_boolean(type) do
    t_is_boolean(type, :universe)
  end

  def t_is_boolean(type, opaques) do
    do_opaque(type, opaques, &is_boolean/1)
  end

  def t_boolean() do
    r_c(tag: :atom, elements: set_from_list([false, true]))
  end

  defp is_boolean(r_c(tag: :atom, elements: set)) do
    case (set) do
      [atom] when :erlang.is_boolean(atom) ->
        true
      [false, true] ->
        true
      _ ->
        false
    end
  end

  defp is_boolean(_) do
    false
  end

  def t_binary() do
    r_c(tag: :binary, elements: {8, 0})
  end

  def t_nonempty_binary() do
    r_c(tag: :binary, elements: {8, 8})
  end

  def t_is_binary(type) do
    t_is_binary(type, :universe)
  end

  def t_is_binary(type, opaques) do
    do_opaque(type, opaques, &is_binary/1)
  end

  defp is_binary(r_c(tag: :binary, elements: {u, b})) do
    rem(u, 8) === 0 and rem(b, 8) === 0
  end

  defp is_binary(_) do
    false
  end

  def t_bitstr() do
    r_c(tag: :binary, elements: {1, 0})
  end

  def t_nonempty_bitstring() do
    r_c(tag: :binary, elements: {1, 1})
  end

  def t_bitstr(u, b) do
    newB = (cond do
              u === 0 ->
                b
              b >= u * (8 + 1) ->
                rem(b, u) + u * 8
              true ->
                b
            end)
    r_c(tag: :binary, elements: {u, newB})
  end

  def t_bitstr_unit(r_c(tag: :binary, elements: {u, _})) do
    u
  end

  def t_bitstr_base(r_c(tag: :binary, elements: {_, b})) do
    b
  end

  def t_bitstr_concat(list) do
    t_bitstr_concat_1(list, t_bitstr(0, 0))
  end

  defp t_bitstr_concat_1([t | left], acc) do
    t_bitstr_concat_1(left, t_bitstr_concat(acc, t))
  end

  defp t_bitstr_concat_1([], acc) do
    acc
  end

  def t_bitstr_concat(t1, t2) do
    t1p = t_inf(t_bitstr(), t1)
    t2p = t_inf(t_bitstr(), t2)
    bitstr_concat(t_unopaque(t1p), t_unopaque(t2p))
  end

  def t_bitstr_match(t1, t2) do
    t1p = t_inf(t_bitstr(), t1)
    t2p = t_inf(t_bitstr(), t2)
    bitstr_match(t_unopaque(t1p), t_unopaque(t2p))
  end

  def t_is_bitstr(type) do
    t_is_bitstr(type, :universe)
  end

  def t_is_bitstr(type, opaques) do
    do_opaque(type, opaques, &is_bitstr/1)
  end

  defp is_bitstr(r_c(tag: :binary, elements: {_, _})) do
    true
  end

  defp is_bitstr(_) do
    false
  end

  def t_fun() do
    r_c(tag: :function, elements: {:any, :any})
  end

  def t_fun(range) do
    r_c(tag: :function, elements: {:any, range})
  end

  def t_fun(domain, range) when is_list(domain) do
    r_c(tag: :function,
        elements: {r_c(tag: :product, elements: domain), range})
  end

  def t_fun(arity, range) when (is_integer(arity) and
                               0 <= arity and arity <= 255) do
    r_c(tag: :function,
        elements: {r_c(tag: :product,
                       elements: :lists.duplicate(arity, :any)),
                     range})
  end

  def t_fun_args(type) do
    t_fun_args(type, :universe)
  end

  def t_fun_args(type, opaques) do
    do_opaque(type, opaques, &fun_args/1)
  end

  defp fun_args(r_c(tag: :function, elements: {:any, _})) do
    :unknown
  end

  defp fun_args(r_c(tag: :function,
              elements: {r_c(tag: :product, elements: domain), _}))
      when is_list(domain) do
    domain
  end

  def t_fun_arity(type) do
    t_fun_arity(type, :universe)
  end

  def t_fun_arity(type, opaques) do
    do_opaque(type, opaques, &fun_arity/1)
  end

  defp fun_arity(r_c(tag: :function, elements: {:any, _})) do
    :unknown
  end

  defp fun_arity(r_c(tag: :function,
              elements: {r_c(tag: :product, elements: domain), _})) do
    length(domain)
  end

  def t_fun_range(type) do
    t_fun_range(type, :universe)
  end

  def t_fun_range(type, opaques) do
    do_opaque(type, opaques, &fun_range/1)
  end

  defp fun_range(r_c(tag: :function, elements: {_, range})) do
    range
  end

  def t_is_fun(type) do
    t_is_fun(type, :universe)
  end

  def t_is_fun(type, opaques) do
    do_opaque(type, opaques, &is_fun/1)
  end

  defp is_fun(r_c(tag: :function, elements: {_, _})) do
    true
  end

  defp is_fun(_) do
    false
  end

  def t_identifier() do
    r_c(tag: :identifier, elements: :any)
  end

  def t_is_identifier(r_c(tag: :identifier, elements: _)) do
    true
  end

  def t_is_identifier(_) do
    false
  end

  def t_port() do
    r_c(tag: :identifier, elements: set_singleton(:port))
  end

  def t_is_port(type) do
    t_is_port(type, :universe)
  end

  def t_is_port(type, opaques) do
    do_opaque(type, opaques, &is_port1/1)
  end

  defp is_port1(r_c(tag: :identifier, elements: :any)) do
    false
  end

  defp is_port1(r_c(tag: :identifier, elements: set)) do
    set_is_singleton(:port, set)
  end

  defp is_port1(_) do
    false
  end

  def t_pid() do
    r_c(tag: :identifier, elements: set_singleton(:pid))
  end

  def t_is_pid(type) do
    t_is_pid(type, :universe)
  end

  def t_is_pid(type, opaques) do
    do_opaque(type, opaques, &is_pid1/1)
  end

  defp is_pid1(r_c(tag: :identifier, elements: :any)) do
    false
  end

  defp is_pid1(r_c(tag: :identifier, elements: set)) do
    set_is_singleton(:pid, set)
  end

  defp is_pid1(_) do
    false
  end

  def t_reference() do
    r_c(tag: :identifier, elements: set_singleton(:reference))
  end

  def t_is_reference(type) do
    t_is_reference(type, :universe)
  end

  def t_is_reference(type, opaques) do
    do_opaque(type, opaques, &is_reference1/1)
  end

  defp is_reference1(r_c(tag: :identifier, elements: :any)) do
    false
  end

  defp is_reference1(r_c(tag: :identifier, elements: set)) do
    set_is_singleton(:reference, set)
  end

  defp is_reference1(_) do
    false
  end

  def t_number() do
    r_c(tag: :number, elements: :any, qualifier: :unknown)
  end

  def t_number(x) when is_integer(x) do
    t_integer(x)
  end

  def t_is_number(type) do
    t_is_number(type, :universe)
  end

  def t_is_number(type, opaques) do
    do_opaque(type, opaques, &is_number/1)
  end

  defp is_number(r_c(tag: :number, elements: _, qualifier: _)) do
    true
  end

  defp is_number(_) do
    false
  end

  def t_number_vals(type) do
    t_number_vals(type, :universe)
  end

  def t_number_vals(type, opaques) do
    do_opaque(type, opaques, &number_vals/1)
  end

  defp number_vals(r_c(tag: :number, elements: r_int_set(set: set),
              qualifier: :integer)) do
    set
  end

  defp number_vals(r_c(tag: :number, elements: _, qualifier: _)) do
    :unknown
  end

  defp number_vals(r_c(tag: :opaque, elements: _)) do
    :unknown
  end

  defp number_vals(other) do
    inf = t_inf(other, t_number())
    false = t_is_none(inf)
    number_vals(inf)
  end

  def t_float() do
    r_c(tag: :number, elements: :any, qualifier: :float)
  end

  def t_is_float(type) do
    t_is_float(type, :universe)
  end

  def t_is_float(type, opaques) do
    do_opaque(type, opaques, &is_float1/1)
  end

  defp is_float1(r_c(tag: :number, elements: :any,
              qualifier: :float)) do
    true
  end

  defp is_float1(_) do
    false
  end

  def t_integer() do
    r_c(tag: :number, elements: :any, qualifier: :integer)
  end

  def t_integer(i) when is_integer(i) do
    r_c(tag: :number, elements: r_int_set(set: set_singleton(i)),
        qualifier: :integer)
  end

  def t_integers(list) when is_list(list) do
    t_sup(for i <- list do
            t_integer(i)
          end)
  end

  def t_is_integer(type) do
    t_is_integer(type, :universe)
  end

  def t_is_integer(type, opaques) do
    do_opaque(type, opaques, &is_integer1/1)
  end

  defp is_integer1(r_c(tag: :number, elements: _,
              qualifier: :integer)) do
    true
  end

  defp is_integer1(_) do
    false
  end

  def t_byte() do
    r_c(tag: :number, elements: r_int_rng(from: 0, to: 255),
        qualifier: :integer)
  end

  def t_is_byte(r_c(tag: :number,
             elements: r_int_rng(from: :neg_inf, to: _),
             qualifier: :integer)) do
    false
  end

  def t_is_byte(r_c(tag: :number,
             elements: r_int_rng(from: _, to: :pos_inf),
             qualifier: :integer)) do
    false
  end

  def t_is_byte(r_c(tag: :number, elements: r_int_rng(from: from, to: to),
             qualifier: :integer))
      when (is_integer(from) and from >= 0 and
              is_integer(to) and to <= 255) do
    true
  end

  def t_is_byte(r_c(tag: :number, elements: r_int_set(set: set),
             qualifier: :integer)) do
    set_min(set) >= 0 and set_max(set) <= 255
  end

  def t_is_byte(_) do
    false
  end

  def t_char() do
    r_c(tag: :number, elements: r_int_rng(from: 0, to: 1114111),
        qualifier: :integer)
  end

  def t_is_char(r_c(tag: :number,
             elements: r_int_rng(from: :neg_inf, to: _),
             qualifier: :integer)) do
    false
  end

  def t_is_char(r_c(tag: :number,
             elements: r_int_rng(from: _, to: :pos_inf),
             qualifier: :integer)) do
    false
  end

  def t_is_char(r_c(tag: :number, elements: r_int_rng(from: from, to: to),
             qualifier: :integer))
      when (is_integer(from) and from >= 0 and
              is_integer(to) and to <= 1114111) do
    true
  end

  def t_is_char(r_c(tag: :number, elements: r_int_set(set: set),
             qualifier: :integer)) do
    set_min(set) >= 0 and set_max(set) <= 1114111
  end

  def t_is_char(_) do
    false
  end

  def t_cons() do
    r_c(tag: :list, elements: {:any, :any},
        qualifier: :nonempty)
  end

  def t_cons(:none, _) do
    :none
  end

  def t_cons(_, :none) do
    :none
  end

  def t_cons(:unit, _) do
    :none
  end

  def t_cons(_, :unit) do
    :none
  end

  def t_cons(hd, r_c(tag: nil)) do
    r_c(tag: :list, elements: {hd, r_c(tag: nil)},
        qualifier: :nonempty)
  end

  def t_cons(hd,
           r_c(tag: :list, elements: {contents, termination},
               qualifier: _)) do
    r_c(tag: :list,
        elements: {t_sup(contents, hd), termination},
        qualifier: :nonempty)
  end

  def t_cons(hd, tail) do
    case (cons_tail(t_inf(tail,
                            t_maybe_improper_list()))) do
      r_c(tag: :list, elements: {contents, termination},
          qualifier: _Size) ->
        newTermination = t_sup(t_subtract(tail,
                                            t_maybe_improper_list()),
                                 termination)
        r_c(tag: :list,
            elements: {t_sup(hd, contents), newTermination},
            qualifier: :nonempty)
      r_c(tag: nil) ->
        r_c(tag: :list, elements: {hd, tail},
            qualifier: :nonempty)
      :none ->
        r_c(tag: :list, elements: {hd, tail},
            qualifier: :nonempty)
      :unit ->
        :none
    end
  end

  defp cons_tail(type) do
    do_opaque(type, :universe,
                fn t ->
                     t
                end)
  end

  def t_is_cons(type) do
    t_is_cons(type, :universe)
  end

  def t_is_cons(type, opaques) do
    do_opaque(type, opaques, &is_cons/1)
  end

  defp is_cons(r_c(tag: :list, elements: {_, _},
              qualifier: :nonempty)) do
    true
  end

  defp is_cons(_) do
    false
  end

  def t_cons_hd(type) do
    t_cons_hd(type, :universe)
  end

  def t_cons_hd(type, opaques) do
    do_opaque(type, opaques, &cons_hd/1)
  end

  defp cons_hd(r_c(tag: :list,
              elements: {contents, _Termination},
              qualifier: :nonempty)) do
    contents
  end

  def t_cons_tl(type) do
    t_cons_tl(type, :universe)
  end

  def t_cons_tl(type, opaques) do
    do_opaque(type, opaques, &cons_tl/1)
  end

  defp cons_tl(r_c(tag: :list,
              elements: {_Contents, termination},
              qualifier: :nonempty) = t) do
    t_sup(termination, t)
  end

  def t_nil() do
    r_c(tag: nil)
  end

  def t_is_nil(type) do
    t_is_nil(type, :universe)
  end

  def t_is_nil(type, opaques) do
    do_opaque(type, opaques, &is_nil/1)
  end

  defp is_nil(r_c(tag: nil)) do
    true
  end

  defp is_nil(_) do
    false
  end

  def t_list() do
    r_c(tag: :list, elements: {:any, r_c(tag: nil)},
        qualifier: :unknown)
  end

  def t_list(contents) do
    t_sup(t_nonempty_list(contents), t_nil())
  end

  def t_list_elements(type) do
    t_list_elements(type, :universe)
  end

  def t_list_elements(type, opaques) do
    do_opaque(type, opaques, &list_elements/1)
  end

  defp list_elements(r_c(tag: :list, elements: {contents, _},
              qualifier: _)) do
    contents
  end

  defp list_elements(r_c(tag: nil)) do
    :none
  end

  def t_list_termination(type, opaques) do
    do_opaque(type, opaques, &t_list_termination/1)
  end

  def t_list_termination(r_c(tag: nil)) do
    r_c(tag: nil)
  end

  def t_list_termination(r_c(tag: :list, elements: {_, term},
             qualifier: _)) do
    term
  end

  def t_is_list(r_c(tag: :list, elements: {_Contents, r_c(tag: nil)},
             qualifier: _)) do
    true
  end

  def t_is_list(r_c(tag: nil)) do
    true
  end

  def t_is_list(_) do
    false
  end

  def t_nonempty_list() do
    t_cons(:any, r_c(tag: nil))
  end

  def t_nonempty_list(type) do
    t_cons(type, r_c(tag: nil))
  end

  def t_nonempty_string() do
    t_nonempty_list(t_char())
  end

  def t_string() do
    t_list(t_char())
  end

  def t_is_string(x) do
    t_is_list(x) and t_is_char(t_list_elements(x))
  end

  def t_maybe_improper_list() do
    r_c(tag: :list, elements: {:any, :any},
        qualifier: :unknown)
  end

  defp t_maybe_improper_list(_Content, :unit) do
    :none
  end

  defp t_maybe_improper_list(:unit, _Termination) do
    :none
  end

  defp t_maybe_improper_list(_Content, :none) do
    :none
  end

  defp t_maybe_improper_list(:none, _Termination) do
    :none
  end

  defp t_maybe_improper_list(content, termination) do
    r_c(tag: :list, elements: {content, termination},
        qualifier: :unknown)
  end

  def t_is_maybe_improper_list(type) do
    t_is_maybe_improper_list(type, :universe)
  end

  def t_is_maybe_improper_list(type, opaques) do
    do_opaque(type, opaques, &is_maybe_improper_list/1)
  end

  defp is_maybe_improper_list(r_c(tag: :list, elements: {_, _},
              qualifier: _)) do
    true
  end

  defp is_maybe_improper_list(r_c(tag: nil)) do
    true
  end

  defp is_maybe_improper_list(_) do
    false
  end

  def lift_list_to_pos_empty(type, opaques) do
    do_opaque(type, opaques, &lift_list_to_pos_empty/1)
  end

  def lift_list_to_pos_empty(r_c(tag: nil)) do
    r_c(tag: nil)
  end

  def lift_list_to_pos_empty(r_c(tag: :list, elements: {content, termination},
             qualifier: _)) do
    r_c(tag: :list, elements: {content, termination},
        qualifier: :unknown)
  end

  def t_widen_to_number(:any) do
    :any
  end

  def t_widen_to_number(:none) do
    :none
  end

  def t_widen_to_number(:unit) do
    :unit
  end

  def t_widen_to_number(r_c(tag: :atom, elements: _Set) = t) do
    t
  end

  def t_widen_to_number(r_c(tag: :binary, elements: {_Unit, _Base}) = t) do
    t
  end

  def t_widen_to_number(r_c(tag: :number, elements: :any,
             qualifier: :float)) do
    t_number()
  end

  def t_widen_to_number(r_c(tag: :function, elements: {domain, range})) do
    r_c(tag: :function,
        elements: {t_widen_to_number(domain),
                     t_widen_to_number(range)})
  end

  def t_widen_to_number(r_c(tag: :identifier, elements: _Types) = t) do
    t
  end

  def t_widen_to_number(r_c(tag: :number,
             elements: r_int_rng(from: _From, to: _To),
             qualifier: :integer)) do
    t_number()
  end

  def t_widen_to_number(r_c(tag: :number, elements: r_int_set(set: _Set),
             qualifier: :integer)) do
    t_number()
  end

  def t_widen_to_number(r_c(tag: :number, elements: _Types,
             qualifier: :integer)) do
    t_number()
  end

  def t_widen_to_number(r_c(tag: :list, elements: {type, tail},
             qualifier: size)) do
    r_c(tag: :list,
        elements: {t_widen_to_number(type),
                     t_widen_to_number(tail)},
        qualifier: size)
  end

  def t_widen_to_number(r_c(tag: :map, elements: {pairs, defK, defV})) do
    l = (for {k, mNess, v} <- pairs do
           {t_widen_to_number(k), mNess, t_widen_to_number(v)}
         end)
    t_map(l, t_widen_to_number(defK),
            t_widen_to_number(defV))
  end

  def t_widen_to_number(r_c(tag: nil)) do
    r_c(tag: nil)
  end

  def t_widen_to_number(r_c(tag: :number, elements: _Set,
             qualifier: _Tag)) do
    t_number()
  end

  def t_widen_to_number(r_c(tag: :opaque, elements: set)) do
    l = (for (r_opaque(struct: s) = opaque) <- set do
           r_opaque(opaque, struct: t_widen_to_number(s))
         end)
    r_c(tag: :opaque, elements: :ordsets.from_list(l))
  end

  def t_widen_to_number(r_c(tag: :product, elements: types)) do
    r_c(tag: :product, elements: list_widen_to_number(types))
  end

  def t_widen_to_number(r_c(tag: :tuple, elements: :any,
             qualifier: {_, _}) = t) do
    t
  end

  def t_widen_to_number(r_c(tag: :tuple, elements: types,
             qualifier: {arity, tag})) do
    r_c(tag: :tuple, elements: list_widen_to_number(types),
        qualifier: {arity, tag})
  end

  def t_widen_to_number(r_c(tag: :tuple_set, elements: _) = tuples) do
    t_sup(for t <- t_tuple_subtypes(tuples) do
            t_widen_to_number(t)
          end)
  end

  def t_widen_to_number(r_c(tag: :union, elements: list)) do
    r_c(tag: :union, elements: list_widen_to_number(list))
  end

  def t_widen_to_number(r_c(tag: :var, elements: _Id) = t) do
    t
  end

  defp list_widen_to_number(list) do
    for e <- list do
      t_widen_to_number(e)
    end
  end

  def t_map() do
    t_map([], t_any(), t_any())
  end

  def t_map(l) do
    :lists.foldl(&t_map_put/2, t_map(), l)
  end

  def t_map(pairs0, defK0, defV0) do
    defK1 = :lists.foldl(fn {k, _, _}, acc ->
                              t_subtract(acc, k)
                         end,
                           defK0, pairs0)
    {defK2,
       defV1} = (case (t_is_impossible(defK1) or t_is_impossible(defV0)) do
                   true ->
                     {:none, :none}
                   false ->
                     {defK1, defV0}
                 end)
    {pairs1, defK3,
       defV} = (case (is_singleton_type(defK2)) do
                  true ->
                    {mapdict_insert({defK2, :optional, defV1}, pairs0),
                       :none, :none}
                  false ->
                    {pairs0, defK2, defV1}
                end)
    {pairs, defK} = normalise_map_optionals(pairs1, defK3,
                                              defV)
    try do
      validate_map_elements(pairs)
    catch
      :error, :badarg ->
        :erlang.error(:badarg, [pairs0, defK0, defV0])
    end
    case (map_pairs_are_none(pairs)) do
      true ->
        :none
      false ->
        r_c(tag: :map, elements: {pairs, defK, defV})
    end
  end

  defp normalise_map_optionals(pairs, defK, defV) do
    case (normalise_map_optionals(pairs, defK, defV, [],
                                    :defk_unchanged)) do
      {pairs1, defK1, :defk_changed} ->
        normalise_map_optionals(pairs1, defK1, defV)
      {pairs1, defK1, :defk_unchanged} ->
        {pairs1, defK1}
    end
  end

  defp normalise_map_optionals([], defK, _, es, f) do
    {:lists.reverse(es), defK, f}
  end

  defp normalise_map_optionals([e = {k, :optional, :none} | t], defK, defV, es,
            f) do
    diff = t_subtract(defK, k)
    case (t_is_subtype(k, defK) and defK === diff) do
      true ->
        normalise_map_optionals(t, defK, defV, [e | es], f)
      false ->
        normalise_map_optionals(t, diff, defV, es, f)
    end
  end

  defp normalise_map_optionals([e = {k, :optional, v} | t], defK, defV, es,
            f) do
    howToHandleE = (case (t_is_equal(v, defV)) do
                      true ->
                        case (t_is_subtype(k, defK)) do
                          true ->
                            :skip
                          false ->
                            case (needs_to_be_merged(k, defK)) do
                              true ->
                                :add_to_default_key
                              false ->
                                :keep
                            end
                        end
                      false ->
                        :keep
                    end)
    case (howToHandleE) do
      :skip ->
        normalise_map_optionals(t, defK, defV, es, f)
      :keep ->
        normalise_map_optionals(t, defK, defV, [e | es], f)
      :add_to_default_key ->
        normalise_map_optionals(t, t_sup(k, defK), defV, es,
                                  :defk_changed)
    end
  end

  defp normalise_map_optionals([e | t], defK, defV, es, f) do
    normalise_map_optionals(t, defK, defV, [e | es], f)
  end

  defp needs_to_be_merged(r_c(tag: :number, elements: r_int_set(set: set),
              qualifier: :integer),
            defK) do
    [i] = set
    iplus = t_integer(i + 1)
    iminus = t_integer(i - 1)
    infPlus = t_inf(iplus, defK)
    infMinus = t_inf(iminus, defK)
    not (t_is_none(infPlus) and t_is_none(infMinus))
  end

  defp needs_to_be_merged(r_c(tag: :atom, elements: _Set), defK) do
    infAtom = t_inf(t_atom(), defK)
    not t_is_none(infAtom)
  end

  defp needs_to_be_merged(r_c(tag: nil), defK) do
    infNonEmpty = t_inf(t_nonempty_list(), defK)
    t_is_cons(infNonEmpty)
  end

  defp needs_to_be_merged(_, _) do
    false
  end

  defp validate_map_elements([{k1, _, _} | rest = [{k2, _, _} | _]]) do
    case (is_singleton_type(k1) and k1 < k2) do
      false ->
        :erlang.error(:badarg)
      true ->
        validate_map_elements(rest)
    end
  end

  defp validate_map_elements([{k, _, _}]) do
    case (is_singleton_type(k)) do
      false ->
        :erlang.error(:badarg)
      true ->
        true
    end
  end

  defp validate_map_elements([]) do
    true
  end

  defp map_pairs_are_none([]) do
    false
  end

  defp map_pairs_are_none([{_, :mandatory, :none} | _]) do
    true
  end

  defp map_pairs_are_none([_ | ps]) do
    map_pairs_are_none(ps)
  end

  def t_is_map(type) do
    t_is_map(type, :universe)
  end

  def t_is_map(type, opaques) do
    do_opaque(type, opaques, &is_map1/1)
  end

  defp is_map1(r_c(tag: :map, elements: {_, _, _})) do
    true
  end

  defp is_map1(_) do
    false
  end

  def t_map_entries(m) do
    t_map_entries(m, :universe)
  end

  def t_map_entries(m, opaques) do
    do_opaque(m, opaques, &map_entries/1)
  end

  defp map_entries(r_c(tag: :map, elements: {pairs, _, _})) do
    pairs
  end

  def t_map_def_key(m) do
    t_map_def_key(m, :universe)
  end

  def t_map_def_key(m, opaques) do
    do_opaque(m, opaques, &map_def_key/1)
  end

  defp map_def_key(r_c(tag: :map, elements: {_, defK, _})) do
    defK
  end

  def t_map_def_val(m) do
    t_map_def_val(m, :universe)
  end

  def t_map_def_val(m, opaques) do
    do_opaque(m, opaques, &map_def_val/1)
  end

  defp map_def_val(r_c(tag: :map, elements: {_, _, defV})) do
    defV
  end

  defp mapdict_store(e = {k, _, _}, [{k, _, _} | t]) do
    [e | t]
  end

  defp mapdict_store(e1 = {k1, _, _}, [e2 = {k2, _, _} | t])
      when k1 > k2 do
    [e2 | mapdict_store(e1, t)]
  end

  defp mapdict_store(e = {_, _, _}, t) do
    [e | t]
  end

  defp mapdict_insert(e = {k, _, _}, d = [{k, _, _} | _]) do
    :erlang.error(:badarg, [e, d])
  end

  defp mapdict_insert(e1 = {k1, _, _}, [e2 = {k2, _, _} | t])
      when k1 > k2 do
    [e2 | mapdict_insert(e1, t)]
  end

  defp mapdict_insert(e = {_, _, _}, t) do
    [e | t]
  end

  def t_map_pairwise_merge(f, mapA, mapB, opaques) do
    do_opaque(mapA, opaques,
                fn uMapA ->
                     do_opaque(mapB, opaques,
                                 fn uMapB ->
                                      map_pairwise_merge(f, uMapA, uMapB)
                                 end)
                end)
  end

  defp map_pairwise_merge(f,
            r_c(tag: :map, elements: {aPairs, aDefK, aDefV}),
            r_c(tag: :map, elements: {bPairs, bDefK, bDefV})) do
    map_pairwise_merge(f, aPairs, aDefK, aDefV, bPairs,
                         bDefK, bDefV)
  end

  defp map_pairwise_merge(_, [], _, _, [], _, _) do
    []
  end

  defp map_pairwise_merge(f, as0, aDefK, aDefV, bs0, bDefK, bDefV) do
    {k1, aMNess1, aV1, as1, bMNess1, bV1,
       bs1} = (case ({as0, bs0}) do
                 {[{k, aMNess, aV} | as], [{k, bMNess, bV} | bs]} ->
                   {k, aMNess, aV, as, bMNess, bV, bs}
                 {[{k, aMNess, aV} | as], [{bK, _, _} | _] = bs}
                     when k < bK ->
                   {k, aMNess, aV, as, :optional,
                      mapmerge_otherv(k, bDefK, bDefV), bs}
                 {as, [{k, bMNess, bV} | bs]} ->
                   {k, :optional, mapmerge_otherv(k, aDefK, aDefV), as,
                      bMNess, bV, bs}
                 {[{k, aMNess, aV} | as], [] = bs} ->
                   {k, aMNess, aV, as, :optional,
                      mapmerge_otherv(k, bDefK, bDefV), bs}
               end)
    mK = k1
    case (f.(k1, aMNess1, aV1, bMNess1, bV1)) do
      false ->
        map_pairwise_merge(f, as1, aDefK, aDefV, bs1, bDefK,
                             bDefV)
      {^mK, _, _} = m ->
        [m | map_pairwise_merge(f, as1, aDefK, aDefV, bs1,
                                  bDefK, bDefV)]
    end
  end

  defp map_pairwise_merge_foldr(f, accIn,
            r_c(tag: :map, elements: {aPairs, aDefK, aDefV}),
            r_c(tag: :map, elements: {bPairs, bDefK, bDefV})) do
    map_pairwise_merge_foldr(f, accIn, aPairs, aDefK, aDefV,
                               bPairs, bDefK, bDefV)
  end

  defp map_pairwise_merge_foldr(_, acc, [], _, _, [], _, _) do
    acc
  end

  defp map_pairwise_merge_foldr(f, accIn, as0, aDefK, aDefV, bs0, bDefK,
            bDefV) do
    {k1, aMNess1, aV1, as1, bMNess1, bV1,
       bs1} = (case ({as0, bs0}) do
                 {[{k, aMNess, aV} | as], [{k, bMNess, bV} | bs]} ->
                   {k, aMNess, aV, as, bMNess, bV, bs}
                 {[{k, aMNess, aV} | as], [{bK, _, _} | _] = bs}
                     when k < bK ->
                   {k, aMNess, aV, as, :optional,
                      mapmerge_otherv(k, bDefK, bDefV), bs}
                 {as, [{k, bMNess, bV} | bs]} ->
                   {k, :optional, mapmerge_otherv(k, aDefK, aDefV), as,
                      bMNess, bV, bs}
                 {[{k, aMNess, aV} | as], [] = bs} ->
                   {k, aMNess, aV, as, :optional,
                      mapmerge_otherv(k, bDefK, bDefV), bs}
               end)
    f.(k1, aMNess1, aV1, bMNess1, bV1,
         map_pairwise_merge_foldr(f, accIn, as1, aDefK, aDefV,
                                    bs1, bDefK, bDefV))
  end

  defp mapmerge_otherv(k, oDefK, oDefV) do
    case (t_inf(k, oDefK)) do
      :none ->
        :none
      _KOrOpaque ->
        oDefV
    end
  end

  def t_map_put(kV, map) do
    t_map_put(kV, map, :universe)
  end

  def t_map_put(kV, map, opaques) do
    do_opaque(map, opaques,
                fn uM ->
                     map_put(kV, uM, opaques)
                end)
  end

  defp map_put(_, :none, _) do
    :none
  end

  defp map_put(_, :unit, _) do
    :none
  end

  defp map_put({key, value},
            r_c(tag: :map, elements: {pairs, defK, defV}), opaques) do
    case (t_is_impossible(key) or t_is_impossible(value)) do
      true ->
        :none
      false ->
        case (is_singleton_type(key)) do
          true ->
            t_map(mapdict_store({key, :mandatory, value}, pairs),
                    defK, defV)
          false ->
            t_map(for {k, mNess, v} <- pairs do
                    {k, mNess,
                       case (t_is_none(t_inf(k, key, opaques))) do
                         true ->
                           v
                         false ->
                           t_sup(v, value)
                       end}
                  end,
                    t_sup(defK, key), t_sup(defV, value))
        end
    end
  end

  def t_map_remove(key, map, opaques) do
    do_opaque(map, opaques,
                fn uM ->
                     map_remove(key, uM)
                end)
  end

  defp map_remove(_, :none) do
    :none
  end

  defp map_remove(_, :unit) do
    :none
  end

  defp map_remove(key, map) do
    case (is_singleton_type(key)) do
      false ->
        map
      true ->
        r_c(tag: :map, elements: {pairs, defK, defV}) = map
        case (:lists.keyfind(key, 1, pairs)) do
          false ->
            map
          {^key, _, _} ->
            pairs1 = :lists.keydelete(key, 1, pairs)
            t_map(pairs1, defK, defV)
        end
    end
  end

  def t_map_update(kV, map) do
    t_map_update(kV, map, :universe)
  end

  def t_map_update(_, :none, _) do
    :none
  end

  def t_map_update(_, :unit, _) do
    :none
  end

  def t_map_update(kV = {key, _}, m, opaques) do
    case (t_is_subtype(t_atom(true),
                         t_map_is_key(key, m, opaques))) do
      false ->
        :none
      true ->
        t_map_put(kV, m, opaques)
    end
  end

  def t_map_get(key, map) do
    t_map_get(key, map, :universe)
  end

  def t_map_get(key, map, opaques) do
    do_opaque(map, opaques,
                fn uM ->
                     do_opaque(key, opaques,
                                 fn uK ->
                                      :erlang.map_get(uK, uM)
                                 end)
                end)
  end

  defp map_get(_, :none) do
    :none
  end

  defp map_get(_, :unit) do
    :none
  end

  defp map_get(key,
            r_c(tag: :map, elements: {pairs, defK, defV})) do
    defRes = (case (t_do_overlap(defK, key)) do
                false ->
                  t_none()
                true ->
                  defV
              end)
    case (is_singleton_type(key)) do
      false ->
        :lists.foldl(fn {k, _, v}, res ->
                          case (t_do_overlap(k, key)) do
                            false ->
                              res
                            true ->
                              t_sup(res, v)
                          end
                     end,
                       defRes, pairs)
      true ->
        case (:lists.keyfind(key, 1, pairs)) do
          false ->
            defRes
          {_, _, valType} ->
            valType
        end
    end
  end

  def t_map_is_key(key, map) do
    t_map_is_key(key, map, :universe)
  end

  def t_map_is_key(key, map, opaques) do
    do_opaque(map, opaques,
                fn uM ->
                     do_opaque(key, opaques,
                                 fn uK ->
                                      map_is_key(uK, uM)
                                 end)
                end)
  end

  defp map_is_key(_, :none) do
    :none
  end

  defp map_is_key(_, :unit) do
    :none
  end

  defp map_is_key(key,
            r_c(tag: :map, elements: {pairs, defK, _DefV})) do
    case (is_singleton_type(key)) do
      true ->
        case (:lists.keyfind(key, 1, pairs)) do
          {^key, :mandatory, _} ->
            t_atom(true)
          {^key, :optional, :none} ->
            t_atom(false)
          {^key, :optional, _} ->
            t_boolean()
          false ->
            case (t_do_overlap(defK, key)) do
              false ->
                t_atom(false)
              true ->
                t_boolean()
            end
        end
      false ->
        case (t_do_overlap(defK, key) or :lists.any(fn {_, _,
                                                          :none} ->
                                                         false
                                                       {k, _, _} ->
                                                         t_do_overlap(k, key)
                                                    end,
                                                      pairs)) do
          true ->
            t_boolean()
          false ->
            t_atom(false)
        end
    end
  end

  def t_tuple() do
    r_c(tag: :tuple, elements: :any, qualifier: {:any, :any})
  end

  def t_tuple(n) when (is_integer(n) and n > 1 <<< 10) do
    t_tuple()
  end

  def t_tuple(n) when is_integer(n) do
    r_c(tag: :tuple, elements: :lists.duplicate(n, :any),
        qualifier: {n, :any})
  end

  def t_tuple(list) do
    case (any_none_or_unit(list)) do
      true ->
        t_none()
      false ->
        arity = length(list)
        case (get_tuple_tags(list)) do
          [tag] ->
            r_c(tag: :tuple, elements: list, qualifier: {arity, tag})
          tagList ->
            sortedTagList = :lists.sort(tagList)
            tuples = (for t <- sortedTagList do
                        r_c(tag: :tuple, elements: [t | tl(list)],
                            qualifier: {arity, t})
                      end)
            r_c(tag: :tuple_set, elements: [{arity, tuples}])
        end
    end
  end

  defp get_tuple_tags([tag | _]) do
    do_opaque(tag, :universe, &tuple_tags/1)
  end

  defp get_tuple_tags(_) do
    [:any]
  end

  defp tuple_tags(r_c(tag: :atom, elements: :any)) do
    [:any]
  end

  defp tuple_tags(r_c(tag: :atom, elements: set)) do
    case (length(set) > 5) do
      true ->
        [:any]
      false ->
        for a <- set do
          t_atom(a)
        end
    end
  end

  defp tuple_tags(_) do
    [:any]
  end

  def t_tuple_args(type) do
    t_tuple_args(type, :universe)
  end

  def t_tuple_args(type, opaques) do
    do_opaque(type, opaques, &tuple_args/1)
  end

  defp tuple_args(r_c(tag: :tuple, elements: args,
              qualifier: {_, _}))
      when is_list(args) do
    args
  end

  def t_tuple_size(type) do
    t_tuple_size(type, :universe)
  end

  def t_tuple_size(type, opaques) do
    do_opaque(type, opaques, &tuple_size1/1)
  end

  defp tuple_size1(r_c(tag: :tuple, elements: _,
              qualifier: {size, _}))
      when is_integer(size) do
    size
  end

  def t_tuple_sizes(type) do
    do_opaque(type, :universe, &tuple_sizes/1)
  end

  defp tuple_sizes(r_c(tag: :tuple, elements: :any,
              qualifier: {:any, :any})) do
    :unknown
  end

  defp tuple_sizes(r_c(tag: :tuple, elements: _,
              qualifier: {size, _}))
      when is_integer(size) do
    [size]
  end

  defp tuple_sizes(r_c(tag: :tuple_set, elements: list)) do
    for {size, _} <- list do
      size
    end
  end

  def t_tuple_subtypes(type, opaques) do
    fun = fn r_c(tag: :tuple_set, elements: list) ->
               t_tuple_subtypes_tuple_list(list, opaques)
             r_c(tag: :opaque, elements: _) ->
               :unknown
             t ->
               t_tuple_subtypes(t)
          end
    do_opaque(type, opaques, fun)
  end

  defp t_tuple_subtypes_tuple_list(list, opaques) do
    :lists.append(for {_Size, tuples} <- list do
                    t_tuple_subtypes_list(tuples, opaques)
                  end)
  end

  defp t_tuple_subtypes_list(list, opaques) do
    listOfLists = (for e <- list, e !== :none do
                     t_tuple_subtypes(e, opaques)
                   end)
    :lists.append(for l <- listOfLists, l !== :unknown do
                    l
                  end)
  end

  def t_tuple_subtypes(r_c(tag: :tuple, elements: :any,
             qualifier: {:any, :any})) do
    :unknown
  end

  def t_tuple_subtypes(r_c(tag: :tuple, elements: _,
             qualifier: {_, _}) = t) do
    [t]
  end

  def t_tuple_subtypes(r_c(tag: :tuple_set, elements: list)) do
    :lists.append(for {_Size, tuples} <- list do
                    tuples
                  end)
  end

  def t_is_tuple(type) do
    t_is_tuple(type, :universe)
  end

  def t_is_tuple(type, opaques) do
    do_opaque(type, opaques, &is_tuple1/1)
  end

  defp is_tuple1(r_c(tag: :tuple, elements: _,
              qualifier: {_, _})) do
    true
  end

  defp is_tuple1(r_c(tag: :tuple_set, elements: _)) do
    true
  end

  defp is_tuple1(_) do
    false
  end

  def t_bitstrlist() do
    t_iolist(1, t_bitstr())
  end

  def t_arity() do
    t_from_range(0, 255)
  end

  def t_pos_integer() do
    t_from_range(1, :pos_inf)
  end

  def t_non_neg_integer() do
    t_from_range(0, :pos_inf)
  end

  def t_is_non_neg_integer(r_c(tag: :number, elements: _,
             qualifier: :integer) = t) do
    t_is_subtype(t, t_non_neg_integer())
  end

  def t_is_non_neg_integer(_) do
    false
  end

  def t_neg_integer() do
    t_from_range(:neg_inf, - 1)
  end

  def t_fixnum() do
    t_integer()
  end

  def t_pos_fixnum() do
    t_pos_integer()
  end

  def t_non_neg_fixnum() do
    t_non_neg_integer()
  end

  def t_mfa() do
    t_tuple([t_atom(), t_atom(), t_arity()])
  end

  def t_module() do
    t_atom()
  end

  def t_node() do
    t_atom()
  end

  def t_iodata() do
    t_sup(t_iolist(), t_binary())
  end

  def t_iolist() do
    t_iolist(1, t_binary())
  end

  defp t_iolist(n, t) when n > 0 do
    t_maybe_improper_list(t_sup([t_iolist(n - 1, t), t,
                                                         t_byte()]),
                            t_sup(t, t_nil()))
  end

  defp t_iolist(0, t) do
    t_maybe_improper_list(t_any(), t_sup(t, t_nil()))
  end

  def t_timeout() do
    t_sup(t_non_neg_integer(), t_atom(:infinity))
  end

  def t_product([t]) do
    t
  end

  def t_product(types) when is_list(types) do
    r_c(tag: :product, elements: types)
  end

  def t_to_tlist(r_c(tag: :product, elements: types)) do
    types
  end

  def t_to_tlist(t)
      when t !== :any or t !== :none or t !== :unit do
    [t]
  end

  def t_var(atom) when is_atom(atom) do
    r_c(tag: :var, elements: atom)
  end

  def t_var(int) when is_integer(int) do
    r_c(tag: :var, elements: int)
  end

  def t_is_var(r_c(tag: :var, elements: _)) do
    true
  end

  def t_is_var(_) do
    false
  end

  def t_var_name(r_c(tag: :var, elements: id)) do
    id
  end

  def t_has_var(r_c(tag: :var, elements: _)) do
    true
  end

  def t_has_var(r_c(tag: :function, elements: {domain, range})) do
    t_has_var(domain) or t_has_var(range)
  end

  def t_has_var(r_c(tag: :list, elements: {contents, r_c(tag: nil)},
             qualifier: _)) do
    t_has_var(contents)
  end

  def t_has_var(r_c(tag: :list, elements: {contents, termination},
             qualifier: _)) do
    t_has_var(contents) or t_has_var(termination)
  end

  def t_has_var(r_c(tag: :product, elements: types)) do
    t_has_var_list(types)
  end

  def t_has_var(r_c(tag: :tuple, elements: :any,
             qualifier: {:any, :any})) do
    false
  end

  def t_has_var(r_c(tag: :tuple, elements: elements,
             qualifier: {_, _})) do
    t_has_var_list(elements)
  end

  def t_has_var(r_c(tag: :tuple_set, elements: _) = t) do
    t_has_var_list(t_tuple_subtypes(t))
  end

  def t_has_var(r_c(tag: :map, elements: {_, defK, _}) = map) do
    t_has_var_list(map_all_values(map)) or t_has_var(defK)
  end

  def t_has_var(r_c(tag: :opaque, elements: set)) do
    t_has_var_list(for o <- set do
                     r_opaque(o, :struct)
                   end)
  end

  def t_has_var(r_c(tag: :union, elements: list)) do
    t_has_var_list(list)
  end

  def t_has_var(_) do
    false
  end

  defp t_has_var_list([t | ts]) do
    t_has_var(t) or t_has_var_list(ts)
  end

  defp t_has_var_list([]) do
    false
  end

  def t_collect_var_names(t) do
    t_collect_var_names(t, [])
  end

  defp t_collect_var_names(r_c(tag: :var, elements: id), acc) do
    :ordsets.add_element(id, acc)
  end

  defp t_collect_var_names(r_c(tag: :function, elements: {domain, range}),
            acc) do
    acc1 = t_collect_var_names(domain, acc)
    t_collect_var_names(range, acc1)
  end

  defp t_collect_var_names(r_c(tag: :list, elements: {contents, termination},
              qualifier: _),
            acc) do
    acc1 = t_collect_var_names(contents, acc)
    t_collect_var_names(termination, acc1)
  end

  defp t_collect_var_names(r_c(tag: :product, elements: types), acc) do
    t_collect_vars_list(types, acc)
  end

  defp t_collect_var_names(r_c(tag: :tuple, elements: :any,
              qualifier: {:any, :any}),
            acc) do
    acc
  end

  defp t_collect_var_names(r_c(tag: :tuple, elements: types,
              qualifier: {_, _}),
            acc) do
    t_collect_vars_list(types, acc)
  end

  defp t_collect_var_names(r_c(tag: :tuple_set, elements: _) = tS, acc) do
    t_collect_vars_list(t_tuple_subtypes(tS), acc)
  end

  defp t_collect_var_names(r_c(tag: :map, elements: {_, defK, _}) = map,
            acc0) do
    acc = t_collect_vars_list(map_all_values(map), acc0)
    t_collect_var_names(defK, acc)
  end

  defp t_collect_var_names(r_c(tag: :opaque, elements: set), acc) do
    t_collect_vars_list(for o <- set do
                          r_opaque(o, :struct)
                        end,
                          acc)
  end

  defp t_collect_var_names(r_c(tag: :union, elements: list), acc) do
    t_collect_vars_list(list, acc)
  end

  defp t_collect_var_names(_, acc) do
    acc
  end

  defp t_collect_vars_list([t | ts], acc0) do
    acc = t_collect_var_names(t, acc0)
    t_collect_vars_list(ts, acc)
  end

  defp t_collect_vars_list([], acc) do
    acc
  end

  def t_from_range(:pos_inf, :pos_inf) do
    r_c(tag: :number, elements: r_int_rng(from: 1, to: :pos_inf),
        qualifier: :integer)
  end

  def t_from_range(:neg_inf, :neg_inf) do
    r_c(tag: :number, elements: r_int_rng(from: :neg_inf, to: - 1),
        qualifier: :integer)
  end

  def t_from_range(:neg_inf, :pos_inf) do
    t_integer()
  end

  def t_from_range(:neg_inf, y) when (is_integer(y) and y < 0) do
    r_c(tag: :number, elements: r_int_rng(from: :neg_inf, to: - 1),
        qualifier: :integer)
  end

  def t_from_range(:neg_inf, y) when (is_integer(y) and y >= 0) do
    t_integer()
  end

  def t_from_range(x, :pos_inf) when (is_integer(x) and x >= 1) do
    r_c(tag: :number, elements: r_int_rng(from: 1, to: :pos_inf),
        qualifier: :integer)
  end

  def t_from_range(x, :pos_inf) when (is_integer(x) and x >= 0) do
    r_c(tag: :number, elements: r_int_rng(from: 0, to: :pos_inf),
        qualifier: :integer)
  end

  def t_from_range(x, :pos_inf) when (is_integer(x) and x < 0) do
    t_integer()
  end

  def t_from_range(x, y) when (is_integer(x) and is_integer(y) and
                       x > y) do
    t_none()
  end

  def t_from_range(x, y) when (is_integer(x) and is_integer(y)) do
    case (y - x < 13) do
      true ->
        t_integers(:lists.seq(x, y))
      false ->
        case (x >= 0) do
          false ->
            cond do
              y < 0 ->
                r_c(tag: :number, elements: r_int_rng(from: :neg_inf, to: - 1),
                    qualifier: :integer)
              true ->
                t_integer()
            end
          true ->
            cond do
              (y <= 255 and x >= 1) ->
                r_c(tag: :number, elements: r_int_rng(from: 1, to: 255),
                    qualifier: :integer)
              y <= 255 ->
                t_byte()
              (y <= 1114111 and x >= 1) ->
                r_c(tag: :number, elements: r_int_rng(from: 1, to: 1114111),
                    qualifier: :integer)
              y <= 1114111 ->
                t_char()
              x >= 1 ->
                r_c(tag: :number, elements: r_int_rng(from: 1, to: :pos_inf),
                    qualifier: :integer)
              x >= 0 ->
                r_c(tag: :number, elements: r_int_rng(from: 0, to: :pos_inf),
                    qualifier: :integer)
            end
        end
    end
  end

  def t_from_range(:pos_inf, :neg_inf) do
    t_none()
  end

  def number_min(type) do
    number_min(type, :universe)
  end

  def number_min(type, opaques) do
    do_opaque(type, opaques, &number_min2/1)
  end

  defp number_min2(r_c(tag: :number, elements: r_int_rng(from: from, to: _),
              qualifier: :integer)) do
    from
  end

  defp number_min2(r_c(tag: :number, elements: r_int_set(set: set),
              qualifier: :integer)) do
    set_min(set)
  end

  defp number_min2(r_c(tag: :number, elements: :any,
              qualifier: _Tag)) do
    :neg_inf
  end

  def number_max(type) do
    number_max(type, :universe)
  end

  def number_max(type, opaques) do
    do_opaque(type, opaques, &number_max2/1)
  end

  defp number_max2(r_c(tag: :number, elements: r_int_rng(from: _, to: to),
              qualifier: :integer)) do
    to
  end

  defp number_max2(r_c(tag: :number, elements: r_int_set(set: set),
              qualifier: :integer)) do
    set_max(set)
  end

  defp number_max2(r_c(tag: :number, elements: :any,
              qualifier: _Tag)) do
    :pos_inf
  end

  defp in_range(_,
            r_c(tag: :number,
                elements: r_int_rng(from: :neg_inf, to: :pos_inf),
                qualifier: :integer)) do
    true
  end

  defp in_range(x,
            r_c(tag: :number, elements: r_int_rng(from: from, to: :pos_inf),
                qualifier: :integer)) do
    x >= from
  end

  defp in_range(x,
            r_c(tag: :number, elements: r_int_rng(from: :neg_inf, to: to),
                qualifier: :integer)) do
    x <= to
  end

  defp in_range(x,
            r_c(tag: :number, elements: r_int_rng(from: from, to: to),
                qualifier: :integer)) do
    x >= from and x <= to
  end

  def min(:neg_inf, _) do
    :neg_inf
  end

  def min(_, :neg_inf) do
    :neg_inf
  end

  def min(:pos_inf, y) do
    y
  end

  def min(x, :pos_inf) do
    x
  end

  def min(x, y) when x <= y do
    x
  end

  def min(_, y) do
    y
  end

  def max(:neg_inf, y) do
    y
  end

  def max(x, :neg_inf) do
    x
  end

  def max(:pos_inf, _) do
    :pos_inf
  end

  def max(_, :pos_inf) do
    :pos_inf
  end

  def max(x, y) when x <= y do
    y
  end

  def max(x, _) do
    x
  end

  defp expand_range_from_set(range = r_c(tag: :number,
                      elements: r_int_rng(from: from, to: to), qualifier: :integer),
            set) do
    min = min(set_min(set), from)
    max = max(set_max(set), to)
    cond do
      (from === min and to === max) ->
        range
      true ->
        t_from_range(min, max)
    end
  end

  def t_sup([]) do
    :none
  end

  def t_sup(ts) do
    case (any_any(ts)) do
      true ->
        :any
      false ->
        [type | newTs] = ts
        t_sup1(newTs, type)
    end
  end

  defp any_any([:any | _]) do
    true
  end

  defp any_any([_ | t]) do
    any_any(t)
  end

  defp any_any([]) do
    false
  end

  defp t_sup1([h | t], type) do
    t_sup1(t, t_sup(h, type))
  end

  defp t_sup1([], type) do
    do_not_subst_all_vars_to_any(type)
  end

  def t_sup(:any, _) do
    :any
  end

  def t_sup(_, :any) do
    :any
  end

  def t_sup(:none, t) do
    t
  end

  def t_sup(t, :none) do
    t
  end

  def t_sup(:unit, t) do
    t
  end

  def t_sup(t, :unit) do
    t
  end

  def t_sup(t, t) do
    do_not_subst_all_vars_to_any(t)
  end

  def t_sup(r_c(tag: :var, elements: _), _) do
    :any
  end

  def t_sup(_, r_c(tag: :var, elements: _)) do
    :any
  end

  def t_sup(r_c(tag: :atom, elements: set1),
           r_c(tag: :atom, elements: set2)) do
    r_c(tag: :atom, elements: set_union(set1, set2))
  end

  def t_sup(r_c(tag: :binary, elements: {u1, b1}),
           r_c(tag: :binary, elements: {u2, b2})) do
    t_bitstr(gcd(gcd(u1, u2), abs(b1 - b2)),
               :lists.min([b1, b2]))
  end

  def t_sup(r_c(tag: :function, elements: {domain1, range1}),
           r_c(tag: :function, elements: {domain2, range2})) do
    r_c(tag: :function,
        elements: {t_sup(domain1, domain2),
                     t_sup(range1, range2)})
  end

  def t_sup(r_c(tag: :identifier, elements: set1),
           r_c(tag: :identifier, elements: set2)) do
    r_c(tag: :identifier, elements: set_union(set1, set2))
  end

  def t_sup(r_c(tag: :opaque, elements: set1),
           r_c(tag: :opaque, elements: set2)) do
    sup_opaque(:ordsets.union(set1, set2))
  end

  def t_sup(r_c(tag: nil),
           r_c(tag: :list, elements: {contents, termination},
               qualifier: _)) do
    r_c(tag: :list,
        elements: {contents, t_sup(r_c(tag: nil), termination)},
        qualifier: :unknown)
  end

  def t_sup(r_c(tag: :list, elements: {contents, termination},
             qualifier: _),
           r_c(tag: nil)) do
    r_c(tag: :list,
        elements: {contents, t_sup(r_c(tag: nil), termination)},
        qualifier: :unknown)
  end

  def t_sup(r_c(tag: :list,
             elements: {contents1, termination1}, qualifier: size1),
           r_c(tag: :list, elements: {contents2, termination2},
               qualifier: size2)) do
    newSize = (case ({size1, size2}) do
                 {:unknown, :unknown} ->
                   :unknown
                 {:unknown, :nonempty} ->
                   :unknown
                 {:nonempty, :unknown} ->
                   :unknown
                 {:nonempty, :nonempty} ->
                   :nonempty
               end)
    newContents = t_sup(contents1, contents2)
    newTermination = t_sup(termination1, termination2)
    r_c(tag: :list, elements: {newContents, newTermination},
        qualifier: newSize)
  end

  def t_sup(r_c(tag: :number, elements: _, qualifier: _),
           r_c(tag: :number, elements: :any,
               qualifier: :unknown) = t) do
    t
  end

  def t_sup(r_c(tag: :number, elements: :any,
             qualifier: :unknown) = t,
           r_c(tag: :number, elements: _, qualifier: _)) do
    t
  end

  def t_sup(r_c(tag: :number, elements: :any,
             qualifier: :float),
           r_c(tag: :number, elements: _, qualifier: :integer)) do
    t_number()
  end

  def t_sup(r_c(tag: :number, elements: _,
             qualifier: :integer),
           r_c(tag: :number, elements: :any, qualifier: :float)) do
    t_number()
  end

  def t_sup(r_c(tag: :number, elements: :any,
             qualifier: :integer) = t,
           r_c(tag: :number, elements: _, qualifier: :integer)) do
    t
  end

  def t_sup(r_c(tag: :number, elements: _,
             qualifier: :integer),
           r_c(tag: :number, elements: :any,
               qualifier: :integer) = t) do
    t
  end

  def t_sup(r_c(tag: :number, elements: r_int_set(set: set1),
             qualifier: :integer),
           r_c(tag: :number, elements: r_int_set(set: set2),
               qualifier: :integer)) do
    case (set_union(set1, set2)) do
      :any ->
        t_from_range(min(set_min(set1), set_min(set2)),
                       max(set_max(set1), set_max(set2)))
      set ->
        r_c(tag: :number, elements: r_int_set(set: set),
            qualifier: :integer)
    end
  end

  def t_sup(r_c(tag: :number,
             elements: r_int_rng(from: from1, to: to1), qualifier: :integer),
           r_c(tag: :number, elements: r_int_rng(from: from2, to: to2),
               qualifier: :integer)) do
    t_from_range(min(from1, from2), max(to1, to2))
  end

  def t_sup(range = r_c(tag: :number,
                     elements: r_int_rng(from: _, to: _), qualifier: :integer),
           r_c(tag: :number, elements: r_int_set(set: set),
               qualifier: :integer)) do
    expand_range_from_set(range, set)
  end

  def t_sup(r_c(tag: :number, elements: r_int_set(set: set),
             qualifier: :integer),
           range = r_c(tag: :number, elements: r_int_rng(from: _, to: _),
                       qualifier: :integer)) do
    expand_range_from_set(range, set)
  end

  def t_sup(r_c(tag: :product, elements: types1),
           r_c(tag: :product, elements: types2)) do
    l1 = length(types1)
    l2 = length(types2)
    cond do
      l1 === l2 ->
        r_c(tag: :product, elements: t_sup_lists(types1, types2))
      true ->
        :any
    end
  end

  def t_sup(r_c(tag: :product, elements: _), _) do
    :any
  end

  def t_sup(_, r_c(tag: :product, elements: _)) do
    :any
  end

  def t_sup(r_c(tag: :tuple, elements: :any,
             qualifier: {:any, :any}) = t,
           r_c(tag: :tuple, elements: _, qualifier: {_, _})) do
    t
  end

  def t_sup(r_c(tag: :tuple, elements: _, qualifier: {_, _}),
           r_c(tag: :tuple, elements: :any,
               qualifier: {:any, :any}) = t) do
    t
  end

  def t_sup(r_c(tag: :tuple, elements: :any,
             qualifier: {:any, :any}) = t,
           r_c(tag: :tuple_set, elements: _)) do
    t
  end

  def t_sup(r_c(tag: :tuple_set, elements: _),
           r_c(tag: :tuple, elements: :any,
               qualifier: {:any, :any}) = t) do
    t
  end

  def t_sup(r_c(tag: :tuple, elements: elements1,
             qualifier: {arity, tag1}) = t1,
           r_c(tag: :tuple, elements: elements2,
               qualifier: {arity, tag2}) = t2) do
    cond do
      tag1 == tag2 ->
        t_tuple(t_sup_lists(elements1, elements2))
      tag1 == :any ->
        t_tuple(t_sup_lists(elements1, elements2))
      tag2 == :any ->
        t_tuple(t_sup_lists(elements1, elements2))
      tag1 < tag2 ->
        r_c(tag: :tuple_set, elements: [{arity, [t1, t2]}])
      tag1 > tag2 ->
        r_c(tag: :tuple_set, elements: [{arity, [t2, t1]}])
    end
  end

  def t_sup(r_c(tag: :tuple, elements: _,
             qualifier: {arity1, _}) = t1,
           r_c(tag: :tuple, elements: _,
               qualifier: {arity2, _}) = t2) do
    sup_tuple_sets([{arity1, [t1]}], [{arity2, [t2]}])
  end

  def t_sup(r_c(tag: :tuple_set, elements: list1),
           r_c(tag: :tuple_set, elements: list2)) do
    sup_tuple_sets(list1, list2)
  end

  def t_sup(r_c(tag: :tuple_set, elements: list1),
           t2 = r_c(tag: :tuple, elements: _,
                    qualifier: {arity, _})) do
    sup_tuple_sets(list1, [{arity, [t2]}])
  end

  def t_sup(r_c(tag: :tuple, elements: _,
             qualifier: {arity, _}) = t1,
           r_c(tag: :tuple_set, elements: list2)) do
    sup_tuple_sets([{arity, [t1]}], list2)
  end

  def t_sup(r_c(tag: :map, elements: {_, aDefK, aDefV}) = a,
           r_c(tag: :map, elements: {_, bDefK, bDefV}) = b) do
    pairs = map_pairwise_merge(fn k, mNess, v1, mNess, v2 ->
                                    {k, mNess, t_sup(v1, v2)}
                                  k, _, v1, _, v2 ->
                                    {k, :optional, t_sup(v1, v2)}
                               end,
                                 a, b)
    t_map(pairs, t_sup(aDefK, bDefK), t_sup(aDefV, bDefV))
  end

  def t_sup(t1, t2) do
    r_c(tag: :union, elements: u1) = force_union(t1)
    r_c(tag: :union, elements: u2) = force_union(t2)
    sup_union(u1, u2)
  end

  defp sup_opaque([]) do
    :none
  end

  defp sup_opaque(list) do
    l = sup_opaq(list)
    r_c(tag: :opaque, elements: :ordsets.from_list(l))
  end

  defp sup_opaq(l0) do
    l1 = (for (r_opaque(mod: mod, name: name,
                   arity: arity) = t) <- l0 do
            {{mod, name, arity}, t}
          end)
    f = :dialyzer_utils.family(l1)
    for {_, ts} <- f do
      supl(ts)
    end
  end

  defp supl([o]) do
    o
  end

  defp supl(ts) do
    supl(ts, t_none())
  end

  defp supl([r_opaque(struct: s) = o | l], s0) do
    s1 = t_sup(s, s0)
    case (l === []) do
      true ->
        r_opaque(o, struct: s1)
      false ->
        supl(l, s1)
    end
  end

  defp t_sup_lists([t1 | left1], [t2 | left2]) do
    [t_sup(t1, t2) | t_sup_lists(left1, left2)]
  end

  defp t_sup_lists([], []) do
    []
  end

  defp sup_tuple_sets(l1, l2) do
    totalArities = :ordsets.union(for {arity, _} <- l1 do
                                    arity
                                  end,
                                    for {arity, _} <- l2 do
                                      arity
                                    end)
    cond do
      length(totalArities) > 8 ->
        t_tuple()
      true ->
        case (sup_tuple_sets(l1, l2, [])) do
          [{_Arity,
              [oneTuple = r_c(tag: :tuple, elements: _,
                              qualifier: {_, _})]}] ->
            oneTuple
          list ->
            r_c(tag: :tuple_set, elements: list)
        end
    end
  end

  defp sup_tuple_sets([{arity, tuples1} | left1],
            [{arity, tuples2} | left2], acc) do
    newAcc = [{arity, sup_tuples_in_set(tuples1, tuples2)} |
                  acc]
    sup_tuple_sets(left1, left2, newAcc)
  end

  defp sup_tuple_sets([{arity1, _} = t1 | left1] = l1,
            [{arity2, _} = t2 | left2] = l2, acc) do
    cond do
      arity1 < arity2 ->
        sup_tuple_sets(left1, l2, [t1 | acc])
      arity1 > arity2 ->
        sup_tuple_sets(l1, left2, [t2 | acc])
    end
  end

  defp sup_tuple_sets([], l2, acc) do
    :lists.reverse(acc, l2)
  end

  defp sup_tuple_sets(l1, [], acc) do
    :lists.reverse(acc, l1)
  end

  defp sup_tuples_in_set([r_c(tag: :tuple, elements: _,
               qualifier: {_, :any}) = t],
            l) do
    [t_tuple(sup_tuple_elements([t | l]))]
  end

  defp sup_tuples_in_set(l,
            [r_c(tag: :tuple, elements: _,
                 qualifier: {_, :any}) = t]) do
    [t_tuple(sup_tuple_elements([t | l]))]
  end

  defp sup_tuples_in_set(l1, l2) do
    foldFun = fn r_c(tag: :tuple, elements: _,
                     qualifier: {_, tag}),
                   accTag ->
                   t_sup(tag, accTag)
              end
    totalTag0 = :lists.foldl(foldFun, :none, l1)
    totalTag = :lists.foldl(foldFun, totalTag0, l2)
    case (totalTag) do
      r_c(tag: :atom, elements: :any) ->
        [t_tuple(sup_tuple_elements(l1 ++ l2))]
      r_c(tag: :atom, elements: set) ->
        case (length(set) > 5) do
          true ->
            [t_tuple(sup_tuple_elements(l1 ++ l2))]
          false ->
            sup_tuples_in_set(l1, l2, [])
        end
    end
  end

  defp sup_tuple_elements([r_c(tag: :tuple, elements: elements,
               qualifier: {_, _}) |
               l]) do
    :lists.foldl(fn r_c(tag: :tuple, elements: es,
                        qualifier: {_, _}),
                      acc ->
                      t_sup_lists(es, acc)
                 end,
                   elements, l)
  end

  defp sup_tuples_in_set([r_c(tag: :tuple, elements: elements1,
               qualifier: {arity, tag1}) = t1 |
               left1] = l1,
            [r_c(tag: :tuple, elements: elements2,
                 qualifier: {arity, tag2}) = t2 |
                 left2] = l2,
            acc) do
    cond do
      tag1 < tag2 ->
        sup_tuples_in_set(left1, l2, [t1 | acc])
      tag1 > tag2 ->
        sup_tuples_in_set(l1, left2, [t2 | acc])
      tag1 == tag2 ->
        newElements = t_sup_lists(elements1, elements2)
        newAcc = [r_c(tag: :tuple, elements: newElements,
                      qualifier: {arity, tag1}) |
                      acc]
        sup_tuples_in_set(left1, left2, newAcc)
    end
  end

  defp sup_tuples_in_set([], l2, acc) do
    :lists.reverse(acc, l2)
  end

  defp sup_tuples_in_set(l1, [], acc) do
    :lists.reverse(acc, l1)
  end

  defp sup_union(u1, u2) do
    sup_union(u1, u2, 0, [])
  end

  defp sup_union([:none | left1], [:none | left2], n, acc) do
    sup_union(left1, left2, n, [:none | acc])
  end

  defp sup_union([t1 | left1], [t2 | left2], n, acc) do
    sup_union(left1, left2, n + 1, [t_sup(t1, t2) | acc])
  end

  defp sup_union([], [], n, acc) do
    cond do
      n === 0 ->
        :none
      n === 1 ->
        [type] = (for t <- acc, t !== :none do
                    t
                  end)
        type
      n === length([:any, :any, :any, :any, :any, :any, :any,
                                                            :any, :any]) ->
        :any
      true ->
        r_c(tag: :union, elements: :lists.reverse(acc))
    end
  end

  defp force_union(t = r_c(tag: :atom, elements: _)) do
    r_c(tag: :union,
        elements: [t, :none, :none, :none, :none, :none, :none,
                                                             :none, :none])
  end

  defp force_union(t = r_c(tag: :binary, elements: {_, _})) do
    r_c(tag: :union,
        elements: [:none, t, :none, :none, :none, :none, :none,
                                                             :none, :none])
  end

  defp force_union(t = r_c(tag: :function, elements: {_, _})) do
    r_c(tag: :union,
        elements: [:none, :none, t, :none, :none, :none, :none,
                                                             :none, :none])
  end

  defp force_union(t = r_c(tag: :identifier, elements: _)) do
    r_c(tag: :union,
        elements: [:none, :none, :none, t, :none, :none, :none,
                                                             :none, :none])
  end

  defp force_union(t = r_c(tag: :list, elements: {_, _},
                  qualifier: _)) do
    r_c(tag: :union,
        elements: [:none, :none, :none, :none, t, :none, :none,
                                                             :none, :none])
  end

  defp force_union(t = r_c(tag: nil)) do
    r_c(tag: :union,
        elements: [:none, :none, :none, :none, t, :none, :none,
                                                             :none, :none])
  end

  defp force_union(t = r_c(tag: :number, elements: _,
                  qualifier: _)) do
    r_c(tag: :union,
        elements: [:none, :none, :none, :none, :none, t, :none,
                                                             :none, :none])
  end

  defp force_union(t = r_c(tag: :opaque, elements: _)) do
    r_c(tag: :union,
        elements: [:none, :none, :none, :none, :none, :none,
                                                          :none, t, :none])
  end

  defp force_union(t = r_c(tag: :map, elements: {_, _, _})) do
    r_c(tag: :union,
        elements: [:none, :none, :none, :none, :none, :none,
                                                          :none, :none, t])
  end

  defp force_union(t = r_c(tag: :tuple, elements: _,
                  qualifier: {_, _})) do
    r_c(tag: :union,
        elements: [:none, :none, :none, :none, :none, :none, t,
                                                                 :none, :none])
  end

  defp force_union(t = r_c(tag: :tuple_set, elements: _)) do
    r_c(tag: :union,
        elements: [:none, :none, :none, :none, :none, :none, t,
                                                                 :none, :none])
  end

  defp force_union(t = r_c(tag: :union, elements: _)) do
    t
  end

  def t_elements(t) do
    t_elements(t, :universe)
  end

  def t_elements(:none, _Opaques) do
    []
  end

  def t_elements(:unit, _Opaques) do
    []
  end

  def t_elements(:any = t, _Opaques) do
    [t]
  end

  def t_elements(r_c(tag: nil) = t, _Opaques) do
    [t]
  end

  def t_elements(r_c(tag: :atom, elements: :any) = t, _Opaques) do
    [t]
  end

  def t_elements(r_c(tag: :atom, elements: atoms), _Opaques) do
    for a <- atoms do
      t_atom(a)
    end
  end

  def t_elements(r_c(tag: :binary, elements: {_, _}) = t,
           _Opaques) do
    [t]
  end

  def t_elements(r_c(tag: :function, elements: {_, _}) = t,
           _Opaques) do
    [t]
  end

  def t_elements(r_c(tag: :identifier, elements: :any) = t,
           _Opaques) do
    [t]
  end

  def t_elements(r_c(tag: :identifier, elements: iDs), _Opaques) do
    for t <- iDs do
      r_c(tag: :identifier, elements: [t])
    end
  end

  def t_elements(r_c(tag: :list, elements: {_, _},
             qualifier: _) = t,
           _Opaques) do
    [t]
  end

  def t_elements(r_c(tag: :number, elements: _, qualifier: _) = t,
           _Opaques) do
    case (t) do
      r_c(tag: :number, elements: :any, qualifier: :unknown) ->
        [r_c(tag: :number, elements: :any, qualifier: :float),
             r_c(tag: :number, elements: :any, qualifier: :integer)]
      r_c(tag: :number, elements: :any, qualifier: :float) ->
        [t]
      r_c(tag: :number, elements: :any, qualifier: :integer) ->
        [t]
      r_c(tag: :number, elements: r_int_rng(from: _, to: _),
          qualifier: :integer) ->
        [t]
      r_c(tag: :number, elements: r_int_set(set: set),
          qualifier: :integer) ->
        for i <- set do
          t_integer(i)
        end
    end
  end

  def t_elements(r_c(tag: :opaque, elements: _) = t, opaques) do
    do_elements(t, opaques)
  end

  def t_elements(r_c(tag: :map, elements: {_, _, _}) = t,
           _Opaques) do
    [t]
  end

  def t_elements(r_c(tag: :tuple, elements: _,
             qualifier: {_, _}) = t,
           _Opaques) do
    [t]
  end

  def t_elements(r_c(tag: :tuple_set, elements: _) = tS,
           _Opaques) do
    case (t_tuple_subtypes(tS)) do
      :unknown ->
        []
      elems ->
        elems
    end
  end

  def t_elements(r_c(tag: :union, elements: _) = t, opaques) do
    do_elements(t, opaques)
  end

  def t_elements(r_c(tag: :var, elements: _), _Opaques) do
    [:any]
  end

  defp do_elements(type0, opaques) do
    case (do_opaque(type0, opaques,
                      fn t ->
                           t
                      end)) do
      r_c(tag: :union, elements: list) ->
        :lists.append(for t <- list do
                        t_elements(t, opaques)
                      end)
      r_c(tag: :opaque, elements: _) = type ->
        [type]
      type ->
        t_elements(type, opaques)
    end
  end

  def t_inf([h1, h2 | t]) do
    case (t_inf(h1, h2)) do
      :none ->
        :none
      newH ->
        t_inf([newH | t])
    end
  end

  def t_inf([h]) do
    h
  end

  def t_inf([]) do
    :none
  end

  def t_inf(t1, t2) do
    t_inf(t1, t2, :universe)
  end

  def t_inf(r_c(tag: :var, elements: _),
           r_c(tag: :var, elements: _), _Opaques) do
    :any
  end

  def t_inf(r_c(tag: :var, elements: _), t, _Opaques) do
    do_not_subst_all_vars_to_any(t)
  end

  def t_inf(t, r_c(tag: :var, elements: _), _Opaques) do
    do_not_subst_all_vars_to_any(t)
  end

  def t_inf(:any, t, _Opaques) do
    do_not_subst_all_vars_to_any(t)
  end

  def t_inf(t, :any, _Opaques) do
    do_not_subst_all_vars_to_any(t)
  end

  def t_inf(:none, _, _Opaques) do
    :none
  end

  def t_inf(_, :none, _Opaques) do
    :none
  end

  def t_inf(:unit, _, _Opaques) do
    :unit
  end

  def t_inf(_, :unit, _Opaques) do
    :unit
  end

  def t_inf(t, t, _Opaques) do
    do_not_subst_all_vars_to_any(t)
  end

  def t_inf(r_c(tag: :atom, elements: set1),
           r_c(tag: :atom, elements: set2), _) do
    case (set_intersection(set1, set2)) do
      :none ->
        :none
      newSet ->
        r_c(tag: :atom, elements: newSet)
    end
  end

  def t_inf(r_c(tag: :binary, elements: {u1, b1}),
           r_c(tag: :binary, elements: {0, b2}), _Opaques) do
    cond do
      b2 >= b1 and rem(b2 - b1, u1) === 0 ->
        t_bitstr(0, b2)
      true ->
        :none
    end
  end

  def t_inf(r_c(tag: :binary, elements: {0, b1}),
           r_c(tag: :binary, elements: {u2, b2}), _Opaques) do
    cond do
      b1 >= b2 and rem(b1 - b2, u2) === 0 ->
        t_bitstr(0, b1)
      true ->
        :none
    end
  end

  def t_inf(r_c(tag: :binary, elements: {u1, b1}),
           r_c(tag: :binary, elements: {u1, b1}), _Opaques) do
    t_bitstr(u1, b1)
  end

  def t_inf(r_c(tag: :binary, elements: {u1, b1}),
           r_c(tag: :binary, elements: {u2, b2}), _Opaques)
      when u2 > u1 do
    inf_bitstr(u2, b2, u1, b1)
  end

  def t_inf(r_c(tag: :binary, elements: {u1, b1}),
           r_c(tag: :binary, elements: {u2, b2}), _Opaques) do
    inf_bitstr(u1, b1, u2, b2)
  end

  def t_inf(r_c(tag: :function, elements: {domain1, range1}),
           r_c(tag: :function, elements: {domain2, range2}),
           opaques) do
    case (t_inf(domain1, domain2, opaques)) do
      :none ->
        :none
      domain ->
        r_c(tag: :function,
            elements: {domain, t_inf(range1, range2, opaques)})
    end
  end

  def t_inf(r_c(tag: :identifier, elements: set1),
           r_c(tag: :identifier, elements: set2), _Opaques) do
    case (set_intersection(set1, set2)) do
      :none ->
        :none
      set ->
        r_c(tag: :identifier, elements: set)
    end
  end

  def t_inf(r_c(tag: :map, elements: {_, aDefK, aDefV}) = a,
           r_c(tag: :map, elements: {_, bDefK, bDefV}) = b,
           _Opaques) do
    pairs = map_pairwise_merge(fn k, :optional, v1,
                                    :optional, v2 ->
                                    {k, :optional, t_inf(v1, v2)}
                                  k, _, v1, _, v2 ->
                                    {k, :mandatory, t_inf(v1, v2)}
                               end,
                                 a, b)
    t_map(pairs, t_inf(aDefK, bDefK), t_inf(aDefV, bDefV))
  end

  def t_inf(r_c(tag: nil), r_c(tag: nil), _Opaques) do
    r_c(tag: nil)
  end

  def t_inf(r_c(tag: nil),
           r_c(tag: :list, elements: {_, _}, qualifier: :nonempty),
           _Opaques) do
    :none
  end

  def t_inf(r_c(tag: :list, elements: {_, _},
             qualifier: :nonempty),
           r_c(tag: nil), _Opaques) do
    :none
  end

  def t_inf(r_c(tag: nil),
           r_c(tag: :list, elements: {_Contents, termination},
               qualifier: _),
           opaques) do
    t_inf(r_c(tag: nil), t_unopaque(termination), opaques)
  end

  def t_inf(r_c(tag: :list, elements: {_Contents, termination},
             qualifier: _),
           r_c(tag: nil), opaques) do
    t_inf(r_c(tag: nil), t_unopaque(termination), opaques)
  end

  def t_inf(r_c(tag: :list,
             elements: {contents1, termination1}, qualifier: size1),
           r_c(tag: :list, elements: {contents2, termination2},
               qualifier: size2),
           opaques) do
    case (t_inf(termination1, termination2, opaques)) do
      :none ->
        :none
      termination ->
        case (t_inf(contents1, contents2, opaques)) do
          :none ->
            case (size1 === :unknown and size2 === :unknown) do
              true ->
                t_nil()
              false ->
                :none
            end
          contents ->
            size = (case ({size1, size2}) do
                      {:unknown, :unknown} ->
                        :unknown
                      {:unknown, :nonempty} ->
                        :nonempty
                      {:nonempty, :unknown} ->
                        :nonempty
                      {:nonempty, :nonempty} ->
                        :nonempty
                    end)
            r_c(tag: :list, elements: {contents, termination},
                qualifier: size)
        end
    end
  end

  def t_inf(r_c(tag: :number, elements: _, qualifier: _) = t1,
           r_c(tag: :number, elements: _, qualifier: _) = t2,
           _Opaques) do
    case ({t1, t2}) do
      {t, t} ->
        t
      {_,
         r_c(tag: :number, elements: :any, qualifier: :unknown)} ->
        t1
      {r_c(tag: :number, elements: :any, qualifier: :unknown),
         _} ->
        t2
      {r_c(tag: :number, elements: :any, qualifier: :float),
         r_c(tag: :number, elements: _, qualifier: :integer)} ->
        :none
      {r_c(tag: :number, elements: _, qualifier: :integer),
         r_c(tag: :number, elements: :any, qualifier: :float)} ->
        :none
      {r_c(tag: :number, elements: :any, qualifier: :integer),
         r_c(tag: :number, elements: _, qualifier: :integer)} ->
        t2
      {r_c(tag: :number, elements: _, qualifier: :integer),
         r_c(tag: :number, elements: :any, qualifier: :integer)} ->
        t1
      {r_c(tag: :number, elements: r_int_set(set: set1),
           qualifier: :integer),
         r_c(tag: :number, elements: r_int_set(set: set2),
             qualifier: :integer)} ->
        case (set_intersection(set1, set2)) do
          :none ->
            :none
          set ->
            r_c(tag: :number, elements: r_int_set(set: set),
                qualifier: :integer)
        end
      {r_c(tag: :number, elements: r_int_rng(from: from1, to: to1),
           qualifier: :integer),
         r_c(tag: :number, elements: r_int_rng(from: from2, to: to2),
             qualifier: :integer)} ->
        t_from_range(max(from1, from2), min(to1, to2))
      {range = r_c(tag: :number, elements: r_int_rng(from: _, to: _),
                   qualifier: :integer),
         r_c(tag: :number, elements: r_int_set(set: set),
             qualifier: :integer)} ->
        ans2 = (case (set_filter(fn x ->
                                      in_range(x, range)
                                 end,
                                   set)) do
                  :none ->
                    :none
                  newSet ->
                    r_c(tag: :number, elements: r_int_set(set: newSet),
                        qualifier: :integer)
                end)
        ans2
      {r_c(tag: :number, elements: r_int_set(set: set),
           qualifier: :integer),
         r_c(tag: :number, elements: r_int_rng(from: _, to: _),
             qualifier: :integer) = range} ->
        case (set_filter(fn x ->
                              in_range(x, range)
                         end,
                           set)) do
          :none ->
            :none
          newSet ->
            r_c(tag: :number, elements: r_int_set(set: newSet),
                qualifier: :integer)
        end
    end
  end

  def t_inf(r_c(tag: :product, elements: types1),
           r_c(tag: :product, elements: types2), opaques) do
    l1 = length(types1)
    l2 = length(types2)
    cond do
      l1 === l2 ->
        r_c(tag: :product,
            elements: t_inf_lists(types1, types2, opaques))
      true ->
        :none
    end
  end

  def t_inf(r_c(tag: :product, elements: _), _, _Opaques) do
    :none
  end

  def t_inf(_, r_c(tag: :product, elements: _), _Opaques) do
    :none
  end

  def t_inf(r_c(tag: :tuple, elements: :any,
             qualifier: {:any, :any}),
           r_c(tag: :tuple, elements: _, qualifier: {_, _}) = t,
           _Opaques) do
    do_not_subst_all_vars_to_any(t)
  end

  def t_inf(r_c(tag: :tuple, elements: _,
             qualifier: {_, _}) = t,
           r_c(tag: :tuple, elements: :any, qualifier: {:any, :any}),
           _Opaques) do
    do_not_subst_all_vars_to_any(t)
  end

  def t_inf(r_c(tag: :tuple, elements: :any,
             qualifier: {:any, :any}),
           r_c(tag: :tuple_set, elements: _) = t, _Opaques) do
    do_not_subst_all_vars_to_any(t)
  end

  def t_inf(r_c(tag: :tuple_set, elements: _) = t,
           r_c(tag: :tuple, elements: :any, qualifier: {:any, :any}),
           _Opaques) do
    do_not_subst_all_vars_to_any(t)
  end

  def t_inf(r_c(tag: :tuple, elements: elements1,
             qualifier: {arity, _Tag1}),
           r_c(tag: :tuple, elements: elements2,
               qualifier: {arity, _Tag2}),
           opaques) do
    case (t_inf_lists_strict(elements1, elements2,
                               opaques)) do
      :bottom ->
        :none
      newElements ->
        t_tuple(newElements)
    end
  end

  def t_inf(r_c(tag: :tuple_set, elements: list1),
           r_c(tag: :tuple_set, elements: list2), opaques) do
    inf_tuple_sets(list1, list2, opaques)
  end

  def t_inf(r_c(tag: :tuple_set, elements: list),
           r_c(tag: :tuple, elements: _, qualifier: {arity, _}) = t,
           opaques) do
    inf_tuple_sets(list, [{arity, [t]}], opaques)
  end

  def t_inf(r_c(tag: :tuple, elements: _,
             qualifier: {arity, _}) = t,
           r_c(tag: :tuple_set, elements: list), opaques) do
    inf_tuple_sets(list, [{arity, [t]}], opaques)
  end

  def t_inf(r_c(tag: :union, elements: u1), t, opaques) do
    r_c(tag: :union, elements: u2) = force_union(t)
    inf_union(u1, u2, opaques)
  end

  def t_inf(t, r_c(tag: :union, elements: u2), opaques) do
    r_c(tag: :union, elements: u1) = force_union(t)
    inf_union(u1, u2, opaques)
  end

  def t_inf(r_c(tag: :opaque, elements: set1),
           r_c(tag: :opaque, elements: set2), opaques) do
    inf_opaque(set1, set2, opaques)
  end

  def t_inf(r_c(tag: :opaque, elements: _) = t1, t2,
           opaques) do
    inf_opaque1(t2, t1, 1, opaques)
  end

  def t_inf(t1, r_c(tag: :opaque, elements: _) = t2,
           opaques) do
    inf_opaque1(t1, t2, 2, opaques)
  end

  def t_inf(r_c(), r_c(), _) do
    :none
  end

  defp inf_opaque1(t1, r_c(tag: :opaque, elements: set2) = t2, pos,
            opaques) do
    case (opaques === :universe or inf_is_opaque_type(t2,
                                                        pos, opaques)) do
      false ->
        :none
      true ->
        case (inf_collect(t1, set2, opaques, [])) do
          [] ->
            :none
          opL ->
            r_c(tag: :opaque, elements: :ordsets.from_list(opL))
        end
    end
  end

  defp inf_is_opaque_type(t, pos, {:match, opaques}) do
    is_opaque_type(t, opaques) or throw({:pos, [pos]})
  end

  defp inf_is_opaque_type(t, _Pos, opaques) do
    is_opaque_type(t, opaques)
  end

  defp inf_collect(t1, [t2 | list2], opaques, opL) do
    r_opaque(struct: s2) = t2
    case (t_inf(t1, s2, opaques)) do
      :none ->
        inf_collect(t1, list2, opaques, opL)
      inf ->
        op = r_opaque(t2, struct: inf)
        inf_collect(t1, list2, opaques, [op | opL])
    end
  end

  defp inf_collect(_T1, [], _Opaques, opL) do
    opL
  end

  defp combine(s, t1, t2) do
    case (is_compat_opaque_names(t1, t2)) do
      true ->
        combine(s, [t1])
      false ->
        combine(s, [t1, t2])
    end
  end

  defp combine(r_c(tag: :opaque, elements: set), ts) do
    for o <- set, t <- ts do
      comb2(o, t)
    end
  end

  defp combine(s, ts) do
    for t <- ts do
      r_opaque(t, struct: s)
    end
  end

  defp comb2(o, t) do
    case (is_compat_opaque_names(o, t)) do
      true ->
        o
      false ->
        r_opaque(t, struct: r_c(tag: :opaque,
                         elements: set_singleton(o)))
    end
  end

  defp inf_opaque(set1, set2, opaques) do
    list1 = inf_look_up(set1, opaques)
    list2 = inf_look_up(set2, opaques)
    list0 = (for {is1, t1} <- list1, {is2, t2} <- list2,
                   not
                   t_is_none(inf = inf_opaque_types(is1, t1, is2, t2,
                                                      opaques)) do
               combine(inf, t1, t2)
             end)
    list = :lists.append(list0)
    sup_opaque(list)
  end

  defp inf_look_up(set, opaques) do
    for t <- set do
      {opaques === :universe or inf_is_opaque_type2(t,
                                                      opaques),
         t}
    end
  end

  defp inf_is_opaque_type2(t, {:match, opaques}) do
    is_opaque_type2(t, opaques)
  end

  defp inf_is_opaque_type2(t, opaques) do
    is_opaque_type2(t, opaques)
  end

  defp inf_opaque_types(isOpaque1, t1, isOpaque2, t2, opaques) do
    r_opaque(struct: s1) = t1
    r_opaque(struct: s2) = t2
    case (opaques === :universe or is_compat_opaque_names(t1,
                                                            t2)) do
      true ->
        t_inf(s1, s2, opaques)
      false ->
        case ({isOpaque1, isOpaque2}) do
          {true, true} ->
            t_inf(s1, s2, opaques)
          {true, false} ->
            t_inf(s1, r_c(tag: :opaque, elements: set_singleton(t2)),
                    opaques)
          {false, true} ->
            t_inf(r_c(tag: :opaque, elements: set_singleton(t1)), s2,
                    opaques)
          {false, false} when :erlang.element(1,
                                                opaques) === :match
                              ->
            throw({:pos, [1, 2]})
          {false, false} ->
            t_none()
        end
    end
  end

  defp compatible_opaque_types(r_c(tag: :opaque, elements: es1),
            r_c(tag: :opaque, elements: es2)) do
    for o1 <- es1, o2 <- es2,
          is_compat_opaque_names(o1, o2) do
      {o1, o2}
    end
  end

  defp is_compat_opaque_names(opaque1, opaque2) do
    r_opaque(mod: mod1, name: name1, arity: arity1) = opaque1
    r_opaque(mod: mod2, name: name2, arity: arity2) = opaque2
    case ({{mod1, name1, arity1}, {mod2, name2, arity2}}) do
      {modNameArity, modNameArity} ->
        true
      _ ->
        false
    end
  end

  def t_inf_lists(l1, l2) do
    t_inf_lists(l1, l2, :universe)
  end

  def t_inf_lists(l1, l2, opaques) do
    t_inf_lists(l1, l2, [], opaques)
  end

  defp t_inf_lists([t1 | left1], [t2 | left2], acc, opaques) do
    t_inf_lists(left1, left2,
                  [t_inf(t1, t2, opaques) | acc], opaques)
  end

  defp t_inf_lists([], [], acc, _Opaques) do
    :lists.reverse(acc)
  end

  defp t_inf_lists_strict(l1, l2, opaques) do
    t_inf_lists_strict(l1, l2, [], opaques)
  end

  defp t_inf_lists_strict([t1 | left1], [t2 | left2], acc, opaques) do
    case (t_inf(t1, t2, opaques)) do
      :none ->
        :bottom
      t ->
        t_inf_lists_strict(left1, left2, [t | acc], opaques)
    end
  end

  defp t_inf_lists_strict([], [], acc, _Opaques) do
    :lists.reverse(acc)
  end

  defp inf_tuple_sets(l1, l2, opaques) do
    case (inf_tuple_sets(l1, l2, [], opaques)) do
      [] ->
        :none
      [{_Arity,
          [r_c(tag: :tuple, elements: _,
               qualifier: {_, _}) = oneTuple]}] ->
        oneTuple
      list ->
        r_c(tag: :tuple_set, elements: list)
    end
  end

  defp inf_tuple_sets([{arity, tuples1} | ts1],
            [{arity, tuples2} | ts2], acc, opaques) do
    case (inf_tuples_in_sets(tuples1, tuples2, opaques)) do
      [] ->
        inf_tuple_sets(ts1, ts2, acc, opaques)
      [r_c(tag: :tuple_set, elements: [{^arity, newTuples}])] ->
        inf_tuple_sets(ts1, ts2, [{arity, newTuples} | acc],
                         opaques)
      newTuples ->
        inf_tuple_sets(ts1, ts2, [{arity, newTuples} | acc],
                         opaques)
    end
  end

  defp inf_tuple_sets([{arity1, _} | ts1] = l1,
            [{arity2, _} | ts2] = l2, acc, opaques) do
    cond do
      arity1 < arity2 ->
        inf_tuple_sets(ts1, l2, acc, opaques)
      arity1 > arity2 ->
        inf_tuple_sets(l1, ts2, acc, opaques)
    end
  end

  defp inf_tuple_sets([], _, acc, _Opaques) do
    :lists.reverse(acc)
  end

  defp inf_tuple_sets(_, [], acc, _Opaques) do
    :lists.reverse(acc)
  end

  defp inf_tuples_in_sets([r_c(tag: :tuple, elements: elements1,
               qualifier: {_, :any})],
            l2, opaques) do
    newList = (for r_c(tag: :tuple, elements: elements2,
                       qualifier: {_, _}) <- l2 do
                 t_inf_lists_strict(elements1, elements2, opaques)
               end)
    for es <- newList, es !== :bottom do
      t_tuple(es)
    end
  end

  defp inf_tuples_in_sets(l1,
            [r_c(tag: :tuple, elements: elements2,
                 qualifier: {_, :any})],
            opaques) do
    newList = (for r_c(tag: :tuple, elements: elements1,
                       qualifier: {_, _}) <- l1 do
                 t_inf_lists_strict(elements1, elements2, opaques)
               end)
    for es <- newList, es !== :bottom do
      t_tuple(es)
    end
  end

  defp inf_tuples_in_sets(l1, l2, opaques) do
    inf_tuples_in_sets2(l1, l2, [], opaques)
  end

  defp inf_tuples_in_sets2([r_c(tag: :tuple, elements: elements1,
               qualifier: {arity, tag}) |
               ts1],
            [r_c(tag: :tuple, elements: elements2,
                 qualifier: {arity, tag}) |
                 ts2],
            acc, opaques) do
    case (t_inf_lists_strict(elements1, elements2,
                               opaques)) do
      :bottom ->
        inf_tuples_in_sets2(ts1, ts2, acc, opaques)
      newElements ->
        inf_tuples_in_sets2(ts1, ts2,
                              [r_c(tag: :tuple, elements: newElements,
                                   qualifier: {arity, tag}) |
                                   acc],
                              opaques)
    end
  end

  defp inf_tuples_in_sets2([r_c(tag: :tuple, elements: _,
               qualifier: {_, tag1}) |
               ts1] = l1,
            [r_c(tag: :tuple, elements: _, qualifier: {_, tag2}) |
                 ts2] = l2,
            acc, opaques) do
    cond do
      tag1 < tag2 ->
        inf_tuples_in_sets2(ts1, l2, acc, opaques)
      tag1 > tag2 ->
        inf_tuples_in_sets2(l1, ts2, acc, opaques)
    end
  end

  defp inf_tuples_in_sets2([], _, acc, _Opaques) do
    :lists.reverse(acc)
  end

  defp inf_tuples_in_sets2(_, [], acc, _Opaques) do
    :lists.reverse(acc)
  end

  defp inf_union(u1, u2, opaques) do
    opaqueFun = fn union1, union2, infFun ->
                     [_, _, _, _, _, _, _, opaque, _] = union1
                     [a, b, f, i, l, n, t, _, map] = union2
                     list = [a, b, f, i, l, n, t, map]
                     inf_union_collect(list, opaque, infFun, [], [])
                end
    {o1, throwList1} = opaqueFun.(u1, u2,
                                    fn e, opaque ->
                                         t_inf(opaque, e, opaques)
                                    end)
    {o2, throwList2} = opaqueFun.(u2, u1,
                                    fn e, opaque ->
                                         t_inf(e, opaque, opaques)
                                    end)
    {union, throwList3} = inf_union(u1, u2, :none, [], [],
                                      opaques)
    throwList = :lists.merge3(throwList1, throwList2,
                                throwList3)
    case (t_sup([o1, o2, union])) do
      :none when throwList !== [] ->
        throw({:pos, :lists.usort(throwList)})
      sup ->
        sup
    end
  end

  defp inf_union_collect([], _Opaque, _InfFun, infList, throwList) do
    {t_sup(infList), :lists.usort(throwList)}
  end

  defp inf_union_collect([:none | l], opaque, infFun, infList,
            throwList) do
    inf_union_collect(l, opaque, infFun, [:none | infList],
                        throwList)
  end

  defp inf_union_collect([e | l], opaque, infFun, infList, throwList) do
    try do
      infFun.(e, opaque)
    catch
      {:pos, ns} ->
        inf_union_collect(l, opaque, infFun, infList,
                            ns ++ throwList)
    else
      inf ->
        inf_union_collect(l, opaque, infFun, [inf | infList],
                            throwList)
    end
  end

  defp inf_union([:none | left1], [:none | left2], type, acc,
            throwList, opaques) do
    inf_union(left1, left2, type, [:none | acc], throwList,
                opaques)
  end

  defp inf_union([t1 | left1], [t2 | left2], type, acc,
            throwList, opaques) do
    try do
      t_inf(t1, t2, opaques)
    catch
      {:pos, ns} ->
        inf_union(left1, left2, type, [:none | acc],
                    ns ++ throwList, opaques)
    else
      :none ->
        inf_union(left1, left2, type, [:none | acc], throwList,
                    opaques)
      t when type === :none ->
        inf_union(left1, left2, t, [t | acc], throwList,
                    opaques)
      t ->
        inf_union(left1, left2, :union, [t | acc], throwList,
                    opaques)
    end
  end

  defp inf_union([], [], type, acc, throwList, _Opaques) do
    case (type) do
      :union ->
        {r_c(tag: :union, elements: :lists.reverse(acc)),
           throwList}
      _ ->
        {type, throwList}
    end
  end

  defp inf_bitstr(u1, b1, u2, b2) do
    gCD = gcd(u1, u2)
    case (rem(b2 - b1, gCD)) do
      0 ->
        u = div(u1 * u2, gCD)
        b = findfirst(0, 0, u1, b1, u2, b2)
        t_bitstr(u, b)
      _ ->
        :none
    end
  end

  defp findfirst(n1, n2, u1, b1, u2, b2) do
    val1 = u1 * n1 + b1
    val2 = u2 * n2 + b2
    cond do
      val1 === val2 ->
        val1
      val1 > val2 ->
        n2_1 = n2 + max(div((val1 - val2), u2), 1)
        findfirst(n1, n2_1, u1, b1, u2, b2)
      val1 < val2 ->
        n1_1 = n1 + max(div((val2 - val1), u1), 1)
        findfirst(n1_1, n2, u1, b1, u2, b2)
    end
  end

  defp do_not_subst_all_vars_to_any(t) do
    t
  end

  def t_subst(t, map) do
    case (t_has_var(t)) do
      true ->
        t_subst_aux(t, map)
      false ->
        t
    end
  end

  def subst_all_vars_to_any(t) do
    t_subst(t, %{})
  end

  defp t_subst_aux(r_c(tag: :var, elements: id), map) do
    case (map) do
      %{^id => type} ->
        type
      %{} ->
        :any
    end
  end

  defp t_subst_aux(r_c(tag: :list, elements: {contents, termination},
              qualifier: size),
            map) do
    case (t_subst_aux(contents, map)) do
      :none ->
        :none
      :unit ->
        :none
      newContents ->
        case (t_subst_aux(termination, map)) do
          r_c(tag: nil) ->
            r_c(tag: :list, elements: {newContents, r_c(tag: nil)},
                qualifier: size)
          :any ->
            r_c(tag: :list, elements: {newContents, :any},
                qualifier: size)
          other ->
            r_c(tag: :list, elements: {newContents2, newTermination},
                qualifier: _) = t_cons(newContents, other)
            r_c(tag: :list, elements: {newContents2, newTermination},
                qualifier: size)
        end
    end
  end

  defp t_subst_aux(r_c(tag: :function, elements: {domain, range}),
            map) do
    r_c(tag: :function,
        elements: {t_subst_aux(domain, map),
                     t_subst_aux(range, map)})
  end

  defp t_subst_aux(r_c(tag: :product, elements: types), map) do
    r_c(tag: :product,
        elements: for t <- types do
                    t_subst_aux(t, map)
                  end)
  end

  defp t_subst_aux(r_c(tag: :tuple, elements: :any,
              qualifier: {:any, :any}) = t,
            _Map) do
    t
  end

  defp t_subst_aux(r_c(tag: :tuple, elements: elements,
              qualifier: {_Arity, _Tag}),
            map) do
    t_tuple(for e <- elements do
              t_subst_aux(e, map)
            end)
  end

  defp t_subst_aux(r_c(tag: :tuple_set, elements: _) = tS, map) do
    t_sup(for t <- t_tuple_subtypes(tS) do
            t_subst_aux(t, map)
          end)
  end

  defp t_subst_aux(r_c(tag: :map, elements: {pairs, defK, defV}),
            map) do
    t_map(for {k, mNess, v} <- pairs do
            {k, mNess, t_subst_aux(v, map)}
          end,
            t_subst_aux(defK, map), t_subst_aux(defV, map))
  end

  defp t_subst_aux(r_c(tag: :opaque, elements: es), map) do
    list = (for (opaque = r_opaque(struct: s)) <- es do
              r_opaque(opaque, struct: t_subst_aux(s, map))
            end)
    r_c(tag: :opaque, elements: :ordsets.from_list(list))
  end

  defp t_subst_aux(r_c(tag: :union, elements: list), map) do
    r_c(tag: :union,
        elements: for e <- list do
                    t_subst_aux(e, map)
                  end)
  end

  defp t_subst_aux(t, _Map) do
    t
  end

  def t_unify_table_only(t1, t2) do
    t_unify_table_only(t1, t2, %{})
  end

  defp t_unify_table_only(r_c(tag: :var, elements: id),
            r_c(tag: :var, elements: id), varMap) do
    varMap
  end

  defp t_unify_table_only(r_c(tag: :var, elements: id1) = lHS,
            r_c(tag: :var, elements: id2) = rHS, varMap) do
    case (varMap) do
      %{^id1 => type1, ^id2 => type2} ->
        t_unify_table_only(type1, type2, varMap)
      %{^id1 => type} ->
        t_unify_table_only(type, rHS, varMap)
      %{^id2 => type} ->
        t_unify_table_only(lHS, type, varMap)
      %{} ->
        Map.merge(varMap, %{id1 => lHS, id2 => rHS})
    end
  end

  defp t_unify_table_only(r_c(tag: :var, elements: id), type, varMap) do
    case (varMap) do
      %{^id => varType} ->
        t_unify_table_only(varType, type, varMap)
      %{} ->
        Map.put(varMap, id, type)
    end
  end

  defp t_unify_table_only(type, r_c(tag: :var, elements: id), varMap) do
    case (varMap) do
      %{^id => varType} ->
        t_unify_table_only(varType, type, varMap)
      %{} ->
        Map.put(varMap, id, type)
    end
  end

  defp t_unify_table_only(r_c(tag: :function, elements: {domain1, range1}),
            r_c(tag: :function, elements: {domain2, range2}),
            varMap) do
    varMap1 = t_unify_table_only(domain1, domain2, varMap)
    t_unify_table_only(range1, range2, varMap1)
  end

  defp t_unify_table_only(r_c(tag: :list,
              elements: {contents1, termination1}, qualifier: size),
            r_c(tag: :list, elements: {contents2, termination2},
                qualifier: size),
            varMap) do
    varMap1 = t_unify_table_only(contents1, contents2,
                                   varMap)
    t_unify_table_only(termination1, termination2, varMap1)
  end

  defp t_unify_table_only(r_c(tag: :product, elements: types1),
            r_c(tag: :product, elements: types2), varMap) do
    unify_lists_table_only(types1, types2, varMap)
  end

  defp t_unify_table_only(r_c(tag: :tuple, elements: :any,
              qualifier: {:any, :any}),
            r_c(tag: :tuple, elements: :any, qualifier: {:any, :any}),
            varMap) do
    varMap
  end

  defp t_unify_table_only(r_c(tag: :tuple, elements: elements1,
              qualifier: {arity, _}),
            r_c(tag: :tuple, elements: elements2,
                qualifier: {arity, _}),
            varMap)
      when arity !== :any do
    unify_lists_table_only(elements1, elements2, varMap)
  end

  defp t_unify_table_only(r_c(tag: :tuple_set, elements: [{arity, _}]) = t1,
            r_c(tag: :tuple, elements: _, qualifier: {arity, _}) = t2,
            varMap)
      when arity !== :any do
    unify_tuple_set_and_tuple1_table_only(t1, t2, varMap)
  end

  defp t_unify_table_only(r_c(tag: :tuple, elements: _,
              qualifier: {arity, _}) = t1,
            r_c(tag: :tuple_set, elements: [{arity, _}]) = t2, varMap)
      when arity !== :any do
    unify_tuple_set_and_tuple2_table_only(t1, t2, varMap)
  end

  defp t_unify_table_only(r_c(tag: :tuple_set, elements: list1) = t1,
            r_c(tag: :tuple_set, elements: list2) = t2, varMap) do
    try do
      unify_lists_table_only(:lists.append(for {_Arity,
                                                  t} <- list1 do
                                             t
                                           end),
                               :lists.append(for {_Arity, t} <- list2 do
                                               t
                                             end),
                               varMap)
    catch
      _, _ ->
        throw({:mismatch, t1, t2})
    end
  end

  defp t_unify_table_only(r_c(tag: :map, elements: {_, aDefK, aDefV}) = a,
            r_c(tag: :map, elements: {_, bDefK, bDefV}) = b,
            varMap0) do
    varMap1 = t_unify_table_only(aDefK, bDefK, varMap0)
    varMap2 = t_unify_table_only(aDefV, bDefV, varMap1)
    {[], varMap} = map_pairwise_merge_foldr(fn _K, mNess,
                                                 v1, mNess, v2,
                                                 {pairs0, varMap3} ->
                                                 varMap4 = t_unify_table_only(v1,
                                                                                v2,
                                                                                varMap3)
                                                 {pairs0, varMap4}
                                               _K, _, v1, _, v2,
                                                 {pairs0, varMap3} ->
                                                 varMap4 = t_unify_table_only(v1,
                                                                                v2,
                                                                                varMap3)
                                                 {pairs0, varMap4}
                                            end,
                                              {[], varMap2}, a, b)
    varMap
  end

  defp t_unify_table_only(r_c(tag: :opaque, elements: _) = t1,
            r_c(tag: :opaque, elements: _) = t2, varMap) do
    t_unify_table_only(t_opaque_structure(t1),
                         t_opaque_structure(t2), varMap)
  end

  defp t_unify_table_only(t1, r_c(tag: :opaque, elements: _) = t2,
            varMap) do
    t_unify_table_only(t1, t_opaque_structure(t2), varMap)
  end

  defp t_unify_table_only(r_c(tag: :opaque, elements: _) = t1, t2,
            varMap) do
    t_unify_table_only(t_opaque_structure(t1), t2, varMap)
  end

  defp t_unify_table_only(t, t, varMap) do
    varMap
  end

  defp t_unify_table_only(r_c(tag: :union, elements: _) = t1,
            r_c(tag: :union, elements: _) = t2, varMap) do
    {type1, type2} = unify_union2(t1, t2)
    t_unify_table_only(type1, type2, varMap)
  end

  defp t_unify_table_only(r_c(tag: :union, elements: _) = t1, t2, varMap) do
    t_unify_table_only(unify_union1(t1, t1, t2), t2, varMap)
  end

  defp t_unify_table_only(t1, r_c(tag: :union, elements: _) = t2, varMap) do
    t_unify_table_only(t1, unify_union1(t2, t1, t2), varMap)
  end

  defp t_unify_table_only(t1, t2, _) do
    throw({:mismatch, t1, t2})
  end

  defp unify_tuple_set_and_tuple1_table_only(r_c(tag: :tuple_set, elements: [{arity, list}]),
            r_c(tag: :tuple, elements: elements2,
                qualifier: {arity, _}),
            varMap) do
    unify_lists_table_only(sup_tuple_elements(list),
                             elements2, varMap)
  end

  defp unify_tuple_set_and_tuple2_table_only(r_c(tag: :tuple, elements: elements2,
              qualifier: {arity, _}),
            r_c(tag: :tuple_set, elements: [{arity, list}]),
            varMap) do
    unify_lists_table_only(elements2,
                             sup_tuple_elements(list), varMap)
  end

  defp unify_lists_table_only([t1 | left1], [t2 | left2], varMap) do
    newVarMap = t_unify_table_only(t1, t2, varMap)
    unify_lists_table_only(left1, left2, newVarMap)
  end

  defp unify_lists_table_only([], [], varMap) do
    varMap
  end

  defp unify_union2(r_c(tag: :union, elements: list1) = t1,
            r_c(tag: :union, elements: list2) = t2) do
    case ({unify_union(list1), unify_union(list2)}) do
      {{:yes, type1}, {:yes, type2}} ->
        {type1, type2}
      {{:yes, type1}, :no} ->
        {type1, t2}
      {:no, {:yes, type2}} ->
        {t1, type2}
      {:no, :no} ->
        throw({:mismatch, t1, t2})
    end
  end

  defp unify_union1(r_c(tag: :union, elements: list), t1, t2) do
    case (unify_union(list)) do
      {:yes, type} ->
        type
      :no ->
        throw({:mismatch, t1, t2})
    end
  end

  defp unify_union(list) do
    [a, b, f, i, l, n, t, o, map] = list
    cond do
      o === :none ->
        :no
      true ->
        s = t_opaque_structure(o)
        {:yes, t_sup([a, b, f, i, l, n, t, s, map])}
    end
  end

  def is_opaque_type(r_c(tag: :opaque, elements: elements), opaques) do
    :lists.any(fn opaque ->
                    is_opaque_type2(opaque, opaques)
               end,
                 elements)
  end

  defp is_opaque_type2(r_opaque(mod: mod1, name: name1, arity: arity1),
            opaques) do
    f1 = fn r_c(tag: :opaque, elements: es) ->
              f2 = fn r_opaque(mod: mod, name: name, arity: arity) ->
                        is_type_name(mod1, name1, arity1, mod, name, arity)
                   end
              :lists.any(f2, es)
         end
    :lists.any(f1, opaques)
  end

  defp is_type_name(mod, name, arity, mod, name, arity) do
    true
  end

  defp is_type_name(_Mod1, _Name1, _Arity1, _Mod2, _Name2,
            _Arity2) do
    false
  end

  def t_subtract_list(t1, [t2 | left]) do
    t_subtract_list(t_subtract(t1, t2), left)
  end

  def t_subtract_list(t, []) do
    t
  end

  def t_subtract(_, :any) do
    :none
  end

  def t_subtract(t, r_c(tag: :var, elements: _)) do
    t
  end

  def t_subtract(:any, _) do
    :any
  end

  def t_subtract(r_c(tag: :var, elements: _) = t, _) do
    t
  end

  def t_subtract(t, :unit) do
    t
  end

  def t_subtract(:unit, _) do
    :unit
  end

  def t_subtract(:none, _) do
    :none
  end

  def t_subtract(t, :none) do
    t
  end

  def t_subtract(r_c(tag: :atom, elements: set1),
           r_c(tag: :atom, elements: set2)) do
    case (set_subtract(set1, set2)) do
      :none ->
        :none
      set ->
        r_c(tag: :atom, elements: set)
    end
  end

  def t_subtract(r_c(tag: :binary, elements: {u1, b1}),
           r_c(tag: :binary, elements: {u2, b2})) do
    subtract_bin(t_bitstr(u1, b1),
                   t_inf(t_bitstr(u1, b1), t_bitstr(u2, b2)))
  end

  def t_subtract(r_c(tag: :function, elements: {_, _}) = t1,
           r_c(tag: :function, elements: {_, _}) = t2) do
    case (t_is_subtype(t1, t2)) do
      true ->
        :none
      false ->
        t1
    end
  end

  def t_subtract(r_c(tag: :identifier, elements: set1),
           r_c(tag: :identifier, elements: set2)) do
    case (set_subtract(set1, set2)) do
      :none ->
        :none
      set ->
        r_c(tag: :identifier, elements: set)
    end
  end

  def t_subtract(r_c(tag: :opaque, elements: _) = t1,
           r_c(tag: :opaque, elements: _) = t2) do
    opaque_subtract(t1, t_opaque_structure(t2))
  end

  def t_subtract(r_c(tag: :opaque, elements: _) = t1, t2) do
    opaque_subtract(t1, t2)
  end

  def t_subtract(t1, r_c(tag: :opaque, elements: _) = t2) do
    t_subtract(t1, t_opaque_structure(t2))
  end

  def t_subtract(r_c(tag: nil), r_c(tag: nil)) do
    :none
  end

  def t_subtract(r_c(tag: nil),
           r_c(tag: :list, elements: {_, _},
               qualifier: :nonempty)) do
    r_c(tag: nil)
  end

  def t_subtract(r_c(tag: nil),
           r_c(tag: :list, elements: {_, _}, qualifier: _)) do
    :none
  end

  def t_subtract(r_c(tag: :list, elements: {contents, termination},
             qualifier: _Size) = t,
           r_c(tag: nil)) do
    case (termination === r_c(tag: nil)) do
      true ->
        r_c(tag: :list, elements: {contents, termination},
            qualifier: :nonempty)
      false ->
        t
    end
  end

  def t_subtract(r_c(tag: :list,
             elements: {contents1, termination1},
             qualifier: size1) = t,
           r_c(tag: :list, elements: {contents2, termination2},
               qualifier: size2)) do
    case (t_is_subtype(contents1, contents2)) do
      true ->
        case (t_is_subtype(termination1, termination2)) do
          true ->
            case ({size1, size2}) do
              {:nonempty, :unknown} ->
                :none
              {:unknown, :nonempty} ->
                r_c(tag: nil)
              {s, s} ->
                :none
            end
          false ->
            t
        end
      false ->
        t
    end
  end

  def t_subtract(r_c(tag: :number, elements: :any,
             qualifier: :float),
           r_c(tag: :number, elements: :any, qualifier: :float)) do
    :none
  end

  def t_subtract(r_c(tag: :number, elements: _, qualifier: _) = t1,
           r_c(tag: :number, elements: :any, qualifier: :float)) do
    t_inf(t1, t_integer())
  end

  def t_subtract(r_c(tag: :number, elements: :any,
             qualifier: :float),
           r_c(tag: :number, elements: _Set, qualifier: tag)) do
    case (tag) do
      :unknown ->
        :none
      _ ->
        r_c(tag: :number, elements: :any, qualifier: :float)
    end
  end

  def t_subtract(r_c(tag: :number, elements: _, qualifier: _),
           r_c(tag: :number, elements: :any, qualifier: :unknown)) do
    :none
  end

  def t_subtract(r_c(tag: :number, elements: _, qualifier: _) = t1,
           r_c(tag: :number, elements: :any, qualifier: :integer)) do
    t_inf(r_c(tag: :number, elements: :any,
              qualifier: :float),
            t1)
  end

  def t_subtract(r_c(tag: :number, elements: r_int_set(set: set1),
             qualifier: :integer),
           r_c(tag: :number, elements: r_int_set(set: set2),
               qualifier: :integer)) do
    case (set_subtract(set1, set2)) do
      :none ->
        :none
      set ->
        r_c(tag: :number, elements: r_int_set(set: set),
            qualifier: :integer)
    end
  end

  def t_subtract(r_c(tag: :number,
             elements: r_int_rng(from: from1, to: to1),
             qualifier: :integer) = t1,
           r_c(tag: :number, elements: r_int_rng(from: _, to: _),
               qualifier: :integer) = t2) do
    case (t_inf(t1, t2)) do
      :none ->
        t1
      r_c(tag: :number, elements: r_int_rng(from: ^from1, to: ^to1),
          qualifier: :integer) ->
        :none
      r_c(tag: :number, elements: r_int_rng(from: :neg_inf, to: to),
          qualifier: :integer) ->
        t_from_range(to + 1, to1)
      r_c(tag: :number, elements: r_int_rng(from: from, to: :pos_inf),
          qualifier: :integer) ->
        t_from_range(from1, from - 1)
      r_c(tag: :number, elements: r_int_rng(from: from, to: to),
          qualifier: :integer) ->
        t_sup(t_from_range(from1, from - 1),
                t_from_range(to + 1, to))
    end
  end

  def t_subtract(r_c(tag: :number, elements: r_int_rng(from: from, to: to),
             qualifier: :integer) = t1,
           r_c(tag: :number, elements: r_int_set(set: set),
               qualifier: :integer)) do
    newFrom = (case (set_is_element(from, set)) do
                 true ->
                   from + 1
                 false ->
                   from
               end)
    newTo = (case (set_is_element(to, set)) do
               true ->
                 to - 1
               false ->
                 to
             end)
    cond do
      newFrom === from and newTo === to ->
        t1
      true ->
        t_from_range(newFrom, newTo)
    end
  end

  def t_subtract(r_c(tag: :number, elements: r_int_set(set: set),
             qualifier: :integer),
           r_c(tag: :number, elements: r_int_rng(from: from, to: to),
               qualifier: :integer)) do
    case (set_filter(fn x ->
                          not (x <= from or x >= to)
                     end,
                       set)) do
      :none ->
        :none
      newSet ->
        r_c(tag: :number, elements: r_int_set(set: newSet),
            qualifier: :integer)
    end
  end

  def t_subtract(r_c(tag: :number, elements: :any,
             qualifier: :integer) = t1,
           r_c(tag: :number, elements: _, qualifier: :integer)) do
    t1
  end

  def t_subtract(r_c(tag: :number, elements: _, qualifier: _) = t1,
           r_c(tag: :number, elements: _, qualifier: _)) do
    t1
  end

  def t_subtract(r_c(tag: :tuple, elements: _, qualifier: {_, _}),
           r_c(tag: :tuple, elements: :any,
               qualifier: {:any, :any})) do
    :none
  end

  def t_subtract(r_c(tag: :tuple_set, elements: _),
           r_c(tag: :tuple, elements: :any,
               qualifier: {:any, :any})) do
    :none
  end

  def t_subtract(r_c(tag: :tuple, elements: :any,
             qualifier: {:any, :any}) = t1,
           r_c(tag: :tuple_set, elements: _)) do
    t1
  end

  def t_subtract(r_c(tag: :tuple, elements: elements1,
             qualifier: {arity1, _Tag1}) = t1,
           r_c(tag: :tuple, elements: elements2,
               qualifier: {arity2, _Tag2})) do
    cond do
      arity1 !== arity2 ->
        t1
      arity1 === arity2 ->
        newElements = t_subtract_lists(elements1, elements2)
        case (for e <- newElements, e !== :none do
                e
              end) do
          [] ->
            :none
          [_] ->
            t_tuple(replace_nontrivial_element(elements1,
                                                 newElements))
          _ ->
            t1
        end
    end
  end

  def t_subtract(r_c(tag: :tuple_set, elements: list1) = t1,
           r_c(tag: :tuple, elements: _,
               qualifier: {arity, _}) = t2) do
    case (:orddict.find(arity, list1)) do
      :error ->
        t1
      {:ok, list2} ->
        tuplesLeft0 = (for {_Arity,
                              tuple} <- :orddict.erase(arity, list1) do
                         tuple
                       end)
        tuplesLeft1 = :lists.append(tuplesLeft0)
        t_sup((for l <- list2 do
                 t_subtract(l, t2)
               end) ++ tuplesLeft1)
    end
  end

  def t_subtract(r_c(tag: :tuple, elements: _,
             qualifier: {arity, _}) = t1,
           r_c(tag: :tuple_set, elements: list1)) do
    case (:orddict.find(arity, list1)) do
      :error ->
        t1
      {:ok, list2} ->
        t_inf(for l <- list2 do
                t_subtract(t1, l)
              end)
    end
  end

  def t_subtract(r_c(tag: :tuple_set, elements: _) = t1,
           r_c(tag: :tuple_set, elements: _) = t2) do
    t_sup(for t <- t_tuple_subtypes(t1) do
            t_subtract(t, t2)
          end)
  end

  def t_subtract(r_c(tag: :product, elements: elements1) = t1,
           r_c(tag: :product, elements: elements2)) do
    arity1 = length(elements1)
    arity2 = length(elements2)
    cond do
      arity1 !== arity2 ->
        t1
      arity1 === arity2 ->
        newElements = t_subtract_lists(elements1, elements2)
        case (for e <- newElements, e !== :none do
                e
              end) do
          [] ->
            :none
          [_] ->
            t_product(replace_nontrivial_element(elements1,
                                                   newElements))
          _ ->
            t1
        end
    end
  end

  def t_subtract(r_c(tag: :map,
             elements: {aPairs, aDefK, aDefV}) = a,
           r_c(tag: :map, elements: {_, bDefK, bDefV}) = b) do
    case (t_is_subtype(aDefK, bDefK) and t_is_subtype(aDefV,
                                                        bDefV)) do
      false ->
        a
      true ->
        case (map_pairwise_merge(fn k, :optional, v1,
                                      :mandatory, v2 ->
                                      {k, :optional, t_subtract(v1, v2)}
                                    k, _, v1, _, v2 ->
                                      case (t_subtract(v1, v2)) do
                                        :none ->
                                          false
                                        partial ->
                                          {k, :mandatory, partial}
                                      end
                                 end,
                                   a, b)) do
          [] ->
            :none
          [e] ->
            t_map(mapdict_store(e, aPairs), aDefK, aDefV)
          _ ->
            a
        end
    end
  end

  def t_subtract(r_c(tag: :product, elements: p1), _) do
    r_c(tag: :product, elements: p1)
  end

  def t_subtract(t, r_c(tag: :product, elements: _)) do
    t
  end

  def t_subtract(r_c(tag: :union, elements: u1),
           r_c(tag: :union, elements: u2)) do
    subtract_union(u1, u2)
  end

  def t_subtract(t1, t2) do
    r_c(tag: :union, elements: u1) = force_union(t1)
    r_c(tag: :union, elements: u2) = force_union(t2)
    subtract_union(u1, u2)
  end

  defp opaque_subtract(r_c(tag: :opaque, elements: set1), t2) do
    list = (for (r_opaque(struct: s1) = t1) <- set1,
                  not t_is_none(sub = t_subtract(s1, t2)) do
              r_opaque(t1, struct: sub)
            end)
    case (list) do
      [] ->
        :none
      _ ->
        r_c(tag: :opaque, elements: :ordsets.from_list(list))
    end
  end

  defp t_subtract_lists(l1, l2) do
    t_subtract_lists(l1, l2, [])
  end

  defp t_subtract_lists([t1 | left1], [t2 | left2], acc) do
    t_subtract_lists(left1, left2,
                       [t_subtract(t1, t2) | acc])
  end

  defp t_subtract_lists([], [], acc) do
    :lists.reverse(acc)
  end

  defp subtract_union(u1, u2) do
    [a1, b1, f1, i1, l1, n1, t1, o1, map1] = u1
    [a2, b2, f2, i2, l2, n2, t2, o2, map2] = u2
    list1 = [a1, b1, f1, i1, l1, n1, t1, :none, map1]
    list2 = [a2, b2, f2, i2, l2, n2, t2, :none, map2]
    sub1 = subtract_union(list1, list2, :none, [])
    o = (cond do
           o1 === :none ->
             o1
           true ->
             t_subtract(o1, r_c(tag: :union, elements: u2))
         end)
    sub2 = (cond do
              o2 === :none ->
                sub1
              true ->
                t_subtract(sub1, t_opaque_structure(o2))
            end)
    t_sup(o, sub2)
  end

  defp subtract_union([t1 | left1], [t2 | left2], type, acc) do
    case (t_subtract(t1, t2)) do
      :none ->
        subtract_union(left1, left2, type, [:none | acc])
      t when type === :none ->
        subtract_union(left1, left2, t, [t | acc])
      t ->
        subtract_union(left1, left2, :union, [t | acc])
    end
  end

  defp subtract_union([], [], type, acc) do
    case (type) do
      :union ->
        r_c(tag: :union, elements: :lists.reverse(acc))
      _ ->
        type
    end
  end

  defp replace_nontrivial_element([t1 | left1], [:none | left2]) do
    [t1 | replace_nontrivial_element(left1, left2)]
  end

  defp replace_nontrivial_element([_ | left1], [t2 | _]) do
    [t2 | left1]
  end

  defp subtract_bin(r_c(tag: :binary, elements: {u1, b1}),
            r_c(tag: :binary, elements: {u1, b1})) do
    :none
  end

  defp subtract_bin(r_c(tag: :binary, elements: {u1, b1}), :none) do
    t_bitstr(u1, b1)
  end

  defp subtract_bin(r_c(tag: :binary, elements: {u1, b1}),
            r_c(tag: :binary, elements: {0, b1})) do
    t_bitstr(u1, b1 + u1)
  end

  defp subtract_bin(r_c(tag: :binary, elements: {u1, b1}),
            r_c(tag: :binary, elements: {u1, b2})) do
    cond do
      b1 + u1 !== b2 ->
        t_bitstr(0, b1)
      true ->
        t_bitstr(u1, b1)
    end
  end

  defp subtract_bin(r_c(tag: :binary, elements: {u1, b1}),
            r_c(tag: :binary, elements: {u2, b2})) do
    cond do
      2 * u1 === u2 ->
        cond do
          b1 === b2 ->
            t_bitstr(u2, b1 + u1)
          b1 + u1 === b2 ->
            t_bitstr(u2, b1)
          true ->
            t_bitstr(u1, b1)
        end
      true ->
        t_bitstr(u1, b1)
    end
  end

  def t_is_equal(t, t) do
    true
  end

  def t_is_equal(_, _) do
    false
  end

  def t_is_subtype(t1, t2) do
    inf = t_inf(t1, t2)
    subtype_is_equal(t1, inf)
  end

  defp subtype_is_equal(t, t) do
    true
  end

  defp subtype_is_equal(t1, t2) do
    t_is_equal(case (t_contains_opaque(t1)) do
                 true ->
                   t_unopaque(t1)
                 false ->
                   t1
               end,
                 case (t_contains_opaque(t2)) do
                   true ->
                     t_unopaque(t2)
                   false ->
                     t2
                 end)
  end

  def t_is_instance(concreteType, type) do
    t_is_subtype(concreteType, t_unopaque(type))
  end

  defp t_do_overlap(typeA, typeB) do
    not t_is_impossible(t_inf(typeA, typeB))
  end

  def t_unopaque(t) do
    t_unopaque(t, :universe)
  end

  def t_unopaque(r_c(tag: :opaque, elements: _) = t, opaques) do
    case (opaques === :universe or is_opaque_type(t,
                                                    opaques)) do
      true ->
        t_unopaque(t_opaque_structure(t), opaques)
      false ->
        t
    end
  end

  def t_unopaque(r_c(tag: :list, elements: {elemT, termination},
             qualifier: sz),
           opaques) do
    r_c(tag: :list,
        elements: {t_unopaque(elemT, opaques),
                     t_unopaque(termination, opaques)},
        qualifier: sz)
  end

  def t_unopaque(r_c(tag: :tuple, elements: :any,
             qualifier: {_, _}) = t,
           _) do
    t
  end

  def t_unopaque(r_c(tag: :tuple, elements: argTs,
             qualifier: {sz, tag}),
           opaques)
      when is_list(argTs) do
    newArgTs = (for a <- argTs do
                  t_unopaque(a, opaques)
                end)
    r_c(tag: :tuple, elements: newArgTs, qualifier: {sz, tag})
  end

  def t_unopaque(r_c(tag: :tuple_set, elements: set), opaques) do
    newSet = (for {sz, tuples} <- set do
                {sz,
                   for t <- tuples do
                     t_unopaque(t, opaques)
                   end}
              end)
    r_c(tag: :tuple_set, elements: newSet)
  end

  def t_unopaque(r_c(tag: :product, elements: types), opaques) do
    r_c(tag: :product,
        elements: for t <- types do
                    t_unopaque(t, opaques)
                  end)
  end

  def t_unopaque(r_c(tag: :function, elements: {domain, range}),
           opaques) do
    r_c(tag: :function,
        elements: {t_unopaque(domain, opaques),
                     t_unopaque(range, opaques)})
  end

  def t_unopaque(r_c(tag: :union,
             elements: [a, b, f, i, l, n, t, o, map]),
           opaques) do
    uL = t_unopaque(l, opaques)
    uT = t_unopaque(t, opaques)
    uF = t_unopaque(f, opaques)
    uMap = t_unopaque(map, opaques)
    {oF, uO} = (case (t_unopaque(o, opaques)) do
                  r_c(tag: :opaque, elements: _) = o1 ->
                    {o1, []}
                  type ->
                    {:none, [type]}
                end)
    t_sup([r_c(tag: :union,
               elements: [a, b, uF, i, uL, n, uT, oF, uMap]) |
               uO])
  end

  def t_unopaque(r_c(tag: :map, elements: {pairs, defK, defV}),
           opaques) do
    t_map(for {k, mNess, v} <- pairs do
            {k, mNess, t_unopaque(v, opaques)}
          end,
            t_unopaque(defK, opaques), t_unopaque(defV, opaques))
  end

  def t_unopaque(t, _) do
    t
  end

  def t_limit(term, k) when is_integer(k) do
    case (is_limited(term, k)) do
      true ->
        term
      false ->
        t_limit_k(term, k)
    end
  end

  defp is_limited(:any, _) do
    true
  end

  defp is_limited(_, k) when k <= 0 do
    false
  end

  defp is_limited(r_c(tag: :tuple, elements: :any,
              qualifier: {:any, :any}),
            _K) do
    true
  end

  defp is_limited(r_c(tag: :tuple, elements: elements,
              qualifier: {_Arity, _}),
            k) do
    cond do
      k === 1 ->
        false
      true ->
        are_all_limited(elements, k - 1)
    end
  end

  defp is_limited(r_c(tag: :tuple_set, elements: _) = t, k) do
    are_all_limited(t_tuple_subtypes(t), k)
  end

  defp is_limited(r_c(tag: :list, elements: {elements, r_c(tag: nil)},
              qualifier: _Size),
            k) do
    is_limited(elements, k - 1)
  end

  defp is_limited(r_c(tag: :list, elements: {elements, termination},
              qualifier: _Size),
            k) do
    (cond do
       k === 1 ->
         is_limited(termination, k)
       true ->
         is_limited(termination, k - 1)
     end) and is_limited(elements, k - 1)
  end

  defp is_limited(r_c(tag: :function, elements: {domain, range}),
            k) do
    is_limited(domain, k) and is_limited(range, k - 1)
  end

  defp is_limited(r_c(tag: :product, elements: elements), k) do
    are_all_limited(elements, k - 1)
  end

  defp is_limited(r_c(tag: :union, elements: elements), k) do
    are_all_limited(elements, k)
  end

  defp is_limited(r_c(tag: :opaque, elements: es), k) do
    :lists.all(fn r_opaque(struct: s) ->
                    is_limited(s, k)
               end,
                 es)
  end

  defp is_limited(r_c(tag: :map, elements: {pairs, defK, defV}),
            k) do
    k1 = k - 1
    :lists.all(fn {key, _, value} ->
                    (is_limited(key, k1) and is_limited(value, k1))
               end,
                 pairs) and is_limited(defK, k1) and is_limited(defV, k1)
  end

  defp is_limited(_, _K) do
    true
  end

  defp are_all_limited([e | es], k) do
    is_limited(e, k) and are_all_limited(es, k)
  end

  defp are_all_limited([], _) do
    true
  end

  defp t_limit_k(_, k) when k <= 0 do
    :any
  end

  defp t_limit_k(r_c(tag: :tuple, elements: :any,
              qualifier: {:any, :any}) = t,
            _K) do
    t
  end

  defp t_limit_k(r_c(tag: :tuple, elements: elements,
              qualifier: {arity, _}),
            k) do
    cond do
      k === 1 ->
        t_tuple(arity)
      true ->
        t_tuple(for e <- elements do
                  t_limit_k(e, k - 1)
                end)
    end
  end

  defp t_limit_k(r_c(tag: :tuple_set, elements: _) = t, k) do
    t_sup(for tuple <- t_tuple_subtypes(t) do
            t_limit_k(tuple, k)
          end)
  end

  defp t_limit_k(r_c(tag: :list, elements: {elements, r_c(tag: nil)},
              qualifier: size),
            k) do
    newElements = t_limit_k(elements, k - 1)
    r_c(tag: :list, elements: {newElements, r_c(tag: nil)},
        qualifier: size)
  end

  defp t_limit_k(r_c(tag: :list, elements: {elements, termination},
              qualifier: size),
            k) do
    newTermination = (cond do
                        k === 1 ->
                          t_limit_k(termination, k)
                        true ->
                          t_limit_k(termination, k - 1)
                      end)
    newElements = t_limit_k(elements, k - 1)
    r_c(tag: :list, elements: {newElements, newTermination},
        qualifier: size)
  end

  defp t_limit_k(r_c(tag: :function, elements: {domain, range}),
            k) do
    r_c(tag: :function,
        elements: {t_limit_k(domain, k),
                     t_limit_k(range, k - 1)})
  end

  defp t_limit_k(r_c(tag: :product, elements: elements), k) do
    r_c(tag: :product,
        elements: for x <- elements do
                    t_limit_k(x, k - 1)
                  end)
  end

  defp t_limit_k(r_c(tag: :union, elements: elements), k) do
    r_c(tag: :union,
        elements: for x <- elements do
                    t_limit_k(x, k)
                  end)
  end

  defp t_limit_k(r_c(tag: :opaque, elements: es), k) do
    list = (for (r_opaque(struct: s) = opaque) <- es do
              (
                newS = t_limit_k(s, k)
                r_opaque(opaque, struct: newS)
              )
            end)
    r_c(tag: :opaque, elements: :ordsets.from_list(list))
  end

  defp t_limit_k(r_c(tag: :map, elements: {pairs0, defK0, defV0}),
            k) do
    fun = fn {eK, mNess, eV}, {exact, defK1, defV1} ->
               lV = t_limit_k(eV, k - 1)
               case (t_limit_k(eK, k - 1)) do
                 ^eK ->
                   {[{eK, mNess, lV} | exact], defK1, defV1}
                 lK ->
                   {exact, t_sup(lK, defK1), t_sup(lV, defV1)}
               end
          end
    {pairs, defK2, defV2} = :lists.foldr(fun,
                                           {[], defK0, defV0}, pairs0)
    t_map(pairs, t_limit_k(defK2, k - 1),
            t_limit_k(defV2, k - 1))
  end

  defp t_limit_k(t, _K) do
    t
  end

  def t_abstract_records(r_c(tag: :list, elements: {contents, termination},
             qualifier: size),
           recDict) do
    case (t_abstract_records(contents, recDict)) do
      :none ->
        :none
      newContents ->
        case (t_abstract_records(termination, recDict)) do
          r_c(tag: nil) ->
            r_c(tag: :list, elements: {newContents, r_c(tag: nil)},
                qualifier: size)
          :any ->
            r_c(tag: :list, elements: {newContents, :any},
                qualifier: size)
          other ->
            r_c(tag: :list, elements: {newContents2, newTermination},
                qualifier: _) = t_cons(newContents, other)
            r_c(tag: :list, elements: {newContents2, newTermination},
                qualifier: size)
        end
    end
  end

  def t_abstract_records(r_c(tag: :function, elements: {domain, range}),
           recDict) do
    r_c(tag: :function,
        elements: {t_abstract_records(domain, recDict),
                     t_abstract_records(range, recDict)})
  end

  def t_abstract_records(r_c(tag: :product, elements: types), recDict) do
    r_c(tag: :product,
        elements: for t <- types do
                    t_abstract_records(t, recDict)
                  end)
  end

  def t_abstract_records(r_c(tag: :union, elements: types), recDict) do
    t_sup(for t <- types do
            t_abstract_records(t, recDict)
          end)
  end

  def t_abstract_records(r_c(tag: :tuple, elements: :any,
             qualifier: {:any, :any}) = t,
           _RecDict) do
    t
  end

  def t_abstract_records(r_c(tag: :tuple, elements: elements,
             qualifier: {arity, r_c(tag: :atom, elements: _) = tag}),
           recDict) do
    [tagAtom] = atom_vals(tag)
    case (lookup_record(tagAtom, arity - 1, recDict)) do
      :error ->
        t_tuple(for e <- elements do
                  t_abstract_records(e, recDict)
                end)
      {:ok, fields} ->
        t_tuple([tag | for {_Name, _Abstr, t} <- fields do
                         t
                       end])
    end
  end

  def t_abstract_records(r_c(tag: :tuple, elements: elements,
             qualifier: {_Arity, _Tag}),
           recDict) do
    t_tuple(for e <- elements do
              t_abstract_records(e, recDict)
            end)
  end

  def t_abstract_records(r_c(tag: :tuple_set, elements: _) = tuples,
           recDict) do
    t_sup(for t <- t_tuple_subtypes(tuples) do
            t_abstract_records(t, recDict)
          end)
  end

  def t_abstract_records(r_c(tag: :opaque, elements: _) = type, recDict) do
    t_abstract_records(t_opaque_structure(type), recDict)
  end

  def t_abstract_records(t, _RecDict) do
    t
  end

  def t_to_string(t) do
    t_to_string(t, :maps.new())
  end

  def t_to_string(:any, _RecDict) do
    'any()'
  end

  def t_to_string(:none, _RecDict) do
    'none()'
  end

  def t_to_string(:unit, _RecDict) do
    'no_return()'
  end

  def t_to_string(r_c(tag: :atom, elements: :any), _RecDict) do
    'atom()'
  end

  def t_to_string(r_c(tag: :atom, elements: set), _RecDict) do
    case (length(set)) do
      2 ->
        case (set_is_element(true,
                               set) and set_is_element(false, set)) do
          true ->
            'boolean()'
          false ->
            set_to_string(set)
        end
      _ ->
        set_to_string(set)
    end
  end

  def t_to_string(r_c(tag: :binary, elements: {0, 0}), _RecDict) do
    '<<>>'
  end

  def t_to_string(r_c(tag: :binary, elements: {8, 0}), _RecDict) do
    'binary()'
  end

  def t_to_string(r_c(tag: :binary, elements: {8, 8}), _RecDict) do
    'nonempty_binary()'
  end

  def t_to_string(r_c(tag: :binary, elements: {1, 0}), _RecDict) do
    'bitstring()'
  end

  def t_to_string(r_c(tag: :binary, elements: {1, 1}), _RecDict) do
    'nonempty_bitstring()'
  end

  def t_to_string(r_c(tag: :binary, elements: {0, b}), _RecDict) do
    flat_format('<<_:~w>>', [b])
  end

  def t_to_string(r_c(tag: :binary, elements: {u, 0}), _RecDict) do
    flat_format('<<_:_*~w>>', [u])
  end

  def t_to_string(r_c(tag: :binary, elements: {u, b}), _RecDict) do
    flat_format('<<_:~w,_:_*~w>>', [b, u])
  end

  def t_to_string(r_c(tag: :function, elements: {:any, :any}),
           _RecDict) do
    'fun()'
  end

  def t_to_string(r_c(tag: :function, elements: {:any, range}),
           recDict) do
    'fun((...) -> ' ++ t_to_string(range, recDict) ++ ')'
  end

  def t_to_string(r_c(tag: :function,
             elements: {r_c(tag: :product, elements: argList), range}),
           recDict) do
    'fun((' ++ comma_sequence(argList,
                          recDict) ++ ') -> ' ++ t_to_string(range, recDict) ++ ')'
  end

  def t_to_string(r_c(tag: :identifier, elements: set), _RecDict) do
    case (set) do
      :any ->
        'identifier()'
      _ ->
        flat_join(for t <- set do
                    flat_format('~w()', [t])
                  end,
                    ' | ')
    end
  end

  def t_to_string(r_c(tag: :opaque, elements: set), recDict) do
    flat_join(for r_opaque(mod: mod, name: name, struct: s,
                      arity: arity) <- set do
                opaque_type(mod, name, arity, s, recDict)
              end,
                ' | ')
  end

  def t_to_string(r_c(tag: nil), _RecDict) do
    '[]'
  end

  def t_to_string(r_c(tag: :list, elements: {contents, termination},
             qualifier: :nonempty),
           recDict) do
    contentString = t_to_string(contents, recDict)
    case (termination) do
      r_c(tag: nil) ->
        case (contents) do
          r_c(tag: :number, elements: r_int_rng(from: 0, to: 1114111),
              qualifier: :integer) ->
            'nonempty_string()'
          _ ->
            '[' ++ contentString ++ ',...]'
        end
      :any ->
        case (contents === :any) do
          true ->
            :ok
          false ->
            :ok
        end
        'nonempty_maybe_improper_list()'
      _ ->
        case (t_is_subtype(t_nil(), termination)) do
          true ->
            'nonempty_maybe_improper_list(' ++ contentString ++ ',' ++ t_to_string(termination,
                                                     recDict) ++ ')'
          false ->
            'nonempty_improper_list(' ++ contentString ++ ',' ++ t_to_string(termination,
                                                     recDict) ++ ')'
        end
    end
  end

  def t_to_string(r_c(tag: :list, elements: {contents, termination},
             qualifier: :unknown),
           recDict) do
    contentString = t_to_string(contents, recDict)
    case (termination) do
      r_c(tag: nil) ->
        case (contents) do
          r_c(tag: :number, elements: r_int_rng(from: 0, to: 1114111),
              qualifier: :integer) ->
            'string()'
          _ ->
            '[' ++ contentString ++ ']'
        end
      :any ->
        case (contents === :any) do
          true ->
            :ok
          false ->
            :ok
        end
        'maybe_improper_list()'
      _ ->
        case (t_is_subtype(t_nil(), termination)) do
          true ->
            'maybe_improper_list(' ++ contentString ++ ',' ++ t_to_string(termination,
                                                     recDict) ++ ')'
          false ->
            'maybe_improper_list(' ++ contentString ++ ',' ++ t_to_string(termination,
                                                     recDict) ++ ')'
        end
    end
  end

  def t_to_string(r_c(tag: :number, elements: r_int_set(set: set),
             qualifier: :integer),
           _RecDict) do
    set_to_string(set)
  end

  def t_to_string(r_c(tag: :number, elements: r_int_rng(from: 0, to: 255),
             qualifier: :integer),
           _RecDict) do
    'byte()'
  end

  def t_to_string(r_c(tag: :number,
             elements: r_int_rng(from: 0, to: 1114111), qualifier: :integer),
           _RecDict) do
    'char()'
  end

  def t_to_string(r_c(tag: :number,
             elements: r_int_rng(from: 1, to: :pos_inf),
             qualifier: :integer),
           _RecDict) do
    'pos_integer()'
  end

  def t_to_string(r_c(tag: :number,
             elements: r_int_rng(from: 0, to: :pos_inf),
             qualifier: :integer),
           _RecDict) do
    'non_neg_integer()'
  end

  def t_to_string(r_c(tag: :number,
             elements: r_int_rng(from: :neg_inf, to: - 1),
             qualifier: :integer),
           _RecDict) do
    'neg_integer()'
  end

  def t_to_string(r_c(tag: :number, elements: r_int_rng(from: from, to: to),
             qualifier: :integer),
           _RecDict) do
    flat_format('~w..~w', [from, to])
  end

  def t_to_string(r_c(tag: :number, elements: :any,
             qualifier: :integer),
           _RecDict) do
    'integer()'
  end

  def t_to_string(r_c(tag: :number, elements: :any,
             qualifier: :float),
           _RecDict) do
    'float()'
  end

  def t_to_string(r_c(tag: :number, elements: :any,
             qualifier: :unknown),
           _RecDict) do
    'number()'
  end

  def t_to_string(r_c(tag: :product, elements: list), recDict) do
    '<' ++ comma_sequence(list, recDict) ++ '>'
  end

  def t_to_string(r_c(tag: :map, elements: {[], :any, :any}),
           _RecDict) do
    'map()'
  end

  def t_to_string(r_c(tag: :map, elements: {pairs0, defK, defV}),
           recDict) do
    {pairs, extraEl} = (case ({defK, defV}) do
                          {:none, :none} ->
                            {pairs0, []}
                          _ ->
                            {pairs0 ++ [{defK, :optional, defV}], []}
                        end)
    tos = fn t ->
               case (t) do
                 :any ->
                   '_'
                 _ ->
                   t_to_string(t, recDict)
               end
          end
    strMand = (for {k, :mandatory, v} <- pairs do
                 {tos.(k), tos.(v)}
               end)
    strOpt = (for {k, :optional, v} <- pairs do
                {tos.(k), tos.(v)}
              end)
    '\#{' ++ flat_join(((for {k, v} <- strMand do
                         k ++ ':=' ++ v
                       end) ++ (for {k, v} <- strOpt do
                                  k ++ '=>' ++ v
                                end) ++ extraEl),
                       ', ') ++ '}'
  end

  def t_to_string(r_c(tag: :tuple, elements: :any,
             qualifier: {:any, :any}),
           _RecDict) do
    'tuple()'
  end

  def t_to_string(r_c(tag: :tuple, elements: elements,
             qualifier: {_Arity, :any}),
           recDict) do
    '{' ++ comma_sequence(elements, recDict) ++ '}'
  end

  def t_to_string(r_c(tag: :tuple, elements: elements,
             qualifier: {arity, tag}),
           recDict) do
    [tagAtom] = atom_vals(tag)
    case (lookup_record(tagAtom, arity - 1, recDict)) do
      :error ->
        '{' ++ comma_sequence(elements, recDict) ++ '}'
      {:ok, fieldNames} ->
        record_to_string(tagAtom, elements, fieldNames, recDict)
    end
  end

  def t_to_string(r_c(tag: :tuple_set, elements: _) = t, recDict) do
    union_sequence(t_tuple_subtypes(t), recDict)
  end

  def t_to_string(r_c(tag: :union, elements: types), recDict) do
    union_sequence(for t <- types, t !== :none do
                     t
                   end,
                     recDict)
  end

  def t_to_string(r_c(tag: :var, elements: id), _RecDict)
      when is_atom(id) do
    flat_format('~s', [:erlang.atom_to_list(id)])
  end

  def t_to_string(r_c(tag: :var, elements: id), _RecDict)
      when is_integer(id) do
    flat_format('var(~w)', [id])
  end

  defp record_to_string(tag, [_ | fields], fieldNames, recDict) do
    fieldStrings = record_fields_to_string(fields,
                                             fieldNames, recDict, [])
    '#' ++ atom_to_string(tag) ++ '{' ++ flat_join(fieldStrings,
                                                 ',') ++ '}'
  end

  defp record_fields_to_string([f | fs], [{fName, _Abstr, defType} | fDefs],
            recDict, acc) do
    newAcc = (case (t_is_equal(f,
                                 t_any()) or t_is_any_atom(:undefined,
                                                             f) and not
                                                                    t_is_none(t_inf(f,
                                                                                      defType))) do
                true ->
                  acc
                false ->
                  strFV = atom_to_string(fName) ++ '::' ++ t_to_string(f,
                                                                      recDict)
                  [strFV | acc]
              end)
    record_fields_to_string(fs, fDefs, recDict, newAcc)
  end

  defp record_fields_to_string([], [], _RecDict, acc) do
    :lists.reverse(acc)
  end

  def record_field_diffs_to_string(r_c(tag: :tuple, elements: [_ | fs],
             qualifier: {arity, tag}),
           recDict) do
    [tagAtom] = atom_vals(tag)
    {:ok, fieldNames} = lookup_record(tagAtom, arity - 1,
                                        recDict)
    diffs = field_diffs(fs, fieldNames, 1, recDict, [])
    {fNs, fieldDiffs} = :lists.unzip(diffs)
    {fNs, flat_join(fieldDiffs, ' and ')}
  end

  defp field_diffs([f | fs], [{fName, _Abstr, defType} | fDefs],
            pos, recDict, acc) do
    newAcc = (case (not t_is_none(t_inf(f, defType))) do
                true ->
                  acc
                false ->
                  str = atom_to_string(fName) ++ '::' ++ t_to_string(defType,
                                                                    recDict)
                  [{pos, str} | acc]
              end)
    field_diffs(fs, fDefs, pos + 1, recDict, newAcc)
  end

  defp field_diffs([], [], _, _, acc) do
    :lists.reverse(acc)
  end

  defp comma_sequence(types, recDict) do
    list = (for t <- types do
              case (t === :any) do
                true ->
                  '_'
                false ->
                  t_to_string(t, recDict)
              end
            end)
    flat_join(list, ',')
  end

  defp union_sequence(types, recDict) do
    list = (for t <- types do
              t_to_string(t, recDict)
            end)
    flat_join(list, ' | ')
  end

  defp opaque_type(mod, name, arity, _S, _RecDict) do
    opaque_name(mod, name, arity)
  end

  defp opaque_name(mod, name, arity) do
    s = mod_name(mod, name)
    args = :lists.join(?,, :lists.duplicate(arity, ?_))
    flat_format('~ts(~ts)', [s, args])
  end

  defp mod_name(mod, name) do
    flat_format('~w:~tw', [mod, name])
  end

  Record.defrecord(:r_cache, :cache, types: %{}, mod_recs: %{})
  def t_from_form(form, expTypes, site, recDict, varTab, cache) do
    t_from_form1(form, expTypes, site, recDict, varTab,
                   cache)
  end

  def t_from_form_without_remote(form, site, typeTable) do
    module = site_module(site)
    modRecs = %{module => typeTable}
    expTypes = :replace_by_none
    varTab = var_table__new()
    cache0 = cache__new()
    cache = r_cache(cache0, mod_recs: modRecs)
    {type, _} = t_from_form1(form, expTypes, site,
                               :undefined, varTab, cache)
    type
  end

  Record.defrecord(:r_from_form, :from_form, site: :undefined,
                                     xtypes: :undefined, mrecs: :undefined,
                                     vtab: :undefined, tnames: :undefined)
  def t_from_form_check_remote(form, expTypes, site, recDict) do
    state = r_from_form(site: site, xtypes: expTypes, mrecs: recDict,
                vtab: var_table__new(), tnames: [])
    d = 1 <<< 25
    l = 1 <<< 25
    cache0 = cache__new()
    _ = t_from_form2(form, state, d, l, cache0)
    :ok
  end

  defp t_from_form1(form, eT, site, mR, v, c) do
    typeNames = initial_typenames(site)
    d = 16
    l = 10000
    state = r_from_form(site: site, xtypes: eT, mrecs: mR, vtab: v,
                tnames: typeNames)
    t_from_form2(form, state, d, l, c)
  end

  defp t_from_form2(form, state, d, l, c) do
    {t0, l0, c0} = from_form(form, state, d, l, c)
    cond do
      l0 <= 0 ->
        {t1, _, c1} = from_form(form, state, 1, l, c0)
        from_form_loop(form, state, 2, l, c1, t1)
      true ->
        {t0, c0}
    end
  end

  defp initial_typenames({:type, mTA, _File}) do
    [{:type, mTA}]
  end

  defp initial_typenames({:spec, _MFA, _File}) do
    []
  end

  defp initial_typenames({:record, _MRA, _File}) do
    []
  end

  defp from_form_loop(form, state, d, limit, c, t0) do
    {t1, l1, c1} = from_form(form, state, d, limit, c)
    delta = limit - l1
    cond do
      l1 <= 0 ->
        {t0, c1}
      delta * 8 > limit ->
        {t1, c1}
      d === 4 ->
        {t1, c1}
      true ->
        d1 = d + 1
        from_form_loop(form, state, d1, limit, c1, t1)
    end
  end

  defp from_form(_, _S, d, l, _C) when not is_integer(d) or
                                  not is_integer(l) do
    :erlang.error(:badarg)
  end

  defp from_form(_, _S, d, l, c) when d <= 0 or l <= 0 do
    {t_any(), l, c}
  end

  defp from_form({:var, _Anno, :_}, _S, _D, l, c) do
    {t_any(), l, c}
  end

  defp from_form({:var, _Anno, name}, s, _D, l, c) do
    case (r_from_form(s, :vtab)) do
      %{^name => val} ->
        {val, l, c}
      %{} ->
        {t_var(name), l, c}
    end
  end

  defp from_form({:ann_type, _Anno, [_Var, type]}, s, d, l, c) do
    from_form(type, s, d, l, c)
  end

  defp from_form({:paren_type, _Anno, [type]}, s, d, l, c) do
    from_form(type, s, d, l, c)
  end

  defp from_form({:remote_type, anno,
             [{:atom, _, module}, {:atom, _, type}, args]},
            s, d, l, c) do
    remote_from_form(anno, module, type, args, s, d, l, c)
  end

  defp from_form({:atom, _Anno, atom}, _S, _D, l, c) do
    {t_atom(atom), l, c}
  end

  defp from_form({:integer, _Anno, int}, _S, _D, l, c) do
    {t_integer(int), l, c}
  end

  defp from_form({:char, _Anno, char}, _S, _D, l, c) do
    {t_integer(char), l, c}
  end

  defp from_form({:op, _Anno, _Op, _Arg} = op, _S, _D, l, c) do
    case (:erl_eval.partial_eval(op)) do
      {:integer, _, val} ->
        {t_integer(val), l, c}
      _ ->
        throw({:error, :io_lib.format('Unable to evaluate type ~w\n', [op])})
    end
  end

  defp from_form({:op, _Anno, _Op, _Arg1, _Arg2} = op, _S, _D, l,
            c) do
    case (:erl_eval.partial_eval(op)) do
      {:integer, _, val} ->
        {t_integer(val), l, c}
      _ ->
        throw({:error, :io_lib.format('Unable to evaluate type ~w\n', [op])})
    end
  end

  defp from_form({:type, _Anno, :any, []}, _S, _D, l, c) do
    {t_any(), l, c}
  end

  defp from_form({:type, _Anno, :arity, []}, _S, _D, l, c) do
    {t_arity(), l, c}
  end

  defp from_form({:type, _Anno, :atom, []}, _S, _D, l, c) do
    {t_atom(), l, c}
  end

  defp from_form({:type, _Anno, :binary, []}, _S, _D, l, c) do
    {t_binary(), l, c}
  end

  defp from_form({:type, _Anno, :binary, [base, unit]} = type,
            _S, _D, l, c) do
    case ({:erl_eval.partial_eval(base),
             :erl_eval.partial_eval(unit)}) do
      {{:integer, _, b}, {:integer, _, u}} when (b >= 0 and
                                                   u >= 0)
                                                ->
        {t_bitstr(u, b), l, c}
      _ ->
        throw({:error, :io_lib.format('Unable to evaluate type ~w\n', [type])})
    end
  end

  defp from_form({:type, _Anno, :bitstring, []}, _S, _D, l, c) do
    {t_bitstr(), l, c}
  end

  defp from_form({:type, _Anno, :bool, []}, _S, _D, l, c) do
    {t_boolean(), l, c}
  end

  defp from_form({:type, _Anno, :boolean, []}, _S, _D, l, c) do
    {t_boolean(), l, c}
  end

  defp from_form({:type, _Anno, :byte, []}, _S, _D, l, c) do
    {t_byte(), l, c}
  end

  defp from_form({:type, _Anno, :char, []}, _S, _D, l, c) do
    {t_char(), l, c}
  end

  defp from_form({:type, _Anno, :dynamic, []}, _S, _D, l, c) do
    {t_any(), l, c}
  end

  defp from_form({:type, _Anno, :float, []}, _S, _D, l, c) do
    {t_float(), l, c}
  end

  defp from_form({:type, _Anno, :function, []}, _S, _D, l, c) do
    {t_fun(), l, c}
  end

  defp from_form({:type, _Anno, :fun, []}, _S, _D, l, c) do
    {t_fun(), l, c}
  end

  defp from_form({:type, _Anno, :fun, [{:type, _, :any}, range]},
            s, d, l, c) do
    {t, l1, c1} = from_form(range, s, d - 1, l - 1, c)
    {t_fun(t), l1, c1}
  end

  defp from_form({:type, _Anno, :fun,
             [{:type, _, :product, domain}, range]},
            s, d, l, c) do
    {dom1, l1, c1} = list_from_form(domain, s, d, l, c)
    {ran1, l2, c2} = from_form(range, s, d, l1, c1)
    {t_fun(dom1, ran1), l2, c2}
  end

  defp from_form({:type, _Anno, :identifier, []}, _S, _D, l,
            c) do
    {t_identifier(), l, c}
  end

  defp from_form({:type, _Anno, :integer, []}, _S, _D, l, c) do
    {t_integer(), l, c}
  end

  defp from_form({:type, _Anno, :iodata, []}, _S, _D, l, c) do
    {t_iodata(), l, c}
  end

  defp from_form({:type, _Anno, :iolist, []}, _S, _D, l, c) do
    {t_iolist(), l, c}
  end

  defp from_form({:type, _Anno, :list, []}, _S, _D, l, c) do
    {t_list(), l, c}
  end

  defp from_form({:type, _Anno, :list, [type]}, s, d, l, c) do
    {t, l1, c1} = from_form(type, s, d - 1, l - 1, c)
    {t_list(t), l1, c1}
  end

  defp from_form({:type, _Anno, :map, :any}, s, d, l, c) do
    builtin_type(:map, t_map(), s, d, l, c)
  end

  defp from_form({:type, _Anno, :map, list}, s, d0, l, c) do
    {pairs1, l5, c5} = (fn pairsFromForm
                        _, l1, c1 when l1 <= 0 ->
                          {[{:any, :optional, :any}], l1, c1}
                        [], l1, c1 ->
                          {[], l1, c1}
                        [{:type, _, oper, [kF, vF]} | t], l1, c1 ->
                          d = d0 - 1
                          {key, l2, c2} = from_form(kF, s, d, l1, c1)
                          {val, l3, c3} = from_form(vF, s, d, l2, c2)
                          {pairs0, l4, c4} = pairsFromForm.(t, l3 - 1, c3)
                          case (oper) do
                            :map_field_assoc ->
                              {[{key, :optional, val} | pairs0], l4, c4}
                            :map_field_exact ->
                              {[{key, :mandatory, val} | pairs0], l4, c4}
                          end
                        end)(list, l, c)
    try do
      pairs2 = singleton_elements(pairs1)
      {pairs, defK, defV} = map_from_form(pairs2, [], [], [],
                                            :none, :none)
      {t_map(pairs, defK, defV), l5, c5}
    catch
      :none ->
        {t_none(), l5, c5}
    end
  end

  defp from_form({:type, _Anno, :mfa, []}, _S, _D, l, c) do
    {t_mfa(), l, c}
  end

  defp from_form({:type, _Anno, :module, []}, _S, _D, l, c) do
    {t_module(), l, c}
  end

  defp from_form({:type, _Anno, nil, []}, _S, _D, l, c) do
    {t_nil(), l, c}
  end

  defp from_form({:type, _Anno, :neg_integer, []}, _S, _D, l,
            c) do
    {t_neg_integer(), l, c}
  end

  defp from_form({:type, _Anno, :non_neg_integer, []}, _S, _D, l,
            c) do
    {t_non_neg_integer(), l, c}
  end

  defp from_form({:type, _Anno, :no_return, []}, _S, _D, l, c) do
    {t_unit(), l, c}
  end

  defp from_form({:type, _Anno, :node, []}, _S, _D, l, c) do
    {t_node(), l, c}
  end

  defp from_form({:type, _Anno, :none, []}, _S, _D, l, c) do
    {t_none(), l, c}
  end

  defp from_form({:type, _Anno, :nonempty_binary, []}, s, d, l,
            c) do
    try do
      type_from_form(:nonempty_binary, [], s, d, l, c)
    catch
      _, _ ->
        {t_nonempty_binary(), l, c}
    end
  end

  defp from_form({:type, _Anno, :nonempty_bitstring, []}, s, d,
            l, c) do
    try do
      type_from_form(:nonempty_binary, [], s, d, l, c)
    catch
      _, _ ->
        {t_nonempty_bitstring(), l, c}
    end
  end

  defp from_form({:type, _Anno, :nonempty_list, []}, _S, _D, l,
            c) do
    {t_nonempty_list(), l, c}
  end

  defp from_form({:type, _Anno, :nonempty_list, [type]}, s, d, l,
            c) do
    {t, l1, c1} = from_form(type, s, d, l - 1, c)
    {t_nonempty_list(t), l1, c1}
  end

  defp from_form({:type, _Anno, :nonempty_improper_list,
             [cont, term]},
            s, d, l, c) do
    {t1, l1, c1} = from_form(cont, s, d, l - 1, c)
    {t2, l2, c2} = from_form(term, s, d, l1, c1)
    {t_cons(t1, t2), l2, c2}
  end

  defp from_form({:type, _Anno, :nonempty_maybe_improper_list,
             []},
            _S, _D, l, c) do
    {t_cons(:any, :any), l, c}
  end

  defp from_form({:type, _Anno, :nonempty_maybe_improper_list,
             [cont, term]},
            s, d, l, c) do
    {t1, l1, c1} = from_form(cont, s, d, l - 1, c)
    {t2, l2, c2} = from_form(term, s, d, l1, c1)
    {t_cons(t1, t2), l2, c2}
  end

  defp from_form({:type, _Anno, :nonempty_string, []}, _S, _D, l,
            c) do
    {t_nonempty_string(), l, c}
  end

  defp from_form({:type, _Anno, :number, []}, _S, _D, l, c) do
    {t_number(), l, c}
  end

  defp from_form({:type, _Anno, :pid, []}, _S, _D, l, c) do
    {t_pid(), l, c}
  end

  defp from_form({:type, _Anno, :port, []}, _S, _D, l, c) do
    {t_port(), l, c}
  end

  defp from_form({:type, _Anno, :pos_integer, []}, _S, _D, l,
            c) do
    {t_pos_integer(), l, c}
  end

  defp from_form({:type, _Anno, :maybe_improper_list, []}, _S,
            _D, l, c) do
    {t_maybe_improper_list(), l, c}
  end

  defp from_form({:type, _Anno, :maybe_improper_list,
             [content, termination]},
            s, d, l, c) do
    {t1, l1, c1} = from_form(content, s, d, l - 1, c)
    {t2, l2, c2} = from_form(termination, s, d, l1, c1)
    {t_maybe_improper_list(t1, t2), l2, c2}
  end

  defp from_form({:type, _Anno, :product, elements}, s, d, l,
            c) do
    {lst, l1, c1} = list_from_form(elements, s, d - 1, l, c)
    {t_product(lst), l1, c1}
  end

  defp from_form({:type, _Anno, :range, [from, to]} = type, _S,
            _D, l, c) do
    case ({:erl_eval.partial_eval(from),
             :erl_eval.partial_eval(to)}) do
      {{:integer, _, fromVal}, {:integer, _, toVal}} ->
        {t_from_range(fromVal, toVal), l, c}
      _ ->
        throw({:error, :io_lib.format('Unable to evaluate type ~w\n', [type])})
    end
  end

  defp from_form({:type, _Anno, :record, [name | fields]}, s, d,
            l, c) do
    record_from_form(name, fields, s, d, l, c)
  end

  defp from_form({:type, _Anno, :reference, []}, _S, _D, l, c) do
    {t_reference(), l, c}
  end

  defp from_form({:type, _Anno, :string, []}, _S, _D, l, c) do
    {t_string(), l, c}
  end

  defp from_form({:type, _Anno, :term, []}, _S, _D, l, c) do
    {t_any(), l, c}
  end

  defp from_form({:type, _Anno, :timeout, []}, _S, _D, l, c) do
    {t_timeout(), l, c}
  end

  defp from_form({:type, _Anno, :tuple, :any}, _S, _D, l, c) do
    {t_tuple(), l, c}
  end

  defp from_form({:type, _Anno, :tuple, args}, s, d, l, c) do
    {lst, l1, c1} = list_from_form(args, s, d - 1, l, c)
    {t_tuple(lst), l1, c1}
  end

  defp from_form({:type, _Anno, :union, args}, s, d, l, c) do
    {lst, l1, c1} = list_from_form(args, s, d, l, c)
    {t_sup(lst), l1, c1}
  end

  defp from_form({:user_type, _Anno, name, args}, s, d, l, c) do
    type_from_form(name, args, s, d, l, c)
  end

  defp from_form({:type, _Anno, name, args}, s, d, l, c) do
    type_from_form(name, args, s, d, l, c)
  end

  defp from_form({:opaque, _Anno, name, {mod, args, rep}}, _S,
            _D, l, c) do
    {t_opaque(mod, name, args, rep), l, c}
  end

  defp builtin_type(name, type, s, d, l, c) do
    r_from_form(site: site, mrecs: mR) = s
    m = site_module(site)
    case (lookup_module_types(m, mR, c)) do
      {r, c1} ->
        case (lookup_type(name, 0, r)) do
          {_, {{_M, _FL, _F, _A}, _T}} ->
            type_from_form(name, [], s, d, l, c1)
          :error ->
            {type, l, c1}
        end
      :error ->
        {type, l, c}
    end
  end

  defp type_from_form(name, args, s, d, l, c) do
    r_from_form(site: site, mrecs: mR, tnames: typeNames) = s
    argsLen = length(args)
    module = site_module(site)
    typeName = {:type, {module, name, argsLen}}
    case (can_unfold_more(typeName, typeNames)) do
      true ->
        {r, c1} = lookup_module_types(module, mR, c)
        type_from_form1(name, args, argsLen, r, typeName,
                          typeNames, site, s, d, l, c1)
      false ->
        {t_any(), l, c}
    end
  end

  defp type_from_form1(name, args, argsLen, r, typeName, typeNames,
            site, s, d, l, c) do
    case (lookup_type(name, argsLen, r)) do
      {_, {_, _}} when :erlang.element(1, site) === :check ->
        {_ArgTypes, l1, c1} = list_from_form(args, s, d, l, c)
        {t_any(), l1, c1}
      {tag,
         {{module, {file, _Location}, form, argNames}, type}} ->
        newTypeNames = [typeName | typeNames]
        s1 = r_from_form(s, tnames: newTypeNames)
        {argTypes, l1, c1} = list_from_form(args, s1, d, l, c)
        cKey = cache_key(module, name, argTypes, typeNames, d)
        case (cache_find(cKey, c)) do
          {cachedType, deltaL} ->
            {cachedType, l1 - deltaL, c}
          :error ->
            list = :lists.zip(argNames, argTypes)
            tmpV = :maps.from_list(list)
            {siteTag, mFA} = typeName
            site1 = {siteTag, mFA, file}
            s2 = r_from_form(s1, site: site1,  vtab: tmpV)
            fun = fn dD, lL ->
                       from_form(form, s2, dD, lL, c1)
                  end
            {newType, l3, c3} = (case (tag) do
                                   :type ->
                                     recur_limit(fun, d, l1, typeName,
                                                   typeNames)
                                   :opaque ->
                                     {rep, l2, c2} = recur_limit(fun, d, l1,
                                                                   typeName,
                                                                   typeNames)
                                     rep1 = choose_opaque_type(rep, type)
                                     rep2 = (case (cannot_have_opaque(rep1,
                                                                        typeName,
                                                                        typeNames)) do
                                               true ->
                                                 rep
                                               false ->
                                                 argTypes2 = subst_all_vars_to_any_list(argTypes)
                                                 t_opaque(module, name,
                                                            argTypes2, rep1)
                                             end)
                                     {rep2, l2, c2}
                                 end)
            c4 = cache_put(cKey, newType, l1 - l3, c3)
            {newType, l3, c4}
        end
      :error ->
        msg = :io_lib.format('Unable to find type ~tw/~w\n', [name, argsLen])
        throw({:error, msg})
    end
  end

  defp remote_from_form(anno, remMod, name, args, s, d, l, c) do
    r_from_form(site: site, xtypes: eT, mrecs: mR,
        tnames: typeNames) = s
    cond do
      eT === :replace_by_none ->
        {t_none(), l, c}
      true ->
        argsLen = length(args)
        mFA = {remMod, name, argsLen}
        case (lookup_module_types(remMod, mR, c)) do
          :error ->
            send(self(), {self(), :ext_types,
                            ext_types_message(mFA, anno, site)})
            {t_any(), l, c}
          {remDict, c1} ->
            case (:ets.member(eT, mFA)) do
              true ->
                remType = {:type, mFA}
                case (can_unfold_more(remType, typeNames)) do
                  true ->
                    remote_from_form1(remMod, name, args, argsLen, remDict,
                                        remType, typeNames, site, s, d, l, c1)
                  false ->
                    {t_any(), l, c1}
                end
              false ->
                send(self(), {self(), :ext_types,
                                ext_types_message(mFA, anno, site)})
                {t_any(), l, c1}
            end
        end
    end
  end

  defp ext_types_message(mFA, anno, site) do
    {mFA,
       {site_file(site), :erl_anno.location(anno),
          site_mfa(site)}}
  end

  defp remote_from_form1(remMod, name, args, argsLen, remDict, remType,
            typeNames, site, s, d, l, c) do
    case (lookup_type(name, argsLen, remDict)) do
      {_, {_, _}} when :erlang.element(1, site) === :check ->
        {_ArgTypes, l1, c1} = list_from_form(args, s, d, l, c)
        {t_any(), l1, c1}
      {tag,
         {{mod, {file, _Location}, form, argNames}, type}} ->
        newTypeNames = [remType | typeNames]
        s1 = r_from_form(s, tnames: newTypeNames)
        {argTypes, l1, c1} = list_from_form(args, s1, d, l, c)
        cKey = cache_key(remMod, name, argTypes, typeNames, d)
        case (cache_find(cKey, c)) do
          {cachedType, deltaL} ->
            {cachedType, l - deltaL, c}
          :error ->
            list = :lists.zip(argNames, argTypes)
            tmpVarTab = :maps.from_list(list)
            {siteTag, mFA} = remType
            site1 = {siteTag, mFA, file}
            s2 = r_from_form(s1, site: site1,  vtab: tmpVarTab)
            fun = fn dD, lL ->
                       from_form(form, s2, dD, lL, c1)
                  end
            {newType, l3, c3} = (case (tag) do
                                   :type ->
                                     recur_limit(fun, d, l1, remType, typeNames)
                                   :opaque ->
                                     {newRep, l2, c2} = recur_limit(fun, d, l1,
                                                                      remType,
                                                                      typeNames)
                                     newRep1 = choose_opaque_type(newRep, type)
                                     newRep2 = (case (cannot_have_opaque(newRep1,
                                                                           remType,
                                                                           typeNames)) do
                                                  true ->
                                                    newRep
                                                  false ->
                                                    argTypes2 = subst_all_vars_to_any_list(argTypes)
                                                    t_opaque(mod, name,
                                                               argTypes2,
                                                               newRep1)
                                                end)
                                     {newRep2, l2, c2}
                                 end)
            c4 = cache_put(cKey, newType, l1 - l3, c3)
            {newType, l3, c4}
        end
      :error ->
        msg = :io_lib.format('Unable to find remote type ~w:~tw()\n', [remMod, name])
        throw({:error, msg})
    end
  end

  defp subst_all_vars_to_any_list(types) do
    for type <- types do
      subst_all_vars_to_any(type)
    end
  end

  defp choose_opaque_type(type, declType) do
    case (t_is_subtype(subst_all_vars_to_any(type),
                         subst_all_vars_to_any(declType))) do
      true ->
        type
      false ->
        declType
    end
  end

  defp record_from_form({:atom, _, name}, modFields, s, d0, l0, c) do
    r_from_form(site: site, mrecs: mR, tnames: typeNames) = s
    recordType = {:record, name}
    case (can_unfold_more(recordType, typeNames)) do
      true ->
        m = site_module(site)
        {r, c1} = lookup_module_types(m, mR, c)
        case (lookup_record(name, r)) do
          {:ok, _} when :erlang.element(1, site) === :check ->
            {t_any(), l0, c1}
          {:ok, declFields} ->
            newTypeNames = [recordType | typeNames]
            site1 = {:record, {m, name, length(declFields)},
                       site_file(site)}
            s1 = r_from_form(s, site: site1,  tnames: newTypeNames)
            fun = fn d, l ->
                       {getModRec, l1, c2} = get_mod_record(modFields,
                                                              declFields, s1, d,
                                                              l, c1)
                       case (getModRec) do
                         {:error, fieldName} ->
                           throw({:error, :io_lib.format('Illegal declaration of #~tw{~tw}\n', [name, fieldName])})
                         {:ok, newFields} ->
                           s2 = r_from_form(s1, vtab: var_table__new())
                           {newFields1, l2, c3} = fields_from_form(newFields,
                                                                     s2, d, l1,
                                                                     c2)
                           rec = t_tuple([t_atom(name) | for {_FieldName,
                                                                type} <- newFields1 do
                                                           type
                                                         end])
                           {rec, l2, c3}
                       end
                  end
            recur_limit(fun, d0, l0, recordType, typeNames)
          :error ->
            throw({:error, :io_lib.format('Unknown record #~tw{}\n', [name])})
        end
      false ->
        {t_any(), l0, c}
    end
  end

  defp get_mod_record([], declFields, _S, _D, l, c) do
    {{:ok, declFields}, l, c}
  end

  defp get_mod_record(modFields, declFields, s, d, l, c) do
    declFieldsDict = :lists.keysort(1, declFields)
    {modFieldsDict, l1, c1} = build_field_dict(modFields, s,
                                                 d, l, c)
    case (get_mod_record_types(declFieldsDict,
                                 modFieldsDict, [])) do
      {:error, _FieldName} = error ->
        {error, l1, c1}
      {:ok, finalKeyDict} ->
        fields = (for {fieldName, _, _} <- declFields do
                    :lists.keyfind(fieldName, 1, finalKeyDict)
                  end)
        {{:ok, fields}, l1, c1}
    end
  end

  defp build_field_dict(fieldTypes, s, d, l, c) do
    build_field_dict(fieldTypes, s, d, l, c, [])
  end

  defp build_field_dict([{:type, _, :field_type,
              [{:atom, _, name}, type]} |
               left],
            s, d, l, c, acc) do
    {t, l1, c1} = from_form(type, s, d, l - 1, c)
    newAcc = [{name, type, t} | acc]
    build_field_dict(left, s, d, l1, c1, newAcc)
  end

  defp build_field_dict([], _S, _D, l, c, acc) do
    {:lists.keysort(1, acc), l, c}
  end

  defp get_mod_record_types([{fieldName, _Abstr, _DeclType} | left1],
            [{fieldName, typeForm, modType} | left2], acc) do
    get_mod_record_types(left1, left2,
                           [{fieldName, typeForm, modType} | acc])
  end

  defp get_mod_record_types([{fieldName1, _Abstr, _DeclType} = dT | left1],
            [{fieldName2, _FormType, _ModType} | _] = list2, acc)
      when fieldName1 < fieldName2 do
    get_mod_record_types(left1, list2, [dT | acc])
  end

  defp get_mod_record_types(left1, [], acc) do
    {:ok, :lists.keysort(1, left1 ++ acc)}
  end

  defp get_mod_record_types(_, [{fieldName2, _FormType, _ModType} | _],
            _Acc) do
    {:error, fieldName2}
  end

  defp fields_from_form([], _S, _D, l, c) do
    {[], l, c}
  end

  defp fields_from_form([{name, abstr, _Type} | tail], s, d, l, c) do
    {t, l1, c1} = from_form(abstr, s, d, l, c)
    {f, l2, c2} = fields_from_form(tail, s, d, l1, c1)
    {[{name, t} | f], l2, c2}
  end

  defp list_from_form([], _S, _D, l, c) do
    {[], l, c}
  end

  defp list_from_form([h | tail], s, d, l, c) do
    {h1, l1, c1} = from_form(h, s, d, l - 1, c)
    {t1, l2, c2} = list_from_form(tail, s, d, l1, c1)
    {[h1 | t1], l2, c2}
  end

  defp singleton_elements([]) do
    []
  end

  defp singleton_elements([{k, :mandatory, v} = pair | pairs]) do
    case (is_singleton_type(k)) do
      true ->
        [pair | singleton_elements(pairs)]
      false ->
        singleton_elements([{k, :optional, v} | pairs])
    end
  end

  defp singleton_elements([{key0, mNess, val} | pairs]) do
    (for key <- separate_key(key0) do
       {key, mNess, val}
     end) ++ singleton_elements(pairs)
  end

  defp separate_key(r_c(tag: :atom, elements: atoms))
      when atoms !== :any do
    for a <- atoms do
      t_atom(a)
    end
  end

  defp separate_key(r_c(tag: :number, elements: _,
              qualifier: _) = t) do
    t_elements(t)
  end

  defp separate_key(r_c(tag: :union, elements: list)) do
    :lists.append(for k <- list, not t_is_none(k) do
                    separate_key(k)
                  end)
  end

  defp separate_key(key) do
    [key]
  end

  defp map_from_form([], shdwPs, mKs, pairs, defK, defV) do
    verify_possible(mKs, shdwPs)
    {promote_to_mand(mKs, pairs), defK, defV}
  end

  defp map_from_form([{sKey, mNess, val} | sPairs], shdwPs0, mKs0,
            pairs0, defK0, defV0) do
    key = :lists.foldl(fn {k, _}, s ->
                            t_subtract(s, k)
                       end,
                         sKey, shdwPs0)
    shdwPs = (case (key) do
                :none ->
                  shdwPs0
                _ ->
                  [{key, val} | shdwPs0]
              end)
    mKs = (case (mNess) do
             :mandatory ->
               [sKey | mKs0]
             :optional ->
               mKs0
           end)
    cond do
      (mNess === :mandatory and sKey === :none) ->
        throw(:none)
      true ->
        :ok
    end
    {pairs, defK, defV} = (case (is_singleton_type(key)) do
                             true ->
                               mNess1 = (case (val === :none) do
                                           true ->
                                             :optional
                                           false ->
                                             mNess
                                         end)
                               {mapdict_insert({key, mNess1, val}, pairs0),
                                  defK0, defV0}
                             false ->
                               case (key === :none or val === :none) do
                                 true ->
                                   {pairs0, defK0, defV0}
                                 false ->
                                   {pairs0, t_sup(defK0, key),
                                      t_sup(defV0, val)}
                               end
                           end)
    map_from_form(sPairs, shdwPs, mKs, pairs, defK, defV)
  end

  defp verify_possible(mKs, shdwPs) do
    :lists.foreach(fn m ->
                        verify_possible_1(m, shdwPs)
                   end,
                     mKs)
  end

  defp verify_possible_1(m, shdwPs) do
    case (:lists.any(fn {k, _} ->
                          t_inf(m, k) !== :none
                     end,
                       shdwPs)) do
      true ->
        :ok
      false ->
        throw(:none)
    end
  end

  defp promote_to_mand(_, []) do
    []
  end

  defp promote_to_mand(mKs, [e = {k, _, v} | t]) do
    [case (:lists.any(fn m ->
                           t_is_equal(k, m)
                      end,
                        mKs)) do
       true ->
         {k, :mandatory, v}
       false ->
         e
     end |
         promote_to_mand(mKs, t)]
  end

  defp recur_limit(fun, d, l, _, _) when (l <= 2 and d <= 10) do
    fun.(d, l)
  end

  defp recur_limit(fun, d, l, typeName, typeNames) do
    case (is_recursive(typeName, typeNames)) do
      true ->
        {t, l1, c1} = fun.(2, 10)
        {t, l - l1, c1}
      false ->
        fun.(d, l)
    end
  end

  def t_check_record_fields(form, expTypes, site, recDict, varTable,
           cache) do
    state = r_from_form(site: site, xtypes: expTypes, mrecs: recDict,
                vtab: varTable, tnames: [])
    check_record_fields(form, state, cache)
  end

  defp check_record_fields({:var, _Anno, _}, _S, c) do
    c
  end

  defp check_record_fields({:ann_type, _Anno, [_Var, type]}, s, c) do
    check_record_fields(type, s, c)
  end

  defp check_record_fields({:paren_type, _Anno, [type]}, s, c) do
    check_record_fields(type, s, c)
  end

  defp check_record_fields({:remote_type, _Anno,
             [{:atom, _, _}, {:atom, _, _}, args]},
            s, c) do
    list_check_record_fields(args, s, c)
  end

  defp check_record_fields({:atom, _Anno, _}, _S, c) do
    c
  end

  defp check_record_fields({:integer, _Anno, _}, _S, c) do
    c
  end

  defp check_record_fields({:char, _Anno, _}, _S, c) do
    c
  end

  defp check_record_fields({:op, _Anno, _Op, _Arg}, _S, c) do
    c
  end

  defp check_record_fields({:op, _Anno, _Op, _Arg1, _Arg2}, _S, c) do
    c
  end

  defp check_record_fields({:type, _Anno, :tuple, :any}, _S, c) do
    c
  end

  defp check_record_fields({:type, _Anno, :map, :any}, _S, c) do
    c
  end

  defp check_record_fields({:type, _Anno, :binary, [_Base, _Unit]}, _S,
            c) do
    c
  end

  defp check_record_fields({:type, _Anno, :fun, [{:type, _, :any}, range]},
            s, c) do
    check_record_fields(range, s, c)
  end

  defp check_record_fields({:type, _Anno, :range, [_From, _To]}, _S, c) do
    c
  end

  defp check_record_fields({:type, _Anno, :record, [name | fields]}, s,
            c) do
    check_record(name, fields, s, c)
  end

  defp check_record_fields({:type, _Anno, _, args}, s, c) do
    list_check_record_fields(args, s, c)
  end

  defp check_record_fields({:user_type, _Anno, _Name, args}, s, c) do
    list_check_record_fields(args, s, c)
  end

  defp check_record({:atom, _, name}, modFields, s, c) do
    r_from_form(site: site, mrecs: mR) = s
    m = site_module(site)
    {r, c1} = lookup_module_types(m, mR, c)
    {:ok, declFields} = lookup_record(name, r)
    case (check_fields(name, modFields, declFields, s,
                         c1)) do
      {:error, fieldName} ->
        throw({:error, :io_lib.format('Illegal declaration of #~tw{~tw}\n', [name, fieldName])})
      c2 ->
        c2
    end
  end

  defp check_fields(recName,
            [{:type, _, :field_type, [{:atom, _, name}, abstr]} |
                 left],
            declFields, s, c) do
    r_from_form(site: site0, xtypes: eT, mrecs: mR, vtab: v) = s
    m = site_module(site0)
    site = {:record, {m, recName, length(declFields)},
              site_file(site0)}
    {type, c1} = t_from_form(abstr, eT, site, mR, v, c)
    {^name, _, declType} = :lists.keyfind(name, 1,
                                            declFields)
    typeNoVars = subst_all_vars_to_any(type)
    case (t_is_subtype(typeNoVars, declType)) do
      false ->
        {:error, name}
      true ->
        check_fields(recName, left, declFields, s, c1)
    end
  end

  defp check_fields(_RecName, [], _Decl, _S, c) do
    c
  end

  defp list_check_record_fields([], _S, c) do
    c
  end

  defp list_check_record_fields([h | tail], s, c) do
    c1 = check_record_fields(h, s, c)
    list_check_record_fields(tail, s, c1)
  end

  defp site_module({_, {module, _, _}, _}) do
    module
  end

  defp site_mfa({_, {m, f, a}, _}) do
    {m, f, a}
  end

  defp site_file({_, _, file}) do
    file
  end

  def cache__new() do
    r_cache()
  end

  defp cache_key(module, name, argTypes, typeNames, d) do
    {module, name, d, argTypes, typeNames}
  end

  defp cache_find(key, r_cache(types: types)) do
    case (types) do
      %{^key => value} ->
        value
      %{} ->
        :error
    end
  end

  defp cache_put(_Key, _Type, deltaL, cache) when deltaL < 0 do
    cache
  end

  defp cache_put(key, type, deltaL, r_cache(types: types) = cache) do
    newTypes = Map.put(types, key, {type, deltaL})
    r_cache(cache, types: newTypes)
  end

  def t_var_names([{:var, _, name} | l]) when name !== :_ do
    [name | t_var_names(l)]
  end

  def t_var_names([]) do
    []
  end

  def t_form_to_string({:var, _Anno, :_}) do
    '_'
  end

  def t_form_to_string({:var, _Anno, name}) do
    :erlang.atom_to_list(name)
  end

  def t_form_to_string({:atom, _Anno, atom}) do
    :io_lib.write_string(:erlang.atom_to_list(atom), ?')
  end

  def t_form_to_string({:integer, _Anno, int}) do
    :erlang.integer_to_list(int)
  end

  def t_form_to_string({:char, _Anno, char}) do
    :erlang.integer_to_list(char)
  end

  def t_form_to_string({:op, _Anno, _Op, _Arg} = op) do
    case (:erl_eval.partial_eval(op)) do
      {:integer, _, _} = int ->
        t_form_to_string(int)
      _ ->
        :io_lib.format('Badly formed type ~w', [op])
    end
  end

  def t_form_to_string({:op, _Anno, _Op, _Arg1, _Arg2} = op) do
    case (:erl_eval.partial_eval(op)) do
      {:integer, _, _} = int ->
        t_form_to_string(int)
      _ ->
        :io_lib.format('Badly formed type ~w', [op])
    end
  end

  def t_form_to_string({:ann_type, _Anno, [var, type]}) do
    t_form_to_string(var) ++ '::' ++ t_form_to_string(type)
  end

  def t_form_to_string({:paren_type, _Anno, [type]}) do
    flat_format('(~ts)', [t_form_to_string(type)])
  end

  def t_form_to_string({:remote_type, _Anno,
            [{:atom, _, mod}, {:atom, _, name}, args]}) do
    argString = '(' ++ flat_join(t_form_to_string_list(args),
                                 ',') ++ ')'
    flat_format('~w:~tw', [mod, name]) ++ argString
  end

  def t_form_to_string({:type, _Anno, :arity, []}) do
    'arity()'
  end

  def t_form_to_string({:type, _Anno, :binary, []}) do
    'binary()'
  end

  def t_form_to_string({:type, _Anno, :binary, [base, unit]} = type) do
    case ({:erl_eval.partial_eval(base),
             :erl_eval.partial_eval(unit)}) do
      {{:integer, _, b}, {:integer, _, u}} ->
        case ({u, b}) do
          {0, 0} ->
            '<<>>'
          {8, 0} ->
            'binary()'
          {1, 0} ->
            'bitstring()'
          {0, ^b} ->
            flat_format('<<_:~w>>', [b])
          {^u, 0} ->
            flat_format('<<_:_*~w>>', [u])
          {^u, ^b} ->
            flat_format('<<_:~w,_:_*~w>>', [b, u])
        end
      _ ->
        :io_lib.format('Badly formed bitstr type ~w', [type])
    end
  end

  def t_form_to_string({:type, _Anno, :bitstring, []}) do
    'bitstring()'
  end

  def t_form_to_string({:type, _Anno, :dynamic, []}) do
    'dynamic()'
  end

  def t_form_to_string({:type, _Anno, :fun, []}) do
    'fun()'
  end

  def t_form_to_string({:type, _Anno, :fun,
            [{:type, _, :any}, range]}) do
    'fun(...) -> ' ++ t_form_to_string(range)
  end

  def t_form_to_string({:type, _Anno, :fun,
            [{:type, _, :product, domain}, range]}) do
    'fun((' ++ flat_join(t_form_to_string_list(domain),
                     ',') ++ ') -> ' ++ t_form_to_string(range) ++ ')'
  end

  def t_form_to_string({:type, _Anno, :iodata, []}) do
    'iodata()'
  end

  def t_form_to_string({:type, _Anno, :iolist, []}) do
    'iolist()'
  end

  def t_form_to_string({:type, _Anno, :list, [type]}) do
    '[' ++ t_form_to_string(type) ++ ']'
  end

  def t_form_to_string({:type, _Anno, :map, :any}) do
    'map()'
  end

  def t_form_to_string({:type, _Anno, :map, args}) do
    '\#{' ++ flat_join(t_form_to_string_list(args), ',') ++ '}'
  end

  def t_form_to_string({:type, _Anno, :map_field_assoc, [key, val]}) do
    t_form_to_string(key) ++ '=>' ++ t_form_to_string(val)
  end

  def t_form_to_string({:type, _Anno, :map_field_exact, [key, val]}) do
    t_form_to_string(key) ++ ':=' ++ t_form_to_string(val)
  end

  def t_form_to_string({:type, _Anno, :mfa, []}) do
    'mfa()'
  end

  def t_form_to_string({:type, _Anno, :module, []}) do
    'module()'
  end

  def t_form_to_string({:type, _Anno, :node, []}) do
    'node()'
  end

  def t_form_to_string({:type, _Anno, :nonempty_binary, []}) do
    'nonempty_binary()'
  end

  def t_form_to_string({:type, _Anno, :nonempty_bitstring, []}) do
    'nonempty_bitstring()'
  end

  def t_form_to_string({:type, _Anno, :nonempty_list, [type]}) do
    '[' ++ t_form_to_string(type) ++ ',...]'
  end

  def t_form_to_string({:type, _Anno, :nonempty_string, []}) do
    'nonempty_string()'
  end

  def t_form_to_string({:type, _Anno, :product, elements}) do
    '<' ++ flat_join(t_form_to_string_list(elements), ',') ++ '>'
  end

  def t_form_to_string({:type, _Anno, :range, [from, to]} = type) do
    case ({:erl_eval.partial_eval(from),
             :erl_eval.partial_eval(to)}) do
      {{:integer, _, fromVal}, {:integer, _, toVal}} ->
        flat_format('~w..~w', [fromVal, toVal])
      _ ->
        flat_format('Badly formed type ~w', [type])
    end
  end

  def t_form_to_string({:type, _Anno, :record, [{:atom, _, name}]}) do
    flat_format('#~tw{}', [name])
  end

  def t_form_to_string({:type, _Anno, :record,
            [{:atom, _, name} | fields]}) do
    fieldString = flat_join(t_form_to_string_list(fields),
                              ',')
    flat_format('#~tw{~ts}', [name, fieldString])
  end

  def t_form_to_string({:type, _Anno, :field_type,
            [{:atom, _, name}, type]}) do
    flat_format('~tw::~ts', [name, t_form_to_string(type)])
  end

  def t_form_to_string({:type, _Anno, :term, []}) do
    'term()'
  end

  def t_form_to_string({:type, _Anno, :timeout, []}) do
    'timeout()'
  end

  def t_form_to_string({:type, _Anno, :tuple, :any}) do
    'tuple()'
  end

  def t_form_to_string({:type, _Anno, :tuple, args}) do
    '{' ++ flat_join(t_form_to_string_list(args), ',') ++ '}'
  end

  def t_form_to_string({:type, _Anno, :union, args}) do
    flat_join(:lists.map(fn arg ->
                              case (arg) do
                                {:ann_type, _AL, _} ->
                                  '(' ++ t_form_to_string(arg) ++ ')'
                                _ ->
                                  t_form_to_string(arg)
                              end
                         end,
                           args),
                ' | ')
  end

  def t_form_to_string({:type, _Anno, name, []} = t) do
    try do
      m = :mod
      site = {:type, {m, name, 0}, ''}
      v = var_table__new()
      c = cache__new()
      state = r_from_form(site: site, xtypes: :replace_by_none,
                  mrecs: :undefined, vtab: v, tnames: [])
      {t1, _, _} = from_form(t, state, _Deep = 1000,
                               _ALot = 1000000, c)
      t_to_string(t1)
    catch
      {:error, _} ->
        atom_to_string(name) ++ '()'
    end
  end

  def t_form_to_string({:user_type, _Anno, name, list}) do
    flat_format('~tw(~ts)',
                  [name, flat_join(t_form_to_string_list(list), ',')])
  end

  def t_form_to_string({:type, anno, name, list}) do
    t_form_to_string({:user_type, anno, name, list})
  end

  defp t_form_to_string_list(list) do
    t_form_to_string_list(list, [])
  end

  defp t_form_to_string_list([h | t], acc) do
    t_form_to_string_list(t, [t_form_to_string(h) | acc])
  end

  defp t_form_to_string_list([], acc) do
    :lists.reverse(acc)
  end

  def atom_to_string(atom) do
    flat_format('~tw', [atom])
  end

  def any_none([:none | _Left]) do
    true
  end

  def any_none([_ | left]) do
    any_none(left)
  end

  def any_none([]) do
    false
  end

  def any_none_or_unit([:none | _]) do
    true
  end

  def any_none_or_unit([:unit | _]) do
    true
  end

  def any_none_or_unit([_ | left]) do
    any_none_or_unit(left)
  end

  def any_none_or_unit([]) do
    false
  end

  def is_erl_type(:any) do
    true
  end

  def is_erl_type(:none) do
    true
  end

  def is_erl_type(:unit) do
    true
  end

  def is_erl_type(r_c()) do
    true
  end

  def is_erl_type(_) do
    false
  end

  defp lookup_module_types(module, codeTable, cache) do
    r_cache(mod_recs: mRecs) = cache
    case (mRecs) do
      %{^module => r} ->
        {r, cache}
      %{} ->
        case (:ets.lookup_element(codeTable, module, 2,
                                    :error)) do
          :error ->
            :error
          r ->
            newMRecs = Map.put(mRecs, module, r)
            {r, r_cache(cache, mod_recs: newMRecs)}
        end
    end
  end

  defp lookup_record(tag, table) when is_atom(tag) do
    key = {:record, tag}
    case (table) do
      %{^key => {_FileLocation, [{_Arity, fields}]}} ->
        {:ok, fields}
      %{^key => {_FileLocation, list}} when is_list(list) ->
        :error
      %{} ->
        :error
    end
  end

  def lookup_record(tag, arity, table) when is_atom(tag) do
    key = {:record, tag}
    case (table) do
      %{^key => {_FileLocation, [{^arity, fields}]}} ->
        {:ok, fields}
      %{^key => {_FileLocation, ordDict}} ->
        :orddict.find(arity, ordDict)
      %{} ->
        :error
    end
  end

  defp lookup_type(name, arity, table) do
    case (table) do
      %{{:type, ^name, ^arity} => found} ->
        {:type, found}
      %{{:opaque, ^name, ^arity} => found} ->
        {:opaque, found}
      %{} ->
        :error
    end
  end

  def type_is_defined(typeOrOpaque, name, arity, table) do
    :maps.is_key({typeOrOpaque, name, arity}, table)
  end

  defp cannot_have_opaque(type, typeName, typeNames) do
    t_is_none(type) or is_recursive(typeName, typeNames)
  end

  defp is_recursive(typeName, typeNames) do
    :lists.member(typeName, typeNames)
  end

  defp can_unfold_more(typeName, typeNames) do
    fun = fn e, acc ->
               case (e) do
                 ^typeName ->
                   acc + 1
                 _ ->
                   acc
               end
          end
    :lists.foldl(fun, 0, typeNames) < 2
  end

  defp do_opaque(r_c(tag: :opaque, elements: _) = type, opaques,
            pred) do
    case (opaques === :universe or is_opaque_type(type,
                                                    opaques)) do
      true ->
        do_opaque(t_opaque_structure(type), opaques, pred)
      false ->
        pred.(type)
    end
  end

  defp do_opaque(r_c(tag: :union, elements: list) = type, opaques,
            pred) do
    [a, b, f, i, l, n, t, o, map] = list
    cond do
      o === :none ->
        pred.(type)
      true ->
        case (opaques === :universe or is_opaque_type(o,
                                                        opaques)) do
          true ->
            s = t_opaque_structure(o)
            do_opaque(t_sup([a, b, f, i, l, n, t, s, map]), opaques,
                        pred)
          false ->
            pred.(type)
        end
    end
  end

  defp do_opaque(type, _Opaques, pred) do
    pred.(type)
  end

  defp map_all_values(r_c(tag: :map, elements: {pairs, _, defV})) do
    [defV | for {v, _, _} <- pairs do
              v
            end]
  end

  defp map_all_keys(r_c(tag: :map, elements: {pairs, defK, _})) do
    [defK | for {_, _, k} <- pairs do
              k
            end]
  end

  defp map_all_types(m) do
    map_all_keys(m) ++ map_all_values(m)
  end

  def t_is_singleton(type) do
    t_is_singleton(type, :universe)
  end

  def t_is_singleton(type, opaques) do
    do_opaque(type, opaques, &is_singleton_type/1)
  end

  defp is_singleton_type(r_c(tag: nil)) do
    true
  end

  defp is_singleton_type(r_c(tag: :atom, elements: :any)) do
    false
  end

  defp is_singleton_type(r_c(tag: :atom, elements: [_])) do
    true
  end

  defp is_singleton_type(r_c(tag: :number, elements: r_int_rng(from: v, to: v),
              qualifier: :integer)) do
    true
  end

  defp is_singleton_type(r_c(tag: :number, elements: r_int_set(set: [_]),
              qualifier: :integer)) do
    true
  end

  defp is_singleton_type(_) do
    false
  end

  defp set_singleton(element) do
    [element]
  end

  defp set_is_singleton(element, [element]) do
    true
  end

  defp set_is_singleton(_, _) do
    false
  end

  defp set_is_element(element, set) do
    :ordsets.is_element(element, set)
  end

  defp set_union(:any, _) do
    :any
  end

  defp set_union(_, :any) do
    :any
  end

  defp set_union(s1, s2) do
    case (:ordsets.union(s1, s2)) do
      s when length(s) <= 13 ->
        s
      _ ->
        :any
    end
  end

  defp set_intersection(:any, s) do
    s
  end

  defp set_intersection(s, :any) do
    s
  end

  defp set_intersection(s1, s2) do
    case (:ordsets.intersection(s1, s2)) do
      [] ->
        :none
      s ->
        s
    end
  end

  defp set_subtract(_, :any) do
    :none
  end

  defp set_subtract(:any, _) do
    :any
  end

  defp set_subtract(s1, s2) do
    case (:ordsets.subtract(s1, s2)) do
      [] ->
        :none
      s ->
        s
    end
  end

  defp set_from_list(list) do
    case (length(list)) do
      l when l <= 13 ->
        :ordsets.from_list(list)
      l when l > 13 ->
        :any
    end
  end

  defp set_filter(pred, set) do
    case (for e <- set, pred.(e) do
            e
          end) do
      [] ->
        :none
      newSet ->
        newSet
    end
  end

  defp set_to_string(set) do
    l = (for x <- set do
           case (is_atom(x)) do
             true ->
               :io_lib.write_string(:erlang.atom_to_list(x), ?')
             false ->
               flat_format('~tw', [x])
           end
         end)
    flat_join(l, ' | ')
  end

  defp set_min([h | _]) do
    h
  end

  defp set_max(set) do
    :lists.last(set)
  end

  defp flat_format(f, s) do
    :lists.flatten(:io_lib.format(f, s))
  end

  defp flat_join(list, sep) do
    :lists.flatten(:lists.join(sep, list))
  end

  defp gcd(a, b) when b > a do
    gcd1(b, a)
  end

  defp gcd(a, b) do
    gcd1(a, b)
  end

  defp gcd1(a, 0) do
    a
  end

  defp gcd1(a, b) do
    case (rem(a, b)) do
      0 ->
        b
      x ->
        gcd1(b, x)
    end
  end

  defp bitstr_concat(:none, _) do
    :none
  end

  defp bitstr_concat(_, :none) do
    :none
  end

  defp bitstr_concat(r_c(tag: :binary, elements: {u1, b1}),
            r_c(tag: :binary, elements: {u2, b2})) do
    t_bitstr(gcd(u1, u2), b1 + b2)
  end

  defp bitstr_match(:none, _) do
    :none
  end

  defp bitstr_match(_, :none) do
    :none
  end

  defp bitstr_match(r_c(tag: :binary, elements: {0, b1}),
            r_c(tag: :binary, elements: {0, b2}))
      when b1 <= b2 do
    t_bitstr(0, b2 - b1)
  end

  defp bitstr_match(r_c(tag: :binary, elements: {0, _B1}),
            r_c(tag: :binary, elements: {0, _B2})) do
    :none
  end

  defp bitstr_match(r_c(tag: :binary, elements: {0, b1}),
            r_c(tag: :binary, elements: {u2, b2}))
      when b1 <= b2 do
    t_bitstr(u2, b2 - b1)
  end

  defp bitstr_match(r_c(tag: :binary, elements: {0, b1}),
            r_c(tag: :binary, elements: {u2, b2})) do
    t_bitstr(u2, handle_base(u2, b2 - b1))
  end

  defp bitstr_match(r_c(tag: :binary, elements: {_, b1}),
            r_c(tag: :binary, elements: {0, b2}))
      when b1 > b2 do
    :none
  end

  defp bitstr_match(r_c(tag: :binary, elements: {u1, b1}),
            r_c(tag: :binary, elements: {u2, b2})) do
    gCD = gcd(u1, u2)
    t_bitstr(gCD, handle_base(gCD, b2 - b1))
  end

  defp handle_base(unit, pos) when pos >= 0 do
    rem(pos, unit)
  end

  defp handle_base(unit, neg) do
    rem(unit + rem(neg, unit), unit)
  end

  def var_table__new() do
    :maps.new()
  end

  def module_type_deps_of_type_defs(typeTable) do
    moduleTypeDependencies = (for typeTableEntry <- :maps.to_list(typeTable) do
                                module_type_deps_of_entry(typeTableEntry)
                              end)
    :lists.append(moduleTypeDependencies)
  end

  defp module_type_deps_of_entry({{:type, _TypeName, _A},
             {{_FromM, _FileLine, abstractType, _ArgNames}, _}}) do
    type_form_to_remote_modules(abstractType)
  end

  defp module_type_deps_of_entry({{:opaque, _TypeName, _A},
             {{_FromM, _FileLine, abstractType, _ArgNames}, _}}) do
    type_form_to_remote_modules(abstractType)
  end

  defp module_type_deps_of_entry({{:record, _Name},
             {_FileLine, sizesAndFields}}) do
    allFields = :lists.append(for {_Size,
                                     fields} <- sizesAndFields do
                                fields
                              end)
    fieldTypes = (for {_, abstractType, _} <- allFields do
                    abstractType
                  end)
    type_form_to_remote_modules(fieldTypes)
  end

  def type_form_to_remote_modules([]) do
    []
  end

  def type_form_to_remote_modules([_ | _] = forms) do
    d = 16
    l = 10000
    {_, mods} = list_get_modules_mentioned(forms, d, l, [])
    :lists.usort(mods)
  end

  def type_form_to_remote_modules(form) do
    d = 16
    l = 10000
    {_, mods} = get_modules_mentioned(form, d, l, [])
    :lists.usort(mods)
  end

  defp get_modules_mentioned(_, d, l, acc) when d <= 0 or l <= 0 do
    {l, acc}
  end

  defp get_modules_mentioned({:var, _L, :_}, _D, l, acc) do
    {l, acc}
  end

  defp get_modules_mentioned({:var, _L, _Name}, _D, l, acc) do
    {l, acc}
  end

  defp get_modules_mentioned({:ann_type, _L, [_Var, type]}, d, l, acc) do
    get_modules_mentioned(type, d, l, acc)
  end

  defp get_modules_mentioned({:paren_type, _L, [type]}, d, l, acc) do
    get_modules_mentioned(type, d, l, acc)
  end

  defp get_modules_mentioned({:atom, _L, _Atom}, _D, l, acc) do
    {l, acc}
  end

  defp get_modules_mentioned({:integer, _L, _Int}, _D, l, acc) do
    {l, acc}
  end

  defp get_modules_mentioned({:char, _L, _Char}, _D, l, acc) do
    {l, acc}
  end

  defp get_modules_mentioned({:op, _L, _Op, _Arg}, _D, l, acc) do
    {l, acc}
  end

  defp get_modules_mentioned({:op, _L, _Op, _Arg1, _Arg2}, _D, l, acc) do
    {l, acc}
  end

  defp get_modules_mentioned({:type, _L, :fun, [{:type, _, :any}, range]}, d,
            l, acc) do
    get_modules_mentioned(range, d - 1, l - 1, acc)
  end

  defp get_modules_mentioned({:type, _L, :fun,
             [{:type, _, :product, domain}, range]},
            d, l, acc) do
    {l1, acc1} = list_get_modules_mentioned(domain, d, l,
                                              acc)
    get_modules_mentioned(range, d, l1, acc1)
  end

  defp get_modules_mentioned({:type, _L, :list, [type]}, d, l, acc) do
    get_modules_mentioned(type, d - 1, l - 1, acc)
  end

  defp get_modules_mentioned({:type, _L, :map, :any}, _D, l, acc) do
    {l, acc}
  end

  defp get_modules_mentioned({:type, _L, :map, list}, d0, l, acc) do
    (fn pairsFromForm
     _, l1, acc1 when l1 <= 0 ->
       acc1
     [], l1, acc1 ->
       {l1, acc1}
     [{:type, _, _Oper, [kF, vF]} | t], l1, acc1 ->
       d = d0 - 1
       {l2, acc2} = get_modules_mentioned(kF, d, l1, acc1)
       {l3, acc3} = get_modules_mentioned(vF, d, l2, acc2)
       pairsFromForm.(t, l3 - 1, acc3)
     end)(list, l, acc)
  end

  defp get_modules_mentioned({:type, _L, :nonempty_list, [type]}, d, l,
            acc) do
    get_modules_mentioned(type, d, l - 1, acc)
  end

  defp get_modules_mentioned({:type, _L, :nonempty_improper_list,
             [cont, term]},
            d, l, acc) do
    {l1, acc1} = get_modules_mentioned(cont, d, l - 1, acc)
    get_modules_mentioned(term, d, l1, acc1)
  end

  defp get_modules_mentioned({:type, _L, :nonempty_maybe_improper_list,
             [cont, term]},
            d, l, acc) do
    {l1, acc1} = get_modules_mentioned(cont, d, l - 1, acc)
    get_modules_mentioned(term, d, l1, acc1)
  end

  defp get_modules_mentioned({:type, _L, :maybe_improper_list,
             [content, termination]},
            d, l, acc) do
    {l1, acc1} = get_modules_mentioned(content, d, l - 1,
                                         acc)
    get_modules_mentioned(termination, d, l1, acc1)
  end

  defp get_modules_mentioned({:type, _L, :product, elements}, d, l, acc) do
    list_get_modules_mentioned(elements, d - 1, l, acc)
  end

  defp get_modules_mentioned({:type, _L, :range, [_From, _To]}, _D, l,
            acc) do
    {l, acc}
  end

  defp get_modules_mentioned({:type, _L, :tuple, :any}, _D, l, acc) do
    {l, acc}
  end

  defp get_modules_mentioned({:type, _L, :tuple, args}, d, l, acc) do
    list_get_modules_mentioned(args, d - 1, l, acc)
  end

  defp get_modules_mentioned({:type, _L, :union, args}, d, l, acc) do
    list_get_modules_mentioned(args, d, l, acc)
  end

  defp get_modules_mentioned({:remote_type, _L,
             [{:atom, _, module}, {:atom, _, _Type}, args]},
            d, l, acc) do
    acc1 = [module | acc]
    list_get_modules_mentioned(args, d, l, acc1)
  end

  defp get_modules_mentioned({:user_type, _L, _Name, args}, d, l, acc) do
    list_get_modules_mentioned(args, d, l, acc)
  end

  defp get_modules_mentioned({:type, _L, _Name, []}, _D, l, acc) do
    {l, acc}
  end

  defp get_modules_mentioned({:type, _L, _Name, args}, d, l, acc) do
    list_get_modules_mentioned(args, d, l, acc)
  end

  defp list_get_modules_mentioned([], _D, l, acc) do
    {l, acc}
  end

  defp list_get_modules_mentioned([h | tail], d, l, acc) do
    {l1, acc1} = get_modules_mentioned(h, d, l - 1, acc)
    list_get_modules_mentioned(tail, d, l1, acc1)
  end

end