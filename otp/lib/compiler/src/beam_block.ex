defmodule :m_beam_block do
  use Bitwise
  import :lists, only: [keysort: 2, member: 2, reverse: 1, reverse: 2, splitwith: 2, usort: 1]
  require Record
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

  def module({mod, exp, attr, fs0, lc}, _Opts) do
    fs =
      for f <- fs0 do
        function(f)
      end

    {:ok, {mod, exp, attr, fs, lc}}
  end

  defp function({:function, name, arity, cLabel, is0}) do
    try do
      is1 = swap_opt(is0)
      is2 = blockify(is1)
      is3 = embed_lines(is2)
      is = opt_maps(is3)
      {:function, name, arity, cLabel, is}
    catch
      class, error ->
        :io.fwrite(~c"Function: ~w/~w\n", [name, arity])
        :erlang.raise(class, error, __STACKTRACE__)
    end
  end

  defp swap_opt([{:move, src, dst}, {:swap, dst, other} | is])
       when src !== other do
    swap_opt([
      {:move, other, dst},
      {:move, src, other}
      | is
    ])
  end

  defp swap_opt([{:move, src, dst}, {:swap, other, dst} | is])
       when src !== other do
    swap_opt([
      {:move, other, dst},
      {:move, src, other}
      | is
    ])
  end

  defp swap_opt([
         {:move, reg1, {:x, _} = temp} = move1,
         {:move, reg2, reg1} = move2
         | is0
       ])
       when reg1 !== temp do
    case swap_opt_end(is0, temp, reg2, []) do
      {:yes, is} ->
        [{:swap, reg1, reg2} | swap_opt(is)]

      :no ->
        [move1 | swap_opt([move2 | is0])]
    end
  end

  defp swap_opt([i | is]) do
    [i | swap_opt(is)]
  end

  defp swap_opt([]) do
    []
  end

  defp swap_opt_end([{:move, s, d} = i | is], temp, dst, acc) do
    case {s, d} do
      {^temp, ^dst} ->
        {:x, x} = temp

        case is_unused(x, is) do
          true ->
            {:yes, reverse(acc, is)}

          false ->
            :no
        end

      {^temp, _} ->
        :no

      {^dst, _} ->
        :no

      {_, ^temp} ->
        :no

      {_, ^dst} ->
        :no

      {_, _} ->
        swap_opt_end(is, temp, dst, [i | acc])
    end
  end

  defp swap_opt_end([{:init_yregs, _} = i | is], temp, dst, acc) do
    swap_opt_end(is, temp, dst, [i | acc])
  end

  defp swap_opt_end(_, _, _, _) do
    :no
  end

  defp is_unused(x, [{:call, a, _} | _]) when a <= x do
    true
  end

  defp is_unused(x, [{:call_ext, a, _} | _]) when a <= x do
    true
  end

  defp is_unused(x, [{:make_fun2, _, _, _, a} | _])
       when a <= x do
    true
  end

  defp is_unused(x, [{:move, src, dst} | is]) do
    case {src, dst} do
      {{:x, ^x}, _} ->
        false

      {_, {:x, ^x}} ->
        true

      {_, _} ->
        is_unused(x, is)
    end
  end

  defp is_unused(x, [{:line, _} | is]) do
    is_unused(x, is)
  end

  defp is_unused(_, _) do
    false
  end

  defp blockify(is) do
    blockify(is, [])
  end

  defp blockify([i | is0] = isAll, acc) do
    case collect(i) do
      :error ->
        blockify(is0, [i | acc])

      instr when is_tuple(instr) ->
        {block0, is} = collect_block(isAll)
        block = sort_moves(block0)
        blockify(is, [{:block, block} | acc])
    end
  end

  defp blockify([], acc) do
    reverse(acc)
  end

  defp collect_block(is) do
    collect_block(is, [])
  end

  defp collect_block([{:allocate, n, r} | is0], acc) do
    {inits, is} =
      splitwith(
        fn
          {:init, {:y, _}} ->
            true

          _ ->
            false
        end,
        is0
      )

    collect_block(
      is,
      [
        {:set, [], [], {:alloc, r, {:nozero, n, 0, inits}}}
        | acc
      ]
    )
  end

  defp collect_block([i | is] = is0, acc) do
    case collect(i) do
      :error ->
        {reverse(acc), is0}

      instr ->
        collect_block(is, [instr | acc])
    end
  end

  defp collect_block([], acc) do
    {reverse(acc), []}
  end

  defp collect({:allocate, n, r}) do
    {:set, [], [], {:alloc, r, {:nozero, n, 0, []}}}
  end

  defp collect({:allocate_heap, ns, nh, r}) do
    {:set, [], [], {:alloc, r, {:nozero, ns, nh, []}}}
  end

  defp collect({:test_heap, n, r}) do
    {:set, [], [], {:alloc, r, {:nozero, :nostack, n, []}}}
  end

  defp collect({:bif, n, {:f, 0}, as, d}) do
    {:set, [d], as, {:bif, n, {:f, 0}}}
  end

  defp collect({:gc_bif, n, {:f, 0}, r, as, d}) do
    {:set, [d], as, {:alloc, r, {:gc_bif, n, {:f, 0}}}}
  end

  defp collect({:move, s, d}) do
    {:set, [d], [s], :move}
  end

  defp collect({:put_list, s1, s2, d}) do
    {:set, [d], [s1, s2], :put_list}
  end

  defp collect({:put_tuple2, d, {:list, els}}) do
    {:set, [d], els, :put_tuple2}
  end

  defp collect({:get_tuple_element, s, i, d}) do
    {:set, [d], [s], {:get_tuple_element, i}}
  end

  defp collect({:set_tuple_element, s, d, i}) do
    {:set, [], [s, d], {:set_tuple_element, i}}
  end

  defp collect({:get_hd, s, d}) do
    {:set, [d], [s], :get_hd}
  end

  defp collect({:get_tl, s, d}) do
    {:set, [d], [s], :get_tl}
  end

  defp collect(:remove_message) do
    {:set, [], [], :remove_message}
  end

  defp collect({:put_map, {:f, 0}, op, s, d, r, {:list, puts}}) do
    {:set, [d], [s | puts], {:alloc, r, {:put_map, op, {:f, 0}}}}
  end

  defp collect({:fmove, s, d}) do
    {:set, [d], [s], :fmove}
  end

  defp collect({:fconv, s, d}) do
    {:set, [d], [s], :fconv}
  end

  defp collect(_) do
    :error
  end

  defp embed_lines(is) do
    embed_lines(reverse(is), [])
  end

  defp embed_lines(
         [
           {:block, b2},
           {:line, _} = line,
           {:block, b1}
           | t
         ],
         acc
       ) do
    b = {:block, b1 ++ [{:set, [], [], line}] ++ b2}
    embed_lines([b | t], acc)
  end

  defp embed_lines([{:block, b1}, {:line, _} = line | t], acc) do
    b = {:block, [{:set, [], [], line} | b1]}
    embed_lines([b | t], acc)
  end

  defp embed_lines([i | is], acc) do
    embed_lines(is, [i | acc])
  end

  defp embed_lines([], acc) do
    acc
  end

  defp sort_moves([
         {:set, [{:x, _}], [{:y, _}], :move} = i
         | is0
       ]) do
    {moves, is} = sort_moves_1(is0, :x, :y, [i])
    moves ++ sort_moves(is)
  end

  defp sort_moves([
         {:set, [{:y, _}], [{:x, _}], :move} = i
         | is0
       ]) do
    {moves, is} = sort_moves_1(is0, :y, :x, [i])
    moves ++ sort_moves(is)
  end

  defp sort_moves([i | is]) do
    [i | sort_moves(is)]
  end

  defp sort_moves([]) do
    []
  end

  defp sort_moves_1([{:set, [{:x, 0}], [_], :move} = i | is], _DTag, _STag, acc) do
    {sort_on_yreg(acc) ++ [i], is}
  end

  defp sort_moves_1(
         [
           {:set, [{dTag, _}], [{sTag, _}], :move} = i
           | is
         ],
         dTag,
         sTag,
         acc
       ) do
    sort_moves_1(is, dTag, sTag, [i | acc])
  end

  defp sort_moves_1(is, _DTag, _STag, acc) do
    {sort_on_yreg(acc), is}
  end

  defp sort_on_yreg([{:set, [dst], [src], :move} | _] = moves) do
    case {dst, src} do
      {{:y, _}, {:x, _}} ->
        keysort(2, moves)

      {{:x, _}, {:y, _}} ->
        keysort(3, moves)
    end
  end

  defp opt_maps(is) do
    opt_maps(is, [])
  end

  defp opt_maps(
         [{:get_map_elements, fail, src, list} = i | is],
         acc0
       ) do
    case simplify_get_map_elements(fail, src, list, acc0) do
      {:ok, acc} ->
        opt_maps(is, acc)

      :error ->
        opt_maps(is, [i | acc0])
    end
  end

  defp opt_maps(
         [{:test, :has_map_fields, fail, ops} = i | is],
         acc0
       ) do
    case simplify_has_map_fields(fail, ops, acc0) do
      {:ok, acc} ->
        opt_maps(is, acc)

      :error ->
        opt_maps(is, [i | acc0])
    end
  end

  defp opt_maps([i | is], acc) do
    opt_maps(is, [i | acc])
  end

  defp opt_maps([], acc) do
    reverse(acc)
  end

  defp simplify_get_map_elements(fail, src, {:list, [key, dst]}, [
         {:get_map_elements, fail, src, {:list, list1}}
         | acc
       ]) do
    case are_keys_literals([key]) and are_keys_literals(list1) and
           not is_reg_overwritten(
             src,
             list1
           ) and
           not is_reg_overwritten(
             dst,
             list1
           ) do
      true ->
        case member(key, list1) do
          true ->
            :error

          false ->
            list = [key, dst | list1]
            {:ok, [{:get_map_elements, fail, src, {:list, list}} | acc]}
        end

      false ->
        :error
    end
  end

  defp simplify_get_map_elements(_, _, _, _) do
    :error
  end

  defp simplify_has_map_fields(fail, [src | keys0], [
         {:test, :has_map_fields, fail, [src | keys1]}
         | acc
       ]) do
    case are_keys_literals(keys0) and are_keys_literals(keys1) do
      true ->
        keys = usort(keys0 ++ keys1)
        {:ok, [{:test, :has_map_fields, fail, [src | keys]} | acc]}

      false ->
        :error
    end
  end

  defp simplify_has_map_fields(_, _, _) do
    :error
  end

  defp are_keys_literals([r_tr() | _]) do
    false
  end

  defp are_keys_literals([{:x, _} | _]) do
    false
  end

  defp are_keys_literals([{:y, _} | _]) do
    false
  end

  defp are_keys_literals([_ | _]) do
    true
  end

  defp is_reg_overwritten(src, [_Key, src | _]) do
    true
  end

  defp is_reg_overwritten(src, [_Key, _Src | t]) do
    is_reg_overwritten(src, t)
  end

  defp is_reg_overwritten(_, []) do
    false
  end
end
