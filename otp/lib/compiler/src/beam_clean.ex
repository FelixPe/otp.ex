defmodule :m_beam_clean do
  use Bitwise

  defp rootset(fs, root0, attr) do
    root1 =
      case :proplists.get_value(:on_load, attr) do
        :undefined ->
          root0

        [onLoad] ->
          [onLoad | root0]
      end

    root = :sofs.set(root1, [:function])

    map0 =
      for {:function, name, arity, lbl, _} <- fs do
        {{name, arity}, lbl}
      end

    map = :sofs.relation(map0, [{:function, :label}])
    :sofs.to_external(:sofs.image(map, root))
  end

  defp remove_unused(fs, used, all) do
    for f <- fs, :sets.is_element(f, used) do
      :erlang.map_get(f, all)
    end
  end

  defp find_all_used([f | fs0], all, used0) do
    {:function, _, _, _, code} = :erlang.map_get(f, all)
    {fs, used} = update_work_list(code, {fs0, used0})
    find_all_used(fs, all, used)
  end

  defp find_all_used([], _All, used) do
    used
  end

  defp update_work_list([{:call, _, {:f, l}} | is], sets) do
    update_work_list(is, add_to_work_list(l, sets))
  end

  defp update_work_list([{:make_fun2, {:f, l}, _, _, _} | is], sets) do
    update_work_list(is, add_to_work_list(l, sets))
  end

  defp update_work_list(
         [{:make_fun3, {:f, l}, _, _, _, _} | is],
         sets
       ) do
    update_work_list(is, add_to_work_list(l, sets))
  end

  defp update_work_list([_ | is], sets) do
    update_work_list(is, sets)
  end

  defp update_work_list([], sets) do
    sets
  end

  defp add_to_work_list(f, {fs, used} = sets) do
    case :sets.is_element(f, used) do
      true ->
        sets

      false ->
        {[f | fs], :sets.add_element(f, used)}
    end
  end

  require Record
  Record.defrecord(:r_st, :st, lmap: :undefined, entry: :undefined, lc: :undefined)

  defp clean_labels(fs0) do
    st0 = r_st(lmap: [], entry: 1, lc: 1)
    {fs1, r_st(lmap: lmap0, lc: lc)} = function_renumber(fs0, st0, [])
    lmap = :maps.from_list(lmap0)
    fs = function_replace(fs1, lmap, [])
    {fs, lc}
  end

  defp function_renumber([{:function, name, arity, _Entry, asm0} | fs], st0, acc) do
    {asm, st} = renumber_labels(asm0, [], st0)
    function_renumber(fs, st, [{:function, name, arity, r_st(st, :entry), asm} | acc])
  end

  defp function_renumber([], st, acc) do
    {acc, st}
  end

  defp renumber_labels([{:label, old} | is], [{:label, new} | _] = acc, r_st(lmap: d0) = st) do
    d = [{old, new} | d0]
    renumber_labels(is, acc, r_st(st, lmap: d))
  end

  defp renumber_labels([{:label, old} | is], acc, st0) do
    new = r_st(st0, :lc)
    d = [{old, new} | r_st(st0, :lmap)]
    renumber_labels(is, [{:label, new} | acc], r_st(st0, lmap: d, lc: new + 1))
  end

  defp renumber_labels([{:func_info, _, _, _} = fi | is], acc, st0) do
    renumber_labels(is, [fi | acc], r_st(st0, entry: r_st(st0, :lc)))
  end

  defp renumber_labels([i | is], acc, st0) do
    renumber_labels(is, [i | acc], st0)
  end

  defp renumber_labels([], acc, st) do
    {acc, st}
  end

  defp function_replace([{:function, name, arity, entry, asm0} | fs], dict, acc) do
    asm =
      try do
        fb = fn old ->
          throw({:error, {:undefined_label, old}})
        end

        :beam_utils.replace_labels(asm0, [], dict, fb)
      catch
        {:error, {:undefined_label, lbl} = reason} ->
          :io.format(~c"Function ~s/~w refers to undefined label ~w\n", [name, arity, lbl])
          exit(reason)
      end

    function_replace(fs, dict, [{:function, name, arity, entry, asm} | acc])
  end

  defp function_replace([], _, acc) do
    acc
  end

  defp fix_swap(fs, opts) do
    case :proplists.get_bool(:no_swap, opts) do
      false ->
        fs

      true ->
        fold_functions(&swap_moves/1, fs)
    end
  end

  defp swap_moves([{:swap, reg1, reg2} | is]) do
    temp = {:x, 1022}

    [
      {:move, reg1, temp},
      {:move, reg2, reg1},
      {:move, temp, reg2}
      | swap_moves(is)
    ]
  end

  defp swap_moves([i | is]) do
    [i | swap_moves(is)]
  end

  defp swap_moves([]) do
    []
  end

  defp maybe_remove_lines(fs, opts) do
    case :proplists.get_bool(:no_line_info, opts) do
      false ->
        fs

      true ->
        fold_functions(&remove_lines/1, fs)
    end
  end

  defp remove_lines([{:line, _} | is]) do
    remove_lines(is)
  end

  defp remove_lines([{:block, bl0} | is]) do
    bl = remove_lines_block(bl0)
    [{:block, bl} | remove_lines(is)]
  end

  defp remove_lines([i | is]) do
    [i | remove_lines(is)]
  end

  defp remove_lines([]) do
    []
  end

  defp remove_lines_block([{:set, _, _, {:line, _}} | is]) do
    remove_lines_block(is)
  end

  defp remove_lines_block([i | is]) do
    [i | remove_lines_block(is)]
  end

  defp remove_lines_block([]) do
    []
  end

  defp fix_bs_create_bin(fs, opts) do
    case :proplists.get_bool(:no_bs_create_bin, opts) do
      false ->
        fs

      true ->
        fold_functions(&fix_bs_create_bin/1, fs)
    end
  end

  defp fix_bs_create_bin([
         {:bs_create_bin, fail, alloc, live, unit, dst, {:list, list}}
         | is
       ]) do
    tail = fix_bs_create_bin(is)
    flags = {:field_flags, []}

    try do
      bs_pre_size_calc(list)
    catch
      :invalid_size ->
        [
          {:move, {:atom, :badarg}, {:x, 0}},
          {:call_ext_only, 1, {:extfunc, :erlang, :error, 1}}
          | tail
        ]
    else
      sizeCalc0 ->
        sizeCalc = fold_size_calc(sizeCalc0, 0, [])
        tmpDst = sizeReg = {:x, live}
        sizeIs0 = bs_size_calc(sizeCalc, fail, sizeReg, {:x, live + 1})
        sizeIs = [{:move, {:integer, 0}, sizeReg} | sizeIs0]

        restIs =
          bs_puts(list, fail) ++
            [
              {:move, tmpDst, dst}
              | tail
            ]

        case list do
          [{:atom, :append}, _, _, _, src | _] ->
            sizeIs ++
              [
                {:bs_append, fail, sizeReg, alloc, live + 1, unit, src, flags, tmpDst}
                | restIs
              ]

          [{:atom, :private_append}, _, _, _, src | _] ->
            testHeap = {:test_heap, alloc, live + 1}

            sizeIs ++
              [
                testHeap,
                {:bs_private_append, fail, sizeReg, unit, src, flags, tmpDst}
                | restIs
              ]

          _ ->
            sizeIs ++
              [
                {:bs_init_bits, fail, sizeReg, alloc, live + 1, flags, tmpDst}
                | restIs
              ]
        end
    end
  end

  defp fix_bs_create_bin([i | is]) do
    [i | fix_bs_create_bin(is)]
  end

  defp fix_bs_create_bin([]) do
    []
  end

  defp bs_pre_size_calc([type, _Seg, unit, _Flags, src, size | segs]) do
    case type do
      {:atom, t} when t === :append or t === :private_append ->
        bs_pre_size_calc(segs)

      _ ->
        [
          bs_pre_size_calc_1(type, unit, src, size)
          | bs_pre_size_calc(segs)
        ]
    end
  end

  defp bs_pre_size_calc([]) do
    []
  end

  defp bs_pre_size_calc_1({:atom, type}, unit, src, size) do
    case {unit, size} do
      {0, {:atom, :undefined}} ->
        {8,
         case type do
           :utf8 ->
             {{:instr, :bs_utf8_size}, src}

           :utf16 ->
             {{:instr, :bs_utf16_size}, src}

           :utf32 ->
             {:term, {:integer, 4}}
         end}

      {^unit, _} ->
        case {type, size} do
          {:binary, {:atom, :all}} ->
            case rem(unit, 8) do
              0 ->
                {8, {{:bif, :byte_size}, src}}

              _ ->
                {1, {{:bif, :bit_size}, src}}
            end

          {_, _} ->
            ensure_valid_size(size)
            {unit, {:term, size}}
        end
    end
  end

  defp ensure_valid_size({:x, _}) do
    :ok
  end

  defp ensure_valid_size({:y, _}) do
    :ok
  end

  defp ensure_valid_size({:integer, size}) when size >= 0 do
    :ok
  end

  defp ensure_valid_size(_) do
    throw(:invalid_size)
  end

  defp fold_size_calc([{unit, {:term, {:integer, size}}} | t], bits, acc) do
    fold_size_calc(t, bits + unit * size, acc)
  end

  defp fold_size_calc(
         [
           {unit, {{:bif, bif}, {:literal, lit}}} = h
           | t
         ],
         bits,
         acc
       ) do
    try do
      apply(:erlang, bif, [lit])
    catch
      _, _ ->
        fold_size_calc(t, bits, [h | acc])
    else
      result ->
        fold_size_calc(
          [
            {unit, {:term, {:integer, result}}}
            | t
          ],
          bits,
          acc
        )
    end
  end

  defp fold_size_calc([{u, _} = h | t], bits, acc)
       when u === 1 or
              u === 8 do
    fold_size_calc(t, bits, [h | acc])
  end

  defp fold_size_calc([{u, var} | t], bits, acc) do
    fold_size_calc(t, bits, [{1, {:*, {:term, {:integer, u}}, var}} | acc])
  end

  defp fold_size_calc([], bits, acc) do
    bytes = div(bits, 8)
    remBits = rem(bits, 8)

    sizes = [
      {1, {:term, {:integer, remBits}}},
      {8, {:term, {:integer, bytes}}}
      | acc
    ]

    for {_, sz} = pair <- sizes,
        sz !== {:term, {:integer, 0}} do
      pair
    end
  end

  defp bs_size_calc([{unit, {{:bif, bif}, reg}} | t], fail, sizeReg, tmpReg) do
    live = :erlang.element(2, sizeReg) + 1

    [
      {:gc_bif, bif, fail, live, [reg], tmpReg},
      {:bs_add, fail, [sizeReg, tmpReg, unit], sizeReg}
      | bs_size_calc(t, fail, sizeReg, tmpReg)
    ]
  end

  defp bs_size_calc(
         [
           {unit, {:*, {:term, term1}, {:term, term2}}}
           | t
         ],
         fail,
         sizeReg,
         tmpReg
       ) do
    live = :erlang.element(2, sizeReg) + 1

    [
      {:gc_bif, :*, fail, live, [term1, term2], tmpReg},
      {:bs_add, fail, [sizeReg, tmpReg, unit], sizeReg}
      | bs_size_calc(t, fail, sizeReg, tmpReg)
    ]
  end

  defp bs_size_calc([{unit, {{:instr, instr}, reg}} | t], fail, sizeReg, tmpReg) do
    [
      {instr, fail, reg, tmpReg},
      {:bs_add, fail, [sizeReg, tmpReg, unit], sizeReg}
      | bs_size_calc(t, fail, sizeReg, tmpReg)
    ]
  end

  defp bs_size_calc([{unit, {:term, term}} | t], fail, sizeReg, tmpReg) do
    [
      {:bs_add, fail, [sizeReg, term, unit], sizeReg}
      | bs_size_calc(t, fail, sizeReg, tmpReg)
    ]
  end

  defp bs_size_calc([], _Fail, _SizeReg, _TmpReg) do
    []
  end

  defp bs_puts(
         [
           {:atom, :string},
           _Seg,
           _Unit,
           _Flags,
           {:string, _} = str,
           {:integer, size}
           | is
         ],
         fail
       ) do
    [{:bs_put_string, size, str} | bs_puts(is, fail)]
  end

  defp bs_puts([{:atom, :append}, _, _, _, _, _ | is], fail) do
    bs_puts(is, fail)
  end

  defp bs_puts(
         [{:atom, :private_append}, _, _, _, _, _ | is],
         fail
       ) do
    bs_puts(is, fail)
  end

  defp bs_puts(
         [
           {:atom, type},
           _Seg,
           unit,
           flags0,
           src,
           size
           | is
         ],
         fail
       ) do
    op =
      case type do
        :integer ->
          :bs_put_integer

        :float ->
          :bs_put_float

        :binary ->
          :bs_put_binary

        :utf8 ->
          :bs_put_utf8

        :utf16 ->
          :bs_put_utf16

        :utf32 ->
          :bs_put_utf32
      end

    flags =
      case flags0 do
        nil ->
          []

        {:literal, fs} ->
          fs
      end

    i =
      cond do
        unit === 0 ->
          {:bs_put, fail, {op, {:field_flags, flags}}, [src]}

        true ->
          {:bs_put, fail, {op, unit, {:field_flags, flags}}, [size, src]}
      end

    [i | bs_puts(is, fail)]
  end

  defp bs_puts([], _Fail) do
    []
  end

  defp fold_functions(f, [{:function, n, a, lbl, is0} | t]) do
    is = f.(is0)
    [{:function, n, a, lbl, is} | fold_functions(f, t)]
  end

  defp fold_functions(_F, []) do
    []
  end
end
