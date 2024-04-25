defmodule :m_beam_z do
  use Bitwise
  import :lists, only: [dropwhile: 2, sort: 1]

  def module({mod, exp, attr, fs0, lc}, opts) do
    noInitYregs = :proplists.get_bool(:no_init_yregs, opts)

    fs =
      for f <- fs0 do
        function(f, noInitYregs)
      end

    {:ok, {mod, exp, attr, fs, lc}}
  end

  defp function(
         {:function, name, arity, cLabel, is0},
         noInitYregs
       ) do
    try do
      is1 = undo_renames(is0)
      is2 = maybe_eliminate_init_yregs(is1, noInitYregs)
      is = remove_redundant_lines(is2)
      {:function, name, arity, cLabel, is}
    catch
      class, error ->
        :io.fwrite(~c"Function: ~w/~w\n", [name, arity])
        :erlang.raise(class, error, __STACKTRACE__)
    end
  end

  defp undo_renames([{:call_ext, 2, :send} | is]) do
    [:send | undo_renames(is)]
  end

  defp undo_renames([
         {:apply, a},
         {:deallocate, n},
         :return
         | is
       ]) do
    [{:apply_last, a, n} | undo_renames(is)]
  end

  defp undo_renames([{:call, a, f}, {:%, {:var_info, {:x, 0}, _}}, {:deallocate, n}, :return | is]) do
    [{:call_last, a, f, n} | undo_renames(is)]
  end

  defp undo_renames([
         {:call, a, f},
         {:deallocate, n},
         :return
         | is
       ]) do
    [{:call_last, a, f, n} | undo_renames(is)]
  end

  defp undo_renames([
         {:call_ext, a, f},
         {:%, {:var_info, {:x, 0}, _}},
         {:deallocate, n},
         :return | is
       ]) do
    [{:call_ext_last, a, f, n} | undo_renames(is)]
  end

  defp undo_renames([
         {:call_ext, a, f},
         {:deallocate, n},
         :return
         | is
       ]) do
    [{:call_ext_last, a, f, n} | undo_renames(is)]
  end

  defp undo_renames([{:call, a, f}, {:%, {:var_info, {:x, 0}, _}}, :return | is]) do
    [{:call_only, a, f} | undo_renames(is)]
  end

  defp undo_renames([{:call, a, f}, :return | is]) do
    [{:call_only, a, f} | undo_renames(is)]
  end

  defp undo_renames([{:call_ext, a, f}, {:%, {:var_info, {:x, 0}, _}}, :return | is]) do
    [{:call_ext_only, a, f} | undo_renames(is)]
  end

  defp undo_renames([{:call_ext, a, f}, :return | is]) do
    [{:call_ext_only, a, f} | undo_renames(is)]
  end

  defp undo_renames([{:bif, :raise, _, _, _} = i | is0]) do
    is =
      dropwhile(
        fn
          {:label, _} ->
            false

          _ ->
            true
        end,
        is0
      )

    [i | undo_renames(is)]
  end

  defp undo_renames([{:get_hd, src, hd}, {:get_tl, src, tl} | is])
       when src !== hd do
    get_list(src, hd, tl, is)
  end

  defp undo_renames([{:get_tl, src, tl}, {:get_hd, src, hd} | is])
       when src !== tl do
    get_list(src, hd, tl, is)
  end

  defp undo_renames([i | is]) do
    [undo_rename(i) | undo_renames(is)]
  end

  defp undo_renames([]) do
    []
  end

  defp get_list(src, hd, tl, [{:swap, r1, r2} | is] = is0) do
    case sort([hd, tl]) === sort([r1, r2]) do
      true ->
        [{:get_list, src, tl, hd} | undo_renames(is)]

      false ->
        [{:get_list, src, hd, tl} | undo_renames(is0)]
    end
  end

  defp get_list(src, hd, tl, is) do
    [{:get_list, src, hd, tl} | undo_renames(is)]
  end

  defp undo_rename({:bs_put, f, {i, u, fl}, [sz, src]}) do
    {i, f, sz, u, fl, src}
  end

  defp undo_rename({:bs_put, f, {i, fl}, [src]}) do
    {i, f, fl, src}
  end

  defp undo_rename({:bif, :bs_add = i, f, [src1, src2, {:integer, u}], dst}) do
    {i, f, [src1, src2, u], dst}
  end

  defp undo_rename({:bif, :bs_utf8_size = i, f, [src], dst}) do
    {i, f, src, dst}
  end

  defp undo_rename({:bif, :bs_utf16_size = i, f, [src], dst}) do
    {i, f, src, dst}
  end

  defp undo_rename({:bs_init, f, {i, u, flags}, :none, [sz, src], dst}) do
    {i, f, sz, u, src, flags, dst}
  end

  defp undo_rename({:bs_init, f, {i, extra, flags}, live, [sz], dst}) do
    {i, f, sz, extra, live, flags, dst}
  end

  defp undo_rename({:bs_init, f, {i, extra, u, flags}, live, [sz, src], dst}) do
    {i, f, sz, extra, live, u, src, flags, dst}
  end

  defp undo_rename({:bs_init, _, :bs_init_writable = i, _, _, _}) do
    i
  end

  defp undo_rename({:put_map, fail, :assoc, s, d, r, l}) do
    {:put_map_assoc, fail, s, d, r, l}
  end

  defp undo_rename({:put_map, fail, :exact, s, d, r, l}) do
    {:put_map_exact, fail, s, d, r, l}
  end

  defp undo_rename({:test, :has_map_fields, fail, [src | list]}) do
    {:test, :has_map_fields, fail, src, {:list, list}}
  end

  defp undo_rename({:get_map_elements, fail, src, {:list, list}}) do
    {:get_map_elements, fail, src, {:list, list}}
  end

  defp undo_rename({:test, :is_eq_exact, fail, [src, nil]}) do
    {:test, :is_nil, fail, [src]}
  end

  defp undo_rename({:select, i, reg, fail, list}) do
    {i, reg, fail, {:list, list}}
  end

  defp undo_rename(i) do
    i
  end

  defp maybe_eliminate_init_yregs(is, true) do
    eliminate_init_yregs(is)
  end

  defp maybe_eliminate_init_yregs(is, false) do
    is
  end

  defp eliminate_init_yregs([
         {:allocate, ns, live},
         {:init_yregs, _}
         | is
       ]) do
    [{:allocate_zero, ns, live} | eliminate_init_yregs(is)]
  end

  defp eliminate_init_yregs([
         {:allocate_heap, ns, nh, live},
         {:init_yregs, _}
         | is
       ]) do
    [
      {:allocate_heap_zero, ns, nh, live}
      | eliminate_init_yregs(is)
    ]
  end

  defp eliminate_init_yregs([{:init_yregs, {:list, yregs}} | is]) do
    inits =
      for y <- yregs do
        {:init, y}
      end

    inits ++ eliminate_init_yregs(is)
  end

  defp eliminate_init_yregs([i | is]) do
    [i | eliminate_init_yregs(is)]
  end

  defp eliminate_init_yregs([]) do
    []
  end

  defp remove_redundant_lines(is) do
    remove_redundant_lines_1(is, :none)
  end

  defp remove_redundant_lines_1([{:line, loc} = i | is], prevLoc) do
    cond do
      loc === prevLoc ->
        remove_redundant_lines_1(is, loc)

      true ->
        [i | remove_redundant_lines_1(is, loc)]
    end
  end

  defp remove_redundant_lines_1([i | is], prevLoc) do
    [i | remove_redundant_lines_1(is, prevLoc)]
  end

  defp remove_redundant_lines_1([], _) do
    []
  end
end
