defmodule :m_beam_ssa_alias do
  use Bitwise
  import :lists, only: [any: 2, foldl: 3, reverse: 1,
                          zip: 2]
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
  Record.defrecord(:r_aas, :aas, caller: :undefined,
                               call_args: %{}, alias_map: %{},
                               func_db: :undefined, kills: :undefined,
                               st_map: :undefined, orig_st_map: :undefined,
                               repeats: :sets.new([{:version, 2}]))
  Record.defrecord(:r_liveness_st, :liveness_st, in: :sets.new([{:version,
                                                       2}]),
                                       out: :sets.new([{:version, 2}]))
  Record.defrecord(:r_vas, :vas, status: :undefined,
                               parents: [], child: :none, extracted: [],
                               tuple_elems: [], pair_elems: :none)
  def opt(stMap0, funcDb0) do
    case (any_huge_function(stMap0)) do
      true ->
        {stMap0, funcDb0}
      false ->
        funs = (for f <- :maps.keys(stMap0),
                      :erlang.is_map_key(f, funcDb0), not is_nif(f, stMap0) do
                  f
                end)
        liveness = liveness(funs, stMap0)
        killsMap = killsets(liveness, stMap0)
        aa(funs, killsMap, stMap0, funcDb0)
    end
  end

  defp any_huge_function(stMap) do
    any(fn r_opt_st(ssa: code) ->
             length(code) > 2000
        end,
          :maps.values(stMap))
  end

  defp liveness([f | funs], stMap) do
    liveness = liveness_fun(f, stMap)
    [{f, liveness} | liveness(funs, stMap)]
  end

  defp liveness([], _StMap) do
    []
  end

  defp liveness_blks_fixp(_SSA, state0, state0, _UseDefCache) do
    state0
  end

  defp liveness_blks_fixp(sSA, state0, _Old, useDefCache) do
    state = liveness_blks(sSA, state0, useDefCache)
    liveness_blks_fixp(sSA, state, state0, useDefCache)
  end

  defp liveness_blks([{lbl, blk} | blocks], state0, useDefCache) do
    outOld = get_live_out(lbl, state0)
    %{^lbl => {defs, uses}} = useDefCache
    in__ = :sets.union(uses, :sets.subtract(outOld, defs))
    out = successor_live_ins(blk, state0)
    liveness_blks(blocks,
                    set_block_liveness(lbl, in__, out, state0), useDefCache)
  end

  defp liveness_blks([], state0, _UseDefCache) do
    state0
  end

  defp get_live_in(lbl, state) do
    r_liveness_st(in: in__) = :erlang.map_get(lbl, state)
    in__
  end

  defp get_live_out(lbl, state) do
    r_liveness_st(out: out) = :erlang.map_get(lbl, state)
    out
  end

  defp set_block_liveness(lbl, in__, out, state) do
    l = :erlang.map_get(lbl, state)
    Map.put(state, lbl, r_liveness_st(l, in: in__,  out: out))
  end

  defp successor_live_ins(blk, state) do
    foldl(fn lbl, acc ->
               :sets.union(acc, get_live_in(lbl, state))
          end,
            :sets.new([{:version, 2}]), :beam_ssa.successors(blk))
  end

  defp blk_defs(r_b_blk(is: is)) do
    foldl(fn r_b_set(dst: dst), acc ->
               :sets.add_element(dst, acc)
          end,
            :sets.new([{:version, 2}]), is)
  end

  defp blk_effective_uses(r_b_blk(is: is, last: last)) do
    blk_effective_uses([last | reverse(is)],
                         :sets.new([{:version, 2}]))
  end

  defp blk_effective_uses([i | is], uses0) do
    uses = (case (i) do
              r_b_set(dst: dst) ->
                :sets.del_element(dst, uses0)
              _ ->
                uses0
            end)
    localUses = :sets.from_list(:beam_ssa.used(i),
                                  [{:version, 2}])
    blk_effective_uses(is, :sets.union(uses, localUses))
  end

  defp blk_effective_uses([], uses) do
    uses
  end

  defp liveness_make_cache(sSA) do
    liveness_make_cache(sSA, %{})
  end

  defp liveness_make_cache([{lbl, blk} | blocks], cache0) do
    defs = blk_defs(blk)
    uses = blk_effective_uses(blk)
    cache = Map.put(cache0, lbl, {defs, uses})
    liveness_make_cache(blocks, cache)
  end

  defp liveness_make_cache([], cache) do
    cache
  end

  defp is_nif(f, stMap) do
    r_opt_st(ssa: [{0, r_b_blk(is: is)} | _]) = :erlang.map_get(f, stMap)
    case (is) do
      [r_b_set(op: :nif_start) | _] ->
        true
      _ ->
        false
    end
  end

  defp kills_fun(fun, stMap, liveness) do
    r_opt_st(ssa: sSA) = :erlang.map_get(fun, stMap)
    kills_fun1(sSA, %{}, liveness)
  end

  defp kills_fun1([{lbl, blk} | blocks], killsMap0, liveness) do
    killsMap = kills_block(lbl, blk,
                             :erlang.map_get(lbl, liveness), killsMap0)
    kills_fun1(blocks, killsMap, liveness)
  end

  defp kills_fun1([], killsMap, _) do
    killsMap
  end

  defp kills_block(lbl, r_b_blk(is: is, last: last), r_liveness_st(out: out),
            killsMap0) do
    kills_is([last | reverse(is)], out, killsMap0, lbl)
  end

  defp kills_is([i | is], live0, killsMap0, blk) do
    {live, key} = (case (i) do
                     r_b_set(dst: dst) ->
                       {:sets.del_element(dst, live0), dst}
                     _ ->
                       {live0, {:terminator, blk}}
                   end)
    uses = :sets.from_list(:beam_ssa.used(i),
                             [{:version, 2}])
    remainingUses = :sets.union(live0, uses)
    killed = :sets.subtract(remainingUses, live0)
    killsMap = Map.put(killsMap0, key, killed)
    kills_is(is, :sets.union(live, killed), killsMap, blk)
  end

  defp kills_is([], _, killsMap, _) do
    killsMap
  end

  defp aa(funs, killsMap, stMap, funcDb) do
    argsInfo = foldl(fn f = r_b_local(), acc ->
                          r_func_info(exported: e, arg_types: aT) = :erlang.map_get(f,
                                                                            funcDb)
                          s = (case (e) do
                                 true ->
                                   :aliased
                                 false ->
                                   :unique
                               end)
                          Map.put(acc, f,
                                         for _ <- aT do
                                           s
                                         end)
                     end,
                       %{}, funs)
    aAS = r_aas(call_args: argsInfo, func_db: funcDb,
              kills: killsMap, st_map: stMap, orig_st_map: stMap)
    aa_fixpoint(funs, aAS)
  end

  defp aa_fixpoint(funs,
            aAS = r_aas(alias_map: aliasMap, call_args: callArgs,
                      func_db: funcDb)) do
    order = aa_breadth_first(funs, funcDb)
    aa_fixpoint(order, order, aliasMap, callArgs, aAS, 16)
  end

  defp aa_fixpoint([f | fs], order, oldAliasMap, oldCallArgs,
            aAS0 = r_aas(st_map: stMap), limit) do
    r_b_local(name: r_b_literal(val: _N), arity: _A) = f
    aAS1 = r_aas(aAS0, caller: f)
    :skip
    aAS = aa_fun(f, :erlang.map_get(f, stMap), aAS1)
    aa_fixpoint(fs, order, oldAliasMap, oldCallArgs, aAS,
                  limit)
  end

  defp aa_fixpoint([], order, oldAliasMap, oldCallArgs,
            r_aas(alias_map: oldAliasMap, call_args: oldCallArgs,
                func_db: funcDb) = aAS,
            _Limit) do
    :skip
    {stMap, _} = aa_update_annotations(order, aAS)
    {stMap, funcDb}
  end

  defp aa_fixpoint([], _, _, _,
            r_aas(func_db: funcDb, orig_st_map: stMap), 0) do
    :skip
    {stMap, funcDb}
  end

  defp aa_fixpoint([], order, _OldAliasMap, _OldCallArgs,
            r_aas(alias_map: aliasMap, call_args: callArgs,
                repeats: repeats) = aAS,
            limit) do
    :skip
    newOrder = (for id <- order,
                      :sets.is_element(id, repeats) do
                  id
                end)
    aa_fixpoint(newOrder, order, aliasMap, callArgs,
                  r_aas(aAS, repeats: :sets.new([{:version, 2}])), limit - 1)
  end

  defp aa_fun(f, r_opt_st(ssa: linear0, args: args),
            aAS0 = r_aas(alias_map: aliasMap0, call_args: callArgs0,
                       func_db: funcDb, repeats: repeats0)) do
    argsStatus = aa_get_call_args_status(args, f, aAS0)
    sS0 = foldl(fn {var, status}, acc ->
                     aa_new_ssa_var(var, status, acc)
                end,
                  %{}, argsStatus)
    :skip
    {sS, r_aas(call_args: callArgs) = aAS} = aa_blocks(linear0,
                                                     %{0 => sS0}, aAS0)
    :skip
    aliasMap = Map.put(aliasMap0, f, sS)
    prevSS = :maps.get(f, aliasMap0, %{})
    repeats = (case (prevSS !== sS or callArgs0 !== callArgs) do
                 true ->
                   %{^f => r_func_info(in: in__, out: out)} = funcDb
                   foldl(&:sets.add_element/2,
                           foldl(&:sets.add_element/2, repeats0, out), in__)
                 false ->
                   repeats0
               end)
    r_aas(aAS, alias_map: aliasMap,  repeats: repeats)
  end

  defp aa_blocks([{l, r_b_blk(is: is0, last: t0)} | bs0], lbl2SS0,
            aAS0) do
    %{^l => sS0} = lbl2SS0
    {sS1, aAS1} = aa_is(is0, l, sS0, aAS0)
    lbl2SS1 = aa_terminator(t0, sS1, l, lbl2SS0)
    aa_blocks(bs0, lbl2SS1, aAS1)
  end

  defp aa_blocks([], lbl2SS, aAS) do
    {lbl2SS, aAS}
  end

  defp aa_is([i = r_b_set(dst: dst, op: op, args: args,
                   anno: anno0) |
               is],
            thisBlock, sS0, aAS0) do
    sS1 = aa_new_ssa_var(dst, :unique, sS0)
    {sS, aAS} = (case (op) do
                   {:bif, bif} ->
                     {aa_bif(dst, bif, args, sS1, aAS0), aAS0}
                   :bs_create_bin ->
                     case (args) do
                       [r_b_literal(val: flag), _, arg | _]
                           when flag === :private_append or flag === :append ->
                         case (aa_all_dies([arg], dst, aAS0)) do
                           true ->
                             {aa_derive_from(dst, arg, sS1), aAS0}
                           false ->
                             {aa_set_aliased([dst | args], sS1), aAS0}
                         end
                       _ ->
                         {aa_set_aliased([dst | args], sS1), aAS0}
                     end
                   :bs_extract ->
                     {aa_set_aliased([dst | args], sS1), aAS0}
                   :bs_get_tail ->
                     {aa_set_aliased([dst | args], sS1), aAS0}
                   :bs_match ->
                     {aa_set_aliased([dst | args], sS1), aAS0}
                   :bs_start_match ->
                     [_, bin] = args
                     {aa_set_aliased([dst, bin], sS1), aAS0}
                   :build_stacktrace ->
                     {aa_alias_all(sS1), aAS0}
                   :call ->
                     aa_call(dst, args, anno0, sS1, aAS0)
                   :catch_end ->
                     [_Tag, arg] = args
                     {aa_derive_from(dst, arg, sS1), aAS0}
                   :extract ->
                     [arg, _] = args
                     {aa_derive_from(dst, arg, sS1), aAS0}
                   :get_hd ->
                     [arg] = args
                     {aa_pair_extraction(dst, arg, :hd, sS1), aAS0}
                   :get_map_element ->
                     [map, _Key] = args
                     {aa_map_extraction(dst, map, sS1, aAS0), aAS0}
                   :get_tl ->
                     [arg] = args
                     {aa_pair_extraction(dst, arg, :tl, sS1), aAS0}
                   :get_tuple_element ->
                     [arg, idx] = args
                     {aa_tuple_extraction(dst, arg, idx, sS1), aAS0}
                   :landingpad ->
                     {aa_set_aliased(dst, sS1), aAS0}
                   :make_fun ->
                     [callee | env] = args
                     aa_make_fun(dst, callee, env, sS1, aAS0)
                   :old_make_fun ->
                     [callee | env] = args
                     aa_make_fun(dst, callee, env, sS1, aAS0)
                   :peek_message ->
                     {aa_set_aliased(dst, sS1), aAS0}
                   :phi ->
                     {aa_phi(dst, args, sS1), aAS0}
                   :put_list ->
                     {aa_construct_term(dst, args, sS1, aAS0), aAS0}
                   :put_map ->
                     {aa_construct_term(dst, args, sS1, aAS0), aAS0}
                   :put_tuple ->
                     {aa_construct_term(dst, args, sS1, aAS0), aAS0}
                   :update_tuple ->
                     {aa_construct_term(dst, args, sS1, aAS0), aAS0}
                   :update_record ->
                     [_Hint, _Size, src | updates] = args
                     values = [src | aa_update_record_get_vars(updates)]
                     {aa_construct_term(dst, values, sS1, aAS0), aAS0}
                   {:float, _} ->
                     {sS1, aAS0}
                   {:succeeded, _} ->
                     {sS1, aAS0}
                   :bs_init_writable ->
                     {sS1, aAS0}
                   :bs_test_tail ->
                     {sS1, aAS0}
                   :has_map_field ->
                     {sS1, aAS0}
                   :is_nonempty_list ->
                     {sS1, aAS0}
                   :is_tagged_tuple ->
                     {sS1, aAS0}
                   :kill_try_tag ->
                     {sS1, aAS0}
                   :match_fail ->
                     {sS1, aAS0}
                   :new_try_tag ->
                     {sS1, aAS0}
                   :nif_start ->
                     {sS1, aAS0}
                   :raw_raise ->
                     {sS1, aAS0}
                   :recv_marker_bind ->
                     {sS1, aAS0}
                   :recv_marker_clear ->
                     {sS1, aAS0}
                   :recv_marker_reserve ->
                     {sS1, aAS0}
                   :recv_next ->
                     {sS1, aAS0}
                   :remove_message ->
                     {sS1, aAS0}
                   :resume ->
                     {sS1, aAS0}
                   :wait_timeout ->
                     {sS1, aAS0}
                   _ ->
                     exit({:unknown_instruction, i})
                 end)
    aa_is(is, thisBlock, sS, aAS)
  end

  defp aa_is([], _, sS, aAS) do
    {sS, aAS}
  end

  defp aa_terminator(r_b_br(succ: s, fail: s), sS, thisBlock, lbl2SS) do
    aa_set_block_exit_ss(thisBlock, sS,
                           aa_add_block_entry_ss([s], sS, lbl2SS))
  end

  defp aa_terminator(r_b_br(succ: s, fail: f), sS, thisBlock, lbl2SS) do
    aa_set_block_exit_ss(thisBlock, sS,
                           aa_add_block_entry_ss([s, f], sS, lbl2SS))
  end

  defp aa_terminator(r_b_ret(arg: arg, anno: anno0), sS, thisBlock,
            lbl2SS0) do
    type = :maps.get(:result_type, anno0, :any)
    status0 = aa_get_status(arg, sS)
    :skip
    type2Status0 = :maps.get(:returns, lbl2SS0, %{})
    status = (case (type2Status0) do
                %{^type => otherStatus} ->
                  aa_meet(status0, otherStatus)
                %{} ->
                  status0
              end)
    type2Status = Map.put(type2Status0, type, status)
    :skip
    lbl2SS = Map.put(lbl2SS0, :returns, type2Status)
    aa_set_block_exit_ss(thisBlock, sS, lbl2SS)
  end

  defp aa_terminator(r_b_switch(fail: f, list: ls), sS, thisBlock, lbl2SS0) do
    lbl2SS = aa_add_block_entry_ss([f | for {_, l} <- ls do
                                          l
                                        end],
                                     sS, lbl2SS0)
    aa_set_block_exit_ss(thisBlock, sS, lbl2SS)
  end

  defp aa_set_block_exit_ss(thisBlockLbl, sS, lbl2SS) do
    Map.put(lbl2SS, thisBlockLbl, sS)
  end

  defp aa_add_block_entry_ss([l | blockLabels], newSS, lbl2SS) do
    aa_add_block_entry_ss(blockLabels, newSS,
                            aa_merge_ss(l, newSS, lbl2SS))
  end

  defp aa_add_block_entry_ss([], _, lbl2SS) do
    lbl2SS
  end

  defp aa_merge_ss(blockLbl, newSS, lbl2SS)
      when :erlang.is_map_key(blockLbl, lbl2SS) do
    %{^blockLbl => origSS} = lbl2SS
    newSize = :maps.size(newSS)
    origSize = :maps.size(origSS)
    _ = origSS
    _ = newSS
    tmp = (cond do
             newSize < origSize ->
               :skip
               aa_merge_continue(origSS, newSS, :maps.keys(newSS), [],
                                   [])
             true ->
               :skip
               aa_merge_continue(newSS, origSS, :maps.keys(origSS), [],
                                   [])
           end)
    Map.put(lbl2SS, blockLbl, tmp)
  end

  defp aa_merge_ss(blockLbl, newSS, lbl2SS) do
    Map.put(lbl2SS, blockLbl, newSS)
  end

  defp aa_merge_continue(a, b, [v | vars], parentFixups, aliasFixups) do
    %{^v => bVas} = b
    case (a) do
      %{^v => aVas} ->
        :skip
        aa_merge_1(v, aVas, bVas, a, b, vars, parentFixups,
                     aliasFixups)
      %{} ->
        :skip
        aa_merge_continue(Map.put(a, v, bVas), b, vars,
                            parentFixups, aliasFixups)
    end
  end

  defp aa_merge_continue(a0, _, [], parentFixups, aliasFixups) do
    a = aa_merge_parent_fixups(a0, parentFixups)
    aa_merge_alias_fixups(a, aliasFixups)
  end

  defp aa_merge_1(_V, vas, vas, a, b, vars, parentFixups,
            aliasFixups) do
    :skip
    aa_merge_continue(a, b, vars, parentFixups, aliasFixups)
  end

  defp aa_merge_1(_V, r_vas(status: :aliased), bVas, a, b, vars,
            parentFixups, aliasFixups) do
    :skip
    aa_merge_continue(a, b, vars, parentFixups,
                        aa_related(bVas) ++ aliasFixups)
  end

  defp aa_merge_1(v, aVas, r_vas(status: :aliased), a, b, vars,
            parentFixups, aliasFixups) do
    :skip
    aa_merge_continue(Map.put(a, v, r_vas(status: :aliased)), b,
                        vars, parentFixups, aa_related(aVas) ++ aliasFixups)
  end

  defp aa_merge_1(v, r_vas(status: s) = aVas, r_vas(status: s) = bVas, a,
            b, vars, parentFixups, aliasFixups)
      when s == :unique or s == :as_parent do
    aa_merge_child(v, aVas, bVas, a, b, vars, parentFixups,
                     aliasFixups)
  end

  defp aa_merge_child(v, r_vas(child: child) = aVas,
            r_vas(child: child) = bVas, a, b, vars, parentFixups,
            aliasFixups) do
    :skip
    aa_merge_tuple(v, aVas, bVas, a, b, vars, parentFixups,
                     aliasFixups)
  end

  defp aa_merge_child(v, r_vas(child: :none) = aVas,
            r_vas(child: child) = bVas, a, b, vars, parentFixups,
            aliasFixups) do
    :skip
    aa_merge_tuple(v, r_vas(aVas, child: child), bVas,
                     Map.put(a, v, bVas), b, vars,
                     [{child, v} | parentFixups], aliasFixups)
  end

  defp aa_merge_child(v, aVas, r_vas(child: :none) = bVas, a, b, vars,
            parentFixups, aliasFixups) do
    :skip
    aa_merge_tuple(v, aVas, bVas, a, b, vars, parentFixups,
                     aliasFixups)
  end

  defp aa_merge_child(v, aVas, bVas, a, b, vars, parentFixups,
            aliasFixups) do
    :skip
    aa_merge_continue(Map.put(a, v, r_vas(status: :aliased)), b,
                        vars, parentFixups,
                        aa_related(aVas) ++ aa_related(bVas) ++ aliasFixups)
  end

  defp aa_merge_tuple(v, r_vas(tuple_elems: es) = aVas,
            r_vas(tuple_elems: es) = bVas, a, b, vars, parentFixups,
            aliasFixups) do
    :skip
    aa_merge_pair(v, aVas, bVas, a, b, vars, parentFixups,
                    aliasFixups)
  end

  defp aa_merge_tuple(v, r_vas(tuple_elems: aEs) = aVas,
            r_vas(tuple_elems: bEs) = bVas, a, b, vars, parentFixups,
            aliasFixups) do
    case (aa_non_aliasing_tuple_elements(aEs ++ bEs)) do
      true ->
        :skip
        elements = :ordsets.union(aEs, bEs)
        vas = r_vas(aVas, tuple_elems: elements)
        aa_merge_pair(v, vas, bVas, Map.put(a, v, vas), b, vars,
                        parentFixups, aliasFixups)
      false ->
        :skip
        aa_merge_continue(Map.put(a, v, r_vas(status: :aliased)), b,
                            vars, parentFixups,
                            aa_related(aVas) ++ aa_related(bVas) ++ aliasFixups)
    end
  end

  defp aa_merge_pair(v, r_vas(pair_elems: es) = aVas,
            r_vas(pair_elems: es) = bVas, a, b, vars, parentFixups,
            aliasFixups) do
    :skip
    aa_merge_extracted(v, aVas, bVas, a, b, vars,
                         parentFixups, aliasFixups)
  end

  defp aa_merge_pair(v, r_vas(pair_elems: aEs) = aVas,
            r_vas(pair_elems: bEs) = bVas, a, b, vars, parentFixups,
            aliasFixups) do
    r = (case ({aEs, bEs}) do
           {{:hd, h}, {:tl, t}} ->
             {:both, h, t}
           {{:tl, t}, {:hd, h}} ->
             {:both, h, t}
           {e, :none} ->
             e
           {:none, e} ->
             e
           _ ->
             :alias
         end)
    case (r) do
      :alias ->
        :skip
        aa_merge_continue(Map.put(a, v, r_vas(status: :aliased)), b,
                            vars, parentFixups,
                            aa_related(aVas) ++ aa_related(bVas) ++ aliasFixups)
      pair ->
        :skip
        vas = r_vas(aVas, pair_elems: pair)
        aa_merge_extracted(v, vas, bVas, Map.put(a, v, vas), b,
                             vars, parentFixups, aliasFixups)
    end
  end

  defp aa_merge_extracted(v, r_vas(extracted: aEs) = aVas, r_vas(extracted: bEs),
            a, b, vars, parentFixups, aliasFixups) do
    extracted = :ordsets.union(aEs, bEs)
    aa_merge_continue(Map.put(a, v,
                                   r_vas(aVas, extracted: extracted)),
                        b, vars, parentFixups, aliasFixups)
  end

  defp aa_related(r_vas(parents: ps, child: child, extracted: ex)) do
    (case (child) do
       :none ->
         []
       ^child ->
         [child]
     end) ++ ps ++ ex
  end

  defp aa_non_aliasing_tuple_elements(elems) do
    aa_non_aliasing_tuple_elements(elems, %{})
  end

  defp aa_non_aliasing_tuple_elements([{i, v} | es], seen) do
    case (seen) do
      %{^i => x} when x !== v ->
        false
      %{} ->
        aa_non_aliasing_tuple_elements(es, Map.put(seen, i, v))
    end
  end

  defp aa_non_aliasing_tuple_elements([], _) do
    true
  end

  defp aa_merge_alias_fixups(sS, fixups) do
    :skip
    aa_set_status_1(fixups, :none, sS)
  end

  defp aa_merge_parent_fixups(sS0, [{child, parent} | fixups]) do
    :skip
    %{^child => r_vas(parents: parents) = vas} = sS0
    sS = Map.put(sS0, child,
                        r_vas(vas, parents: :ordsets.add_element(parent, parents)))
    aa_merge_parent_fixups(sS, fixups)
  end

  defp aa_merge_parent_fixups(sS, []) do
    :skip
    sS
  end

  defp aa_merge_ss_successor(blockLbl, newSS, lbl2SS) do
    %{^blockLbl => origSS} = lbl2SS
    Map.put(lbl2SS, blockLbl,
                      aa_merge_ss_successor(origSS, newSS))
  end

  defp aa_merge_ss_successor(orig, new) do
    :maps.fold(fn v, vas, acc ->
                    case (new) do
                      %{^v => ^vas} ->
                        acc
                      %{^v => r_vas(status: :aliased)} ->
                        aa_set_aliased(v, acc)
                      %{} ->
                        acc
                    end
               end,
                 orig, orig)
  end

  defp aa_new_ssa_var(var, status, state) do
    :skip
    Map.put(state, var, r_vas(status: status))
  end

  defp aa_get_status(v = r_b_var(), state) do
    case (state) do
      %{^v => r_vas(status: :as_parent, parents: ps)} ->
        aa_get_status(ps, state)
      %{^v => r_vas(status: status)} ->
        status
    end
  end

  defp aa_get_status(r_b_literal(), _State) do
    :unique
  end

  defp aa_get_status([v = r_b_var()], state) do
    aa_get_status(v, state)
  end

  defp aa_get_status([v = r_b_var() | parents], state) do
    aa_meet(aa_get_status(v, state),
              aa_get_status(parents, state))
  end

  defp aa_get_element_extraction_status(v = r_b_var(), state) do
    case (state) do
      %{^v => r_vas(status: :aliased)} ->
        :aliased
      %{^v => r_vas(tuple_elems: elems)} when elems !== [] ->
        :unique
      %{^v => r_vas(pair_elems: elems)} when elems !== :none ->
        :unique
    end
  end

  defp aa_get_element_extraction_status(r_b_literal(), _State) do
    :unique
  end

  defp aa_set_status(v = r_b_var(), :aliased, state) do
    case (state) do
      %{^v => r_vas(status: :unique, parents: [])} ->
        aa_set_status_1(v, :none, state)
      %{^v => r_vas(status: :aliased)} ->
        state
      %{^v => r_vas(parents: parents)} ->
        aa_set_status(parents, :aliased, state)
    end
  end

  defp aa_set_status(_V = r_b_var(), :unique, state) do
    :skip
    state
  end

  defp aa_set_status(r_b_literal(), _Status, state) do
    state
  end

  defp aa_set_status([x | t], status, state) do
    aa_set_status(x, status,
                    aa_set_status(t, status, state))
  end

  defp aa_set_status([], _, state) do
    state
  end

  defp aa_set_status_1(r_b_var() = v, parent, state0) do
    %{^v
      =>
      r_vas(child: child, extracted: extracted,
          parents: parents)} = state0
    state = Map.put(state0, v, r_vas(status: :aliased))
    work = (case (child) do
              :none ->
                []
              _ ->
                [child]
            end) ++ :ordsets.del_element(parent,
                                           parents) ++ extracted
    aa_set_status_1(work, v, state)
  end

  defp aa_set_status_1([r_b_var() = v | rest], parent, state) do
    aa_set_status_1(rest, parent,
                      aa_set_status_1(v, parent, state))
  end

  defp aa_set_status_1([], _Parent, state) do
    state
  end

  defp aa_derive_from(dst, [parent | parents], state0) do
    aa_derive_from(dst, parents,
                     aa_derive_from(dst, parent, state0))
  end

  defp aa_derive_from(_Dst, [], state0) do
    state0
  end

  defp aa_derive_from(r_b_var(), r_b_literal(), state) do
    state
  end

  defp aa_derive_from(r_b_var() = dst, r_b_var() = parent, state) do
    case (state) do
      %{^dst => r_vas(status: :aliased)} ->
        state
      %{^parent => r_vas(status: :aliased)} ->
        aa_set_aliased(dst, state)
      %{^parent => r_vas(child: child)} when child !== :none ->
        aa_set_aliased([dst, parent], state)
      %{^parent => r_vas(child: :none, tuple_elems: elems)}
          when elems !== [] ->
        aa_set_aliased([dst, parent], state)
      %{^parent => r_vas(child: :none, pair_elems: elems)}
          when elems !== :none ->
        aa_set_aliased([dst, parent], state)
      %{^dst => r_vas(parents: parents) = childVas0,
          parent => r_vas(child: :none) = parentVas0} ->
        childVas = r_vas(childVas0, parents: :ordsets.add_element(parent,
                                                                parents), 
                                  status: :as_parent)
        parentVas = r_vas(parentVas0, child: dst)
        Map.merge(state, %{dst => childVas,
                             parent => parentVas})
    end
  end

  defp aa_update_annotations(funs,
            r_aas(alias_map: aliasMap0, st_map: stMap0) = aAS) do
    foldl(fn f, {stMapAcc, aliasMapAcc} ->
               %{^f => lbl2SS0} = aliasMapAcc
               %{^f => optSt0} = stMapAcc
               {optSt, lbl2SS} = aa_update_fun_annotation(optSt0,
                                                            lbl2SS0,
                                                            r_aas(aAS, caller: f))
               {Map.put(stMapAcc, f, optSt),
                  Map.put(aliasMapAcc, f, lbl2SS)}
          end,
            {stMap0, aliasMap0}, funs)
  end

  defp aa_update_fun_annotation(r_opt_st(ssa: sSA0) = optSt0, lbl2SS0, aAS) do
    {sSA,
       lbl2SS} = aa_update_annotation_blocks(reverse(sSA0), [],
                                               lbl2SS0, aAS)
    {r_opt_st(optSt0, ssa: sSA), lbl2SS}
  end

  defp aa_update_annotation_blocks([{lbl, block0} | blocks], acc, lbl2SS0, aAS) do
    successors = :beam_ssa.successors(block0)
    lbl2SS = foldl(fn 1, lbl2SSAcc ->
                        lbl2SSAcc
                      successor, lbl2SSAcc ->
                        %{^successor => otherSS} = lbl2SSAcc
                        aa_merge_ss_successor(lbl, otherSS, lbl2SSAcc)
                   end,
                     lbl2SS0, successors)
    %{^lbl => sS} = lbl2SS
    block = aa_update_annotation_block(block0, sS, aAS)
    aa_update_annotation_blocks(blocks,
                                  [{lbl, block} | acc], lbl2SS, aAS)
  end

  defp aa_update_annotation_blocks([], acc, lbl2SS, _AAS) do
    {acc, lbl2SS}
  end

  defp aa_update_annotation_block(r_b_blk(is: linear, last: last) = blk, sS, aAS) do
    r_b_blk(blk, is: for i <- linear do
                 aa_update_annotation(i, sS, aAS)
               end, 
             last: aa_update_annotation(last, sS, aAS))
  end

  defp aa_update_annotation(i = r_b_set(args: [tuple, idx],
                  op: :get_tuple_element),
            sS, aAS) do
    args = [{tuple,
               aa_get_element_extraction_status(tuple, sS)},
                {idx, aa_get_status(idx, sS)}]
    aa_update_annotation1(args, i, aAS)
  end

  defp aa_update_annotation(i = r_b_set(args: [idx, tuple], op: {:bif, :element}),
            sS, aAS) do
    args = [{idx, aa_get_status(idx, sS)}, {tuple,
                                              aa_get_element_extraction_status(tuple,
                                                                                 sS)}]
    aa_update_annotation1(args, i, aAS)
  end

  defp aa_update_annotation(i = r_b_set(args: [pair], op: :get_hd), sS, aAS) do
    args = [{pair,
               aa_get_element_extraction_status(pair, sS)}]
    aa_update_annotation1(args, i, aAS)
  end

  defp aa_update_annotation(i = r_b_set(args: [pair], op: :get_tl), sS, aAS) do
    args = [{pair,
               aa_get_element_extraction_status(pair, sS)}]
    aa_update_annotation1(args, i, aAS)
  end

  defp aa_update_annotation(i = r_b_set(args: [pair], op: {:bif, :hd}), sS,
            aAS) do
    args = [{pair,
               aa_get_element_extraction_status(pair, sS)}]
    aa_update_annotation1(args, i, aAS)
  end

  defp aa_update_annotation(i = r_b_set(args: [pair], op: {:bif, :tl}), sS,
            aAS) do
    args = [{pair,
               aa_get_element_extraction_status(pair, sS)}]
    aa_update_annotation1(args, i, aAS)
  end

  defp aa_update_annotation(i = r_b_set(args: args0), sS, aAS) do
    args = (for (r_b_var() = v) <- args0 do
              {v, aa_get_status(v, sS)}
            end)
    aa_update_annotation1(args, i, aAS)
  end

  defp aa_update_annotation(i = r_b_ret(arg: r_b_var() = v), sS, aAS) do
    aa_update_annotation1(aa_get_status(v, sS), i, aAS)
  end

  defp aa_update_annotation(i, _SS, _AAS) do
    i
  end

  defp aa_update_annotation1(argsStatus,
            i = r_b_set(anno: anno0, args: args, op: op), aAS) do
    {aliased, unique} = foldl(fn {r_b_var() = v, :aliased},
                                   {as, us} ->
                                   {:ordsets.add_element(v, as), us}
                                 {r_b_var() = v, :unique}, {as, us} ->
                                   {as, :ordsets.add_element(v, us)}
                                 _, s ->
                                   s
                              end,
                                {:ordsets.new(), :ordsets.new()}, argsStatus)
    anno1 = (case (aliased) do
               [] ->
                 :maps.remove(:aliased, anno0)
               _ ->
                 Map.put(anno0, :aliased, aliased)
             end)
    anno2 = (case (unique) do
               [] ->
                 :maps.remove(:unique, anno1)
               _ ->
                 Map.put(anno1, :unique, unique)
             end)
    anno = (case ({op, args}) do
              {:bs_create_bin, [r_b_literal(val: :append), _, var | _]} ->
                r_aas(caller: caller, kills: killsMap) = aAS
                r_b_set(dst: dst) = i
                killMap = :maps.get(caller, killsMap)
                dies = :sets.is_element(var,
                                          :erlang.map_get(dst, killMap))
                Map.put(anno2, :first_fragment_dies, dies)
              _ ->
                anno2
            end)
    r_b_set(i, anno: anno)
  end

  defp aa_update_annotation1(status, i = r_b_ret(arg: r_b_var() = v, anno: anno0),
            _AAS) do
    anno = (case (status) do
              :aliased ->
                :maps.remove(:unique, Map.put(anno0, :aliased, [v]))
              :unique ->
                :maps.remove(:aliased, Map.put(anno0, :unique, [v]))
            end)
    r_b_ret(i, anno: anno)
  end

  defp aa_set_aliased(args, sS) do
    aa_set_status(args, :aliased, sS)
  end

  defp aa_alias_all(sS) do
    aa_set_aliased(:maps.keys(sS), sS)
  end

  defp aa_register_extracted(extracted, aggregate, state) do
    :skip
    %{^aggregate => r_vas(extracted: exVars) = aggVas0,
        extracted => r_vas(parents: parents) = exVas0} = state
    aggVas = r_vas(aggVas0, extracted: :ordsets.add_element(extracted,
                                                          exVars))
    exVas = r_vas(exVas0, status: :as_parent, 
                        parents: :ordsets.add_element(aggregate, parents))
    Map.merge(state, %{aggregate => aggVas,
                         extracted => exVas})
  end

  defp aa_meet(r_b_var() = var, otherStatus, state) do
    status = aa_get_status(var, state)
    aa_set_status(var, aa_meet(otherStatus, status), state)
  end

  defp aa_meet(r_b_literal(), _SetStatus, state) do
    state
  end

  defp aa_meet([var | vars], [status | statuses], state) do
    aa_meet(vars, statuses, aa_meet(var, status, state))
  end

  defp aa_meet([], [], state) do
    state
  end

  defp aa_meet(statusA, statusB) do
    case ({statusA, statusB}) do
      {_, :aliased} ->
        :aliased
      {:aliased, _} ->
        :aliased
      {:unique, :unique} ->
        :unique
    end
  end

  defp aa_meet([h | t]) do
    aa_meet(h, aa_meet(t))
  end

  defp aa_meet([]) do
    :unique
  end

  defp aa_all_dies(vars, where, r_aas(caller: caller, kills: kills)) do
    killMap = :erlang.map_get(caller, kills)
    killSet = :erlang.map_get(where, killMap)
    aa_all_dies(vars, killSet)
  end

  defp aa_all_dies([r_b_literal() | vars], killSet) do
    aa_all_dies(vars, killSet)
  end

  defp aa_all_dies([r_b_var() = v | vars], killSet) do
    case (:sets.is_element(v, killSet)) do
      true ->
        aa_all_dies(vars, killSet)
      false ->
        false
    end
  end

  defp aa_all_dies([], _) do
    true
  end

  defp aa_alias_if_args_dont_die(args, where, sS, aAS) do
    case (aa_all_dies(args, where, aAS)) do
      true ->
        sS
      false ->
        aa_set_aliased([where | args], sS)
    end
  end

  defp aa_alias_inherit_and_alias_if_arg_does_not_die(dst, arg, sS0, aAS) do
    sS1 = aa_alias_if_args_dont_die([arg], dst, sS0, aAS)
    aa_set_status(dst, aa_get_status(arg, sS1), sS1)
  end

  defp aa_all_vars_unique(args, sS) do
    aa_all_vars_unique(args, %{}, sS)
  end

  defp aa_all_vars_unique([r_b_literal() | args], seen, sS) do
    aa_all_vars_unique(args, seen, sS)
  end

  defp aa_all_vars_unique([r_b_var() = v | args], seen, sS) do
    aa_get_status(v, sS) === :unique and (case (seen) do
                                            %{^v => _} ->
                                              false
                                            %{} ->
                                              aa_all_vars_unique(args,
                                                                   Map.put(seen, v,
                                                                                   true),
                                                                   sS)
                                          end)
  end

  defp aa_all_vars_unique([], _, _) do
    true
  end

  defp aa_construct_term(dst, values, sS, aAS) do
    case (aa_all_vars_unique(values,
                               sS) and aa_all_dies(values, dst, aAS)) do
      true ->
        aa_derive_from(dst, values, sS)
      false ->
        aa_set_aliased([dst | values], sS)
    end
  end

  defp aa_update_record_get_vars([r_b_literal(), value | updates]) do
    [value | aa_update_record_get_vars(updates)]
  end

  defp aa_update_record_get_vars([]) do
    []
  end

  defp aa_bif(dst, :element, [r_b_literal(val: idx), tuple], sS, _AAS)
      when (is_integer(idx) and idx > 0) do
    aa_tuple_extraction(dst, tuple, r_b_literal(val: idx - 1), sS)
  end

  defp aa_bif(dst, :element, [r_b_literal(), tuple], sS, _AAS) do
    aa_set_aliased([dst, tuple], sS)
  end

  defp aa_bif(dst, :element, [r_b_var(), tuple], sS, _AAS) do
    aa_set_aliased([dst, tuple], sS)
  end

  defp aa_bif(dst, :hd, [pair], sS, _AAS) do
    aa_pair_extraction(dst, pair, :hd, sS)
  end

  defp aa_bif(dst, :tl, [pair], sS, _AAS) do
    aa_pair_extraction(dst, pair, :tl, sS)
  end

  defp aa_bif(dst, :map_get, [_Key, map], sS, aAS) do
    aa_map_extraction(dst, map, sS, aAS)
  end

  defp aa_bif(dst, bif, args, sS, _AAS) do
    arity = length(args)
    case (:erl_internal.guard_bif(bif,
                                    arity) or :erl_internal.bool_op(bif,
                                                                      arity) or :erl_internal.comp_op(bif,
                                                                                                        arity) or :erl_internal.arith_op(bif,
                                                                                                                                           arity) or :erl_internal.new_type_test(bif,
                                                                                                                                                                                   arity)) do
      true ->
        sS
      false ->
        aa_set_aliased([dst | args], sS)
    end
  end

  defp aa_phi(dst, args0, sS) do
    args = (for {v, _} <- args0 do
              v
            end)
    aa_derive_from(dst, args, sS)
  end

  defp aa_call(dst, [r_b_local() = callee | args], anno, sS0,
            r_aas(alias_map: aliasMap, st_map: stMap) = aAS0) do
    r_b_local(name: r_b_literal(val: _N), arity: _A) = callee
    :skip
    isNif = is_nif(callee, stMap)
    case (aliasMap) do
      %{^callee => %{0 => calleeSS} = lbl2SS} when not isNif
                                                   ->
        :skip
        r_opt_st(args: calleeArgs) = :erlang.map_get(callee, stMap)
        :skip
        :skip
        :skip
        argStates = (for arg <- calleeArgs do
                       aa_get_status(arg, calleeSS)
                     end)
        :skip
        aAS = aa_add_call_info(callee, args, sS0, aAS0)
        sS = aa_meet(args, argStates, sS0)
        :skip
        :skip
        returnStatusByType = :maps.get(:returns, lbl2SS, %{})
        :skip
        returnedType = (case (anno) do
                          %{result_type: resultType} ->
                            resultType
                          %{} ->
                            :any
                        end)
        :skip
        resultStatus = aa_get_status_by_type(returnedType,
                                               returnStatusByType)
        :skip
        {aa_set_status(dst, resultStatus, sS), aAS}
      _ when isNif ->
        aa_set_aliased([dst | args], sS0)
      %{} ->
        {sS0, aAS0}
    end
  end

  defp aa_call(dst, [_Callee | args], _Anno, sS, aAS) do
    {aa_set_aliased([dst | args], sS), aAS}
  end

  defp aa_add_call_info(callee, args, sS0, r_aas(call_args: info0) = aAS) do
    argStats = (for arg <- args do
                  aa_get_status(arg, sS0)
                end)
    %{^callee => stats} = info0
    newStats = (for {a, b} <- zip(stats, argStats) do
                  aa_meet(a, b)
                end)
    info = Map.put(info0, callee, newStats)
    r_aas(aAS, call_args: info)
  end

  defp aa_get_call_args_status(args, callee, r_aas(call_args: info)) do
    %{^callee => status} = info
    zip(args, status)
  end

  defp aa_pair_extraction(dst, r_b_var() = pair, element, sS) do
    case (sS) do
      %{^pair => r_vas(status: :aliased)} ->
        aa_set_aliased(dst, sS)
      %{^pair => r_vas(pair_elems: {:both, _, _})} ->
        aa_set_aliased([dst, pair], sS)
      %{^pair => r_vas(pair_elems: :none) = vas} ->
        aa_register_extracted(dst, pair,
                                Map.put(sS, pair,
                                              r_vas(vas, pair_elems: {element,
                                                                    dst})))
      %{^pair => r_vas(pair_elems: {^element, _})} ->
        aa_set_aliased([dst, pair], sS)
      %{^pair => r_vas(pair_elems: {:tl, t}) = vas}
          when element === :hd ->
        aa_register_extracted(dst, pair,
                                Map.put(sS, pair,
                                              r_vas(vas, pair_elems: {:both, dst,
                                                                    t})))
      %{^pair => r_vas(pair_elems: {:hd, h}) = vas}
          when element === :tl ->
        aa_register_extracted(dst, pair,
                                Map.put(sS, pair,
                                              r_vas(vas, pair_elems: {:both, h,
                                                                    dst})))
    end
  end

  defp aa_pair_extraction(_Dst, r_b_literal(), _Element, sS) do
    sS
  end

  defp aa_map_extraction(dst, map, sS, aAS) do
    aa_derive_from(dst, map,
                     aa_alias_inherit_and_alias_if_arg_does_not_die(dst, map,
                                                                      sS, aAS))
  end

  defp aa_tuple_extraction(dst, r_b_var() = tuple, r_b_literal(val: i), sS) do
    case (sS) do
      %{^tuple => r_vas(status: :aliased)} ->
        aa_set_aliased(dst, sS)
      %{^tuple => r_vas(child: child)} when child !== :none ->
        aa_set_aliased([dst, tuple], sS)
      %{^tuple => r_vas(tuple_elems: []) = tupleVas} ->
        aa_register_extracted(dst, tuple,
                                Map.put(sS, tuple,
                                              r_vas(tupleVas, tuple_elems: [{i,
                                                                           dst}])))
      %{^tuple => r_vas(tuple_elems: elems0) = tupleVas} ->
        case (for {idx, _} <- elems0, i === idx do
                idx
              end) do
          [] ->
            elems = :ordsets.add_element({i, dst}, elems0)
            aa_register_extracted(dst, tuple,
                                    Map.put(sS, tuple,
                                                  r_vas(tupleVas, tuple_elems: elems)))
          _ ->
            aa_set_aliased([dst, tuple], sS)
        end
    end
  end

  defp aa_tuple_extraction(_, r_b_literal(), _, sS) do
    sS
  end

  defp aa_make_fun(dst, callee = r_b_local(name: r_b_literal()), env0, sS0,
            aAS0 = r_aas(call_args: info0, repeats: repeats0)) do
    sS = aa_set_aliased([dst | env0], sS0)
    %{^callee => status0} = info0
    status = (for _ <- status0 do
                :aliased
              end)
    %{^callee => prevStatus} = info0
    info = %{info0 | callee => status}
    repeats = (case (prevStatus !== status) do
                 true ->
                   :sets.add_element(callee, repeats0)
                 false ->
                   repeats0
               end)
    aAS = r_aas(aAS0, call_args: info,  repeats: repeats)
    {sS, aAS}
  end

  defp aa_breadth_first(funs, funcDb) do
    isExported = fn f ->
                      %{^f => r_func_info(exported: e)} = funcDb
                      e
                 end
    exported = (for f <- funs, isExported.(f) do
                  f
                end)
    aa_breadth_first(exported, [],
                       :sets.new([{:version, 2}]), funcDb)
  end

  defp aa_breadth_first([f | work], next, seen, funcDb) do
    case (:sets.is_element(f, seen)) do
      true ->
        aa_breadth_first(work, next, seen, funcDb)
      false ->
        case (funcDb) do
          %{^f => r_func_info(out: children)} ->
            [f | aa_breadth_first(work, children ++ next,
                                    :sets.add_element(f, seen), funcDb)]
          %{} ->
            aa_breadth_first(work, next, seen, funcDb)
        end
    end
  end

  defp aa_breadth_first([], [], _Seen, _FuncDb) do
    []
  end

  defp aa_breadth_first([], next, seen, funcDb) do
    aa_breadth_first(next, [], seen, funcDb)
  end

end