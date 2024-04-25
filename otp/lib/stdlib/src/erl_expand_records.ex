defmodule :m_erl_expand_records do
  use Bitwise
  import :lists, only: [duplicate: 2, foldl: 3, foldr: 3, map: 2, reverse: 1, sort: 1]
  require Record

  Record.defrecord(:r_exprec, :exprec,
    compile: [],
    vcount: 0,
    calltype: %{},
    records: %{},
    raw_records: [],
    strict_ra: [],
    checked_ra: [],
    dialyzer: false
  )

  def module(fs0, opts0) do
    opts = compiler_options(fs0) ++ opts0
    dialyzer = :lists.member(:dialyzer, opts)
    calltype = init_calltype(fs0)
    st0 = r_exprec(compile: opts, dialyzer: dialyzer, calltype: calltype)
    {fs, _St} = forms(fs0, st0)
    fs
  end

  defp compiler_options(forms) do
    :lists.flatten(
      for {:attribute, _, :compile, c} <- forms do
        c
      end
    )
  end

  defp init_calltype_imports(
         [{:attribute, _, :import, {mod, fs}} | t],
         ctype0
       ) do
    true = is_atom(mod)

    ctype =
      foldl(
        fn fA, acc ->
          Map.put(acc, fA, {:imported, mod})
        end,
        ctype0,
        fs
      )

    init_calltype_imports(t, ctype)
  end

  defp init_calltype_imports([_ | t], ctype) do
    init_calltype_imports(t, ctype)
  end

  defp init_calltype_imports([], ctype) do
    ctype
  end

  defp forms(
         [
           {:attribute, _, :record, {name, defs}} = attr
           | fs
         ],
         st0
       ) do
    nDefs = normalise_fields(defs)

    st =
      r_exprec(st0,
        records: :maps.put(name, nDefs, r_exprec(st0, :records)),
        raw_records: [attr | r_exprec(st0, :raw_records)]
      )

    {fs1, st1} = forms(fs, st)
    {[attr | fs1], st1}
  end

  defp forms([{:function, anno, n, a, cs0} | fs0], st0) do
    {cs, st1} = clauses(cs0, st0)
    {fs, st2} = forms(fs0, st1)
    {[{:function, anno, n, a, cs} | fs], st2}
  end

  defp forms([f | fs0], st0) do
    {fs, st} = forms(fs0, st0)
    {[f | fs], st}
  end

  defp forms([], st) do
    {[], st}
  end

  defp clauses([{:clause, anno, h0, g0, b0} | cs0], st0) do
    {h1, st1} = head(h0, st0)
    {g1, st2} = guard(g0, st1)
    {h, g} = optimize_is_record(h1, g1, st2)
    {b, st3} = exprs(b0, st2)
    {cs, st4} = clauses(cs0, st3)
    {[{:clause, anno, h, g, b} | cs], st4}
  end

  defp clauses([], st) do
    {[], st}
  end

  defp head(as, st) do
    pattern_list(as, st)
  end

  defp pattern({:var, _, :_} = var, st) do
    {var, st}
  end

  defp pattern({:var, _, _} = var, st) do
    {var, st}
  end

  defp pattern({:char, _, _} = char, st) do
    {char, st}
  end

  defp pattern({:integer, _, _} = int, st) do
    {int, st}
  end

  defp pattern({:float, _, _} = float, st) do
    {float, st}
  end

  defp pattern({:atom, _, _} = atom, st) do
    {atom, st}
  end

  defp pattern({:string, _, _} = string, st) do
    {string, st}
  end

  defp pattern({nil, _} = nil__, st) do
    {nil__, st}
  end

  defp pattern({:cons, anno, h, t}, st0) do
    {tH, st1} = pattern(h, st0)
    {tT, st2} = pattern(t, st1)
    {{:cons, anno, tH, tT}, st2}
  end

  defp pattern({:tuple, anno, ps}, st0) do
    {tPs, st1} = pattern_list(ps, st0)
    {{:tuple, anno, tPs}, st1}
  end

  defp pattern({:map, anno, ps}, st0) do
    {tPs, st1} = pattern_list(ps, st0)
    {{:map, anno, tPs}, st1}
  end

  defp pattern({:map_field_exact, anno, k0, v0}, st0) do
    {k, st1} = expr(k0, st0)
    {v, st2} = pattern(v0, st1)
    {{:map_field_exact, anno, k, v}, st2}
  end

  defp pattern({:record_index, anno, name, field}, st) do
    {index_expr(anno, field, name, record_fields(name, anno, st)), st}
  end

  defp pattern({:record, anno0, name, pfs}, st0) do
    fs = record_fields(name, anno0, st0)
    {tMs, st1} = pattern_list(pattern_fields(fs, pfs), st0)
    anno = mark_record(anno0, st1)
    {{:tuple, anno, [{:atom, anno0, name} | tMs]}, st1}
  end

  defp pattern({:bin, anno, es0}, st0) do
    {es1, st1} = pattern_bin(es0, st0)
    {{:bin, anno, es1}, st1}
  end

  defp pattern({:match, anno, pat1, pat2}, st0) do
    {tH, st1} = pattern(pat2, st0)
    {tT, st2} = pattern(pat1, st1)
    {{:match, anno, tT, tH}, st2}
  end

  defp pattern({:op, anno, op, a0}, st0) do
    {a, st1} = pattern(a0, st0)
    {{:op, anno, op, a}, st1}
  end

  defp pattern({:op, anno, op, l0, r0}, st0) do
    {l, st1} = pattern(l0, st0)
    {r, st2} = pattern(r0, st1)
    {{:op, anno, op, l, r}, st2}
  end

  defp pattern_list([p0 | ps0], st0) do
    {p, st1} = pattern(p0, st0)
    {ps, st2} = pattern_list(ps0, st1)
    {[p | ps], st2}
  end

  defp pattern_list([], st) do
    {[], st}
  end

  defp guard([g0 | gs0], st0) do
    {g, st1} = guard_tests(g0, st0)
    {gs, st2} = guard(gs0, st1)
    {[g | gs], st2}
  end

  defp guard([], st) do
    {[], st}
  end

  defp guard_tests(gts0, st0) do
    {gts1, st1} = guard_tests1(gts0, st0)
    {gts1, r_exprec(st1, checked_ra: [])}
  end

  defp guard_tests1([gt0 | gts0], st0) do
    {gt1, st1} = guard_test(gt0, st0)
    {gts1, st2} = guard_tests1(gts0, st1)
    {[gt1 | gts1], st2}
  end

  defp guard_tests1([], st) do
    {[], st}
  end

  defp guard_test(g0, st0) do
    in_guard(fn ->
      {g1, st1} = guard_test1(g0, st0)
      strict_record_access(g1, st1)
    end)
  end

  defp guard_test1({:call, anno, {:atom, tanno, tname}, as}, st) do
    test = {:atom, tanno, normalise_test(tname, length(as))}
    expr({:call, anno, test, as}, st)
  end

  defp guard_test1(test, st) do
    expr(test, st)
  end

  defp normalise_test(:atom, 1) do
    :is_atom
  end

  defp normalise_test(:binary, 1) do
    :is_binary
  end

  defp normalise_test(:float, 1) do
    :is_float
  end

  defp normalise_test(:function, 1) do
    :is_function
  end

  defp normalise_test(:integer, 1) do
    :is_integer
  end

  defp normalise_test(:list, 1) do
    :is_list
  end

  defp normalise_test(:number, 1) do
    :is_number
  end

  defp normalise_test(:pid, 1) do
    :is_pid
  end

  defp normalise_test(:port, 1) do
    :is_port
  end

  defp normalise_test(:record, 2) do
    :is_record
  end

  defp normalise_test(:reference, 1) do
    :is_reference
  end

  defp normalise_test(:tuple, 1) do
    :is_tuple
  end

  defp normalise_test(name, _) do
    name
  end

  defp is_in_guard() do
    :erlang.get(:erl_expand_records_in_guard) !== :undefined
  end

  defp in_guard(f) do
    :undefined =
      :erlang.put(
        :erl_expand_records_in_guard,
        true
      )

    res = f.()
    true = :erlang.erase(:erl_expand_records_in_guard)
    res
  end

  defp record_test(anno, term, name, st) do
    case is_in_guard() do
      false ->
        record_test_in_body(anno, term, name, st)

      true ->
        record_test_in_guard(anno, term, name, st)
    end
  end

  defp record_test_in_guard(anno, term, name, st) do
    case not_a_tuple(term) do
      true ->
        expr({:atom, anno, false}, st)

      false ->
        fs = record_fields(name, anno, st)
        nAnno = no_compiler_warning(anno)

        expr(
          {:call, nAnno, {:remote, nAnno, {:atom, nAnno, :erlang}, {:atom, nAnno, :is_record}},
           [term, {:atom, anno, name}, {:integer, anno, length(fs) + 1}]},
          st
        )
    end
  end

  defp not_a_tuple({:atom, _, _}) do
    true
  end

  defp not_a_tuple({:integer, _, _}) do
    true
  end

  defp not_a_tuple({:float, _, _}) do
    true
  end

  defp not_a_tuple({nil, _}) do
    true
  end

  defp not_a_tuple({:cons, _, _, _}) do
    true
  end

  defp not_a_tuple({:char, _, _}) do
    true
  end

  defp not_a_tuple({:string, _, _}) do
    true
  end

  defp not_a_tuple({:record_index, _, _, _}) do
    true
  end

  defp not_a_tuple({:bin, _, _}) do
    true
  end

  defp not_a_tuple({:op, _, _, _}) do
    true
  end

  defp not_a_tuple({:op, _, _, _, _}) do
    true
  end

  defp not_a_tuple(_) do
    false
  end

  defp record_test_in_body(anno, expr, name, st0) do
    fs = record_fields(name, anno, st0)
    {var, st} = new_var(anno, st0)
    nAnno = no_compiler_warning(anno)

    expr(
      {:block, anno,
       [
         {:match, anno, var, expr},
         {:call, nAnno, {:remote, nAnno, {:atom, nAnno, :erlang}, {:atom, nAnno, :is_record}},
          [var, {:atom, anno, name}, {:integer, anno, length(fs) + 1}]}
       ]},
      st
    )
  end

  defp exprs([e0 | es0], st0) do
    {e, st1} = expr(e0, st0)
    {es, st2} = exprs(es0, st1)
    {[e | es], st2}
  end

  defp exprs([], st) do
    {[], st}
  end

  defp expr({:var, _, _} = var, st) do
    {var, st}
  end

  defp expr({:char, _, _} = char, st) do
    {char, st}
  end

  defp expr({:integer, _, _} = int, st) do
    {int, st}
  end

  defp expr({:float, _, _} = float, st) do
    {float, st}
  end

  defp expr({:atom, _, _} = atom, st) do
    {atom, st}
  end

  defp expr({:string, _, _} = string, st) do
    {string, st}
  end

  defp expr({nil, _} = nil__, st) do
    {nil__, st}
  end

  defp expr({:cons, anno, h0, t0}, st0) do
    {h, st1} = expr(h0, st0)
    {t, st2} = expr(t0, st1)
    {{:cons, anno, h, t}, st2}
  end

  defp expr({:lc, anno, e0, qs0}, st0) do
    {qs1, st1} = lc_tq(anno, qs0, st0)
    {e1, st2} = expr(e0, st1)
    {{:lc, anno, e1, qs1}, st2}
  end

  defp expr({:bc, anno, e0, qs0}, st0) do
    {qs1, st1} = lc_tq(anno, qs0, st0)
    {e1, st2} = expr(e0, st1)
    {{:bc, anno, e1, qs1}, st2}
  end

  defp expr({:mc, anno, e0, qs0}, st0) do
    {qs1, st1} = lc_tq(anno, qs0, st0)
    {e1, st2} = expr(e0, st1)
    {{:mc, anno, e1, qs1}, st2}
  end

  defp expr({:tuple, anno, es0}, st0) do
    {es1, st1} = expr_list(es0, st0)
    {{:tuple, anno, es1}, st1}
  end

  defp expr({:map, anno, es0}, st0) do
    {es1, st1} = expr_list(es0, st0)
    {{:map, anno, es1}, st1}
  end

  defp expr({:map, anno, arg0, es0}, st0) do
    {arg1, st1} = expr(arg0, st0)
    {es1, st2} = expr_list(es0, st1)
    {{:map, anno, arg1, es1}, st2}
  end

  defp expr({:map_field_assoc, anno, k0, v0}, st0) do
    {k, st1} = expr(k0, st0)
    {v, st2} = expr(v0, st1)
    {{:map_field_assoc, anno, k, v}, st2}
  end

  defp expr({:map_field_exact, anno, k0, v0}, st0) do
    {k, st1} = expr(k0, st0)
    {v, st2} = expr(v0, st1)
    {{:map_field_exact, anno, k, v}, st2}
  end

  defp expr({:record_index, anno, name, f}, st) do
    i = index_expr(anno, f, name, record_fields(name, anno, st))
    expr(i, st)
  end

  defp expr({:record, anno0, name, is}, st) do
    anno = mark_record(anno0, st)

    expr(
      {:tuple, anno,
       [
         {:atom, anno0, name}
         | record_inits(
             record_fields(name, anno0, st),
             is
           )
       ]},
      st
    )
  end

  defp expr({:record_field, _A, r, name, f}, st) do
    anno = :erl_parse.first_anno(r)
    get_record_field(anno, r, f, name, st)
  end

  defp expr({:record, anno, r, name, us}, st0) do
    {ue, st1} = record_update(r, name, record_fields(name, anno, st0), us, st0)
    expr(ue, st1)
  end

  defp expr({:bin, anno, es0}, st0) do
    {es1, st1} = expr_bin(es0, st0)
    {{:bin, anno, es1}, st1}
  end

  defp expr({:block, anno, es0}, st0) do
    {es, st1} = exprs(es0, st0)
    {{:block, anno, es}, st1}
  end

  defp expr({:if, anno, cs0}, st0) do
    {cs, st1} = clauses(cs0, st0)
    {{:if, anno, cs}, st1}
  end

  defp expr({:case, anno, e0, cs0}, st0) do
    {e, st1} = expr(e0, st0)
    {cs, st2} = clauses(cs0, st1)
    {{:case, anno, e, cs}, st2}
  end

  defp expr({:receive, anno, cs0}, st0) do
    {cs, st1} = clauses(cs0, st0)
    {{:receive, anno, cs}, st1}
  end

  defp expr({:receive, anno, cs0, to0, toEs0}, st0) do
    {to, st1} = expr(to0, st0)
    {toEs, st2} = exprs(toEs0, st1)
    {cs, st3} = clauses(cs0, st2)
    {{:receive, anno, cs, to, toEs}, st3}
  end

  defp expr({:fun, anno, {:function, f, a}} = fun0, st0) do
    case :erl_internal.bif(f, a) do
      true ->
        {as, st1} = new_vars(a, anno, st0)
        cs = [{:clause, anno, as, [], [{:call, anno, {:atom, anno, f}, as}]}]
        fun = {:fun, anno, {:clauses, cs}}
        expr(fun, st1)

      false ->
        {fun0, st0}
    end
  end

  defp expr({:fun, _, {:function, _M, _F, _A}} = fun, st) do
    {fun, st}
  end

  defp expr({:fun, anno, {:clauses, cs0}}, st0) do
    {cs, st1} = clauses(cs0, st0)
    {{:fun, anno, {:clauses, cs}}, st1}
  end

  defp expr({:named_fun, anno, name, cs0}, st0) do
    {cs, st1} = clauses(cs0, st0)
    {{:named_fun, anno, name, cs}, st1}
  end

  defp expr(
         {:call, anno, {:atom, _, :is_record}, [a, {:atom, _, name}]},
         st
       ) do
    record_test(anno, a, name, st)
  end

  defp expr(
         {:call, anno, {:remote, _, {:atom, _, :erlang}, {:atom, _, :is_record}},
          [a, {:atom, _, name}]},
         st
       ) do
    record_test(anno, a, name, st)
  end

  defp expr(
         {:call, anno, {:tuple, _, [{:atom, _, :erlang}, {:atom, _, :is_record}]},
          [a, {:atom, _, name}]},
         st
       ) do
    record_test(anno, a, name, st)
  end

  defp expr(
         {:call, anno, {:atom, _, :is_record}, [_, _, {:integer, _, sz}]},
         st
       )
       when is_integer(sz) and sz <= 0 do
    {{:atom, anno, false}, st}
  end

  defp expr(
         {:call, anno, {:remote, _, {:atom, _, :erlang}, {:atom, _, :is_record}},
          [_, _, {:integer, _, sz}]},
         st
       )
       when is_integer(sz) and sz <= 0 do
    {{:atom, anno, false}, st}
  end

  defp expr(
         {:call, anno, {:atom, _AnnoA, :record_info}, [_, _] = as0},
         st0
       ) do
    {as, st1} = expr_list(as0, st0)
    record_info_call(anno, as, st1)
  end

  defp expr(
         {:call, anno, {:atom, _AnnoA, n} = atom, as0},
         st0
       ) do
    {as, st1} = expr_list(as0, st0)
    ar = length(as)
    nA = {n, ar}

    case r_exprec(st0, :calltype) do
      %{^nA => :local} ->
        {{:call, anno, atom, as}, st1}

      %{^nA => {:imported, module}} ->
        modAtom = {:atom, anno, module}
        {{:call, anno, {:remote, anno, modAtom, atom}, as}, st1}

      _ ->
        case :erl_internal.bif(n, ar) do
          true ->
            modAtom = {:atom, anno, :erlang}
            {{:call, anno, {:remote, anno, modAtom, atom}, as}, st1}

          false ->
            {{:call, anno, atom, as}, st1}
        end
    end
  end

  defp expr(
         {:call, anno, {:remote, annoR, m, f}, as0},
         st0
       ) do
    {[m1, f1 | as1], st1} = expr_list([m, f | as0], st0)
    {{:call, anno, {:remote, annoR, m1, f1}, as1}, st1}
  end

  defp expr({:call, anno, f, as0}, st0) do
    {[fun1 | as1], st1} = expr_list([f | as0], st0)
    {{:call, anno, fun1, as1}, st1}
  end

  defp expr({:try, anno, es0, scs0, ccs0, as0}, st0) do
    {es1, st1} = exprs(es0, st0)
    {scs1, st2} = clauses(scs0, st1)
    {ccs1, st3} = clauses(ccs0, st2)
    {as1, st4} = exprs(as0, st3)
    {{:try, anno, es1, scs1, ccs1, as1}, st4}
  end

  defp expr({:catch, anno, e0}, st0) do
    {e, st1} = expr(e0, st0)
    {{:catch, anno, e}, st1}
  end

  defp expr({:maybe, maybeAnno, es0}, st0) do
    {es, st1} = exprs(es0, st0)
    {{:maybe, maybeAnno, es}, st1}
  end

  defp expr(
         {:maybe, maybeAnno, es0, {:else, elseAnno, cs0}},
         st0
       ) do
    {es, st1} = exprs(es0, st0)
    {cs, st2} = clauses(cs0, st1)
    {{:maybe, maybeAnno, es, {:else, elseAnno, cs}}, st2}
  end

  defp expr({:maybe_match, anno, p0, e0}, st0) do
    {e, st1} = expr(e0, st0)
    {p, st2} = pattern(p0, st1)
    {{:maybe_match, anno, p, e}, st2}
  end

  defp expr({:match, anno, p0, e0}, st0) do
    {e, st1} = expr(e0, st0)
    {p, st2} = pattern(p0, st1)
    {{:match, anno, p, e}, st2}
  end

  defp expr({:op, anno, :not, a0}, st0) do
    {a, st1} = bool_operand(a0, st0)
    {{:op, anno, :not, a}, st1}
  end

  defp expr({:op, anno, op, a0}, st0) do
    {a, st1} = expr(a0, st0)
    {{:op, anno, op, a}, st1}
  end

  defp expr({:op, anno, op, l0, r0}, st0)
       when op === :and or op === :or do
    {l, st1} = bool_operand(l0, st0)
    {r, st2} = bool_operand(r0, st1)
    {{:op, anno, op, l, r}, st2}
  end

  defp expr({:op, anno, op, l0, r0}, st0)
       when op === :andalso or op === :orelse do
    {l, st1} = bool_operand(l0, st0)
    {r, st2} = bool_operand(r0, st1)
    {{:op, anno, op, l, r}, r_exprec(st2, checked_ra: r_exprec(st1, :checked_ra))}
  end

  defp expr({:op, anno, op, l0, r0}, st0) do
    {l, st1} = expr(l0, st0)
    {r, st2} = expr(r0, st1)
    {{:op, anno, op, l, r}, st2}
  end

  defp expr(e = {:ssa_check_when, _, _, _, _, _}, st) do
    {e, st}
  end

  defp expr_list([e0 | es0], st0) do
    {e, st1} = expr(e0, st0)
    {es, st2} = expr_list(es0, st1)
    {[e | es], st2}
  end

  defp expr_list([], st) do
    {[], st}
  end

  defp bool_operand(e0, st0) do
    {e1, st1} = expr(e0, st0)
    strict_record_access(e1, st1)
  end

  defp strict_record_access(e, r_exprec(strict_ra: []) = st) do
    {e, st}
  end

  defp strict_record_access(e0, st0) do
    r_exprec(strict_ra: strictRA, checked_ra: checkedRA) = st0

    {new, nC} =
      :lists.foldl(
        fn {key, _Anno, _R, _Sz} = a, {l, c} ->
          case :lists.keymember(key, 1, c) do
            true ->
              {l, c}

            false ->
              {[a | l], [a | c]}
          end
        end,
        {[], checkedRA},
        strictRA
      )

    e1 =
      cond do
        new === [] ->
          e0

        true ->
          conj(new, e0)
      end

    st1 = r_exprec(st0, strict_ra: [], checked_ra: nC)
    expr(e1, st1)
  end

  defp conj([], _E) do
    :empty
  end

  defp conj([{{name, _Rp}, anno, r, sz} | aL], e) do
    nAnno = no_compiler_warning(anno)

    t1 =
      {:op, nAnno, :orelse,
       {:call, nAnno, {:remote, nAnno, {:atom, nAnno, :erlang}, {:atom, nAnno, :is_record}},
        [r, {:atom, nAnno, name}, {:integer, nAnno, sz}]}, {:atom, nAnno, :fail}}

    t2 =
      case conj(aL, :none) do
        :empty ->
          t1

        c ->
          {:op, nAnno, :and, c, t1}
      end

    case e do
      :none ->
        case t2 do
          {:op, _, :and, _, _} ->
            t2

          _ ->
            {:op, nAnno, :and, t2, {:atom, nAnno, true}}
        end

      _ ->
        {:op, nAnno, :and, t2, e}
    end
  end

  defp lc_tq(anno, [{:generate, annoG, p0, g0} | qs0], st0) do
    {g1, st1} = expr(g0, st0)
    {p1, st2} = pattern(p0, st1)
    {qs1, st3} = lc_tq(anno, qs0, st2)
    {[{:generate, annoG, p1, g1} | qs1], st3}
  end

  defp lc_tq(anno, [{:b_generate, annoG, p0, g0} | qs0], st0) do
    {g1, st1} = expr(g0, st0)
    {p1, st2} = pattern(p0, st1)
    {qs1, st3} = lc_tq(anno, qs0, st2)
    {[{:b_generate, annoG, p1, g1} | qs1], st3}
  end

  defp lc_tq(anno, [{:m_generate, annoG, p0, g0} | qs0], st0) do
    {g1, st1} = expr(g0, st0)
    {:map_field_exact, annoMFE, keyP0, valP0} = p0
    {keyP1, st2} = pattern(keyP0, st1)
    {valP1, st3} = pattern(valP0, st2)
    {qs1, st4} = lc_tq(anno, qs0, st3)
    p1 = {:map_field_exact, annoMFE, keyP1, valP1}
    {[{:m_generate, annoG, p1, g1} | qs1], st4}
  end

  defp lc_tq(anno, [f0 | qs0], r_exprec(calltype: calltype, raw_records: records) = st0) do
    isOverriden = fn fA ->
      case calltype do
        %{^fA => :local} ->
          true

        %{^fA => {:imported, _}} ->
          true

        _ ->
          false
      end
    end

    case :erl_lint.is_guard_test(f0, records, isOverriden) do
      true ->
        {f1, st1} = guard_test(f0, st0)
        {qs1, st2} = lc_tq(anno, qs0, st1)
        {[f1 | qs1], st2}

      false ->
        {f1, st1} = expr(f0, st0)
        {qs1, st2} = lc_tq(anno, qs0, st1)
        {[f1 | qs1], st2}
    end
  end

  defp lc_tq(_Anno, [], st0) do
    {[], r_exprec(st0, checked_ra: [])}
  end

  defp normalise_fields(fs) do
    map(
      fn
        {:record_field, anno, field} ->
          {:record_field, anno, field, {:atom, anno, :undefined}}

        {:typed_record_field, {:record_field, anno, field}, _Type} ->
          {:record_field, anno, field, {:atom, anno, :undefined}}

        {:typed_record_field, field, _Type} ->
          field

        f ->
          f
      end,
      fs
    )
  end

  defp record_fields(r, anno, st) do
    fields = :maps.get(r, r_exprec(st, :records))

    for {:record_field, _Anno, {:atom, _AnnoA, f}, di} <- fields do
      {:record_field, anno, {:atom, anno, f}, copy_expr(di, anno)}
    end
  end

  defp find_field(
         f,
         [{:record_field, _, {:atom, _, f}, val} | _]
       ) do
    {:ok, val}
  end

  defp find_field(f, [_ | fs]) do
    find_field(f, fs)
  end

  defp find_field(_, []) do
    :error
  end

  defp copy_expr(expr, anno) do
    :erl_parse.map_anno(
      fn _A ->
        anno
      end,
      expr
    )
  end

  defp field_names(fs) do
    map(
      fn {:record_field, _, field, _Val} ->
        field
      end,
      fs
    )
  end

  defp index_expr(anno, {:atom, _, f}, _Name, fs) do
    {:integer, anno, index_expr(f, fs, 2)}
  end

  defp index_expr(f, [{:record_field, _, {:atom, _, f}, _} | _], i) do
    i
  end

  defp index_expr(f, [_ | fs], i) do
    index_expr(f, fs, i + 1)
  end

  defp get_record_field(anno, r, index, name, st) do
    case strict_record_tests(r_exprec(st, :compile)) do
      false ->
        sloppy_get_record_field(anno, r, index, name, st)

      true ->
        strict_get_record_field(anno, r, index, name, st)
    end
  end

  defp strict_get_record_field(anno, r, {:atom, _, f} = index, name, st0) do
    case is_in_guard() do
      false ->
        {var, st} = new_var(anno, st0)
        fs = record_fields(name, anno, st)
        i = index_expr(f, fs, 2)
        p = record_pattern(2, i, var, length(fs) + 1, anno, [{:atom, anno, name}])
        nAnno = no_compiler_warning(anno)
        rAnno = mark_record(nAnno, st)

        e =
          {:case, anno, r,
           [
             {:clause, nAnno, [{:tuple, rAnno, p}], [], [var]},
             {:clause, nAnno, [var], [],
              [
                {:call, nAnno, {:remote, nAnno, {:atom, nAnno, :erlang}, {:atom, nAnno, :error}},
                 [{:tuple, nAnno, [{:atom, nAnno, :badrecord}, var]}]}
              ]}
           ]}

        expr(e, st)

      true ->
        fs = record_fields(name, anno, st0)
        i = index_expr(anno, index, name, fs)
        {expR, st1} = expr(r, st0)
        a0 = :erl_anno.new(0)

        expRp =
          :erl_parse.map_anno(
            fn _A ->
              a0
            end,
            expR
          )

        rA = {{name, expRp}, anno, expR, length(fs) + 1}
        st2 = r_exprec(st1, strict_ra: [rA | r_exprec(st1, :strict_ra)])

        {{:call, anno, {:remote, anno, {:atom, anno, :erlang}, {:atom, anno, :element}},
          [i, expR]}, st2}
    end
  end

  defp record_pattern(i, i, var, sz, anno, acc) do
    record_pattern(i + 1, i, var, sz, anno, [var | acc])
  end

  defp record_pattern(cur, i, var, sz, anno, acc) when cur <= sz do
    record_pattern(cur + 1, i, var, sz, anno, [{:var, anno, :_} | acc])
  end

  defp record_pattern(_, _, _, _, _, acc) do
    reverse(acc)
  end

  defp sloppy_get_record_field(anno, r, index, name, st) do
    fs = record_fields(name, anno, st)
    i = index_expr(anno, index, name, fs)

    expr(
      {:call, anno, {:remote, anno, {:atom, anno, :erlang}, {:atom, anno, :element}}, [i, r]},
      st
    )
  end

  defp strict_record_tests([:strict_record_tests | _]) do
    true
  end

  defp strict_record_tests([:no_strict_record_tests | _]) do
    false
  end

  defp strict_record_tests([_ | os]) do
    strict_record_tests(os)
  end

  defp strict_record_tests([]) do
    true
  end

  defp strict_record_updates([:strict_record_updates | _]) do
    true
  end

  defp strict_record_updates([:no_strict_record_updates | _]) do
    false
  end

  defp strict_record_updates([_ | os]) do
    strict_record_updates(os)
  end

  defp strict_record_updates([]) do
    false
  end

  defp pattern_fields(fs, ms) do
    wildcard = record_wildcard_init(ms)

    map(
      fn {:record_field, anno, {:atom, _, f}, _} ->
        case find_field(f, ms) do
          {:ok, match} ->
            match

          :error when wildcard === :none ->
            {:var, anno, :_}

          :error ->
            wildcard
        end
      end,
      fs
    )
  end

  defp record_inits(fs, is) do
    wildcardInit = record_wildcard_init(is)

    map(
      fn {:record_field, _, {:atom, _, f}, d} ->
        case find_field(f, is) do
          {:ok, init} ->
            init

          :error when wildcardInit === :none ->
            d

          :error ->
            wildcardInit
        end
      end,
      fs
    )
  end

  defp record_wildcard_init([{:record_field, _, {:var, _, :_}, d} | _]) do
    d
  end

  defp record_wildcard_init([_ | is]) do
    record_wildcard_init(is)
  end

  defp record_wildcard_init([]) do
    :none
  end

  defp record_update(r, name, fs, us0, st0) do
    anno = :erlang.element(2, r)
    {pre, us, st1} = record_exprs(us0, st0)
    {var, st2} = new_var(anno, st1)
    strictUpdates = strict_record_updates(r_exprec(st2, :compile))

    {update, st} =
      cond do
        not strictUpdates and us !== [] ->
          {record_setel(var, name, fs, us), st2}

        true ->
          record_match(var, name, anno, fs, us, st2)
      end

    {{:block, anno, pre ++ [{:match, anno, var, r}, update]}, st}
  end

  defp record_match(r, name, annoR, fs, us, st0) do
    {ps, news, st1} = record_upd_fs(fs, us, st0)
    nAnnoR = no_compiler_warning(annoR)
    rAnno = mark_record(annoR, st1)

    {{:case, annoR, r,
      [
        {:clause, annoR, [{:tuple, rAnno, [{:atom, annoR, name} | ps]}], [],
         [{:tuple, rAnno, [{:atom, annoR, name} | news]}]},
        {:clause, nAnnoR, [{:var, nAnnoR, :_}], [],
         [
           call_error(
             nAnnoR,
             {:tuple, nAnnoR, [{:atom, nAnnoR, :badrecord}, r]}
           )
         ]}
      ]}, st1}
  end

  defp record_upd_fs(
         [
           {:record_field, anno, {:atom, _AnnoA, f}, _Val}
           | fs
         ],
         us,
         st0
       ) do
    {p, st1} = new_var(anno, st0)
    {ps, news, st2} = record_upd_fs(fs, us, st1)

    case find_field(f, us) do
      {:ok, new} ->
        {[p | ps], [new | news], st2}

      :error ->
        {[p | ps], [p | news], st2}
    end
  end

  defp record_upd_fs([], _, st) do
    {[], [], st}
  end

  defp record_setel(r, name, fs, us0) do
    us1 =
      foldl(
        fn {:record_field, anno, field, val}, acc ->
          {:integer, _, fieldIndex} = i = index_expr(anno, field, name, fs)
          [{fieldIndex, {i, anno, val}} | acc]
        end,
        [],
        us0
      )

    us2 = sort(us1)

    us =
      for {_, t} <- us2 do
        t
      end

    annoR = :erlang.element(2, hd(us))
    wildcards = duplicate(length(fs), {:var, annoR, :_})
    nAnnoR = no_compiler_warning(annoR)

    {:case, annoR, r,
     [
       {:clause, annoR, [{:tuple, annoR, [{:atom, annoR, name} | wildcards]}], [],
        [
          foldr(
            fn {i, anno, val}, acc ->
              {:call, anno, {:remote, anno, {:atom, anno, :erlang}, {:atom, anno, :setelement}},
               [i, acc, val]}
            end,
            r,
            us
          )
        ]},
       {:clause, nAnnoR, [{:var, nAnnoR, :_}], [],
        [
          call_error(
            nAnnoR,
            {:tuple, nAnnoR, [{:atom, nAnnoR, :badrecord}, r]}
          )
        ]}
     ]}
  end

  defp record_info_call(anno, [{:atom, _AnnoI, info}, {:atom, _AnnoN, name}], st) do
    case info do
      :size ->
        {{:integer, anno, 1 + length(record_fields(name, anno, st))}, st}

      :fields ->
        {make_list(
           field_names(record_fields(name, anno, st)),
           anno
         ), st}
    end
  end

  defp record_exprs(us, st) do
    record_exprs(us, st, [], [])
  end

  defp record_exprs(
         [
           {:record_field, anno, {:atom, _AnnoA, _F} = name, val} = field0
           | us
         ],
         st0,
         pre,
         fs
       ) do
    case is_simple_val(val) do
      true ->
        record_exprs(us, st0, pre, [field0 | fs])

      false ->
        {var, st} = new_var(anno, st0)
        bind = {:match, anno, var, val}
        field = {:record_field, anno, name, var}
        record_exprs(us, st, [bind | pre], [field | fs])
    end
  end

  defp record_exprs([], st, pre, fs) do
    {reverse(pre), fs, st}
  end

  defp is_simple_val({:var, _, _}) do
    true
  end

  defp is_simple_val(val) do
    try do
      :erl_parse.normalise(val)
      true
    catch
      :error, _ ->
        false
    end
  end

  defp pattern_bin(es0, st) do
    foldr(
      fn e, acc ->
        pattern_element(e, acc)
      end,
      {[], st},
      es0
    )
  end

  defp pattern_element(
         {:bin_element, anno, expr0, size0, type},
         {es, st0}
       ) do
    {expr, st1} = pattern(expr0, st0)

    {size, st2} =
      case size0 do
        :default ->
          {size0, st1}

        _ ->
          expr(size0, st1)
      end

    {[{:bin_element, anno, expr, size, type} | es], st2}
  end

  defp expr_bin(es0, st) do
    foldr(
      fn e, acc ->
        bin_element(e, acc)
      end,
      {[], st},
      es0
    )
  end

  defp bin_element(
         {:bin_element, anno, expr, size, type},
         {es, st0}
       ) do
    {expr1, st1} = expr(expr, st0)

    {size1, st2} =
      cond do
        size === :default ->
          {:default, st1}

        true ->
          expr(size, st1)
      end

    {[{:bin_element, anno, expr1, size1, type} | es], st2}
  end

  defp new_vars(n, anno, st) do
    new_vars(n, anno, st, [])
  end

  defp new_vars(n, anno, st0, vs) when n > 0 do
    {v, st1} = new_var(anno, st0)
    new_vars(n - 1, anno, st1, [v | vs])
  end

  defp new_vars(0, _Anno, st, vs) do
    {vs, st}
  end

  defp new_var(anno, st0) do
    {new, st1} = new_var_name(st0)
    {{:var, anno, new}, st1}
  end

  defp new_var_name(st) do
    c = r_exprec(st, :vcount)
    {:erlang.list_to_atom(~c"rec" ++ :erlang.integer_to_list(c)), r_exprec(st, vcount: c + 1)}
  end

  defp make_list(ts, anno) do
    foldr(
      fn h, t ->
        {:cons, anno, h, t}
      end,
      {nil, anno},
      ts
    )
  end

  defp call_error(anno, r) do
    {:call, anno, {:remote, anno, {:atom, anno, :erlang}, {:atom, anno, :error}}, [r]}
  end

  defp optimize_is_record(h0, g0, r_exprec(dialyzer: dialyzer)) do
    case opt_rec_vars(g0) do
      [] ->
        {h0, g0}

      rs0 ->
        case dialyzer do
          true ->
            {h0, g0}

          false ->
            {h, rs} = opt_pattern_list(h0, rs0)
            g = opt_remove(g0, rs)
            {h, g}
        end
    end
  end

  defp opt_rec_vars([g | gs]) do
    rs = opt_rec_vars_1(g, :orddict.new())
    opt_rec_vars(gs, rs)
  end

  defp opt_rec_vars([]) do
    :orddict.new()
  end

  defp opt_rec_vars([g | gs], rs0) do
    rs1 = opt_rec_vars_1(g, :orddict.new())
    rs = :ordsets.intersection(rs0, rs1)
    opt_rec_vars(gs, rs)
  end

  defp opt_rec_vars([], rs) do
    rs
  end

  defp opt_rec_vars_1([t | ts], rs0) do
    rs = opt_rec_vars_2(t, rs0)
    opt_rec_vars_1(ts, rs)
  end

  defp opt_rec_vars_1([], rs) do
    rs
  end

  defp opt_rec_vars_2({:op, _, :and, a1, a2}, rs) do
    opt_rec_vars_1([a1, a2], rs)
  end

  defp opt_rec_vars_2({:op, _, :andalso, a1, a2}, rs) do
    opt_rec_vars_1([a1, a2], rs)
  end

  defp opt_rec_vars_2(
         {:op, _, :orelse, arg, {:atom, _, :fail}},
         rs
       ) do
    opt_rec_vars_2(arg, rs)
  end

  defp opt_rec_vars_2(
         {:call, anno, {:remote, _, {:atom, _, :erlang}, {:atom, _, :is_record} = isRecord},
          args},
         rs
       ) do
    opt_rec_vars_2({:call, anno, isRecord, args}, rs)
  end

  defp opt_rec_vars_2(
         {:call, _, {:atom, _, :is_record}, [{:var, _, v}, {:atom, _, tag}, {:integer, _, sz}]},
         rs
       )
       when is_integer(sz) and 0 < sz and sz < 100 do
    :orddict.store(v, {tag, sz}, rs)
  end

  defp opt_rec_vars_2(_, rs) do
    rs
  end

  defp opt_pattern_list(ps, rs) do
    opt_pattern_list(ps, rs, [])
  end

  defp opt_pattern_list([p0 | ps], rs0, acc) do
    {p, rs} = opt_pattern(p0, rs0)
    opt_pattern_list(ps, rs, [p | acc])
  end

  defp opt_pattern_list([], rs, acc) do
    {reverse(acc), rs}
  end

  defp opt_pattern({:var, _, v} = var, rs0) do
    case :orddict.find(v, rs0) do
      {:ok, {tag, sz}} ->
        rs = :orddict.store(v, {:remove, tag, sz}, rs0)
        {opt_var(var, tag, sz), rs}

      _ ->
        {var, rs0}
    end
  end

  defp opt_pattern({:cons, anno, h0, t0}, rs0) do
    {h, rs1} = opt_pattern(h0, rs0)
    {t, rs} = opt_pattern(t0, rs1)
    {{:cons, anno, h, t}, rs}
  end

  defp opt_pattern({:tuple, anno, es0}, rs0) do
    {es, rs} = opt_pattern_list(es0, rs0)
    {{:tuple, anno, es}, rs}
  end

  defp opt_pattern({:match, anno, pa0, pb0}, rs0) do
    {pa, rs1} = opt_pattern(pa0, rs0)
    {pb, rs} = opt_pattern(pb0, rs1)
    {{:match, anno, pa, pb}, rs}
  end

  defp opt_pattern(p, rs) do
    {p, rs}
  end

  defp opt_var({:var, anno, _} = var, tag, sz) do
    rp = record_pattern(2, -1, :ignore, sz, anno, [{:atom, anno, tag}])
    {:match, anno, {:tuple, anno, rp}, var}
  end

  defp opt_remove(gs, rs) do
    for g <- gs do
      opt_remove_1(g, rs)
    end
  end

  defp opt_remove_1(ts, rs) do
    for t <- ts do
      opt_remove_2(t, rs)
    end
  end

  defp opt_remove_2({:op, anno, :and = op, a1, a2}, rs) do
    {:op, anno, op, opt_remove_2(a1, rs), opt_remove_2(a2, rs)}
  end

  defp opt_remove_2({:op, anno, :andalso = op, a1, a2}, rs) do
    {:op, anno, op, opt_remove_2(a1, rs), opt_remove_2(a2, rs)}
  end

  defp opt_remove_2({:op, anno, :orelse, a1, a2}, rs) do
    {:op, anno, :orelse, opt_remove_2(a1, rs), a2}
  end

  defp opt_remove_2(
         {:call, anno, {:remote, _, {:atom, _, :erlang}, {:atom, _, :is_record}},
          [{:var, _, v}, {:atom, _, tag}, {:integer, _, sz}]} = a,
         rs
       ) do
    case :orddict.find(v, rs) do
      {:ok, {:remove, ^tag, ^sz}} ->
        {:atom, anno, true}

      _ ->
        a
    end
  end

  defp opt_remove_2(
         {:call, anno, {:atom, _, :is_record}, [{:var, _, v}, {:atom, _, tag}, {:integer, _, sz}]} =
           a,
         rs
       ) do
    case :orddict.find(v, rs) do
      {:ok, {:remove, ^tag, ^sz}} ->
        {:atom, anno, true}

      _ ->
        a
    end
  end

  defp opt_remove_2(a, _) do
    a
  end

  defp no_compiler_warning(anno) do
    :erl_anno.set_generated(true, anno)
  end

  defp mark_record(anno, st) do
    case r_exprec(st, :dialyzer) do
      true ->
        :erl_anno.set_record(true, anno)

      false ->
        anno
    end
  end
end
