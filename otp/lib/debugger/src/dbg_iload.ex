defmodule :m_dbg_iload do
  use Bitwise
  def load_mod(mod, file, binary, db) do
    flag = :erlang.process_flag(:trap_exit, true)
    pid = spawn_link(load_mod1(mod, file, binary, db))
    receive do
      {:EXIT, ^pid, what} ->
        :erlang.process_flag(:trap_exit, flag)
        what
    end
  end

  defp load_mod1(mod, file, binary, db) do
    fn () ->
         store_module(mod, file, binary, db)
         exit({:ok, mod})
    end
  end

  defp store_module(mod, file, binary, db) do
    {:interpreter_module, exp, abst, src,
       mD5} = :erlang.binary_to_term(binary)
    forms0 = (case (abstr(abst)) do
                {:abstract_v1, _} ->
                  exit({mod, :too_old_beam_file})
                {:abstract_v2, _} ->
                  exit({mod, :too_old_beam_file})
                {:raw_abstract_v1, code} ->
                  code
              end)
    :dbg_idb.insert(db, :mod_file, file)
    :dbg_idb.insert(db, :defs, [])
    :erlang.put(:vcount, 0)
    :erlang.put(:fun_count, 0)
    :erlang.put(:funs, [])
    :erlang.put(:mod_md5, mD5)
    forms1 = interpret_file_attribute(forms0)
    {forms, ctype} = standard_transforms(forms1)
    store_forms(forms, mod, db, %{exp: exp, ctype: ctype})
    :erlang.erase(:mod_md5)
    :erlang.erase(:current_function)
    :erlang.erase(:vcount)
    :erlang.erase(:funs)
    :erlang.erase(:fun_count)
    newBinary = store_mod_line_no(mod, db,
                                    :erlang.binary_to_list(src))
    :dbg_idb.insert(db, :mod_bin, newBinary)
    :dbg_idb.insert(db, :mod_raw,
                      <<src :: binary, 0 :: size(8)>>)
  end

  defp standard_transforms(forms0) do
    forms = :erl_internal.add_predefined_functions(forms0)
    ctype = init_calltype(forms)
    {forms, ctype}
  end

  defp init_calltype(forms) do
    locals = (for {:function, _, name, arity, _} <- forms do
                {{name, arity}, :local}
              end)
    ctype = :maps.from_list(locals)
    init_calltype_imports(forms, ctype)
  end

  defp init_calltype_imports([{:attribute, _, :import, {mod, fs}} | t],
            ctype0) do
    true = is_atom(mod)
    ctype = :lists.foldl(fn fA, acc ->
                              Map.put(acc, fA, {:imported, mod})
                         end,
                           ctype0, fs)
    init_calltype_imports(t, ctype)
  end

  defp init_calltype_imports([_ | t], ctype) do
    init_calltype_imports(t, ctype)
  end

  defp init_calltype_imports([], ctype) do
    ctype
  end

  defp interpret_file_attribute(code) do
    :epp.interpret_file_attribute(code)
  end

  defp abstr(bin) when is_binary(bin) do
    :erlang.binary_to_term(bin)
  end

  defp abstr(term) do
    term
  end

  defp store_forms([{:function, _, name, arity, cs0} | fs], mod,
            db, %{exp: exp} = st) do
    fA = {name, arity}
    :erlang.put(:current_function, fA)
    cs = clauses(cs0, st)
    exported = :lists.member(fA, exp)
    :dbg_idb.insert(db, {mod, name, arity, exported}, cs)
    store_forms(fs, mod, db, st)
  end

  defp store_forms([{:attribute, _, :record, {name, defs}} | fs],
            mod, db, st) do
    nDefs = normalise_rec_fields(defs)
    fields = (for {:record_field, _, {:atom, _, f},
                     _} <- nDefs do
                f
              end)
    :dbg_idb.insert(db,
                      {:record, mod, name, length(fields)}, fields)
    recs = :maps.get(:recs, st, %{})
    store_forms(fs, mod, db,
                  Map.put(st, :recs, Map.put(recs, name, nDefs)))
  end

  defp store_forms([{:attribute, _, _Name, _Val} | fs], mod, db,
            st) do
    store_forms(fs, mod, db, st)
  end

  defp store_forms([_ | fs], mod, db, st) do
    store_forms(fs, mod, db, st)
  end

  defp store_forms([], _, _, _) do
    :ok
  end

  defp store_mod_line_no(mod, db, contents) do
    store_mod_line_no(mod, db, contents, 1, 0, [])
  end

  defp store_mod_line_no(_, _, [], _, _, newCont) do
    :erlang.list_to_binary(:lists.reverse(newCont))
  end

  defp store_mod_line_no(mod, db, contents, lineNo, pos, newCont)
      when is_integer(lineNo) do
    {contTail, pos1, newCont1} = store_line(mod, db,
                                              contents, lineNo, pos, newCont)
    store_mod_line_no(mod, db, contTail, lineNo + 1, pos1,
                        newCont1)
  end

  defp store_line(_, db, contents, lineNo, pos, newCont) do
    {contHead, contTail, posNL} = get_nl(contents, pos + 8,
                                           [])
    :dbg_idb.insert(db, lineNo, {pos + 8, posNL})
    {contTail, posNL + 1,
       [make_lineno(lineNo, 8, contHead) | newCont]}
  end

  defp make_lineno(n, p, acc) do
    s = :erlang.integer_to_list(n)
    s ++ [?: | spaces(p - length(s) - 1, acc)]
  end

  defp spaces(p, acc) when p > 0 do
    spaces(p - 1, [?\s | acc])
  end

  defp spaces(_, acc) do
    acc
  end

  defp normalise_rec_fields(fs) do
    :lists.map(fn {:record_field, anno, field} ->
                    {:record_field, anno, field, {:atom, anno, :undefined}}
                  {:typed_record_field, {:record_field, anno, field},
                     _Type} ->
                    {:record_field, anno, field, {:atom, anno, :undefined}}
                  {:typed_record_field, field, _Type} ->
                    field
                  f ->
                    f
               end,
                 fs)
  end

  defp get_nl([10 | t], pos, head) do
    {:lists.reverse([10 | head]), t, pos}
  end

  defp get_nl([h | t], pos, head) do
    get_nl(t, pos + 1, [h | head])
  end

  defp get_nl([], pos, head) do
    {:lists.reverse(head), [], pos}
  end

  defp clauses([c0 | cs], st) do
    c1 = clause(c0, true, st)
    [c1 | clauses(cs, st)]
  end

  defp clauses([], _St) do
    []
  end

  defp clause({:clause, anno, h0, g0, b0}, lc, st) do
    h1 = head(h0, st)
    g1 = guard(g0, st)
    b1 = exprs(b0, lc, st)
    {:clause, ln(anno), h1, g1, b1}
  end

  defp head(ps, st) do
    patterns(ps, st)
  end

  defp patterns([p0 | ps], st) do
    p1 = pattern(p0, st)
    [p1 | patterns(ps, st)]
  end

  defp patterns([], _St) do
    []
  end

  defp pattern({:var, anno, v}, _St) do
    {:var, ln(anno), v}
  end

  defp pattern({:char, anno, i}, _St) do
    {:value, ln(anno), i}
  end

  defp pattern({:integer, anno, i}, _St) do
    {:value, ln(anno), i}
  end

  defp pattern({:match, anno, pat1, pat2}, st) do
    {:match, ln(anno), pattern(pat1, st), pattern(pat2, st)}
  end

  defp pattern({:float, anno, f}, _St) do
    {:value, ln(anno), f}
  end

  defp pattern({:atom, anno, a}, _St) do
    {:value, ln(anno), a}
  end

  defp pattern({:string, anno, s}, _St) do
    {:value, ln(anno), s}
  end

  defp pattern({nil, anno}, _St) do
    {:value, ln(anno), []}
  end

  defp pattern({:cons, anno, h0, t0}, st) do
    h1 = pattern(h0, st)
    t1 = pattern(t0, st)
    {:cons, ln(anno), h1, t1}
  end

  defp pattern({:tuple, anno, ps0}, st) do
    ps1 = pattern_list(ps0, st)
    {:tuple, ln(anno), ps1}
  end

  defp pattern({:record_index, anno, name, field} = _DBG,
            st) do
    expr = index_expr(anno, field, name,
                        record_fields(name, anno, st))
    pattern(expr, st)
  end

  defp pattern({:record, anno, name, pfs}, st0) do
    fs = record_fields(name, anno, st0)
    tMs = pattern_list(pattern_fields(fs, pfs), st0)
    {:tuple, ln(anno), [{:value, ln(anno), name} | tMs]}
  end

  defp pattern({:map, anno, fs0}, st) do
    fs1 = :lists.map(fn {:map_field_exact, l, k, v} ->
                          {:map_field_exact, l, gexpr(k, st), pattern(v, st)}
                     end,
                       fs0)
    {:map, ln(anno), fs1}
  end

  defp pattern({:op, _, :-, {:integer, anno, i}}, _St) do
    {:value, ln(anno), - i}
  end

  defp pattern({:op, _, :"+", {:integer, anno, i}}, _St) do
    {:value, ln(anno), i}
  end

  defp pattern({:op, _, :-, {:char, anno, i}}, _St) do
    {:value, ln(anno), - i}
  end

  defp pattern({:op, _, :"+", {:char, anno, i}}, _St) do
    {:value, ln(anno), i}
  end

  defp pattern({:op, _, :-, {:float, anno, i}}, _St) do
    {:value, ln(anno), - i}
  end

  defp pattern({:op, _, :"+", {:float, anno, i}}, _St) do
    {:value, ln(anno), i}
  end

  defp pattern({:bin, anno, grp}, st) do
    grp1 = pattern_list(bin_expand_strings(grp), st)
    {:bin, ln(anno), grp1}
  end

  defp pattern({:bin_element, anno, expr0, size0, type0},
            st) do
    {size1, type} = make_bit_type(anno, size0, type0)
    expr1 = pattern(expr0, st)
    expr = coerce_to_float(expr1, type0)
    size = expr(size1, false, st)
    {:bin_element, ln(anno), expr, size, type}
  end

  defp pattern({:op, _, :"++", {nil, _}, r}, st) do
    pattern(r, st)
  end

  defp pattern({:op, _, :"++", {:cons, li, h, t}, r}, st) do
    pattern({:cons, li, h, {:op, li, :"++", t, r}}, st)
  end

  defp pattern({:op, _, :"++", {:string, li, l}, r}, st) do
    pattern(string_to_conses(li, l, r), st)
  end

  defp pattern({:op, _Line, _Op, _A} = op, st) do
    pattern(:erl_eval.partial_eval(op), st)
  end

  defp pattern({:op, _Line, _Op, _L, _R} = op, st) do
    pattern(:erl_eval.partial_eval(op), st)
  end

  defp string_to_conses(anno, cs, tail) do
    :lists.foldr(fn c, t ->
                      {:cons, anno, {:char, anno, c}, t}
                 end,
                   tail, cs)
  end

  defp coerce_to_float({:value, anno, int} = e, [:float | _])
      when is_integer(int) do
    try do
      {:value, anno, :erlang.float(int)}
    catch
      :error, :badarg ->
        e
    end
  end

  defp coerce_to_float(e, _) do
    e
  end

  defp pattern_list([p0 | ps], st) do
    p1 = pattern(p0, st)
    [p1 | pattern_list(ps, st)]
  end

  defp pattern_list([], _St) do
    []
  end

  defp guard([g0 | gs], st) do
    g1 = and_guard(g0, st)
    [g1 | guard(gs, st)]
  end

  defp guard([], _St) do
    []
  end

  defp and_guard([g0 | gs], st) do
    g1 = guard_test(g0, st)
    [g1 | and_guard(gs, st)]
  end

  defp and_guard([], _St) do
    []
  end

  defp guard_test({:call, anno, {:atom, _, :is_record},
             [a, {:atom, _, name}]},
            st) do
    record_test_in_guard(anno, a, name, st)
  end

  defp guard_test({:call, anno,
             {:remote, _, {:atom, _, :erlang},
                {:atom, _, :is_record}},
             [a, {:atom, _, name}]},
            st) do
    record_test_in_guard(anno, a, name, st)
  end

  defp guard_test({:call, anno,
             {:tuple, _,
                [{:atom, _, :erlang}, {:atom, _, :is_record}]},
             [a, {:atom, _, name}]},
            st) do
    record_test_in_guard(anno, a, name, st)
  end

  defp guard_test({:call, anno,
             {:remote, _, {:atom, _, :erlang}, {:atom, _, f}}, as0},
            st) do
    as = gexpr_list(as0, st)
    {:safe_bif, ln(anno), :erlang, f, as}
  end

  defp guard_test({:call, anno, {:atom, _, f0}, as0}, st) do
    f = normalise_test(f0, length(as0))
    true = :erl_internal.bif(f, length(as0))
    as = gexpr_list(as0, st)
    {:safe_bif, ln(anno), :erlang, f, as}
  end

  defp guard_test({:op, anno, op, l0}, st) do
    true = :erl_internal.arith_op(op,
                                    1) or :erl_internal.bool_op(op, 1)
    l1 = gexpr(l0, st)
    {:safe_bif, ln(anno), :erlang, op, [l1]}
  end

  defp guard_test({:op, anno, op, l0, r0}, st)
      when op === :andalso or op === :orelse do
    l1 = gexpr(l0, st)
    r1 = gexpr(r0, st)
    {op, ln(anno), l1, r1}
  end

  defp guard_test({:op, anno, op, l0, r0}, st) do
    true = :erl_internal.comp_op(op,
                                   2) or :erl_internal.bool_op(op,
                                                                 2) or :erl_internal.arith_op(op,
                                                                                                2)
    l1 = gexpr(l0, st)
    r1 = gexpr(r0, st)
    {:safe_bif, ln(anno), :erlang, op, [l1, r1]}
  end

  defp guard_test({:record_field, _A, r, name, f}, st) do
    anno = :erl_parse.first_anno(r)
    get_record_field_guard(anno, r, f, name, st)
  end

  defp guard_test({:var, _, _} = v, _St) do
    v
  end

  defp guard_test({:atom, anno, true}, _St) do
    {:value, ln(anno), true}
  end

  defp guard_test({:atom, anno, _}, _St) do
    {:value, ln(anno), false}
  end

  defp guard_test({:integer, anno, _}, _St) do
    {:value, ln(anno), false}
  end

  defp guard_test({:char, anno, _}, _St) do
    {:value, ln(anno), false}
  end

  defp guard_test({:float, anno, _}, _St) do
    {:value, ln(anno), false}
  end

  defp guard_test({:string, anno, _}, _St) do
    {:value, ln(anno), false}
  end

  defp guard_test({nil, anno}, _St) do
    {:value, ln(anno), false}
  end

  defp guard_test({:cons, anno, _, _}, _St) do
    {:value, ln(anno), false}
  end

  defp guard_test({:tuple, anno, _}, _St) do
    {:value, ln(anno), false}
  end

  defp guard_test({:map, anno, _}, _St) do
    {:value, ln(anno), false}
  end

  defp guard_test({:map, anno, _, _}, _St) do
    {:value, ln(anno), false}
  end

  defp guard_test({:bin, anno, _}, _St) do
    {:value, ln(anno), false}
  end

  defp gexpr({:var, anno, v}, _St) do
    {:var, ln(anno), v}
  end

  defp gexpr({:integer, anno, i}, _St) do
    {:value, ln(anno), i}
  end

  defp gexpr({:char, anno, i}, _St) do
    {:value, ln(anno), i}
  end

  defp gexpr({:float, anno, f}, _St) do
    {:value, ln(anno), f}
  end

  defp gexpr({:atom, anno, a}, _St) do
    {:value, ln(anno), a}
  end

  defp gexpr({:string, anno, s}, _St) do
    {:value, ln(anno), s}
  end

  defp gexpr({nil, anno}, _St) do
    {:value, ln(anno), []}
  end

  defp gexpr({:cons, anno, h0, t0}, st) do
    case ({gexpr(h0, st), gexpr(t0, st)}) do
      {{:value, line, h1}, {:value, line, t1}} ->
        {:value, line, [h1 | t1]}
      {h1, t1} ->
        {:cons, ln(anno), h1, t1}
    end
  end

  defp gexpr({:tuple, anno, es0}, st) do
    es1 = gexpr_list(es0, st)
    {:tuple, ln(anno), es1}
  end

  defp gexpr({:record, _, _, _} = rec, st) do
    expr(rec, false, st)
  end

  defp gexpr({:map, anno, fs0}, st) do
    new_map(fs0, anno, st,
              fn f ->
                   gexpr(f, st)
              end)
  end

  defp gexpr({:map, anno, e0, fs0}, st) do
    e1 = gexpr(e0, st)
    fs1 = map_fields(fs0, st,
                       fn f ->
                            gexpr(f, st)
                       end)
    {:map, ln(anno), e1, fs1}
  end

  defp gexpr({:bin, anno, flds0}, st) do
    flds = gexpr_list(bin_expand_strings(flds0), st)
    {:bin, ln(anno), flds}
  end

  defp gexpr({:bin_element, anno, expr0, size0, type0},
            st) do
    {size1, type} = make_bit_type(anno, size0, type0)
    expr = gexpr(expr0, st)
    size = gexpr(size1, st)
    {:bin_element, ln(anno), expr, size, type}
  end

  defp gexpr({:call, anno, {:atom, _, :is_record},
             [a, {:atom, _, name}]},
            st) do
    record_test_in_guard(anno, a, name, st)
  end

  defp gexpr({:call, anno,
             {:remote, _, {:atom, _, :erlang},
                {:atom, _, :is_record}},
             [a, {:atom, _, name}]},
            st) do
    record_test_in_guard(anno, a, name, st)
  end

  defp gexpr({:call, anno,
             {:tuple, _,
                [{:atom, _, :erlang}, {:atom, _, :is_record}]},
             [a, {:atom, _, name}]},
            st) do
    record_test_in_guard(anno, a, name, st)
  end

  defp gexpr({:record_field, _A, r, name, f}, st) do
    anno = :erl_parse.first_anno(r)
    get_record_field_guard(anno, r, f, name, st)
  end

  defp gexpr({:record_index, anno, name, f}, st) do
    i = index_expr(anno, f, name,
                     record_fields(name, anno, st))
    gexpr(i, st)
  end

  defp gexpr({:call, anno,
             {:remote, _, {:atom, _, :erlang}, {:atom, _, :self}},
             []},
            _St) do
    {:dbg, ln(anno), :self, []}
  end

  defp gexpr({:call, anno,
             {:remote, _, {:atom, _, :erlang}, {:atom, _, f}}, as0},
            st) do
    as = gexpr_list(as0, st)
    {:safe_bif, ln(anno), :erlang, f, as}
  end

  defp gexpr({:call, anno, {:atom, _, :self}, []}, _St) do
    {:dbg, ln(anno), :self, []}
  end

  defp gexpr({:call, anno, {:atom, _, f}, as0}, st) do
    true = :erl_internal.bif(f, length(as0))
    as = gexpr_list(as0, st)
    {:safe_bif, ln(anno), :erlang, f, as}
  end

  defp gexpr({:op, anno, op, a0}, st) do
    :erl_internal.arith_op(op, 1)
    a1 = gexpr(a0, st)
    {:safe_bif, ln(anno), :erlang, op, [a1]}
  end

  defp gexpr({:op, anno, op, l0, r0}, st)
      when op === :andalso or op === :orelse do
    l1 = gexpr(l0, st)
    r1 = gexpr(r0, st)
    {op, ln(anno), l1, r1}
  end

  defp gexpr({:op, anno, op, l0, r0}, st) do
    true = :erl_internal.arith_op(op,
                                    2) or :erl_internal.comp_op(op,
                                                                  2) or :erl_internal.bool_op(op,
                                                                                                2)
    l1 = gexpr(l0, st)
    r1 = gexpr(r0, st)
    {:safe_bif, ln(anno), :erlang, op, [l1, r1]}
  end

  defp gexpr_list([e0 | es], st) do
    e1 = gexpr(e0, st)
    [e1 | gexpr_list(es, st)]
  end

  defp gexpr_list([], _St) do
    []
  end

  defp exprs([e], lc, st) do
    [expr(e, lc, st)]
  end

  defp exprs([e0 | es], lc, st) do
    e1 = expr(e0, false, st)
    [e1 | exprs(es, lc, st)]
  end

  defp exprs([], _Lc, _St) do
    []
  end

  defp expr({:var, anno, v}, _Lc, _St) do
    {:var, ln(anno), v}
  end

  defp expr({:integer, anno, i}, _Lc, _St) do
    {:value, ln(anno), i}
  end

  defp expr({:char, anno, i}, _Lc, _St) do
    {:value, ln(anno), i}
  end

  defp expr({:float, anno, f}, _Lc, _St) do
    {:value, ln(anno), f}
  end

  defp expr({:atom, anno, a}, _Lc, _St) do
    {:value, ln(anno), a}
  end

  defp expr({:string, anno, s}, _Lc, _St) do
    {:value, ln(anno), s}
  end

  defp expr({nil, anno}, _Lc, _St) do
    {:value, ln(anno), []}
  end

  defp expr({:cons, anno, h0, t0}, _Lc, st) do
    case ({expr(h0, false, st), expr(t0, false, st)}) do
      {{:value, line, h1}, {:value, line, t1}} ->
        {:value, line, [h1 | t1]}
      {h1, t1} ->
        {:cons, ln(anno), h1, t1}
    end
  end

  defp expr({:tuple, anno, es0}, _Lc, st) do
    es1 = expr_list(es0, st)
    {:tuple, ln(anno), es1}
  end

  defp expr({:record_index, anno, name, f}, lc, st) do
    i = index_expr(anno, f, name,
                     record_fields(name, anno, st))
    expr(i, lc, st)
  end

  defp expr({:record_field, _A, r, name, f}, _Lc, st) do
    anno = :erl_parse.first_anno(r)
    get_record_field_body(anno, r, f, name, st)
  end

  defp expr({:record, anno, r, name, us}, lc, st) do
    ue = record_update(r, name,
                         record_fields(name, anno, st), us, st)
    expr(ue, lc, st)
  end

  defp expr({:record, anno, name, is}, lc, st) do
    expr({:tuple, anno,
            [{:atom, anno, name} | record_inits(record_fields(name,
                                                                anno, st),
                                                  is)]},
           lc, st)
  end

  defp expr({:record_update, anno, es0}, lc, st) do
    es1 = exprs(es0, lc, st)
    {:record_update, ln(anno), es1}
  end

  defp expr({:map, anno, fs}, _Lc, st) do
    new_map(fs, anno, st,
              fn e ->
                   expr(e, false, st)
              end)
  end

  defp expr({:map, anno, e0, fs0}, _Lc, st) do
    e1 = expr(e0, false, st)
    fs1 = map_fields(fs0, st)
    {:map, ln(anno), e1, fs1}
  end

  defp expr({:block, anno, es0}, lc, st) do
    es1 = exprs(es0, lc, st)
    {:block, ln(anno), es1}
  end

  defp expr({:if, anno, cs0}, lc, st) do
    cs1 = icr_clauses(cs0, lc, st)
    {:if, ln(anno), cs1}
  end

  defp expr({:case, anno, e0, cs0}, lc, st) do
    e1 = expr(e0, false, st)
    cs1 = icr_clauses(cs0, lc, st)
    {:case, ln(anno), e1, cs1}
  end

  defp expr({:receive, anno, cs0}, lc, st) do
    cs1 = icr_clauses(cs0, lc, st)
    {:receive, ln(anno), cs1}
  end

  defp expr({:receive, anno, cs0, to0, toEs0}, lc, st) do
    to1 = expr(to0, false, st)
    toEs1 = exprs(toEs0, lc, st)
    cs1 = icr_clauses(cs0, lc, st)
    {:receive, ln(anno), cs1, to1, toEs1}
  end

  defp expr({:maybe, anno, es0}, lc, st) do
    es1 = exprs(es0, lc, st)
    {:maybe, ln(anno), es1}
  end

  defp expr({:maybe, anno, es0, {:else, _ElseAnno, cs0}},
            lc, st) do
    es1 = exprs(es0, lc, st)
    cs1 = icr_clauses(cs0, lc, st)
    {:maybe, ln(anno), es1, cs1}
  end

  defp expr({:fun, anno, {:clauses, cs0}}, _Lc, st) do
    cs = fun_clauses(cs0, st)
    name = new_fun_name()
    {:make_fun, ln(anno), name, cs}
  end

  defp expr({:fun, anno, {:function, f, a}}, _Lc, _St) do
    line = ln(anno)
    as = new_vars(a, line)
    name = new_fun_name()
    cs = [{:clause, line, as, [],
             [{:local_call, line, f, as, true}]}]
    {:make_fun, line, name, cs}
  end

  defp expr({:named_fun, anno, fName, cs0}, _Lc, st) do
    cs = fun_clauses(cs0, st)
    name = new_fun_name()
    {:make_named_fun, ln(anno), name, fName, cs}
  end

  defp expr({:fun, anno,
             {:function, {:atom, _, m}, {:atom, _, f},
                {:integer, _, a}}},
            _Lc, _St)
      when (0 <= a and a <= 255) do
    {:value, ln(anno), :erlang.make_fun(m, f, a)}
  end

  defp expr({:fun, anno, {:function, m, f, a}}, _Lc, st) do
    mFA = expr_list([m, f, a], st)
    {:make_ext_fun, ln(anno), mFA}
  end

  defp expr({:call, anno,
             {:remote, _, {:atom, _, :erlang}, {:atom, _, :self}},
             []},
            _Lc, _St) do
    {:dbg, ln(anno), :self, []}
  end

  defp expr({:call, anno,
             {:remote, _, {:atom, _, :erlang}, {:atom, _, :throw}},
             [_] = as},
            _Lc, st) do
    {:dbg, ln(anno), :throw, expr_list(as, st)}
  end

  defp expr({:call, anno,
             {:remote, _, {:atom, _, :erlang}, {:atom, _, :error}},
             [_] = as},
            _Lc, st) do
    {:dbg, ln(anno), :error, expr_list(as, st)}
  end

  defp expr({:call, anno,
             {:remote, _, {:atom, _, :erlang}, {:atom, _, :exit}},
             [_] = as},
            _Lc, st) do
    {:dbg, ln(anno), :exit, expr_list(as, st)}
  end

  defp expr({:call, anno,
             {:remote, _, {:atom, _, :erlang}, {:atom, _, :raise}},
             [_, _, _] = as},
            _Lc, st) do
    {:dbg, ln(anno), :raise, expr_list(as, st)}
  end

  defp expr({:call, anno,
             {:remote, _, {:atom, _, :erlang}, {:atom, _, :apply}},
             [_, _, _] = as0},
            lc, st) do
    as = expr_list(as0, st)
    {:apply, ln(anno), as, lc}
  end

  defp expr({:call, anno, {:atom, _, :is_record},
             [a, {:atom, _, name}]},
            lc, st) do
    record_test_in_body(anno, a, name, lc, st)
  end

  defp expr({:call, anno,
             {:remote, _, {:atom, _, :erlang},
                {:atom, _, :is_record}},
             [a, {:atom, _, name}]},
            lc, st) do
    record_test_in_body(anno, a, name, lc, st)
  end

  defp expr({:call, anno,
             {:tuple, _,
                [{:atom, _, :erlang}, {:atom, _, :is_record}]},
             [a, {:atom, _, name}]},
            lc, st) do
    record_test_in_body(anno, a, name, lc, st)
  end

  defp expr({:call, anno, {:atom, _AnnoA, :record_info},
             [_, _] = as0},
            lc, st) do
    as = expr_list(as0, st)
    expr(record_info_call(anno, as, st), lc, st)
  end

  defp expr({:call, anno,
             {:remote, _, {:atom, _, mod}, {:atom, _, func}}, as0},
            lc, st) do
    as = expr_list(as0, st)
    case (:erlang.is_builtin(mod, func, length(as))) do
      false ->
        {:call_remote, ln(anno), mod, func, as, lc}
      true ->
        case (bif_type(mod, func, length(as0))) do
          :safe ->
            {:safe_bif, ln(anno), mod, func, as}
          :unsafe ->
            {:bif, ln(anno), mod, func, as}
        end
    end
  end

  defp expr({:call, anno, {:remote, _, mod0, func0}, as0},
            lc, st) do
    mod = expr(mod0, false, st)
    func = expr(func0, false, st)
    as = consify(expr_list(as0, st))
    {:apply, ln(anno), [mod, func, as], lc}
  end

  defp expr({:call, anno, {:atom, _, func} = f, as0}, lc,
            %{ctype: ctypes} = st) do
    as = expr_list(as0, st)
    ar = length(as)
    nA = {func, ar}
    special = :lists.member(func,
                              [:self, :throw, :error, :exit, :raise, :apply])
    case (:maps.get(nA, ctypes, :undefined)) do
      :local ->
        {:local_call, ln(anno), func, as, lc}
      {:imported, mod} ->
        {:call_remote, ln(anno), mod, func, as, lc}
      :undefined when special ->
        expr({:call, anno,
                {:remote, anno, {:atom, anno, :erlang}, f}, as0},
               lc, st)
      :undefined ->
        case (:erl_internal.bif(func, ar) and bif_type(:erlang,
                                                         func, ar)) do
          false ->
            {:local_call, ln(anno), func, as, lc}
          :safe ->
            {:safe_bif, ln(anno), :erlang, func, as}
          :unsafe ->
            {:bif, ln(anno), :erlang, func, as}
        end
    end
  end

  defp expr({:call, anno, fun0, as0}, lc, st) do
    fun = expr(fun0, false, st)
    as = expr_list(as0, st)
    {:apply_fun, ln(anno), fun, as, lc}
  end

  defp expr({:catch, anno, e0}, _Lc, st) do
    e1 = expr(e0, false, st)
    {:catch, ln(anno), e1}
  end

  defp expr({:try, anno, es0, caseCs0, catchCs0, as0}, lc,
            st) do
    es = expr_list(es0, st)
    caseCs = icr_clauses(caseCs0, lc, st)
    catchCs = icr_clauses(catchCs0, lc, st)
    as = expr_list(as0, st)
    {:try, ln(anno), es, caseCs, catchCs, as}
  end

  defp expr({:lc, _, _, _} = compr, _Lc, st) do
    expr_comprehension(compr, st)
  end

  defp expr({:bc, _, _, _} = compr, _Lc, st) do
    expr_comprehension(compr, st)
  end

  defp expr({:mc, _, _, _} = compr, _Lc, st) do
    expr_comprehension(compr, st)
  end

  defp expr({:match, anno, p0, e0}, _Lc, st) do
    e1 = expr(e0, false, st)
    p1 = pattern(p0, st)
    {:match, ln(anno), p1, e1}
  end

  defp expr({:maybe_match, anno, p0, e0}, _Lc, st) do
    e1 = expr(e0, false, st)
    p1 = pattern(p0, st)
    {:maybe_match, ln(anno), p1, e1}
  end

  defp expr({:op, anno, op, a0}, _Lc, st) do
    a1 = expr(a0, false, st)
    {:op, ln(anno), op, [a1]}
  end

  defp expr({:op, anno, :"++", l0, r0}, _Lc, st) do
    l1 = expr(l0, false, st)
    r1 = expr(r0, false, st)
    {:op, ln(anno), :append, [l1, r1]}
  end

  defp expr({:op, anno, :"--", l0, r0}, _Lc, st) do
    l1 = expr(l0, false, st)
    r1 = expr(r0, false, st)
    {:op, ln(anno), :subtract, [l1, r1]}
  end

  defp expr({:op, anno, :"!", l0, r0}, _Lc, st) do
    l1 = expr(l0, false, st)
    r1 = expr(r0, false, st)
    {:send, ln(anno), l1, r1}
  end

  defp expr({:op, anno, op, l0, r0}, _Lc, st)
      when op === :andalso or op === :orelse do
    l1 = expr(l0, false, st)
    r1 = expr(r0, false, st)
    {op, ln(anno), l1, r1}
  end

  defp expr({:op, anno, op, l0, r0}, _Lc, st) do
    l1 = expr(l0, false, st)
    r1 = expr(r0, false, st)
    {:op, ln(anno), op, [l1, r1]}
  end

  defp expr({:bin, anno, grp}, _Lc, st) do
    grp1 = expr_list(bin_expand_strings(grp), st)
    {:bin, ln(anno), grp1}
  end

  defp expr({:bin_element, anno, expr0, size0, type0}, _Lc,
            st) do
    {size1, type} = make_bit_type(anno, size0, type0)
    expr = expr(expr0, false, st)
    size = expr(size1, false, st)
    {:bin_element, ln(anno), expr, size, type}
  end

  defp expr({:map_field_assoc, l, k0, v0}, _Lc, st) do
    k = expr(k0, false, st)
    v = expr(v0, false, st)
    {:map_field_assoc, l, k, v}
  end

  defp consify([a | as]) do
    {:cons, 0, a, consify(as)}
  end

  defp consify([]) do
    {:value, 0, []}
  end

  defp make_bit_type(line, :default, type0) do
    case (:erl_bits.set_bit_type(:default, type0)) do
      {:ok, :all, bt} ->
        {{:atom, line, :all}, :erl_bits.as_list(bt)}
      {:ok, :undefined, bt} ->
        {{:atom, line, :undefined}, :erl_bits.as_list(bt)}
      {:ok, size, bt} ->
        {{:integer, line, size}, :erl_bits.as_list(bt)}
    end
  end

  defp make_bit_type(_Line, size, type0) do
    {:ok, ^size, bt} = :erl_bits.set_bit_type(size, type0)
    {size, :erl_bits.as_list(bt)}
  end

  defp expr_comprehension({tag, anno, e0, gs0}, st) do
    gs = (for g <- gs0 do
            case (g) do
              {:generate, l, p0, qs} ->
                {:generator,
                   {:generate, l, pattern(p0, st), expr(qs, false, st)}}
              {:b_generate, l, p0, qs} ->
                {:generator,
                   {:b_generate, l, pattern(p0, st), expr(qs, false, st)}}
              {:m_generate, l, p0, qs} ->
                {:generator,
                   {:m_generate, l, mc_pattern(p0, st),
                      expr(qs, false, st)}}
              expr ->
                case (is_guard_test(expr, st)) do
                  true ->
                    {:guard, guard([[expr]], st)}
                  false ->
                    expr(expr, false, st)
                end
            end
          end)
    {tag, ln(anno), expr(e0, false, st), gs}
  end

  defp mc_pattern({:map_field_exact, l, keyP0, valP0}, st) do
    keyP1 = pattern(keyP0, st)
    valP1 = pattern(valP0, st)
    {:map_field_exact, l, keyP1, valP1}
  end

  defp is_guard_test(expr, %{ctype: ctypes}) do
    isOverridden = fn nA ->
                        case (:maps.get(nA, ctypes, :undefined)) do
                          :local ->
                            true
                          {:imported, _} ->
                            true
                          :undefined ->
                            false
                        end
                   end
    :erl_lint.is_guard_test(expr, [], isOverridden)
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

  defp record_test_in_body(anno, expr, name, lc, st) do
    fs = record_fields(name, anno, st)
    var = {:var, anno, new_var_name()}
    expr({:block, anno,
            [{:match, anno, var, expr}, {:call, anno,
                                           {:remote, anno,
                                              {:atom, anno, :erlang},
                                              {:atom, anno, :is_record}},
                                           [var, {:atom, anno, name}, {:integer,
                                                                         anno,
                                                                         length(fs) + 1}]}]},
           lc, st)
  end

  defp record_test_in_guard(anno, term, name, st) do
    fs = record_fields(name, anno, st)
    expr({:call, anno,
            {:remote, anno, {:atom, anno, :erlang},
               {:atom, anno, :is_record}},
            [term, {:atom, anno, name}, {:integer, anno,
                                           length(fs) + 1}]},
           false, st)
  end

  defp record_info_call(anno,
            [{:value, _AnnoI, info}, {:value, _AnnoN, name}], st) do
    case (info) do
      :size ->
        {:integer, anno,
           1 + length(record_fields(name, anno, st))}
      :fields ->
        fs = :lists.map(fn {:record_field, _, field, _Val} ->
                             field
                        end,
                          record_fields(name, anno, st))
        :lists.foldr(fn h, t ->
                          {:cons, anno, h, t}
                     end,
                       {nil, anno}, fs)
    end
  end

  defp record_fields(r, anno, %{recs: recs}) do
    fields = :maps.get(r, recs)
    for {:record_field, _Anno, {:atom, _AnnoA, f},
           di} <- fields do
      {:record_field, anno, {:atom, anno, f},
         copy_expr(di, anno)}
    end
  end

  defp record_inits(fs, is) do
    wildcardInit = record_wildcard_init(is)
    :lists.map(fn {:record_field, _, {:atom, _, f}, d} ->
                    case (find_field(f, is)) do
                      {:ok, init} ->
                        init
                      :error when wildcardInit === :none ->
                        d
                      :error ->
                        wildcardInit
                    end
               end,
                 fs)
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

  defp copy_expr(expr, anno) do
    :erl_parse.map_anno(fn _A ->
                             anno
                        end,
                          expr)
  end

  defp find_field(f,
            [{:record_field, _, {:atom, _, f}, val} | _]) do
    {:ok, val}
  end

  defp find_field(f, [_ | fs]) do
    find_field(f, fs)
  end

  defp find_field(_, []) do
    :error
  end

  defp record_update(r, name, fs, us0, st) do
    anno = :erlang.element(2, r)
    {pre, us} = record_exprs(us0, st)
    var = {:var, anno, new_var_name()}
    update = record_match(var, name, anno, fs, us, st)
    {:record_update, anno,
       pre ++ [{:match, anno, var, r}, update]}
  end

  defp record_match(r, name, anno, fs, us, st) do
    {ps, news} = record_upd_fs(fs, us, st)
    {:case, ln(anno), r,
       [{:clause, ln(anno),
           [{:tuple, anno, [{:atom, anno, name} | ps]}], [],
           [{:tuple, anno, [{:atom, anno, name} | news]}]},
            {:clause, anno, [{:var, anno, :_}], [],
               [call_error(anno,
                             {:tuple, anno,
                                [{:atom, anno, :badrecord}, {:atom, anno,
                                                               name}]})]}]}
  end

  defp record_upd_fs([{:record_field, anno, {:atom, _AnnoA, f},
              _Val} |
               fs],
            us, st) do
    p = {:var, anno, new_var_name()}
    {ps, news} = record_upd_fs(fs, us, st)
    case (find_field(f, us)) do
      {:ok, new} ->
        {[p | ps], [new | news]}
      :error ->
        {[p | ps], [p | news]}
    end
  end

  defp record_upd_fs([], _, _) do
    {[], []}
  end

  defp call_error(anno, r) do
    {:call, anno,
       {:remote, anno, {:atom, anno, :erlang},
          {:atom, anno, :error}},
       [r]}
  end

  defp record_exprs(us, st) do
    record_exprs(us, st, [], [])
  end

  defp record_exprs([{:record_field, anno,
              {:atom, _AnnoA, _F} = name, val} = field0 |
               us],
            st, pre, fs) do
    case (is_simple_val(val)) do
      true ->
        record_exprs(us, st, pre, [field0 | fs])
      false ->
        var = {:var, anno, new_var_name()}
        bind = {:match, ln(anno), var, val}
        field = {:record_field, ln(anno), name, var}
        record_exprs(us, st, [bind | pre], [field | fs])
    end
  end

  defp record_exprs([], _St, pre, fs) do
    {:lists.reverse(pre), fs}
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

  defp pattern_fields(fs, ms) do
    wildcard = record_wildcard_init(ms)
    :lists.map(fn {:record_field, anno, {:atom, _, f}, _} ->
                    case (find_field(f, ms)) do
                      {:ok, match} ->
                        match
                      :error when wildcard === :none ->
                        {:var, anno, :_}
                      :error ->
                        wildcard
                    end
               end,
                 fs)
  end

  defp index_expr(anno, {:atom, _, f}, _Name, fs) do
    {:integer, anno, index_expr(f, fs, 2)}
  end

  defp index_expr(f, [{:record_field, _, {:atom, _, f}, _} | _],
            i) do
    i
  end

  defp index_expr(f, [_ | fs], i) do
    index_expr(f, fs, i + 1)
  end

  defp get_record_field_body(anno, r, {:atom, _, f}, name, st) do
    var = {:var, anno, new_var_name()}
    fs = record_fields(name, anno, st)
    i = index_expr(f, fs, 2)
    p = record_pattern(2, i, var, length(fs) + 1, anno,
                         [{:atom, anno, name}])
    e = {:case, anno, r,
           [{:clause, anno, [{:tuple, anno, p}], [], [var]},
                {:clause, anno, [{:var, anno, :_}], [],
                   [{:call, anno,
                       {:remote, anno, {:atom, anno, :erlang},
                          {:atom, anno, :error}},
                       [{:tuple, anno,
                           [{:atom, anno, :badrecord}, {:atom, anno,
                                                          name}]}]}]}]}
    expr(e, false, st)
  end

  defp get_record_field_guard(anno, r, {:atom, _, f}, name, st) do
    fs = record_fields(name, anno, st)
    i = index_expr(f, fs, 2)
    expR = expr(r, false, st)
    {:safe_bif, ln(anno), :erlang, :element,
       [{:value, ln(anno), i}, expR]}
  end

  defp record_pattern(i, i, var, sz, anno, acc) do
    record_pattern(i + 1, i, var, sz, anno, [var | acc])
  end

  defp record_pattern(cur, i, var, sz, anno, acc) when cur <= sz do
    record_pattern(cur + 1, i, var, sz, anno,
                     [{:var, anno, :_} | acc])
  end

  defp record_pattern(_, _, _, _, _, acc) do
    :lists.reverse(acc)
  end

  defp bin_expand_strings(es) do
    :lists.foldr(fn {:bin_element, line, {:string, _, s},
                       sz, ts},
                      es1 ->
                      :lists.foldr(fn c, es2 ->
                                        [{:bin_element, line, {:char, line, c},
                                            sz, ts} |
                                             es2]
                                   end,
                                     es1, s)
                    e, es1 ->
                      [e | es1]
                 end,
                   [], es)
  end

  defp expr_list([e0 | es], st) do
    e1 = expr(e0, false, st)
    [e1 | expr_list(es, st)]
  end

  defp expr_list([], _St) do
    []
  end

  defp icr_clauses([c0 | cs], lc, st) do
    c1 = clause(c0, lc, st)
    [c1 | icr_clauses(cs, lc, st)]
  end

  defp icr_clauses([], _, _St) do
    []
  end

  defp fun_clauses([{:clause, a, h, g, b} | cs], st) do
    [{:clause, ln(a), head(h, st), guard(g, st),
        exprs(b, true, st)} |
         fun_clauses(cs, st)]
  end

  defp fun_clauses([], _St) do
    []
  end

  defp new_map(fs0, anno, st, f) do
    line = ln(anno)
    fs1 = map_fields(fs0, st, f)
    fs2 = (for {:map_field_assoc, l, k, v} <- fs1 do
             {l, k, v}
           end)
    try do
      {:value, line, map_literal(fs2, %{})}
    catch
      :not_literal ->
        {:map, line, fs2}
    end
  end

  defp map_literal([{_, {:value, _, k}, {:value, _, v}} | t], m) do
    map_literal(t, :maps.put(k, v, m))
  end

  defp map_literal([_ | _], _) do
    throw(:not_literal)
  end

  defp map_literal([], m) do
    m
  end

  defp map_fields(fs, st) do
    map_fields(fs, st,
                 fn e ->
                      expr(e, false, st)
                 end)
  end

  defp map_fields([{:map_field_assoc, a, n, v} | fs], st, f) do
    [{:map_field_assoc, ln(a), f.(n), f.(v)} |
         map_fields(fs, st, f)]
  end

  defp map_fields([{:map_field_exact, a, n, v} | fs], st, f) do
    [{:map_field_exact, ln(a), f.(n), f.(v)} |
         map_fields(fs, st, f)]
  end

  defp map_fields([], _St, _) do
    []
  end

  defp new_var_name() do
    c = :erlang.get(:vcount)
    :erlang.put(:vcount, c + 1)
    :erlang.list_to_atom('%' ++ :erlang.integer_to_list(c))
  end

  defp new_vars(n, l) do
    new_vars(n, l, [])
  end

  defp new_vars(n, l, vs) when n > 0 do
    v = {:var, l, new_var_name()}
    new_vars(n - 1, l, [v | vs])
  end

  defp new_vars(0, _, vs) do
    vs
  end

  defp new_fun_name() do
    {f, a} = :erlang.get(:current_function)
    i = :erlang.get(:fun_count)
    :erlang.put(:fun_count, i + 1)
    name = '-' ++ :erlang.atom_to_list(f) ++ '/' ++ :erlang.integer_to_list(a) ++ '-fun-' ++ :erlang.integer_to_list(i) ++ '-'
    :erlang.list_to_atom(name)
  end

  defp ln(anno) do
    :erl_anno.line(anno)
  end

  defp bif_type(:erlang, name, arity) do
    case (:erl_internal.guard_bif(name, arity)) do
      true ->
        :safe
      false ->
        bif_type(name)
    end
  end

  defp bif_type(_, _, _) do
    :unsafe
  end

  defp bif_type(:register) do
    :safe
  end

  defp bif_type(:unregister) do
    :safe
  end

  defp bif_type(:whereis) do
    :safe
  end

  defp bif_type(:registered) do
    :safe
  end

  defp bif_type(:setelement) do
    :safe
  end

  defp bif_type(:atom_to_list) do
    :safe
  end

  defp bif_type(:list_to_atom) do
    :safe
  end

  defp bif_type(:integer_to_list) do
    :safe
  end

  defp bif_type(:list_to_integer) do
    :safe
  end

  defp bif_type(:float_to_list) do
    :safe
  end

  defp bif_type(:list_to_float) do
    :safe
  end

  defp bif_type(:tuple_to_list) do
    :safe
  end

  defp bif_type(:list_to_tuple) do
    :safe
  end

  defp bif_type(:make_ref) do
    :safe
  end

  defp bif_type(:time) do
    :safe
  end

  defp bif_type(:date) do
    :safe
  end

  defp bif_type(:processes) do
    :safe
  end

  defp bif_type(:process_info) do
    :safe
  end

  defp bif_type(:load_module) do
    :safe
  end

  defp bif_type(:delete_module) do
    :safe
  end

  defp bif_type(:halt) do
    :safe
  end

  defp bif_type(:check_process_code) do
    :safe
  end

  defp bif_type(:purge_module) do
    :safe
  end

  defp bif_type(:pid_to_list) do
    :safe
  end

  defp bif_type(:list_to_pid) do
    :safe
  end

  defp bif_type(:module_loaded) do
    :safe
  end

  defp bif_type(:binary_to_term) do
    :safe
  end

  defp bif_type(:term_to_binary) do
    :safe
  end

  defp bif_type(:nodes) do
    :safe
  end

  defp bif_type(:is_alive) do
    :safe
  end

  defp bif_type(:disconnect_node) do
    :safe
  end

  defp bif_type(:binary_to_list) do
    :safe
  end

  defp bif_type(:list_to_binary) do
    :safe
  end

  defp bif_type(:split_binary) do
    :safe
  end

  defp bif_type(:hash) do
    :safe
  end

  defp bif_type(:pre_loaded) do
    :safe
  end

  defp bif_type(:set_cookie) do
    :safe
  end

  defp bif_type(:get_cookie) do
    :safe
  end

  defp bif_type(_) do
    :unsafe
  end

end