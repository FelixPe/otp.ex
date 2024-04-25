defmodule :m_core_pp do
  use Bitwise
  require Record
  Record.defrecord(:r_c_alias, :c_alias, anno: [],
                                   var: :undefined, pat: :undefined)
  Record.defrecord(:r_c_apply, :c_apply, anno: [], op: :undefined,
                                   args: :undefined)
  Record.defrecord(:r_c_binary, :c_binary, anno: [],
                                    segments: :undefined)
  Record.defrecord(:r_c_bitstr, :c_bitstr, anno: [],
                                    val: :undefined, size: :undefined,
                                    unit: :undefined, type: :undefined,
                                    flags: :undefined)
  Record.defrecord(:r_c_call, :c_call, anno: [],
                                  module: :undefined, name: :undefined,
                                  args: :undefined)
  Record.defrecord(:r_c_case, :c_case, anno: [], arg: :undefined,
                                  clauses: :undefined)
  Record.defrecord(:r_c_catch, :c_catch, anno: [],
                                   body: :undefined)
  Record.defrecord(:r_c_clause, :c_clause, anno: [],
                                    pats: :undefined, guard: :undefined,
                                    body: :undefined)
  Record.defrecord(:r_c_cons, :c_cons, anno: [], hd: :undefined,
                                  tl: :undefined)
  Record.defrecord(:r_c_fun, :c_fun, anno: [], vars: :undefined,
                                 body: :undefined)
  Record.defrecord(:r_c_let, :c_let, anno: [], vars: :undefined,
                                 arg: :undefined, body: :undefined)
  Record.defrecord(:r_c_letrec, :c_letrec, anno: [],
                                    defs: :undefined, body: :undefined)
  Record.defrecord(:r_c_literal, :c_literal, anno: [],
                                     val: :undefined)
  Record.defrecord(:r_c_map, :c_map, anno: [],
                                 arg: :EFE_TODO_NESTED_RECORD, es: :undefined,
                                 is_pat: false)
  Record.defrecord(:r_c_map_pair, :c_map_pair, anno: [],
                                      op: :undefined, key: :undefined,
                                      val: :undefined)
  Record.defrecord(:r_c_module, :c_module, anno: [],
                                    name: :undefined, exports: :undefined,
                                    attrs: :undefined, defs: :undefined)
  Record.defrecord(:r_c_opaque, :c_opaque, anno: [],
                                    val: :undefined)
  Record.defrecord(:r_c_primop, :c_primop, anno: [],
                                    name: :undefined, args: :undefined)
  Record.defrecord(:r_c_receive, :c_receive, anno: [],
                                     clauses: :undefined, timeout: :undefined,
                                     action: :undefined)
  Record.defrecord(:r_c_seq, :c_seq, anno: [], arg: :undefined,
                                 body: :undefined)
  Record.defrecord(:r_c_try, :c_try, anno: [], arg: :undefined,
                                 vars: :undefined, body: :undefined,
                                 evars: :undefined, handler: :undefined)
  Record.defrecord(:r_c_tuple, :c_tuple, anno: [], es: :undefined)
  Record.defrecord(:r_c_values, :c_values, anno: [],
                                    es: :undefined)
  Record.defrecord(:r_c_var, :c_var, anno: [], name: :undefined)
  Record.defrecord(:r_ctxt, :ctxt, indent: 0, item_indent: 2,
                                body_indent: 4, line: 0, clean: true)
  def format(node) do
    format(node, r_ctxt())
  end

  def format_all(node) do
    format(node, r_ctxt(clean: false))
  end

  defp maybe_anno(node, fun, r_ctxt(clean: false) = ctxt) do
    as = :cerl.get_ann(node)
    maybe_anno(node, fun, ctxt, as)
  end

  defp maybe_anno(node, fun, r_ctxt(clean: true) = ctxt) do
    as0 = :cerl.get_ann(node)
    case (get_line(as0)) do
      :none ->
        maybe_anno(node, fun, ctxt, as0)
      line ->
        as = strip_line(as0)
        cond do
          line > r_ctxt(ctxt, :line) ->
            [:io_lib.format('%% Line ~w', [line]), nl_indent(ctxt),
                                            maybe_anno(node, fun,
                                                         r_ctxt(ctxt, line: line),
                                                         as)]
          true ->
            maybe_anno(node, fun, ctxt, as)
        end
    end
  end

  defp maybe_anno(node, fun, ctxt, []) do
    fun.(node, ctxt)
  end

  defp maybe_anno(node, fun, ctxt, list) do
    ctxt1 = add_indent(ctxt, 2)
    ctxt2 = add_indent(ctxt1, 3)
    ['( ', fun.(node, ctxt1), nl_indent(ctxt1), '-| ',
                                                 format_anno(list, ctxt2), ' )']
  end

  defp format_anno([_ | _] = list, ctxt) do
    [?[, format_anno_list(list, ctxt), ?]]
  end

  defp format_anno({:file, name}, _Ctxt) do
    :io_lib.format('{\'file\',~p}', [name])
  end

  defp format_anno(tuple, ctxt) when is_tuple(tuple) do
    [?{, format_anno_list(:erlang.tuple_to_list(tuple),
                            ctxt),
             ?}]
  end

  defp format_anno(val, ctxt) when is_atom(val) do
    format_1(r_c_literal(val: val), ctxt)
  end

  defp format_anno(val, ctxt) when is_integer(val) do
    format_1(r_c_literal(val: val), ctxt)
  end

  defp format_anno_list([h | [_ | _] = t], ctxt) do
    [format_anno(h, ctxt), ?, | format_anno_list(t, ctxt)]
  end

  defp format_anno_list([h], ctxt) do
    format_anno(h, ctxt)
  end

  defp strip_line([a | as]) when is_integer(a) do
    strip_line(as)
  end

  defp strip_line([{a, c} | as]) when (is_integer(a) and
                                 is_integer(c)) do
    strip_line(as)
  end

  defp strip_line([{:file, _File} | as]) do
    strip_line(as)
  end

  defp strip_line([a | as]) do
    [a | strip_line(as)]
  end

  defp strip_line([]) do
    []
  end

  defp get_line([l | _As]) when is_integer(l) do
    l
  end

  defp get_line([{l, _Column} | _As]) when is_integer(l) do
    l
  end

  defp get_line([_ | as]) do
    get_line(as)
  end

  defp get_line([]) do
    :none
  end

  defp format(node, ctxt) do
    maybe_anno(node, &format_1/2, ctxt)
  end

  defp format_funcs(fs, ctxt) do
    format_vseq(fs, '', '', ctxt, &format_def/2)
  end

  defp format_def({n, v}, ctxt0) do
    ctxt1 = add_indent(ctxt0, r_ctxt(ctxt0, :body_indent))
    [format(n, ctxt0), ' =', nl_indent(ctxt1) | format(v,
                                                      ctxt1)]
  end

  defp format_values(vs, ctxt) do
    [?<, format_hseq(vs, ',', add_indent(ctxt, 1), &format/2),
             ?>]
  end

  defp format_bitstr(node, ctxt) do
    maybe_anno(node, &do_format_bitstr/2, ctxt)
  end

  defp do_format_bitstr(r_c_bitstr(val: v, size: s, unit: u, type: t, flags: fs),
            ctxt0) do
    vs = [s, u, t, fs]
    ctxt1 = add_indent(ctxt0, 2)
    val = format(v, ctxt1)
    ctxt2 = add_indent(ctxt1, width(val, ctxt1) + 2)
    ['#<', val, '>(', format_hseq(vs, ',', ctxt2, &format/2), ?)]
  end

  defp format_clauses(cs, ctxt) do
    format_vseq(cs, '', '', ctxt, &format_clause/2)
  end

  defp format_clause(node, ctxt) do
    maybe_anno(node, &format_clause_1/2, ctxt)
  end

  defp format_clause_1(r_c_clause(pats: ps, guard: g, body: b), ctxt) do
    ptxt = format_values(ps, ctxt)
    ctxt2 = add_indent(ctxt, r_ctxt(ctxt, :body_indent))
    [ptxt, (case (is_trivial_guard(g)) do
              true ->
                [' when ', format_guard(g,
                                   add_indent(ctxt, width(ptxt, ctxt) + 6))]
              false ->
                [nl_indent(ctxt2), 'when ', format_guard(g,
                                                     add_indent(ctxt2, 2))]
            end) ++ ' ->',
               nl_indent(ctxt2) | format(b, ctxt2)]
  end

  defp is_trivial_guard(r_c_literal(val: val)) when is_atom(val) do
    true
  end

  defp is_trivial_guard(_) do
    false
  end

  defp format_guard(node, ctxt) do
    maybe_anno(node, &format_guard_1/2, ctxt)
  end

  defp format_guard_1(r_c_call(module: m, name: n, args: as), ctxt0) do
    ctxt1 = add_indent(ctxt0, 5)
    mod = format(m, ctxt1)
    ctxt2 = add_indent(ctxt1, width(mod, ctxt1) + 1)
    name = format(n, ctxt2)
    ctxt3 = add_indent(ctxt0, 4)
    ['call ', mod, ':', name, nl_indent(ctxt3), ?(, format_vseq(as,
                                                          '', ',',
                                                          add_indent(ctxt3, 1),
                                                          &format_guard/2),
                                                ?)]
  end

  defp format_guard_1(e, ctxt) do
    format_1(e, ctxt)
  end

  defp format_hseq([h], _, ctxt, fun) do
    fun.(h, ctxt)
  end

  defp format_hseq([h | t], sep, ctxt, fun) do
    txt = [fun.(h, ctxt) | sep]
    ctxt1 = add_indent(ctxt, width(txt, ctxt))
    [txt | format_hseq(t, sep, ctxt1, fun)]
  end

  defp format_hseq([], _, _, _) do
    ''
  end

  defp format_vseq([h], _Pre, _Suf, ctxt, fun) do
    fun.(h, ctxt)
  end

  defp format_vseq([h | t], pre, suf, ctxt, fun) do
    [fun.(h, ctxt), suf, nl_indent(ctxt), pre |
                                              format_vseq(t, pre, suf, ctxt,
                                                            fun)]
  end

  defp format_vseq([], _, _, _, _) do
    ''
  end

  defp format_list_tail(r_c_literal(anno: [], val: []), _) do
    ']'
  end

  defp format_list_tail(r_c_cons(anno: [], hd: h, tl: t), ctxt) do
    txt = [?, | format(h, ctxt)]
    ctxt1 = add_indent(ctxt, width(txt, ctxt))
    [txt | format_list_tail(t, ctxt1)]
  end

  defp format_list_tail(tail, ctxt) do
    ['|', format(tail, add_indent(ctxt, 1)), ']']
  end

  defp format_map_pair(op, k, v, ctxt0) do
    ctxt1 = add_indent(ctxt0, 1)
    txt = format(k, ctxt1)
    ctxt2 = add_indent(ctxt0, width(txt, ctxt1))
    [txt, op, format(v, ctxt2)]
  end

  defp indent(r_ctxt(indent: n)) do
    cond do
      n <= 0 ->
        ''
      true ->
        :lists.duplicate(div(n, 8), ?\t) ++ spaces(rem(n, 8))
    end
  end

  defp nl_indent(ctxt) do
    [?\n | indent(ctxt)]
  end

  defp spaces(0) do
    ''
  end

  defp spaces(1) do
    ' '
  end

  defp spaces(2) do
    '  '
  end

  defp spaces(3) do
    '   '
  end

  defp spaces(4) do
    '    '
  end

  defp spaces(5) do
    '     '
  end

  defp spaces(6) do
    '      '
  end

  defp spaces(7) do
    '       '
  end

  defp unindent(t, ctxt) do
    unindent(t, r_ctxt(ctxt, :indent), [])
  end

  defp unindent(t, n, c) when n <= 0 do
    [t | c]
  end

  defp unindent([?\s | t], n, c) do
    unindent(t, n - 1, c)
  end

  defp unindent([?\t | t], n, c) do
    tab = 8
    cond do
      n >= tab ->
        unindent(t, n - tab, c)
      true ->
        unindent([spaces(tab - n) | t], 0, c)
    end
  end

  defp unindent([l | t], n, c) when is_list(l) do
    unindent(l, n, [t | c])
  end

  defp width(txt, ctxt) do
    width(txt, 0, ctxt, [])
  end

  defp width([?\t | t], a, ctxt, c) do
    width(t, a + 8, ctxt, c)
  end

  defp width([?\n | t], _, ctxt, c) do
    width(unindent([t | c], ctxt), ctxt)
  end

  defp width([h | t], a, ctxt, c) when is_list(h) do
    width(h, a, ctxt, [t | c])
  end

  defp width([_ | t], a, ctxt, c) do
    width(t, a + 1, ctxt, c)
  end

  defp width([], a, ctxt, [h | t]) do
    width(h, a, ctxt, t)
  end

  defp width([], a, _, []) do
    a
  end

  defp add_indent(ctxt, dx) do
    r_ctxt(ctxt, indent: r_ctxt(ctxt, :indent) + dx)
  end

  defp core_atom(a) do
    :io_lib.write_string(:erlang.atom_to_list(a), ?')
  end

  defp is_simple_term(r_c_tuple(es: es)) do
    length(es) < 4 and :lists.all(&is_simple_term/1, es)
  end

  defp is_simple_term(r_c_var()) do
    true
  end

  defp is_simple_term(r_c_literal(val: [_ | _])) do
    false
  end

  defp is_simple_term(r_c_literal(val: v)) do
    not is_tuple(v)
  end

  defp is_simple_term(_) do
    false
  end

  defp segs_from_bitstring(<<h, t :: bitstring>>) do
    [r_c_bitstr(val: r_c_literal(val: h), size: r_c_literal(val: 8), unit: r_c_literal(val: 1),
         type: r_c_literal(val: :integer),
         flags: r_c_literal(val: [:unsigned, :big])) |
         segs_from_bitstring(t)]
  end

  defp segs_from_bitstring(<<>>) do
    []
  end

  defp segs_from_bitstring(bitstring) do
    n = bit_size(bitstring)
    <<i :: size(n)>> = bitstring
    [r_c_bitstr(val: r_c_literal(val: i), size: r_c_literal(val: n), unit: r_c_literal(val: 1),
         type: r_c_literal(val: :integer),
         flags: r_c_literal(val: [:unsigned, :big]))]
  end

  defp clean_anno_carefully(node) do
    anno = clean_anno_carefully_1(:cerl.get_ann(node))
    :cerl.set_ann(node, anno)
  end

  defp clean_anno_carefully_1([:letrec_goto = keep | annos]) do
    [keep | clean_anno_carefully_1(annos)]
  end

  defp clean_anno_carefully_1([_ | annos]) do
    clean_anno_carefully_1(annos)
  end

  defp clean_anno_carefully_1([]) do
    []
  end

end