defmodule :m_beam_ssa_pp do
  use Bitwise
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
  def format_instr(r_b_set() = i) do
    cs = :lists.flatten(format_instr(r_b_set(i, anno: %{}), %{},
                                       true))
    :string.trim(cs, :leading)
  end

  def format_instr(i0) do
    i = :erlang.setelement(2, i0, %{})
    cs = :lists.flatten(format_terminator(i, %{}))
    :string.trim(cs, :both)
  end

  def format_var(v) do
    cs = :lists.flatten(format_var(v, %{}))
    :string.trim(cs, :leading)
  end

  defp format_anno(:parameter_info, map) when is_map(map) do
    case (map_size(map)) do
      0 ->
        []
      _ ->
        params = :lists.sort(:maps.to_list(map))
        break = '\n%%     '
        [:io_lib.format('%% Parameters\n', []), for {v, i} <- params do
                                  :io_lib.format('%%    ~s =>~s~s\n',
                                                   [format_var(v), break,
                                                                       format_param_info(i,
                                                                                           break)])
                                end]
    end
  end

  defp format_anno(key, map) when is_map(map) do
    sorted = :maps.to_list(:maps.iterator(map, :ordered))
    [:io_lib.format('%% ~s:\n', [key]), for {k, v} <- sorted do
                                 :io_lib.format('%%    ~kw => ~kw\n', [k, v])
                               end]
  end

  defp format_anno(key, value) do
    :io_lib.format('%% ~s: ~kp\n', [key, value])
  end

  defp format_param_info([{:type, t} | infos], break) do
    [format_type(t, break) | format_param_info(infos,
                                                 break)]
  end

  defp format_param_info([info | infos], break) do
    [:io_lib.format('~s~kp', [break, info]) |
         format_param_info(infos, break)]
  end

  defp format_param_info([], _Break) do
    []
  end

  defp format_type(t, break) do
    indented = :unicode.characters_to_list(format_type(t))
    :string.replace(indented, [?\n], break, :all)
  end

  defp format_blocks(ls, blocks, anno) do
    pP = (for l <- ls do
            format_block(l, blocks, anno)
          end)
    :lists.join(?\n, pP)
  end

  defp format_block(l, blocks, funcAnno) do
    r_b_blk(anno: anno, is: is, last: last) = :maps.get(l, blocks)
    [case (map_size(anno)) do
       0 ->
         []
       _ ->
         :io_lib.format('%% ~kp\n', [anno])
     end,
         :io_lib.format('~kp:', [l]), format_instrs(is, funcAnno,
                                                 true),
                                     ?\n, format_terminator(last, funcAnno)]
  end

  defp format_instrs([i | is], funcAnno, first) do
    [?\n, format_instr(i, funcAnno, first),
              format_instrs(is, funcAnno, false)]
  end

  defp format_instrs([], _FuncAnno, _First) do
    []
  end

  defp format_instr(r_b_set(anno: anno, op: op, dst: dst, args: args),
            funcAnno, first) do
    annoStr = format_instr_anno(anno, funcAnno, args)
    liveIntervalStr = format_live_interval(dst, funcAnno)
    [cond do
       first ->
         []
       annoStr !== [] or liveIntervalStr !== [] ->
         ?\n
       true ->
         []
     end,
         annoStr, liveIntervalStr, :io_lib.format('  ~s~ts = ~ts',
                                                    [format_i_number(anno),
                                                         format_var(dst,
                                                                      funcAnno),
                                                             format_op(op)]),
                                       case (args) do
                                         [] ->
                                           []
                                         [_ | _] ->
                                           :io_lib.format(' ~ts',
                                                            [format_args(args,
                                                                           funcAnno)])
                                       end]
  end

  defp format_i_number(%{n: n}) do
    :io_lib.format('[~p] ', [n])
  end

  defp format_i_number(%{}) do
    []
  end

  defp format_terminator(r_b_br(anno: a, bool: r_b_literal(val: true), succ: same,
              fail: same),
            _) do
    :io_lib.format('~s  ~sbr ~ts\n',
                     [format_terminator_anno(a), format_i_number(a),
                                                     format_label(same)])
  end

  defp format_terminator(r_b_br(anno: a, bool: bool, succ: succ, fail: fail),
            funcAnno) do
    :io_lib.format('~s  ~sbr ~ts, ~ts, ~ts\n',
                     [format_terminator_anno(a), format_i_number(a),
                                                     format_arg(bool, funcAnno),
                                                         format_label(succ),
                                                             format_label(fail)])
  end

  defp format_terminator(r_b_switch(anno: a, arg: arg, fail: fail, list: list),
            funcAnno) do
    :io_lib.format('~s  ~sswitch ~ts, ~ts, ~ts\n',
                     [format_terminator_anno(a), format_i_number(a),
                                                     format_arg(arg, funcAnno),
                                                         format_label(fail),
                                                             format_switch_list(list,
                                                                                  funcAnno)])
  end

  defp format_terminator(r_b_ret(anno: a, arg: arg), funcAnno) do
    :io_lib.format('~s  ~sret ~ts\n',
                     [format_terminator_anno(a), format_i_number(a),
                                                     format_arg(arg, funcAnno)])
  end

  defp format_terminator_anno(anno) do
    format_instr_anno(anno, %{}, [])
  end

  defp format_op({prefix, name}) do
    :io_lib.format('~p:~p', [prefix, name])
  end

  defp format_op(name) do
    :io_lib.format('~p', [name])
  end

  defp format_register(r_b_var() = v, %{registers: regs}) do
    {tag, n} = :maps.get(v, regs)
    :io_lib.format('~p~p', [tag, n])
  end

  defp format_register(_, %{}) do
    ''
  end

  defp format_var(var, funcAnno) do
    varString = format_var_1(var)
    case (format_register(var, funcAnno)) do
      [] ->
        varString
      [_ | _] = reg ->
        [reg, ?/, varString]
    end
  end

  defp format_var_1(r_b_var(name: {name, uniq})) do
    cond do
      is_atom(name) ->
        :io_lib.format('~ts:~p', [name, uniq])
      is_integer(name) ->
        :io_lib.format('_~p:~p', [name, uniq])
    end
  end

  defp format_var_1(r_b_var(name: name)) when is_atom(name) do
    :erlang.atom_to_list(name)
  end

  defp format_var_1(r_b_var(name: name)) when is_integer(name) do
    '_' ++ :erlang.integer_to_list(name)
  end

  defp format_args(args, funcAnno) do
    ss = (for arg <- args do
            format_arg(arg, funcAnno)
          end)
    :lists.join(', ', ss)
  end

  defp format_arg(r_b_var() = arg, funcAnno) do
    format_var(arg, funcAnno)
  end

  defp format_arg(r_b_literal(val: val), _FuncAnno) do
    :io_lib.format('`~kp`', [val])
  end

  defp format_arg(r_b_remote(mod: mod, name: name, arity: arity),
            funcAnno) do
    :io_lib.format('(~ts:~ts/~p)',
                     [format_arg(mod, funcAnno), format_arg(name, funcAnno),
                                                     arity])
  end

  defp format_arg(r_b_local(name: name, arity: arity), funcAnno) do
    :io_lib.format('(~ts/~p)', [format_arg(name, funcAnno), arity])
  end

  defp format_arg({value, label}, funcAnno)
      when is_integer(label) do
    :io_lib.format('{ ~ts, ~ts }',
                     [format_arg(value, funcAnno), format_label(label)])
  end

  defp format_arg(other, _) do
    :io_lib.format('*** ~kp ***', [other])
  end

  defp format_switch_list(list, funcAnno) do
    ss = (for {val, l} <- list do
            :io_lib.format('{ ~ts, ~ts }',
                             [format_arg(val, funcAnno), format_label(l)])
          end)
    :io_lib.format('[\n    ~ts\n  ]', [:lists.join(',\n    ', ss)])
  end

  defp format_label(l) do
    :io_lib.format('^~w', [l])
  end

  defp format_instr_anno(%{n: _} = anno, funcAnno, args) do
    format_instr_anno(:maps.remove(:n, anno), funcAnno,
                        args)
  end

  defp format_instr_anno(%{location: {file, line}} = anno0, funcAnno,
            args) do
    anno = :maps.remove(:location, anno0)
    [:io_lib.format('  %% ~ts:~p\n', [file, line]) |
         format_instr_anno(anno, funcAnno, args)]
  end

  defp format_instr_anno(%{result_type: t} = anno0, funcAnno, args) do
    anno = :maps.remove(:result_type, anno0)
    break = '\n  %%    '
    [:io_lib.format('  %% Result type:~s~s\n', [break, format_type(t, break)]) |
         format_instr_anno(anno, funcAnno, args)]
  end

  defp format_instr_anno(%{arg_types: ts} = anno0, funcAnno, args) do
    anno = :maps.remove(:arg_types, anno0)
    break = '\n  %%    '
    iota = :lists.seq(0, length(args) - 1)
    formatted0 = (for {idx, arg} <- :lists.zip(iota, args),
                        :erlang.is_map_key(idx, ts) do
                    [format_arg(arg, funcAnno), ' => ',
                                                    format_type(:erlang.map_get(idx,
                                                                                  ts),
                                                                  break)]
                  end)
    formatted = :lists.join(break, formatted0)
    [:io_lib.format('  %% Argument types:~s~ts\n',
                      [break, :unicode.characters_to_list(formatted)]) |
         format_instr_anno(anno, funcAnno, args)]
  end

  defp format_instr_anno(%{aliased: as} = anno, funcAnno, args) do
    break = '\n  %%    '
    ['  %% Aliased:', :string.join(for v <- as do
                       [break, format_var(v)]
                     end,
                       ', '),
            '\n', format_instr_anno(:maps.remove(:aliased, anno),
                                   funcAnno, args)]
  end

  defp format_instr_anno(%{unique: us} = anno, funcAnno, args) do
    break = '\n  %%    '
    ['  %% Unique:', :string.join(for v <- us do
                       [break, format_var(v)]
                     end,
                       ', '),
            '\n', format_instr_anno(:maps.remove(:unique, anno),
                                   funcAnno, args)]
  end

  defp format_instr_anno(anno, _FuncAnno, _Args) do
    format_instr_anno_1(anno)
  end

  defp format_instr_anno_1(anno) do
    case (map_size(anno)) do
      0 ->
        []
      _ ->
        [:io_lib.format('  %% Anno: ~kp\n', [anno])]
    end
  end

  defp format_live_interval(r_b_var() = dst, %{live_intervals: intervals}) do
    case (intervals) do
      %{^dst => rs0} ->
        rs1 = (for {start, end__} <- rs0 do
                 :io_lib.format('~p..~p', [start, end__])
               end)
        rs = :lists.join(' ', rs1)
        :io_lib.format('  %% ~ts: ~s\n', [format_var_1(dst), rs])
      %{} ->
        []
    end
  end

  defp format_live_interval(_, _) do
    []
  end

  def format_type(:any) do
    'any()'
  end

  def format_type(r_t_atom(elements: :any)) do
    'atom()'
  end

  def format_type(r_t_atom(elements: es)) do
    :string.join(for e <- :ordsets.to_list(es) do
                   :io_lib.format('\'~p\'', [e])
                 end,
                   ' | ')
  end

  def format_type(r_t_bs_matchable(tail_unit: u)) do
    :io_lib.format('bs_matchable(~p)', [u])
  end

  def format_type(r_t_bitstring(size_unit: s, appendable: true)) do
    :io_lib.format('bitstring(~p,appendable)', [s])
  end

  def format_type(r_t_bitstring(size_unit: s)) do
    :io_lib.format('bitstring(~p)', [s])
  end

  def format_type(r_t_bs_context(tail_unit: u)) do
    :io_lib.format('bs_context(~p)', [u])
  end

  def format_type(r_t_fun(arity: :any, type: :any)) do
    'fun()'
  end

  def format_type(r_t_fun(arity: :any, type: t)) do
    ['fun((...) -> ', format_type(t), ')']
  end

  def format_type(r_t_fun(arity: a, type: :any)) do
    ['fun((', format_fun_args(a), '))']
  end

  def format_type(r_t_fun(arity: a, type: t)) do
    ['fun((', format_fun_args(a), ') -> ', format_type(t), ')']
  end

  def format_type(r_t_map(super_key: :any, super_value: :any)) do
    'map()'
  end

  def format_type(r_t_map(super_key: :none, super_value: :none)) do
    '\#{}'
  end

  def format_type(r_t_map(super_key: k, super_value: v)) do
    ['\#{', format_type(k), '=>', format_type(v), '}']
  end

  def format_type(:number) do
    'number()'
  end

  def format_type(r_t_float(elements: :any)) do
    'float()'
  end

  def format_type(r_t_float(elements: {x, x})) do
    :io_lib.format('~p', [x])
  end

  def format_type(r_t_float(elements: {low, high})) do
    :io_lib.format('~p..~p', [low, high])
  end

  def format_type(r_t_integer(elements: :any)) do
    'integer()'
  end

  def format_type(r_t_integer(elements: {x, x})) do
    :io_lib.format('~p', [x])
  end

  def format_type(r_t_integer(elements: {low, high})) do
    :io_lib.format('~p..~p', [low, high])
  end

  def format_type(r_t_number(elements: :any)) do
    'number()'
  end

  def format_type(r_t_number(elements: {x, x})) do
    :io_lib.format('number(~p)', [x])
  end

  def format_type(r_t_number(elements: {low, high})) do
    :io_lib.format('number(~p, ~p)', [low, high])
  end

  def format_type(r_t_list(type: eT, terminator: nil)) do
    ['list(', format_type(eT), ')']
  end

  def format_type(r_t_list(type: eT, terminator: tT)) do
    ['maybe_improper_list(', format_type(eT), ', ', format_type(tT), ')']
  end

  def format_type(r_t_cons(type: eT, terminator: nil)) do
    ['nonempty_list(', format_type(eT), ')']
  end

  def format_type(r_t_cons(type: eT, terminator: tT)) do
    ['nonempty_improper_list(', format_type(eT), ', ', format_type(tT), ')']
  end

  def format_type(nil) do
    'nil()'
  end

  def format_type(r_t_tuple(elements: es, exact: ex, size: s)) do
    ['{', :string.join(format_tuple_elems(s, ex, es, 1), ', '),
            '}']
  end

  def format_type(:other) do
    'other()'
  end

  def format_type(:pid) do
    'pid()'
  end

  def format_type(:port) do
    'pid()'
  end

  def format_type(:reference) do
    'reference()'
  end

  def format_type(:identifier) do
    'identifier()'
  end

  def format_type(:none) do
    'none()'
  end

  def format_type(r_t_union(atom: a, list: l, number: n, tuple_set: ts,
             other: o)) do
    es = (case (a) do
            :none ->
              []
            _ ->
              [format_type(a)]
          end) ++ (case (l) do
                     :none ->
                       []
                     _ ->
                       [format_type(l)]
                   end) ++ (case (n) do
                              :none ->
                                []
                              _ ->
                                [format_type(n)]
                            end) ++ (case (ts) do
                                       :none ->
                                         []
                                       _ ->
                                         [format_tuple_set(ts)]
                                     end) ++ (case (o) do
                                                :none ->
                                                  []
                                                _ ->
                                                  [format_type(o)]
                                              end)
    :string.join(es, ' | ')
  end

  defp format_fun_args(a) do
    :string.join(:lists.duplicate(a, '_'), ', ')
  end

  defp format_tuple_elems(size, true, _Elems, idx) when idx > size do
    []
  end

  defp format_tuple_elems(size, false, _Elems, idx) when idx > size do
    ['...']
  end

  defp format_tuple_elems(size, exact, elems, idx) do
    t = (case (elems) do
           %{^idx => ty} ->
             ty
           _ ->
             :any
         end)
    [format_type(t) | format_tuple_elems(size, exact, elems,
                                           idx + 1)]
  end

  defp format_tuple_set(r_t_tuple() = t) do
    format_type(t)
  end

  defp format_tuple_set(recordSet) do
    :string.join(for t <- :ordsets.to_list(recordSet) do
                   format_tuple_set_1(t)
                 end,
                   ' | ')
  end

  defp format_tuple_set_1({{arity, key},
             r_t_tuple(size: arity, elements: elems) = tuple}) do
    ^key = :erlang.map_get(1, elems)
    format_type(tuple)
  end

end