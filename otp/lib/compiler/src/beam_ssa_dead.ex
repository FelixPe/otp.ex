defmodule :m_beam_ssa_dead do
  use Bitwise

  import :lists,
    only: [
      append: 1,
      foldl: 3,
      keymember: 3,
      last: 1,
      member: 2,
      reverse: 1,
      reverse: 2,
      takewhile: 2
    ]

  require Record

  Record.defrecord(:r_b_module, :b_module,
    anno: %{},
    name: :undefined,
    exports: :undefined,
    attributes: :undefined,
    body: :undefined
  )

  Record.defrecord(:r_b_function, :b_function,
    anno: %{},
    args: :undefined,
    bs: :undefined,
    cnt: :undefined
  )

  Record.defrecord(:r_b_blk, :b_blk, anno: %{}, is: :undefined, last: :undefined)
  Record.defrecord(:r_b_set, :b_set, anno: %{}, dst: :none, op: :undefined, args: [])
  Record.defrecord(:r_b_ret, :b_ret, anno: %{}, arg: :undefined)

  Record.defrecord(:r_b_br, :b_br,
    anno: %{},
    bool: :undefined,
    succ: :undefined,
    fail: :undefined
  )

  Record.defrecord(:r_b_switch, :b_switch,
    anno: %{},
    arg: :undefined,
    fail: :undefined,
    list: :undefined
  )

  Record.defrecord(:r_b_var, :b_var, name: :undefined)
  Record.defrecord(:r_b_literal, :b_literal, val: :undefined)
  Record.defrecord(:r_b_remote, :b_remote, mod: :undefined, name: :undefined, arity: :undefined)

  Record.defrecord(:r_b_local, :b_local,
    name: :undefined,
    arity: :undefined
  )

  Record.defrecord(:r_st, :st,
    bs: :undefined,
    us: :undefined,
    skippable: :undefined,
    test: :none,
    target: :any
  )

  def opt(linear0) do
    {used, skippable} = used_vars(linear0)
    blocks0 = :maps.from_list(linear0)
    st0 = r_st(bs: blocks0, us: used, skippable: skippable)
    st = shortcut_opt(st0)
    r_st(bs: blocks) = combine_eqs(r_st(st, us: %{}))
    opt_redundant_tests(blocks)
  end

  defp shortcut_opt(r_st(bs: blocks) = st) do
    ls = :beam_ssa.rpo(blocks)
    shortcut_opt(ls, st)
  end

  defp shortcut_opt([l | ls], r_st(bs: blocks0) = st) do
    r_b_blk(is: is, last: last0) = blk0 = get_block(l, st)

    case shortcut_terminator(last0, is, l, st) do
      ^last0 ->
        shortcut_opt(ls, st)

      last ->
        blk = r_b_blk(blk0, last: last)
        blocks = Map.put(blocks0, l, blk)
        shortcut_opt(ls, r_st(st, bs: blocks))
    end
  end

  defp shortcut_opt([], st) do
    st
  end

  defp shortcut_terminator(r_b_br(bool: r_b_literal(val: true), succ: succ0), _Is, from, st0) do
    st = r_st(st0, test: :none)
    shortcut(succ0, from, %{}, st)
  end

  defp shortcut_terminator(
         r_b_br(bool: r_b_var() = bool, succ: succ0, fail: fail0) = br,
         is,
         from,
         st0
       ) do
    st = r_st(st0, target: :one_way)
    test = get_test(bool, is)
    succBs = bind_var_if_used(succ0, bool, r_b_literal(val: true), st)
    brSucc = shortcut(succ0, from, succBs, r_st(st, test: test))
    failBs = bind_var_if_used(fail0, bool, r_b_literal(val: false), st)
    brFail = shortcut(fail0, from, failBs, r_st(st, test: invert_test(test)))

    case {brSucc, brFail} do
      {r_b_br(bool: r_b_literal(val: true), succ: succ),
       r_b_br(bool: r_b_literal(val: true), succ: fail)}
      when succ !== succ0 or fail !== fail0 ->
        :beam_ssa.normalize(r_b_br(br, succ: succ, fail: fail))

      {_, _} ->
        br
    end
  end

  defp shortcut_terminator(r_b_switch(arg: bool, fail: fail0, list: list0) = sw, _Is, from, st) do
    fail = shortcut_sw_fail(fail0, list0, bool, from, st)
    list = shortcut_sw_list(list0, bool, from, st)
    r_b_switch(sw, fail: fail, list: list)
  end

  defp shortcut_terminator(last, _Is, _From, _St) do
    last
  end

  defp shortcut_sw_fail(fail0, list, bool, from, st0) do
    case list do
      [{r_b_literal(val: false), _}, {r_b_literal(val: true), _}] ->
        test = {{:not, :is_boolean}, bool}
        st = r_st(st0, test: test, target: :one_way)
        r_b_br(bool: r_b_literal(val: true), succ: fail) = shortcut(fail0, from, %{}, st)
        fail

      _ ->
        fail0
    end
  end

  defp shortcut_sw_list([{lit, l0} | t], bool, from, st0) do
    test = {:"=:=", bool, lit}
    st = r_st(st0, test: test)

    r_b_br(bool: r_b_literal(val: true), succ: l) =
      shortcut(l0, from, bind_var(bool, lit, %{}), r_st(st, target: :one_way))

    [{lit, l} | shortcut_sw_list(t, bool, from, st0)]
  end

  defp shortcut_sw_list([], _, _, _) do
    []
  end

  defp shortcut(l, _From, bs, r_st(test: :none, target: :one_way))
       when map_size(bs) === 0 do
    r_b_br(bool: r_b_literal(val: true), succ: l, fail: l)
  end

  defp shortcut(l, from, bs, st) do
    shortcut_1(l, from, bs, :sets.new([{:version, 2}]), st)
  end

  defp shortcut_1(l, from, bs0, unsetVars0, st) do
    case shortcut_2(l, from, bs0, unsetVars0, st) do
      :none ->
        r_b_br(bool: r_b_literal(val: true), succ: l, fail: l)

      {r_b_br(bool: r_b_var()) = br, _, _} ->
        br

      {r_b_br(bool: r_b_literal(val: true), succ: succ), bs, unsetVars} ->
        shortcut_1(succ, l, bs, unsetVars, st)
    end
  end

  defp shortcut_2(l, from, bs, unsetVars, st) do
    case :sets.size(unsetVars) do
      setSize when setSize > 64 ->
        :none

      _SetSize ->
        shortcut_3(l, from, bs, unsetVars, st)
    end
  end

  defp shortcut_3(l, from, bs0, unsetVars0, st) do
    r_b_blk(is: is, last: last) = get_block(l, st)

    case eval_is(is, from, bs0, st) do
      :none ->
        :none

      bs ->
        case eval_terminator(last, bs, st) do
          :none ->
            :none

          r_b_br() = br ->
            case update_unset_vars(l, is, br, unsetVars0, st) do
              :unsafe ->
                shortcut_unsafe_br(br, l, bs, unsetVars0, st)

              unsetVars ->
                shortcut_test_br(br, l, bs, unsetVars, st)
            end
        end
    end
  end

  defp shortcut_test_br(br, from, bs, unsetVars, st) do
    case is_br_safe(unsetVars, br, st) do
      false ->
        shortcut_unsafe_br(br, from, bs, unsetVars, st)

      true ->
        shortcut_safe_br(br, from, bs, unsetVars, st)
    end
  end

  defp shortcut_unsafe_br(br, from, bs, unsetVars, r_st(target: target) = st) do
    case br do
      r_b_br(bool: r_b_literal(val: true), succ: l) ->
        case target do
          ^l ->
            :none

          _ ->
            shortcut_2(l, from, bs, unsetVars, st)
        end

      r_b_br(bool: r_b_var(), succ: succ, fail: fail) ->
        case {succ, fail} do
          {l, ^target} ->
            shortcut_2(l, from, bs, unsetVars, st)

          {^target, l} ->
            shortcut_2(l, from, bs, unsetVars, st)

          {_, _} ->
            case target do
              :any ->
                shortcut_two_way(br, from, bs, unsetVars, st)

              :one_way ->
                shortcut_two_way(br, from, bs, unsetVars, st)

              _ when is_integer(target) ->
                :none
            end
        end
    end
  end

  defp shortcut_safe_br(br, from, bs, unsetVars, r_st(target: target) = st) do
    case br do
      r_b_br(bool: r_b_literal(val: true), succ: l) ->
        case target do
          :any ->
            {br, bs, unsetVars}

          :one_way ->
            {br, bs, unsetVars}

          ^l when is_integer(target) ->
            {br, bs, unsetVars}

          _ when is_integer(target) ->
            shortcut_2(l, from, bs, unsetVars, st)
        end

      r_b_br(bool: r_b_var()) ->
        cond do
          target === :any or target === :one_way ->
            case shortcut_two_way(br, from, bs, unsetVars, st) do
              :none when target === :any ->
                {br, bs, unsetVars}

              :none when target === :one_way ->
                :none

              {_, _, _} = res ->
                res
            end

          is_integer(target) ->
            :none
        end
    end
  end

  defp update_unset_vars(l, is, br, unsetVars, r_st(skippable: skippable)) do
    case :erlang.is_map_key(l, skippable) do
      true ->
        case br do
          r_b_br(bool: r_b_var() = bool) ->
            case keymember(bool, r_b_set(:dst), is) do
              true ->
                :unsafe

              false ->
                unsetVars
            end

          r_b_br() ->
            unsetVars
        end

      false ->
        setInThisBlock =
          for r_b_set(dst: v) <- is do
            v
          end

        list_set_union(setInThisBlock, unsetVars)
    end
  end

  defp shortcut_two_way(r_b_br(succ: succ, fail: fail), from, bs0, unsetVars0, st0) do
    case shortcut_2(succ, from, bs0, unsetVars0, r_st(st0, target: fail)) do
      {r_b_br(bool: r_b_literal(), succ: ^fail), _, _} = res ->
        res

      :none ->
        st = r_st(st0, target: succ)

        case shortcut_2(fail, from, bs0, unsetVars0, st) do
          {r_b_br(bool: r_b_literal(), succ: ^succ), _, _} = res ->
            res

          :none ->
            :none
        end
    end
  end

  defp get_block(l, st) do
    r_st(bs: %{^l => blk}) = st
    blk
  end

  defp is_br_safe(unsetVars, br, r_st(us: us) = st) do
    case br do
      r_b_br(bool: r_b_var() = v, succ: succ, fail: fail) ->
        %{^succ => used0, ^fail => used1} = us

        not :sets.is_element(
          v,
          unsetVars
        ) and
          :sets.is_disjoint(
            used0,
            unsetVars
          ) and
          :sets.is_disjoint(
            used1,
            unsetVars
          )

      r_b_br(succ: same, fail: same) ->
        not is_forbidden(
          same,
          st
        ) and
          :sets.is_disjoint(
            :erlang.map_get(same, us),
            unsetVars
          )
    end
  end

  defp is_forbidden(l, st) do
    case get_block(l, st) do
      r_b_blk(is: [r_b_set(op: :phi) | _]) ->
        true

      r_b_blk(is: [r_b_set() = i | _]) ->
        :beam_ssa.is_loop_header(i)

      r_b_blk() ->
        false
    end
  end

  defp eval_is([r_b_set(op: :phi, dst: dst, args: args) | is], from, bs0, st) do
    val = get_phi_arg(args, from)
    bs = bind_var(dst, val, bs0)
    eval_is(is, from, bs, st)
  end

  defp eval_is([r_b_set(op: {:succeeded, :guard}, dst: dst, args: [var])], _From, bs, _St) do
    case bs do
      %{^var => r_b_literal()} ->
        bind_var(dst, r_b_literal(val: true), bs)

      %{} ->
        bs
    end
  end

  defp eval_is([r_b_set(op: {:bif, _}, dst: dst) = i0 | is], from, bs, st) do
    i = sub(i0, bs)

    case eval_bif(i, st) do
      r_b_literal() = val ->
        eval_is(is, from, bind_var(dst, val, bs), st)

      :none ->
        eval_is(is, from, bs, st)
    end
  end

  defp eval_is([r_b_set(op: op, dst: dst) = i | is], from, bs, st)
       when op === :is_tagged_tuple or
              op === :is_nonempty_list do
    r_b_set(args: args) = sub(i, bs)

    case eval_test(op, args, st) do
      r_b_literal() = val ->
        eval_is(is, from, bind_var(dst, val, bs), st)

      :none ->
        eval_is(is, from, bs, st)
    end
  end

  defp eval_is([r_b_set() = i | is], from, bs, st) do
    case :beam_ssa.no_side_effect(i) do
      true ->
        eval_is(is, from, bs, st)

      false ->
        :none
    end
  end

  defp eval_is([], _From, bs, _St) do
    bs
  end

  defp get_phi_arg([{val, from} | _], from) do
    val
  end

  defp get_phi_arg([_ | as], from) do
    get_phi_arg(as, from)
  end

  defp eval_terminator(r_b_br(bool: r_b_var() = bool) = br, bs, _St) do
    case get_value(bool, bs) do
      r_b_literal(val: val) = lit ->
        case is_boolean(val) do
          true ->
            :beam_ssa.normalize(r_b_br(br, bool: lit))

          false ->
            :none
        end

      r_b_var() = var ->
        :beam_ssa.normalize(r_b_br(br, bool: var))
    end
  end

  defp eval_terminator(r_b_br(bool: r_b_literal()) = br, _Bs, _St) do
    :beam_ssa.normalize(br)
  end

  defp eval_terminator(r_b_switch(arg: arg, fail: fail, list: list) = sw, bs, st) do
    case get_value(arg, bs) do
      r_b_literal() = val ->
        :beam_ssa.normalize(r_b_switch(sw, arg: val))

      r_b_var() ->
        case eval_switch(list, arg, st, fail) do
          :none ->
            :none

          to when is_integer(to) ->
            r_b_br(bool: r_b_literal(val: true), succ: to, fail: to)
        end
    end
  end

  defp eval_terminator(r_b_ret(), _Bs, _St) do
    :none
  end

  defp eval_switch(list, arg, r_st(test: {_, arg, _} = prevOp), fail) do
    eval_switch_1(list, arg, prevOp, fail)
  end

  defp eval_switch(_, _, _, _) do
    :none
  end

  defp eval_switch_1([{lit, lbl} | t], arg, prevOp, fail) do
    test = {:"=:=", arg, lit}

    case will_succeed(prevOp, test) do
      :yes ->
        lbl

      :no ->
        eval_switch_1(t, arg, prevOp, fail)

      :maybe ->
        eval_switch_1(t, arg, prevOp, :none)
    end
  end

  defp eval_switch_1([], _Arg, _PrevOp, fail) do
    fail
  end

  defp bind_var_if_used(l, var, val, r_st(us: us)) do
    case :sets.is_element(var, :erlang.map_get(l, us)) do
      true ->
        %{var => val}

      false ->
        %{}
    end
  end

  defp bind_var(var, val0, bs) do
    val = get_value(val0, bs)
    Map.put(bs, var, val)
  end

  defp get_value(r_b_var() = var, bs) do
    case bs do
      %{^var => val} ->
        get_value(val, bs)

      %{} ->
        var
    end
  end

  defp get_value(r_b_literal() = lit, _Bs) do
    lit
  end

  defp eval_bif(r_b_set(op: {:bif, bif}, args: args), st) do
    arity = length(args)

    case :erl_bifs.is_pure(:erlang, bif, arity) do
      false ->
        :none

      true ->
        case get_lit_args(args) do
          :none ->
            eval_test({:bif, bif}, args, st)

          litArgs ->
            try do
              apply(:erlang, bif, litArgs)
            catch
              :error, _ ->
                :none
            else
              val ->
                r_b_literal(val: val)
            end
        end
    end
  end

  defp get_lit_args([r_b_literal(val: lit1)]) do
    [lit1]
  end

  defp get_lit_args([r_b_literal(val: lit1), r_b_literal(val: lit2)]) do
    [lit1, lit2]
  end

  defp get_lit_args([r_b_literal(val: lit1), r_b_literal(val: lit2), r_b_literal(val: lit3)]) do
    [lit1, lit2, lit3]
  end

  defp get_lit_args(_) do
    :none
  end

  defp get_test(bool, [_ | _] = is) do
    case last(is) do
      r_b_set(op: op, dst: ^bool, args: args) ->
        normalize_test(op, args)

      r_b_set() ->
        :none
    end
  end

  defp get_test(_, []) do
    :none
  end

  defp normalize_test(
         :is_tagged_tuple,
         [arg, r_b_literal(val: size), r_b_literal(val: tag)]
       )
       when is_integer(size) and is_atom(tag) do
    {{:is_tagged_tuple, size, tag}, arg}
  end

  defp normalize_test(:is_nonempty_list, [arg]) do
    {:is_nonempty_list, arg}
  end

  defp normalize_test({:bif, bif}, [arg]) do
    case :erl_internal.new_type_test(bif, 1) do
      true ->
        {bif, arg}

      false ->
        :none
    end
  end

  defp normalize_test({:bif, bif}, [_, _] = args) do
    case :erl_internal.comp_op(bif, 2) do
      true ->
        normalize_test_1(bif, args)

      false ->
        :none
    end
  end

  defp normalize_test(_, _) do
    :none
  end

  defp normalize_test_1(bif, args) do
    case args do
      [r_b_literal() = arg1, r_b_var() = arg2] ->
        {turn_op(bif), arg2, arg1}

      [r_b_var() = arg1, r_b_literal() = arg2] ->
        {bif, arg1, arg2}

      [r_b_var() = a, r_b_var() = b] ->
        cond do
          a < b ->
            {bif, a, b}

          true ->
            {turn_op(bif), b, a}
        end

      [r_b_literal(), r_b_literal()] ->
        :none
    end
  end

  defp invert_test({op, arg1, arg2}) do
    {invert_op(op), arg1, arg2}
  end

  defp invert_test({typeTest, arg}) do
    {{:not, typeTest}, arg}
  end

  defp invert_test(:none) do
    :none
  end

  defp invert_op(:>=) do
    :<
  end

  defp invert_op(:<) do
    :>=
  end

  defp invert_op(:"=<") do
    :>
  end

  defp invert_op(:>) do
    :"=<"
  end

  defp invert_op(:"=:=") do
    :"=/="
  end

  defp invert_op(:"=/=") do
    :"=:="
  end

  defp invert_op(:==) do
    :"/="
  end

  defp invert_op(:"/=") do
    :==
  end

  defp turn_op(:<) do
    :>
  end

  defp turn_op(:"=<") do
    :>=
  end

  defp turn_op(:>) do
    :<
  end

  defp turn_op(:>=) do
    :"=<"
  end

  defp turn_op(:"=:=" = op) do
    op
  end

  defp turn_op(:"=/=" = op) do
    op
  end

  defp turn_op(:== = op) do
    op
  end

  defp turn_op(:"/=" = op) do
    op
  end

  defp eval_test(_Bif, _Args, r_st(test: :none)) do
    :none
  end

  defp eval_test(bif, args, r_st(test: prev)) do
    case normalize_test(bif, args) do
      :none ->
        :none

      test ->
        case will_succeed(prev, test) do
          :yes ->
            r_b_literal(val: true)

          :no ->
            r_b_literal(val: false)

          :maybe ->
            :none
        end
    end
  end

  defp will_succeed({_, _, _} = same, {_, _, _} = same) do
    :yes
  end

  defp will_succeed({op1, var, r_b_literal(val: a)}, {op2, var, r_b_literal(val: b)}) do
    will_succeed_1(op1, a, op2, b)
  end

  defp will_succeed({op1, var, r_b_var() = a}, {op2, var, r_b_var() = b}) do
    will_succeed_vars(op1, a, op2, b)
  end

  defp will_succeed({:"=:=", var, r_b_literal(val: a)}, {typeTest, var}) do
    eval_type_test(typeTest, a)
  end

  defp will_succeed({_, _} = same, {_, _} = same) do
    :yes
  end

  defp will_succeed({test1, var}, {test2, var}) do
    will_succeed_test(test1, test2)
  end

  defp will_succeed(
         {{:not, :is_boolean}, var},
         {:"=:=", var, r_b_literal(val: lit)}
       )
       when is_boolean(lit) do
    :no
  end

  defp will_succeed({_, _}, {_, _}) do
    :maybe
  end

  defp will_succeed({_, _}, {_, _, _}) do
    :maybe
  end

  defp will_succeed({_, _, _}, {_, _}) do
    :maybe
  end

  defp will_succeed({_, _, _}, {_, _, _}) do
    :maybe
  end

  defp will_succeed_test({:not, test1}, test2) do
    case test1 === test2 do
      true ->
        :no

      false ->
        :maybe
    end
  end

  defp will_succeed_test(:is_tuple, {:is_tagged_tuple, _, _}) do
    :maybe
  end

  defp will_succeed_test({:is_tagged_tuple, _, _}, :is_tuple) do
    :yes
  end

  defp will_succeed_test(:is_list, :is_nonempty_list) do
    :maybe
  end

  defp will_succeed_test(:is_nonempty_list, :is_list) do
    :yes
  end

  defp will_succeed_test(_T1, _T2) do
    :maybe
  end

  defp will_succeed_1(:"=:=", a, :<, b) do
    cond do
      b <= a ->
        :no

      true ->
        :yes
    end
  end

  defp will_succeed_1(:"=:=", a, :"=<", b) do
    cond do
      b < a ->
        :no

      true ->
        :yes
    end
  end

  defp will_succeed_1(:"=:=", a, :"=:=", b) when a !== b do
    :no
  end

  defp will_succeed_1(:"=:=", a, :"=/=", b) do
    cond do
      a === b ->
        :no

      true ->
        :yes
    end
  end

  defp will_succeed_1(:"=:=", a, :>=, b) do
    cond do
      b > a ->
        :no

      true ->
        :yes
    end
  end

  defp will_succeed_1(:"=:=", a, :>, b) do
    cond do
      b >= a ->
        :no

      true ->
        :yes
    end
  end

  defp will_succeed_1(:"=/=", a, :"=:=", b) when a === b do
    :no
  end

  defp will_succeed_1(:<, a, :"=:=", b) when b >= a do
    :no
  end

  defp will_succeed_1(:<, a, :<, b) when b >= a do
    :yes
  end

  defp will_succeed_1(:<, a, :"=<", b) when b >= a do
    :yes
  end

  defp will_succeed_1(:<, a, :>=, b) when b >= a do
    :no
  end

  defp will_succeed_1(:<, a, :>, b) when b >= a do
    :no
  end

  defp will_succeed_1(:"=<", a, :"=:=", b) when b > a do
    :no
  end

  defp will_succeed_1(:"=<", a, :<, b) when b > a do
    :yes
  end

  defp will_succeed_1(:"=<", a, :"=<", b) when b >= a do
    :yes
  end

  defp will_succeed_1(:"=<", a, :>=, b) when b > a do
    :no
  end

  defp will_succeed_1(:"=<", a, :>, b) when b >= a do
    :no
  end

  defp will_succeed_1(:>=, a, :"=:=", b) when b < a do
    :no
  end

  defp will_succeed_1(:>=, a, :<, b) when b <= a do
    :no
  end

  defp will_succeed_1(:>=, a, :"=<", b) when b < a do
    :no
  end

  defp will_succeed_1(:>=, a, :>=, b) when b <= a do
    :yes
  end

  defp will_succeed_1(:>=, a, :>, b) when b < a do
    :yes
  end

  defp will_succeed_1(:>, a, :"=:=", b) when b <= a do
    :no
  end

  defp will_succeed_1(:>, a, :<, b) when b <= a do
    :no
  end

  defp will_succeed_1(:>, a, :"=<", b) when b <= a do
    :no
  end

  defp will_succeed_1(:>, a, :>=, b) when b <= a do
    :yes
  end

  defp will_succeed_1(:>, a, :>, b) when b <= a do
    :yes
  end

  defp will_succeed_1(:==, a, :==, b) do
    cond do
      a == b ->
        :yes

      true ->
        :no
    end
  end

  defp will_succeed_1(:==, a, :"/=", b) do
    cond do
      a == b ->
        :no

      true ->
        :yes
    end
  end

  defp will_succeed_1(:"/=", a, :"/=", b) when a == b do
    :yes
  end

  defp will_succeed_1(:"/=", a, :==, b) when a == b do
    :no
  end

  defp will_succeed_1(_, _, _, _) do
    :maybe
  end

  defp will_succeed_vars(:"=/=", val, :"=:=", val) do
    :no
  end

  defp will_succeed_vars(:"=:=", val, :"=/=", val) do
    :no
  end

  defp will_succeed_vars(:"=:=", val, :>=, val) do
    :yes
  end

  defp will_succeed_vars(:"=:=", val, :"=<", val) do
    :yes
  end

  defp will_succeed_vars(:"/=", val1, :==, val2) when val1 == val2 do
    :no
  end

  defp will_succeed_vars(:==, val1, :"/=", val2) when val1 == val2 do
    :no
  end

  defp will_succeed_vars(_, _, _, _) do
    :maybe
  end

  defp eval_type_test(test, arg) do
    case eval_type_test_1(test, arg) do
      true ->
        :yes

      false ->
        :no
    end
  end

  defp eval_type_test_1(:is_nonempty_list, arg) do
    case arg do
      [_ | _] ->
        true

      _ ->
        false
    end
  end

  defp eval_type_test_1({:is_tagged_tuple, sz, tag}, arg) do
    cond do
      tuple_size(arg) === sz and
          :erlang.element(1, arg) === tag ->
        true

      true ->
        false
    end
  end

  defp eval_type_test_1(test, arg) do
    apply(:erlang, test, [arg])
  end

  defp combine_eqs(r_st(bs: blocks) = st) do
    ls = reverse(:beam_ssa.rpo(blocks))
    combine_eqs_1(ls, st)
  end

  defp combine_eqs_1([l | ls], r_st(bs: blocks0) = st0) do
    case comb_get_sw(l, st0) do
      :none ->
        combine_eqs_1(ls, st0)

      {_, arg, _, fail0, list0} ->
        case comb_get_sw(fail0, st0) do
          {true, ^arg, fail1, fail, list1} ->
            case combine_lists(fail1, list0, list1, blocks0) do
              :none ->
                combine_eqs_1(ls, st0)

              list ->
                st = combine_build_sw(l, arg, fail, list, st0)
                combine_eqs_1(ls, st)
            end

          _ ->
            [{_, succ} | _] = list0

            case comb_get_sw(succ, st0) do
              {true, ^arg, _, _, _} ->
                st = combine_build_sw(l, arg, fail0, list0, st0)
                combine_eqs_1(ls, st)

              _ ->
                combine_eqs_1(ls, st0)
            end
        end
    end
  end

  defp combine_eqs_1([], st) do
    st
  end

  defp combine_build_sw(from, arg, fail, list, r_st(bs: blocks0) = st) do
    sw0 = r_b_switch(arg: arg, fail: fail, list: list)
    sw = :beam_ssa.normalize(sw0)
    blk0 = :erlang.map_get(from, blocks0)
    blk = r_b_blk(blk0, last: sw)
    blocks = %{blocks0 | from => blk}
    r_st(st, bs: blocks)
  end

  defp comb_get_sw(l, r_st(bs: blocks, skippable: skippable)) do
    r_b_blk(is: is, last: last) = :erlang.map_get(l, blocks)
    safe0 = :erlang.is_map_key(l, skippable)

    case last do
      r_b_ret() ->
        :none

      r_b_br(bool: r_b_var() = bool, succ: succ, fail: fail) ->
        case comb_is(is, bool, safe0) do
          {:none, safe} ->
            {safe, bool, l, fail, [{r_b_literal(val: true), succ}]}

          {r_b_set(op: {:bif, :"=:="}, args: [r_b_var() = arg, r_b_literal() = lit]), safe} ->
            {safe, arg, l, fail, [{lit, succ}]}

          {r_b_set(op: {:bif, :is_boolean}, args: [r_b_var() = arg]), safe} ->
            swList = [{r_b_literal(val: false), succ}, {r_b_literal(val: true), succ}]
            {safe, arg, l, fail, swList}

          {r_b_set(), _} ->
            :none
        end

      r_b_br() ->
        :none

      r_b_switch(arg: r_b_var() = arg, fail: fail, list: list) ->
        {:none, safe} = comb_is(is, :none, safe0)
        {safe, arg, l, fail, list}
    end
  end

  defp comb_is([r_b_set(dst: r_b_var() = bool) = i], bool, safe) do
    {i, safe}
  end

  defp comb_is([r_b_set() = i | is], bool, safe0) do
    safe = safe0 and :beam_ssa.no_side_effect(i)
    comb_is(is, bool, safe)
  end

  defp comb_is([], _Bool, safe) do
    {:none, safe}
  end

  defp combine_lists(fail, l1, l2, blocks) do
    ls =
      :beam_ssa.rpo(
        for {_, lbl} <- l1 do
          lbl
        end,
        blocks
      )

    case member(fail, ls) do
      true ->
        :none

      false ->
        combine_lists_1(l1, l2)
    end
  end

  defp combine_lists_1(list0, list1) do
    case are_lists_compatible(list0, list1) do
      true ->
        first = :maps.from_list(list0)

        list0 ++
          for {val, lbl} <- list1,
              not :erlang.is_map_key(val, first) do
            {val, lbl}
          end

      false ->
        :none
    end
  end

  defp are_lists_compatible(
         [{r_b_literal(val: val1), _} | _],
         [{r_b_literal(val: val2), _} | _]
       ) do
    case lit_type(val1) do
      :none ->
        false

      type ->
        type === lit_type(val2)
    end
  end

  defp lit_type(val) do
    cond do
      is_atom(val) ->
        :atom

      is_float(val) ->
        :float

      is_integer(val) ->
        :integer

      true ->
        :none
    end
  end

  defp opt_redundant_tests(blocks) do
    all = %{0 => %{}, 1 => %{}}
    rPO = :beam_ssa.rpo(blocks)
    linear = opt_redundant_tests(rPO, blocks, all)
    :beam_ssa.trim_unreachable(linear)
  end

  defp opt_redundant_tests([l | ls], blocks, all0) do
    case all0 do
      %{^l => tests} ->
        blk0 = :erlang.map_get(l, blocks)
        ^tests = :erlang.map_get(l, all0)
        blk1 = opt_switch(blk0, tests)
        r_b_blk(is: is0) = blk1

        case opt_redundant_tests_is(is0, tests, []) do
          :none ->
            all = update_successors(blk1, tests, all0)
            [{l, blk1} | opt_redundant_tests(ls, blocks, all)]

          {:new_test, bool, test, mustInvert} ->
            all = update_successors(blk1, bool, test, mustInvert, tests, all0)
            [{l, blk1} | opt_redundant_tests(ls, blocks, all)]

          {:old_test, is, boolVar, boolValue} ->
            blk =
              case blk1 do
                r_b_blk(last: r_b_br(bool: ^boolVar) = br0) ->
                  br = :beam_ssa.normalize(r_b_br(br0, bool: boolValue))
                  r_b_blk(blk1, is: is, last: br)

                r_b_blk() = blk2 ->
                  r_b_blk(blk2, is: is)
              end

            all = update_successors(blk, tests, all0)
            [{l, blk} | opt_redundant_tests(ls, blocks, all)]
        end

      %{} ->
        opt_redundant_tests(ls, blocks, all0)
    end
  end

  defp opt_redundant_tests([], _Blocks, _All) do
    []
  end

  defp opt_switch(
         r_b_blk(last: r_b_switch(arg: arg, list: list0) = sw) = blk,
         tests
       )
       when map_size(tests) !== 0 do
    list = opt_switch_1(list0, arg, tests)
    r_b_blk(blk, last: r_b_switch(sw, list: list))
  end

  defp opt_switch(blk, _Tests) do
    blk
  end

  defp opt_switch_1([{lit, _} = h | t], arg, tests) do
    case tests do
      %{{:"=:=", ^arg, ^lit} => false} ->
        opt_switch_1(t, arg, tests)

      %{} ->
        [h | opt_switch_1(t, arg, tests)]
    end
  end

  defp opt_switch_1([], _, _) do
    []
  end

  defp opt_redundant_tests_is([r_b_set(op: op, args: args, dst: bool) = i0], tests, acc) do
    case canonical_test(op, args) do
      :none ->
        :none

      {test, mustInvert} ->
        case old_result(test, tests) do
          result0 when is_boolean(result0) ->
            result = r_b_literal(val: :erlang.xor(result0, mustInvert))
            i = r_b_set(i0, op: {:bif, :"=:="}, args: [result, r_b_literal(val: true)])
            {:old_test, reverse(acc, [i]), bool, result}

          :none ->
            {:new_test, bool, test, mustInvert}
        end
    end
  end

  defp opt_redundant_tests_is([i | is], tests, acc) do
    opt_redundant_tests_is(is, tests, [i | acc])
  end

  defp opt_redundant_tests_is([], _Tests, _Acc) do
    :none
  end

  defp old_result(test, tests) do
    case tests do
      %{^test => val} ->
        val

      %{} ->
        old_result_1(test, tests)
    end
  end

  defp old_result_1({:==, a, b}, tests) do
    case tests do
      %{{:<, ^a, ^b} => false, {:"=<", ^a, ^b} => true} ->
        true

      %{} ->
        :none
    end
  end

  defp old_result_1({:"=<", a, b}, tests) do
    case tests do
      %{{:<, ^a, ^b} => false, {:==, ^a, ^b} => false} ->
        false

      %{} ->
        :none
    end
  end

  defp old_result_1({:<, a, b}, tests) do
    case tests do
      %{{:"=<", ^a, ^b} => true, {:==, ^a, ^b} => false} ->
        true

      %{} ->
        :none
    end
  end

  defp old_result_1({:is_nonempty_list, a}, tests) do
    case tests do
      %{{:is_list, ^a} => false} ->
        false

      %{} ->
        :none
    end
  end

  defp old_result_1(_, _) do
    :none
  end

  defp canonical_test(op, args) do
    case normalize_test(op, args) do
      :none ->
        :none

      test ->
        inv =
          case test do
            {:"=/=", _, _} ->
              true

            {:"/=", _, _} ->
              true

            {:>, _, _} ->
              true

            {:>=, _, _} ->
              true

            _ ->
              false
          end

        case inv do
          true ->
            {invert_test(test), true}

          false ->
            {test, false}
        end
    end
  end

  defp update_successors(
         r_b_blk(last: r_b_br(bool: bool, succ: succ, fail: fail)),
         bool,
         test,
         mustInvert,
         tests,
         all0
       ) do
    all1 = update_successor(succ, Map.put(tests, test, not mustInvert), all0)
    update_successor(fail, Map.put(tests, test, mustInvert), all1)
  end

  defp update_successors(blk, _, _, _, testsA, all) do
    update_successors(blk, testsA, all)
  end

  defp update_successors(r_b_blk(last: r_b_ret()), _Tests, all) do
    all
  end

  defp update_successors(r_b_blk(last: r_b_switch(arg: arg, fail: fail, list: list)), tests, all0) do
    all1 = update_successors_sw_fail(list, arg, fail, tests, all0)
    update_successors_sw(list, arg, tests, all1)
  end

  defp update_successors(blk, tests, all) do
    foldl(
      fn l, a ->
        update_successor(l, tests, a)
      end,
      all,
      :beam_ssa.successors(blk)
    )
  end

  defp update_successors_sw_fail(list, arg, fail, tests0, all) do
    tests =
      foldl(
        fn {lit, _}, a ->
          Map.put(a, {:"=:=", arg, lit}, false)
        end,
        tests0,
        list
      )

    update_successor(fail, tests, all)
  end

  defp update_successors_sw([{lit, l} | t], arg, tests, all0) do
    all = update_successor(l, Map.put(tests, {:"=:=", arg, lit}, true), all0)
    update_successors_sw(t, arg, tests, all)
  end

  defp update_successors_sw([], _, _, all) do
    all
  end

  defp update_successor(1, _Tests, all) do
    all
  end

  defp update_successor(l, testsA, all0) do
    case all0 do
      %{^l => testsB} ->
        %{all0 | l => maps_intersect_kv(testsA, testsB)}

      %{} ->
        Map.put(all0, l, testsA)
    end
  end

  defp maps_intersect_kv(map, map) do
    map
  end

  defp maps_intersect_kv(map1, map2) do
    cond do
      map_size(map1) < map_size(map2) ->
        map_intersect_kv_1(map1, map2)

      true ->
        map_intersect_kv_1(map2, map1)
    end
  end

  defp map_intersect_kv_1(smallMap, bigMap) do
    next = :maps.next(:maps.iterator(smallMap))

    case maps_is_subset_kv(next, bigMap) do
      true ->
        smallMap

      false ->
        map_intersect_kv_2(next, bigMap, [])
    end
  end

  defp map_intersect_kv_2({k, v, iterator}, bigMap, acc) do
    next = :maps.next(iterator)

    case bigMap do
      %{^k => ^v} ->
        map_intersect_kv_2(next, bigMap, [{k, v} | acc])

      %{} ->
        map_intersect_kv_2(next, bigMap, acc)
    end
  end

  defp map_intersect_kv_2(:none, _BigMap, acc) do
    :maps.from_list(acc)
  end

  defp maps_is_subset_kv({k, v, iterator}, bigMap) do
    next = :maps.next(iterator)

    case bigMap do
      %{^k => ^v} ->
        maps_is_subset_kv(next, bigMap)

      %{} ->
        false
    end
  end

  defp maps_is_subset_kv(:none, _BigMap) do
    true
  end

  defp used_vars(linear) do
    used_vars(reverse(linear), %{}, %{})
  end

  defp used_vars([{l, r_b_blk(is: is) = blk} | bs], usedVars0, skip0) do
    successors = :beam_ssa.successors(blk)
    used0 = used_vars_succ(successors, l, usedVars0, :sets.new([{:version, 2}]))
    used = used_vars_blk(blk, used0)
    usedVars = used_vars_phis(is, l, used, usedVars0)

    defined0 =
      for r_b_set(dst: def__) <- is do
        def__
      end

    defined = :sets.from_list(defined0, [{:version, 2}])
    maySkip = :sets.is_disjoint(defined, used0)

    case maySkip do
      true ->
        skip = Map.put(skip0, l, true)
        used_vars(bs, usedVars, skip)

      false ->
        used_vars(bs, usedVars, skip0)
    end
  end

  defp used_vars([], usedVars, skip) do
    {usedVars, skip}
  end

  defp used_vars_succ([s | ss], l, liveMap, live0) do
    key = {s, l}

    case liveMap do
      %{^key => live} ->
        used_vars_succ(ss, l, liveMap, :sets.union(live, live0))

      %{^s => live} ->
        used_vars_succ(ss, l, liveMap, :sets.union(live, live0))

      %{} ->
        used_vars_succ(ss, l, liveMap, live0)
    end
  end

  defp used_vars_succ([], _, _, acc) do
    acc
  end

  defp used_vars_blk(r_b_blk(is: is, last: last), used0) do
    used = list_set_union(:beam_ssa.used(last), used0)
    used_vars_is(reverse(is), used)
  end

  defp used_vars_is([r_b_set(op: :phi) | is], used) do
    used_vars_is(is, used)
  end

  defp used_vars_is([r_b_set(dst: dst) = i | is], used0) do
    used1 = list_set_union(:beam_ssa.used(i), used0)
    used = :sets.del_element(dst, used1)
    used_vars_is(is, used)
  end

  defp used_vars_is([], used) do
    used
  end

  defp list_set_union([], set) do
    set
  end

  defp list_set_union([e], set) do
    :sets.add_element(e, set)
  end

  defp list_set_union(list, set) do
    :sets.union(:sets.from_list(list, [{:version, 2}]), set)
  end

  defp sub(r_b_set(args: args) = i, sub)
       when map_size(sub) !== 0 do
    r_b_set(i,
      args:
        for a <- args do
          sub_arg(a, sub)
        end
    )
  end

  defp sub(i, _Sub) do
    i
  end

  defp sub_arg(r_b_var() = old, sub) do
    case sub do
      %{^old => new} ->
        new

      %{} ->
        old
    end
  end

  defp sub_arg(old, _Sub) do
    old
  end

  defp rel2fam(s0) do
    s1 = :sofs.relation(s0)
    s = :sofs.rel2fam(s1)
    :sofs.to_external(s)
  end
end
