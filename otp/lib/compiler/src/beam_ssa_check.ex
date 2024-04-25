defmodule :m_beam_ssa_check do
  use Bitwise
  import :lists, only: [flatten: 1, reverse: 1]
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

  def module(r_b_module(body: body), tag) do
    errors = functions(tag, body)

    case errors do
      [] ->
        :ok

      _ ->
        {:error, reverse(errors)}
    end
  end

  defp functions(tag, [f | rest]) do
    function(tag, f) ++ functions(tag, rest)
  end

  defp functions(_Tag, []) do
    []
  end

  defp function(tag, f) do
    run_checks(:beam_ssa.get_anno(:ssa_checks, f, []), f, tag)
  end

  defp run_checks(
         [
           {:ssa_check_when, wantedResult, {:atom, _, tag}, args, exprs}
           | checks
         ],
         f,
         tag
       ) do
    check_function(args, exprs, wantedResult, f) ++ run_checks(checks, f, tag)
  end

  defp run_checks([_ | checks], f, tag) do
    run_checks(checks, f, tag)
  end

  defp run_checks([], _, _) do
    []
  end

  defp check_function(checkArgs, exprs, {:atom, loc, :pass}, r_b_function(args: _Args) = f) do
    run_check(checkArgs, exprs, loc, f)
  end

  defp check_function(checkArgs, exprs, {:atom, loc, key}, r_b_function(args: _Args) = f)
       when key === :fail or key === :xfail do
    case run_check(checkArgs, exprs, loc, f) do
      [] ->
        {file, _} = :beam_ssa.get_anno(:location, f)
        [{file, [{loc, :beam_ssa_check, :xfail_passed}]}]

      _ ->
        []
    end
  end

  defp check_function(_, _, {:atom, loc, result}, f) do
    {file, _} = :beam_ssa.get_anno(:location, f)
    [{file, [{loc, :beam_ssa_check, {:unknown_result_kind, result}}]}]
  end

  defp run_check(checkArgs, exprs, loc, r_b_function(args: funArgs) = f) do
    init_and_run_check(checkArgs, funArgs, %{}, loc, exprs, f)
  end

  defp init_and_run_check([{:var, loc, :_} | checkArgs], [r_b_var() | funArgs], env, _, exprs, f) do
    init_and_run_check(checkArgs, funArgs, env, loc, exprs, f)
  end

  defp init_and_run_check(
         [{:var, loc, checkV} | checkArgs],
         [v = r_b_var() | funArgs],
         env,
         _,
         exprs,
         f
       ) do
    init_and_run_check(checkArgs, funArgs, Map.put(env, checkV, v), loc, exprs, f)
  end

  defp init_and_run_check([{:..., _}], [_ | _], env, _Loc, exprs, f) do
    check_exprs(exprs, env, f)
  end

  defp init_and_run_check([], [], env, _Loc, exprs, f) do
    check_exprs(exprs, env, f)
  end

  defp init_and_run_check([], _, _Env, loc, _Exprs, f) do
    {file, _} = :beam_ssa.get_anno(:location, f)
    [{file, [{loc, :beam_ssa_check, :too_few_pattern_args}]}]
  end

  defp init_and_run_check(_, [], _Env, loc, _Exprs, f) do
    {file, _} = :beam_ssa.get_anno(:location, f)
    [{file, [{loc, :beam_ssa_check, :too_many_pattern_args}]}]
  end

  defp check_exprs(exprs, env, r_b_function(bs: blocks) = f) do
    code =
      :lists.foldr(
        fn lbl, acc ->
          r_b_blk(is: is, last: last) =
            :erlang.map_get(
              lbl,
              blocks
            )

          [{:label, lbl} | is] ++ [last] ++ acc
        end,
        [],
        :beam_ssa.rpo(blocks)
      )

    :skip
    :skip
    :skip
    {file, _} = :beam_ssa.get_anno(:location, f)
    check_expr_seq(exprs, code, env, :never, file)
  end

  defp check_expr_seq(
         [
           {:check_expr, loc, args, anno}
           | rest
         ] = checks,
         [first | code],
         env0,
         lastMatchedLoc,
         file
       ) do
    env =
      try do
        :skip
        op_check(args, anno, first, env0)
      catch
        :no_match ->
          :skip
          false

        :error, _E ->
          :skip
          false
      end

    case env do
      false ->
        check_expr_seq(checks, code, env0, lastMatchedLoc, file)

      ^env ->
        check_expr_seq(rest, code, env, loc, file)
    end
  end

  defp check_expr_seq([], _Blocks, _Env, _LastMatchedLoc, _File) do
    []
  end

  defp check_expr_seq([{:check_expr, loc, args, _} | _], [], env, lastMatchedLoc, file) do
    [{file, [{loc, :beam_ssa_check, {:no_match, args, lastMatchedLoc, env}}]}]
  end

  defp op_check(
         [:set, result, {:atom, _, op} | pArgs],
         pAnno,
         r_b_set(dst: dst, args: aArgs, op: op, anno: aAnno) = _I,
         env0
       ) do
    :skip
    env = check_annos(pAnno, aAnno, env0)
    op_check_call(op, result, dst, pArgs, aArgs, env)
  end

  defp op_check(
         [
           :set,
           result,
           {{:atom, _, :bif}, {:atom, _, op}}
           | pArgs
         ],
         pAnno,
         r_b_set(dst: dst, args: aArgs, op: {:bif, op}, anno: aAnno) = _I,
         env0
       ) do
    :skip
    env = check_annos(pAnno, aAnno, env0)
    op_check_call(op, result, dst, pArgs, aArgs, env)
  end

  defp op_check(
         [:none, {:atom, _, :ret} | pArgs],
         pAnno,
         r_b_ret(arg: aArg, anno: aAnno) = _I,
         env0
       ) do
    :skip
    env = check_annos(pAnno, aAnno, env0)
    post_args(pArgs, [aArg], env)
  end

  defp op_check(
         [:none, {:atom, _, :br} | pArgs],
         pAnno,
         r_b_br(bool: aBool, succ: aSucc, fail: aFail, anno: aAnno) = _I,
         env0
       ) do
    :skip
    env = check_annos(pAnno, aAnno, env0)
    post_args(pArgs, [aBool, r_b_literal(val: aSucc), r_b_literal(val: aFail)], env)
  end

  defp op_check(
         [:none, {:atom, _, :switch}, pArg, pFail, {:list, _, pArgs}],
         pAnno,
         r_b_switch(arg: aArg, fail: aFail, list: aList, anno: aAnno) = _I,
         env0
       ) do
    :skip
    env1 = env_post(pArg, aArg, env_post(pFail, r_b_literal(val: aFail), env0))
    env = check_annos(pAnno, aAnno, env1)
    post_switch_args(pArgs, aList, env)
  end

  defp op_check([:label, pLbl], _Anno, {:label, aLbl}, env)
       when is_integer(aLbl) do
    env_post(pLbl, r_b_literal(val: aLbl), env)
  end

  defp op_check_call(op, pResult, aResult, pArgs, aArgs, env0) do
    env = env_post(pResult, aResult, env0)

    case op do
      :phi ->
        post_phi_args(pArgs, aArgs, env)

      _ ->
        post_args(pArgs, aArgs, env)
    end
  end

  defp post_args([{:..., _}], _, env) do
    env
  end

  defp post_args([pA | pArgs], [aA | aArgs], env) do
    post_args(pArgs, aArgs, env_post(pA, aA, env))
  end

  defp post_args([], [], env) do
    env
  end

  defp post_args(pattern, args, _Env) do
    :io.format(~c"Failed to match ~kp <-> ~kp~n", [pattern, args])
    :erlang.error({:internal_pattern_match_error, :post_args})
  end

  defp post_phi_args([{:..., _}], _, env) do
    env
  end

  defp post_phi_args([{:tuple, _, [pVar, pLbl]} | pArgs], [{aVar, aLbl} | aArgs], env0) do
    env = env_post(pVar, aVar, env_post(pLbl, aLbl, env0))
    post_phi_args(pArgs, aArgs, env)
  end

  defp post_phi_args([], [], env) do
    env
  end

  defp post_switch_args([{:..., _}], _, env) do
    env
  end

  defp post_switch_args([{:tuple, _, [pVal, pLbl]} | pArgs], [{aVal, aLbl} | aArgs], env0) do
    env = env_post(pVal, aVal, env_post(pLbl, r_b_literal(val: aLbl), env0))
    post_switch_args(pArgs, aArgs, env)
  end

  defp post_switch_args([], [], env) do
    env
  end

  defp env_post({:var, _, pV}, actual, env) do
    env_post1(pV, actual, env)
  end

  defp env_post({:atom, _, atom}, r_b_literal(val: atom), env) do
    env
  end

  defp env_post({:atom, _, atom}, atom, env)
       when is_atom(atom) do
    env
  end

  defp env_post(
         {:local_fun, {:atom, _, n}, {:integer, _, a}},
         r_b_local(name: r_b_literal(val: n), arity: a),
         env
       ) do
    env
  end

  defp env_post(
         {:external_fun, {:atom, _, m}, {:atom, _, n}, {:integer, _, a}},
         r_b_remote(mod: r_b_literal(val: m), name: r_b_literal(val: n), arity: a),
         env
       ) do
    env
  end

  defp env_post(
         {:external_fun, {:atom, _, m}, {:atom, _, n}, {:integer, _, a}},
         r_b_literal(val: f),
         env
       ) do
    {^m, ^n, ^a} = :erlang.fun_info_mfa(f)
    env
  end

  defp env_post({:integer, _, v}, r_b_literal(val: v), env) do
    env
  end

  defp env_post({:integer, _, v}, v, env) when is_integer(v) do
    env
  end

  defp env_post({:float, _, v}, r_b_literal(val: v), env) do
    env
  end

  defp env_post({:float, _, v}, v, env) when is_float(v) do
    env
  end

  defp env_post(
         {:float_epsilon, {:float, _, v}, {:float, _, epsilon}},
         r_b_literal(val: actual),
         env
       ) do
    true = abs(v - actual) < epsilon
    env
  end

  defp env_post({:float_epsilon, {:float, _, v}, {:float, _, epsilon}}, actual, env)
       when is_float(actual) do
    true = abs(v - actual) < epsilon
    env
  end

  defp env_post({:binary, _, bits}, r_b_literal(val: v), env) do
    post_bitstring(bits, v, env)
  end

  defp env_post({:binary, _, bits}, bin, env)
       when is_bitstring(bin) do
    post_bitstring(bits, bin, env)
  end

  defp env_post({:list, _, elems}, r_b_literal(val: ls), env) do
    post_list(elems, ls, env)
  end

  defp env_post({:list, _, elems}, ls, env) when is_list(ls) do
    post_list(elems, ls, env)
  end

  defp env_post({:tuple, _, es}, r_b_literal(val: ls), env) do
    post_tuple(es, :erlang.tuple_to_list(ls), env)
  end

  defp env_post({:tuple, _, es}, tuple, env)
       when is_tuple(tuple) do
    post_tuple(es, :erlang.tuple_to_list(tuple), env)
  end

  defp env_post({:map, _, elems}, r_b_literal(val: map), env)
       when is_map(map) do
    post_map(elems, map, env)
  end

  defp env_post({:map, _, elems}, map, env) when is_map(map) do
    post_map(elems, map, env)
  end

  defp env_post(_Pattern, _Args, _Env) do
    :skip
    :erlang.error({:internal_pattern_match_error, :env_post})
  end

  defp env_post1(:_, _Actual, env) do
    :skip
    env
  end

  defp env_post1(pV, actual, env)
       when :erlang.is_map_key(
              pV,
              env
            ) do
    :skip
    ^actual = :erlang.map_get(pV, env)
    env
  end

  defp env_post1(pV, r_b_var() = actual, env) do
    :skip
    Map.put(env, pV, actual)
  end

  defp env_post1(pV, r_b_literal() = actual, env) do
    :skip
    Map.put(env, pV, actual)
  end

  defp env_post1(_Pattern, _Actual, _Env) do
    :skip
    :erlang.error({:internal_pattern_match_error, :env_post1})
  end

  defp post_bitstring(bytes, actual, env) do
    ^actual = build_bitstring(bytes, <<>>)
    env
  end

  defp build_bitstring([{:integer, _, v} | bytes], acc) do
    build_bitstring(bytes, <<acc::bits, v::size(8)>>)
  end

  defp build_bitstring(
         [{{:integer, _, v}, {:integer, _, n}} | bytes],
         acc
       ) do
    build_bitstring(bytes, <<acc::bits, v::size(n)>>)
  end

  defp build_bitstring([], acc) do
    acc
  end

  defp post_list([{:..., _}], _, env) do
    env
  end

  defp post_list([elem | elements], [a | actual], env0) do
    env = env_post(elem, a, env0)
    post_list(elements, actual, env)
  end

  defp post_list([], [], env) do
    env
  end

  defp post_list(elem, actual, env) do
    env_post(elem, actual, env)
  end

  defp post_tuple([{:..., _}], _, env) do
    env
  end

  defp post_tuple([elem | elements], [a | actual], env0) do
    env = env_post(elem, a, env0)
    post_tuple(elements, actual, env)
  end

  defp post_tuple([], [], env) do
    env
  end

  defp post_map([{key, val} | items], map, env) do
    k = build_map_key(key)
    v = build_map_key(val)
    %{^k => ^v} = map
    post_map(items, :maps.remove(k, map), env)
  end

  defp post_map([], map, env) do
    0 = :maps.size(map)
    env
  end

  defp build_map_key_list([e | elems]) do
    [build_map_key(e) | build_map_key_list(elems)]
  end

  defp build_map_key_list([]) do
    []
  end

  defp build_map_key_list(e) do
    build_map_key(e)
  end

  defp check_annos([{:term, {:atom, _, key}, pTerm} | patterns], actual, env0) do
    :skip
    %{^key => aTerm} = actual
    :skip
    env = env_post(pTerm, r_b_literal(val: aTerm), env0)
    :skip
    check_annos(patterns, actual, env)
  end

  defp check_annos([], _, env) do
    env
  end

  def format_error(:xfail_passed) do
    ~c"test which was expected to fail passed"
  end

  def format_error({:unknown_result_kind, result}) do
    ~c"unknown expected result: " ++ :erlang.atom_to_list(result)
  end

  def format_error(:too_many_pattern_args) do
    ~c"pattern has more arguments than the function"
  end

  def format_error(:too_few_pattern_args) do
    ~c"pattern has fewer arguments than the function"
  end

  def format_error({:no_match, _Args, _LastMatchedLoc, env}) do
    flatten(:io_lib.format(~c"no match found for pattern, env: ~p~n", [env]))
  end
end
