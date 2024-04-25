defmodule :m_erl_eval do
  use Bitwise
  import :lists, only: [foldl: 3, member: 2, reverse: 1]
  defp empty_fun_used_vars() do
    %{}
  end

  def exprs(exprs, bs) do
    case (check_command(exprs, bs)) do
      :ok ->
        exprs(exprs, bs, :none, :none, :none,
                empty_fun_used_vars())
      {:error, {_Location, _Mod, error}} ->
        :erlang.raise(:error, error,
                        :erlang.element(2,
                                          :erlang.process_info(self(),
                                                                 :current_stacktrace)))
    end
  end

  def exprs(exprs, bs, lf) do
    exprs(exprs, bs, lf, :none, :none,
            empty_fun_used_vars())
  end

  def exprs(exprs, bs, lf, ef) do
    exprs(exprs, bs, lf, ef, :none, empty_fun_used_vars())
  end

  defp exprs([e], bs0, lf, ef, rBs, fUVs) do
    expr(e, bs0, lf, ef, rBs, fUVs)
  end

  defp exprs([e | es], bs0, lf, ef, rBs, fUVs) do
    rBs1 = :none
    {:value, _V, bs} = expr(e, bs0, lf, ef, rBs1, fUVs)
    exprs(es, bs, lf, ef, rBs, fUVs)
  end

  defp maybe_match_exprs([{:maybe_match, anno, lhs, rhs0} | es], bs0, lf,
            ef) do
    {:value, rhs, bs1} = expr(rhs0, bs0, lf, ef, :none)
    case (match(lhs, rhs, anno, bs1, bs1, ef)) do
      {:match, bs} ->
        case (es) do
          [] ->
            {:success, rhs}
          [_ | _] ->
            maybe_match_exprs(es, bs, lf, ef)
        end
      :nomatch ->
        {:failure, rhs}
    end
  end

  defp maybe_match_exprs([e], bs0, lf, ef) do
    {:value, v, _Bs} = expr(e, bs0, lf, ef, :none)
    {:success, v}
  end

  defp maybe_match_exprs([e | es], bs0, lf, ef) do
    {:value, _V, bs} = expr(e, bs0, lf, ef, :none)
    maybe_match_exprs(es, bs, lf, ef)
  end

  def expr(e, bs) do
    case (check_command([e], bs)) do
      :ok ->
        expr(e, bs, :none, :none, :none)
      {:error, {_Location, _Mod, error}} ->
        :erlang.raise(:error, error,
                        :erlang.element(2,
                                          :erlang.process_info(self(),
                                                                 :current_stacktrace)))
    end
  end

  def expr(e, bs, lf) do
    expr(e, bs, lf, :none, :none)
  end

  def expr(e, bs, lf, ef) do
    expr(e, bs, lf, ef, :none)
  end

  def check_command(es, bs) do
    opts = [:bitlevel_binaries, :binary_comprehension]
    case (:erl_lint.exprs_opt(es, bindings(bs), opts)) do
      {:ok, _Ws} ->
        :ok
      {:error, [{_File, [error | _]}], _Ws} ->
        {:error, error}
    end
  end

  def fun_data(f) when is_function(f) do
    case (:erlang.fun_info(f, :module)) do
      {:module, :erl_eval} ->
        case (:erlang.fun_info(f, :env)) do
          {:env, [{_FAnno, fBs, _FLf, _FEf, _FUVs, fCs}]} ->
            {:fun_data, fBs, fCs}
          {:env,
             [{_FAnno, fBs, _FLf, _FEf, _FUVs, fCs, fName}]} ->
            {:named_fun_data, fBs, fName, fCs}
        end
      _ ->
        false
    end
  end

  def fun_data(_T) do
    false
  end

  def expr(expr, bs, lf, ef, rbs) do
    expr(expr, bs, lf, ef, rbs, empty_fun_used_vars())
  end

  defp expr({:var, anno, v}, bs, _Lf, ef, rBs, _FUVs) do
    case (binding(v, bs)) do
      {:value, val} ->
        ret_expr(val, bs, rBs)
      :unbound ->
        apply_error({:unbound, v},
                      :erlang.element(2,
                                        :erlang.process_info(self(),
                                                               :current_stacktrace)),
                      anno, bs, ef, rBs)
    end
  end

  defp expr({:char, _, c}, bs, _Lf, _Ef, rBs, _FUVs) do
    ret_expr(c, bs, rBs)
  end

  defp expr({:integer, _, i}, bs, _Lf, _Ef, rBs, _FUVs) do
    ret_expr(i, bs, rBs)
  end

  defp expr({:float, _, f}, bs, _Lf, _Ef, rBs, _FUVs) do
    ret_expr(f, bs, rBs)
  end

  defp expr({:atom, _, a}, bs, _Lf, _Ef, rBs, _FUVs) do
    ret_expr(a, bs, rBs)
  end

  defp expr({:string, _, s}, bs, _Lf, _Ef, rBs, _FUVs) do
    ret_expr(s, bs, rBs)
  end

  defp expr({nil, _}, bs, _Lf, _Ef, rBs, _FUVs) do
    ret_expr([], bs, rBs)
  end

  defp expr({:cons, anno, h0, t0}, bs0, lf, ef, rBs,
            fUVs) do
    {:value, h, bs1} = expr(h0, bs0, lf, ef, :none, fUVs)
    {:value, t, bs2} = expr(t0, bs0, lf, ef, :none, fUVs)
    ret_expr([h | t], merge_bindings(bs1, bs2, anno, ef),
               rBs)
  end

  defp expr({:lc, _, e, qs}, bs, lf, ef, rBs, fUVs) do
    eval_lc(e, qs, bs, lf, ef, rBs, fUVs)
  end

  defp expr({:bc, _, e, qs}, bs, lf, ef, rBs, fUVs) do
    eval_bc(e, qs, bs, lf, ef, rBs, fUVs)
  end

  defp expr({:mc, _, e, qs}, bs, lf, ef, rBs, fUVs) do
    eval_mc(e, qs, bs, lf, ef, rBs, fUVs)
  end

  defp expr({:tuple, _, es}, bs0, lf, ef, rBs, fUVs) do
    {vs, bs} = expr_list(es, bs0, lf, ef, fUVs)
    ret_expr(:erlang.list_to_tuple(vs), bs, rBs)
  end

  defp expr({:record_field, anno, _, name, _}, bs, _Lf, ef,
            rBs, _FUVs) do
    apply_error({:undef_record, name},
                  :erlang.element(2,
                                    :erlang.process_info(self(),
                                                           :current_stacktrace)),
                  anno, bs, ef, rBs)
  end

  defp expr({:record_index, anno, name, _}, bs, _Lf, ef,
            rBs, _FUVs) do
    apply_error({:undef_record, name},
                  :erlang.element(2,
                                    :erlang.process_info(self(),
                                                           :current_stacktrace)),
                  anno, bs, ef, rBs)
  end

  defp expr({:record, anno, name, _}, bs, _Lf, ef, rBs,
            _FUVs) do
    apply_error({:undef_record, name},
                  :erlang.element(2,
                                    :erlang.process_info(self(),
                                                           :current_stacktrace)),
                  anno, bs, ef, rBs)
  end

  defp expr({:record, anno, _, name, _}, bs, _Lf, ef, rBs,
            _FUVs) do
    apply_error({:undef_record, name},
                  :erlang.element(2,
                                    :erlang.process_info(self(),
                                                           :current_stacktrace)),
                  anno, bs, ef, rBs)
  end

  defp expr({:map, anno, binding, es}, bs0, lf, ef, rBs,
            fUVs) do
    {:value, map0, bs1} = expr(binding, bs0, lf, ef, :none,
                                 fUVs)
    {vs, bs2} = eval_map_fields(es, bs0, lf, ef, fUVs)
    _ = :maps.put(:k, :v, map0)
    map1 = :lists.foldl(fn {:map_assoc, k, v}, mi ->
                             :maps.put(k, v, mi)
                           {:map_exact, k, v}, mi ->
                             :maps.update(k, v, mi)
                        end,
                          map0, vs)
    ret_expr(map1, merge_bindings(bs2, bs1, anno, ef), rBs)
  end

  defp expr({:map, _, es}, bs0, lf, ef, rBs, fUVs) do
    {vs, bs} = eval_map_fields(es, bs0, lf, ef, fUVs)
    ret_expr(:lists.foldl(fn {:map_assoc, k, v}, mi ->
                               :maps.put(k, v, mi)
                          end,
                            :maps.new(), vs),
               bs, rBs)
  end

  defp expr({:block, _, es}, bs, lf, ef, rBs, fUVs) do
    exprs(es, bs, lf, ef, rBs, fUVs)
  end

  defp expr({:if, anno, cs}, bs, lf, ef, rBs, fUVs) do
    if_clauses(cs, anno, bs, lf, ef, rBs, fUVs)
  end

  defp expr({:case, anno, e, cs}, bs0, lf, ef, rBs, fUVs) do
    {:value, val, bs} = expr(e, bs0, lf, ef, :none, fUVs)
    case_clauses(val, cs, anno, bs, lf, ef, rBs, fUVs)
  end

  defp expr({:try, anno, b, cases, catches, aB}, bs, lf, ef,
            rBs, fUVs) do
    try_clauses(b, cases, catches, aB, anno, bs, lf, ef,
                  rBs, fUVs)
  end

  defp expr({:receive, _, cs}, bs, lf, ef, rBs, fUVs) do
    receive_clauses(cs, bs, lf, ef, rBs, fUVs)
  end

  defp expr({:receive, _, cs, e, tB}, bs0, lf, ef, rBs,
            fUVs) do
    {:value, t, bs} = expr(e, bs0, lf, ef, :none, fUVs)
    receive_clauses(t, cs, {tB, bs}, bs0, lf, ef, rBs, fUVs)
  end

  defp expr({:fun, _Anno, {:function, mod0, name0, arity0}},
            bs0, lf, ef, rBs, fUVs) do
    {[mod, name, arity], bs} = expr_list([mod0, name0,
                                                    arity0],
                                           bs0, lf, ef, fUVs)
    f = :erlang.make_fun(mod, name, arity)
    ret_expr(f, bs, rBs)
  end

  defp expr({:fun, anno, {:function, name, arity}}, bs0,
            _Lf, ef, rBs, _FUVs) do
    apply_error(:undef,
                  [{:erl_eval, name, arity} | :erlang.element(2,
                                                                :erlang.process_info(self(),
                                                                                       :current_stacktrace))],
                  anno, bs0, ef, rBs)
  end

  defp expr({:fun, anno, {:clauses, cs}} = ex, bs, lf, ef,
            rBs, fUVs) do
    {en, newFUVs} = fun_used_bindings(ex, cs, bs, fUVs)
    info = {anno, en, lf, ef, newFUVs, cs}
    f = (case (length(:erlang.element(3, hd(cs)))) do
           0 ->
             fn () ->
                  eval_fun([], info)
             end
           1 ->
             fn a ->
                  eval_fun([a], info)
             end
           2 ->
             fn a, b ->
                  eval_fun([a, b], info)
             end
           3 ->
             fn a, b, c ->
                  eval_fun([a, b, c], info)
             end
           4 ->
             fn a, b, c, d ->
                  eval_fun([a, b, c, d], info)
             end
           5 ->
             fn a, b, c, d, e ->
                  eval_fun([a, b, c, d, e], info)
             end
           6 ->
             fn a, b, c, d, e, f ->
                  eval_fun([a, b, c, d, e, f], info)
             end
           7 ->
             fn a, b, c, d, e, f, g ->
                  eval_fun([a, b, c, d, e, f, g], info)
             end
           8 ->
             fn a, b, c, d, e, f, g, h ->
                  eval_fun([a, b, c, d, e, f, g, h], info)
             end
           9 ->
             fn a, b, c, d, e, f, g, h, i ->
                  eval_fun([a, b, c, d, e, f, g, h, i], info)
             end
           10 ->
             fn a, b, c, d, e, f, g, h, i, j ->
                  eval_fun([a, b, c, d, e, f, g, h, i, j], info)
             end
           11 ->
             fn a, b, c, d, e, f, g, h, i, j, k ->
                  eval_fun([a, b, c, d, e, f, g, h, i, j, k], info)
             end
           12 ->
             fn a, b, c, d, e, f, g, h, i, j, k, l ->
                  eval_fun([a, b, c, d, e, f, g, h, i, j, k, l], info)
             end
           13 ->
             fn a, b, c, d, e, f, g, h, i, j, k, l, m ->
                  eval_fun([a, b, c, d, e, f, g, h, i, j, k, l, m], info)
             end
           14 ->
             fn a, b, c, d, e, f, g, h, i, j, k, l, m, n ->
                  eval_fun([a, b, c, d, e, f, g, h, i, j, k, l, m, n],
                             info)
             end
           15 ->
             fn a, b, c, d, e, f, g, h, i, j, k, l, m, n, o ->
                  eval_fun([a, b, c, d, e, f, g, h, i, j, k, l, m, n, o],
                             info)
             end
           16 ->
             fn a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p ->
                  eval_fun([a, b, c, d, e, f, g, h, i, j, k, l, m, n, o,
                                                                          p],
                             info)
             end
           17 ->
             fn a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q ->
                  eval_fun([a, b, c, d, e, f, g, h, i, j, k, l, m, n, o,
                                                                          p, q],
                             info)
             end
           18 ->
             fn a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q,
                  r ->
                  eval_fun([a, b, c, d, e, f, g, h, i, j, k, l, m, n, o,
                                                                          p, q,
                                                                                 r],
                             info)
             end
           19 ->
             fn a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r,
                  s ->
                  eval_fun([a, b, c, d, e, f, g, h, i, j, k, l, m, n, o,
                                                                          p, q,
                                                                                 r,
                                                                                     s],
                             info)
             end
           20 ->
             fn a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r,
                  s, t ->
                  eval_fun([a, b, c, d, e, f, g, h, i, j, k, l, m, n, o,
                                                                          p, q,
                                                                                 r,
                                                                                     s,
                                                                                         t],
                             info)
             end
           _Other ->
             l = :erl_anno.location(anno)
             reason = {:argument_limit, {:fun, l, to_terms(cs)}}
             apply_error(reason,
                           :erlang.element(2,
                                             :erlang.process_info(self(),
                                                                    :current_stacktrace)),
                           anno, bs, ef, rBs)
         end)
    ret_expr(f, bs, rBs)
  end

  defp expr({:named_fun, anno, name, cs} = ex, bs, lf, ef,
            rBs, fUVs) do
    {en, newFUVs} = fun_used_bindings(ex, cs, bs, fUVs)
    info = {anno, en, lf, ef, newFUVs, cs, name}
    f = (case (length(:erlang.element(3, hd(cs)))) do
           0 ->
             fn rF
              ->
               eval_named_fun([], rF, info)
             end
           1 ->
             fn rF
             a ->
               eval_named_fun([a], rF, info)
             end
           2 ->
             fn rF
             a, b ->
               eval_named_fun([a, b], rF, info)
             end
           3 ->
             fn rF
             a, b, c ->
               eval_named_fun([a, b, c], rF, info)
             end
           4 ->
             fn rF
             a, b, c, d ->
               eval_named_fun([a, b, c, d], rF, info)
             end
           5 ->
             fn rF
             a, b, c, d, e ->
               eval_named_fun([a, b, c, d, e], rF, info)
             end
           6 ->
             fn rF
             a, b, c, d, e, f ->
               eval_named_fun([a, b, c, d, e, f], rF, info)
             end
           7 ->
             fn rF
             a, b, c, d, e, f, g ->
               eval_named_fun([a, b, c, d, e, f, g], rF, info)
             end
           8 ->
             fn rF
             a, b, c, d, e, f, g, h ->
               eval_named_fun([a, b, c, d, e, f, g, h], rF, info)
             end
           9 ->
             fn rF
             a, b, c, d, e, f, g, h, i ->
               eval_named_fun([a, b, c, d, e, f, g, h, i], rF, info)
             end
           10 ->
             fn rF
             a, b, c, d, e, f, g, h, i, j ->
               eval_named_fun([a, b, c, d, e, f, g, h, i, j], rF, info)
             end
           11 ->
             fn rF
             a, b, c, d, e, f, g, h, i, j, k ->
               eval_named_fun([a, b, c, d, e, f, g, h, i, j, k], rF,
                                info)
             end
           12 ->
             fn rF
             a, b, c, d, e, f, g, h, i, j, k, l ->
               eval_named_fun([a, b, c, d, e, f, g, h, i, j, k, l], rF,
                                info)
             end
           13 ->
             fn rF
             a, b, c, d, e, f, g, h, i, j, k, l, m ->
               eval_named_fun([a, b, c, d, e, f, g, h, i, j, k, l, m],
                                rF, info)
             end
           14 ->
             fn rF
             a, b, c, d, e, f, g, h, i, j, k, l, m, n ->
               eval_named_fun([a, b, c, d, e, f, g, h, i, j, k, l, m,
                                                                       n],
                                rF, info)
             end
           15 ->
             fn rF
             a, b, c, d, e, f, g, h, i, j, k, l, m, n, o ->
               eval_named_fun([a, b, c, d, e, f, g, h, i, j, k, l, m,
                                                                       n, o],
                                rF, info)
             end
           16 ->
             fn rF
             a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p ->
               eval_named_fun([a, b, c, d, e, f, g, h, i, j, k, l, m,
                                                                       n, o, p],
                                rF, info)
             end
           17 ->
             fn rF
             a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q ->
               eval_named_fun([a, b, c, d, e, f, g, h, i, j, k, l, m,
                                                                       n, o, p,
                                                                                 q],
                                rF, info)
             end
           18 ->
             fn rF
             a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r ->
               eval_named_fun([a, b, c, d, e, f, g, h, i, j, k, l, m,
                                                                       n, o, p,
                                                                                 q,
                                                                                     r],
                                rF, info)
             end
           19 ->
             fn rF
             a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r,
               s ->
               eval_named_fun([a, b, c, d, e, f, g, h, i, j, k, l, m,
                                                                       n, o, p,
                                                                                 q,
                                                                                     r,
                                                                                         s],
                                rF, info)
             end
           20 ->
             fn rF
             a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s,
               t ->
               eval_named_fun([a, b, c, d, e, f, g, h, i, j, k, l, m,
                                                                       n, o, p,
                                                                                 q,
                                                                                     r,
                                                                                         s,
                                                                                             t],
                                rF, info)
             end
           _Other ->
             l = :erl_anno.location(anno)
             reason = {:argument_limit,
                         {:named_fun, l, name, to_terms(cs)}}
             apply_error(reason,
                           :erlang.element(2,
                                             :erlang.process_info(self(),
                                                                    :current_stacktrace)),
                           anno, bs, ef, rBs)
         end)
    ret_expr(f, bs, rBs)
  end

  defp expr({:call, _,
             {:remote, _, {:atom, _, :qlc}, {:atom, _, :q}},
             [{:lc, _, _E, _Qs} = lC | as0]},
            bs0, lf, ef, rBs, fUVs)
      when length(as0) <= 1 do
    maxLine = find_maxline(lC)
    {lC1, d} = hide_calls(lC, maxLine)
    case (:qlc.transform_from_evaluator(lC1, bs0)) do
      {:ok, {:call, a, remote, [qLC]}} ->
        qLC1 = unhide_calls(qLC, maxLine, d)
        expr({:call, a, remote, [qLC1 | as0]}, bs0, lf, ef, rBs,
               fUVs)
      {:not_ok, error} ->
        ret_expr(error, bs0, rBs)
    end
  end

  defp expr({:call, a1,
             {:remote, a2,
                {:record_field, _, {:atom, _, :""},
                   {:atom, _, :qlc} = mod},
                {:atom, _, :q} = func},
             [{:lc, _, _E, _Qs} | as0] = as},
            bs, lf, ef, rBs, fUVs)
      when length(as0) <= 1 do
    expr({:call, a1, {:remote, a2, mod, func}, as}, bs, lf,
           ef, rBs, fUVs)
  end

  defp expr({:call, anno, {:remote, _, mod, func}, as0},
            bs0, lf, ef, rBs, fUVs) do
    {:value, m, bs1} = expr(mod, bs0, lf, ef, :none, fUVs)
    {:value, f, bs2} = expr(func, bs0, lf, ef, :none, fUVs)
    {as, bs3} = expr_list(as0,
                            merge_bindings(bs1, bs2, anno, ef), lf, ef, fUVs)
    case (is_atom(m) and :erl_internal.bif(m, f,
                                             length(as))) do
      true ->
        bif(f, as, anno, bs3, ef, rBs)
      false ->
        do_apply(m, f, as, anno, bs3, ef, rBs)
    end
  end

  defp expr({:call, anno, {:atom, _, func}, as0}, bs0, lf,
            ef, rBs, fUVs) do
    case (:erl_internal.bif(func, length(as0))) do
      true ->
        {as, bs} = expr_list(as0, bs0, lf, ef)
        bif(func, as, anno, bs, ef, rBs)
      false ->
        local_func(func, as0, anno, bs0, lf, ef, rBs, fUVs)
    end
  end

  defp expr({:call, anno, func0, as0}, bs0, lf, ef, rBs,
            fUVs) do
    {:value, func, bs1} = expr(func0, bs0, lf, ef, :none,
                                 fUVs)
    {as, bs2} = expr_list(as0, bs1, lf, ef, fUVs)
    case (func) do
      {m, f} when (is_atom(m) and is_atom(f)) ->
        apply_error({:badfun, func},
                      :erlang.element(2,
                                        :erlang.process_info(self(),
                                                               :current_stacktrace)),
                      anno, bs0, ef, rBs)
      _ ->
        do_apply(func, as, anno, bs2, ef, rBs)
    end
  end

  defp expr({:catch, _, expr}, bs0, lf, ef, rBs, fUVs) do
    try do
      expr(expr, bs0, lf, ef, :none, fUVs)
    catch
      term ->
        ret_expr(term, bs0, rBs)
      :exit, reason ->
        ret_expr({:EXIT, reason}, bs0, rBs)
      :error, reason ->
        ret_expr({:EXIT, {reason, __STACKTRACE__}}, bs0, rBs)
    else
      {:value, v, bs} ->
        ret_expr(v, bs, rBs)
    end
  end

  defp expr({:match, anno, lhs, rhs0}, bs0, lf, ef, rBs,
            fUVs) do
    {:value, rhs, bs1} = expr(rhs0, bs0, lf, ef, :none,
                                fUVs)
    case (match(lhs, rhs, anno, bs1, bs1, ef)) do
      {:match, bs} ->
        ret_expr(rhs, bs, rBs)
      :nomatch ->
        apply_error({:badmatch, rhs},
                      :erlang.element(2,
                                        :erlang.process_info(self(),
                                                               :current_stacktrace)),
                      anno, bs0, ef, rBs)
    end
  end

  defp expr({:maybe, _, es}, bs, lf, ef, rBs, _FUVs) do
    {_, val} = maybe_match_exprs(es, bs, lf, ef)
    ret_expr(val, bs, rBs)
  end

  defp expr({:maybe, anno, es, {:else, _, cs}}, bs0, lf, ef,
            rBs, fUVs) do
    case (maybe_match_exprs(es, bs0, lf, ef)) do
      {:success, val} ->
        ret_expr(val, bs0, rBs)
      {:failure, val} ->
        case (match_clause(cs, [val], bs0, lf, ef)) do
          {b, bs} ->
            exprs(b, bs, lf, ef, rBs, fUVs)
          :nomatch ->
            apply_error({:else_clause, val},
                          :erlang.element(2,
                                            :erlang.process_info(self(),
                                                                   :current_stacktrace)),
                          anno, bs0, ef, rBs)
        end
    end
  end

  defp expr({:op, anno, op, a0}, bs0, lf, ef, rBs, fUVs) do
    {:value, a, bs} = expr(a0, bs0, lf, ef, :none, fUVs)
    eval_op(op, a, anno, bs, ef, rBs)
  end

  defp expr({:op, anno, :andalso, l0, r0}, bs0, lf, ef, rBs,
            fUVs) do
    {:value, l, bs1} = expr(l0, bs0, lf, ef, :none, fUVs)
    v = (case (l) do
           true ->
             {:value, r, _} = expr(r0, bs1, lf, ef, :none, fUVs)
             r
           false ->
             false
           _ ->
             apply_error({:badarg, l},
                           :erlang.element(2,
                                             :erlang.process_info(self(),
                                                                    :current_stacktrace)),
                           anno, bs0, ef, rBs)
         end)
    ret_expr(v, bs1, rBs)
  end

  defp expr({:op, anno, :orelse, l0, r0}, bs0, lf, ef, rBs,
            fUVs) do
    {:value, l, bs1} = expr(l0, bs0, lf, ef, :none, fUVs)
    v = (case (l) do
           true ->
             true
           false ->
             {:value, r, _} = expr(r0, bs1, lf, ef, :none, fUVs)
             r
           _ ->
             apply_error({:badarg, l},
                           :erlang.element(2,
                                             :erlang.process_info(self(),
                                                                    :current_stacktrace)),
                           anno, bs0, ef, rBs)
         end)
    ret_expr(v, bs1, rBs)
  end

  defp expr({:op, anno, op, l0, r0}, bs0, lf, ef, rBs,
            fUVs) do
    {:value, l, bs1} = expr(l0, bs0, lf, ef, :none, fUVs)
    {:value, r, bs2} = expr(r0, bs0, lf, ef, :none, fUVs)
    eval_op(op, l, r, anno,
              merge_bindings(bs1, bs2, anno, ef), ef, rBs)
  end

  defp expr({:bin, _, fs}, bs0, lf, ef, rBs, fUVs) do
    evalFun = fn e, b ->
                   expr(e, b, lf, ef, :none, fUVs)
              end
    errorFun = fn a, r, s ->
                    apply_error(r, s, a, bs0, ef, rBs)
               end
    {:value, v, bs} = :eval_bits.expr_grp(fs, bs0, evalFun,
                                            errorFun)
    ret_expr(v, bs, rBs)
  end

  defp expr({:remote, anno, _, _}, bs0, _Lf, ef, rBs,
            _FUVs) do
    apply_error({:badexpr, :":"},
                  :erlang.element(2,
                                    :erlang.process_info(self(),
                                                           :current_stacktrace)),
                  anno, bs0, ef, rBs)
  end

  defp apply_error(reason, stack, anno, bs0, ef, rBs) do
    do_apply(:erlang, :raise, [:error, reason, stack], anno,
               bs0, ef, rBs)
  end

  defp find_maxline(lC) do
    :erlang.put(:"$erl_eval_max_line", 0)
    f = fn a ->
             case (:erl_anno.is_anno(a)) do
               true ->
                 l = :erl_anno.line(a)
                 case (:erlang.and(is_integer(l),
                                     l > :erlang.get(:"$erl_eval_max_line"))) do
                   true ->
                     :erlang.put(:"$erl_eval_max_line", l)
                   false ->
                     :ok
                 end
               false ->
                 :ok
             end
        end
    _ = :erl_parse.map_anno(f, lC)
    :erlang.erase(:"$erl_eval_max_line")
  end

  defp fun_used_bindings(fun, cs, bs, fUVs) do
    {used, innerFUVs} = (case (fUVs) do
                           %{^cs => usedAndFUVs} ->
                             usedAndFUVs
                           %{} ->
                             allUsedVars = :erl_lint.used_vars([fun],
                                                                 bindings(bs))
                             [{_, usedAndFUVs}] = :maps.to_list(allUsedVars)
                             usedAndFUVs
                         end)
    {filter_bindings(fn k, _V ->
                          member(k, used)
                     end,
                       bs),
       innerFUVs}
  end

  defp hide_calls(lC, maxLine) do
    lineId0 = maxLine + 1
    {nLC, _, d} = hide(lC, lineId0, :maps.new())
    {nLC, d}
  end

  defp hide({:call, a, {:atom, _, n} = atom, args}, id0,
            d0) do
    {nArgs, id, d} = hide(args, id0, d0)
    c = (case (:erl_internal.bif(n, length(args))) do
           true ->
             {:call, a, atom, nArgs}
           false ->
             anno = :erl_anno.new(id)
             {:call, anno,
                {:remote, a, {:atom, a, :m}, {:atom, a, :f}}, nArgs}
         end)
    {c, id + 1, :maps.put(id, {:call, atom}, d)}
  end

  defp hide(t0, id0, d0) when is_tuple(t0) do
    {l, id, d} = hide(:erlang.tuple_to_list(t0), id0, d0)
    {:erlang.list_to_tuple(l), id, d}
  end

  defp hide([e0 | es0], id0, d0) do
    {e, id1, d1} = hide(e0, id0, d0)
    {es, id, d} = hide(es0, id1, d1)
    {[e | es], id, d}
  end

  defp hide(e, id, d) do
    {e, id, d}
  end

  defp unhide_calls({:call, anno,
             {:remote, a, {:atom, a, :m}, {:atom, a, :f}} = f, args},
            maxLine, d) do
    line = :erl_anno.line(anno)
    cond do
      line > maxLine ->
        {:call, atom} = :erlang.map_get(line, d)
        {:call, a, atom, unhide_calls(args, maxLine, d)}
      true ->
        {:call, anno, f, unhide_calls(args, maxLine, d)}
    end
  end

  defp unhide_calls(t, maxLine, d) when is_tuple(t) do
    :erlang.list_to_tuple(unhide_calls(:erlang.tuple_to_list(t),
                                         maxLine, d))
  end

  defp unhide_calls([e | es], maxLine, d) do
    [unhide_calls(e, maxLine, d) | unhide_calls(es, maxLine,
                                                  d)]
  end

  defp unhide_calls(e, _MaxLine, _D) do
    e
  end

  defp local_func(func, as0, _Anno, bs0, {:value, f}, ef, :value,
            fUVs) do
    {as1, _Bs1} = expr_list(as0, bs0, {:value, f}, ef, fUVs)
    f.(func, as1)
  end

  defp local_func(func, as0, _Anno, bs0, {:value, f}, ef, rBs,
            fUVs) do
    {as1, bs1} = expr_list(as0, bs0, {:value, f}, ef, fUVs)
    ret_expr(f.(func, as1), bs1, rBs)
  end

  defp local_func(func, as0, anno, bs0, {:value, f, eas}, ef, rBs,
            fUVs) do
    fun = fn name, args ->
               apply(f, [name, args | eas])
          end
    local_func(func, as0, anno, bs0, {:value, fun}, ef, rBs,
                 fUVs)
  end

  defp local_func(func, as, anno, bs, {:eval, f}, _Ef, rBs,
            _FUVs) do
    local_func2(f.(func, as, bs), anno, rBs)
  end

  defp local_func(func, as, anno, bs, {:eval, f, eas}, _Ef, rBs,
            _FUVs) do
    local_func2(apply(f, [func, as, bs | eas]), anno, rBs)
  end

  defp local_func(func, as0, _Anno, bs0, {m, f}, ef, rBs, fUVs) do
    {as1, bs1} = expr_list(as0, bs0, {m, f}, ef, fUVs)
    ret_expr(apply(m, f, [func, as1]), bs1, rBs)
  end

  defp local_func(func, as, anno, _Bs, {m, f, eas}, _Ef, rBs,
            _FUVs) do
    local_func2(apply(m, f, [func, as | eas]), anno, rBs)
  end

  defp local_func(func, as0, anno, bs0, :none, ef, rBs, _FUVs) do
    apply_error(:undef,
                  [{:erl_eval, func, length(as0)} | :erlang.element(2,
                                                                      :erlang.process_info(self(),
                                                                                             :current_stacktrace))],
                  anno, bs0, ef, rBs)
  end

  defp local_func2({:value, v, bs}, _Anno, rBs) do
    ret_expr(v, bs, rBs)
  end

  defp local_func2({:eval, f, as, bs}, anno, rBs) do
    do_apply(f, as, anno, bs, :none, rBs)
  end

  defp bif(:apply, [:erlang, :apply, as], anno, bs, ef,
            rBs) do
    bif(:apply, as, anno, bs, ef, rBs)
  end

  defp bif(:apply, [m, f, as], anno, bs, ef, rBs) do
    do_apply(m, f, as, anno, bs, ef, rBs)
  end

  defp bif(:apply, [f, as], anno, bs, ef, rBs) do
    do_apply(f, as, anno, bs, ef, rBs)
  end

  defp bif(name, as, anno, bs, ef, rBs) do
    do_apply(:erlang, name, as, anno, bs, ef, rBs)
  end

  defp do_apply(func, as, anno, bs0, ef, rBs) do
    env = (cond do
             is_function(func) ->
               case ({:erlang.fun_info(func, :module),
                        :erlang.fun_info(func, :env)}) do
                 {{:module, :erl_eval}, {:env, env1}} when env1 !== [] ->
                   {:env, env1}
                 _ ->
                   :no_env
               end
             true ->
               :no_env
           end)
    case ({env, ef}) do
      {{:env, [{fAnno, fBs, fLf, fEf, fFUVs, fCs}]}, _} ->
        nRBs = (cond do
                  rBs === :none ->
                    bs0
                  true ->
                    rBs
                end)
        case ({:erlang.fun_info(func, :arity), length(as)}) do
          {{:arity, arity}, arity} ->
            eval_fun(fCs, as, fAnno, fBs, fLf, fEf, nRBs, fFUVs)
          _ ->
            apply_error({:badarity, {func, as}},
                          :erlang.element(2,
                                            :erlang.process_info(self(),
                                                                   :current_stacktrace)),
                          anno, bs0, ef, rBs)
        end
      {{:env, [{fAnno, fBs, fLf, fEf, fFUVs, fCs, fName}]},
         _} ->
        nRBs = (cond do
                  rBs === :none ->
                    bs0
                  true ->
                    rBs
                end)
        case ({:erlang.fun_info(func, :arity), length(as)}) do
          {{:arity, arity}, arity} ->
            eval_named_fun(fCs, as, fAnno, fBs, fLf, fEf, fName,
                             func, nRBs, fFUVs)
          _ ->
            apply_error({:badarity, {func, as}},
                          :erlang.element(2,
                                            :erlang.process_info(self(),
                                                                   :current_stacktrace)),
                          anno, bs0, ef, rBs)
        end
      {:no_env, :none} when rBs === :value ->
        apply(func, as)
      {:no_env, :none} ->
        ret_expr(apply(func, as), bs0, rBs)
      {:no_env, {:value, f}} when rBs === :value ->
        do_apply(f, anno, func, as)
      {:no_env, {:value, f}} ->
        ret_expr(do_apply(f, anno, func, as), bs0, rBs)
    end
  end

  defp do_apply(mod, func, as, anno, bs0, ef, rBs) do
    case (ef) do
      :none when rBs === :value ->
        apply(mod, func, as)
      :none ->
        ret_expr(apply(mod, func, as), bs0, rBs)
      {:value, f} when rBs === :value ->
        do_apply(f, anno, {mod, func}, as)
      {:value, f} ->
        ret_expr(do_apply(f, anno, {mod, func}, as), bs0, rBs)
    end
  end

  defp do_apply(f, anno, funOrModFun, args) when is_function(f,
                                                         3) do
    f.(anno, funOrModFun, args)
  end

  defp do_apply(f, _Anno, funOrModFun, args) when is_function(f,
                                                          2) do
    f.(funOrModFun, args)
  end

  defp eval_lc(e, qs, bs, lf, ef, rBs, fUVs) do
    ret_expr(:lists.reverse(eval_lc1(e, qs, bs, lf, ef,
                                       fUVs, [])),
               bs, rBs)
  end

  defp eval_lc1(e, [q | qs], bs0, lf, ef, fUVs, acc0) do
    case (is_generator(q)) do
      true ->
        cF = fn bs, acc ->
                  eval_lc1(e, qs, bs, lf, ef, fUVs, acc)
             end
        eval_generator(q, bs0, lf, ef, fUVs, acc0, cF)
      false ->
        cF = fn bs ->
                  eval_lc1(e, qs, bs, lf, ef, fUVs, acc0)
             end
        eval_filter(q, bs0, lf, ef, cF, fUVs, acc0)
    end
  end

  defp eval_lc1(e, [], bs, lf, ef, fUVs, acc) do
    {:value, v, _} = expr(e, bs, lf, ef, :none, fUVs)
    [v | acc]
  end

  defp eval_bc(e, qs, bs, lf, ef, rBs, fUVs) do
    ret_expr(eval_bc1(e, qs, bs, lf, ef, fUVs, <<>>), bs,
               rBs)
  end

  defp eval_bc1(e, [q | qs], bs0, lf, ef, fUVs, acc0) do
    case (is_generator(q)) do
      true ->
        cF = fn bs, acc ->
                  eval_bc1(e, qs, bs, lf, ef, fUVs, acc)
             end
        eval_generator(q, bs0, lf, ef, fUVs, acc0, cF)
      false ->
        cF = fn bs ->
                  eval_bc1(e, qs, bs, lf, ef, fUVs, acc0)
             end
        eval_filter(q, bs0, lf, ef, cF, fUVs, acc0)
    end
  end

  defp eval_bc1(e, [], bs, lf, ef, fUVs, acc) do
    {:value, v, _} = expr(e, bs, lf, ef, :none, fUVs)
    <<acc :: bitstring, v :: bitstring>>
  end

  defp eval_mc(e, qs, bs, lf, ef, rBs, fUVs) do
    l = eval_mc1(e, qs, bs, lf, ef, fUVs, [])
    map = :maps.from_list(l)
    ret_expr(map, bs, rBs)
  end

  defp eval_mc1(e, [q | qs], bs0, lf, ef, fUVs, acc0) do
    case (is_generator(q)) do
      true ->
        cF = fn bs, acc ->
                  eval_mc1(e, qs, bs, lf, ef, fUVs, acc)
             end
        eval_generator(q, bs0, lf, ef, fUVs, acc0, cF)
      false ->
        cF = fn bs ->
                  eval_mc1(e, qs, bs, lf, ef, fUVs, acc0)
             end
        eval_filter(q, bs0, lf, ef, cF, fUVs, acc0)
    end
  end

  defp eval_mc1({:map_field_assoc, lfa, k0, v0}, [], bs, lf, ef,
            fUVs, acc) do
    {:value, kV, _} = expr({:tuple, lfa, [k0, v0]}, bs, lf,
                             ef, :none, fUVs)
    [kV | acc]
  end

  defp eval_generator({:generate, anno, p, l0}, bs0, lf, ef, fUVs,
            acc0, compFun) do
    {:value, l1, _Bs1} = expr(l0, bs0, lf, ef, :none, fUVs)
    eval_generate(l1, p, anno, bs0, lf, ef, compFun, acc0)
  end

  defp eval_generator({:b_generate, anno, p, bin0}, bs0, lf, ef, fUVs,
            acc0, compFun) do
    {:value, bin, _Bs1} = expr(bin0, bs0, lf, ef, :none,
                                 fUVs)
    eval_b_generate(bin, p, anno, bs0, lf, ef, compFun,
                      acc0)
  end

  defp eval_generator({:m_generate, anno, p, map0}, bs0, lf, ef, fUVs,
            acc0, compFun) do
    {:map_field_exact, _, k, v} = p
    {:value, map, _Bs1} = expr(map0, bs0, lf, ef, :none,
                                 fUVs)
    iter = (case (is_map(map)) do
              true ->
                :maps.iterator(map)
              false ->
                try do
                  :maps.foreach(fn _, _ ->
                                     :ok
                                end,
                                  map)
                catch
                  _, _ ->
                    apply_error({:bad_generator, map},
                                  :erlang.element(2,
                                                    :erlang.process_info(self(),
                                                                           :current_stacktrace)),
                                  anno, bs0, ef, :none)
                else
                  _ ->
                    map
                end
            end)
    eval_m_generate(iter, {:tuple, anno, [k, v]}, anno, bs0,
                      lf, ef, compFun, acc0)
  end

  defp eval_generate([v | rest], p, anno, bs0, lf, ef, compFun,
            acc) do
    case (match(p, v, anno, new_bindings(bs0), bs0, ef)) do
      {:match, bsn} ->
        bs2 = add_bindings(bsn, bs0)
        newAcc = compFun.(bs2, acc)
        eval_generate(rest, p, anno, bs0, lf, ef, compFun,
                        newAcc)
      :nomatch ->
        eval_generate(rest, p, anno, bs0, lf, ef, compFun, acc)
    end
  end

  defp eval_generate([], _P, _Anno, _Bs0, _Lf, _Ef, _CompFun, acc) do
    acc
  end

  defp eval_generate(term, _P, anno, bs0, _Lf, ef, _CompFun, _Acc) do
    apply_error({:bad_generator, term},
                  :erlang.element(2,
                                    :erlang.process_info(self(),
                                                           :current_stacktrace)),
                  anno, bs0, ef, :none)
  end

  defp eval_b_generate(<<_ :: bitstring>> = bin, p, anno, bs0, lf, ef,
            compFun, acc) do
    mfun = match_fun(bs0, ef)
    efun = fn exp, bs ->
                expr(exp, bs, lf, ef, :none)
           end
    errorFun = fn a, r, s ->
                    apply_error(r, s, a, bs0, ef, :none)
               end
    case (:eval_bits.bin_gen(p, bin, new_bindings(bs0), bs0,
                               mfun, efun, errorFun)) do
      {:match, rest, bs1} ->
        bs2 = add_bindings(bs1, bs0)
        newAcc = compFun.(bs2, acc)
        eval_b_generate(rest, p, anno, bs0, lf, ef, compFun,
                          newAcc)
      {:nomatch, rest} ->
        eval_b_generate(rest, p, anno, bs0, lf, ef, compFun,
                          acc)
      :done ->
        acc
    end
  end

  defp eval_b_generate(term, _P, anno, bs0, _Lf, ef, _CompFun, _Acc) do
    apply_error({:bad_generator, term},
                  :erlang.element(2,
                                    :erlang.process_info(self(),
                                                           :current_stacktrace)),
                  anno, bs0, ef, :none)
  end

  defp eval_m_generate(iter0, p, anno, bs0, lf, ef, compFun, acc0) do
    case (:maps.next(iter0)) do
      {k, v, iter} ->
        case (match(p, {k, v}, anno, new_bindings(bs0), bs0,
                      ef)) do
          {:match, bsn} ->
            bs2 = add_bindings(bsn, bs0)
            acc = compFun.(bs2, acc0)
            eval_m_generate(iter, p, anno, bs0, lf, ef, compFun,
                              acc)
          :nomatch ->
            eval_m_generate(iter, p, anno, bs0, lf, ef, compFun,
                              acc0)
        end
      :none ->
        acc0
    end
  end

  defp eval_filter(f, bs0, lf, ef, compFun, fUVs, acc) do
    case (:erl_lint.is_guard_test(f)) do
      true ->
        case (guard_test(f, bs0, lf, ef)) do
          {:value, true, bs1} ->
            compFun.(bs1)
          {:value, false, _} ->
            acc
        end
      false ->
        case (expr(f, bs0, lf, ef, :none, fUVs)) do
          {:value, true, bs1} ->
            compFun.(bs1)
          {:value, false, _} ->
            acc
          {:value, v, _} ->
            apply_error({:bad_filter, v},
                          :erlang.element(2,
                                            :erlang.process_info(self(),
                                                                   :current_stacktrace)),
                          :erlang.element(2, f), bs0, ef, :none)
        end
    end
  end

  defp is_generator({:generate, _, _, _}) do
    true
  end

  defp is_generator({:b_generate, _, _, _}) do
    true
  end

  defp is_generator({:m_generate, _, _, _}) do
    true
  end

  defp is_generator(_) do
    false
  end

  defp eval_map_fields(fs, bs, lf, ef, fUVs) do
    eval_map_fields(fs, bs, lf, ef, fUVs, [])
  end

  defp eval_map_fields([{:map_field_assoc, _, k0, v0} | fs], bs0, lf,
            ef, fUVs, acc) do
    {:value, k1, bs1} = expr(k0, bs0, lf, ef, :none, fUVs)
    {:value, v1, bs2} = expr(v0, bs1, lf, ef, :none, fUVs)
    eval_map_fields(fs, bs2, lf, ef, fUVs,
                      [{:map_assoc, k1, v1} | acc])
  end

  defp eval_map_fields([{:map_field_exact, _, k0, v0} | fs], bs0, lf,
            ef, fUVs, acc) do
    {:value, k1, bs1} = expr(k0, bs0, lf, ef, :none, fUVs)
    {:value, v1, bs2} = expr(v0, bs1, lf, ef, :none, fUVs)
    eval_map_fields(fs, bs2, lf, ef, fUVs,
                      [{:map_exact, k1, v1} | acc])
  end

  defp eval_map_fields([], bs, _Lf, _Ef, _FUVs, acc) do
    {:lists.reverse(acc), bs}
  end

  defp ret_expr(v, _Bs, :value) do
    v
  end

  defp ret_expr(v, bs, :none) do
    {:value, v, bs}
  end

  defp ret_expr(v, _Bs, rBs) when is_list(rBs) or is_map(rBs) do
    {:value, v, rBs}
  end

  defp eval_fun(as, {anno, bs0, lf, ef, fUVs, cs}) do
    eval_fun(cs, as, anno, bs0, lf, ef, :value, fUVs)
  end

  defp eval_fun([{:clause, _, h, g, b} | cs], as, anno, bs0, lf,
            ef, rBs, fUVs) do
    case (match_list(h, as, anno, new_bindings(bs0), bs0,
                       ef)) do
      {:match, bsn} ->
        bs1 = add_bindings(bsn, bs0)
        case (guard(g, bs1, lf, ef)) do
          true ->
            exprs(b, bs1, lf, ef, rBs, fUVs)
          false ->
            eval_fun(cs, as, anno, bs0, lf, ef, rBs, fUVs)
        end
      :nomatch ->
        eval_fun(cs, as, anno, bs0, lf, ef, rBs, fUVs)
    end
  end

  defp eval_fun([], as, anno, bs, _Lf, ef, rBs, _FUVs) do
    stack = [{:erl_eval, :"-inside-an-interpreted-fun-", as} | :erlang.element(2,
                                                     :erlang.process_info(self(),
                                                                            :current_stacktrace))]
    apply_error(:function_clause, stack, anno, bs, ef, rBs)
  end

  defp eval_named_fun(as, fun, {anno, bs0, lf, ef, fUVs, cs, name}) do
    eval_named_fun(cs, as, anno, bs0, lf, ef, name, fun,
                     :value, fUVs)
  end

  defp eval_named_fun([{:clause, _, h, g, b} | cs], as, anno, bs0, lf,
            ef, name, fun, rBs, fUVs) do
    bs1 = add_binding(name, fun, bs0)
    case (match_list(h, as, anno, new_bindings(bs0), bs1,
                       ef)) do
      {:match, bsn} ->
        bs2 = add_bindings(bsn, bs1)
        case (guard(g, bs2, lf, ef)) do
          true ->
            exprs(b, bs2, lf, ef, rBs, fUVs)
          false ->
            eval_named_fun(cs, as, anno, bs0, lf, ef, name, fun,
                             rBs, fUVs)
        end
      :nomatch ->
        eval_named_fun(cs, as, anno, bs0, lf, ef, name, fun,
                         rBs, fUVs)
    end
  end

  defp eval_named_fun([], as, anno, bs, _Lf, ef, _Name, _Fun, rBs,
            _FUVs) do
    stack = [{:erl_eval, :"-inside-an-interpreted-fun-", as} | :erlang.element(2,
                                                     :erlang.process_info(self(),
                                                                            :current_stacktrace))]
    apply_error(:function_clause, stack, anno, bs, ef, rBs)
  end

  def expr_list(es, bs) do
    expr_list(es, bs, :none, :none, empty_fun_used_vars())
  end

  def expr_list(es, bs, lf) do
    expr_list(es, bs, lf, :none, empty_fun_used_vars())
  end

  def expr_list(es, bs, lf, ef) do
    expr_list(es, bs, lf, ef, empty_fun_used_vars())
  end

  defp expr_list(es, bs, lf, ef, fUVs) do
    expr_list(es, [], bs, bs, lf, ef, fUVs)
  end

  defp expr_list([e | es], vs, bsOrig, bs0, lf, ef, fUVs) do
    {:value, v, bs1} = expr(e, bsOrig, lf, ef, :none, fUVs)
    expr_list(es, [v | vs], bsOrig,
                merge_bindings(bs1, bs0, :erlang.element(2, e), ef), lf,
                ef, fUVs)
  end

  defp expr_list([], vs, _, bs, _Lf, _Ef, _FUVs) do
    {reverse(vs), bs}
  end

  defp eval_op(op, arg1, arg2, anno, bs, ef, rBs) do
    do_apply(:erlang, op, [arg1, arg2], anno, bs, ef, rBs)
  end

  defp eval_op(op, arg, anno, bs, ef, rBs) do
    do_apply(:erlang, op, [arg], anno, bs, ef, rBs)
  end

  defp if_clauses([{:clause, _, [], g, b} | cs], anno, bs, lf, ef,
            rBs, fUVs) do
    case (guard(g, bs, lf, ef)) do
      true ->
        exprs(b, bs, lf, ef, rBs, fUVs)
      false ->
        if_clauses(cs, anno, bs, lf, ef, rBs, fUVs)
    end
  end

  defp if_clauses([], anno, bs, _Lf, ef, rBs, _FUVs) do
    apply_error(:if_clause,
                  :erlang.element(2,
                                    :erlang.process_info(self(),
                                                           :current_stacktrace)),
                  anno, bs, ef, rBs)
  end

  defp try_clauses(b, cases, catches, aB, anno, bs, lf, ef, rBs,
            fUVs) do
    check_stacktrace_vars(catches, anno, bs, ef, rBs)
    try do
      exprs(b, bs, lf, ef, :none, fUVs)
    catch
      class, reason when catches === [] ->
        :erlang.raise(class, reason, __STACKTRACE__)
      class, reason ->
        v = {class, reason, __STACKTRACE__}
        case (match_clause(catches, [v], bs, lf, ef)) do
          {b2, bs2} ->
            exprs(b2, bs2, lf, ef, rBs, fUVs)
          :nomatch ->
            :erlang.raise(class, reason, __STACKTRACE__)
        end
    else
      {:value, v, bs1} when cases === [] ->
        ret_expr(v, bs1, rBs)
      {:value, v, bs1} ->
        case (match_clause(cases, [v], bs1, lf, ef)) do
          {b2, bs2} ->
            exprs(b2, bs2, lf, ef, rBs, fUVs)
          :nomatch ->
            apply_error({:try_clause, v},
                          :erlang.element(2,
                                            :erlang.process_info(self(),
                                                                   :current_stacktrace)),
                          anno, bs, ef, rBs)
        end
    after
      cond do
        aB === [] ->
          bs
        true ->
          exprs(aB, bs, lf, ef, :none, fUVs)
      end
    end
  end

  defp check_stacktrace_vars([{:clause, _, [{:tuple, _, [_, _, sTV]}], _,
              _} |
               cs],
            anno, bs, ef, rBs) do
    case (sTV) do
      {:var, _, v} ->
        case (binding(v, bs)) do
          {:value, _} ->
            apply_error(:stacktrace_bound,
                          :erlang.element(2,
                                            :erlang.process_info(self(),
                                                                   :current_stacktrace)),
                          anno, bs, ef, rBs)
          :unbound ->
            check_stacktrace_vars(cs, anno, bs, ef, rBs)
        end
      _ ->
        reason = {:illegal_stacktrace_variable, sTV}
        apply_error(reason,
                      :erlang.element(2,
                                        :erlang.process_info(self(),
                                                               :current_stacktrace)),
                      anno, bs, ef, rBs)
    end
  end

  defp check_stacktrace_vars([], _Anno, _Bs, _Ef, _RBs) do
    :ok
  end

  defp case_clauses(val, cs, anno, bs, lf, ef, rBs, fUVs) do
    case (match_clause(cs, [val], bs, lf, ef)) do
      {b, bs1} ->
        exprs(b, bs1, lf, ef, rBs, fUVs)
      :nomatch ->
        apply_error({:case_clause, val},
                      :erlang.element(2,
                                        :erlang.process_info(self(),
                                                               :current_stacktrace)),
                      anno, bs, ef, rBs)
    end
  end

  defp receive_clauses(cs, bs, lf, ef, rBs, fUVs) do
    receive_clauses(:infinity, cs, :unused, bs, lf, ef, rBs,
                      fUVs)
  end

  defp receive_clauses(t, cs, tB, bs, lf, ef, rBs, fUVs) do
    f = fn m ->
             match_clause(cs, [m], bs, lf, ef)
        end
    case (:prim_eval.receive(f, t)) do
      {b, bs1} ->
        exprs(b, bs1, lf, ef, rBs, fUVs)
      :timeout ->
        {b, bs1} = tB
        exprs(b, bs1, lf, ef, rBs, fUVs)
    end
  end

  def match_clause(cs, vs, bs, lf) do
    match_clause(cs, vs, bs, lf, :none)
  end

  defp match_clause([{:clause, anno, h, g, b} | cs], vals, bs, lf,
            ef) do
    case (match_list(h, vals, anno, bs, bs, ef)) do
      {:match, bs1} ->
        case (guard(g, bs1, lf, ef)) do
          true ->
            {b, bs1}
          false ->
            match_clause(cs, vals, bs, lf, ef)
        end
      :nomatch ->
        match_clause(cs, vals, bs, lf, ef)
    end
  end

  defp match_clause([], _Vals, _Bs, _Lf, _Ef) do
    :nomatch
  end

  defp guard(l = [g | _], bs0, lf, ef) when is_list(g) do
    guard1(l, bs0, lf, ef)
  end

  defp guard(l, bs0, lf, ef) do
    guard0(l, bs0, lf, ef)
  end

  defp guard1([g | gs], bs0, lf, ef) when is_list(g) do
    case (guard0(g, bs0, lf, ef)) do
      true ->
        true
      false ->
        guard1(gs, bs0, lf, ef)
    end
  end

  defp guard1([], _Bs, _Lf, _Ef) do
    false
  end

  defp guard0([g | gs], bs0, lf, ef) do
    case (:erl_lint.is_guard_test(g)) do
      true ->
        case (guard_test(g, bs0, lf, ef)) do
          {:value, true, bs} ->
            guard0(gs, bs, lf, ef)
          {:value, false, _} ->
            false
        end
      false ->
        apply_error(:guard_expr,
                      :erlang.element(2,
                                        :erlang.process_info(self(),
                                                               :current_stacktrace)),
                      :erlang.element(2, g), bs0, ef, :none)
    end
  end

  defp guard0([], _Bs, _Lf, _Ef) do
    true
  end

  defp guard_test({:call, a, {:atom, ln, f}, as0}, bs0, lf, ef) do
    tT = type_test(f)
    g = {:call, a, {:atom, ln, tT}, as0}
    expr_guard_test(g, bs0, lf, ef)
  end

  defp guard_test({:call, a,
             {:remote, ar, {:atom, am, :erlang}, {:atom, af, f}},
             as0},
            bs0, lf, ef) do
    tT = type_test(f)
    g = {:call, a,
           {:remote, ar, {:atom, am, :erlang}, {:atom, af, tT}},
           as0}
    expr_guard_test(g, bs0, lf, ef)
  end

  defp guard_test(g, bs0, lf, ef) do
    expr_guard_test(g, bs0, lf, ef)
  end

  defp expr_guard_test(g, bs0, lf, ef) do
    try do
      {:value, true, _} = expr(g, bs0, lf, ef, :none)
    catch
      :error, _ ->
        {:value, false, bs0}
    end
  end

  defp type_test(:integer) do
    :is_integer
  end

  defp type_test(:float) do
    :is_float
  end

  defp type_test(:number) do
    :is_number
  end

  defp type_test(:atom) do
    :is_atom
  end

  defp type_test(:list) do
    :is_list
  end

  defp type_test(:tuple) do
    :is_tuple
  end

  defp type_test(:pid) do
    :is_pid
  end

  defp type_test(:reference) do
    :is_reference
  end

  defp type_test(:port) do
    :is_port
  end

  defp type_test(:function) do
    :is_function
  end

  defp type_test(:binary) do
    :is_binary
  end

  defp type_test(:record) do
    :is_record
  end

  defp type_test(:map) do
    :is_map
  end

  defp type_test(test) do
    test
  end

  defp match(pat, term, anno, bs, bBs, ef) do
    case ((try do
            match1(pat, term, bs, bBs, ef)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      :invalid ->
        apply_error({:illegal_pattern, to_term(pat)},
                      :erlang.element(2,
                                        :erlang.process_info(self(),
                                                               :current_stacktrace)),
                      anno, bs, ef, :none)
      other ->
        other
    end
  end

  defp string_to_conses([], _, tail) do
    tail
  end

  defp string_to_conses([e | rest], anno, tail) do
    {:cons, anno, {:integer, anno, e},
       string_to_conses(rest, anno, tail)}
  end

  defp match1({:atom, _, a0}, a, bs, _BBs, _Ef) do
    case (a) do
      ^a0 ->
        {:match, bs}
      _ ->
        throw(:nomatch)
    end
  end

  defp match1({:integer, _, i0}, i, bs, _BBs, _Ef) do
    case (i) do
      ^i0 ->
        {:match, bs}
      _ ->
        throw(:nomatch)
    end
  end

  defp match1({:float, _, f0}, f, bs, _BBs, _Ef) do
    case (f) do
      ^f0 ->
        {:match, bs}
      _ ->
        throw(:nomatch)
    end
  end

  defp match1({:char, _, c0}, c, bs, _BBs, _Ef) do
    case (c) do
      ^c0 ->
        {:match, bs}
      _ ->
        throw(:nomatch)
    end
  end

  defp match1({:var, _, :_}, _, bs, _BBs, _Ef) do
    {:match, bs}
  end

  defp match1({:var, _, name}, term, bs, _BBs, _Ef) do
    case (binding(name, bs)) do
      {:value, ^term} ->
        {:match, bs}
      {:value, _} ->
        throw(:nomatch)
      :unbound ->
        {:match, add_binding(name, term, bs)}
    end
  end

  defp match1({:match, _, pat1, pat2}, term, bs0, bBs, ef) do
    {:match, bs1} = match1(pat1, term, bs0, bBs, ef)
    match1(pat2, term, bs1, bBs, ef)
  end

  defp match1({:string, _, s0}, s, bs, _BBs, _Ef) do
    case (s) do
      ^s0 ->
        {:match, bs}
      _ ->
        throw(:nomatch)
    end
  end

  defp match1({nil, _}, nil__, bs, _BBs, _Ef) do
    case (nil__) do
      [] ->
        {:match, bs}
      _ ->
        throw(:nomatch)
    end
  end

  defp match1({:cons, _, h, t}, [h1 | t1], bs0, bBs, ef) do
    {:match, bs} = match1(h, h1, bs0, bBs, ef)
    match1(t, t1, bs, bBs, ef)
  end

  defp match1({:cons, _, _, _}, _, _Bs, _BBs, _Ef) do
    throw(:nomatch)
  end

  defp match1({:tuple, _, elts}, tuple, bs, bBs, ef)
      when length(elts) === tuple_size(tuple) do
    match_tuple(elts, tuple, 1, bs, bBs, ef)
  end

  defp match1({:tuple, _, _}, _, _Bs, _BBs, _Ef) do
    throw(:nomatch)
  end

  defp match1({:map, _, fs}, %{} = map, bs, bBs, ef) do
    match_map(fs, map, bs, bBs, ef)
  end

  defp match1({:map, _, _}, _, _Bs, _BBs, _Ef) do
    throw(:nomatch)
  end

  defp match1({:bin, _, fs}, <<_ :: bitstring>> = b, bs0, bBs,
            ef) do
    evalFun = fn e, bs ->
                   case (:erl_lint.is_guard_expr(e)) do
                     true ->
                       :ok
                     false ->
                       throw(:invalid)
                   end
                   try do
                     expr(e, bs, :none, :none, :none)
                   catch
                     :error, {:unbound, _} ->
                       throw(:invalid)
                   end
              end
    errorFun = fn a, r, s ->
                    apply_error(r, s, a, bs0, ef, :none)
               end
    :eval_bits.match_bits(fs, b, bs0, bBs,
                            match_fun(bBs, ef), evalFun, errorFun)
  end

  defp match1({:bin, _, _}, _, _Bs, _BBs, _Ef) do
    throw(:nomatch)
  end

  defp match1({:op, _, :"++", {nil, _}, r}, term, bs, bBs, ef) do
    match1(r, term, bs, bBs, ef)
  end

  defp match1({:op, _, :"++", {:cons, ai, {:integer, a2, i}, t},
             r},
            term, bs, bBs, ef) do
    match1({:cons, ai, {:integer, a2, i},
              {:op, ai, :"++", t, r}},
             term, bs, bBs, ef)
  end

  defp match1({:op, _, :"++", {:cons, ai, {:char, a2, c}, t}, r},
            term, bs, bBs, ef) do
    match1({:cons, ai, {:char, a2, c}, {:op, ai, :"++", t, r}},
             term, bs, bBs, ef)
  end

  defp match1({:op, _, :"++", {:string, ai, l}, r}, term, bs,
            bBs, ef) do
    match1(string_to_conses(l, ai, r), term, bs, bBs, ef)
  end

  defp match1({:op, anno, op, a}, term, bs, bBs, ef) do
    case (partial_eval({:op, anno, op, a})) do
      {:op, ^anno, ^op, ^a} ->
        throw(:invalid)
      x ->
        match1(x, term, bs, bBs, ef)
    end
  end

  defp match1({:op, anno, op, l, r}, term, bs, bBs, ef) do
    case (partial_eval({:op, anno, op, l, r})) do
      {:op, ^anno, ^op, ^l, ^r} ->
        throw(:invalid)
      x ->
        match1(x, term, bs, bBs, ef)
    end
  end

  defp match1(_, _, _Bs, _BBs, _Ef) do
    throw(:invalid)
  end

  defp match_fun(bBs, ef) do
    fn :match, {l, r, bs} ->
         match1(l, r, bs, bBs, ef)
       :binding, {name, bs} ->
         binding(name, bs)
       :add_binding, {name, val, bs} ->
         add_binding(name, val, bs)
    end
  end

  defp match_tuple([e | es], tuple, i, bs0, bBs, ef) do
    {:match, bs} = match1(e, :erlang.element(i, tuple), bs0,
                            bBs, ef)
    match_tuple(es, tuple, i + 1, bs, bBs, ef)
  end

  defp match_tuple([], _, _, bs, _BBs, _Ef) do
    {:match, bs}
  end

  defp match_map([{:map_field_exact, _, k, v} | fs], map, bs0,
            bBs, ef) do
    vm = (try do
            {:value, ke, _} = expr(k, bBs)
            :maps.get(ke, map)
          catch
            :error, _ ->
              throw(:nomatch)
          end)
    {:match, bs} = match1(v, vm, bs0, bBs, ef)
    match_map(fs, map, bs, bBs, ef)
  end

  defp match_map([], _, bs, _, _) do
    {:match, bs}
  end

  defp match_list([p | ps], [t | ts], anno, bs0, bBs, ef) do
    case (match(p, t, anno, bs0, bBs, ef)) do
      {:match, bs1} ->
        match_list(ps, ts, anno, bs1, bBs, ef)
      :nomatch ->
        :nomatch
    end
  end

  defp match_list([], [], _Anno, bs, _BBs, _Ef) do
    {:match, bs}
  end

  defp match_list(_, _, _Anno, _Bs, _BBs, _Ef) do
    :nomatch
  end

  def new_bindings() do
    :orddict.new()
  end

  def bindings(bs) when is_map(bs) do
    :maps.to_list(bs)
  end

  def bindings(bs) when is_list(bs) do
    :orddict.to_list(bs)
  end

  def binding(name, bs) when is_map(bs) do
    case (:maps.find(name, bs)) do
      {:ok, val} ->
        {:value, val}
      :error ->
        :unbound
    end
  end

  def binding(name, bs) when is_list(bs) do
    case (:orddict.find(name, bs)) do
      {:ok, val} ->
        {:value, val}
      :error ->
        :unbound
    end
  end

  def add_binding(name, val, bs) when is_map(bs) do
    :maps.put(name, val, bs)
  end

  def add_binding(name, val, bs) when is_list(bs) do
    :orddict.store(name, val, bs)
  end

  def del_binding(name, bs) when is_map(bs) do
    :maps.remove(name, bs)
  end

  def del_binding(name, bs) when is_list(bs) do
    :orddict.erase(name, bs)
  end

  defp add_bindings(bs1, bs2) when (is_map(bs1) and is_map(bs2)) do
    :maps.merge(bs2, bs1)
  end

  defp add_bindings(bs1, bs2) do
    foldl(fn {name, val}, bs ->
               :orddict.store(name, val, bs)
          end,
            bs2, :orddict.to_list(bs1))
  end

  defp merge_bindings(bs1, bs2, anno, ef) when (is_map(bs1) and
                                      is_map(bs2)) do
    :maps.merge_with(fn _K, v, v ->
                          v
                        _K, _, v ->
                          apply_error({:badmatch, v},
                                        :erlang.element(2,
                                                          :erlang.process_info(self(),
                                                                                 :current_stacktrace)),
                                        anno, bs1, ef, :none)
                     end,
                       bs2, bs1)
  end

  defp merge_bindings(bs1, bs2, anno, ef) do
    foldl(fn {name, val}, bs ->
               case (:orddict.find(name, bs)) do
                 {:ok, ^val} ->
                   bs
                 {:ok, v1} ->
                   apply_error({:badmatch, v1},
                                 :erlang.element(2,
                                                   :erlang.process_info(self(),
                                                                          :current_stacktrace)),
                                 anno, bs1, ef, :none)
                 :error ->
                   :orddict.store(name, val, bs)
               end
          end,
            bs2, :orddict.to_list(bs1))
  end

  defp new_bindings(bs) when is_map(bs) do
    :maps.new()
  end

  defp new_bindings(bs) when is_list(bs) do
    :orddict.new()
  end

  defp filter_bindings(fun, bs) when is_map(bs) do
    :maps.filter(fun, bs)
  end

  defp filter_bindings(fun, bs) when is_list(bs) do
    :orddict.filter(fun, bs)
  end

  defp to_terms(abstrs) do
    for abstr <- abstrs do
      to_term(abstr)
    end
  end

  defp to_term(abstr) do
    :erl_parse.anno_to_term(abstr)
  end

  def extended_parse_exprs(tokens) do
    ts = tokens_fixup(tokens)
    case (:erl_parse.parse_exprs(ts)) do
      {:ok, exprs0} ->
        exprs = expr_fixup(exprs0)
        {:ok, reset_expr_anno(exprs)}
      _ErrorInfo ->
        :erl_parse.parse_exprs(reset_token_anno(ts))
    end
  end

  defp tokens_fixup([]) do
    []
  end

  defp tokens_fixup([t | ts] = ts0) do
    try do
      token_fixup(ts0)
    catch
      _, _ ->
        [t | tokens_fixup(ts)]
    else
      {newT, newTs} ->
        [newT | tokens_fixup(newTs)]
    end
  end

  defp token_fixup(ts) do
    {annoL, newTs, fixupTag} = unscannable(ts)
    string = :lists.append(for a <- annoL do
                             :erl_anno.text(a)
                           end)
    _ = validate_tag(fixupTag, string)
    newAnno = :erl_anno.set_text(fixup_text(fixupTag),
                                   hd(annoL))
    {{:string, newAnno, string}, newTs}
  end

  defp unscannable([{:"#", a1}, {:var, a2, :Fun}, {:"<", a3}, {:atom,
                                                    a4, _},
                                                     {:".", a5}, {:float, a6, _},
                                                                   {:">", a7} |
                                                                       ts]) do
    {[a1, a2, a3, a4, a5, a6, a7], ts, :function}
  end

  defp unscannable([{:"#", a1}, {:var, a2, :Fun}, {:"<", a3}, {:atom,
                                                    a4, _},
                                                     {:".", a5}, {:atom, a6, _},
                                                                   {:".", a7},
                                                                       {:integer,
                                                                          a8,
                                                                          _},
                                                                           {:">",
                                                                              a9} |
                                                                               ts]) do
    {[a1, a2, a3, a4, a5, a6, a7, a8, a9], ts, :function}
  end

  defp unscannable([{:"<", a1}, {:float, a2, _}, {:".", a3}, {:integer,
                                                   a4, _},
                                                    {:">", a5} | ts]) do
    {[a1, a2, a3, a4, a5], ts, :pid}
  end

  defp unscannable([{:"#", a1}, {:var, a2, :Port}, {:"<", a3}, {:float,
                                                     a4, _},
                                                      {:">", a5} | ts]) do
    {[a1, a2, a3, a4, a5], ts, :port}
  end

  defp unscannable([{:"#", a1}, {:var, a2, :Ref}, {:"<", a3}, {:float,
                                                    a4, _},
                                                     {:".", a5}, {:float, a6, _},
                                                                   {:">", a7} |
                                                                       ts]) do
    {[a1, a2, a3, a4, a5, a6, a7], ts, :reference}
  end

  defp expr_fixup({:string, a, s} = t) do
    try do
      string_fixup(a, s, t)
    catch
      _, _ ->
        t
    else
      expr ->
        expr
    end
  end

  defp expr_fixup(tuple) when is_tuple(tuple) do
    l = expr_fixup(:erlang.tuple_to_list(tuple))
    :erlang.list_to_tuple(l)
  end

  defp expr_fixup([e0 | es0]) do
    e = expr_fixup(e0)
    es = expr_fixup(es0)
    [e | es]
  end

  defp expr_fixup(t) do
    t
  end

  defp string_fixup(anno, string, token) do
    text = :erl_anno.text(anno)
    fixupTag = fixup_tag(text, string)
    fixup_ast(fixupTag, anno, string, token)
  end

  defp reset_token_anno(tokens) do
    for t <- tokens do
      :erlang.setelement(2, t,
                           (reset_anno()).(:erlang.element(2, t)))
    end
  end

  defp reset_expr_anno(exprs) do
    for e <- exprs do
      :erl_parse.map_anno(reset_anno(), e)
    end
  end

  defp reset_anno() do
    fn a ->
         :erl_anno.new(:erl_anno.location(a))
    end
  end

  defp fixup_ast(:pid, a, _S, t) do
    {:call, a,
       {:remote, a, {:atom, a, :erlang},
          {:atom, a, :list_to_pid}},
       [t]}
  end

  defp fixup_ast(:port, a, _S, t) do
    {:call, a,
       {:remote, a, {:atom, a, :erlang},
          {:atom, a, :list_to_port}},
       [t]}
  end

  defp fixup_ast(:reference, a, _S, t) do
    {:call, a,
       {:remote, a, {:atom, a, :erlang},
          {:atom, a, :list_to_ref}},
       [t]}
  end

  defp fixup_ast(:function, a, s, _T) do
    {module, function, arity} = fixup_mfa(s)
    {:fun, a,
       {:function, {:atom, a, module}, {:atom, a, function},
          {:integer, a, arity}}}
  end

  defp fixup_text(:function) do
    'function'
  end

  defp fixup_text(:pid) do
    'pid'
  end

  defp fixup_text(:port) do
    'port'
  end

  defp fixup_text(:reference) do
    'reference'
  end

  defp fixup_tag('function', '#' ++ _) do
    :function
  end

  defp fixup_tag('pid', '<' ++ _) do
    :pid
  end

  defp fixup_tag('port', '#' ++ _) do
    :port
  end

  defp fixup_tag('reference', '#' ++ _) do
    :reference
  end

  defp fixup_mfa(s) do
    {:ok,
       [_, _, _, {:atom, _, module}, _, {:atom, _, function},
                                            _, {:integer, _, arity} | _],
       _} = :erl_scan.string(s)
    {module, function, arity}
  end

  defp validate_tag(:pid, string) do
    :erlang.list_to_pid(string)
  end

  defp validate_tag(:port, string) do
    :erlang.list_to_port(string)
  end

  defp validate_tag(:reference, string) do
    :erlang.list_to_ref(string)
  end

  defp validate_tag(:function, string) do
    {module, function, arity} = fixup_mfa(string)
    :erlang.make_fun(module, function, arity)
  end

  def extended_parse_term(tokens) do
    case (extended_parse_exprs(tokens)) do
      {:ok, [expr]} ->
        try do
          normalise(expr)
        catch
          _, _ ->
            loc = :erl_anno.location(:erlang.element(2, expr))
            {:error, {loc, :erl_eval, 'bad term'}}
        else
          term ->
            {:ok, term}
        end
      {:ok, [_, expr | _]} ->
        loc = :erl_anno.location(:erlang.element(2, expr))
        {:error, {loc, :erl_eval, 'bad term'}}
      {:error, _} = error ->
        error
    end
  end

  defp normalise({:char, _, c}) do
    c
  end

  defp normalise({:integer, _, i}) do
    i
  end

  defp normalise({:float, _, f}) do
    f
  end

  defp normalise({:atom, _, a}) do
    a
  end

  defp normalise({:string, _, s}) do
    s
  end

  defp normalise({nil, _}) do
    []
  end

  defp normalise({:bin, _, fs}) do
    {:value, b, _} = :eval_bits.expr_grp(fs, [],
                                           fn e, _ ->
                                                {:value, normalise(e), []}
                                           end)
    b
  end

  defp normalise({:cons, _, head, tail}) do
    [normalise(head) | normalise(tail)]
  end

  defp normalise({:tuple, _, args}) do
    :erlang.list_to_tuple(normalise_list(args))
  end

  defp normalise({:map, _, pairs}) do
    :maps.from_list(:lists.map(fn {:map_field_assoc, _, k,
                                     v} ->
                                    {normalise(k), normalise(v)}
                               end,
                                 pairs))
  end

  defp normalise({:op, _, :"+", {:char, _, i}}) do
    i
  end

  defp normalise({:op, _, :"+", {:integer, _, i}}) do
    i
  end

  defp normalise({:op, _, :"+", {:float, _, f}}) do
    f
  end

  defp normalise({:op, _, :-, {:char, _, i}}) do
    - i
  end

  defp normalise({:op, _, :-, {:integer, _, i}}) do
    - i
  end

  defp normalise({:op, _, :-, {:float, _, f}}) do
    - f
  end

  defp normalise({:call, _,
             {:remote, _, {:atom, _, :erlang}, {:atom, _, fun}},
             [{:string, _, s}]})
      when fun === :list_to_ref or fun === :list_to_port or
             fun === :list_to_pid do
    apply(:erlang, fun, [s])
  end

  defp normalise({:fun, _,
             {:function, {:atom, _, m}, {:atom, _, f},
                {:integer, _, a}}}) do
    Function.capture(m, f, a)
  end

  defp normalise_list([h | t]) do
    [normalise(h) | normalise_list(t)]
  end

  defp normalise_list([]) do
    []
  end

  def is_constant_expr(expr) do
    case (eval_expr(expr)) do
      {:ok, x} when is_number(x) ->
        true
      _ ->
        false
    end
  end

  defp eval_expr(expr) do
    case ((try do
            ev_expr(expr)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      x when is_integer(x) ->
        {:ok, x}
      x when is_float(x) ->
        {:ok, x}
      x when is_atom(x) ->
        {:ok, x}
      {:EXIT, reason} ->
        {:error, reason}
      _ ->
        {:error, :badarg}
    end
  end

  def partial_eval(expr) do
    anno = anno(expr)
    case ((try do
            ev_expr(expr)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      x when is_integer(x) ->
        ret_expr(expr, {:integer, anno, x})
      x when is_float(x) ->
        ret_expr(expr, {:float, anno, x})
      x when is_atom(x) ->
        ret_expr(expr, {:atom, anno, x})
      _ ->
        expr
    end
  end

  defp ev_expr({:op, _, op, l, r}) do
    apply(:erlang, op, [ev_expr(l), ev_expr(r)])
  end

  defp ev_expr({:op, _, op, a}) do
    apply(:erlang, op, [ev_expr(a)])
  end

  defp ev_expr({:integer, _, x}) do
    x
  end

  defp ev_expr({:char, _, x}) do
    x
  end

  defp ev_expr({:float, _, x}) do
    x
  end

  defp ev_expr({:atom, _, x}) do
    x
  end

  defp ev_expr({:tuple, _, es}) do
    :erlang.list_to_tuple(for x <- es do
                            ev_expr(x)
                          end)
  end

  defp ev_expr({nil, _}) do
    []
  end

  defp ev_expr({:cons, _, h, t}) do
    [ev_expr(h) | ev_expr(t)]
  end

  def eval_str(str) when is_list(str) do
    case (:erl_scan.tokens([], str, 0)) do
      {:more, _} ->
        {:error, 'Incomplete form (missing .<cr>)??'}
      {:done, {:ok, toks, _}, rest} ->
        case (all_white(rest)) do
          true ->
            case (:erl_parse.parse_exprs(toks)) do
              {:ok, exprs} ->
                case ((try do
                        :erl_eval.exprs(exprs, :erl_eval.new_bindings())
                      catch
                        :error, e -> {:EXIT, {e, __STACKTRACE__}}
                        :exit, e -> {:EXIT, e}
                        e -> e
                      end)) do
                  {:value, val, _} ->
                    {:ok, val}
                  other ->
                    {:error, :lists.flatten(:io_lib.format('*** eval: ~p', [other]))}
                end
              {:error, {_Location, mod, args}} ->
                msg = :lists.flatten(:io_lib.format('*** ~ts',
                                                      [mod.format_error(args)]))
                {:error, msg}
            end
          false ->
            {:error, :lists.flatten(:io_lib.format('Non-white space found after end-of-form :~ts', [rest]))}
        end
    end
  end

  def eval_str(bin) when is_binary(bin) do
    eval_str(:erlang.binary_to_list(bin))
  end

  defp all_white([?\s | t]) do
    all_white(t)
  end

  defp all_white([?\n | t]) do
    all_white(t)
  end

  defp all_white([?\t | t]) do
    all_white(t)
  end

  defp all_white([]) do
    true
  end

  defp all_white(_) do
    false
  end

  defp ret_expr(_Old, new) do
    new
  end

  defp anno(expr) do
    :erlang.element(2, expr)
  end

end