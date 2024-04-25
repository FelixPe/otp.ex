defmodule :m_shell do
  use Bitwise
  require Record
  Record.defrecord(:r_shell_state, :shell_state, bindings: [], records: [], functions: [])

  def local_allowed(:q, [], state) do
    {true, state}
  end

  def local_allowed(_, _, state) do
    {false, state}
  end

  def non_local_allowed({:init, :stop}, [], state) do
    {true, state}
  end

  def non_local_allowed(_, _, state) do
    {false, state}
  end

  def start_interactive() do
    :user_drv.start_shell()
  end

  def start_interactive({node, {m, f, a}}) do
    :user_drv.start_shell(%{initial_shell: {node, m, f, a}})
  end

  def start_interactive(initialShell) do
    :user_drv.start_shell(%{initial_shell: initialShell})
  end

  def whereis() do
    :group.whereis_shell()
  end

  def start() do
    start(false, false)
  end

  def start(:init) do
    start(false, true)
  end

  def start(noCtrlG) do
    start(noCtrlG, false)
  end

  def start(noCtrlG, startSync) do
    _ = :code.ensure_loaded(:user_default)

    ancestors = [
      self()
      | case :erlang.get(:"$ancestors") do
          :undefined ->
            []

          anc ->
            anc
        end
    ]

    spawn(fn ->
      :erlang.put(:"$ancestors", ancestors)
      server(noCtrlG, startSync)
    end)
  end

  def start_restricted(rShMod) when is_atom(rShMod) do
    case :code.ensure_loaded(rShMod) do
      {:module, ^rShMod} ->
        :application.set_env(:stdlib, :restricted_shell, rShMod)
        exit(:restricted_shell_started)

      {:error, what} = error ->
        :error_logger.error_report(
          :lists.flatten(
            :io_lib.fwrite(
              ~c"Restricted shell module ~w not found: ~tp\n",
              [rShMod, what]
            )
          )
        )

        error
    end
  end

  def stop_restricted() do
    :application.unset_env(:stdlib, :restricted_shell)
    exit(:restricted_shell_stopped)
  end

  def server(noCtrlG, startSync) do
    :erlang.put(:no_control_g, noCtrlG)
    server(startSync)
  end

  def server(startSync) do
    case :init.get_argument(:async_shell_start) do
      {:ok, _} ->
        :ok

      _ when not startSync ->
        :ok

      _ ->
        case :init.notify_when_started(self()) do
          :started ->
            :ok

          _ ->
            :init.wait_until_started()
        end
    end

    bs = :erl_eval.new_bindings()
    rT = :ets.new(:shell_records, [:public, :ordered_set])
    _ = initiate_records(bs, rT)
    :erlang.process_flag(:trap_exit, true)
    fT = :ets.new(:user_functions, [:public, :ordered_set])

    rShErr =
      case :application.get_env(
             :stdlib,
             :restricted_shell
           ) do
        {:ok, rShMod} when is_atom(rShMod) ->
          :io.fwrite("Restricted ", [])

          case :code.ensure_loaded(rShMod) do
            {:module, ^rShMod} ->
              :undefined

            {:error, what} ->
              {rShMod, what}
          end

        {:ok, term} ->
          {term, :not_an_atom}

        :undefined ->
          :undefined
      end

    jCL =
      case :erlang.get(:no_control_g) do
        true ->
          ~c" (type help(). for help)"

        _ ->
          ~c" (press Ctrl+G to abort, type help(). for help)"
      end

    defaultSessionSlogan =
      :io_lib.format(
        "Eshell V~s",
        [:erlang.system_info(:version)]
      )

    sessionSlogan =
      case :application.get_env(
             :stdlib,
             :shell_session_slogan,
             defaultSessionSlogan
           ) do
        sloganFun when is_function(sloganFun, 0) ->
          sloganFun.()

        slogan ->
          slogan
      end

    try do
      :io.fwrite(
        ~c"~ts~ts\n",
        [:unicode.characters_to_list(sessionSlogan), jCL]
      )
    catch
      _, _ ->
        :io.fwrite(~c"Warning! The slogan \"~p\" could not be printed.\n", [sessionSlogan])
    end

    :erlang.erase(:no_control_g)

    case rShErr do
      :undefined ->
        :ok

      {rShMod2, what2} ->
        :io.fwrite(
          ~c"Warning! Restricted shell module ~w not found: ~tp.\nOnly the commands q() and init:stop() will be allowed!\n",
          [rShMod2, what2]
        )

        :application.set_env(:stdlib, :restricted_shell, :shell)
    end

    {history, results} = check_and_get_history_and_results()
    server_loop(0, start_eval(bs, rT, fT, []), bs, rT, fT, [], history, results)
  end

  defp server_loop(n0, eval_0, bs00, rT, fT, ds00, history0, results0) do
    n = n0 + 1
    {eval_1, bs0, ds0, prompt} = prompt(n, eval_0, bs00, rT, fT, ds00)
    {res, eval0} = get_command(prompt, eval_1, bs0, rT, fT, ds0)

    case res do
      {:ok, es0} ->
        case expand_hist(es0, n) do
          {:ok, es} ->
            {v, eval, bs, ds} = shell_cmd(es, eval0, bs0, rT, fT, ds0, :cmd)
            {history, results} = check_and_get_history_and_results()
            add_cmd(n, es, v)
            hB1 = del_cmd(:command, n - history, n - history0, false)
            hB = del_cmd(:result, n - results, n - results0, hB1)

            cond do
              hB ->
                garb(self())

              results < results0 ->
                garb(self())

              true ->
                :ok
            end

            server_loop(n, eval, bs, rT, fT, ds, history, results)

          {:error, e} ->
            fwrite_severity(:benign, "~ts", [e])
            server_loop(n0, eval0, bs0, rT, fT, ds0, history0, results0)
        end

      {:error, {location, mod, what}} ->
        fwrite_severity(:benign, "~s: ~ts", [pos(location), mod.format_error(what)])
        server_loop(n0, eval0, bs0, rT, fT, ds0, history0, results0)

      {:error, :terminated} ->
        :erlang.exit(eval0, :kill)
        :terminated

      {:error, :interrupted} ->
        :erlang.exit(eval0, :kill)
        {_, eval, _, _} = shell_rep(eval0, bs0, rT, fT, ds0)
        server_loop(n0, eval, bs0, rT, fT, ds0, history0, results0)

      {:error, :tokens} ->
        fwrite_severity(:benign, "~w: Invalid tokens.", [n])
        server_loop(n0, eval0, bs0, rT, fT, ds0, history0, results0)

      :eof ->
        fwrite_severity(:fatal, "Terminating erlang (~w)", [node()])
        :erlang.halt()
    end
  end

  defp get_command(prompt, eval, bs, rT, fT, ds) do
    ancestors = [self() | :erlang.get(:"$ancestors")]
    resWordFun = &:erl_scan.reserved_word/1

    parse = fn ->
      :erlang.put(:"$ancestors", ancestors)

      exit(
        case :io.scan_erl_exprs(:erlang.group_leader(), prompt, {1, 1}, [
               :text,
               {:reserved_word_fun, resWordFun}
             ]) do
          {:ok, toks, _EndPos} ->
            case toks do
              [{:-, _}, {:atom, _, atom} | _] ->
                specialCase = fn localFunc ->
                  fakeLine =
                    case :erl_parse.parse_form(toks) do
                      {:ok, def__} ->
                        :lists.flatten(:erl_pp.form(def__))

                      e ->
                        exit(e)
                    end

                  {:done, {:ok, fakeResult, _}, _} =
                    :erl_scan.tokens(
                      [],
                      :erlang.atom_to_list(localFunc) ++ ~c"(\"" ++ fakeLine ++ ~c"\").\n",
                      {1, 1},
                      [:text, {:reserved_word_fun, &:erl_scan.reserved_word/1}]
                    )

                  :erl_eval.extended_parse_exprs(fakeResult)
                end

                case atom do
                  :record ->
                    specialCase.(:rd)

                  :spec ->
                    specialCase.(:ft)

                  :type ->
                    specialCase.(:td)

                  _ ->
                    :erl_eval.extended_parse_exprs(toks)
                end

              [{:atom, _, funName}, {:"(", _} | _] ->
                case :erl_parse.parse_form(toks) do
                  {:ok, funDef} ->
                    case {:edlin_expand.shell_default_or_bif(:erlang.atom_to_list(funName)),
                          :shell.local_func(funName)} do
                      {~c"user_defined", false} ->
                        fakeLine = reconstruct(funDef, funName)

                        {:done, {:ok, fakeResult, _}, _} =
                          :erl_scan.tokens(
                            [],
                            ~c"fd(" ++
                              :erlang.atom_to_list(funName) ++ ~c", " ++ fakeLine ++ ~c").\n",
                            {1, 1},
                            [:text, {:reserved_word_fun, &:erl_scan.reserved_word/1}]
                          )

                        :erl_eval.extended_parse_exprs(fakeResult)

                      _ ->
                        :erl_eval.extended_parse_exprs(toks)
                    end

                  _ ->
                    :erl_eval.extended_parse_exprs(toks)
                end

              _ ->
                :erl_eval.extended_parse_exprs(toks)
            end

          {:eof, _EndPos} ->
            :eof

          {:error, errorInfo, _EndPos} ->
            opts = :io.getopts()
            tmpOpts = :lists.keyreplace(:echo, 1, opts, {:echo, false})
            _ = :io.setopts(tmpOpts)
            _ = :io.get_line(:"")
            _ = :io.setopts(opts)
            {:error, errorInfo}

          else__ ->
            else__
        end
      )
    end

    pid = spawn_link(parse)
    get_command1(pid, eval, bs, rT, fT, ds)
  end

  defp reconstruct(fun, name) do
    :lists.flatten(:erl_pp.expr(reconstruct1(fun, name)))
  end

  defp reconstruct1(
         {:function, anno, name, arity, clauses},
         name
       ) do
    {:named_fun, anno, :RecursiveFuncVar, reconstruct1(clauses, name, arity)}
  end

  defp reconstruct1(
         [
           {:call, anno, {:atom, anno1, name}, args}
           | body
         ],
         name,
         arity
       )
       when length(args) === arity do
    [
      {:call, anno, {:var, anno1, :RecursiveFuncVar}, reconstruct1(args, name, arity)}
      | reconstruct1(body, name, arity)
    ]
  end

  defp reconstruct1(
         [
           {:call, anno, {:atom, anno1, name}, args}
           | body
         ],
         name,
         arity
       ) do
    [
      {:call, anno, {:remote, anno1, {:atom, anno1, :shell_default}, {:atom, anno1, name}},
       reconstruct1(args, name, arity)}
      | reconstruct1(body, name, arity)
    ]
  end

  defp reconstruct1(
         [
           {:call, anno, {:atom, anno1, fun}, args}
           | body
         ],
         name,
         arity
       ) do
    case {:edlin_expand.shell_default_or_bif(:erlang.atom_to_list(fun)), :shell.local_func(fun)} do
      {~c"user_defined", false} ->
        [
          {:call, anno, {:remote, anno1, {:atom, anno1, :shell_default}, {:atom, anno1, fun}},
           reconstruct1(args, name, arity)}
          | reconstruct1(body, name, arity)
        ]

      {~c"shell_default", false} ->
        [
          {:call, anno, {:remote, anno1, {:atom, anno1, :shell_default}, {:atom, anno1, fun}},
           reconstruct1(args, name, arity)}
          | reconstruct1(body, name, arity)
        ]

      {~c"erlang", false} ->
        [
          {:call, anno, {:remote, anno1, {:atom, anno1, :erlang}, {:atom, anno1, fun}},
           reconstruct1(args, name, arity)}
          | reconstruct1(body, name, arity)
        ]

      {_, true} ->
        [
          {:call, anno, {:atom, anno1, fun}, reconstruct1(args, name, arity)}
          | reconstruct1(body, name, arity)
        ]
    end
  end

  defp reconstruct1([e | body], name, arity) when is_tuple(e) do
    [
      :erlang.list_to_tuple(reconstruct1(:erlang.tuple_to_list(e), name, arity))
      | reconstruct1(body, name, arity)
    ]
  end

  defp reconstruct1([e | body], name, arity) when is_list(e) do
    [reconstruct1(e, name, arity) | reconstruct1(body, name, arity)]
  end

  defp reconstruct1([e | body], name, arity) do
    [e | reconstruct1(body, name, arity)]
  end

  defp reconstruct1([], _, _) do
    []
  end

  defp get_command1(pid, eval, bs, rT, fT, ds) do
    receive do
      {:shell_state, from} ->
        send(from, {:shell_state, bs, rT, fT})
        get_command1(pid, eval, bs, rT, fT, ds)

      {:EXIT, ^pid, res} ->
        {res, eval}

      {:EXIT, ^eval, {reason, stacktrace}} ->
        report_exception(:error, {reason, stacktrace}, rT)
        get_command1(pid, start_eval(bs, rT, fT, ds), bs, rT, fT, ds)

      {:EXIT, ^eval, reason} ->
        report_exception(:error, {reason, []}, rT)
        get_command1(pid, start_eval(bs, rT, fT, ds), bs, rT, fT, ds)
    end
  end

  defp prompt(n, eval0, bs0, rT, fT, ds0) do
    case get_prompt_func() do
      {m, f} ->
        a = :erl_anno.new(1)
        l = {:cons, a, {:tuple, a, [{:atom, a, :history}, {:integer, a, n}]}, {nil, a}}
        c = {:call, a, {:remote, a, {:atom, a, m}, {:atom, a, f}}, [l]}
        {v, eval, bs, ds} = shell_cmd([c], eval0, bs0, rT, fT, ds0, :pmt)

        {eval, bs, ds,
         case v do
           {:pmt, val} ->
             val

           _ ->
             bad_prompt_func({m, f})
             default_prompt(n)
         end}

      :default ->
        {eval0, bs0, ds0, default_prompt(n)}
    end
  end

  defp get_prompt_func() do
    case :application.get_env(:stdlib, :shell_prompt_func, :default) do
      {m, f} = promptFunc when is_atom(m) and is_atom(f) ->
        promptFunc

      :default = default ->
        default

      term ->
        bad_prompt_func(term)
        :default
    end
  end

  defp bad_prompt_func(m) do
    fwrite_severity(:benign, ~c"Bad prompt function: ~tp", [m])
  end

  defp default_prompt(n) do
    case :erlang.is_alive() do
      true ->
        :io_lib.format("(~s)~w> ", [node(), n])

      false ->
        :io_lib.format("~w> ", [n])
    end
  end

  defp expand_hist(es, c) do
    try do
      {:ok, expand_exprs(es, c)}
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end
  end

  defp expand_exprs([e | es], c) do
    [expand_expr(e, c) | expand_exprs(es, c)]
  end

  defp expand_exprs([], _C) do
    []
  end

  defp expand_expr({:cons, a, h, t}, c) do
    {:cons, a, expand_expr(h, c), expand_expr(t, c)}
  end

  defp expand_expr({:lc, a, e, qs}, c) do
    {:lc, a, expand_expr(e, c), expand_quals(qs, c)}
  end

  defp expand_expr({:bc, a, e, qs}, c) do
    {:bc, a, expand_expr(e, c), expand_quals(qs, c)}
  end

  defp expand_expr({:tuple, a, elts}, c) do
    {:tuple, a, expand_exprs(elts, c)}
  end

  defp expand_expr({:map, a, es}, c) do
    {:map, a, expand_exprs(es, c)}
  end

  defp expand_expr({:map, a, arg, es}, c) do
    {:map, a, expand_expr(arg, c), expand_exprs(es, c)}
  end

  defp expand_expr({:map_field_assoc, a, k, v}, c) do
    {:map_field_assoc, a, expand_expr(k, c), expand_expr(v, c)}
  end

  defp expand_expr({:map_field_exact, a, k, v}, c) do
    {:map_field_exact, a, expand_expr(k, c), expand_expr(v, c)}
  end

  defp expand_expr({:record_index, a, name, f}, c) do
    {:record_index, a, name, expand_expr(f, c)}
  end

  defp expand_expr({:record, a, name, is}, c) do
    {:record, a, name, expand_fields(is, c)}
  end

  defp expand_expr({:record_field, a, r, name, f}, c) do
    {:record_field, a, expand_expr(r, c), name, expand_expr(f, c)}
  end

  defp expand_expr({:record, a, r, name, ups}, c) do
    {:record, a, expand_expr(r, c), name, expand_fields(ups, c)}
  end

  defp expand_expr({:record_field, a, r, f}, c) do
    {:record_field, a, expand_expr(r, c), expand_expr(f, c)}
  end

  defp expand_expr({:block, a, es}, c) do
    {:block, a, expand_exprs(es, c)}
  end

  defp expand_expr({:if, a, cs}, c) do
    {:if, a, expand_cs(cs, c)}
  end

  defp expand_expr({:case, a, e, cs}, c) do
    {:case, a, expand_expr(e, c), expand_cs(cs, c)}
  end

  defp expand_expr({:try, a, es, scs, ccs, as}, c) do
    {:try, a, expand_exprs(es, c), expand_cs(scs, c), expand_cs(ccs, c), expand_exprs(as, c)}
  end

  defp expand_expr({:receive, a, cs}, c) do
    {:receive, a, expand_cs(cs, c)}
  end

  defp expand_expr({:receive, a, cs, to, toEs}, c) do
    {:receive, a, expand_cs(cs, c), expand_expr(to, c), expand_exprs(toEs, c)}
  end

  defp expand_expr({:call, a, {:atom, _, :e}, [n]}, c) do
    case get_cmd(n, c) do
      {:undefined, _, _} ->
        no_command(n)

      {[ce], _V, _CommandN} ->
        ce

      {ces, _V, _CommandN} when is_list(ces) ->
        {:block, a, ces}
    end
  end

  defp expand_expr({:call, cA, {:atom, vA, :v}, [n]}, c) do
    case get_cmd(n, c) do
      {:undefined, _, _} ->
        no_command(n)

      {ces, _V, commandN} when is_list(ces) ->
        {:call, cA, {:atom, vA, :v}, [{:integer, vA, commandN}]}
    end
  end

  defp expand_expr({:call, a, f, args}, c) do
    {:call, a, expand_expr(f, c), expand_exprs(args, c)}
  end

  defp expand_expr({:catch, a, e}, c) do
    {:catch, a, expand_expr(e, c)}
  end

  defp expand_expr({:match, a, lhs, rhs}, c) do
    {:match, a, lhs, expand_expr(rhs, c)}
  end

  defp expand_expr({:op, a, op, arg}, c) do
    {:op, a, op, expand_expr(arg, c)}
  end

  defp expand_expr({:op, a, op, larg, rarg}, c) do
    {:op, a, op, expand_expr(larg, c), expand_expr(rarg, c)}
  end

  defp expand_expr({:remote, a, m, f}, c) do
    {:remote, a, expand_expr(m, c), expand_expr(f, c)}
  end

  defp expand_expr({:fun, a, {:clauses, cs}}, c) do
    {:fun, a, {:clauses, expand_exprs(cs, c)}}
  end

  defp expand_expr({:named_fun, a, name, cs}, c) do
    {:named_fun, a, name, expand_exprs(cs, c)}
  end

  defp expand_expr({:clause, a, h, g, b}, c) do
    {:clause, a, h, g, expand_exprs(b, c)}
  end

  defp expand_expr({:bin, a, fs}, c) do
    {:bin, a, expand_bin_elements(fs, c)}
  end

  defp expand_expr(e, _C) do
    e
  end

  defp expand_cs([{:clause, a, p, g, b} | cs], c) do
    [
      {:clause, a, p, g, expand_exprs(b, c)}
      | expand_cs(
          cs,
          c
        )
    ]
  end

  defp expand_cs([], _C) do
    []
  end

  defp expand_fields([{:record_field, a, f, v} | fs], c) do
    [
      {:record_field, a, expand_expr(f, c), expand_expr(v, c)}
      | expand_fields(fs, c)
    ]
  end

  defp expand_fields([], _C) do
    []
  end

  defp expand_quals([{:generate, a, p, e} | qs], c) do
    [
      {:generate, a, p, expand_expr(e, c)}
      | expand_quals(
          qs,
          c
        )
    ]
  end

  defp expand_quals([{:b_generate, a, p, e} | qs], c) do
    [
      {:b_generate, a, p, expand_expr(e, c)}
      | expand_quals(qs, c)
    ]
  end

  defp expand_quals([e | qs], c) do
    [expand_expr(e, c) | expand_quals(qs, c)]
  end

  defp expand_quals([], _C) do
    []
  end

  defp expand_bin_elements([], _C) do
    []
  end

  defp expand_bin_elements([{:bin_element, a, e, sz, ts} | fs], c) do
    [
      {:bin_element, a, expand_expr(e, c), sz, ts}
      | expand_bin_elements(fs, c)
    ]
  end

  defp no_command(n) do
    throw({:error, :io_lib.fwrite("~ts: command not found", [:erl_pp.expr(n, enc())])})
  end

  defp add_cmd(n, es, v) do
    :erlang.put({:command, n}, es)
    :erlang.put({:result, n}, v)
  end

  defp getc(n) do
    {:erlang.get({:command, n}), :erlang.get({:result, n}), n}
  end

  defp get_cmd(num, c) do
    case (try do
            :erl_eval.expr(num, :erl_eval.new_bindings())
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      {:value, n, _} when n < 0 ->
        getc(c + n)

      {:value, n, _} ->
        getc(n)

      _Other ->
        {:undefined, :undefined, :undefined}
    end
  end

  defp del_cmd(_Type, n, n0, hasBin) when n < n0 do
    hasBin
  end

  defp del_cmd(type, n, n0, hasBin0) do
    t = :erlang.erase({type, n})
    hasBin = hasBin0 or has_binary(t)
    del_cmd(type, n - 1, n0, hasBin)
  end

  defp has_binary(t) do
    try do
      has_bin(t)
      false
    catch
      true = thrown ->
        thrown
    end
  end

  defp has_bin(t) when is_tuple(t) do
    has_bin(t, tuple_size(t))
  end

  defp has_bin([e | es]) do
    has_bin(e)
    has_bin(es)
  end

  defp has_bin(b) when byte_size(b) > 64 do
    throw(true)
  end

  defp has_bin(t) do
    t
  end

  defp has_bin(t, 0) do
    t
  end

  defp has_bin(t, i) do
    has_bin(:erlang.element(i, t))
    has_bin(t, i - 1)
  end

  def get_state() do
    send(whereis(), {:shell_state, self()})

    receive do
      {:shell_state, bs, rT, fT} ->
        r_shell_state(bindings: bs, records: :ets.tab2list(rT), functions: :ets.tab2list(fT))
    end
  end

  def get_function(func, arity) do
    {:shell_state, _Bs, _RT, fT} = get_state()

    try do
      {:value, {_, fun}} = :lists.keysearch({:function, {:shell_default, func, arity}}, 1, fT)
      fun
    catch
      _, _ ->
        :undefined
    end
  end

  defp shell_cmd(es, eval, bs, rT, fT, ds, w) do
    send(eval, {:shell_cmd, self(), {:eval, es}, w})
    shell_rep(eval, bs, rT, fT, ds)
  end

  defp shell_rep(ev, bs0, rT, fT, ds0) do
    receive do
      {:shell_rep, ^ev, {:value, v, bs, ds}} ->
        {v, ev, bs, ds}

      {:shell_rep, ^ev, {:command_error, {location, m, error}}} ->
        fwrite_severity(:benign, "~s: ~ts", [pos(location), m.format_error(error)])
        {{:EXIT, error}, ev, bs0, ds0}

      {:shell_req, ^ev, {:get_cmd, n}} ->
        send(ev, {:shell_rep, self(), getc(n)})
        shell_rep(ev, bs0, rT, fT, ds0)

      {:shell_req, ^ev, :get_cmd} ->
        send(ev, {:shell_rep, self(), :erlang.get()})
        shell_rep(ev, bs0, rT, fT, ds0)

      {:shell_req, ^ev, :exit} ->
        send(ev, {:shell_rep, self(), :exit})
        exit(:normal)

      {:shell_req, ^ev, {:update_dict, ds}} ->
        send(ev, {:shell_rep, self(), :ok})
        shell_rep(ev, bs0, rT, fT, ds)

      {:shell_state, from} ->
        send(from, {:shell_state, bs0, rT, fT})
        shell_rep(ev, bs0, rT, fT, ds0)

      {:ev_exit, {^ev, class, reason0}} ->
        receive do
          {:EXIT, ^ev, :normal} ->
            :ok
        end

        report_exception(class, reason0, rT)
        reason = nocatch(class, reason0)
        {{:EXIT, reason}, start_eval(bs0, rT, fT, ds0), bs0, ds0}

      {:ev_caught, {^ev, class, reason0}} ->
        report_exception(class, :benign, reason0, rT)
        reason = nocatch(class, reason0)
        {{:EXIT, reason}, ev, bs0, ds0}

      {:EXIT, _Id, :interrupt} ->
        :erlang.exit(ev, :kill)
        shell_rep(ev, bs0, rT, fT, ds0)

      {:EXIT, ^ev, {reason, stacktrace}} ->
        report_exception(:exit, {reason, stacktrace}, rT)
        {{:EXIT, reason}, start_eval(bs0, rT, fT, ds0), bs0, ds0}

      {:EXIT, ^ev, reason} ->
        report_exception(:exit, {reason, []}, rT)
        {{:EXIT, reason}, start_eval(bs0, rT, fT, ds0), bs0, ds0}

      {:EXIT, _Id, r} ->
        :erlang.exit(ev, r)
        exit(r)

      _Other ->
        :io.format(~c"Throwing ~p~n", [_Other])
        shell_rep(ev, bs0, rT, fT, ds0)
    end
  end

  defp nocatch(:throw, {term, stack}) do
    {{:nocatch, term}, stack}
  end

  defp nocatch(:error, reason) do
    reason
  end

  defp nocatch(:exit, reason) do
    reason
  end

  defp report_exception(class, reason, rT) do
    report_exception(class, :serious, reason, rT)
  end

  defp report_exception(class, severity, {reason, stacktrace}, rT) do
    tag = severity_tag(severity)
    i = :erlang.iolist_size(tag) + 1

    pF = fn term, i1 ->
      pp(term, i1, rT)
    end

    sF = fn m, _F, _A ->
      :erlang.or(m === :erl_eval, m === :shell)
    end

    enc = encoding()
    str = :erl_error.format_exception(i, class, reason, stacktrace, sF, pF, enc)
    :io.requests([{:put_chars, :latin1, tag}, {:put_chars, :unicode, str}, :nl])
  end

  defp start_eval(bs, rT, fT, ds) do
    self = self()
    ancestors = [self() | :erlang.get(:"$ancestors")]

    eval =
      spawn_link(fn ->
        :erlang.put(:"$ancestors", ancestors)
        evaluator(self, bs, rT, fT, ds)
      end)

    :erlang.put(:evaluator, eval)
    eval
  end

  defp evaluator(shell, bs, rT, fT, ds) do
    init_dict(ds)

    case :application.get_env(
           :stdlib,
           :restricted_shell
         ) do
      :undefined ->
        eval_loop(shell, bs, rT, fT)

      {:ok, rShMod} ->
        case :erlang.get(:restricted_shell_state) do
          :undefined ->
            :erlang.put(:restricted_shell_state, [])

          _ ->
            :ok
        end

        :erlang.put(:restricted_expr_state, [])
        restricted_eval_loop(shell, bs, rT, fT, rShMod)
    end
  end

  defp eval_loop(shell, bs0, rT, fT) do
    receive do
      {:shell_cmd, ^shell, {:eval, es}, w} ->
        ef =
          {:value,
           fn mForFun, as ->
             apply_fun(mForFun, as, shell)
           end}

        lf = local_func_handler(shell, rT, fT, ef)
        bs = eval_exprs(es, shell, bs0, rT, lf, ef, w)
        eval_loop(shell, bs, rT, fT)
    end
  end

  defp restricted_eval_loop(shell, bs0, rT, fT, rShMod) do
    receive do
      {:shell_cmd, ^shell, {:eval, es}, w} ->
        {lFH, nLFH} = restrict_handlers(rShMod, shell, rT, fT)
        :erlang.put(:restricted_expr_state, [])
        bs = eval_exprs(es, shell, bs0, rT, {:eval, lFH}, {:value, nLFH}, w)
        restricted_eval_loop(shell, bs, rT, fT, rShMod)
    end
  end

  defp eval_exprs(es, shell, bs0, rT, lf, ef, w) do
    try do
      {r, bs2} = exprs(es, bs0, rT, lf, ef, w)
      send(shell, {:shell_rep, self(), r})
      bs2
    catch
      :exit, :normal ->
        exit(:normal)

      class, reason ->
        m = {self(), class, {reason, __STACKTRACE__}}

        case do_catch(class, reason) do
          true ->
            send(shell, {:ev_caught, m})
            bs0

          false ->
            {:links, lPs} = :erlang.process_info(self(), :links)
            eR = nocatch(class, {reason, __STACKTRACE__})

            :lists.foreach(
              fn p ->
                :erlang.exit(p, eR)
              end,
              lPs -- [shell]
            )

            send(shell, {:ev_exit, m})
            exit(:normal)
        end
    end
  end

  defp do_catch(:exit, :restricted_shell_stopped) do
    false
  end

  defp do_catch(:exit, :restricted_shell_started) do
    false
  end

  defp do_catch(_Class, _Reason) do
    case :application.get_env(:stdlib, :shell_catch_exception, false) do
      true ->
        true

      _ ->
        false
    end
  end

  defp exprs(es, bs0, rT, lf, ef, w) do
    exprs(es, bs0, rT, lf, ef, bs0, w)
  end

  defp exprs([e0 | es], bs1, rT, lf, ef, bs0, w) do
    usedRecords = used_record_defs(e0, rT)
    rBs = record_bindings(usedRecords, bs1)

    case check_command(prep_check([e0]), rBs) do
      :ok ->
        e1 = expand_records(usedRecords, e0)
        {:value, v0, bs2} = expr(e1, bs1, lf, ef)

        bs =
          :orddict.from_list(
            for {x, _} = vV <- :erl_eval.bindings(bs2),
                not is_expand_variable(x) do
              vV
            end
          )

        cond do
          es === [] ->
            vS = pp(v0, 1, rT)

            case w do
              :cmd ->
                :io.requests([{:put_chars, :unicode, vS}, :nl])

              :pmt ->
                :ok
            end

            v =
              cond do
                w === :pmt ->
                  {w, v0}

                true ->
                  case result_will_be_saved() do
                    true ->
                      v0

                    false ->
                      :erlang.garbage_collect()
                      :ignored
                  end
              end

            {{:value, v, bs, :erlang.get()}, bs}

          true ->
            exprs(es, bs, rT, lf, ef, bs0, w)
        end

      {:error, error} ->
        {{:command_error, error}, bs0}
    end
  end

  defp is_expand_variable(v) do
    case (try do
            :erlang.atom_to_list(v)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      ~c"rec" ++ _Integer ->
        true

      _ ->
        false
    end
  end

  defp result_will_be_saved() do
    case get_history_and_results() do
      {_, 0} ->
        false

      _ ->
        true
    end
  end

  defp used_record_defs(e, rT) do
    uR =
      case used_records(e, [], rT, []) do
        [] ->
          []

        l0 ->
          l1 = :lists.zip(l0, :lists.seq(1, length(l0)))
          l2 = :lists.keysort(2, :lists.ukeysort(1, l1))

          for {r, _} <- l2 do
            r
          end
      end

    record_defs(rT, uR)
  end

  defp used_records(e, u0, rT, skip) do
    case used_records(e) do
      {:name, name, e1} ->
        u =
          case :lists.member(name, skip) do
            true ->
              u0

            false ->
              r = :ets.lookup(rT, name)
              used_records(r, [name | u0], rT, [name | skip])
          end

        used_records(e1, u, rT, skip)

      {:expr, [e1 | es]} ->
        used_records(es, used_records(e1, u0, rT, skip), rT, skip)

      _ ->
        u0
    end
  end

  defp used_records({:record_index, _, name, f}) do
    {:name, name, f}
  end

  defp used_records({:record, _, name, is}) do
    {:name, name, is}
  end

  defp used_records({:record_field, _, r, name, f}) do
    {:name, name, [r | f]}
  end

  defp used_records({:record, _, r, name, ups}) do
    {:name, name, [r | ups]}
  end

  defp used_records({:record_field, _, r, f}) do
    {:expr, [r | f]}
  end

  defp used_records({:call, _, {:atom, _, :record}, [a, {:atom, _, name}]}) do
    {:name, name, a}
  end

  defp used_records({:call, _, {:atom, _, :is_record}, [a, {:atom, _, name}]}) do
    {:name, name, a}
  end

  defp used_records(
         {:call, _, {:remote, _, {:atom, _, :erlang}, {:atom, _, :is_record}},
          [a, {:atom, _, name}]}
       ) do
    {:name, name, a}
  end

  defp used_records({:call, _, {:atom, _, :record_info}, [a, {:atom, _, name}]}) do
    {:name, name, a}
  end

  defp used_records({:call, a, {:tuple, _, [m, f]}, as}) do
    used_records({:call, a, {:remote, a, m, f}, as})
  end

  defp used_records({:type, _, :record, [{:atom, _, name} | fs]}) do
    {:name, name, fs}
  end

  defp used_records(t) when is_tuple(t) do
    {:expr, :erlang.tuple_to_list(t)}
  end

  defp used_records(e) do
    {:expr, e}
  end

  defp fwrite_severity(severity, s, as) do
    :io.fwrite("~ts\n", [format_severity(severity, s, as)])
  end

  defp format_severity(severity, s, as) do
    add_severity(severity, :io_lib.fwrite(s, as))
  end

  defp add_severity(severity, s) do
    [severity_tag(severity), s]
  end

  defp severity_tag(:fatal) do
    "*** "
  end

  defp severity_tag(:serious) do
    "** "
  end

  defp severity_tag(:benign) do
    "* "
  end

  defp restrict_handlers(rShMod, shell, rT, fT) do
    {fn f, as, binds ->
       local_allowed(f, as, rShMod, binds, shell, rT, fT)
     end,
     fn mF, as ->
       non_local_allowed(mF, as, rShMod, shell)
     end}
  end

  defp local_allowed(f, as, rShMod, bs, shell, rT, fT)
       when is_atom(f) do
    {lFH, nLFH} = restrict_handlers(rShMod, shell, rT, fT)

    case not_restricted(f, as) do
      true ->
        local_func(f, as, bs, shell, rT, fT, {:eval, lFH}, {:value, nLFH})

      false ->
        {asEv, bs1} = expr_list(as, bs, {:eval, lFH}, {:value, nLFH})

        case rShMod.local_allowed(
               f,
               asEv,
               {:erlang.get(:restricted_shell_state), :erlang.get(:restricted_expr_state)}
             ) do
          {result, {rShShSt, rShExprSt}} ->
            :erlang.put(:restricted_shell_state, rShShSt)
            :erlang.put(:restricted_expr_state, rShExprSt)

            cond do
              not result ->
                shell_req(shell, {:update_dict, :erlang.get()})
                exit({:restricted_shell_disallowed, {f, asEv}})

              true ->
                non_builtin_local_func(f, asEv, bs1, fT)
            end

          unexpected ->
            try do
              :erlang.error(:reason)
            catch
              _, _ ->
                :erlang.raise(
                  :exit,
                  {:restricted_shell_bad_return, unexpected},
                  [{rShMod, :local_allowed, 3} | __STACKTRACE__]
                )
            end
        end
    end
  end

  defp non_local_allowed(mForFun, as, rShMod, shell) do
    case rShMod.non_local_allowed(
           mForFun,
           as,
           {:erlang.get(:restricted_shell_state), :erlang.get(:restricted_expr_state)}
         ) do
      {result, {rShShSt, rShExprSt}} ->
        :erlang.put(:restricted_shell_state, rShShSt)
        :erlang.put(:restricted_expr_state, rShExprSt)

        case result do
          false ->
            shell_req(shell, {:update_dict, :erlang.get()})
            exit({:restricted_shell_disallowed, {mForFun, as}})

          {:redirect, newMForFun, newAs} ->
            apply_fun(newMForFun, newAs, shell)

          _ ->
            apply_fun(mForFun, as, shell)
        end

      unexpected ->
        try do
          :erlang.error(:reason)
        catch
          _, _ ->
            :erlang.raise(
              :exit,
              {:restricted_shell_bad_return, unexpected},
              [{rShMod, :non_local_allowed, 3} | __STACKTRACE__]
            )
        end
    end
  end

  defp not_restricted(:f, []) do
    true
  end

  defp not_restricted(:f, [_]) do
    true
  end

  defp not_restricted(:h, []) do
    true
  end

  defp not_restricted(:b, []) do
    true
  end

  defp not_restricted(:history, [_]) do
    true
  end

  defp not_restricted(:results, [_]) do
    true
  end

  defp not_restricted(:catch_exception, [_]) do
    true
  end

  defp not_restricted(:exit, []) do
    true
  end

  defp not_restricted(:fl, []) do
    true
  end

  defp not_restricted(:fd, [_, _]) do
    true
  end

  defp not_restricted(:ft, [_]) do
    true
  end

  defp not_restricted(:td, [_]) do
    true
  end

  defp not_restricted(:rd, [_]) do
    true
  end

  defp not_restricted(:rd, [_, _]) do
    true
  end

  defp not_restricted(:rf, []) do
    true
  end

  defp not_restricted(:rf, [_]) do
    true
  end

  defp not_restricted(:rl, []) do
    true
  end

  defp not_restricted(:rl, [_]) do
    true
  end

  defp not_restricted(:rp, [_]) do
    true
  end

  defp not_restricted(:rr, [_]) do
    true
  end

  defp not_restricted(:rr, [_, _]) do
    true
  end

  defp not_restricted(:rr, [_, _, _]) do
    true
  end

  defp not_restricted(:v, [_]) do
    true
  end

  defp not_restricted(_, _) do
    false
  end

  defp apply_fun({:erlang, :garbage_collect}, [], shell) do
    garb(shell)
  end

  defp apply_fun({m, f}, as, _Shell) do
    apply(m, f, as)
  end

  defp apply_fun(mForFun, as, _Shell) do
    apply(mForFun, as)
  end

  defp prep_check({:call, anno, {:atom, _, :f}, [{:var, _, _Name}]}) do
    {:atom, anno, :ok}
  end

  defp prep_check({:value, _CommandN, _Val}) do
    {:atom, a0(), :ok}
  end

  defp prep_check(t) when is_tuple(t) do
    :erlang.list_to_tuple(prep_check(:erlang.tuple_to_list(t)))
  end

  defp prep_check([e | es]) do
    [prep_check(e) | prep_check(es)]
  end

  defp prep_check(e) do
    e
  end

  defp expand_records([], e0) do
    e0
  end

  defp expand_records(usedRecords, e0) do
    recordDefs =
      for {_Name, def__} <- usedRecords do
        def__
      end

    a = :erl_anno.new(1)
    e = prep_rec(e0)
    forms0 = recordDefs ++ [{:function, a, :foo, 0, [{:clause, a, [], [], [e]}]}]

    forms =
      :erl_expand_records.module(
        forms0,
        [:strict_record_tests]
      )

    {:function, ^a, :foo, 0, [{:clause, ^a, [], [], [nE]}]} = :lists.last(forms)
    prep_rec(nE)
  end

  defp prep_rec({:value, _CommandN, _V} = value) do
    {:atom, value, :ok}
  end

  defp prep_rec({:atom, {:value, _CommandN, _V} = value, :ok}) do
    value
  end

  defp prep_rec(t) when is_tuple(t) do
    :erlang.list_to_tuple(prep_rec(:erlang.tuple_to_list(t)))
  end

  defp prep_rec([e | es]) do
    [prep_rec(e) | prep_rec(es)]
  end

  defp prep_rec(e) do
    e
  end

  defp init_dict([{k, v} | ds]) do
    :erlang.put(k, v)
    init_dict(ds)
  end

  defp init_dict([]) do
    true
  end

  def local_func() do
    [:v, :h, :b, :f, :fl, :rd, :rf, :rl, :rp, :rr, :history, :results, :catch_exception]
  end

  def local_func(func) do
    :lists.member(func, local_func())
  end

  defp local_func(:v, [{:integer, _, v}], bs, shell, _RT, _FT, _Lf, _Ef) do
    {_Ces, value, _N} = shell_req(shell, {:get_cmd, v})
    {:value, value, bs}
  end

  defp local_func(:h, [], bs, shell, rT, _FT, _Lf, _Ef) do
    cs = shell_req(shell, :get_cmd)

    cs1 =
      :lists.filter(
        fn
          {{:command, _}, _} ->
            true

          {{:result, _}, _} ->
            true

          _ ->
            false
        end,
        cs
      )

    cs2 =
      :lists.map(
        fn {{t, n}, v} ->
          {{n, t}, v}
        end,
        cs1
      )

    cs3 = :lists.keysort(1, cs2)
    {:value, list_commands(cs3, rT), bs}
  end

  defp local_func(:b, [], bs, _Shell, rT, _FT, _Lf, _Ef) do
    {:value, list_bindings(:erl_eval.bindings(bs), rT), bs}
  end

  defp local_func(:f, [], _Bs, _Shell, _RT, _FT, _Lf, _Ef) do
    {:value, :ok, :erl_eval.new_bindings()}
  end

  defp local_func(:f, [{:var, _, name}], bs, _Shell, _RT, _FT, _Lf, _Ef) do
    {:value, :ok, :erl_eval.del_binding(name, bs)}
  end

  defp local_func(:f, [_Other], _Bs, _Shell, _RT, _FT, _Lf, _Ef) do
    :erlang.raise(:error, :function_clause, [{:shell, :f, 1}])
  end

  defp local_func(:fl, [], bs, _Shell, _RT, fT, _Lf, _Ef) do
    {:value, :ets.tab2list(fT), bs}
  end

  defp local_func(:fd, [{:atom, _, funName}, funExpr], bs, _Shell, _RT, fT, _Lf, _Ef) do
    {:value, fun, []} = :erl_eval.expr(funExpr, [])
    {:arity, arity} = :erlang.fun_info(fun, :arity)

    :ets.insert(
      fT,
      [{{:function, {:shell_default, funName, arity}}, fun}]
    )

    {:value, :ok, bs}
  end

  defp local_func(:fd, [_], _Bs, _Shell, _RT, _FT, _Lf, _Ef) do
    :erlang.raise(:error, :function_clause, [{:shell, :fd, 1}])
  end

  defp local_func(:ft, [{:string, _, typeDef}], bs, _Shell, _RT, fT, _Lf, _Ef) do
    case :erl_scan.tokens([], typeDef, {1, 1}, [
           :text,
           {:reserved_word_fun, &:erl_scan.reserved_word/1}
         ]) do
      {:done, {:ok, toks, _}, _} ->
        case :erl_parse.parse_form(toks) do
          {:ok, {:attribute, _, :spec, {{funName, arity}, _}} = attrForm} ->
            :ets.insert(
              fT,
              [{{:function_type, {:shell_default, funName, arity}}, attrForm}]
            )

            {:value, :ok, bs}

          {:error, {_Location, m, errDesc}} ->
            errStr = :io_lib.fwrite("~ts", [m.format_error(errDesc)])
            exit(:lists.flatten(errStr))
        end

      {:done, {:error, {_Location, m, errDesc}, _}, _} ->
        errStr = :io_lib.fwrite("~ts", [m.format_error(errDesc)])
        exit(:lists.flatten(errStr))
    end
  end

  defp local_func(:ft, [_], _Bs, _Shell, _RT, _FT, _Lf, _Ef) do
    :erlang.raise(:error, :function_clause, [{:shell, :ft, 1}])
  end

  defp local_func(:td, [{:string, _, typeDef}], bs, _Shell, _RT, fT, _Lf, _Ef) do
    case :erl_scan.tokens([], typeDef, {1, 1}, [
           :text,
           {:reserved_word_fun, &:erl_scan.reserved_word/1}
         ]) do
      {:done, {:ok, toks, _}, _} ->
        case :erl_parse.parse_form(toks) do
          {:ok, {:attribute, _, :type, {typeName, _, _}} = attrForm} ->
            :ets.insert(fT, [{{:type, typeName}, attrForm}])
            {:value, :ok, bs}

          {:error, {_Location, m, errDesc}} ->
            errStr = :io_lib.fwrite("~ts", [m.format_error(errDesc)])
            exit(:lists.flatten(errStr))
        end

      {:done, {:error, {_Location, m, errDesc}, _}, _} ->
        errStr = :io_lib.fwrite("~ts", [m.format_error(errDesc)])
        exit(:lists.flatten(errStr))
    end
  end

  defp local_func(:td, [_], _Bs, _Shell, _RT, _FT, _Lf, _Ef) do
    :erlang.raise(:error, :function_clause, [{:shell, :td, 1}])
  end

  defp local_func(:rd, [{:string, _, typeDef}], bs, _Shell, rT, _FT, _Lf, _Ef) do
    case :erl_scan.tokens([], typeDef, {1, 1}, [
           :text,
           {:reserved_word_fun, &:erl_scan.reserved_word/1}
         ]) do
      {:done, {:ok, toks, _}, _} ->
        case :erl_parse.parse_form(toks) do
          {:ok, {:attribute, _, _, _} = attrForm} ->
            [_] = add_records([attrForm], bs, rT)
            {:value, :ok, bs}

          {:error, {_Location, m, errDesc}} ->
            errStr = :io_lib.fwrite("~ts", [m.format_error(errDesc)])
            exit(:lists.flatten(errStr))
        end

      {:done, {:error, {_Location, m, errDesc}, _}, _} ->
        errStr = :io_lib.fwrite("~ts", [m.format_error(errDesc)])
        exit(:lists.flatten(errStr))
    end
  end

  defp local_func(:rd, [_], _Bs, _Shell, _RT, _FT, _Lf, _Ef) do
    :erlang.raise(:error, :function_clause, [{:shell, :rd, 1}])
  end

  defp local_func(:rd, [{:atom, _, recName0}, recDef0], bs, _Shell, rT, _FT, _Lf, _Ef) do
    recDef = expand_value(recDef0)
    rDs = :lists.flatten(:erl_pp.expr(recDef))
    recName = :io_lib.write_atom_as_latin1(recName0)
    attr = :lists.concat([~c"-record(", recName, ~c",", rDs, ~c")."])
    {:ok, tokens, _} = :erl_scan.string(attr)

    case :erl_parse.parse_form(tokens) do
      {:ok, attrForm} ->
        [rN] = add_records([attrForm], bs, rT)
        {:value, rN, bs}

      {:error, {_Location, m, errDesc}} ->
        errStr = :io_lib.fwrite("~ts", [m.format_error(errDesc)])
        exit(:lists.flatten(errStr))
    end
  end

  defp local_func(:rd, [_, _], _Bs, _Shell, _RT, _FT, _Lf, _Ef) do
    :erlang.raise(:error, :function_clause, [{:shell, :rd, 2}])
  end

  defp local_func(:rf, [], bs, _Shell, rT, _FT, _Lf, _Ef) do
    true = :ets.delete_all_objects(rT)
    {:value, initiate_records(bs, rT), bs}
  end

  defp local_func(:rf, [a], bs0, _Shell, rT, _FT, lf, ef) do
    {[recs], bs} = expr_list([a], bs0, lf, ef)

    cond do
      :_ === recs ->
        true = :ets.delete_all_objects(rT)

      true ->
        :lists.foreach(
          fn name ->
            true = :ets.delete(rT, name)
          end,
          listify(recs)
        )
    end

    {:value, :ok, bs}
  end

  defp local_func(:rl, [], bs, _Shell, rT, _FT, _Lf, _Ef) do
    {:value, list_records(:ets.tab2list(rT)), bs}
  end

  defp local_func(:rl, [a], bs0, _Shell, rT, _FT, lf, ef) do
    {[recs], bs} = expr_list([a], bs0, lf, ef)
    {:value, list_records(record_defs(rT, listify(recs))), bs}
  end

  defp local_func(:rp, [a], bs0, _Shell, rT, _FT, lf, ef) do
    {[v], bs} = expr_list([a], bs0, lf, ef)
    cs = pp(v, _Column = 1, _Depth = -1, rT)
    :io.requests([{:put_chars, :unicode, cs}, :nl])
    {:value, :ok, bs}
  end

  defp local_func(:rr, [a], bs0, _Shell, rT, _FT, lf, ef) do
    {[file], bs} = expr_list([a], bs0, lf, ef)
    {:value, read_and_add_records(file, :_, [], bs, rT), bs}
  end

  defp local_func(:rr, [_, _] = as0, bs0, _Shell, rT, _FT, lf, ef) do
    {[file, sel], bs} = expr_list(as0, bs0, lf, ef)
    {:value, read_and_add_records(file, sel, [], bs, rT), bs}
  end

  defp local_func(:rr, [_, _, _] = as0, bs0, _Shell, rT, _FT, lf, ef) do
    {[file, sel, options], bs} = expr_list(as0, bs0, lf, ef)
    {:value, read_and_add_records(file, sel, options, bs, rT), bs}
  end

  defp local_func(:history, [{:integer, _, n}], bs, _Shell, _RT, _FT, _Lf, _Ef) do
    {:value, history(n), bs}
  end

  defp local_func(:history, [_Other], _Bs, _Shell, _RT, _FT, _Lf, _Ef) do
    :erlang.raise(:error, :function_clause, [{:shell, :history, 1}])
  end

  defp local_func(:results, [{:integer, _, n}], bs, _Shell, _RT, _FT, _Lf, _Ef) do
    {:value, results(n), bs}
  end

  defp local_func(:results, [_Other], _Bs, _Shell, _RT, _FT, _Lf, _Ef) do
    :erlang.raise(:error, :function_clause, [{:shell, :results, 1}])
  end

  defp local_func(:catch_exception, [{:atom, _, bool}], bs, _Shell, _RT, _FT, _Lf, _Ef)
       when bool or not bool do
    {:value, catch_exception(bool), bs}
  end

  defp local_func(:catch_exception, [_Other], _Bs, _Shell, _RT, _FT, _Lf, _Ef) do
    :erlang.raise(:error, :function_clause, [{:shell, :catch_exception, 1}])
  end

  defp local_func(:exit, [], _Bs, shell, _RT, _FT, _Lf, _Ef) do
    shell_req(shell, :exit)
    exit(:normal)
  end

  defp local_func(f, as0, bs0, _Shell, _RT, fT, lf, ef)
       when is_atom(f) do
    {as, bs} = expr_list(as0, bs0, lf, ef)
    non_builtin_local_func(f, as, bs, fT)
  end

  defp non_builtin_local_func(f, as, bs, fT) do
    arity = length(as)

    case :erlang.function_exported(:user_default, f, arity) do
      true ->
        {:eval, :erlang.make_fun(:user_default, f, arity), as, bs}

      false ->
        shell_default(f, as, bs, fT)
    end
  end

  defp shell_default(f, as, bs, fT) do
    m = :shell_default
    a = length(as)

    case :code.ensure_loaded(m) do
      {:module, _} ->
        case :erlang.function_exported(m, f, a) do
          true ->
            {:eval, :erlang.make_fun(m, f, a), as, bs}

          false ->
            shell_default_local_func(f, as, bs, fT)
        end

      {:error, _} ->
        shell_default_local_func(f, as, bs, fT)
    end
  end

  defp shell_default_local_func(f, as, bs, fT) do
    case :ets.lookup(
           fT,
           {:function, {:shell_default, f, length(as)}}
         ) do
      [] ->
        shell_undef(f, length(as))

      [{_, fun}] ->
        {:eval, fun, as, bs}
    end
  end

  defp shell_undef(f, a) do
    :erlang.error({:shell_undef, f, a, []})
  end

  defp local_func_handler(shell, rT, fT, ef) do
    h = fn lf ->
      fn f, as, bs ->
        local_func(f, as, bs, shell, rT, fT, {:eval, lf.(lf)}, ef)
      end
    end

    {:eval, h.(h)}
  end

  defp record_print_fun(rT) do
    fn tag, noFields ->
      case :ets.lookup(rT, tag) do
        [{_, {:attribute, _, :record, {^tag, fields}}}]
        when length(fields) === noFields ->
          record_fields(fields)

        _ ->
          :no
      end
    end
  end

  defp record_fields([{:record_field, _, {:atom, _, field}} | fs]) do
    [field | record_fields(fs)]
  end

  defp record_fields([
         {:record_field, _, {:atom, _, field}, _}
         | fs
       ]) do
    [field | record_fields(fs)]
  end

  defp record_fields([{:typed_record_field, field, _Type} | fs]) do
    record_fields([field | fs])
  end

  defp record_fields([]) do
    []
  end

  defp initiate_records(bs, rT) do
    rNs1 = init_rec(:shell_default, bs, rT)

    rNs2 =
      case :code.is_loaded(:user_default) do
        {:file, _File} ->
          init_rec(:user_default, bs, rT)

        false ->
          []
      end

    :lists.usort(rNs1 ++ rNs2)
  end

  defp init_rec(module, bs, rT) do
    case read_records(module, []) do
      rAs when is_list(rAs) ->
        case (try do
                add_records(rAs, bs, rT)
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end) do
          {:EXIT, _} ->
            []

          rNs ->
            rNs
        end

      _Error ->
        []
    end
  end

  def read_and_add_records(file, selected, options, bs, rT) do
    case read_records(file, selected, options) do
      rAs when is_list(rAs) ->
        add_records(rAs, bs, rT)

      error ->
        error
    end
  end

  defp read_records(file, selected, options) do
    case read_records(file, listify(options)) do
      error when is_tuple(error) ->
        error

      rAs when selected === :_ ->
        rAs

      rAs ->
        sel = listify(selected)

        for {:attribute, _, _, {name, _}} = rA <- rAs,
            :lists.member(name, sel) do
          rA
        end
    end
  end

  defp add_records(rAs, bs0, rT) do
    recs =
      for {:attribute, _, _, {name, _}} = d <- rAs do
        {name, d}
      end

    bs1 = record_bindings(recs, bs0)

    case check_command([], bs1) do
      {:error, {_Location, m, errDesc}} ->
        errStr = :io_lib.fwrite("~ts", [m.format_error(errDesc)])
        exit(:lists.flatten(errStr))

      :ok ->
        true = :ets.insert(rT, recs)

        :lists.usort(
          for {name, _} <- recs do
            name
          end
        )
    end
  end

  defp listify(l) when is_list(l) do
    l
  end

  defp listify(e) do
    [e]
  end

  defp check_command(es, bs) do
    :erl_eval.check_command(es, bs)
  end

  defp expr(e, bs, lf, ef) do
    :erl_eval.expr(e, bs, lf, ef)
  end

  defp expr_list(es, bs, lf, ef) do
    :erl_eval.expr_list(es, bs, lf, ef)
  end

  defp record_bindings([], bs) do
    bs
  end

  defp record_bindings(recs0, bs0) do
    {recs1, _} =
      :lists.mapfoldl(
        fn {name, def__}, i ->
          {{name, i, def__}, i + 1}
        end,
        0,
        recs0
      )

    recs2 = :lists.keysort(2, :lists.ukeysort(1, recs1))

    :lists.foldl(
      fn {name, i, def__}, bs ->
        :erl_eval.add_binding({:record, i, name}, def__, bs)
      end,
      bs0,
      recs2
    )
  end

  defp read_records(fileOrModule, opts0) do
    opts = :lists.delete(:report_warnings, opts0)

    case find_file(fileOrModule) do
      {:beam, beam, file} ->
        read_records_from_beam(beam, file)

      {:files, [file]} ->
        read_file_records(file, opts)

      {:files, files} ->
        :lists.flatmap(
          fn file ->
            case read_file_records(file, opts) do
              rAs when is_list(rAs) ->
                rAs

              _ ->
                []
            end
          end,
          files
        )

      error ->
        error
    end
  end

  Record.defrecord(:r_file_info, :file_info,
    size: :undefined,
    type: :undefined,
    access: :undefined,
    atime: :undefined,
    mtime: :undefined,
    ctime: :undefined,
    mode: :undefined,
    links: :undefined,
    major_device: :undefined,
    minor_device: :undefined,
    inode: :undefined,
    uid: :undefined,
    gid: :undefined
  )

  Record.defrecord(:r_file_descriptor, :file_descriptor,
    module: :undefined,
    data: :undefined
  )

  defp find_file(mod) when is_atom(mod) do
    case :code.which(mod) do
      file when is_list(file) ->
        case :erl_prim_loader.get_file(file) do
          {:ok, beam, _} ->
            {:beam, beam, file}

          :error ->
            {:error, :nofile}
        end

      :preloaded ->
        {_M, beam, file} = :code.get_object_code(mod)
        {:beam, beam, file}

      _Else ->
        {:error, :nofile}
    end
  end

  defp find_file(file) do
    case (try do
            :filelib.wildcard(file)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      {:EXIT, _} ->
        {:error, :invalid_filename}

      files ->
        {:files, files}
    end
  end

  defp read_file_records(file, opts) do
    case :filename.extension(file) do
      ~c".beam" ->
        read_records_from_beam(file, file)

      _ ->
        parse_file(file, opts)
    end
  end

  defp read_records_from_beam(beam, file) do
    case :beam_lib.chunks(beam, [:abstract_code, ~c"CInf"]) do
      {:ok, {_Mod, [{:abstract_code, {version, forms}}, {~c"CInf", cB}]}} ->
        case record_attrs(forms) do
          [] when version === :raw_abstract_v1 ->
            []

          [] ->
            try_source(file, cB)

          records ->
            records
        end

      {:ok, {_Mod, [{:abstract_code, :no_abstract_code}, {~c"CInf", cB}]}} ->
        try_source(file, cB)

      error ->
        error
    end
  end

  defp try_source(beam, rawCB) do
    ebinDir = :filename.dirname(beam)
    cB = :erlang.binary_to_term(rawCB)
    os = :proplists.get_value(:options, cB, [])
    src0 = :filename.rootname(beam) ++ ~c".erl"
    src1 = :filename.join([:filename.dirname(ebinDir), ~c"src", :filename.basename(src0)])
    src2 = :proplists.get_value(:source, cB, [])
    try_sources([src0, src1, src2], os)
  end

  defp try_sources([], _) do
    {:error, :nofile}
  end

  defp try_sources([src | rest], os) do
    case is_file(src) do
      true ->
        parse_file(src, os)

      false ->
        try_sources(rest, os)
    end
  end

  defp is_file(name) do
    case :filelib.is_file(name) do
      true ->
        not :filelib.is_dir(name)

      false ->
        false
    end
  end

  defp parse_file(file, opts) do
    cwd = ~c"."
    dir = :filename.dirname(file)
    includePath = [cwd, dir | inc_paths(opts)]

    case :epp.parse_file(file, includePath, pre_defs(opts)) do
      {:ok, forms} ->
        record_attrs(forms)

      error ->
        error
    end
  end

  defp pre_defs([{:d, m, v} | opts]) do
    [{m, v} | pre_defs(opts)]
  end

  defp pre_defs([{:d, m} | opts]) do
    [m | pre_defs(opts)]
  end

  defp pre_defs([_ | opts]) do
    pre_defs(opts)
  end

  defp pre_defs([]) do
    []
  end

  defp inc_paths(opts) do
    for {:i, p} <- opts, is_list(p) do
      p
    end
  end

  defp record_attrs(forms) do
    for a = {:attribute, _, :record, _D} <- forms do
      a
    end
  end

  defp shell_req(shell, req) do
    send(shell, {:shell_req, self(), req})

    receive do
      {:shell_rep, ^shell, rep} ->
        rep
    end
  end

  defp list_commands(
         [{{n, :command}, es0}, {{n, :result}, v} | ds],
         rT
       ) do
    es = prep_list_commands(es0)
    vS = pp(v, 4, rT)
    ns = :io_lib.fwrite("~w: ", [n])
    i = :erlang.iolist_size(ns)

    :io.requests([
      {:put_chars, :latin1, ns},
      {:format, "~ts\n", [:erl_pp.exprs(es, i, enc())]},
      {:format, "-> ", []},
      {:put_chars, :unicode, vS},
      :nl
    ])

    list_commands(ds, rT)
  end

  defp list_commands([{{n, :command}, es0} | ds], rT) do
    es = prep_list_commands(es0)
    ns = :io_lib.fwrite("~w: ", [n])
    i = :erlang.iolist_size(ns)
    :io.requests([{:put_chars, :latin1, ns}, {:format, "~ts\n", [:erl_pp.exprs(es, i, enc())]}])
    list_commands(ds, rT)
  end

  defp list_commands([_D | ds], rT) do
    list_commands(ds, rT)
  end

  defp list_commands([], _RT) do
    :ok
  end

  defp list_bindings([{name, val} | bs], rT) do
    case :erl_eval.fun_data(val) do
      {:fun_data, _FBs, fCs0} ->
        fCs = expand_value(fCs0)
        a = a0()
        f = {:fun, a, {:clauses, fCs}}
        m = {:match, a, {:var, a, name}, f}
        :io.fwrite("~ts\n", [:erl_pp.expr(m, enc())])

      {:named_fun_data, _FBs, fName, fCs0} ->
        fCs = expand_value(fCs0)
        a = a0()
        f = {:named_fun, a, fName, fCs}
        m = {:match, a, {:var, a, name}, f}
        :io.fwrite("~ts\n", [:erl_pp.expr(m, enc())])

      false ->
        namel = :io_lib.fwrite("~s = ", [name])
        nl = :erlang.iolist_size(namel) + 1
        valS = pp(val, nl, rT)
        :io.requests([{:put_chars, :latin1, namel}, {:put_chars, :unicode, valS}, :nl])
    end

    list_bindings(bs, rT)
  end

  defp list_bindings([], _RT) do
    :ok
  end

  defp list_records(records) do
    :lists.foreach(
      fn {_Name, attr} ->
        :io.fwrite("~ts", [:erl_pp.attribute(attr, enc())])
      end,
      records
    )
  end

  defp record_defs(rT, names) do
    :lists.flatmap(
      fn name ->
        :ets.lookup(rT, name)
      end,
      names
    )
  end

  defp expand_value(e) do
    substitute_v1(
      fn {:value, commandN, v} ->
        try_abstract(v, commandN)
      end,
      e
    )
  end

  defp try_abstract(v, commandN) do
    try do
      :erl_parse.abstract(v)
    catch
      _, _ ->
        a = a0()
        {:call, a, {:atom, a, :v}, [{:integer, a, commandN}]}
    end
  end

  defp prep_list_commands(e) do
    a = a0()

    substitute_v1(
      fn {:value, anno, _V} ->
        commandN = :erl_anno.line(anno)
        {:call, a, {:atom, a, :v}, [{:integer, a, commandN}]}
      end,
      e
    )
  end

  defp substitute_v1(f, {:value, _, _} = value) do
    f.(value)
  end

  defp substitute_v1(f, t) when is_tuple(t) do
    :erlang.list_to_tuple(
      substitute_v1(
        f,
        :erlang.tuple_to_list(t)
      )
    )
  end

  defp substitute_v1(f, [e | es]) do
    [substitute_v1(f, e) | substitute_v1(f, es)]
  end

  defp substitute_v1(_F, e) do
    e
  end

  defp a0() do
    :erl_anno.new(0)
  end

  defp pos({line, col}) do
    :io_lib.format(~c"~w:~w", [line, col])
  end

  defp pos(line) do
    :io_lib.format(~c"~w", [line])
  end

  defp check_and_get_history_and_results() do
    check_env(:shell_history_length)
    check_env(:shell_saved_results)
    get_history_and_results()
  end

  defp get_history_and_results() do
    history = get_env(:shell_history_length, 20)
    results = get_env(:shell_saved_results, 20)
    {history, :erlang.min(results, history)}
  end

  defp pp(v, i, rT) do
    pp(v, i, _Depth = 30, rT)
  end

  defp pp(v, i, d, rT) do
    strings = :application.get_env(:stdlib, :shell_strings, true) !== false

    :io_lib_pretty.print(
      v,
      [
        {:column, i},
        {:line_length, columns()},
        {:depth, d},
        {:line_max_chars, 60},
        {:strings, strings},
        {:record_print_fun, record_print_fun(rT)}
      ] ++ enc()
    )
  end

  defp columns() do
    case :io.columns() do
      {:ok, n} ->
        n

      _ ->
        80
    end
  end

  defp encoding() do
    [{:encoding, encoding}] = enc()
    encoding
  end

  defp enc() do
    case :lists.keyfind(:encoding, 1, :io.getopts()) do
      false ->
        [{:encoding, :latin1}]

      enc ->
        [enc]
    end
  end

  defp garb(shell) do
    :erlang.garbage_collect(shell)

    try do
      :erlang.garbage_collect(:erlang.whereis(:user))
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end

    try do
      :erlang.garbage_collect(:erlang.group_leader())
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end

    :erlang.garbage_collect()
  end

  defp get_env(v, def__) do
    case :application.get_env(:stdlib, v, def__) do
      val when is_integer(val) and val >= 0 ->
        val

      _ ->
        def__
    end
  end

  defp check_env(v) do
    case :application.get_env(:stdlib, v, 0) do
      val when is_integer(val) and val >= 0 ->
        :ok

      val ->
        txt =
          :io_lib.fwrite(~c"Invalid value of STDLIB configuration parameter~tw: ~tp\n", [v, val])

        :error_logger.info_report(:lists.flatten(txt))
    end
  end

  defp set_env(app, name, val, default) do
    prev =
      case :application.get_env(app, name) do
        :undefined ->
          default

        {:ok, old} ->
          old
      end

    :application_controller.set_env(app, name, val)
    prev
  end

  def history(l) when is_integer(l) and l >= 0 do
    set_env(:stdlib, :shell_history_length, l, 20)
  end

  def results(l) when is_integer(l) and l >= 0 do
    set_env(:stdlib, :shell_saved_results, l, 20)
  end

  def catch_exception(bool) do
    set_env(:stdlib, :shell_catch_exception, bool, false)
  end

  def prompt_func(promptFunc) do
    set_env(:stdlib, :shell_prompt_func, promptFunc, :default)
  end

  def strings(strings) do
    set_env(:stdlib, :shell_strings, strings, true)
  end
end
