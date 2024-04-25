defmodule :m_eunit_lib do
  use Bitwise
  require Record

  Record.defrecord(:r_test, :test,
    f: :undefined,
    desc: :undefined,
    timeout: :undefined,
    location: :undefined,
    line: 0
  )

  Record.defrecord(:r_group, :group,
    desc: :undefined,
    options: :undefined,
    order: :undefined,
    timeout: :undefined,
    context: :undefined,
    spawn: :undefined,
    tests: :undefined
  )

  Record.defrecord(:r_context, :context, setup: :undefined, cleanup: :undefined, process: :local)

  def format_exception(exception) do
    format_exception(exception, 20)
  end

  def format_exception({class, term, trace}, depth)
      when is_atom(class) and is_list(trace) do
    case is_stacktrace(trace) do
      true ->
        :io_lib.format(
          ~c"~ts**~w:~ts",
          [
            format_stacktrace(trace),
            class,
            format_term(
              term,
              depth
            )
          ]
        )

      false ->
        format_term(term, depth)
    end
  end

  def format_exception(term, depth) do
    format_term(term, depth)
  end

  defp format_term(term, depth) do
    :io_lib.format(~c"~tP\n", [term, depth])
  end

  def format_exit_term(term) do
    {reason, trace} = analyze_exit_term(term)
    :io_lib.format(~c"~tP~ts", [reason, 15, trace])
  end

  defp analyze_exit_term({reason, [_ | _] = trace} = term) do
    case is_stacktrace(trace) do
      true ->
        {reason, format_stacktrace(trace)}

      false ->
        {term, ~c""}
    end
  end

  defp analyze_exit_term(term) do
    {term, ~c""}
  end

  defp is_stacktrace([]) do
    true
  end

  defp is_stacktrace([{m, f, a, l} | fs])
       when is_atom(m) and
              is_atom(f) and is_integer(a) and
              is_list(l) do
    is_stacktrace(fs)
  end

  defp is_stacktrace([{m, f, as, l} | fs])
       when is_atom(m) and
              is_atom(f) and is_list(as) and
              is_list(l) do
    is_stacktrace(fs)
  end

  defp is_stacktrace([{m, f, a} | fs])
       when is_atom(m) and
              is_atom(f) and is_integer(a) do
    is_stacktrace(fs)
  end

  defp is_stacktrace([{m, f, as} | fs])
       when is_atom(m) and
              is_atom(f) and is_list(as) do
    is_stacktrace(fs)
  end

  defp is_stacktrace(_) do
    false
  end

  def format_stacktrace(trace) do
    format_stacktrace(trace, ~c"in function", ~c"in call from")
  end

  defp format_stacktrace([{m, f, a, l} | fs], pre, pre1)
       when is_integer(a) do
    [
      :io_lib.fwrite(
        ~c"~ts ~w:~tw/~w~ts\n",
        [pre, m, f, a, format_stacktrace_location(l)]
      )
      | format_stacktrace(fs, pre1, pre1)
    ]
  end

  defp format_stacktrace([{m, f, as, l} | fs], pre, pre1)
       when is_list(as) do
    a = length(as)

    c =
      case is_op(m, f, a) do
        true when a === 1 ->
          [a1] = as
          :io_lib.fwrite(~c"~ts ~ts", [f, format_arg(a1)])

        true when a === 2 ->
          [a1, a2] = as
          :io_lib.fwrite(~c"~ts ~ts ~ts", [format_arg(a1), f, format_arg(a2)])

        false ->
          :io_lib.fwrite(~c"~tw(~ts)", [f, format_arglist(as)])
      end

    [
      :io_lib.fwrite(
        ~c"~ts ~w:~tw/~w~ts\n  called as ~ts\n",
        [pre, m, f, a, format_stacktrace_location(l), c]
      )
      | format_stacktrace(fs, pre1, pre1)
    ]
  end

  defp format_stacktrace([{m, f, as} | fs], pre, pre1) do
    format_stacktrace([{m, f, as, []} | fs], pre, pre1)
  end

  defp format_stacktrace([], _Pre, _Pre1) do
    ~c""
  end

  defp format_stacktrace_location(location) do
    file = :proplists.get_value(:file, location)
    line = :proplists.get_value(:line, location)

    cond do
      file !== :undefined and line !== :undefined ->
        :io_lib.format(~c" (~ts, line ~w)", [file, line])

      true ->
        ~c""
    end
  end

  defp format_arg(a) do
    :io_lib.format(~c"~tP", [a, 15])
  end

  defp format_arglist([a]) do
    format_arg(a)
  end

  defp format_arglist([a | as]) do
    [:io_lib.format(~c"~tP,", [a, 15]) | format_arglist(as)]
  end

  defp format_arglist([]) do
    ~c""
  end

  defp is_op(:erlang, f, a) do
    :erl_internal.arith_op(f, a) or
      :erl_internal.bool_op(
        f,
        a
      ) or
      :erl_internal.comp_op(
        f,
        a
      ) or
      :erl_internal.list_op(
        f,
        a
      ) or
      :erl_internal.send_op(
        f,
        a
      )
  end

  defp is_op(_M, _F, _A) do
    false
  end

  def format_error(error) do
    format_error(error, 20)
  end

  def format_error({:bad_test, term}, depth) do
    error_msg(~c"bad test descriptor", ~c"~tP", [term, depth])
  end

  def format_error({:bad_generator, {{m, f, a}, term}}, depth) do
    error_msg(
      :io_lib.format(~c"result from generator ~w:~tw/~w is not a test", [m, f, a]),
      ~c"~tP",
      [term, depth]
    )
  end

  def format_error(
        {:generator_failed, {{m, f, a}, exception}},
        depth
      ) do
    error_msg(:io_lib.format(~c"test generator ~w:~tw/~w failed", [m, f, a]), ~c"~ts", [
      format_exception(exception, depth)
    ])
  end

  def format_error({:no_such_function, {m, f, a}}, _)
      when is_atom(m) and is_atom(f) and is_integer(a) do
    error_msg(:io_lib.format(~c"no such function: ~w:~tw/~w", [m, f, a]), ~c"", [])
  end

  def format_error({:module_not_found, m}, _) do
    error_msg(~c"test module not found", ~c"~tp", [m])
  end

  def format_error({:application_not_found, a}, _)
      when is_atom(a) do
    error_msg(~c"application not found", ~c"~w", [a])
  end

  def format_error({:file_read_error, {_R, msg, f}}, _) do
    error_msg(~c"error reading file", ~c"~ts: ~ts", [msg, f])
  end

  def format_error({:setup_failed, exception}, depth) do
    error_msg(~c"context setup failed", ~c"~ts", [format_exception(exception, depth)])
  end

  def format_error({:cleanup_failed, exception}, depth) do
    error_msg(~c"context cleanup failed", ~c"~ts", [format_exception(exception, depth)])
  end

  def format_error(
        {{:bad_instantiator, {{m, f, a}, term}}, _DummyException},
        depth
      ) do
    error_msg(
      :io_lib.format(~c"result from instantiator ~w:~tw/~w is not a test", [m, f, a]),
      ~c"~tP",
      [term, depth]
    )
  end

  def format_error({:instantiation_failed, exception}, depth) do
    error_msg(~c"instantiation of subtests failed", ~c"~ts", [format_exception(exception, depth)])
  end

  defp error_msg(title, fmt, args) do
    msg = :io_lib.format(~c"**" ++ fmt, args)
    :io_lib.fwrite(~c"*** ~ts ***\n~ts\n\n", [title, msg])
  end

  defp format_exception_test_() do
    [
      {205,
       fn ->
         (fn ->
            case :lists.reverse(
                   :lists.flatten(
                     format_exception(
                       try do
                         :erlang.error(:dummy)
                       catch
                         c, r ->
                           {c, r, __STACKTRACE__}
                       end
                     )
                   )
                 ) do
              ~c"\nymmud:rorre" ++ _ ->
                :ok

              x__V ->
                :erlang.error(
                  {:assertMatch,
                   [
                     {:module, :eunit_lib},
                     {:line, 206},
                     {:expression,
                      ~c"lists : reverse ( lists : flatten ( format_exception ( try erlang : error ( dummy ) catch C : R : S -> { C , R , S } end ) ) )"},
                     {:pattern, ~c"\"\\nymmud:rorre\" ++ _"},
                     {:value, x__V}
                   ]}
                )
            end
          end).()
       end},
      {211,
       fn ->
         (fn ->
            case :lists.reverse(
                   :lists.flatten(
                     format_exception(
                       try do
                         :erlang.error(
                           :dummy,
                           [:a]
                         )
                       catch
                         c, r ->
                           {c, r, __STACKTRACE__}
                       end
                     )
                   )
                 ) do
              ~c"\nymmud:rorre" ++ _ ->
                :ok

              x__V ->
                :erlang.error(
                  {:assertMatch,
                   [
                     {:module, :eunit_lib},
                     {:line, 212},
                     {:expression,
                      ~c"lists : reverse ( lists : flatten ( format_exception ( try erlang : error ( dummy , [ a ] ) catch C : R : S -> { C , R , S } end ) ) )"},
                     {:pattern, ~c"\"\\nymmud:rorre\" ++ _"},
                     {:value, x__V}
                   ]}
                )
            end
          end).()
       end}
    ]
  end

  def is_not_test(t) do
    case t do
      :ok ->
        true

      :error ->
        true

      true ->
        true

      false ->
        true

      :undefined ->
        true

      {:ok, _} ->
        true

      {:error, _} ->
        true

      {:EXIT, _} ->
        true

      n when is_number(n) ->
        true

      [n | _] when is_number(n) ->
        true

      x when is_binary(x) ->
        true

      x when is_pid(x) ->
        true

      x when is_port(x) ->
        true

      x when is_reference(x) ->
        true

      _ ->
        false
    end
  end

  def dlist_next([x | xs] = xs0) when is_list(x) do
    case is_nonempty_string(x) do
      true ->
        xs0

      false ->
        dlist_next(x, xs)
    end
  end

  def dlist_next([_ | _] = xs) do
    case is_nonempty_string(xs) do
      true ->
        [xs]

      false ->
        xs
    end
  end

  def dlist_next([]) do
    []
  end

  def dlist_next(x) do
    [x]
  end

  defp dlist_next([x], ys) when is_list(x) do
    case is_nonempty_string(x) do
      true ->
        [x | ys]

      false ->
        dlist_next(x, ys)
    end
  end

  defp dlist_next([x], ys) do
    [x | ys]
  end

  defp dlist_next([x | xs], ys) when is_list(x) do
    case is_nonempty_string(x) do
      true ->
        [x, xs | ys]

      false ->
        dlist_next(x, [xs | ys])
    end
  end

  defp dlist_next([x | xs], ys) do
    [x, xs | ys]
  end

  defp dlist_next([], xs) do
    dlist_next(xs)
  end

  defp dlist_test_() do
    {~c"deep list traversal",
     [
       {~c"non-list term -> singleton list",
        {288,
         fn ->
           [:any] = dlist_next(:any)
         end}},
       {~c"empty list -> empty list",
        {290,
         fn ->
           [] = dlist_next([])
         end}},
       {~c"singleton list -> singleton list",
        {292,
         fn ->
           [:any] = dlist_next([:any])
         end}},
       {~c"taking the head of a flat list",
        {294,
         fn ->
           [:a, :b, :c] = dlist_next([:a, :b, :c])
         end}},
       {~c"skipping an initial empty list",
        {296,
         fn ->
           [:a, :b, :c] = dlist_next([[], :a, :b, :c])
         end}},
       {~c"skipping nested initial empty lists",
        {298,
         fn ->
           [:a, :b, :c] = dlist_next([[[[]]], :a, :b, :c])
         end}},
       {~c"skipping a final empty list",
        {300,
         fn ->
           [] = dlist_next([[]])
         end}},
       {~c"skipping nested final empty lists",
        {302,
         fn ->
           [] = dlist_next([[[[]]]])
         end}},
       {~c"the first element is in a sublist",
        {304,
         fn ->
           [:a, :b, :c] = dlist_next([[:a], :b, :c])
         end}},
       {~c"recognizing a naked string",
        {306,
         fn ->
           [~c"abc"] = dlist_next(~c"abc")
         end}},
       {~c"recognizing a wrapped string",
        {308,
         fn ->
           [~c"abc"] = dlist_next([~c"abc"])
         end}},
       {~c"recognizing a leading string",
        {310,
         fn ->
           [~c"abc", :a, :b, :c] = dlist_next([~c"abc", :a, :b, :c])
         end}},
       {~c"recognizing a nested string",
        {312,
         fn ->
           [~c"abc"] = dlist_next([[~c"abc"]])
         end}},
       {~c"recognizing a leading string in a sublist",
        {314,
         fn ->
           [~c"abc", :a, :b, :c] = dlist_next([[~c"abc"], :a, :b, :c])
         end}},
       {~c"traversing an empty list",
        {316,
         fn ->
           [] = dlist_flatten([])
         end}},
       {~c"traversing a flat list",
        {318,
         fn ->
           [:a, :b, :c] = dlist_flatten([:a, :b, :c])
         end}},
       {~c"traversing a deep list",
        {320,
         fn ->
           [:a, :b, :c] = dlist_flatten([[], [:a, [:b, []], :c], []])
         end}},
       {~c"traversing a deep but empty list",
        {322,
         fn ->
           [] = dlist_flatten([[], [[[]]], []])
         end}}
     ]}
  end

  defp dlist_flatten(xs) do
    case dlist_next(xs) do
      [x | xs1] ->
        [x | dlist_flatten(xs1)]

      [] ->
        []
    end
  end

  def is_string([c | cs])
      when is_integer(c) and c >= 0 and
             c <= 1_114_111 do
    is_string(cs)
  end

  def is_string([_ | _]) do
    false
  end

  def is_string([]) do
    true
  end

  def is_string(_) do
    false
  end

  defp is_nonempty_string([]) do
    false
  end

  defp is_nonempty_string(cs) do
    is_string(cs)
  end

  defp is_string_test_() do
    {~c"is_string",
     [
       {~c"no non-lists",
        {352,
         fn ->
           (fn ->
              x__T = :erlang.is_process_alive(self())

              case not is_string(?A) do
                ^x__T ->
                  :ok

                x__V ->
                  :erlang.error(
                    {:assert,
                     [
                       {:module, :eunit_lib},
                       {:line, 352},
                       {:expression, ~c"not is_string ( $A )"},
                       {:expected, true},
                       case not x__T do
                         ^x__V ->
                           {:value, false}

                         _ ->
                           {:not_boolean, x__V}
                       end
                     ]}
                  )
              end
            end).()
         end}},
       {~c"no non-integer lists",
        {353,
         fn ->
           (fn ->
              x__T = :erlang.is_process_alive(self())

              case not is_string([true]) do
                ^x__T ->
                  :ok

                x__V ->
                  :erlang.error(
                    {:assert,
                     [
                       {:module, :eunit_lib},
                       {:line, 353},
                       {:expression, ~c"not is_string ( [ true ] )"},
                       {:expected, true},
                       case not x__T do
                         ^x__V ->
                           {:value, false}

                         _ ->
                           {:not_boolean, x__V}
                       end
                     ]}
                  )
              end
            end).()
         end}},
       {~c"empty string",
        {354,
         fn ->
           (fn ->
              x__T = :erlang.is_process_alive(self())

              case is_string(~c"") do
                ^x__T ->
                  :ok

                x__V ->
                  :erlang.error(
                    {:assert,
                     [
                       {:module, :eunit_lib},
                       {:line, 354},
                       {:expression, ~c"is_string ( \"\" )"},
                       {:expected, true},
                       case not x__T do
                         ^x__V ->
                           {:value, false}

                         _ ->
                           {:not_boolean, x__V}
                       end
                     ]}
                  )
              end
            end).()
         end}},
       {~c"ascii string",
        {355,
         fn ->
           (fn ->
              x__T = :erlang.is_process_alive(self())

              case is_string(:lists.seq(0, 127)) do
                ^x__T ->
                  :ok

                x__V ->
                  :erlang.error(
                    {:assert,
                     [
                       {:module, :eunit_lib},
                       {:line, 355},
                       {:expression, ~c"is_string ( lists : seq ( 0 , 127 ) )"},
                       {:expected, true},
                       case not x__T do
                         ^x__V ->
                           {:value, false}

                         _ ->
                           {:not_boolean, x__V}
                       end
                     ]}
                  )
              end
            end).()
         end}},
       {~c"latin-1 string",
        {356,
         fn ->
           (fn ->
              x__T = :erlang.is_process_alive(self())

              case is_string(
                     :lists.seq(
                       0,
                       255
                     )
                   ) do
                ^x__T ->
                  :ok

                x__V ->
                  :erlang.error(
                    {:assert,
                     [
                       {:module, :eunit_lib},
                       {:line, 356},
                       {:expression, ~c"is_string ( lists : seq ( 0 , 255 ) )"},
                       {:expected, true},
                       case not x__T do
                         ^x__V ->
                           {:value, false}

                         _ ->
                           {:not_boolean, x__V}
                       end
                     ]}
                  )
              end
            end).()
         end}},
       {~c"unicode string",
        {358,
         fn ->
           (fn ->
              x__T = :erlang.is_process_alive(self())

              case is_string([0, ?A, 1_114_110, 1_114_111]) do
                ^x__T ->
                  :ok

                x__V ->
                  :erlang.error(
                    {:assert,
                     [
                       {:module, :eunit_lib},
                       {:line, 358},
                       {:expression, ~c"is_string ( [ 0 , $A , 1114110 , 1114111 ] )"},
                       {:expected, true},
                       case not x__T do
                         ^x__V ->
                           {:value, false}

                         _ ->
                           {:not_boolean, x__V}
                       end
                     ]}
                  )
              end
            end).()
         end}},
       {~c"not above unicode range",
        {360,
         fn ->
           (fn ->
              x__T = :erlang.is_process_alive(self())

              case not is_string([0, ?A, 1_114_112]) do
                ^x__T ->
                  :ok

                x__V ->
                  :erlang.error(
                    {:assert,
                     [
                       {:module, :eunit_lib},
                       {:line, 360},
                       {:expression, ~c"not is_string ( [ 0 , $A , 1114112 ] )"},
                       {:expected, true},
                       case not x__T do
                         ^x__V ->
                           {:value, false}

                         _ ->
                           {:not_boolean, x__V}
                       end
                     ]}
                  )
              end
            end).()
         end}},
       {~c"no negative codepoints",
        {361,
         fn ->
           (fn ->
              x__T = :erlang.is_process_alive(self())

              case not is_string([?A, -1, 0]) do
                ^x__T ->
                  :ok

                x__V ->
                  :erlang.error(
                    {:assert,
                     [
                       {:module, :eunit_lib},
                       {:line, 361},
                       {:expression, ~c"not is_string ( [ $A , - 1 , 0 ] )"},
                       {:expected, true},
                       case not x__T do
                         ^x__V ->
                           {:value, false}

                         _ ->
                           {:not_boolean, x__V}
                       end
                     ]}
                  )
              end
            end).()
         end}}
     ]}
  end

  def split_node(n) when is_atom(n) do
    split_node(:erlang.atom_to_list(n))
  end

  def split_node(cs) do
    split_node_1(cs, [])
  end

  defp split_node_1([?@ | cs], as) do
    split_node_2(as, cs)
  end

  defp split_node_1([c | cs], as) do
    split_node_1(cs, [c | as])
  end

  defp split_node_1([], as) do
    split_node_2(as, ~c"localhost")
  end

  defp split_node_2(as, cs) do
    {:erlang.list_to_atom(:lists.reverse(as)), :erlang.list_to_atom(cs)}
  end

  def uniq([x, x | xs]) do
    uniq([x | xs])
  end

  def uniq([x | xs]) do
    [x | uniq(xs)]
  end

  def uniq([]) do
    []
  end

  defp uniq_test_() do
    {~c"uniq",
     [
       {391,
        fn ->
          (fn ->
             try do
               uniq(:ok)
             catch
               :error, :function_clause ->
                 :ok

               x__C, x__T ->
                 :erlang.error(
                   {:assertException,
                    [
                      {:module, :eunit_lib},
                      {:line, 391},
                      {:expression, ~c"uniq ( ok )"},
                      {:pattern,
                       ~c"{ " ++ ~c"error" ++ ~c" , " ++ ~c"function_clause" ++ ~c" , [...] }"},
                      {:unexpected_exception, {x__C, x__T, __STACKTRACE__}}
                    ]}
                 )
             else
               x__V ->
                 :erlang.error(
                   {:assertException,
                    [
                      {:module, :eunit_lib},
                      {:line, 391},
                      {:expression, ~c"uniq ( ok )"},
                      {:pattern,
                       ~c"{ " ++ ~c"error" ++ ~c" , " ++ ~c"function_clause" ++ ~c" , [...] }"},
                      {:unexpected_success, x__V}
                    ]}
                 )
             end
           end).()
        end},
       {392,
        fn ->
          (fn ->
             try do
               uniq([1 | 2])
             catch
               :error, :function_clause ->
                 :ok

               x__C, x__T ->
                 :erlang.error(
                   {:assertException,
                    [
                      {:module, :eunit_lib},
                      {:line, 392},
                      {:expression, ~c"uniq ( [ 1 | 2 ] )"},
                      {:pattern,
                       ~c"{ " ++ ~c"error" ++ ~c" , " ++ ~c"function_clause" ++ ~c" , [...] }"},
                      {:unexpected_exception, {x__C, x__T, __STACKTRACE__}}
                    ]}
                 )
             else
               x__V ->
                 :erlang.error(
                   {:assertException,
                    [
                      {:module, :eunit_lib},
                      {:line, 392},
                      {:expression, ~c"uniq ( [ 1 | 2 ] )"},
                      {:pattern,
                       ~c"{ " ++ ~c"error" ++ ~c" , " ++ ~c"function_clause" ++ ~c" , [...] }"},
                      {:unexpected_success, x__V}
                    ]}
                 )
             end
           end).()
        end},
       {393,
        fn ->
          [] = uniq([])
        end},
       {394,
        fn ->
          [1, 2, 3] = uniq([1, 2, 3])
        end},
       {395,
        fn ->
          [1, 2, 3] = uniq([1, 2, 2, 3])
        end},
       {396,
        fn ->
          [1, 2, 3, 2, 1] = uniq([1, 2, 2, 3, 2, 2, 1])
        end},
       {397,
        fn ->
          [1, 2, 3] = uniq([1, 1, 1, 2, 2, 2, 3, 3, 3])
        end},
       {398,
        fn ->
          [~c"1", ~c"2", ~c"3"] = uniq([~c"1", ~c"1", ~c"2", ~c"2", ~c"3", ~c"3"])
        end}
     ]}
  end

  def command(cmd) do
    command(cmd, ~c"")
  end

  def command(cmd, dir) do
    command(cmd, dir, [])
  end

  def command(cmd, dir, env) do
    cD =
      cond do
        dir === ~c"" ->
          []

        true ->
          [{:cd, dir}]
      end

    setEnv =
      cond do
        env === [] ->
          []

        true ->
          [{:env, env}]
      end

    opt = cD ++ setEnv ++ [:stream, :exit_status, :use_stdio, :stderr_to_stdout, :in, :eof]
    p = :erlang.open_port({:spawn, cmd}, opt)
    get_data(p, [])
  end

  defp get_data(p, d) do
    receive do
      {^p, {:data, d1}} ->
        get_data(p, [d1 | d])

      {^p, :eof} ->
        :erlang.port_close(p)

        receive do
          {^p, {:exit_status, n}} ->
            {n, normalize(:lists.flatten(:lists.reverse(d)))}
        end
    end
  end

  defp normalize([?\r, ?\n | cs]) do
    [?\n | normalize(cs)]
  end

  defp normalize([?\r | cs]) do
    [?\n | normalize(cs)]
  end

  defp normalize([c | cs]) do
    [c | normalize(cs)]
  end

  defp normalize([]) do
    []
  end

  defp cmd_test_() do
    [
      {451,
       fn ->
         {0, ~c"hello\n"} = :eunit_lib.command(~c"echo hello")
       end}
    ] ++
      case :os.type() do
        {:unix, _} ->
          unix_cmd_tests()

        {:win32, _} ->
          win32_cmd_tests()

        _ ->
          []
      end
  end

  defp unix_cmd_tests() do
    [
      {~c"command execution, status, and output",
       [
         {463,
          fn ->
            (fn ->
               case :eunit_lib.command(~c"echo hello") do
                 {0, __Out} ->
                   __Out

                 {__N, _} ->
                   :erlang.error(
                     {:command_failed,
                      [
                        {:module, :eunit_lib},
                        {:line, 463},
                        {:command, ~c"echo hello"},
                        {:expected_status, 0},
                        {:status, __N}
                      ]}
                   )
               end
             end).()
          end},
         {464,
          fn ->
            (fn ->
               case :eunit_lib.command(~c"true") do
                 {0, _} ->
                   :ok

                 {__N, _} ->
                   :erlang.error(
                     {:assertCmd_failed,
                      [
                        {:module, :eunit_lib},
                        {:line, 464},
                        {:command, ~c"true"},
                        {:expected_status, 0},
                        {:status, __N}
                      ]}
                   )
               end
             end).()
          end},
         {465,
          fn ->
            (fn ->
               case :eunit_lib.command(~c"false") do
                 {1, _} ->
                   :ok

                 {__N, _} ->
                   :erlang.error(
                     {:assertCmd_failed,
                      [
                        {:module, :eunit_lib},
                        {:line, 465},
                        {:command, ~c"false"},
                        {:expected_status, 1},
                        {:status, __N}
                      ]}
                   )
               end
             end).()
          end},
         {466,
          fn ->
            (fn ->
               case :eunit_lib.command(~c"true") do
                 {0, _} ->
                   :ok

                 {__N, _} ->
                   :erlang.error(
                     {:assertCmd_failed,
                      [
                        {:module, :eunit_lib},
                        {:line, 466},
                        {:command, ~c"true"},
                        {:expected_status, 0},
                        {:status, __N}
                      ]}
                   )
               end
             end).()
          end},
         {467,
          fn ->
            (fn ->
               case :eunit_lib.command(~c"echo hello") do
                 {_, ~c"hello\n"} ->
                   :ok

                 {_, __T} ->
                   :erlang.error(
                     {:assertCmdOutput_failed,
                      [
                        {:module, :eunit_lib},
                        {:line, 467},
                        {:command, ~c"echo hello"},
                        {:expected_output, ~c"hello\n"},
                        {:output, __T}
                      ]}
                   )
               end
             end).()
          end},
         {468,
          fn ->
            (fn ->
               case :eunit_lib.command(~c"echo -n hello") do
                 {_, ~c"hello"} ->
                   :ok

                 {_, __T} ->
                   :erlang.error(
                     {:assertCmdOutput_failed,
                      [
                        {:module, :eunit_lib},
                        {:line, 468},
                        {:command, ~c"echo -n hello"},
                        {:expected_output, ~c"hello"},
                        {:output, __T}
                      ]}
                   )
               end
             end).()
          end}
       ]},
      {~c"file setup and cleanup", :setup,
       fn ->
         (fn ->
            case :eunit_lib.command(~c"mktemp tmp.XXXXXXXX") do
              {0, __Out} ->
                __Out

              {__N, _} ->
                :erlang.error(
                  {:command_failed,
                   [
                     {:module, :eunit_lib},
                     {:line, 472},
                     {:command, ~c"mktemp tmp.XXXXXXXX"},
                     {:expected_status, 0},
                     {:status, __N}
                   ]}
                )
            end
          end).()
       end,
       fn file ->
         (fn ->
            case :eunit_lib.command(~c"rm " ++ file) do
              {0, __Out} ->
                __Out

              {__N, _} ->
                :erlang.error(
                  {:command_failed,
                   [
                     {:module, :eunit_lib},
                     {:line, 473},
                     {:command, ~c"rm " ++ file},
                     {:expected_status, 0},
                     {:status, __N}
                   ]}
                )
            end
          end).()
       end,
       fn file ->
         [
           {475,
            fn ->
              (fn ->
                 case :eunit_lib.command(~c"echo xyzzy >" ++ file) do
                   {0, _} ->
                     :ok

                   {__N, _} ->
                     :erlang.error(
                       {:assertCmd_failed,
                        [
                          {:module, :eunit_lib},
                          {:line, 475},
                          {:command, ~c"echo xyzzy >" ++ file},
                          {:expected_status, 0},
                          {:status, __N}
                        ]}
                     )
                 end
               end).()
            end},
           {476,
            fn ->
              (fn ->
                 case :eunit_lib.command(~c"cat " ++ file) do
                   {_, ~c"xyzzy\n"} ->
                     :ok

                   {_, __T} ->
                     :erlang.error(
                       {:assertCmdOutput_failed,
                        [
                          {:module, :eunit_lib},
                          {:line, 476},
                          {:command, ~c"cat " ++ file},
                          {:expected_output, ~c"xyzzy\n"},
                          {:output, __T}
                        ]}
                     )
                 end
               end).()
            end}
         ]
       end}
    ]
  end

  defp win32_cmd_tests() do
    [
      {~c"command execution, status, and output",
       [
         {482,
          fn ->
            (fn ->
               case :eunit_lib.command(~c"echo hello") do
                 {0, __Out} ->
                   __Out

                 {__N, _} ->
                   :erlang.error(
                     {:command_failed,
                      [
                        {:module, :eunit_lib},
                        {:line, 482},
                        {:command, ~c"echo hello"},
                        {:expected_status, 0},
                        {:status, __N}
                      ]}
                   )
               end
             end).()
          end},
         {483,
          fn ->
            (fn ->
               case :eunit_lib.command(~c"echo hello") do
                 {_, ~c"hello\n"} ->
                   :ok

                 {_, __T} ->
                   :erlang.error(
                     {:assertCmdOutput_failed,
                      [
                        {:module, :eunit_lib},
                        {:line, 483},
                        {:command, ~c"echo hello"},
                        {:expected_output, ~c"hello\n"},
                        {:output, __T}
                      ]}
                   )
               end
             end).()
          end}
       ]}
    ]
  end

  def consult_file(file) do
    case :file.path_consult(
           [~c"."] ++ :code.get_path(),
           file
         ) do
      {:ok, data, _Path} ->
        data

      {:error, reason} ->
        msg = :file.format_error(reason)
        throw({:file_read_error, {reason, msg, file}})
    end
  end

  def list_dir(dir) do
    case :file.list_dir(dir) do
      {:ok, fs} ->
        fs

      {:error, reason} ->
        msg = :file.format_error(reason)
        throw({:file_read_error, {reason, msg, dir}})
    end
  end

  def trie_new() do
    :gb_trees.empty()
  end

  def trie_store([_ | _], []) do
    []
  end

  def trie_store([e | es], t) do
    case :gb_trees.lookup(e, t) do
      :none ->
        cond do
          es === [] ->
            :gb_trees.insert(e, [], t)

          true ->
            :gb_trees.insert(e, trie_store(es, :gb_trees.empty()), t)
        end

      {:value, []} ->
        t

      {:value, t1} ->
        :gb_trees.update(e, trie_store(es, t1), t)
    end
  end

  def trie_store([], _T) do
    []
  end

  def trie_match([_ | _], []) do
    :prefix
  end

  def trie_match([e | es], t) do
    case :gb_trees.lookup(e, t) do
      :none ->
        :no

      {:value, []} ->
        cond do
          es === [] ->
            :exact

          true ->
            :prefix
        end

      {:value, t1} ->
        trie_match(es, t1)
    end
  end

  def trie_match([], []) do
    :exact
  end

  def trie_match([], _T) do
    :no
  end

  defp trie_test_() do
    [
      {~c"basic representation",
       [
         {569,
          fn ->
            (fn ->
               x__T = :erlang.is_process_alive(self())

               case trie_new() === :gb_trees.empty() do
                 ^x__T ->
                   :ok

                 x__V ->
                   :erlang.error(
                     {:assert,
                      [
                        {:module, :eunit_lib},
                        {:line, 569},
                        {:expression, ~c"trie_new ( ) =:= gb_trees : empty ( )"},
                        {:expected, true},
                        case not x__T do
                          ^x__V ->
                            {:value, false}

                          _ ->
                            {:not_boolean, x__V}
                        end
                      ]}
                   )
               end
             end).()
          end},
         {570,
          fn ->
            (fn ->
               x__T = :erlang.is_process_alive(self())

               case trie_store(
                      [1],
                      trie_new()
                    ) ===
                      :gb_trees.insert(
                        1,
                        [],
                        :gb_trees.empty()
                      ) do
                 ^x__T ->
                   :ok

                 x__V ->
                   :erlang.error(
                     {:assert,
                      [
                        {:module, :eunit_lib},
                        {:line, 571},
                        {:expression,
                         ~c"trie_store ( [ 1 ] , trie_new ( ) ) =:= gb_trees : insert ( 1 , [ ] , gb_trees : empty ( ) )"},
                        {:expected, true},
                        case not x__T do
                          ^x__V ->
                            {:value, false}

                          _ ->
                            {:not_boolean, x__V}
                        end
                      ]}
                   )
               end
             end).()
          end},
         {572,
          fn ->
            (fn ->
               x__T = :erlang.is_process_alive(self())

               case trie_store(
                      [1, 2],
                      trie_new()
                    ) ===
                      :gb_trees.insert(
                        1,
                        :gb_trees.insert(
                          2,
                          [],
                          :gb_trees.empty()
                        ),
                        :gb_trees.empty()
                      ) do
                 ^x__T ->
                   :ok

                 x__V ->
                   :erlang.error(
                     {:assert,
                      [
                        {:module, :eunit_lib},
                        {:line, 576},
                        {:expression,
                         ~c"trie_store ( [ 1 , 2 ] , trie_new ( ) ) =:= gb_trees : insert ( 1 , gb_trees : insert ( 2 , [ ] , gb_trees : empty ( ) ) , gb_trees : empty ( ) )"},
                        {:expected, true},
                        case not x__T do
                          ^x__V ->
                            {:value, false}

                          _ ->
                            {:not_boolean, x__V}
                        end
                      ]}
                   )
               end
             end).()
          end},
         {577,
          fn ->
            (fn ->
               x__T = :erlang.is_process_alive(self())

               case [] === trie_store([1], []) do
                 ^x__T ->
                   :ok

                 x__V ->
                   :erlang.error(
                     {:assert,
                      [
                        {:module, :eunit_lib},
                        {:line, 577},
                        {:expression, ~c"[ ] =:= trie_store ( [ 1 ] , [ ] )"},
                        {:expected, true},
                        case not x__T do
                          ^x__V ->
                            {:value, false}

                          _ ->
                            {:not_boolean, x__V}
                        end
                      ]}
                   )
               end
             end).()
          end},
         {578,
          fn ->
            (fn ->
               x__T = :erlang.is_process_alive(self())

               case [] ===
                      trie_store(
                        [],
                        :gb_trees.empty()
                      ) do
                 ^x__T ->
                   :ok

                 x__V ->
                   :erlang.error(
                     {:assert,
                      [
                        {:module, :eunit_lib},
                        {:line, 578},
                        {:expression, ~c"[ ] =:= trie_store ( [ ] , gb_trees : empty ( ) )"},
                        {:expected, true},
                        case not x__T do
                          ^x__V ->
                            {:value, false}

                          _ ->
                            {:not_boolean, x__V}
                        end
                      ]}
                   )
               end
             end).()
          end}
       ]},
      {~c"basic storing and matching",
       [
         {581,
          fn ->
            :no = trie_match([], trie_new())
          end},
         {582,
          fn ->
            :exact = trie_match([], trie_store([], trie_new()))
          end},
         {583,
          fn ->
            :no = trie_match([], trie_store([1], trie_new()))
          end},
         {584,
          fn ->
            :exact =
              trie_match(
                [1],
                trie_store(
                  [1],
                  trie_new()
                )
              )
          end},
         {585,
          fn ->
            :prefix =
              trie_match(
                [1, 2],
                trie_store(
                  [1],
                  trie_new()
                )
              )
          end},
         {586,
          fn ->
            :no =
              trie_match(
                [1],
                trie_store(
                  [1, 2],
                  trie_new()
                )
              )
          end},
         {587,
          fn ->
            :no =
              trie_match(
                [1, 3],
                trie_store(
                  [1, 2],
                  trie_new()
                )
              )
          end},
         {588,
          fn ->
            :exact =
              trie_match(
                [1, 2, 3, 4, 5],
                trie_store(
                  [1, 2, 3, 4, 5],
                  trie_new()
                )
              )
          end},
         {590,
          fn ->
            :prefix =
              trie_match(
                [1, 2, 3, 4, 5],
                trie_store(
                  [1, 2, 3],
                  trie_new()
                )
              )
          end},
         {592,
          fn ->
            :no =
              trie_match(
                [1, 2, 2, 4, 5],
                trie_store(
                  [1, 2, 3],
                  trie_new()
                )
              )
          end}
       ]},
      {~c"matching with partially overlapping patterns", :setup,
       fn ->
         trie_store([1, 3, 2], trie_store([1, 2, 3], trie_new()))
       end,
       fn t ->
         [
           {601,
            fn ->
              :no = trie_match([], t)
            end},
           {602,
            fn ->
              :no = trie_match([1], t)
            end},
           {603,
            fn ->
              :no = trie_match([1, 2], t)
            end},
           {604,
            fn ->
              :no = trie_match([1, 3], t)
            end},
           {605,
            fn ->
              :exact = trie_match([1, 2, 3], t)
            end},
           {606,
            fn ->
              :exact =
                trie_match(
                  [1, 3, 2],
                  t
                )
            end},
           {607,
            fn ->
              :no =
                trie_match(
                  [1, 2, 2],
                  t
                )
            end},
           {608,
            fn ->
              :no =
                trie_match(
                  [1, 3, 3],
                  t
                )
            end},
           {609,
            fn ->
              :prefix =
                trie_match(
                  [1, 2, 3, 4],
                  t
                )
            end},
           {610,
            fn ->
              :prefix =
                trie_match(
                  [1, 3, 2, 1],
                  t
                )
            end}
         ]
       end},
      {~c"matching with more general pattern overriding less general", :setup,
       fn ->
         trie_store([1], trie_store([1, 2, 3], trie_new()))
       end,
       fn _ ->
         :ok
       end,
       fn t ->
         [
           {617,
            fn ->
              :no = trie_match([], t)
            end},
           {618,
            fn ->
              :exact = trie_match([1], t)
            end},
           {619,
            fn ->
              :prefix = trie_match([1, 2], t)
            end},
           {620,
            fn ->
              :prefix = trie_match([1, 2, 3], t)
            end},
           {621,
            fn ->
              :prefix =
                trie_match(
                  [1, 2, 3, 4],
                  t
                )
            end}
         ]
       end}
    ]
  end
end
