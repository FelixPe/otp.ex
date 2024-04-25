defmodule :m_eunit_data do
  use Bitwise
  require Record
  Record.defrecord(:r_test, :test, f: :undefined,
                                desc: :undefined, timeout: :undefined,
                                location: :undefined, line: 0)
  Record.defrecord(:r_group, :group, desc: :undefined,
                                 options: :undefined, order: :undefined,
                                 timeout: :undefined, context: :undefined,
                                 spawn: :undefined, tests: :undefined)
  Record.defrecord(:r_context, :context, setup: :undefined,
                                   cleanup: :undefined, process: :local)
  Record.defrecord(:r_file_info, :file_info, size: :undefined,
                                     type: :undefined, access: :undefined,
                                     atime: :undefined, mtime: :undefined,
                                     ctime: :undefined, mode: :undefined,
                                     links: :undefined,
                                     major_device: :undefined,
                                     minor_device: :undefined,
                                     inode: :undefined, uid: :undefined,
                                     gid: :undefined)
  Record.defrecord(:r_file_descriptor, :file_descriptor, module: :undefined,
                                           data: :undefined)
  Record.defrecord(:r_iter, :iter, prev: [], next: [],
                                tests: [], options: :undefined, pos: 0,
                                parent: [])
  def iter_init(tests, parentID, options) do
    r_iter(tests: tests, parent: :lists.reverse(parentID),
        options: options)
  end

  def iter_id(r_iter(pos: n, parent: ns)) do
    :lists.reverse(ns, [n])
  end

  def iter_next(i = r_iter(next: [], options: options)) do
    case (next(r_iter(i, :tests), options)) do
      {t, tests} ->
        {t,
           r_iter(i, prev: [t | r_iter(i, :prev)],  tests: tests, 
                  pos: r_iter(i, :pos) + 1)}
      :none ->
        :none
    end
  end

  def iter_next(i = r_iter(next: [t | ts])) do
    {t,
       r_iter(i, next: ts,  prev: [t | r_iter(i, :prev)], 
              pos: r_iter(i, :pos) + 1)}
  end

  def iter_prev(r_iter(prev: [])) do
    :none
  end

  def iter_prev(r_iter(prev: [t | ts]) = i) do
    {t,
       r_iter(i, prev: ts,  next: [t | r_iter(i, :next)], 
              pos: r_iter(i, :pos) - 1)}
  end

  defp next(tests, options) do
    case (:eunit_lib.dlist_next(tests)) do
      [t | ts] ->
        case (parse(t, options)) do
          {:data, t1} ->
            next([t1 | ts], options)
          t1 ->
            {t1, ts}
        end
      [] ->
        :none
    end
  end

  defp parse({:foreach, s, fs}, options)
      when (is_function(s) and is_list(fs)) do
    parse({:foreach, s, &ok/1, fs}, options)
  end

  defp parse({:foreach, s, c, fs}, options)
      when (is_function(s) and is_function(c) and
              is_list(fs)) do
    parse({:foreach, :spawn, s, c, fs}, options)
  end

  defp parse({:foreach, p, s, fs}, options)
      when (is_function(s) and is_list(fs)) do
    parse({:foreach, p, s, &ok/1, fs}, options)
  end

  defp parse({:foreach, p, s, c, fs} = t, _Options)
      when (is_function(s) and is_function(c) and
              is_list(fs)) do
    check_arity(s, 0, t)
    check_arity(c, 1, t)
    case (fs) do
      [f | fs1] ->
        {:data,
           [{:setup, p, s, c, f}, {:foreach, p, s, c, fs1}]}
      [] ->
        {:data, []}
    end
  end

  defp parse({:foreachx, s1, ps}, options)
      when (is_function(s1) and is_list(ps)) do
    parse({:foreachx, s1, &ok/2, ps}, options)
  end

  defp parse({:foreachx, s1, c1, ps}, options)
      when (is_function(s1) and is_function(c1) and
              is_list(ps)) do
    parse({:foreachx, :spawn, s1, c1, ps}, options)
  end

  defp parse({:foreachx, p, s1, ps}, options)
      when (is_function(s1) and is_list(ps)) do
    parse({:foreachx, p, s1, &ok/2, ps}, options)
  end

  defp parse({:foreachx, p, s1, c1, ps} = t, _Options)
      when (is_function(s1) and is_function(c1) and
              is_list(ps)) do
    check_arity(s1, 1, t)
    check_arity(c1, 2, t)
    case (ps) do
      [{x, f1} | ps1] when is_function(f1) ->
        check_arity(f1, 2, t)
        s = fn () ->
                 s1.(x)
            end
        c = fn r ->
                 c1.(x, r)
            end
        f = fn r ->
                 f1.(x, r)
            end
        {:data,
           [{:setup, p, s, c, f}, {:foreachx, p, s1, c1, ps1}]}
      [_ | _] ->
        bad_test(t)
      [] ->
        {:data, []}
    end
  end

  defp parse({:generator, f}, options) when is_function(f) do
    {:module, m} = :erlang.fun_info(f, :module)
    {:name, n} = :erlang.fun_info(f, :name)
    {:arity, a} = :erlang.fun_info(f, :arity)
    parse({:generator, f, {m, n, a}}, options)
  end

  defp parse({:generator, f, {m, n, a}} = t, _Options)
      when (is_function(f) and is_atom(m) and is_atom(n) and
              is_integer(a)) do
    check_arity(f, 0, t)
    case (:eunit_test.run_testfun(f)) do
      {:ok, t1} ->
        case (:eunit_lib.is_not_test(t1)) do
          true ->
            throw({:bad_generator, {{m, n, a}, t1}})
          false ->
            :ok
        end
        {:data, t1}
      {:error, {class, reason, trace}} ->
        throw({:generator_failed,
                 {{m, n, a}, {class, reason, trace}}})
    end
  end

  defp parse({:generator, m, f}, options)
      when (is_atom(m) and is_atom(f)) do
    parse({:generator, :eunit_test.mf_wrapper(m, f),
             {m, f, 0}},
            options)
  end

  defp parse({:inorder, t}, options) do
    group(r_group(tests: t, options: options, order: :inorder))
  end

  defp parse({:inparallel, t}, options) do
    parse({:inparallel, 0, t}, options)
  end

  defp parse({:inparallel, n, t}, options)
      when (is_integer(n) and n >= 0) do
    group(r_group(tests: t, options: options,
              order: {:inparallel, n}))
  end

  defp parse({:timeout, n, t}, options)
      when (is_number(n) and n >= 0) do
    group(r_group(tests: t, options: options,
              timeout: round(n * 1000)))
  end

  defp parse({:spawn, t}, options) do
    group(r_group(tests: t, options: options, spawn: :local))
  end

  defp parse({:spawn, n, t}, options) when is_atom(n) do
    group(r_group(tests: t, options: options,
              spawn: {:remote, n}))
  end

  defp parse({:setup, s, i}, options) when is_function(s) or
                                          is_list(s) do
    parse({:setup, :spawn, s, i}, options)
  end

  defp parse({:setup, s, c, i}, options)
      when (is_function(s) and is_function(c)) do
    parse({:setup, :spawn, s, c, i}, options)
  end

  defp parse({:setup, p, s, i}, options)
      when is_function(s) do
    parse({:setup, p, s, &ok/1, i}, options)
  end

  defp parse({:setup, p, l, i} = t, options)
      when is_list(l) do
    check_setup_list(l, t)
    {s, c} = :eunit_test.multi_setup(l)
    parse({:setup, p, s, c, i}, options)
  end

  defp parse({:setup, p, s, c, i} = t, options)
      when (is_function(s) and is_function(c) and
              is_function(i)) do
    check_arity(s, 0, t)
    check_arity(c, 1, t)
    case (:erlang.fun_info(i, :arity)) do
      {:arity, 0} ->
        parse({:setup, s, c,
                 fn _ ->
                      i
                 end},
                options)
      _ ->
        check_arity(i, 1, t)
        case (p) do
          :local ->
            :ok
          :spawn ->
            :ok
          {:spawn, n} when is_atom(n) ->
            :ok
          _ ->
            bad_test(t)
        end
        group(r_group(tests: i, options: options,
                  context: r_context(setup: s, cleanup: c, process: p)))
    end
  end

  defp parse({:setup, p, s, c, {:with, as}}, options)
      when is_list(as) do
    parse({:setup, p, s, c,
             fn x ->
                  {:with, x, as}
             end},
            options)
  end

  defp parse({:setup, p, s, c, t}, options)
      when (is_function(s) and is_function(c)) do
    parse({:setup, p, s, c,
             fn _ ->
                  t
             end},
            options)
  end

  defp parse({:node, n, t}, options) when is_atom(n) do
    parse({:node, n, '', t}, options)
  end

  defp parse({:node, n, a, t1} = t, options)
      when is_atom(n) do
    case (:eunit_lib.is_string(a)) do
      true ->
        parse({:setup,
                 fn () ->
                      startedNet = false
                      {name, host} = :eunit_lib.split_node(n)
                      {:ok, node} = :slave.start_link(host, name, a)
                      {node, startedNet}
                 end,
                 fn {node, stopNet} ->
                      :slave.stop(node)
                      case (stopNet) do
                        true ->
                          :net_kernel.stop()
                        false ->
                          :ok
                      end
                 end,
                 t1},
                options)
      false ->
        bad_test(t)
    end
  end

  defp parse({:module, m}, options) when is_atom(m) do
    {:data,
       {'module \'' ++ :erlang.atom_to_list(m) ++ '\'',
          get_module_tests(m, options)}}
  end

  defp parse({:application, a}, options) when is_atom(a) do
    try do
      parse({:file, :erlang.atom_to_list(a) ++ '.app'}, options)
    catch
      {:file_read_error, {:enoent, _, _}} ->
        case (:code.lib_dir(a)) do
          dir when is_list(dir) ->
            binDir = :filename.join(dir, 'ebin')
            case (:file.read_file_info(binDir)) do
              {:ok, r_file_info(type: :directory)} ->
                parse({:dir, binDir}, options)
              _ ->
                parse({:dir, dir}, options)
            end
          _ ->
            throw({:application_not_found, a})
        end
    end
  end

  defp parse({:application, a, info} = t, _Options)
      when is_atom(a) do
    case (:proplists.get_value(:modules, info)) do
      ms when is_list(ms) ->
        case (for m <- ms, not is_atom(m) do
                m
              end) do
          [] ->
            {:data, {'application \'' ++ :erlang.atom_to_list(a) ++ '\'', ms}}
          _ ->
            bad_test(t)
        end
      _ ->
        bad_test(t)
    end
  end

  defp parse({:file, f} = t, _Options) when is_list(f) do
    case (:eunit_lib.is_string(f)) do
      true ->
        {:data, {'file "' ++ f ++ '"', get_file_tests(f)}}
      false ->
        bad_test(t)
    end
  end

  defp parse({:dir, d} = t, _Options) when is_list(d) do
    case (:eunit_lib.is_string(d)) do
      true ->
        {:data, {'directory "' ++ d ++ '"', get_directory_module_tests(d)}}
      false ->
        bad_test(t)
    end
  end

  defp parse({:with, x, as} = t, _Options)
      when is_list(as) do
    case (as) do
      [a | as1] ->
        check_arity(a, 1, t)
        {:data,
           [{:erlang.fun_info_mfa(a),
               fn () ->
                    a.(x)
               end},
                {:with, x, as1}]}
      [] ->
        {:data, []}
    end
  end

  defp parse({s, t1} = t, options) when is_list(s) do
    case (:eunit_lib.is_string(s)) do
      true ->
        group(r_group(tests: t1, options: options,
                  desc: :unicode.characters_to_binary(s)))
      false ->
        bad_test(t)
    end
  end

  defp parse({s, t1}, options) when is_binary(s) do
    group(r_group(tests: t1, options: options, desc: s))
  end

  defp parse(t, options) when (tuple_size(t) > 2 and
                              is_list(:erlang.element(1, t))) do
    [s | es] = :erlang.tuple_to_list(t)
    parse({s, :erlang.list_to_tuple(es)}, options)
  end

  defp parse(t, options) when (tuple_size(t) > 2 and
                              is_binary(:erlang.element(1, t))) do
    [s | es] = :erlang.tuple_to_list(t)
    parse({s, :erlang.list_to_tuple(es)}, options)
  end

  defp parse(m, options) when is_atom(m) do
    parse({:module, m}, options)
  end

  defp parse(t, options) when is_list(t) do
    case (:eunit_lib.is_string(t)) do
      true ->
        try do
          parse({:dir, t}, options)
        catch
          {:file_read_error, {r, _, _}} when r === :enotdir or
                                               r === :enoent
                                             ->
            parse({:file, t}, options)
        end
      false ->
        bad_test(t)
    end
  end

  defp parse(t, _Options) do
    parse_simple(t)
  end

  defp parse_simple({l, f}) when (is_integer(l) and l >= 0) do
    r_test(parse_simple(f), line: l)
  end

  defp parse_simple({{m, n, a} = loc, f}) when (is_atom(m) and
                                        is_atom(n) and is_integer(a)) do
    r_test(parse_simple(f), location: loc)
  end

  defp parse_simple(f) do
    parse_function(f)
  end

  defp parse_function(f) when is_function(f) do
    check_arity(f, 0, f)
    r_test(f: f, location: :erlang.fun_info_mfa(f))
  end

  defp parse_function({:test, m, f}) when (is_atom(m) and
                                 is_atom(f)) do
    r_test(f: :eunit_test.mf_wrapper(m, f), location: {m, f, 0})
  end

  defp parse_function({m, f}) when (is_atom(m) and is_atom(f)) do
    parse_function({:test, m, f})
  end

  defp parse_function(f) do
    bad_test(f)
  end

  defp check_arity(f, n, _) when is_function(f, n) do
    :ok
  end

  defp check_arity(_, _, t) do
    bad_test(t)
  end

  defp check_setup_list([{tag, s, c} | es], t) when (is_atom(tag) and
                                         is_function(s) and is_function(c)) do
    check_arity(s, 0, t)
    check_arity(c, 1, t)
    check_setup_list(es, t)
  end

  defp check_setup_list([{tag, s} | es], t) when (is_atom(tag) and
                                      is_function(s)) do
    check_arity(s, 0, t)
    check_setup_list(es, t)
  end

  defp check_setup_list([], _T) do
    :ok
  end

  defp check_setup_list(_, t) do
    bad_test(t)
  end

  defp bad_test(t) do
    throw({:bad_test, t})
  end

  defp ok(_) do
    :ok
  end

  defp ok(_, _) do
    :ok
  end

  defp group(r_group(context: r_context()) = g) do
    g
  end

  defp group(r_group(tests: t0, desc: desc, options: options,
              order: order, context: context, spawn: spawn,
              timeout: timeout) = g) do
    {t1, ts} = lookahead(t0, options)
    {t2, _} = lookahead(ts, options)
    case (t1) do
      r_test(desc: desc1, timeout: timeout1) when (t2 === :none and
                                                spawn === :undefined and
                                                context === :undefined and
                                                desc === :undefined or desc1 === :undefined and
                                                timeout === :undefined or timeout1 === :undefined)
                                             ->
        r_test(t1, desc: join_properties(desc, desc1), 
                timeout: join_properties(timeout, timeout1))
      r_test(timeout: :undefined) when (t2 === :none and
                                     timeout !== :undefined and
                                     context === :undefined)
                                  ->
        r_group(g, tests: {:timeout, div(timeout, 1000), t0}, 
               timeout: :undefined)
      r_group(desc: desc1, order: order1, context: context1,
          spawn: spawn1, timeout: timeout1)
          when (t2 === :none and
                  desc === :undefined or desc1 === :undefined and
                  order === :undefined or order1 === :undefined and
                  context === :undefined or context1 === :undefined and
                  spawn === :undefined or spawn1 === :undefined and
                  timeout === :undefined or timeout1 === :undefined)
               ->
        group(r_group(t1, desc: join_properties(desc, desc1), 
                      order: join_properties(order, order1), 
                      context: join_properties(context, context1), 
                      spawn: join_properties(spawn, spawn1), 
                      timeout: join_properties(timeout, timeout1)))
      r_group(order: order1, timeout: timeout1) when t2 === :none ->
        push_order(order, order1,
                     push_timeout(timeout, timeout1, g))
      _ ->
        g
    end
  end

  defp lookahead(t, options) do
    case (next(t, options)) do
      {t1, ts} ->
        {t1, ts}
      :none ->
        {:none, []}
    end
  end

  defp join_properties(:undefined, x) do
    x
  end

  defp join_properties(x, :undefined) do
    x
  end

  defp push_timeout(timeout, :undefined, g = r_group(context: :undefined))
      when timeout !== :undefined do
    r_group(g, tests: {:timeout, div(timeout, 1000),
                   r_group(g, :tests)}, 
           timeout: :undefined)
  end

  defp push_timeout(_, _, g) do
    g
  end

  defp push_order(:inorder, :undefined, g) do
    r_group(g, tests: {:inorder, r_group(g, :tests)}, 
           order: :undefined)
  end

  defp push_order({:inparallel, n}, :undefined, g) do
    r_group(g, tests: {:inparallel, n, r_group(g, :tests)}, 
           order: :undefined)
  end

  defp push_order(_, _, g) do
    g
  end

  def get_module_tests(module, options) do
    try do
      module.module_info(:exports)
    catch
      :error, :undef ->
        throw({:module_not_found, module})
    else
      exports ->
        testFuns = extract_module_tests(module, exports,
                                          options)
        case (:lists.member({:eunit_wrapper_, 1}, exports)) do
          false ->
            testFuns
          true ->
            {:generator,
               fn () ->
                    module.eunit_wrapper_(testFuns)
               end}
        end
    end
  end

  defp extract_module_tests(module, exports, options) do
    testFuns = extract_testfuns(exports, module, '_test', '_test_')
    moduleName = :erlang.atom_to_list(module)
    exact = :proplists.get_bool(:exact_execution, options)
    case ({:lists.suffix('_tests', moduleName), exact}) do
      {false, false} ->
        moduleNameWithSuffix = moduleName ++ '_tests'
        moduleWithSuffix = :erlang.list_to_atom(moduleNameWithSuffix)
        try do
          get_module_tests(moduleWithSuffix, options)
        catch
          {:module_not_found, ^moduleWithSuffix} ->
            testFuns
        else
          moreTestFuns ->
            testFuns ++ [{'module \'' ++ moduleNameWithSuffix ++ '\'',
                            moreTestFuns}]
        end
      _ ->
        testFuns
    end
  end

  defp extract_testfuns(exports, module, testSuffix, generatorSuffix) do
    getTestFun = fn {function, 0}, acc ->
                      functionName = :erlang.atom_to_list(function)
                      case (:lists.suffix(testSuffix, functionName)) do
                        true ->
                          [{:test, module, function} | acc]
                        false ->
                          case (:lists.suffix(generatorSuffix, functionName)) do
                            true ->
                              [{:generator, module, function} | acc]
                            false ->
                              acc
                          end
                      end
                    _, acc ->
                      acc
                 end
    :lists.foldr(getTestFun, [], exports)
  end

  defp get_file_tests(f) do
    case (is_module_filename(f)) do
      true ->
        case (:file.read_file_info(f)) do
          {:ok, r_file_info(type: :regular)} ->
            objfile_test(f)
          _ ->
            case (:code.where_is_file(f)) do
              :non_existing ->
                objfile_test(f)
              path ->
                objfile_test(path)
            end
        end
      false ->
        :eunit_lib.consult_file(f)
    end
  end

  defp is_module_filename(f) do
    :filename.extension(f) === :code.objfile_extension()
  end

  defp objfile_test({m, file}) do
    {:setup,
       fn () ->
            :code.purge(m)
            {:module, ^m} = :code.load_abs(:filename.rootname(file))
            :ok
       end,
       {:module, m}}
  end

  defp objfile_test(file) do
    objfile_test({objfile_module(file), file})
  end

  defp objfile_module(file) do
    try do
      {:value, {:module, m}} = :lists.keysearch(:module, 1,
                                                  :beam_lib.info(file))
      m
    catch
      _, _ ->
        throw({:file_read_error, {:undefined, 'extracting module name failed', file}})
    end
  end

  defp get_directory_module_tests(d) do
    ms = get_directory_modules(d)
    f = fn {m, _}, s ->
             name = :erlang.atom_to_list(m)
             case (:lists.suffix('_tests', name)) do
               false ->
                 name1 = name ++ '_tests'
                 m1 = :erlang.list_to_atom(name1)
                 :dict.erase(m1, s)
               true ->
                 s
             end
        end
    for obj <- :dict.to_list(:lists.foldl(f,
                                            :dict.from_list(ms), ms)) do
      objfile_test(obj)
    end
  end

  defp get_directory_modules(d) do
    for f <- :eunit_lib.list_dir(d),
          is_module_filename(f) do
      (
        f1 = :filename.join(d, f)
        {objfile_module(f1), f1}
      )
    end
  end

  def enter_context(r_context(setup: s, cleanup: c, process: p), i, f) do
    f1 = (case (p) do
            :local ->
              f
            :spawn ->
              fn x ->
                   f.({:spawn, x})
              end
            {:spawn, n} ->
              fn t ->
                   f.({:spawn, n, t})
              end
          end)
    :eunit_test.enter_context(s, c, i, f1)
  end

  defp generator_exported_() do
    generator()
  end

  defp generator() do
    t = {729,
           fn () ->
                :ok
           end}
    [t, t, t]
  end

  defp echo_proc() do
    receive do
      {p, x} ->
        send(p, x)
        echo_proc()
    end
  end

  defp ping(p) do
    send(p, {self(), :ping})
    receive do
      :ping ->
        :ok
    end
  end

  defp data_test_() do
    setup = fn () ->
                 spawn(&echo_proc/0)
            end
    cleanup = fn pid ->
                   :erlang.exit(pid, :kill)
              end
    fail = {741,
              fn () ->
                   throw(:eunit)
              end}
    t = {742,
           fn () ->
                :ok
           end}
    tests = [t, t, t]
    [{744,
        fn () ->
             (
               (fn () ->
                     case (:eunit.test(t)) do
                       :ok ->
                         :ok
                       x__V ->
                         :erlang.error({:assertMatch,
                                          [{:module, :eunit_data}, {:line, 744},
                                                                       {:expression,
                                                                          'eunit : test ( T )'},
                                                                           {:pattern,
                                                                              'ok'},
                                                                               {:value,
                                                                                  x__V}]})
                     end
                end).()
             )
        end},
         {745,
            fn () ->
                 (
                   (fn () ->
                         case (:eunit.test(fail)) do
                           :error ->
                             :ok
                           x__V ->
                             :erlang.error({:assertMatch,
                                              [{:module, :eunit_data}, {:line,
                                                                          745},
                                                                           {:expression,
                                                                              'eunit : test ( Fail )'},
                                                                               {:pattern,
                                                                                  'error'},
                                                                                   {:value,
                                                                                      x__V}]})
                         end
                    end).()
                 )
            end},
             {746,
                fn () ->
                     (
                       (fn () ->
                             case (:eunit.test({:test, :eunit_data,
                                                  :trivial_test})) do
                               :ok ->
                                 :ok
                               x__V ->
                                 :erlang.error({:assertMatch,
                                                  [{:module, :eunit_data},
                                                       {:line, 746},
                                                           {:expression, 'eunit : test ( { test , ? MODULE , trivial_test } )'},
                                                               {:pattern, 'ok'},
                                                                   {:value,
                                                                      x__V}]})
                             end
                        end).()
                     )
                end},
                 {747,
                    fn () ->
                         (
                           (fn () ->
                                 case (:eunit.test({:generator,
                                                      fn () ->
                                                           tests
                                                      end})) do
                                   :ok ->
                                     :ok
                                   x__V ->
                                     :erlang.error({:assertMatch,
                                                      [{:module, :eunit_data},
                                                           {:line, 747},
                                                               {:expression, 'eunit : test ( { generator , fun ( ) -> Tests end } )'},
                                                                   {:pattern,
                                                                      'ok'},
                                                                       {:value,
                                                                          x__V}]})
                                 end
                            end).()
                         )
                    end},
                     {748,
                        fn () ->
                             (
                               (fn () ->
                                     case (:eunit.test({:generator,
                                                          &generator/0})) do
                                       :ok ->
                                         :ok
                                       x__V ->
                                         :erlang.error({:assertMatch,
                                                          [{:module,
                                                              :eunit_data},
                                                               {:line, 748},
                                                                   {:expression,
                                                                      'eunit : test ( { generator , fun generator / 0 } )'},
                                                                       {:pattern,
                                                                          'ok'},
                                                                           {:value,
                                                                              x__V}]})
                                     end
                                end).()
                             )
                        end},
                         {749,
                            fn () ->
                                 (
                                   (fn () ->
                                         case (:eunit.test({:generator,
                                                              :eunit_data,
                                                              :generator_exported_})) do
                                           :ok ->
                                             :ok
                                           x__V ->
                                             :erlang.error({:assertMatch,
                                                              [{:module,
                                                                  :eunit_data},
                                                                   {:line, 749},
                                                                       {:expression,
                                                                          'eunit : test ( { generator , ? MODULE , generator_exported_ } )'},
                                                                           {:pattern,
                                                                              'ok'},
                                                                               {:value,
                                                                                  x__V}]})
                                         end
                                    end).()
                                 )
                            end},
                             {750,
                                fn () ->
                                     (
                                       (fn () ->
                                             case (:eunit.test({:inorder,
                                                                  tests})) do
                                               :ok ->
                                                 :ok
                                               x__V ->
                                                 :erlang.error({:assertMatch,
                                                                  [{:module,
                                                                      :eunit_data},
                                                                       {:line,
                                                                          750},
                                                                           {:expression,
                                                                              'eunit : test ( { inorder , Tests } )'},
                                                                               {:pattern,
                                                                                  'ok'},
                                                                                   {:value,
                                                                                      x__V}]})
                                             end
                                        end).()
                                     )
                                end},
                                 {751,
                                    fn () ->
                                         (
                                           (fn () ->
                                                 case (:eunit.test({:inparallel,
                                                                      tests})) do
                                                   :ok ->
                                                     :ok
                                                   x__V ->
                                                     :erlang.error({:assertMatch,
                                                                      [{:module,
                                                                          :eunit_data},
                                                                           {:line,
                                                                              751},
                                                                               {:expression,
                                                                                  'eunit : test ( { inparallel , Tests } )'},
                                                                                   {:pattern,
                                                                                      'ok'},
                                                                                       {:value,
                                                                                          x__V}]})
                                                 end
                                            end).()
                                         )
                                    end},
                                     {752,
                                        fn () ->
                                             (
                                               (fn () ->
                                                     case (:eunit.test({:timeout,
                                                                          10,
                                                                          tests})) do
                                                       :ok ->
                                                         :ok
                                                       x__V ->
                                                         :erlang.error({:assertMatch,
                                                                          [{:module,
                                                                              :eunit_data},
                                                                               {:line,
                                                                                  752},
                                                                                   {:expression,
                                                                                      'eunit : test ( { timeout , 10 , Tests } )'},
                                                                                       {:pattern,
                                                                                          'ok'},
                                                                                           {:value,
                                                                                              x__V}]})
                                                     end
                                                end).()
                                             )
                                        end},
                                         {753,
                                            fn () ->
                                                 (
                                                   (fn () ->
                                                         case (:eunit.test({:spawn,
                                                                              tests})) do
                                                           :ok ->
                                                             :ok
                                                           x__V ->
                                                             :erlang.error({:assertMatch,
                                                                              [{:module,
                                                                                  :eunit_data},
                                                                                   {:line,
                                                                                      753},
                                                                                       {:expression,
                                                                                          'eunit : test ( { spawn , Tests } )'},
                                                                                           {:pattern,
                                                                                              'ok'},
                                                                                               {:value,
                                                                                                  x__V}]})
                                                         end
                                                    end).()
                                                 )
                                            end},
                                             {754,
                                                fn () ->
                                                     (
                                                       (fn () ->
                                                             case (:eunit.test({:setup,
                                                                                  setup,
                                                                                  cleanup,
                                                                                  fn p ->
                                                                                       {755,
                                                                                          fn () ->
                                                                                               :ok = ping(p)
                                                                                          end}
                                                                                  end})) do
                                                               :ok ->
                                                                 :ok
                                                               x__V ->
                                                                 :erlang.error({:assertMatch,
                                                                                  [{:module,
                                                                                      :eunit_data},
                                                                                       {:line,
                                                                                          754},
                                                                                           {:expression,
                                                                                              'eunit : test ( { setup , Setup , Cleanup , fun ( P ) -> ? _test ( ok = ping ( P ) ) end } )'},
                                                                                               {:pattern,
                                                                                                  'ok'},
                                                                                                   {:value,
                                                                                                      x__V}]})
                                                             end
                                                        end).()
                                                     )
                                                end},
                                                 {757,
                                                    fn () ->
                                                         (
                                                           (fn () ->
                                                                 case (:eunit.test({:module,
                                                                                      :eunit_lib})) do
                                                                   :ok ->
                                                                     :ok
                                                                   x__V ->
                                                                     :erlang.error({:assertMatch,
                                                                                      [{:module,
                                                                                          :eunit_data},
                                                                                           {:line,
                                                                                              757},
                                                                                               {:expression,
                                                                                                  'eunit : test ( { module , eunit_lib } )'},
                                                                                                   {:pattern,
                                                                                                      'ok'},
                                                                                                       {:value,
                                                                                                          x__V}]})
                                                                 end
                                                            end).()
                                                         )
                                                    end},
                                                     {758,
                                                        fn () ->
                                                             (
                                                               (fn () ->
                                                                     case (:eunit.test(:eunit_lib)) do
                                                                       :ok ->
                                                                         :ok
                                                                       x__V ->
                                                                         :erlang.error({:assertMatch,
                                                                                          [{:module,
                                                                                              :eunit_data},
                                                                                               {:line,
                                                                                                  758},
                                                                                                   {:expression,
                                                                                                      'eunit : test ( eunit_lib )'},
                                                                                                       {:pattern,
                                                                                                          'ok'},
                                                                                                           {:value,
                                                                                                              x__V}]})
                                                                     end
                                                                end).()
                                                             )
                                                        end},
                                                         {759,
                                                            fn () ->
                                                                 (
                                                                   (fn () ->
                                                                         case (:eunit.test('examples/tests.txt')) do
                                                                           :ok ->
                                                                             :ok
                                                                           x__V ->
                                                                             :erlang.error({:assertMatch,
                                                                                              [{:module,
                                                                                                  :eunit_data},
                                                                                                   {:line,
                                                                                                      759},
                                                                                                       {:expression,
                                                                                                          'eunit : test ( "examples/tests.txt" )'},
                                                                                                           {:pattern,
                                                                                                              'ok'},
                                                                                                               {:value,
                                                                                                                  x__V}]})
                                                                         end
                                                                    end).()
                                                                 )
                                                            end}]
  end

  defp trivial_test() do
    :ok
  end

  defp trivial_generator_test_() do
    [{768,
        fn () ->
             :ok
        end}]
  end

  defp lazy_test_() do
    {:spawn,
       [{771,
           fn () ->
                :undefined = :erlang.put(:count, 0)
           end},
            lazy_gen(7), {773,
                            fn () ->
                                 (
                                   (fn () ->
                                         case (:erlang.get(:count)) do
                                           7 ->
                                             :ok
                                           x__V ->
                                             :erlang.error({:assertMatch,
                                                              [{:module,
                                                                  :eunit_data},
                                                                   {:line, 773},
                                                                       {:expression,
                                                                          'get ( count )'},
                                                                           {:pattern,
                                                                              '7'},
                                                                               {:value,
                                                                                  x__V}]})
                                         end
                                    end).()
                                 )
                            end}]}
  end

  defp lazy_gen(n) do
    {:generator,
       fn () ->
            cond do
              n > 0 ->
                [{780,
                    fn () ->
                         :erlang.put(:count, 1 + :erlang.get(:count))
                    end} |
                     lazy_gen(n - 1)]
              true ->
                []
            end
       end}
  end

end