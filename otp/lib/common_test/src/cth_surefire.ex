defmodule :m_cth_surefire do
  use Bitwise
  require Record
  Record.defrecord(:r_state, :state, filepath: :undefined,
                                 axis: :undefined, properties: :undefined,
                                 package: :undefined, hostname: :undefined,
                                 curr_suite: :undefined,
                                 curr_suite_file: :undefined,
                                 curr_suite_ast: :undefined,
                                 curr_suite_ts: :undefined, curr_group: [],
                                 curr_log_dir: :undefined, timer: :undefined,
                                 tc_log: :undefined, url_base: :undefined,
                                 test_cases: [], test_suites: [])
  Record.defrecord(:r_testcase, :testcase, log: :undefined,
                                    url: :undefined, group: :undefined,
                                    file: :undefined, line: :undefined,
                                    classname: :undefined, name: :undefined,
                                    time: :undefined, result: :undefined,
                                    timestamp: :undefined)
  Record.defrecord(:r_testsuite, :testsuite, errors: :undefined,
                                     failures: :undefined, skipped: :undefined,
                                     hostname: :undefined, name: :undefined,
                                     tests: :undefined, time: :undefined,
                                     timestamp: :undefined, id: :undefined,
                                     package: :undefined,
                                     properties: :undefined,
                                     testcases: :undefined, log: :undefined,
                                     url: :undefined)
  def init(path, opts) do
    {:ok, pid} = :gen_server.start(:cth_surefire,
                                     [path, opts], [])
    pid
  end

  def init([path, opts]) do
    :ct_util.mark_process()
    {:ok, host} = :inet.gethostname()
    {:ok,
       r_state(filepath: path,
           hostname: :proplists.get_value(:hostname, opts, host),
           package: :proplists.get_value(:package, opts),
           axis: :proplists.get_value(:axis, opts, []),
           properties: :proplists.get_value(:properties, opts, []),
           url_base: :proplists.get_value(:url_base, opts),
           timer: :os.timestamp())}
  end

  def handle_call({:terminate, args}, _From, state) do
    res = apply(:cth_surefire, :terminate, args ++ [state])
    {:stop, :normal, res, state}
  end

  def handle_call({function, args}, _From, state)
      when function === :on_tc_fail or
             function === :on_tc_skip do
    newState = apply(:cth_surefire, function,
                       args ++ [state])
    {:reply, :ok, newState}
  end

  def handle_call({function, args}, _From, state) do
    {reply, newState} = apply(:cth_surefire, function,
                                args ++ [state])
    {:reply, reply, newState}
  end

  def id(opts) do
    case (:proplists.get_value(:path, opts)) do
      :undefined ->
        'junit_report.xml'
      path ->
        :filename.absname(path)
    end
  end

  def pre_init_per_suite(suite, skipOrFail, proxy) when is_pid(proxy) do
    {:gen_server.call(proxy,
                        {:pre_init_per_suite, [suite, skipOrFail]}),
       proxy}
  end

  def pre_init_per_suite(suite, skipOrFail, r_state(test_cases: []) = state)
      when is_tuple(skipOrFail) do
    {skipOrFail,
       init_tc(r_state(state, curr_suite: suite, 
                          curr_suite_ts: :os.timestamp()),
                 skipOrFail)}
  end

  def pre_init_per_suite(suite, config, r_state(test_cases: []) = state) do
    tcLog = :proplists.get_value(:tc_logfile, config)
    currLogDir = :filename.dirname(tcLog)
    path = (case (r_state(state, :filepath)) do
              'junit_report.xml' ->
                rootDir = get_test_root(tcLog)
                :filename.join(rootDir, 'junit_report.xml')
              p ->
                p
            end)
    ast = (case (:beam_lib.chunks(:code.which(suite),
                                    [:debug_info])) do
             {:ok,
                {^suite,
                   [{:debug_info,
                       {:debug_info_v1, :erl_abstract_code,
                          {abstr, _Opts}}}]}} ->
               cond do
                 abstr === :none ->
                   :undefined
                 true ->
                   abstr
               end
             _ ->
               :undefined
           end)
    {config,
       init_tc(r_state(state, filepath: path,  curr_suite: suite, 
                          curr_suite_file: get_file(suite), 
                          curr_suite_ast: ast,  curr_suite_ts: :os.timestamp(), 
                          curr_log_dir: currLogDir),
                 config)}
  end

  def pre_init_per_suite(suite, config, state) do
    pre_init_per_suite(suite, config, close_suite(state))
  end

  defp get_file(suite) do
    case (:beam_lib.chunks(:code.which(suite), ['CInf'])) do
      {:ok, {_, [{'CInf', bin}]}} ->
        source = :proplists.get_value(:source,
                                        :erlang.binary_to_term(bin))
        case (:filelib.is_file(source)) do
          true ->
            source
          false ->
            :undefined
        end
      _ ->
        :undefined
    end
  end

  def post_init_per_suite(suite, config, result, proxy)
      when is_pid(proxy) do
    {:gen_server.call(proxy,
                        {:post_init_per_suite, [suite, config, result]}),
       proxy}
  end

  def post_init_per_suite(_Suite, config, result, state) do
    {result, end_tc(:init_per_suite, config, result, state)}
  end

  def pre_end_per_suite(suite, config, proxy) when is_pid(proxy) do
    {:gen_server.call(proxy,
                        {:pre_end_per_suite, [suite, config]}),
       proxy}
  end

  def pre_end_per_suite(_Suite, config, state) do
    {config, init_tc(state, config)}
  end

  def post_end_per_suite(suite, config, result, proxy)
      when is_pid(proxy) do
    {:gen_server.call(proxy,
                        {:post_end_per_suite, [suite, config, result]}),
       proxy}
  end

  def post_end_per_suite(_Suite, config, result, state) do
    {result, end_tc(:end_per_suite, config, result, state)}
  end

  def pre_init_per_group(suite, group, config, proxy)
      when is_pid(proxy) do
    {:gen_server.call(proxy,
                        {:pre_init_per_group, [suite, group, config]}),
       proxy}
  end

  def pre_init_per_group(_Suite, group, config, state) do
    {config,
       init_tc(r_state(state, curr_group: [group |
                                         r_state(state, :curr_group)]),
                 config)}
  end

  def post_init_per_group(suite, group, config, result, proxy)
      when is_pid(proxy) do
    {:gen_server.call(proxy,
                        {:post_init_per_group, [suite, group, config, result]}),
       proxy}
  end

  def post_init_per_group(_Suite, _Group, config, result, state) do
    {result, end_tc(:init_per_group, config, result, state)}
  end

  def pre_end_per_group(suite, group, config, proxy)
      when is_pid(proxy) do
    {:gen_server.call(proxy,
                        {:pre_end_per_group, [suite, group, config]}),
       proxy}
  end

  def pre_end_per_group(_Suite, _Group, config, state) do
    {config, init_tc(state, config)}
  end

  def post_end_per_group(suite, group, config, result, proxy)
      when is_pid(proxy) do
    {:gen_server.call(proxy,
                        {:post_end_per_group, [suite, group, config, result]}),
       proxy}
  end

  def post_end_per_group(_Suite, _Group, config, result, state) do
    newState = end_tc(:end_per_group, config, result, state)
    {result,
       r_state(newState, curr_group: tl(r_state(newState, :curr_group)))}
  end

  def pre_init_per_testcase(suite, tC, config, proxy) when is_pid(proxy) do
    {:gen_server.call(proxy,
                        {:pre_init_per_testcase, [suite, tC, config]}),
       proxy}
  end

  def pre_init_per_testcase(_Suite, _TC, config, state) do
    {config, init_tc(state, config)}
  end

  def post_end_per_testcase(suite, tC, config, result, proxy)
      when is_pid(proxy) do
    {:gen_server.call(proxy,
                        {:post_end_per_testcase, [suite, tC, config, result]}),
       proxy}
  end

  def post_end_per_testcase(_Suite, tC, config, result, state) do
    {result, end_tc(tC, config, result, state)}
  end

  def on_tc_fail(suite, tC, result, proxy) when is_pid(proxy) do
    _ = :gen_server.call(proxy,
                           {:on_tc_fail, [suite, tC, result]})
    proxy
  end

  def on_tc_fail(_Suite, _TC, _Res, state = r_state(test_cases: [])) do
    state
  end

  def on_tc_fail(suite, _TC, res, state) do
    tCs = r_state(state, :test_cases)
    tC = hd(tCs)
    line = (case (get_line_from_result(suite, res)) do
              :undefined ->
                r_testcase(tC, :line)
              l ->
                l
            end)
    newTC = r_testcase(tC, line: line, 
                    result: {:fail,
                               :lists.flatten(:io_lib.format('~tp', [res]))})
    r_state(state, test_cases: [newTC | tl(tCs)])
  end

  defp get_line_from_result(suite,
            {_Error, [{__M, __F, __A, __I} | _] = stackTrace}) do
    case (:lists.filter(fn {mod, _Func, _Arity, _Info} ->
                             mod === suite
                        end,
                          stackTrace)) do
      [{^suite, _F, _A, info} | _] ->
        :proplists.get_value(:line, info)
      _ ->
        :undefined
    end
  end

  defp get_line_from_result(_, _) do
    :undefined
  end

  def on_tc_skip(suite, tC, result, proxy) when is_pid(proxy) do
    _ = :gen_server.call(proxy,
                           {:on_tc_skip, [suite, tC, result]})
    proxy
  end

  def on_tc_skip(suite, {configFunc, _GrName}, res, state) do
    on_tc_skip(suite, configFunc, res, state)
  end

  def on_tc_skip(suite, tc, res, state0) do
    tcStr = :erlang.atom_to_list(tc)
    state = (case (r_state(state0, :test_cases)) do
               [r_testcase(name: ^tcStr) | tCs] ->
                 r_state(state0, test_cases: tCs)
               _ ->
                 state0
             end)
    do_tc_skip(res,
                 end_tc(tc, [], res,
                          init_tc(set_suite(suite, state), [])))
  end

  defp do_tc_skip(res, state) do
    tCs = r_state(state, :test_cases)
    tC = hd(tCs)
    newTC = r_testcase(tC, result: {:skipped,
                             :lists.flatten(:io_lib.format('~tp', [res]))})
    r_state(state, test_cases: [newTC | tl(tCs)])
  end

  defp init_tc(state, config) when is_list(config) == false do
    r_state(state, timer: :os.timestamp(),  tc_log: '')
  end

  defp init_tc(state, config) do
    r_state(state, timer: :os.timestamp(), 
               tc_log: :proplists.get_value(:tc_logfile, config, []))
  end

  defp end_tc(func, config, res, state) when is_atom(func) do
    end_tc(:erlang.atom_to_list(func), config, res, state)
  end

  defp end_tc(func, config, res, state = r_state(tc_log: '')) do
    end_tc(func, config, res,
             r_state(state, tc_log: :proplists.get_value(:tc_logfile,
                                                     config)))
  end

  defp end_tc(name, _Config, _Res,
            state = r_state(curr_suite: suite, curr_group: groups,
                        curr_log_dir: currLogDir, timer: tS,
                        url_base: urlBase)) do
    log = (case (r_state(state, :tc_log)) do
             :undefined ->
               lowerSuiteName = :string.lowercase(:erlang.atom_to_list(suite))
               case (:filelib.wildcard(:filename.join(currLogDir,
                                                        lowerSuiteName ++ '.' ++ name ++ '.*html'))) do
                 [] ->
                   ''
                 [logFile | _] ->
                   logFile
               end
             logFile ->
               logFile
           end)
    url = make_url(urlBase, log)
    className = :erlang.atom_to_list(suite)
    pGroup = :lists.concat(:lists.join('.',
                                         :lists.reverse(groups)))
    timeTakes = :io_lib.format('~f',
                                 [:timer.now_diff(:os.timestamp(),
                                                    tS) / 1000000])
    r_state(state, test_cases: [r_testcase(log: log, url: url,
                              timestamp: now_to_string(tS),
                              classname: className, group: pGroup, name: name,
                              time: timeTakes, file: r_state(state, :curr_suite_file),
                              line: get_line_from_suite(r_state(state, :curr_suite_ast),
                                                          name),
                              result: :passed) |
                              r_state(state, :test_cases)], 
               tc_log: '')
  end

  defp set_suite(suite, r_state(curr_suite: :undefined) = state) do
    r_state(state, curr_suite: suite, 
               curr_suite_ts: :os.timestamp())
  end

  defp set_suite(_, state) do
    state
  end

  defp close_suite(r_state(test_cases: []) = state) do
    state
  end

  defp close_suite(r_state(test_cases: tCs,
              url_base: urlBase) = state) do
    {total, fail, skip} = count_tcs(tCs, 0, 0, 0)
    timeTaken = :timer.now_diff(:os.timestamp(),
                                  r_state(state, :curr_suite_ts)) / 1000000
    suiteLog = :filename.join(r_state(state, :curr_log_dir), 'suite.log.html')
    suiteUrl = make_url(urlBase, suiteLog)
    suite = r_testsuite(name: :erlang.atom_to_list(r_state(state, :curr_suite)),
                package: r_state(state, :package),
                hostname: r_state(state, :hostname),
                time: :io_lib.format('~f', [timeTaken]),
                timestamp: now_to_string(r_state(state, :curr_suite_ts)),
                errors: 0, failures: fail, skipped: skip, tests: total,
                testcases: :lists.reverse(tCs), log: suiteLog,
                url: suiteUrl)
    r_state(state, curr_suite: :undefined,  test_cases: [], 
               test_suites: [suite | r_state(state, :test_suites)])
  end

  def terminate(proxy) when is_pid(proxy) do
    :gen_server.call(proxy, {:terminate, []})
    :ok
  end

  def terminate(state = r_state(test_cases: [])) do
    {:ok, d} = :file.open(r_state(state, :filepath),
                            [:write, {:encoding, :utf8}])
    :io.format(d, '<?xml version="1.0" encoding= "UTF-8" ?>', [])
    :io.format(d, '~ts', [to_xml(state)])
    (try do
      :file.sync(d)
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end)
    (try do
      :file.close(d)
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end)
  end

  def terminate(state) do
    terminate(close_suite(state))
  end

  defp get_line_from_suite(:undefined, _TC) do
    :undefined
  end

  defp get_line_from_suite(abstr, tC) do
    case (for {:function, anno, name, 1, _} <- abstr,
                tC === :erlang.atom_to_list(name) do
            anno
          end) do
      [{line, _Col}] ->
        line
      _ ->
        case (for {:function, anno, name, _, _} <- abstr,
                    tC === :erlang.atom_to_list(name) do
                anno
              end) do
          [{line, _} | _] ->
            line
          _ ->
            :undefined
        end
    end
  end

  defp to_xml(r_testcase(group: group, classname: cL, log: l, url: u,
              file: file, line: line, name: n, time: t, timestamp: tS,
              result: r)) do
    ['<testcase ', for _ <- [:EFE_DUMMY_GEN], group != '' do
          ['group="', group, '" ']
        end,
            'name="', n, '" time="', t, '" timestamp="', tS, '" ', for _ <- [:EFE_DUMMY_GEN],
                                        u != :undefined do
                                    ['url="', u, '" ']
                                  end,
                                      for _ <- [:EFE_DUMMY_GEN],
                                            file != :undefined do
                                        ['file="', file, '" ']
                                      end,
                                          for _ <- [:EFE_DUMMY_GEN],
                                                line != :undefined do
                                            ['line="', :erlang.integer_to_list(line),
                                                    '" ']
                                          end,
                                              'log="', l, '">', case (r) do
                                                         :passed ->
                                                           []
                                                         {:skipped, reason} ->
                                                           ['<skipped type="skip" message="Test ', n, ' in ', cL, ' skipped!">',
                                                                             sanitize(reason),
                                                                                 '</skipped>']
                                                         {:fail, reason} ->
                                                           ['<failure message="Test ', n, ' in ', cL, ' failed!" type="crash">',
                                                                             sanitize(reason),
                                                                                 '</failure>']
                                                       end,
                                                           '</testcase>']
  end

  defp to_xml(r_testsuite(package: p, hostname: h, errors: e,
              failures: f, skipped: s, time: time, timestamp: tS,
              tests: t, name: n, testcases: cases, log: log,
              url: url)) do
    ['<testsuite ', for _ <- [:EFE_DUMMY_GEN], p != :undefined do
          ['package="', p, '" ']
        end,
            'hostname="', h, '" name="', n, '" time="', time, '" timestamp="', tS, '" errors="',
                                            :erlang.integer_to_list(e), '" failures="',
                                                                            :erlang.integer_to_list(f),
                                                                                '" skipped="',
                                                                                    :erlang.integer_to_list(s),
                                                                                        '" tests="',
                                                                                            :erlang.integer_to_list(t),
                                                                                                '" ',
                                                                                                    for _ <- [:EFE_DUMMY_GEN],
                                                                                                          url != :undefined do
                                                                                                      ['url="',
                                                                                                           url,
                                                                                                               '" ']
                                                                                                    end,
                                                                                                        'log="',
                                                                                                            log,
                                                                                                                '">',
                                                                                                                    for case__ <- cases do
                                                                                                                      to_xml(case__)
                                                                                                                    end,
                                                                                                                        '</testsuite>']
  end

  defp to_xml(r_state(test_suites: testSuites, axis: axis,
              properties: props)) do
    ['<testsuites>', properties_to_xml(axis, props),
            for testSuite <- testSuites do
              to_xml(testSuite)
            end,
                '</testsuites>']
  end

  defp properties_to_xml([], []) do
    []
  end

  defp properties_to_xml(axis, props) do
    ['<properties>', for {name, value} <- axis do
          ['<property name="', name, '" axis="yes" value="', value, '" />']
        end,
            for {name, value} <- props do
              ['<property name="', name, '" value="', value, '" />']
            end,
                '</properties>']
  end

  defp sanitize([?> | t]) do
    '&gt;' ++ sanitize(t)
  end

  defp sanitize([?< | t]) do
    '&lt;' ++ sanitize(t)
  end

  defp sanitize([?" | t]) do
    '&quot;' ++ sanitize(t)
  end

  defp sanitize([?' | t]) do
    '&apos;' ++ sanitize(t)
  end

  defp sanitize([?& | t]) do
    '&amp;' ++ sanitize(t)
  end

  defp sanitize([h | t]) do
    [h | sanitize(t)]
  end

  defp sanitize([]) do
    []
  end

  defp now_to_string(now) do
    {{yY, mM, dD},
       {hH, mi, sS}} = :calendar.now_to_local_time(now)
    :io_lib.format('~w-~2..0B-~2..0BT~2..0B:~2..0B:~2..0B', [yY, mM, dD, hH, mi, sS])
  end

  defp make_url(:undefined, _) do
    :undefined
  end

  defp make_url(_, []) do
    :undefined
  end

  defp make_url(urlBase0, log) do
    urlBase = :string.trim(urlBase0, :trailing, [?/])
    relativeLog = get_relative_log_url(log)
    :lists.flatten(:lists.join(?/, [urlBase, relativeLog]))
  end

  defp get_test_root(log) do
    logParts = :filename.split(log)
    :filename.join(:lists.sublist(logParts, 1,
                                    length(logParts) - 3))
  end

  defp get_relative_log_url(log) do
    logParts = :filename.split(log)
    start = length(logParts) - 3
    length = 3 + 1
    :lists.flatten(:lists.join(?/,
                                 :lists.sublist(logParts, start, length)))
  end

  defp count_tcs([r_testcase(name: confCase) | tCs], ok, f, s)
      when confCase == 'init_per_suite' or confCase == 'end_per_suite' or confCase == 'init_per_group' or
             confCase == 'end_per_group' do
    count_tcs(tCs, ok, f, s)
  end

  defp count_tcs([r_testcase(result: :passed) | tCs], ok, f, s) do
    count_tcs(tCs, ok + 1, f, s)
  end

  defp count_tcs([r_testcase(result: {:fail, _}) | tCs], ok, f, s) do
    count_tcs(tCs, ok, f + 1, s)
  end

  defp count_tcs([r_testcase(result: {:skipped, _}) | tCs], ok, f, s) do
    count_tcs(tCs, ok, f, s + 1)
  end

  defp count_tcs([r_testcase(result: {:auto_skipped, _}) | tCs], ok, f,
            s) do
    count_tcs(tCs, ok, f, s + 1)
  end

  defp count_tcs([], ok, f, s) do
    {ok + f + s, f, s}
  end

end