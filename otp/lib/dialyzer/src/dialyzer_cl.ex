defmodule :m_dialyzer_cl do
  use Bitwise
  require Record
  Record.defrecord(:r_plt_info, :plt_info, files: :undefined,
                                    mod_deps: :dict.new())
  Record.defrecord(:r_iplt_info, :iplt_info, files: :undefined,
                                     mod_deps: :dict.new(), warning_map: :none,
                                     legal_warnings: :none)
  Record.defrecord(:r_plt, :plt, info: :undefined,
                               types: :undefined, contracts: :undefined,
                               callbacks: :undefined,
                               exported_types: :undefined)
  Record.defrecord(:r_analysis, :analysis, analysis_pid: :undefined,
                                    type: :succ_typings, defines: [],
                                    doc_plt: :undefined, files: [],
                                    include_dirs: [], start_from: :byte_code,
                                    plt: :undefined, use_contracts: true,
                                    behaviours_chk: false, timing: false,
                                    timing_server: :none, callgraph_file: '',
                                    mod_deps_file: '', solvers: :undefined)
  Record.defrecord(:r_options, :options, files: [], files_rec: [],
                                   warning_files: [], warning_files_rec: [],
                                   analysis_type: :succ_typings, timing: false,
                                   defines: [], from: :byte_code,
                                   get_warnings: :maybe, init_plts: [],
                                   include_dirs: [], output_plt: :none,
                                   legal_warnings: :ordsets.new(),
                                   report_mode: :normal, erlang_mode: false,
                                   use_contracts: true, output_file: :none,
                                   output_format: :formatted,
                                   filename_opt: :basename, indent_opt: true,
                                   callgraph_file: '', mod_deps_file: '',
                                   check_plt: true, error_location: :column,
                                   metrics_file: :none,
                                   module_lookup_file: :none, solvers: [])
  Record.defrecord(:r_contract, :contract, contracts: [], args: [],
                                    forms: [])
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
  Record.defrecord(:r_cl_state, :cl_state, backend_pid: :undefined,
                                    code_server: :none, erlang_mode: false,
                                    external_calls: [], external_types: [],
                                    legal_warnings: :ordsets.new(),
                                    mod_deps: :dict.new(), output: :standard_io,
                                    output_format: :formatted,
                                    filename_opt: :basename, indent_opt: true,
                                    error_location: :column, output_plt: :none,
                                    plt_info: :none, report_mode: :normal,
                                    return_status: 0, stored_warnings: [])
  def start(opts) do
    {{ret, warns},
       _ModulesAnalyzed} = start_report_modules_analyzed(opts)
    {ret, warns}
  end

  def start_report_modules_analyzed(opts) do
    {{ret, warns}, _ModulesChanged,
       modulesAnalyzed} = start_report_modules_changed_and_analyzed(opts)
    {{ret, warns}, modulesAnalyzed}
  end

  def start_report_modules_changed_and_analyzed(r_options(analysis_type: analysisType) = options) do
    :erlang.process_flag(:trap_exit, true)
    case (analysisType) do
      :plt_check ->
        check_plt(options)
      :plt_build ->
        build_plt(options)
      :plt_add ->
        add_to_plt(options)
      :plt_remove ->
        remove_from_plt(options)
      :succ_typings ->
        enrich_with_modules_changed(do_analysis(options),
                                      :undefined)
    end
  end

  defp build_plt(opts) do
    opts1 = init_opts_for_build(opts)
    files = get_files_from_opts(opts1)
    md5 = :dialyzer_cplt.compute_md5_from_files(files)
    pltInfo = r_plt_info(files: md5)
    enrich_with_modules_changed(do_analysis(files, opts1,
                                              :dialyzer_plt.new(), pltInfo),
                                  :undefined)
  end

  defp init_opts_for_build(opts) do
    case (r_options(opts, :output_plt) === :none) do
      true ->
        case (r_options(opts, :init_plts)) do
          [] ->
            r_options(opts, output_plt: get_default_output_plt())
          [plt] ->
            r_options(opts, init_plts: [],  output_plt: plt)
          plts ->
            msg = :io_lib.format('Could not build multiple PLT files: ~ts\n', [format_plts(plts)])
            cl_error(msg)
        end
      false ->
        r_options(opts, init_plts: [])
    end
  end

  defp add_to_plt(opts) do
    opts1 = init_opts_for_add(opts)
    addFiles = get_files_from_opts(opts1)
    case (r_options(opts1, :init_plts)) do
      [] ->
        plt_common(opts1, [], addFiles)
      [_] ->
        plt_common(opts1, [], addFiles)
      pltFiles ->
        plts = (for f <- pltFiles do
                  :dialyzer_cplt.from_file(f)
                end)
        _ = :dialyzer_cplt.merge_plts_or_report_conflicts(pltFiles,
                                                            plts)
        _ = (for plt <- pltFiles do
               plt_common(r_options(opts, init_plts: [plt]), [], addFiles)
             end)
        {{0, []}, [], []}
    end
  end

  defp init_opts_for_add(opts) do
    case (r_options(opts, :output_plt) === :none) do
      true ->
        case (r_options(opts, :init_plts)) do
          [] ->
            r_options(opts, output_plt: get_default_output_plt(), 
                      init_plts: get_default_init_plt())
          [plt] ->
            r_options(opts, output_plt: plt)
          plts ->
            msg = :io_lib.format('Could not add to multiple PLT files: ~ts\n', [format_plts(plts)])
            cl_error(msg)
        end
      false ->
        case (r_options(opts, :init_plts) === []) do
          true ->
            r_options(opts, init_plts: get_default_init_plt())
          false ->
            opts
        end
    end
  end

  defp check_plt(r_options(init_plts: []) = opts) do
    opts1 = init_opts_for_check(opts)
    report_check(opts1)
    plt_common(opts1, [], [])
  end

  defp check_plt(r_options(init_plts: plts) = opts) do
    check_plt_aux(plts, opts)
  end

  defp check_plt_aux([_] = plt, opts) do
    opts1 = r_options(opts, init_plts: plt)
    opts2 = init_opts_for_check(opts1)
    report_check(opts2)
    plt_common(opts2, [], [])
  end

  defp check_plt_aux([plt | plts], opts) do
    case (check_plt_aux([plt], opts)) do
      {{0, []}, modulesChanged, modulesAnalyzed} ->
        {{ret, warns}, moreModulesChanged,
           moreModulesAnalyzed} = check_plt_aux(plts, opts)
        {{ret, warns},
           :ordsets.union(modulesChanged, moreModulesChanged),
           :ordsets.union(modulesAnalyzed, moreModulesAnalyzed)}
      {{2, warns}, modulesChanged, modulesAnalyzed} ->
        {{_RET, moreWarns}, moreModulesChanged,
           moreModulesAnalyzed} = check_plt_aux(plts, opts)
        {{2, warns ++ moreWarns},
           :ordsets.union(modulesChanged, moreModulesChanged),
           :ordsets.union(modulesAnalyzed, moreModulesAnalyzed)}
    end
  end

  defp init_opts_for_check(opts) do
    initPlt = (case (r_options(opts, :init_plts)) do
                 [] ->
                   get_default_init_plt()
                 plt ->
                   plt
               end)
    [outputPlt] = initPlt
    r_options(opts, files: [],  files_rec: [], 
              analysis_type: :plt_check,  defines: [], 
              from: :byte_code,  init_plts: initPlt, 
              include_dirs: [],  output_plt: outputPlt, 
              use_contracts: true)
  end

  defp remove_from_plt(opts) do
    opts1 = init_opts_for_remove(opts)
    files = get_files_from_opts(opts1)
    plt_common(opts1, files, [])
  end

  defp init_opts_for_remove(opts) do
    case (r_options(opts, :output_plt) === :none) do
      true ->
        case (r_options(opts, :init_plts)) do
          [] ->
            r_options(opts, output_plt: get_default_output_plt(), 
                      init_plts: get_default_init_plt())
          [plt] ->
            r_options(opts, output_plt: plt)
          plts ->
            msg = :io_lib.format('Could not remove from multiple PLT files: ~ts\n', [format_plts(plts)])
            cl_error(msg)
        end
      false ->
        case (r_options(opts, :init_plts) === []) do
          true ->
            r_options(opts, init_plts: get_default_init_plt())
          false ->
            opts
        end
    end
  end

  defp plt_common(r_options(init_plts: [initPlt]) = opts, removeFiles,
            addFiles) do
    case (check_plt(opts, removeFiles, addFiles)) do
      :ok ->
        case (r_options(opts, :output_plt)) do
          :none ->
            :ok
          ^initPlt ->
            :ok
          outPlt ->
            {:ok, binary} = :file.read_file(initPlt)
            :ok = :file.write_file(outPlt, binary)
        end
        case (r_options(opts, :report_mode)) do
          :quiet ->
            :ok
          _ ->
            :io.put_chars(' yes\n')
        end
        {{0, []}, [], []}
      {:old_version, md5} ->
        pltInfo = r_plt_info(files: md5)
        files = (for {f, _} <- md5 do
                   f
                 end)
        enrich_with_modules_changed(do_analysis(files, opts,
                                                  :dialyzer_plt.new(), pltInfo),
                                      :undefined)
      {:differ, md5, diffMd5, modDeps} ->
        report_failed_plt_check(opts, diffMd5)
        {analFiles, removedMods,
           modDeps1} = expand_dependent_modules(md5, diffMd5,
                                                  modDeps)
        plt = clean_plt(initPlt, removedMods)
        changedOrRemovedMods = (for {_,
                                       changedOrRemovedMod} <- diffMd5 do
                                  changedOrRemovedMod
                                end)
        case (analFiles === []) do
          true ->
            :dialyzer_cplt.to_file(r_options(opts, :output_plt), plt,
                                     modDeps1,
                                     r_plt_info(files: md5, mod_deps: modDeps1))
            {{0, []}, changedOrRemovedMods, []}
          false ->
            enrich_with_modules_changed(do_analysis(analFiles, opts,
                                                      plt,
                                                      r_plt_info(files: md5,
                                                          mod_deps: modDeps1)),
                                          changedOrRemovedMods)
        end
      {:error, :no_such_file} ->
        msg = :io_lib.format('Could not find the PLT: ~ts~n~s',
                               [initPlt, default_plt_error_msg()])
        cl_error(msg)
      {:error, :not_valid} ->
        msg = :io_lib.format('The file: ~ts is not a valid PLT file~n~s',
                               [initPlt, default_plt_error_msg()])
        cl_error(msg)
      {:error, :read_error} ->
        msg = :io_lib.format('Could not read the PLT: ~ts~n~s',
                               [initPlt, default_plt_error_msg()])
        cl_error(msg)
      {:error, {:no_file_to_remove, f}} ->
        msg = :io_lib.format('Could not remove the file ~ts from the PLT: ~ts~n', [f, initPlt])
        cl_error(msg)
    end
  end

  defp enrich_with_modules_changed({{ret, warns}, analyzed}, changed) do
    {{ret, warns}, changed, analyzed}
  end

  defp default_plt_error_msg() do
    'Use the options:\n   --build_plt   to build a new PLT; or\n   --add_to_plt  to add to an existing PLT\n\nFor example, use a command like the following:\n   dialyzer --build_plt --apps erts kernel stdlib mnesia\nNote that building a PLT such as the above may take 20 mins or so\n\nIf you later need information about other applications, say crypto,\nyou can extend the PLT by the command:\n  dialyzer --add_to_plt --apps crypto\nFor applications that are not in Erlang/OTP use an absolute file name.\n'
  end

  defp check_plt(r_options(init_plts: [plt]) = opts, removeFiles,
            addFiles) do
    case (:dialyzer_cplt.check_plt(plt, removeFiles,
                                     addFiles)) do
      {:old_version, _MD5} = oldVersion ->
        report_old_version(opts)
        oldVersion
      {:differ, _MD5, _DiffMd5, _ModDeps} = differ ->
        differ
      :ok ->
        :ok
      {:error, _Reason} = error ->
        error
    end
  end

  defp report_check(r_options(report_mode: reportMode,
              init_plts: [initPlt])) do
    case (reportMode) do
      :quiet ->
        :ok
      _ ->
        :io.format('  Checking whether the PLT ~ts is up-to-date...', [initPlt])
    end
  end

  defp report_old_version(r_options(report_mode: reportMode,
              init_plts: [initPlt])) do
    case (reportMode) do
      :quiet ->
        :ok
      _ ->
        :io.put_chars(' no\n')
        :io.format('    (the PLT ~ts was built with an old version of Dialyzer)\n', [initPlt])
    end
  end

  defp report_failed_plt_check(r_options(analysis_type: analType,
              report_mode: reportMode),
            diffMd5) do
    case (analType === :plt_check) do
      true ->
        case (reportMode) do
          :quiet ->
            :ok
          :normal ->
            :io.format(' no\n', [])
          :verbose ->
            report_md5_diff(diffMd5)
        end
      false ->
        :ok
    end
  end

  defp report_analysis_start(r_options(analysis_type: type, report_mode: reportMode,
              init_plts: initPlts, output_plt: outputPlt)) do
    case (reportMode) do
      :quiet ->
        :ok
      _ ->
        :io.format('  ')
        case (type) do
          :plt_add ->
            [initPlt] = initPlts
            case (initPlt === outputPlt) do
              true ->
                :io.format('Adding information to ~ts...', [outputPlt])
              false ->
                :io.format('Adding information from ~ts to ~ts...', [initPlt, outputPlt])
            end
          :plt_build ->
            :io.format('Creating PLT ~ts ...', [outputPlt])
          :plt_check ->
            :io.format('Rebuilding the information in ~ts...', [outputPlt])
          :plt_remove ->
            [initPlt] = initPlts
            case (initPlt === outputPlt) do
              true ->
                :io.format('Removing information from ~ts...', [outputPlt])
              false ->
                :io.format('Removing information from ~ts to ~ts...', [initPlt, outputPlt])
            end
          :succ_typings ->
            :io.format('Proceeding with analysis...')
        end
    end
  end

  defp report_elapsed_time(t1, t2, r_options(report_mode: reportMode)) do
    case (reportMode) do
      :quiet ->
        :ok
      _ ->
        elapsedTime = t2 - t1
        mins = div(elapsedTime, 60000)
        secs = rem(elapsedTime, 60000) / 1000
        :io.format(' done in ~wm~.2fs\n', [mins, secs])
    end
  end

  defp report_md5_diff(list) do
    :io.format('    The PLT information is not up to date:\n', [])
    case (for {:removed, mod} <- list do
            mod
          end) do
      [] ->
        :ok
      removedMods ->
        :io.format('    Removed modules: ~p\n', [removedMods])
    end
    case (for {:differ, mod} <- list do
            mod
          end) do
      [] ->
        :ok
      changedMods ->
        :io.format('    Changed modules: ~p\n', [changedMods])
    end
  end

  defp get_default_init_plt() do
    [:dialyzer_cplt.get_default_cplt_filename()]
  end

  defp get_default_output_plt() do
    :dialyzer_cplt.get_default_cplt_filename()
  end

  defp format_plts([plt]) do
    plt
  end

  defp format_plts([plt | plts]) do
    plt ++ ', ' ++ format_plts(plts)
  end

  defp do_analysis(options) do
    files = get_files_from_opts(options)
    case (r_options(options, :init_plts)) do
      [] ->
        do_analysis(files, options, :dialyzer_plt.new(), :none)
      pltFiles ->
        plts = (for f <- pltFiles do
                  :dialyzer_cplt.from_file(f)
                end)
        plt = :dialyzer_cplt.merge_plts_or_report_conflicts(pltFiles,
                                                              plts)
        do_analysis(files, options, plt, :none)
    end
  end

  defp do_analysis(files, options, plt, pltInfo) do
    assert_writable(r_options(options, :output_plt))
    report_analysis_start(options)
    state0 = new_state()
    state1 = init_output(state0, options)
    state2 = r_cl_state(state1, legal_warnings: r_options(options, :legal_warnings), 
                         output_plt: r_options(options, :output_plt), 
                         plt_info: pltInfo, 
                         erlang_mode: r_options(options, :erlang_mode), 
                         report_mode: r_options(options, :report_mode))
    analysisType = convert_analysis_type(r_options(options, :analysis_type),
                                           r_options(options, :get_warnings))
    initAnalysis = r_analysis(type: analysisType,
                       defines: r_options(options, :defines),
                       include_dirs: r_options(options, :include_dirs), files: files,
                       start_from: r_options(options, :from),
                       timing: r_options(options, :timing), plt: plt,
                       use_contracts: r_options(options, :use_contracts),
                       callgraph_file: r_options(options, :callgraph_file),
                       mod_deps_file: r_options(options, :mod_deps_file),
                       solvers: r_options(options, :solvers))
    state3 = start_analysis(state2, initAnalysis)
    {t1, _} = :erlang.statistics(:wall_clock)
    retAndWarns = cl_loop(state3)
    {t2, _} = :erlang.statistics(:wall_clock)
    report_elapsed_time(t1, t2, options)
    {retAndWarns,
       :lists.usort(for f <- files do
                      path_to_mod(f)
                    end)}
  end

  defp convert_analysis_type(:succ_typings, _) do
    :succ_typings
  end

  defp convert_analysis_type(_, true) do
    :succ_typings
  end

  defp convert_analysis_type(_, false) do
    :plt_build
  end

  defp assert_writable(:none) do
    :ok
  end

  defp assert_writable(pltFile) do
    case (check_if_writable(pltFile)) do
      true ->
        :ok
      false ->
        msg = :io_lib.format('    The PLT file ~ts is not writable', [pltFile])
        cl_error(msg)
    end
  end

  defp check_if_writable(pltFile) do
    case (:filelib.is_regular(pltFile)) do
      true ->
        is_writable_file_or_dir(pltFile)
      false ->
        case (:filelib.is_dir(pltFile)) do
          true ->
            false
          false ->
            dirName = :filename.dirname(pltFile)
            case (:filelib.is_dir(dirName)) do
              false ->
                case (:filelib.ensure_dir(pltFile)) do
                  :ok ->
                    true
                  {:error, _} ->
                    false
                end
              true ->
                is_writable_file_or_dir(dirName)
            end
        end
    end
  end

  defp is_writable_file_or_dir(pltFile) do
    case (:file.read_file_info(pltFile)) do
      {:ok, r_file_info(access: a)} ->
        a === :write or a === :read_write
      {:error, _} ->
        false
    end
  end

  defp clean_plt(pltFile, removedMods) do
    plt = :dialyzer_cplt.from_file(pltFile)
    :sets.fold(fn m, accPlt ->
                    :dialyzer_plt.delete_module(accPlt, m)
               end,
                 plt, removedMods)
  end

  defp expand_dependent_modules(md5, diffMd5, modDeps) do
    changedMods = :sets.from_list(for {:differ,
                                         m} <- diffMd5 do
                                    m
                                  end,
                                    [{:version, 2}])
    removedMods = :sets.from_list(for {:removed,
                                         m} <- diffMd5 do
                                    m
                                  end,
                                    [{:version, 2}])
    bigSet = :sets.union(changedMods, removedMods)
    bigList = :sets.to_list(bigSet)
    expandedSet = expand_dependent_modules_1(bigList,
                                               bigSet, modDeps)
    newModDeps = :dialyzer_callgraph.strip_module_deps(modDeps,
                                                         bigSet)
    analyzeMods = :sets.subtract(expandedSet, removedMods)
    filterFun = fn file ->
                     mod = path_to_mod(file)
                     :sets.is_element(mod, analyzeMods)
                end
    {for {f, _} <- md5, filterFun.(f) do
       f
     end,
       bigSet, newModDeps}
  end

  defp expand_dependent_modules_1([mod | mods], included, modDeps) do
    case (:dict.find(mod, modDeps)) do
      {:ok, deps} ->
        newDeps = :sets.subtract(:sets.from_list(deps),
                                   included)
        case (:sets.size(newDeps) === 0) do
          true ->
            expand_dependent_modules_1(mods, included, modDeps)
          false ->
            newIncluded = :sets.union(included, newDeps)
            expand_dependent_modules_1(:sets.to_list(newDeps) ++ mods,
                                         newIncluded, modDeps)
        end
      :error ->
        expand_dependent_modules_1(mods, included, modDeps)
    end
  end

  defp expand_dependent_modules_1([], included, _ModDeps) do
    included
  end

  defp path_to_mod(file) do
    :erlang.list_to_atom(:filename.basename(file, '.beam'))
  end

  defp new_state() do
    r_cl_state()
  end

  defp init_output(state0,
            r_options(output_file: outFile, output_format: outFormat,
                filename_opt: fOpt, indent_opt: iOpt,
                error_location: eOpt)) do
    state = r_cl_state(state0, output_format: outFormat, 
                        filename_opt: fOpt,  indent_opt: iOpt, 
                        error_location: eOpt)
    case (outFile === :none) do
      true ->
        state
      false ->
        case (:file.open(outFile, [:write])) do
          {:ok, file} ->
            :ok = :io.setopts(file, [{:encoding, :unicode}])
            r_cl_state(state, output: file)
          {:error, reason} ->
            msg = :io_lib.format('Could not open output file ~tp, Reason: ~p\n', [outFile, reason])
            cl_error(state, :lists.flatten(msg))
        end
    end
  end

  defp maybe_close_output_file(state) do
    case (r_cl_state(state, :output)) do
      :standard_io ->
        :ok
      file ->
        :ok = :file.close(file)
    end
  end

  defp cl_loop(state) do
    cl_loop(state, [])
  end

  defp cl_loop(state, logCache) do
    backendPid = r_cl_state(state, :backend_pid)
    receive do
      {^backendPid, :log, logMsg} ->
        cl_loop(state, :lists.sublist([logMsg | logCache], 10))
      {^backendPid, :warnings, warnings} ->
        newState = store_warnings(state, warnings)
        cl_loop(newState, logCache)
      {^backendPid, :cserver, codeServer, _Plt} ->
        newState = r_cl_state(state, code_server: codeServer)
        cl_loop(newState, logCache)
      {^backendPid, :done, newPlt, _NewDocPlt} ->
        return_value(state, newPlt)
      {^backendPid, :ext_calls, extCalls} ->
        cl_loop(r_cl_state(state, external_calls: extCalls), logCache)
      {^backendPid, :ext_types, extTypes} ->
        cl_loop(r_cl_state(state, external_types: extTypes), logCache)
      {^backendPid, :mod_deps, modDeps} ->
        newState = r_cl_state(state, mod_deps: modDeps)
        cl_loop(newState, logCache)
      {:EXIT, ^backendPid, {:error, reason}} ->
        msg = failed_anal_msg(reason, logCache)
        cl_error(state, msg)
      {:EXIT, ^backendPid, reason} when reason !== :normal ->
        msg = failed_anal_msg(:io_lib.format('~p', [reason]),
                                logCache)
        cl_error(state, msg)
      _Other ->
        cl_loop(state, logCache)
    end
  end

  defp failed_anal_msg(reason, logCache) do
    msg = 'Analysis failed with error:\n' ++ :lists.flatten(reason) ++ '\n'
    case (logCache === []) do
      true ->
        msg
      false ->
        msg ++ 'Last messages in the log cache:\n  ' ++ format_log_cache(logCache)
    end
  end

  defp format_log_cache(logCache) do
    str = :lists.append(:lists.reverse(logCache))
    :lists.join('\n  ', :string.lexemes(str, '\n'))
  end

  defp store_warnings(r_cl_state(stored_warnings: storedWarnings) = st,
            warnings) do
    r_cl_state(st, stored_warnings: storedWarnings ++ warnings)
  end

  defp cl_error(msg) do
    throw({:dialyzer_error, :lists.flatten(msg)})
  end

  defp cl_error(state, msg) do
    case (r_cl_state(state, :output)) do
      :standard_io ->
        :ok
      outfile ->
        :io.format(outfile, '\n~ts\n', [msg])
    end
    maybe_close_output_file(state)
    throw({:dialyzer_error, :lists.flatten(msg)})
  end

  defp return_value(r_cl_state(code_server: codeServer,
              erlang_mode: erlangMode, mod_deps: modDeps,
              output_plt: outputPlt, plt_info: pltInfo,
              error_location: eOpt,
              stored_warnings: storedWarnings) = state,
            plt) do
    unknownWarnings = unknown_warnings(state)
    case (codeServer === :none) do
      true ->
        :ok
      false ->
        :dialyzer_codeserver.delete(codeServer)
    end
    case (outputPlt === :none) do
      true ->
        :dialyzer_plt.delete(plt)
      false ->
        :dialyzer_cplt.to_file(outputPlt, plt, modDeps, pltInfo)
    end
    retValue = (case (storedWarnings === [] and unknownWarnings === []) do
                  true ->
                    0
                  false ->
                    2
                end)
    case (erlangMode) do
      false ->
        fns = [&print_warnings/1, &print_ext_calls/1,
                                      &print_ext_types/1,
                                          &maybe_close_output_file/1]
        :lists.foreach(fn f ->
                            f.(state)
                       end,
                         fns)
        {retValue, []}
      true ->
        resultingWarnings = process_warnings(storedWarnings ++ unknownWarnings)
        {retValue, set_warning_id(resultingWarnings, eOpt)}
    end
  end

  defp unknown_warnings(state) do
    for {_M,
           warning} <- unknown_warnings_by_module(state) do
      warning
    end
  end

  defp unknown_warnings_by_module(r_cl_state(legal_warnings: legalWarnings) = state) do
    case (:ordsets.is_element(:warn_unknown,
                                legalWarnings)) do
      true ->
        :lists.sort(unknown_functions(state)) ++ :lists.sort(unknown_types(state))
      false ->
        []
    end
  end

  defp unknown_functions(r_cl_state(external_calls: calls,
              code_server: codeServer)) do
    for {mFA,
           warningInfo = {_, _, {mod, _, _} = warnMFA}} <- calls,
          not
          :dialyzer_codeserver.is_member_meta_info(warnMFA,
                                                     codeServer) do
      {mod,
         {:warn_unknown, warningInfo, {:unknown_function, mFA}}}
    end
  end

  defp unknown_types(r_cl_state(external_types: types)) do
    for {mFA, warningInfo = {_, _, {mod, _, _}}} <- types do
      {mod,
         {:warn_unknown, warningInfo, {:unknown_type, mFA}}}
    end
  end

  defp set_warning_id(warnings, eOpt) do
    :lists.map(fn {tag, {file, location, _MorMFA}, msg} ->
                    {tag, {file, set_location(location, eOpt)}, msg}
               end,
                 warnings)
  end

  defp set_location({line, _}, :line) do
    line
  end

  defp set_location(location, _EOpt) do
    location
  end

  defp print_ext_calls(r_cl_state(report_mode: :quiet)) do
    :ok
  end

  defp print_ext_calls(r_cl_state(output: output, external_calls: calls,
              stored_warnings: warnings, output_format: format)) do
    case (calls === []) do
      true ->
        :ok
      false ->
        case (warnings === []) do
          true ->
            :io.nl(output)
          false ->
            :ok
        end
        calls1 = limit_unknown(calls)
        case (format) do
          :formatted ->
            :io.put_chars(output, 'Unknown functions:\n')
            do_print_ext_calls(output, calls1, '  ')
          :raw ->
            :io.put_chars(output, '%% Unknown functions:\n')
            do_print_ext_calls(output, calls1, '%%  ')
        end
    end
  end

  defp do_print_ext_calls(output,
            [{{m, f, a}, {file, location, _FromMFA}} | t],
            before) do
    :io.format(output, '~s~tp:~tp/~p (~ts)\n',
                 [before, m, f, a, file_pos(file, location)])
    do_print_ext_calls(output, t, before)
  end

  defp do_print_ext_calls(_, [], _) do
    :ok
  end

  defp print_ext_types(r_cl_state(report_mode: :quiet)) do
    :ok
  end

  defp print_ext_types(r_cl_state(output: output, external_calls: calls,
              external_types: types, stored_warnings: warnings,
              output_format: format)) do
    case (types === []) do
      true ->
        :ok
      false ->
        case (warnings === [] and calls === []) do
          true ->
            :io.nl(output)
          false ->
            :ok
        end
        types1 = limit_unknown(types)
        case (format) do
          :formatted ->
            :io.put_chars(output, 'Unknown types:\n')
            do_print_ext_types(output, types1, '  ')
          :raw ->
            :io.put_chars(output, '%% Unknown types:\n')
            do_print_ext_types(output, types1, '%%  ')
        end
    end
  end

  defp do_print_ext_types(output, [{{m, f, a}, {file, location, _}} | t],
            before) do
    :io.format(output, '~s~tp:~tp/~p (~ts)\n',
                 [before, m, f, a, file_pos(file, location)])
    do_print_ext_types(output, t, before)
  end

  defp do_print_ext_types(_, [], _) do
    :ok
  end

  defp file_pos(file, 0) do
    :io_lib.format('~ts', [file])
  end

  defp file_pos(file, pos) do
    :io_lib.format('~ts:~s', [file, pos(pos)])
  end

  defp pos({line, col}) do
    :io_lib.format('~w:~w', [line, col])
  end

  defp pos(line) do
    :io_lib.format('~w', [line])
  end

  defp limit_unknown(unknowns) do
    l = (for {mFA, {file, line, fromMFA}} <- unknowns do
           {{mFA, file}, {fromMFA, line}}
         end)
    for {{mFA, file},
           [{fromMFA, line} | _]} <- :dialyzer_utils.family(l) do
      {mFA, {file, line, fromMFA}}
    end
  end

  defp print_warnings(r_cl_state(stored_warnings: [])) do
    :ok
  end

  defp print_warnings(r_cl_state(output: output, output_format: format,
              filename_opt: fOpt, indent_opt: iOpt,
              error_location: eOpt, stored_warnings: warnings)) do
    prWarnings = process_warnings(warnings)
    case (prWarnings) do
      [] ->
        :ok
      [_ | _] ->
        prWarningsId = set_warning_id(prWarnings, eOpt)
        s = (case (format) do
               :formatted ->
                 opts = [{:filename_opt, fOpt}, {:indent_opt, iOpt},
                                                    {:error_location, eOpt}]
                 for w <- prWarningsId do
                   :dialyzer.format_warning(w, opts)
                 end
               :raw ->
                 for w <- set_warning_id(prWarningsId, eOpt) do
                   :io_lib.format('~tp. \n', [w])
                 end
             end)
        :io.format(output, '\n~ts', [s])
    end
  end

  defp process_warnings(warnings) do
    warnings1 = :lists.keysort(3, warnings)
    warnings2 = :lists.keysort(2, warnings1)
    remove_duplicate_warnings(warnings2, [])
  end

  defp remove_duplicate_warnings([duplicate, duplicate | left], acc) do
    remove_duplicate_warnings([duplicate | left], acc)
  end

  defp remove_duplicate_warnings([notDuplicate | left], acc) do
    remove_duplicate_warnings(left, [notDuplicate | acc])
  end

  defp remove_duplicate_warnings([], acc) do
    :lists.reverse(acc)
  end

  defp get_files_from_opts(options) do
    from = r_options(options, :from)
    files1 = add_files(r_options(options, :files), from)
    files2 = add_files_rec(r_options(options, :files_rec), from)
    :ordsets.union(files1, files2)
  end

  defp add_files_rec(files, from) do
    add_files(files, from, true)
  end

  defp add_files(files, from) do
    add_files(files, from, false)
  end

  defp add_files(files, from, rec) do
    files1 = (for f <- files do
                :filename.absname(f)
              end)
    files2 = :ordsets.from_list(files1)
    dirs = :ordsets.filter(fn x ->
                                :filelib.is_dir(x)
                           end,
                             files2)
    files3 = :ordsets.subtract(files2, dirs)
    extension = (case (from) do
                   :byte_code ->
                     '.beam'
                   :src_code ->
                     '.erl'
                 end)
    fun = add_file_fun(extension)
    :lists.foldl(fn dir, acc ->
                      :filelib.fold_files(dir, extension, rec, fun, acc)
                 end,
                   files3, dirs)
  end

  defp add_file_fun(extension) do
    fn file, accFiles ->
         case (:filename.extension(file) === extension) do
           true ->
             absName = :filename.absname(file)
             :ordsets.add_element(absName, accFiles)
           false ->
             accFiles
         end
    end
  end

  defp start_analysis(state, analysis) do
    self = self()
    legalWarnings = r_cl_state(state, :legal_warnings)
    fun = fn () ->
               :dialyzer_analysis_callgraph.start(self, legalWarnings,
                                                    analysis)
          end
    backendPid = spawn_link(fun)
    r_cl_state(state, backend_pid: backendPid)
  end

end