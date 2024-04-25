defmodule :m_dialyzer_incremental do
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
  Record.defrecord(:r_incremental_state, :incremental_state, backend_pid: :undefined,
                                             code_server: :none,
                                             erlang_mode: false,
                                             external_calls: [],
                                             external_types: [],
                                             legal_warnings: :ordsets.new(),
                                             mod_deps: :dict.new(),
                                             output: :standard_io,
                                             output_format: :formatted,
                                             filename_opt: :basename,
                                             error_location: :column,
                                             indent_opt: true,
                                             output_plt: :none, plt_info: :none,
                                             report_mode: :normal,
                                             return_status: 0,
                                             warning_modules: [],
                                             stored_warnings: [])
  Record.defrecord(:r_incrementality_metrics, :incrementality_metrics, total_modules: :undefined,
                                                  analysed_modules: :undefined,
                                                  reason: :undefined)
  def start(opts) do
    {{ret, warns},
       _ModulesAnalyzed} = start_report_modules_analyzed(opts)
    {ret, warns}
  end

  def start_report_modules_analyzed(r_options(analysis_type: :incremental) = options) do
    {{ret, warn}, _Changed,
       analyzed} = start_report_modules_changed_and_analyzed(options)
    {{ret, warn}, analyzed}
  end

  def start_report_modules_changed_and_analyzed(r_options(analysis_type: :incremental) = options) do
    opts1 = init_opts_for_incremental(options)
    assert_metrics_file_valid(opts1)
    r_options(init_plts: [initPlt],
        legal_warnings: legalWarnings) = opts1
    files = get_files_from_opts(opts1)
    case (:dialyzer_iplt.check_incremental_plt(initPlt,
                                                 opts1, files)) do
      {:ok, r_iplt_info(files: md5, warning_map: :none),
         moduleToPathLookup} ->
        report_no_stored_warnings(opts1, md5)
        pltInfo = r_iplt_info(files: md5, legal_warnings: legalWarnings)
        write_module_to_path_lookup(opts1, moduleToPathLookup)
        enrich_with_modules_changed(do_analysis(:maps.values(moduleToPathLookup),
                                                  opts1, :dialyzer_plt.new(),
                                                  pltInfo),
                                      [])
      {:ok, r_iplt_info(warning_map: warningMap, files: md5),
         moduleToPathLookup} ->
        report_stored_warnings_no_changes(opts1, md5)
        write_module_to_path_lookup(opts1, moduleToPathLookup)
        enrich_with_modules_changed(return_existing_errors(opts1,
                                                             warningMap),
                                      [])
      {:old_version, md5, moduleToPathLookup} ->
        report_different_plt_version(opts1, md5)
        pltInfo = r_iplt_info(files: md5, legal_warnings: legalWarnings)
        write_module_to_path_lookup(opts1, moduleToPathLookup)
        enrich_with_modules_changed(do_analysis(:maps.values(moduleToPathLookup),
                                                  opts1, :dialyzer_plt.new(),
                                                  pltInfo),
                                      :undefined)
      {:new_file, md5, moduleToPathLookup} ->
        report_new_plt_file(opts1, initPlt, md5)
        pltInfo = r_iplt_info(files: md5, legal_warnings: legalWarnings)
        write_module_to_path_lookup(opts1, moduleToPathLookup)
        enrich_with_modules_changed(do_analysis(:maps.values(moduleToPathLookup),
                                                  opts1, :dialyzer_plt.new(),
                                                  pltInfo),
                                      :undefined)
      {:differ, md5, _DiffMd5, _ModDeps, :none,
         moduleToPathLookup} ->
        report_no_stored_warnings(opts1, md5)
        pltInfo = r_iplt_info(files: md5, legal_warnings: legalWarnings)
        allFiles = :maps.values(moduleToPathLookup)
        write_module_to_path_lookup(opts1, moduleToPathLookup)
        enrich_with_modules_changed(do_analysis(allFiles, opts1,
                                                  :dialyzer_plt.new(), pltInfo),
                                      :undefined)
      {:differ, md5, diffMd5, modDeps, warningMap,
         moduleToPathLookup} ->
        report_incremental_analysis_needed(opts1, diffMd5)
        {analFiles, modsToRemove,
           modDepsInRemainingPlt} = expand_dependent_modules(md5,
                                                               diffMd5, modDeps,
                                                               moduleToPathLookup)
        warningsInRemainingPlt = :sets.fold(fn mod, acc ->
                                                 :maps.remove(mod, acc)
                                            end,
                                              warningMap, modsToRemove)
        plt = clean_plt(initPlt, modsToRemove)
        pltInfo = r_iplt_info(files: md5, mod_deps: modDepsInRemainingPlt,
                      warning_map: warningsInRemainingPlt,
                      legal_warnings: legalWarnings)
        changedOrRemovedMods = (for {_,
                                       changedOrRemovedMod} <- diffMd5 do
                                  changedOrRemovedMod
                                end)
        case (analFiles === []) do
          true ->
            report_stored_warnings_only_safe_removals(opts1, md5,
                                                        diffMd5)
            :dialyzer_iplt.to_file(r_options(opts1, :output_plt), plt,
                                     modDepsInRemainingPlt, pltInfo)
            write_module_to_path_lookup(opts1, moduleToPathLookup)
            enrich_with_modules_changed(return_existing_errors(opts1,
                                                                 warningsInRemainingPlt),
                                          changedOrRemovedMods)
          false ->
            report_degree_of_incrementality(opts1, md5, diffMd5,
                                              analFiles)
            write_module_to_path_lookup(opts1, moduleToPathLookup)
            enrich_with_modules_changed(do_analysis(analFiles,
                                                      opts1, plt, pltInfo),
                                          changedOrRemovedMods)
        end
      {:legal_warnings_changed, md5, moduleToPathLookup} ->
        report_change_in_legal_warnings(opts1, md5)
        pltInfo = r_iplt_info(files: md5, legal_warnings: legalWarnings)
        allFiles = :maps.values(moduleToPathLookup)
        write_module_to_path_lookup(opts1, moduleToPathLookup)
        enrich_with_modules_changed(do_analysis(allFiles, opts1,
                                                  :dialyzer_plt.new(), pltInfo),
                                      :undefined)
      {:error, :not_valid} ->
        msg = :io_lib.format('The file: ~ts is not a valid PLT file\n~s',
                               [initPlt, default_plt_error_msg()])
        cl_error(msg)
      {:error, :read_error} ->
        msg = :io_lib.format('Could not read the PLT: ~ts\n~s',
                               [initPlt, default_plt_error_msg()])
        cl_error(msg)
    end
  end

  defp enrich_with_modules_changed({{ret, warns}, analyzed}, changed) do
    {{ret, warns}, changed, analyzed}
  end

  defp default_plt_error_msg() do
    'Remove the broken PLT file or point to the correct location.\n'
  end

  defp init_opts_for_incremental(opts) do
    initPlt = (case (r_options(opts, :init_plts)) do
                 [] ->
                   :dialyzer_iplt.get_default_iplt_filename()
                 [plt] ->
                   plt
                 plts ->
                   msg = :io_lib.format('Incremental mode does not support multiple PLT files (~ts)\n', [format_plts(plts)])
                   cl_error(msg)
               end)
    outputPlt = (case (r_options(opts, :output_plt)) do
                   :none ->
                     initPlt
                   explicitlySetOutputPlt ->
                     explicitlySetOutputPlt
                 end)
    r_options(opts, analysis_type: :incremental,  defines: [], 
              from: :byte_code,  init_plts: [initPlt], 
              include_dirs: [],  output_plt: outputPlt, 
              use_contracts: true,  get_warnings: true)
  end

  defp assert_metrics_file_valid(r_options(metrics_file: :none)) do
    :ok
  end

  defp assert_metrics_file_valid(r_options(metrics_file: metricsFile)) do
    case (check_if_writable(metricsFile)) do
      true ->
        :ok
      false ->
        msg = :io_lib.format('    The metrics file ~ts is not writable', [metricsFile])
        cl_error(msg)
    end
  end

  defp write_metrics_file(r_options(metrics_file: :none), _Format, _Args) do
    :ok
  end

  defp write_metrics_file(r_options(metrics_file: metricsFile), format, args) do
    case (:file.write_file(metricsFile,
                             :io_lib.fwrite(format, args))) do
      :ok ->
        :ok
      {:error, reason} ->
        msg = :io_lib.format('Could not write metrics file ~ts: ~w\n', [metricsFile, reason])
        throw({:dialyzer_error, msg})
    end
  end

  defp write_metrics_file(opts,
            r_incrementality_metrics(total_modules: numTotalModules,
                analysed_modules: numAnalysedModules,
                reason: reason)) do
    reasonDescription = (case (reason) do
                           :no_stored_warnings_in_plt ->
                             'no_stored_warnings_in_plt'
                           :plt_built_with_different_version ->
                             'plt_built_with_different_version'
                           :new_plt_file ->
                             'new_plt_file'
                           :warnings_changed ->
                             'warnings_changed'
                           {:incremental_changes, numChangedModules} ->
                             :io_lib.format('incremental_changes\nchanged_or_removed_modules: ~B', [numChangedModules])
                         end)
    write_metrics_file(opts, 'total_modules: ~B\nanalysed_modules: ~B\nreason: ~s\n',
                         [numTotalModules, numAnalysedModules,
                                               reasonDescription])
  end

  defp report_new_plt_file(r_options(report_mode: reportMode) = opts, initPlt,
            md5) do
    numTotalModules = length(md5)
    metrics = r_incrementality_metrics(total_modules: numTotalModules,
                  analysed_modules: numTotalModules,
                  reason: :new_plt_file)
    case (reportMode) do
      :quiet ->
        :ok
      :normal ->
        :ok
      :verbose ->
        :io.format('PLT does not yet exist at ~s, so an analysis must be run for ~w modules to populate it\n', [initPlt, numTotalModules])
    end
    write_metrics_file(opts, metrics)
  end

  defp report_different_plt_version(r_options(report_mode: reportMode) = opts, md5) do
    numTotalModules = length(md5)
    metrics = r_incrementality_metrics(total_modules: numTotalModules,
                  analysed_modules: numTotalModules,
                  reason: :plt_built_with_different_version)
    case (reportMode) do
      :quiet ->
        :ok
      :normal ->
        :ok
      :verbose ->
        :io.format('PLT is for a different Dialyzer version, so an analysis must be run for ~w modules to rebuild it\n', [numTotalModules])
    end
    write_metrics_file(opts, metrics)
  end

  defp report_stored_warnings_no_changes(r_options(report_mode: reportMode) = opts, md5) do
    numTotalModules = length(md5)
    metrics = r_incrementality_metrics(total_modules: numTotalModules,
                  analysed_modules: 0, reason: {:incremental_changes, 0})
    case (reportMode) do
      :quiet ->
        :ok
      :normal ->
        :ok
      :verbose ->
        :io.format('PLT has fully cached the request, so no additional analysis is needed\n', [])
    end
    write_metrics_file(opts, metrics)
  end

  defp report_stored_warnings_only_safe_removals(r_options(report_mode: reportMode) = opts, md5,
            removed) do
    numTotalModules = length(md5)
    numRemovedModuled = length(removed)
    metrics = r_incrementality_metrics(total_modules: numTotalModules,
                  analysed_modules: 0,
                  reason: {:incremental_changes, numRemovedModuled})
    case (reportMode) do
      :quiet ->
        :ok
      :normal ->
        :ok
      :verbose ->
        :io.format('PLT has fully cached the request because nothing depended on the file removed, so no additional analysis is needed\n', [])
    end
    write_metrics_file(opts, metrics)
  end

  defp report_no_stored_warnings(r_options(report_mode: reportMode) = opts, md5) do
    numTotalModules = length(md5)
    metrics = r_incrementality_metrics(total_modules: numTotalModules,
                  analysed_modules: numTotalModules,
                  reason: :no_stored_warnings_in_plt)
    case (reportMode) do
      :quiet ->
        :ok
      :normal ->
        :ok
      :verbose ->
        :io.format('PLT does not contain cached warnings, so an analysis must be run for ~w modules to rebuild it\n', [length(md5)])
    end
    write_metrics_file(opts, metrics)
  end

  defp report_incremental_analysis_needed(r_options(report_mode: reportMode), diffMd5) do
    case (reportMode) do
      :quiet ->
        :ok
      :normal ->
        :io.format('There have been changes to analyze\n', [])
      :verbose ->
        report_md5_diff(diffMd5)
    end
  end

  defp report_degree_of_incrementality(r_options(report_mode: reportMode) = opts, md5,
            changedOrRemovedFiles, filesThatNeedAnalysis) do
    numTotalModules = length(md5)
    numChangedOrRemovedModules = length(changedOrRemovedFiles)
    numAnalysedModules = length(filesThatNeedAnalysis)
    metrics = r_incrementality_metrics(total_modules: numTotalModules,
                  analysed_modules: numAnalysedModules,
                  reason: {:incremental_changes,
                             numChangedOrRemovedModules})
    reportFun = fn () ->
                     :io.format('    Of the ~B files being tracked, ~B have been changed or removed, resulting in ~B requiring analysis because they depend on those changes\n',
                                  [numTotalModules, numChangedOrRemovedModules,
                                                        numAnalysedModules])
                end
    case (reportMode) do
      :quiet ->
        :ok
      :normal ->
        reportFun.()
      :verbose ->
        reportFun.()
        :io.format('    Modules which will be analysed: ~p\n',
                     [for p <- filesThatNeedAnalysis do
                        path_to_mod(p)
                      end])
    end
    write_metrics_file(opts, metrics)
  end

  defp report_change_in_legal_warnings(r_options(report_mode: reportMode) = opts, md5) do
    numTotalModules = length(md5)
    metrics = r_incrementality_metrics(total_modules: numTotalModules,
                  analysed_modules: numTotalModules,
                  reason: :warnings_changed)
    reportFun = fn () ->
                     :io.format('PLT was built for a different set of enabled warnings, so an analysis must be run for ~w modules to rebuild it\n', [numTotalModules])
                end
    case (reportMode) do
      :quiet ->
        :ok
      :normal ->
        reportFun.()
      :verbose ->
        reportFun.()
    end
    write_metrics_file(opts, metrics)
  end

  defp report_analysis_start(r_options(report_mode: :quiet)) do
    :ok
  end

  defp report_analysis_start(_) do
    :io.format('Proceeding with incremental analysis...')
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

  defp format_plts([plt]) do
    plt
  end

  defp format_plts([plt | plts]) do
    plt ++ ', ' ++ format_plts(plts)
  end

  defp do_analysis(files, options, plt, pltInfo) do
    assert_writable(r_options(options, :output_plt))
    report_analysis_start(options)
    state1 = init_output(options)
    state2 = r_incremental_state(state1, legal_warnings: r_options(options, :legal_warnings), 
                         output_plt: r_options(options, :output_plt), 
                         plt_info: pltInfo, 
                         erlang_mode: r_options(options, :erlang_mode), 
                         report_mode: r_options(options, :report_mode), 
                         warning_modules: get_warning_modules_from_opts(options))
    initAnalysis = r_analysis(type: :succ_typings,
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

  defp is_writable_file_or_dir(file) do
    case (:file.read_file_info(file)) do
      {:ok, r_file_info(access: a)} ->
        a === :write or a === :read_write
      {:error, _} ->
        false
    end
  end

  defp clean_plt(pltFile, removedMods) do
    plt = :dialyzer_iplt.from_file(pltFile)
    :sets.fold(fn m, accPlt ->
                    :dialyzer_plt.delete_module(accPlt, m)
               end,
                 plt, removedMods)
  end

  defp expand_dependent_modules(_Md5, diffMd5, modDeps, moduleToPathLookup) do
    changedMods = :sets.from_list(for {:differ,
                                         m} <- diffMd5 do
                                    m
                                  end)
    removedMods = :sets.from_list(for {:removed,
                                         m} <- diffMd5 do
                                    m
                                  end)
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
    {for f <- :maps.values(moduleToPathLookup),
           filterFun.(f) do
       f
     end,
       expandedSet, newModDeps}
  end

  defp expand_dependent_modules_1([mod | mods], included, modDeps) do
    case (:dict.find(mod, modDeps)) do
      {:ok, deps} ->
        newDeps = :sets.subtract(:sets.from_list(deps),
                                   included)
        case (:sets.size(newDeps)) do
          0 ->
            expand_dependent_modules_1(mods, included, modDeps)
          _ ->
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

  defp init_output(r_options(output_file: outFile, output_plt: outPlt,
              output_format: outFormat, filename_opt: fOpt,
              indent_opt: iOpt, error_location: eOpt) = opts) do
    state = r_incremental_state(output_format: outFormat, output_plt: outPlt,
                filename_opt: fOpt, indent_opt: iOpt,
                error_location: eOpt,
                warning_modules: get_warning_modules_from_opts(opts))
    case (outFile === :none) do
      true ->
        state
      false ->
        case (:file.open(outFile, [:write])) do
          {:ok, file} ->
            :ok = :io.setopts(file, [{:encoding, :unicode}])
            r_incremental_state(state, output: file)
          {:error, reason} ->
            msg = :io_lib.format('Could not open output file ~tp, Reason: ~p\n', [outFile, reason])
            cl_error(state, :lists.flatten(msg))
        end
    end
  end

  defp maybe_close_output_file(state, outputPltInUse) do
    case (r_incremental_state(state, :output)) do
      :standard_io ->
        :ok
      file when outputPltInUse ->
        :ok = :file.close(file)
      _File ->
        :ok
    end
  end

  defp cl_loop(state) do
    cl_loop(state, [])
  end

  defp cl_loop(state, logCache) do
    backendPid = r_incremental_state(state, :backend_pid)
    receive do
      {^backendPid, :log, logMsg} ->
        cl_loop(state, :lists.sublist([logMsg | logCache], 10))
      {^backendPid, :warnings, warnings} ->
        newState = store_warnings(state, warnings)
        cl_loop(newState, logCache)
      {^backendPid, :cserver, codeServer, _Plt} ->
        newState = r_incremental_state(state, code_server: codeServer)
        cl_loop(newState, logCache)
      {^backendPid, :done, newPlt, _NewDocPlt} ->
        return_value(state, newPlt)
      {^backendPid, :ext_calls, extCalls} ->
        cl_loop(r_incremental_state(state, external_calls: extCalls), logCache)
      {^backendPid, :ext_types, extTypes} ->
        cl_loop(r_incremental_state(state, external_types: extTypes), logCache)
      {^backendPid, :mod_deps, modDeps} ->
        newState = r_incremental_state(state, mod_deps: modDeps)
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

  defp store_warnings(r_incremental_state(stored_warnings: storedWarnings) = st,
            warnings) do
    r_incremental_state(st, stored_warnings: storedWarnings ++ warnings)
  end

  defp cl_error(msg) do
    throw({:dialyzer_error, :lists.flatten(msg)})
  end

  defp cl_error(state, msg) do
    case (r_incremental_state(state, :output)) do
      :standard_io ->
        :ok
      outfile ->
        :io.format(outfile, '\n~ts\n', [msg])
    end
    maybe_close_output_file(state, true)
    throw({:dialyzer_error, :lists.flatten(msg)})
  end

  defp return_value(state = r_incremental_state(code_server: codeServer,
                      mod_deps: modDeps, output_plt: outputPlt,
                      plt_info: pltInfo, stored_warnings: newPLTWarnings),
            plt) do
    case (codeServer === :none) do
      true ->
        :ok
      false ->
        :dialyzer_codeserver.delete(codeServer)
    end
    oldPltWarnings = r_iplt_info(pltInfo, :warning_map)
    pLTUnknownWarnings = unknown_warnings_by_module(state)
    pLTWarningMap = :dialyzer_iplt.merge_warnings(newPLTWarnings,
                                                    pLTUnknownWarnings,
                                                    oldPltWarnings)
    pLTWarningList = (for mod <- :maps.keys(pLTWarningMap),
                            warn <- :maps.get(mod, pLTWarningMap, []) do
                        warn
                      end)
    newState = r_incremental_state(state, stored_warnings: pLTWarningList)
    :dialyzer_iplt.to_file(outputPlt, plt, modDeps,
                             r_iplt_info(pltInfo, warning_map: pLTWarningMap))
    handle_return_and_print(newState, pLTWarningMap, true)
  end

  defp handle_return_and_print(state, allWarningsMap, outputPltInUse) do
    warningModules = r_incremental_state(state, :warning_modules)
    warningsToReport = (case (warningModules === []) do
                          true ->
                            for mod <- :maps.keys(allWarningsMap),
                                  warn <- :maps.get(mod, allWarningsMap, []) do
                              warn
                            end
                          false ->
                            for mod <- warningModules,
                                  warn <- :maps.get(mod, allWarningsMap, []) do
                              warn
                            end
                        end)
    retValue = (case (warningsToReport === []) do
                  true ->
                    0
                  false ->
                    2
                end)
    case (r_incremental_state(state, :erlang_mode)) do
      false ->
        r_incremental_state(output: output, output_format: format,
            filename_opt: fOpt, indent_opt: iOpt,
            error_location: eOpt) = state
        print_warnings(warningsToReport, output, format, fOpt,
                         iOpt, eOpt)
        maybe_close_output_file(state, outputPltInUse)
        {retValue, []}
      true ->
        {retValue,
           set_warning_id(process_warnings(warningsToReport),
                            r_incremental_state(state, :error_location))}
    end
  end

  defp return_existing_errors(opts, pltWarnings) do
    state = init_output(opts)
    state1 = r_incremental_state(state, erlang_mode: r_options(opts, :erlang_mode))
    state2 = r_incremental_state(state1, warning_modules: get_warning_modules_from_opts(opts))
    modulesAnalyzed = []
    {handle_return_and_print(state2, pltWarnings, false),
       modulesAnalyzed}
  end

  defp unknown_warnings_by_module(r_incremental_state(legal_warnings: legalWarnings,
              external_calls: calls, external_types: types)) do
    case (:ordsets.is_element(:warn_unknown,
                                legalWarnings)) do
      true ->
        unknown_functions(calls) ++ unknown_types(types)
      false ->
        []
    end
  end

  defp unknown_functions(calls) do
    for {mFA, warningInfo = {_, _, {mod, _, _}}} <- calls do
      {mod,
         {:warn_unknown, warningInfo, {:unknown_function, mFA}}}
    end
  end

  defp unknown_types(types) do
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

  defp print_warnings([], _, _, _, _, _) do
    :ok
  end

  defp print_warnings(warnings, output, format, fOpt, iOpt, eOpt) do
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
    files1 = add_files(r_options(options, :files))
    files2 = add_files_rec(r_options(options, :files_rec))
    :ordsets.union(files1, files2)
  end

  defp get_warning_modules_from_opts(options) do
    files1 = add_files(r_options(options, :warning_files))
    files2 = add_files_rec(r_options(options, :warning_files_rec))
    for file <- :ordsets.union(files1, files2) do
      path_to_mod(file)
    end
  end

  defp add_files_rec(files) do
    add_files(files, true)
  end

  defp add_files(files) do
    add_files(files, false)
  end

  defp add_files(files, rec) do
    files1 = (for f <- files do
                :filename.absname(f)
              end)
    files2 = :ordsets.from_list(files1)
    dirs = :ordsets.filter(fn x ->
                                :filelib.is_dir(x)
                           end,
                             files2)
    files3 = :ordsets.subtract(files2, dirs)
    extension = '.beam'
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
    legalWarnings = r_incremental_state(state, :legal_warnings)
    fun = fn () ->
               :dialyzer_analysis_callgraph.start(self, legalWarnings,
                                                    analysis)
          end
    backendPid = spawn_link(fun)
    r_incremental_state(state, backend_pid: backendPid)
  end

end