defmodule :m_dialyzer_options do
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
  def build(opts) do
    defaultWarns = [:warn_return_no_exit, :warn_not_called,
                                              :warn_non_proper_list,
                                                  :warn_fun_app, :warn_matching,
                                                                     :warn_opaque,
                                                                         :warn_callgraph,
                                                                             :warn_failing_call,
                                                                                 :warn_bin_construction,
                                                                                     :warn_map_construction,
                                                                                         :warn_contract_range,
                                                                                             :warn_contract_types,
                                                                                                 :warn_contract_syntax,
                                                                                                     :warn_behaviour,
                                                                                                         :warn_undefined_callbacks,
                                                                                                             :warn_unknown]
    defaultWarns1 = :ordsets.from_list(defaultWarns)
    try do
      warningsFromConfig = :proplists.get_value(:warnings,
                                                  get_config(), [])
      update_path_from_config()
      defaultWarns2 = build_warnings(warningsFromConfig,
                                       defaultWarns1)
      defaultOpts = r_options()
      defaultOpts1 = r_options(defaultOpts, legal_warnings: defaultWarns2)
      opts1 = preprocess_opts(opts)
      env = env_default_opts()
      errLoc = :proplists.get_value(:error_location, env,
                                      :column)
      envOpts = [{:error_location, errLoc}]
      newOpts = build_options(envOpts ++ opts1, defaultOpts1)
      postprocess_opts(newOpts)
    catch
      {:dialyzer_options_error, msg} ->
        {:error, msg}
    end
  end

  defp update_path_from_config() do
    config = get_config()
    pAs = :proplists.get_value(:add_pathsa, config, [])
    pZs = :proplists.get_value(:add_pathsz, config, [])
    case (is_list(pAs)) do
      true ->
        :ok
      false ->
        bad_option('Bad list of paths in config', {:add_pathsa, pAs})
    end
    case (is_list(pZs)) do
      true ->
        :ok
      false ->
        bad_option('Bad list of paths in config', {:add_pathsz, pZs})
    end
    for pA <- pAs do
      case (:code.add_patha(pA)) do
        true ->
          :ok
        {:error, _} ->
          bad_option('Failed to add path from config', {:add_patha, pA})
      end
    end
    for pZ <- pZs do
      case (:code.add_pathz(pZ)) do
        true ->
          :ok
        {:error, _} ->
          bad_option('Failed to add path from config', {:add_pathz, pZ})
      end
    end
    :ok
  end

  defp preprocess_opts([]) do
    []
  end

  defp preprocess_opts([{:init_plt, file} | opts]) do
    [{:plts, [file]} | preprocess_opts(opts)]
  end

  defp preprocess_opts([opt | opts]) do
    [opt | preprocess_opts(opts)]
  end

  defp postprocess_opts(opts = r_options()) do
    opts1 = (case ({r_options(opts, :init_plts),
                      r_options(opts, :analysis_type)}) do
               {[], :incremental} ->
                 r_options(opts, init_plts: [:dialyzer_iplt.get_default_iplt_filename()])
               {[], _} ->
                 r_options(opts, init_plts: [:dialyzer_cplt.get_default_cplt_filename()])
               {[_ | _], _} ->
                 opts
             end)
    check_file_existence(opts1)
    check_metrics_file_validity(opts1)
    check_module_lookup_file_validity(opts1)
    opts2 = check_output_plt(opts1)
    check_init_plt_kind(opts2)
    opts3 = manage_default_incremental_apps(opts2)
    adapt_get_warnings(opts3)
  end

  defp check_metrics_file_validity(r_options(analysis_type: :incremental,
              metrics_file: :none)) do
    :ok
  end

  defp check_metrics_file_validity(r_options(analysis_type: :incremental,
              metrics_file: fileName)) do
    assert_filename(fileName)
  end

  defp check_metrics_file_validity(r_options(analysis_type: _NotIncremental,
              metrics_file: :none)) do
    :ok
  end

  defp check_metrics_file_validity(r_options(analysis_type: _NotIncremental,
              metrics_file: fileName)) do
    bad_option('A metrics filename may only be given when in incremental mode', {:metrics_file, fileName})
  end

  defp check_module_lookup_file_validity(r_options(analysis_type: :incremental,
              module_lookup_file: :none)) do
    :ok
  end

  defp check_module_lookup_file_validity(r_options(analysis_type: :incremental,
              module_lookup_file: fileName)) do
    assert_filename(fileName)
  end

  defp check_module_lookup_file_validity(r_options(analysis_type: _NotIncremental,
              module_lookup_file: :none)) do
    :ok
  end

  defp check_module_lookup_file_validity(r_options(analysis_type: _NotIncremental,
              module_lookup_file: fileName)) do
    bad_option('A module lookup filename may only be given when in incremental mode', {:module_lookup_file, fileName})
  end

  defp check_file_existence(r_options(analysis_type: :plt_remove)) do
    :ok
  end

  defp check_file_existence(r_options(files: files, files_rec: filesRec,
              warning_files: warningFiles,
              warning_files_rec: warningFilesRec)) do
    assert_filenames_exist(files)
    assert_filenames_exist(filesRec)
    assert_filenames_exist(warningFiles)
    assert_filenames_exist(warningFilesRec)
  end

  defp check_output_plt(opts = r_options(analysis_type: mode, from: from,
                     output_plt: outPLT)) do
    case (is_plt_mode(mode)) do
      true ->
        case (from === :byte_code) do
          true ->
            opts
          false ->
            msg = 'Byte code compiled with debug_info is needed to build the PLT'
            throw({:dialyzer_error, msg})
        end
      false ->
        case (outPLT === :none) do
          true ->
            opts
          false ->
            msg = :io_lib.format('Output PLT cannot be specified in analysis mode ~w', [mode])
            throw({:dialyzer_error, :lists.flatten(msg)})
        end
    end
  end

  defp check_init_plt_kind(r_options(analysis_type: :incremental,
              init_plts: initPlts)) do
    runCheck = fn fileName ->
                    case (:dialyzer_plt.plt_kind(fileName)) do
                      :no_file ->
                        :ok
                      :iplt ->
                        :ok
                      :cplt ->
                        bad_option('Given file is a classic PLT file, but in incremental mode, an incremental PLT file is expected', {:init_plt_file, fileName})
                      :bad_file ->
                        bad_option('Given file is not a PLT file', {:init_plt_file, fileName})
                    end
               end
    :lists.foreach(runCheck, initPlts)
  end

  defp check_init_plt_kind(r_options(analysis_type: _NotIncremental,
              init_plts: initPlts)) do
    runCheck = fn fileName ->
                    case (:dialyzer_plt.plt_kind(fileName)) do
                      :no_file ->
                        :ok
                      :cplt ->
                        :ok
                      :iplt ->
                        bad_option('Given file is an incremental PLT file, but outside of incremental mode, a classic PLT file is expected', {:init_plt_file, fileName})
                      :bad_file ->
                        bad_option('Given file is not a PLT file', {:init_plt_file, fileName})
                    end
               end
    :lists.foreach(runCheck, initPlts)
  end

  defp manage_default_incremental_apps(opts = r_options(analysis_type: :incremental, files: [],
                     files_rec: [], warning_files: [],
                     warning_files_rec: [])) do
    set_default_apps(get_config(), opts)
  end

  defp manage_default_incremental_apps(opts) do
    opts
  end

  defp set_default_apps([configElem | moreConfig], opts) do
    case (configElem) do
      {:incremental, {:default_apps, defaultApps} = term}
          when is_list(defaultApps) ->
        appDirs = get_app_dirs(defaultApps)
        assert_filenames_form(term, appDirs)
        r_options(opts, files_rec: appDirs)
      {:incremental, {:default_apps, defaultApps} = termApps,
         {:default_warning_apps, defaultWarningApps} = termWarns}
          when (is_list(defaultApps) and
                  is_list(defaultWarningApps))
               ->
        appDirs = get_app_dirs(defaultApps ++ defaultWarningApps)
        assert_filenames_form(termApps, appDirs)
        warningAppDirs = get_app_dirs(defaultWarningApps)
        assert_filenames_form(termWarns, warningAppDirs)
        r_options(opts, files_rec: appDirs, 
                  warning_files_rec: warningAppDirs)
      _ when :erlang.element(1, configElem) === :incremental
             ->
        bad_option('Given Erlang terms in \'incremental\' section could not be understood as Dialyzer config', configElem)
      _ ->
        set_default_apps(moreConfig, opts)
    end
  end

  defp set_default_apps([], opts) do
    opts
  end

  defp get_config() do
    defaultConfig = get_default_config_filename()
    case (:filelib.is_regular(defaultConfig)) do
      true ->
        case (:file.consult(defaultConfig)) do
          {:ok, config} when is_list(config) ->
            config
          {:error, reason} ->
            bad_option(:file.format_error(reason), defaultConfig)
        end
      false ->
        []
    end
  end

  def get_default_config_filename() do
    case (:os.getenv('DIALYZER_CONFIG')) do
      false ->
        cacheDir = :filename.basedir(:user_config, 'erlang')
        :filename.join(cacheDir, 'dialyzer.config')
      userSpecConfig ->
        userSpecConfig
    end
  end

  defp adapt_get_warnings(opts = r_options(analysis_type: mode,
                     get_warnings: warns)) do
    case (is_plt_mode(mode)) do
      true ->
        case (warns === :maybe) do
          true ->
            r_options(opts, get_warnings: false)
          false ->
            opts
        end
      false ->
        case (warns === :maybe) do
          true ->
            r_options(opts, get_warnings: true)
          false ->
            opts
        end
    end
  end

  defp bad_option(string, term) do
    msg = :io_lib.format('~ts: ~tP', [string, term, 25])
    throw({:dialyzer_options_error, :lists.flatten(msg)})
  end

  defp build_options([{optName, :undefined} | rest], options)
      when is_atom(optName) do
    build_options(rest, options)
  end

  defp build_options([{optionName, value} = term | rest], options) do
    case (optionName) do
      :apps ->
        oldValues = r_options(options, :files_rec)
        appDirs = get_app_dirs(value)
        assert_filenames_form(term, appDirs)
        build_options(rest,
                        r_options(options, files_rec: appDirs ++ oldValues))
      :files ->
        assert_filenames_form(term, value)
        build_options(rest, r_options(options, files: value))
      :files_rec ->
        oldValues = r_options(options, :files_rec)
        assert_filenames_form(term, value)
        build_options(rest,
                        r_options(options, files_rec: value ++ oldValues))
      :warning_apps ->
        oldValues = r_options(options, :warning_files_rec)
        appDirs = get_app_dirs(value)
        assert_filenames_form(term, appDirs)
        build_options(rest,
                        r_options(options, warning_files_rec: appDirs ++ oldValues))
      :warning_files ->
        assert_filenames_form(term, value)
        build_options(rest, r_options(options, warning_files: value))
      :warning_files_rec ->
        oldValues = r_options(options, :warning_files_rec)
        assert_filenames_form(term, value)
        build_options(rest,
                        r_options(options, warning_files_rec: value ++ oldValues))
      :analysis_type ->
        newOptions = (case (value) do
                        :succ_typings ->
                          r_options(options, analysis_type: value)
                        :plt_add ->
                          r_options(options, analysis_type: value)
                        :plt_build ->
                          r_options(options, analysis_type: value)
                        :plt_check ->
                          r_options(options, analysis_type: value)
                        :plt_remove ->
                          r_options(options, analysis_type: value)
                        :incremental ->
                          r_options(options, analysis_type: value)
                        :dataflow ->
                          bad_option('Analysis type is no longer supported', term)
                        :old_style ->
                          bad_option('Analysis type is no longer supported', term)
                        other ->
                          bad_option('Unknown analysis type', other)
                      end)
        assert_plt_op(options, newOptions)
        build_options(rest, newOptions)
      :check_plt when is_boolean(value) ->
        build_options(rest, r_options(options, check_plt: value))
      :defines ->
        assert_defines(term, value)
        oldVal = r_options(options, :defines)
        newVal = :ordsets.union(:ordsets.from_list(value),
                                  oldVal)
        build_options(rest, r_options(options, defines: newVal))
      :from when value === :byte_code or value === :src_code
                 ->
        build_options(rest, r_options(options, from: value))
      :get_warnings ->
        build_options(rest, r_options(options, get_warnings: value))
      :plts ->
        build_options(rest, r_options(options, init_plts: value))
      :include_dirs ->
        assert_filenames(term, value)
        oldVal = r_options(options, :include_dirs)
        newVal = :ordsets.union(:ordsets.from_list(value),
                                  oldVal)
        build_options(rest, r_options(options, include_dirs: newVal))
      :use_spec when is_boolean(value) ->
        build_options(rest, r_options(options, use_contracts: value))
      :no_spec when is_boolean(value) ->
        build_options(rest,
                        r_options(options, use_contracts: not value))
      :old_style ->
        bad_option('Analysis type is no longer supported', :old_style)
      :output_file ->
        assert_filename(value)
        build_options(rest, r_options(options, output_file: value))
      :metrics_file ->
        assert_filename(value)
        build_options(rest, r_options(options, metrics_file: value))
      :module_lookup_file ->
        assert_filename(value)
        build_options(rest,
                        r_options(options, module_lookup_file: value))
      :output_format ->
        assert_output_format(value)
        build_options(rest, r_options(options, output_format: value))
      :filename_opt ->
        assert_filename_opt(value)
        build_options(rest, r_options(options, filename_opt: value))
      :indent_opt ->
        build_options(rest, r_options(options, indent_opt: value))
      :output_plt ->
        assert_filename(value)
        build_options(rest, r_options(options, output_plt: value))
      :report_mode ->
        build_options(rest, r_options(options, report_mode: value))
      :erlang_mode ->
        build_options(rest, r_options(options, erlang_mode: true))
      :warnings ->
        newWarnings = build_warnings(value,
                                       r_options(options, :legal_warnings))
        build_options(rest,
                        r_options(options, legal_warnings: newWarnings))
      :callgraph_file ->
        assert_filename(value)
        build_options(rest, r_options(options, callgraph_file: value))
      :mod_deps_file ->
        assert_filename(value)
        build_options(rest, r_options(options, mod_deps_file: value))
      :error_location ->
        assert_error_location(value)
        build_options(rest, r_options(options, error_location: value))
      :timing ->
        build_options(rest, r_options(options, timing: value))
      :solvers ->
        assert_solvers(value)
        build_options(rest, r_options(options, solvers: value))
      :native ->
        build_options(rest, options)
      :native_cache ->
        build_options(rest, options)
      _ ->
        bad_option('Unknown dialyzer command line option', term)
    end
  end

  defp build_options([], options) do
    options
  end

  defp get_app_dirs(apps) when is_list(apps) do
    get_lib_dir(for a <- apps do
                  :erlang.atom_to_list(a)
                end)
  end

  defp get_app_dirs(apps) do
    bad_option('Use a list of otp applications', apps)
  end

  defp get_lib_dir(apps) do
    get_lib_dir(apps, [])
  end

  defp get_lib_dir([h | t], acc) do
    newElem = (case (:code.lib_dir(:erlang.list_to_atom(h))) do
                 {:error, :bad_name} ->
                   h
                 libDir when h === 'erts' ->
                   ebinDir = :filename.join([libDir, 'ebin'])
                   case (:file.read_file_info(ebinDir)) do
                     {:error, :enoent} ->
                       :filename.join([libDir, 'preloaded', 'ebin'])
                     _ ->
                       ebinDir
                   end
                 libDir ->
                   :filename.join(libDir, 'ebin')
               end)
    get_lib_dir(t, [newElem | acc])
  end

  defp get_lib_dir([], acc) do
    :lists.reverse(acc)
  end

  defp assert_filenames(term, files) do
    assert_filenames_form(term, files)
    assert_filenames_exist(files)
  end

  defp assert_filenames_form(term, [fileName | left])
      when length(fileName) >= 0 do
    assert_filenames_form(term, left)
  end

  defp assert_filenames_form(_Term, []) do
    :ok
  end

  defp assert_filenames_form(term, [_ | _]) do
    bad_option('Malformed or non-existing filename', term)
  end

  defp assert_filenames_exist([fileName | left]) do
    case (:filelib.is_file(fileName) or :filelib.is_dir(fileName)) do
      true ->
        :ok
      false ->
        bad_option('No such file, directory or application', fileName)
    end
    assert_filenames_exist(left)
  end

  defp assert_filenames_exist([]) do
    :ok
  end

  defp assert_filename(fileName) when length(fileName) >= 0 do
    :ok
  end

  defp assert_filename(fileName) do
    bad_option('Malformed or non-existing filename', fileName)
  end

  defp assert_defines(term, [{macro, _Value} | defs])
      when is_atom(macro) do
    assert_defines(term, defs)
  end

  defp assert_defines(_Term, []) do
    :ok
  end

  defp assert_defines(term, [_ | _]) do
    bad_option('Malformed define', term)
  end

  defp assert_output_format(:raw) do
    :ok
  end

  defp assert_output_format(:formatted) do
    :ok
  end

  defp assert_output_format(term) do
    bad_option('Illegal value for output_format', term)
  end

  defp assert_filename_opt(:basename) do
    :ok
  end

  defp assert_filename_opt(:fullpath) do
    :ok
  end

  defp assert_filename_opt(term) do
    bad_option('Illegal value for filename_opt', term)
  end

  defp assert_plt_op(r_options(analysis_type: oldVal),
            r_options(analysis_type: newVal)) do
    case (is_plt_mode(oldVal) and is_plt_mode(newVal)) do
      true ->
        bad_option('Options cannot be combined', [oldVal, newVal])
      false ->
        :ok
    end
  end

  defp is_plt_mode(:plt_add) do
    true
  end

  defp is_plt_mode(:plt_build) do
    true
  end

  defp is_plt_mode(:plt_remove) do
    true
  end

  defp is_plt_mode(:plt_check) do
    true
  end

  defp is_plt_mode(:incremental) do
    true
  end

  defp is_plt_mode(:succ_typings) do
    false
  end

  defp assert_error_location(:column) do
    :ok
  end

  defp assert_error_location(:line) do
    :ok
  end

  defp assert_error_location(term) do
    bad_option('Illegal value for error_location', term)
  end

  defp assert_solvers([]) do
    :ok
  end

  defp assert_solvers([:v1 | terms]) do
    assert_solvers(terms)
  end

  defp assert_solvers([:v2 | terms]) do
    assert_solvers(terms)
  end

  defp assert_solvers([term | _]) do
    bad_option('Illegal value for solver', term)
  end

  def build_warnings([opt | opts], warnings) do
    newWarnings = (case (opt) do
                     :no_return ->
                       :ordsets.del_element(:warn_return_no_exit, warnings)
                     :no_unused ->
                       :ordsets.del_element(:warn_not_called, warnings)
                     :no_unknown ->
                       :ordsets.del_element(:warn_unknown, warnings)
                     :no_improper_lists ->
                       :ordsets.del_element(:warn_non_proper_list, warnings)
                     :no_fun_app ->
                       :ordsets.del_element(:warn_fun_app, warnings)
                     :no_match ->
                       :ordsets.del_element(:warn_matching, warnings)
                     :no_opaque ->
                       :ordsets.del_element(:warn_opaque, warnings)
                     :no_fail_call ->
                       :ordsets.del_element(:warn_failing_call, warnings)
                     :no_contracts ->
                       warnings1 = :ordsets.del_element(:warn_contract_syntax,
                                                          warnings)
                       :ordsets.del_element(:warn_contract_types, warnings1)
                     :no_behaviours ->
                       :ordsets.del_element(:warn_behaviour, warnings)
                     :no_undefined_callbacks ->
                       :ordsets.del_element(:warn_undefined_callbacks,
                                              warnings)
                     :unmatched_returns ->
                       :ordsets.add_element(:warn_umatched_return, warnings)
                     :error_handling ->
                       :ordsets.add_element(:warn_return_only_exit, warnings)
                     :no_missing_calls ->
                       :ordsets.del_element(:warn_callgraph, warnings)
                     :specdiffs ->
                       s = :ordsets.from_list([:warn_contract_subtype,
                                                   :warn_contract_supertype,
                                                       :warn_contract_not_equal,
                                                           :warn_contract_missing_return,
                                                               :warn_contract_extra_return])
                       :ordsets.union(s, warnings)
                     :overspecs ->
                       s = :ordsets.from_list([:warn_contract_subtype,
                                                   :warn_contract_missing_return])
                       :ordsets.union(s, warnings)
                     :underspecs ->
                       s = :ordsets.from_list([:warn_contract_supertype,
                                                   :warn_contract_extra_return])
                       :ordsets.union(s, warnings)
                     :no_underspecs ->
                       :ordsets.del_element(:warn_contract_supertype, warnings)
                     :extra_return ->
                       :ordsets.add_element(:warn_contract_extra_return,
                                              warnings)
                     :no_extra_return ->
                       :ordsets.del_element(:warn_contract_extra_return,
                                              warnings)
                     :missing_return ->
                       :ordsets.add_element(:warn_contract_missing_return,
                                              warnings)
                     :no_missing_return ->
                       :ordsets.del_element(:warn_contract_missing_return,
                                              warnings)
                     :unknown ->
                       :ordsets.add_element(:warn_unknown, warnings)
                     :overlapping_contract ->
                       :ordsets.add_element(:warn_overlapping_contract,
                                              warnings)
                     otherAtom ->
                       bad_option('Unknown dialyzer warning option', otherAtom)
                   end)
    build_warnings(opts, newWarnings)
  end

  def build_warnings([], warnings) do
    warnings
  end

  defp env_default_opts() do
    key = 'ERL_COMPILER_OPTIONS'
    case (:os.getenv(key)) do
      false ->
        []
      str when is_list(str) ->
        case (:erl_scan.string(str)) do
          {:ok, tokens, _} ->
            dot = {:dot, :erl_anno.new(1)}
            case (:erl_parse.parse_term(tokens ++ [dot])) do
              {:ok, list} when is_list(list) ->
                list
              {:ok, term} ->
                [term]
              {:error, _Reason} ->
                :io.format('Ignoring bad term in ~s\n', [key])
                []
            end
          {:error, {_, _, _Reason}, _} ->
            :io.format('Ignoring bad term in ~s\n', [key])
            []
        end
    end
  end

end