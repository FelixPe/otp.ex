defmodule :m_dialyzer_cl_parse do
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
  def start() do
    args = :init.get_plain_arguments()
    try do
      :argparse.parse(args, cli(), %{progname: :dialyzer})
    catch
      {:dialyzer_cl_parse_error, msg} ->
        {:error, msg}
      _, r ->
        msg = :io_lib.format('~tp\n~tp\n', [r, __STACKTRACE__])
        {:error, :lists.flatten(msg)}
    else
      {:ok, argMap, _, _} ->
        {command, opts} = postprocess_side_effects(argMap)
        case (:dialyzer_options.build(:maps.to_list(opts))) do
          {:error, msg2} ->
            {:error, msg2}
          optsRecord ->
            {command, optsRecord}
        end
      {:error, error} ->
        {:error, :argparse.format_error(error)}
    end
  end

  defp parse_app(appOrDir) do
    case (:code.lib_dir(:erlang.list_to_atom(appOrDir))) do
      {:error, :bad_name} ->
        appOrDir
      libDir when appOrDir === 'erts' ->
        ebinDir = :filename.join([libDir, 'ebin'])
        case (:file.read_file_info(ebinDir)) do
          {:error, :enoent} ->
            :filename.join([libDir, 'preloaded', 'ebin'])
          _ ->
            ebinDir
        end
      libDir ->
        :filename.join(libDir, 'ebin')
    end
  end

  defp parse_input_list(file) do
    case (:file.read_file(file)) do
      {:ok, bin} ->
        files = :binary.split(bin, "\n", [:trim_all, :global])
        for f <- files do
          :erlang.binary_to_list(:string.trim(f))
        end
      {:error, reason} ->
        cl_error(:io_lib.format('Reading of ~s failed: ~s',
                                  [file, :file.format_error(reason)]))
    end
  end

  defp parse_define(arg) do
    case (:re.split(arg, '=',
                      [{:return, :list}, :unicode])) do
      [def__, val] ->
        {:ok, tokens, _} = :erl_scan.string(val ++ '.')
        {:ok, erlVal} = :erl_parse.parse_term(tokens)
        {:erlang.list_to_atom(def__), erlVal}
      [def__] ->
        {:erlang.list_to_atom(def__), true}
    end
  end

  defp cli() do
    %{arguments:
      [%{name: :files, action: :extend, nargs: :list,
           required: false, help: "Use Dialyzer from the command line to detect defects in the specified files or directories containing .erl or .beam files, depending on the type of the analysis."},
           %{name: :files, short: ?c, long: '-com', action: :extend,
               nargs: :list, help: "Same as files, specifies files to run the analysis on (left for compatibility)"},
               %{name: :files_rec, short: ?r, action: :extend,
                   nargs: :list, help: "Search the specified directories recursively for subdirectories containing .erl or .beam files in them, depending on the type of analysis."},
                   %{name: :files, long: '-input_list_file',
                       type: {:custom, &parse_input_list/1}, action: :extend,
                       help: "Specify the name of a file that contains the names of the files to be analyzed (one file name per line)."},
                       %{name: :files_rec, long: '-apps',
                           type: {:custom, &parse_app/1}, nargs: :list,
                           action: :extend, help: "Option typically used when building or modifying a plt as in: \ndialyzer --build_plt --apps erts kernel stdlib mnesia ... \nto conveniently refer to library applications corresponding to the Erlang/OTP installation. However, the option is general and can also be used during analysis in order to refer to Erlang/OTP applications. In addition, file or directory names can also be included, as in: \ndialyzer --apps inets ssl ./ebin ../other_lib/ebin/my_module.beam"},
                           %{name: :output_file, short: ?o, long: '-output', help: "When using Dialyzer from the command line, send the analysis results to the specified outfile rather than to stdout."},
                               %{name: :output_format, long: '-raw', type: :boolean,
                                   action: {:store, :raw}, help: "When using Dialyzer from the command line, output the raw analysis results (Erlang terms) instead of the formatted result. The raw format is easier to post-process (for instance, to filter warnings or to output HTML pages)."},
                                   %{name: :from, long: '-src', type: :boolean,
                                       action: {:store, :src_code}, help: "Override the default, which is to analyze BEAM files, and analyze starting from Erlang source code instead."},
                                       %{name: :defines, short: ?D,
                                           type: {:custom, &parse_define/1},
                                           action: :append, help: "When analyzing from source, pass the define to Dialyzer. (**)"},
                                           %{name: :include_dirs, short: ?I,
                                               action: :append, help: "When analyzing from source, pass the include_dir to Dialyzer. (**)"},
                                               %{name: :pa, long: 'pa',
                                                   action: :append, help: "Include dir in the path for Erlang (useful when analyzing files that have '-include_lib()' directives)."},
                                                   %{name: :output_plt, long: '-output_plt',
                                                       help: "Store the plt at the specified file after building it."},
                                                       %{name: :plts, long: '-plt',
                                                           nargs: 1, help: "Use the specified plt as the initial plt (if the plt was built during setup the files will be checked for consistency)."},
                                                           %{name: :plts,
                                                               long: '-plts',
                                                               nargs:
                                                               :nonempty_list,
                                                               help: "Merge the specified plts to create the initial plt -- requires that the plts are disjoint (i.e., do not have any module appearing in more than one plt). The plts are created in the usual way: \n  dialyzer --build_plt --output_plt plt_1 files_to_include   ... \n  dialyzer --build_plt --output_plt plt_n files_to_include and then can be used in either of the following ways: \n  dialyzer files_to_analyze --plts plt_1 ... plt_n \nor: \n  dialyzer --plts plt_1 ... plt_n -- files_to_analyze \n(Note the -- delimiter in the second case)"},
                                                               %{name:
                                                                 :warnings,
                                                                   short: ?W,
                                                                   action:
                                                                   :append,
                                                                   type:
                                                                   {:atom,
                                                                      [:error_handling,
                                                                           :no_behaviours,
                                                                               :no_contracts,
                                                                                   :no_fail_call,
                                                                                       :no_fun_app,
                                                                                           :no_improper_lists,
                                                                                               :no_match,
                                                                                                   :no_missing_calls,
                                                                                                       :no_opaque,
                                                                                                           :no_return,
                                                                                                               :no_undefined_callbacks,
                                                                                                                   :no_underspecs,
                                                                                                                       :no_unknown,
                                                                                                                           :no_unused,
                                                                                                                               :underspecs,
                                                                                                                                   :unknown,
                                                                                                                                       :unmatched_returns,
                                                                                                                                           :overspecs,
                                                                                                                                               :specdiffs,
                                                                                                                                                   :extra_return,
                                                                                                                                                       :no_extra_return,
                                                                                                                                                           :missing_return,
                                                                                                                                                               :no_missing_return]},
                                                                   help:
                                                                   {"[-Wwarn]*", ["A family of options which selectively turn on/off warnings"]}},
                                                                   %{name:
                                                                     :shell,
                                                                       long: '-shell',
                                                                       type:
                                                                       :boolean,
                                                                       help: "Do not disable the Erlang shell while running the GUI."},
                                                                       %{name:
                                                                         :version,
                                                                           short:
                                                                           ?v,
                                                                           long:
                                                                           '-version',
                                                                           type:
                                                                           :boolean,
                                                                           help:
                                                                           "Print the Dialyzer version and some more information and exit."},
                                                                           %{name:
                                                                             :help,
                                                                               short:
                                                                               ?h,
                                                                               long:
                                                                               '-help',
                                                                               type:
                                                                               :boolean,
                                                                               help:
                                                                               "Print this message and exit."},
                                                                               %{name:
                                                                                 :report_mode,
                                                                                   short:
                                                                                   ?q,
                                                                                   long:
                                                                                   '-quiet',
                                                                                   type:
                                                                                   :boolean,
                                                                                   action:
                                                                                   {:store,
                                                                                      :quiet},
                                                                                   default:
                                                                                   :normal,
                                                                                   help:
                                                                                   "Make Dialyzer a bit more quiet."},
                                                                                   %{name:
                                                                                     :report_mode,
                                                                                       long:
                                                                                       '-verbose',
                                                                                       type:
                                                                                       :boolean,
                                                                                       action:
                                                                                       {:store,
                                                                                          :verbose},
                                                                                       help:
                                                                                       "Make Dialyzer a bit more verbose."},
                                                                                       %{name:
                                                                                         :timing,
                                                                                           long:
                                                                                           '-statistics',
                                                                                           type:
                                                                                           :boolean,
                                                                                           help:
                                                                                           "Prints information about the progress of execution (analysis phases, time spent in each and size of the relative input)."},
                                                                                           %{name:
                                                                                             :analysis_type,
                                                                                               long:
                                                                                               '-build_plt',
                                                                                               type:
                                                                                               :boolean,
                                                                                               action:
                                                                                               {:store,
                                                                                                  :plt_build},
                                                                                               help:
                                                                                               "The analysis starts from an empty plt and creates a new one from the files specified with -c and -r. Only works for beam files. Use --plt(s) or --output_plt to override the default plt location."},
                                                                                               %{name:
                                                                                                 :analysis_type,
                                                                                                   long:
                                                                                                   '-add_to_plt',
                                                                                                   type:
                                                                                                   :boolean,
                                                                                                   action:
                                                                                                   {:store,
                                                                                                      :plt_add},
                                                                                                   help:
                                                                                                   "The plt is extended to also include the files specified with -c and -r. Use --plt(s) to specify which plt to start from, and --output_plt to specify where to put the plt. Note that the analysis might include files from the plt if they depend on the new files. This option only works with beam files."},
                                                                                                   %{name:
                                                                                                     :analysis_type,
                                                                                                       long:
                                                                                                       '-remove_from_plt',
                                                                                                       type:
                                                                                                       :boolean,
                                                                                                       action:
                                                                                                       {:store,
                                                                                                          :plt_remove},
                                                                                                       help:
                                                                                                       "The information from the files specified with -c and -r is removed from the plt. Note that this may cause a re-analysis of the remaining dependent files."},
                                                                                                       %{name:
                                                                                                         :analysis_type,
                                                                                                           long:
                                                                                                           '-check_plt',
                                                                                                           type:
                                                                                                           :boolean,
                                                                                                           action:
                                                                                                           {:store,
                                                                                                              :plt_check},
                                                                                                           help:
                                                                                                           "Check the plt for consistency and rebuild it if it is not up-to-date. Actually, this option is of rare use as it is on by default."},
                                                                                                           %{name:
                                                                                                             :check_plt,
                                                                                                               long:
                                                                                                               '-no_check_plt',
                                                                                                               short:
                                                                                                               ?n,
                                                                                                               type:
                                                                                                               :boolean,
                                                                                                               action:
                                                                                                               {:store,
                                                                                                                  false},
                                                                                                               help:
                                                                                                               "Skip the plt check when running Dialyzer. Useful when working with installed plts that never change."},
                                                                                                               %{name:
                                                                                                                 :analysis_type,
                                                                                                                   long:
                                                                                                                   '-incremental',
                                                                                                                   type:
                                                                                                                   :boolean,
                                                                                                                   action:
                                                                                                                   {:store,
                                                                                                                      :incremental},
                                                                                                                   help:
                                                                                                                   "The analysis starts from an existing incremental PLT, or builds one from scratch if one doesn't exist, and runs the minimal amount of additional analysis to report all issues in the given set of apps. Notably, incremental PLT files are not compatible with \"classic\" PLT files, and vice versa. The initial incremental PLT will be updated unless an alternative output incremental PLT is given."},
                                                                                                                   %{name:
                                                                                                                     :analysis_type,
                                                                                                                       long:
                                                                                                                       '-plt_info',
                                                                                                                       type:
                                                                                                                       :boolean,
                                                                                                                       action:
                                                                                                                       {:store,
                                                                                                                          :plt_info},
                                                                                                                       help:
                                                                                                                       "Make Dialyzer print information about the plt and then quit. The plt can be specified with --plt(s)."},
                                                                                                                       %{name:
                                                                                                                         :get_warnings,
                                                                                                                           long:
                                                                                                                           '-get_warnings',
                                                                                                                           type:
                                                                                                                           :boolean,
                                                                                                                           help:
                                                                                                                           "Make Dialyzer emit warnings even when manipulating the plt. Warnings are only emitted for files that are actually analyzed."},
                                                                                                                           %{name:
                                                                                                                             :callgraph_file,
                                                                                                                               long:
                                                                                                                               '-dump_callgraph',
                                                                                                                               help:
                                                                                                                               "Dump the call graph into the specified file whose format is determined by the file name extension. Supported extensions are: raw, dot, and ps. If something else is used as file name extension, default format '.raw' will be used."},
                                                                                                                               %{name:
                                                                                                                                 :mod_deps_file,
                                                                                                                                   long:
                                                                                                                                   '-dump_full_dependencies_graph',
                                                                                                                                   help:
                                                                                                                                   "Dump the full dependency graph (i.e. dependencies induced by function calls, usages of types in specs, behaviour implementations, etc.) into the specified file whose format is determined by the file name extension. Supported extensions are: dot and ps."},
                                                                                                                                   %{name:
                                                                                                                                     :error_location,
                                                                                                                                       long:
                                                                                                                                       '-error_location',
                                                                                                                                       type:
                                                                                                                                       {:atom,
                                                                                                                                          [:column,
                                                                                                                                               :line]},
                                                                                                                                       help:
                                                                                                                                       "Use a pair {Line, Column} or an integer Line to pinpoint the location of warnings. The default is to use a pair {Line, Column}. When formatted, the line and the column are separated by a colon."},
                                                                                                                                       %{name:
                                                                                                                                         :filename_opt,
                                                                                                                                           long:
                                                                                                                                           '-fullpath',
                                                                                                                                           type:
                                                                                                                                           :boolean,
                                                                                                                                           action:
                                                                                                                                           {:store,
                                                                                                                                              :fullpath},
                                                                                                                                           help:
                                                                                                                                           "Display the full path names of files for which warnings are emitted."},
                                                                                                                                           %{name:
                                                                                                                                             :indent_opt,
                                                                                                                                               long:
                                                                                                                                               '-no_indentation',
                                                                                                                                               type:
                                                                                                                                               :boolean,
                                                                                                                                               action:
                                                                                                                                               {:store,
                                                                                                                                                  false},
                                                                                                                                               help:
                                                                                                                                               "Do not indent contracts and success typings. Note that this option has no effect when combined with the --raw option."},
                                                                                                                                               %{name:
                                                                                                                                                 :gui,
                                                                                                                                                   long:
                                                                                                                                                   '-gui',
                                                                                                                                                   type:
                                                                                                                                                   :boolean,
                                                                                                                                                   help:
                                                                                                                                                   "Use the GUI."},
                                                                                                                                                   %{name:
                                                                                                                                                     :metrics_file,
                                                                                                                                                       long:
                                                                                                                                                       '-metrics_file',
                                                                                                                                                       help:
                                                                                                                                                       "Write metrics about Dialyzer's incrementality (for example, total number of modules considered, how many modules were changed since the PLT was last updated, how many modules needed to be analyzed) to a file. This can be useful for tracking and debugging Dialyzer's incrementality."},
                                                                                                                                                       %{name:
                                                                                                                                                         :warning_files_rec,
                                                                                                                                                           long:
                                                                                                                                                           '-warning_apps',
                                                                                                                                                           type:
                                                                                                                                                           {:custom,
                                                                                                                                                              &parse_app/1},
                                                                                                                                                           nargs:
                                                                                                                                                           :list,
                                                                                                                                                           action:
                                                                                                                                                           :extend,
                                                                                                                                                           help:
                                                                                                                                                           "By default, warnings will be reported to all applications given by --apps. However, if --warning_apps is used, only those applications given to --warning_apps will have warnings reported. All applications given by --apps, but not --warning_apps, will be analysed to provide context to the analysis, but warnings will not be reported for them. For example, you may want to include libraries you depend on in the analysis with --apps so discrepancies in their usage can be found, but only include your own code with --warning_apps so that discrepancies are only reported in code that you own."},
                                                                                                                                                           %{name:
                                                                                                                                                             :solvers,
                                                                                                                                                               long:
                                                                                                                                                               '-solver',
                                                                                                                                                               type:
                                                                                                                                                               {:atom,
                                                                                                                                                                  [:v1,
                                                                                                                                                                       :v2]},
                                                                                                                                                               action:
                                                                                                                                                               :append,
                                                                                                                                                               help:
                                                                                                                                                               :hidden},
                                                                                                                                                               %{name:
                                                                                                                                                                 :timing,
                                                                                                                                                                   long:
                                                                                                                                                                   '-resources',
                                                                                                                                                                   type:
                                                                                                                                                                   :boolean,
                                                                                                                                                                   action:
                                                                                                                                                                   {:store,
                                                                                                                                                                      :debug},
                                                                                                                                                                   help:
                                                                                                                                                                   :hidden},
                                                                                                                                                                   %{name:
                                                                                                                                                                     :shell,
                                                                                                                                                                       short:
                                                                                                                                                                       ?-,
                                                                                                                                                                       type:
                                                                                                                                                                       :boolean,
                                                                                                                                                                       help:
                                                                                                                                                                       :hidden}],
        help:
        ["Usage: ", :usage, "\n\nOptions:\n", :arguments, :options,
                                       '\nNote:\n  * denotes that multiple occurrences of these options are possible.\n ** options -D and -I work both from command-line and in the Dialyzer GUI;\n    the syntax of defines and includes is the same as that used by "erlc".\n\n' ++ warning_options_msg() ++ '\n' ++ configuration_file_msg() ++ '\n\nThe exit status of the command line version is:\n  0 - No problems were encountered during the analysis and no\n      warnings were emitted.\n  1 - Problems were encountered during the analysis.\n  2 - No problems were encountered, but warnings were emitted.\n\n']}
  end

  defp postprocess_side_effects(argMap) when :erlang.is_map_key(:version,
                                            argMap) do
    :io.format('Dialyzer version ' ++ :EFE_TODO_VSN_MACRO ++ '\n')
    :erlang.halt(0)
  end

  defp postprocess_side_effects(argMap) when :erlang.is_map_key(:help,
                                            argMap) do
    :io.format(:argparse.help(cli(),
                                %{progname: :dialyzer}))
    :erlang.halt(0)
  end

  defp postprocess_side_effects(argMap) when :erlang.is_map_key(:pa, argMap) do
    for path <- :erlang.map_get(:pa, argMap) do
      :code.add_patha(path) !== true and cl_error('Bad directory for -pa: ' ++ path)
    end
    postprocess_side_effects(:maps.remove(:pa, argMap))
  end

  defp postprocess_side_effects(argMap) when :erlang.is_map_key(:shell,
                                            argMap) do
    postprocess_side_effects(:maps.remove(:shell, argMap))
  end

  defp postprocess_side_effects(argMap) do
    argMap1 = (case (:erlang.is_map_key(:files,
                                          argMap) and :lists.all(fn f ->
                                                                      :filename.extension(f) === '.erl'
                                                                 end,
                                                                   :maps.get(:files,
                                                                               argMap))) do
                 true ->
                   Map.put(argMap, :from, :src_code)
                 false ->
                   argMap
               end)
    case (:maps.get(:analysis_type, argMap1, :undefined)) do
      :plt_info ->
        {:plt_info,
           Map.put(argMap1, :analysis_type, :plt_check)}
      :plt_check ->
        {:check_init, argMap1}
      _ when :erlang.map_get(:gui, argMap1) ->
        allowed = [:defines, :from, :include_dirs, :plts,
                                                       :output_plt,
                                                           :report_mode,
                                                               :use_spec,
                                                                   :warnings,
                                                                       :check_plt,
                                                                           :solvers]
        {:gui, :maps.with(allowed, argMap1)}
      _ ->
        {:cl, argMap1}
    end
  end

  defp cl_error(str) do
    msg = :lists.flatten(str)
    throw({:dialyzer_cl_parse_error, msg})
  end

  defp warning_options_msg() do
    'Warning options:\n  -Wno_return\n     Suppress warnings for functions that will never return a value.\n  -Wno_unused\n     Suppress warnings for unused functions.\n  -Wno_improper_lists\n     Suppress warnings for construction of improper lists.\n  -Wno_fun_app\n     Suppress warnings for fun applications that will fail.\n  -Wno_match\n     Suppress warnings for patterns that are unused or cannot match.\n  -Wno_opaque\n     Suppress warnings for violations of opacity of data types.\n  -Wno_fail_call\n     Suppress warnings for failing calls.\n  -Wno_contracts\n     Suppress warnings about invalid contracts.\n  -Wno_behaviours\n     Suppress warnings about behaviour callbacks which drift from the published\n     recommended interfaces.\n  -Wno_missing_calls\n     Suppress warnings about calls to missing functions.\n  -Wno_undefined_callbacks\n     Suppress warnings about behaviours that have no -callback attributes for\n     their callbacks.\n  -Wno_unknown\n     Suppress warnings about unknown functions and types. The default is to\n     warn about unknown functions and types when setting the exit\n     status. When using Dialyzer from Erlang, warnings about unknown functions\n     and types are returned.\n  -Wunmatched_returns ***\n     Include warnings for function calls which ignore a structured return\n     value or do not match against one of many possible return value(s).\n  -Werror_handling ***\n     Include warnings for functions that only return by means of an exception.\n  -Wunderspecs ***\n     Warn about underspecified functions\n     (those whose -spec is strictly more allowing than the success typing).\n  -Wextra_return ***\n     Warn about functions whose specification includes types that the\n     function cannot return.\n  -Wmissing_return ***\n     Warn about functions that return values that are not part\n     of the specification.\n  -Woverlapping_contract ***\n     Warn about overloaded functions whose specification include types that overlap.\n\nThe following options are also available but their use is not recommended:\n(they are mostly for Dialyzer developers and internal debugging)\n  -Woverspecs ***\n     Warn about overspecified functions\n     (those whose -spec is strictly less allowing than the success typing).\n  -Wspecdiffs ***\n     Warn when the -spec is different than the success typing.\n\n*** Identifies options that turn on warnings rather than turning them off.\n\nThe following options are not strictly needed as they specify the default.\nThey are primarily intended to be used with the -dialyzer attribute:\n  -Wno_underspecs\n     Suppress warnings about underspecified functions (those whose -spec\n     is strictly more allowing than the success typing).\n  -Wno_extra_return\n     Suppress warnings about functions whose specification includes types that the function cannot return.\n  -Wno_missing_return\n     Suppress warnings about functions that return values that are not part of the specification.\n'
  end

  defp configuration_file_msg() do
    'Configuration file:\n     Dialyzer\'s configuration file may also be used to augment the default\n     options and those given directly to the Dialyzer command. It is commonly\n     used to avoid repeating options which would otherwise need to be given\n     explicitly to Dialyzer on every invocation.\n\n     The location of the configuration file can be set via the\n     DIALYZER_CONFIG environment variable, and defaults to\n     within the user_config location given by filename:basedir/3.\n\n     On your system, the location is currently configured as:\n       ' ++ :dialyzer_options.get_default_config_filename() ++ '\n\n     An example configuration file\'s contents might be:\n\n       {incremental,\n         {default_apps,[stdlib,kernel,erts]},\n         {default_warning_apps,[stdlib]}\n       }.\n       {warnings, [no_improper_lists]}.\n       {add_pathsa,["/users/samwise/potatoes/ebin"]}.\n       {add_pathsz,["/users/smeagol/fish/ebin"]}.\n'
  end

end