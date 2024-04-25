defmodule :m_dialyzer do
  use Bitwise
  require Record

  Record.defrecord(:r_plt_info, :plt_info,
    files: :undefined,
    mod_deps: :dict.new()
  )

  Record.defrecord(:r_iplt_info, :iplt_info,
    files: :undefined,
    mod_deps: :dict.new(),
    warning_map: :none,
    legal_warnings: :none
  )

  Record.defrecord(:r_plt, :plt,
    info: :undefined,
    types: :undefined,
    contracts: :undefined,
    callbacks: :undefined,
    exported_types: :undefined
  )

  Record.defrecord(:r_analysis, :analysis,
    analysis_pid: :undefined,
    type: :succ_typings,
    defines: [],
    doc_plt: :undefined,
    files: [],
    include_dirs: [],
    start_from: :byte_code,
    plt: :undefined,
    use_contracts: true,
    behaviours_chk: false,
    timing: false,
    timing_server: :none,
    callgraph_file: ~c"",
    mod_deps_file: ~c"",
    solvers: :undefined
  )

  Record.defrecord(:r_options, :options,
    files: [],
    files_rec: [],
    warning_files: [],
    warning_files_rec: [],
    analysis_type: :succ_typings,
    timing: false,
    defines: [],
    from: :byte_code,
    get_warnings: :maybe,
    init_plts: [],
    include_dirs: [],
    output_plt: :none,
    legal_warnings: :ordsets.new(),
    report_mode: :normal,
    erlang_mode: false,
    use_contracts: true,
    output_file: :none,
    output_format: :formatted,
    filename_opt: :basename,
    indent_opt: true,
    callgraph_file: ~c"",
    mod_deps_file: ~c"",
    check_plt: true,
    error_location: :column,
    metrics_file: :none,
    module_lookup_file: :none,
    solvers: []
  )

  Record.defrecord(:r_contract, :contract, contracts: [], args: [], forms: [])

  def plain_cl() do
    case :dialyzer_cl_parse.start() do
      {:check_init, opts} ->
        cl_halt(cl_check_init(opts), opts)

      {:plt_info, opts} ->
        cl_halt(cl_print_plt_info(opts), opts)

      {:gui, opts} ->
        try do
          check_gui_options(opts)
        catch
          {:dialyzer_error, msg} ->
            cl_error(msg)
        end

        case r_options(opts, :check_plt) do
          true ->
            case cl_check_init(r_options(opts, get_warnings: false)) do
              {:ok, _} ->
                gui_halt(internal_gui(opts), opts)

              {:error, _} = error ->
                cl_halt(error, opts)
            end

          false ->
            gui_halt(internal_gui(opts), opts)
        end

      {:cl, opts} ->
        case r_options(opts, :check_plt) do
          true ->
            case cl_check_init(r_options(opts, get_warnings: false)) do
              {:error, _} = error ->
                cl_halt(error, opts)

              {:ok, _} ->
                cl_halt(cl(opts), opts)
            end

          false ->
            cl_halt(cl(opts), opts)
        end

      {:error, msg} ->
        cl_error(msg)
    end
  end

  defp cl_check_init(r_options(analysis_type: analType) = opts) do
    case analType do
      :plt_build ->
        {:ok, 0}

      :plt_add ->
        {:ok, 0}

      :plt_remove ->
        {:ok, 0}

      :incremental ->
        {:ok, 0}

      other
      when other === :succ_typings or
             other === :plt_check ->
        f = fn ->
          newOpts = r_options(opts, analysis_type: :plt_check)
          {ret, _Warnings} = :dialyzer_cl.start(newOpts)
          ret
        end

        doit(f)
    end
  end

  defp cl_print_plt_info(opts) do
    f = fn ->
      print_plt_info(opts)
    end

    doit(f)
  end

  defp print_plt_info(r_options(init_plts: pLTs, output_file: outputFile)) do
    pLTInfo = get_plt_info(pLTs)
    do_print_plt_info(pLTInfo, outputFile)
  end

  defp get_plt_info([pLT | pLTs]) do
    string =
      case :dialyzer_plt.plt_kind(pLT) do
        :cplt ->
          case :dialyzer_cplt.included_files(pLT) do
            {:ok, files} ->
              :io_lib.format(~c"The classic PLT ~ts includes the following files:\n~tp\n\n", [
                pLT,
                files
              ])

            {:error, :read_error} ->
              msg = :io_lib.format(~c"Could not read the classic PLT file ~tp\n\n", [pLT])
              throw({:dialyzer_error, msg})

            {:error, :no_such_file} ->
              msg = :io_lib.format(~c"The classic PLT file ~tp does not exist\n\n", [pLT])
              throw({:dialyzer_error, msg})
          end

        :iplt ->
          case :dialyzer_iplt.included_modules(pLT) do
            {:ok, modules} ->
              :io_lib.format(
                ~c"The incremental PLT ~ts includes the following modules:\n~tp\n\n",
                [pLT, modules]
              )

            {:error, :read_error} ->
              msg = :io_lib.format(~c"Could not read the incremental PLT file ~tp\n\n", [pLT])
              throw({:dialyzer_error, msg})

            {:error, :no_such_file} ->
              msg = :io_lib.format(~c"The incremental PLT file ~tp does not exist\n\n", [pLT])
              throw({:dialyzer_error, msg})
          end

        :bad_file ->
          msg = :io_lib.format(~c"Could not read the PLT file ~tp\n\n", [pLT])
          throw({:dialyzer_error, msg})

        :no_file ->
          msg = :io_lib.format(~c"The PLT file ~tp does not exist\n\n", [pLT])
          throw({:dialyzer_error, msg})
      end

    string ++ get_plt_info(pLTs)
  end

  defp get_plt_info([]) do
    ~c""
  end

  defp do_print_plt_info(pLTInfo, outputFile) do
    case outputFile === :none do
      true ->
        :io.format(~c"~ts", [pLTInfo])
        0

      false ->
        case :file.open(outputFile, [:write]) do
          {:ok, fileDesc} ->
            :io.format(fileDesc, ~c"~ts", [pLTInfo])
            :ok = :file.close(fileDesc)
            0

          {:error, reason} ->
            msg1 =
              :io_lib.format(~c"Could not open output file ~tp, Reason: ~p\n", [
                outputFile,
                reason
              ])

            throw({:dialyzer_error, msg1})
        end
    end
  end

  defp cl(opts) do
    f = fn ->
      {ret, _Warnings} =
        case r_options(opts, :analysis_type) do
          :incremental ->
            :dialyzer_incremental.start(opts)

          _ ->
            :dialyzer_cl.start(opts)
        end

      ret
    end

    doit(f)
  end

  def run(opts) do
    {warnings, _ModulesAnalyzed} = run_report_modules_analyzed(opts)
    warnings
  end

  def run_report_modules_analyzed(opts) do
    {warnings, _ModulesChanged, modulesAnalyzed} = run_report_modules_changed_and_analyzed(opts)
    {warnings, modulesAnalyzed}
  end

  def run_report_modules_changed_and_analyzed(opts) do
    try do
      :dialyzer_options.build([{:report_mode, :quiet}, {:erlang_mode, true} | opts])
    catch
      {:dialyzer_error, errorMsg} ->
        :erlang.error({:dialyzer_error, :lists.flatten(errorMsg)})
    else
      {:error, msg} ->
        throw({:dialyzer_error, msg})

      optsRecord ->
        :ok = check_init(optsRecord)

        analysisResult =
          case r_options(optsRecord, :analysis_type) do
            :incremental ->
              :dialyzer_incremental.start_report_modules_changed_and_analyzed(optsRecord)

            _ ->
              :dialyzer_cl.start_report_modules_changed_and_analyzed(optsRecord)
          end

        case analysisResult do
          {{2, warnings}, modulesChanged, modulesAnalyzed} ->
            {warnings, modulesChanged, modulesAnalyzed}

          {{0, _}, modulesChanged, modulesAnalyzed} ->
            {[], modulesChanged, modulesAnalyzed}
        end
    end
  end

  defp check_init(r_options(analysis_type: :plt_check)) do
    :ok
  end

  defp check_init(r_options(check_plt: true) = optsRecord) do
    case cl_check_init(optsRecord) do
      {:ok, _} ->
        :ok

      {:error, msg} ->
        throw({:dialyzer_error, msg})
    end
  end

  defp check_init(r_options(check_plt: false)) do
    :ok
  end

  defp internal_gui(optsRecord) do
    f = fn ->
      :dialyzer_gui_wx.start(optsRecord)
      0
    end

    doit(f)
  end

  def gui() do
    gui([])
  end

  def gui(opts) do
    try do
      :dialyzer_options.build([{:report_mode, :quiet} | opts])
    catch
      {:dialyzer_error, errorMsg} ->
        :erlang.error({:dialyzer_error, :lists.flatten(errorMsg)})
    else
      {:error, msg} ->
        throw({:dialyzer_error, msg})

      optsRecord ->
        :ok = check_gui_options(optsRecord)
        :ok = check_init(optsRecord)

        f = fn ->
          :dialyzer_gui_wx.start(optsRecord)
        end

        case doit(f) do
          {:ok, _} ->
            :ok

          {:error, msg} ->
            throw({:dialyzer_error, msg})
        end
    end
  end

  defp check_gui_options(r_options(analysis_type: :succ_typings)) do
    :ok
  end

  defp check_gui_options(r_options(analysis_type: mode)) do
    msg = :io_lib.format(~c"Analysis mode ~w is illegal in GUI mode", [mode])
    throw({:dialyzer_error, msg})
  end

  def plt_info(plt) do
    case :dialyzer_plt.plt_kind(plt) do
      :cplt ->
        case :dialyzer_cplt.included_files(plt) do
          {:ok, files} ->
            {:ok, [{:files, files}]}

          error ->
            error
        end

      :iplt ->
        case :dialyzer_iplt.included_modules(plt) do
          {:ok, modules} ->
            {:ok, {:incremental, [{:modules, modules}]}}

          error ->
            error
        end

      :bad_file ->
        {:error, :not_valid}

      :no_file ->
        {:error, :no_such_file}
    end
  end

  defp doit(f) do
    try do
      {:ok, f.()}
    catch
      {:dialyzer_error, msg} ->
        {:error, :lists.flatten(msg)}
    end
  end

  defp cl_error(msg) do
    cl_halt({:error, msg}, r_options())
  end

  defp gui_halt(r, opts) do
    cl_halt(r, r_options(opts, report_mode: :quiet))
  end

  defp cl_halt({:ok, r = 0}, r_options(report_mode: :quiet)) do
    :erlang.halt(r)
  end

  defp cl_halt({:ok, r = 2}, r_options(report_mode: :quiet)) do
    :erlang.halt(r)
  end

  defp cl_halt({:ok, r = 0}, r_options()) do
    :io.put_chars(~c"done (passed successfully)\n")
    :erlang.halt(r)
  end

  defp cl_halt({:ok, r = 2}, r_options(output_file: output)) do
    :io.put_chars(~c"done (warnings were emitted)\n")
    cl_check_log(output)
    :erlang.halt(r)
  end

  defp cl_halt({:error, msg1}, r_options(output_file: output)) do
    :io.format(~c"\ndialyzer: ~ts\n", [msg1])
    cl_check_log(output)
    :erlang.halt(1)
  end

  defp cl_check_log(:none) do
    :ok
  end

  defp cl_check_log(output) do
    :io.format(~c"  Check output file `~ts' for details\n", [output])
  end

  def format_warning(w) do
    format_warning(w, :basename)
  end

  def format_warning(rawWarning, fOpt) when is_atom(fOpt) do
    format_warning(rawWarning, [{:filename_opt, fOpt}])
  end

  def format_warning({tag, {file, location, _MFA}, msg}, opts) do
    format_warning({tag, {file, location}, msg}, opts)
  end

  def format_warning({_Tag, {file, location}, msg}, opts)
      when is_list(file) do
    f =
      case :proplists.get_value(:filename_opt, opts, :basename) do
        :fullpath ->
          file

        :basename ->
          :filename.basename(file)
      end

    indent = :proplists.get_value(:indent_opt, opts, true)
    errorLocation = :proplists.get_value(:error_location, opts, :column)
    string = message_to_string(msg, indent, errorLocation)
    posString = pos(location, errorLocation)

    :lists.flatten(
      :io_lib.format(
        ~c"~ts:~s: ~ts",
        [f, posString, string]
      )
    )
  end

  defp pos({line, _Column}, :line) do
    pos(line)
  end

  defp pos(location, _ErrorLocation) do
    pos(location)
  end

  defp pos({line, column})
       when is_integer(line) and
              is_integer(column) do
    :io_lib.format(~c"~w:~w", [line, column])
  end

  defp pos(line) when is_integer(line) do
    :io_lib.format(~c"~w", [line])
  end

  defp message_to_string({:apply, [args, argNs, failReason, sigArgs, sigRet, contract]}, i, _E) do
    :io_lib.format(
      ~c"Fun application with arguments ~ts ",
      [a(args, i)]
    ) ++ call_or_apply_to_string(argNs, failReason, sigArgs, sigRet, contract, i)
  end

  defp message_to_string({:app_call, [m, f, args, culprit, expectedType, foundType]}, i, _E) do
    :io_lib.format(
      ~c"The call ~s:~ts~ts requires that ~ts is of type ~ts not ~ts\n",
      [m, f, a(args, i), c(culprit, i), t(expectedType, i), t(foundType, i)]
    )
  end

  defp message_to_string({:bin_construction, [culprit, size, seg, type]}, i, _E) do
    :io_lib.format(
      ~c"Binary construction will fail since the ~ts field ~ts in segment ~ts has type ~ts\n",
      [culprit, c(size, i), c(seg, i), t(type, i)]
    )
  end

  defp message_to_string(
         {:call, [m, f, args, argNs, failReason, sigArgs, sigRet, contract]},
         i,
         _E
       ) do
    :io_lib.format(
      ~c"The call ~w:~tw~ts ",
      [m, f, a(args, i)]
    ) ++
      call_or_apply_to_string(
        argNs,
        failReason,
        sigArgs,
        sigRet,
        contract,
        i
      )
  end

  defp message_to_string({:call_to_missing, [m, f, a]}, _I, _E) do
    :io_lib.format(~c"Call to missing or unexported function ~w:~tw/~w\n", [m, f, a])
  end

  defp message_to_string({:exact_eq, [type1, op, type2]}, i, _E) do
    :io_lib.format(~c"The test ~ts ~s ~ts can never evaluate to 'true'\n", [
      t(type1, i),
      op,
      t(type2, i)
    ])
  end

  defp message_to_string({:fun_app_args, [argNs, args, type]}, i, _E) do
    positionString = form_position_string(argNs)

    :io_lib.format(
      ~c"Fun application with arguments ~ts will fail since the function has type ~ts, which differs in the ~s argument\n",
      [a(args, i), t(type, i), positionString]
    )
  end

  defp message_to_string({:fun_app_no_fun, [op, type, arity]}, i, _E) do
    :io_lib.format(
      ~c"Fun application will fail since ~ts :: ~ts is not a function of arity ~w\n",
      [op, t(type, i), arity]
    )
  end

  defp message_to_string({:guard_fail, []}, _I, _E) do
    ~c"Clause guard cannot succeed.\n"
  end

  defp message_to_string({:guard_fail, [arg1, infix, arg2]}, i, _E) do
    :io_lib.format(~c"Guard test ~ts ~s ~ts can never succeed\n", [a(arg1, i), infix, a(arg2, i)])
  end

  defp message_to_string({:map_update, [type, key]}, i, _E) do
    :io_lib.format(~c"A key of type ~ts cannot exist in a map of type ~ts\n", [
      t(key, i),
      t(type, i)
    ])
  end

  defp message_to_string({:neg_guard_fail, [arg1, infix, arg2]}, i, _E) do
    :io_lib.format(~c"Guard test not(~ts ~s ~ts) can never succeed\n", [
      a(arg1, i),
      infix,
      a(arg2, i)
    ])
  end

  defp message_to_string({:guard_fail, [guard, args]}, i, _E) do
    :io_lib.format(~c"Guard test ~s~ts can never succeed\n", [guard, a(args, i)])
  end

  defp message_to_string({:neg_guard_fail, [guard, args]}, i, _E) do
    :io_lib.format(~c"Guard test not(~s~ts) can never succeed\n", [guard, a(args, i)])
  end

  defp message_to_string({:guard_fail_pat, [pat, type]}, i, _E) do
    :io_lib.format(~c"Clause guard cannot succeed. The ~ts was matched against the type ~ts\n", [
      ps(pat, i),
      t(type, i)
    ])
  end

  defp message_to_string({:improper_list_constr, [tlType]}, i, _E) do
    :io_lib.format(~c"Cons will produce an improper list since its 2nd argument is ~ts\n", [
      t(tlType, i)
    ])
  end

  defp message_to_string({:no_return, [type | name]}, _I, _E) do
    nameString =
      case name do
        [] ->
          ~c"The created fun "

        [f, a] ->
          :io_lib.format(~c"Function ~tw/~w ", [f, a])
      end

    case type do
      :no_match ->
        nameString ++ ~c"has no clauses that will ever match\n"

      :only_explicit ->
        nameString ++ ~c"only terminates with explicit exception\n"

      :only_normal ->
        nameString ++ ~c"has no local return\n"

      :both ->
        nameString ++ ~c"has no local return\n"
    end
  end

  defp message_to_string({:record_constr, [recConstr, fieldDiffs]}, i, _E) do
    :io_lib.format(
      ~c"Record construction ~ts violates the declared type of field ~ts\n",
      [t(recConstr, i), field_diffs(fieldDiffs, i)]
    )
  end

  defp message_to_string({:record_constr, [name, field, type]}, i, _E) do
    :io_lib.format(
      ~c"Record construction violates the declared type for #~tw{} since ~ts cannot be of type ~ts\n",
      [name, ps(field, i), t(type, i)]
    )
  end

  defp message_to_string({:record_matching, [string, name]}, i, _E) do
    :io_lib.format(~c"The ~ts violates the declared type for #~tw{}\n", [
      rec_type(string, i),
      name
    ])
  end

  defp message_to_string({:record_match, [pat, type]}, i, _E) do
    :io_lib.format(
      ~c"Matching of ~ts tagged with a record name violates the declared type of ~ts\n",
      [ps(pat, i), t(type, i)]
    )
  end

  defp message_to_string({:pattern_match, [pat, type]}, i, _E) do
    :io_lib.format(~c"The ~ts can never match the type ~ts\n", [ps(pat, i), t(type, i)])
  end

  defp message_to_string({:pattern_match_cov, [pat, type]}, i, _E) do
    :io_lib.format(
      ~c"The ~ts can never match since previous clauses completely covered the type ~ts\n",
      [ps(pat, i), t(type, i)]
    )
  end

  defp message_to_string({:unmatched_return, [type]}, i, _E) do
    :io_lib.format(~c"Expression produces a value of type ~ts, but this value is unmatched\n", [
      t(type, i)
    ])
  end

  defp message_to_string({:unused_fun, [f, a]}, _I, _E) do
    :io_lib.format(~c"Function ~tw/~w will never be called\n", [f, a])
  end

  defp message_to_string({:contract_diff, [m, f, _A, contract, sig]}, i, _E) do
    :io_lib.format(
      ~c"Type specification ~ts is not equal to the success typing: ~ts\n",
      [con(m, f, contract, i), con(m, f, sig, i)]
    )
  end

  defp message_to_string({:contract_subtype, [m, f, _A, contract, sig]}, i, _E) do
    :io_lib.format(
      ~c"Type specification ~ts is a subtype of the success typing: ~ts\n",
      [con(m, f, contract, i), con(m, f, sig, i)]
    )
  end

  defp message_to_string({:contract_supertype, [m, f, _A, contract, sig]}, i, _E) do
    :io_lib.format(
      ~c"Type specification ~ts is a supertype of the success typing: ~ts\n",
      [con(m, f, contract, i), con(m, f, sig, i)]
    )
  end

  defp message_to_string({:contract_range, [contract, m, f, argStrings, location, cRet]}, i, e) do
    :io_lib.format(
      ~c"The contract ~ts cannot be right because the inferred return for ~tw~ts on position ~s is ~ts\n",
      [
        con(m, f, contract, i),
        f,
        a(argStrings, i),
        pos(location, e),
        t(
          cRet,
          i
        )
      ]
    )
  end

  defp message_to_string({:invalid_contract, [m, f, a, :none, contract, sig]}, i, _E) do
    :io_lib.format(
      ~c"Invalid type specification for function ~w:~tw/~w.\n The success typing is ~ts\n But the spec is ~ts\n",
      [m, f, a, con(m, f, sig, i), con(m, f, contract, i)]
    )
  end

  defp message_to_string(
         {:invalid_contract, [m, f, a, invalidContractDetails, contract, sig]},
         i,
         _E
       ) do
    :io_lib.format(
      ~c"Invalid type specification for function ~w:~tw/~w.\n The success typing is ~ts\n But the spec is ~ts\n~ts",
      [
        m,
        f,
        a,
        con(m, f, sig, i),
        con(m, f, contract, i),
        format_invalid_contract_details(invalidContractDetails)
      ]
    )
  end

  defp message_to_string({:contract_with_opaque, [m, f, a, opaqueType, sigType]}, i, _E) do
    :io_lib.format(
      ~c"The specification for ~w:~tw/~w has an opaque subtype ~ts which is violated by the success typing ~ts\n",
      [m, f, a, t(opaqueType, i), sig(sigType, i)]
    )
  end

  defp message_to_string({:extra_range, [m, f, a, extraRanges, sigRange]}, i, _E) do
    :io_lib.format(
      ~c"The specification for ~w:~tw/~w states that the function might also return ~ts but the inferred return is ~ts\n",
      [m, f, a, t(extraRanges, i), t(sigRange, i)]
    )
  end

  defp message_to_string({:missing_range, [m, f, a, extraRanges, contrRange]}, i, _E) do
    :io_lib.format(
      ~c"The success typing for ~w:~tw/~w implies that the function might also return ~ts but the specification return is ~ts\n",
      [m, f, a, t(extraRanges, i), t(contrRange, i)]
    )
  end

  defp message_to_string({:overlapping_contract, [m, f, a]}, _I, _E) do
    :io_lib.format(
      ~c"Overloaded contract for ~w:~tw/~w has overlapping domains; such contracts cannot establish a dependency between the overloaded input and output types\n",
      [m, f, a]
    )
  end

  defp message_to_string({:spec_missing_fun, [m, f, a]}, _I, _E) do
    :io_lib.format(~c"Contract for function that does not exist: ~w:~tw/~w\n", [m, f, a])
  end

  defp message_to_string({:call_with_opaque, [m, f, args, argNs, expArgs]}, i, _E) do
    :io_lib.format(
      ~c"The call ~w:~tw~ts contains ~ts when ~ts\n",
      [m, f, a(args, i), form_positions(argNs), form_expected(expArgs, i)]
    )
  end

  defp message_to_string({:call_without_opaque, [m, f, args, expectedTriples]}, i, _E) do
    :io_lib.format(
      ~c"The call ~w:~tw~ts does not have ~ts\n",
      [
        m,
        f,
        a(args, i),
        form_expected_without_opaque(
          expectedTriples,
          i
        )
      ]
    )
  end

  defp message_to_string({:opaque_eq, [type, _Op, opaqueType]}, i, _E) do
    :io_lib.format(
      ~c"Attempt to test for equality between a term of type ~ts and a term of opaque type ~ts\n",
      [t(type, i), t(opaqueType, i)]
    )
  end

  defp message_to_string({:opaque_guard, [arg1, infix, arg2, argNs]}, i, _E) do
    :io_lib.format(
      ~c"Guard test ~ts ~s ~ts contains ~s\n",
      [a(arg1, i), infix, a(arg2, i), form_positions(argNs)]
    )
  end

  defp message_to_string({:opaque_guard, [guard, args]}, i, _E) do
    :io_lib.format(~c"Guard test ~w~ts breaks the opacity of its argument\n", [guard, a(args, i)])
  end

  defp message_to_string({:opaque_match, [pat, opaqueType, opaqueTerm]}, i, _E) do
    term =
      cond do
        opaqueType === opaqueTerm ->
          ~c"the term"

        true ->
          t(opaqueTerm, i)
      end

    :io_lib.format(
      ~c"The attempt to match a term of type ~ts against the ~ts breaks the opacity of ~ts\n",
      [t(opaqueType, i), ps(pat, i), term]
    )
  end

  defp message_to_string({:opaque_neq, [type, _Op, opaqueType]}, i, _E) do
    :io_lib.format(
      ~c"Attempt to test for inequality between a term of type ~ts and a term of opaque type ~ts\n",
      [t(type, i), t(opaqueType, i)]
    )
  end

  defp message_to_string({:opaque_type_test, [fun, args, arg, argType]}, i, _E) do
    :io_lib.format(~c"The type test ~ts~ts breaks the opacity of the term ~ts~ts\n", [
      fun,
      a(args, i),
      arg,
      t(argType, i)
    ])
  end

  defp message_to_string({:opaque_size, [sizeType, size]}, i, _E) do
    :io_lib.format(~c"The size ~ts breaks the opacity of ~ts\n", [t(sizeType, i), c(size, i)])
  end

  defp message_to_string({:opaque_call, [m, f, args, culprit, opaqueType]}, i, _E) do
    :io_lib.format(
      ~c"The call ~s:~ts~ts breaks the opacity of the term ~ts :: ~ts\n",
      [m, f, a(args, i), c(culprit, i), t(opaqueType, i)]
    )
  end

  defp message_to_string({:callback_type_mismatch, [b, f, a, sT, cT]}, i, _E) do
    :io_lib.format(
      ~c"The inferred return type of ~tw/~w ~ts has nothing in common with ~ts, which is the expected return type for the callback of the ~w behaviour\n",
      [f, a, t(~c"(" ++ sT ++ ~c")", i), t(cT, i), b]
    )
  end

  defp message_to_string({:callback_arg_type_mismatch, [b, f, a, n, sT, cT]}, i, _E) do
    :io_lib.format(
      ~c"The inferred type for the ~s argument of ~tw/~w (~ts) has nothing in common with ~ts, which is expected type for this argument in the callback of the ~w behaviour\n",
      [ordinal(n), f, a, t(sT, i), t(cT, i), b]
    )
  end

  defp message_to_string({:callback_spec_type_mismatch, [b, f, a, sT, cT]}, i, _E) do
    :io_lib.format(
      ~c"The return type ~ts in the specification of ~tw/~w has nothing in common with ~ts, which is the expected return type for the callback of the ~w behaviour\n",
      [t(sT, i), f, a, t(cT, i), b]
    )
  end

  defp message_to_string({:callback_spec_arg_type_mismatch, [b, f, a, n, sT, cT]}, i, _E) do
    :io_lib.format(
      ~c"The specified type for the ~ts argument of ~tw/~w (~ts) has nothing in common with ~ts, which is expected type for this argument in the callback of the ~w behaviour\n",
      [ordinal(n), f, a, t(sT, i), t(cT, i), b]
    )
  end

  defp message_to_string({:callback_missing, [b, f, a]}, _I, _E) do
    :io_lib.format(~c"Undefined callback function ~tw/~w (behaviour ~w)\n", [f, a, b])
  end

  defp message_to_string({:callback_not_exported, [b, f, a]}, _I, _E) do
    :io_lib.format(~c"Callback function ~tw/~w exists but is not exported (behaviour ~w)\n", [
      f,
      a,
      b
    ])
  end

  defp message_to_string({:callback_info_missing, [b]}, _I, _E) do
    :io_lib.format(~c"Callback info about the ~w behaviour is not available\n", [b])
  end

  defp message_to_string({:unknown_type, {m, f, a}}, _I, _E) do
    :io_lib.format(~c"Unknown type ~w:~tw/~w\n", [m, f, a])
  end

  defp message_to_string({:unknown_function, {m, f, a}}, _I, _E) do
    :io_lib.format(~c"Unknown function ~w:~tw/~w\n", [m, f, a])
  end

  defp message_to_string({:unknown_behaviour, b}, _I, _E) do
    :io_lib.format(~c"Unknown behaviour ~w\n", [b])
  end

  defp format_invalid_contract_details({invalidArgIdxs, isRangeInvalid}) do
    argOrd = form_position_string(invalidArgIdxs)

    argDesc =
      case invalidArgIdxs do
        [] ->
          ~c""

        [_] ->
          :io_lib.format(~c"They do not overlap in the ~ts argument", [argOrd])

        [_ | _] ->
          :io_lib.format(~c"They do not overlap in the ~ts arguments", [argOrd])
      end

    rangeDesc =
      case isRangeInvalid do
        true ->
          ~c"return types do not overlap"

        false ->
          ~c""
      end

    case {argDesc, rangeDesc} do
      {~c"", ~c""} ->
        ~c""

      {~c"", [_ | _]} ->
        :io_lib.format(~c" The ~ts\n", [rangeDesc])

      {[_ | _], ~c""} ->
        :io_lib.format(~c" ~ts\n", [argDesc])

      {[_ | _], [_ | _]} ->
        :io_lib.format(~c" ~ts, and the ~ts\n", [argDesc, rangeDesc])
    end
  end

  defp call_or_apply_to_string(argNs, failReason, sigArgs, sigRet, {isOverloaded, contract}, i) do
    positionString = form_position_string(argNs)

    case failReason do
      :only_sig ->
        case argNs === [] do
          true ->
            :io_lib.format(~c"will never return since the success typing arguments are ~ts\n", [
              t(sigArgs, i)
            ])

          false ->
            :io_lib.format(
              ~c"will never return since it differs in the ~s argument from the success typing arguments: ~ts\n",
              [positionString, t(sigArgs, i)]
            )
        end

      :only_contract ->
        case argNs === [] or isOverloaded do
          true ->
            :io_lib.format(~c"breaks the contract ~ts\n", [sig(contract, i)])

          false ->
            :io_lib.format(~c"breaks the contract ~ts in the ~s argument\n", [
              sig(contract, i),
              positionString
            ])
        end

      :both ->
        :io_lib.format(
          ~c"will never return since the success typing is ~ts -> ~ts and the contract is ~ts\n",
          [t(sigArgs, i), t(sigRet, i), sig(contract, i)]
        )
    end
  end

  defp form_positions(argNs) do
    case argNs do
      [_] ->
        ~c"an opaque term as "

      [_, _ | _] ->
        ~c"opaque terms as "
    end ++
      form_position_string(argNs) ++
      case argNs do
        [_] ->
          ~c" argument"

        [_, _ | _] ->
          ~c" arguments"
      end
  end

  defp form_expected_without_opaque([{n, t, tStr}], i) do
    case :erl_types.t_is_opaque(t) do
      true ->
        :io_lib.format(~c"an opaque term of type ~ts as ", [t(tStr, i)])

      false ->
        :io_lib.format(~c"a term of type ~ts (with opaque subterms) as ", [t(tStr, i)])
    end ++ form_position_string([n]) ++ ~c" argument"
  end

  defp form_expected_without_opaque(expectedTriples, _I) do
    {argNs, _Ts, _TStrs} = :lists.unzip3(expectedTriples)
    ~c"opaque terms as " ++ form_position_string(argNs) ++ ~c" arguments"
  end

  defp form_expected(expectedArgs, i) do
    case expectedArgs do
      [t] ->
        tS = :erl_types.t_to_string(t)

        case :erl_types.t_is_opaque(t) do
          true ->
            :io_lib.format(~c"an opaque term of type ~ts is expected", [t(tS, i)])

          false ->
            :io_lib.format(~c"a structured term of type ~ts is expected", [t(tS, i)])
        end

      [_, _ | _] ->
        ~c"terms of different types are expected in these positions"
    end
  end

  defp form_position_string(argNs) do
    case argNs do
      [] ->
        ~c""

      [n1] ->
        ordinal(n1)

      [_, _ | _] ->
        [last | prevs] = :lists.reverse(argNs)

        ~c", " ++ head =
          :lists.flatten(
            for n <- :lists.reverse(prevs) do
              :io_lib.format(~c", ~s", [ordinal(n)])
            end
          )

        head ++ ~c" and " ++ ordinal(last)
    end
  end

  defp ordinal(n)
       when (is_integer(n) and
               rem(n, 100) === 11) or rem(n, 100) === 12 or rem(n, 100) === 13 do
    :io_lib.format(~c"~Bth", [n])
  end

  defp ordinal(n) when is_integer(n) do
    case min(rem(n, 10), 4) do
      1 ->
        :io_lib.format(~c"~Bst", [n])

      2 ->
        :io_lib.format(~c"~Bnd", [n])

      3 ->
        :io_lib.format(~c"~Brd", [n])

      _ ->
        :io_lib.format(~c"~Bth", [n])
    end
  end

  defp con(m, f, src, i) do
    s = sig(src, i)
    :io_lib.format(~c"~w:~tw~ts", [m, f, s])
  end

  defp sig(src, false) do
    src
  end

  defp sig(src, true) do
    try do
      str = :lists.flatten(:io_lib.format(~c"-spec ~w:~tw~ts.", [:a, :b, src]))
      {:ok, tokens, _EndLocation} = :erl_scan.string(str)
      {:ok, {:attribute, _, :spec, {_MFA, types}}} = :erl_parse.parse_form(tokens)
      indentation(10) ++ pp_spec(types)
    catch
      _, _ ->
        src
    end
  end

  defp a(~c"" = args, _I) do
    args
  end

  defp a(args, i) do
    t(args, i)
  end

  defp c(cerl, _I) do
    cerl
  end

  defp field_diffs(src, false) do
    src
  end

  defp field_diffs(src, true) do
    fields = :string.split(src, ~c" and ", :all)

    :lists.join(
      ~c" and ",
      for field <- fields do
        field_diff(field)
      end
    )
  end

  defp field_diff(field) do
    [f | ts] = :string.split(field, ~c"::", :all)
    f ++ ~c" ::" ++ t(:lists.flatten(:lists.join(~c"::", ts)), true)
  end

  defp rec_type(~c"record " ++ src, i) do
    ~c"record " ++ t(src, i)
  end

  defp ps(~c"pattern " ++ src, i) do
    ~c"pattern " ++ t(src, i)
  end

  defp ps(~c"variable " ++ _ = src, _I) do
    src
  end

  defp ps(~c"record field" ++ rest, i) do
    [s, typeStr] = :string.split(rest, ~c"of type ", :all)
    ~c"record field" ++ s ++ ~c"of type " ++ t(typeStr, i)
  end

  defp t(src, false) do
    src
  end

  defp t(~c"(" ++ _ = src, true) do
    ts(src)
  end

  defp t(src, true) do
    try do
      parse_type_or_literal(src)
    catch
      _, _ ->
        ts(src)
    else
      typeOrLiteral ->
        indentation(10) ++ pp_type(typeOrLiteral)
    end
  end

  defp ts(src) do
    ind = indentation(10)
    [c1 | src1] = src
    [c2 | revSrc2] = :lists.reverse(src1)
    src2 = :lists.reverse(revSrc2)

    try do
      types = parse_types_and_literals(src2)
      commaInd = [?, | ind]

      indentation(10 - 1) ++
        [
          c1
          | :lists.join(
              commaInd,
              for type <- types do
                pp_type(type)
              end
            )
        ] ++ [c2]
    catch
      _, _ ->
        src
    end
  end

  defp indentation(i) do
    [?\n | :lists.duplicate(i, ?\s)]
  end

  defp pp_type(type) do
    form = {:attribute, :erl_anno.new(0), :type, {:t, type, []}}

    typeDef =
      :erl_pp.form(
        form,
        [{:quote_singleton_atom_types, true}]
      )

    {:match, [s]} =
      :re.run(typeDef, "::\\s*(.*)\\.\\n*", [{:capture, :all_but_first, :list}, :dotall, :unicode])

    s
  end

  defp pp_spec(spec) do
    form = {:attribute, :erl_anno.new(0), :spec, {{:a, :b, 0}, spec}}

    sig =
      :erl_pp.form(
        form,
        [{:quote_singleton_atom_types, true}]
      )

    {:match, [s]} =
      :re.run(sig, "-spec a:b\\s*(.*)\\.\\n*", [
        {:capture, :all_but_first, :list},
        :dotall,
        :unicode
      ])

    s
  end

  defp parse_types_and_literals(src) do
    {:ok, tokens, _EndLocation} = :erl_scan.string(src)

    for ts <- types(tokens) do
      parse_a_type_or_literal(ts)
    end
  end

  defp parse_type_or_literal(src) do
    {:ok, tokens, _EndLocation} = :erl_scan.string(src)
    parse_a_type_or_literal(tokens)
  end

  defp parse_a_type_or_literal(ts0) do
    l = :erl_anno.new(1)
    ts = ts0 ++ [{:dot, l}]
    tokens = [{:-, l}, {:atom, l, :type}, {:atom, l, :t}, {:"(", l}, {:")", l}, {:"::", l}] ++ ts

    case :erl_parse.parse_form(tokens) do
      {:ok, {:attribute, _, :type, {:t, type, []}}} ->
        type

      {:error, _} ->
        {:ok, [t]} = :erl_parse.parse_exprs(ts)
        t
    end
  end

  defp types([]) do
    []
  end

  defp types(ts) do
    {ts0, ts1} = one_type(ts, [], [])
    [ts0 | types(ts1)]
  end

  defp one_type([], [], ts) do
    {:lists.reverse(ts), []}
  end

  defp one_type([{:",", _Lc} | toks], [], ts0) do
    {:lists.reverse(ts0), toks}
  end

  defp one_type([{:")", lrp} | toks], [], ts0) do
    {:lists.reverse(ts0), [{:")", lrp} | toks]}
  end

  defp one_type([{:"(", llp} | toks], e, ts0) do
    one_type(toks, [:")" | e], [{:"(", llp} | ts0])
  end

  defp one_type([{:"<<", lls} | toks], e, ts0) do
    one_type(toks, [:">>" | e], [{:"<<", lls} | ts0])
  end

  defp one_type([{:"[", lls} | toks], e, ts0) do
    one_type(toks, [:"]" | e], [{:"[", lls} | ts0])
  end

  defp one_type([{:"{", llc} | toks], e, ts0) do
    one_type(toks, [:"}" | e], [{:"{", llc} | ts0])
  end

  defp one_type([{rb, lrb} | toks], [rb | e], ts0) do
    one_type(toks, e, [{rb, lrb} | ts0])
  end

  defp one_type([t | toks], e, ts0) do
    one_type(toks, e, [t | ts0])
  end
end
