defmodule :m_typer_core do
  use Bitwise
  require Record
  Record.defrecord(:r_analysis, :analysis, mode: :undefined,
                                    macros: [], includes: [],
                                    codeserver: :dialyzer_codeserver.new(),
                                    callgraph: :dialyzer_callgraph.new(),
                                    files: [], plt: :none, no_spec: false,
                                    show_succ: false, edoc: false, fms: [],
                                    ex_func: :maps.new(), record: :maps.new(),
                                    func: :maps.new(), inc_func: :maps.new(),
                                    trust_plt: :dialyzer_plt.new(),
                                    io: default_io())
  Record.defrecord(:r_args, :args, files: [], files_r: [],
                                trusted: [])
  def run(opts) do
    {args, analysis} = process_cl_args(opts)
    msg(:debug, 'Opts: ~p\nArgs: ~p\nAnalysis: ~p', [opts, args, analysis], analysis)
    timer = :dialyzer_timing.init(false)
    trustedFiles = filter_fd(r_args(args, :trusted), [],
                               &is_erl_file/1, analysis)
    analysis2 = extract(analysis, trustedFiles)
    all_Files = get_all_files(args, analysis2)
    msg(:debug, 'All_Files: ~tp', [all_Files], analysis2)
    analysis3 = r_analysis(analysis2, files: all_Files)
    analysis4 = collect_info(analysis3)
    msg(:debug, 'Final: ~p', [r_analysis(analysis4, :fms)], analysis3)
    typeInfo = get_type_info(analysis4)
    :dialyzer_timing.stop(timer)
    show_or_annotate(typeInfo)
    msg(:debug, '\nTyper analysis finished', [], analysis4)
    :ok
  end

  defp extract(r_analysis(macros: macros, includes: includes,
              trust_plt: trustPLT) = analysis,
            trustedFiles) do
    msg(:debug, 'Extracting trusted typer info...', [], analysis)
    ds = (for {name, value} <- macros do
            {:d, name, value}
          end)
    codeServer = :dialyzer_codeserver.new()
    fun = fn file, cS ->
               allIncludes = [:filename.dirname(:filename.dirname(file)) |
                                  includes]
               is = (for dir <- allIncludes do
                       {:i, dir}
                     end)
               compOpts = :dialyzer_utils.src_compiler_opts() ++ is ++ ds
               case (:dialyzer_utils.get_core_from_src(file,
                                                         compOpts)) do
                 {:ok, core} ->
                   case (:dialyzer_utils.get_record_and_type_info(core)) do
                     {:ok, recDict} ->
                       mod = :erlang.list_to_atom(:filename.basename(file, '.erl'))
                       case (:dialyzer_utils.get_spec_info(mod, core,
                                                             recDict)) do
                         {:ok, specDict, cbDict} ->
                           cS1 = :dialyzer_codeserver.store_temp_records(mod,
                                                                           recDict,
                                                                           cS)
                           :dialyzer_codeserver.store_temp_contracts(mod,
                                                                       specDict,
                                                                       cbDict,
                                                                       cS1)
                         {:error, reason} ->
                           compile_error([reason], analysis)
                       end
                     {:error, reason} ->
                       compile_error([reason], analysis)
                   end
                 {:error, reason} ->
                   compile_error(reason, analysis)
               end
          end
    codeServer1 = :lists.foldl(fun, codeServer,
                                 trustedFiles)
    newCodeServer = (try do
                       codeServer2 = :dialyzer_utils.merge_types(codeServer1,
                                                                   trustPLT)
                       newExpTypes = :dialyzer_codeserver.get_temp_exported_types(codeServer1)
                       case (:sets.size(newExpTypes)) do
                         0 ->
                           :ok
                       end
                       codeServer3 = :dialyzer_codeserver.finalize_exported_types(newExpTypes,
                                                                                    codeServer2)
                       codeServer4 = :dialyzer_utils.process_record_remote_types(codeServer3)
                       :dialyzer_contracts.process_contract_remote_types(codeServer4)
                     catch
                       {:error, errorMsg} ->
                         compile_error(errorMsg, analysis)
                     end)
    contractsDict = :dialyzer_codeserver.get_contracts(newCodeServer)
    contracts = :orddict.from_list(:dict.to_list(contractsDict))
    newTrustPLT = :dialyzer_plt.insert_contract_list(trustPLT,
                                                       contracts)
    r_analysis(analysis, trust_plt: newTrustPLT)
  end

  defp get_type_info(r_analysis(callgraph: callGraph, trust_plt: trustPLT,
              codeserver: codeServer) = analysis) do
    strippedCallGraph = remove_external(callGraph, trustPLT,
                                          analysis)
    msg(:debug, 'Analyizing callgraph...', [], analysis)
    try do
      newPlt = :dialyzer_succ_typings.analyze_callgraph(strippedCallGraph,
                                                          trustPLT, codeServer,
                                                          :none, [])
      r_analysis(analysis, callgraph: strippedCallGraph, 
                    trust_plt: newPlt)
    catch
      :error, what ->
        fatal_error(:io_lib.format('Analysis failed with message: ~tp', [{what, __STACKTRACE__}]),
                      analysis)
      {:dialyzer_succ_typing_error, msg} ->
        fatal_error(:io_lib.format('Analysis failed with message: ~ts', [msg]), analysis)
    end
  end

  defp remove_external(callGraph, pLT, analysis) do
    {strippedCG0,
       ext} = :dialyzer_callgraph.remove_external(callGraph)
    case (get_external(ext, pLT)) do
      [] ->
        :ok
      externals ->
        msg(:warn, ' Unknown functions: ~tp', [:lists.usort(externals)], analysis)
        extTypes = rcv_ext_types()
        case (extTypes) do
          [] ->
            :ok
          _ ->
            msg(:warn, ' Unknown types: ~tp', [extTypes], analysis)
        end
    end
    strippedCG0
  end

  defp get_external(exts, plt) do
    fun = fn {_From, to = {m, f, a}}, acc ->
               case (:dialyzer_plt.contains_mfa(plt, to)) do
                 false ->
                   case (:erl_bif_types.is_known(m, f, a)) do
                     true ->
                       acc
                     false ->
                       [to | acc]
                   end
                 true ->
                   acc
               end
          end
    :lists.foldl(fun, [], exts)
  end

  Record.defrecord(:r_info, :info, records: :maps.new(),
                                functions: [], types: :maps.new(), edoc: false)
  Record.defrecord(:r_inc, :inc, map: :maps.new(), filter: [])
  defp show_or_annotate(r_analysis(mode: mode, fms: files) = analysis) do
    case (mode) do
      :show ->
        show(analysis)
      :show_exported ->
        show(analysis)
      ^mode when mode == :annotate or
                   mode == :annotate_in_place
                 ->
        fun = fn {file, module} ->
                   info = get_final_info(file, module, analysis)
                   write_typed_file(file, info, analysis)
              end
        :lists.foreach(fun, files)
      :annotate_inc_files ->
        incInfo = write_and_collect_inc_info(analysis)
        write_inc_files(incInfo, analysis)
    end
  end

  defp write_and_collect_inc_info(analysis) do
    fun = fn {file, module}, inc ->
               info = get_final_info(file, module, analysis)
               write_typed_file(file, info, analysis)
               incFuns = get_inc_functions(file, analysis)
               collect_imported_functions(incFuns, r_info(info, :types),
                                            inc, analysis)
          end
    newInc = :lists.foldl(fun, r_inc(), r_analysis(analysis, :fms))
    clean_inc(newInc)
  end

  defp write_inc_files(inc, analysis) do
    fun = fn file ->
               val = :maps.get(file, r_inc(inc, :map), :none)
               functions = (for {key, _} <- val do
                              key
                            end)
               val1 = (for {{_Line, f, a}, type} <- val do
                         {{f, a}, type}
                       end)
               info = r_info(types: :maps.from_list(val1),
                          records: :maps.new(),
                          functions: :lists.keysort(1, functions))
               msg(:debug, 'Types ~tp', [r_info(info, :types)], analysis)
               msg(:debug, 'Functions ~tp', [r_info(info, :functions)], analysis)
               msg(:debug, 'Records ~tp', [r_info(info, :records)], analysis)
               write_typed_file(file, info, analysis)
          end
    :lists.foreach(fun, :maps.keys(r_inc(inc, :map)))
  end

  defp show(analysis) do
    fun = fn {file, module} ->
               info = get_final_info(file, module, analysis)
               show_type_info(file, info, analysis)
          end
    :lists.foreach(fun, r_analysis(analysis, :fms))
  end

  defp get_final_info(file, module, analysis) do
    records = get_records(file, analysis)
    types = get_types(module, analysis, records)
    functions = get_functions(file, analysis)
    edoc = r_analysis(analysis, :edoc)
    r_info(records: records, functions: functions, types: types,
        edoc: edoc)
  end

  defp collect_imported_functions(functions, types, inc, analysis) do
    fun = fn {file, _} = obj, i ->
               case (is_yecc_gen(file, i)) do
                 {true, newI} ->
                   newI
                 {false, newI} ->
                   check_imported_functions(obj, newI, types, analysis)
               end
          end
    :lists.foldl(fun, inc, functions)
  end

  defp is_yecc_gen(file, r_inc(filter: fs) = inc) do
    case (:lists.member(file, fs)) do
      true ->
        {true, inc}
      false ->
        case (:filename.extension(file)) do
          '.yrl' ->
            rootname = :filename.rootname(file, '.yrl')
            obj = rootname ++ '.erl'
            case (:lists.member(obj, fs)) do
              true ->
                {true, inc}
              false ->
                newInc = r_inc(inc, filter: [obj | fs])
                {true, newInc}
            end
          _ ->
            case (:filename.basename(file)) do
              'yeccpre.hrl' ->
                {true, inc}
              _ ->
                {false, inc}
            end
        end
    end
  end

  defp check_imported_functions({file, {line, f, a}}, inc, types, analysis) do
    incMap = r_inc(inc, :map)
    fA = {f, a}
    type = get_type_info(fA, types, analysis)
    case (incMap) do
      %{^file => val} ->
        case (:lists.keyfind(fA, 1, val)) do
          false ->
            r_inc(inc, map: Map.put(incMap, file,
                                          val ++ [{fA, {line, type}}]))
          {^fA, {_, ^type}} ->
            inc
          _ ->
            inc_warning(fA, file, analysis)
            elem = :lists.keydelete(fA, 1, val)
            newMap = (case (elem) do
                        [] ->
                          :maps.remove(file, incMap)
                        _ ->
                          Map.put(incMap, file, elem)
                      end)
            r_inc(inc, map: newMap)
        end
      _ ->
        newMap = Map.put(incMap, file, [{fA, {line, type}}])
        r_inc(inc, map: newMap)
    end
  end

  defp inc_warning({f, a}, file, analysis) do
    msg(:warn, '      ***Warning: Skip function ~tp/~p in file ~tp because of inconsistent type', [f, a, file], analysis)
  end

  defp clean_inc(inc) do
    inc1 = remove_yecc_generated_file(inc)
    normalize_obj(inc1)
  end

  defp remove_yecc_generated_file(r_inc(filter: filter) = inc) do
    fun = fn key, r_inc(map: map) = i ->
               r_inc(i, map: :maps.remove(key, map))
          end
    :lists.foldl(fun, inc, filter)
  end

  defp normalize_obj(tmpInc) do
    fun = fn key, val, inc ->
               newVal = (for {{f, a}, {line, type}} <- val do
                           {{line, f, a}, type}
                         end)
               Map.put(inc, key, newVal)
          end
    r_inc(tmpInc, map: :maps.fold(fun, :maps.new(),
                                r_inc(tmpInc, :map)))
  end

  defp get_records(file, analysis) do
    :maps.get(file, r_analysis(analysis, :record), :none)
  end

  defp get_types(module, analysis, records) do
    typeInfoPlt = r_analysis(analysis, :trust_plt)
    typeInfo = (case (:dialyzer_plt.lookup_module(typeInfoPlt,
                                                    module)) do
                  :none ->
                    []
                  {:value, list} ->
                    list
                end)
    codeServer = r_analysis(analysis, :codeserver)
    typeInfoList = (case (r_analysis(analysis, :show_succ)) do
                      true ->
                        for i <- typeInfo do
                          convert_type_info(i)
                        end
                      false ->
                        for i <- typeInfo do
                          get_type(i, codeServer, records, analysis)
                        end
                    end)
    :maps.from_list(typeInfoList)
  end

  defp convert_type_info({{_M, f, a}, range, arg}) do
    {{f, a}, {range, arg}}
  end

  defp get_type({{m, f, a} = mFA, range, arg}, codeServer,
            records, analysis) do
    case (:dialyzer_codeserver.lookup_mfa_contract(mFA,
                                                     codeServer)) do
      :error ->
        {{f, a}, {range, arg}}
      {:ok, {_FileLine, contract, _Xtra}} ->
        sig = :erl_types.t_fun(arg, range)
        case (:dialyzer_contracts.check_contract(contract,
                                                   sig)) do
          :ok ->
            {{f, a}, {:contract, contract}}
          {:range_warnings, _} ->
            {{f, a}, {:contract, contract}}
          {:error, {:overlapping_contract, []}} ->
            {{f, a}, {:contract, contract}}
          {:error, {:invalid_contract, _}} ->
            cString = :dialyzer_contracts.contract_to_string(contract)
            sigString = :dialyzer_utils.format_sig(sig, records)
            msg = :io_lib.format('Error in contract of function ~w:~tw/~w\n\t The contract is: ' ++ cString ++ '\n' ++ '\t but the inferred signature is: ~ts',
                                   [m, f, a, sigString])
            fatal_error(msg, analysis)
          {:error, errorStr} when is_list(errorStr) ->
            msg = :io_lib.format('Error in contract of function ~w:~tw/~w: ~ts', [m, f, a, errorStr])
            fatal_error(msg, analysis)
        end
    end
  end

  defp get_functions(file, analysis) do
    case (r_analysis(analysis, :mode)) do
      :show ->
        funcs = :maps.get(file, r_analysis(analysis, :func), :none)
        incFuncs = :maps.get(file, r_analysis(analysis, :inc_func),
                               :none)
        remove_module_info(funcs) ++ normalize_inc_funcs(incFuncs)
      :show_exported ->
        exFuncs = :maps.get(file, r_analysis(analysis, :ex_func), :none)
        remove_module_info(exFuncs)
      mode when mode == :annotate or
                  mode == :annotate_in_place
                ->
        funcs = :maps.get(file, r_analysis(analysis, :func), :none)
        remove_module_info(funcs)
      :annotate_inc_files ->
        normalize_inc_funcs(:maps.get(file,
                                        r_analysis(analysis, :inc_func), :none))
    end
  end

  defp get_inc_functions(file, analysis) do
    case (r_analysis(analysis, :mode)) do
      :show ->
        funcs = :maps.get(file, r_analysis(analysis, :func), :none)
        incFuncs = :maps.get(file, r_analysis(analysis, :inc_func),
                               :none)
        extend_functions(file,
                           remove_module_info(funcs)) ++ incFuncs
      :show_exported ->
        exFuncs = :maps.get(file, r_analysis(analysis, :ex_func), :none)
        extend_functions(file, remove_module_info(exFuncs))
      mode
          when mode === :annotate or mode === :annotate_in_place
               ->
        funcs = :maps.get(file, r_analysis(analysis, :func), :none)
        extend_functions(file, remove_module_info(funcs))
      :annotate_inc_files ->
        :maps.get(file, r_analysis(analysis, :inc_func), :none)
    end
  end

  defp extend_functions(fileName, functions) do
    for funInfo <- functions do
      {fileName, funInfo}
    end
  end

  defp normalize_inc_funcs(functions) do
    for {_FileName, funInfo} <- functions do
      funInfo
    end
  end

  defp remove_module_info(funInfoList) do
    f = fn {_, :module_info, 0} ->
             false
           {_, :module_info, 1} ->
             false
           {line, f, a} when (is_integer(line) and is_atom(f) and
                                is_integer(a))
                             ->
             true
        end
    :lists.filter(f, funInfoList)
  end

  defp write_typed_file(file, info, analysis) do
    msg(:info, '      Processing file: ~tp', [file], analysis)
    dir = :filename.dirname(file)
    rootName = :filename.basename(:filename.rootname(file))
    ext = :filename.extension(file)
    case (r_analysis(analysis, :mode)) do
      :annotate_in_place ->
        write_typed_file(file, info, file, analysis)
      _ ->
        typerAnnDir = :filename.join(dir, 'typer_ann')
        tmpNewFilename = :lists.concat([rootName, '.ann', ext])
        newFileName = :filename.join(typerAnnDir,
                                       tmpNewFilename)
        case (:file.make_dir(typerAnnDir)) do
          {:error, reason} ->
            case (reason) do
              :eexist ->
                delete_file(newFileName, analysis)
                write_typed_file(file, info, newFileName, analysis)
              :enospc ->
                msg = :io_lib.format('Not enough space in ~tp', [dir])
                fatal_error(msg, analysis)
              :eacces ->
                msg = :io_lib.format('No write permission in ~tp', [dir])
                fatal_error(msg, analysis)
              _ ->
                msg = :io_lib.format('Unhandled error ~ts when writing ~tp', [reason, dir])
                fatal_error(msg, analysis)
            end
          :ok ->
            write_typed_file(file, info, newFileName, analysis)
        end
    end
  end

  defp delete_file(file, analysis) do
    case (:file.delete(file)) do
      :ok ->
        :ok
      {:error, :enoent} ->
        :ok
      {:error, _} ->
        msg = :io_lib.format('Error in deleting file ~ts', [file])
        fatal_error(msg, analysis)
    end
  end

  defp write_typed_file(file, info, newFileName, analysis) do
    {:ok, binary} = :file.read_file(file)
    case (r_analysis(analysis, :mode)) do
      :annotate_in_place ->
        delete_file(newFileName, analysis)
      _ ->
        :ok
    end
    chars = :unicode.characters_to_list(binary)
    write_typed_file(chars, newFileName, info, 1, [],
                       analysis)
    msg(:info, '             Saved as: ~tp', [newFileName], analysis)
  end

  defp write_typed_file(chars, file, r_info(functions: []), _LNo, _Acc,
            _Analysis) do
    :ok = :file.write_file(file,
                             :unicode.characters_to_binary(chars), [:append])
  end

  defp write_typed_file([ch | chs] = chars, file, info, lineNo, acc,
            analysis) do
    [{line, f, a} | restFuncs] = r_info(info, :functions)
    case (line) do
      1 ->
        :ok = raw_write(f, a, info, file, [], analysis)
        newInfo = r_info(info, functions: restFuncs)
        newAcc = []
        write_typed_file(chars, file, newInfo, line, newAcc,
                           analysis)
      _ ->
        case (ch) do
          10 ->
            newLineNo = lineNo + 1
            {newInfo, newAcc} = (case (newLineNo) do
                                   ^line ->
                                     :ok = raw_write(f, a, info, file,
                                                       [ch | acc], analysis)
                                     {r_info(info, functions: restFuncs), []}
                                   _ ->
                                     {info, [ch | acc]}
                                 end)
            write_typed_file(chs, file, newInfo, newLineNo, newAcc,
                               analysis)
          _ ->
            write_typed_file(chs, file, info, lineNo, [ch | acc],
                               analysis)
        end
    end
  end

  defp raw_write(f, a, info, file, content,
            r_analysis(mode: mode) = analysis) do
    typeInfo = get_type_string(f, a, info, :file, analysis)
    contentList = (case ({typeInfo, mode}) do
                     {'', :annotate_in_place} ->
                       :lists.reverse(content) ++ typeInfo
                     _ ->
                       :lists.reverse(content) ++ typeInfo ++ '\n'
                   end)
    contentBin = :unicode.characters_to_binary(contentList)
    :file.write_file(file, contentBin, [:append])
  end

  defp get_type_string(f, a, info, mode, analysis) do
    type = get_type_info({f, a}, r_info(info, :types), analysis)
    typeStr = (case (type) do
                 {:contract, c} ->
                   :dialyzer_contracts.contract_to_string(c)
                 {retType, argType} ->
                   sig = :erl_types.t_fun(argType, retType)
                   :dialyzer_utils.format_sig(sig, r_info(info, :records))
               end)
    case (r_info(info, :edoc)) do
      false ->
        case ({mode, type}) do
          {:file, {:contract, _}} ->
            ''
          _ ->
            prefix = :lists.concat(['-spec ',
                                        :erl_types.atom_to_string(f)])
            :lists.concat([prefix, typeStr, '.'])
        end
      true ->
        prefix = :lists.concat(['%% @spec ', f])
        :lists.concat([prefix, typeStr, '.'])
    end
  end

  defp show_type_info(file, info, analysis) do
    msg(:info, '\n%% File: ~tp', [file], analysis)
    outputString = :lists.concat(['~.', length(file) + 8, 'c'])
    msg(:info, [?%, ?%, ?\s | outputString], [?-], analysis)
    fun = fn {_LineNo, f, a} ->
               typeInfo = get_type_string(f, a, info, :show, analysis)
               msg(:info, '~ts', [typeInfo], analysis)
          end
    :lists.foreach(fun, r_info(info, :functions))
  end

  defp get_type_info(func, types, analysis) do
    case (types) do
      %{^func => {:contract, _Fun} = c} ->
        c
      %{^func => {_RetType, _ArgType} = rA} ->
        rA
      _ ->
        msg = :io_lib.format('No type info for function: ~tp\n', [func])
        fatal_error(msg, analysis)
    end
  end

  defp process_cl_args(opts) do
    analyze_args(:maps.to_list(opts), r_args(), r_analysis())
  end

  defp analyze_args([], args, analysis) do
    {args, analysis}
  end

  defp analyze_args([result | rest], args, analysis) do
    {newArgs, newAnalysis} = analyze_result(result, args,
                                              analysis)
    analyze_args(rest, newArgs, newAnalysis)
  end

  defp analyze_result({:files, val}, args, analysis) do
    newVal = r_args(args, :files) ++ val
    {r_args(args, files: newVal), analysis}
  end

  defp analyze_result({:files_r, val}, args, analysis) do
    newVal = r_args(args, :files_r) ++ val
    {r_args(args, files_r: newVal), analysis}
  end

  defp analyze_result({:trusted, val}, args, analysis) do
    newVal = r_args(args, :trusted) ++ val
    {r_args(args, trusted: newVal), analysis}
  end

  defp analyze_result({:edoc, value}, args, analysis) do
    {args, r_analysis(analysis, edoc: value)}
  end

  defp analyze_result({:io, val}, args, analysis) do
    {args, r_analysis(analysis, io: val)}
  end

  defp analyze_result({:mode, mode}, args, analysis) do
    {args, r_analysis(analysis, mode: mode)}
  end

  defp analyze_result({:macros, macros}, args, analysis) do
    {args, r_analysis(analysis, macros: macros)}
  end

  defp analyze_result({:includes, includes}, args, analysis) do
    {args, r_analysis(analysis, includes: includes)}
  end

  defp analyze_result({:plt, plt}, args, analysis) do
    {args, r_analysis(analysis, plt: plt)}
  end

  defp analyze_result({:show_succ, value}, args, analysis) do
    {args, r_analysis(analysis, show_succ: value)}
  end

  defp analyze_result({:no_spec, value}, args, analysis) do
    {args, r_analysis(analysis, no_spec: value)}
  end

  defp get_all_files(r_args(files: fs, files_r: ds), analysis) do
    case (filter_fd(fs, ds, &test_erl_file_exclude_ann/1,
                      analysis)) do
      [] ->
        fatal_error('no file(s) to analyze', analysis)
      allFiles ->
        allFiles
    end
  end

  defp test_erl_file_exclude_ann(file) do
    case (is_erl_file(file)) do
      true ->
        case (:re.run(file, '[.]ann[.]erl$', [:unicode])) do
          {:match, _} ->
            false
          :nomatch ->
            true
        end
      false ->
        false
    end
  end

  defp is_erl_file(file) do
    :filename.extension(file) === '.erl'
  end

  defp filter_fd(file_Dir, dir_R, fun, analysis) do
    all_File_1 = process_file_and_dir(file_Dir, fun,
                                        analysis)
    all_File_2 = process_dir_rec(dir_R, fun, analysis)
    remove_dup(all_File_1 ++ all_File_2)
  end

  defp process_file_and_dir(file_Dir, testFun, analysis) do
    fun = fn elem, acc ->
               case (:filelib.is_regular(elem)) do
                 true ->
                   process_file(elem, testFun, acc)
                 false ->
                   check_dir(elem, false, acc, testFun, analysis)
               end
          end
    :lists.foldl(fun, [], file_Dir)
  end

  defp process_dir_rec(dirs, testFun, analysis) do
    fun = fn dir, acc ->
               check_dir(dir, true, acc, testFun, analysis)
          end
    :lists.foldl(fun, [], dirs)
  end

  defp check_dir(dir, recursive, acc, fun, analysis) do
    case (:file.list_dir(dir)) do
      {:ok, files} ->
        {tmpDirs, tmpFiles} = split_dirs_and_files(files, dir)
        case (recursive) do
          false ->
            finalFiles = process_file_and_dir(tmpFiles, fun,
                                                analysis)
            acc ++ finalFiles
          true ->
            tmpAcc1 = process_file_and_dir(tmpFiles, fun, analysis)
            tmpAcc2 = process_dir_rec(tmpDirs, fun, analysis)
            acc ++ tmpAcc1 ++ tmpAcc2
        end
      {:error, :eacces} ->
        fatal_error('no access permission to dir "' ++ dir ++ '"', analysis)
      {:error, :enoent} ->
        fatal_error('cannot access ' ++ dir ++ ': No such file or directory', analysis)
      {:error, _Reason} ->
        fatal_error('error involving a use of file:list_dir/1', analysis)
    end
  end

  defp process_file(file, testFun, acc) do
    case (testFun.(file)) do
      true ->
        acc ++ [file]
      false ->
        acc
    end
  end

  defp split_dirs_and_files(elems, dir) do
    test_Fun = fn elem, {dirAcc, fileAcc} ->
                    file = :filename.join(dir, elem)
                    case (:filelib.is_regular(file)) do
                      false ->
                        {[file | dirAcc], fileAcc}
                      true ->
                        {dirAcc, [file | fileAcc]}
                    end
               end
    {dirs, files} = :lists.foldl(test_Fun, {[], []}, elems)
    {:lists.reverse(dirs), :lists.reverse(files)}
  end

  defp remove_dup(files) do
    test_Dup = fn file, acc ->
                    case (:lists.member(file, acc)) do
                      true ->
                        acc
                      false ->
                        [file | acc]
                    end
               end
    reversed_Elems = :lists.foldl(test_Dup, [], files)
    :lists.reverse(reversed_Elems)
  end

  Record.defrecord(:r_tmpAcc, :tmpAcc, file: :undefined,
                                  module: :undefined, funcAcc: [],
                                  incFuncAcc: [], dialyzerObj: [])
  defp collect_info(analysis) do
    newPlt = (try do
                get_dialyzer_plt(analysis)
              catch
                {:dialyzer_error, _Reason} ->
                  fatal_error('Dialyzer\'s PLT is missing or is not up-to-date; please (re)create it', analysis)
              else
                dialyzerPlt ->
                  :dialyzer_plt.merge_plts([r_analysis(analysis, :trust_plt),
                                                dialyzerPlt])
              end)
    newAnalysis = :lists.foldl(&collect_one_file_info/2,
                                 r_analysis(analysis, trust_plt: newPlt),
                                 r_analysis(analysis, :files))
    tmpCServer = r_analysis(newAnalysis, :codeserver)
    newCServer = (try do
                    tmpCServer1 = :dialyzer_utils.merge_types(tmpCServer,
                                                                newPlt)
                    newExpTypes = :dialyzer_codeserver.get_temp_exported_types(tmpCServer)
                    oldExpTypes = :dialyzer_plt.get_exported_types(newPlt)
                    mergedExpTypes = :sets.union(newExpTypes, oldExpTypes)
                    tmpCServer2 = :dialyzer_codeserver.finalize_exported_types(mergedExpTypes,
                                                                                 tmpCServer1)
                    tmpCServer3 = :dialyzer_utils.process_record_remote_types(tmpCServer2)
                    :dialyzer_contracts.process_contract_remote_types(tmpCServer3)
                  catch
                    {:error, errorMsg} ->
                      fatal_error(errorMsg, newAnalysis)
                  end)
    r_analysis(newAnalysis, codeserver: newCServer)
  end

  defp collect_one_file_info(file, analysis) do
    ds = (for {name, val} <- r_analysis(analysis, :macros) do
            {:d, name, val}
          end)
    includes = [:filename.dirname(file) |
                    r_analysis(analysis, :includes)]
    is = (for dir <- includes do
            {:i, dir}
          end)
    options = :dialyzer_utils.src_compiler_opts() ++ is ++ ds
    case (:dialyzer_utils.get_core_from_src(file,
                                              options)) do
      {:error, reason} ->
        msg(:debug, 'File=~tp\n,Options=~p\n,Error=~p', [file, options, reason], analysis)
        compile_error(reason, analysis)
      {:ok, core} ->
        case (:dialyzer_utils.get_record_and_type_info(core)) do
          {:error, reason} ->
            compile_error([reason], analysis)
          {:ok, records} ->
            mod = :cerl.concrete(:cerl.module_name(core))
            case (:dialyzer_utils.get_spec_info(mod, core,
                                                  records)) do
              {:error, reason} ->
                compile_error([reason], analysis)
              {:ok, specInfo, cbInfo} ->
                expTypes = get_exported_types_from_core(core)
                analyze_core_tree(core, records, specInfo, cbInfo,
                                    expTypes, analysis, file)
            end
        end
    end
  end

  defp analyze_core_tree(core, records, specInfo, cbInfo, expTypes,
            analysis, file) do
    module = :cerl.concrete(:cerl.module_name(core))
    tmpTree = :cerl.from_records(core)
    cS1 = r_analysis(analysis, :codeserver)
    nextLabel = :dialyzer_codeserver.get_next_core_label(cS1)
    {tree, newLabel} = :cerl_trees.label(tmpTree, nextLabel)
    cS2 = :dialyzer_codeserver.insert(module, tree, cS1)
    cS3 = :dialyzer_codeserver.set_next_core_label(newLabel,
                                                     cS2)
    cS4 = :dialyzer_codeserver.store_temp_records(module,
                                                    records, cS3)
    cS5 = (case (r_analysis(analysis, :no_spec)) do
             true ->
               cS4
             false ->
               :dialyzer_codeserver.store_temp_contracts(module,
                                                           specInfo, cbInfo,
                                                           cS4)
           end)
    oldExpTypes = :dialyzer_codeserver.get_temp_exported_types(cS5)
    mergedExpTypes = :sets.union(expTypes, oldExpTypes)
    cS6 = :dialyzer_codeserver.insert_temp_exported_types(mergedExpTypes,
                                                            cS5)
    exFuncs = (for {_, _,
                      {f, a}} <- :cerl.module_exports(tree) do
                 {0, f, a}
               end)
    cG = r_analysis(analysis, :callgraph)
    {v, e} = :dialyzer_callgraph.scan_core_tree(tree, cG)
    :dialyzer_callgraph.add_edges(e, v, cG)
    fun = &analyze_one_function/2
    all_Defs = :cerl.module_defs(tree)
    acc = :lists.foldl(fun, r_tmpAcc(file: file, module: module),
                         all_Defs)
    exportedFuncMap = :maps.put(file, exFuncs,
                                  r_analysis(analysis, :ex_func))
    sortedFunctions = :lists.keysort(1, r_tmpAcc(acc, :funcAcc))
    funcMap = :maps.put(file, sortedFunctions,
                          r_analysis(analysis, :func))
    incFuncMap = :maps.put(file, r_tmpAcc(acc, :incFuncAcc),
                             r_analysis(analysis, :inc_func))
    fMs = r_analysis(analysis, :fms) ++ [{file, module}]
    recordMap = :maps.put(file, records,
                            r_analysis(analysis, :record))
    r_analysis(analysis, fms: fMs,  callgraph: cG,  codeserver: cS6, 
                  ex_func: exportedFuncMap,  inc_func: incFuncMap, 
                  record: recordMap,  func: funcMap)
  end

  defp analyze_one_function({var, funBody} = function, acc) do
    f = :cerl.fname_id(var)
    a = :cerl.fname_arity(var)
    tmpDialyzerObj = {{r_tmpAcc(acc, :module), f, a}, function}
    newDialyzerObj = r_tmpAcc(acc, :dialyzerObj) ++ [tmpDialyzerObj]
    anno = :cerl.get_ann(funBody)
    lineNo = get_line(anno)
    fileName = get_file(anno)
    baseName = :filename.basename(fileName)
    funcInfo = {lineNo, f, a}
    originalName = r_tmpAcc(acc, :file)
    {funcAcc,
       incFuncAcc} = (case (fileName === originalName or baseName === originalName) do
                        true ->
                          {r_tmpAcc(acc, :funcAcc) ++ [funcInfo], r_tmpAcc(acc, :incFuncAcc)}
                        false ->
                          {r_tmpAcc(acc, :funcAcc),
                             r_tmpAcc(acc, :incFuncAcc) ++ [{fileName, funcInfo}]}
                      end)
    r_tmpAcc(acc, funcAcc: funcAcc,  incFuncAcc: incFuncAcc, 
             dialyzerObj: newDialyzerObj)
  end

  defp get_line([line | _]) when is_integer(line) do
    line
  end

  defp get_line([{line, _Column} | _Tail])
      when is_integer(line) do
    line
  end

  defp get_line([_ | tail]) do
    get_line(tail)
  end

  defp get_line([]) do
    - 1
  end

  defp get_file([{:file, file} | _]) do
    file
  end

  defp get_file([_ | t]) do
    get_file(t)
  end

  defp get_file([]) do
    'no_file'
  end

  defp get_dialyzer_plt(r_analysis(plt: pltFile0) = analysis) do
    pltFile = (case (pltFile0 === :none) do
                 true ->
                   case (:filelib.is_regular(:dialyzer_cplt.get_default_cplt_filename())) do
                     true ->
                       :dialyzer_cplt.get_default_cplt_filename()
                     false ->
                       case (:filelib.is_regular(:dialyzer_iplt.get_default_iplt_filename())) do
                         true ->
                           :dialyzer_iplt.get_default_iplt_filename()
                         false ->
                           fatal_error('No PLT file given, and no existing PLT was found at default locations ' ++ :dialyzer_cplt.get_default_cplt_filename() ++ ' and ' ++ :dialyzer_iplt.get_default_iplt_filename(),
                                         analysis)
                       end
                   end
                 false ->
                   pltFile0
               end)
    case (:dialyzer_plt.plt_kind(pltFile)) do
      :cplt ->
        :dialyzer_cplt.from_file(pltFile)
      :iplt ->
        :dialyzer_iplt.from_file(pltFile)
      :bad_file ->
        fatal_error('Invalid PLT file at path ' ++ pltFile, analysis)
      :no_file ->
        fatal_error('No PLT file found at path ' ++ pltFile, analysis)
    end
  end

  defp get_exported_types_from_core(core) do
    attrs = :cerl.module_attrs(core)
    expTypes1 = (for {l1, l2} <- attrs,
                       :cerl.is_literal(l1), :cerl.is_literal(l2),
                       :cerl.concrete(l1) === :export_type do
                   :cerl.concrete(l2)
                 end)
    expTypes2 = :lists.flatten(expTypes1)
    m = :cerl.atom_val(:cerl.module_name(core))
    :sets.from_list(for {f, a} <- expTypes2 do
                      {m, f, a}
                    end)
  end

  defp default_io() do
    %{debug: &swallow_output/2, info: &format/2,
        warn: &format_on_stderr/2, abort: &format_and_halt/2}
  end

  defp fatal_error(slogan, analysis) do
    msg(:abort, 'typer: ~ts', [slogan], analysis)
  end

  defp compile_error(reason, analysis) do
    joinedString = :lists.flatten(for x <- reason do
                                    x ++ '\n'
                                  end)
    msg = 'Analysis failed with error report:\n' ++ joinedString
    fatal_error(msg, analysis)
  end

  defp msg(level, format, data, r_analysis(io: io)) do
    printer = :maps.get(level, io, &swallow_output/2)
    printer.(format, data)
  end

  defp format(format, data) do
    :io.format(format ++ '\n', data)
  end

  defp swallow_output(_Format, _Data) do
    :ok
  end

  defp format_on_stderr(format, data) do
    :io.format(:standard_error, format ++ '\n', data)
  end

  defp format_and_halt(format, data) do
    format_on_stderr(format, data)
    :erlang.halt(1)
  end

  defp rcv_ext_types() do
    self = self()
    send(self, {self, :done})
    rcv_ext_types(self, [])
  end

  defp rcv_ext_types(self, extTypes) do
    receive do
      {^self, :ext_types, extType} ->
        rcv_ext_types(self, [extType | extTypes])
      {^self, :done} ->
        :lists.usort(extTypes)
    end
  end

end