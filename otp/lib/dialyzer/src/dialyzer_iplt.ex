defmodule :m_dialyzer_iplt do
  use Bitwise
  require Record

  Record.defrecord(:r_incremental_data, :incremental_data,
    mod_deps: :undefined,
    warning_map: :none,
    legal_warnings: :none
  )

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

  Record.defrecord(:r_ifile_plt, :ifile_plt,
    version: ~c"",
    module_md5_list: [],
    info: :erlang.term_to_binary(%{}),
    contracts: :erlang.term_to_binary(%{}),
    callbacks: :erlang.term_to_binary(%{}),
    types: :erlang.term_to_binary(%{}),
    exported_types: :erlang.term_to_binary(%{}),
    incremental_data: :erlang.term_to_binary(r_incremental_data()),
    implementation_md5: []
  )

  def get_default_iplt_filename() do
    case :os.getenv(~c"DIALYZER_IPLT") do
      false ->
        cacheDir = :filename.basedir(:user_cache, ~c"erlang")
        :filename.join(cacheDir, ~c".dialyzer_iplt")

      userSpecPlt ->
        userSpecPlt
    end
  end

  def plt_and_info_from_file(fileName) do
    from_file(fileName, true)
  end

  def from_file(fileName) do
    from_file(fileName, false)
  end

  defp from_file(fileName, returnInfo) do
    plt = :dialyzer_plt.new()

    fun = fn ->
      from_file1(plt, fileName, returnInfo)
    end

    case subproc(fun) do
      {:ok, return} ->
        return

      {:error, msg} ->
        :dialyzer_plt.delete(plt)
        plt_error(msg)
    end
  end

  defp from_file1(plt, fileName, returnInfo) do
    case get_record_from_file(fileName) do
      {:ok, rec} ->
        case check_version(rec) do
          :error ->
            msg = :io_lib.format(~c"Old IPLT file ~ts\n", [fileName])
            {:error, msg}

          :ok ->
            r_ifile_plt(
              info: compressedInfo,
              contracts: compressedContracts,
              callbacks: compressedCallbacks,
              types: compressedTypes,
              exported_types: compressedExpTypes
            ) = rec

            fileInfo = :erlang.binary_to_term(compressedInfo)
            fileContracts = :erlang.binary_to_term(compressedContracts)
            fileCallbacks = :erlang.binary_to_term(compressedCallbacks)
            fileTypes = :erlang.binary_to_term(compressedTypes)
            fileExpTypes = :erlang.binary_to_term(compressedExpTypes)
            callbacksList = :maps.to_list(fileCallbacks)

            callbacksByModule =
              for m <-
                    :lists.usort(
                      for {{m, _, _}, _} <- callbacksList do
                        m
                      end
                    ) do
                {m,
                 for {{m1, _, _}, _} = cb <- callbacksList,
                     m1 === m do
                   cb
                 end}
              end

            r_plt(
              info: eTSInfo,
              types: eTSTypes,
              contracts: eTSContracts,
              callbacks: eTSCallbacks,
              exported_types: eTSExpTypes
            ) = plt

            [true, true, true] =
              for {eTS, data} <- [
                    {eTSInfo, :maps.to_list(fileInfo)},
                    {eTSTypes, fileTypes},
                    {eTSContracts, :maps.to_list(fileContracts)}
                  ] do
                :ets.insert(eTS, data)
              end

            true = :ets.insert(eTSCallbacks, callbacksByModule)

            true =
              :ets.insert(
                eTSExpTypes,
                for eT <- :sets.to_list(fileExpTypes) do
                  {eT}
                end
              )

            case returnInfo do
              false ->
                {:ok, plt}

              true ->
                incrementalData = get_incremental_data(rec)

                pltInfo =
                  r_iplt_info(
                    files: r_ifile_plt(rec, :module_md5_list),
                    mod_deps: r_incremental_data(incrementalData, :mod_deps),
                    warning_map: r_incremental_data(incrementalData, :warning_map),
                    legal_warnings: r_incremental_data(incrementalData, :legal_warnings)
                  )

                {:ok, {plt, pltInfo}}
            end
        end

      {:error, reason} ->
        msg = :io_lib.format(~c"Could not read IPLT file ~ts: ~p\n", [fileName, reason])
        {:error, msg}
    end
  end

  defp get_incremental_data(r_ifile_plt(incremental_data: data)) do
    case data do
      compressedData when is_binary(compressedData) ->
        :erlang.binary_to_term(compressedData)

      uncompressedData = r_incremental_data() ->
        uncompressedData
    end
  end

  def included_modules(fileName) do
    fun = fn ->
      included_modules1(fileName)
    end

    subproc(fun)
  end

  defp included_modules1(fileName) do
    case get_record_from_file(fileName) do
      {:ok, r_ifile_plt(module_md5_list: md5)} ->
        {:ok,
         for {moduleName, _} <- md5 do
           moduleName
         end}

      {:error, _What} = error ->
        error
    end
  end

  defp check_version(
         r_ifile_plt(
           version: :EFE_TODO_VSN_MACRO,
           implementation_md5: implMd5
         )
       ) do
    case compute_new_md5(implMd5, [], [], implementation_module_paths()) do
      :ok ->
        :ok

      {:differ, _, _} ->
        :error

      {:error, _} ->
        :error
    end
  end

  defp check_version(r_ifile_plt()) do
    :error
  end

  defp get_record_from_file(fileName) do
    case :file.read_file(fileName) do
      {:ok, bin} ->
        try do
          :erlang.binary_to_term(bin)
        catch
          _, _ ->
            {:error, :not_valid}
        else
          r_ifile_plt() = filePLT ->
            {:ok, filePLT}

          _ ->
            {:error, :not_valid}
        end

      {:error, :enoent} ->
        {:error, :no_such_file}

      {:error, _} ->
        {:error, :read_error}
    end
  end

  def is_iplt(fileName) do
    case get_record_from_file(fileName) do
      {:ok, _} ->
        true

      {:error, _} ->
        false
    end
  end

  def to_file(fileName, plt, modDeps, pLTInfo) do
    fun = fn ->
      to_file1(fileName, plt, modDeps, pLTInfo)
    end

    return = subproc(fun)
    :dialyzer_plt.delete(plt)

    case return do
      :ok ->
        :ok

      {:error, msg} ->
        plt_error(msg)
    end
  end

  defp to_file1(fileName, plt, modDeps, pltInfo) do
    to_file_custom_vsn(fileName, plt, modDeps, pltInfo, :none, :none)
  end

  def merge_warnings(:none, _, oldWarningMap) do
    oldWarningMap
  end

  def merge_warnings(newWarnings, unknownWarnings, :none) do
    convert_to_warning_map(newWarnings, unknownWarnings)
  end

  def merge_warnings(newWarnings, unknownWarnings, oldWarningMap) do
    :maps.merge(
      convert_to_warning_map(
        newWarnings,
        unknownWarnings
      ),
      oldWarningMap
    )
  end

  defp convert_to_warning_map(warningList, unknownWarnings) do
    temp =
      :lists.foldl(
        fn {_, {_, _, morMFA}, _} = warn, acc ->
          update = fn old ->
            [warn | old]
          end

          :maps.update_with(get_module(morMFA), update, [warn], acc)
        end,
        %{},
        warningList
      )

    :lists.foldl(
      fn {m, warn}, acc ->
        update = fn old ->
          [warn | old]
        end

        :maps.update_with(m, update, [warn], acc)
      end,
      temp,
      unknownWarnings
    )
  end

  defp get_module({m, _F, _A}) do
    m
  end

  defp get_module(m) do
    m
  end

  def check_incremental_plt(fileName, opts, pltFiles) do
    fun = fn ->
      check_incremental_plt1(fileName, opts, pltFiles)
    end

    subproc(fun)
  end

  defp find_files_to_remove_and_add(md5, pltModules) do
    oldPltFiles =
      :gb_sets.from_list(
        for {name, _Md5Bin} <- md5 do
          name
        end
      )

    newPltFiles = :gb_sets.from_list(pltModules)

    {:gb_sets.to_list(
       :gb_sets.subtract(
         oldPltFiles,
         newPltFiles
       )
     ),
     :gb_sets.to_list(
       :gb_sets.subtract(
         newPltFiles,
         oldPltFiles
       )
     )}
  end

  defp check_version_and_compute_md5(rec, removeFiles, addFiles, moduleToPathLookup) do
    md5 = r_ifile_plt(rec, :module_md5_list)

    case check_version(rec) do
      :ok ->
        case compute_new_md5(md5, removeFiles, addFiles, moduleToPathLookup) do
          :ok ->
            :ok

          {:differ, newMd5, diffMd5} ->
            incrementalData = get_incremental_data(rec)

            {:differ, newMd5, diffMd5, r_incremental_data(incrementalData, :mod_deps),
             r_incremental_data(incrementalData, :warning_map)}

          {:error, _What} = err ->
            err
        end

      :error ->
        case compute_new_md5(md5, removeFiles, addFiles, moduleToPathLookup) do
          :ok ->
            {:old_version, md5}

          {:differ, newMd5, _DiffMd5} ->
            {:old_version, newMd5}

          {:error, _What} = err ->
            err
        end
    end
  end

  defp compute_new_md5(md5, [], [], moduleToPathLookup) do
    compute_new_md5_1(md5, [], moduleToPathLookup)
  end

  defp compute_new_md5(md5, removeFiles0, addFiles0, moduleToPathLookup) do
    removeFiles = removeFiles0 -- addFiles0
    addFiles = addFiles0 -- removeFiles0
    initDiffList = init_diff_list(removeFiles, addFiles)

    case init_md5_list(md5, removeFiles, addFiles) do
      {:ok, newMd5} ->
        compute_new_md5_1(newMd5, initDiffList, moduleToPathLookup)

      {:error, _What} = error ->
        error
    end
  end

  defp compute_new_md5_1(entries, initDiffs, moduleToPathLookup) do
    modules =
      for {module, _Md5} <- entries do
        module
      end

    existingHashes =
      for {_Module, md5} <- entries do
        md5
      end

    files =
      for module <- modules do
        :maps.get(module, moduleToPathLookup)
      end

    newHashes =
      :dialyzer_utils.p_map(
        &compute_md5_from_file/1,
        files
      )

    diffs =
      :lists.zipwith3(
        fn module, beforeHash, afterHash ->
          case beforeHash do
            ^afterHash ->
              :none

            _ ->
              {:differ, module}
          end
        end,
        modules,
        existingHashes,
        newHashes
      )

    diffs1 =
      initDiffs ++
        :lists.filter(
          fn
            {:differ, _} ->
              true

            :none ->
              false
          end,
          diffs
        )

    case diffs1 do
      [] ->
        :ok

      _ ->
        moduleHashes = :lists.zip(modules, newHashes)
        {:differ, :lists.keysort(1, moduleHashes), diffs1}
    end
  end

  defp compute_implementation_md5() do
    modules = implementation_module_paths()
    compute_md5_from_files(modules)
  end

  defp compute_md5_from_files(moduleToPathLookup) do
    {modules, files} = :lists.unzip(:maps.to_list(moduleToPathLookup))

    hashes =
      :dialyzer_utils.p_map(
        &compute_md5_from_file/1,
        files
      )

    :lists.keysort(1, :lists.zip(modules, hashes))
  end

  defp compute_md5_from_file(file) do
    case :beam_lib.chunks(file, [:debug_info]) do
      {:ok, {moduleName, [{:debug_info, {:debug_info_v1, backend, data}}]}} ->
        case backend.debug_info(:erlang_v1, moduleName, data, []) do
          {:ok, code} ->
            stabilisedCode =
              :lists.filtermap(
                fn form ->
                  make_stable(moduleName, form)
                end,
                code
              )

            stabilisedCodeBin = :erlang.term_to_binary(stabilisedCode)
            :erlang.md5(stabilisedCodeBin)

          {:error, reason} ->
            msg =
              :io_lib.format(
                ~c"Could not compute MD5 for .beam (debug_info error) - did you forget to set the debug_info compilation option? ~ts ~tw\n",
                [file, reason]
              )

            throw({:dialyzer_error, msg})
        end

      {:ok, {_, [{:debug_info, :no_debug_info}]}} ->
        msg =
          :io_lib.format(~c"Could not compute MD5 for .beam (debug_info missing): ~ts\n", [file])

        throw({:dialyzer_error, msg})

      {:error, :beam_lib, {:file_error, _, :enoent}} ->
        msg = :io_lib.format(~c"File not found: ~ts\n", [file])
        plt_error(msg)

      {:error, :beam_lib, _} ->
        msg = :io_lib.format(~c"Could not compute MD5 for .beam: ~ts\n", [file])
        plt_error(msg)
    end
  end

  defp make_stable(
         _,
         {:attribute, anno, :file, {srcFilePath, line}}
       ) do
    {true, {:attribute, anno, :file, {:filename.basename(srcFilePath), line}}}
  end

  defp make_stable(_, attr) do
    {true, attr}
  end

  defp init_diff_list(removeFiles, addFiles) do
    removeSet0 =
      :sets.from_list(
        for f <- removeFiles do
          beam_file_to_module(f)
        end
      )

    addSet0 =
      :sets.from_list(
        for f <- addFiles do
          beam_file_to_module(f)
        end
      )

    diffSet = :sets.intersection(addSet0, removeSet0)
    removeSet = :sets.subtract(removeSet0, diffSet)

    for f <- :sets.to_list(removeSet) do
      {:removed, f}
    end
  end

  defp init_md5_list(md5, removeFiles, addFiles) do
    mods =
      for f <- removeFiles do
        {:remove, beam_file_to_module(f)}
      end ++
        for f <- addFiles do
          {:add, beam_file_to_module(f)}
        end

    diffMods = :lists.keysort(2, mods)
    md5Sorted = :lists.keysort(1, md5)
    init_md5_list_1(md5Sorted, diffMods, [])
  end

  defp init_md5_list_1([{mod, _Md5} | md5Left], [{:remove, mod} | diffLeft], acc) do
    init_md5_list_1(md5Left, diffLeft, acc)
  end

  defp init_md5_list_1([{mod, _Md5} = entry | md5Left], [{:add, mod} | diffLeft], acc) do
    init_md5_list_1(md5Left, diffLeft, [entry | acc])
  end

  defp init_md5_list_1(
         [{mod1, _Md5} = entry | md5Left] = md5List,
         [{tag, mod2} | diffLeft] = diffList,
         acc
       ) do
    case mod1 < mod2 do
      true ->
        init_md5_list_1(md5Left, diffList, [entry | acc])

      false ->
        true = mod1 > mod2

        case tag do
          :add ->
            init_md5_list_1(md5List, diffLeft, [{mod2, <<>>} | acc])

          :remove ->
            {:error, {:no_file_to_remove, mod2}}
        end
    end
  end

  defp init_md5_list_1([], diffList, acc) do
    addMods =
      for {:add, m} <- diffList do
        {m, <<>>}
      end

    {:ok, :lists.reverse(acc, addMods)}
  end

  defp init_md5_list_1(md5List, [], acc) do
    {:ok, :lists.reverse(acc, md5List)}
  end

  defp subproc(fun) do
    f = fn ->
      exit(
        try do
          fun.()
        catch
          t ->
            {:thrown, t}
        end
      )
    end

    {pid, ref} = :erlang.spawn_monitor(f)

    receive do
      {:DOWN, ^ref, :process, ^pid, return} ->
        case return do
          {:thrown, t} ->
            throw(t)

          _ ->
            return
        end
    end
  end

  defp beam_file_to_module(filename) do
    :erlang.list_to_atom(:filename.basename(filename, ~c".beam"))
  end

  defp plt_error(msg) do
    throw({:dialyzer_error, :lists.flatten(msg)})
  end

  def pp_non_returning() do
    pltFile = get_default_iplt_filename()
    plt = from_file(pltFile)
    list = :ets.tab2list(r_plt(plt, :info))

    unit =
      for {mFA, {ret, args}} <- list,
          :erl_types.t_is_unit(ret) do
        {mFA, :erl_types.t_fun(args, ret)}
      end

    none =
      for {mFA, {ret, args}} <- list,
          :erl_types.t_is_none(ret) do
        {mFA, :erl_types.t_fun(args, ret)}
      end

    :io.format(~c"=========================================\n")
    :io.format(~c"=                Loops                  =\n")
    :io.format(~c"=========================================\n\n")

    :lists.foreach(
      fn {{m, f, _}, type} ->
        :io.format(~c"~w:~tw~ts.\n", [m, f, :dialyzer_utils.format_sig(type)])
      end,
      :lists.sort(unit)
    )

    :io.format(~c"\n")
    :io.format(~c"=========================================\n")
    :io.format(~c"=                Errors                 =\n")
    :io.format(~c"=========================================\n\n")

    :lists.foreach(
      fn {{m, f, _}, type} ->
        :io.format(~c"~w:~w~s.\n", [m, f, :dialyzer_utils.format_sig(type)])
      end,
      :lists.sort(none)
    )

    :dialyzer_plt.delete(plt)
  end

  def pp_mod(mod) when is_atom(mod) do
    pltFile = get_default_iplt_filename()
    plt = from_file(pltFile)

    case :dialyzer_plt.lookup_module(plt, mod) do
      {:value, list} ->
        :lists.foreach(
          fn {{_, f, _}, ret, args} ->
            t = :erl_types.t_fun(args, ret)
            s = :dialyzer_utils.format_sig(t)
            :io.format(~c"-spec ~tw~ts.\n", [f, s])
          end,
          :lists.sort(list)
        )

      :none ->
        :io.format(~c"dialyzer: Found no module named '~s' in the IPLT\n", [mod])
    end

    :dialyzer_plt.delete(plt)
  end
end
