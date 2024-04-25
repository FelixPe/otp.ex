defmodule :m_dialyzer_cplt do
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

  Record.defrecord(:r_file_plt, :file_plt,
    version: ~c"",
    file_md5_list: [],
    info: :dict.new(),
    contracts: :dict.new(),
    callbacks: :dict.new(),
    types: :dict.new(),
    exported_types: :sets.new(),
    mod_deps: :undefined,
    implementation_md5: []
  )

  def get_default_cplt_filename() do
    case :os.getenv(~c"DIALYZER_PLT") do
      false ->
        cacheDir = :filename.basedir(:user_cache, ~c"erlang")
        :filename.join(cacheDir, ~c".dialyzer_plt")

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
            msg = :io_lib.format(~c"Old PLT file ~ts\n", [fileName])
            {:error, msg}

          :ok ->
            r_file_plt(
              info: fileInfo,
              contracts: fileContracts,
              callbacks: fileCallbacks,
              types: fileTypes,
              exported_types: fileExpTypes
            ) = rec

            types =
              for {mod, types} <- :dict.to_list(fileTypes) do
                {mod, :maps.from_list(:dict.to_list(types))}
              end

            callbacksList = :dict.to_list(fileCallbacks)

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
                    {eTSInfo, :dict.to_list(fileInfo)},
                    {eTSTypes, types},
                    {eTSContracts, :dict.to_list(fileContracts)}
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
                pltInfo =
                  r_plt_info(
                    files: r_file_plt(rec, :file_md5_list),
                    mod_deps: r_file_plt(rec, :mod_deps)
                  )

                {:ok, {plt, pltInfo}}
            end
        end

      {:error, reason} ->
        msg = :io_lib.format(~c"Could not read PLT file ~ts: ~p\n", [fileName, reason])
        {:error, msg}
    end
  end

  def included_files(fileName) do
    fun = fn ->
      included_files1(fileName)
    end

    subproc(fun)
  end

  defp included_files1(fileName) do
    case get_record_from_file(fileName) do
      {:ok, r_file_plt(file_md5_list: md5)} ->
        {:ok,
         for {file, _} <- md5 do
           file
         end}

      {:error, _What} = error ->
        error
    end
  end

  defp check_version(
         r_file_plt(
           version: :EFE_TODO_VSN_MACRO,
           implementation_md5: implMd5
         )
       ) do
    case compute_new_md5(implMd5, [], []) do
      :ok ->
        :ok

      {:differ, _, _} ->
        :error

      {:error, _} ->
        :error
    end
  end

  defp check_version(r_file_plt()) do
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
          r_file_plt() = filePLT ->
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

  def is_cplt(fileName) do
    case get_record_from_file(fileName) do
      {:ok, _} ->
        true

      {:error, _} ->
        false
    end
  end

  defp merge_disj_plts(list) do
    {infoList, typesList, expTypesList, contractsList, callbacksList} = group_fields(list)

    r_plt(
      info: table_disj_merge(infoList),
      types: table_disj_merge(typesList),
      exported_types: sets_disj_merge(expTypesList),
      contracts: table_disj_merge(contractsList),
      callbacks: table_disj_merge(callbacksList)
    )
  end

  defp group_fields(list) do
    infoList =
      for r_plt(info: info) <- list do
        info
      end

    typesList =
      for r_plt(types: types) <- list do
        types
      end

    expTypesList =
      for r_plt(exported_types: expTypes) <- list do
        expTypes
      end

    contractsList =
      for r_plt(contracts: contracts) <- list do
        contracts
      end

    callbacksList =
      for r_plt(callbacks: callbacks) <- list do
        callbacks
      end

    {infoList, typesList, expTypesList, contractsList, callbacksList}
  end

  def merge_plts_or_report_conflicts(pltFiles, plts) do
    try do
      merge_disj_plts(plts)
    catch
      {:dialyzer_error, :not_disjoint_plts} ->
        incFiles =
          :lists.append(
            for f <- pltFiles do
              {:ok, fs} = included_files(f)
              fs
            end
          )

        confFiles = find_duplicates(incFiles)

        msg =
          :io_lib.format(
            ~c"Could not merge PLTs since they are not disjoint\nThe following files are included in more than one PLTs:\n~tp\n",
            [confFiles]
          )

        plt_error(msg)
    end
  end

  defp find_duplicates(list) do
    modList =
      for e <- list do
        :filename.basename(e)
      end

    sortedList = :lists.usort(modList)
    :lists.usort(modList -- sortedList)
  end

  def to_file(fileName, plt, modDeps, mD5_OldModDeps) do
    fun = fn ->
      to_file1(fileName, plt, modDeps, mD5_OldModDeps)
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

  defp to_file1(
         fileName,
         r_plt(
           info: eTSInfo,
           types: eTSTypes,
           contracts: eTSContracts,
           callbacks: eTSCallbacks,
           exported_types: eTSExpTypes
         ),
         modDeps,
         r_plt_info(files: mD5, mod_deps: oldModDeps)
       ) do
    newModDeps =
      :dict.merge(
        fn _Key, oldVal, newVal ->
          :ordsets.union(oldVal, newVal)
        end,
        oldModDeps,
        modDeps
      )

    implMd5 = compute_implementation_md5()

    callbacksList =
      for {_M, cbs} <- :dialyzer_utils.ets_tab2list(eTSCallbacks),
          cb <- cbs do
        cb
      end

    callbacks = :dict.from_list(callbacksList)
    info = :dict.from_list(:dialyzer_utils.ets_tab2list(eTSInfo))
    types = :dialyzer_utils.ets_tab2list(eTSTypes)
    contracts = :dict.from_list(:dialyzer_utils.ets_tab2list(eTSContracts))

    expTypes =
      :sets.from_list(
        for {e} <- :dialyzer_utils.ets_tab2list(eTSExpTypes) do
          e
        end
      )

    fileTypes =
      :dict.from_list(
        for {mod, mTypes} <- types do
          {mod, :dict.from_list(:maps.to_list(mTypes))}
        end
      )

    record =
      r_file_plt(
        version: :EFE_TODO_VSN_MACRO,
        file_md5_list: mD5,
        info: info,
        contracts: contracts,
        callbacks: callbacks,
        types: fileTypes,
        exported_types: expTypes,
        mod_deps: newModDeps,
        implementation_md5: implMd5
      )

    bin = :erlang.term_to_binary(record, [:compressed])

    case :file.write_file(fileName, bin) do
      :ok ->
        :ok

      {:error, reason} ->
        msg = :io_lib.format(~c"Could not write PLT file ~ts: ~w\n", [fileName, reason])
        {:error, msg}
    end
  end

  def check_plt(fileName, removeFiles, addFiles) do
    fun = fn ->
      check_plt1(fileName, removeFiles, addFiles)
    end

    subproc(fun)
  end

  defp check_plt1(fileName, removeFiles, addFiles) do
    case get_record_from_file(fileName) do
      {:ok, r_file_plt(file_md5_list: md5, mod_deps: modDeps) = rec} ->
        case check_version(rec) do
          :ok ->
            case compute_new_md5(md5, removeFiles, addFiles) do
              :ok ->
                :ok

              {:differ, newMd5, diffMd5} ->
                {:differ, newMd5, diffMd5, modDeps}

              {:error, _What} = err ->
                err
            end

          :error ->
            case compute_new_md5(md5, removeFiles, addFiles) do
              :ok ->
                {:old_version, md5}

              {:differ, newMd5, _DiffMd5} ->
                {:old_version, newMd5}

              {:error, _What} = err ->
                err
            end
        end

      error ->
        error
    end
  end

  defp compute_new_md5(md5, [], []) do
    compute_new_md5_1(md5, [], [])
  end

  defp compute_new_md5(md5, removeFiles0, addFiles0) do
    removeFiles = removeFiles0 -- addFiles0
    addFiles = addFiles0 -- removeFiles0
    initDiffList = init_diff_list(removeFiles, addFiles)

    case init_md5_list(md5, removeFiles, addFiles) do
      {:ok, newMd5} ->
        compute_new_md5_1(newMd5, [], initDiffList)

      {:error, _What} = error ->
        error
    end
  end

  defp compute_new_md5_1([{file, md5} = entry | entries], newList, diff) do
    case compute_md5_from_file(file) do
      ^md5 ->
        compute_new_md5_1(entries, [entry | newList], diff)

      newMd5 ->
        modName = beam_file_to_module(file)
        compute_new_md5_1(entries, [{file, newMd5} | newList], [{:differ, modName} | diff])
    end
  end

  defp compute_new_md5_1([], _NewList, []) do
    :ok
  end

  defp compute_new_md5_1([], newList, diff) do
    {:differ, :lists.keysort(1, newList), diff}
  end

  defp compute_implementation_md5() do
    dir = :code.lib_dir(:dialyzer)
    files1 = [~c"erl_bif_types.beam", ~c"erl_types.beam"]

    files2 =
      for f <- files1 do
        :filename.join([dir, ~c"ebin", f])
      end

    compute_md5_from_files(files2)
  end

  def compute_md5_from_files(files) do
    :lists.keysort(
      1,
      for f <- files do
        {f, compute_md5_from_file(f)}
      end
    )
  end

  defp compute_md5_from_file(file) do
    case :beam_lib.all_chunks(file) do
      {:ok, _, chunks} ->
        filtered =
          for {iD, chunk} <- chunks, iD !== ~c"CInf", iD !== ~c"Docs" do
            [iD, chunk]
          end

        :erlang.md5(:lists.sort(filtered))

      {:error, :beam_lib, {:file_error, _, :enoent}} ->
        msg = :io_lib.format(~c"File not found: ~ts\n", [file])
        plt_error(msg)

      {:error, :beam_lib, _} ->
        msg = :io_lib.format(~c"Could not compute MD5 for .beam: ~ts\n", [file])
        plt_error(msg)
    end
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
    files =
      for f <- removeFiles do
        {:remove, f}
      end ++
        for f <- addFiles do
          {:add, f}
        end

    diffFiles = :lists.keysort(2, files)
    md5Sorted = :lists.keysort(1, md5)
    init_md5_list_1(md5Sorted, diffFiles, [])
  end

  defp init_md5_list_1([{file, _Md5} | md5Left], [{:remove, file} | diffLeft], acc) do
    init_md5_list_1(md5Left, diffLeft, acc)
  end

  defp init_md5_list_1([{file, _Md5} = entry | md5Left], [{:add, file} | diffLeft], acc) do
    init_md5_list_1(md5Left, diffLeft, [entry | acc])
  end

  defp init_md5_list_1(
         [{file1, _Md5} = entry | md5Left] = md5List,
         [{tag, file2} | diffLeft] = diffList,
         acc
       ) do
    case file1 < file2 do
      true ->
        init_md5_list_1(md5Left, diffList, [entry | acc])

      false ->
        true = file1 > file2

        case tag do
          :add ->
            init_md5_list_1(md5List, diffLeft, [{file2, <<>>} | acc])

          :remove ->
            {:error, {:no_file_to_remove, file2}}
        end
    end
  end

  defp init_md5_list_1([], diffList, acc) do
    addFiles =
      for {:add, f} <- diffList do
        {f, <<>>}
      end

    {:ok, :lists.reverse(acc, addFiles)}
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

  defp table_disj_merge([h | t]) do
    table_disj_merge(t, h)
  end

  defp table_disj_merge([], acc) do
    acc
  end

  defp table_disj_merge([plt | plts], acc) do
    case table_is_disjoint(plt, acc) do
      true ->
        newAcc = merge_tables(plt, acc)
        table_disj_merge(plts, newAcc)

      false ->
        throw({:dialyzer_error, :not_disjoint_plts})
    end
  end

  defp sets_disj_merge([h | t]) do
    sets_disj_merge(t, h)
  end

  defp sets_disj_merge([], acc) do
    acc
  end

  defp sets_disj_merge([plt | plts], acc) do
    case table_is_disjoint(plt, acc) do
      true ->
        newAcc = merge_tables(plt, acc)
        sets_disj_merge(plts, newAcc)

      false ->
        throw({:dialyzer_error, :not_disjoint_plts})
    end
  end

  defp table_is_disjoint(t1, t2) do
    tab_is_disj(:ets.first(t1), t1, t2)
  end

  defp tab_is_disj(:"$end_of_table", _T1, _T2) do
    true
  end

  defp tab_is_disj(k1, t1, t2) do
    case :ets.member(t2, k1) do
      false ->
        tab_is_disj(:ets.next(t1, k1), t1, t2)

      true ->
        false
    end
  end

  defp merge_tables(t1, t2) do
    tab_merge(:ets.first(t1), t1, t2)
  end

  defp tab_merge(:"$end_of_table", t1, t2) do
    case :ets.first(t1) do
      :"$end_of_table" ->
        true = :ets.delete(t1)
        t2

      key ->
        tab_merge(key, t1, t2)
    end
  end

  defp tab_merge(k1, t1, t2) do
    vs = :ets.lookup(t1, k1)
    nextK1 = :ets.next(t1, k1)
    true = :ets.delete(t1, k1)
    true = :ets.insert(t2, vs)
    tab_merge(nextK1, t1, t2)
  end

  def pp_non_returning() do
    pltFile = get_default_cplt_filename()
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
    pltFile = get_default_cplt_filename()
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
        :io.format(~c"dialyzer: Found no module named '~s' in the PLT\n", [mod])
    end

    :dialyzer_plt.delete(plt)
  end
end
