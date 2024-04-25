defmodule :m_code do
  use Bitwise
  require Record
  Record.defrecord(:r_docs_v1, :docs_v1, anno: :undefined,
                                   beam_language: :erlang, format: "application/erlang+html",
                                   module_doc: :undefined,
                                   metadata: %{otp_doc_vsn: {1, 0, 0}},
                                   docs: :undefined)
  Record.defrecord(:r_docs_v1_entry, :docs_v1_entry, kind_name_arity: :undefined,
                                         anno: :undefined,
                                         signature: :undefined, doc: :undefined,
                                         metadata: :undefined)
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
  def get_chunk(<<"FOR1", _ :: bits>> = beam, chunk) do
    get_chunk_1(beam, chunk)
  end

  def get_chunk(beam, chunk) do
    get_chunk_1(try_decompress(beam), chunk)
  end

  defp get_chunk_1(beam, chunk) do
    try do
      :erts_internal.beamfile_chunk(beam, chunk)
    catch
      :error, reason ->
        {:EXIT,
           {:new_stacktrace, [{mod, _, l, loc} | rest]}} = ((try do
                                                              :erlang.error(:new_stacktrace,
                                                                              [beam,
                                                                                   chunk])
                                                            catch
                                                              :error, e -> {:EXIT, {e, __STACKTRACE__}}
                                                              :exit, e -> {:EXIT, e}
                                                              e -> e
                                                            end))
        :erlang.raise(:error, reason,
                        [{mod, :get_chunk, l, loc} | rest])
    end
  end

  def module_md5(<<"FOR1", _ :: bits>> = beam) do
    module_md5_1(beam)
  end

  def module_md5(beam) do
    module_md5_1(try_decompress(beam))
  end

  defp module_md5_1(beam) do
    try do
      :erts_internal.beamfile_module_md5(beam)
    catch
      :error, reason ->
        {:EXIT,
           {:new_stacktrace, [{mod, _, l, loc} | rest]}} = ((try do
                                                              :erlang.error(:new_stacktrace,
                                                                              [beam])
                                                            catch
                                                              :error, e -> {:EXIT, {e, __STACKTRACE__}}
                                                              :exit, e -> {:EXIT, e}
                                                              e -> e
                                                            end))
        :erlang.raise(:error, reason,
                        [{mod, :module_md5, l, loc} | rest])
    end
  end

  defp try_decompress(bin0) do
    try do
      :zlib.gunzip(bin0)
    catch
      _, _ ->
        bin0
    else
      decompressed ->
        decompressed
    end
  end

  def objfile_extension() do
    :init.objfile_extension()
  end

  def load_file(mod) when is_atom(mod) do
    case (get_object_code(mod)) do
      :error ->
        {:error, :nofile}
      {^mod, binary, file} ->
        load_module(mod, file, binary, false)
    end
  end

  def ensure_loaded(mod) when is_atom(mod) do
    case (:erlang.module_loaded(mod)) do
      true ->
        {:module, mod}
      false ->
        case (call({:get_object_code_for_loading, mod})) do
          {:module, ^mod} ->
            {:module, mod}
          {:error, what} ->
            {:error, what}
          {binary, file, ref} ->
            case (:erlang.prepare_loading(mod, binary)) do
              {:error, _} = error ->
                call({:load_error, ref, mod, error})
              prepared ->
                call({:load_module, prepared, mod, file, false, ref})
            end
        end
    end
  end

  def load_abs(file) when is_list(file) or is_atom(file) do
    load_abs(file,
               :erlang.list_to_atom(:filename.basename(file)))
  end

  def load_abs(file, m) when (is_list(file) or is_atom(file) and
                          is_atom(m)) do
    case (modp(file)) do
      true ->
        fileName0 = :lists.concat([file, objfile_extension()])
        fileName = :code_server.absname(fileName0)
        case (:erl_prim_loader.get_file(fileName)) do
          {:ok, bin, _} ->
            load_module(m, fileName, bin, false)
          :error ->
            {:error, :nofile}
        end
      false ->
        {:error, :badarg}
    end
  end

  def load_binary(mod, file, bin) when (is_atom(mod) and
                                 is_list(file) or is_atom(file) and
                                 is_binary(bin)) do
    case (modp(file)) do
      true ->
        load_module(mod, file, bin, true)
      false ->
        {:error, :badarg}
    end
  end

  defp load_module(mod, file, bin, purge) do
    case (:erlang.prepare_loading(mod, bin)) do
      {:error, _} = error ->
        error
      prepared ->
        call({:load_module, prepared, mod, file, purge, false})
    end
  end

  defp modp(atom) when is_atom(atom) do
    true
  end

  defp modp(list) when is_list(list) do
    int_list(list)
  end

  defp modp(_) do
    false
  end

  defp int_list([h | t]) when is_integer(h) do
    int_list(t)
  end

  defp int_list([_ | _]) do
    false
  end

  defp int_list([]) do
    true
  end

  def delete(mod) when is_atom(mod) do
    call({:delete, mod})
  end

  def purge(mod) when is_atom(mod) do
    call({:purge, mod})
  end

  def soft_purge(mod) when is_atom(mod) do
    call({:soft_purge, mod})
  end

  def is_loaded(mod) when is_atom(mod) do
    :code_server.is_loaded(mod)
  end

  def get_object_code(mod) when is_atom(mod) do
    call({:get_object_code, mod})
  end

  def all_loaded() do
    call(:all_loaded)
  end

  def all_available() do
    case (:code.get_mode()) do
      :interactive ->
        all_available(get_path(), %{})
      :embedded ->
        all_available([], %{})
    end
  end

  defp all_available([path | tail], acc) do
    case (:erl_prim_loader.list_dir(path)) do
      {:ok, files} ->
        all_available(tail, all_available(path, files, acc))
      _Error ->
        all_available(tail, acc)
    end
  end

  defp all_available([], allModules) do
    allLoaded = (for {m, path} <- all_loaded() do
                   {:erlang.atom_to_list(m), path, true}
                 end)
    allAvailable = :maps.fold(fn file, path, acc ->
                                   [{:filename.rootname(file),
                                       :filename.append(path, file), false} |
                                        acc]
                              end,
                                [], allModules)
    orderFun = fn f
               {a, _, _}, {b, _, _} ->
                 f.(a, b)
               a, b ->
                 a <= b
               end
    :lists.umerge(orderFun,
                    :lists.sort(orderFun, allLoaded),
                    :lists.sort(orderFun, allAvailable))
  end

  defp all_available(path, [file | t], acc) do
    case (:filename.extension(file)) do
      '.beam' ->
        case (:maps.is_key(file, acc)) do
          false ->
            all_available(path, t, Map.put(acc, file, path))
          true ->
            all_available(path, t, acc)
        end
      _Else ->
        all_available(path, t, acc)
    end
  end

  defp all_available(_Path, [], acc) do
    acc
  end

  def stop() do
    call(:stop)
  end

  def root_dir() do
    call({:dir, :root_dir})
  end

  def lib_dir() do
    call({:dir, :lib_dir})
  end

  def lib_dir(app) when is_atom(app) or is_list(app) do
    call({:dir, {:lib_dir, app}})
  end

  def lib_dir(app, subDir) when (is_atom(app) and
                              is_atom(subDir)) do
    call({:dir, {:lib_dir, app, subDir}})
  end

  def compiler_dir() do
    call({:dir, :compiler_dir})
  end

  def priv_dir(app) when is_atom(app) or is_list(app) do
    call({:dir, {:priv_dir, app}})
  end

  def stick_dir(dir) when is_list(dir) do
    call({:stick_dir, dir})
  end

  def unstick_dir(dir) when is_list(dir) do
    call({:unstick_dir, dir})
  end

  def stick_mod(mod) when is_atom(mod) do
    call({:stick_mod, mod})
  end

  def unstick_mod(mod) when is_atom(mod) do
    call({:unstick_mod, mod})
  end

  def is_sticky(mod) when is_atom(mod) do
    :code_server.is_sticky(mod)
  end

  def set_path(pathList) do
    set_path(pathList, :nocache)
  end

  def set_path(pathList, cache) when (is_list(pathList) and
                                  cache === :cache or cache === :nocache) do
    call({:set_path, pathList, cache})
  end

  def get_path() do
    call(:get_path)
  end

  def add_path(dir) do
    add_path(dir, :nocache)
  end

  def add_path(dir, cache) when (is_list(dir) and
                             cache === :cache or cache === :nocache) do
    call({:add_path, :last, dir, cache})
  end

  def add_pathz(dir) do
    add_pathz(dir, :nocache)
  end

  def add_pathz(dir, cache) when (is_list(dir) and
                             cache === :cache or cache === :nocache) do
    call({:add_path, :last, dir, cache})
  end

  def add_patha(dir) do
    add_patha(dir, :nocache)
  end

  def add_patha(dir, cache) when (is_list(dir) and
                             cache === :cache or cache === :nocache) do
    call({:add_path, :first, dir, cache})
  end

  def add_paths(dirs) do
    add_paths(dirs, :nocache)
  end

  def add_paths(dirs, cache) when (is_list(dirs) and
                              cache === :cache or cache === :nocache) do
    call({:add_paths, :last, dirs, cache})
  end

  def add_pathsz(dirs) do
    add_pathsz(dirs, :nocache)
  end

  def add_pathsz(dirs, cache) when (is_list(dirs) and
                              cache === :cache or cache === :nocache) do
    call({:add_paths, :last, dirs, cache})
  end

  def add_pathsa(dirs) do
    add_pathsa(dirs, :nocache)
  end

  def add_pathsa(dirs, cache) when (is_list(dirs) and
                              cache === :cache or cache === :nocache) do
    call({:add_paths, :first, dirs, cache})
  end

  def del_path(name) when is_list(name) or is_atom(name) do
    call({:del_path, name})
  end

  def del_paths(dirs) when is_list(dirs) do
    call({:del_paths, dirs})
  end

  def replace_path(name, dir) do
    replace_path(name, dir, :nocache)
  end

  def replace_path(name, dir, cache)
      when (is_atom(name) or is_list(name) and
              is_atom(dir) or is_list(dir) and
              cache === :cache or cache === :nocache) do
    call({:replace_path, name, dir, cache})
  end

  def get_mode() do
    call(:get_mode)
  end

  def clear_cache() do
    call(:clear_cache)
  end

  def ensure_modules_loaded(modules) when is_list(modules) do
    case (prepare_ensure(modules, [])) do
      ms when is_list(ms) ->
        ensure_modules_loaded_1(ms)
      :error ->
        :erlang.error(:function_clause, [modules])
    end
  end

  defp ensure_modules_loaded_1(ms0) do
    ms = :lists.usort(ms0)
    {prep, error0} = load_mods(ms)
    {onLoad, normal} = partition_on_load(prep)
    error1 = (case (finish_loading(normal, true)) do
                :ok ->
                  error0
                {:error, err} ->
                  err ++ error0
              end)
    ensure_modules_loaded_2(onLoad, error1)
  end

  defp ensure_modules_loaded_2([{m, {prepared, file}} | ms], errors) do
    case (call({:load_module, prepared, m, file, false,
                  true})) do
      {:module, ^m} ->
        ensure_modules_loaded_2(ms, errors)
      {:error, err} ->
        ensure_modules_loaded_2(ms, [{m, err} | errors])
    end
  end

  defp ensure_modules_loaded_2([], []) do
    :ok
  end

  defp ensure_modules_loaded_2([], [_ | _] = errors) do
    {:error, errors}
  end

  defp prepare_ensure([m | ms], acc) when is_atom(m) do
    case (:erlang.module_loaded(m)) do
      true ->
        prepare_ensure(ms, acc)
      false ->
        prepare_ensure(ms, [m | acc])
    end
  end

  defp prepare_ensure([], acc) do
    acc
  end

  defp prepare_ensure(_, _) do
    :error
  end

  def atomic_load(modules) do
    case (do_prepare_loading(modules)) do
      {:ok, prep} ->
        finish_loading(prep, false)
      {:error, _} = error ->
        error
      :badarg ->
        :erlang.error(:function_clause, [modules])
    end
  end

  def prepare_loading(modules) do
    case (do_prepare_loading(modules)) do
      {:ok, prep} ->
        {:ok, {:"$prepared$", prep}}
      {:error, _} = error ->
        error
      :badarg ->
        :erlang.error(:function_clause, [modules])
    end
  end

  def finish_loading({:"$prepared$", prepared} = arg) when is_list(prepared) do
    case (verify_prepared(prepared)) do
      :ok ->
        finish_loading(prepared, false)
      :error ->
        :erlang.error(:function_clause, [arg])
    end
  end

  defp partition_load([item | t], bs, ms) do
    case (item) do
      {m, file, bin}
          when is_atom(m) and is_list(file) and is_binary(bin) ->
        partition_load(t, [item | bs], ms)
      m when is_atom(m) ->
        partition_load(t, bs, [item | ms])
      _ ->
        :error
    end
  end

  defp partition_load([], bs, ms) do
    {bs, ms}
  end

  defp do_prepare_loading(modules) do
    case (partition_load(modules, [], [])) do
      {modBins, ms} ->
        case (prepare_loading_1(modBins, ms)) do
          {:error, _} = error ->
            error
          prep when is_list(prep) ->
            {:ok, prep}
        end
      :error ->
        :badarg
    end
  end

  defp prepare_loading_1(modBins, ms) do
    case (prepare_check_uniq(modBins, ms)) do
      :ok ->
        prepare_loading_2(modBins, ms)
      error ->
        error
    end
  end

  defp prepare_loading_2(modBins, ms) do
    {prep0, error0} = load_bins(modBins)
    {prep1, error1} = load_mods(ms)
    case (error0 ++ error1) do
      [] ->
        prepare_loading_3(prep0 ++ prep1)
      [_ | _] = error ->
        {:error, error}
    end
  end

  defp prepare_loading_3(prep) do
    case (partition_on_load(prep)) do
      {[_ | _] = onLoad, _} ->
        error = (for {m, _} <- onLoad do
                   {m, :on_load_not_allowed}
                 end)
        {:error, error}
      {[], _} ->
        prep
    end
  end

  defp prepare_check_uniq([{m, _, _} | t], ms) do
    prepare_check_uniq(t, [m | ms])
  end

  defp prepare_check_uniq([], ms) do
    prepare_check_uniq_1(:lists.sort(ms), [])
  end

  defp prepare_check_uniq_1([m | [m | _] = ms], acc) do
    prepare_check_uniq_1(ms, [{m, :duplicated} | acc])
  end

  defp prepare_check_uniq_1([_ | ms], acc) do
    prepare_check_uniq_1(ms, acc)
  end

  defp prepare_check_uniq_1([], []) do
    :ok
  end

  defp prepare_check_uniq_1([], [_ | _] = errors) do
    {:error, errors}
  end

  defp partition_on_load(prep) do
    p = fn {_, {pC, _}} ->
             :erlang.has_prepared_code_on_load(pC)
        end
    :lists.partition(p, prep)
  end

  defp verify_prepared([{m, {prep, name}} | t]) when (is_atom(m) and
                                           is_list(name)) do
    try do
      :erlang.has_prepared_code_on_load(prep)
    catch
      :error, _ ->
        :error
    else
      false ->
        verify_prepared(t)
      _ ->
        :error
    end
  end

  defp verify_prepared([]) do
    :ok
  end

  defp verify_prepared(_) do
    :error
  end

  defp finish_loading(prepared, ensureLoaded) do
    call({:finish_loading, prepared, ensureLoaded})
  end

  defp load_mods([]) do
    {[], []}
  end

  defp load_mods(mods) do
    f = fn mod ->
             case (get_object_code(mod)) do
               {^mod, beam, file} ->
                 prepare_loading(mod, file, beam)
               :error ->
                 {:error, :nofile}
             end
        end
    do_par(f, mods)
  end

  defp load_bins([]) do
    {[], []}
  end

  defp load_bins(binItems) do
    f = fn {mod, file, beam} ->
             prepare_loading(mod, file, beam)
        end
    do_par(f, binItems)
  end

  defp prepare_loading(mod, fullName, beam) do
    case (:erlang.prepare_loading(mod, beam)) do
      {:error, _} = error ->
        error
      prepared ->
        {:ok, {prepared, fullName}}
    end
  end

  defp do_par(fun, l) do
    {_, ref} = spawn_monitor(do_par_fun(fun, l))
    receive do
      {:DOWN, ^ref, :process, _, res} ->
        res
    end
  end

  defp do_par_fun(fun, l) do
    fn () ->
         _ = (for item <- l do
                spawn_monitor(do_par_fun_each(fun, item))
              end)
         exit(do_par_recv(length(l), [], []))
    end
  end

  defp do_par_fun_each(fun, mod) when is_atom(mod) do
    do_par_fun_each(fun, mod, mod)
  end

  defp do_par_fun_each(fun, {mod, _, _} = item) do
    do_par_fun_each(fun, mod, item)
  end

  defp do_par_fun_each(fun, mod, item) do
    fn () ->
         try do
           fun.(item)
         catch
           _, error ->
             exit({:bad, {mod, error}})
         else
           {:ok, res} ->
             exit({:good, {mod, res}})
           {:error, error} ->
             exit({:bad, {mod, error}})
         end
    end
  end

  defp do_par_recv(0, good, bad) do
    {good, bad}
  end

  defp do_par_recv(n, good, bad) do
    receive do
      {:DOWN, _, :process, _, {:good, res}} ->
        do_par_recv(n - 1, [res | good], bad)
      {:DOWN, _, :process, _, {:bad, res}} ->
        do_par_recv(n - 1, good, [res | bad])
    end
  end

  defp call(req) do
    :code_server.call(req)
  end

  def start_link() do
    do_start()
  end

  defp do_start() do
    maybe_warn_for_cache()
    load_code_server_prerequisites()
    {:ok, [[root0]]} = :init.get_argument(:root)
    mode = start_get_mode()
    root = :filename.join([root0])
    res = :code_server.start_link([root, mode])
    maybe_stick_dirs(mode)
    res
  end

  defp load_code_server_prerequisites() do
    needed = [:beam_lib, :binary, :ets, :filename, :gb_sets,
                                                       :gb_trees, :lists, :os,
                                                                              :unicode]
    _ = (for m <- needed do
           ^m = m.module_info(:module)
         end)
    _ = :erl_features.enabled()
    :ok
  end

  defp maybe_stick_dirs(:interactive) do
    case (:init.get_argument(:nostick)) do
      {:ok, [[]]} ->
        :ok
      _ ->
        do_stick_dirs()
    end
  end

  defp maybe_stick_dirs(_) do
    :ok
  end

  defp do_stick_dirs() do
    do_s(:compiler)
    do_s(:stdlib)
    do_s(:kernel)
  end

  defp do_s(lib) do
    case (lib_dir(lib)) do
      {:error, _} ->
        :ok
      dir ->
        _ = stick_dir(:filename.append(dir, 'ebin'))
        :ok
    end
  end

  defp start_get_mode() do
    case (:init.get_argument(:mode)) do
      {:ok, [firstMode | rest]} ->
        case (rest) do
          [] ->
            :ok
          _ ->
            case (:logger.allow(:warning, :code)) do
              true ->
                :erlang.apply(:logger, :macro_log,
                                [%{mfa: {:code, :start_get_mode, 0}, line: 835,
                                     file: 'otp/lib/kernel/src/code.erl'},
                                     :warning, 'Multiple -mode given to erl, using the first, ~p', [firstMode]])
              false ->
                :ok
            end
        end
        case (firstMode) do
          ['embedded'] ->
            :embedded
          _ ->
            :interactive
        end
      _ ->
        :interactive
    end
  end

  def which(module) when is_atom(module) do
    case (is_loaded(module)) do
      false ->
        which(module, get_path())
      {:file, file} ->
        file
    end
  end

  defp which(module, path) when is_atom(module) do
    file = :erlang.atom_to_list(module) ++ objfile_extension()
    where_is_file(path, file)
  end

  def where_is_file(file) when is_list(file) do
    path = get_path()
    where_is_file(path, file)
  end

  def where_is_file([], _) do
    :non_existing
  end

  def where_is_file([{path, files} | tail], file) do
    where_is_file(tail, file, path, files)
  end

  def where_is_file([path | tail], file) do
    case (:erl_prim_loader.list_dir(path)) do
      {:ok, files} ->
        where_is_file(tail, file, path, files)
      _Error ->
        where_is_file(tail, file)
    end
  end

  defp where_is_file(tail, file, path, files) do
    case (:lists.member(file, files)) do
      true ->
        :filename.append(path, file)
      false ->
        where_is_file(tail, file)
    end
  end

  def get_doc(mod) when is_atom(mod) do
    get_doc(mod, %{sources: [:eep48, :debug_info]})
  end

  def get_doc(mod, %{sources: [source | sources]} = options) do
    getDoc = fn fn__ ->
                  r = (case (source) do
                         :debug_info ->
                           get_doc_chunk_from_ast(fn__)
                         :eep48 ->
                           get_doc_chunk(fn__, mod)
                       end)
                  case (r) do
                    {:error, :missing} ->
                      get_doc(mod, Map.put(options, :sources, sources))
                    _ ->
                      r
                  end
             end
    case (which(mod)) do
      :preloaded ->
        case (:code.lib_dir(:erts)) do
          {:error, _} ->
            {:error, :missing}
          ertsDir ->
            ertsEbinDir = (case (:filelib.is_dir(:filename.join([ertsDir,
                                                                     'ebin']))) do
                             true ->
                               :filename.join([ertsDir, 'ebin'])
                             false ->
                               :filename.join([ertsDir, 'preloaded', 'ebin'])
                           end)
            fn__ = :filename.join([ertsEbinDir,
                                       :erlang.atom_to_list(mod) ++ '.beam'])
            getDoc.(fn__)
        end
      error when is_atom(error) ->
        {:error, error}
      fn__ ->
        getDoc.(fn__)
    end
  end

  def get_doc(_, %{sources: []}) do
    {:error, :missing}
  end

  defp get_doc_chunk(filename, mod) when is_atom(mod) do
    case (:beam_lib.chunks(filename, ['Docs'])) do
      {:error, :beam_lib, {:missing_chunk, _, _}} ->
        get_doc_chunk(filename, :erlang.atom_to_list(mod))
      {:error, :beam_lib, {:file_error, _Filename, _Err}} ->
        get_doc_chunk(filename, :erlang.atom_to_list(mod))
      {:ok, {^mod, [{'Docs', bin}]}} ->
        {:ok, :erlang.binary_to_term(bin)}
    end
  end

  defp get_doc_chunk(filename, mod) do
    rootDir = :code.root_dir()
    case (:filename.dirname(filename)) do
      ^filename ->
        {:error, :missing}
      ^rootDir ->
        {:error, :missing}
      dir ->
        chunkFile = :filename.join([dir, 'doc', 'chunks', mod ++ '.chunk'])
        case (:file.read_file(chunkFile)) do
          {:ok, bin} ->
            {:ok, :erlang.binary_to_term(bin)}
          {:error, :enoent} ->
            get_doc_chunk(dir, mod)
          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp get_doc_chunk_from_ast(filename) do
    case (:beam_lib.chunks(filename, [:abstract_code])) do
      {:error, :beam_lib, {:missing_chunk, _, _}} ->
        {:error, :missing}
      {:error, :beam_lib, {:file_error, _, _}} ->
        {:error, :missing}
      {:ok,
         {_Mod, [{:abstract_code, {:raw_abstract_v1, aST}}]}} ->
        docs = get_function_docs_from_ast(aST)
        types = get_type_docs_from_ast(aST)
        {:ok,
           r_docs_v1(anno: 0, beam_language: :erlang, module_doc: :none,
               metadata: %{generated: true, otp_doc_vsn: {1, 0, 0}},
               docs: docs ++ types)}
      {:ok, {_Mod, [{:abstract_code, :no_abstract_code}]}} ->
        {:error, :missing}
      error ->
        error
    end
  end

  defp get_type_docs_from_ast(aST) do
    :lists.flatmap(fn e ->
                        get_type_docs_from_ast(e, aST)
                   end,
                     aST)
  end

  defp get_type_docs_from_ast({:attribute, anno, :type,
             {typeName, _, ps}} = meta,
            _) do
    arity = length(ps)
    signature = :io_lib.format('~p/~p', [typeName, arity])
    [{{:type, typeName, arity}, anno,
        [:unicode.characters_to_binary(signature)], :none,
        %{signature: [meta]}}]
  end

  defp get_type_docs_from_ast(_, _) do
    []
  end

  defp get_function_docs_from_ast(aST) do
    :lists.flatmap(fn e ->
                        get_function_docs_from_ast(e, aST)
                   end,
                     aST)
  end

  defp get_function_docs_from_ast({:function, anno, name, arity, _Code}, aST) do
    signature = :io_lib.format('~p/~p', [name, arity])
    specs = :lists.filter(fn {:attribute, _Ln, :spec,
                                {fA, _}} ->
                               case (fA) do
                                 {f, a} ->
                                   f === name and a === arity
                                 {_, f, a} ->
                                   f === name and a === arity
                               end
                             _ ->
                               false
                          end,
                            aST)
    specMd = (case (specs) do
                [s] ->
                  %{signature: [s]}
                [] ->
                  %{}
              end)
    [{{:function, name, arity}, anno,
        [:unicode.characters_to_binary(signature)], :none,
        specMd}]
  end

  defp get_function_docs_from_ast(_, _) do
    []
  end

  def set_primary_archive(archiveFile0, archiveBin, r_file_info() = fileInfo,
           parserFun)
      when (is_list(archiveFile0) and
              is_binary(archiveBin)) do
    archiveFile = :filename.absname(archiveFile0)
    case (call({:set_primary_archive, archiveFile,
                  archiveBin, fileInfo, parserFun})) do
      {:ok, []} ->
        :ok
      {:ok, _Mode, ebins} ->
        ebins2 = (for e <- ebins do
                    :filename.join([archiveFile, e])
                  end)
        add_pathsa(ebins2)
      {:error, _Reason} = error ->
        error
    end
  end

  def clash() do
    path = get_path()
    struct = :lists.flatten(build(path))
    len = length(search(struct))
    :io.format('** Found ~w name clashes in code paths ~n', [len])
  end

  defp search([]) do
    []
  end

  defp search([{dir, file} | tail]) do
    case (:lists.keyfind(file, 2, tail)) do
      false ->
        search(tail)
      {dir2, ^file} ->
        :io.format('** ~ts hides ~ts~n',
                     [:filename.join(dir, file), :filename.join(dir2, file)])
        [:clash | search(tail)]
    end
  end

  defp build([]) do
    []
  end

  defp build([dir | tail]) do
    files = filter(objfile_extension(), dir,
                     :erl_prim_loader.list_dir(dir))
    [decorate(files, dir) | build(tail)]
  end

  defp decorate([], _) do
    []
  end

  defp decorate([file | tail], dir) do
    [{dir, file} | decorate(tail, dir)]
  end

  defp filter(_Ext, dir, :error) do
    :io.format('** Bad path can\'t read ~ts~n', [dir])
    []
  end

  defp filter(ext, _, {:ok, files}) do
    filter2(ext, length(ext), files)
  end

  defp filter2(_Ext, _Extlen, []) do
    []
  end

  defp filter2(ext, extlen, [file | tail]) do
    case (has_ext(ext, extlen, file)) do
      true ->
        [file | filter2(ext, extlen, tail)]
      false ->
        filter2(ext, extlen, tail)
    end
  end

  defp has_ext(ext, extlen, file) do
    l = length(file)
    case ((try do
            :lists.nthtail(l - extlen, file)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      ^ext ->
        true
      _ ->
        false
    end
  end

  defp maybe_warn_for_cache() do
    case (:init.get_argument(:code_path_cache)) do
      {:ok, _} ->
        cache_warning()
      :error ->
        :ok
    end
  end

  defp cache_warning() do
    w = 'The code path cache functionality has been removed'
    :error_logger.warning_report(w)
  end

  def module_status() do
    module_status(for {m, _} <- all_loaded() do
                    m
                  end)
  end

  def module_status(modules) when is_list(modules) do
    pathFiles = path_files()
    for m <- modules do
      {m, module_status(m, pathFiles)}
    end
  end

  def module_status(module) do
    module_status(module, :code.get_path())
  end

  defp module_status(module, pathFiles) do
    case (is_loaded(module)) do
      false ->
        :not_loaded
      {:file, :preloaded} ->
        :loaded
      {:file, :cover_compiled} ->
        case (which(module, pathFiles)) do
          :non_existing ->
            :removed
          _File ->
            :modified
        end
      {:file, []} ->
        :loaded
      {:file, [_ | _]} ->
        case (which(module, pathFiles)) do
          :non_existing ->
            :removed
          path ->
            case (module_changed_on_disk(module, path)) do
              true ->
                :modified
              false ->
                :loaded
            end
        end
    end
  end

  defp module_changed_on_disk(module, path) do
    mD5 = :erlang.get_module_info(module, :md5)
    mD5 !== beam_file_md5(module, path)
  end

  defp beam_file_md5(module, path) do
    case (do_beam_file_md5(path)) do
      mD5 when is_binary(mD5) ->
        mD5
      :undefined ->
        case (get_object_code(module)) do
          {^module, code, _Path} ->
            do_beam_file_md5(code)
          :error ->
            :undefined
        end
    end
  end

  defp do_beam_file_md5(pathOrCode) do
    case (:beam_lib.md5(pathOrCode)) do
      {:ok, {_Mod, mD5}} ->
        mD5
      _ ->
        :undefined
    end
  end

  def modified_modules() do
    for {m, :modified} <- module_status() do
      m
    end
  end

  defp path_files() do
    path_files(:code.get_path())
  end

  defp path_files([]) do
    []
  end

  defp path_files([path | tail]) do
    case (:erl_prim_loader.list_dir(path)) do
      {:ok, files} ->
        [{path, files} | path_files(tail)]
      _Error ->
        path_files(tail)
    end
  end

end