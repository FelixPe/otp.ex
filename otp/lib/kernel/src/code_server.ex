defmodule :m_code_server do
  use Bitwise
  import :lists, only: [foreach: 2]
  require Record
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
  Record.defrecord(:r_state, :state, supervisor: :undefined,
                                 root: :undefined, path: :undefined,
                                 moddb: :undefined, namedb: :undefined,
                                 mode: :interactive, on_load: [], loading: %{})
  def start_link(args) do
    ref = make_ref()
    parent = self()
    init = fn () ->
                init(ref, parent, args)
           end
    spawn_link(init)
    receive do
      {^ref, res} ->
        res
    end
  end

  def is_loaded(mod) do
    case (:ets.lookup(:code_server, mod)) do
      [{^mod, file}] ->
        {:file, file}
      [] ->
        false
    end
  end

  def is_sticky(mod) do
    is_sticky(mod, :code_server)
  end

  defp init(ref, parent, [root, mode]) do
    :erlang.register(:code_server, self())
    :erlang.process_flag(:trap_exit, true)
    db = :ets.new(:code_server, [:named_table, :protected])
    foreach(fn m ->
                 :ets.insert(db, [{m, :preloaded}, {{:sticky, m}, true}])
            end,
              :erlang.pre_loaded())
    loaded0 = :init.fetch_loaded()
    loaded = (for {m, p} <- loaded0 do
                {m, :filename.join([p])}
              end)
    :ets.insert(db, loaded)
    iPath = (case (mode) do
               :interactive ->
                 libDir = :filename.append(root, 'lib')
                 {:ok, dirs} = :erl_prim_loader.list_dir(libDir)
                 paths = make_path(libDir, dirs)
                 userLibPaths = get_user_lib_dirs()
                 ['.'] ++ userLibPaths ++ paths
               _ ->
                 []
             end)
    path = add_loader_path(iPath, mode)
    state = r_state(supervisor: parent, root: root, path: path,
                moddb: db, namedb: create_namedb(path, root),
                mode: mode)
    send(parent, {ref, {:ok, self()}})
    loop(state)
  end

  defp get_user_lib_dirs() do
    case (:os.getenv('ERL_LIBS')) do
      libDirs0 when is_list(libDirs0) ->
        sep = (case (:os.type()) do
                 {:win32, _} ->
                   ?;
                 _ ->
                   ?:
               end)
        libDirs = split_paths(libDirs0, sep, [], [])
        get_user_lib_dirs_1(libDirs)
      false ->
        []
    end
  end

  defp get_user_lib_dirs_1([dir | dirList]) do
    case (:erl_prim_loader.list_dir(dir)) do
      {:ok, dirs} ->
        paths = make_path(dir, dirs)
        (for p <- paths, :filename.basename(p) === 'ebin' do
           p
         end) ++ get_user_lib_dirs_1(dirList)
      :error ->
        get_user_lib_dirs_1(dirList)
    end
  end

  defp get_user_lib_dirs_1([]) do
    []
  end

  defp split_paths([s | t], s, path, paths) do
    split_paths(t, s, [], [:lists.reverse(path) | paths])
  end

  defp split_paths([c | t], s, path, paths) do
    split_paths(t, s, [c | path], paths)
  end

  defp split_paths([], _S, path, paths) do
    :lists.reverse(paths, [:lists.reverse(path)])
  end

  def call(req) do
    ref = :erlang.monitor(:process, :code_server)
    send(:code_server, {:code_call, self(), req})
    receive do
      {:code_server, reply} ->
        :erlang.demonitor(ref, [:flush])
        reply
      {:DOWN, ^ref, :process, _, _} ->
        exit({:DOWN, :code_server, req})
    end
  end

  defp reply(pid, res) do
    send(pid, {:code_server, res})
  end

  defp loop(r_state(supervisor: supervisor) = state0) do
    receive do
      {:code_call, pid, req} ->
        case (handle_call(req, pid, state0)) do
          {:reply, res, state} ->
            _ = reply(pid, res)
            loop(state)
          {:noreply, state} ->
            loop(state)
          {:stop, why, :stopped, state} ->
            system_terminate(why, supervisor, [], state)
        end
      {:EXIT, ^supervisor, reason} ->
        system_terminate(reason, supervisor, [], state0)
      {:system, from, msg} ->
        handle_system_msg(:running, msg, from, supervisor,
                            state0)
      {:DOWN, ref, :process, pid, res} ->
        state = finish_on_load({pid, ref}, res, state0)
        loop(state)
      {{:LOADER_DOWN, info}, _Ref, :process, _Pid, _Res} ->
        state = loader_down(state0, info)
        loop(state)
      _Msg ->
        loop(state0)
    end
  end

  defp handle_system_msg(sysState, msg, from, parent, misc) do
    case (do_sys_cmd(sysState, msg, parent, misc)) do
      {:suspended, reply, nMisc} ->
        gen_reply(from, reply)
        suspend_loop(:suspended, parent, nMisc)
      {:running, reply, nMisc} ->
        gen_reply(from, reply)
        system_continue(parent, [], nMisc)
    end
  end

  defp gen_reply({to, tag}, reply) do
    (try do
      send(to, {tag, reply})
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end)
  end

  defp suspend_loop(sysState, parent, misc) do
    receive do
      {:system, from, msg} ->
        handle_system_msg(sysState, msg, from, parent, misc)
      {:EXIT, ^parent, reason} ->
        system_terminate(reason, parent, [], misc)
    end
  end

  defp do_sys_cmd(_, :suspend, _Parent, misc) do
    {:suspended, :ok, misc}
  end

  defp do_sys_cmd(_, :resume, _Parent, misc) do
    {:running, :ok, misc}
  end

  defp do_sys_cmd(sysState, :get_status, parent, misc) do
    status = {:status, self(), {:module, :code_server},
                [:erlang.get(), sysState, parent, [], misc]}
    {sysState, status, misc}
  end

  defp do_sys_cmd(sysState, {:debug, _What}, _Parent, misc) do
    {sysState, :ok, misc}
  end

  defp do_sys_cmd(:suspended, {:change_code, module, vsn, extra},
            _Parent, misc0) do
    {res, misc} = (case ((try do
                           :code_server.system_code_change(misc0, module, vsn,
                                                             extra)
                         catch
                           :error, e -> {:EXIT, {e, __STACKTRACE__}}
                           :exit, e -> {:EXIT, e}
                           e -> e
                         end)) do
                     {:ok, _} = ok ->
                       ok
                     else__ ->
                       {{:error, else__}, misc0}
                   end)
    {:suspended, res, misc}
  end

  defp do_sys_cmd(sysState, other, _Parent, misc) do
    {sysState, {:error, {:unknown_system_msg, other}}, misc}
  end

  defp system_continue(_Parent, _Debug, state) do
    loop(state)
  end

  defp system_terminate(_Reason, _Parent, _Debug, _State) do
    exit(:shutdown)
  end

  def system_code_change(state, _Module, _OldVsn, _Extra) do
    {:ok, state}
  end

  defp handle_call({:stick_dir, dir}, _From, s) do
    {:reply, stick_dir(dir, true, s), s}
  end

  defp handle_call({:unstick_dir, dir}, _From, s) do
    {:reply, stick_dir(dir, false, s), s}
  end

  defp handle_call({:stick_mod, mod}, _From, s) do
    {:reply, stick_mod(mod, true, s), s}
  end

  defp handle_call({:unstick_mod, mod}, _From, s) do
    {:reply, stick_mod(mod, false, s), s}
  end

  defp handle_call({:dir, dir}, _From, s) do
    root = r_state(s, :root)
    resp = do_dir(root, dir, r_state(s, :namedb))
    {:reply, resp, s}
  end

  defp handle_call({:add_path, where, dir0, cache}, _From,
            r_state(namedb: namedb, path: path0) = s) do
    {resp, path} = add_path(where, dir0, path0, cache,
                              namedb)
    {:reply, resp, r_state(s, path: path)}
  end

  defp handle_call({:add_paths, where, dirs0, cache}, _From,
            r_state(namedb: namedb, path: path0) = s) do
    {resp, path} = add_paths(where, dirs0, path0, cache,
                               namedb)
    {:reply, resp, r_state(s, path: path)}
  end

  defp handle_call({:set_path, pathList, cache}, _From,
            r_state(root: root, path: path0, namedb: namedb) = s) do
    {resp, path, newDb} = set_path(pathList, path0, cache,
                                     namedb, root)
    {:reply, resp, r_state(s, path: path,  namedb: newDb)}
  end

  defp handle_call({:del_path, name}, _From,
            r_state(path: path0, namedb: namedb) = s) do
    {resp, path} = del_path(name, path0, namedb)
    {:reply, resp, r_state(s, path: path)}
  end

  defp handle_call({:del_paths, names}, _From,
            r_state(path: path0, namedb: namedb) = s) do
    {resp, path} = del_paths(names, path0, namedb)
    {:reply, resp, r_state(s, path: path)}
  end

  defp handle_call({:replace_path, name, dir, cache}, _From,
            r_state(path: path0, namedb: namedb) = s) do
    {resp, path} = replace_path(name, dir, path0, cache,
                                  namedb)
    {:reply, resp, r_state(s, path: path)}
  end

  defp handle_call(:get_path, _From, s) do
    {:reply,
       for {p, _Cache} <- r_state(s, :path) do
         p
       end,
       s}
  end

  defp handle_call(:clear_cache, _From, s) do
    path = (for {p, cache} <- r_state(s, :path) do
              {p,
                 cond do
                   is_atom(cache) ->
                     cache
                   true ->
                     :cache
                 end}
            end)
    {:reply, :ok, r_state(s, path: path)}
  end

  defp handle_call({:load_module, pC, mod, file, purge,
             ensureLoaded},
            from, s)
      when is_atom(mod) do
    case (purge and :erlang.module_loaded(mod)) do
      true ->
        do_purge(mod)
      false ->
        :ok
    end
    try_finish_module(file, mod, pC, ensureLoaded, from, s)
  end

  defp handle_call({:load_error, ref, mod, error}, _From, s) do
    reply_loading(ref, mod, error, s)
  end

  defp handle_call({:delete, mod}, _From, st) when is_atom(mod) do
    case ((try do
            :erlang.delete_module(mod)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      true ->
        :ets.delete(r_state(st, :moddb), mod)
        {:reply, true, st}
      _ ->
        {:reply, false, st}
    end
  end

  defp handle_call({:purge, mod}, _From, st) when is_atom(mod) do
    {:reply, do_purge(mod), st}
  end

  defp handle_call({:soft_purge, mod}, _From, st)
      when is_atom(mod) do
    {:reply, do_soft_purge(mod), st}
  end

  defp handle_call(:all_loaded, _From, s) do
    db = r_state(s, :moddb)
    {:reply, all_loaded(db), s}
  end

  defp handle_call({:get_object_code, mod}, _From, st0)
      when is_atom(mod) do
    case (get_object_code(st0, mod)) do
      {bin, fName, st1} ->
        {:reply, {mod, bin, fName}, st1}
      {:error, st1} ->
        {:reply, :error, st1}
    end
  end

  defp handle_call({:get_object_code_for_loading, mod}, from, st0)
      when is_atom(mod) do
    case (:erlang.module_loaded(mod)) do
      true ->
        {:reply, {:module, mod}, st0}
      false when r_state(st0, :mode) === :interactive ->
        action = fn _, st1 ->
                      case (:erlang.module_loaded(mod)) do
                        true ->
                          {:reply, {:module, mod}, st1}
                        false ->
                          get_object_code_for_loading(st1, mod, from)
                      end
                 end
        handle_pending_on_load(action, mod, from, st0)
      false ->
        {:reply, {:error, :embedded}, st0}
    end
  end

  defp handle_call(:stop, _From, s) do
    {:stop, :normal, :stopped, s}
  end

  defp handle_call({:set_primary_archive, file, archiveBin,
             fileInfo, parserFun},
            _From, s = r_state(mode: mode)) do
    case (:erl_prim_loader.set_primary_archive(file,
                                                 archiveBin, fileInfo,
                                                 parserFun)) do
      {:ok, files} ->
        {:reply, {:ok, mode, files}, s}
      {:error, _Reason} = error ->
        {:reply, error, s}
    end
  end

  defp handle_call(:get_mode, _From, s = r_state(mode: mode)) do
    {:reply, mode, s}
  end

  defp handle_call({:finish_loading, prepared, ensureLoaded},
            _From, s) do
    {:reply, finish_loading(prepared, ensureLoaded, s), s}
  end

  defp handle_call(other, _From, s) do
    error_msg(' ** Codeserver*** ignoring ~w~n ', [other])
    {:noreply, s}
  end

  defp make_path(bundleDir, bundles0) do
    bundles = choose_bundles(bundles0)
    make_path(bundleDir, bundles, [])
  end

  defp choose_bundles(bundles) do
    archiveExt = archive_extension()
    bs = :lists.sort(for b <- bundles do
                       create_bundle(b, archiveExt)
                     end)
    for {_Name, _NumVsn,
           fullName} <- choose(:lists.reverse(bs), [],
                                 archiveExt) do
      fullName
    end
  end

  defp create_bundle(fullName, archiveExt) do
    baseName = :filename.basename(fullName, archiveExt)
    case (split_base(baseName)) do
      {name, vsnStr} ->
        case (vsn_to_num(vsnStr)) do
          {:ok, vsnNum} ->
            {name, vsnNum, fullName}
          false ->
            {fullName, [0], fullName}
        end
      _ ->
        {fullName, [0], fullName}
    end
  end

  defp vsn_to_num(vsn) do
    case (is_vsn(vsn)) do
      true ->
        {:ok,
           for s <- split(vsn, '.') do
             :erlang.list_to_integer(s)
           end}
      _ ->
        false
    end
  end

  defp is_vsn(str) when is_list(str) do
    vsns = split(str, '.')
    :lists.all(&is_numstr/1, vsns)
  end

  defp is_numstr(cs) do
    :lists.all(fn c when (?0 <= c and c <= ?9) ->
                    true
                  _ ->
                    false
               end,
                 cs)
  end

  defp split(cs, s) do
    split1(cs, s, [])
  end

  defp split1([c | s], seps, toks) do
    case (:lists.member(c, seps)) do
      true ->
        split1(s, seps, toks)
      false ->
        split2(s, seps, toks, [c])
    end
  end

  defp split1([], _Seps, toks) do
    :lists.reverse(toks)
  end

  defp split2([c | s], seps, toks, cs) do
    case (:lists.member(c, seps)) do
      true ->
        split1(s, seps, [:lists.reverse(cs) | toks])
      false ->
        split2(s, seps, toks, [c | cs])
    end
  end

  defp split2([], _Seps, toks, cs) do
    :lists.reverse([:lists.reverse(cs) | toks])
  end

  defp join([h1, h2 | t], s) do
    h1 ++ s ++ join([h2 | t], s)
  end

  defp join([h], _) do
    h
  end

  defp join([], _) do
    []
  end

  defp choose([{name, numVsn, newFullName} = new | bs], acc,
            archiveExt) do
    case (:lists.keyfind(name, 1, acc)) do
      {_, nV, oldFullName} when nV === numVsn ->
        case (:filename.extension(oldFullName) === archiveExt) do
          false ->
            choose(bs, acc, archiveExt)
          true ->
            acc2 = :lists.keystore(name, 1, acc, new)
            choose(bs, acc2, archiveExt)
        end
      {_, _, _} ->
        choose(bs, acc, archiveExt)
      false ->
        choose(bs, [{name, numVsn, newFullName} | acc],
                 archiveExt)
    end
  end

  defp choose([], acc, _ArchiveExt) do
    acc
  end

  defp make_path(_, [], res) do
    res
  end

  defp make_path(bundleDir, [bundle | tail], res) do
    dir = :filename.append(bundleDir, bundle)
    ebin = :filename.append(dir, 'ebin')
    case (is_dir(ebin)) do
      true ->
        make_path(bundleDir, tail, [ebin | res])
      false ->
        ext = archive_extension()
        base = :filename.basename(bundle, ext)
        ebin2 = :filename.join([bundleDir, base ++ ext, base,
                                                            'ebin'])
        ebins = (case (split_base(base)) do
                   {appName, _} ->
                     ebin3 = :filename.join([bundleDir, base ++ ext, appName,
                                                                         'ebin'])
                     [ebin3, ebin2, dir]
                   _ ->
                     [ebin2, dir]
                 end)
        case (try_ebin_dirs(ebins)) do
          {:ok, foundEbin} ->
            make_path(bundleDir, tail, [foundEbin | res])
          :error ->
            make_path(bundleDir, tail, res)
        end
    end
  end

  defp try_ebin_dirs([ebin | ebins]) do
    case (is_dir(ebin)) do
      true ->
        {:ok, ebin}
      false ->
        try_ebin_dirs(ebins)
    end
  end

  defp try_ebin_dirs([]) do
    :error
  end

  defp add_loader_path(iPath0, mode) do
    {:ok, primP0} = :erl_prim_loader.get_path()
    case (mode) do
      :embedded ->
        cache_path(strip_path(primP0, mode))
      _ ->
        pa0 = get_arg(:pa)
        pz0 = get_arg(:pz)
        pa = patch_path(pa0)
        pz = patch_path(pz0)
        primP = patch_path(primP0)
        iPath = patch_path(iPath0)
        path0 = exclude_pa_pz(primP, pa, pz)
        path1 = strip_path(path0, mode)
        path2 = merge_path(path1, iPath, [])
        path3 = cache_path(path2)
        add_pa_pz(path3, pa, pz)
    end
  end

  defp cache_path(path) do
    default = cache_boot_paths()
    for p <- path do
      {p, do_cache_path(p, default)}
    end
  end

  defp do_cache_path('.', _) do
    :nocache
  end

  defp do_cache_path(_, default) do
    default
  end

  defp cache_boot_paths() do
    case (:init.get_argument(:cache_boot_paths)) do
      {:ok, [['false']]} ->
        :nocache
      _ ->
        :cache
    end
  end

  defp patch_path(path) do
    case (check_path(path)) do
      {:ok, newPath} ->
        newPath
      {:error, _Reason} ->
        path
    end
  end

  defp exclude_pa_pz(p0, pa, []) do
    p0 -- pa
  end

  defp exclude_pa_pz(p0, pa, pz) do
    :lists.reverse(:lists.reverse((p0 -- pa)) -- pz)
  end

  defp strip_path([p0 | ps], mode) do
    p = :filename.join([p0])
    case (check_path([p])) do
      {:ok, [newP]} ->
        [newP | strip_path(ps, mode)]
      _ when mode === :embedded ->
        [p | strip_path(ps, mode)]
      _ ->
        strip_path(ps, mode)
    end
  end

  defp strip_path(_, _) do
    []
  end

  defp merge_path(path, ['.' | iPath], acc) do
    rPath = merge_path1(path, iPath, acc)
    ['.' | :lists.delete('.', rPath)]
  end

  defp merge_path(path, iPath, acc) do
    merge_path1(path, iPath, acc)
  end

  defp merge_path1([p | path], iPath, acc) do
    case (:lists.member(p, acc)) do
      true ->
        merge_path1(path, iPath, acc)
      false ->
        iPath1 = exclude(p, iPath)
        merge_path1(path, iPath1, [p | acc])
    end
  end

  defp merge_path1(_, iPath, acc) do
    :lists.reverse(acc) ++ iPath
  end

  defp add_pa_pz(path0, patha, pathz) do
    {_, path1} = add_paths(:first, patha, path0, :nocache,
                             false)
    case (pathz) do
      [] ->
        path1
      _ ->
        {_, path2} = add_paths(:first, pathz,
                                 :lists.reverse(path1), :nocache, false)
        :lists.reverse(path2)
    end
  end

  defp get_arg(arg) do
    case (:init.get_argument(arg)) do
      {:ok, values} ->
        :lists.append(values)
      _ ->
        []
    end
  end

  defp exclude(dir, path) do
    name = get_name(dir)
    for d <- path, d !== dir, get_name(d) !== name do
      d
    end
  end

  defp get_name(dir) do
    get_name_from_splitted(:filename.split(dir))
  end

  defp get_name_from_splitted([dirName, 'ebin']) do
    discard_after_hyphen(dirName)
  end

  defp get_name_from_splitted([dirName]) do
    discard_after_hyphen(dirName)
  end

  defp get_name_from_splitted([_ | t]) do
    get_name_from_splitted(t)
  end

  defp get_name_from_splitted([]) do
    ''
  end

  defp discard_after_hyphen('-' ++ _) do
    []
  end

  defp discard_after_hyphen([h | t]) do
    [h | discard_after_hyphen(t)]
  end

  defp discard_after_hyphen([]) do
    []
  end

  defp split_base(baseName) do
    case (split(baseName, '-')) do
      [_, _ | _] = toks ->
        vsn = :lists.last(toks)
        allButLast = :lists.droplast(toks)
        {join(allButLast, '-'), vsn}
      [_ | _] ->
        baseName
    end
  end

  defp check_path(path) do
    pathChoice = :init.code_path_choice()
    archiveExt = archive_extension()
    do_check_path(path, pathChoice, archiveExt, [])
  end

  defp do_check_path([], _PathChoice, _ArchiveExt, acc) do
    {:ok, :lists.reverse(acc)}
  end

  defp do_check_path([dir | tail], pathChoice, archiveExt, acc) do
    case (is_dir(dir)) do
      true ->
        do_check_path(tail, pathChoice, archiveExt, [dir | acc])
      false when pathChoice === :strict ->
        {:error, :bad_directory}
      false when pathChoice === :relaxed ->
        case ((try do
                :lists.reverse(:filename.split(dir))
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end)) do
          {:EXIT, _} ->
            {:error, :bad_directory}
          ['ebin', app] ->
            dir2 = :filename.join([app ++ archiveExt, app, 'ebin'])
            case (is_dir(dir2)) do
              true ->
                do_check_path(tail, pathChoice, archiveExt,
                                [dir2 | acc])
              false ->
                {:error, :bad_directory}
            end
          ['ebin', app, optArchive | revTop] ->
            ext = :filename.extension(optArchive)
            base = :filename.basename(optArchive, ext)
            dir2 = (cond do
                      (ext === archiveExt and base === app) ->
                        top = :lists.reverse(revTop)
                        :filename.join(top ++ [app, 'ebin'])
                      ext === archiveExt ->
                        {:error, :bad_directory}
                      true ->
                        top = :lists.reverse([optArchive | revTop])
                        :filename.join(top ++ [app ++ archiveExt, app, 'ebin'])
                    end)
            case (is_dir(dir2)) do
              true ->
                do_check_path(tail, pathChoice, archiveExt,
                                [dir2 | acc])
              false ->
                {:error, :bad_directory}
            end
          _ ->
            {:error, :bad_directory}
        end
    end
  end

  defp add_path(where, dir, path, cache, nameDb)
      when is_atom(dir) do
    add_path(where, :erlang.atom_to_list(dir), path, cache,
               nameDb)
  end

  defp add_path(where, dir0, path, cache, nameDb)
      when is_list(dir0) do
    case (int_list(dir0)) do
      true ->
        dir = :filename.join([dir0])
        case (check_path([dir])) do
          {:ok, [newDir]} ->
            {true, do_add(where, newDir, path, cache, nameDb)}
          error ->
            {error, path}
        end
      false ->
        {{:error, :bad_directory}, path}
    end
  end

  defp add_path(_, _, path, _, _) do
    {{:error, :bad_directory}, path}
  end

  defp do_add(:first, dir, path, cache, nameDb) do
    update(dir, nameDb)
    [{dir, cache} | :lists.keydelete(dir, 1, path)]
  end

  defp do_add(:last, dir, path, cache, nameDb) do
    case (:lists.keymember(dir, 1, path)) do
      true ->
        :lists.keyreplace(dir, 1, path, {dir, cache})
      false ->
        maybe_update(dir, nameDb)
        path ++ [{dir, cache}]
    end
  end

  defp maybe_update(dir, nameDb) do
    lookup_name(get_name(dir),
                  nameDb) === false and update(dir, nameDb)
  end

  defp update(_Dir, false) do
    true
  end

  defp update(dir, nameDb) do
    replace_name(dir, nameDb)
  end

  defp set_path(newPath0, oldPath, cache, nameDb, root) do
    newPath = normalize(newPath0)
    case (check_path(newPath)) do
      {:ok, newPath2} ->
        :ets.delete(nameDb)
        newPath3 = (for p <- newPath2 do
                      {p, cache}
                    end)
        newDb = create_namedb(newPath3, root)
        {true, newPath3, newDb}
      error ->
        {error, oldPath, nameDb}
    end
  end

  defp normalize([p | path]) when is_atom(p) do
    normalize([:erlang.atom_to_list(p) | path])
  end

  defp normalize([p | path]) when is_list(p) do
    case (int_list(p)) do
      true ->
        [:filename.join([p]) | normalize(path)]
      false ->
        [p | normalize(path)]
    end
  end

  defp normalize([p | path]) do
    [p | normalize(path)]
  end

  defp normalize([]) do
    []
  end

  defp normalize(other) do
    other
  end

  defp create_namedb(path, root) do
    db = :ets.new(:code_names, [:named_table, :public])
    init_namedb(:lists.reverse(path), db)
    case (lookup_name('erts', db)) do
      {:ok, _, _, _} ->
        :ok
      false ->
        ertsDir = :filename.join(root, 'erts')
        case (:erl_prim_loader.read_file_info(ertsDir)) do
          :error ->
            :ok
          _ ->
            do_insert_name('erts', ertsDir, db)
        end
    end
    db
  end

  defp init_namedb([{p, _Cache} | path], db) do
    insert_dir(p, db)
    init_namedb(path, db)
  end

  defp init_namedb([], _) do
    :ok
  end

  defp insert_dir(dir, db) do
    splitted = :filename.split(dir)
    case (get_name_from_splitted(splitted)) do
      name when (name != 'ebin' and name != '.') ->
        name
      _ ->
        splittedAbsName = :filename.split(absname(dir))
        name = get_name_from_splitted(splittedAbsName)
    end
    appDir = :filename.join(del_ebin_1(splitted))
    do_insert_name(name, appDir, db)
  end

  defp insert_name(name, dir, db) do
    appDir = del_ebin(dir)
    do_insert_name(name, appDir, db)
  end

  defp do_insert_name(name, appDir, db) do
    {base, subDirs} = archive_subdirs(appDir)
    :ets.insert(db, {name, appDir, base, subDirs})
    true
  end

  defp archive_subdirs(appDir) do
    base = :filename.basename(appDir)
    dirs = (case (split_base(base)) do
              {name, _} ->
                [name, base]
              _ ->
                [base]
            end)
    ext = archive_extension()
    try_archive_subdirs(appDir ++ ext, base, dirs)
  end

  defp try_archive_subdirs(archive, base, [dir | dirs]) do
    archiveDir = :filename.append(archive, dir)
    case (:erl_prim_loader.list_dir(archiveDir)) do
      {:ok, files} ->
        isDir = fn relFile ->
                     file = :filename.append(archiveDir, relFile)
                     is_dir(file)
                end
        {dir, :lists.filter(isDir, files)}
      _ ->
        try_archive_subdirs(archive, base, dirs)
    end
  end

  defp try_archive_subdirs(_Archive, base, []) do
    {base, []}
  end

  defp del_path(name0, path, nameDb) do
    case ((try do
            :filename.join([to_list(name0)])
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      {:EXIT, _} ->
        {{:error, :bad_name}, path}
      name ->
        case (del_path1(name, path, nameDb)) do
          ^path ->
            {false, path}
          newPath ->
            {true, newPath}
        end
    end
  end

  defp del_path1(name, [{p, cache} | path], nameDb) do
    case (get_name(p)) do
      ^name ->
        delete_name(name, nameDb)
        insert_old_shadowed(name, path, nameDb)
        path
      _ when name === p ->
        case (delete_name_dir(name, nameDb)) do
          true ->
            insert_old_shadowed(get_name(name), path, nameDb)
          false ->
            :ok
        end
        path
      _ ->
        [{p, cache} | del_path1(name, path, nameDb)]
    end
  end

  defp del_path1(_, [], _) do
    []
  end

  defp insert_old_shadowed(name, [{p, _Cache} | path], nameDb) do
    case (get_name(p)) do
      ^name ->
        insert_name(name, p, nameDb)
      _ ->
        insert_old_shadowed(name, path, nameDb)
    end
  end

  defp insert_old_shadowed(_, [], _) do
    :ok
  end

  defp replace_path(name, dir, path, cache, nameDb) do
    case ((try do
            check_pars(name, dir)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      {:ok, n, d} ->
        {true, replace_path1(n, d, path, cache, nameDb)}
      {:EXIT, _} ->
        {{:error, {:badarg, [name, dir]}}, path}
      error ->
        {error, path}
    end
  end

  defp replace_path1(name, dir, [{p, _} = pair | path], cache,
            nameDb) do
    case (get_name(p)) do
      ^name ->
        insert_name(name, dir, nameDb)
        [{dir, cache} | path]
      _ ->
        [pair | replace_path1(name, dir, path, cache, nameDb)]
    end
  end

  defp replace_path1(name, dir, [], cache, nameDb) do
    insert_name(name, dir, nameDb)
    [{dir, cache}]
  end

  defp check_pars(name, dir) do
    n = to_list(name)
    d = :filename.join([to_list(dir)])
    case (get_name(dir)) do
      ^n ->
        case (check_path([d])) do
          {:ok, [newD]} ->
            {:ok, n, newD}
          error ->
            error
        end
      _ ->
        {:error, :bad_name}
    end
  end

  defp del_ebin(dir) do
    :filename.join(del_ebin_1(:filename.split(dir)))
  end

  defp del_ebin_1([parent, app, 'ebin']) do
    case (:filename.basename(parent)) do
      [] ->
        [parent, app]
      _ ->
        ext = archive_extension()
        case (:filename.basename(parent, ext)) do
          ^parent ->
            [parent, app]
          archive ->
            [archive]
        end
    end
  end

  defp del_ebin_1(path = [_App, 'ebin']) do
    del_ebin_1(:filename.split(absname(:filename.join(path))))
  end

  defp del_ebin_1(['ebin']) do
    del_ebin_1(:filename.split(absname('ebin')))
  end

  defp del_ebin_1([h | t]) do
    [h | del_ebin_1(t)]
  end

  defp del_ebin_1([]) do
    []
  end

  defp replace_name(dir, db) do
    case (get_name(dir)) do
      ^dir ->
        false
      name ->
        delete_name(name, db)
        insert_name(name, dir, db)
    end
  end

  defp delete_name(name, db) do
    :ets.delete(db, name)
  end

  defp delete_name_dir(dir, db) do
    case (get_name(dir)) do
      ^dir ->
        false
      name ->
        dir0 = del_ebin(dir)
        case (lookup_name(name, db)) do
          {:ok, ^dir0, _Base, _SubDirs} ->
            :ets.delete(db, name)
            true
          _ ->
            false
        end
    end
  end

  defp lookup_name(name, db) do
    case (:ets.lookup(db, name)) do
      [{^name, dir, base, subDirs}] ->
        {:ok, dir, base, subDirs}
      _ ->
        false
    end
  end

  defp do_dir(root, :lib_dir, _) do
    :filename.append(root, 'lib')
  end

  defp do_dir(root, :root_dir, _) do
    root
  end

  defp do_dir(_Root, :compiler_dir, nameDb) do
    case (lookup_name('compiler', nameDb)) do
      {:ok, dir, _Base, _SubDirs} ->
        dir
      _ ->
        ''
    end
  end

  defp do_dir(_Root, {:lib_dir, name}, nameDb) do
    case ((try do
            lookup_name(to_list(name), nameDb)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      {:ok, dir, _Base, _SubDirs} ->
        dir
      _ ->
        {:error, :bad_name}
    end
  end

  defp do_dir(_Root, {:lib_dir, name, subDir0}, nameDb) do
    subDir = :erlang.atom_to_list(subDir0)
    case ((try do
            lookup_name(to_list(name), nameDb)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end)) do
      {:ok, dir, base, subDirs} ->
        case (:lists.member(subDir, subDirs)) do
          true ->
            :filename.join([dir ++ archive_extension(), base,
                                                            subDir])
          false ->
            :filename.join([dir, subDir])
        end
      _ ->
        {:error, :bad_name}
    end
  end

  defp do_dir(_Root, {:priv_dir, name}, nameDb) do
    do_dir(_Root, {:lib_dir, name, :priv}, nameDb)
  end

  defp do_dir(_, _, _) do
    :"bad request to code"
  end

  defp stick_dir(dir, stick, st) do
    case (:erl_prim_loader.list_dir(dir)) do
      {:ok, listing} ->
        mods = get_mods(listing, objfile_extension())
        db = r_state(st, :moddb)
        case (stick) do
          true ->
            foreach(fn m ->
                         :ets.insert(db, {{:sticky, m}, true})
                    end,
                      mods)
          false ->
            foreach(fn m ->
                         :ets.delete(db, {:sticky, m})
                    end,
                      mods)
        end
      error ->
        error
    end
  end

  defp stick_mod(m, stick, st) do
    db = r_state(st, :moddb)
    case (stick) do
      true ->
        :ets.insert(db, {{:sticky, m}, true})
      false ->
        :ets.delete(db, {:sticky, m})
    end
  end

  defp get_mods([file | tail], extension) do
    case (:filename.extension(file)) do
      ^extension ->
        [:erlang.list_to_atom(:filename.basename(file,
                                                   extension)) |
             get_mods(tail, extension)]
      _ ->
        get_mods(tail, extension)
    end
  end

  defp get_mods([], _) do
    []
  end

  defp is_sticky(mod, db) do
    :erlang.module_loaded(mod) and :ets.lookup(db,
                                                 {:sticky, mod}) !== []
  end

  defp add_paths(where, [dir | tail], path, cache, nameDb) do
    {_, nPath} = add_path(where, dir, path, cache, nameDb)
    add_paths(where, tail, nPath, cache, nameDb)
  end

  defp add_paths(_, _, path, _, _) do
    {:ok, path}
  end

  defp del_paths([name | names], path, nameDb) do
    {_, nPath} = del_path(name, path, nameDb)
    del_paths(names, nPath, nameDb)
  end

  defp del_paths(_, path, _) do
    {:ok, path}
  end

  defp try_finish_module(file, mod, pC, ensureLoaded, from, st) do
    action = (case (ensureLoaded) do
                false ->
                  fn _, s ->
                       try_finish_module_1(file, mod, pC, from, false, s)
                  end
                _ ->
                  fn _, s0 ->
                       case (:erlang.module_loaded(mod)) do
                         true ->
                           reply_loading(ensureLoaded, mod, {:module, mod}, s0)
                         false when r_state(s0, :mode) === :interactive ->
                           try_finish_module_1(file, mod, pC, from,
                                                 ensureLoaded, s0)
                         false ->
                           reply_loading(ensureLoaded, mod, {:error, :embedded},
                                           s0)
                       end
                  end
              end)
    handle_pending_on_load(action, mod, from, st)
  end

  defp try_finish_module_1(file, mod, pC, from, ensureLoaded,
            r_state(moddb: db) = st) do
    case (is_sticky(mod, db)) do
      true ->
        error_msg('Can\'t load module \'~w\' that resides in sticky dir\n', [mod])
        reply_loading(ensureLoaded, mod,
                        {:error, :sticky_directory}, st)
      false ->
        try_finish_module_2(file, mod, pC, from, ensureLoaded,
                              st)
    end
  end

  defp try_finish_module_2(file, mod, pC, from, ensureLoaded, st0) do
    action = fn result, r_state(moddb: db) = st1 ->
                  case (result) do
                    {:module, _} ->
                      :ets.insert(db, {mod, file})
                    {:error, :on_load_failure} ->
                      :ok
                    {:error, what} ->
                      error_msg('Loading of ~ts failed: ~p\n', [file, what])
                  end
                  reply_loading(ensureLoaded, mod, result, st1)
             end
    res = (case (:erlang.finish_loading([pC])) do
             :ok ->
               {:module, mod}
             {error, [^mod]} ->
               {:error, error}
           end)
    handle_on_load(res, action, mod, from, st0)
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

  defp get_object_code(r_state(path: path) = st, mod) when is_atom(mod) do
    modStr = :erlang.atom_to_list(mod)
    case (:erl_prim_loader.is_basename(modStr)) do
      true ->
        case (mod_to_bin(path, modStr ++ objfile_extension(),
                           [])) do
          {binary, file, newPath} ->
            {binary, file, r_state(st, path: newPath)}
          {:error, newPath} ->
            {:error, r_state(st, path: newPath)}
        end
      false ->
        {:error, st}
    end
  end

  defp get_object_code_for_loading(st0, mod, from) do
    case (wait_loading(st0, mod, from)) do
      {true, st1} ->
        {:noreply, st1}
      false ->
        case (get_object_code(st0, mod)) do
          {bin, fName, st1} ->
            {ref, st2} = monitor_loader(st1, mod, from, bin, fName)
            {:reply, {bin, fName, ref}, st2}
          {:error, st1} ->
            {:reply, {:error, :nofile}, st1}
        end
    end
  end

  defp monitor_loader(r_state(loading: loading0) = st, mod, pid, bin,
            fName) do
    tag = {:LOADER_DOWN, {mod, bin, fName}}
    ref = :erlang.monitor(:process, pid, [{:tag, tag}])
    loading = Map.put(loading0, mod, [])
    {ref, r_state(st, loading: loading)}
  end

  defp wait_loading(r_state(loading: loading0) = st, mod, pid) do
    case (loading0) do
      %{^mod => waiting} ->
        loading = %{loading0 | mod => [pid | waiting]}
        {true, r_state(st, loading: loading)}
      _ ->
        false
    end
  end

  defp reply_loading(ref, mod, reply, r_state(loading: loading0) = st)
      when is_reference(ref) do
    {waiting, loading} = :maps.take(mod, loading0)
    _ = (for pid <- waiting do
           reply(pid, reply)
         end)
    :erlang.demonitor(ref, [:flush])
    {:reply, reply, r_state(st, loading: loading)}
  end

  defp reply_loading(ref, _Mod, reply, st) when is_boolean(ref) do
    {:reply, reply, st}
  end

  defp loader_down(r_state(loading: loading0) = st, {mod, bin, fName}) do
    case (loading0) do
      %{^mod => [first | rest]} ->
        tag = {:LOADER_DOWN, {mod, bin, fName}}
        ref = :erlang.monitor(:process, first, [{:tag, tag}])
        loading = %{loading0 | mod => rest}
        _ = reply(first, {bin, fName, ref})
        r_state(st, loading: loading)
      %{^mod => []} ->
        loading = :maps.remove(mod, loading0)
        r_state(st, loading: loading)
      %{} ->
        st
    end
  end

  defp mod_to_bin([{dir, cache0} | tail], modFile, acc) do
    case (with_cache(cache0, dir, modFile)) do
      {true, cache1} ->
        file = :filename.append(dir, modFile)
        case (:erl_prim_loader.get_file(file)) do
          :error ->
            mod_to_bin(tail, modFile, [{dir, cache1} | acc])
          {:ok, bin, _} ->
            path = :lists.reverse(acc, [{dir, cache1} | tail])
            case (:filename.pathtype(file)) do
              :absolute ->
                {bin, file, path}
              _ ->
                {bin, absname(file), path}
            end
        end
      {false, cache1} ->
        mod_to_bin(tail, modFile, [{dir, cache1} | acc])
    end
  end

  defp mod_to_bin([], modFile, acc) do
    case (:erl_prim_loader.get_file(modFile)) do
      :error ->
        {:error, :lists.reverse(acc)}
      {:ok, bin, fName} ->
        {bin, absname(fName), :lists.reverse(acc)}
    end
  end

  defp with_cache(:nocache, _Dir, _ModFile) do
    {true, :nocache}
  end

  defp with_cache(:cache, dir, modFile) do
    case (:erl_prim_loader.list_dir(dir)) do
      {:ok, entries} ->
        with_cache(:maps.from_keys(entries, []), dir, modFile)
      :error ->
        {false, :cache}
    end
  end

  defp with_cache(cache, _Dir, modFile) when is_map(cache) do
    {:erlang.is_map_key(modFile, cache), cache}
  end

  def absname(file) do
    case (:erl_prim_loader.get_cwd()) do
      {:ok, cwd} ->
        absname(file, cwd)
      _Error ->
        file
    end
  end

  defp absname(name, absBase) do
    case (:filename.pathtype(name)) do
      :relative ->
        :filename.absname_join(absBase, name)
      :absolute ->
        :filename.join([:filename.flatten(name)])
      :volumerelative ->
        absname_vr(:filename.split(name),
                     :filename.split(absBase), absBase)
    end
  end

  defp absname_vr(['/' | rest1], [volume | _], _AbsBase) do
    :filename.join([volume | rest1])
  end

  defp absname_vr([[x, ?:] | rest1], [[x | _] | _], absBase) do
    absname(:filename.join(rest1), absBase)
  end

  defp absname_vr([[x, ?:] | name], _, _AbsBase) do
    dcwd = (case (:erl_prim_loader.get_cwd([x, ?:])) do
              {:ok, dir} ->
                dir
              :error ->
                [x, ?:, ?/]
            end)
    absname(:filename.join(name), dcwd)
  end

  defp do_purge(mod) do
    {_WasOld, didKill} = :erts_code_purger.purge(mod)
    didKill
  end

  defp do_soft_purge(mod) do
    :erts_code_purger.soft_purge(mod)
  end

  defp is_dir(path) do
    case (:erl_prim_loader.read_file_info(path)) do
      {:ok, r_file_info(type: :directory)} ->
        true
      _ ->
        false
    end
  end

  defp finish_loading(prepared, ensureLoaded, r_state(moddb: db) = st) do
    ps = [fn l ->
               finish_loading_ensure(l, ensureLoaded)
          end,
              fn l ->
                   abort_if_pending_on_load(l, st)
              end,
                  fn l ->
                       abort_if_sticky(l, db)
                  end,
                      fn l ->
                           do_finish_loading(l, st)
                      end]
    run(ps, prepared)
  end

  defp finish_loading_ensure(prepared, true) do
    {:ok,
       for ({m, _} = p) <- prepared,
             not :erlang.module_loaded(m) do
         p
       end}
  end

  defp finish_loading_ensure(prepared, false) do
    {:ok, prepared}
  end

  defp abort_if_pending_on_load(l, r_state(on_load: [])) do
    {:ok, l}
  end

  defp abort_if_pending_on_load(l, r_state(on_load: onLoad)) do
    pending = (for {m, _} <- l,
                     :lists.keymember(m, 2, onLoad) do
                 {m, :pending_on_load}
               end)
    case (pending) do
      [] ->
        {:ok, l}
      [_ | _] ->
        {:error, pending}
    end
  end

  defp abort_if_sticky(l, db) do
    sticky = (for {m, _} <- l, is_sticky(m, db) do
                {m, :sticky_directory}
              end)
    case (sticky) do
      [] ->
        {:ok, l}
      [_ | _] ->
        {:error, sticky}
    end
  end

  defp do_finish_loading(prepared, r_state(moddb: db)) do
    magicBins = (for {_, {b, _}} <- prepared do
                   b
                 end)
    case (:erlang.finish_loading(magicBins)) do
      :ok ->
        mFs = (for {m, {_, f}} <- prepared do
                 {m, f}
               end)
        true = :ets.insert(db, mFs)
        :ok
      {reason, ms} ->
        {:error,
           for m <- ms do
             {m, reason}
           end}
    end
  end

  defp run([f], data) do
    f.(data)
  end

  defp run([f | fs], data0) do
    case (f.(data0)) do
      {:ok, data} ->
        run(fs, data)
      {:error, _} = error ->
        error
    end
  end

  defp handle_on_load({:error, :on_load}, action, mod, from, st0) do
    r_state(on_load: onLoad0) = st0
    fun = fn () ->
               res = :erlang.call_on_load_function(mod)
               exit(res)
          end
    pidRef = spawn_monitor(fun)
    pidAction = {from, action}
    onLoad = [{pidRef, mod, [pidAction]} | onLoad0]
    st = r_state(st0, on_load: onLoad)
    {:noreply, st}
  end

  defp handle_on_load(res, action, _, _, st) do
    action.(res, st)
  end

  defp handle_pending_on_load(action, mod, from, r_state(on_load: onLoad0) = st) do
    case (:lists.keyfind(mod, 2, onLoad0)) do
      false ->
        action.({:module, mod}, st)
      {{^from, _Ref}, ^mod, _Pids} ->
        {:reply, {:error, :deadlock}, st}
      {_, _, _} ->
        onLoad = handle_pending_on_load_1(mod, {from, action},
                                            onLoad0)
        {:noreply, r_state(st, on_load: onLoad)}
    end
  end

  defp handle_pending_on_load_1(mod, from, [{pidRef, mod, pids} | t]) do
    [{pidRef, mod, [from | pids]} | t]
  end

  defp handle_pending_on_load_1(mod, from, [h | t]) do
    [h | handle_pending_on_load_1(mod, from, t)]
  end

  defp handle_pending_on_load_1(_, _, []) do
    []
  end

  defp finish_on_load(pidRef, onLoadRes, r_state(on_load: onLoad0) = st0) do
    case (:lists.keyfind(pidRef, 1, onLoad0)) do
      false ->
        st0
      {^pidRef, mod, waiting} ->
        st = finish_on_load_1(mod, onLoadRes, waiting, st0)
        onLoad = (for ({r, _, _} = e) <- onLoad0,
                        r !== pidRef do
                    e
                  end)
        r_state(st, on_load: onLoad)
    end
  end

  defp finish_on_load_1(mod, onLoadRes, waiting, st) do
    keep = onLoadRes === :ok
    :erts_code_purger.finish_after_on_load(mod, keep)
    res = (case (keep) do
             false ->
               _ = finish_on_load_report(mod, onLoadRes)
               {:error, :on_load_failure}
             true ->
               {:module, mod}
           end)
    finish_on_load_2(waiting, res, st)
  end

  defp finish_on_load_2([{pid, action} | t], res, st0) do
    case (action.(res, st0)) do
      {:reply, rep, st} ->
        _ = reply(pid, rep)
        finish_on_load_2(t, res, st)
      {:noreply, st} ->
        finish_on_load_2(t, res, st)
    end
  end

  defp finish_on_load_2([], _, st) do
    st
  end

  defp finish_on_load_report(_Mod, atom) when is_atom(atom) do
    :ok
  end

  defp finish_on_load_report(mod, term) do
    spawn(fn () ->
               f = 'The on_load function for module ~s returned:~n~P\n'
               e = :error_logger
               e.warning_msg(f, [mod, term, 10])
          end)
  end

  defp all_loaded(db) do
    ms = :ets.fun2ms(fn {m, _} = t when is_atom(m) ->
                          t
                     end)
    :ets.select(db, ms)
  end

  def error_msg(format, args) do
    _ = (try do
           send(:logger, {:log, :error, format, args,
                            %{pid: self(), gl: :erlang.group_leader(),
                                time: :os.system_time(:microsecond),
                                error_logger: %{tag: :error}}})
         catch
           _, _ ->
             :erlang.display({:code_server, :error})
             :erlang.display({format, args})
         end)
    :ok
  end

  def info_msg(format, args) do
    (try do
      send(:logger, {:log, :info, format, args,
                       %{pid: self(), gl: :erlang.group_leader(),
                           time: :os.system_time(:microsecond),
                           error_logger: %{tag: :info_msg}}})
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end)
    :ok
  end

  defp objfile_extension() do
    :init.objfile_extension()
  end

  defp archive_extension() do
    :init.archive_extension()
  end

  defp to_list(x) when is_list(x) do
    x
  end

  defp to_list(x) when is_atom(x) do
    :erlang.atom_to_list(x)
  end

end