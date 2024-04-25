defmodule :m_ct_master_logs do
  use Bitwise
  require Record

  Record.defrecord(:r_conn, :conn,
    handle: :undefined,
    targetref: :undefined,
    address: :undefined,
    callback: :undefined
  )

  Record.defrecord(:r_testspec, :testspec,
    spec_dir: :undefined,
    nodes: [],
    init: [],
    label: [],
    profile: [],
    logdir: [~c"."],
    logopts: [],
    basic_html: [],
    esc_chars: [],
    verbosity: [],
    silent_connections: [],
    cover: [],
    cover_stop: [],
    config: [],
    userconfig: [],
    event_handler: [],
    ct_hooks: [],
    enable_builtin_hooks: true,
    release_shell: false,
    include: [],
    auto_compile: [],
    abort_if_missing_suites: [],
    stylesheet: [],
    multiply_timetraps: [],
    scale_timetraps: [],
    create_priv_dir: [],
    alias: [],
    tests: [],
    unknown: [],
    merge_tests: true
  )

  Record.defrecord(:r_cover, :cover,
    app: :none,
    local_only: false,
    level: :details,
    excl_mods: [],
    incl_mods: [],
    cross: [],
    src: []
  )

  Record.defrecord(:r_conn_log, :conn_log,
    header: true,
    client: :undefined,
    name: :undefined,
    address: :undefined,
    conn_pid: :undefined,
    action: :undefined,
    module: :undefined
  )

  Record.defrecord(:r_state, :state,
    log_fd: :undefined,
    start_time: :undefined,
    logdir: :undefined,
    rundir: :undefined,
    nodedir_ix_fd: :undefined,
    nodes: :undefined,
    nodedirs: []
  )

  def start(logDir, nodes) do
    self = self()

    pid =
      spawn_link(fn ->
        init(self, logDir, nodes)
      end)

    mRef = :erlang.monitor(:process, pid)

    receive do
      {:started, ^pid, result} ->
        :erlang.demonitor(mRef, [:flush])
        {pid, result}

      {:DOWN, ^mRef, :process, _, reason} ->
        exit({:could_not_start_process, :ct_master_logs, reason})
    end
  end

  def log(heading, format, args) do
    cast(
      {:log, self(),
       [
         {int_header(), [log_timestamp(:os.timestamp()), heading]},
         {format, args},
         {int_footer(), []}
       ]}
    )

    :ok
  end

  def make_all_runs_index() do
    call(:make_all_runs_index)
  end

  def nodedir(node, runDir) do
    call({:nodedir, node, runDir})
  end

  def stop() do
    case :erlang.whereis(:ct_master_logs) do
      pid when is_pid(pid) ->
        mRef = :erlang.monitor(:process, pid)
        send(:ct_master_logs, :stop)

        receive do
          {:DOWN, ^mRef, :process, _, _} ->
            :ok
        end

      :undefined ->
        :ok
    end

    :ok
  end

  defp init(parent, logDir, nodes) do
    :erlang.register(:ct_master_logs, self())
    :ct_util.mark_process()
    time = :calendar.local_time()
    runDir = make_dirname(time)
    runDirAbs = :filename.join(logDir, runDir)
    :ok = make_dir(runDirAbs)
    _ = write_details_file(runDirAbs, {node(), nodes})

    case basic_html() do
      true ->
        :erlang.put(:basic_html, true)

      basicHtml ->
        :erlang.put(:basic_html, basicHtml)
        cTPath = :code.lib_dir(:common_test)
        privFiles = [~c"ct_default.css", ~c"jquery-latest.js", ~c"jquery.tablesorter.min.js"]

        privFilesSrc =
          for f <- privFiles do
            :filename.join(:filename.join(cTPath, ~c"priv"), f)
          end

        privFilesDestTop =
          for f <- privFiles do
            :filename.join(logDir, f)
          end

        privFilesDestRun =
          for f <- privFiles do
            :filename.join(runDirAbs, f)
          end

        case copy_priv_files(
               privFilesSrc,
               privFilesDestTop
             ) do
          {:error, src1, dest1, reason1} ->
            :io.format(
              :user,
              ~c"ERROR! " ++ ~c"Priv file ~tp could not be copied to ~tp. " ++ ~c"Reason: ~tp~n",
              [src1, dest1, reason1]
            )

            exit({:priv_file_error, dest1})

          :ok ->
            case copy_priv_files(
                   privFilesSrc,
                   privFilesDestRun
                 ) do
              {:error, src2, dest2, reason2} ->
                :io.format(
                  :user,
                  ~c"ERROR! " ++
                    ~c"Priv file ~tp could not be copied to ~tp. " ++ ~c"Reason: ~tp~n",
                  [src2, dest2, reason2]
                )

                exit({:priv_file_error, dest2})

              :ok ->
                :ok
            end
        end
    end

    _ = make_all_runs_index(logDir)
    ctLogFd = open_ct_master_log(runDirAbs)

    nodeStr =
      :lists.flatten(
        :lists.map(
          fn n ->
            :erlang.atom_to_list(n) ++ ~c" "
          end,
          nodes
        )
      )

    :io.format(ctLogFd, int_header(), [log_timestamp(:os.timestamp()), ~c"Test Nodes\n"])
    :io.format(ctLogFd, ~c"~ts\n", [nodeStr])
    :io.put_chars(ctLogFd, [int_footer(), ~c"\n"])
    nodeDirIxFd = open_nodedir_index(runDirAbs, time)
    send(parent, {:started, self(), {time, runDirAbs}})

    loop(
      r_state(
        log_fd: ctLogFd,
        start_time: time,
        logdir: logDir,
        rundir: runDirAbs,
        nodedir_ix_fd: nodeDirIxFd,
        nodes: nodes,
        nodedirs:
          :lists.map(
            fn n ->
              {n, ~c""}
            end,
            nodes
          )
      )
    )
  end

  defp copy_priv_files([srcF | srcFs], [destF | destFs]) do
    case :file.copy(srcF, destF) do
      {:error, reason} ->
        {:error, srcF, destF, reason}

      _ ->
        copy_priv_files(srcFs, destFs)
    end
  end

  defp copy_priv_files([], []) do
    :ok
  end

  defp loop(state) do
    receive do
      {:log, _From, list} ->
        fd = r_state(state, :log_fd)

        fun = fn {str, args} ->
          case (try do
                  :io.format(fd, str ++ ~c"\n", args)
                catch
                  :error, e -> {:EXIT, {e, __STACKTRACE__}}
                  :exit, e -> {:EXIT, e}
                  e -> e
                end) do
            {:EXIT, reason} ->
              :io.format(fd, ~c"Logging fails! Str: ~tp, Args: ~tp~n", [str, args])
              exit({:logging_failed, reason})
              :ok

            _ ->
              :ok
          end
        end

        :lists.foreach(fun, list)
        loop(state)

      {:make_all_runs_index, from} ->
        _ = make_all_runs_index(r_state(state, :logdir))
        return(from, r_state(state, :logdir))
        loop(state)

      {{:nodedir, node, runDir}, from} ->
        print_nodedir(node, runDir, r_state(state, :nodedir_ix_fd))
        return(from, :ok)
        loop(state)

      :stop ->
        _ = make_all_runs_index(r_state(state, :logdir))

        :io.format(
          r_state(state, :log_fd),
          int_header() ++ int_footer(),
          [log_timestamp(:os.timestamp()), ~c"Finished!"]
        )

        _ = close_ct_master_log(r_state(state, :log_fd))
        _ = close_nodedir_index(r_state(state, :nodedir_ix_fd))
        :ok
    end
  end

  defp open_ct_master_log(dir) do
    fullName = :filename.join(dir, ~c"ct_master_log.html")

    {:ok, fd} =
      :file.open(
        fullName,
        [:write, {:encoding, :utf8}]
      )

    :io.put_chars(fd, header(~c"Common Test Master Log", {[], [1, 2], []}))
    :io.put_chars(fd, config_table([]))

    :io.put_chars(
      fd,
      ~c"<style>\ndiv.ct_internal { background:lightgrey; color:black }\ndiv.default     { background:lightgreen; color:black }\n</style>\n"
    )

    :io.put_chars(
      fd,
      xhtml(~c"<br><h2>Progress Log</h2>\n<pre>\n", ~c"<br /><h2>Progress Log</h2>\n<pre>\n")
    )

    fd
  end

  defp close_ct_master_log(fd) do
    :io.put_chars(fd, [~c"</pre>", footer()])
    :file.close(fd)
  end

  defp config_table(vars) do
    [config_table_header() | config_table1(vars)]
  end

  defp config_table_header() do
    [
      ~c"<h2>Configuration</h2>\n",
      xhtml([~c"<table border=\"3\" cellpadding=\"5\" bgcolor=\"", ~c"lightblue", ~c"\"\n"], [
        ~c"<table id=\"",
        ~c"SortableTable",
        ~c"\">\n",
        ~c"<thead>\n"
      ]),
      ~c"<tr><th>Key</th><th>Value</th></tr>\n",
      xhtml(~c"", ~c"</thead>\n<tbody>\n")
    ]
  end

  defp config_table1([]) do
    [~c"</tbody>\n</table>\n"]
  end

  defp int_header() do
    ~c"</pre>\n<div class=\"ct_internal\"><pre><b>*** CT MASTER ~s *** ~ts</b>"
  end

  defp int_footer() do
    ~c"</pre></div>\n<pre>"
  end

  defp open_nodedir_index(dir, startTime) do
    fullName = :filename.join(dir, ~c"index.html")

    {:ok, fd} =
      :file.open(
        fullName,
        [:write, {:encoding, :utf8}]
      )

    :io.put_chars(fd, nodedir_index_header(startTime))
    fd
  end

  defp print_nodedir(node, runDir, fd) do
    index = :filename.join(runDir, ~c"index.html")

    :io.put_chars(
      fd,
      [
        ~c"<tr>\n<td align=center>",
        :erlang.atom_to_list(node),
        ~c"</td>\n",
        ~c"<td align=left><a href=\"",
        :ct_logs.uri(index),
        ~c"\">",
        index,
        ~c"</a></td>\n",
        ~c"</tr>\n"
      ]
    )

    :ok
  end

  defp close_nodedir_index(fd) do
    :io.put_chars(fd, index_footer())
    :file.close(fd)
  end

  defp nodedir_index_header(startTime) do
    [
      header(~c"Log Files " ++ format_time(startTime), {[], [1, 2], []}),
      ~c"<center>\n",
      ~c"<p><a href=\"",
      ~c"ct_master_log.html",
      ~c"\">Common Test Master Log</a></p>",
      xhtml([~c"<table border=\"3\" cellpadding=\"5\" bgcolor=\"", ~c"lightblue", ~c"\">\n"], [
        ~c"<table id=\"",
        ~c"SortableTable",
        ~c"\">\n",
        ~c"<thead>\n<tr>\n"
      ]),
      ~c"<th><b>Node</b></th>\n",
      ~c"<th><b>Log</b></th>\n",
      xhtml(~c"", ~c"</tr>\n</thead>\n<tbody>\n")
    ]
  end

  defp make_all_runs_index(logDir) do
    fullName = :filename.join(logDir, ~c"master_runs.html")
    match = :filename.join(logDir, logdir_prefix() ++ ~c"*.*")
    dirs = :filelib.wildcard(match)

    dirsSorted =
      try do
        sort_all_runs(dirs)
      catch
        :error, e -> {:EXIT, {e, __STACKTRACE__}}
        :exit, e -> {:EXIT, e}
        e -> e
      end

    header = all_runs_header()

    index =
      for dir <- dirsSorted do
        runentry(dir)
      end

    result =
      :file.write_file(
        fullName,
        :unicode.characters_to_binary(header ++ index ++ index_footer())
      )

    result
  end

  defp sort_all_runs(dirs) do
    keyList =
      :lists.map(
        fn dir ->
          case :lists.reverse(
                 :string.lexemes(
                   dir,
                   [?., ?_]
                 )
               ) do
            [sS, mM, hH, date | _] ->
              {{date, hH, mM, sS}, dir}

            _Other ->
              throw(dirs)
          end
        end,
        dirs
      )

    :lists.reverse(
      :lists.map(
        fn {_, dir} ->
          dir
        end,
        :lists.keysort(1, keyList)
      )
    )
  end

  defp runentry(dir) do
    {masterStr, nodesStr} =
      case read_details_file(dir) do
        {master, nodes} when is_list(nodes) ->
          [_, host] =
            :string.lexemes(
              :erlang.atom_to_list(master),
              ~c"@"
            )

          {host, :lists.concat(:lists.join(~c", ", nodes))}

        _Error ->
          {~c"unknown", ~c""}
      end

    index = :filename.join(dir, ~c"index.html")

    [
      ~c"<tr>\n<td align=center><a href=\"",
      :ct_logs.uri(index),
      ~c"\">",
      timestamp(dir),
      ~c"</a></td>\n",
      ~c"<td align=center>",
      masterStr,
      ~c"</td>\n",
      ~c"<td align=center>",
      nodesStr,
      ~c"</td>\n",
      ~c"</tr>\n"
    ]
  end

  defp all_runs_header() do
    [
      header(~c"Master Test Runs", {[1], [2, 3], []}),
      ~c"<center>\n",
      xhtml(
        [~c"<table border=\"3\" cellpadding=\"5\" bgcolor=\"", ~c"lightblue", ~c"\">\n"],
        [~c"<table id=\"", ~c"SortableTable", ~c"\">\n", ~c"<thead>\n<tr>\n"]
      ),
      ~c"<th><b>History</b></th>\n<th><b>Master Host</b></th>\n<th><b>Test Nodes</b></th>\n",
      xhtml(~c"", ~c"</tr></thead>\n<tbody>\n")
    ]
  end

  defp timestamp(dir) do
    [
      s,
      min,
      h,
      d,
      m,
      y
      | _
    ] = :lists.reverse(:string.lexemes(dir, ~c".-_"))

    [s1, min1, h1, d1, m1, y1] =
      for n <- [s, min, h, d, m, y] do
        :erlang.list_to_integer(n)
      end

    format_time({{y1, m1, d1}, {h1, min1, s1}})
  end

  defp write_details_file(dir, details) do
    fullName = :filename.join(dir, ~c"details.info")

    force_write_file(
      fullName,
      :erlang.term_to_binary(details)
    )
  end

  defp read_details_file(dir) do
    fullName = :filename.join(dir, ~c"details.info")

    case :file.read_file(fullName) do
      {:ok, bin} ->
        :erlang.binary_to_term(bin)

      error ->
        error
    end
  end

  defp header(title, tableCols) do
    cSSFile =
      xhtml(
        fn ->
          ~c""
        end,
        fn ->
          make_relative(locate_priv_file(~c"ct_default.css"))
        end
      )

    jQueryFile =
      xhtml(
        fn ->
          ~c""
        end,
        fn ->
          make_relative(locate_priv_file(~c"jquery-latest.js"))
        end
      )

    tableSorterFile =
      xhtml(
        fn ->
          ~c""
        end,
        fn ->
          make_relative(locate_priv_file(~c"jquery.tablesorter.min.js"))
        end
      )

    [
      xhtml([~c"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n", ~c"<html>\n"], [
        ~c"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n",
        ~c"\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n",
        ~c"<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n"
      ]),
      ~c"<!-- autogenerated by '" ++ :erlang.atom_to_list(:ct_master_logs) ++ ~c"' -->\n",
      ~c"<head>\n",
      ~c"<title>" ++ title ++ ~c"</title>\n",
      ~c"<meta http-equiv=\"cache-control\" content=\"no-cache\"></meta>\n",
      ~c"<meta http-equiv=\"content-type\" content=\"text/html; ",
      ~c"charset=utf-8\"></meta>\n",
      xhtml(
        ~c"",
        [
          ~c"<link rel=\"stylesheet\" href=\"",
          :ct_logs.uri(cSSFile),
          ~c"\" type=\"text/css\"></link>\n"
        ]
      ),
      xhtml(
        ~c"",
        [~c"<script type=\"text/javascript\" src=\"", jQueryFile, ~c"\"></script>\n"]
      ),
      xhtml(
        ~c"",
        [~c"<script type=\"text/javascript\" src=\"", tableSorterFile, ~c"\"></script>\n"]
      ),
      xhtml(
        fn ->
          ~c""
        end,
        fn ->
          :ct_logs.insert_javascript({:tablesorter, ~c"SortableTable", tableCols})
        end
      ),
      ~c"</head>\n",
      body_tag(),
      ~c"<center>\n",
      ~c"<h1>" ++ title ++ ~c"</h1>\n",
      ~c"</center>\n"
    ]
  end

  defp index_footer() do
    [~c"</tbody>\n</table>\n</center>\n" | footer()]
  end

  defp footer() do
    [
      ~c"<center>\n",
      xhtml(~c"<br><hr>\n", ~c"<br />\n"),
      xhtml(~c"<p><font size=\"-1\">\n", ~c"<div class=\"copyright\">"),
      ~c"Copyright &copy; ",
      year(),
      ~c" <a href=\"http://www.erlang.org\">Open Telecom Platform</a>",
      xhtml(~c"<br>\n", ~c"<br />\n"),
      ~c"Updated: <!--date-->",
      current_time(),
      ~c"<--!/date-->",
      xhtml(
        ~c"<br>\n",
        ~c"<br />\n"
      ),
      xhtml(
        ~c"</font></p>\n",
        ~c"</div>\n"
      ),
      ~c"</center>\n</body>\n"
    ]
  end

  defp body_tag() do
    xhtml(
      ~c"<body bgcolor=\"#FFFFFF\" text=\"#000000\" link=\"#0000FF\" vlink=\"#800080\" alink=\"#FF0000\">\n",
      ~c"<body>\n"
    )
  end

  defp current_time() do
    format_time(:calendar.local_time())
  end

  defp format_time({{y, mon, d}, {h, min, s}}) do
    weekday = weekday(:calendar.day_of_the_week(y, mon, d))

    :lists.flatten(
      :io_lib.format(
        ~c"~s ~s ~2.2.0w ~w ~2.2.0w:~2.2.0w:~2.2.0w",
        [weekday, month(mon), d, y, h, min, s]
      )
    )
  end

  defp weekday(1) do
    ~c"Mon"
  end

  defp weekday(2) do
    ~c"Tue"
  end

  defp weekday(3) do
    ~c"Wed"
  end

  defp weekday(4) do
    ~c"Thu"
  end

  defp weekday(5) do
    ~c"Fri"
  end

  defp weekday(6) do
    ~c"Sat"
  end

  defp weekday(7) do
    ~c"Sun"
  end

  defp month(1) do
    ~c"Jan"
  end

  defp month(2) do
    ~c"Feb"
  end

  defp month(3) do
    ~c"Mar"
  end

  defp month(4) do
    ~c"Apr"
  end

  defp month(5) do
    ~c"May"
  end

  defp month(6) do
    ~c"Jun"
  end

  defp month(7) do
    ~c"Jul"
  end

  defp month(8) do
    ~c"Aug"
  end

  defp month(9) do
    ~c"Sep"
  end

  defp month(10) do
    ~c"Oct"
  end

  defp month(11) do
    ~c"Nov"
  end

  defp month(12) do
    ~c"Dec"
  end

  defp year() do
    {y, _, _} = :erlang.date()
    :erlang.integer_to_list(y)
  end

  defp make_dirname({{yY, mM, dD}, {h, m, s}}) do
    :io_lib.format(
      logdir_prefix() ++ ~c".~w-~2.2.0w-~2.2.0w_~2.2.0w.~2.2.0w.~2.2.0w",
      [yY, mM, dD, h, m, s]
    )
  end

  defp logdir_prefix() do
    ~c"ct_master_run"
  end

  defp log_timestamp(now) do
    :erlang.put(:log_timestamp, now)
    {_, {h, m, s}} = :calendar.now_to_local_time(now)
    :lists.flatten(:io_lib.format(~c"~2.2.0w:~2.2.0w:~2.2.0w", [h, m, s]))
  end

  defp basic_html() do
    case :application.get_env(
           :common_test_master,
           :basic_html
         ) do
      {:ok, true} ->
        true

      _ ->
        false
    end
  end

  defp xhtml(hTML, xHTML) do
    :ct_logs.xhtml(hTML, xHTML)
  end

  defp locate_priv_file(file) do
    :ct_logs.locate_priv_file(file)
  end

  defp make_relative(dir) do
    :ct_logs.make_relative(dir)
  end

  defp force_write_file(name, contents) do
    _ = force_delete(name)
    :file.write_file(name, contents)
  end

  defp force_delete(name) do
    case :file.delete(name) do
      {:error, :eacces} ->
        force_rename(name, name ++ ~c".old.", 0)

      other ->
        other
    end
  end

  defp force_rename(from, to, number) do
    dest = [to | :erlang.integer_to_list(number)]

    case :file.read_file_info(dest) do
      {:ok, _} ->
        force_rename(from, to, number + 1)

      {:error, _} ->
        :file.rename(from, dest)
    end
  end

  defp call(msg) do
    case :erlang.whereis(:ct_master_logs) do
      :undefined ->
        {:error, :does_not_exist}

      pid ->
        mRef = :erlang.monitor(:process, pid)
        ref = make_ref()
        send(:ct_master_logs, {msg, {self(), ref}})

        receive do
          {^ref, result} ->
            :erlang.demonitor(mRef, [:flush])
            result

          {:DOWN, ^mRef, :process, _, reason} ->
            {:error, {:process_down, :ct_master_logs, reason}}
        end
    end
  end

  defp return({to, ref}, result) do
    send(to, {ref, result})
    :ok
  end

  defp cast(msg) do
    case :erlang.whereis(:ct_master_logs) do
      :undefined ->
        :io.format(~c"Warning: ct_master_logs not started~n")
        {_, _, content} = msg
        formatArgs = get_format_args(content)

        _ =
          for {format, args} <- formatArgs do
            :io.format(format, args)
          end

        :ok

      _Pid ->
        send(:ct_master_logs, msg)
        :ok
    end
  end

  defp get_format_args(content) do
    :lists.map(
      fn c ->
        case c do
          {_, fA, _} ->
            fA

          _ ->
            c
        end
      end,
      content
    )
  end

  defp make_dir(dir) do
    case :file.make_dir(dir) do
      {:error, :eexist} ->
        :ok

      else__ ->
        else__
    end
  end
end
