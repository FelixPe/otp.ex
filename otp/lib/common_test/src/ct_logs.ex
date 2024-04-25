defmodule :m_ct_logs do
  use Bitwise
  require Record
  Record.defrecord(:r_event, :event, name: :undefined, node: :undefined, data: :undefined)

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

  Record.defrecord(:r_file_info, :file_info,
    size: :undefined,
    type: :undefined,
    access: :undefined,
    atime: :undefined,
    mtime: :undefined,
    ctime: :undefined,
    mode: :undefined,
    links: :undefined,
    major_device: :undefined,
    minor_device: :undefined,
    inode: :undefined,
    uid: :undefined,
    gid: :undefined
  )

  Record.defrecord(:r_file_descriptor, :file_descriptor,
    module: :undefined,
    data: :undefined
  )

  Record.defrecord(:r_log_cache, :log_cache, version: :undefined, all_runs: [], tests: [])

  def init(mode, verbosity, customStylesheet) do
    self = self()

    pid =
      spawn_link(fn ->
        logger(self, mode, verbosity, customStylesheet)
      end)

    mRef = :erlang.monitor(:process, pid)

    receive do
      {:started, ^pid, result} ->
        :erlang.demonitor(mRef, [:flush])
        result

      {:DOWN, ^mRef, :process, _, reason} ->
        exit({:could_not_start_process, :ct_logs, reason})
    end
  end

  defp date2str({{yY, mM, dD}, {h, m, s}}) do
    :lists.flatten(
      :io_lib.format(~c"~w-~2.2.0w-~2.2.0w_~2.2.0w.~2.2.0w.~2.2.0w", [yY, mM, dD, h, m, s])
    )
  end

  defp logdir_prefix() do
    ~c"ct_run"
  end

  defp logdir_node_prefix() do
    logdir_prefix() ++ ~c"." ++ :erlang.atom_to_list(node())
  end

  defp make_dirname(dateTime) do
    logdir_node_prefix() ++ ~c"." ++ date2str(dateTime)
  end

  defp datestr_from_dirname([
         y1,
         y2,
         y3,
         y4,
         ?-,
         mo1,
         mo2,
         ?-,
         d1,
         d2,
         ?_,
         h1,
         h2,
         ?.,
         m1,
         m2,
         ?.,
         s1,
         s2
         | _
       ]) do
    [y1, y2, y3, y4, ?-, mo1, mo2, ?-, d1, d2, ?_, h1, h2, ?., m1, m2, ?., s1, s2]
  end

  defp datestr_from_dirname([_Ch | rest]) do
    datestr_from_dirname(rest)
  end

  defp datestr_from_dirname([]) do
    ~c""
  end

  def close(info, startDir, customStylesheet) do
    logCacheBin =
      case make_last_run_index() do
        {:error, reason} ->
          :io.format(~c"Warning! ct_logs not responding: ~tp~n", [reason])
          :undefined

        lCB ->
          lCB
      end

    :erlang.put(:ct_log_cache, logCacheBin)

    cache2File = fn ->
      case :erlang.get(:ct_log_cache) do
        :undefined ->
          :ok

        cacheBin ->
          write_log_cache(cacheBin)
          :erlang.put(:ct_log_cache, :undefined)
      end
    end

    :ct_event.notify(r_event(name: :stop_logging, node: node(), data: []))

    case :erlang.whereis(:ct_logs) do
      pid when is_pid(pid) ->
        mRef = :erlang.monitor(:process, pid)
        send(:ct_logs, :stop)

        receive do
          {:DOWN, ^mRef, :process, _, _} ->
            :ok
        end

      :undefined ->
        :ok
    end

    cond do
      info == :clean ->
        case cleanup() do
          :ok ->
            :ok

          error ->
            :io.format(~c"Warning! Cleanup failed: ~tp~n", [error])
        end

        _ = make_all_suites_index(:stop, customStylesheet)
        make_all_runs_index(:stop, customStylesheet)
        cache2File.()

      true ->
        :ok = :file.set_cwd(~c"..")
        _ = make_all_suites_index(:stop, customStylesheet)
        make_all_runs_index(:stop, customStylesheet)
        cache2File.()

        case :ct_util.get_profile_data(:browser, startDir) do
          :undefined ->
            :ok

          browserData ->
            case {:proplists.get_value(:prog, browserData),
                  :proplists.get_value(:args, browserData),
                  :proplists.get_value(:page, browserData)} do
              {prog, args, page}
              when is_list(args) and
                     is_list(page) ->
                uRL = ~c"\"file://" ++ :filename.absname(page) ++ ~c"\""
                :ct_util.open_url(prog, args, uRL)

              _ ->
                :ok
            end
        end
    end

    :ok
  end

  defp get_stylesheet() do
    call(:get_stylesheet)
  end

  def set_stylesheet(tC, sSFile) do
    cast({:set_stylesheet, tC, sSFile})
  end

  def clear_stylesheet(tC) do
    cast({:clear_stylesheet, tC})
  end

  def get_log_dir() do
    get_log_dir(false)
  end

  def get_log_dir(returnAbsName) do
    case call({:get_log_dir, returnAbsName}) do
      {:error, :does_not_exist} when returnAbsName == true ->
        {:ok, :filename.absname(~c".")}

      {:error, :does_not_exist} ->
        {:ok, ~c"."}

      result ->
        result
    end
  end

  def make_last_run_index() do
    call(:make_last_run_index)
  end

  defp call(msg) do
    case :erlang.whereis(:ct_logs) do
      :undefined ->
        {:error, :does_not_exist}

      pid ->
        mRef = :erlang.monitor(:process, pid)
        ref = make_ref()
        send(pid, {msg, {self(), ref}})

        receive do
          {^ref, result} ->
            :erlang.demonitor(mRef, [:flush])
            result

          {:DOWN, ^mRef, :process, _, reason} ->
            {:error, {:process_down, :ct_logs, reason}}
        end
    end
  end

  defp return({to, ref}, result) do
    send(to, {ref, result})
    :ok
  end

  defp cast(msg) do
    case :erlang.whereis(:ct_logs) do
      :undefined ->
        :io.format(~c"Warning: ct_logs not started~n")
        {_, _, _, _, _, _, content, _} = msg
        formatArgs = get_format_args(content)

        _ =
          for {format, args} <- formatArgs do
            :io.format(format, args)
          end

        :ok

      _Pid ->
        send(:ct_logs, msg)
        :ok
    end
  end

  defp get_format_args(content) do
    :lists.map(
      fn c ->
        case c do
          {_, fA, _} ->
            fA

          {_, _} ->
            c
        end
      end,
      content
    )
  end

  def init_tc(refreshLog) do
    call({:init_tc, self(), :erlang.group_leader(), refreshLog})
    tc_io_format(:erlang.group_leader(), xhtml(~c"", ~c"<br />"), [])
    :ok
  end

  def end_tc(tCPid) do
    call({:end_tc, tCPid})
  end

  def register_groupleader(pid, groupLeader) do
    call({:register_groupleader, pid, groupLeader})
    :ok
  end

  def unregister_groupleader(pid) do
    call({:unregister_groupleader, pid})
    :ok
  end

  def log(heading, format, args) do
    cast(
      {:log, :sync, self(), :erlang.group_leader(), :ct_internal, 99,
       [
         {:hd, int_header(), [log_timestamp(:os.timestamp()), heading]},
         {format, args},
         {:ft, int_footer(), []}
       ], true}
    )

    :ok
  end

  def start_log(heading) do
    cast(
      {:log, :sync, self(), :erlang.group_leader(), :ct_internal, 99,
       [{:hd, int_header(), [log_timestamp(:os.timestamp()), heading]}], false}
    )

    :ok
  end

  def cont_log([], []) do
    :ok
  end

  def cont_log(format, args) do
    maybe_log_timestamp()
    cast({:log, :sync, self(), :erlang.group_leader(), :ct_internal, 99, [{format, args}], true})
    :ok
  end

  def cont_log_no_timestamp([], []) do
    :ok
  end

  def cont_log_no_timestamp(format, args) do
    cast({:log, :sync, self(), :erlang.group_leader(), :ct_internal, 99, [{format, args}], true})
    :ok
  end

  def end_log() do
    cast(
      {:log, :sync, self(), :erlang.group_leader(), :ct_internal, 99, [{:ft, int_footer(), []}],
       false}
    )

    :ok
  end

  def add_external_logs(logs) do
    start_log(~c"External Logs")

    for log <- logs do
      cont_log(~c"<a href=\"~ts\">~ts</a>\n", [uri(:filename.join(~c"log_private", log)), log])
    end

    end_log()
  end

  def add_link(heading, file, type) do
    log(heading, ~c"<a href=\"~ts\" type=~tp>~ts</a>\n", [
      uri(:filename.join(~c"log_private", file)),
      type,
      file
    ])
  end

  def tc_log(category, format, args) do
    tc_log(category, 50, ~c"User", format, args, [])
  end

  def tc_log(category, importance, format, args) do
    tc_log(category, importance, ~c"User", format, args, [])
  end

  def tc_log(category, importance, format, args, opts) do
    tc_log(category, importance, ~c"User", format, args, opts)
  end

  def tc_log(category, importance, heading, format, args, opts) do
    data =
      case :lists.member(:no_css, opts) do
        true ->
          [{format, args}]

        false ->
          heading1 =
            case :proplists.get_value(
                   :heading,
                   opts
                 ) do
              :undefined ->
                heading

              str ->
                str
            end

          [{:hd, div_header(category, heading1), []}, {format, args}, {:ft, div_footer(), []}]
      end

    cast(
      {:log, :sync, self(), :erlang.group_leader(), category, importance, data,
       :lists.member(:esc_chars, opts)}
    )

    :ok
  end

  def tc_log_async(category, format, args) do
    tc_log_async(category, 50, ~c"User", format, args)
  end

  def tc_log_async(category, importance, heading, format, args) do
    cast(
      {:log, :async, self(), :erlang.group_leader(), category, importance,
       [{:hd, div_header(category, heading), []}, {format, args}, {:ft, div_footer(), []}], true}
    )

    :ok
  end

  def tc_print(category, format, args) do
    tc_print(category, 50, format, args, [])
  end

  def tc_print(category, importance, format, args) do
    tc_print(category, importance, format, args, [])
  end

  def tc_print(category, importance, format, args, opts) do
    vLvl =
      case :ct_util.get_verbosity(category) do
        :undefined ->
          :ct_util.get_verbosity(:"$unspecified")

        {:error, :bad_invocation} ->
          100

        {:error, _Failure} ->
          100

        val ->
          val
      end

    cond do
      importance >= 100 - vLvl ->
        heading =
          case :proplists.get_value(
                 :heading,
                 opts
               ) do
            :undefined ->
              :erlang.atom_to_list(category)

            hd ->
              hd
          end

        str = :lists.flatten([get_header(heading), format, ~c"\n\n"])

        try do
          :io.format(:ct_default_gl, str, args)
        catch
          _, _ ->
            :io.format(:user, str, args)
        end

        :ok

      true ->
        :ok
    end
  end

  defp get_header(~c"default") do
    :io_lib.format(~c"\n----------------------------------------------------\n~s\n", [
      log_timestamp(:os.timestamp())
    ])
  end

  defp get_header(heading) do
    :io_lib.format(
      ~c"\n----------------------------------------------------\n~ts ~s\n",
      [heading, log_timestamp(:os.timestamp())]
    )
  end

  def tc_pal(category, format, args) do
    tc_pal(category, 50, format, args, [])
  end

  def tc_pal(category, importance, format, args) do
    tc_pal(category, importance, format, args, [])
  end

  def tc_pal(category, importance, format, args, opts) do
    tc_print(category, importance, format, args, opts)
    tc_log(category, importance, ~c"User", format, args, [:esc_chars | opts])
  end

  def ct_log(category, format, args) do
    cast(
      {:ct_log, [{:hd, div_header(category), []}, {format, args}, {:ft, div_footer(), []}], true}
    )

    :ok
  end

  defp int_header() do
    ~c"</pre>\n<div class=\"ct_internal\"><pre><b>*** CT ~s *** ~ts</b>"
  end

  defp int_footer() do
    ~c"</pre></div>\n<pre>"
  end

  defp div_header(class) do
    div_header(class, ~c"User")
  end

  defp div_header(class, heading) do
    ~c"\n</pre>\n<div class=\"" ++
      :erlang.atom_to_list(class) ++
      ~c"\"><pre><b>*** " ++ heading ++ ~c" " ++ log_timestamp(:os.timestamp()) ++ ~c" ***</b>"
  end

  defp div_footer() do
    ~c"</pre></div>\n<pre>"
  end

  defp maybe_log_timestamp() do
    {mS, s, uS} = :os.timestamp()

    case :erlang.get(:log_timestamp) do
      {^mS, ^s, _} ->
        :ok

      _ ->
        cast(
          {:log, :sync, self(), :erlang.group_leader(), :ct_internal, 99,
           [{:hd, ~c"<i>~s</i>", [log_timestamp({mS, s, uS})]}], false}
        )
    end
  end

  defp log_timestamp({mS, s, uS}) do
    :erlang.put(:log_timestamp, {mS, s, uS})
    {{year, month, day}, {hour, min, sec}} = :calendar.now_to_local_time({mS, s, uS})
    milliSec = trunc(uS / 1000)

    :lists.flatten(
      :io_lib.format(
        ~c"~4.10.0B-~2.10.0B-~2.10.0B ~2.10.0B:~2.10.0B:~2.10.0B.~3.10.0B",
        [year, month, day, hour, min, sec, milliSec]
      )
    )
  end

  Record.defrecord(:r_logger_state, :logger_state,
    parent: :undefined,
    log_dir: :undefined,
    start_time: :undefined,
    orig_GL: :undefined,
    ct_log_fd: :undefined,
    tc_groupleaders: :undefined,
    stylesheet: :undefined,
    async_print_jobs: :undefined,
    tc_esc_chars: :undefined,
    log_index: :undefined
  )

  defp logger(parent, mode, verbosity, customStylesheet) do
    :erlang.register(:ct_logs, self())
    :ct_util.mark_process()
    time0 = :calendar.local_time()
    dir0 = make_dirname(time0)

    {time, dir} =
      case :filelib.is_dir(dir0) do
        true ->
          :timer.sleep(1000)
          time1 = :calendar.local_time()
          dir1 = make_dirname(time1)
          {time1, dir1}

        false ->
          {time0, dir0}
      end

    _ = :file.make_dir(dir)
    absDir = :filename.absname(dir)
    :erlang.put(:ct_run_dir, absDir)

    case basic_html() do
      true ->
        :erlang.put(:basic_html, true)

      basicHtml ->
        :erlang.put(:basic_html, basicHtml)
        {:ok, cwd} = :file.get_cwd()
        cTPath = :code.lib_dir(:common_test)
        privFiles = [~c"ct_default.css", ~c"jquery-latest.js", ~c"jquery.tablesorter.min.js"]

        privFilesSrc =
          for f <- privFiles do
            :filename.join(:filename.join(cTPath, ~c"priv"), f)
          end

        privFilesDestTop =
          for f <- privFiles do
            :filename.join(cwd, f)
          end

        privFilesDestRun =
          for f <- privFiles do
            :filename.join(absDir, f)
          end

        case copy_priv_files(
               privFilesSrc,
               privFilesDestTop
             ) do
          {:error, src1, dest1, reason1} ->
            :io.format(
              :ct_default_gl,
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
                  :ct_default_gl,
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

    _ = :test_server_io.start_link()
    miscIoName = :filename.join(dir, ~c"misc_io.log.html")

    {:ok, miscIoFd} =
      :file.open(
        miscIoName,
        [:write, {:encoding, :utf8}]
      )

    :test_server_io.set_fd(:unexpected_io, miscIoFd)

    {miscIoHeader, miscIoFooter} =
      case get_ts_html_wrapper(
             ~c"Pre/post-test I/O log",
             dir,
             false,
             dir,
             :undefined,
             :utf8,
             customStylesheet
           ) do
        {:basic_html, uH, uF} ->
          {uH, uF}

        {:xhtml, uH, uF} ->
          {uH, uF}
      end

    :io.put_chars(
      miscIoFd,
      [
        miscIoHeader,
        ~c"<a name=\"pretest\"></a>\n",
        xhtml(~c"<br>\n<h2>Pre-test Log</h2>", ~c"<br />\n<h3>PRE-TEST LOG</h3>"),
        ~c"\n<pre>\n"
      ]
    )

    miscIoDivider =
      ~c"\n<a name=\"posttest\"></a>\n" ++
        xhtml(
          ~c"</pre>\n<br><h2>Post-test Log</h2>\n<pre>\n",
          ~c"</pre>\n<br />\n<h3>POST-TEST LOG</h3>\n<pre>\n"
        )

    :ct_util.set_testdata_async(
      {:misc_io_log, {:filename.absname(miscIoName), miscIoDivider, miscIoFooter}}
    )

    :ct_event.notify(r_event(name: :start_logging, node: node(), data: absDir))
    make_all_runs_index(:start, customStylesheet)
    _ = make_all_suites_index(:start, customStylesheet)

    case mode do
      :interactive ->
        interactive_link()

      _ ->
        :ok
    end

    :ok = :file.set_cwd(dir)
    _ = make_last_run_index(time, customStylesheet)
    ctLogFd = open_ctlog(~c"misc_io.log.html", customStylesheet)

    :io.format(ctLogFd, int_header() ++ int_footer(), [
      log_timestamp(:os.timestamp()),
      ~c"Common Test Logger started"
    ])

    send(parent, {:started, self(), {time, :filename.absname(~c"")}})
    set_evmgr_gl(ctLogFd)
    :io.format(ctLogFd, ~c"\nVERBOSITY LEVELS:\n", [])

    case :proplists.get_value(:"$unspecified", verbosity) do
      :undefined ->
        :ok

      genLvl ->
        :io.format(ctLogFd, ~c"~-25s~3w~n", [~c"general level", genLvl])
    end

    _ =
      for {cat, vLvl} <- verbosity do
        :erlang.put({:verbosity, cat}, vLvl)

        cond do
          cat == :"$unspecified" ->
            :ok

          true ->
            :io.format(ctLogFd, ~c"~-25w~3w~n", [cat, vLvl])
        end
      end

    :io.nl(ctLogFd)

    tcEscChars =
      case :application.get_env(
             :common_test,
             :esc_chars
           ) do
        {:ok, eCBool} ->
          eCBool

        _ ->
          true
      end

    logger_loop(
      r_logger_state(
        parent: parent,
        log_dir: absDir,
        start_time: time,
        orig_GL: :erlang.group_leader(),
        ct_log_fd: ctLogFd,
        tc_groupleaders: [],
        async_print_jobs: [],
        tc_esc_chars: tcEscChars,
        stylesheet: customStylesheet,
        log_index: 1
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

  defp logger_loop(state) do
    receive do
      {:log, syncOrAsync, pid, gL, category, importance, content, escChars} ->
        vLvl =
          case category do
            :ct_internal ->
              100

            _ ->
              case :erlang.get({:verbosity, category}) do
                :undefined ->
                  :erlang.get({:verbosity, :"$unspecified"})

                val ->
                  val
              end
          end

        cond do
          importance >= 100 - vLvl ->
            ctLogFd = r_logger_state(state, :ct_log_fd)

            doEscChars =
              :erlang.and(
                r_logger_state(state, :tc_esc_chars),
                escChars
              )

            case get_groupleader(pid, gL, state) do
              {:tc_log, tCGL, tCGLs} ->
                case :erlang.is_process_alive(tCGL) do
                  true ->
                    state1 =
                      print_to_log(syncOrAsync, pid, category, tCGL, content, doEscChars, state)

                    logger_loop(r_logger_state(state1, tc_groupleaders: tCGLs))

                  false ->
                    unexpected_io(pid, category, importance, content, ctLogFd, doEscChars)
                    logger_loop(state)
                end

              {:ct_log, _Fd, tCGLs} ->
                unexpected_io(pid, category, importance, content, ctLogFd, doEscChars)
                logger_loop(r_logger_state(state, tc_groupleaders: tCGLs))
            end

          true ->
            logger_loop(state)
        end

      {{:init_tc, tCPid, gL, refreshLog}, from} ->
        :test_server.permit_io(gL, self())
        ioFormat = &tc_io_format/3
        print_style(gL, ioFormat, r_logger_state(state, :stylesheet))
        set_evmgr_gl(gL)
        tCGLs = add_tc_gl(tCPid, gL, state)

        _ =
          cond do
            not refreshLog ->
              :ok

            true ->
              make_last_run_index(
                r_logger_state(state, :start_time),
                r_logger_state(state, :stylesheet)
              )
          end

        return(from, :ok)
        logger_loop(r_logger_state(state, tc_groupleaders: tCGLs))

      {{:end_tc, tCPid}, from} ->
        set_evmgr_gl(r_logger_state(state, :ct_log_fd))
        return(from, :ok)

        logger_loop(
          r_logger_state(state,
            tc_groupleaders:
              rm_tc_gl(
                tCPid,
                state
              )
          )
        )

      {{:register_groupleader, pid, gL}, from} ->
        gLs = add_tc_gl(pid, gL, state)
        return(from, :ok)
        logger_loop(r_logger_state(state, tc_groupleaders: gLs))

      {{:unregister_groupleader, pid}, from} ->
        return(from, :ok)

        logger_loop(
          r_logger_state(state,
            tc_groupleaders:
              rm_tc_gl(
                pid,
                state
              )
          )
        )

      {{:get_log_dir, true}, from} ->
        return(from, {:ok, r_logger_state(state, :log_dir)})
        logger_loop(state)

      {{:get_log_dir, false}, from} ->
        return(
          from,
          {:ok, :filename.basename(r_logger_state(state, :log_dir))}
        )

        logger_loop(state)

      {:make_last_run_index, from} ->
        _ =
          make_last_run_index(
            r_logger_state(state, :start_time),
            r_logger_state(state, :stylesheet)
          )

        return(from, :erlang.get(:ct_log_cache))
        logger_loop(state)

      {:get_stylesheet, from} ->
        return(from, r_logger_state(state, :stylesheet))
        logger_loop(state)

      {:set_stylesheet, _, sSFile}
      when r_logger_state(state, :stylesheet) == sSFile ->
        logger_loop(state)

      {:set_stylesheet, tC, sSFile} ->
        fd = r_logger_state(state, :ct_log_fd)
        :io.format(fd, ~c"~tp loading external style sheet: ~ts~n", [tC, sSFile])
        logger_loop(r_logger_state(state, stylesheet: sSFile))

      {:clear_stylesheet, _}
      when r_logger_state(state, :stylesheet) == :undefined ->
        logger_loop(state)

      {:clear_stylesheet, _} ->
        logger_loop(r_logger_state(state, stylesheet: :undefined))

      {:ct_log, content, escChars} ->
        str =
          :lists.map(
            fn
              {_HdOrFt, str, args} ->
                [:io_lib.format(str, args), :io_lib.nl()]

              {str, args} when escChars ->
                io = :io_lib.format(str, args)
                [escape_chars(io), :io_lib.nl()]

              {str, args} ->
                [:io_lib.format(str, args), :io_lib.nl()]
            end,
            content
          )

        fd = r_logger_state(state, :ct_log_fd)
        :io.format(fd, ~c"~ts", [str])
        logger_loop(state)

      {:DOWN, ref, _, _Pid, _} ->
        case :lists.delete(
               ref,
               r_logger_state(state, :async_print_jobs)
             ) do
          [] ->
            logger_loop(r_logger_state(state, async_print_jobs: []))

          jobs ->
            [next | jobsRev] = :lists.reverse(jobs)
            jobs1 = [print_next(next) | :lists.reverse(jobsRev)]
            logger_loop(r_logger_state(state, async_print_jobs: jobs1))
        end

      :stop ->
        :io.format(
          r_logger_state(state, :ct_log_fd),
          int_header() ++ int_footer(),
          [log_timestamp(:os.timestamp()), ~c"Common Test Logger finished"]
        )

        close_ctlog(r_logger_state(state, :ct_log_fd))
        :ok
    end
  end

  defp create_io_fun(fromPid, ctLogFd, escChars) do
    create_io_fun(fromPid, ctLogFd, escChars, :undefined)
  end

  defp create_io_fun(fromPid, ctLogFd, escChars, logIndex) do
    fn formatData, ioList ->
      {escapable, addAnchor, str, args} =
        case formatData do
          {:hd, s, a} ->
            {false, true, s, a}

          {_ft, s, a} ->
            {false, false, s, a}

          {s, a} ->
            {true, false, s, a}
        end

      try do
        :io_lib.format(:lists.flatten(str), args)
      catch
        _, _Reason ->
          :io.format(ctLogFd, ~c"Logging fails! Str: ~tp, Args: ~tp~n", [str, args])
          :erlang.exit(fromPid, {:log_printout_error, str, args})
          []
      else
        ioStr when escapable and escChars and ioList == [] ->
          escape_chars(ioStr)

        ioStr when escapable and escChars ->
          [ioList, ~c"\n", escape_chars(ioStr)]

        ioStr when ioList == [] ->
          ioStr ++
            for _ <- [:EFE_DUMMY_GEN], addAnchor do
              anchor_link(logIndex)
            end

        ioStr ->
          [ioList, ~c"\n", ioStr] ++
            for _ <- [:EFE_DUMMY_GEN],
                addAnchor do
              anchor_link(logIndex)
            end
      end
    end
  end

  defp anchor_link(:undefined) do
    []
  end

  defp anchor_link(logIndex) do
    idLink = [~c"e-", :erlang.integer_to_list(logIndex)]

    [
      ~c"<a id=",
      idLink,
      ~c" class=\"link-to-entry\" ",
      ~c"href=\"#",
      idLink,
      ~c"\">&#x1f517;</a>"
    ]
  end

  def escape_chars([bin | io]) when is_binary(bin) do
    [bin | escape_chars(io)]
  end

  def escape_chars([list | io]) when is_list(list) do
    [escape_chars(list) | escape_chars(io)]
  end

  def escape_chars([?< | io]) do
    [~c"&lt;" | escape_chars(io)]
  end

  def escape_chars([?> | io]) do
    [~c"&gt;" | escape_chars(io)]
  end

  def escape_chars([?& | io]) do
    [~c"&amp;" | escape_chars(io)]
  end

  def escape_chars([char | io]) when is_integer(char) do
    [char | escape_chars(io)]
  end

  def escape_chars([]) do
    []
  end

  def escape_chars(bin) do
    bin
  end

  defp print_to_log(
         :sync,
         fromPid,
         category,
         tCGL,
         content,
         escChars,
         r_logger_state(log_index: logIndex) = state
       ) do
    ctLogFd = r_logger_state(state, :ct_log_fd)

    cond do
      fromPid != tCGL ->
        ioFun = create_io_fun(fromPid, ctLogFd, escChars, logIndex)
        ioList = :lists.foldl(ioFun, [], content)

        try do
          tc_io_format(tCGL, ~c"~ts", [ioList])
        catch
          _, _ ->
            :io.format(tCGL, ~c"~ts", [ioList])
        else
          :ok ->
            :ok
        end

      true ->
        unexpected_io(fromPid, category, 99, content, ctLogFd, escChars)
    end

    r_logger_state(state, log_index: logIndex + 1)
  end

  defp print_to_log(
         :async,
         fromPid,
         category,
         tCGL,
         content,
         escChars,
         r_logger_state(log_index: logIndex) = state
       ) do
    ctLogFd = r_logger_state(state, :ct_log_fd)

    printer =
      cond do
        fromPid != tCGL ->
          ioFun = create_io_fun(fromPid, ctLogFd, escChars, logIndex)

          fn ->
            :ct_util.mark_process()
            :test_server.permit_io(tCGL, self())

            case :erlang.is_process_alive(tCGL) do
              true ->
                try do
                  tc_io_format(tCGL, ~c"~ts", [:lists.foldl(ioFun, [], content)])
                catch
                  _, :terminated ->
                    unexpected_io(fromPid, category, 99, content, ctLogFd, escChars)

                  _, _ ->
                    :io.format(tCGL, ~c"~ts", [:lists.foldl(ioFun, [], content)])
                else
                  _ ->
                    :ok
                end

              false ->
                unexpected_io(fromPid, category, 99, content, ctLogFd, escChars)
            end
          end

        true ->
          fn ->
            :ct_util.mark_process()
            unexpected_io(fromPid, category, 99, content, ctLogFd, escChars)
          end
      end

    state1 = r_logger_state(state, log_index: logIndex + 1)

    case r_logger_state(state1, :async_print_jobs) do
      [] ->
        {_Pid, ref} = spawn_monitor(printer)
        r_logger_state(state1, async_print_jobs: [ref])

      queue ->
        r_logger_state(state1, async_print_jobs: [printer | queue])
    end
  end

  defp print_next(printFun) do
    {_Pid, ref} = spawn_monitor(printFun)
    ref
  end

  defp get_groupleader(pid, gL, state) do
    tCGLs = r_logger_state(state, :tc_groupleaders)

    case :proplists.get_value(pid, tCGLs) do
      :undefined ->
        case :lists.keysearch({:tc, gL}, 2, tCGLs) do
          {:value, _} ->
            {:tc_log, gL, [{pid, {:io, gL}} | tCGLs]}

          false ->
            case (for {_, {type, tCGL}} <- tCGLs, type == :tc do
                    tCGL
                  end) do
              [tCGL] ->
                {:tc_log, tCGL, tCGLs}

              _ ->
                {:ct_log, r_logger_state(state, :ct_log_fd), tCGLs}
            end
        end

      {_, ^gL} ->
        {:tc_log, gL, tCGLs}

      _ ->
        tCGLs1 = :proplists.delete(pid, tCGLs)

        case (for {_, {type, tCGL}} <- tCGLs1, type == :tc do
                tCGL
              end) do
          [tCGL] ->
            {:tc_log, tCGL, tCGLs1}

          _ ->
            {:ct_log, r_logger_state(state, :ct_log_fd), tCGLs1}
        end
    end
  end

  defp add_tc_gl(tCPid, gL, state) do
    tCGLs = r_logger_state(state, :tc_groupleaders)
    [{tCPid, {:tc, gL}} | :lists.keydelete(tCPid, 1, tCGLs)]
  end

  defp rm_tc_gl(tCPid, state) do
    tCGLs = r_logger_state(state, :tc_groupleaders)

    case :proplists.get_value(tCPid, tCGLs) do
      {:tc, gL} ->
        tCGLs1 = :lists.keydelete(tCPid, 1, tCGLs)

        case :lists.keysearch({:tc, gL}, 2, tCGLs1) do
          {:value, _} ->
            tCGLs1

          false ->
            :lists.filter(
              fn
                {_, {:io, gLPid}} when gL == gLPid ->
                  false

                _ ->
                  true
              end,
              tCGLs1
            )
        end

      _ ->
        tCGLs
    end
  end

  defp set_evmgr_gl(gL) do
    case :erlang.whereis(:ct_event) do
      :undefined ->
        :ok

      evMgrPid ->
        :erlang.group_leader(gL, evMgrPid)
    end
  end

  defp open_ctlog(miscIoName, customStylesheet) do
    {:ok, fd} = :file.open(~c"ctlog.html", [:write, {:encoding, :utf8}])

    :io.format(fd, ~c"~ts", [
      header(~c"Common Test Framework Log", ~c"", {[], [1, 2], []}, customStylesheet)
    ])

    case :file.consult(:ct_run.variables_file_name(~c"../")) do
      {:ok, vars} ->
        :io.format(fd, ~c"~ts", [config_table(vars)])

      {:error, reason} ->
        {:ok, cwd} = :file.get_cwd()
        dir = :filename.dirname(cwd)
        variables = :ct_run.variables_file_name(dir)

        :io.format(
          fd,
          ~c"Can not read the file '~ts' Reason: ~tw\nNo configuration found for test!!\n",
          [variables, reason]
        )
    end

    :io.format(
      fd,
      xhtml(
        ~c"<br><br><h2>Pre/post-test I/O Log</h2>\n",
        ~c"<br /><br />\n<h4>PRE/POST TEST I/O LOG</h4>\n"
      ),
      []
    )

    :io.format(
      fd,
      ~c"\n<ul>\n<li><a href=\"~ts#pretest\">View I/O logged before the test run</a></li>\n<li><a href=\"~ts#posttest\">View I/O logged after the test run</a></li>\n</ul>\n",
      [miscIoName, miscIoName]
    )

    print_style(fd, &:io.format/3, :undefined)

    :io.format(
      fd,
      xhtml(~c"<br><h2>Progress Log</h2>\n<pre>\n", ~c"<br />\n<h4>PROGRESS LOG</h4>\n<pre>\n"),
      []
    )

    fd
  end

  defp print_style(fd, ioFormat, :undefined) do
    case basic_html() do
      true ->
        style =
          ~c"<style>\n\n\t\tdiv.ct_internal { background:lightgrey; color:black; }\n\n\t\tdiv.default     { background:lightgreen; color:black; }\n\n\t\t</style>\n"

        ioFormat.(fd, style, [])

      _ ->
        :ok
    end
  end

  defp print_style(fd, ioFormat, styleSheet) do
    case stylesheet_to_style_html(styleSheet) do
      {:ok, markup} ->
        ioFormat.(fd, markup, [])

      {:error, reason} ->
        print_style_error(fd, ioFormat, styleSheet, reason)
    end
  end

  defp print_style_error(fd, ioFormat, styleSheet, reason) do
    iO = :io_lib.format(~c"\n<!-- Failed to load stylesheet ~ts: ~tp -->\n", [styleSheet, reason])
    ioFormat.(fd, iO, [])
    print_style(fd, ioFormat, :undefined)
  end

  defp stylesheet_to_style_html(path) do
    case :file.read_file(path) do
      {:ok, bin} ->
        str = b2s(bin, encoding(path))

        case :re.run(str, ~c"<style>.*</style>", [:dotall, :caseless, {:capture, :all, :list}]) do
          :nomatch ->
            case :re.run(str, ~c"</?style>", [:caseless, {:capture, :all, :list}]) do
              :nomatch ->
                {:ok, :io_lib.fwrite(~c"<style>\n~ts</style>\n", [str])}

              {:match, [~c"</" ++ _]} ->
                {:error, :missing_style_start_tag}

              {:match, [_]} ->
                {:error, :missing_style_end_tag}
            end

          {:match, [style]} ->
            {:ok, :io_lib.fwrite(~c"~ts\n", [style])}
        end

      {:error, _Reason} = result ->
        result
    end
  end

  defp close_ctlog(fd) do
    :io.format(fd, ~c"\n</pre>\n", [])
    :io.format(fd, ~c"~ts", [[xhtml(~c"<br><br>\n", ~c"<br /><br />\n") | footer()]])
    :ok = :file.close(fd)
  end

  defp tc_io_format(fd, format0, args) do
    format =
      case cloaked_true() do
        true ->
          [~c"$tc_html", format0]

        false ->
          format0
      end

    :io.format(fd, format, args)
  end

  defp cloaked_true() do
    :erlang.is_process_alive(self())
  end

  defp make_last_run_index(startTime, customStylesheet) do
    indexName = ~c"index.html"
    absIndexName = :filename.absname(indexName)

    result =
      case (try do
              make_last_run_index1(startTime, indexName, customStylesheet)
            catch
              :error, e -> {:EXIT, {e, __STACKTRACE__}}
              :exit, e -> {:EXIT, e}
              e -> e
            end) do
        {:EXIT, reason} ->
          :io.put_chars(~c"CRASHED while updating " ++ absIndexName ++ ~c"!\n")
          :io.format(~c"~tp~n", [reason])
          {:error, reason}

        {:error, reason} ->
          :io.put_chars(~c"FAILED while updating " ++ absIndexName ++ ~c"\n")
          :io.format(~c"~tp~n", [reason])
          {:error, reason}

        :ok ->
          :ok

        err ->
          :io.format(
            ~c"Unknown internal error while updating ~ts. Please report.\n(Err: ~p, ID: 1)",
            [absIndexName, err]
          )

          {:error, err}
      end

    result
  end

  defp make_last_run_index1(startTime, indexName, customStylesheet) do
    logs1 =
      case :filelib.wildcard([?* | ~c".logs"]) do
        [log] ->
          [log]

        logs ->
          case read_totals_file(~c"totals.info") do
            {_Node, _Lbl, logs0, _Totals} ->
              insert_dirs(logs, logs0)

            _ ->
              logs
          end
      end

    missing =
      case :file.read_file(~c"missing_suites.info") do
        {:ok, bin} ->
          :erlang.binary_to_term(bin)

        _ ->
          []
      end

    label =
      case :application.get_env(
             :common_test,
             :test_label
           ) do
        {:ok, lbl} ->
          lbl

        _ ->
          :undefined
      end

    {:ok, index0, totals} =
      make_last_run_index(
        logs1,
        index_header(label, startTime, customStylesheet),
        0,
        0,
        0,
        0,
        0,
        missing
      )

    write_totals_file(~c"totals.info", label, logs1, totals)
    index = [index0 | last_run_index_footer()]

    case force_write_file(
           indexName,
           :unicode.characters_to_binary(index)
         ) do
      :ok ->
        :ok

      {:error, reason} ->
        {:error, {:index_write_error, reason}}
    end
  end

  defp insert_dirs([newDir | newDirs], dirs) do
    dirs1 = insert_dir(newDir, dirs)
    insert_dirs(newDirs, dirs1)
  end

  defp insert_dirs([], dirs) do
    dirs
  end

  defp insert_dir(d, dirs = [d | _]) do
    dirs
  end

  defp insert_dir(d, [d1 | ds]) do
    [d1 | insert_dir(d, ds)]
  end

  defp insert_dir(d, []) do
    [d]
  end

  defp make_last_run_index(
         [name | rest],
         result,
         totSucc,
         totFail,
         userSkip,
         autoSkip,
         totNotBuilt,
         missing
       ) do
    case get_run_dirs(name) do
      false ->
        make_last_run_index(
          rest,
          result,
          totSucc,
          totFail,
          userSkip,
          autoSkip,
          totNotBuilt,
          missing
        )

      logDirs ->
        suiteName = :filename.rootname(:filename.basename(name))

        {result1, totSucc1, totFail1, userSkip1, autoSkip1, totNotBuilt1} =
          make_last_run_index1(
            suiteName,
            logDirs,
            result,
            totSucc,
            totFail,
            userSkip,
            autoSkip,
            totNotBuilt,
            missing
          )

        make_last_run_index(
          rest,
          result1,
          totSucc1,
          totFail1,
          userSkip1,
          autoSkip1,
          totNotBuilt1,
          missing
        )
    end
  end

  defp make_last_run_index([], result, totSucc, totFail, userSkip, autoSkip, totNotBuilt, _) do
    {:ok, [result | total_row(totSucc, totFail, userSkip, autoSkip, totNotBuilt, false)],
     {totSucc, totFail, userSkip, autoSkip, totNotBuilt}}
  end

  defp make_last_run_index1(
         suiteName,
         [logDir | logDirs],
         result,
         totSucc,
         totFail,
         userSkip,
         autoSkip,
         totNotBuilt,
         missing
       ) do
    case make_one_index_entry(suiteName, logDir, ~c"-", false, missing, :undefined) do
      {result1, succ, fail, uSkip, aSkip, notBuilt, _URIs1} ->
        autoSkip1 =
          case (try do
                  autoSkip + aSkip
                catch
                  :error, e -> {:EXIT, {e, __STACKTRACE__}}
                  :exit, e -> {:EXIT, e}
                  e -> e
                end) do
            {:EXIT, _} ->
              :undefined

            res ->
              res
          end

        make_last_run_index1(
          suiteName,
          logDirs,
          [result | result1],
          totSucc + succ,
          totFail + fail,
          userSkip + uSkip,
          autoSkip1,
          totNotBuilt + notBuilt,
          missing
        )

      :error ->
        make_last_run_index1(
          suiteName,
          logDirs,
          result,
          totSucc,
          totFail,
          userSkip,
          autoSkip,
          totNotBuilt,
          missing
        )
    end
  end

  defp make_last_run_index1(_, [], result, totSucc, totFail, userSkip, autoSkip, totNotBuilt, _) do
    {result, totSucc, totFail, userSkip, autoSkip, totNotBuilt}
  end

  defp make_one_index_entry(suiteName, logDir, label, all, missing, uRIs) do
    case count_cases(logDir) do
      {succ, fail, userSkip, autoSkip} ->
        notBuilt = not_built(suiteName, logDir, all, missing)

        {newResult, uRIs1} =
          make_one_index_entry1(
            suiteName,
            logDir,
            label,
            succ,
            fail,
            userSkip,
            autoSkip,
            notBuilt,
            all,
            :normal,
            uRIs
          )

        {newResult, succ, fail, userSkip, autoSkip, notBuilt, uRIs1}

      :error ->
        :error
    end
  end

  defp make_one_index_entry1(
         suiteName,
         link,
         label,
         success,
         fail,
         userSkip,
         autoSkip,
         notBuilt,
         all,
         mode,
         uRIs
       ) do
    logFile = :filename.join(link, ~c"suite.log" ++ ~c".html")
    ctRunDir = :filename.dirname(:filename.dirname(link))
    crashDumpName = suiteName ++ ~c"_erl_crash.dump"

    uRIs1 =
      {ctRunLogURI, logFileURI, crashDumpURI} =
      case uRIs do
        :undefined ->
          {uri(:filename.join(ctRunDir, ~c"ctlog.html")), uri(logFile), uri(crashDumpName)}

        _ ->
          uRIs
      end

    crashDumpLink =
      case mode do
        :temp ->
          ~c""

        :normal ->
          case :filelib.is_file(crashDumpName) do
            true ->
              [~c"&nbsp;<a href=\"", crashDumpURI, ~c"\">(CrashDump)</a>"]

            false ->
              ~c""
          end
      end

    {lbl, timestamp, node, allInfo} =
      case all do
        {true, oldRuns} ->
          [
            _Prefix,
            nodeOrDate
            | _
          ] =
            :string.lexemes(
              link,
              ~c"."
            )

          node1 =
            case :string.find(
                   nodeOrDate,
                   [?@]
                 ) do
              :nomatch ->
                ~c"-"

              _ ->
                nodeOrDate
            end

          tS = timestamp(ctRunDir)

          n =
            xhtml(
              [~c"<td align=right><font size=\"-1\">", node1, ~c"</font></td>\n"],
              [~c"<td align=right>", node1, ~c"</td>\n"]
            )

          l =
            xhtml(
              [~c"<td align=center><font size=\"-1\"><b>", label, ~c"</font></b></td>\n"],
              [~c"<td align=center><b>", label, ~c"</b></td>\n"]
            )

          t =
            xhtml([~c"<td><font size=\"-1\">", tS, ~c"</font></td>\n"], [
              ~c"<td>",
              tS,
              ~c"</td>\n"
            ])

          oldRunsLink =
            case oldRuns do
              [] ->
                ~c"none"

              _ ->
                ~c"<a href=\"" ++ ~c"all_runs.html" ++ ~c"\">Old Runs</a>"
            end

          a =
            xhtml(
              [
                ~c"<td><font size=\"-1\"><a href=\"",
                ctRunLogURI,
                ~c"\">CT Log</a></font></td>\n",
                ~c"<td><font size=\"-1\">",
                oldRunsLink,
                ~c"</font></td>\n"
              ],
              [
                ~c"<td><a href=\"",
                ctRunLogURI,
                ~c"\">CT Log</a></td>\n",
                ~c"<td>",
                oldRunsLink,
                ~c"</td>\n"
              ]
            )

          {l, t, n, a}

        false ->
          {~c"", ~c"", ~c"", ~c""}
      end

    notBuiltStr =
      cond do
        notBuilt == 0 ->
          [~c"<td align=right>", :erlang.integer_to_list(notBuilt), ~c"</td>\n"]

        true ->
          [
            ~c"<td align=right><a href=\"",
            ctRunLogURI,
            ~c"\">",
            :erlang.integer_to_list(notBuilt),
            ~c"</a></td>\n"
          ]
      end

    failStr =
      cond do
        fail > 0 or notBuilt > 0 or success + fail + userSkip + autoSkip == 0 ->
          [~c"<font color=\"red\">", :erlang.integer_to_list(fail), ~c"</font>"]

        true ->
          :erlang.integer_to_list(fail)
      end

    {allSkip, userSkipStr, autoSkipStr} =
      cond do
        autoSkip == :undefined ->
          {userSkip, ~c"?", ~c"?"}

        true ->
          aSStr =
            cond do
              autoSkip > 0 ->
                [~c"<font color=\"brown\">", :erlang.integer_to_list(autoSkip), ~c"</font>"]

              true ->
                :erlang.integer_to_list(autoSkip)
            end

          {userSkip + autoSkip, :erlang.integer_to_list(userSkip), aSStr}
      end

    {[
       xhtml(~c"<tr valign=top>\n", [~c"<tr class=\"", odd_or_even(), ~c"\">\n"]),
       xhtml(~c"<td><font size=\"-1\"><a href=\"", ~c"<td><a href=\""),
       logFileURI,
       ~c"\">",
       suiteName,
       ~c"</a>",
       crashDumpLink,
       xhtml(
         ~c"</font></td>\n",
         ~c"</td>\n"
       ),
       lbl,
       timestamp,
       ~c"<td align=right>",
       :erlang.integer_to_list(success),
       ~c"</td>\n",
       ~c"<td align=right>",
       failStr,
       ~c"</td>\n",
       ~c"<td align=right>",
       :erlang.integer_to_list(allSkip),
       ~c" (",
       userSkipStr,
       ~c"/",
       autoSkipStr,
       ~c")</td>\n",
       notBuiltStr,
       node,
       allInfo,
       ~c"</tr>\n"
     ], uRIs1}
  end

  defp total_row(success, fail, userSkip, autoSkip, notBuilt, all) do
    {label, timestampCell, allInfo} =
      case all do
        true ->
          {~c"<td>&nbsp;</td>\n", ~c"<td>&nbsp;</td>\n",
           ~c"<td>&nbsp;</td>\n<td>&nbsp;</td>\n<td>&nbsp;</td>\n"}

        false ->
          {~c"", ~c"", ~c""}
      end

    {allSkip, userSkipStr, autoSkipStr} =
      cond do
        autoSkip == :undefined ->
          {userSkip, ~c"?", ~c"?"}

        true ->
          {userSkip + autoSkip, :erlang.integer_to_list(userSkip),
           :erlang.integer_to_list(autoSkip)}
      end

    [
      xhtml(~c"<tr valign=top>\n", [~c"</tbody>\n<tfoot>\n<tr class=\"", odd_or_even(), ~c"\">\n"]),
      ~c"<td><b>Total</b></td>\n",
      label,
      timestampCell,
      ~c"<td align=right><b>",
      :erlang.integer_to_list(success),
      ~c"</b></td>\n",
      ~c"<td align=right><b>",
      :erlang.integer_to_list(fail),
      ~c"</b></td>\n",
      ~c"<td align=right>",
      :erlang.integer_to_list(allSkip),
      ~c" (",
      userSkipStr,
      ~c"/",
      autoSkipStr,
      ~c")</td>\n",
      ~c"<td align=right><b>",
      :erlang.integer_to_list(notBuilt),
      ~c"</b></td>\n",
      allInfo,
      ~c"</tr>\n",
      xhtml(
        ~c"",
        ~c"</tfoot>\n"
      )
    ]
  end

  defp not_built(_BaseName, _LogDir, _All, []) do
    0
  end

  defp not_built(baseName, _LogDir, _All, missing) do
    failed =
      case :string.lexemes(baseName, ~c".") do
        [t, o] when is_list(t) ->
          locate_info({t, o}, :all, missing)

        [t, o, ~c"suites"] ->
          locate_info({t, o}, :suites, missing)

        [t, o, s] ->
          locate_info({t, o}, :erlang.list_to_atom(s), missing)

        [t, o, s, _] ->
          locate_info({t, o}, :erlang.list_to_atom(s), missing)

        _ ->
          []
      end

    length(failed)
  end

  defp locate_info(path = {top, obj}, allOrSuite, [{{dir, suite}, failed} | errors]) do
    case :lists.reverse(:filename.split(dir)) do
      [~c"test", ^obj, ^top | _] ->
        get_missing_suites(
          allOrSuite,
          {suite, failed}
        ) ++ locate_info(path, allOrSuite, errors)

      [^obj, ^top | _] ->
        get_missing_suites(
          allOrSuite,
          {suite, failed}
        ) ++ locate_info(path, allOrSuite, errors)

      _ ->
        locate_info(path, allOrSuite, errors)
    end
  end

  defp locate_info(_, _, []) do
    []
  end

  defp get_missing_suites(:all, {~c"all", failed}) do
    failed
  end

  defp get_missing_suites(:suites, {_Suite, failed}) do
    failed
  end

  defp get_missing_suites(suite, {suite, failed}) do
    failed
  end

  defp get_missing_suites(_, _) do
    []
  end

  defp term_to_text(term) do
    :lists.flatten(:io_lib.format(~c"~tp.\n", [term]))
  end

  defp index_header(label, startTime, customStylesheet) do
    head =
      case label do
        :undefined ->
          header(
            ~c"Test Results",
            format_time(startTime),
            {[], [1], [2, 3, 4, 5]},
            customStylesheet
          )

        _ ->
          header(
            ~c"Test Results for '" ++ label ++ ~c"'",
            format_time(startTime),
            {[], [1], [2, 3, 4, 5]},
            customStylesheet
          )
      end

    cover =
      case :filelib.is_regular(:filename.absname(~c"cover.html")) do
        true ->
          xhtml([~c"<p><a href=\"", ~c"cover.html", ~c"\">Cover Log</a></p><br>\n"], [
            ~c"<br /><div id=\"button_holder\" class=\"btn\">\n<a href=\"",
            ~c"cover.html",
            ~c"\">COVER LOG</a>\n</div><br /><br />"
          ])

        false ->
          xhtml(~c"<br>\n", ~c"<br /><br /><br />\n")
      end

    [
      head,
      ~c"<center>\n",
      xhtml([~c"<p><a href=\"", ~c"ctlog.html", ~c"\">Common Test Framework Log</a></p>"], [
        ~c"<br /><div id=\"button_holder\" class=\"btn\">\n<a href=\"",
        ~c"ctlog.html",
        ~c"\">COMMON TEST FRAMEWORK LOG</a>\n</div><br>\n"
      ]),
      cover,
      xhtml(
        [~c"<table border=\"3\" cellpadding=\"5\" bgcolor=\"", ~c"#F0F8FF", ~c"\">\n"],
        [~c"<table id=\"", ~c"SortableTable", ~c"\">\n", ~c"<thead>\n<tr>\n"]
      ),
      ~c"<th><b>Test Name</b></th>\n",
      xhtml(
        [
          ~c"<th><font color=\"",
          ~c"#F0F8FF",
          ~c"\">_</font>Ok<font color=\"",
          ~c"#F0F8FF",
          ~c"\">_</font></th>\n"
        ],
        ~c"<th>Ok</th>\n"
      ),
      ~c"<th>Failed</th>\n",
      ~c"<th>Skipped",
      xhtml(~c"<br>", ~c"<br />"),
      ~c"(User/Auto)</th>\n<th>Missing",
      xhtml(
        ~c"<br>",
        ~c"<br />"
      ),
      ~c"Suites</th>\n",
      xhtml(
        ~c"",
        ~c"</tr>\n</thead>\n<tbody>\n"
      )
    ]
  end

  defp all_suites_index_header(customStylesheet) do
    {:ok, cwd} = :file.get_cwd()
    all_suites_index_header(cwd, customStylesheet)
  end

  defp all_suites_index_header(indexDir, customStylesheet) do
    logDir = :filename.basename(indexDir)
    allRuns = xhtml([~c"All test runs in \"" ++ logDir ++ ~c"\""], ~c"ALL RUNS")

    allRunsLink =
      xhtml(
        [~c"<a href=\"", ~c"all_runs.html", ~c"\">", allRuns, ~c"</a>\n"],
        [
          ~c"<div id=\"button_holder\" class=\"btn\">\n<a href=\"",
          ~c"all_runs.html",
          ~c"\">",
          allRuns,
          ~c"</a>\n</div>"
        ]
      )

    [
      header(~c"Test Results", ~c"", {[3], [1, 2, 8, 9, 10], [4, 5, 6, 7]}, customStylesheet),
      ~c"<center>\n",
      allRunsLink,
      xhtml(~c"<br><br>\n", ~c"<br /><br />\n"),
      xhtml(
        [~c"<table border=\"3\" cellpadding=\"5\" bgcolor=\"", ~c"#E4F0FE", ~c"\">\n"],
        [~c"<table id=\"", ~c"SortableTable", ~c"\">\n", ~c"<thead>\n<tr>\n"]
      ),
      ~c"<th>Test Name</th>\n",
      ~c"<th>Label</th>\n",
      ~c"<th>Test Run Started</th>\n",
      xhtml(
        [
          ~c"<th><font color=\"",
          ~c"#E4F0FE",
          ~c"\">_</font>Ok<font color=\"",
          ~c"#E4F0FE",
          ~c"\">_</font></th>\n"
        ],
        ~c"<th>Ok</th>\n"
      ),
      ~c"<th>Failed</th>\n",
      ~c"<th>Skipped<br>(User/Auto)</th>\n<th>Missing<br>Suites</th>\n<th>Node</th>\n",
      ~c"<th>CT Log</th>\n",
      ~c"<th>Old Runs</th>\n",
      xhtml(
        ~c"",
        ~c"</tr>\n</thead>\n<tbody>\n"
      )
    ]
  end

  defp all_runs_header(customStylesheet) do
    {:ok, cwd} = :file.get_cwd()
    logDir = :filename.basename(cwd)
    title = ~c"All test runs in \"" ++ logDir ++ ~c"\""

    ixLink = [
      xhtml([~c"<p><a href=\"", ~c"index.html", ~c"\">Test Index Page</a></p>"], [
        ~c"<div id=\"button_holder\" class=\"btn\">\n<a href=\"",
        ~c"index.html",
        ~c"\">TEST INDEX PAGE</a>\n</div>"
      ]),
      xhtml(~c"<br>\n", ~c"<br /><br />\n")
    ]

    [
      header(title, ~c"", {[1], [2, 3, 5], [4, 6, 7, 8, 9, 10]}, customStylesheet),
      ~c"<center>\n",
      ixLink,
      xhtml([~c"<table border=\"3\" cellpadding=\"5\" bgcolor=\"", ~c"#ADD8E6", ~c"\">\n"], [
        ~c"<table id=\"",
        ~c"SortableTable",
        ~c"\">\n",
        ~c"<thead>\n<tr>\n"
      ]),
      ~c"<th><b>History</b></th>\n<th><b>Node</b></th>\n<th><b>Label</b></th>\n<th>Tests</th>\n<th><b>Test Names</b></th>\n<th>Total</th>\n",
      xhtml(
        [
          ~c"<th><font color=\"",
          ~c"#ADD8E6",
          ~c"\">_</font>Ok<font color=\"",
          ~c"#ADD8E6",
          ~c"\">_</font></th>\n"
        ],
        ~c"<th>Ok</th>\n"
      ),
      ~c"<th>Failed</th>\n<th>Skipped<br>(User/Auto)</th>\n<th>Missing<br>Suites</th>\n",
      xhtml(~c"", ~c"</tr>\n</thead>\n<tbody>\n")
    ]
  end

  defp header(title, subTitle, tableCols, customStylesheet) do
    subTitleHTML =
      cond do
        subTitle !== ~c"" ->
          [
            ~c"<center>\n",
            ~c"<h3>" ++ subTitle ++ ~c"</h3>\n",
            xhtml(~c"</center>\n<br>\n", ~c"</center>\n<br />\n")
          ]

        true ->
          xhtml(~c"<br>", ~c"<br />")
      end

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

    customCSSFileHtml = custom_stylesheet_header(customStylesheet)

    [
      xhtml([~c"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n", ~c"<html>\n"], [
        ~c"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n",
        ~c"\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n",
        ~c"<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n"
      ]),
      ~c"<!-- autogenerated by '" ++ :erlang.atom_to_list(:ct_logs) ++ ~c"' -->\n",
      ~c"<head>\n",
      ~c"<title>" ++ title ++ ~c" " ++ subTitle ++ ~c"</title>\n",
      ~c"<meta http-equiv=\"cache-control\" content=\"no-cache\"></meta>\n",
      ~c"<meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\"></meta>\n",
      xhtml(
        ~c"",
        [~c"<link rel=\"stylesheet\" href=\"", uri(cSSFile), ~c"\" type=\"text/css\"></link>\n"]
      ),
      customCSSFileHtml,
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
          insert_javascript({:tablesorter, ~c"SortableTable", tableCols})
        end
      ),
      ~c"</head>\n",
      body_tag(),
      ~c"<center>\n",
      ~c"<h1>" ++ title ++ ~c"</h1>\n",
      ~c"</center>\n",
      subTitleHTML,
      ~c"\n"
    ]
  end

  defp custom_stylesheet_header(:unknown) do
    custom_stylesheet_header(get_stylesheet())
  end

  defp custom_stylesheet_header(:undefined) do
    ~c""
  end

  defp custom_stylesheet_header(path) when is_list(path) do
    case stylesheet_to_style_html(path) do
      {:ok, styleMarkup} ->
        xhtml(~c"", styleMarkup)

      {:error, _Reason} ->
        ~c""
    end
  end

  defp last_run_index_footer() do
    allRuns = :filename.join(~c"../", ~c"all_runs.html")
    testIndex = :filename.join(~c"../", ~c"index.html")

    [
      ~c"</table>\n",
      xhtml(~c"<br><hr><p>\n", ~c"<br /><hr /><p>\n"),
      ~c"<a href=\"",
      uri(allRuns),
      ~c"\">Test run history\n</a>  |  ",
      ~c"<a href=\"",
      uri(testIndex),
      ~c"\">Top level test index\n</a>\n</p>\n",
      ~c"</center>\n" | footer()
    ]
  end

  defp all_suites_index_footer() do
    [~c"</table>\n", ~c"</center>\n", xhtml(~c"<br><br>\n", ~c"<br /><br />\n") | footer()]
  end

  defp all_runs_index_footer() do
    [
      xhtml(~c"", ~c"</tbody>\n"),
      ~c"</table>\n",
      ~c"</center>\n",
      xhtml(~c"<br><br>\n", ~c"<br /><br />\n") | footer()
    ]
  end

  defp footer() do
    [
      ~c"<center>\n",
      xhtml(~c"<hr>\n", ~c""),
      xhtml(~c"<p><font size=\"-1\">\n", ~c"<div class=\"copyright\">"),
      ~c"Copyright &copy; ",
      year(),
      ~c" <a href=\"http://www.erlang.org\">Open Telecom Platform</a>",
      xhtml(~c"<br>\n", ~c"<br />\n"),
      ~c"Updated: <!--date-->",
      current_time(),
      ~c"<!--/date-->",
      xhtml(
        ~c"<br>\n",
        ~c"<br />\n"
      ),
      xhtml(
        ~c"</font></p>\n",
        ~c"</div>\n"
      ),
      ~c"</center>\n</body>\n</html>\n"
    ]
  end

  defp body_tag() do
    cTPath = :code.lib_dir(:common_test)
    tileFile = :filename.join(:filename.join(cTPath, ~c"priv"), ~c"tile1.jpg")

    xhtml(
      ~c"<body background=\"" ++
        tileFile ++
        ~c"\" bgcolor=\"#FFFFFF\" text=\"#000000\" link=\"#0000FF\" vlink=\"#800080\" alink=\"#FF0000\">\n",
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

  defp count_cases(dir) do
    sumFile = :filename.join(dir, ~c"suite.summary")

    case read_summary(sumFile, [:summary]) do
      {:ok, [{succ, fail, skip}]} ->
        {succ, fail, skip, :undefined}

      {:ok, [summary]} ->
        summary

      {:error, _} ->
        logFile = :filename.join(dir, ~c"suite.log")

        case :file.read_file(logFile) do
          {:ok, bin} ->
            case count_cases1(
                   b2s(bin),
                   {:undefined, :undefined, :undefined, :undefined}
                 ) do
              {:error, :not_complete} ->
                {0, 0, 0, 0}

              summary ->
                _ = write_summary(sumFile, summary)
                summary
            end

          {:error, reason} ->
            :io.format(~c"\nFailed to read ~tp: ~tp (skipped)\n", [logFile, reason])
            :error
        end
    end
  end

  defp write_summary(name, summary) do
    file = [term_to_text({:summary, summary})]
    force_write_file(name, file)
  end

  defp read_summary(name, keys) do
    case :file.consult(name) do
      {:ok, []} ->
        {:error, ~c"Empty summary file"}

      {:ok, terms} ->
        {:ok,
         :lists.map(
           fn key ->
             {:value, {_, value}} = :lists.keysearch(key, 1, terms)
             value
           end,
           keys
         )}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp count_cases1(
         ~c"=failed" ++ rest,
         {success, _Fail, userSkip, autoSkip}
       ) do
    {nextLine, count} = get_number(rest)

    count_cases1(
      nextLine,
      {success, count, userSkip, autoSkip}
    )
  end

  defp count_cases1(
         ~c"=successful" ++ rest,
         {_Success, fail, userSkip, autoSkip}
       ) do
    {nextLine, count} = get_number(rest)

    count_cases1(
      nextLine,
      {count, fail, userSkip, autoSkip}
    )
  end

  defp count_cases1(
         ~c"=skipped" ++ rest,
         {success, fail, _UserSkip, _AutoSkip}
       ) do
    {nextLine, count} = get_number(rest)

    count_cases1(
      nextLine,
      {success, fail, count, :undefined}
    )
  end

  defp count_cases1(
         ~c"=user_skipped" ++ rest,
         {success, fail, _UserSkip, autoSkip}
       ) do
    {nextLine, count} = get_number(rest)
    count_cases1(nextLine, {success, fail, count, autoSkip})
  end

  defp count_cases1(
         ~c"=auto_skipped" ++ rest,
         {success, fail, userSkip, _AutoSkip}
       ) do
    {nextLine, count} = get_number(rest)
    count_cases1(nextLine, {success, fail, userSkip, count})
  end

  defp count_cases1([], {su, f, uSk, _ASk})
       when su == :undefined or
              f == :undefined or uSk == :undefined do
    {:error, :not_complete}
  end

  defp count_cases1([], counters) do
    counters
  end

  defp count_cases1(other, counters) do
    count_cases1(skip_to_nl(other), counters)
  end

  defp get_number([?\s | rest]) do
    get_number(rest)
  end

  defp get_number([digit | rest])
       when ?0 <= digit and
              digit <= ?9 do
    get_number(rest, digit - ?0)
  end

  defp get_number([digit | rest], acc)
       when ?0 <= digit and
              digit <= ?9 do
    get_number(rest, acc * 10 + digit - ?0)
  end

  defp get_number([?\n | rest], acc) do
    {rest, acc}
  end

  defp get_number([_ | rest], acc) do
    get_number(rest, acc)
  end

  defp skip_to_nl([?\n | rest]) do
    rest
  end

  defp skip_to_nl([_ | rest]) do
    skip_to_nl(rest)
  end

  defp skip_to_nl([]) do
    []
  end

  defp config_table(vars) do
    [config_table_header() | config_table1(vars)]
  end

  defp config_table_header() do
    [
      xhtml(
        [
          ~c"<h2>Configuration</h2>\n<table border=\"3\" cellpadding=\"5\" bgcolor=\"",
          ~c"#ADD8E6",
          ~c"\">\n"
        ],
        [
          ~c"<h4>CONFIGURATION</h4>\n",
          ~c"<table id=\"",
          ~c"SortableTable",
          ~c"\">\n",
          ~c"<thead>\n"
        ]
      ),
      ~c"<tr><th>Key</th><th>Value</th></tr>\n",
      xhtml(~c"", ~c"</thead>\n<tbody>\n")
    ]
  end

  defp config_table1([{key, value} | vars]) do
    [
      xhtml(
        [
          ~c"<tr><td>",
          :erlang.atom_to_list(key),
          ~c"</td>\n",
          ~c"<td><pre>",
          :io_lib.format(~c"~tp", [value]),
          ~c"</pre></td></tr>\n"
        ],
        [
          ~c"<tr class=\"",
          odd_or_even(),
          ~c"\">\n",
          ~c"<td>",
          :erlang.atom_to_list(key),
          ~c"</td>\n",
          ~c"<td>",
          :io_lib.format(
            ~c"~tp",
            [value]
          ),
          ~c"</td>\n</tr>\n"
        ]
      )
      | config_table1(vars)
    ]
  end

  defp config_table1([]) do
    [xhtml(~c"", ~c"</tbody>\n"), ~c"</table>\n"]
  end

  def make_all_runs_index(when__, customStylesheet) do
    :erlang.put(:basic_html, basic_html())
    absName = :filename.absname(~c"all_runs.html")
    notify_and_lock_file(absName)

    cond do
      when__ == :start ->
        :ok

      true ->
        :io.put_chars(~c"Updating " ++ absName ++ ~c" ... ")
    end

    useCache =
      cond do
        when__ == :refresh ->
          :save_only

        true ->
          case :application.get_env(
                 :common_test,
                 :disable_log_cache
               ) do
            {:ok, true} ->
              :disabled

            _ ->
              case :erlang.get(:ct_log_cache) do
                :undefined ->
                  :file.read_file(~c"ct_log_cache")

                logCacheBin ->
                  {:ok, logCacheBin}
              end
          end
      end

    dirs = :filelib.wildcard(logdir_prefix() ++ ~c"*.*")

    dirsSorted0 =
      try do
        sort_all_runs(dirs)
      catch
        :error, e -> {:EXIT, {e, __STACKTRACE__}}
        :exit, e -> {:EXIT, e}
        e -> e
      end

    dirsSorted =
      cond do
        when__ == :start ->
          dirsSorted0

        true ->
          maybe_delete_old_dirs(dirsSorted0)
      end

    logCacheInfo = get_cache_data(useCache)

    result =
      case logCacheInfo do
        {:ok, logCache} ->
          make_all_runs_from_cache(absName, dirsSorted, logCache, customStylesheet)

        _WhyNot ->
          header = all_runs_header(customStylesheet)

          getLogResult = fn dir, {runData, logTxt} ->
            {tot, xHTML, ixLink} =
              runentry(
                dir,
                :undefined,
                :undefined
              )

            {[{dir, tot, ixLink} | runData], [xHTML | logTxt]}
          end

          {allRunsData, index} = :lists.foldr(getLogResult, {[], []}, dirsSorted)

          cond do
            useCache == :disabled ->
              :ok

            true ->
              update_all_runs_in_cache(allRunsData)
          end

          :ok =
            :file.write_file(
              absName,
              :unicode.characters_to_binary(header ++ index ++ all_runs_index_footer())
            )
      end

    notify_and_unlock_file(absName)

    cond do
      when__ == :start ->
        :ok

      true ->
        :io.put_chars(~c"done\n")
    end

    result
  end

  defp make_all_runs_from_cache(absName, dirs, logCache, customStylesheet) do
    header = all_runs_header(customStylesheet)
    allRunsDirs = dir_diff_all_runs(dirs, logCache)

    getLogResult = fn
      {dir, :no_test_data, ixLink}, {runData, logTxt} ->
        {tot, xHTML, _} = runentry(dir, :undefined, ixLink)
        {[{dir, tot, ixLink} | runData], [xHTML | logTxt]}

      {dir, cachedTotals, ixLink}, {runData, logTxt} ->
        {tot, xHTML, _} = runentry(dir, cachedTotals, ixLink)
        {[{dir, tot, ixLink} | runData], [xHTML | logTxt]}

      dir, {runData, logTxt} ->
        {tot, xHTML, ixLink} = runentry(dir, :undefined, :undefined)
        {[{dir, tot, ixLink} | runData], [xHTML | logTxt]}
    end

    {allRunsData, index} = :lists.foldr(getLogResult, {[], []}, allRunsDirs)
    update_all_runs_in_cache(allRunsData, logCache)

    :ok =
      :file.write_file(
        absName,
        :unicode.characters_to_binary(header ++ index ++ all_runs_index_footer())
      )
  end

  defp update_all_runs_in_cache(allRunsData) do
    case :erlang.get(:ct_log_cache) do
      :undefined ->
        logCache =
          r_log_cache(
            version: cache_vsn(),
            all_runs: allRunsData
          )

        case {self(), :erlang.whereis(:ct_logs)} do
          {pid, pid} ->
            :erlang.put(
              :ct_log_cache,
              :erlang.term_to_binary(logCache)
            )

          _ ->
            write_log_cache(:erlang.term_to_binary(logCache))
        end

      savedLogCache ->
        update_all_runs_in_cache(
          allRunsData,
          :erlang.binary_to_term(savedLogCache)
        )
    end
  end

  defp update_all_runs_in_cache(allRunsData, logCache) do
    logCache1 = r_log_cache(logCache, all_runs: allRunsData)

    case {self(), :erlang.whereis(:ct_logs)} do
      {pid, pid} ->
        :erlang.put(
          :ct_log_cache,
          :erlang.term_to_binary(logCache1)
        )

      _ ->
        write_log_cache(:erlang.term_to_binary(logCache1))
    end
  end

  defp sort_all_runs(dirs) do
    :lists.sort(
      fn dir1, dir2 ->
        [
          sS1,
          mM1,
          hH1,
          date1
          | _
        ] =
          :lists.reverse(
            :string.lexemes(
              dir1,
              [?., ?_]
            )
          )

        [
          sS2,
          mM2,
          hH2,
          date2
          | _
        ] =
          :lists.reverse(
            :string.lexemes(
              dir2,
              [?., ?_]
            )
          )

        {date1, hH1, mM1, sS1} > {date2, hH2, mM2, sS2}
      end,
      dirs
    )
  end

  defp sort_ct_runs(dirs) do
    :lists.sort(
      fn dir1, dir2 ->
        [
          sS1,
          mM1,
          dateHH1
          | _
        ] =
          :lists.reverse(
            :string.lexemes(
              :filename.dirname(dir1),
              [?.]
            )
          )

        [
          sS2,
          mM2,
          dateHH2
          | _
        ] =
          :lists.reverse(
            :string.lexemes(
              :filename.dirname(dir2),
              [?.]
            )
          )

        {dateHH1, mM1, sS1} <= {dateHH2, mM2, sS2}
      end,
      dirs
    )
  end

  def parse_keep_logs([str = ~c"all"]) do
    parse_keep_logs(:erlang.list_to_atom(str))
  end

  def parse_keep_logs([nStr]) do
    parse_keep_logs(:erlang.list_to_integer(nStr))
  end

  def parse_keep_logs(:all) do
    :all
  end

  def parse_keep_logs(n) when is_integer(n) and n > 0 do
    n
  end

  defp maybe_delete_old_dirs(sorted) do
    {keep, delete} =
      case :application.get_env(
             :common_test,
             :keep_logs
           ) do
        {:ok, maxN}
        when is_integer(maxN) and
               length(sorted) > maxN ->
          :lists.split(maxN, sorted)

        _ ->
          {sorted, []}
      end

    delete_old_dirs(delete)
    keep
  end

  defp delete_old_dirs([]) do
    :ok
  end

  defp delete_old_dirs(dirs) do
    :io.put_chars(~c"\n  Removing old test directories:\n")

    for dir <- dirs do
      :io.put_chars(~c"    " ++ dir ++ ~c"\n")
      rm_dir(dir)
    end

    :ok
  end

  defp dir_diff_all_runs(dirs, logCache) do
    case r_log_cache(logCache, :all_runs) do
      [] ->
        dirs

      cached = [{cDir, _, _} | _] ->
        allRunsDirs = dir_diff_all_runs(dirs, cached, datestr_from_dirname(cDir), [])
        :lists.reverse(allRunsDirs)
    end
  end

  defp dir_diff_all_runs(
         logDirs = [dir | dirs],
         cached = [cElem | cElems],
         latestInCache,
         allRunsDirs
       ) do
    dirDate = datestr_from_dirname(dir)

    cond do
      dirDate > latestInCache ->
        dir_diff_all_runs(dirs, cached, latestInCache, [dir | allRunsDirs])

      dirDate == latestInCache and cElems != [] ->
        elemToAdd =
          case cElem do
            {_CDir, {_NodeStr, _Label, _Logs, {0, 0, 0, 0, 0}}, _IxLink} ->
              dir

            _ ->
              cElem
          end

        dir_diff_all_runs(
          dirs,
          cElems,
          datestr_from_dirname(
            :erlang.element(
              1,
              hd(cElems)
            )
          ),
          [elemToAdd | allRunsDirs]
        )

      dirDate == latestInCache and cElems == [] ->
        :lists.reverse(dirs) ++ [cElem | allRunsDirs]

      cElems != [] ->
        dir_diff_all_runs(
          logDirs,
          cElems,
          datestr_from_dirname(
            :erlang.element(
              1,
              hd(cElems)
            )
          ),
          allRunsDirs
        )

      cElems == [] ->
        :lists.reverse(logDirs) ++ allRunsDirs
    end
  end

  defp dir_diff_all_runs([], _Cached, _, allRunsDirs) do
    allRunsDirs
  end

  defp interactive_link() do
    [
      dir
      | _
    ] = :lists.reverse(:filelib.wildcard(logdir_prefix() ++ ~c"*.*"))

    ctLog = :filename.join(dir, ~c"ctlog.html")

    body = [
      xhtml([~c"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n", ~c"<html>\n"], [
        ~c"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n",
        ~c"\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n",
        ~c"<html xmlns=\"http://www.w3.org/1999/xhtml\" ",
        ~c"xml:lang=\"en\" lang=\"en\">\n"
      ]),
      ~c"<!-- autogenerated by '" ++ :erlang.atom_to_list(:ct_logs) ++ ~c"' -->\n",
      ~c"<head>\n",
      ~c"<title>Last interactive run</title>\n",
      ~c"<meta http-equiv=\"cache-control\" content=\"no-cache\"></meta>\n",
      ~c"<meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\"></meta>\n",
      ~c"</head>\n",
      ~c"<body>\n",
      ~c"Log from last interactive run: <a href=\"",
      uri(ctLog),
      ~c"\">",
      timestamp(dir),
      ~c"</a>",
      ~c"</body>\n",
      ~c"</html>\n"
    ]

    _ =
      :file.write_file(
        ~c"last_interactive.html",
        :unicode.characters_to_binary(body)
      )

    :io.format(~c"~n~nUpdated ~ts\nAny CT activities will be logged here\n", [
      :filename.absname(~c"last_interactive.html")
    ])
  end

  defp runentry(dir, :undefined, _) do
    totalsFile = :filename.join(dir, ~c"totals.info")
    index = uri(:filename.join(dir, ~c"index.html"))
    runentry(dir, read_totals_file(totalsFile), index)
  end

  defp runentry(
         dir,
         totals = {node, label, logs, {totSucc, totFail, userSkip, autoSkip, notBuilt}},
         index
       ) do
    totFailStr =
      cond do
        totFail > 0 or notBuilt > 0 or totSucc + totFail + userSkip + autoSkip == 0 ->
          [~c"<font color=\"red\">", :erlang.integer_to_list(totFail), ~c"</font>"]

        true ->
          :erlang.integer_to_list(totFail)
      end

    {allSkip, userSkipStr, autoSkipStr} =
      cond do
        autoSkip == :undefined ->
          {userSkip, ~c"?", ~c"?"}

        true ->
          aSStr =
            cond do
              autoSkip > 0 ->
                [~c"<font color=\"brown\">", :erlang.integer_to_list(autoSkip), ~c"</font>"]

              true ->
                :erlang.integer_to_list(autoSkip)
            end

          {userSkip + autoSkip, :erlang.integer_to_list(userSkip), aSStr}
      end

    noOfTests =
      case length(logs) do
        0 ->
          ~c"-"

        n ->
          :erlang.integer_to_list(n)
      end

    rootNames =
      :lists.map(
        fn f ->
          :filename.rootname(f, ~c".logs")
        end,
        logs
      )

    testNames = :lists.flatten(:lists.join(~c", ", rootNames))

    testNamesTrunc =
      cond do
        length(testNames) < 60 ->
          testNames

        true ->
          trunc = :string.trim(:string.slice(testNames, 0, 60 - 3), :trailing, ~c", ")
          :lists.flatten(:io_lib.format(~c"~ts...", [trunc]))
      end

    totMissingStr =
      cond do
        notBuilt > 0 ->
          [~c"<font color=\"red\">", :erlang.integer_to_list(notBuilt), ~c"</font>"]

        true ->
          :erlang.integer_to_list(notBuilt)
      end

    total = totSucc + totFail + allSkip

    a =
      xhtml(
        [
          ~c"<td align=center><font size=\"-1\">",
          node,
          ~c"</font></td>\n",
          ~c"<td align=center><font size=\"-1\"><b>",
          label,
          ~c"</b></font></td>\n",
          ~c"<td align=right>",
          noOfTests,
          ~c"</td>\n"
        ],
        [
          ~c"<td align=center>",
          node,
          ~c"</td>\n",
          ~c"<td align=center><b>",
          label,
          ~c"</b></td>\n",
          ~c"<td align=right>",
          noOfTests,
          ~c"</td>\n"
        ]
      )

    b =
      xhtml(
        [
          ~c"<td align=center title='",
          testNames,
          ~c"'><font size=\"-1\"> ",
          testNamesTrunc,
          ~c"</font></td>\n"
        ],
        [~c"<td align=center title='", testNames, ~c"'> ", testNamesTrunc, ~c"</td>\n"]
      )

    c = [
      ~c"<td align=right>",
      :erlang.integer_to_list(total),
      ~c"</td>\n",
      ~c"<td align=right>",
      :erlang.integer_to_list(totSucc),
      ~c"</td>\n",
      ~c"<td align=right>",
      totFailStr,
      ~c"</td>\n",
      ~c"<td align=right>",
      :erlang.integer_to_list(allSkip),
      ~c" (",
      userSkipStr,
      ~c"/",
      autoSkipStr,
      ~c")</td>\n",
      ~c"<td align=right>",
      totMissingStr,
      ~c"</td>\n"
    ]

    totalsStr = a ++ b ++ c

    xHTML = [
      xhtml(~c"<tr>\n", [~c"<tr class=\"", odd_or_even(), ~c"\">\n"]),
      xhtml(
        [
          ~c"<td><font size=\"-1\"><a href=\"",
          index,
          ~c"\">",
          timestamp(dir),
          ~c"</a>",
          totalsStr,
          ~c"</font></td>\n"
        ],
        [~c"<td><a href=\"", index, ~c"\">", timestamp(dir), ~c"</a>", totalsStr, ~c"</td>\n"]
      ),
      ~c"</tr>\n"
    ]

    {totals, xHTML, index}
  end

  defp runentry(dir, _, _) do
    a =
      xhtml(
        [
          ~c"<td align=center><font size=\"-1\" color=\"red\">Test data missing or corrupt</font></td>\n",
          ~c"<td align=center><font size=\"-1\">?</font></td>\n",
          ~c"<td align=right>?</td>\n"
        ],
        [
          ~c"<td align=center><font color=\"red\">Test data missing or corrupt</font></td>\n",
          ~c"<td align=center>?</td>\n",
          ~c"<td align=right>?</td>\n"
        ]
      )

    b =
      xhtml([~c"<td align=center><font size=\"-1\">?</font></td>\n"], [
        ~c"<td align=center>?</td>\n"
      ])

    c = [
      ~c"<td align=right>?</td>\n",
      ~c"<td align=right>?</td>\n",
      ~c"<td align=right>?</td>\n",
      ~c"<td align=right>?</td>\n",
      ~c"<td align=right>?</td>\n"
    ]

    totalsStr = a ++ b ++ c
    index = uri(:filename.join(dir, ~c"index.html"))

    xHTML = [
      xhtml(~c"<tr>\n", [~c"<tr class=\"", odd_or_even(), ~c"\">\n"]),
      xhtml(
        [
          ~c"<td><font size=\"-1\"><a href=\"",
          index,
          ~c"\">",
          timestamp(dir),
          ~c"</a>",
          totalsStr,
          ~c"</font></td>\n"
        ],
        [~c"<td><a href=\"", index, ~c"\">", timestamp(dir), ~c"</a>", totalsStr, ~c"</td>\n"]
      ),
      ~c"</tr>\n"
    ]

    {:no_test_data, xHTML, index}
  end

  defp write_totals_file(name, label, logs, totals) do
    absName = :filename.absname(name)
    notify_and_lock_file(absName)

    _ =
      force_write_file(
        absName,
        :erlang.term_to_binary({:erlang.atom_to_list(node()), label, logs, totals})
      )

    notify_and_unlock_file(absName)
  end

  defp read_totals_file(name) do
    absName = :filename.absname(name)
    notify_and_lock_file(absName)

    result =
      case :file.read_file(absName) do
        {:ok, bin} ->
          case (try do
                  :erlang.binary_to_term(bin)
                catch
                  :error, e -> {:EXIT, {e, __STACKTRACE__}}
                  :exit, e -> {:EXIT, e}
                  e -> e
                end) do
            {:EXIT, _Reason} ->
              {~c"-", [], :undefined}

            {node, label, ls, tot} ->
              label1 =
                case label do
                  :undefined ->
                    ~c"-"

                  _ ->
                    label
                end

              case tot do
                {_Ok, _Fail, _USkip, _ASkip, _NoBuild} ->
                  {node, label1, ls, tot}

                {totSucc, totFail, allSkip, notBuilt} ->
                  {node, label1, ls, {totSucc, totFail, allSkip, :undefined, notBuilt}}
              end

            {node, ls, tot} ->
              case tot do
                {_Ok, _Fail, _USkip, _ASkip, _NoBuild} ->
                  {node, ~c"-", ls, tot}

                {totSucc, totFail, allSkip, notBuilt} ->
                  {node, ~c"-", ls, {totSucc, totFail, allSkip, :undefined, notBuilt}}
              end

            {ls, tot} ->
              {~c"-", ls, tot}

            tot ->
              {~c"-", [], tot}
          end

        error ->
          error
      end

    notify_and_unlock_file(absName)
    result
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

  defp timestamp(dir) do
    tsR = :lists.reverse(:string.lexemes(dir, ~c".-_"))

    [s, min, h, d, m, y] =
      for n <-
            :lists.sublist(
              tsR,
              6
            ) do
        :erlang.list_to_integer(n)
      end

    format_time({{y, m, d}, {h, min, s}})
  end

  def make_all_suites_index(when__, customStylesheet) when is_atom(when__) do
    :erlang.put(:basic_html, basic_html())
    absIndexName = :filename.absname(~c"index.html")
    notify_and_lock_file(absIndexName)

    useCache =
      cond do
        when__ == :refresh ->
          :save_only

        true ->
          case :application.get_env(
                 :common_test,
                 :disable_log_cache
               ) do
            {:ok, true} ->
              :disabled

            _ ->
              case :erlang.get(:ct_log_cache) do
                :undefined ->
                  :file.read_file(~c"ct_log_cache")

                logCacheBin ->
                  {:ok, logCacheBin}
              end
          end
      end

    wildcard = logdir_prefix() ++ ~c".*/*" ++ ~c".logs"
    logDirs = sort_ct_runs(:filelib.wildcard(wildcard))
    logCacheInfo = get_cache_data(useCache)

    result =
      case logCacheInfo do
        {:ok, logCache} ->
          make_all_suites_index_from_cache(
            when__,
            absIndexName,
            logDirs,
            logCache,
            customStylesheet
          )

        _WhyNot ->
          sorted = sort_and_filter_logdirs(logDirs)
          tempData = make_all_suites_index1(when__, absIndexName, sorted, customStylesheet)
          notify_and_unlock_file(absIndexName)

          cond do
            useCache == :disabled ->
              :ok

            true ->
              update_tests_in_cache(tempData)
          end

          tempData
      end

    case result do
      error = {:error, _} ->
        error

      _ ->
        :ok
    end
  end

  def make_all_suites_index(
        newTestData = {_TestName, dirName},
        customStylesheet
      ) do
    :erlang.put(:basic_html, basic_html())
    {absIndexName, logDirData} = :ct_util.get_testdata(:test_index)
    ctRunDirPos = length(:filename.split(absIndexName))

    ctRunDir =
      :filename.join(
        :lists.sublist(
          :filename.split(dirName),
          ctRunDirPos
        )
      )

    label =
      case read_totals_file(
             :filename.join(
               ctRunDir,
               ~c"totals.info"
             )
           ) do
        {_, ~c"-", _, _} ->
          ~c"..."

        {_, lbl, _, _} ->
          lbl

        _ ->
          ~c"..."
      end

    notify_and_lock_file(absIndexName)

    result =
      case (try do
              make_all_suites_ix_temp(
                absIndexName,
                newTestData,
                label,
                logDirData,
                customStylesheet
              )
            catch
              :error, e -> {:EXIT, {e, __STACKTRACE__}}
              :exit, e -> {:EXIT, e}
              e -> e
            end) do
        {:EXIT, reason} ->
          :io.put_chars(~c"CRASHED while updating " ++ absIndexName ++ ~c"!\n")
          :io.format(~c"~tp~n", [reason])
          {:error, reason}

        {:error, reason} ->
          :io.put_chars(~c"FAILED while updating " ++ absIndexName ++ ~c"\n")
          :io.format(~c"~tp~n", [reason])
          {:error, reason}

        :ok ->
          :ok

        err ->
          :io.format(
            ~c"Unknown internal error while updating ~ts. Please report.\n(Err: ~tp, ID: 1)",
            [absIndexName, err]
          )

          {:error, err}
      end

    notify_and_unlock_file(absIndexName)
    result
  end

  defp make_all_suites_index_from_cache(when__, absIndexName, logDirs, logCache, customStylesheet) do
    {newAdded, oldTests} = dir_diff_tests(logDirs, logCache)
    logCache1 = delete_tests_from_cache(oldTests, logCache)

    sorted =
      sort_and_filter_logdirs(
        newAdded,
        r_log_cache(logCache1, :tests)
      )

    tempData =
      cond do
        sorted != [] ->
          make_all_suites_index1(when__, absIndexName, sorted, customStylesheet)

        true ->
          data = r_log_cache(logCache1, :tests)
          :ct_util.set_testdata_async({:test_index, {absIndexName, data}})
          data
      end

    notify_and_unlock_file(absIndexName)
    update_tests_in_cache(tempData, logCache1)
    tempData
  end

  defp sort_and_filter_logdirs(newDirs, cachedTests) when cachedTests != [] do
    newSorted = sort_and_filter_logdirs1(newDirs, [])
    sort_and_filter_logdirs(newSorted, cachedTests, [])
  end

  defp sort_and_filter_logdirs(newDirs, _CachedTests) do
    sort_and_filter_logdirs(newDirs)
  end

  defp sort_and_filter_logdirs([{testName, ixDirs} | tests], cachedTests, combined) do
    case :lists.keysearch(testName, 1, cachedTests) do
      {:value, {^testName, _, _, {ixDir0, _, _}, ixDirs0}} ->
        groups = sort_and_filter_logdirs2(testName, ixDirs ++ [ixDir0 | ixDirs0], [])
        sort_and_filter_logdirs(tests, cachedTests, groups ++ combined)

      _ ->
        ixDirs1 =
          :lists.map(
            fn
              elem = {_, _} ->
                elem

              runDir ->
                {:filename.basename(runDir), runDir}
            end,
            ixDirs
          )

        sort_and_filter_logdirs(tests, cachedTests, [{testName, ixDirs1} | combined])
    end
  end

  defp sort_and_filter_logdirs([], cachedTests, combined) do
    cached1 =
      :lists.foldl(
        fn {testName, _}, cached ->
          :lists.keydelete(testName, 1, cached)
        end,
        cachedTests,
        combined
      )

    :lists.keysort(1, sort_each_group(combined) ++ cached1)
  end

  defp sort_and_filter_logdirs(dirs) do
    sort_and_filter_logdirs1(dirs, [])
  end

  defp sort_and_filter_logdirs1([dir | dirs], groups) do
    testName = :filename.rootname(:filename.basename(dir))

    case :filelib.wildcard(:filename.join(dir, ~c"run.*")) do
      runDirs = [_ | _] ->
        groups1 = sort_and_filter_logdirs2(testName, runDirs, groups)
        sort_and_filter_logdirs1(dirs, groups1)

      _ ->
        sort_and_filter_logdirs1(dirs, groups)
    end
  end

  defp sort_and_filter_logdirs1([], groups) do
    :lists.keysort(1, sort_each_group(groups))
  end

  defp sort_and_filter_logdirs2(testName, [runDir | runDirs], groups) do
    groups1 = insert_test(testName, {:filename.basename(runDir), runDir}, groups)
    sort_and_filter_logdirs2(testName, runDirs, groups1)
  end

  defp sort_and_filter_logdirs2(_, [], groups) do
    groups
  end

  defp insert_test(test, ixDir, [{test, ixDirs} | groups]) do
    [{test, [ixDir | ixDirs]} | groups]
  end

  defp insert_test(test, ixDir, []) do
    [{test, [ixDir]}]
  end

  defp insert_test(test, ixDir, [testDir | groups]) do
    [testDir | insert_test(test, ixDir, groups)]
  end

  defp sort_each_group([{test, ixDirs} | groups]) do
    sorted =
      :lists.reverse(
        for {_, dir} <- :lists.keysort(1, ixDirs) do
          dir
        end
      )

    [{test, sorted} | sort_each_group(groups)]
  end

  defp sort_each_group([]) do
    []
  end

  defp dir_diff_tests(logDirs, r_log_cache(tests: cachedTests)) do
    allTestNames =
      for {testName, _, _, _, _} <- cachedTests do
        testName
      end

    dir_diff_tests(logDirs, cachedTests, [], allTestNames, [], [])
  end

  defp dir_diff_tests(
         [logDir | logDirs],
         cachedTests,
         newAdded,
         deletedTests,
         validLast,
         invalidLast
       ) do
    testName = :filename.rootname(:filename.basename(logDir))
    time = datestr_from_dirname(logDir)

    {new, deletedTests1, validLast1, invalidLast1} =
      case :lists.keysearch(testName, 1, cachedTests) do
        {:value, {_, _, _, {lastLogDir, _, _}, _PrevLogDirs}} ->
          lastLogTime = datestr_from_dirname(lastLogDir)

          cond do
            time > lastLogTime ->
              {[logDir | newAdded], :lists.delete(testName, deletedTests), validLast,
               [{testName, lastLogDir} | invalidLast]}

            time == lastLogTime ->
              tDir = {testName, lastLogDir}
              {newAdded, :lists.delete(testName, deletedTests), [tDir | validLast], invalidLast}

            true ->
              {[], :lists.delete(testName, deletedTests), validLast,
               [{testName, lastLogDir} | invalidLast]}
          end

        _ ->
          {[logDir | newAdded], deletedTests, validLast, invalidLast}
      end

    dir_diff_tests(logDirs, cachedTests, new, deletedTests1, validLast1, invalidLast1)
  end

  defp dir_diff_tests([], _CachedTests, newAdded, deletedTests, validLast, invalidLast) do
    invalidLast1 =
      :lists.foldl(
        fn tDir, iL ->
          case :lists.member(tDir, validLast) do
            true ->
              for tD <- iL, tD != tDir do
                tD
              end

            false ->
              [
                tDir
                | for tD <- iL, tD != tDir do
                    tD
                  end
              ]
          end
        end,
        invalidLast,
        invalidLast
      )

    deletedTests1 =
      for {t, _} <- invalidLast1 do
        t
      end ++ deletedTests

    newAdded1 =
      :lists.map(
        fn {_TestName, runDir} ->
          [topDir, testDir | _] = :filename.split(runDir)
          :filename.join(topDir, testDir)
        end,
        invalidLast1
      ) ++ newAdded

    {newAdded1, deletedTests1}
  end

  defp delete_tests_from_cache(oldTests, logCache = r_log_cache(tests: tests)) do
    tests2 =
      :lists.foldl(
        fn t, tests1 ->
          :lists.keydelete(t, 1, tests1)
        end,
        tests,
        oldTests
      )

    r_log_cache(logCache, tests: tests2)
  end

  defp update_tests_in_cache(tempData) do
    case :erlang.get(:ct_log_cache) do
      :undefined ->
        update_tests_in_cache(
          tempData,
          r_log_cache(version: cache_vsn(), tests: [])
        )

      savedLogCache ->
        update_tests_in_cache(
          tempData,
          :erlang.binary_to_term(savedLogCache)
        )
    end
  end

  defp update_tests_in_cache(tempData, logCache = r_log_cache(tests: tests)) do
    cached1 =
      cond do
        tests == [] ->
          []

        true ->
          :lists.foldl(
            fn {testName, _, _, _, _}, cached ->
              :lists.keydelete(testName, 1, cached)
            end,
            tests,
            tempData
          )
      end

    tests1 = :lists.keysort(1, tempData ++ cached1)
    cacheBin = :erlang.term_to_binary(r_log_cache(logCache, tests: tests1))

    case {self(), :erlang.whereis(:ct_logs)} do
      {pid, pid} ->
        :erlang.put(:ct_log_cache, cacheBin)

      _ ->
        write_log_cache(cacheBin)
    end
  end

  defp make_all_suites_index1(when__, absIndexName, allTestLogDirs, customStylesheet) do
    indexName = ~c"index.html"

    cond do
      when__ == :start ->
        :ok

      true ->
        :io.put_chars(~c"Updating " ++ absIndexName ++ ~c" ... ")
    end

    case (try do
            make_all_suites_index2(indexName, allTestLogDirs, customStylesheet)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      {:EXIT, reason} ->
        :io.put_chars(~c"CRASHED while updating " ++ absIndexName ++ ~c"!\n")
        :io.format(~c"~tp~n", [reason])
        {:error, reason}

      {:error, reason} ->
        :io.put_chars(~c"FAILED while updating " ++ absIndexName ++ ~c"\n")
        :io.format(~c"~tp~n", [reason])
        {:error, reason}

      {:ok, tempData} ->
        case when__ do
          :start ->
            :ct_util.set_testdata_async({:test_index, {absIndexName, tempData}})
            tempData

          _ ->
            :io.put_chars(~c"done\n")
            tempData
        end

      err ->
        :io.format(
          ~c"Unknown internal error while updating ~ts. Please report.\n(Err: ~tp, ID: 1)",
          [absIndexName, err]
        )

        {:error, err}
    end
  end

  defp make_all_suites_index2(indexName, allTestLogDirs, customStylesheet) do
    {:ok, index0, _Totals, tempData} =
      make_all_suites_index3(
        allTestLogDirs,
        all_suites_index_header(customStylesheet),
        0,
        0,
        0,
        0,
        0,
        [],
        []
      )

    index = [index0 | all_suites_index_footer()]

    case force_write_file(
           indexName,
           :unicode.characters_to_binary(index)
         ) do
      :ok ->
        {:ok, tempData}

      {:error, reason} ->
        {:error, {:index_write_error, reason}}
    end
  end

  defp make_all_suites_index3(
         [
           ixEntry = {testName, label, missing, {lastLogDir, summary, uRIs}, oldDirs}
           | rest
         ],
         result,
         totSucc,
         totFail,
         userSkip,
         autoSkip,
         totNotBuilt,
         labels,
         tempData
       ) do
    [entryDir | _] = :filename.split(lastLogDir)
    labels1 = [{entryDir, label} | labels]

    case summary do
      {succ, fail, uSkip, aSkip} ->
        all = {true, oldDirs}
        notBuilt = not_built(testName, lastLogDir, all, missing)

        {result1, _} =
          make_one_index_entry1(
            testName,
            lastLogDir,
            label,
            succ,
            fail,
            uSkip,
            aSkip,
            notBuilt,
            all,
            :temp,
            uRIs
          )

        autoSkip1 =
          case (try do
                  autoSkip + aSkip
                catch
                  :error, e -> {:EXIT, {e, __STACKTRACE__}}
                  :exit, e -> {:EXIT, e}
                  e -> e
                end) do
            {:EXIT, _} ->
              :undefined

            res ->
              res
          end

        make_all_suites_index3(
          rest,
          [result | result1],
          totSucc + succ,
          totFail + fail,
          userSkip + uSkip,
          autoSkip1,
          totNotBuilt + notBuilt,
          labels1,
          [ixEntry | tempData]
        )

      :error ->
        make_all_suites_index3(
          rest,
          result,
          totSucc,
          totFail,
          userSkip,
          autoSkip,
          totNotBuilt,
          labels1,
          [ixEntry | tempData]
        )
    end
  end

  defp make_all_suites_index3(
         [{testName, [lastLogDir | oldDirs]} | rest],
         result,
         totSucc,
         totFail,
         userSkip,
         autoSkip,
         totNotBuilt,
         labels,
         tempData
       ) do
    [entryDir | _] = :filename.split(lastLogDir)

    missing =
      case :file.read_file(
             :filename.join(
               entryDir,
               ~c"missing_suites.info"
             )
           ) do
        {:ok, bin} ->
          :erlang.binary_to_term(bin)

        _ ->
          []
      end

    {label, labels1} =
      case :proplists.get_value(
             entryDir,
             labels
           ) do
        :undefined ->
          case read_totals_file(
                 :filename.join(
                   entryDir,
                   ~c"totals.info"
                 )
               ) do
            {_, lbl, _, _} ->
              {lbl, [{entryDir, lbl} | labels]}

            _ ->
              {~c"-", [{entryDir, ~c"-"} | labels]}
          end

        lbl ->
          {lbl, labels}
      end

    case make_one_index_entry(testName, lastLogDir, label, {true, oldDirs}, missing, :undefined) do
      {result1, succ, fail, uSkip, aSkip, notBuilt, uRIs} ->
        autoSkip1 =
          case (try do
                  autoSkip + aSkip
                catch
                  :error, e -> {:EXIT, {e, __STACKTRACE__}}
                  :exit, e -> {:EXIT, e}
                  e -> e
                end) do
            {:EXIT, _} ->
              :undefined

            res ->
              res
          end

        ixEntry =
          {testName, label, missing, {lastLogDir, {succ, fail, uSkip, aSkip}, uRIs}, oldDirs}

        make_all_suites_index3(
          rest,
          [result | result1],
          totSucc + succ,
          totFail + fail,
          userSkip + uSkip,
          autoSkip1,
          totNotBuilt + notBuilt,
          labels1,
          [ixEntry | tempData]
        )

      :error ->
        ixEntry = {testName, label, missing, {lastLogDir, :error, :undefined}, oldDirs}

        make_all_suites_index3(
          rest,
          result,
          totSucc,
          totFail,
          userSkip,
          autoSkip,
          totNotBuilt,
          labels1,
          [ixEntry | tempData]
        )
    end
  end

  defp make_all_suites_index3(
         [_ | rest],
         result,
         totSucc,
         totFail,
         userSkip,
         autoSkip,
         totNotBuilt,
         labels,
         tempData
       ) do
    make_all_suites_index3(
      rest,
      result,
      totSucc,
      totFail,
      userSkip,
      autoSkip,
      totNotBuilt,
      labels,
      tempData
    )
  end

  defp make_all_suites_index3(
         [],
         result,
         totSucc,
         totFail,
         userSkip,
         autoSkip,
         totNotBuilt,
         _,
         tempData
       ) do
    {:ok, [result | total_row(totSucc, totFail, userSkip, autoSkip, totNotBuilt, true)],
     {totSucc, totFail, userSkip, autoSkip, totNotBuilt}, :lists.reverse(tempData)}
  end

  defp make_all_suites_ix_temp(absIndexName, newTestData, label, allTestLogDirs, customStylesheet) do
    allTestLogDirs1 = insert_new_test_data(newTestData, label, allTestLogDirs)
    indexDir = :filename.dirname(absIndexName)

    index0 =
      make_all_suites_ix_temp1(
        allTestLogDirs1,
        all_suites_index_header(
          indexDir,
          customStylesheet
        ),
        0,
        0,
        0,
        0,
        0
      )

    index = [index0 | all_suites_index_footer()]

    case force_write_file(
           absIndexName,
           :unicode.characters_to_binary(index)
         ) do
      :ok ->
        :ok

      {:error, reason} ->
        {:error, {:index_write_error, reason}}
    end
  end

  defp insert_new_test_data({newTestName, newTestDir}, newLabel, allTestLogDirs) do
    allTestLogDirs1 =
      case :lists.keysearch(newTestName, 1, allTestLogDirs) do
        {:value, {_, _, _, {lastLogDir, _, _}, oldDirs}} ->
          [
            {newTestName, newLabel, [], {newTestDir, {0, 0, 0, 0}, :undefined},
             [lastLogDir | oldDirs]}
            | :lists.keydelete(newTestName, 1, allTestLogDirs)
          ]

        false ->
          [
            {newTestName, newLabel, [], {newTestDir, {0, 0, 0, 0}, :undefined}, []}
            | allTestLogDirs
          ]
      end

    :lists.keysort(1, allTestLogDirs1)
  end

  defp make_all_suites_ix_temp1(
         [
           {testName, label, missing, lastLogDirData, oldDirs}
           | rest
         ],
         result,
         totSucc,
         totFail,
         userSkip,
         autoSkip,
         totNotBuilt
       ) do
    case make_one_ix_entry_temp(testName, lastLogDirData, label, {true, oldDirs}, missing) do
      {result1, succ, fail, uSkip, aSkip, notBuilt, _URIs} ->
        autoSkip1 =
          case (try do
                  autoSkip + aSkip
                catch
                  :error, e -> {:EXIT, {e, __STACKTRACE__}}
                  :exit, e -> {:EXIT, e}
                  e -> e
                end) do
            {:EXIT, _} ->
              :undefined

            res ->
              res
          end

        make_all_suites_ix_temp1(
          rest,
          [result | result1],
          totSucc + succ,
          totFail + fail,
          userSkip + uSkip,
          autoSkip1,
          totNotBuilt + notBuilt
        )

      :error ->
        make_all_suites_ix_temp1(rest, result, totSucc, totFail, userSkip, autoSkip, totNotBuilt)
    end
  end

  defp make_all_suites_ix_temp1([], result, totSucc, totFail, userSkip, autoSkip, totNotBuilt) do
    [result | total_row(totSucc, totFail, userSkip, autoSkip, totNotBuilt, true)]
  end

  defp make_one_ix_entry_temp(testName, {logDir, summary, uRIs}, label, all, missing) do
    case summary do
      {succ, fail, userSkip, autoSkip} ->
        notBuilt = not_built(testName, logDir, all, missing)

        {newResult, uRIs1} =
          make_one_index_entry1(
            testName,
            logDir,
            label,
            succ,
            fail,
            userSkip,
            autoSkip,
            notBuilt,
            all,
            :temp,
            uRIs
          )

        {newResult, succ, fail, userSkip, autoSkip, notBuilt, uRIs1}

      :error ->
        :error
    end
  end

  defp get_cache_data({:ok, cacheBin}) do
    case :erlang.binary_to_term(cacheBin) do
      cacheRec when elem(cacheRec, 0) === :log_cache ->
        case is_correct_cache_vsn(cacheRec) do
          true ->
            {:ok, cacheRec}

          false ->
            _ = :file.delete(~c"ct_log_cache")
            {:error, :old_cache_file}
        end

      _ ->
        _ = :file.delete(~c"ct_log_cache")
        {:error, :invalid_cache_file}
    end
  end

  defp get_cache_data(noCache) do
    noCache
  end

  defp cache_vsn() do
    _ = :application.load(:common_test)

    case :application.get_key(:common_test, :vsn) do
      {:ok, vSN} ->
        vSN

      _ ->
        ebinDir = :filename.dirname(:code.which(:ct))
        vSNfile = :filename.join([ebinDir, ~c"..", ~c"vsn.mk"])

        case :file.read_file(vSNfile) do
          {:ok, bin} ->
            [_, vSN] =
              :string.lexemes(
                :erlang.binary_to_list(bin),
                [?=, ?\n, ?\s]
              )

            vSN

          _ ->
            :undefined
        end
    end
  end

  defp is_correct_cache_vsn(r_log_cache(version: cVSN)) do
    case cache_vsn() do
      ^cVSN ->
        true

      _ ->
        false
    end
  end

  defp cleanup() do
    {:ok, cwd} = :file.get_cwd()
    :ok = :file.set_cwd(~c"../")
    {:ok, top} = :file.get_cwd()

    result =
      case (try do
              try_cleanup(cwd)
            catch
              :error, e -> {:EXIT, {e, __STACKTRACE__}}
              :exit, e -> {:EXIT, e}
              e -> e
            end) do
        :ok ->
          :ok

        {:EXIT, reason} ->
          {:error, reason}

        error ->
          {:error, error}
      end

    :ok = :file.set_cwd(top)
    result
  end

  defp try_cleanup(cTRunDir) do
    case :lists.reverse(:filename.split(cTRunDir)) do
      [[?c, ?t, ?_, ?r, ?u, ?n, ?. | _] | _] ->
        case :filelib.wildcard(:filename.join(cTRunDir, ~c"ct_run.*")) do
          [] ->
            rm_dir(cTRunDir)

          _ ->
            :unknown_logdir
        end

      _ ->
        :unknown_logdir
    end
  end

  defp rm_dir(dir) do
    case :file.list_dir(dir) do
      {:error, errno} ->
        exit({:ls_failed, dir, errno})

      {:ok, files} ->
        rm_files(
          for f <- files do
            :filename.join(dir, f)
          end
        )

        case :file.del_dir(dir) do
          {:error, errno} ->
            exit({:rmdir_failed, errno})

          :ok ->
            :ok
        end
    end
  end

  defp rm_files([f | fs]) do
    base = :filename.basename(f)

    cond do
      base == ~c"." or base == ~c".." ->
        rm_files(fs)

      true ->
        case :file.read_file_info(f) do
          {:ok, r_file_info(type: :directory)} ->
            rm_dir(f)
            rm_files(fs)

          {:ok, _Regular} ->
            case :file.delete(f) do
              :ok ->
                rm_files(fs)

              {:error, errno} ->
                exit({:del_failed, f, errno})
            end
        end
    end
  end

  defp rm_files([]) do
    :ok
  end

  def simulate() do
    cast(:stop)
    s = self()

    pid =
      spawn(fn ->
        :erlang.register(:ct_logs, self())
        :ct_util.mark_process()
        send(s, {self(), :started})
        simulate_logger_loop()
      end)

    receive do
      {^pid, :started} ->
        pid
    end
  end

  defp simulate_logger_loop() do
    receive do
      {:log, _, _, _, _, _, content, _} ->
        s =
          :lists.map(
            fn
              {_, str, args} ->
                [:io_lib.format(str, args), :io_lib.nl()]

              {str, args} ->
                [:io_lib.format(str, args), :io_lib.nl()]
            end,
            content
          )

        :io.format(~c"~ts", [s])
        simulate_logger_loop()

      :stop ->
        :ok
    end
  end

  defp notify_and_lock_file(file) do
    case :ct_event.is_alive() do
      true ->
        :ct_event.sync_notify(r_event(name: :start_write_file, node: node(), data: file))

      false ->
        :ok
    end
  end

  defp notify_and_unlock_file(file) do
    case :ct_event.is_alive() do
      true ->
        :ct_event.sync_notify(r_event(name: :finished_write_file, node: node(), data: file))

      false ->
        :ok
    end
  end

  defp get_run_dirs(dir) do
    case :filelib.wildcard(:filename.join(dir, ~c"run.[1-2]*")) do
      [] ->
        false

      runDirs ->
        :lists.sort(runDirs)
    end
  end

  def xhtml(hTML, xHTML)
      when is_function(hTML) and
             is_function(xHTML) do
    case :erlang.get(:basic_html) do
      true ->
        hTML.()

      _ ->
        xHTML.()
    end
  end

  def xhtml(hTML, xHTML) do
    case :erlang.get(:basic_html) do
      true ->
        hTML

      _ ->
        xHTML
    end
  end

  defp odd_or_even() do
    case :erlang.get(:odd_or_even) do
      :even ->
        :erlang.put(:odd_or_even, :odd)
        ~c"even"

      _ ->
        :erlang.put(:odd_or_even, :even)
        ~c"odd"
    end
  end

  def basic_html() do
    case :application.get_env(
           :common_test,
           :basic_html
         ) do
      {:ok, true} ->
        true

      _ ->
        false
    end
  end

  def locate_priv_file(fileName) do
    {:ok, cWD} = :file.get_cwd()
    privFileInCwd = :filename.join(cWD, fileName)

    case :filelib.is_file(privFileInCwd) do
      true ->
        privFileInCwd

      false ->
        privResultFile =
          case {:erlang.whereis(:ct_logs), self()} do
            {self, self} ->
              :filename.join(:erlang.get(:ct_run_dir), fileName)

            _ ->
              {:ok, logDir} = get_log_dir(true)
              :filename.join(logDir, fileName)
          end

        case :filelib.is_file(privResultFile) do
          true ->
            privResultFile

          false ->
            cTPath = :code.lib_dir(:common_test)
            :filename.join(:filename.join(cTPath, ~c"priv"), fileName)
        end
    end
  end

  def make_relative(absDir) do
    {:ok, cwd} = :file.get_cwd()
    make_relative(absDir, cwd)
  end

  defp make_relative(absDir, cwd) do
    dirTokens = :filename.split(absDir)
    cwdTokens = :filename.split(cwd)
    :filename.join(make_relative1(dirTokens, cwdTokens))
  end

  defp make_relative1([t | dirTs], [t | cwdTs]) do
    make_relative1(dirTs, cwdTs)
  end

  defp make_relative1(last = [_File], []) do
    last
  end

  defp make_relative1(last = [_File], cwdTs) do
    ups =
      for _ <- cwdTs do
        ~c"../"
      end

    ups ++ last
  end

  defp make_relative1(dirTs, []) do
    dirTs
  end

  defp make_relative1(dirTs, cwdTs) do
    ups =
      for _ <- cwdTs do
        ~c"../"
      end

    ups ++ dirTs
  end

  def get_ts_html_wrapper(testName, printLabel, cwd, tableCols, encoding) do
    get_ts_html_wrapper(testName, :undefined, printLabel, cwd, tableCols, encoding, :unknown)
  end

  defp get_ts_html_wrapper(
         testName,
         logdir,
         printLabel,
         cwd,
         tableCols,
         encoding,
         customStylesheet
       ) do
    testName1 =
      cond do
        is_list(testName) ->
          :lists.flatten(testName)

        true ->
          :lists.flatten(:io_lib.format(~c"~tp", [testName]))
      end

    basic = basic_html()

    labelStr =
      cond do
        not printLabel ->
          ~c""

        true ->
          case {basic,
                :application.get_env(
                  :common_test,
                  :test_label
                )} do
            {true, {:ok, lbl}} when lbl !== :undefined ->
              ~c"<h1><font color=\"green\">" ++ lbl ++ ~c"</font></h1>\n"

            {_, {:ok, lbl}} when lbl !== :undefined ->
              ~c"<div class=\"label\">'" ++ lbl ++ ~c"'</div>\n"

            _ ->
              ~c""
          end
      end

    cTPath = :code.lib_dir(:common_test)

    {:ok, ctLogdir} =
      cond do
        logdir == :undefined ->
          get_log_dir(true)

        true ->
          {:ok, logdir}
      end

    allRuns =
      make_relative(
        :filename.join(
          :filename.dirname(ctLogdir),
          ~c"all_runs.html"
        ),
        cwd
      )

    testIndex =
      make_relative(
        :filename.join(
          :filename.dirname(ctLogdir),
          ~c"index.html"
        ),
        cwd
      )

    latestTest =
      make_relative(
        :filename.join(
          :filename.dirname(ctLogdir),
          ~c"suite.log" ++ ~c".latest.html"
        ),
        cwd
      )

    case basic do
      true ->
        tileFile = :filename.join(:filename.join(cTPath, ~c"priv"), ~c"tile1.jpg")
        bgr = ~c" background=\"" ++ tileFile ++ ~c"\""

        copyright = [
          ~c"<p><font size=\"-1\">\n",
          ~c"Copyright &copy; ",
          year(),
          ~c" <a href=\"http://www.erlang.org\">",
          ~c"Open Telecom Platform</a><br>\n",
          ~c"Updated: <!--date-->",
          current_time(),
          ~c"<!--/date-->",
          ~c"<br>\n</font></p>\n"
        ]

        {:basic_html,
         [
           ~c"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n",
           ~c"<html>\n",
           ~c"<head><title>",
           testName1,
           ~c"</title>\n",
           ~c"<meta http-equiv=\"cache-control\" content=\"no-cache\"></meta>\n",
           ~c"<meta http-equiv=\"content-type\" content=\"text/html; charset=",
           html_encoding(encoding),
           ~c"\"></meta>\n",
           ~c"</head>\n",
           ~c"<body",
           bgr,
           ~c" bgcolor=\"white\" text=\"black\" ",
           ~c"link=\"blue\" vlink=\"purple\" alink=\"red\">\n",
           labelStr,
           ~c"\n"
         ],
         [
           ~c"<center>\n<br><hr><p>\n",
           ~c"<a href=\"",
           uri(allRuns),
           ~c"\">Test run history\n</a>  |  ",
           ~c"<a href=\"",
           uri(testIndex),
           ~c"\">Top level test index\n</a>  |  ",
           ~c"<a href=\"",
           uri(latestTest),
           ~c"\">Latest test result</a>\n</p>\n",
           copyright,
           ~c"</center>\n</body>\n</html>\n"
         ]}

      _ ->
        copyright = [
          ~c"<div class=\"copyright\">",
          ~c"Copyright &copy; ",
          year(),
          ~c" <a href=\"http://www.erlang.org\">",
          ~c"Open Telecom Platform</a><br />\n",
          ~c"Updated: <!--date-->",
          current_time(),
          ~c"<!--/date-->",
          ~c"<br />\n</div>\n"
        ]

        cSSFile =
          xhtml(
            fn ->
              ~c""
            end,
            fn ->
              make_relative(locate_priv_file(~c"ct_default.css"), cwd)
            end
          )

        customCSSFileHtml = custom_stylesheet_header(customStylesheet)

        jQueryFile =
          xhtml(
            fn ->
              ~c""
            end,
            fn ->
              make_relative(locate_priv_file(~c"jquery-latest.js"), cwd)
            end
          )

        tableSorterFile =
          xhtml(
            fn ->
              ~c""
            end,
            fn ->
              make_relative(locate_priv_file(~c"jquery.tablesorter.min.js"), cwd)
            end
          )

        tableSorterScript =
          xhtml(
            fn ->
              ~c""
            end,
            fn ->
              insert_javascript({:tablesorter, ~c"SortableTable", tableCols})
            end
          )

        {:xhtml,
         [
           ~c"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n",
           ~c"\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n",
           ~c"<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n",
           ~c"<head>\n<title>",
           testName1,
           ~c"</title>\n",
           ~c"<meta http-equiv=\"cache-control\" content=\"no-cache\"></meta>\n",
           ~c"<meta http-equiv=\"content-type\" content=\"text/html; ",
           ~c"charset=utf-8\"></meta>\n",
           ~c"<link rel=\"stylesheet\" href=\"",
           uri(cSSFile),
           ~c"\" type=\"text/css\"></link>\n",
           customCSSFileHtml,
           ~c"<script type=\"text/javascript\" src=\"",
           jQueryFile,
           ~c"\"></script>\n",
           ~c"<script type=\"text/javascript\" src=\"",
           tableSorterFile,
           ~c"\"></script>\n"
         ] ++ tableSorterScript ++ [~c"</head>\n", ~c"<body>\n", labelStr, ~c"\n"],
         [
           ~c"<center>\n<br /><hr /><p>\n",
           ~c"<a href=\"",
           uri(allRuns),
           ~c"\">Test run history\n</a>  |  ",
           ~c"<a href=\"",
           uri(testIndex),
           ~c"\">Top level test index\n</a>  |  ",
           ~c"<a href=\"",
           uri(latestTest),
           ~c"\">Latest test result</a>\n</p>\n",
           copyright,
           ~c"</center>\n</body>\n</html>\n"
         ]}
    end
  end

  def insert_javascript({:tablesorter, _TableName, :undefined}) do
    []
  end

  def insert_javascript({:tablesorter, tableName, {dateCols, textCols, valCols}}) do
    headers =
      :lists.flatten(
        :lists.sort(
          :lists.flatmap(
            fn {sorter, cols} ->
              for col <- cols do
                :lists.flatten(
                  :io_lib.format(
                    ~c"      ~w: { sorter: '~s' },\n",
                    [col - 1, sorter]
                  )
                )
              end
            end,
            [
              {~c"CTDateSorter", dateCols},
              {~c"CTTextSorter", textCols},
              {~c"CTValSorter", valCols}
            ]
          )
        )
      )

    headers1 = :string.trim(headers, :trailing, ~c",\n")

    [
      ~c"<script type=\"text/javascript\">\n",
      ~c"// Parser for date format, e.g: Wed Jul 4 2012 11:24:15\n",
      ~c"var monthNames = {};\n",
      ~c"monthNames[\"Jan\"] = \"01\"; monthNames[\"Feb\"] = \"02\";\n",
      ~c"monthNames[\"Mar\"] = \"03\"; monthNames[\"Apr\"] = \"04\";\n",
      ~c"monthNames[\"May\"] = \"05\"; monthNames[\"Jun\"] = \"06\";\n",
      ~c"monthNames[\"Jul\"] = \"07\"; monthNames[\"Aug\"] = \"08\";\n",
      ~c"monthNames[\"Sep\"] = \"09\"; monthNames[\"Oct\"] = \"10\";\n",
      ~c"monthNames[\"Nov\"] = \"11\"; monthNames[\"Dec\"] = \"12\";\n",
      ~c"$.tablesorter.addParser({\n",
      ~c"  id: 'CTDateSorter',\n",
      ~c"  is: function(s) {\n",
      ~c"      return false; },\n",
      ~c"  format: function(s) {\n",
      ~c"      if (s.length < 2) return 999999999;\n",
      ~c"      else {\n",
      ~c"          var date = s.match(/(\\w{3})\\s(\\w{3})\\s(\\d{2})\\s(\\d{4})\\s(\\d{2}):(\\d{2}):(\\d{2})/);\n",
      ~c"          var y = date[4]; var mo = monthNames[date[2]]; var d = String(date[3]);\n",
      ~c"          var h = String(date[5]); var mi = String(date[6]); var sec = String(date[7]);\n",
      ~c"          return (parseInt('' + y + mo + d + h + mi + sec)); }},\n",
      ~c"  type: 'numeric' });\n",
      ~c"// Parser for general text format\n",
      ~c"$.tablesorter.addParser({\n",
      ~c"  id: 'CTTextSorter',\n",
      ~c"  is: function(s) {\n",
      ~c"    return false; },\n",
      ~c"  format: function(s) {\n",
      ~c"    if (s.length < 1) return 'zzzzzzzz';\n",
      ~c"    else if (s == \"?\") return 'zzzzzzz';\n",
      ~c"    else if (s == \"-\") return 'zzzzzz';\n",
      ~c"    else if (s == \"FAILED\") return 'A';\n",
      ~c"    else if (s == \"SKIPPED\") return 'B';\n",
      ~c"    else if (s == \"OK\") return 'C';\n",
      ~c"    else return '' + s; },\n",
      ~c"  type: 'text' });\n",
      ~c"// Parser for numerical values\n",
      ~c"$.tablesorter.addParser({\n",
      ~c"  id: 'CTValSorter',\n",
      ~c"  is: function(s) {\n",
      ~c"    return false; },\n",
      ~c"  format: function(s) {\n    if (s.length < 1) return '-2';\n",
      ~c"    else if (s == \"?\") return '-1';\n",
      ~c"    else if ((s.search(/(\\d{1,})\\s/)) >= 0) {\n",
      ~c"      var num = s.match(/(\\d{1,})\\s/);\n",
      ~c"      return (parseInt('' + num[1])); }\n",
      ~c"    else if ((s.search(/(\\d{1,})\\.(\\d{3})s/)) >= 0) {\n",
      ~c"      var num = s.match(/(\\d{1,})\\.(\\d{3})/);\n",
      ~c"      if (num[1] == \"0\") return (parseInt('' + num[2]));\n",
      ~c"      else return (parseInt('' + num[1] + num[2])); }\n",
      ~c"    else return '' + s; },\n",
      ~c"  type: 'numeric' });\n",
      ~c"$(document).ready(function() {\n",
      ~c"  $(\"#",
      tableName,
      ~c"\").tablesorter({\n",
      ~c"    headers: { \n",
      headers1,
      ~c"\n    }\n  });\n",
      ~c"  $(\"#",
      tableName,
      ~c"\").trigger(\"update\");\n",
      ~c"  $(\"#",
      tableName,
      ~c"\").trigger(\"appendCache\");\n",
      ~c"});\n</script>\n"
    ]
  end

  def uri(~c"") do
    ~c""
  end

  def uri(href) do
    :test_server_ctrl.uri_encode(href)
  end

  defp encoding(file) do
    case :epp.read_encoding(file) do
      :none ->
        :epp.default_encoding()

      e ->
        e
    end
  end

  defp b2s(bin) do
    b2s(bin, :epp.default_encoding())
  end

  defp b2s(bin, encoding) do
    :unicode.characters_to_list(bin, encoding)
  end

  defp html_encoding(:latin1) do
    ~c"iso-8859-1"
  end

  defp html_encoding(:utf8) do
    ~c"utf-8"
  end

  defp unexpected_io(pid, :ct_internal, _Importance, content, ctLogFd, escChars) do
    ioFun = create_io_fun(pid, ctLogFd, escChars)
    :io.format(ctLogFd, ~c"~ts", [:lists.foldl(ioFun, [], content)])
  end

  defp unexpected_io(pid, _Category, _Importance, content, ctLogFd, escChars) do
    ioFun = create_io_fun(pid, ctLogFd, escChars)

    data =
      :io_lib.format(
        ~c"~ts",
        [:lists.foldl(ioFun, [], content)]
      )

    :test_server_io.print_unexpected(data)
    :ok
  end

  defp write_log_cache(logCacheBin) when is_binary(logCacheBin) do
    tmpFile = ~c"ct_log_cache" ++ ~c".tmp"
    _ = :file.write_file(tmpFile, logCacheBin)
    _ = :file.rename(tmpFile, ~c"ct_log_cache")
    :ok
  end
end
