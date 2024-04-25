defmodule :m_disksup do
  use Bitwise
  @behaviour :gen_server
  require Record

  Record.defrecord(:r_state, :state,
    threshold: :undefined,
    timeout: :undefined,
    os: :undefined,
    diskdata: [],
    port: :undefined
  )

  def start_link() do
    :gen_server.start_link({:local, :disksup}, :disksup, [], [])
  end

  def get_disk_data() do
    :os_mon.call(:disksup, :get_disk_data, :infinity)
  end

  def get_disk_info() do
    :os_mon.call(:disksup, :get_disk_info, :infinity)
  end

  def get_disk_info(path) do
    :os_mon.call(:disksup, {:get_disk_info, path}, :infinity)
  end

  def get_check_interval() do
    :os_mon.call(:disksup, :get_check_interval, :infinity)
  end

  def set_check_interval(value) do
    case param_type(:disk_space_check_interval, value) do
      true ->
        :os_mon.call(:disksup, {:set_check_interval, value}, :infinity)

      false ->
        :erlang.error(:badarg)
    end
  end

  def get_almost_full_threshold() do
    :os_mon.call(:disksup, :get_almost_full_threshold, :infinity)
  end

  def set_almost_full_threshold(float) do
    case param_type(:disk_almost_full_threshold, float) do
      true ->
        :os_mon.call(:disksup, {:set_almost_full_threshold, float}, :infinity)

      false ->
        :erlang.error(:badarg)
    end
  end

  def dummy_reply(:get_disk_data) do
    [{~c"none", 0, 0}]
  end

  def dummy_reply(:get_disk_info) do
    [{~c"none", 0, 0, 0}]
  end

  def dummy_reply({:get_disk_info, path}) do
    [{path, 0, 0, 0}]
  end

  def dummy_reply(:get_check_interval) do
    case :os_mon.get_env(
           :disksup,
           :disk_space_check_interval
         ) do
      {timeUnit, time} ->
        :erlang.convert_time_unit(time, timeUnit, :millisecond)

      minute ->
        minutes_to_ms(minute)
    end
  end

  def dummy_reply({:set_check_interval, _}) do
    :ok
  end

  def dummy_reply(:get_almost_full_threshold) do
    round(
      :os_mon.get_env(
        :disksup,
        :disk_almost_full_threshold
      ) * 100
    )
  end

  def dummy_reply({:set_almost_full_threshold, _}) do
    :ok
  end

  def param_type(:disk_space_check_interval, {timeUnit, time}) do
    try do
      :erlang.convert_time_unit(time, timeUnit, :millisecond)
    catch
      _, _ ->
        false
    else
      msTime when msTime > 0 ->
        true

      _ ->
        false
    end
  end

  def param_type(:disk_space_check_interval, val)
      when is_integer(val) and val >= 1 do
    true
  end

  def param_type(:disk_almost_full_threshold, val)
      when is_number(val) and 0 <= val and val <= 1 do
    true
  end

  def param_type(:disksup_posix_only, val)
      when val == true or
             val == false do
    true
  end

  def param_type(_Param, _Val) do
    false
  end

  def param_default(:disk_space_check_interval) do
    30
  end

  def param_default(:disk_almost_full_threshold) do
    0.8
  end

  def param_default(:disksup_posix_only) do
    false
  end

  def init([]) do
    :erlang.process_flag(:trap_exit, true)
    :erlang.process_flag(:priority, :low)

    posixOnly =
      :os_mon.get_env(
        :disksup,
        :disksup_posix_only
      )

    oS = get_os(posixOnly)

    port =
      case oS do
        {:unix, flavor}
        when flavor == :sunos4 or
               flavor == :solaris or flavor == :freebsd or
               flavor == :dragonfly or
               flavor == :darwin or flavor == :linux or
               flavor == :posix or flavor == :openbsd or
               flavor == :netbsd or flavor == :irix64 or
               flavor == :irix ->
          start_portprogram()

        {:win32, _OSname} ->
          :not_used

        _ ->
          exit({:unsupported_os, oS})
      end

    threshold =
      :os_mon.get_env(
        :disksup,
        :disk_almost_full_threshold
      )

    timeout =
      case :os_mon.get_env(
             :disksup,
             :disk_space_check_interval
           ) do
        {timeUnit, time} ->
          :erlang.convert_time_unit(time, timeUnit, :millisecond)

        minutes ->
          minutes_to_ms(minutes)
      end

    send(self(), :timeout)
    {:ok, r_state(port: port, os: oS, threshold: round(threshold * 100), timeout: timeout)}
  end

  def handle_call(:get_disk_data, _From, state) do
    {:reply, r_state(state, :diskdata), state}
  end

  def handle_call(:get_disk_info, _From, r_state(os: oS, port: port) = state) do
    {:reply, get_disk_info(oS, port), state}
  end

  def handle_call({:get_disk_info, path}, _From, r_state(os: oS, port: port) = state) do
    {:reply, get_disk_info(path, oS, port), state}
  end

  def handle_call(:get_check_interval, _From, state) do
    {:reply, r_state(state, :timeout), state}
  end

  def handle_call({:set_check_interval, {timeUnit, time}}, _From, state) do
    timeout = :erlang.convert_time_unit(time, timeUnit, :millisecond)
    {:reply, :ok, r_state(state, timeout: timeout)}
  end

  def handle_call({:set_check_interval, minutes}, _From, state) do
    timeout = minutes_to_ms(minutes)
    {:reply, :ok, r_state(state, timeout: timeout)}
  end

  def handle_call(:get_almost_full_threshold, _From, state) do
    {:reply, r_state(state, :threshold), state}
  end

  def handle_call({:set_almost_full_threshold, float}, _From, state) do
    threshold = round(float * 100)
    {:reply, :ok, r_state(state, threshold: threshold)}
  end

  def handle_call({:set_threshold, threshold}, _From, state) do
    {:reply, :ok, r_state(state, threshold: threshold)}
  end

  def handle_cast(_Msg, state) do
    {:noreply, state}
  end

  def handle_info(:timeout, state) do
    newDiskData =
      check_disk_space(r_state(state, :os), r_state(state, :port), r_state(state, :threshold))

    {:ok, _Tref} =
      :timer.send_after(
        r_state(state, :timeout),
        :timeout
      )

    {:noreply, r_state(state, diskdata: newDiskData)}
  end

  def handle_info({:EXIT, _Port, reason}, state) do
    {:stop, {:port_died, reason}, r_state(state, port: :not_used)}
  end

  def handle_info(_Info, state) do
    {:noreply, state}
  end

  def terminate(_Reason, state) do
    clear_alarms()

    case r_state(state, :port) do
      :not_used ->
        :ok

      port ->
        :erlang.port_close(port)
    end

    :ok
  end

  def format_status(
        _Opt,
        [_PDict, r_state(os: oS, threshold: threshold, timeout: timeout, diskdata: diskData)]
      ) do
    [
      {:data,
       [
         {~c"OS", oS},
         {~c"Timeout", timeout},
         {~c"Threshold", threshold},
         {~c"DiskData", diskData}
       ]}
    ]
  end

  defp get_os(posixOnly) do
    case :os.type() do
      {:unix, :sunos} ->
        case :os.version() do
          {5, _, _} ->
            {:unix, :solaris}

          {4, _, _} ->
            {:unix, :sunos4}

          v ->
            exit({:unknown_os_version, v})
        end

      {:unix, _} when posixOnly ->
        {:unix, :posix}

      {:unix, :irix64} ->
        {:unix, :irix}

      oS ->
        oS
    end
  end

  defp start_portprogram() do
    :erlang.open_port({:spawn, ~c"sh -s disksup 2>&1"}, [:stream])
  end

  defp my_cmd(cmd0, port) do
    cmd = :io_lib.format(~c"(~s\n) </dev/null; echo  \"\r\"\n", [cmd0])
    send(port, {self(), {:command, [cmd, 10]}})
    get_reply(port, [])
  end

  defp get_reply(port, o) do
    receive do
      {^port, {:data, n}} ->
        case newline(n, o) do
          {:ok, str} ->
            str

          {:more, acc} ->
            get_reply(port, acc)
        end

      {:EXIT, ^port, reason} ->
        exit({:port_died, reason})
    end
  end

  defp newline([13 | _], b) do
    {:ok, :lists.reverse(b)}
  end

  defp newline([h | t], b) do
    newline(t, [h | b])
  end

  defp newline([], b) do
    {:more, b}
  end

  defp find_cmd(cmd) do
    :os.find_executable(cmd)
  end

  defp find_cmd(cmd, path) do
    case :os.find_executable(cmd, path) do
      false ->
        find_cmd(cmd)

      found ->
        found
    end
  end

  defp run_df(oS, port) do
    run_df(~c"", oS, port)
  end

  defp run_df(path, {:unix, :solaris}, port) do
    my_cmd(~c"/usr/bin/df -lk " ++ path, port)
  end

  defp run_df(path, {:unix, :irix}, port) do
    my_cmd(~c"/usr/sbin/df -lk " ++ path, port)
  end

  defp run_df(path, {:unix, :linux}, port) do
    df = find_cmd(~c"df", ~c"/bin")
    my_cmd(df ++ ~c" -lk -x squashfs " ++ path, port)
  end

  defp run_df(path, {:unix, :posix}, port) do
    my_cmd(~c"df -k -P " ++ path, port)
  end

  defp run_df(path, {:unix, :dragonfly}, port) do
    my_cmd(~c"/bin/df -k -t ufs,hammer " ++ path, port)
  end

  defp run_df(path, {:unix, :freebsd}, port) do
    my_cmd(~c"/bin/df -k -l " ++ path, port)
  end

  defp run_df(path, {:unix, :openbsd}, port) do
    my_cmd(~c"/bin/df -k -l " ++ path, port)
  end

  defp run_df(path, {:unix, :netbsd}, port) do
    my_cmd(~c"/bin/df -k -t ffs " ++ path, port)
  end

  defp run_df(path, {:unix, :sunos4}, port) do
    my_cmd(~c"df " ++ path, port)
  end

  defp run_df(path, {:unix, :darwin}, port) do
    my_cmd(~c"/bin/df -i -k -t ufs,hfs,apfs " ++ path, port)
  end

  defp get_disk_info(oS, port) do
    get_disk_info(~c"", oS, port)
  end

  defp get_disk_info(path, oS, port) do
    case do_get_disk_info(path, oS, port) do
      [] ->
        dummy_reply({:get_disk_info, path})

      diskInfo ->
        diskInfo
    end
  end

  defp do_get_disk_info(~c"", {:win32, _}, :not_used) do
    result = :os_mon_sysinfo.get_disk_info()
    disk_info_win32(result)
  end

  defp do_get_disk_info(driveRoot, {:win32, _}, :not_used) do
    result = :os_mon_sysinfo.get_disk_info(driveRoot)
    disk_info_win32(result)
  end

  defp do_get_disk_info(path, {:unix, :solaris} = oS, port) do
    result = run_df(path, oS, port)
    disk_info_solaris(skip_to_eol(result))
  end

  defp do_get_disk_info(path, {:unix, :irix} = oS, port) do
    result = run_df(path, oS, port)
    disk_info_irix(skip_to_eol(result))
  end

  defp do_get_disk_info(path, {:unix, :linux} = oS, port) do
    result = run_df(path, oS, port)
    disk_info_solaris(skip_to_eol(result))
  end

  defp do_get_disk_info(path, {:unix, :posix} = oS, port) do
    result = run_df(path, oS, port)
    disk_info_solaris(skip_to_eol(result))
  end

  defp do_get_disk_info(path, {:unix, :dragonfly} = oS, port) do
    result = run_df(path, oS, port)
    disk_info_solaris(skip_to_eol(result))
  end

  defp do_get_disk_info(path, {:unix, :freebsd} = oS, port) do
    result = run_df(path, oS, port)
    disk_info_solaris(skip_to_eol(result))
  end

  defp do_get_disk_info(path, {:unix, :openbsd} = oS, port) do
    result = run_df(path, oS, port)
    disk_info_solaris(skip_to_eol(result))
  end

  defp do_get_disk_info(path, {:unix, :netbsd} = oS, port) do
    result = run_df(path, oS, port)
    disk_info_solaris(skip_to_eol(result))
  end

  defp do_get_disk_info(path, {:unix, :sunos4} = oS, port) do
    result = run_df(path, oS, port)
    disk_info_solaris(skip_to_eol(result))
  end

  defp do_get_disk_info(path, {:unix, :darwin} = oS, port) do
    result = run_df(path, oS, port)
    disk_info_susv3(skip_to_eol(result))
  end

  defp disk_info_win32([]) do
    []
  end

  defp disk_info_win32([h | t]) do
    case :io_lib.fread(~c"~s~s~d~d~d", h) do
      {:ok, [drive, ~c"DRIVE_FIXED", bAvail, bTot, _TotFree], _RestStr} ->
        kiBTotal = div(bTot, 1024)
        kiBAvailable = div(bAvail, 1024)
        bUsed = bTot - bAvail
        capacity = trunc(:math.ceil(100 * (bUsed / bTot)))

        [
          {drive, kiBTotal, kiBAvailable, capacity}
          | disk_info_win32(t)
        ]

      {:ok, _, _RestStr} ->
        disk_info_win32(t)

      _Other ->
        []
    end
  end

  defp disk_info_solaris(~c"") do
    []
  end

  defp disk_info_solaris(~c"\n") do
    []
  end

  defp disk_info_solaris(str) do
    case parse_df(str, :posix) do
      {:ok, {kiBTotal, kiBAvailable, capacity, mntOn}, restStr} ->
        [
          {mntOn, kiBTotal, kiBAvailable, capacity}
          | disk_info_solaris(restStr)
        ]

      _Other ->
        disk_info_solaris(skip_to_eol(str))
    end
  end

  defp disk_info_irix(~c"") do
    []
  end

  defp disk_info_irix(~c"\n") do
    []
  end

  defp disk_info_irix(str) do
    case :io_lib.fread(~c"~s~s~d~d~d~d~s", str) do
      {:ok, [_FS, _FSType, kiBAvailable, capacity, _Avail, kiBTotal, mntOn], restStr} ->
        [
          {mntOn, kiBTotal, kiBAvailable, capacity}
          | disk_info_irix(restStr)
        ]

      _Other ->
        disk_info_irix(skip_to_eol(str))
    end
  end

  defp disk_info_susv3(~c"") do
    []
  end

  defp disk_info_susv3(~c"\n") do
    []
  end

  defp disk_info_susv3(str) do
    case parse_df(str, :susv3) do
      {:ok, {kiBTotal, kiBAvailable, capacity, mntOn}, restStr} ->
        [
          {mntOn, kiBTotal, kiBAvailable, capacity}
          | disk_info_susv3(restStr)
        ]

      _Other ->
        disk_info_susv3(skip_to_eol(str))
    end
  end

  defp check_disk_space({:win32, _}, :not_used, threshold) do
    result = :os_mon_sysinfo.get_disk_info()
    check_disks_win32(result, threshold)
  end

  defp check_disk_space({:unix, :solaris} = oS, port, threshold) do
    result = run_df(oS, port)
    check_disks_solaris(skip_to_eol(result), threshold)
  end

  defp check_disk_space({:unix, :irix} = oS, port, threshold) do
    result = run_df(oS, port)
    check_disks_irix(skip_to_eol(result), threshold)
  end

  defp check_disk_space({:unix, :linux} = oS, port, threshold) do
    result = run_df(oS, port)
    check_disks_solaris(skip_to_eol(result), threshold)
  end

  defp check_disk_space({:unix, :posix} = oS, port, threshold) do
    result = run_df(oS, port)
    check_disks_solaris(skip_to_eol(result), threshold)
  end

  defp check_disk_space({:unix, :dragonfly} = oS, port, threshold) do
    result = run_df(oS, port)
    check_disks_solaris(skip_to_eol(result), threshold)
  end

  defp check_disk_space({:unix, :freebsd} = oS, port, threshold) do
    result = run_df(oS, port)
    check_disks_solaris(skip_to_eol(result), threshold)
  end

  defp check_disk_space({:unix, :openbsd} = oS, port, threshold) do
    result = run_df(oS, port)
    check_disks_solaris(skip_to_eol(result), threshold)
  end

  defp check_disk_space({:unix, :netbsd} = oS, port, threshold) do
    result = run_df(oS, port)
    check_disks_solaris(skip_to_eol(result), threshold)
  end

  defp check_disk_space({:unix, :sunos4} = oS, port, threshold) do
    result = run_df(oS, port)
    check_disks_solaris(skip_to_eol(result), threshold)
  end

  defp check_disk_space({:unix, :darwin} = oS, port, threshold) do
    result = run_df(oS, port)
    check_disks_susv3(skip_to_eol(result), threshold)
  end

  defp check_disks_solaris(~c"", _Threshold) do
    []
  end

  defp check_disks_solaris(~c"\n", _Threshold) do
    []
  end

  defp check_disks_solaris(str, threshold) do
    case parse_df(str, :posix) do
      {:ok, {kiBTotal, _KiBAvailable, capacity, mntOn}, restStr} ->
        cond do
          capacity >= threshold ->
            set_alarm({:disk_almost_full, mntOn}, [])

          true ->
            clear_alarm({:disk_almost_full, mntOn})
        end

        [
          {mntOn, kiBTotal, capacity}
          | check_disks_solaris(restStr, threshold)
        ]

      _Other ->
        check_disks_solaris(skip_to_eol(str), threshold)
    end
  end

  defp parse_df_is_not_space(?\s) do
    false
  end

  defp parse_df_is_not_space(?%) do
    false
  end

  defp parse_df_is_not_space(_) do
    true
  end

  defp parse_df_is_space(?\s) do
    true
  end

  defp parse_df_is_space(_) do
    false
  end

  defp parse_df_is_not_eol(?\r) do
    false
  end

  defp parse_df_is_not_eol(?\n) do
    false
  end

  defp parse_df_is_not_eol(_) do
    true
  end

  defp parse_df_skip_word(input) do
    remaining =
      :lists.dropwhile(
        &parse_df_is_not_space/1,
        input
      )

    :lists.dropwhile(&parse_df_is_space/1, remaining)
  end

  defp parse_df_take_word(input) do
    {word, remaining0} =
      :lists.splitwith(
        &parse_df_is_not_space/1,
        input
      )

    remaining1 =
      :lists.dropwhile(
        &parse_df_is_space/1,
        remaining0
      )

    {word, remaining1}
  end

  defp parse_df_take_word_percent(input) do
    {word, remaining0} =
      :lists.splitwith(
        &parse_df_is_not_space/1,
        input
      )

    remaining1 =
      case remaining0 do
        [?% | r1] ->
          r1

        _ ->
          remaining0
      end

    remaining2 =
      :lists.dropwhile(
        &parse_df_is_space/1,
        remaining1
      )

    {word, remaining2}
  end

  def parse_df(input0, flavor) do
    input1 = parse_df_skip_word(input0)
    {kiBTotalStr, input2} = parse_df_take_word(input1)
    input3 = parse_df_skip_word(input2)
    {kiBAvailableStr, input4} = parse_df_take_word(input3)
    {capacityStr, input5} = parse_df_take_word_percent(input4)

    input6 =
      case flavor do
        :posix ->
          input5

        :susv3 ->
          input5a = parse_df_skip_word(input5)
          input5b = parse_df_skip_word(input5a)
          {_, input5c} = parse_df_take_word_percent(input5b)
          input5c
      end

    {mountPath, input7} =
      :lists.splitwith(
        &parse_df_is_not_eol/1,
        input6
      )

    remaining =
      :lists.dropwhile(
        fn x ->
          not parse_df_is_not_eol(x)
        end,
        input7
      )

    try do
      kiBTotal = :erlang.list_to_integer(kiBTotalStr)
      kiBAvailable = :erlang.list_to_integer(kiBAvailableStr)
      capacity = :erlang.list_to_integer(capacityStr)
      {:ok, {kiBTotal, kiBAvailable, capacity, mountPath}, remaining}
    catch
      :error, :badarg ->
        {:error, :parse_df}
    end
  end

  defp check_disks_susv3(~c"", _Threshold) do
    []
  end

  defp check_disks_susv3(~c"\n", _Threshold) do
    []
  end

  defp check_disks_susv3(str, threshold) do
    case parse_df(str, :susv3) do
      {:ok, {kiBTotal, _KiBAvailable, capacity, mntOn}, restStr} ->
        cond do
          capacity >= threshold ->
            set_alarm({:disk_almost_full, mntOn}, [])

          true ->
            clear_alarm({:disk_almost_full, mntOn})
        end

        [
          {mntOn, kiBTotal, capacity}
          | check_disks_susv3(restStr, threshold)
        ]

      _Other ->
        check_disks_susv3(skip_to_eol(str), threshold)
    end
  end

  defp check_disks_irix(~c"", _Threshold) do
    []
  end

  defp check_disks_irix(~c"\n", _Threshold) do
    []
  end

  defp check_disks_irix(str, threshold) do
    case :io_lib.fread(~c"~s~s~d~d~d~d~s", str) do
      {:ok, [_FS, _FSType, kB, _Used, _Avail, cap, mntOn], restStr} ->
        cond do
          cap >= threshold ->
            set_alarm({:disk_almost_full, mntOn}, [])

          true ->
            clear_alarm({:disk_almost_full, mntOn})
        end

        [
          {mntOn, kB, cap}
          | check_disks_irix(
              restStr,
              threshold
            )
        ]

      _Other ->
        check_disks_irix(skip_to_eol(str), threshold)
    end
  end

  defp check_disks_win32([], _Threshold) do
    []
  end

  defp check_disks_win32([h | t], threshold) do
    case :io_lib.fread(~c"~s~s~d~d~d", h) do
      {:ok, [drive, ~c"DRIVE_FIXED", bAvail, bTot, _TotFree], _RestStr} ->
        cap = trunc((bTot - bAvail) / bTot * 100)

        cond do
          cap >= threshold ->
            set_alarm({:disk_almost_full, drive}, [])

          true ->
            clear_alarm({:disk_almost_full, drive})
        end

        [
          {drive, div(bTot, 1024), cap}
          | check_disks_win32(
              t,
              threshold
            )
        ]

      {:ok, _, _RestStr} ->
        check_disks_win32(t, threshold)

      _Other ->
        []
    end
  end

  defp set_alarm(alarmId, alarmDescr) do
    case :erlang.get(alarmId) do
      :set ->
        :ok

      :undefined ->
        :alarm_handler.set_alarm({alarmId, alarmDescr})
        :erlang.put(alarmId, :set)
    end
  end

  defp clear_alarm(alarmId) do
    case :erlang.get(alarmId) do
      :set ->
        :alarm_handler.clear_alarm(alarmId)
        :erlang.erase(alarmId)

      :undefined ->
        :ok
    end
  end

  defp clear_alarms() do
    :lists.foreach(
      fn
        {{:disk_almost_full, _MntOn} = alarmId, :set} ->
          :alarm_handler.clear_alarm(alarmId)

        _Other ->
          :ignore
      end,
      :erlang.get()
    )
  end

  defp minutes_to_ms(minutes) do
    trunc(60000 * minutes)
  end

  defp skip_to_eol([]) do
    []
  end

  defp skip_to_eol([?\n | t]) do
    t
  end

  defp skip_to_eol([_ | t]) do
    skip_to_eol(t)
  end
end
