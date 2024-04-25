defmodule :m_etop_txt do
  use Bitwise
  import :etop, only: [loadinfo: 2, meminfo: 2]
  @author :"siri@erix.ericsson.se"
  require Record
  Record.defrecord(:r_etop_info, :etop_info, now: {0, 0, 0},
                                     n_procs: 0, wall_clock: :undefined,
                                     runtime: :undefined, run_queue: 0,
                                     alloc_areas: [],
                                     memi: [{:total, 0}, {:processes, 0}, {:ets,
                                                                             0},
                                                                              {:atom,
                                                                                 0},
                                                                                  {:code,
                                                                                     0},
                                                                                      {:binary,
                                                                                         0}],
                                     procinfo: [])
  Record.defrecord(:r_etop_proc_info, :etop_proc_info, pid: :undefined,
                                          mem: 0, reds: 0, name: :undefined,
                                          runtime: 0, cf: :undefined, mq: 0)
  Record.defrecord(:r_opts, :opts, node: node(), port: 8415,
                                accum: false, intv: 5000, lines: 10, width: 700,
                                height: 340, sort: :runtime, tracing: :on,
                                out_mod: :etop_txt, out_proc: :undefined,
                                server: :undefined, host: :undefined,
                                tracer: :undefined, store: :undefined,
                                accum_tab: :undefined, remote: :undefined)
  Record.defrecord(:r_field_widths, :field_widths, cols: :undefined,
                                        used_cols: :undefined,
                                        init_func: :undefined, reds: :undefined,
                                        mem: :undefined, msgq: :undefined,
                                        curr_func: :undefined)
  def stop(pid) do
    send(pid, :stop)
  end

  def init(config) do
    loop(r_etop_info(), config)
  end

  defp loop(prev, config) do
    info = do_update(prev, config)
    receive do
      :stop ->
        :stopped
      {:dump, fd} ->
        do_update(fd, info, prev, config)
        loop(info, config)
      {:config, _, config1} ->
        loop(info, config1)
    after r_opts(config, :intv) ->
      loop(info, config)
    end
  end

  defp do_update(prev, config) do
    info = :etop.update(config)
    do_update(:standard_io, info, prev, config)
  end

  def do_update(fd, info, prev, config) do
    {cpu, nProcs, rQ, clock} = loadinfo(info, prev)
    fieldWidths = calc_field_widths(r_etop_info(info, :procinfo))
    :io.nl(fd)
    writedoubleline(fd, fieldWidths)
    case (r_etop_info(info, :memi)) do
      :undefined ->
        :io.fwrite(fd, ' ~-72w~10s~n Load:  cpu  ~8w~n        procs~8w~n        runq ~8w~n',
                     [r_opts(config, :node), clock, cpu, nProcs, rQ])
      memi ->
        [tot, procs, atom, bin, code, ets] = meminfo(memi,
                                                       [:total, :processes,
                                                                    :atom,
                                                                        :binary,
                                                                            :code,
                                                                                :ets])
        :io.fwrite(fd, ' ~-72w~10s~n Load:  cpu  ~8w               Memory:  total    ~8w    binary   ~8w~n        procs~8w                        processes~8w    code     ~8w~n        runq ~8w                        atom     ~8w    ets      ~8w~n',
                     [r_opts(config, :node), clock, cpu, tot, bin, nProcs, procs,
                                                                          code,
                                                                              rQ,
                                                                                  atom,
                                                                                      ets])
    end
    :io.nl(fd)
    writepinfo_header(fd, fieldWidths)
    writesingleline(fd, fieldWidths)
    writepinfo(fd, r_etop_info(info, :procinfo), modifier(fd),
                 fieldWidths)
    writedoubleline(fd, fieldWidths)
    :io.nl(fd)
    info
  end

  defp calc_field_widths(procInfoL) do
    cols = (case (:io.columns()) do
              {:ok, ioCols} ->
                max(ioCols, 89)
              {:error, :enotsup} ->
                89
            end)
    colsLeft0 = cols - 15 - 20 - 8 - 8 - 1 - 8 - 1 - 8 - 20
    redsWidth = get_width(:reds, procInfoL, colsLeft0)
    colsLeft1 = colsLeft0 + 8 - redsWidth
    memWidth = get_width(:mem, procInfoL, colsLeft1)
    colsLeft2 = colsLeft1 + 8 - memWidth
    msgQWidth = get_width(:msgq, procInfoL, colsLeft2)
    colsLeft3 = colsLeft2 + 8 - msgQWidth
    cond do
      colsLeft3 > 0 ->
        fieldSize = 19 + round((colsLeft3 - 1) / 2)
        initFuncWidth = fieldSize
        currFuncWidth = fieldSize
      true ->
        initFuncWidth = 20
        currFuncWidth = 20
    end
    usedCols = 15 + initFuncWidth + 8 + redsWidth + 1 + memWidth + 1 + msgQWidth + currFuncWidth + 1
    r_field_widths(cols: cols, used_cols: usedCols,
        init_func: initFuncWidth, reds: redsWidth,
        mem: memWidth, msgq: msgQWidth,
        curr_func: currFuncWidth)
  end

  defp get_width(:reds, procInfoL, colsLeft) do
    get_width(4, procInfoL, colsLeft)
  end

  defp get_width(:mem, procInfoL, colsLeft) do
    get_width(3, procInfoL, colsLeft)
  end

  defp get_width(:msgq, procInfoL, colsLeft) do
    get_width(8, procInfoL, colsLeft)
  end

  defp get_width(n, procInfoL, colsLeft) do
    maxNum = :lists.foldr(fn info, acc
                                 when :erlang.element(n, info) > acc ->
                               :erlang.element(n, info)
                             _, acc ->
                               acc
                          end,
                            0, procInfoL)
    maxWidth = (cond do
                  maxNum > 0 ->
                    round(:math.log10(maxNum)) + 1
                  true ->
                    1
                end)
    cond do
      maxWidth > 8 and colsLeft - maxWidth > 0 ->
        maxWidth
      true ->
        8
    end
  end

  defp writepinfo_header(fd,
            r_field_widths(init_func: initFunc, reds: reds, mem: mem,
                msgq: msgQ)) do
    header = 'Pid            Name or Initial Func' ++ :lists.duplicate(max(initFunc - 16, 4),
                                     ?\s) ++ 'Time' ++ :lists.duplicate(max(reds - 4,
                                                                         4),
                                                                     ?\s) ++ 'Reds' ++ :lists.duplicate(max(mem - 5,
                                                                                                         3),
                                                                                                     ?\s) ++ 'Memory' ++ :lists.duplicate(max(msgQ - 3,
                                                                                                                                         5),
                                                                                                                                     ?\s) ++ 'MsgQ Current Function\n'
    :io.fwrite(fd, header, [])
  end

  defp writesingleline(fd, fieldWidths) do
    writedupline(fd, ?-, fieldWidths)
  end

  defp writedoubleline(fd, fieldWidths) do
    writedupline(fd, ?=, fieldWidths)
  end

  defp writedupline(fd, char, r_field_widths(used_cols: usedCols)) do
    line = :lists.duplicate(usedCols, char) ++ '\n'
    :io.fwrite(fd, line, [])
  end

  defp writepinfo(fd,
            [r_etop_proc_info(pid: pid, mem: mem, reds: reds, name: name,
                 runtime: time, cf: mFA, mq: mQ) |
                 t],
            modifier, fieldWidths) do
    :io.fwrite(fd, proc_format(modifier, fieldWidths),
                 [pid, to_string(name, modifier), time, reds, mem, mQ,
                                                                       to_string(mFA,
                                                                                   modifier)])
    writepinfo(fd, t, modifier, fieldWidths)
  end

  defp writepinfo(_Fd, [], _, _) do
    :ok
  end

  defp proc_format(modifier,
            r_field_widths(init_func: initFunc, reds: reds, mem: mem, msgq: msgQ,
                curr_func: currFunc)) do
    '~-15w~-' ++ i2l(initFunc) ++ modifier ++ 's~8w~' ++ i2l(reds) ++ 'w ~' ++ i2l(mem) ++ 'w ~' ++ i2l(msgQ) ++ 'w ~-' ++ i2l(currFunc) ++ modifier ++ 's~n'
  end

  defp to_string({m, f, a}, modifier) do
    :io_lib.format('~w:~' ++ modifier ++ 'w/~w', [m, f, a])
  end

  defp to_string(other, modifier) do
    :io_lib.format('~' ++ modifier ++ 'w', [other])
  end

  defp i2l(i) do
    :erlang.integer_to_list(i)
  end

  defp modifier(device) do
    case (encoding(device)) do
      :latin1 ->
        ''
      _ ->
        't'
    end
  end

  defp encoding(device) do
    case (:io.getopts(device)) do
      list when is_list(list) ->
        :proplists.get_value(:encoding, list, :latin1)
      _ ->
        :latin1
    end
  end

end