defmodule :m_observer_backend do
  use Bitwise
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
  def vsn() do
    case (:application.load(:runtime_tools)) do
      r when r === :ok or
               r === {:error, {:already_loaded, :runtime_tools}}
             ->
        :application.get_key(:runtime_tools, :vsn)
      error ->
        error
    end
  end

  def socket_info() do
    info0 = :socket.info()
    {counters, info1} = :maps.take(:counters, info0)
    iovMax = :maps.get(:iov_max, info1)
    numMons = :socket.number_of_monitors()
    [{:iov_max, iovMax}, {:num_monitors, numMons} |
                             :maps.to_list(counters)]
  end

  def sys_info() do
    memInfo = (try do
                 :erlang.memory()
               catch
                 _, _ ->
                   []
               else
                 mem ->
                   mem
               end)
    schedulersOnline = :erlang.system_info(:schedulers_online)
    schedulersAvailable = (case (:erlang.system_info(:multi_scheduling)) do
                             :enabled ->
                               schedulersOnline
                             _ ->
                               1
                           end)
    {{_, input}, {_, output}} = :erlang.statistics(:io)
    [{:uptime,
        :erlang.element(1, :erlang.statistics(:wall_clock))},
         {:run_queue, :erlang.statistics(:run_queue)},
             {:io_input, input}, {:io_output, output},
                                     {:logical_processors,
                                        :erlang.system_info(:logical_processors)},
                                         {:logical_processors_online,
                                            :erlang.system_info(:logical_processors_online)},
                                             {:logical_processors_available,
                                                :erlang.system_info(:logical_processors_available)},
                                                 {:schedulers,
                                                    :erlang.system_info(:schedulers)},
                                                     {:schedulers_online,
                                                        schedulersOnline},
                                                         {:schedulers_available,
                                                            schedulersAvailable},
                                                             {:otp_release,
                                                                :erlang.system_info(:otp_release)},
                                                                 {:version,
                                                                    :erlang.system_info(:version)},
                                                                     {:system_architecture,
                                                                        :erlang.system_info(:system_architecture)},
                                                                         {:kernel_poll,
                                                                            :erlang.system_info(:kernel_poll)},
                                                                             {:smp_support,
                                                                                :erlang.system_info(:smp_support)},
                                                                                 {:threads,
                                                                                    :erlang.system_info(:threads)},
                                                                                     {:thread_pool_size,
                                                                                        :erlang.system_info(:thread_pool_size)},
                                                                                         {:wordsize_internal,
                                                                                            :erlang.system_info({:wordsize,
                                                                                                                   :internal})},
                                                                                             {:wordsize_external,
                                                                                                :erlang.system_info({:wordsize,
                                                                                                                       :external})},
                                                                                                 {:alloc_info,
                                                                                                    alloc_info()},
                                                                                                     {:process_count,
                                                                                                        :erlang.system_info(:process_count)},
                                                                                                         {:atom_limit,
                                                                                                            :erlang.system_info(:atom_limit)},
                                                                                                             {:atom_count,
                                                                                                                :erlang.system_info(:atom_count)},
                                                                                                                 {:process_limit,
                                                                                                                    :erlang.system_info(:process_limit)},
                                                                                                                     {:process_count,
                                                                                                                        :erlang.system_info(:process_count)},
                                                                                                                         {:port_limit,
                                                                                                                            :erlang.system_info(:port_limit)},
                                                                                                                             {:port_count,
                                                                                                                                :erlang.system_info(:port_count)},
                                                                                                                                 {:ets_limit,
                                                                                                                                    :erlang.system_info(:ets_limit)},
                                                                                                                                     {:ets_count,
                                                                                                                                        :erlang.system_info(:ets_count)},
                                                                                                                                         {:dist_buf_busy_limit,
                                                                                                                                            :erlang.system_info(:dist_buf_busy_limit)} |
                                                                                                                                             memInfo]
  end

  defp alloc_info() do
    alcuAllocs = :erlang.system_info(:alloc_util_allocators)
    try do
      :erlang.system_info({:allocator_sizes, alcuAllocs})
    catch
      _, _ ->
        []
    else
      allocators ->
        allocators
    end
  end

  def get_table(parent, table, module) do
    spawn(fn () ->
               :erlang.link(parent)
               get_table2(parent, table, module)
          end)
  end

  defp get_table2(parent, table, type) do
    size = (case (type) do
              :ets ->
                :ets.info(table, :size)
              :mnesia ->
                :mnesia.table_info(table, :size)
            end)
    case (size !== :undefined and size > 0) do
      false ->
        send(parent, {self(), :"$end_of_table"})
        :normal
      true when type === :ets ->
        mem = :ets.info(table, :memory)
        average = div(mem, size)
        noElements = max(10, div(20000, average))
        get_ets_loop(parent, :ets.match(table, :"$1", noElements))
      true ->
        mem = :mnesia.table_info(table, :memory)
        average = div(mem, size)
        noElements = max(10, div(20000, average))
        ms = [{:"$1", [], [:"$1"]}]
        get = fn () ->
                   get_mnesia_loop(parent,
                                     :mnesia.select(table, ms, noElements,
                                                      :read))
              end
        :mnesia.async_dirty(get)
    end
  end

  defp get_ets_loop(parent, :"$end_of_table") do
    send(parent, {self(), :"$end_of_table"})
  end

  defp get_ets_loop(parent, {match, cont}) do
    send(parent, {self(), match})
    get_ets_loop(parent, :ets.match(cont))
  end

  defp get_mnesia_loop(parent, :"$end_of_table") do
    send(parent, {self(), :"$end_of_table"})
  end

  defp get_mnesia_loop(parent, {match, cont}) do
    send(parent, {self(), match})
    get_mnesia_loop(parent, :mnesia.select(cont))
  end

  def get_port_list() do
    extraItems = [:monitors, :monitored_by, :parallelism,
                                                :locking, :queue_size, :memory]
    portInfo = fn p, acc ->
                    case (:erlang.port_info(p)) do
                      :undefined ->
                        acc
                      info ->
                        [[{:port_id, p} | info] ++ port_info(p,
                                                               extraItems) ++ inet_port_extra(:erlang.port_info(p,
                                                                                                                  :name),
                                                                                                p) |
                             acc]
                    end
               end
    pIs = :lists.foldl(portInfo, [], :erlang.ports())
    :lists.reverse(pIs)
  end

  defp port_info(p, [item | items]) do
    case (:erlang.port_info(p, item)) do
      :undefined ->
        port_info(p, items)
      value ->
        [value | port_info(p, items)]
    end
  end

  defp port_info(_, []) do
    []
  end

  defp inet_port_extra({_, type}, port) when type === 'udp_inet' or
                                  type === 'tcp_inet' or type === 'sctp_inet' do
    data = (case (:inet.getstat(port)) do
              {:ok, stats} ->
                [{:statistics, stats}]
              _ ->
                []
            end) ++ (case (:inet.peername(port)) do
                       {:ok, {rAddr, rPort}} when (is_tuple(rAddr) and
                                                     is_integer(rPort))
                                                  ->
                         [{:remote_address, rAddr}, {:remote_port, rPort}]
                       {:ok, rAddr} ->
                         [{:remote_address, rAddr}]
                       {:error, _} ->
                         []
                     end) ++ (case (:inet.sockname(port)) do
                                {:ok, {lAddr, lPort}} when (is_tuple(lAddr) and
                                                              is_integer(lPort))
                                                           ->
                                  [{:local_address, lAddr}, {:local_port,
                                                               lPort}]
                                {:ok, lAddr} ->
                                  [{:local_address, lAddr}]
                                {:error, _} ->
                                  []
                              end) ++ [{:options, get_sock_opts(port)}]
    [{:inet, data}]
  end

  defp inet_port_extra(_, _) do
    []
  end

  defp sock_opts() do
    [:active, :broadcast, :buffer, :bind_to_device,
                                       :delay_send, :deliver, :dontroute,
                                                                  :exit_on_close,
                                                                      :header,
                                                                          :high_msgq_watermark,
                                                                              :high_watermark,
                                                                                  :ipv6_v6only,
                                                                                      :keepalive,
                                                                                          :linger,
                                                                                              :low_msgq_watermark,
                                                                                                  :low_watermark,
                                                                                                      :mode,
                                                                                                          :netns,
                                                                                                              :nodelay,
                                                                                                                  :packet,
                                                                                                                      :packet_size,
                                                                                                                          :priority,
                                                                                                                              :read_packets,
                                                                                                                                  :recbuf,
                                                                                                                                      :reuseaddr,
                                                                                                                                          :send_timeout,
                                                                                                                                              :send_timeout_close,
                                                                                                                                                  :show_econnreset,
                                                                                                                                                      :sndbuf,
                                                                                                                                                          :tos,
                                                                                                                                                              :tclass]
  end

  defp get_sock_opts(port) do
    get_sock_opts(port, sock_opts())
  end

  defp get_sock_opts(port, opts) do
    get_sock_opts(port, opts, [])
  end

  defp get_sock_opts(_Port, [], acc) do
    :lists.reverse(acc)
  end

  defp get_sock_opts(port, [opt | opts], acc) do
    case (:inet.getopts(port, [opt])) do
      {:ok, [res]} ->
        get_sock_opts(port, opts, [res | acc])
      {:ok, []} ->
        res = {opt, '-'}
        get_sock_opts(port, opts, [res | acc])
      {:error, :einval} ->
        res = {opt, 'Not Supported'}
        get_sock_opts(port, opts, [res | acc])
      {:error, reason} ->
        res = {opt, f('error:~p', [reason])}
        get_sock_opts(port, opts, [res | acc])
    end
  end

  def get_socket_list() do
    getOpt = fn _Sock, {opt, false} ->
                  {opt, 'Not Supported'}
                sock, {opt, true} ->
                  case (:socket.getopt(sock, opt)) do
                    {:ok, value0} ->
                      value = (cond do
                                 value0 === [] ->
                                   '-'
                                 true ->
                                   value0
                               end)
                      {opt, value}
                    {:error, :enotsup} = _ERROR ->
                      {opt, 'Not Supported'}
                    {:error, :enoprotoopt} = _ERROR ->
                      {opt, 'Not Supported'}
                    {:error, :enotconn} = _ERROR ->
                      {opt, 'Not Connected'}
                    {:error, {:invalid, _}} = _ERROR ->
                      {opt, 'Not Implemented'}
                    {:error, reason} ->
                      {opt, f('error:~p', [reason])}
                  end
             end
    for s <- :socket.which_sockets() do
      (
        kind = :socket.which_socket_kind(s)
        fD = (case (:socket.getopt(s, :otp, :fd)) do
                {:ok, fD0} ->
                  fD0
                _ ->
                  - 1
              end)
        info0 = :socket.info(s)
        idStr0 = :socket.to_list(s)
        idStr = (case (info0) do
                   %{type: :stream, protocol: :tcp} when kind === :compat
                                                         ->
                     '#Socket' ++ id = idStr0
                     '#InetSocket' ++ id
                   _ ->
                     idStr0
                 end)
        {counters0, info1} = :maps.take(:counters, info0)
        counters = :maps.to_list(counters0)
        info2 = :maps.remove(:ctype, info1)
        info3 = :maps.remove(:num_acceptors, info2)
        info4 = :maps.remove(:num_readers, info3)
        info5 = :maps.remove(:num_writers, info4)
        info6 = (case (:socket.peername(s)) do
                   {:ok, rAddr} ->
                     rAddrStr = sockaddr_to_list(rAddr)
                     :maps.put(:raddress, rAddrStr, info5)
                   _ ->
                     info5
                 end)
        info7 = (case (:socket.sockname(s)) do
                   {:ok, lAddr} ->
                     lAddrStr = sockaddr_to_list(lAddr)
                     :maps.put(:laddress, lAddrStr, info6)
                   _ ->
                     info6
                 end)
        sockOpts = (for {opt,
                           supported} <- :socket.supports(:options, :socket),
                          true do
                      {{:socket, opt}, supported}
                    end)
        domainOpts = (case (info7) do
                        %{domain: :inet6} ->
                          for {opt, supported} <- :socket.supports(:options,
                                                                     :ipv6),
                                true do
                            {{:ipv6, opt}, supported}
                          end
                        _ ->
                          for {opt, supported} <- :socket.supports(:options,
                                                                     :ip),
                                true do
                            {{:ip, opt}, supported}
                          end
                      end)
        protoOpts = (case (info7) do
                       %{domain: domain, type: :stream, protocol: :tcp}
                           when domain === :inet or domain === :inet6 ->
                         for {opt, supported} <- :socket.supports(:options,
                                                                    :tcp),
                               true do
                           {{:tcp, opt}, supported}
                         end
                       %{domain: domain, type: :dgram, protocol: :udp}
                           when domain === :inet or domain === :inet6 ->
                         for {opt, supported} <- :socket.supports(:options,
                                                                    :udp),
                               true do
                           {{:udp, opt}, supported}
                         end
                       %{domain: domain, type: :seqpacket, protocol: :sctp}
                           when domain === :inet or domain === :inet6 ->
                         for {opt, supported} <- :socket.supports(:options,
                                                                    :sctp),
                               true do
                           {{:sctp, opt}, supported}
                         end
                       _ ->
                         []
                     end)
        opts = sockOpts ++ domainOpts ++ protoOpts
        options = (for opt <- opts do
                     getOpt.(s, opt)
                   end)
        Map.merge(info7, %{id: s, id_str: idStr, fd: fD,
                             kind: kind, monitored_by: :socket.monitored_by(s),
                             statistics: counters,
                             options: :lists.sort(options)})
      )
    end
  end

  defp sockaddr_to_list(%{family: :local, path: pathBin})
      when is_binary(pathBin) do
    :erlang.binary_to_list(pathBin)
  end

  defp sockaddr_to_list(%{family: :local, path: path})
      when is_list(path) do
    path
  end

  defp sockaddr_to_list(%{family: :inet, addr: addr, port: port}) do
    :inet_parse.ntoa(addr) ++ ' : ' ++ :erlang.integer_to_list(port)
  end

  defp sockaddr_to_list(%{family: :inet6, addr: addr, port: port,
              flowinfo: fI, scope_id: sID}) do
    :inet_parse.ntoa(addr) ++ ' : ' ++ :erlang.integer_to_list(port) ++ ' , ' ++ :erlang.integer_to_list(fI) ++ ' , ' ++ :erlang.integer_to_list(sID)
  end

  defp sockaddr_to_list(addr) do
    f('~p', [addr])
  end

  def get_table_list(:ets, opts) do
    hideUnread = :proplists.get_value(:unread_hidden, opts,
                                        true)
    hideSys = :proplists.get_value(:sys_hidden, opts, true)
    info = fn id, acc ->
                try do
                  tabId = (case (:ets.info(id, :named_table)) do
                             true ->
                               :ignore
                             false ->
                               id
                           end)
                  name = :ets.info(id, :name)
                  protection = :ets.info(id, :protection)
                  ignore(hideUnread and protection == :private,
                           :unreadable)
                  owner = :ets.info(id, :owner)
                  regName = (case ((try do
                                     :erlang.process_info(owner,
                                                            :registered_name)
                                   catch
                                     :error, e -> {:EXIT, {e, __STACKTRACE__}}
                                     :exit, e -> {:EXIT, e}
                                     e -> e
                                   end)) do
                               [] ->
                                 :ignore
                               {:registered_name, procName} ->
                                 procName
                             end)
                  ignore(hideSys and :ordsets.is_element(regName,
                                                           sys_processes()),
                           :system_tab)
                  ignore(hideSys and :ordsets.is_element(name,
                                                           sys_tables()),
                           :system_tab)
                  ignore(regName == :mnesia_monitor and name != :schema and is_atom((try do
                                                                                      :mnesia.table_info(name,
                                                                                                           :where_to_read)
                                                                                    catch
                                                                                      :error, e -> {:EXIT, {e, __STACKTRACE__}}
                                                                                      :exit, e -> {:EXIT, e}
                                                                                      e -> e
                                                                                    end)),
                           :mnesia_tab)
                  memory = :ets.info(id,
                                       :memory) * :erlang.system_info(:wordsize)
                  tab = [{:name, name}, {:id, tabId}, {:protection,
                                                         protection},
                                                          {:owner, owner},
                                                              {:size,
                                                                 :ets.info(id,
                                                                             :size)},
                                                                  {:reg_name,
                                                                     regName},
                                                                      {:type,
                                                                         :ets.info(id,
                                                                                     :type)},
                                                                          {:keypos,
                                                                             :ets.info(id,
                                                                                         :keypos)},
                                                                              {:heir,
                                                                                 :ets.info(id,
                                                                                             :heir)},
                                                                                  {:memory,
                                                                                     memory},
                                                                                      {:compressed,
                                                                                         :ets.info(id,
                                                                                                     :compressed)},
                                                                                          {:fixed,
                                                                                             :ets.info(id,
                                                                                                         :fixed)}]
                  [tab | acc]
                catch
                  _, _What ->
                    acc
                end
           end
    :lists.foldl(info, [], :ets.all())
  end

  def get_table_list(:mnesia, opts) do
    hideSys = :proplists.get_value(:sys_hidden, opts, true)
    owner = :ets.info(:schema, :owner)
    owner != :undefined or throw({:error,
                                    'Mnesia is not running on: ' ++ :erlang.atom_to_list(node())})
    {:registered_name,
       regName} = :erlang.process_info(owner, :registered_name)
    info = fn id, acc ->
                try do
                  name = id
                  ignore(hideSys and :ordsets.is_element(name,
                                                           mnesia_tables()),
                           :system_tab)
                  ignore(name === :schema, :mnesia_tab)
                  storage = :mnesia.table_info(id, :storage_type)
                  tab0 = [{:name, name}, {:owner, owner}, {:size,
                                                             :mnesia.table_info(id,
                                                                                  :size)},
                                                              {:reg_name,
                                                                 regName},
                                                                  {:type,
                                                                     :mnesia.table_info(id,
                                                                                          :type)},
                                                                      {:keypos,
                                                                         2},
                                                                          {:memory,
                                                                             :mnesia.table_info(id,
                                                                                                  :memory) * :erlang.system_info(:wordsize)},
                                                                              {:storage,
                                                                                 storage},
                                                                                  {:index,
                                                                                     :mnesia.table_info(id,
                                                                                                          :index)}]
                  tab = (cond do
                           storage == :disc_only_copies ->
                             [{:fixed, :dets.info(id, :safe_fixed)} | tab0]
                           storage == :ram_copies or storage == :disc_copies ->
                             [{:fixed, :ets.info(id, :fixed)}, {:compressed,
                                                                  :ets.info(id,
                                                                              :compressed)} |
                                                                   tab0]
                           true ->
                             tab0
                         end)
                  [tab | acc]
                catch
                  _, _What ->
                    acc
                end
           end
    :lists.foldl(info, [], :mnesia.system_info(:tables))
  end

  def fetch_stats(parent, time) do
    :erlang.process_flag(:trap_exit, true)
    fetch_stats_loop(parent, time)
  end

  defp fetch_stats_loop(parent, time) do
    :erlang.system_flag(:scheduler_wall_time, true)
    receive do
      _Msg ->
        :erlang.system_flag(:scheduler_wall_time, false)
        :ok
    after time ->
      _M = send(parent, {:stats, 1,
                           :erlang.statistics(:scheduler_wall_time),
                           :erlang.statistics(:io),
                           try do
                             :erlang.memory()
                           catch
                             _, _ ->
                               []
                           end})
      fetch_stats_loop(parent, time)
    end
  end

  def procs_info(collector) do
    all = :erlang.processes()
    send = fn send
           pids ->
             try do
               :lists.split(10000, pids)
             catch
               _, _ ->
                 send(collector, {:procs_info, self(),
                                    etop_collect(pids, [])})
             else
               {first, rest} ->
                 send(collector, {:procs_info, self(),
                                    etop_collect(first, [])})
                 send.(rest)
             end
           end
    send.(all)
  end

  def etop_collect(collector) do
    schedulerWallTime = :erlang.statistics(:scheduler_wall_time)
    procInfo = etop_collect(:erlang.processes(), [])
    send(collector, {self(),
                       r_etop_info(now: :erlang.timestamp(), n_procs: length(procInfo),
                           run_queue: :erlang.statistics(:run_queue),
                           runtime: schedulerWallTime, memi: etop_memi(),
                           procinfo: procInfo)})
    case (schedulerWallTime) do
      :undefined ->
        spawn(fn () ->
                   flag_holder_proc(collector)
              end)
        :ok
      _ ->
        :ok
    end
  end

  defp flag_holder_proc(collector) do
    :erlang.system_flag(:scheduler_wall_time, true)
    ref = :erlang.monitor(:process, collector)
    receive do
      {:DOWN, ^ref, _, _, _} ->
        :erlang.system_flag(:scheduler_wall_time, false)
        :ok
    end
  end

  defp etop_memi() do
    try do
      [{:total, :c.memory(:total)}, {:processes,
                                       :c.memory(:processes)},
                                        {:ets, :c.memory(:ets)}, {:atom,
                                                                    :c.memory(:atom)},
                                                                     {:code,
                                                                        :c.memory(:code)},
                                                                         {:binary,
                                                                            :c.memory(:binary)}]
    catch
      :error, :notsup ->
        :undefined
    end
  end

  defp etop_collect([p | ps], acc) when p === self() do
    etop_collect(ps, acc)
  end

  defp etop_collect([p | ps], acc) do
    fs = [:registered_name, :initial_call, :memory,
                                               :reductions, :current_function,
                                                                :message_queue_len]
    case (:erlang.process_info(p, fs)) do
      :undefined ->
        etop_collect(ps, acc)
      [{:registered_name, reg}, {:initial_call, initial},
                                    {:memory, mem}, {:reductions, reds},
                                                        {:current_function,
                                                           current},
                                                            {:message_queue_len,
                                                               qlen}] ->
        name = (case (reg) do
                  [] ->
                    initial_call(initial, p)
                  _ ->
                    reg
                end)
        info = r_etop_proc_info(pid: p, mem: mem, reds: reds, name: name,
                   cf: current, mq: qlen)
        etop_collect(ps, [info | acc])
    end
  end

  defp etop_collect([], acc) do
    acc
  end

  defp initial_call({:proc_lib, :init_p, _}, pid) do
    :proc_lib.translate_initial_call(pid)
  end

  defp initial_call(initial, _Pid) do
    initial
  end

  def ttb_init_node(metaFile_0, pI, traci) do
    cond do
      is_list(metaFile_0) or is_atom(metaFile_0) ->
        {:ok, cwd} = :file.get_cwd()
        metaFile = :filename.join(cwd, metaFile_0)
        :file.delete(metaFile)
      true ->
        metaFile = metaFile_0
    end
    case (:proplists.get_value(:resume, traci)) do
      {true, _} ->
        (autostart_module()).write_config(traci)
      _ ->
        :ok
    end
    self = self()
    metaPid = spawn(fn () ->
                         ttb_meta_tracer(metaFile, pI, self, traci)
                    end)
    receive do
      {^metaPid, :started} ->
        :ok
    end
    send(metaPid, {:metadata, traci})
    case (pI) do
      true ->
        send(metaPid, {:metadata, pnames()})
        :ok
      false ->
        :ok
    end
    {:ok, metaFile, metaPid}
  end

  def ttb_write_trace_info(metaPid, key, what) do
    send(metaPid, {:metadata, key, what})
    :ok
  end

  defp ttb_meta_tracer(metaFile, pI, parent, sessionData) do
    :erlang.monitor(:process,
                      :proplists.get_value(:ttb_control, sessionData))
    case (pI) do
      true ->
        returnMS = [{:_, [], [{:return_trace}]}]
        :erlang.trace_pattern({:erlang, :spawn, 3}, returnMS,
                                [:meta])
        :erlang.trace_pattern({:erlang, :spawn_link, 3},
                                returnMS, [:meta])
        :erlang.trace_pattern({:erlang, :spawn_opt, 4},
                                returnMS, [:meta])
        :erlang.trace_pattern({:erts_internal, :spawn_init, 1},
                                [], [:meta])
        :erlang.trace_pattern({:erts_internal, :dist_spawn_init,
                                 1},
                                [], [:meta])
        :erlang.trace_pattern({:erlang, :register, 2}, [],
                                [:meta])
        :erlang.trace_pattern({:global, :register_name, 2}, [],
                                [:meta])
        :ok
      false ->
        :ok
    end
    send(parent, {self(), :started})
    case (:proplists.get_value(:overload_check,
                                 sessionData)) do
      {ms, m, f} ->
        (try do
          apply(m, f, [:init])
        catch
          :error, e -> {:EXIT, {e, __STACKTRACE__}}
          :exit, e -> {:EXIT, e}
          e -> e
        end)
        :erlang.send_after(ms, self(), :overload_check)
        :ok
      _ ->
        :ok
    end
    ttb_meta_tracer_loop(metaFile, pI, :dict.new(),
                           sessionData)
  end

  defp ttb_meta_tracer_loop(metaFile, pI, acc, state) do
    receive do
      {:trace_ts, _, :call, {:erlang, :register, [name, pid]},
         _} ->
        :ok = ttb_store_meta({:pid, {pid, name}}, metaFile)
        ttb_meta_tracer_loop(metaFile, pI, acc, state)
      {:trace_ts, _, :call,
         {:global, :register_name, [name, pid]}, _} ->
        :ok = ttb_store_meta({:pid, {pid, {:global, name}}},
                               metaFile)
        ttb_meta_tracer_loop(metaFile, pI, acc, state)
      {:trace_ts, callingPid, :call,
         {:erlang, :spawn_opt, [m, f, args, _]}, _} ->
        mFA = {m, f, length(args)}
        newAcc = :dict.update(callingPid,
                                fn old ->
                                     [mFA | old]
                                end,
                                [mFA], acc)
        ttb_meta_tracer_loop(metaFile, pI, newAcc, state)
      {:trace_ts, callingPid, :return_from,
         {:erlang, :spawn_opt, _Arity}, ret, _} ->
        case (ret) do
          {newPid, _Mref} when is_pid(newPid) ->
            :ok
          newPid when is_pid(newPid) ->
            :ok
        end
        newAcc = :dict.update(callingPid,
                                fn [h | t] ->
                                     :ok = ttb_store_meta({:pid, {newPid, h}},
                                                            metaFile)
                                     t
                                end,
                                acc)
        ttb_meta_tracer_loop(metaFile, pI, newAcc, state)
      {:trace_ts, callingPid, :call,
         {:erlang, spawn, [m, f, args]}, _}
          when spawn == :spawn or spawn == :spawn_link ->
        mFA = {m, f, length(args)}
        newAcc = :dict.update(callingPid,
                                fn old ->
                                     [mFA | old]
                                end,
                                [mFA], acc)
        ttb_meta_tracer_loop(metaFile, pI, newAcc, state)
      {:trace_ts, callingPid, :return_from,
         {:erlang, spawn, _Arity}, newPid, _}
          when spawn == :spawn or spawn == :spawn_link ->
        newAcc = :dict.update(callingPid,
                                fn [h | t] ->
                                     :ok = ttb_store_meta({:pid, {newPid, h}},
                                                            metaFile)
                                     t
                                end,
                                acc)
        ttb_meta_tracer_loop(metaFile, pI, newAcc, state)
      {:trace_ts, callingPid, :call,
         {:erts_internal, :spawn_init, [{m, f, args}]}, _} ->
        :ok = ttb_store_meta({:pid,
                                {callingPid, {m, f, length(args)}}},
                               metaFile)
        ttb_meta_tracer_loop(metaFile, pI, acc, state)
      {:trace_ts, callingPid, :call,
         {:erts_internal, :dist_spawn_init, [mFnoA]}, _} ->
        :ok = ttb_store_meta({:pid, {callingPid, mFnoA}},
                               metaFile)
        ttb_meta_tracer_loop(metaFile, pI, acc, state)
      {:metadata, data} when is_list(data) ->
        :ok = ttb_store_meta(data, metaFile)
        ttb_meta_tracer_loop(metaFile, pI, acc, state)
      {:metadata, key, fun} when is_function(fun) ->
        :ok = ttb_store_meta([{key, fun.()}], metaFile)
        ttb_meta_tracer_loop(metaFile, pI, acc, state)
      {:metadata, key, what} ->
        :ok = ttb_store_meta([{key, what}], metaFile)
        ttb_meta_tracer_loop(metaFile, pI, acc, state)
      :overload_check ->
        {ms, m, f} = :proplists.get_value(:overload_check,
                                            state)
        case ((try do
                apply(m, f, [:check])
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end)) do
          true ->
            :erlang.trace(:all, false, [:all])
            controlPid = :proplists.get_value(:ttb_control, state)
            send(controlPid, {:node_overloaded, node()})
            (try do
              apply(m, f, [:stop])
            catch
              :error, e -> {:EXIT, {e, __STACKTRACE__}}
              :exit, e -> {:EXIT, e}
              e -> e
            end)
            ttb_meta_tracer_loop(metaFile, pI, acc,
                                   :lists.keydelete(:overload_check, 1, state))
          _ ->
            :erlang.send_after(ms, self(), :overload_check)
            ttb_meta_tracer_loop(metaFile, pI, acc, state)
        end
      {:DOWN, _, _, _, _} ->
        _ = stop_seq_trace()
        send(self(), :stop)
        ttb_meta_tracer_loop(metaFile, pI, acc, state)
      :stop when pI === true ->
        try_stop_resume(state)
        try_stop_overload_check(state)
        :erlang.trace_pattern({:erlang, :spawn, 3}, false,
                                [:meta])
        :erlang.trace_pattern({:erlang, :spawn_link, 3}, false,
                                [:meta])
        :erlang.trace_pattern({:erlang, :spawn_opt, 4}, false,
                                [:meta])
        :erlang.trace_pattern({:erts_internal, :spawn_init, 1},
                                false, [:meta])
        :erlang.trace_pattern({:erts_internal, :dist_spawn_init,
                                 1},
                                false, [:meta])
        :erlang.trace_pattern({:erlang, :register, 2}, false,
                                [:meta])
        :erlang.trace_pattern({:global, :register_name, 2},
                                false, [:meta])
      :stop ->
        try_stop_resume(state)
        try_stop_overload_check(state)
    end
  end

  defp try_stop_overload_check(state) do
    case (:proplists.get_value(:overload, state)) do
      :undefined ->
        :ok
      {_, m, f} ->
        (try do
          apply(m, f, [:stop])
        catch
          :error, e -> {:EXIT, {e, __STACKTRACE__}}
          :exit, e -> {:EXIT, e}
          e -> e
        end)
    end
  end

  defp pnames() do
    processes = :erlang.processes()
    globals = :lists.map(fn g ->
                              {:global.whereis_name(g), g}
                         end,
                           :global.registered_names())
    :lists.flatten(:lists.foldl(fn pid, acc ->
                                     [pinfo(pid, globals) | acc]
                                end,
                                  [], processes))
  end

  defp pinfo(p, globals) do
    case (:erlang.process_info(p, :registered_name)) do
      [] ->
        case (:lists.keysearch(p, 1, globals)) do
          {:value, {^p, g}} ->
            {:pid, {p, {:global, g}}}
          false ->
            case (:erlang.process_info(p, :initial_call)) do
              {_, i} ->
                {:pid, {p, i}}
              :undefined ->
                []
            end
        end
      {_, r} ->
        {:pid, {p, r}}
      :undefined ->
        []
    end
  end

  defp autostart_module() do
    :erlang.element(2,
                      :application.get_env(:runtime_tools,
                                             :ttb_autostart_module))
  end

  defp try_stop_resume(state) do
    case (:proplists.get_value(:resume, state)) do
      true ->
        (autostart_module()).delete_config()
      _ ->
        :ok
    end
  end

  def ttb_resume_trace() do
    case ((autostart_module()).read_config()) do
      {:error, _} ->
        :ok
      {:ok, data} ->
        pid = :proplists.get_value(:ttb_control, data)
        {_, timeout} = :proplists.get_value(:resume, data)
        case (:rpc.call(node(pid), :erlang, :whereis,
                          [:ttb])) do
          ^pid ->
            send(pid, {:noderesumed, node(), self()})
            wait_for_fetch_ready(timeout)
          _ ->
            :ok
        end
        (autostart_module()).delete_config()
        :ok
    end
  end

  defp wait_for_fetch_ready(timeout) do
    receive do
      :trace_resumed ->
        :ok
    after timeout ->
      :ok
    end
  end

  defp ttb_store_meta(data, {:local, metaFile, port})
      when is_list(data) do
    ttb_send_to_port(port, metaFile, data)
  end

  defp ttb_store_meta(data, metaFile) when is_list(data) do
    {:ok, fd} = :file.open(metaFile, [:raw, :append])
    ttb_write_binary(fd, data)
    :file.close(fd)
  end

  defp ttb_store_meta(data, metaFile) do
    ttb_store_meta([data], metaFile)
  end

  def ttb_write_binary(fd, [h | t]) do
    :ok = :file.write(fd, ttb_make_binary(h))
    ttb_write_binary(fd, t)
  end

  def ttb_write_binary(_Fd, []) do
    :ok
  end

  defp ttb_send_to_port(port, metaFile, [h | t]) do
    b1 = ttb_make_binary(h)
    b2 = :erlang.term_to_binary({:metadata, metaFile, b1})
    :erlang.port_command(port, b2)
    ttb_send_to_port(port, metaFile, t)
  end

  defp ttb_send_to_port(_Port, _MetaFile, []) do
    :ok
  end

  defp ttb_make_binary(term) do
    b = :erlang.term_to_binary(term)
    sizeB = byte_size(b)
    cond do
      sizeB > 255 ->
        sB = :erlang.term_to_binary({:"$size", sizeB})
        <<byte_size(sB) :: size(8), sB :: binary, b :: binary>>
      true ->
        <<sizeB :: size(8), b :: binary>>
    end
  end

  def ttb_stop(metaPid) do
    delivered = :erlang.trace_delivered(:all)
    receive do
      {:trace_delivered, :all, ^delivered} ->
        :ok
    end
    ref = :erlang.monitor(:process, metaPid)
    send(metaPid, :stop)
    receive do
      {:DOWN, ^ref, :process, ^metaPid, _Info} ->
        :ok
    end
    stop_seq_trace()
  end

  defp stop_seq_trace() do
    :seq_trace.reset_trace()
    :seq_trace.set_system_tracer(false)
  end

  def ttb_fetch(metaFile, {port, host}) do
    ttb_fetch(metaFile, {port, host}, :undefined)
  end

  def ttb_fetch(metaFile, {port, host}, masterEnc) do
    :erlang.process_flag(:priority, :low)
    files = ttb_get_filenames(metaFile)
    {:ok, sock} = :gen_tcp.connect(host, port,
                                     [:binary, {:packet, 2}])
    send_files({sock, host}, files, masterEnc,
                 :file.native_name_encoding())
    :ok = :gen_tcp.close(sock)
  end

  defp send_files({sock, host}, [file | files], masterEnc,
            myEnc) do
    {:ok, fd} = :file.open(file, [:raw, :read, :binary])
    basename = :filename.basename(file)
    {code, filenameBin} = encode_filename(basename,
                                            masterEnc, myEnc)
    :ok = :gen_tcp.send(sock,
                          <<code, filenameBin :: binary>>)
    send_chunks(sock, fd)
    :ok = :file.delete(file)
    send_files({sock, host}, files, masterEnc, myEnc)
  end

  defp send_files({_Sock, _Host}, [], _MasterEnc, _MyEnc) do
    :done
  end

  defp encode_filename(basename, :undefined, myEnc) do
    {1,
       :unicode.characters_to_binary(basename, myEnc, myEnc)}
  end

  defp encode_filename(basename, masterEnc, myEnc) do
    case (:unicode.characters_to_binary(basename, myEnc,
                                          masterEnc)) do
      bin when is_binary(bin) ->
        {2, bin}
      _ ->
        {3,
           :unicode.characters_to_binary(basename, myEnc, myEnc)}
    end
  end

  defp send_chunks(sock, fd) do
    case (:file.read(fd, 8191)) do
      {:ok, bin} ->
        :ok = :gen_tcp.send(sock, <<0, bin :: binary>>)
        send_chunks(sock, fd)
      :eof ->
        :ok
      {:error, reason} ->
        :ok = :gen_tcp.send(sock,
                              <<2, :erlang.term_to_binary(reason) :: binary>>)
    end
  end

  def ttb_get_filenames(metaFile) do
    dir = :filename.dirname(metaFile)
    root = :filename.rootname(:filename.basename(metaFile))
    {:ok, list} = :file.list_dir(dir)
    match_filenames(dir, root, list, [])
  end

  defp match_filenames(dir, metaFile, [h | t], files) do
    case (:lists.prefix(metaFile, h)) do
      true ->
        match_filenames(dir, metaFile, t,
                          [:filename.join(dir, h) | files])
      false ->
        match_filenames(dir, metaFile, t, files)
    end
  end

  defp match_filenames(_Dir, _MetaFile, [], files) do
    files
  end

  defp sys_tables() do
    [:ac_tab, :asn1, :cdv_dump_index_table, :cdv_menu_table,
                                                :cdv_decode_heap_table,
                                                    :cell_id, :cell_pos, :clist,
                                                                             :cover_internal_data_table,
                                                                                 :cover_collected_remote_data_table,
                                                                                     :cover_binary_code_table,
                                                                                         :code,
                                                                                             :code_names,
                                                                                                 :cookies,
                                                                                                     :corba_policy,
                                                                                                         :corba_policy_associations,
                                                                                                             :dets,
                                                                                                                 :dets_owners,
                                                                                                                     :dets_registry,
                                                                                                                         :disk_log_names,
                                                                                                                             :disk_log_pids,
                                                                                                                                 :eprof,
                                                                                                                                     :erl_atom_cache,
                                                                                                                                         :erl_epmd_nodes,
                                                                                                                                             :etop_accum_tab,
                                                                                                                                                 :etop_tr,
                                                                                                                                                     :ets_coverage_data,
                                                                                                                                                         :file_io_servers,
                                                                                                                                                             :gs_mapping,
                                                                                                                                                                 :gs_names,
                                                                                                                                                                     :gstk_db,
                                                                                                                                                                         :gstk_grid_cellid,
                                                                                                                                                                             :gstk_grid_cellpos,
                                                                                                                                                                                 :gstk_grid_id,
                                                                                                                                                                                     :httpd,
                                                                                                                                                                                         :id,
                                                                                                                                                                                             :ign_req_index,
                                                                                                                                                                                                 :ign_requests,
                                                                                                                                                                                                     :index,
                                                                                                                                                                                                         :inet_cache,
                                                                                                                                                                                                             :inet_db,
                                                                                                                                                                                                                 :inet_hosts,
                                                                                                                                                                                                                     :InitialReferences,
                                                                                                                                                                                                                         :int_db,
                                                                                                                                                                                                                             :interpreter_includedirs_macros,
                                                                                                                                                                                                                                 :ir_WstringDef,
                                                                                                                                                                                                                                     :lmcounter,
                                                                                                                                                                                                                                         :locks,
                                                                                                                                                                                                                                             :mnesia_gvar,
                                                                                                                                                                                                                                                 :mnesia_stats,
                                                                                                                                                                                                                                                     :pg2_table,
                                                                                                                                                                                                                                                         :pg,
                                                                                                                                                                                                                                                             :queue,
                                                                                                                                                                                                                                                                 :schema,
                                                                                                                                                                                                                                                                     :shell_records,
                                                                                                                                                                                                                                                                         :snmp_agent_table,
                                                                                                                                                                                                                                                                             :snmp_local_db2,
                                                                                                                                                                                                                                                                                 :snmp_mib_data,
                                                                                                                                                                                                                                                                                     :snmp_note_store,
                                                                                                                                                                                                                                                                                         :snmp_symbolic_ets,
                                                                                                                                                                                                                                                                                             :tkFun,
                                                                                                                                                                                                                                                                                                 :tkLink,
                                                                                                                                                                                                                                                                                                     :tkPriv,
                                                                                                                                                                                                                                                                                                         :ttb,
                                                                                                                                                                                                                                                                                                             :ttb_history_table,
                                                                                                                                                                                                                                                                                                                 :udp_fds,
                                                                                                                                                                                                                                                                                                                     :udp_pids]
  end

  defp sys_processes() do
    [:auth, :code_server, :global_name_server, :inet_db,
                                                   :mnesia_recover, :net_kernel,
                                                                        :pg,
                                                                            :timer_server,
                                                                                :wxe_master]
  end

  defp mnesia_tables() do
    [:ir_AliasDef, :ir_ArrayDef, :ir_AttributeDef,
                                     :ir_ConstantDef, :ir_Contained,
                                                          :ir_Container,
                                                              :ir_EnumDef,
                                                                  :ir_ExceptionDef,
                                                                      :ir_IDLType,
                                                                          :ir_IRObject,
                                                                              :ir_InterfaceDef,
                                                                                  :ir_ModuleDef,
                                                                                      :ir_ORB,
                                                                                          :ir_OperationDef,
                                                                                              :ir_PrimitiveDef,
                                                                                                  :ir_Repository,
                                                                                                      :ir_SequenceDef,
                                                                                                          :ir_StringDef,
                                                                                                              :ir_StructDef,
                                                                                                                  :ir_TypedefDef,
                                                                                                                      :ir_UnionDef,
                                                                                                                          :logTable,
                                                                                                                              :logTransferTable,
                                                                                                                                  :mesh_meas,
                                                                                                                                      :mesh_type,
                                                                                                                                          :mnesia_clist,
                                                                                                                                              :orber_CosNaming,
                                                                                                                                                  :orber_objkeys,
                                                                                                                                                      :user]
  end

  defp ignore(true, reason) do
    throw(reason)
  end

  defp ignore(_, _) do
    :ok
  end

  defp f(f, a) do
    :lists.flatten(:io_lib.format(f, a))
  end

end