defmodule :m_gen do
  use Bitwise
  def start(genMod, linkP, name, mod, args, options) do
    case (where(name)) do
      :undefined ->
        do_spawn(genMod, linkP, name, mod, args, options)
      pid ->
        {:error, {:already_started, pid}}
    end
  end

  def start(genMod, linkP, mod, args, options) do
    do_spawn(genMod, linkP, mod, args, options)
  end

  defp do_spawn(genMod, :link, mod, args, options) do
    time = timeout(options)
    :proc_lib.start_link(:gen, :init_it,
                           [genMod, self(), self(), mod, args, options], time,
                           spawn_opts(options))
  end

  defp do_spawn(genMod, :monitor, mod, args, options) do
    time = timeout(options)
    ret = :proc_lib.start_monitor(:gen, :init_it,
                                    [genMod, self(), self(), mod, args,
                                                                      options],
                                    time, spawn_opts(options))
    monitor_return(ret)
  end

  defp do_spawn(genMod, _, mod, args, options) do
    time = timeout(options)
    :proc_lib.start(:gen, :init_it,
                      [genMod, self(), :self, mod, args, options], time,
                      spawn_opts(options))
  end

  defp do_spawn(genMod, :link, name, mod, args, options) do
    time = timeout(options)
    :proc_lib.start_link(:gen, :init_it,
                           [genMod, self(), self(), name, mod, args, options],
                           time, spawn_opts(options))
  end

  defp do_spawn(genMod, :monitor, name, mod, args, options) do
    time = timeout(options)
    ret = :proc_lib.start_monitor(:gen, :init_it,
                                    [genMod, self(), self(), name, mod, args,
                                                                            options],
                                    time, spawn_opts(options))
    monitor_return(ret)
  end

  defp do_spawn(genMod, _, name, mod, args, options) do
    time = timeout(options)
    :proc_lib.start(:gen, :init_it,
                      [genMod, self(), :self, name, mod, args, options], time,
                      spawn_opts(options))
  end

  defp monitor_return({{:ok, pid}, mon}) when (is_pid(pid) and
                                     is_reference(mon)) do
    {:ok, {pid, mon}}
  end

  defp monitor_return({error, mon}) when is_reference(mon) do
    receive do
      {:DOWN, ^mon, :process, _Pid, _Reason} ->
        :ok
    end
    error
  end

  def init_it(genMod, starter, parent, mod, args, options) do
    init_it2(genMod, starter, parent, self(), mod, args,
               options)
  end

  def init_it(genMod, starter, parent, name, mod, args,
           options) do
    case (register_name(name)) do
      true ->
        init_it2(genMod, starter, parent, name, mod, args,
                   options)
      {false, pid} ->
        :proc_lib.init_fail(starter,
                              {:error, {:already_started, pid}},
                              {:exit, :normal})
    end
  end

  defp init_it2(genMod, starter, parent, name, mod, args,
            options) do
    genMod.init_it(starter, parent, name, mod, args,
                     options)
  end

  def call(process, label, request) do
    call(process, label, request, 5000)
  end

  def call(process, label, request, timeout)
      when (is_pid(process) and
              timeout === :infinity or is_integer(timeout) and timeout >= 0) do
    do_call(process, label, request, timeout)
  end

  def call(process, label, request, timeout)
      when timeout === :infinity or
             (is_integer(timeout) and timeout >= 0) do
    fun = fn pid ->
               do_call(pid, label, request, timeout)
          end
    do_for_proc(process, fun)
  end

  defp do_call(process, _Label, _Request, _Timeout)
      when process === self() do
    exit(:calling_self)
  end

  defp do_call(process, label, request, :infinity)
      when is_pid(process) and node(process) == node() or :erlang.element(2,
                                                                            process) == node() and is_atom(:erlang.element(1,
                                                                                                                             process)) and tuple_size(process) === 2 do
    mref = :erlang.monitor(:process, process)
    send(process, {label, {self(), mref}, request})
    receive do
      {^mref, reply} ->
        :erlang.demonitor(mref, [:flush])
        {:ok, reply}
      {:DOWN, ^mref, _, _, reason} ->
        exit(reason)
    end
  end

  defp do_call(process, label, request, timeout)
      when is_atom(process) === false do
    mref = :erlang.monitor(:process, process,
                             [{:alias, :demonitor}])
    tag = [:alias | mref]
    :erlang.send(process, {label, {self(), tag}, request},
                   [:noconnect])
    receive do
      {[:alias | ^mref], reply} ->
        :erlang.demonitor(mref, [:flush])
        {:ok, reply}
      {:DOWN, ^mref, _, _, :noconnection} ->
        node = get_node(process)
        exit({:nodedown, node})
      {:DOWN, ^mref, _, _, reason} ->
        exit(reason)
    after timeout ->
      :erlang.demonitor(mref, [:flush])
      receive do
        {[:alias | ^mref], reply} ->
          {:ok, reply}
      after 0 ->
        exit(:timeout)
      end
    end
  end

  defp get_node(process) do
    case (process) do
      {_S, n} when is_atom(n) ->
        n
      _ when is_pid(process) ->
        node(process)
    end
  end

  def send_request(process, tag, request) when is_pid(process) do
    do_send_request(process, tag, request)
  end

  def send_request(process, tag, request) do
    fun = fn pid ->
               do_send_request(pid, tag, request)
          end
    try do
      do_for_proc(process, fun)
    catch
      :exit, reason ->
        mref = :erlang.make_ref()
        send(self(), {:DOWN, mref, :process, process, reason})
        mref
    end
  end

  def send_request(process, tag, request, label, reqIdCol)
      when is_map(reqIdCol) do
    :maps.put(send_request(process, tag, request), label,
                reqIdCol)
  end

  defp do_send_request(process, tag, request) do
    reqId = :erlang.monitor(:process, process,
                              [{:alias, :demonitor}])
    _ = :erlang.send(process,
                       {tag, {self(), [:alias | reqId]}, request},
                       [:noconnect])
    reqId
  end

  def unquote(:"@wait_response_recv_opt")(process, tag, request) do
    _ = wait_response(send_request(process, tag, request),
                        :infinity)
    _ = receive_response(send_request(process, tag,
                                        request),
                           :infinity)
    :ok
  end

  def wait_response(reqId, timeout) do
    tMO = timeout_value(timeout)
    receive do
      {[:alias | ^reqId], reply} ->
        :erlang.demonitor(reqId, [:flush])
        {:reply, reply}
      {:DOWN, ^reqId, _, object, reason} ->
        {:error, {reason, object}}
    after tMO ->
      :timeout
    end
  end

  def wait_response(reqIdCol, timeout, delete)
      when (map_size(reqIdCol) == 0 and is_boolean(delete)) do
    _ = timeout_value(timeout)
    :no_request
  end

  def wait_response(reqIdCol, timeout, delete)
      when (is_map(reqIdCol) and is_boolean(delete)) do
    tMO = timeout_value(timeout)
    receive do
      {[:alias | reqId], _} = msg
          when :erlang.is_map_key(reqId, reqIdCol) ->
        collection_result(msg, reqIdCol, delete)
      {:DOWN, reqId, _, _, _} = msg
          when :erlang.is_map_key(reqId, reqIdCol) ->
        collection_result(msg, reqIdCol, delete)
    after tMO ->
      :timeout
    end
  end

  def receive_response(reqId, timeout) do
    tMO = timeout_value(timeout)
    receive do
      {[:alias | ^reqId], reply} ->
        :erlang.demonitor(reqId, [:flush])
        {:reply, reply}
      {:DOWN, ^reqId, _, object, reason} ->
        {:error, {reason, object}}
    after tMO ->
      :erlang.demonitor(reqId, [:flush])
      receive do
        {[:alias | ^reqId], reply} ->
          {:reply, reply}
      after 0 ->
        :timeout
      end
    end
  end

  def receive_response(reqIdCol, timeout, delete)
      when (map_size(reqIdCol) == 0 and is_boolean(delete)) do
    _ = timeout_value(timeout)
    :no_request
  end

  def receive_response(reqIdCol, timeout, delete)
      when (is_map(reqIdCol) and is_boolean(delete)) do
    tMO = timeout_value(timeout)
    receive do
      {[:alias | reqId], _} = msg
          when :erlang.is_map_key(reqId, reqIdCol) ->
        collection_result(msg, reqIdCol, delete)
      {:DOWN, mref, _, _, _} = msg
          when :erlang.is_map_key(mref, reqIdCol) ->
        collection_result(msg, reqIdCol, delete)
    after tMO ->
      :maps.foreach(fn reqId, _Label when is_reference(reqId)
                                          ->
                         :erlang.demonitor(reqId, [:flush])
                       _, _ ->
                         :erlang.error(:badarg)
                    end,
                      reqIdCol)
      flush_responses(reqIdCol)
      :timeout
    end
  end

  def check_response(msg, reqId) when is_reference(reqId) do
    case (msg) do
      {[:alias | ^reqId], reply} ->
        :erlang.demonitor(reqId, [:flush])
        {:reply, reply}
      {:DOWN, ^reqId, _, object, reason} ->
        {:error, {reason, object}}
      _ ->
        :no_reply
    end
  end

  def check_response(_, _) do
    :erlang.error(:badarg)
  end

  def check_response(_Msg, reqIdCol, delete)
      when (map_size(reqIdCol) == 0 and is_boolean(delete)) do
    :no_request
  end

  def check_response(msg, reqIdCol, delete) when (is_map(reqIdCol) and
                                        is_boolean(delete)) do
    case (msg) do
      {[:alias | reqId], _} = ^msg
          when :erlang.is_map_key(reqId, reqIdCol) ->
        collection_result(msg, reqIdCol, delete)
      {:DOWN, mref, _, _, _} = ^msg
          when :erlang.is_map_key(mref, reqIdCol) ->
        collection_result(msg, reqIdCol, delete)
      _ ->
        :no_reply
    end
  end

  defp collection_result({[:alias | reqId], reply}, reqIdCol, delete) do
    _ = :erlang.demonitor(reqId, [:flush])
    collection_result({:reply, reply}, reqId, reqIdCol,
                        delete)
  end

  defp collection_result({:DOWN, reqId, _, object, reason}, reqIdCol,
            delete) do
    collection_result({:error, {reason, object}}, reqId,
                        reqIdCol, delete)
  end

  defp collection_result(resp, reqId, reqIdCol, false) do
    {resp, :maps.get(reqId, reqIdCol), reqIdCol}
  end

  defp collection_result(resp, reqId, reqIdCol, true) do
    {label, newReqIdCol} = :maps.take(reqId, reqIdCol)
    {resp, label, newReqIdCol}
  end

  defp flush_responses(reqIdCol) do
    receive do
      {[:alias | mref], _Reply} when :erlang.is_map_key(mref,
                                                          reqIdCol)
                                     ->
        flush_responses(reqIdCol)
    after 0 ->
      :ok
    end
  end

  defp timeout_value(:infinity) do
    :infinity
  end

  defp timeout_value(timeout) when (0 <= timeout and
                           timeout <= 4294967295) do
    timeout
  end

  defp timeout_value({:abs, timeout}) when is_integer(timeout) do
    case (timeout - :erlang.monotonic_time(:millisecond)) do
      tMO when tMO < 0 ->
        0
      tMO when tMO > 4294967295 ->
        :erlang.error(:badarg)
      tMO ->
        tMO
    end
  end

  defp timeout_value(_) do
    :erlang.error(:badarg)
  end

  def reqids_new() do
    :maps.new()
  end

  def reqids_size(reqIdCol) when is_map(reqIdCol) do
    :maps.size(reqIdCol)
  end

  def reqids_size(_) do
    :erlang.error(:badarg)
  end

  def reqids_add(reqId, _, reqIdCol) when (is_reference(reqId) and
                                     :erlang.is_map_key(reqId, reqIdCol)) do
    :erlang.error(:badarg)
  end

  def reqids_add(reqId, label, reqIdCol)
      when (is_reference(reqId) and is_map(reqIdCol)) do
    :maps.put(reqId, label, reqIdCol)
  end

  def reqids_add(_, _, _) do
    :erlang.error(:badarg)
  end

  def reqids_to_list(reqIdCol) when is_map(reqIdCol) do
    :maps.to_list(reqIdCol)
  end

  def reqids_to_list(_) do
    :erlang.error(:badarg)
  end

  def reply({_To, [:alias | alias] = tag}, reply)
      when is_reference(alias) do
    send(alias, {tag, reply})
    :ok
  end

  def reply({_To, [[:alias | alias] | _] = tag}, reply)
      when is_reference(alias) do
    send(alias, {tag, reply})
    :ok
  end

  def reply({to, tag}, reply) do
    try do
      send(to, {tag, reply})
      :ok
    catch
      _, _ ->
        :ok
    end
  end

  def stop(process) do
    stop(process, :normal, :infinity)
  end

  def stop(process, reason, timeout)
      when timeout === :infinity or
             (is_integer(timeout) and timeout >= 0) do
    fun = fn pid ->
               :proc_lib.stop(pid, reason, timeout)
          end
    do_for_proc(process, fun)
  end

  defp do_for_proc(pid, fun) when is_pid(pid) do
    fun.(pid)
  end

  defp do_for_proc(name, fun) when is_atom(name) do
    case (:erlang.whereis(name)) do
      pid when is_pid(pid) ->
        fun.(pid)
      :undefined ->
        exit(:noproc)
    end
  end

  defp do_for_proc(process, fun)
      when tuple_size(process) == 2 and :erlang.element(1,
                                                          process) == :global or tuple_size(process) == 3 and :erlang.element(1,
                                                                                                                                process) == :via do
    case (where(process)) do
      pid when is_pid(pid) ->
        node = node(pid)
        try do
          fun.(pid)
        catch
          :exit, {:nodedown, ^node} ->
            exit(:noproc)
        end
      :undefined ->
        exit(:noproc)
    end
  end

  defp do_for_proc({name, node}, fun) when node === node() do
    do_for_proc(name, fun)
  end

  defp do_for_proc({_Name, node} = process, fun)
      when is_atom(node) do
    cond do
      node() === :nonode@nohost ->
        exit({:nodedown, node})
      true ->
        fun.(process)
    end
  end

  defp where({:global, name}) do
    :global.whereis_name(name)
  end

  defp where({:via, module, name}) do
    module.whereis_name(name)
  end

  defp where({:local, name}) do
    :erlang.whereis(name)
  end

  defp where(serverName) do
    :erlang.error(:badarg, [serverName])
  end

  defp register_name({:local, name} = lN) do
    try do
      :erlang.register(name, self())
    catch
      :error, _ ->
        {false, where(lN)}
    else
      true ->
        true
    end
  end

  defp register_name({:global, name} = gN) do
    case (:global.register_name(name, self())) do
      :yes ->
        true
      :no ->
        {false, where(gN)}
    end
  end

  defp register_name({:via, module, name} = gN) do
    case (module.register_name(name, self())) do
      :yes ->
        true
      :no ->
        {false, where(gN)}
    end
  end

  def name({:local, name}) do
    name
  end

  def name({:global, name}) do
    name
  end

  def name({:via, _, name}) do
    name
  end

  def name(pid) when is_pid(pid) do
    pid
  end

  def unregister_name({:local, name}) do
    try do
      :erlang.unregister(name)
    catch
      _, _ ->
        :ok
    else
      _ ->
        :ok
    end
  end

  def unregister_name({:global, name}) do
    _ = :global.unregister_name(name)
    :ok
  end

  def unregister_name({:via, mod, name}) do
    _ = mod.unregister_name(name)
    :ok
  end

  def unregister_name(pid) when is_pid(pid) do
    :ok
  end

  def get_proc_name(pid) when is_pid(pid) do
    pid
  end

  def get_proc_name({:local, name}) do
    case (:erlang.process_info(self(), :registered_name)) do
      {:registered_name, ^name} ->
        name
      {:registered_name, _Name} ->
        exit(:process_not_registered)
      [] ->
        exit(:process_not_registered)
    end
  end

  def get_proc_name({:global, name}) do
    case (:global.whereis_name(name)) do
      :undefined ->
        exit(:process_not_registered_globally)
      pid when pid === self() ->
        name
      _Pid ->
        exit(:process_not_registered_globally)
    end
  end

  def get_proc_name({:via, mod, name}) do
    case (mod.whereis_name(name)) do
      :undefined ->
        exit({:process_not_registered_via, mod})
      pid when pid === self() ->
        name
      _Pid ->
        exit({:process_not_registered_via, mod})
    end
  end

  def get_parent() do
    case (:erlang.get(:"$ancestors")) do
      [parent | _] when is_pid(parent) ->
        parent
      [parent | _] when is_atom(parent) ->
        name_to_pid(parent)
      _ ->
        exit(:process_was_not_started_by_proc_lib)
    end
  end

  defp name_to_pid(name) do
    case (:erlang.whereis(name)) do
      :undefined ->
        case (:global.whereis_name(name)) do
          :undefined ->
            exit(:could_not_find_registered_name)
          pid ->
            pid
        end
      pid ->
        pid
    end
  end

  defp timeout(options) do
    case (:lists.keyfind(:timeout, 1, options)) do
      {_, time} ->
        time
      false ->
        :infinity
    end
  end

  defp spawn_opts(options) do
    case (:lists.keyfind(:spawn_opt, 1, options)) do
      {_, opts} ->
        opts
      false ->
        []
    end
  end

  def hibernate_after(options) do
    case (:lists.keyfind(:hibernate_after, 1, options)) do
      {_, hibernateAfterTimeout} ->
        hibernateAfterTimeout
      false ->
        :infinity
    end
  end

  def debug_options(name, opts) do
    case (:lists.keyfind(:debug, 1, opts)) do
      {_, options} ->
        try do
          :sys.debug_options(options)
        catch
          _, _ ->
            :error_logger.format('~tp: ignoring erroneous debug options - ~tp~n', [name, options])
            []
        end
      false ->
        []
    end
  end

  def format_status_header(tagLine, pid) when is_pid(pid) do
    :lists.concat([tagLine, ' ', :erlang.pid_to_list(pid)])
  end

  def format_status_header(tagLine, regName) when is_atom(regName) do
    :lists.concat([tagLine, ' ', regName])
  end

  def format_status_header(tagLine, name) do
    {tagLine, name}
  end

  def format_status(mod, opt, status, args) do
    case ({:erlang.function_exported(mod, :format_status,
                                       1),
             :erlang.function_exported(mod, :format_status, 2)}) do
      {true, _} ->
        try do
          mod.format_status(status)
        catch
          _, _ ->
            Map.put(status, :EXIT, :erlang.atom_to_list(mod) ++ ':format_status/1 crashed')
        else
          newStatus when is_map(newStatus) ->
            mergedStatus = :maps.merge(status, newStatus)
            case (:maps.size(mergedStatus) === :maps.size(newStatus)) do
              true ->
                mergedStatus
              false ->
                Map.put(status, :EXIT, :erlang.atom_to_list(mod) ++ ':format_status/1 returned a map with unknown keys')
            end
          _ ->
            Map.put(status, :EXIT, :erlang.atom_to_list(mod) ++ ':format_status/1 did not return a map')
        end
      {false, true} when is_list(args) ->
        try do
          mod.format_status(opt, args)
        catch
          result ->
            Map.put(status, :"$status", result)
          _, _ ->
            Map.put(status, :EXIT, :erlang.atom_to_list(mod) ++ ':format_status/2 crashed')
        else
          result ->
            Map.put(status, :"$status", result)
        end
      {false, _} ->
        status
    end
  end

end