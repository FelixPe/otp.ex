defmodule :m_erpc do
  use Bitwise

  def call(n, fun) do
    call(n, fun, :infinity)
  end

  def call(n, fun, timeout) when is_function(fun, 0) do
    call(n, :erlang, :apply, [fun, []], timeout)
  end

  def call(_N, _Fun, _Timeout) do
    :erlang.error({:erpc, :badarg})
  end

  def call(n, m, f, a) do
    call(n, m, f, a, :infinity)
  end

  def call(n, m, f, a, :infinity)
      when node() === n and
             is_atom(m) and is_atom(f) and
             is_list(a) do
    try do
      {:return, return} = execute_call(m, f, a)
      return
    catch
      :exit, reason ->
        exit({:exception, reason})

      :error, reason ->
        case is_arg_error(reason, m, f, a) do
          true ->
            :erlang.error({:erpc, reason})

          false ->
            erpcStack = trim_stack(__STACKTRACE__, m, f, a)
            :erlang.error({:exception, reason, erpcStack})
        end
    end
  end

  def call(n, m, f, a, t)
      when is_atom(n) and
             is_atom(m) and is_atom(f) and is_list(a) do
    timeout = timeout_value(t)
    res = make_ref()

    reqId =
      :erlang.spawn_request(n, :erpc, :execute_call, [res, m, f, a], [
        {:reply, :error_only},
        :monitor
      ])

    receive do
      {:spawn_reply, ^reqId, :error, reason} ->
        result(:spawn_reply, reqId, res, reason)

      {:DOWN, ^reqId, :process, _Pid, reason} ->
        result(:down, reqId, res, reason)
    after
      timeout ->
        result(:timeout, reqId, res, :undefined)
    end
  end

  def call(_N, _M, _F, _A, _T) do
    :erlang.error({:erpc, :badarg})
  end

  def send_request(n, f) when is_atom(n) and is_function(f, 0) do
    send_request(n, :erlang, :apply, [f, []])
  end

  def send_request(_N, _F) do
    :erlang.error({:erpc, :badarg})
  end

  def send_request(n, m, f, a)
      when is_atom(n) and is_atom(m) and
             is_atom(f) and is_list(a) do
    res = make_ref()

    reqId =
      :erlang.spawn_request(n, :erpc, :execute_call, [res, m, f, a], [
        {:reply, :error_only},
        :monitor
      ])

    [res | reqId]
  end

  def send_request(n, f, l, c)
      when is_atom(n) and
             is_function(f, 0) and is_map(c) do
    send_request(n, :erlang, :apply, [f, []], l, c)
  end

  def send_request(_, _, _, _) do
    :erlang.error({:erpc, :badarg})
  end

  def send_request(n, m, f, a, l, c)
      when is_atom(n) and
             is_atom(m) and is_atom(f) and is_list(a) and
             is_map(c) do
    res = make_ref()

    reqId =
      :erlang.spawn_request(n, :erpc, :execute_call, [res, m, f, a], [
        {:reply, :error_only},
        :monitor
      ])

    :maps.put(reqId, [res | l], c)
  end

  def send_request(_N, _M, _F, _A, _L, _C) do
    :erlang.error({:erpc, :badarg})
  end

  def receive_response([res | reqId] = rId)
      when is_reference(res) and
             is_reference(reqId) do
    receive_response(rId, :infinity)
  end

  def receive_response(_) do
    :erlang.error({:erpc, :badarg})
  end

  def receive_response([res | reqId], tmo)
      when is_reference(res) and
             is_reference(reqId) do
    timeout = timeout_value(tmo)

    receive do
      {:spawn_reply, ^reqId, :error, reason} ->
        result(:spawn_reply, reqId, res, reason)

      {:DOWN, ^reqId, :process, _Pid, reason} ->
        result(:down, reqId, res, reason)
    after
      timeout ->
        result(:timeout, reqId, res, :undefined)
    end
  end

  def receive_response(_, _) do
    :erlang.error({:erpc, :badarg})
  end

  def receive_response(reqIdCol, wT, del)
      when map_size(reqIdCol) == 0 and is_boolean(del) do
    _ = timeout_value(wT)
    :no_request
  end

  def receive_response(reqIdCol, tmo, del)
      when is_map(reqIdCol) and
             is_boolean(del) do
    timeout = timeout_value(tmo)

    receive do
      {:spawn_reply, reqId, :error, reason}
      when :erlang.is_map_key(reqId, reqIdCol) and
             is_reference(reqId) ->
        collection_result(:spawn_reply, reqId, reason, reqIdCol, false, del)

      {:DOWN, reqId, :process, _Pid, reason}
      when :erlang.is_map_key(reqId, reqIdCol) and
             is_reference(reqId) ->
        collection_result(:down, reqId, reason, reqIdCol, false, del)
    after
      timeout ->
        collection_result(:timeout, :ok, :ok, reqIdCol, false, del)
    end
  end

  def receive_response(_, _, _) do
    :erlang.error({:erpc, :badarg})
  end

  def wait_response([res | reqId] = rId)
      when is_reference(res) and
             is_reference(reqId) do
    wait_response(rId, 0)
  end

  def wait_response(_) do
    :erlang.error({:erpc, :badarg})
  end

  def wait_response([res | reqId], wT)
      when is_reference(res) and
             is_reference(reqId) do
    timeout = timeout_value(wT)

    receive do
      {:spawn_reply, ^reqId, :error, reason} ->
        result(:spawn_reply, reqId, res, reason)

      {:DOWN, ^reqId, :process, _Pid, reason} ->
        {:response, result(:down, reqId, res, reason)}
    after
      timeout ->
        :no_response
    end
  end

  def wait_response(_, _) do
    :erlang.error({:erpc, :badarg})
  end

  def wait_response(reqIdCol, wT, del)
      when map_size(reqIdCol) == 0 and is_boolean(del) do
    _ = timeout_value(wT)
    :no_request
  end

  def wait_response(reqIdCol, wT, del)
      when is_map(reqIdCol) and
             is_boolean(del) do
    timeout = timeout_value(wT)

    receive do
      {:spawn_reply, reqId, :error, reason}
      when :erlang.is_map_key(reqId, reqIdCol) and
             is_reference(reqId) ->
        collection_result(:spawn_reply, reqId, reason, reqIdCol, true, del)

      {:DOWN, reqId, :process, _Pid, reason}
      when :erlang.is_map_key(reqId, reqIdCol) and
             is_reference(reqId) ->
        collection_result(:down, reqId, reason, reqIdCol, true, del)
    after
      timeout ->
        :no_response
    end
  end

  def wait_response(_, _, _) do
    :erlang.error({:erpc, :badarg})
  end

  def check_response(
        {:spawn_reply, reqId, :error, reason},
        [res | reqId]
      )
      when is_reference(res) and is_reference(reqId) do
    result(:spawn_reply, reqId, res, reason)
  end

  def check_response(
        {:DOWN, reqId, :process, _Pid, reason},
        [res | reqId]
      )
      when is_reference(res) and is_reference(reqId) do
    {:response, result(:down, reqId, res, reason)}
  end

  def check_response(_Msg, [res | reqId])
      when is_reference(res) and
             is_reference(reqId) do
    :no_response
  end

  def check_response(_, _) do
    :erlang.error({:erpc, :badarg})
  end

  def check_response(_Msg, reqIdCol, del)
      when map_size(reqIdCol) == 0 and is_boolean(del) do
    :no_request
  end

  def check_response({:spawn_reply, reqId, :error, reason}, reqIdCol, del)
      when is_reference(reqId) and
             :erlang.is_map_key(reqId, reqIdCol) and
             is_boolean(del) do
    collection_result(:spawn_reply, reqId, reason, reqIdCol, true, del)
  end

  def check_response({:DOWN, reqId, :process, _Pid, reason}, reqIdCol, del)
      when is_reference(reqId) and
             :erlang.is_map_key(reqId, reqIdCol) and
             is_boolean(del) do
    collection_result(:down, reqId, reason, reqIdCol, true, del)
  end

  def check_response(_Msg, reqIdCol, del)
      when is_map(reqIdCol) and
             is_boolean(del) do
    :no_response
  end

  def check_response(_, _, _) do
    :erlang.error({:erpc, :badarg})
  end

  def reqids_new() do
    :maps.new()
  end

  def reqids_size(reqIdCollection) do
    try do
      :maps.size(reqIdCollection)
    catch
      _, _ ->
        :erlang.error({:erpc, :badarg})
    end
  end

  def reqids_add([_ | reqId], _, reqIdCollection)
      when is_reference(reqId) and
             :erlang.is_map_key(reqId, reqIdCollection) do
    :erlang.error({:erpc, :badarg})
  end

  def reqids_add([res | reqId], label, reqIdCollection)
      when is_reference(res) and is_reference(reqId) and
             is_map(reqIdCollection) do
    :maps.put(reqId, [res | label], reqIdCollection)
  end

  def reqids_add(_, _, _) do
    :erlang.error({:erpc, :badarg})
  end

  def reqids_to_list(reqIdCollection) when is_map(reqIdCollection) do
    try do
      :maps.fold(
        fn
          reqId, [res | label], acc
          when is_reference(reqId) and is_reference(res) ->
            [{[res | reqId], label} | acc]

          _, _, _ ->
            throw(:badarg)
        end,
        [],
        reqIdCollection
      )
    catch
      :badarg ->
        :erlang.error({:erpc, :badarg})
    end
  end

  def reqids_to_list(_) do
    :erlang.error({:erpc, :badarg})
  end

  def multicall(ns, fun) do
    multicall(ns, fun, :infinity)
  end

  def multicall(ns, fun, timeout) when is_function(fun, 0) do
    multicall(ns, :erlang, :apply, [fun, []], timeout)
  end

  def multicall(_Ns, _Fun, _Timeout) do
    :erlang.error({:erpc, :badarg})
  end

  def multicall(ns, m, f, a) do
    multicall(ns, m, f, a, :infinity)
  end

  def multicall(ns, m, f, a, t) do
    try do
      true = is_atom(m)
      true = is_atom(f)
      true = is_list(a)
      tag = make_ref()
      timeout = timeout_value(t)
      sendState = mcall_send_requests(tag, ns, m, f, a, timeout)
      mcall_receive_replies(tag, sendState)
    catch
      :error, notIErr when notIErr != :internal_error ->
        :erlang.error({:erpc, :badarg})
    end
  end

  def multicast(n, fun) do
    multicast(n, :erlang, :apply, [fun, []])
  end

  def multicast(nodes, mod, fun, args) do
    try do
      true = is_atom(mod)
      true = is_atom(fun)
      true = is_list(args)
      multicast_send_requests(nodes, mod, fun, args)
    catch
      :error, _ ->
        :erlang.error({:erpc, :badarg})
    end
  end

  defp multicast_send_requests([], _Mod, _Fun, _Args) do
    :ok
  end

  defp multicast_send_requests([node | nodes], mod, fun, args) do
    _ = :erlang.spawn_request(node, :erpc, :execute_cast, [mod, fun, args], [{:reply, :no}])
    multicast_send_requests(nodes, mod, fun, args)
  end

  def cast(n, fun) do
    cast(n, :erlang, :apply, [fun, []])
  end

  def cast(node, mod, fun, args)
      when is_atom(node) and
             is_atom(mod) and is_atom(fun) and
             is_list(args) do
    _ = :erlang.spawn_request(node, :erpc, :execute_cast, [mod, fun, args], [{:reply, :no}])
    :ok
  end

  def cast(_Node, _Mod, _Fun, _Args) do
    :erlang.error({:erpc, :badarg})
  end

  def execute_call(ref, m, f, a) do
    reply =
      try do
        {ref, :return, apply(m, f, a)}
      catch
        reason ->
          {ref, :throw, reason}

        :exit, reason ->
          {ref, :exit, reason}

        :error, reason ->
          case is_arg_error(reason, m, f, a) do
            true ->
              {ref, :error, {:erpc, reason}}

            false ->
              erpcStack = trim_stack(__STACKTRACE__, m, f, a)
              {ref, :error, reason, erpcStack}
          end
      end

    exit(reply)
  end

  def execute_call(m, f, a) do
    {:return, apply(m, f, a)}
  end

  def execute_cast(m, f, a) do
    try do
      apply(m, f, a)
    catch
      :error, reason ->
        case is_arg_error(reason, m, f, a) do
          true ->
            :erlang.error({:erpc, reason})

          false ->
            erpcStack = trim_stack(__STACKTRACE__, m, f, a)
            :erlang.error({:exception, {reason, erpcStack}})
        end
    end
  end

  def call_result(type, reqId, res, reason) do
    result(type, reqId, res, reason)
  end

  def is_arg_error(:system_limit, _M, _F, a) do
    try do
      apply(:erpc, :nonexisting, a)
      false
    catch
      :error, :system_limit ->
        true

      _, _ ->
        false
    end
  end

  def is_arg_error(_R, _M, _F, _A) do
    false
  end

  def trim_stack([cF | _], m, f, a)
      when :erlang.element(
             1,
             cF
           ) == :erpc and
             (:erlang.element(
                2,
                cF
              ) == :execute_call or
                :erlang.element(
                  2,
                  cF
                ) == :execute_cast) do
    [{m, f, a, []}]
  end

  def trim_stack([{m, f, a, _} = sF, cF | _], m, f, a)
      when :erlang.element(
             1,
             cF
           ) == :erpc and
             (:erlang.element(
                2,
                cF
              ) == :execute_call or
                :erlang.element(
                  2,
                  cF
                ) == :execute_cast) do
    [sF]
  end

  def trim_stack(s, m, f, a) do
    try do
      trim_stack_aux(s, m, f, a)
    catch
      :use_all ->
        s
    end
  end

  defp trim_stack_aux([], _M, _F, _A) do
    throw(:use_all)
  end

  defp trim_stack_aux([{m, f, aL, _} = sF, cF | _], m, f, a)
       when :erlang.element(
              1,
              cF
            ) == :erpc and
              (:erlang.element(
                 2,
                 cF
               ) == :execute_call or
                 :erlang.element(
                   2,
                   cF
                 ) == :execute_cast) and
              aL == length(a) do
    [sF]
  end

  defp trim_stack_aux([cF | _], m, f, a)
       when :erlang.element(
              1,
              cF
            ) == :erpc and
              (:erlang.element(
                 2,
                 cF
               ) == :execute_call or
                 :erlang.element(
                   2,
                   cF
                 ) == :execute_cast) do
    try do
      [{m, f, length(a), []}]
    catch
      _, _ ->
        []
    end
  end

  defp trim_stack_aux([sF | sFs], m, f, a) do
    [sF | trim_stack_aux(sFs, m, f, a)]
  end

  defp call_abandon(reqId) do
    case :erlang.spawn_request_abandon(reqId) do
      true ->
        true

      false ->
        :erlang.demonitor(reqId, [:info])
    end
  end

  defp result(:down, _ReqId, res, {res, :return, return}) do
    return
  end

  defp result(:down, _ReqId, res, {res, :throw, throw}) do
    throw(throw)
  end

  defp result(:down, _ReqId, res, {res, :exit, exit}) do
    exit({:exception, exit})
  end

  defp result(:down, _ReqId, res, {res, :error, error, stack}) do
    :erlang.error({:exception, error, stack})
  end

  defp result(:down, _ReqId, res, {res, :error, {:erpc, _} = erpcErr}) do
    :erlang.error(erpcErr)
  end

  defp result(:down, _ReqId, _Res, :noconnection) do
    :erlang.error({:erpc, :noconnection})
  end

  defp result(:down, _ReqId, _Res, reason) do
    exit({:signal, reason})
  end

  defp result(:spawn_reply, _ReqId, _Res, reason) do
    :erlang.error({:erpc, reason})
  end

  defp result(:timeout, reqId, res, _Reason) do
    case call_abandon(reqId) do
      true ->
        :erlang.error({:erpc, :timeout})

      false ->
        receive do
          {:spawn_reply, ^reqId, :error, reason} ->
            result(:spawn_reply, reqId, res, reason)

          {:DOWN, ^reqId, :process, _Pid, reason} ->
            result(:down, reqId, res, reason)
        after
          0 ->
            :erlang.error({:erpc, :badarg})
        end
    end
  end

  defp collection_result(:timeout, _, _, reqIdCollection, _, _) do
    abandon = fn
      reqId, [res | _Label]
      when is_reference(reqId) and is_reference(res) ->
        case call_abandon(reqId) do
          true ->
            :ok

          false ->
            receive do
              {:spawn_reply, ^reqId, :error, _} ->
                :ok

              {:DOWN, ^reqId, :process, _, _} ->
                :ok
            after
              0 ->
                :ok
            end
        end

      _, _ ->
        throw(:badarg)
    end

    try do
      :maps.foreach(abandon, reqIdCollection)
    catch
      :badarg ->
        :erlang.error({:erpc, :badarg})
    end

    :erlang.error({:erpc, :timeout})
  end

  defp collection_result(type, reqId, resultReason, reqIdCol, wrapResponse, delete) do
    reqIdInfo =
      case delete do
        true ->
          :maps.take(reqId, reqIdCol)

        false ->
          {:maps.get(reqId, reqIdCol), reqIdCol}
      end

    case reqIdInfo do
      {[res | label], newReqIdCol} when is_reference(res) ->
        try do
          result = result(type, reqId, res, resultReason)

          response =
            cond do
              wrapResponse ->
                {:response, result}

              true ->
                result
            end

          {response, label, newReqIdCol}
        catch
          class, reason ->
            apply(:erlang, class, [{reason, label, newReqIdCol}])
        end

      _ ->
        :erlang.error({:erpc, :badarg})
    end
  end

  defp timeout_value(:infinity) do
    :infinity
  end

  defp timeout_value(timeout)
       when is_integer(timeout) and 0 <= timeout and timeout <= 4_294_967_295 do
    timeout
  end

  defp timeout_value({:abs, timeout}) when is_integer(timeout) do
    case timeout - :erlang.monotonic_time(:millisecond) do
      tMO when tMO < 0 ->
        0

      tMO when tMO > 4_294_967_295 ->
        :erlang.error({:erpc, :badarg})

      tMO ->
        tMO
    end
  end

  defp timeout_value(_) do
    :erlang.error({:erpc, :badarg})
  end

  defp deadline(:infinity) do
    :infinity
  end

  defp deadline(4_294_967_295) do
    :erlang.convert_time_unit(
      :erlang.monotonic_time(:millisecond) + 4_294_967_295,
      :millisecond,
      :native
    )
  end

  defp deadline(t)
       when is_integer(t) and 0 <= t and t <= 4_294_967_295 do
    now = :erlang.monotonic_time()
    nativeTmo = :erlang.convert_time_unit(t, :millisecond, :native)
    now + nativeTmo
  end

  defp time_left(:infinity) do
    :infinity
  end

  defp time_left(:expired) do
    0
  end

  defp time_left(deadline) do
    case deadline - :erlang.monotonic_time() do
      timeLeft when timeLeft <= 0 ->
        0

      timeLeft ->
        :erlang.convert_time_unit(timeLeft - 1, :native, :millisecond) + 1
    end
  end

  defp mcall_local_call(m, f, a) do
    try do
      {:return, return} = execute_call(m, f, a)
      {:ok, return}
    catch
      thrown ->
        {:throw, thrown}

      :exit, reason ->
        {:exit, {:exception, reason}}

      :error, reason ->
        case is_arg_error(reason, m, f, a) do
          true ->
            {:error, {:erpc, reason}}

          false ->
            erpcStack = trim_stack(__STACKTRACE__, m, f, a)
            {:error, {:exception, reason, erpcStack}}
        end
    end
  end

  defp mcall_send_request(t, n, m, f, a)
       when is_reference(t) and
              is_atom(n) and is_atom(m) and is_atom(f) and
              is_list(a) do
    :erlang.spawn_request(n, :erpc, :execute_call, [t, m, f, a], [
      {:reply, :error_only},
      {:reply_tag, t},
      {:monitor, [{:tag, t}]}
    ])
  end

  defp mcall_send_requests(tag, ns, m, f, a, tmo) do
    dL = deadline(tmo)
    mcall_send_requests(tag, ns, m, f, a, [], dL, :undefined, 0)
  end

  defp mcall_send_requests(_Tag, [], m, f, a, rIDs, dL, :local_call, nRs) do
    lRes = mcall_local_call(m, f, a)
    {:ok, rIDs, %{local_call: lRes}, nRs, dL}
  end

  defp mcall_send_requests(_Tag, [], _M, _F, _A, rIDs, dL, _LC, nRs) do
    {:ok, rIDs, %{}, nRs, dL}
  end

  defp mcall_send_requests(tag, [n | ns], m, f, a, rIDs, :infinity, :undefined, nRs)
       when n == node() do
    mcall_send_requests(tag, ns, m, f, a, [:local_call | rIDs], :infinity, :local_call, nRs)
  end

  defp mcall_send_requests(tag, [n | ns], m, f, a, rIDs, dL, lC, nRs) do
    try do
      mcall_send_request(tag, n, m, f, a)
    catch
      _, _ ->
        {:badarg, rIDs, %{}, nRs, :expired}
    else
      rID ->
        mcall_send_requests(tag, ns, m, f, a, [rID | rIDs], dL, lC, nRs + 1)
    end
  end

  defp mcall_send_requests(_Tag, _Ns, _M, _F, _A, rIDs, _DL, _LC, nRs) do
    {:badarg, rIDs, %{}, nRs, :expired}
  end

  defp mcall_receive_replies(tag, {sendRes, rIDs, rpls, nRs, dL}) do
    resRpls = mcall_receive_replies(tag, rIDs, rpls, nRs, dL)

    cond do
      sendRes != :ok ->
        :erlang.error(sendRes)

      true ->
        mcall_map_replies(rIDs, resRpls, [])
    end
  end

  defp mcall_receive_replies(_Tag, _ReqIds, rpls, 0, _DL) do
    rpls
  end

  defp mcall_receive_replies(tag, reqIDs, rpls, nRs, dL) do
    tmo = time_left(dL)

    receive do
      {^tag, reqId, :error, reason} ->
        res = mcall_result(:spawn_reply, reqId, tag, reason)
        mcall_receive_replies(tag, reqIDs, Map.put(rpls, reqId, res), nRs - 1, dL)

      {^tag, reqId, :process, _Pid, reason} ->
        res = mcall_result(:down, reqId, tag, reason)
        mcall_receive_replies(tag, reqIDs, Map.put(rpls, reqId, res), nRs - 1, dL)
    after
      tmo ->
        cond do
          reqIDs == [] ->
            rpls

          true ->
            newNRs = mcall_abandon(tag, reqIDs, rpls, nRs)
            mcall_receive_replies(tag, [], rpls, newNRs, :expired)
        end
    end
  end

  defp mcall_result(resType, reqId, tag, resultReason) do
    try do
      {:ok, result(resType, reqId, tag, resultReason)}
    catch
      class, reason ->
        {class, reason}
    end
  end

  defp mcall_abandon(_Tag, [], _Rpls, nRs) do
    nRs
  end

  defp mcall_abandon(tag, [:local_call | rIDs], rpls, nRs) do
    mcall_abandon(tag, rIDs, rpls, nRs)
  end

  defp mcall_abandon(tag, [rID | rIDs], rpls, nRs) do
    newNRs =
      case :maps.is_key(rID, rpls) do
        true ->
          nRs

        false ->
          case call_abandon(rID) do
            true ->
              nRs - 1

            false ->
              nRs
          end
      end

    mcall_abandon(tag, rIDs, rpls, newNRs)
  end

  defp mcall_map_replies([], _Rpls, res) do
    res
  end

  defp mcall_map_replies([rID | rIDs], rpls, res) do
    timeout = {:error, {:erpc, :timeout}}
    mcall_map_replies(rIDs, rpls, [:maps.get(rID, rpls, timeout) | res])
  end
end
