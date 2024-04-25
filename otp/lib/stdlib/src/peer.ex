defmodule :m_peer do
  use Bitwise
  @author "maximfca@gmail.com"
  @behaviour :gen_server
  def random_name() do
    random_name(~c"peer")
  end

  def random_name(prefix) do
    osPid = :os.getpid()
    uniq = :erlang.unique_integer([:positive])
    :lists.concat([prefix, ~c"-", uniq, ~c"-", osPid])
  end

  def start_link() do
    start_link(%{name: random_name()})
  end

  def start_link(options) do
    start_it(options, :start_link)
  end

  def start(options) do
    start_it(options, :start)
  end

  def stop(dest) do
    :gen_server.stop(dest)
  end

  def get_state(dest) do
    :gen_server.call(dest, :get_state)
  end

  def call(dest, m, f, a) do
    call(dest, m, f, a, 5000)
  end

  def call(dest, m, f, a, timeout) do
    case :gen_server.call(dest, {:call, m, f, a}, timeout) do
      {:ok, reply} ->
        reply

      {class, {reason, stack}} ->
        :erlang.raise(class, reason, stack)

      {:error, reason} ->
        :erlang.error(reason)
    end
  end

  def cast(dest, m, f, a) do
    :gen_server.cast(dest, {:cast, m, f, a})
  end

  def send(dest, to, message) do
    :gen_server.cast(dest, {:send, to, message})
  end

  require Record

  Record.defrecord(:r_peer_state, :peer_state,
    options: :undefined,
    node: :undefined,
    exec: :undefined,
    args: :undefined,
    connection: :undefined,
    listen_socket: :undefined,
    stdio: <<>>,
    peer_state: :booting,
    notify: false,
    seq: 0,
    outstanding: %{}
  )

  def init([notify, options]) do
    :erlang.process_flag(:trap_exit, true)
    {listenSocket, listen} = maybe_listen(options)
    {exec, args} = command_line(listen, options)
    env = :maps.get(:env, options, [])

    postProcessArgs =
      :maps.get(:post_process_args, options, fn as ->
        as
      end)

    finalArgs = postProcessArgs.(args)

    conn =
      case :maps.find(:connection, options) do
        {:ok, :standard_io} ->
          :erlang.open_port(
            {:spawn_executable, exec},
            [{:args, finalArgs}, {:env, env}, :hide, :binary, :exit_status, :stderr_to_stdout]
          )

        _ ->
          port =
            :erlang.open_port(
              {:spawn_executable, exec},
              [{:args, finalArgs}, {:env, env}, :hide, :binary]
            )

          try do
            :erlang.port_close(port)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end

          receive do
            {:EXIT, ^port, _} ->
              :undefined
          end
      end

    saveOptions =
      case :maps.find(:shutdown, options) do
        {:ok, :halt} ->
          :maps.remove(:shutdown, options)

        _ ->
          options
      end

    state = r_peer_state(options: saveOptions, notify: notify, args: args, exec: exec)

    cond do
      listenSocket === :undefined ->
        {:ok, r_peer_state(state, connection: conn)}

      true ->
        _ = :prim_inet.async_accept(listenSocket, 60000)
        {:ok, r_peer_state(state, listen_socket: listenSocket)}
    end
  end

  def handle_call({:call, _M, _F, _A}, _From, r_peer_state(connection: :undefined) = state) do
    {:reply, {:error, :noconnection}, state}
  end

  def handle_call(
        {:call, m, f, a},
        from,
        r_peer_state(
          connection: port,
          options: %{connection: :standard_io},
          outstanding: out,
          seq: seq
        ) = state
      ) do
    origin_to_peer(:port, port, {:call, seq, m, f, a})

    {:noreply,
     r_peer_state(state,
       outstanding: Map.put(out, seq, from),
       seq: seq + 1
     )}
  end

  def handle_call(
        {:call, m, f, a},
        from,
        r_peer_state(connection: socket, outstanding: out, seq: seq) = state
      ) do
    origin_to_peer(:tcp, socket, {:call, seq, m, f, a})

    {:noreply,
     r_peer_state(state,
       outstanding: Map.put(out, seq, from),
       seq: seq + 1
     )}
  end

  def handle_call({:starting, node}, _From, r_peer_state(options: options) = state) do
    case :maps.find(:shutdown, options) do
      {:ok, {timeout, mainCoverNode}}
      when is_integer(timeout) and is_atom(mainCoverNode) ->
        modules = :erpc.call(mainCoverNode, :cover, :modules, [])

        sticky =
          for m <- modules,
              :erpc.call(node, :code, :is_sticky, [m]) do
            :erpc.call(node, :code, :unstick_mod, [m])
            m
          end

        _ = :erpc.call(mainCoverNode, :cover, :start, [node])

        _ =
          for m <- sticky do
            :erpc.call(node, :code, :stick_mod, [m])
          end

        :ok

      _ ->
        :ok
    end

    {:reply, :ok, state}
  end

  def handle_call(:get_node, _From, r_peer_state(node: node) = state) do
    {:reply, node, state}
  end

  def handle_call(:get_state, _From, r_peer_state(peer_state: peerState) = state) do
    {:reply, peerState, state}
  end

  def handle_call(:group_leader, _From, state) do
    {:reply, :erlang.group_leader(), state}
  end

  def handle_cast(
        {:cast, _M, _F, _A},
        r_peer_state(connection: :undefined) = state
      ) do
    {:noreply, state}
  end

  def handle_cast(
        {:cast, m, f, a},
        r_peer_state(
          connection: port,
          options: %{connection: :standard_io}
        ) = state
      ) do
    origin_to_peer(:port, port, {:cast, m, f, a})
    {:noreply, state}
  end

  def handle_cast(
        {:cast, m, f, a},
        r_peer_state(connection: socket) = state
      ) do
    origin_to_peer(:tcp, socket, {:cast, m, f, a})
    {:noreply, state}
  end

  def handle_cast(
        {:send, _Dest, _Message},
        r_peer_state(connection: :undefined) = state
      ) do
    {:noreply, state}
  end

  def handle_cast(
        {:send, dest, message},
        r_peer_state(
          connection: port,
          options: %{connection: :standard_io}
        ) = state
      ) do
    origin_to_peer(:port, port, {:message, dest, message})
    {:noreply, state}
  end

  def handle_cast(
        {:send, dest, message},
        r_peer_state(connection: socket) = state
      ) do
    origin_to_peer(:tcp, socket, {:message, dest, message})
    {:noreply, state}
  end

  def handle_info(
        {:tcp, socket, socketData},
        r_peer_state(connection: socket) = state
      ) do
    :ok = :inet.setopts(socket, [{:active, :once}])
    {:noreply, handle_alternative_data(:tcp, :erlang.binary_to_term(socketData), state)}
  end

  def handle_info(
        {port, {:data, portData}},
        r_peer_state(connection: port, stdio: prevBin) = state
      ) do
    {str, newBin} = decode_port_data(portData, <<>>, prevBin)
    str !== <<>> and :io.put_chars(str)
    {:noreply, handle_port_binary(newBin, state)}
  end

  def handle_info(
        {:inet_async, lSock, _Ref, {:ok, cliSocket}},
        r_peer_state(listen_socket: lSock) = state
      ) do
    true = :inet_db.register_socket(cliSocket, :inet_tcp)
    :ok = :inet.setopts(cliSocket, [{:active, :once}])

    try do
      :gen_tcp.close(lSock)
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end

    {:noreply,
     r_peer_state(state,
       connection: cliSocket,
       listen_socket: :undefined
     )}
  end

  def handle_info(
        {:inet_async, lSock, _Ref, {:error, reason}},
        r_peer_state(listen_socket: lSock) = state
      ) do
    try do
      :gen_tcp.close(lSock)
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end

    {:stop, {:inet_async, reason},
     r_peer_state(state,
       connection: :undefined,
       listen_socket: :undefined
     )}
  end

  def handle_info({:started, node}, state) do
    true = :erlang.monitor_node(node, true)
    {:noreply, boot_complete(node, :started, state)}
  end

  def handle_info(
        {:nodedown, node},
        r_peer_state(connection: :undefined) = state
      ) do
    maybe_stop({:nodedown, node}, state)
  end

  def handle_info(
        {port, {:exit_status, status}},
        r_peer_state(connection: port) = state
      ) do
    try do
      :erlang.port_close(port)
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end

    maybe_stop({:exit_status, status}, state)
  end

  def handle_info(
        {:EXIT, port, reason},
        r_peer_state(connection: port) = state
      ) do
    try do
      :erlang.port_close(port)
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end

    maybe_stop(reason, state)
  end

  def handle_info(
        {:tcp_closed, sock},
        r_peer_state(connection: sock) = state
      ) do
    try do
      :gen_tcp.close(sock)
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end

    maybe_stop(
      :tcp_closed,
      r_peer_state(state, connection: :undefined)
    )
  end

  def terminate(
        _Reason,
        r_peer_state(connection: port, options: options, node: node)
      ) do
    case {:maps.get(:shutdown, options, {:halt, 5000}), :maps.find(:connection, options)} do
      {:close, {:ok, :standard_io}} ->
        port != :undefined and
          try do
            :erlang.port_close(port)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end

      {:close, {:ok, _TCP}} ->
        port != :undefined and
          try do
            :gen_tcp.close(port)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end

      {:close, :error} ->
        _ = :erlang.disconnect_node(node)

      {{:halt, timeout}, {:ok, :standard_io}} ->
        port != :undefined and
          try do
            :erlang.port_close(port)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end

        wait_disconnected(node, {:timeout, timeout})

      {{:halt, timeout}, {:ok, _TCP}} ->
        port != :undefined and
          try do
            :gen_tcp.close(port)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end

        wait_disconnected(node, {:timeout, timeout})

      {{:halt, timeout}, :error} ->
        try do
          _ = :erpc.call(node, :erlang, :halt, [], timeout)
          :ok
        catch
          :error, {:erpc, :noconnection} ->
            :ok

          _, _ ->
            force_disconnect_node(node)
        end

      {shutdown, :error} ->
        timeout = shutdown(:dist, :undefined, node, shutdown)
        wait_disconnected(node, {:timeout, timeout})

      {shutdown, {:ok, :standard_io}} ->
        timeout = shutdown(:port, port, node, shutdown)
        deadline = deadline(timeout)

        receive do
          {:EXIT, ^port, _Reason2} ->
            :ok
        after
          timeout ->
            :ok
        end

        try do
          :erlang.port_close(port)
        catch
          :error, e -> {:EXIT, {e, __STACKTRACE__}}
          :exit, e -> {:EXIT, e}
          e -> e
        end

        wait_disconnected(node, deadline)

      {shutdown, {:ok, _TCP}} ->
        timeout = shutdown(:tcp, port, node, shutdown)
        deadline = deadline(timeout)

        receive do
          {:tcp_closed, ^port} ->
            :ok
        after
          timeout ->
            :ok
        end

        try do
          try do
            :gen_tcp.close(port)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end
        catch
          :error, e -> {:EXIT, {e, __STACKTRACE__}}
          :exit, e -> {:EXIT, e}
          e -> e
        end

        wait_disconnected(node, deadline)
    end

    :ok
  end

  defp deadline(:infinity) do
    {:timeout, :infinity}
  end

  defp deadline(timeout) when is_integer(timeout) do
    {:deadline, :erlang.monotonic_time(:millisecond) + timeout}
  end

  defp wait_disconnected(node, waitUntil) do
    case :lists.member(node, :erlang.nodes(:connected)) do
      false ->
        :ok

      true ->
        _ =
          :net_kernel.monitor_nodes(
            true,
            [{:node_type, :all}]
          )

        case :lists.member(node, :erlang.nodes(:connected)) do
          false ->
            :ok

          true ->
            tmo =
              case waitUntil do
                {:timeout, t} ->
                  t

                {:deadline, t} ->
                  tL = t - :erlang.monotonic_time(:millisecond)

                  cond do
                    tL < 0 ->
                      0

                    true ->
                      tL
                  end
              end

            receive do
              {:nodedown, ^node, _} ->
                :ok
            after
              tmo ->
                force_disconnect_node(node)
            end
        end
    end
  end

  defp force_disconnect_node(node) do
    _ = :erlang.disconnect_node(node)

    :logger.warning(
      ~c"peer:stop() timed out waiting for disconnect from node ~p. The connection was forcefully taken down.",
      [node]
    )
  end

  defp shutdown(_Type, _Port, node, timeout)
       when is_integer(timeout) or timeout === :infinity do
    :erpc.cast(node, :init, :stop, [])
    timeout
  end

  defp shutdown(:dist, :undefined, node, {timeout, coverNode})
       when is_integer(timeout) or timeout === :infinity do
    :rpc.call(coverNode, :cover, :flush, [node])
    :erpc.cast(node, :init, :stop, [])
    timeout
  end

  defp shutdown(type, port, node, {timeout, coverNode})
       when is_integer(timeout) or timeout === :infinity do
    :rpc.call(coverNode, :cover, :flush, [node])
    port != :undefined and origin_to_peer(type, port, {:cast, :init, :stop, []})
    timeout
  end

  defp verify_args(options) do
    args = :maps.get(:args, options, [])
    is_list(args) or :erlang.error({:invalid_arg, args})

    for arg <- args, not :io_lib.char_list(arg) do
      :erlang.error({:invalid_arg, arg})
    end

    :erlang.is_map_key(
      :connection,
      options
    ) or
      (:erlang.is_map_key(
         :name,
         options
       ) and :erlang.is_alive()) or :erlang.error(:not_alive)

    case :maps.find(:exec, options) do
      {:ok, {exec, strs}} ->
        :io_lib.char_list(exec) or :erlang.error({:exec, exec})

        for str <- strs, not :io_lib.char_list(str) do
          :erlang.error({:exec, str})
        end

        :ok

      {:ok, exec} when is_list(exec) ->
        :io_lib.char_list(exec) or :erlang.error({:exec, exec})
        :ok

      :error ->
        :ok

      {:ok, err} ->
        :erlang.error({:exec, err})
    end

    case :maps.find(:shutdown, options) do
      {:ok, :close} ->
        :ok

      {:ok, :halt} ->
        :ok

      {:ok, {:halt, tmo}}
      when (is_integer(tmo) and 1000 <= tmo and tmo <= 4_294_967_295) or tmo == :infinity ->
        :ok

      {:ok, tmo}
      when (is_integer(tmo) and 1000 <= tmo and tmo <= 4_294_967_295) or tmo == :infinity ->
        :ok

      {:ok, {tmo, node}}
      when ((is_integer(tmo) and 1000 <= tmo and tmo <= 4_294_967_295) or tmo == :infinity) and
             is_atom(node) ->
        :ok

      :error ->
        :ok

      {:ok, err2} ->
        :erlang.error({:shutdown, err2})
    end

    case :maps.find(:detached, options) do
      {:ok, false}
      when :erlang.map_get(
             :connection,
             options
           ) === :standard_io ->
        :erlang.error({:detached, :cannot_detach_with_standard_io})

      _ ->
        :ok
    end
  end

  defp make_notify_ref(:infinity) do
    {self(), make_ref()}
  end

  defp make_notify_ref(waitBoot) when is_integer(waitBoot) do
    {self(), make_ref()}
  end

  defp make_notify_ref({replyTo, tag}) when is_pid(replyTo) do
    {replyTo, tag}
  end

  defp make_notify_ref(false) do
    false
  end

  defp start_it(options, startFun) do
    verify_args(options)
    waitBoot = :maps.get(:wait_boot, options, 15000)
    notify = make_notify_ref(waitBoot)

    case apply(:gen_server, startFun, [:peer, [notify, options], []]) do
      {:ok, pid}
      when waitBoot === :infinity or
             is_integer(waitBoot) ->
        {_, ref} = notify
        mref = :erlang.monitor(:process, pid)

        receive do
          {^ref, {:started, nodeName, ^pid}} ->
            :erlang.demonitor(mref, [:flush])
            {:ok, pid, nodeName}

          {^ref, {:boot_failed, reason, ^pid}} ->
            :erlang.demonitor(mref, [:flush])
            :erlang.exit({:boot_failed, reason})

          {:DOWN, ^mref, _, _, reason} ->
            :erlang.exit(reason)
        after
          waitBoot ->
            _ = :gen_server.stop(pid)
            :erlang.demonitor(mref, [:flush])
            :erlang.exit(:timeout)
        end

      {:ok, pid} when :erlang.is_map_key(:host, options) ->
        {:ok, pid, node_name(options)}

      {:ok, pid} ->
        {:ok, pid}

      error ->
        error
    end
  end

  defp node_name(%{name: name, host: host}) do
    :erlang.list_to_atom(:lists.concat([name, ~c"@", host]))
  end

  defp node_name(_Options) do
    :undefined
  end

  defp maybe_stop(reason, r_peer_state(peer_state: :booting) = state) do
    _ = boot_complete(reason, :boot_failed, state)

    maybe_stop(
      reason,
      r_peer_state(state, peer_state: {:down, reason})
    )
  end

  defp maybe_stop(
         reason,
         r_peer_state(options: %{peer_down: :crash}) = state
       ) do
    {:stop, reason,
     r_peer_state(state,
       peer_state: {:down, reason},
       connection: :undefined
     )}
  end

  defp maybe_stop(
         _Reason,
         r_peer_state(
           options: %{peer_down: :continue},
           peer_state: {:down, _}
         ) = state
       ) do
    {:noreply, state}
  end

  defp maybe_stop(
         reason,
         r_peer_state(options: %{peer_down: :continue}) = state
       ) do
    {:noreply, r_peer_state(state, peer_state: {:down, reason})}
  end

  defp maybe_stop(reason, state) do
    {:stop, :normal, r_peer_state(state, peer_state: {:down, reason})}
  end

  defp handle_alternative_data(
         kind,
         {:io_request, from, fromRef, ioReq},
         r_peer_state(connection: conn) = state
       ) do
    reply = {:io_reply, from, fromRef, forward_request(ioReq)}
    origin_to_peer(kind, conn, reply)
    state
  end

  defp handle_alternative_data(_Kind, {:message, to, content}, state) do
    send(to, content)
    state
  end

  defp handle_alternative_data(
         _Kind,
         {:reply, seq, class, result},
         r_peer_state(outstanding: out) = state
       ) do
    {from, newOut} = :maps.take(seq, out)
    :gen.reply(from, {class, result})
    r_peer_state(state, outstanding: newOut)
  end

  defp handle_alternative_data(_Kind, {:started, nodeName}, state) do
    boot_complete(nodeName, :started, state)
  end

  defp forward_request(req) do
    gL = :erlang.group_leader()
    mRef = :erlang.monitor(:process, gL)
    send(gL, {:io_request, self(), mRef, req})

    receive do
      {:io_reply, ^mRef, reply} ->
        :erlang.demonitor(mRef, [:flush])
        reply

      {:DOWN, ^mRef, _, _, _} ->
        {:error, :terminated}
    end
  end

  defp origin_to_peer(:tcp, sock, term) do
    :ok = :gen_tcp.send(sock, :erlang.term_to_binary(term))
  end

  defp origin_to_peer(:port, port, term) do
    true =
      :erlang.port_command(
        port,
        encode_port_data(:erlang.term_to_binary(term))
      )
  end

  defp peer_to_origin(:tcp, sock, term) do
    :ok = :gen_tcp.send(sock, :erlang.term_to_binary(term))
  end

  defp peer_to_origin(:port, port, term) do
    bytes = :erlang.term_to_binary(term)

    true =
      :erlang.port_command(
        port,
        encode_port_data(bytes)
      )
  end

  defp encode_port_data(bytes) do
    size = byte_size(bytes)
    crc = :erlang.crc32(bytes)
    total = <<size::size(32), bytes::binary, crc::size(32)>>

    for <<(<<upper::size(4), lower::size(4)>> <- total)>>,
      into: <<>> do
      <<3::size(2), upper::size(4), 3::size(2), 3::size(2), lower::size(4), 3::size(2)>>
    end
  end

  defp decode_port_data(<<>>, str, bin) do
    {str, bin}
  end

  defp decode_port_data(<<3::size(2), quad::size(4), 3::size(2), rest::binary>>, str, bin) do
    decode_port_data(rest, str, <<bin::bitstring, quad::size(4)>>)
  end

  defp decode_port_data(<<char::size(8), rest::binary>>, str, bin) do
    decode_port_data(rest, <<str::binary, char>>, bin)
  end

  defp handle_port_binary(
         <<size::size(32), payload::size(size)-binary, crc::size(32), rest::binary>>,
         state
       ) do
    ^crc = :erlang.crc32(payload)
    term = :erlang.binary_to_term(payload)
    newState = handle_alternative_data(:port, term, state)
    handle_port_binary(rest, newState)
  end

  defp handle_port_binary(newBin, state) do
    r_peer_state(state, stdio: newBin)
  end

  defp boot_complete(node, _Result, r_peer_state(notify: false) = state) do
    r_peer_state(state, peer_state: :running, node: node)
  end

  defp boot_complete(node, result, r_peer_state(notify: {replyTo, tag}) = state) do
    send(replyTo, {tag, {result, node, self()}})
    r_peer_state(state, peer_state: :running, node: node)
  end

  defp maybe_listen(%{connection: port}) when is_integer(port) do
    {:ok, lSock} =
      :gen_tcp.listen(
        port,
        [:binary, {:reuseaddr, true}, {:packet, 4}]
      )

    {:ok, waitPort} = :inet.port(lSock)
    {:ok, ifs} = :inet.getifaddrs()

    localUp =
      :lists.append(
        for {_, opts} <- ifs,
            :lists.member(
              :up,
              :proplists.get_value(
                :flags,
                opts,
                []
              )
            ) do
          :proplists.get_all_values(:addr, opts)
        end
      )

    local =
      prefer_localhost(
        for valid <- localUp,
            is_list(:inet.ntoa(valid)) do
          valid
        end,
        [],
        []
      )

    {lSock, {local, waitPort}}
  end

  defp maybe_listen(%{connection: {ip, port}})
       when is_integer(port) do
    {:ok, lSock} =
      :gen_tcp.listen(
        port,
        [:binary, {:reuseaddr, true}, {:packet, 4}, {:ip, ip}]
      )

    waitPort =
      cond do
        port === 0 ->
          {:ok, dyn} = :inet.port(lSock)
          dyn

        true ->
          port
      end

    {lSock, {[ip], waitPort}}
  end

  defp maybe_listen(_Options) do
    {:undefined, :undefined}
  end

  defp prefer_localhost([], preferred, other) do
    preferred ++ other
  end

  defp prefer_localhost([{127, _, _, _} = local | tail], preferred, other) do
    prefer_localhost(tail, [local | preferred], other)
  end

  defp prefer_localhost([{0, 0, 0, 0, 0, 0, 0, 1} = local | tail], preferred, other) do
    prefer_localhost(tail, [local | preferred], other)
  end

  defp prefer_localhost([local | tail], preferred, other) do
    prefer_localhost(tail, preferred, [local | other])
  end

  defp name_arg(:error, :error, _) do
    []
  end

  defp name_arg(:error, {:ok, host}, longOrShort) do
    [name, _] = :string.lexemes(:erlang.atom_to_list(node()), ~c"@")
    name_arg(name ++ ~c"@" ++ host, :error, longOrShort)
  end

  defp name_arg({:ok, name}, host, longOrShort) do
    name_arg(name, host, longOrShort)
  end

  defp name_arg(name, host, longOrShort) when is_atom(name) do
    name_arg(:erlang.atom_to_list(name), host, longOrShort)
  end

  defp name_arg(name, host, {:ok, :ignored}) do
    name_arg(name, host, {:ok, false})
  end

  defp name_arg(name, host, :error) do
    name_arg(name, host, {:ok, :net_kernel.longnames()})
  end

  defp name_arg(name, {:ok, host}, longOrShort) do
    name_arg(name ++ ~c"@" ++ host, :error, longOrShort)
  end

  defp name_arg(name, :error, {:ok, true}) do
    [~c"-name", name]
  end

  defp name_arg(name, :error, {:ok, false}) do
    [~c"-sname", name]
  end

  defp command_line(listen, options) do
    nameArg =
      name_arg(
        :maps.find(:name, options),
        :maps.find(:host, options),
        :maps.find(:longnames, options)
      )

    cmdOpts = :maps.get(:args, options, [])

    detachArgs =
      case :maps.get(:detached, options, true) do
        true ->
          [~c"-detached", ~c"-peer_detached"]

        false ->
          []
      end

    startCmd =
      case listen do
        :undefined
        when :erlang.map_get(
               :connection,
               options
             ) === :standard_io ->
          [~c"-user", :erlang.atom_to_list(:peer)]

        :undefined ->
          self = :base64.encode_to_string(:erlang.term_to_binary(self()))
          detachArgs ++ [~c"-user", :erlang.atom_to_list(:peer), ~c"-origin", self]

        {ips, port} ->
          ipStr =
            :lists.concat(
              :lists.join(
                ~c",",
                for ip <- ips do
                  :inet.ntoa(ip)
                end
              )
            )

          detachArgs ++
            [
              ~c"-user",
              :erlang.atom_to_list(:peer),
              ~c"-origin",
              ipStr,
              :erlang.integer_to_list(port)
            ]
      end

    {exec, preArgs} = exec(options)
    {exec, preArgs ++ nameArg ++ cmdOpts ++ startCmd}
  end

  defp exec(%{exec: prog}) when is_list(prog) do
    {prog, []}
  end

  defp exec(%{exec: {prog, args}})
       when is_list(prog) and
              is_list(args) do
    {prog, args}
  end

  defp exec(options) when not :erlang.is_map_key(:exec, options) do
    case :init.get_argument(:progname) do
      {:ok, [[prog]]} ->
        case :os.find_executable(prog) do
          exec when is_list(exec) ->
            {exec, []}

          false ->
            maybe_otp_test_suite(prog)
        end

      _ ->
        default_erts()
    end
  end

  defp maybe_otp_test_suite(prog) do
    case :string.split(prog, ~c"cerl ") do
      [cerlPath, args] ->
        {:filename.join(cerlPath, ~c"cerl"), parse_args(args)}

      _ ->
        default_erts()
    end
  end

  defp parse_args([]) do
    []
  end

  defp parse_args([deep | _] = alreadyParsed)
       when is_list(deep) do
    alreadyParsed
  end

  defp parse_args(cmdLine) do
    re =
      "((?:\"[^\"\\\\]*(?:\\\\[\\S\\s][^\"\\\\]*)*\"|'[^'\\\\]*(?:\\\\[\\S\\s][^'\\\\]*)*'|\\/[^\\/\\\\]*(?:\\\\[\\S\\s][^\\/\\\\]*)*\\/[gimy]*(?=\\s|$)|(?:\\\\\\s|\\S))+)(?=\\s|$)"

    {:match, args} = :re.run(cmdLine, re, [{:capture, :all_but_first, :list}, :global])

    for [arg] <- args do
      unquote(arg)
    end
  end

  defp unquote([q | arg]) when q === ?" or q === ?' do
    case :lists.last(arg) do
      ^q ->
        :lists.droplast(arg)

      _ ->
        [q | arg]
    end
  end

  defp unquote(arg) do
    arg
  end

  defp default_erts() do
    root = :code.root_dir()

    erts =
      :filename.join(
        root,
        :lists.concat([~c"erts-", :erlang.system_info(:version)])
      )

    binDir = :filename.join(erts, ~c"bin")
    {:filename.join(binDir, ~c"erlexec"), []}
  end

  defp notify_when_started(kind, port) do
    :init.notify_when_started(self()) === :started and
      notify_started(
        kind,
        port
      )

    :ok
  end

  defp notify_started(:dist, process) do
    send(process, {:started, node()})
    :ok
  end

  defp notify_started(kind, port) do
    peer_to_origin(kind, port, {:started, node()})
  end

  def supervision_child_spec() do
    case :init.get_argument(:user) do
      {:ok, [[~c"peer"]]} ->
        {:ok,
         %{
           id: :peer_supervision,
           start: {:peer, :start_supervision, []},
           restart: :permanent,
           shutdown: 1000,
           type: :worker,
           modules: [:peer]
         }}

      _ ->
        :none
    end
  end

  def start_supervision() do
    :proc_lib.start_link(:peer, :init_supervision, [self(), true])
  end

  defp start_orphan_supervision() do
    :proc_lib.start(:peer, :init_supervision, [self(), false])
  end

  Record.defrecord(:r_peer_sup_state, :peer_sup_state,
    parent: :undefined,
    channel: :undefined,
    in_sup_tree: :undefined
  )

  def init_supervision(parent, inSupTree) do
    try do
      :erlang.process_flag(:priority, :high)
      :erlang.process_flag(:trap_exit, true)
      :erlang.register(:peer_supervision, self())
      :proc_lib.init_ack(parent, {:ok, self()})

      channel =
        receive do
          {:channel_connect, ref, from, connectChannel} ->
            true = is_pid(connectChannel)
            send(from, ref)

            try do
              :erlang.link(connectChannel)
            catch
              :error, :noproc ->
                exit({:peer_channel_terminated, :noproc})
            end

            connectChannel
        after
          30000 ->
            exit(:peer_channel_connect_timeout)
        end

      loop_supervision(r_peer_sup_state(parent: parent, channel: channel, in_sup_tree: inSupTree))
    catch
      _, _ when not inSupTree ->
        :erlang.halt(1)
    end
  end

  defp peer_sup_connect_channel(peerSupervision, peerChannelHandler) do
    ref = make_ref()
    send(peerSupervision, {:channel_connect, ref, self(), peerChannelHandler})

    receive do
      ^ref ->
        :ok
    after
      30000 ->
        exit(:peer_supervision_connect_timeout)
    end
  end

  defp loop_supervision(r_peer_sup_state(parent: parent, channel: channel) = state) do
    receive do
      {:EXIT, ^channel, reason} ->
        exit({:peer_channel_terminated, reason})

      {:system, from, request} ->
        :sys.handle_system_msg(request, from, parent, :peer, [], state)

      _ ->
        loop_supervision(state)
    end
  end

  def system_continue(_Parent, _, r_peer_sup_state() = state) do
    loop_supervision(state)
  end

  def system_terminate(reason, _Parent, _Debug, _State) do
    exit(reason)
  end

  def system_code_change(state, _Module, _OldVsn, _Extra) do
    {:ok, state}
  end

  def system_get_state(state) do
    {:ok, state}
  end

  def system_replace_state(stateFun, state) do
    nState = stateFun.(state)
    {:ok, nState, nState}
  end

  def start() do
    try do
      peerChannelHandler = start_peer_channel_handler()

      peerSup =
        case :erlang.whereis(:peer_supervision) do
          peerSup0 when is_pid(peerSup0) ->
            peerSup0

          :undefined ->
            {:ok, peerSup0} = start_orphan_supervision()
            peerSup0
        end

      peer_sup_connect_channel(peerSup, peerChannelHandler)
      peerChannelHandler
    catch
      _, _ ->
        :erlang.halt(1)
    end
  end

  defp start_peer_channel_handler() do
    case :init.get_argument(:origin) do
      {:ok, [[ipStr, portString]]} ->
        port = :erlang.list_to_integer(portString)

        ips =
          for ip <- :string.lexemes(ipStr, ~c",") do
            {:ok, addr} = :inet.parse_address(ip)
            addr
          end

        tCPConnection =
          spawn(fn ->
            tcp_init(ips, port)
          end)

        _ =
          case :init.get_argument(:peer_detached) do
            {:ok, _} ->
              _ = :erlang.register(:user, tCPConnection)

            :error ->
              _ =
                :user_sup.init(
                  for flag <- :init.get_arguments(),
                      flag !== {:user, [~c"peer"]} do
                    flag
                  end
                )
          end

        tCPConnection

      {:ok, [[base64EncProc]]} ->
        originProcess = :erlang.binary_to_term(:base64.decode(base64EncProc))

        originLink =
          spawn(fn ->
            mRef = :erlang.monitor(:process, originProcess)
            notify_when_started(:dist, originProcess)
            origin_link(mRef, originProcess)
          end)

        :ok =
          :gen_server.call(
            originProcess,
            {:starting, node()}
          )

        _ =
          case :init.get_argument(:peer_detached) do
            {:ok, _} ->
              groupLeader =
                :gen_server.call(
                  originProcess,
                  :group_leader
                )

              relayPid =
                spawn(fn ->
                  :erlang.link(originLink)
                  relay(groupLeader)
                end)

              _ = :erlang.register(:user, relayPid)

            :error ->
              _ =
                :user_sup.init(
                  for flag <- :init.get_arguments(),
                      flag !== {:user, [~c"peer"]} do
                    flag
                  end
                )
          end

        originLink

      :error ->
        spawn(&io_server/0)
    end
  end

  defp relay(groupLeader) do
    receive do
      iO ->
        send(groupLeader, iO)
        relay(groupLeader)
    end
  end

  defp origin_link(mRef, origin) do
    receive do
      {:DOWN, ^mRef, :process, ^origin, _Reason} ->
        :erlang.halt()

      {:init, :started} ->
        notify_started(:dist, origin)
        origin_link(mRef, origin)
    end
  end

  defp io_server() do
    try do
      :erlang.process_flag(:trap_exit, true)
      port = :erlang.open_port({:fd, 0, 1}, [:eof, :binary])
      :erlang.register(:user, self())
      :erlang.group_leader(self(), self())
      notify_when_started(:port, port)
      io_server_loop(:port, port, %{}, %{}, <<>>)
    catch
      _, _ ->
        :erlang.halt(1)
    end
  end

  defp tcp_init(ipList, port) do
    try do
      sock = loop_connect(ipList, port)
      :erlang.group_leader(self(), self())
      notify_when_started(:tcp, sock)
      io_server_loop(:tcp, sock, %{}, %{}, :undefined)
    catch
      _, _ ->
        :erlang.halt(1)
    end
  end

  defp loop_connect([], _Port) do
    :erlang.error(:noconnection)
  end

  defp loop_connect([ip | more], port) do
    case :gen_tcp.connect(ip, port, [:binary, {:packet, 4}], 10000) do
      {:ok, sock} ->
        sock

      _Error ->
        loop_connect(more, port)
    end
  end

  defp io_server_loop(kind, port, refs, out, portBuf) do
    receive do
      {:io_request, from, replyAs, request} when is_pid(from) ->
        peer_to_origin(kind, port, {:io_request, from, replyAs, request})
        io_server_loop(kind, port, refs, out, portBuf)

      {^port, {:data, bytes}} when kind === :port ->
        {_Str, newBin} = decode_port_data(bytes, <<>>, portBuf)
        {newRefs, newOut, newBuf} = handle_port_alternative(newBin, refs, out)
        io_server_loop(kind, port, newRefs, newOut, newBuf)

      {^port, :eof} when kind === :port ->
        :erlang.halt(1)

      {:EXIT, ^port, :badsig} when kind === :port ->
        io_server_loop(kind, port, refs, out, portBuf)

      {:EXIT, ^port, _Reason} when kind === :port ->
        :erlang.halt(1)

      {:tcp, ^port, data} when kind === :tcp ->
        :ok = :inet.setopts(port, [{:active, :once}])
        {newRefs, newOut} = handle_peer_alternative(:erlang.binary_to_term(data), refs, out)
        io_server_loop(kind, port, newRefs, newOut, portBuf)

      {:tcp_closed, ^port} when kind === :tcp ->
        :erlang.halt(1)

      {:reply, seq, class, reply}
      when is_integer(seq) and
             :erlang.is_map_key(seq, out) ->
        {callerRef, out2} = :maps.take(seq, out)
        refs2 = :maps.remove(callerRef, refs)
        :erlang.demonitor(callerRef, [:flush])
        peer_to_origin(kind, port, {:reply, seq, class, reply})
        io_server_loop(kind, port, refs2, out2, portBuf)

      {:message, to, content} ->
        peer_to_origin(kind, port, {:message, to, content})
        io_server_loop(kind, port, refs, out, portBuf)

      {:DOWN, callerRef, _, _, reason} ->
        {seq, refs3} = :maps.take(callerRef, refs)
        {^callerRef, out3} = :maps.take(seq, out)
        peer_to_origin(kind, port, {:reply, seq, :crash, reason})
        io_server_loop(kind, port, refs3, out3, portBuf)

      {:init, :started} ->
        notify_started(kind, port)
        io_server_loop(kind, port, refs, out, portBuf)

      _Other ->
        io_server_loop(kind, port, refs, out, portBuf)
    end
  end

  defp handle_peer_alternative({:io_reply, from, fromRef, reply}, refs, out) do
    send(from, {:io_reply, fromRef, reply})
    {refs, out}
  end

  defp handle_peer_alternative({:call, seq, m, f, a}, refs, out) do
    callerRef = do_call(seq, m, f, a)
    {Map.put(refs, callerRef, seq), Map.put(out, seq, callerRef)}
  end

  defp handle_peer_alternative({:cast, m, f, a}, refs, out) do
    spawn(fn ->
      :erlang.apply(m, f, a)
    end)

    {refs, out}
  end

  defp handle_peer_alternative({:message, dest, message}, refs, out) do
    send(dest, message)
    {refs, out}
  end

  defp handle_port_alternative(
         <<size::size(32), payload::size(size)-binary, crc::size(32), rest::binary>>,
         refs,
         out
       ) do
    ^crc = :erlang.crc32(payload)
    {newRefs, newOut} = handle_peer_alternative(:erlang.binary_to_term(payload), refs, out)
    handle_port_alternative(rest, newRefs, newOut)
  end

  defp handle_port_alternative(rest, refs, out) do
    {refs, out, rest}
  end

  defp do_call(seq, m, f, a) do
    proxy = self()

    {_, callerRef} =
      spawn_monitor(fn ->
        try do
          send(proxy, {:reply, seq, :ok, :erlang.apply(m, f, a)})
        catch
          class, reason ->
            send(proxy, {:reply, seq, class, {reason, __STACKTRACE__}})
        end
      end)

    callerRef
  end
end
