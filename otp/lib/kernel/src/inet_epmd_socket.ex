defmodule :m_inet_epmd_socket do
  use Bitwise
  require Record
  Record.defrecord(:r_net_address, :net_address, address: :undefined,
                                       host: :undefined, protocol: :undefined,
                                       family: :undefined)
  Record.defrecord(:r_hs_data, :hs_data, kernel_pid: :undefined,
                                   other_node: :undefined,
                                   this_node: :undefined, socket: :undefined,
                                   timer: :undefined, this_flags: :undefined,
                                   allowed: :undefined,
                                   other_version: :undefined,
                                   other_flags: :undefined,
                                   other_started: :undefined,
                                   f_send: :undefined, f_recv: :undefined,
                                   f_setopts_pre_nodeup: :undefined,
                                   f_setopts_post_nodeup: :undefined,
                                   f_getll: :undefined, f_address: :undefined,
                                   mf_tick: :undefined, mf_getstat: :undefined,
                                   request_type: :normal,
                                   mf_setopts: :undefined,
                                   mf_getopts: :undefined,
                                   f_handshake_complete: :undefined,
                                   add_flags: :undefined,
                                   reject_flags: :undefined,
                                   require_flags: :undefined,
                                   this_creation: :undefined,
                                   other_creation: :undefined)
  def net_address() do
    r_net_address(protocol: :tcp, family: :inet)
  end

  defp setopts(socket, options) do
    :gen_tcp_socket.socket_setopts(socket, options)
  end

  def listen_close(listenSocket) do
    :socket.close(listenSocket)
  end

  def accepted(netAddress, _Timer, socket) do
    start_dist_ctrl(netAddress, socket)
  end

  def start_dist_ctrl(netAddress, socket) do
    controller = self()
    distCtrlTag = make_ref()
    distCtrl = spawn_link(fn () ->
                               receive do
                                 {^distCtrlTag, :handshake_complete, from,
                                    distHandle} ->
                                   sync = make_ref()
                                   distC = self()
                                   inputHandler = spawn_link(fn () ->
                                                                  :erlang.link(controller)
                                                                  send(distC, sync)
                                                                  receive do
                                                                    ^sync ->
                                                                      :ok
                                                                  end
                                                                  input_handler_start(socket,
                                                                                        distHandle)
                                                             end)
                                   false = :erlang.dist_ctrl_set_opt(distHandle,
                                                                       :get_size,
                                                                       true)
                                   :ok = :erlang.dist_ctrl_input_handler(distHandle,
                                                                           inputHandler)
                                   receive do
                                     ^sync ->
                                       send(inputHandler, sync)
                                   end
                                   send(from, {distCtrlTag,
                                                 :handshake_complete})
                                   output_handler_start(socket, distHandle)
                               end
                          end)
    r_hs_data(socket: socket,
        f_send: fn s, packet when s === socket ->
                     send_packet_2(s, packet)
                end,
        f_recv: fn s, 0, :infinity when s === socket ->
                     recv_packet_2(s)
                end,
        f_setopts_pre_nodeup: f_ok(socket),
        f_setopts_post_nodeup: f_ok(socket),
        f_address: fn s, node when s === socket ->
                        :inet_epmd_dist.f_address(netAddress, node)
                   end,
        f_getll: fn s when s === socket ->
                      {:ok, distCtrl}
                 end,
        f_handshake_complete: fn s, _Node, distHandle
                                     when s === socket ->
                                   handshake_complete(distCtrl, distCtrlTag,
                                                        distHandle)
                              end,
        mf_tick: fn s when s === socket ->
                      tick(distCtrl)
                 end)
  end

  defp send_packet_2(socket, packet) do
    size = :erlang.iolist_size(packet)
    true = size < 1 <<< 16
    :socket.send(socket, [<<size :: size(16)>>, packet])
  end

  defp f_ok(socket) do
    fn s when s === socket ->
         :ok
    end
  end

  defp handshake_complete(distCtrl, distCtrlTag, distHandle) do
    send(distCtrl, {distCtrlTag, :handshake_complete,
                      self(), distHandle})
    receive do
      {^distCtrlTag, :handshake_complete} ->
        :ok
    end
  end

  defp tick(distCtrl) do
    send(distCtrl, :dist_tick)
    :ok
  end

  defp output_handler_start(socket, distHandle) do
    try do
      :erlang.dist_ctrl_get_data_notification(distHandle)
      output_handler(socket, distHandle)
    catch
      class, reason when class === :error ->
        :error_logger.error_report([:output_handler_exception,
                                        {:class, class}, {:reason, reason},
                                                             {:stacktrace,
                                                                __STACKTRACE__}])
        :erlang.raise(class, reason, __STACKTRACE__)
    end
  end

  defp output_handler(socket, distHandle) do
    receive do
      msg ->
        case (msg) do
          :dist_tick ->
            output_handler_tick(socket, distHandle)
          :dist_data ->
            output_handler_data(socket, distHandle)
          _ ->
            output_handler(socket, distHandle)
        end
    end
  end

  defp output_handler_tick(socket, distHandle) do
    receive do
      msg ->
        case (msg) do
          :dist_tick ->
            output_handler_tick(socket, distHandle)
          :dist_data ->
            output_handler_data(socket, distHandle)
          _ ->
            output_handler_tick(socket, distHandle)
        end
    after 0 ->
      output_data(socket, [<<0 :: size(32)>>])
      output_handler(socket, distHandle)
    end
  end

  defp output_handler_data(socket, distHandle) do
    output_handler_data(socket, distHandle, [], 0)
  end

  defp output_handler_data(socket, distHandle, buffer, size)
      when 1 <<< 16 <= size do
    output_data(socket, buffer)
    output_handler_data(socket, distHandle)
  end

  defp output_handler_data(socket, distHandle, buffer, size) do
    case (:erlang.dist_ctrl_get_data(distHandle)) do
      :none ->
        cond do
          size === 0 ->
            [] = buffer
            :erlang.dist_ctrl_get_data_notification(distHandle)
            output_handler(socket, distHandle)
          true ->
            output_data(socket, buffer)
            output_handler_data(socket, distHandle)
        end
      {len, iovec} ->
        output_handler_data(socket, distHandle,
                              :lists.reverse(iovec,
                                               [<<len :: size(32)>> | buffer]),
                              len + 4 + size)
    end
  end

  defp output_data(socket, buffer) do
    iovec = :lists.reverse(buffer)
    case (:socket.sendmsg(socket, %{iov: iovec})) do
      :ok ->
        :ok
      {:error, reason} ->
        exit(reason)
    end
  end

  defp input_handler_start(socket, distHandle) do
    try do
      input_handler(socket, distHandle)
    catch
      class, reason when class === :error ->
        :error_logger.error_report([:input_handler_exception,
                                        {:class, class}, {:reason, reason},
                                                             {:stacktrace,
                                                                __STACKTRACE__}])
        :erlang.raise(class, reason, __STACKTRACE__)
    end
  end

  defp input_handler(socket, distHandle) do
    input_handler(socket, distHandle, <<>>, [], 0)
  end

  defp input_handler(socket, distHandle, first, buffer, size) do
    case (first) do
      <<packetSize1 :: size(32),
          packet1 :: size(packetSize1) - binary,
          packetSize2 :: size(32),
          packet2 :: size(packetSize2) - binary,
          rest :: binary>> ->
        put_data(distHandle, packetSize1, packet1)
        put_data(distHandle, packetSize2, packet2)
        dataSize = 4 + packetSize1 + 4 + packetSize2
        input_handler(socket, distHandle, rest, buffer,
                        size - dataSize)
      <<packetSize :: size(32),
          packet :: size(packetSize) - binary, rest :: binary>> ->
        dataSize = 4 + packetSize
        put_data(distHandle, packetSize, packet)
        input_handler(socket, distHandle, rest, buffer,
                        size - dataSize)
      <<packetSize :: size(32), packetStart :: binary>> ->
        input_handler(socket, distHandle, packetStart, buffer,
                        size - 4, packetSize)
      <<bin :: binary>> ->
        cond do
          4 <= size ->
            {first_1, buffer_1,
               packetSize} = input_get_packet_size(bin,
                                                     :lists.reverse(buffer))
            input_handler(socket, distHandle, first_1, buffer_1,
                            size - 4, packetSize)
          true ->
            data = input_data(socket)
            buffer_1 = [data | buffer]
            dataSize = byte_size(data)
            input_handler(socket, distHandle, first, buffer_1,
                            size + dataSize)
        end
    end
  end

  defp input_handler(socket, distHandle, packetStart, buffer, size,
            packetSize) do
    restSize = size - packetSize
    cond do
      restSize < 0 ->
        more = input_data(socket)
        moreSize = byte_size(more)
        input_handler(socket, distHandle, packetStart,
                        [more | buffer], size + moreSize, packetSize)
      (0 < restSize and buffer === []) ->
        <<packet :: size(packetSize) - binary,
            rest :: binary>> = packetStart
        put_data(distHandle, packetSize, packet)
        input_handler(socket, distHandle, rest, [], restSize)
      buffer === [] ->
        ^restSize = 0
        put_data(distHandle, packetSize, packetStart)
        input_handler(socket, distHandle)
      true ->
        bin = hd(buffer)
        lastSize = byte_size(bin) - restSize
        <<lastBin :: size(lastSize) - binary,
            rest :: binary>> = bin
        packet = [packetStart | :lists.reverse(tl(buffer),
                                                 [lastBin])]
        put_data(distHandle, packetSize, packet)
        input_handler(socket, distHandle, rest, [], restSize)
    end
  end

  defp input_get_packet_size(first, [bin | buffer]) do
    missingSize = 4 - byte_size(first)
    cond do
      missingSize <= byte_size(bin) ->
        <<last :: size(missingSize) - binary,
            rest :: binary>> = bin
        <<packetSize :: size(32)>> = <<first :: binary,
                                         last :: binary>>
        {rest, :lists.reverse(buffer), packetSize}
      true ->
        input_get_packet_size(<<first :: binary,
                                  bin :: binary>>,
                                buffer)
    end
  end

  defp input_data(socket) do
    case (:socket.recv(socket)) do
      {:ok, data} ->
        data
      {:error, reason} ->
        exit(reason)
    end
  end

  defp put_data(distHandle, _PacketSize, packet) do
    :erlang.dist_ctrl_put_data(distHandle, packet)
  end

  def supported() do
    try do
      :socket.info()
    catch
      :error, :notsup ->
        {:skip, 'esock not supported'}
      :error, :undef ->
        {:skip, 'esock not configured'}
    else
      %{io_backend: %{name: backendName}}
          when backendName !== :win_esaio ->
        :ok
      _ ->
        {:skip, 'Temporary exclusion'}
    end
  end

end