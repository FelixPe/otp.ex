defmodule :m_dist_util do
  use Bitwise
  import :error_logger, only: [error_msg: 2]
  require Record

  Record.defrecord(:r_hs_data, :hs_data,
    kernel_pid: :undefined,
    other_node: :undefined,
    this_node: :undefined,
    socket: :undefined,
    timer: :undefined,
    this_flags: :undefined,
    allowed: :undefined,
    other_version: :undefined,
    other_flags: :undefined,
    other_started: :undefined,
    f_send: :undefined,
    f_recv: :undefined,
    f_setopts_pre_nodeup: :undefined,
    f_setopts_post_nodeup: :undefined,
    f_getll: :undefined,
    f_address: :undefined,
    mf_tick: :undefined,
    mf_getstat: :undefined,
    request_type: :normal,
    mf_setopts: :undefined,
    mf_getopts: :undefined,
    f_handshake_complete: :undefined,
    add_flags: :undefined,
    reject_flags: :undefined,
    require_flags: :undefined,
    this_creation: :undefined,
    other_creation: :undefined
  )

  Record.defrecord(:r_tick, :tick, read: 0, write: 0, tick: 0, ticked: 0)

  defp dflag2str(1) do
    ~c"PUBLISHED"
  end

  defp dflag2str(2) do
    ~c"ATOM_CACHE"
  end

  defp dflag2str(4) do
    ~c"EXTENDED_REFERENCES"
  end

  defp dflag2str(8) do
    ~c"DIST_MONITOR"
  end

  defp dflag2str(16) do
    ~c"FUN_TAGS"
  end

  defp dflag2str(32) do
    ~c"DIST_MONITOR_NAME"
  end

  defp dflag2str(64) do
    ~c"HIDDEN_ATOM_CACHE"
  end

  defp dflag2str(128) do
    ~c"NEW_FUN_TAGS"
  end

  defp dflag2str(256) do
    ~c"EXTENDED_PIDS_PORTS"
  end

  defp dflag2str(512) do
    ~c"EXPORT_PTR_TAG"
  end

  defp dflag2str(1024) do
    ~c"BIT_BINARIES"
  end

  defp dflag2str(2048) do
    ~c"NEW_FLOATS"
  end

  defp dflag2str(4096) do
    ~c"UNICODE_IO"
  end

  defp dflag2str(8192) do
    ~c"DIST_HDR_ATOM_CACHE"
  end

  defp dflag2str(16384) do
    ~c"SMALL_ATOM_TAGS"
  end

  defp dflag2str(65536) do
    ~c"UTF8_ATOMS"
  end

  defp dflag2str(131_072) do
    ~c"MAP_TAG"
  end

  defp dflag2str(262_144) do
    ~c"BIG_CREATION"
  end

  defp dflag2str(524_288) do
    ~c"SEND_SENDER"
  end

  defp dflag2str(1_048_576) do
    ~c"BIG_SEQTRACE_LABELS"
  end

  defp dflag2str(4_194_304) do
    ~c"EXIT_PAYLOAD"
  end

  defp dflag2str(8_388_608) do
    ~c"FRAGMENTS"
  end

  defp dflag2str(16_777_216) do
    ~c"HANDSHAKE_23"
  end

  defp dflag2str(33_554_432) do
    ~c"UNLINK_ID"
  end

  defp dflag2str(67_108_864) do
    ~c"MANDATORY_25_DIGEST"
  end

  defp dflag2str(4_294_967_296) do
    ~c"SPAWN"
  end

  defp dflag2str(8_589_934_592) do
    ~c"NAME_ME"
  end

  defp dflag2str(17_179_869_184) do
    ~c"V4_NC"
  end

  defp dflag2str(34_359_738_368) do
    ~c"ALIAS"
  end

  defp dflag2str(other) do
    :lists.flatten(:io_lib.format(~c"UNKNOWN<~.16.0B>", [other]))
  end

  defp adjust_flags(thisFlags, otherFlags) do
    thisFlags &&& otherFlags
  end

  defp publish_flag(_, nameMeFlg, _)
       when nameMeFlg &&& 2 <<< 32 !== 0 do
    2 <<< 32
  end

  defp publish_flag(:hidden, _, _) do
    0
  end

  defp publish_flag(_, _, otherNode) do
    case :net_kernel.publish_on_node(otherNode) do
      true ->
        1

      _ ->
        0
    end
  end

  defp name_type(flags) do
    case flags &&& 2 <<< 32 do
      0 ->
        :static

      8_589_934_592 ->
        :dynamic
    end
  end

  Record.defrecord(:r_erts_dflags, :erts_dflags,
    default: :undefined,
    mandatory: :undefined,
    addable: :undefined,
    rejectable: :undefined,
    strict_order: :undefined
  )

  def strict_order_flags() do
    eDF = :erts_internal.get_dflags()
    r_erts_dflags(eDF, :strict_order)
  end

  def rejectable_flags() do
    eDF = :erts_internal.get_dflags()
    r_erts_dflags(eDF, :rejectable)
  end

  defp make_this_flags(
         requestType,
         addFlags,
         rejectFlags,
         otherNode,
         r_erts_dflags() = eDF,
         nameMeFlg
       ) do
    case rejectFlags &&& ~~~r_erts_dflags(eDF, :rejectable) do
      0 ->
        :ok

      rerror ->
        exit({~c"Rejecting non rejectable flags", rerror})
    end

    case addFlags &&& ~~~r_erts_dflags(eDF, :addable) do
      0 ->
        :ok

      aerror ->
        exit({~c"Adding non addable flags", aerror})
    end

    flgs0 = r_erts_dflags(eDF, :default)
    flgs1 = flgs0 ||| publish_flag(requestType, nameMeFlg, otherNode)
    flgs2 = flgs1 ||| addFlags
    flgs2 &&& ~~~rejectFlags
  end

  def handshake_other_started(
        r_hs_data(
          request_type: reqType,
          add_flags: addFlgs0,
          reject_flags: rejFlgs0,
          require_flags: reqFlgs0
        ) = hSData0
      ) do
    addFlgs = convert_flags(addFlgs0)
    rejFlgs = convert_flags(rejFlgs0)
    reqFlgs = convert_flags(reqFlgs0)
    {preOtherFlags0, nodeOrHost, creation} = recv_name(hSData0)
    preOtherFlags = expand_mandatory_25_flag(preOtherFlags0)
    eDF = :erts_internal.get_dflags()
    preThisFlags = make_this_flags(reqType, addFlgs, rejFlgs, nodeOrHost, eDF, preOtherFlags)

    hSData1 =
      r_hs_data(hSData0,
        this_flags: preThisFlags,
        other_flags: preOtherFlags,
        other_node: nodeOrHost,
        other_started: true,
        other_creation: creation,
        add_flags: addFlgs,
        reject_flags: rejFlgs,
        require_flags: reqFlgs
      )

    check_dflags(hSData1, eDF)
    :ok
    {acceptedPending, hSData2} = mark_pending(hSData1)
    node = r_hs_data(hSData2, :other_node)
    cookie = :auth.get_cookie(node)
    challengeA = gen_challenge()
    send_challenge(hSData2, challengeA)
    reset_timer(r_hs_data(hSData2, :timer))
    hSData3 = recv_complement(hSData2)
    check_dflags(hSData3, eDF)

    chosenFlags =
      adjust_flags(
        r_hs_data(hSData3, :this_flags),
        r_hs_data(hSData3, :other_flags)
      )

    hSData4 =
      r_hs_data(hSData3,
        this_flags: chosenFlags,
        other_flags: chosenFlags
      )

    challengeB = recv_challenge_reply(hSData4, challengeA, cookie)

    case acceptedPending do
      :up_pending ->
        wait_pending(hSData4)

      _ ->
        :continue
    end

    send_challenge_ack(
      hSData4,
      gen_digest(challengeB, cookie)
    )

    :ok
    connection(hSData4)
  end

  def handshake_other_started(oldHsData)
      when :erlang.element(
             1,
             oldHsData
           ) === :hs_data do
    handshake_other_started(convert_old_hsdata(oldHsData))
  end

  defp expand_mandatory_25_flag(flags) do
    cond do
      flags &&& 67_108_864 !== 0 ->
        flags |||
          (4 ||| 16 ||| 256 ||| 128 ||| 512 ||| 1024 ||| 2048 ||| 65536 ||| 131_072 ||| 262_144 |||
             16_777_216)

      true ->
        flags
    end
  end

  defp check_dflags(
         r_hs_data(
           other_node: node,
           other_flags: otherFlags,
           other_started: otherStarted,
           require_flags: requiredFlags,
           other_creation: otherCreation
         ) = hSData,
         r_erts_dflags() = eDF
       ) do
    mask =
      case otherCreation do
        :undefined ->
          1 <<< (32 - 1)

        _ ->
          ~~~0
      end

    mandatory = mask &&& (r_erts_dflags(eDF, :mandatory) ||| requiredFlags)
    missing = check_mandatory(mandatory, otherFlags, [])

    case missing do
      [] ->
        :ok

      _ ->
        case otherStarted do
          true ->
            send_status(hSData, :not_allowed)
            dir = ~c"from"
            how = ~c"rejected"

          _ ->
            dir = ~c"to"
            how = ~c"aborted"
        end

        error_msg(~c"** ~w: Connection attempt ~s node ~w ~s since it cannot handle ~p.**~n", [
          node(),
          dir,
          node,
          how,
          missing
        ])

        :dist_util.shutdown(:dist_util, 282, node, {:check_dflags_failed, missing})
    end
  end

  defp check_mandatory(0, _OtherFlags, missing) do
    missing
  end

  defp check_mandatory(mandatory, otherFlags, missing) do
    left = mandatory &&& mandatory - 1
    dFlag = mandatory ^^^ left

    newMissing =
      case dFlag &&& otherFlags do
        0 ->
          [dflag2str(dFlag) | missing]

        _ ->
          missing
      end

    check_mandatory(left, otherFlags, newMissing)
  end

  defp mark_pending(r_hs_data(kernel_pid: kernel, other_node: node, this_node: myNode) = hSData) do
    kernelReply = do_mark_pending(kernel, myNode, node, r_hs_data(hSData, :other_flags))

    {kernelReply,
     case kernelReply do
       :ok ->
         send_status(hSData, :ok)
         reset_timer(r_hs_data(hSData, :timer))
         hSData

       {:ok, dynNodeName, creation} ->
         hSData1 =
           r_hs_data(hSData,
             other_node: dynNodeName,
             other_creation: creation
           )

         send_status(hSData1, :named)
         reset_timer(r_hs_data(hSData1, :timer))
         hSData1

       :ok_pending ->
         send_status(hSData, :ok_simultaneous)
         reset_timer(r_hs_data(hSData, :timer))
         hSData

       :nok_pending ->
         send_status(hSData, :nok)
         :dist_util.shutdown(:dist_util, 330, node)

       :up_pending ->
         do_alive(hSData)
         reset_timer(r_hs_data(hSData, :timer))
         hSData

       :already_pending ->
         :ok
         :dist_util.shutdown(:dist_util, 352, node)
     end}
  end

  defp wait_pending(r_hs_data(kernel_pid: kernel, other_node: node)) do
    send(kernel, {self(), {:wait_pending, node}})

    receive do
      {^kernel, :pending} ->
        :ok
        :ok
    end
  end

  defp do_alive(r_hs_data(other_node: node) = hSData) do
    send_status(hSData, :alive)

    case recv_status_reply(hSData) do
      true ->
        true

      false ->
        :dist_util.shutdown(:dist_util, 375, node)
    end
  end

  defp do_mark_pending(kernel, myNode, node, flags) do
    send(kernel, {self(), {:accept_pending, myNode, node, publish_type(flags)}})

    receive do
      {^kernel, {:accept_pending, ret}} ->
        :ok
        ret
    end
  end

  defp is_pending(kernel, node) do
    send(kernel, {self(), {:is_pending, node}})

    receive do
      {^kernel, {:is_pending, reply}} ->
        reply
    end
  end

  def shutdown(module, line, data) do
    shutdown(module, line, data, :shutdown)
  end

  def shutdown(_Module, _Line, _Data, reason) do
    :noop
    exit(reason)
  end

  def handshake_we_started(
        r_hs_data(
          request_type: reqType,
          this_node: myNode,
          other_node: node,
          add_flags: addFlgs0,
          reject_flags: rejFlgs0,
          require_flags: reqFlgs0
        ) = preHSData
      ) do
    addFlgs = convert_flags(addFlgs0)
    rejFlgs = convert_flags(rejFlgs0)
    reqFlgs = convert_flags(reqFlgs0)
    eDF = :erts_internal.get_dflags()

    {nameMeFlg, nameToSend} =
      case node() do
        :nonode@nohost ->
          {:node, ~c"undefined", host} = split_node(myNode)
          {2 <<< 32, host}

        _ ->
          {0, myNode}
      end

    preThisFlags = make_this_flags(reqType, addFlgs, rejFlgs, node, eDF, nameMeFlg)

    hSData =
      r_hs_data(preHSData,
        this_node: nameToSend,
        this_flags: preThisFlags,
        add_flags: addFlgs,
        reject_flags: rejFlgs,
        require_flags: reqFlgs
      )

    send_name(hSData)
    hSData1 = recv_status(hSData)
    {preOtherFlags0, challengeA, creation} = recv_challenge(hSData1)
    preOtherFlags = expand_mandatory_25_flag(preOtherFlags0)
    chosenFlags = adjust_flags(preThisFlags, preOtherFlags)

    hSData2 =
      r_hs_data(hSData1,
        this_flags: chosenFlags,
        other_flags: chosenFlags,
        other_started: false,
        other_creation: creation
      )

    check_dflags(hSData2, eDF)
    challengeB = gen_challenge()
    cookie = :auth.get_cookie(node)
    send_challenge_reply(hSData2, challengeB, gen_digest(challengeA, cookie))
    reset_timer(r_hs_data(hSData2, :timer))
    recv_challenge_ack(hSData2, challengeB, cookie)
    connection(hSData2)
  end

  def handshake_we_started(oldHsData)
      when :erlang.element(
             1,
             oldHsData
           ) === :hs_data do
    handshake_we_started(convert_old_hsdata(oldHsData))
  end

  defp convert_old_hsdata(oldHsData) do
    oHSDL = :erlang.tuple_to_list(oldHsData)
    noMissing = tuple_size(r_hs_data()) - tuple_size(oldHsData)
    true = noMissing > 0

    :erlang.list_to_tuple(
      oHSDL ++
        :lists.duplicate(
          noMissing,
          :undefined
        )
    )
  end

  defp convert_flags(flags) when is_integer(flags) do
    flags
  end

  defp convert_flags(_Undefined) do
    0
  end

  Record.defrecord(:r_state, :state,
    kernel: :undefined,
    node: :undefined,
    tick_intensity: :undefined,
    socket: :undefined,
    publish_type: :undefined,
    handle: :undefined,
    f_tick: :undefined,
    f_getstat: :undefined,
    f_setopts: :undefined,
    f_getopts: :undefined
  )

  defp connection(
         r_hs_data(
           other_node: node,
           socket: socket,
           f_address: fAddress,
           f_setopts_pre_nodeup: fPreNodeup,
           f_setopts_post_nodeup: fPostNodeup
         ) = hSData
       ) do
    cancel_timer(r_hs_data(hSData, :timer))
    pType = publish_type(r_hs_data(hSData, :other_flags))

    case fPreNodeup.(socket) do
      :ok ->
        {dHandle, namedMe} = do_setnode(hSData)
        address = fAddress.(socket, node)
        tickIntensity = mark_nodeup(hSData, address, namedMe)

        case fPostNodeup.(socket) do
          :ok ->
            case r_hs_data(hSData, :f_handshake_complete) do
              :undefined ->
                :ok

              hsComplete ->
                hsComplete.(socket, node, dHandle)
            end

            con_loop(
              r_state(
                kernel: r_hs_data(hSData, :kernel_pid),
                node: node,
                socket: socket,
                tick_intensity: tickIntensity,
                publish_type: pType,
                handle: dHandle,
                f_tick: r_hs_data(hSData, :mf_tick),
                f_getstat: r_hs_data(hSData, :mf_getstat),
                f_setopts: r_hs_data(hSData, :mf_setopts),
                f_getopts: r_hs_data(hSData, :mf_getopts)
              ),
              r_tick()
            )

          error1 ->
            :dist_util.shutdown(
              :dist_util,
              519,
              {node, socket},
              {:f_setopts_post_nodeup_failed, error1}
            )
        end

      error2 ->
        :dist_util.shutdown(
          :dist_util,
          524,
          {node, socket},
          {:f_setopts_pre_nodeup_failed, error2}
        )
    end
  end

  defp gen_digest(challenge, cookie)
       when is_integer(challenge) and is_atom(cookie) do
    :erlang.md5([
      :erlang.atom_to_list(cookie)
      | :erlang.integer_to_list(challenge)
    ])
  end

  defp gen_challenge() do
    a = :erlang.phash2([:erlang.node()])
    b = :erlang.monotonic_time()
    c = :erlang.unique_integer()
    {d, _} = :erlang.statistics(:reductions)
    {e, _} = :erlang.statistics(:runtime)
    {f, _} = :erlang.statistics(:wall_clock)
    {g, h, _} = :erlang.statistics(:garbage_collection)

    a <<< ((24 + (e <<< 16) + (g <<< 8) + f) ^^^ (b + (c <<< 16)) ^^^ (d + (h <<< 16))) &&&
      4_294_967_295
  end

  defp do_setnode(
         r_hs_data(
           other_node: node,
           socket: socket,
           this_node: myNode,
           other_flags: flags,
           f_getll: getLL,
           other_creation: creation
         ) = hSData
       ) do
    case getLL.(socket) do
      {:ok, port} ->
        namedMe =
          case node() do
            :nonode@nohost ->
              :dynamic = name_type(r_hs_data(hSData, :this_flags))
              :erlang.setnode(myNode, r_hs_data(hSData, :this_creation))
              true

            ^myNode ->
              false
          end

        :ok
        ^myNode = node()

        try do
          dHandle = :erlang.setnode(node, port, {flags, creation})
          {dHandle, namedMe}
        catch
          :error, :system_limit ->
            error_msg(
              ~c"** Distribution system limit reached, no table space left for node ~w ** ~n",
              [node]
            )

            :dist_util.shutdown(:dist_util, 577, {node, socket})

          :error, other ->
            exit({other, __STACKTRACE__})
        end

      _ ->
        error_msg(
          ~c"** Distribution connection error, could not get low level port for node ~w ** ~n",
          [node]
        )

        :dist_util.shutdown(:dist_util, 585, {node, socket})
    end
  end

  defp mark_nodeup(
         r_hs_data(
           kernel_pid: kernel,
           other_node: node,
           other_flags: flags,
           other_started: otherStarted
         ),
         address,
         namedMe
       ) do
    send(kernel, {self(), {:nodeup, node, address, publish_type(flags), namedMe}})

    receive do
      {^kernel, :inserted, tickIntensity} ->
        tickIntensity

      {^kernel, :bad_request} ->
        typeT =
          case otherStarted do
            true ->
              ~c"accepting connection"

            _ ->
              ~c"initiating connection"
          end

        error_msg(~c"Fatal: ~p was not allowed to send {nodeup, ~p} to kernel when ~s~n", [
          self(),
          node,
          typeT
        ])

        :dist_util.shutdown(:dist_util, 607, node)
    end
  end

  defp getstat(dHandle, _Socket, :undefined) do
    :erlang.dist_get_stat(dHandle)
  end

  defp getstat(_DHandle, socket, mFGetstat) do
    mFGetstat.(socket)
  end

  defp con_loop(
         r_state(
           kernel: kernel,
           node: node,
           socket: socket,
           handle: dHandle,
           f_getstat: mFGetstat,
           f_setopts: mFSetOpts,
           f_getopts: mFGetOpts
         ) = conData,
         tick
       ) do
    receive do
      {:tcp_closed, ^socket} ->
        :dist_util.shutdown(:dist_util, 622, {node, socket}, :tcp_closed)

      {^kernel, :disconnect} ->
        :dist_util.shutdown(:dist_util, 624, {node, socket}, :disconnected)

      {^kernel, :aux_tick} ->
        case getstat(dHandle, socket, mFGetstat) do
          {:ok, _, _, pendWrite} ->
            send_aux_tick(conData, pendWrite)

          _ ->
            :ignore_it
        end

        con_loop(conData, tick)

      {^kernel, :tick} ->
        case send_tick(conData, tick) do
          {:ok, newTick} ->
            con_loop(conData, newTick)

          {:error, :not_responding} ->
            error_msg(~c"** Node ~p not responding **~n** Removing (timedout) connection **~n", [
              node
            ])

            :dist_util.shutdown(:dist_util, 641, {node, socket}, :net_tick_timeout)

          error1 ->
            :dist_util.shutdown(:dist_util, 643, {node, socket}, {:send_net_tick_failed, error1})
        end

      {from, :get_status} ->
        case getstat(dHandle, socket, mFGetstat) do
          {:ok, read, write, _} ->
            send(from, {self(), :get_status, {:ok, read, write}})
            con_loop(conData, tick)

          error2 ->
            :dist_util.shutdown(:dist_util, 651, {node, socket}, {:get_status_failed, error2})
        end

      {from, ref, {:setopts, opts}} ->
        ret =
          case mFSetOpts do
            :undefined ->
              {:error, :enotsup}

            _ ->
              mFSetOpts.(socket, opts)
          end

        send(from, {ref, ret})
        con_loop(conData, tick)

      {from, ref, {:getopts, opts}} ->
        ret =
          case mFGetOpts do
            :undefined ->
              {:error, :enotsup}

            _ ->
              mFGetOpts.(socket, opts)
          end

        send(from, {ref, ret})
        con_loop(conData, tick)
    end
  end

  defp send_name(r_hs_data(socket: socket, this_node: node, f_send: fSend, this_flags: flags)) do
    nameBin = to_binary(node)

    creation =
      case name_type(flags) do
        :static ->
          :erts_internal.get_creation()

        :dynamic ->
          0
      end

    nameLen = byte_size(nameBin)
    :ok

    to_port(fSend, socket, [
      <<?N, flags::size(64), creation::size(32), nameLen::size(16)>>,
      nameBin
    ])
  end

  defp to_binary(atom) when is_atom(atom) do
    :erlang.atom_to_binary(atom, :latin1)
  end

  defp to_binary(list) when is_list(list) do
    :erlang.list_to_binary(list)
  end

  defp send_challenge(
         r_hs_data(socket: socket, this_node: node, this_flags: thisFlags, f_send: fSend),
         challenge
       ) do
    creation = :erts_internal.get_creation()
    nodeName = :erlang.atom_to_binary(node, :latin1)
    nameLen = byte_size(nodeName)
    :ok

    to_port(fSend, socket, [
      <<?N, thisFlags::size(64), challenge::size(32), creation::size(32), nameLen::size(16)>>,
      nodeName
    ])
  end

  defp send_challenge_reply(r_hs_data(socket: socket, f_send: fSend), challenge, digest) do
    :ok

    to_port(fSend, socket, [
      ?r,
      [
        challenge >>> 24 &&& 255,
        challenge >>> 16 &&& 255,
        challenge >>> 8 &&& 255,
        challenge &&& 255
      ],
      digest
    ])
  end

  defp send_challenge_ack(r_hs_data(socket: socket, f_send: fSend), digest) do
    :ok
    to_port(fSend, socket, [?a, digest])
  end

  defp recv_name(r_hs_data(socket: socket, f_recv: recv) = hSData) do
    case recv.(socket, 0, :infinity) do
      {:ok, [?n | _] = data} ->
        recv_name_old(hSData, data)

      {:ok, [?N | _] = data} ->
        recv_name_new(hSData, data)

      other ->
        :dist_util.shutdown(:dist_util, 730, {:no_node, socket}, {:recv_name_failed, other})
    end
  end

  defp recv_name_old(
         hSData,
         [?n, v1, v0, f3, f2, f1, f0 | node] = data
       ) do
    <<_Version::size(16)>> = <<v1, v0>>
    <<flags::size(32)>> = <<f3, f2, f1, f0>>
    :ok

    case is_node_name(node) do
      true ->
        check_allowed(hSData, node)
        {flags, :erlang.list_to_atom(node), :undefined}

      false ->
        :dist_util.shutdown(:dist_util, 752, data)
    end
  end

  defp recv_name_new(
         hSData,
         [
           ?N,
           f7,
           f6,
           f5,
           f4,
           f3,
           f2,
           f1,
           f0,
           cr3,
           cr2,
           cr1,
           cr0,
           nL1,
           nL0
           | rest
         ] = data
       ) do
    <<flags::size(64)>> = <<f7, f6, f5, f4, f3, f2, f1, f0>>
    <<creation::size(32)>> = <<cr3, cr2, cr1, cr0>>
    <<nameLen::size(16)>> = <<nL1, nL0>>
    {name, _Residue} = :lists.split(nameLen, rest)
    :ok

    case is_name_ok(name, flags) do
      true ->
        check_allowed(hSData, name)

        nodeOrHost =
          case name_type(flags) do
            :static ->
              :erlang.list_to_atom(name)

            :dynamic ->
              name
          end

        {flags, nodeOrHost, creation}

      false ->
        :dist_util.shutdown(:dist_util, 775, {:name, data})
    end
  end

  def is_node_name(nodeName) do
    is_name_ok(nodeName, 0)
  end

  defp is_name_ok(nodeOrHost, flags) do
    case {:string.split(nodeOrHost, ~c"@", :all), name_type(flags)} do
      {[name, host], :static} ->
        not :string.is_empty(host) and not :string.is_empty(name)

      {[host], :dynamic} ->
        not :string.is_empty(host)

      _ ->
        false
    end
  end

  def split_node(node) do
    split = :string.split(listify(node), ~c"@", :all)

    case split do
      [name, host] ->
        case :string.is_empty(name) do
          true ->
            split

          false ->
            case :string.is_empty(host) do
              true ->
                {:name, name}

              false ->
                {:node, name, host}
            end
        end

      [host] ->
        case :string.is_empty(host) do
          true ->
            split

          false ->
            {:host, host}
        end

      _ ->
        {:error, {:invalid_node, node}}
    end
  end

  defp check_allowed(r_hs_data(allowed: []), _Node) do
    :ok
  end

  defp check_allowed(r_hs_data(allowed: allowed) = hSData, node) do
    case is_allowed(node, allowed) do
      true ->
        :ok

      false ->
        send_status(r_hs_data(hSData, other_node: node), :not_allowed)
        error_msg(~c"** Connection attempt from disallowed node ~s ** ~n", [node])
        :dist_util.shutdown(:dist_util, 834, node, {:is_allowed, :not_allowed})
    end
  end

  def is_allowed(_Node, []) do
    false
  end

  def is_allowed(node, [node | _Allowed]) do
    true
  end

  def is_allowed(node, [allowedNode | allowed]) do
    case split_node(allowedNode) do
      {:node, allowedName, allowedHost} ->
        case split_node(node) do
          {:node, ^allowedName, ^allowedHost} ->
            true

          _ ->
            is_allowed(node, allowed)
        end

      {:host, allowedHost} ->
        case split_node(node) do
          {:node, _, ^allowedHost} ->
            true

          {:host, ^allowedHost} ->
            true

          _ ->
            is_allowed(node, allowed)
        end

      {:name, allowedName} ->
        case split_node(node) do
          {:node, ^allowedName, _} ->
            true

          {:name, ^allowedName} ->
            true

          _ ->
            is_allowed(node, allowed)
        end

      _ ->
        is_allowed(node, allowed)
    end
  end

  defp listify(atom) when is_atom(atom) do
    :erlang.atom_to_list(atom)
  end

  defp listify(node) when is_list(node) do
    node
  end

  defp listify(bin) when is_binary(bin) do
    :erlang.binary_to_list(bin)
  end

  defp publish_type(flags) do
    case flags &&& 1 do
      0 ->
        :hidden

      _ ->
        :normal
    end
  end

  defp recv_challenge(r_hs_data(socket: socket, f_recv: recv) = hSData) do
    case recv.(socket, 0, :infinity) do
      {:ok, [?N | _] = msg} ->
        recv_challenge_new(hSData, msg)

      other ->
        :dist_util.shutdown(:dist_util, 911, {:no_node, socket}, {:recv_challenge_failed, other})
    end
  end

  defp recv_challenge_new(
         r_hs_data(other_node: node),
         [
           ?N,
           f7,
           f6,
           f5,
           f4,
           f3,
           f2,
           f1,
           f0,
           ch3,
           ch2,
           ch1,
           ch0,
           cr3,
           cr2,
           cr1,
           cr0,
           nL1,
           nL0
           | rest
         ] = msg
       ) do
    <<flags::size(64)>> = <<f7, f6, f5, f4, f3, f2, f1, f0>>
    <<challenge::size(32)>> = <<ch3, ch2, ch1, ch0>>
    <<creation::size(32)>> = <<cr3, cr2, cr1, cr0>>
    <<nameLen::size(16)>> = <<nL1, nL0>>

    {ns, _Residue} =
      try do
        :lists.split(nameLen, rest)
      catch
        :error, :badarg ->
          :dist_util.shutdown(:dist_util, 929, :no_node, {:recv_challenge_failed, :no_node, msg})
      end

    :ok

    try do
      :erlang.list_to_existing_atom(ns)
    catch
      :error, :badarg ->
        :dist_util.shutdown(:dist_util, 941, :no_node, {:recv_challenge_failed, :no_node, ns})
    else
      ^node ->
        {flags, challenge, creation}

      _ ->
        :dist_util.shutdown(:dist_util, 938, :no_node, {:recv_challenge_failed, :no_node, ns})
    end
  end

  defp recv_challenge_new(_, other) do
    :dist_util.shutdown(:dist_util, 944, :no_node, {:recv_challenge_failed, other})
  end

  defp recv_complement(
         r_hs_data(socket: socket, f_recv: recv, other_flags: flags, other_creation: :undefined) =
           hSData
       ) do
    case recv.(socket, 0, :infinity) do
      {:ok, [?c, f7, f6, f5, f4, cr3, cr2, cr1, cr0]} ->
        <<flagsHigh::size(32)>> = <<f7, f6, f5, f4>>
        <<creation::size(32)>> = <<cr3, cr2, cr1, cr0>>
        :ok

        r_hs_data(hSData,
          other_creation: creation,
          other_flags: flags ||| flagsHigh <<< 32
        )

      other ->
        :dist_util.shutdown(:dist_util, 960, :no_node, {:recv_complement_failed, other})
    end
  end

  defp recv_complement(hSData) do
    hSData
  end

  defp recv_challenge_reply(
         r_hs_data(socket: socket, other_node: nodeB, f_recv: fRecv),
         challengeA,
         cookie
       ) do
    case fRecv.(socket, 0, :infinity) do
      {:ok, [?r, cB3, cB2, cB1, cB0 | sumB]}
      when length(sumB) === 16 ->
        sumA = gen_digest(challengeA, cookie)
        challengeB = cB3 <<< 24 ||| cB2 <<< 16 ||| cB1 <<< 8 ||| cB0
        :ok
        :ok

        case :erlang.list_to_binary(sumB) do
          ^sumA ->
            challengeB

          _ ->
            error_msg(
              ~c"** Connection attempt from node ~w rejected. Invalid challenge reply. **~n",
              [nodeB]
            )

            :dist_util.shutdown(
              :dist_util,
              986,
              nodeB,
              {:recv_challenge_reply_failed, :bad_cookie}
            )
        end

      other ->
        :dist_util.shutdown(
          :dist_util,
          989,
          {:no_node, socket},
          {:recv_challenge_reply_failed, other}
        )
    end
  end

  defp recv_challenge_ack(
         r_hs_data(socket: socket, f_recv: fRecv, other_node: nodeB),
         challengeB,
         cookieA
       ) do
    case fRecv.(socket, 0, :infinity) do
      {:ok, [?a | sumB]} when length(sumB) === 16 ->
        sumA = gen_digest(challengeB, cookieA)
        :ok
        :ok

        case :erlang.list_to_binary(sumB) do
          ^sumA ->
            :ok

          _ ->
            error_msg(
              ~c"** Connection attempt to node ~w cancelled. Invalid challenge ack. **~n",
              [nodeB]
            )

            :dist_util.shutdown(
              :dist_util,
              1007,
              {nodeB, socket},
              {:recv_challenge_ack_failed, :bad_cookie}
            )
        end

      other ->
        :dist_util.shutdown(
          :dist_util,
          1011,
          {nodeB, socket},
          {:recv_challenge_ack_failed, other}
        )
    end
  end

  defp recv_status(
         r_hs_data(
           kernel_pid: kernel,
           socket: socket,
           this_flags: myFlgs,
           other_node: node,
           f_recv: recv
         ) = hSData
       ) do
    case recv.(socket, 0, :infinity) do
      {:ok, ~c"snamed:" ++ rest} ->
        <<nameLen::size(16), nodeName::size(nameLen)-binary, creation::size(32), _::binary>> =
          :erlang.list_to_binary(rest)

        :dynamic = name_type(myFlgs)
        {:node, _Name, host} = split_node(nodeName)
        ^host = r_hs_data(hSData, :this_node)

        r_hs_data(hSData,
          this_node:
            :erlang.binary_to_atom(
              nodeName,
              :utf8
            ),
          this_creation: creation
        )

      {:ok, [?s | stat]} ->
        :ok

        case {stat, name_type(myFlgs)} do
          {~c"not_allowed", _} ->
            :dist_util.shutdown(
              :dist_util,
              1038,
              {node, socket},
              {:recv_status_failed, :not_allowed}
            )

          {_, :dynamic} ->
            :dist_util.shutdown(
              :dist_util,
              1041,
              {node, socket},
              {:recv_status_failed, :unexpected, stat}
            )

          _ ->
            :continue
        end

        case stat do
          ~c"nok" ->
            receive do
            after
              :infinity ->
                :ok
            end

          ~c"alive" ->
            reply = is_pending(kernel, node)
            :ok
            send_status(hSData, reply)

            cond do
              not reply ->
                :dist_util.shutdown(:dist_util, 1057, {node, socket})

              reply ->
                hSData
            end

          ~c"ok" ->
            hSData

          ~c"ok_simultaneous" ->
            hSData

          other ->
            :dist_util.shutdown(
              :dist_util,
              1064,
              {node, socket},
              {:recv_status_failed, :unknown, other}
            )
        end

      error ->
        :ok
        :dist_util.shutdown(:dist_util, 1070, {node, socket}, {:recv_status_failed, error})
    end
  end

  defp recv_status_reply(r_hs_data(socket: socket, other_node: node, f_recv: recv)) do
    case recv.(socket, 0, :infinity) do
      {:ok, [?s | stat]} ->
        :ok

        case stat do
          ~c"true" ->
            true

          ~c"false" ->
            false

          other ->
            :dist_util.shutdown(
              :dist_util,
              1084,
              {node, socket},
              {:recv_status_failed, :unexpected, other}
            )
        end

      error ->
        :ok
        :dist_util.shutdown(:dist_util, 1091, {node, socket}, {:recv_status_failed, error})
    end
  end

  defp send_status(
         r_hs_data(socket: socket, other_node: node, other_creation: creation, f_send: fSend),
         :named
       ) do
    :ok
    nameBin = :erlang.atom_to_binary(node, :utf8)
    nameLen = byte_size(nameBin)

    case fSend.(
           socket,
           [?s, ~c"named:", <<nameLen::size(16), nameBin::binary>>, <<creation::size(32)>>]
         ) do
      {:error, _} = error ->
        :dist_util.shutdown(:dist_util, 1107, {node, socket}, {:send_status_failed, error})

      _ ->
        :ok
    end
  end

  defp send_status(
         r_hs_data(socket: socket, other_node: node, f_send: fSend),
         stat
       ) do
    :ok

    case fSend.(
           socket,
           [?s | :erlang.atom_to_list(stat)]
         ) do
      {:error, _} = error ->
        :dist_util.shutdown(:dist_util, 1116, {node, socket}, {:send_status_failed, error})

      _ ->
        :ok
    end
  end

  defp to_port(fSend, socket, data) do
    case fSend.(socket, data) do
      {:error, :closed} ->
        send(self(), {:tcp_closed, socket})
        :ok

      {:error, _} = error ->
        :dist_util.shutdown(:dist_util, 1127, socket, {:f_send_failed, error})

      :ok ->
        :ok
    end
  end

  defp send_tick(
         r_state(
           handle: dHandle,
           socket: socket,
           tick_intensity: tickIntensity,
           publish_type: type,
           f_tick: mFTick,
           f_getstat: mFGetstat
         ),
         tick
       ) do
    r_tick(tick: t0, read: read, write: write, ticked: ticked0) = tick
    t = t0 + 1
    t1 = rem(t, tickIntensity)

    case getstat(dHandle, socket, mFGetstat) do
      {:ok, ^read, _, _} when ticked0 === t ->
        {:error, :not_responding}

      {:ok, r, w1, pend} ->
        rDiff = r - read

        w2 =
          case need_to_tick(type, rDiff, w1 - write, pend) do
            true ->
              mFTick.(socket)
              w1 + 1

            false ->
              w1
          end

        ticked1 =
          case rDiff do
            0 ->
              ticked0

            _ ->
              t
          end

        {:ok, r_tick(tick, write: w2, tick: t1, read: r, ticked: ticked1)}

      error ->
        error
    end
  end

  defp need_to_tick(_, _, 0, 0) do
    true
  end

  defp need_to_tick(_, _, 0, false) do
    true
  end

  defp need_to_tick(:hidden, 0, _, _) do
    true
  end

  defp need_to_tick(_, _, _, _) do
    false
  end

  defp send_aux_tick(r_state(publish_type: :normal), pend)
       when pend != false and pend != 0 do
    :ok
  end

  defp send_aux_tick(r_state(socket: socket, f_tick: mFTick), _Pend) do
    mFTick.(socket)
  end

  def start_timer(timeout) do
    spawn_link(:dist_util, :setup_timer, [self(), timeout * 1])
  end

  def setup_timer(pid, timeout) do
    receive do
      {^pid, :reset} ->
        setup_timer(pid, timeout)
    after
      timeout ->
        :ok
        :dist_util.shutdown(:dist_util, 1226, {:timer, pid}, :setup_timer_timeout)
    end
  end

  def reset_timer(timer) do
    send(timer, {self(), :reset})
    :ok
  end

  def cancel_timer(timer) do
    :erlang.unlink(timer)
    :erlang.exit(timer, :cancel_setup_timer)
  end

  def net_ticker_spawn_options() do
    opts = :application.get_env(:kernel, :net_ticker_spawn_options, [])

    [
      :link,
      {:priority, :max}
      | cleanup_net_ticker_spawn_options(opts)
    ]
  end

  defp cleanup_net_ticker_spawn_options([]) do
    []
  end

  defp cleanup_net_ticker_spawn_options([:link | opts]) do
    cleanup_net_ticker_spawn_options(opts)
  end

  defp cleanup_net_ticker_spawn_options([{:priority, _} | opts]) do
    cleanup_net_ticker_spawn_options(opts)
  end

  defp cleanup_net_ticker_spawn_options([:monitor | opts]) do
    cleanup_net_ticker_spawn_options(opts)
  end

  defp cleanup_net_ticker_spawn_options([{:monitor, _} | opts]) do
    cleanup_net_ticker_spawn_options(opts)
  end

  defp cleanup_net_ticker_spawn_options([opt | opts]) do
    [opt | cleanup_net_ticker_spawn_options(opts)]
  end
end
