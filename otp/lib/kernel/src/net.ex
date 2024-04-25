defmodule :m_net do
  use Bitwise

  def call(n, m, f, a) do
    :rpc.call(n, m, f, a)
  end

  def cast(n, m, f, a) do
    :rpc.cast(n, m, f, a)
  end

  def broadcast(m, f, a) do
    :rpc.eval_everywhere(m, f, a)
  end

  def ping(node) do
    :net_adm.ping(node)
  end

  def sleep(t) do
    receive do
    after
      t ->
        :ok
    end
  end

  def info() do
    :prim_net.info()
  end

  def command(cmd) do
    :prim_net.command(cmd)
  end

  def gethostname() do
    :prim_net.gethostname()
  end

  def getnameinfo(sockAddr) do
    getnameinfo(sockAddr, :undefined)
  end

  def getnameinfo(sockAddr, flags)
      when (is_map(sockAddr) and
              is_list(flags)) or
             (is_map(sockAddr) and flags === :undefined) do
    :prim_net.getnameinfo(sockAddr, flags)
  end

  def getaddrinfo(host) when is_list(host) do
    getaddrinfo(host, :undefined)
  end

  def getaddrinfo(host, service)
      when (is_list(host) or host === :undefined) and (is_list(service) or service === :undefined) and
             not (service === :undefined and host === :undefined) do
    :prim_net.getaddrinfo(host, service)
  end

  def getifaddrs() do
    getifaddrs(:default)
  end

  def getifaddrs(filter) when is_atom(filter) or is_map(filter) do
    do_getifaddrs(
      getifaddrs_filter_map(filter),
      fn ->
        :prim_net.getifaddrs(%{})
      end
    )
  end

  def getifaddrs(filter) when is_function(filter, 1) do
    do_getifaddrs(
      filter,
      fn ->
        :prim_net.getifaddrs(%{})
      end
    )
  end

  def getifaddrs(namespace) when is_list(namespace) do
    getifaddrs(:default, namespace)
  end

  def getifaddrs(filter, namespace)
      when (is_atom(filter) or is_map(filter)) and is_list(namespace) do
    do_getifaddrs(
      getifaddrs_filter_map(filter),
      fn ->
        getifaddrs(namespace)
      end
    )
  end

  def getifaddrs(filter, namespace)
      when is_function(
             filter,
             1
           ) and is_list(namespace) do
    do_getifaddrs(
      filter,
      fn ->
        getifaddrs(namespace)
      end
    )
  end

  defp do_getifaddrs(filter, getIfAddrs) do
    try do
      getIfAddrs.()
    catch
      c, e when c === :error and e === :notsup ->
        try do
          win_getifaddrs(filter)
        catch
          _WC, _WE ->
            :erlang.raise(c, e, s)
        end
    else
      {:ok, ifAddrs0} when is_function(filter) ->
        {:ok, :lists.filtermap(filter, ifAddrs0)}

      {:ok, ifAddrs0} when is_map(filter) ->
        filterFun = fn elem ->
          getifaddrs_filter(filter, elem)
        end

        {:ok, :lists.filtermap(filterFun, ifAddrs0)}

      {:error, _} = eRROR ->
        eRROR
    end
  end

  defp getifaddrs_filter_map(:all) do
    getifaddrs_filter_map_all()
  end

  defp getifaddrs_filter_map(:default) do
    getifaddrs_filter_map_default()
  end

  defp getifaddrs_filter_map(:inet) do
    getifaddrs_filter_map_inet()
  end

  defp getifaddrs_filter_map(:inet6) do
    getifaddrs_filter_map_inet6()
  end

  defp getifaddrs_filter_map(:packet) do
    getifaddrs_filter_map_packet()
  end

  defp getifaddrs_filter_map(filterMap) when is_map(filterMap) do
    :maps.merge(getifaddrs_filter_map_default(), filterMap)
  end

  defp getifaddrs_filter_map_all() do
    %{family: :all, flags: :any}
  end

  defp getifaddrs_filter_map_default() do
    %{family: :default, flags: :any}
  end

  defp getifaddrs_filter_map_inet() do
    %{family: :inet, flags: :any}
  end

  defp getifaddrs_filter_map_inet6() do
    %{family: :inet6, flags: :any}
  end

  defp getifaddrs_filter_map_packet() do
    %{family: :packet, flags: :any}
  end

  defp getifaddrs_filter(
         %{family: fFamily, flags: fFlags},
         %{addr: %{family: family}, flags: flags} = _Entry
       )
       when fFamily === :default and (family === :inet or family === :inet6) do
    getifaddrs_filter_flags(fFlags, flags)
  end

  defp getifaddrs_filter(
         %{family: fFamily, flags: fFlags},
         %{addr: %{family: family}, flags: flags} = _Entry
       )
       when fFamily === :inet and family === :inet do
    getifaddrs_filter_flags(fFlags, flags)
  end

  defp getifaddrs_filter(
         %{family: fFamily, flags: fFlags},
         %{addr: %{family: family}, flags: flags} = _Entry
       )
       when fFamily === :inet6 and family === :inet6 do
    getifaddrs_filter_flags(fFlags, flags)
  end

  defp getifaddrs_filter(
         %{family: fFamily, flags: fFlags},
         %{addr: %{family: family}, flags: flags} = _Entry
       )
       when fFamily === :packet and family === :packet do
    getifaddrs_filter_flags(fFlags, flags)
  end

  defp getifaddrs_filter(
         %{family: fFamily, flags: fFlags},
         %{flags: flags} = _Entry
       )
       when fFamily === :all do
    getifaddrs_filter_flags(fFlags, flags)
  end

  defp getifaddrs_filter(_Filter, _Entry) do
    false
  end

  defp getifaddrs_filter_flags(:any, _Flags) do
    true
  end

  defp getifaddrs_filter_flags(filterFlags, flags) do
    [] === filterFlags -- flags
  end

  defp win_getifaddrs(filter) do
    adsAddrs = get_adapters_addresses()
    ipAddrTab = get_ip_address_table(adsAddrs)
    ipIfInfo = get_interface_info()
    win_getifaddrs(filter, adsAddrs, ipAddrTab, ipIfInfo)
  end

  defp get_adapters_addresses() do
    case :prim_net.get_adapters_addresses(%{}) do
      {:ok, adaptersAddresses} ->
        adaptersAddresses

      {:error, _} ->
        []
    end
  end

  defp get_ip_address_table([]) do
    case :prim_net.get_ip_address_table(%{}) do
      {:ok, ipAddressTable} ->
        ipAddressTable

      {:error, _} ->
        []
    end
  end

  defp get_ip_address_table(_) do
    []
  end

  defp get_interface_info() do
    case :prim_net.get_interface_info(%{}) do
      {:ok, interfaceInfo} ->
        interfaceInfo

      {:error, _} ->
        []
    end
  end

  defp win_getifaddrs(filter, [], ipAddrTab, ipIfInfo)
       when ipAddrTab !== [] do
    win_getifaddrs_iat(filter, ipAddrTab, ipIfInfo)
  end

  defp win_getifaddrs(filter, adsAddrs, _IpAddrTab, ipIfInfo)
       when adsAddrs !== [] do
    win_getifaddrs_aa(filter, adsAddrs, ipIfInfo)
  end

  defp win_getifaddrs(_Filter, adsAddrs, ipAddrTab, ipIfInfo) do
    throw({:error, {:insufficient_info, adsAddrs, ipAddrTab, ipIfInfo}})
  end

  defp win_getifaddrs_iat(filter, ipAddrTab, ipIfInfos)
       when is_function(filter) do
    ifAddrs = win_getifaddrs_iat2(ipAddrTab, ipIfInfos)
    {:ok, :lists.filtermap(filter, ifAddrs)}
  end

  defp win_getifaddrs_iat(filter, ipAddrTab, ipIfInfos)
       when is_map(filter) do
    ifAddrs = win_getifaddrs_iat2(ipAddrTab, ipIfInfos)

    filterFun = fn elem ->
      getifaddrs_filter(filter, elem)
    end

    {:ok, :lists.filtermap(filterFun, ifAddrs)}
  end

  defp win_getifaddrs_iat2(ipAddrTab, ipIfInfos) do
    win_getifaddrs_iat2(ipAddrTab, ipIfInfos, [])
  end

  defp win_getifaddrs_iat2([], _IpIfInfos, acc) do
    :lists.reverse(acc)
  end

  defp win_getifaddrs_iat2([%{index: idx} = ipAddr | ipAddrTab], ipIfInfos, acc) do
    case :prim_net.get_if_entry(%{index: idx}) do
      {:ok, %{name: name} = ifEntry} when name !== ~c"" ->
        {ifAddr, pktIfAddr} = win_getifaddrs_iat3(name, ipAddr, ifEntry)
        win_getifaddrs_iat2(ipAddrTab, ipIfInfos, [ifAddr, pktIfAddr | acc])

      {:ok, %{name: name, description: desc} = ifEntry}
      when name === ~c"" ->
        case if_info_search(idx, ipIfInfos) do
          {:value, %{name: name2}} ->
            {ifAddr, pktIfAddr} = win_getifaddrs_iat3(name2, ipAddr, ifEntry)
            win_getifaddrs_iat2(ipAddrTab, ipIfInfos, [ifAddr, pktIfAddr | acc])

          false ->
            {ifAddr, pktIfAddr} = win_getifaddrs_iat3(desc, ipAddr, ifEntry)
            win_getifaddrs_iat2(ipAddrTab, ipIfInfos, [ifAddr, pktIfAddr | acc])
        end

      {:error, _} ->
        win_getifaddrs_iat2(ipAddrTab, ipIfInfos, acc)
    end
  end

  defp win_getifaddrs_iat3(
         name,
         %{addr: addr, mask: mask, bcast_addr: _BCastAddr} = _IpAddr,
         %{
           type: type,
           admin_status: aStatus,
           internal_oper_status: _OStatus,
           phys_addr: physAddr,
           index: idx
         } = _IfEntry
       ) do
    flags1 =
      case type do
        :ethernet_csmacd ->
          [:broadcast, :multicast]

        :software_loopback ->
          [:loopback]

        _ ->
          []
      end

    flags2 =
      case aStatus do
        :non_operational ->
          []

        :connecting ->
          [:up, :pointtopoint]

        :connected ->
          [:up, :runnning, :pointtopoint]

        :operational ->
          [:up, :running]

        _ ->
          [:up]
      end

    flags = :lists.sort(flags1 ++ flags2)
    haType = type2hatype(type)

    pktSockAddr = %{
      addr: process_phys_addr(haType, physAddr),
      family: :packet,
      hatype: haType,
      ifindex: idx,
      pkttype: :host,
      protocol: 0
    }

    pktIfAddr =
      case haType do
        :loopback ->
          %{name: name, addr: pktSockAddr, flags: flags}

        _ ->
          %{
            name: name,
            addr: pktSockAddr,
            broadaddr:
              <<255::size(8), 255::size(8), 255::size(8), 255::size(8), 255::size(8),
                255::size(8)>>,
            flags: flags
          }
      end

    ifAddr = %{
      name: name,
      flags: flags,
      addr: mk_sockaddr_in(addr),
      netmask: mk_sockaddr_in(mask),
      broadaddr: mk_sockaddr_in(iat_broadaddr(addr, mask))
    }

    {ifAddr, pktIfAddr}
  end

  defp mk_sockaddr_in(addr) do
    %{addr: addr, family: :inet, port: 0}
  end

  defp win_getifaddrs_aa(filter, adsAddrs, ipIfInfo)
       when is_function(filter) do
    ifAddrs = win_getifaddrs_aa2(adsAddrs, ipIfInfo)
    {:ok, :lists.filtermap(filter, ifAddrs)}
  end

  defp win_getifaddrs_aa(filter, adsAddrs, ipIfInfo)
       when is_map(filter) do
    ifAddrs = win_getifaddrs_aa2(adsAddrs, ipIfInfo)

    filterFun = fn elem ->
      getifaddrs_filter(filter, elem)
    end

    {:ok, :lists.filtermap(filterFun, ifAddrs)}
  end

  defp win_getifaddrs_aa2(adsAddrs, ipIfInfo) do
    win_getifaddrs_aa2(adsAddrs, ipIfInfo, [])
  end

  defp win_getifaddrs_aa2([], _IpIfInfo, acc) do
    :lists.reverse(:lists.flatten(acc))
  end

  defp win_getifaddrs_aa2([%{index: idx} = adAddrs | adsAddrs], ipIfInfos, acc) do
    case :prim_net.get_if_entry(%{index: idx}) do
      {:ok, %{name: name} = ifEntry} when name !== ~c"" ->
        {ifAddrs, pktIfAddr} = win_getifaddrs_aa3(name, adAddrs, ifEntry)
        win_getifaddrs_aa2(adsAddrs, ipIfInfos, [ifAddrs, pktIfAddr | acc])

      {:ok, %{name: name, description: desc} = ifEntry}
      when name === ~c"" ->
        case if_info_search(idx, ipIfInfos) do
          {:value, %{name: name2}} ->
            {ifAddrs, pktIfAddr} = win_getifaddrs_aa3(name2, adAddrs, ifEntry)
            win_getifaddrs_aa2(adsAddrs, ipIfInfos, [ifAddrs, pktIfAddr | acc])

          false ->
            {ifAddrs, pktIfAddr} = win_getifaddrs_aa3(desc, adAddrs, ifEntry)
            win_getifaddrs_aa2(adsAddrs, ipIfInfos, [ifAddrs, pktIfAddr | acc])
        end

      {:error, _} ->
        win_getifaddrs_aa2(adsAddrs, ipIfInfos, acc)
    end
  end

  defp win_getifaddrs_aa3(
         name,
         %{flags: %{no_multicast: noMC}, unicast_addrs: uCastAddrs, prefixes: prefixes} =
           _AdAddrs,
         %{
           type: type,
           admin_status: aStatus,
           internal_oper_status: _OStatus,
           phys_addr: physAddr,
           index: idx
         } = _IfEntry
       ) do
    flags1 =
      cond do
        noMC === false ->
          [:multicast]

        true ->
          []
      end

    flags2 =
      case type do
        :ethernet_csmacd ->
          [:broadcast]

        :software_loopback ->
          [:loopback]

        _ ->
          []
      end

    flags3 =
      case aStatus do
        :non_operational ->
          []

        :connecting ->
          [:up, :pointtopoint]

        :connected ->
          [:up, :runnning, :pointtopoint]

        :operational ->
          [:up, :running]

        _ ->
          [:up]
      end

    flags = :lists.sort(flags1 ++ flags2 ++ flags3)
    haType = type2hatype(type)

    pktSockAddr = %{
      addr: process_phys_addr(haType, physAddr),
      family: :packet,
      hatype: haType,
      ifindex: idx,
      pkttype: :host,
      protocol: 0
    }

    pktIfAddr =
      case haType do
        :loopback ->
          %{name: name, addr: pktSockAddr, flags: flags}

        _ ->
          %{
            name: name,
            addr: pktSockAddr,
            broadaddr:
              <<255::size(8), 255::size(8), 255::size(8), 255::size(8), 255::size(8),
                255::size(8)>>,
            flags: flags
          }
      end

    ifAddrs =
      for uCastAddr <- uCastAddrs do
        win_getifaddrs_aa4(name, flags, prefixes, uCastAddr)
      end

    {ifAddrs, pktIfAddr}
  end

  defp type2hatype(:ethernet_csmacd) do
    :ether
  end

  defp type2hatype(:software_loopback) do
    :loopback
  end

  defp type2hatype(other) do
    other
  end

  defp process_phys_addr(:loopback, <<>>) do
    <<0::size(8), 0::size(8), 0::size(8), 0::size(8), 0::size(8), 0::size(8)>>
  end

  defp process_phys_addr(_, bin) when is_binary(bin) do
    bin
  end

  defp win_getifaddrs_aa4(name, flags, prefixes, %{addr: %{family: fam} = addr} = uCAddr) do
    sPrefix = shortest_matching_prefix(uCAddr, prefixes)
    mask = win_getifaddrs_mask(sPrefix)

    case :lists.member(:broadcast, flags) do
      true when fam === :inet ->
        broadAddr = win_getifaddrs_broadaddr(mask, sPrefix)
        %{name: name, flags: flags, addr: addr, netmask: mask, broadaddr: broadAddr}

      _ ->
        %{name: name, flags: flags, addr: addr, netmask: mask}
    end
  end

  defp shortest_matching_prefix(%{addr: addr} = uCAddr, prefixes) do
    sPrefix = %{addr: addr, length: :undefined}
    shortest_matching_prefix(uCAddr, prefixes, sPrefix)
  end

  defp shortest_matching_prefix(%{addr: %{family: :inet, addr: {a, _, _, _}} = addr}, [], %{
         length: :undefined
       }) do
    shortest =
      cond do
        a < 128 ->
          8

        a < 192 ->
          16

        a < 224 ->
          24

        true ->
          32
      end

    %{addr: addr, length: shortest}
  end

  defp shortest_matching_prefix(%{addr: %{family: :inet6} = addr}, [], %{length: :undefined}) do
    %{addr: addr, length: 128}
  end

  defp shortest_matching_prefix(_UCAddr, [], sPrefix) do
    sPrefix
  end

  defp shortest_matching_prefix(
         %{addr: %{family: fam, addr: addr}} = uCAddr,
         [
           %{addr: %{family: fam, addr: pAddr}, length: pLen} = prefix
           | prefixes
         ],
         %{length: sPLen} = sPrefix
       )
       when fam === :inet do
    mask = <<4_294_967_295 <<< (32 - pLen)::size(32)>>

    case masked_eq(mask, ipv4_to_bin(addr), ipv4_to_bin(pAddr)) do
      true ->
        cond do
          sPLen === :undefined ->
            shortest_matching_prefix(uCAddr, prefixes, prefix)

          pLen < sPLen ->
            shortest_matching_prefix(uCAddr, prefixes, prefix)

          true ->
            shortest_matching_prefix(uCAddr, prefixes, sPrefix)
        end

      false ->
        shortest_matching_prefix(uCAddr, prefixes, sPrefix)
    end
  end

  defp shortest_matching_prefix(
         %{addr: %{family: fam, addr: addr}} = uCAddr,
         [
           %{addr: %{family: fam, addr: pAddr}, length: pLen} = prefix
           | prefixes
         ],
         %{length: sPLen} = sPrefix
       )
       when fam === :inet6 do
    mask = <<340_282_366_920_938_463_463_374_607_431_768_211_455 <<< (128 - pLen)::size(128)>>

    case masked_eq(mask, ipv6_to_bin(addr), ipv6_to_bin(pAddr)) do
      true ->
        cond do
          sPLen === :undefined ->
            shortest_matching_prefix(uCAddr, prefixes, prefix)

          pLen < sPLen ->
            shortest_matching_prefix(uCAddr, prefixes, prefix)

          true ->
            shortest_matching_prefix(uCAddr, prefixes, sPrefix)
        end

      false ->
        shortest_matching_prefix(uCAddr, prefixes, sPrefix)
    end
  end

  defp shortest_matching_prefix(uCAddr, [_Prefix | prefixes], sPrefix) do
    shortest_matching_prefix(uCAddr, prefixes, sPrefix)
  end

  defp masked_eq(<<m::size(32)>>, <<a::size(32)>>, <<pA::size(32)>>) do
    a &&& m === pA &&& m
  end

  defp masked_eq(
         <<m01::size(8), m02::size(8), m03::size(8), m04::size(8), m05::size(8), m06::size(8),
           m07::size(8), m08::size(8), m09::size(8), m10::size(8), m11::size(8), m12::size(8),
           m13::size(8), m14::size(8), m15::size(8), m16::size(8)>>,
         <<a01::size(8), a02::size(8), a03::size(8), a04::size(8), a05::size(8), a06::size(8),
           a07::size(8), a08::size(8), a09::size(8), a10::size(8), a11::size(8), a12::size(8),
           a13::size(8), a14::size(8), a15::size(8), a16::size(8)>>,
         <<pA01::size(8), pA02::size(8), pA03::size(8), pA04::size(8), pA05::size(8),
           pA06::size(8), pA07::size(8), pA08::size(8), pA09::size(8), pA10::size(8),
           pA11::size(8), pA12::size(8), pA13::size(8), pA14::size(8), pA15::size(8),
           pA16::size(8)>>
       ) do
    a01 &&& m01 === pA01 &&& m01 and a02 &&& m02 === pA02 &&& m02 and a03 &&& m03 === pA03 &&& m03 and
      a04 &&& m04 === pA04 &&& m04 and a05 &&& m05 === pA05 &&& m05 and a06 &&& m06 === pA06 &&&
      m06 and a07 &&& m07 === pA07 &&& m07 and a08 &&& m08 === pA08 &&& m08 and a09 &&&
      m09 === pA09 &&& m09 and a10 &&& m10 === pA10 &&& m10 and a11 &&& m11 === pA11 &&& m11 and
      a12 &&& m12 === pA12 &&& m12 and a13 &&& m13 === pA13 &&& m13 and a14 &&& m14 === pA14 &&&
      m14 and a15 &&& m15 === pA15 &&& m15 and a16 &&& m16 === pA16 &&& m16
  end

  defp ipv4_to_bin({a1, a2, a3, a4}) do
    <<a1::size(8), a2::size(8), a3::size(8), a4::size(8)>>
  end

  defp ipv6_to_bin({a1, a2, a3, a4, a5, a6, a7, a8}) do
    <<a1::size(16), a2::size(16), a3::size(16), a4::size(16), a5::size(16), a6::size(16),
      a7::size(16), a8::size(16)>>
  end

  defp if_info_search(_Idx, []) do
    false
  end

  defp if_info_search(idx, [%{index: idx} = ifInfo | _IfInfos]) do
    {:value, ifInfo}
  end

  defp if_info_search(idx, [_ | ifInfos]) do
    if_info_search(idx, ifInfos)
  end

  defp win_getifaddrs_mask(%{addr: %{addr: _Addr, family: :inet = fam}, length: len}) do
    <<m1::size(8), m2::size(8), m3::size(8), m4::size(8)>> =
      <<4_294_967_295 <<< (32 - len)::size(32)>>

    %{addr: {m1, m2, m3, m4}, family: fam, port: 0}
  end

  defp win_getifaddrs_mask(%{addr: %{addr: _Addr, family: :inet6 = fam}, length: len}) do
    <<m1::size(16), m2::size(16), m3::size(16), m4::size(16), m5::size(16), m6::size(16),
      m7::size(16),
      m8::size(16)>> =
      <<340_282_366_920_938_463_463_374_607_431_768_211_455 <<< (128 - len)::size(128)>>

    %{addr: {m1, m2, m3, m4, m5, m6, m7, m8}, family: fam, flowinfo: 0, port: 0, scope_id: 0}
  end

  defp win_getifaddrs_broadaddr(
         %{addr: {m1, m2, m3, m4}, family: fam} = _Mask,
         %{addr: %{addr: {pA1, pA2, pA3, pA4}}} = _Prefix
       ) do
    bA1 = 255 &&& (pA1 ||| ~~~m1)
    bA2 = 255 &&& (pA2 ||| ~~~m2)
    bA3 = 255 &&& (pA3 ||| ~~~m3)
    bA4 = 255 &&& (pA4 ||| ~~~m4)
    %{family: fam, addr: {bA1, bA2, bA3, bA4}, port: 0}
  end

  defp iat_broadaddr({a1, a2, a3, a4}, {m1, m2, m3, m4}) do
    bA1 = 255 &&& (a1 ||| ~~~m1)
    bA2 = 255 &&& (a2 ||| ~~~m2)
    bA3 = 255 &&& (a3 ||| ~~~m3)
    bA4 = 255 &&& (a4 ||| ~~~m4)
    %{family: :inet, addr: {bA1, bA2, bA3, bA4}, port: 0}
  end

  def if_name2index(name) when is_list(name) do
    try do
      :prim_net.if_name2index(name)
    catch
      c, e when c === :error and e === :notsup ->
        try do
          win_name2index(name)
        catch
          _, _ ->
            :erlang.raise(c, e, __STACKTRACE__)
        end
    else
      result ->
        result
    end
  end

  def if_index2name(idx) when is_integer(idx) do
    try do
      :prim_net.if_index2name(idx)
    catch
      c, e when c === :error and e === :notsup ->
        try do
          win_index2name(idx)
        catch
          _, _ ->
            :erlang.raise(c, e, __STACKTRACE__)
        end
    else
      result ->
        result
    end
  end

  def if_names() do
    try do
      :prim_net.if_names()
    catch
      c, e when c === :error and e === :notsup ->
        try do
          {:ok, win_names()}
        catch
          _, _ ->
            :erlang.raise(c, e, __STACKTRACE__)
        end
    else
      result ->
        result
    end
  end

  defp win_names() do
    for idx <- win_indexes() do
      {idx, win_name(idx)}
    end
  end

  defp win_indexes() do
    case :prim_net.get_adapters_addresses(%{
           flags: %{skip_unicast: true, skip_friendly_name: true, include_prefix: false}
         }) do
      {:ok, aA} ->
        indexes =
          for %{index: idx} <- aA do
            idx
          end

        :lists.sort(indexes)

      {:error, _} ->
        case :prim_net.get_ip_address_table(%{}) do
          {:ok, tab} ->
            indexes =
              for %{index: idx} <- tab do
                idx
              end

            :lists.sort(indexes)

          {:error, _} ->
            throw({:error, :no_index})
        end
    end
  end

  defp win_name(idx) do
    case :prim_net.get_if_entry(%{index: idx}) do
      {:ok, %{name: name}} ->
        name

      {:error, _} ->
        throw({:error, :no_entry})
    end
  end

  defp win_index2name(idx) do
    case :lists.keysearch(idx, 1, win_names()) do
      {:value, {^idx, name}} ->
        {:ok, name}

      false ->
        {:error, :enxio}
    end
  end

  defp win_name2index(name) do
    case :lists.keysearch(name, 2, win_names()) do
      {:value, {idx, ^name}} ->
        {:ok, idx}

      false ->
        {:error, :enodev}
    end
  end
end
