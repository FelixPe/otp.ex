defmodule :m_inet_res do
  use Bitwise
  require Record

  Record.defrecord(:r_hostent, :hostent,
    h_name: :undefined,
    h_aliases: [],
    h_addrtype: :undefined,
    h_length: :undefined,
    h_addr_list: []
  )

  Record.defrecord(:r_dns_header, :dns_header,
    id: 0,
    qr: 0,
    opcode: 0,
    aa: 0,
    tc: 0,
    rd: 0,
    ra: 0,
    pr: 0,
    rcode: 0
  )

  Record.defrecord(:r_dns_rec, :dns_rec,
    header: :undefined,
    qdlist: [],
    anlist: [],
    nslist: [],
    arlist: []
  )

  Record.defrecord(:r_dns_rr, :dns_rr,
    domain: ~c"",
    type: :any,
    class: :in,
    cnt: 0,
    ttl: 0,
    data: [],
    tm: :undefined,
    bm: ~c"",
    func: false
  )

  Record.defrecord(:r_dns_rr_opt, :dns_rr_opt,
    domain: ~c"",
    type: :opt,
    udp_payload_size: 1280,
    ext_rcode: 0,
    version: 0,
    z: 0,
    data: [],
    do: false
  )

  Record.defrecord(:r_dns_query, :dns_query,
    domain: :undefined,
    type: :undefined,
    class: :undefined,
    unicast_response: false
  )

  Record.defrecord(:r_connect_opts, :connect_opts, ifaddr: :undefined, port: 0, fd: -1, opts: [])

  Record.defrecord(:r_listen_opts, :listen_opts,
    ifaddr: :undefined,
    port: 0,
    backlog: 5,
    fd: -1,
    opts: []
  )

  Record.defrecord(:r_udp_opts, :udp_opts,
    ifaddr: :undefined,
    port: 0,
    fd: -1,
    opts: [{:active, true}]
  )

  Record.defrecord(:r_sctp_opts, :sctp_opts,
    ifaddr: :undefined,
    port: 0,
    fd: -1,
    type: :seqpacket,
    opts: [
      {:mode, :binary},
      {:buffer, 65536},
      {:sndbuf, 65536},
      {:recbuf, 1024},
      {:sctp_events, :undefined}
    ]
  )

  def resolve(name, class, type) do
    resolve(name, class, type, [], :infinity)
  end

  def resolve(name, class, type, opts) do
    resolve(name, class, type, opts, :infinity)
  end

  def resolve(name, class, type, opts, timeout) do
    case nsdname(name) do
      {:ok, nm} ->
        timer = :inet.start_timer(timeout)
        res = res_query(nm, class, type, opts, timer)
        _ = :inet.stop_timer(timer)
        res

      {:error, _} = error ->
        error
    end
  end

  def lookup(name, class, type) do
    lookup(name, class, type, [])
  end

  def lookup(name, class, type, opts) do
    lookup(name, class, type, opts, :infinity)
  end

  def lookup(name, class, type, opts, timeout) do
    lookup_filter(resolve(name, class, type, opts, timeout), class, type)
  end

  defp lookup_filter({:ok, r_dns_rec(anlist: answers)}, class, type) do
    for a <- answers,
        class === :any or r_dns_rr(a, :class) === class,
        type === :any or r_dns_rr(a, :type) === type do
      r_dns_rr(a, :data)
    end
  end

  defp lookup_filter({:error, _}, _, _) do
    []
  end

  def nslookup(name, class, type) do
    do_nslookup(name, class, type, [], :infinity)
  end

  def nslookup(name, class, type, timeout)
      when is_integer(timeout) and timeout >= 0 do
    do_nslookup(name, class, type, [], timeout)
  end

  def nslookup(name, class, type, nSs) do
    nnslookup(name, class, type, nSs)
  end

  def nnslookup(name, class, type, nSs) do
    nnslookup(name, class, type, nSs, :infinity)
  end

  def nnslookup(name, class, type, nSs, timeout) do
    do_nslookup(name, class, type, [{:nameservers, nSs}], timeout)
  end

  defp do_nslookup(name, class, type, opts, timeout) do
    case resolve(name, class, type, opts, timeout) do
      {:error, {:qfmterror, _}} ->
        {:error, :einval}

      {:error, {reason, _}} ->
        {:error, reason}

      result ->
        result
    end
  end

  Record.defrecord(:r_options, :options,
    alt_nameservers: :undefined,
    dnssec_ok: :undefined,
    edns: :undefined,
    inet6: :undefined,
    nameservers: :undefined,
    nxdomain_reply: :undefined,
    recurse: :undefined,
    retry: :undefined,
    servfail_retry_timeout: :undefined,
    timeout: :undefined,
    udp_payload_size: :undefined,
    usevc: :undefined,
    verbose: :undefined
  )

  defp make_options(opts0) do
    opts =
      for opt <- opts0 do
        cond do
          is_atom(opt) ->
            case :erlang.atom_to_list(opt) do
              ~c"no" ++ x ->
                {:erlang.list_to_atom(x), false}

              _ ->
                {opt, true}
            end

          true ->
            opt
        end
      end

    sortedOpts =
      :lists.ukeysort(
        1,
        case :lists.keymember(:nameservers, 1, opts) do
          true ->
            case :lists.keymember(:alt_nameservers, 1, opts) do
              false ->
                [{:alt_nameservers, []} | opts]

              true ->
                opts
            end

          false ->
            opts
        end
      )

    sortedNames = Keyword.keys(r_options(r_options()))
    :inet_db.res_update_conf()

    :erlang.list_to_tuple([
      :options
      | make_options(sortedOpts, sortedNames)
    ])
  end

  defp make_options([_ | _] = opts0, [] = names0) do
    :erlang.error(:badarg, [opts0, names0])
  end

  defp make_options([], []) do
    []
  end

  defp make_options(
         [{opt, val} | opts] = opts0,
         [opt | names] = names0
       )
       when opt === :nxdomain_reply or opt === :verbose do
    cond do
      is_boolean(val) ->
        [val | make_options(opts, names)]

      true ->
        :erlang.error(:badarg, [opts0, names0])
    end
  end

  defp make_options(
         [{opt, val} | opts] = opts0,
         [opt | names] = names0
       ) do
    case :inet_db.res_check_option(opt, val) do
      true ->
        [val | make_options(opts, names)]

      false ->
        :erlang.error(:badarg, [opts0, names0])
    end
  end

  defp make_options(opts, [:nxdomain_reply | names]) do
    [false | make_options(opts, names)]
  end

  defp make_options(opts, [:verbose | names]) do
    [false | make_options(opts, names)]
  end

  defp make_options(opts, [name | names]) do
    [:inet_db.res_option(name) | make_options(opts, names)]
  end

  def gethostbyaddr(iP) do
    gethostbyaddr_tm(iP, false)
  end

  def gethostbyaddr(iP, timeout) do
    timer = :inet.start_timer(timeout)
    res = gethostbyaddr_tm(iP, timer)
    _ = :inet.stop_timer(timer)
    res
  end

  def gethostbyaddr_tm(addr, timer) when is_atom(addr) do
    gethostbyaddr_tm(:erlang.atom_to_list(addr), timer)
  end

  def gethostbyaddr_tm(addr, timer) when is_list(addr) do
    case :inet_parse.address(addr) do
      {:ok, iP} ->
        gethostbyaddr_tm(iP, timer)

      _Error ->
        {:error, :formerr}
    end
  end

  def gethostbyaddr_tm(iP, timer) do
    case dn_ip(norm_ip(iP)) do
      {:error, _} = error ->
        error

      {:ok, name} ->
        :inet_db.res_update_conf()

        case :inet_db.gethostbyaddr(name, iP) do
          {:ok, _HEnt} = result ->
            result

          {:error, :nxdomain} ->
            case res_query(name, :in, :ptr, [], timer) do
              {:ok, rec} ->
                :inet_db.res_gethostbyaddr(name, iP, rec)

              {:error, {:qfmterror, _}} ->
                {:error, :einval}

              {:error, {reason, _}} ->
                {:error, reason}

              error ->
                error
            end
        end
    end
  end

  def gethostbyname(name) do
    case :inet_db.res_option(:inet6) do
      true ->
        gethostbyname_tm(name, :inet6, false)

      false ->
        gethostbyname_tm(name, :inet, false)
    end
  end

  def gethostbyname(name, family) do
    gethostbyname_tm(name, family, false)
  end

  def gethostbyname(name, family, timeout) do
    timer = :inet.start_timer(timeout)
    res = gethostbyname_tm(name, family, timer)
    _ = :inet.stop_timer(timer)
    res
  end

  def gethostbyname_tm(name, :inet, timer) do
    getbyname_tm(name, :a, timer)
  end

  def gethostbyname_tm(name, :inet6, timer) do
    getbyname_tm(name, :aaaa, timer)
  end

  def gethostbyname_tm(_Name, _Family, _Timer) do
    {:error, :einval}
  end

  def getbyname(name, type) do
    getbyname_tm(name, type, false)
  end

  def getbyname(name, type, timeout) do
    timer = :inet.start_timer(timeout)
    res = getbyname_tm(name, type, timer)
    _ = :inet.stop_timer(timer)
    res
  end

  def getbyname_tm(name, type, timer) when is_list(name) do
    case type_p(type) do
      true ->
        case :inet_parse.visible_string(name) do
          false ->
            {:error, :formerr}

          true ->
            :inet_db.res_update_conf()

            case :inet_db.getbyname(name, type) do
              {:ok, hEnt} ->
                {:ok, hEnt}

              _ ->
                res_getbyname(name, type, timer)
            end
        end

      false ->
        {:error, :formerr}
    end
  end

  def getbyname_tm(name, type, timer) when is_atom(name) do
    getbyname_tm(:erlang.atom_to_list(name), type, timer)
  end

  def getbyname_tm(_, _, _) do
    {:error, :formerr}
  end

  defp type_p(type) do
    :lists.member(
      type,
      [
        :a,
        :aaaa,
        :mx,
        :ns,
        :md,
        :mf,
        :cname,
        :soa,
        :mb,
        :mg,
        :mr,
        :null,
        :wks,
        :hinfo,
        :txt,
        :srv,
        :naptr,
        :spf,
        :uinfo,
        :uid,
        :gid,
        :uri,
        :caa
      ]
    )
  end

  defp res_getbyname(name, type, timer) do
    {embeddedDots, trailingDot} = :inet_parse.dots(name)

    cond do
      trailingDot ->
        res_getby_query(:lists.droplast(name), type, timer)

      embeddedDots === 0 ->
        res_getby_search(name, :inet_db.get_searchlist(), :nxdomain, type, timer)

      true ->
        case res_getby_query(name, type, timer) do
          {:error, _Reason} = error ->
            res_getby_search(name, :inet_db.get_searchlist(), error, type, timer)

          other ->
            other
        end
    end
  end

  defp res_getby_search(name, [dom | ds], _Reason, type, timer) do
    queryName =
      cond do
        dom === ~c"." or dom === ~c"" ->
          name

        name !== ~c"" and hd(dom) !== ?. ->
          name ++ ~c"." ++ dom

        name === ~c"" and hd(dom) !== ?. ->
          dom

        true ->
          :erlang.error({:if_clause, name, dom})
      end

    case res_getby_query(queryName, type, timer, :inet_db.res_option(:nameservers)) do
      {:ok, hEnt} ->
        {:ok, hEnt}

      {:error, newReason} ->
        res_getby_search(name, ds, newReason, type, timer)
    end
  end

  defp res_getby_search(_Name, [], reason, _, _) do
    {:error, reason}
  end

  defp res_getby_query(name, type, timer) do
    case res_query(name, :in, type, [], timer) do
      {:ok, rec} ->
        :inet_db.res_hostent_by_domain(name, type, rec)

      {:error, {:qfmterror, _}} ->
        {:error, :einval}

      {:error, {reason, _}} ->
        {:error, reason}

      error ->
        error
    end
  end

  defp res_getby_query(name, type, timer, nSs) do
    case res_query(name, :in, type, [], timer, nSs) do
      {:ok, rec} ->
        :inet_db.res_hostent_by_domain(name, type, rec)

      {:error, {:qfmterror, _}} ->
        {:error, :einval}

      {:error, {reason, _}} ->
        {:error, reason}

      error ->
        error
    end
  end

  Record.defrecord(:r_q, :q, options: :undefined, edns: :undefined, dns: :undefined)

  defp res_query(name, class, type, opts, timer) do
    r_q(options: r_options(nameservers: nSs)) = q = make_query(name, class, type, opts)

    case do_query(q, nSs, timer) do
      {:error, :nxdomain} = error ->
        res_query_alt(q, error, timer)

      {:error, {:nxdomain, _}} = error ->
        res_query_alt(q, error, timer)

      {:ok, r_dns_rec(anlist: [])} = reply ->
        res_query_alt(q, reply, timer)

      reply ->
        reply
    end
  end

  defp res_query(name, class, type, opts, timer, nSs) do
    q = make_query(name, class, type, opts)
    do_query(q, nSs, timer)
  end

  defp res_query_alt(r_q(options: r_options(alt_nameservers: nSs)) = q, reply, timer) do
    case nSs do
      [] ->
        reply

      _ ->
        do_query(q, nSs, timer)
    end
  end

  defp make_query(dname, class, type, opts) do
    options = make_options(opts)

    case r_options(options, :edns) do
      false ->
        r_q(
          options: options,
          edns: :undefined,
          dns: make_query(dname, class, type, options, false)
        )

      edns ->
        r_q(
          options: options,
          edns: make_query(dname, class, type, options, edns),
          dns: fn ->
            make_query(dname, class, type, options, false)
          end
        )
    end
  end

  defp make_query(dname, class, type, options, edns) do
    id = :inet_db.res_option(:next_id)
    recurse = r_options(options, :recurse)
    rD = recurse === 1 or recurse === true

    aRList =
      case edns do
        false ->
          []

        _ ->
          r_options(udp_payload_size: pSz, dnssec_ok: dnssecOk) = options
          [r_dns_rr_opt(udp_payload_size: pSz, version: edns, do: dnssecOk)]
      end

    msg =
      r_dns_rec(
        header: r_dns_header(id: id, qr: false, opcode: :query, rd: rD, rcode: 0),
        qdlist: [r_dns_query(domain: dname, type: type, class: class)],
        arlist: aRList
      )

    case r_options(options, :verbose) do
      true ->
        :io.format(
          ~c"Query: ~p~n",
          [dns_msg(msg)]
        )

      false ->
        :ok
    end

    buffer = :inet_dns.encode(msg)
    {msg, buffer}
  end

  Record.defrecord(:r_sock, :sock,
    inet: :undefined,
    inet6: :undefined
  )

  defp udp_open(r_sock(inet6: i) = s, {a, b, c, d, e, f, g, h})
       when (a ||| b ||| c ||| d ||| e ||| f ||| g ||| h) &&& ~~~65535 === 0 do
    case i do
      :undefined ->
        case :gen_udp.open(
               0,
               [{:active, false}, :binary, :inet6]
             ) do
          {:ok, j} ->
            {:ok, r_sock(s, inet6: j)}

          error ->
            error
        end

      _ ->
        {:ok, s}
    end
  end

  defp udp_open(r_sock(inet: i) = s, {a, b, c, d})
       when (a ||| b ||| c ||| d) &&& ~~~255 === 0 do
    case i do
      :undefined ->
        case :gen_udp.open(
               0,
               [{:active, false}, :binary, :inet]
             ) do
          {:ok, j} ->
            {:ok, r_sock(s, inet: j)}

          error ->
            error
        end

      _ ->
        {:ok, s}
    end
  end

  defp udp_connect(r_sock(inet6: i), {a, b, c, d, e, f, g, h} = iP, port)
       when (a ||| b ||| c ||| d ||| e ||| f ||| g ||| h) &&& ~~~65535 === 0 and
              port &&& ~~~65535 === 0 do
    :gen_udp.connect(i, iP, port)
  end

  defp udp_connect(r_sock(inet: i), {a, b, c, d} = iP, port)
       when (a ||| b ||| c ||| d) &&& ~~~255 === 0 do
    :gen_udp.connect(i, iP, port)
  end

  defp udp_send(r_sock(inet6: i), {a, b, c, d, e, f, g, h} = iP, port, buffer)
       when (a ||| b ||| c ||| d ||| e ||| f ||| g ||| h) &&& ~~~65535 === 0 and
              port &&& ~~~65535 === 0 do
    :gen_udp.send(i, iP, port, buffer)
  end

  defp udp_send(r_sock(inet: i), {a, b, c, d} = iP, port, buffer)
       when (a ||| b ||| c ||| d) &&& ~~~255 === 0 and
              port &&& ~~~65535 === 0 do
    :gen_udp.send(i, iP, port, buffer)
  end

  defp udp_recv(r_sock(inet6: i), {a, b, c, d, e, f, g, h} = iP, port, timeout, decode)
       when (a ||| b ||| c ||| d ||| e ||| f ||| g ||| h) &&& ~~~65535 === 0 and
              port &&& ~~~65535 === 0 and 0 <= timeout do
    do_udp_recv(i, iP, port, timeout, decode, time(timeout), timeout)
  end

  defp udp_recv(r_sock(inet: i), {a, b, c, d} = iP, port, timeout, decode)
       when (a ||| b ||| c ||| d) &&& ~~~255 === 0 and
              port &&& ~~~65535 === 0 and 0 <= timeout do
    do_udp_recv(i, iP, port, timeout, decode, time(timeout), timeout)
  end

  defp do_udp_recv(_I, _IP, _Port, 0, _Decode, _Time, pollCnt)
       when pollCnt <= 0 do
    :timeout
  end

  defp do_udp_recv(i, iP, port, timeout, decode, time, pollCnt) do
    case :gen_udp.recv(i, 0, timeout) do
      {:ok, reply} ->
        case decode.(reply) do
          false when timeout === 0 ->
            do_udp_recv(i, iP, port, timeout, decode, time, pollCnt - 50)

          false ->
            do_udp_recv(i, iP, port, timeout(time), decode, time, pollCnt)

          result ->
            result
        end

      error ->
        error
    end
  end

  defp udp_close(r_sock(inet: i, inet6: i6)) do
    cond do
      i !== :undefined ->
        :gen_udp.close(i)

      true ->
        :ok
    end

    cond do
      i6 !== :undefined ->
        :gen_udp.close(i6)

      true ->
        :ok
    end

    :ok
  end

  defp do_query(_Q, [], _Timer) do
    {:error, :nxdomain}
  end

  defp do_query(r_q(options: r_options(retry: retry)) = q, nSs, timer) do
    reason = :timeout

    :lists.all(
      fn
        nS when tuple_size(nS) === 2 ->
          true

        _ ->
          false
      end,
      nSs
    ) or :erlang.error(:badarg, [q, nSs, timer])

    query_retries(q, nSs, timer, retry, 0, r_sock(), reason)
  end

  defp query_retries(q, _NSs, _Timer, retry, i, s, reason)
       when retry === i do
    query_retries_error(q, s, reason)
  end

  defp query_retries(q, [], _Timer, _Retry, _I, s, reason) do
    query_retries_error(q, s, reason)
  end

  defp query_retries(q, nSs, timer, retry, i, s, reason) do
    query_nss(q, nSs, timer, retry, i, s, reason, [])
  end

  defp query_nss(q, [], timer, retry, i, s, reason, retryNSs) do
    query_retries(q, :lists.reverse(retryNSs), timer, retry, i + 1, s, reason)
  end

  defp query_nss(r_q(edns: :undefined) = q, nSs, timer, retry, i, s, reason, retryNSs) do
    query_nss_dns(q, nSs, timer, retry, i, s, reason, retryNSs)
  end

  defp query_nss(q, nSs, timer, retry, i, s, reason, retryNSs) do
    query_nss_edns(q, nSs, timer, retry, i, s, reason, retryNSs)
  end

  defp query_nss_edns(
         r_q(
           options: r_options(udp_payload_size: pSz) = options,
           edns: eDNSQuery
         ) = q,
         [nsSpec | nSs],
         timer,
         retry,
         i,
         s_0,
         reason,
         retryNSs
       ) do
    {iP, port} = nS = servfail_retry_wait(nsSpec)
    {s, result} = query_ns(s_0, eDNSQuery, iP, port, timer, retry, i, options, pSz)

    case result do
      {:error, {e, _}}
      when e === :qfmterror or
             e === :notimp or e === :servfail or e === :badvers ->
        query_nss_dns(q, [nS | nSs], timer, retry, i, s, reason, retryNSs)

      _ ->
        query_nss_result(q, nSs, timer, retry, i, s, reason, retryNSs, nS, result)
    end
  end

  defp query_nss_dns(
         r_q(dns: dNSQuery_0) = q_0,
         [nsSpec | nSs],
         timer,
         retry,
         i,
         s_0,
         reason,
         retryNSs
       ) do
    {iP, port} = nS = servfail_retry_wait(nsSpec)

    r_q(options: options, dns: dNSQuery) =
      q =
      cond do
        is_function(dNSQuery_0, 0) ->
          r_q(q_0, dns: dNSQuery_0.())

        true ->
          q_0
      end

    {s, result} = query_ns(s_0, dNSQuery, iP, port, timer, retry, i, options, 512)
    query_nss_result(q, nSs, timer, retry, i, s, reason, retryNSs, nS, result)
  end

  defp servfail_retry_time(retryTimeout, nS) do
    {:servfail_retry, time(retryTimeout), nS}
  end

  defp servfail_retry_wait(nsSpec) do
    case nsSpec do
      {:servfail_retry, time, nS} ->
        wait(timeout(time))
        nS

      {_IP, _Port} = nS ->
        nS
    end
  end

  defp query_nss_result(q, nSs, timer, retry, i, s, reason, retryNSs, nS, result) do
    case result do
      {:ok, _} ->
        _ = udp_close(s)
        result

      :timeout ->
        query_retries_error(q, s, reason)

      {:error, {:nxdomain, _} = e} ->
        query_retries_error(q, s, e)

      {:error, {e, _} = newReason}
      when e === :qfmterror or
             e === :notimp or e === :refused or
             e === :badvers or e === :unknown ->
        query_nss(q, nSs, timer, retry, i, s, newReason, retryNSs)

      {:error, e = newReason}
      when e === :formerr or
             e === :enetunreach or e === :econnrefused ->
        query_nss(q, nSs, timer, retry, i, s, newReason, retryNSs)

      {:error, :timeout} ->
        query_nss(q, nSs, timer, retry, i, s, reason, [nS | retryNSs])

      {:error, {:servfail, _} = newReason} ->
        retryTimeout = r_options(r_q(q, :options), :servfail_retry_timeout)

        case :inet.timeout(retryTimeout, timer) do
          ^retryTimeout ->
            nsSpec = servfail_retry_time(retryTimeout, nS)
            query_nss(q, nSs, timer, retry, i, s, newReason, [nsSpec | retryNSs])

          _ ->
            query_nss(q, nSs, timer, retry, i, s, newReason, retryNSs)
        end

      {:error, newReason} ->
        query_nss(q, nSs, timer, retry, i, s, newReason, [nS | retryNSs])
    end
  end

  defp query_retries_error(r_q(options: r_options(nxdomain_reply: nxReply)), s, reason) do
    _ = udp_close(s)

    case reason do
      {:nxdomain, _} when not nxReply ->
        {:error, :nxdomain}

      _ ->
        {:error, reason}
    end
  end

  defp query_ns(
         s0,
         {msg, buffer},
         iP,
         port,
         timer,
         retry,
         i,
         r_options(timeout: tm, usevc: useVC, verbose: verbose),
         pSz
       ) do
    case useVC or :erlang.iolist_size(buffer) > pSz do
      true ->
        tcpTimeout = :inet.timeout(tm * 5, timer)
        {s0, query_tcp(tcpTimeout, msg, buffer, iP, port, verbose)}

      false ->
        case udp_open(s0, iP) do
          {:ok, s} ->
            udpTimeout =
              :inet.timeout(
                div(tm * (1 <<< i), retry),
                timer
              )

            case query_udp(s, msg, buffer, iP, port, udpTimeout, verbose) do
              {:ok, r_dns_rec(header: h)} when r_dns_header(h, :tc) ->
                tcpTimeout = :inet.timeout(tm * 5, timer)
                {s, query_tcp(tcpTimeout, msg, buffer, iP, port, verbose)}

              {:error, :econnrefused} = err ->
                :ok = udp_close(s)
                {r_sock(), err}

              reply ->
                {s, reply}
            end

          error ->
            {s0, error}
        end
    end
  end

  defp query_udp(_S, _Msg, _Buffer, _IP, _Port, 0, _Verbose) do
    :timeout
  end

  defp query_udp(s, msg, buffer, iP, port, timeout, verbose) do
    case verbose do
      true ->
        :io.format(
          ~c"Try UDP server : ~p:~p (timeout=~w)\n",
          [iP, port, timeout]
        )

      false ->
        :ok
    end

    case (case udp_connect(s, iP, port) do
            :ok ->
              udp_send(s, iP, port, buffer)

            e1 ->
              e1
          end) do
      :ok ->
        decode = fn
          {recIP, recPort, answer}
          when recIP === iP and recPort === port ->
            case decode_answer(answer, msg, verbose) do
              {:error, :badid} ->
                false

              reply ->
                reply
            end

          {_, _, _} ->
            false
        end

        case udp_recv(s, iP, port, timeout, decode) do
          {:ok, _} = result ->
            result

          e2 ->
            case verbose do
              true ->
                :io.format(
                  ~c"UDP server error: ~p\n",
                  [e2]
                )

              false ->
                :ok
            end

            e2
        end

      e3 ->
        case verbose do
          true ->
            :io.format(
              ~c"UDP send failed: ~p\n",
              [e3]
            )

          false ->
            :ok
        end

        {:error, :econnrefused}
    end
  end

  defp query_tcp(0, _Msg, _Buffer, _IP, _Port, _Verbose) do
    :timeout
  end

  defp query_tcp(timeout, msg, buffer, iP, port, verbose) do
    case verbose do
      true ->
        :io.format(
          ~c"Try TCP server : ~p:~p (timeout=~w)\n",
          [iP, port, timeout]
        )

      false ->
        :ok
    end

    family =
      case iP do
        {a, b, c, d} when (a ||| b ||| c ||| d) &&& ~~~255 === 0 ->
          :inet

        {a, b, c, d, e, f, g, h}
        when (a ||| b ||| c ||| d ||| e ||| f ||| g ||| h) &&& ~~~65535 === 0 ->
          :inet6
      end

    try do
      :gen_tcp.connect(iP, port, [{:active, false}, {:packet, 2}, :binary, family], timeout)
    catch
      _, _ ->
        {:error, :einval}
    else
      {:ok, s} ->
        case :gen_tcp.send(s, buffer) do
          :ok ->
            case :gen_tcp.recv(s, 0, timeout) do
              {:ok, answer} ->
                :gen_tcp.close(s)

                case decode_answer(answer, msg, verbose) do
                  {:ok, _} = oK ->
                    oK

                  {:error, :badid} ->
                    {:error, :servfail}

                  error ->
                    error
                end

              error ->
                :gen_tcp.close(s)

                case verbose do
                  true ->
                    :io.format(
                      ~c"TCP server recv error: ~p\n",
                      [error]
                    )

                  false ->
                    :ok
                end

                error
            end

          error ->
            :gen_tcp.close(s)

            case verbose do
              true ->
                :io.format(
                  ~c"TCP server send error: ~p\n",
                  [error]
                )

              false ->
                :ok
            end

            error
        end

      error ->
        case verbose do
          true ->
            :io.format(
              ~c"TCP server error: ~p\n",
              [error]
            )

          false ->
            :ok
        end

        error
    end
  end

  defp decode_answer(answer, q_Msg, verbose) do
    case :inet_dns.decode(answer) do
      {:ok, r_dns_rec(header: h, arlist: aRList) = msg} ->
        case verbose do
          true ->
            :io.format(
              ~c"Got reply: ~p~n",
              [dns_msg(msg)]
            )

          false ->
            :ok
        end

        e =
          case :lists.keyfind(:dns_rr_opt, 1, aRList) do
            false ->
              0

            r_dns_rr_opt(ext_rcode: extRCode) ->
              extRCode
          end

        rCode = e <<< 4 ||| r_dns_header(h, :rcode)

        case rCode do
          0 ->
            decode_answer_noerror(q_Msg, msg, h)

          1 ->
            {:error, {:qfmterror, msg}}

          2 ->
            {:error, {:servfail, msg}}

          3 ->
            {:error, {:nxdomain, msg}}

          4 ->
            {:error, {:notimp, msg}}

          5 ->
            {:error, {:refused, msg}}

          16 ->
            {:error, {:badvers, msg}}

          _ ->
            {:error, {:unknown, msg}}
        end

      {:error, :formerr} = error ->
        case verbose do
          true ->
            :io.format(
              ~c"Got reply: decode format error~n",
              []
            )

          false ->
            :ok
        end

        error
    end
  end

  defp decode_answer_noerror(
         r_dns_rec(header: q_H, qdlist: [q_RR]),
         r_dns_rec(qdlist: qDList) = msg,
         h
       ) do
    cond do
      r_dns_header(h, :id) !== r_dns_header(q_H, :id) ->
        {:error, :badid}

      r_dns_header(h, :qr) !== true or
        r_dns_header(h, :opcode) !== r_dns_header(q_H, :opcode) or
          (r_dns_header(h, :rd) and not r_dns_header(q_H, :rd)) ->
        {:error, {:unknown, msg}}

      true ->
        case qDList do
          [rR] ->
            case r_dns_query(rR, :class) === r_dns_query(q_RR, :class) and
                   r_dns_query(rR, :type) === r_dns_query(q_RR, :type) and
                   :inet_db.eq_domains(
                     r_dns_query(rR, :domain),
                     r_dns_query(q_RR, :domain)
                   ) do
              true ->
                {:ok, msg}

              false ->
                {:error, {:noquery, msg}}
            end

          _ when is_list(qDList) ->
            {:error, {:noquery, msg}}
        end
    end
  end

  defp nsdname(name) when is_atom(name) do
    nsdname(:erlang.atom_to_list(name))
  end

  defp nsdname(name) when is_list(name) do
    case :inet_parse.visible_string(name) do
      true ->
        case :inet_parse.address(name) do
          {:ok, iP} ->
            dn_ip(iP)

          _ ->
            {:ok, name}
        end

      _ ->
        {:error, :formerr}
    end
  end

  defp nsdname(iP) do
    dn_ip(iP)
  end

  defp dn_ip({a, b, c, d}) when (a ||| b ||| c ||| d) &&& ~~~255 === 0 do
    dn_ipv4([a, b, c, d], ~c"in-addr.arpa")
  end

  defp dn_ip({a, b, c, d, e, f, g, h})
       when (a ||| b ||| c ||| d ||| e ||| f ||| g ||| h) &&& ~~~65535 === 0 do
    dn_ipv6([a, b, c, d, e, f, g, h], ~c"ip6.arpa")
  end

  defp dn_ip(_) do
    {:error, :formerr}
  end

  defp dn_ipv4([], dn) do
    {:ok, dn}
  end

  defp dn_ipv4([a | as], dn_0)
       when is_integer(a) and
              a <= 255 do
    dn = [?. | dn_0]

    cond do
      a < 10 ->
        dn_ipv4(as, dn_dec(a, dn))

      a < 100 ->
        dn_ipv4(as, dn_dec(div(a, 10), dn_dec(rem(a, 10), dn)))

      true ->
        b = rem(a, 100)

        dn_ipv4(
          as,
          dn_dec(
            div(a, 100),
            dn_dec(div(b, 10), dn_dec(rem(b, 10), dn))
          )
        )
    end
  end

  defp dn_ipv6([], dn) do
    {:ok, dn}
  end

  defp dn_ipv6([w | ws], dn)
       when is_integer(w) and
              w <= 65535 do
    d = w &&& 15
    w_1 = w >>> 4
    c = w_1 &&& 15
    w_2 = w_1 >>> 4
    b = w_2 &&& 15
    a = w_2 >>> 4

    dn_ipv6(
      ws,
      dn_hex(d, dn_hex(c, dn_hex(b, dn_hex(a, dn))))
    )
  end

  defp dn_dec(n, tail) when is_integer(n) do
    [n + ?0 | tail]
  end

  defp dn_hex(n, tail) when is_integer(n) do
    cond do
      n < 10 ->
        [n + ?0, ?. | tail]

      true ->
        [n - 10 + ?a, ?. | tail]
    end
  end

  defp norm_ip({0, 0, 0, 0, 0, 65535, g, h}) do
    a = g >>> 8
    b = g &&& 255
    c = h >>> 8
    d = h &&& 255
    {a, b, c, d}
  end

  defp norm_ip(iP) do
    iP
  end

  def dns_msg([]) do
    []
  end

  def dns_msg([{field, msg} | fields]) do
    [{field, dns_msg(msg)} | dns_msg(fields)]
  end

  def dns_msg([msg | msgs]) do
    [dns_msg(msg) | dns_msg(msgs)]
  end

  def dns_msg(msg) do
    case :inet_dns.record_type(msg) do
      :undefined ->
        msg

      type ->
        fields = apply(:inet_dns, type, [msg])
        {type, dns_msg(fields)}
    end
  end

  defp time(timeout) do
    :erlang.monotonic_time(1000) + timeout
  end

  defp timeout(time) do
    timeNow = :erlang.monotonic_time(1000)

    cond do
      timeNow < time ->
        time - timeNow

      true ->
        0
    end
  end

  defp wait(0) do
    :ok
  end

  defp wait(timeout) do
    receive do
    after
      timeout ->
        :ok
    end
  end
end
