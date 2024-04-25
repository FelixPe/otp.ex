defmodule :m_observer_html_lib do
  use Bitwise
  require Record

  Record.defrecord(:r_menu_item, :menu_item,
    index: :undefined,
    picture: :undefined,
    text: :undefined,
    depth: :undefined,
    children: :undefined,
    state: :undefined,
    target: :undefined
  )

  Record.defrecord(:r_general_info, :general_info,
    created: :undefined,
    slogan: :undefined,
    system_vsn: :undefined,
    compile_time: :undefined,
    taints: :undefined,
    node_name: :undefined,
    num_atoms: :undefined,
    num_procs: :undefined,
    num_ets: :undefined,
    num_timers: :undefined,
    num_fun: :undefined,
    mem_tot: :undefined,
    mem_max: :undefined,
    instr_info: :undefined,
    thread: :undefined
  )

  Record.defrecord(:r_proc, :proc,
    pid: :undefined,
    name: :undefined,
    init_func: :undefined,
    parent: ~c"unknown",
    start_time: ~c"unknown",
    state: :undefined,
    current_func: :undefined,
    msg_q_len: 0,
    msg_q: :undefined,
    last_calls: :undefined,
    links: :undefined,
    monitors: :undefined,
    mon_by: :undefined,
    prog_count: :undefined,
    cp: :undefined,
    arity: :undefined,
    dict: :undefined,
    reds: 0,
    num_heap_frag: ~c"unknown",
    heap_frag_data: :undefined,
    stack_heap: 0,
    old_heap: :undefined,
    heap_unused: :undefined,
    old_heap_unused: :undefined,
    bin_vheap: :undefined,
    old_bin_vheap: :undefined,
    bin_vheap_unused: :undefined,
    old_bin_vheap_unused: :undefined,
    new_heap_start: :undefined,
    new_heap_top: :undefined,
    stack_top: :undefined,
    stack_end: :undefined,
    old_heap_start: :undefined,
    old_heap_top: :undefined,
    old_heap_end: :undefined,
    memory: :undefined,
    stack_dump: :undefined,
    run_queue: ~c"unknown",
    int_state: :undefined
  )

  Record.defrecord(:r_port, :port,
    id: :undefined,
    state: :undefined,
    task_flags: 0,
    slot: :undefined,
    connected: :undefined,
    links: :undefined,
    name: :undefined,
    monitors: :undefined,
    suspended: :undefined,
    controls: :undefined,
    input: :undefined,
    output: :undefined,
    queue: :undefined,
    port_data: :undefined
  )

  Record.defrecord(:r_sched, :sched,
    name: :undefined,
    type: :undefined,
    process: :undefined,
    port: :undefined,
    run_q: 0,
    port_q: :undefined,
    details: %{}
  )

  Record.defrecord(:r_ets_table, :ets_table,
    pid: :undefined,
    slot: :undefined,
    id: :undefined,
    name: :undefined,
    is_named: :undefined,
    data_type: ~c"hash",
    buckets: ~c"-",
    size: :undefined,
    memory: :undefined,
    details: %{}
  )

  Record.defrecord(:r_timer, :timer,
    pid: :undefined,
    name: :undefined,
    msg: :undefined,
    time: :undefined
  )

  Record.defrecord(:r_fu, :fu,
    module: :undefined,
    uniq: :undefined,
    index: :undefined,
    address: :undefined,
    native_address: :undefined,
    refc: :undefined
  )

  Record.defrecord(:r_nod, :nod,
    name: :undefined,
    channel: :undefined,
    conn_type: :undefined,
    controller: :undefined,
    creation: :undefined,
    remote_links: [],
    remote_mon: [],
    remote_mon_by: [],
    error: :undefined
  )

  Record.defrecord(:r_loaded_mod, :loaded_mod,
    mod: :undefined,
    current_size: :undefined,
    current_attrib: :undefined,
    current_comp_info: :undefined,
    old_size: :undefined,
    old_attrib: :undefined,
    old_comp_info: :undefined
  )

  Record.defrecord(:r_hash_table, :hash_table,
    name: :undefined,
    size: :undefined,
    used: :undefined,
    objs: :undefined,
    depth: :undefined
  )

  Record.defrecord(:r_index_table, :index_table,
    name: :undefined,
    size: :undefined,
    limit: :undefined,
    used: :undefined,
    rate: :undefined,
    entries: :undefined
  )

  Record.defrecord(:r_match_spec, :match_spec, name: ~c"", term: [], str: [], func: ~c"")
  Record.defrecord(:r_tpattern, :tpattern, m: :undefined, fa: :undefined, ms: :undefined)

  Record.defrecord(:r_traced_func, :traced_func,
    func_name: :undefined,
    arity: :undefined,
    match_spec: :EFE_TODO_NESTED_RECORD
  )

  Record.defrecord(:r_create_menu, :create_menu,
    id: :undefined,
    text: :undefined,
    help: [],
    type: :append,
    check: false
  )

  Record.defrecord(:r_colors, :colors, fg: :undefined, even: :undefined, odd: :undefined)

  Record.defrecord(:r_attrs, :attrs,
    even: :undefined,
    odd: :undefined,
    searched: :undefined,
    deleted: :undefined,
    changed_odd: :undefined,
    changed_even: :undefined,
    new_odd: :undefined,
    new_even: :undefined
  )

  Record.defrecord(:r_ti, :ti, tick: 0, disp: 10 / 2, fetch: 2, secs: 60)

  Record.defrecord(:r_win, :win,
    name: :undefined,
    panel: :undefined,
    size: :undefined,
    geom: :undefined,
    graphs: [],
    no_samples: 0,
    max: :undefined,
    state: :undefined,
    info: []
  )

  def warning(info, colors0) do
    colors = convert(colors0)
    header(body(warning_body(info), colors))
  end

  defp warning_body(info) do
    [warn(info)]
  end

  def plain_page(info, colors0) do
    colors = convert(colors0)
    header(body(plain_body(info), colors))
  end

  defp plain_body(info) do
    [pre(href_proc_port(:lists.flatten(info)))]
  end

  def expandable_term(heading, expanded, tab, colors0) do
    colors = convert(colors0)

    header(
      heading,
      body(
        expandable_term_body(heading, expanded, tab, colors),
        colors
      )
    )
  end

  defp expandable_term_body(heading, [], _Tab, _) do
    [
      case heading do
        ~c"MsgQueue" ->
          ~c"No messages were found"

        ~c"Message Queue" ->
          ~c"No messages were found"

        ~c"StackDump" ->
          ~c"No stack dump was found"

        ~c"Dictionary" ->
          ~c"No dictionary was found"

        ~c"ProcState" ->
          ~c"Information could not be retrieved, system messages may not be handled by this process."

        ~c"SaslLog" ->
          ~c"No log entry was found"

        ~c"Persistent Terms" ->
          ~c"No persistent terms were found"
      end
    ]
  end

  defp expandable_term_body(heading, expanded, tab, colors) do
    attr = ~c"BORDER=0 CELLPADDING=0 CELLSPACING=1 WIDTH=100%"

    [
      case heading do
        ~c"MsgQueue" ->
          table(
            attr,
            [
              tr([th(~c"WIDTH=70%", ~c"Message"), th(~c"WIDTH=30%", ~c"SeqTraceToken")])
              | :erlang.element(
                  1,
                  :lists.mapfoldl(
                    fn msg, even ->
                      {msgq_table(
                         tab,
                         msg,
                         even,
                         colors
                       ), not even}
                    end,
                    true,
                    expanded
                  )
                )
            ]
          )

        ~c"Message Queue" ->
          table(
            attr,
            [
              tr([th(~c"WIDTH=10%", ~c"Id"), th(~c"WIDTH=90%", ~c"Message")])
              | :erlang.element(
                  1,
                  :lists.mapfoldl(
                    fn msg, {even, n} ->
                      {msgq_table(
                         tab,
                         msg,
                         n,
                         even,
                         colors
                       ), {not even, n + 1}}
                    end,
                    {true, 1},
                    expanded
                  )
                )
            ]
          )

        ~c"StackDump" ->
          table(
            attr,
            [
              tr([th(~c"WIDTH=20%", ~c"Label"), th(~c"WIDTH=80%", ~c"Term")])
              | :erlang.element(
                  1,
                  :lists.mapfoldl(
                    fn entry, even ->
                      {stackdump_table(
                         tab,
                         entry,
                         even,
                         colors
                       ), not even}
                    end,
                    true,
                    expanded
                  )
                )
            ]
          )

        ~c"ProcState" ->
          table(
            attr,
            [
              tr([th(~c"WIDTH=20%", ~c"Label"), th(~c"WIDTH=80%", ~c"Information")])
              | :erlang.element(
                  1,
                  :lists.mapfoldl(
                    fn entry, even ->
                      {proc_state(
                         tab,
                         entry,
                         even,
                         colors
                       ), not even}
                    end,
                    true,
                    expanded
                  )
                )
            ]
          )

        ~c"SaslLog" ->
          table(
            attr,
            [tr(~c"BGCOLOR=white", [td(~c"ALIGN=left", pre(href_proc_port(expanded)))])]
          )

        _ ->
          table(
            attr,
            [
              tr([th(~c"WIDTH=30%", ~c"Key"), th(~c"WIDTH=70%", ~c"Value")])
              | :erlang.element(
                  1,
                  :lists.mapfoldl(
                    fn entry, even ->
                      {dict_table(
                         tab,
                         entry,
                         even,
                         colors
                       ), not even}
                    end,
                    true,
                    expanded
                  )
                )
            ]
          )
      end
    ]
  end

  defp msgq_table(tab, {msg0, token0}, even, colors) do
    token =
      case token0 do
        [] ->
          ~c""

        _ ->
          :io_lib.fwrite(~c"~w", [token0])
      end

    msg = all_or_expand(tab, msg0)
    tr(color(even, colors), [td(pre(msg)), td(token)])
  end

  defp msgq_table(tab, msg0, id, even, colors) do
    msg = all_or_expand(tab, msg0)

    tr(
      color(even, colors),
      [td(:erlang.integer_to_list(id)), td(pre(msg))]
    )
  end

  defp stackdump_table(tab, {label0, term0}, even, colors) do
    label = :io_lib.format(~c"~ts", [label0])

    term =
      case :string.split(label, ~c":") do
        [_Addr, ~c"S" ++ _] ->
          href_proc_port(term0)

        _ ->
          all_or_expand(tab, term0)
      end

    tr(
      color(even, colors),
      [td(~c"VALIGN=center", pre(label)), td(pre(term))]
    )
  end

  defp dict_table(tab, {key0, value0}, even, colors) do
    key = all_or_expand(tab, key0)
    value = all_or_expand(tab, value0)

    tr(
      color(even, colors),
      [td(~c"VALIGN=center", pre(key)), td(pre(value))]
    )
  end

  defp proc_state(tab, {key0, value0}, even, colors) do
    key = :lists.flatten(:io_lib.format(~c"~ts", [key0]))
    value = all_or_expand(tab, value0)
    tr(color(even, colors), [td(~c"VALIGN=center", key), td(pre(value))])
  end

  defp all_or_expand(tab, term) do
    preview = :io_lib.format(~c"~tP", [term, 8])
    check = :io_lib.format(~c"~tP", [term, 100])
    exp = preview !== check
    all_or_expand(tab, term, preview, exp)
  end

  defp all_or_expand(_Tab, term, str, false) when not is_binary(term) do
    href_proc_port(:lists.flatten(str))
  end

  defp all_or_expand(tab, term, preview, true) when not is_binary(term) do
    key = {key1, key2, key3} = {:erlang.unique_integer([:positive]), 1, 2}
    :ets.insert(tab, {key, term})

    [
      href_proc_port(:lists.flatten(preview), false),
      ?\n,
      href(
        ~c"TARGET=\"expanded\"",
        [
          ~c"#Term?key1=" ++
            :erlang.integer_to_list(key1) ++
            ~c"&key2=" ++
            :erlang.integer_to_list(key2) ++ ~c"&key3=" ++ :erlang.integer_to_list(key3)
        ],
        ~c"Click to expand above term"
      )
    ]
  end

  defp all_or_expand(tab, bin, _PreviewStr, _Expand)
       when is_binary(bin) do
    oBSBin = :observer_lib.make_obsbin(bin, tab)
    term = :io_lib.format(~c"~tp", [oBSBin])
    href_proc_port(:lists.flatten(term), true)
  end

  defp color(true, r_colors(even: even)) do
    ~c"BGCOLOR=" ++ even
  end

  defp color(false, r_colors(odd: odd)) do
    ~c"BGCOLOR=" ++ odd
  end

  defp start_html() do
    ~c"<HTML>\n"
  end

  defp stop_html() do
    ~c"</HTML>"
  end

  defp start_html_body(r_colors(even: even, fg: fg)) do
    ~c"<BODY BGCOLOR=" ++ even ++ ~c">\n <FONT COLOR=" ++ fg ++ ~c">\n"
  end

  defp stop_html_body() do
    ~c"</FONT> </BODY>\n"
  end

  defp header(body) do
    header(~c"", ~c"", body)
  end

  defp header(title, body) do
    header(title, ~c"", body)
  end

  defp header(title, javaScript, body) do
    [html_header(title, javaScript, body)]
  end

  defp html_header(title, javaScript, body) do
    [start_html(), only_html_header(title, javaScript), body, stop_html()]
  end

  defp only_html_header(title, javaScript) do
    [~c"<HEAD>\n", ~c"<TITLE>", title, ~c"</TITLE>\n", javaScript, ~c"</HEAD>\n"]
  end

  defp body(text, colors) do
    [start_html_body(colors), text, stop_html_body()]
  end

  defp start_table(args) do
    [~c"<TABLE ", args, ~c">\n"]
  end

  defp stop_table() do
    ~c"</TABLE>\n"
  end

  defp table(args, text) do
    [start_table(args), text, stop_table()]
  end

  defp tr(text) do
    [~c"<TR>\n", text, ~c"\n</TR>\n"]
  end

  defp tr(args, text) do
    [~c"<TR ", args, ~c">\n", text, ~c"\n</TR>\n"]
  end

  defp th(args, text) do
    [~c"<TH ", args, ~c">\n", text, ~c"\n</TH>\n"]
  end

  defp td(text) do
    [~c"<TD>", text, ~c"</TD>"]
  end

  defp td(args, text) do
    [~c"<TD ", args, ~c">", text, ~c"</TD>"]
  end

  defp start_pre() do
    ~c"<PRE>"
  end

  defp stop_pre() do
    ~c"</PRE>"
  end

  defp pre(text) do
    [start_pre(), text, stop_pre()]
  end

  defp href(link, text) do
    [~c"<A HREF=\"", link, ~c"\">", text, ~c"</A>"]
  end

  defp href(args, link, text) do
    [~c"<A HREF=\"", link, ~c"\" ", args, ~c">", text, ~c"</A>"]
  end

  defp font(args, text) do
    [~c"<FONT ", args, ~c">\n", text, ~c"\n</FONT>\n"]
  end

  defp p(text) do
    [~c"<P>", text, ~c"</P>\n"]
  end

  defp br() do
    ~c"<BR>\n"
  end

  defp href_proc_port(text) do
    href_proc_port(text, true)
  end

  defp href_proc_port(text, linkToBin) do
    href_proc_port(text, [], linkToBin)
  end

  defp href_proc_port(~c"#Ref<" ++ t, acc, lTB) do
    href_proc_port(t, [~c"#Ref&lt;" | acc], lTB)
  end

  defp href_proc_port(~c"#Fun<" ++ t, acc, lTB) do
    href_proc_port(t, [~c"#Fun&lt;" | acc], lTB)
  end

  defp href_proc_port(~c"#Port<" ++ t, acc, lTB) do
    {port0, rest} = split(?>, t)
    port = ~c"#Port&lt;" ++ port0 ++ ~c"&gt;"
    href_proc_port(rest, [href(port, port) | acc], lTB)
  end

  defp href_proc_port(~c"<<" ++ t, acc, lTB) do
    href_proc_port(t, [~c"&lt;&lt;" | acc], lTB)
  end

  defp href_proc_port(~c"<" ++ ([c | _] = t), acc, lTB)
       when ?0 <= c and
              c <= ?9 do
    {pid0, rest} = split(?>, t)
    pid = ~c"&lt;" ++ pid0 ++ ~c"&gt"
    href_proc_port(rest, [href(pid, pid) | acc], lTB)
  end

  defp href_proc_port(~c"['#CDVBin'" ++ t, acc, lTB) do
    href_proc_bin(:cdv, t, acc, lTB)
  end

  defp href_proc_port(~c"['#OBSBin'" ++ t, acc, lTB) do
    href_proc_bin(:obs, t, acc, lTB)
  end

  defp href_proc_port(~c"['#CDVPort'" ++ t, acc, lTB) do
    {port0, rest} = split(?], t)

    portStr =
      case :string.lexemes(port0, ~c",.|") do
        [x, y] ->
          port = ~c"#Port&lt;" ++ x ++ ~c"." ++ y ++ ~c"&gt;"
          href(port, port)

        ns ->
          ~c"#Port&lt;" ++ :lists.join(?., ns) ++ ~c"...&gt;"
      end

    href_proc_port(rest, [portStr | acc], lTB)
  end

  defp href_proc_port(~c"['#CDVPid'" ++ t, acc, lTB) do
    {pid0, rest} = split(?], t)

    pidStr =
      case :string.lexemes(pid0, ~c",.|") do
        [x, y, z] ->
          pid = ~c"&lt;" ++ x ++ ~c"." ++ y ++ ~c"." ++ z ++ ~c"&gt;"
          href(pid, pid)

        ns ->
          ~c"&lt;" ++ :lists.join(?., ns) ++ ~c"...&gt;"
      end

    href_proc_port(rest, [pidStr | acc], lTB)
  end

  defp href_proc_port(~c"'#CDVIncompleteHeap'" ++ t, acc, lTB) do
    iH = :lists.reverse(:lists.flatten(~c"<FONT COLOR=\"#FF0000\">...(Incomplete Heap)</FONT>"))
    href_proc_port(t, iH ++ acc, lTB)
  end

  defp href_proc_port(~c"'#CDVTruncatedBinary'" ++ t, acc, lTB) do
    iH =
      :lists.reverse(
        :lists.flatten(~c"<FONT COLOR=\"#FF0000\">&lt;&lt;...(Truncated Binary)&gt;&gt;</FONT>")
      )

    href_proc_port(t, iH ++ acc, lTB)
  end

  defp href_proc_port(~c"'#CDVNonexistingBinary'" ++ t, acc, lTB) do
    iH =
      :lists.reverse(
        :lists.flatten(~c"<FONT COLOR=\"#FF0000\">&lt;&lt;...(Nonexisting Binary)&gt;&gt;</FONT>")
      )

    href_proc_port(t, iH ++ acc, lTB)
  end

  defp href_proc_port(~c"<" ++ t, acc, lTB) do
    href_proc_port(t, [~c"&lt;" | acc], lTB)
  end

  defp href_proc_port(~c">" ++ t, acc, lTB) do
    href_proc_port(t, [~c"&gt;" | acc], lTB)
  end

  defp href_proc_port([h | t], acc, lTB) do
    href_proc_port(t, [h | acc], lTB)
  end

  defp href_proc_port([], acc, _) do
    :lists.reverse(acc)
  end

  defp href_proc_bin(from, t, acc, lTB) do
    {offsetSizePos, rest} = split(?], t)

    binStr =
      case :string.lexemes(offsetSizePos, ~c",.| \n") do
        [offset, sizeStr, pos] when from === :cdv ->
          size = :erlang.list_to_integer(sizeStr)
          previewSize = min(size, 10)
          id = {:erlang.list_to_integer(offset), previewSize, :erlang.list_to_integer(pos)}

          case :crashdump_viewer.expand_binary(id) do
            {:ok, :"#CDVTruncatedBinary"} ->
              :lists.flatten(
                ~c"<FONT COLOR=\"#FF0000\">&lt;&lt;...(Truncated Binary)&gt;&gt;</FONT>"
              )

            {:ok, previewBin} ->
              previewStr = preview_string(size, previewBin)

              cond do
                lTB ->
                  href(
                    ~c"TARGET=\"expanded\"",
                    [~c"#Binary?offset=" ++ offset ++ ~c"&size=" ++ sizeStr ++ ~c"&pos=" ++ pos],
                    previewStr
                  )

                true ->
                  previewStr
              end
          end

        [previewIntStr, previewBitSizeStr, sizeStr, md5]
        when from === :obs ->
          size = :erlang.list_to_integer(sizeStr)
          previewInt = :erlang.list_to_integer(previewIntStr)
          previewBitSize = :erlang.list_to_integer(previewBitSizeStr)

          previewStr =
            preview_string(
              size,
              <<previewInt::size(previewBitSize)>>
            )

          cond do
            lTB ->
              href(
                ~c"TARGET=\"expanded\"",
                [
                  ~c"#OBSBinary?key1=" ++
                    previewIntStr ++ ~c"&key2=" ++ sizeStr ++ ~c"&key3=" ++ md5
                ],
                previewStr
              )

            true ->
              previewStr
          end

        _ ->
          ~c"&lt;&lt; ... &gt;&gt;"
      end

    href_proc_port(rest, [binStr | acc], lTB)
  end

  defp preview_string(size, previewBin) when size > 10 do
    [
      ~c"&lt;&lt;",
      remove_lgt(:io_lib.format(~c"~tp", [previewBin])),
      ~c"...(",
      :observer_lib.to_str({:bytes, size}),
      ~c")",
      ~c"&gt;&gt"
    ]
  end

  defp preview_string(_, previewBin) do
    [~c"&lt;&lt;", remove_lgt(:io_lib.format(~c"~tp", [previewBin])), ~c"&gt;&gt"]
  end

  defp remove_lgt(deep) do
    remove_lgt_1(:lists.flatten(deep))
  end

  defp remove_lgt_1([?<, ?< | rest]) do
    [?>, ?> | binStr] = :lists.reverse(rest)
    replace_lgt(:lists.reverse(binStr))
  end

  defp remove_lgt_1(truncBin) do
    truncBin
  end

  defp replace_lgt([?< | r]) do
    [~c"&lt;" | replace_lgt(r)]
  end

  defp replace_lgt([?> | r]) do
    [~c"&gt;" | replace_lgt(r)]
  end

  defp replace_lgt([l = [_ | _] | r]) do
    [replace_lgt(l) | replace_lgt(r)]
  end

  defp replace_lgt([a | r]) do
    [a | replace_lgt(r)]
  end

  defp replace_lgt([]) do
    []
  end

  defp split(char, str) do
    split(char, str, [])
  end

  defp split(char, [char | str], acc) do
    {:lists.reverse(acc), str}
  end

  defp split(char, [h | t], acc) do
    split(char, t, [h | acc])
  end

  defp warn([]) do
    []
  end

  defp warn(warning) do
    font(~c"COLOR=\"#FF0000\"", p([warning, br(), br()]))
  end

  defp convert(r_colors(fg: {fR, fB, fG}, even: {eR, eB, eG}, odd: {oR, oG, oB})) do
    r_colors(
      fg: :io_lib.format(~c"\"#~2.16.0B~2.16.0B~2.16.0B\"", [fR, fB, fG]),
      even: :io_lib.format(~c"\"#~2.16.0B~2.16.0B~2.16.0B\"", [eR, eB, eG]),
      odd: :io_lib.format(~c"\"#~2.16.0B~2.16.0B~2.16.0B\"", [oR, oG, oB])
    )
  end
end
