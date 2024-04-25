defmodule :m_observer_sock_wx do
  use Bitwise
  @behaviour :wx_object
  require Record

  Record.defrecord(:r_wx, :wx,
    id: :undefined,
    obj: :undefined,
    userData: :undefined,
    event: :undefined
  )

  Record.defrecord(:r_wxActivate, :wxActivate,
    type: :undefined,
    active: :undefined
  )

  Record.defrecord(:r_wxAuiManager, :wxAuiManager,
    type: :undefined,
    manager: :undefined,
    pane: :undefined,
    button: :undefined,
    veto_flag: :undefined,
    canveto_flag: :undefined,
    dc: :undefined
  )

  Record.defrecord(:r_wxAuiNotebook, :wxAuiNotebook,
    type: :undefined,
    old_selection: :undefined,
    selection: :undefined,
    drag_source: :undefined
  )

  Record.defrecord(:r_wxBookCtrl, :wxBookCtrl,
    type: :undefined,
    nSel: :undefined,
    nOldSel: :undefined
  )

  Record.defrecord(:r_wxCalendar, :wxCalendar,
    type: :undefined,
    wday: :undefined,
    date: :undefined
  )

  Record.defrecord(:r_wxChildFocus, :wxChildFocus, type: :undefined)
  Record.defrecord(:r_wxClipboardText, :wxClipboardText, type: :undefined)
  Record.defrecord(:r_wxClose, :wxClose, type: :undefined)

  Record.defrecord(:r_wxColourPicker, :wxColourPicker,
    type: :undefined,
    colour: :undefined
  )

  Record.defrecord(:r_wxCommand, :wxCommand,
    type: :undefined,
    cmdString: :undefined,
    commandInt: :undefined,
    extraLong: :undefined
  )

  Record.defrecord(:r_wxContextMenu, :wxContextMenu,
    type: :undefined,
    pos: :undefined
  )

  Record.defrecord(:r_wxDate, :wxDate,
    type: :undefined,
    date: :undefined
  )

  Record.defrecord(:r_wxDisplayChanged, :wxDisplayChanged, type: :undefined)

  Record.defrecord(:r_wxDropFiles, :wxDropFiles,
    type: :undefined,
    pos: :undefined,
    files: :undefined
  )

  Record.defrecord(:r_wxErase, :wxErase,
    type: :undefined,
    dc: :undefined
  )

  Record.defrecord(:r_wxFileDirPicker, :wxFileDirPicker,
    type: :undefined,
    path: :undefined
  )

  Record.defrecord(:r_wxFocus, :wxFocus,
    type: :undefined,
    win: :undefined
  )

  Record.defrecord(:r_wxFontPicker, :wxFontPicker,
    type: :undefined,
    font: :undefined
  )

  Record.defrecord(:r_wxGrid, :wxGrid,
    type: :undefined,
    row: :undefined,
    col: :undefined,
    pos: :undefined,
    selecting: :undefined,
    control: :undefined,
    meta: :undefined,
    shift: :undefined,
    alt: :undefined
  )

  Record.defrecord(:r_wxHelp, :wxHelp, type: :undefined)

  Record.defrecord(:r_wxHtmlLink, :wxHtmlLink,
    type: :undefined,
    linkInfo: :undefined
  )

  Record.defrecord(:r_wxIconize, :wxIconize,
    type: :undefined,
    iconized: :undefined
  )

  Record.defrecord(:r_wxIdle, :wxIdle, type: :undefined)
  Record.defrecord(:r_wxInitDialog, :wxInitDialog, type: :undefined)

  Record.defrecord(:r_wxJoystick, :wxJoystick,
    type: :undefined,
    pos: :undefined,
    zPosition: :undefined,
    buttonChange: :undefined,
    buttonState: :undefined,
    joyStick: :undefined
  )

  Record.defrecord(:r_wxKey, :wxKey,
    type: :undefined,
    x: :undefined,
    y: :undefined,
    keyCode: :undefined,
    controlDown: :undefined,
    shiftDown: :undefined,
    altDown: :undefined,
    metaDown: :undefined,
    uniChar: :undefined,
    rawCode: :undefined,
    rawFlags: :undefined
  )

  Record.defrecord(:r_wxList, :wxList,
    type: :undefined,
    code: :undefined,
    oldItemIndex: :undefined,
    itemIndex: :undefined,
    col: :undefined,
    pointDrag: :undefined
  )

  Record.defrecord(:r_wxMaximize, :wxMaximize, type: :undefined)
  Record.defrecord(:r_wxMenu, :wxMenu, type: :undefined, menuId: :undefined, menu: :undefined)
  Record.defrecord(:r_wxMouseCaptureChanged, :wxMouseCaptureChanged, type: :undefined)
  Record.defrecord(:r_wxMouseCaptureLost, :wxMouseCaptureLost, type: :undefined)

  Record.defrecord(:r_wxMouse, :wxMouse,
    type: :undefined,
    x: :undefined,
    y: :undefined,
    leftDown: :undefined,
    middleDown: :undefined,
    rightDown: :undefined,
    controlDown: :undefined,
    shiftDown: :undefined,
    altDown: :undefined,
    metaDown: :undefined,
    wheelRotation: :undefined,
    wheelDelta: :undefined,
    linesPerAction: :undefined
  )

  Record.defrecord(:r_wxMove, :wxMove, type: :undefined, pos: :undefined, rect: :undefined)

  Record.defrecord(:r_wxNavigationKey, :wxNavigationKey,
    type: :undefined,
    dir: :undefined,
    focus: :undefined
  )

  Record.defrecord(:r_wxPaint, :wxPaint, type: :undefined)
  Record.defrecord(:r_wxPaletteChanged, :wxPaletteChanged, type: :undefined)
  Record.defrecord(:r_wxQueryNewPalette, :wxQueryNewPalette, type: :undefined)

  Record.defrecord(:r_wxSash, :wxSash,
    type: :undefined,
    edge: :undefined,
    dragRect: :undefined,
    dragStatus: :undefined
  )

  Record.defrecord(:r_wxScroll, :wxScroll,
    type: :undefined,
    commandInt: :undefined,
    extraLong: :undefined
  )

  Record.defrecord(:r_wxScrollWin, :wxScrollWin,
    type: :undefined,
    commandInt: :undefined,
    extraLong: :undefined
  )

  Record.defrecord(:r_wxSetCursor, :wxSetCursor,
    type: :undefined,
    x: :undefined,
    y: :undefined,
    cursor: :undefined
  )

  Record.defrecord(:r_wxShow, :wxShow,
    type: :undefined,
    show: :undefined
  )

  Record.defrecord(:r_wxSize, :wxSize, type: :undefined, size: :undefined, rect: :undefined)

  Record.defrecord(:r_wxSpin, :wxSpin,
    type: :undefined,
    commandInt: :undefined
  )

  Record.defrecord(:r_wxSplitter, :wxSplitter, type: :undefined)

  Record.defrecord(:r_wxStyledText, :wxStyledText,
    type: :undefined,
    position: :undefined,
    key: :undefined,
    modifiers: :undefined,
    modificationType: :undefined,
    text: :undefined,
    length: :undefined,
    linesAdded: :undefined,
    line: :undefined,
    foldLevelNow: :undefined,
    foldLevelPrev: :undefined,
    margin: :undefined,
    message: :undefined,
    wParam: :undefined,
    lParam: :undefined,
    listType: :undefined,
    x: :undefined,
    y: :undefined,
    dragText: :undefined,
    dragAllowMove: :undefined,
    dragResult: :undefined
  )

  Record.defrecord(:r_wxSysColourChanged, :wxSysColourChanged, type: :undefined)
  Record.defrecord(:r_wxTaskBarIcon, :wxTaskBarIcon, type: :undefined)

  Record.defrecord(:r_wxTree, :wxTree,
    type: :undefined,
    item: :undefined,
    itemOld: :undefined,
    pointDrag: :undefined
  )

  Record.defrecord(:r_wxUpdateUI, :wxUpdateUI, type: :undefined)

  Record.defrecord(:r_wxWebView, :wxWebView,
    type: :undefined,
    string: :undefined,
    int: :undefined,
    target: :undefined,
    url: :undefined
  )

  Record.defrecord(:r_wxWindowCreate, :wxWindowCreate, type: :undefined)
  Record.defrecord(:r_wxWindowDestroy, :wxWindowDestroy, type: :undefined)

  Record.defrecord(:r_wxMouseState, :wxMouseState,
    x: :undefined,
    y: :undefined,
    leftDown: :undefined,
    middleDown: :undefined,
    rightDown: :undefined,
    controlDown: :undefined,
    shiftDown: :undefined,
    altDown: :undefined,
    metaDown: :undefined,
    cmdDown: :undefined
  )

  Record.defrecord(:r_wxHtmlLinkInfo, :wxHtmlLinkInfo,
    href: :undefined,
    target: :undefined
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

  Record.defrecord(:r_socket, :socket,
    id: :undefined,
    id_str: :undefined,
    kind: :undefined,
    fd: :undefined,
    owner: :undefined,
    domain: :undefined,
    type: :undefined,
    protocol: :undefined,
    raddress: :undefined,
    laddress: :undefined,
    rstate: :undefined,
    wstate: :undefined,
    monitored_by: :undefined,
    statistics: :undefined,
    options: :undefined
  )

  Record.defrecord(:r_opt, :opt, sort_key: 2, sort_incr: true, odd_bg: :undefined)

  Record.defrecord(:r_state, :state,
    parent: :undefined,
    grid: :undefined,
    panel: :undefined,
    sizer: :undefined,
    fields: :undefined,
    node: {node(), true},
    opt: :EFE_TODO_NESTED_RECORD,
    right_clicked_socket: :undefined,
    sockets: :undefined,
    timer: :undefined,
    open_wins: []
  )

  def start_link(notebook, parent, config) do
    :wx_object.start_link(:observer_sock_wx, [notebook, parent, config], [])
  end

  defp info_fields() do
    gen = [
      {~c"General socket info",
       [
         {~c"IOV Max", :iov_max},
         {~c"Counter Size (in bits)", :num_cnt_bits},
         {~c"Number of sockets", :num_sockets},
         {~c"Number of (socket) monitors", :num_monitors},
         {~c"Number of sockets in the 'inet' domain", :num_dinet},
         {~c"Number of sockets in the 'inet6' domain", :num_dinet6},
         {~c"Number of sockets in the 'local' domain", :num_dlocal},
         {~c"Number of type 'stream' sockets", :num_tstreams},
         {~c"Number of type 'dgram' sockets", :num_tdgrams},
         {~c"Number of type 'seqpacket' sockets", :num_tseqpkgs},
         {~c"Number of protocol 'ip' sockets", :num_pip},
         {~c"Number of protocol 'sctp' sockets", :num_psctp},
         {~c"Number of protocol 'tcp' sockets", :num_ptcp},
         {~c"Number of protocol 'udp' sockets", :num_pudp}
       ]}
    ]

    gen
  end

  defp update_gen_socket_info(r_state(node: {node, true}, fields: fields, sizer: sizer)) do
    case :rpc.call(node, :observer_backend, :socket_info, []) do
      info when is_list(info) ->
        gen = info_fields()

        :observer_lib.update_info(
          fields,
          :observer_lib.fill_info(gen, info, ~c"Not Supported")
        )

        :wxSizer.layout(sizer)

      _ ->
        :ignore
    end
  end

  defp update_gen_socket_info(r_state(node: _)) do
    :ignore
  end

  def init([notebook, parent, config]) do
    try do
      do_init(notebook, parent, config, :observer_backend.socket_info())
    catch
      _C, _E ->
        do_init(notebook, parent, config, [])
    end
  end

  defp do_init(notebook, parent, config, info) do
    gen = info_fields()
    panel = :wxPanel.new(notebook)
    sizer = :wxBoxSizer.new(8)
    genSizer = :wxBoxSizer.new(4)

    {genPanel, _GenSizer, genFields} =
      :observer_lib.display_info(
        panel,
        :observer_lib.fill_info(
          gen,
          info,
          ~c"Not Supported"
        )
      )

    :wxSizer.add(genSizer, genPanel, [{:flag, 8192}, {:proportion, 1}])
    borderFlags = 16 ||| 32

    :wxSizer.add(sizer, genSizer, [
      {:flag, 8192 ||| borderFlags ||| 64},
      {:proportion, 0},
      {:border, 5}
    ])

    style = 32 ||| 2

    grid =
      :wxListCtrl.new(
        panel,
        [{:winid, 300}, {:style, style}]
      )

    :wxSizer.add(sizer, grid, [
      {:flag, 8192 ||| (64 ||| 128 ||| 32 ||| 16)},
      {:proportion, 1},
      {:border, 5}
    ])

    :wxWindow.setSizer(panel, sizer)
    li = :wxListItem.new()

    addListEntry = fn {name, align, defSize}, col ->
      :wxListItem.setText(li, name)
      :wxListItem.setAlign(li, align)
      :wxListCtrl.insertColumn(grid, col, li)
      :wxListCtrl.setColumnWidth(grid, col, defSize)
      col + 1
    end

    scale = :observer_wx.get_scale()

    listItems = [
      {~c"Id", 0, scale * 350},
      {~c"Owner", 0, scale * 100},
      {~c"Fd", 0, scale * 50},
      {~c"Domain", 0, scale * 60},
      {~c"Type", 0, scale * 100},
      {~c"Protocol", 0, scale * 100},
      {~c"Read State", 0, scale * 150},
      {~c"Write State", 0, scale * 150}
    ]

    :lists.foldl(addListEntry, 0, listItems)
    :wxListItem.destroy(li)

    :wxListCtrl.connect(
      grid,
      :command_list_item_right_click
    )

    :wxListCtrl.connect(grid, :command_list_item_activated)
    :wxListCtrl.connect(grid, :command_list_col_click)
    :wxListCtrl.connect(grid, :size, [{:skip, true}])
    :wxWindow.setFocus(grid)
    even = :wxSystemSettings.getColour(25)
    odd = :observer_lib.mix(even, :wxSystemSettings.getColour(13), 0.8)
    opt = r_opt(odd_bg: odd)

    {panel,
     r_state(
       parent: parent,
       panel: panel,
       sizer: sizer,
       fields: genFields,
       grid: grid,
       timer: config,
       opt: opt
     )}
  end

  def handle_event(
        r_wx(id: 301),
        state = r_state(node: node, grid: grid, opt: opt) = state
      ) do
    _ = update_gen_socket_info(state)
    sockets0 = get_sockets(node)
    sockets = update_grid(grid, sel(state), opt, sockets0)
    {:noreply, r_state(state, sockets: sockets)}
  end

  def handle_event(
        r_wx(obj: obj, event: r_wxClose()),
        r_state(open_wins: opened) = state
      ) do
    newOpened =
      case :lists.keytake(obj, 2, opened) do
        false ->
          opened

        {:value, _, rest} ->
          rest
      end

    {:noreply, r_state(state, open_wins: newOpened)}
  end

  def handle_event(
        r_wx(
          event:
            r_wxList(
              type: :command_list_col_click,
              col: col
            )
        ),
        state = r_state(node: node, grid: grid, opt: opt0 = r_opt(sort_key: key, sort_incr: bool))
      ) do
    opt =
      case col + 2 do
        ^key ->
          r_opt(opt0, sort_incr: not bool)

        newKey ->
          r_opt(opt0, sort_key: newKey)
      end

    sockets0 = get_sockets(node)
    sockets = update_grid(grid, sel(state), opt, sockets0)
    :wxWindow.setFocus(grid)
    {:noreply, r_state(state, opt: opt, sockets: sockets)}
  end

  def handle_event(
        r_wx(event: r_wxSize(size: {w, _})),
        state = r_state(grid: grid)
      ) do
    :observer_lib.set_listctrl_col_size(grid, w)
    {:noreply, state}
  end

  def handle_event(
        r_wx(
          event:
            r_wxList(
              type: :command_list_item_activated,
              itemIndex: index
            )
        ),
        state = r_state(grid: grid, sockets: sockets, open_wins: opened)
      ) do
    cond do
      length(sockets) >= index + 1 ->
        socket = :lists.nth(index + 1, sockets)
        newOpened = display_socket_info(grid, socket, opened)
        {:noreply, r_state(state, open_wins: newOpened)}

      true ->
        {:noreply, state}
    end
  end

  def handle_event(
        r_wx(
          event:
            r_wxList(
              type: :command_list_item_right_click,
              itemIndex: index
            )
        ),
        state = r_state(panel: panel, sockets: sockets)
      ) do
    case index do
      -1 ->
        {:noreply, state}

      _ ->
        socket = :lists.nth(index + 1, sockets)
        menu = :wxMenu.new()
        :wxMenu.append(menu, 303, f(~c"Socket info for ~s", [r_socket(socket, :id_str)]))
        :wxMenu.append(menu, 309, f(~c"Close ~p", [r_socket(socket, :id_str)]))
        :wxWindow.popupMenu(panel, menu)
        :wxMenu.destroy(menu)
        {:noreply, r_state(state, right_clicked_socket: socket)}
    end
  end

  def handle_event(
        r_wx(id: 303),
        state = r_state(grid: grid, right_clicked_socket: socket, open_wins: opened)
      ) do
    case socket do
      :undefined ->
        {:noreply, state}

      _ ->
        newOpened = display_socket_info(grid, socket, opened)

        {:noreply,
         r_state(state,
           right_clicked_socket: :undefined,
           open_wins: newOpened
         )}
    end
  end

  def handle_event(
        r_wx(id: 304),
        state = r_state(grid: grid, sockets: sockets, open_wins: opened)
      ) do
    case get_selected_items(grid, sockets) do
      [] ->
        :observer_wx.create_txt_dialog(
          r_state(state, :panel),
          ~c"No selected sockets",
          ~c"Socket Info",
          256
        )

        {:noreply, state}

      selected ->
        newOpened =
          :lists.foldl(
            fn s, o ->
              display_socket_info(grid, s, o)
            end,
            opened,
            selected
          )

        {:noreply, r_state(state, open_wins: newOpened)}
    end
  end

  def handle_event(
        r_wx(id: 309),
        state = r_state(right_clicked_socket: socket)
      ) do
    case socket do
      :undefined ->
        {:noreply, state}

      _ ->
        :socket.close(r_socket(socket, :id))
        {:noreply, r_state(state, right_clicked_socket: :undefined)}
    end
  end

  def handle_event(
        r_wx(id: 302),
        state = r_state(grid: grid, timer: timer0)
      ) do
    timer = :observer_lib.interval_dialog(grid, timer0, 10, 5 * 60)
    {:noreply, r_state(state, timer: timer)}
  end

  def handle_event(
        r_wx(obj: moreEntry, event: r_wxMouse(type: :left_down), userData: {:more, more}),
        state
      ) do
    :observer_lib.add_scroll_entries(moreEntry, more)
    {:noreply, state}
  end

  def handle_event(
        r_wx(
          event: r_wxMouse(type: :left_down),
          userData: targetPid
        ),
        state
      ) do
    send(:observer, {:open_link, targetPid})
    {:noreply, state}
  end

  def handle_event(
        r_wx(obj: obj, event: r_wxMouse(type: :enter_window)),
        state
      ) do
    :wxTextCtrl.setForegroundColour(obj, {0, 0, 100, 255})
    {:noreply, state}
  end

  def handle_event(
        r_wx(obj: obj, event: r_wxMouse(type: :leave_window)),
        state
      ) do
    :wxTextCtrl.setForegroundColour(
      obj,
      :wxe_util.get_const(:wxBLUE)
    )

    {:noreply, state}
  end

  def handle_event(event, _State) do
    :erlang.error({:unhandled_event, event})
  end

  def handle_sync_event(_Event, _Obj, _State) do
    :ok
  end

  def handle_call(:get_config, _, r_state(timer: timer) = state) do
    {:reply, :observer_lib.timer_config(timer), state}
  end

  def handle_call(event, from, _State) do
    :erlang.error({:unhandled_call, event, from})
  end

  def handle_cast(event, _State) do
    :erlang.error({:unhandled_cast, event})
  end

  def handle_info(
        :refresh_interval,
        state = r_state(node: node, grid: grid, opt: opt, sockets: oldSockets) = state
      ) do
    case get_sockets(node) do
      ^oldSockets ->
        {:noreply, state}

      sockets0 ->
        _ = update_gen_socket_info(state)
        sockets = update_grid(grid, sel(state), opt, sockets0)
        {:noreply, r_state(state, sockets: sockets)}
    end
  end

  def handle_info(
        {:active, nodeName},
        r_state(parent: parent, grid: grid, opt: opt, timer: timer0) = state0
      ) do
    available = socketinfo_available(nodeName)
    available or popup_unavailable_info(nodeName)
    state1 = r_state(state0, node: {nodeName, available})
    _ = update_gen_socket_info(state1)
    sockets0 = get_sockets(nodeName, available)
    sockets = update_grid(grid, sel(state1), opt, sockets0)
    :wxWindow.setFocus(grid)
    create_menus(parent)
    timer = :observer_lib.start_timer(timer0, 10)
    {:noreply, r_state(state1, sockets: sockets, timer: timer)}
  end

  def handle_info(:not_active, state = r_state(timer: timer0)) do
    timer = :observer_lib.stop_timer(timer0)
    {:noreply, r_state(state, timer: timer)}
  end

  def handle_info(
        {:info, {:socket_info_not_available, nodeName}},
        state = r_state(panel: panel)
      ) do
    str = :io_lib.format(~c"Can not fetch socket info from ~p.~nToo old OTP version.", [nodeName])
    :observer_lib.display_info_dialog(panel, str)
    {:noreply, state}
  end

  def handle_info({:error, error}, r_state(panel: panel) = state) do
    errorStr =
      cond do
        is_list(error) ->
          error

        true ->
          f(~c"~p", [error])
      end

    str = :io_lib.format(~c"ERROR: ~ts~n", [errorStr])
    :observer_lib.display_info_dialog(panel, str)
    {:noreply, state}
  end

  def handle_info(_Event, state) do
    {:noreply, state}
  end

  def terminate(_Event, _State) do
    :ok
  end

  def code_change(_, _, state) do
    state
  end

  defp create_menus(parent) do
    menuEntries = [
      {~c"View",
       [
         r_create_menu(id: 304, text: ~c"Socket info for selected sockets\tCtrl-I"),
         :separator,
         r_create_menu(id: 301, text: ~c"Refresh\tCtrl-R"),
         r_create_menu(
           id: 302,
           text: ~c"Refresh Interval..."
         )
       ]}
    ]

    :observer_wx.create_menus(parent, menuEntries)
  end

  defp get_sockets({nodeName, available}) do
    get_sockets(nodeName, available)
  end

  defp get_sockets(nodeName) when is_atom(nodeName) do
    case :rpc.call(nodeName, :observer_backend, :get_socket_list, []) do
      socketInfoMaps when is_list(socketInfoMaps) ->
        for sockInfo <- socketInfoMaps do
          infomap_to_rec(sockInfo)
        end

      {:badrpc, {:EXIT, {:undef, [{:observer_backend, :get_socket_list, [], []}]}}} ->
        {:error, ~c"No socket backend support"}

      {:badrpc, error} ->
        {:error, error}

      {:error, _} = eRROR ->
        eRROR
    end
  end

  defp get_sockets(_NodeName, false) do
    []
  end

  defp get_sockets(nodeName, true) do
    case get_sockets(nodeName) do
      {:error, _} = eRROR ->
        send(self(), eRROR)
        []

      res ->
        res
    end
  end

  defp infomap_to_rec(
         %{
           id: id,
           id_str: idStr,
           kind: kind,
           fd: fD,
           owner: owner,
           domain: domain,
           type: type,
           protocol: protocol,
           rstates: rState,
           wstates: wState,
           monitored_by: monitoredBy,
           statistics: statistics,
           options: options
         } = info
       ) do
    r_socket(
      id: id,
      id_str: idStr,
      kind: kind,
      fd: fD,
      owner: owner,
      domain: domain,
      type: type,
      protocol: protocol,
      raddress: :maps.get(:raddress, info, :undefined),
      laddress: :maps.get(:laddress, info, :undefined),
      rstate: rState,
      wstate: wState,
      monitored_by: monitoredBy,
      statistics: statistics,
      options: options
    )
  end

  defp socketrec_to_list(
         r_socket(
           id: id,
           id_str: idStr,
           kind: kind,
           fd: fD,
           owner: owner,
           domain: domain,
           type: type,
           protocol: protocol,
           raddress: rAddr,
           laddress: lAddr,
           rstate: rState,
           wstate: wState,
           monitored_by: monitoredBy,
           statistics: statistics,
           options: options
         )
       ) do
    [
      {:id, id},
      {:id_str, idStr},
      {:kind, kind},
      {:fd, fD},
      {:owner, owner},
      {:domain, domain},
      {:type, type},
      {:protocol, protocol},
      {:raddress, rAddr},
      {:laddress, lAddr},
      {:rstate, rState},
      {:wstate, wState},
      {:monitored_by, monitoredBy},
      {:statistics, statistics},
      {:options, options}
    ]
  end

  defp display_socket_info(parent, r_socket(id_str: idStr) = sock, opened) do
    case :lists.keyfind(idStr, 1, opened) do
      false ->
        frame = do_display_socket_info(parent, sock)
        [{idStr, frame} | opened]

      {_, win} ->
        :wxFrame.raise(win)
        opened
    end
  end

  defp do_display_socket_info(parent0, r_socket(id_str: idStr) = socketRec) do
    parent = :observer_lib.get_wx_parent(parent0)
    title = ~c"Socket Info: " ++ idStr
    scale = :observer_wx.get_scale()

    frame =
      :wxMiniFrame.new(parent, -1, title, [
        {:style, 2048 ||| 536_870_912 ||| 4096 ||| 64},
        {:size, {scale * 600, scale * 400}}
      ])

    scrolledWin =
      :wxScrolledWindow.new(
        frame,
        [{:style, 1_073_741_824 ||| -2_147_483_648}]
      )

    :wxScrolledWindow.enableScrolling(scrolledWin, true, true)
    :wxScrolledWindow.setScrollbars(scrolledWin, 20, 20, 0, 0)
    sizer = :wxBoxSizer.new(8)
    :wxWindow.setSizer(scrolledWin, sizer)
    socket = socketrec_to_list(socketRec)
    fields0 = socket_info_fields(socket)
    _UpFields = :observer_lib.display_info(scrolledWin, sizer, fields0)
    :wxFrame.center(frame)
    :wxFrame.connect(frame, :close_window, [{:skip, true}])
    :wxFrame.show(frame)
    frame
  end

  defp socket_info_fields(socket0) do
    {struct0, socket} = extra_fields(socket0)

    struct = [
      {~c"Overview",
       [
         {~c"Owner", {:click, :owner}},
         {~c"Fd", :fd},
         {~c"Domain", :domain},
         {~c"Type", :type},
         {~c"Protocol", :protocol},
         {~c"Read State", :rstate},
         {~c"Write State", :wstate}
       ]},
      {:scroll_boxes, [{~c"Monitored by", 1, {:click, :monitored_by}}]}
      | struct0
    ]

    :observer_lib.fill_info(struct, socket)
  end

  defp extra_fields(socket) do
    statistics = :proplists.get_value(:statistics, socket, [])
    options = :proplists.get_value(:options, socket, [])

    struct = [
      {~c"Net", [{~c"Local Address", :laddress}, {~c"Remote Address", :raddress}]},
      {~c"Statistics",
       for {key, _} <- statistics do
         stat_name_and_unit(key)
       end},
      {~c"Options",
       for {key, _} <- options do
         {:socket, sockopt_to_list(key), key}
       end}
    ]

    socket1 = :lists.keydelete(:statistics, 1, socket)
    socket2 = :lists.keydelete(:options, 1, socket1)
    {struct, socket2 ++ statistics ++ options}
  end

  defp stat_name_and_unit(:acc_fails = key) do
    {~c"Number of accept fails", key}
  end

  defp stat_name_and_unit(:acc_success = key) do
    {~c"Number of accept success", key}
  end

  defp stat_name_and_unit(:acc_tries = key) do
    {~c"Number of accept tries", key}
  end

  defp stat_name_and_unit(:acc_waits = key) do
    {~c"Number of accept waits", key}
  end

  defp stat_name_and_unit(:read_byte = key) do
    {~c"Total read", {:bytes, key}}
  end

  defp stat_name_and_unit(:read_fails = key) do
    {~c"Number of read fails", key}
  end

  defp stat_name_and_unit(:read_tries = key) do
    {~c"Number of read tries", key}
  end

  defp stat_name_and_unit(:read_waits = key) do
    {~c"Number of read waits", key}
  end

  defp stat_name_and_unit(:read_pkg = key) do
    {~c"Number of packats read", key}
  end

  defp stat_name_and_unit(:read_pkg_max = key) do
    {~c"Largest package read", {:bytes, key}}
  end

  defp stat_name_and_unit(:write_byte = key) do
    {~c"Total written", {:bytes, key}}
  end

  defp stat_name_and_unit(:write_fails = key) do
    {~c"Number of write fails", key}
  end

  defp stat_name_and_unit(:write_tries = key) do
    {~c"Number of write tries", key}
  end

  defp stat_name_and_unit(:write_waits = key) do
    {~c"Number of write waits", key}
  end

  defp stat_name_and_unit(:write_pkg = key) do
    {~c"Number of packats written", key}
  end

  defp stat_name_and_unit(:write_pkg_max = key) do
    {~c"Largest package written", {:bytes, key}}
  end

  defp stat_name_and_unit(key) do
    {:erlang.atom_to_list(key), key}
  end

  defp sockopt_to_list({levelOrProto, opt}) do
    f(~c"~w:~w", [levelOrProto, opt])
  end

  defp update_grid(grid, sel, opt, ports) do
    :wx.batch(fn ->
      update_grid2(grid, sel, opt, ports)
    end)
  end

  defp update_grid2(grid, sel, r_opt(sort_key: sort, sort_incr: dir, odd_bg: bG), ports) do
    :wxListCtrl.deleteAllItems(grid)

    update = fn r_socket(
                  id: id,
                  id_str: idStr,
                  owner: owner,
                  fd: fd,
                  domain: domain,
                  type: type,
                  protocol: proto,
                  rstate: rState,
                  wstate: wState
                ),
                row ->
      _Item = :wxListCtrl.insertItem(grid, row, ~c"")

      cond do
        rem(row, 2) === 1 ->
          :wxListCtrl.setItemBackgroundColour(grid, row, bG)

        true ->
          :ignore
      end

      :lists.foreach(
        fn {col, val} ->
          :wxListCtrl.setItem(grid, row, col, :observer_lib.to_str(val))
        end,
        [
          {0, idStr},
          {1, owner},
          {2, fd},
          {3, domain},
          {4, type},
          {5, proto},
          {6,
           cond do
             rState === [] ->
               ~c"-"

             true ->
               rState
           end},
          {7,
           cond do
             wState === [] ->
               ~c"-"

             true ->
               wState
           end}
        ]
      )

      case :lists.member(id, sel) do
        true ->
          :wxListCtrl.setItemState(grid, row, 65535, 4)

        false ->
          :wxListCtrl.setItemState(grid, row, 0, 4)
      end

      row + 1
    end

    portInfo =
      case dir do
        false ->
          :lists.reverse(:lists.keysort(sort, ports))

        true ->
          :lists.keysort(sort, ports)
      end

    :lists.foldl(update, 0, portInfo)
    portInfo
  end

  defp sel(r_state(grid: grid, sockets: sockets)) do
    for r_socket(id: id) <- get_selected_items(grid, sockets) do
      id
    end
  end

  defp get_selected_items(grid, data) do
    get_indecies(get_selected_items(grid, -1, []), data)
  end

  defp get_selected_items(grid, index, itemAcc) do
    item = :wxListCtrl.getNextItem(grid, index, [{:geometry, 1}, {:state, 4}])

    case item do
      -1 ->
        :lists.reverse(itemAcc)

      _ ->
        get_selected_items(grid, item, [item | itemAcc])
    end
  end

  defp get_indecies(items, data) do
    get_indecies(items, 0, data)
  end

  defp get_indecies([i | rest], i, [h | t]) do
    [h | get_indecies(rest, i + 1, t)]
  end

  defp get_indecies(rest = [_ | _], i, [_ | t]) do
    get_indecies(rest, i + 1, t)
  end

  defp get_indecies(_, _, _) do
    []
  end

  defp socketinfo_available(nodeName) do
    _ = :rpc.call(nodeName, :code, :ensure_loaded, [:observer_backend])

    case :rpc.call(nodeName, :erlang, :function_exported, [:observer_backend, :get_socket_list, 0]) do
      true ->
        true

      false ->
        false
    end
  end

  defp popup_unavailable_info(nodeName) do
    send(self(), {:info, {:socket_info_not_available, nodeName}})
    :ok
  end

  defp f(f, a) do
    :lists.flatten(:io_lib.format(f, a))
  end
end
