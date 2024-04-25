defmodule :m_cdv_html_wx do
  use Bitwise
  @behaviour :wx_object
  require Record
  Record.defrecord(:r_wx, :wx, id: :undefined,
                              obj: :undefined, userData: :undefined,
                              event: :undefined)
  Record.defrecord(:r_wxActivate, :wxActivate, type: :undefined,
                                      active: :undefined)
  Record.defrecord(:r_wxAuiManager, :wxAuiManager, type: :undefined,
                                        manager: :undefined, pane: :undefined,
                                        button: :undefined,
                                        veto_flag: :undefined,
                                        canveto_flag: :undefined,
                                        dc: :undefined)
  Record.defrecord(:r_wxAuiNotebook, :wxAuiNotebook, type: :undefined,
                                         old_selection: :undefined,
                                         selection: :undefined,
                                         drag_source: :undefined)
  Record.defrecord(:r_wxBookCtrl, :wxBookCtrl, type: :undefined,
                                      nSel: :undefined, nOldSel: :undefined)
  Record.defrecord(:r_wxCalendar, :wxCalendar, type: :undefined,
                                      wday: :undefined, date: :undefined)
  Record.defrecord(:r_wxChildFocus, :wxChildFocus, type: :undefined)
  Record.defrecord(:r_wxClipboardText, :wxClipboardText, type: :undefined)
  Record.defrecord(:r_wxClose, :wxClose, type: :undefined)
  Record.defrecord(:r_wxColourPicker, :wxColourPicker, type: :undefined,
                                          colour: :undefined)
  Record.defrecord(:r_wxCommand, :wxCommand, type: :undefined,
                                     cmdString: :undefined,
                                     commandInt: :undefined,
                                     extraLong: :undefined)
  Record.defrecord(:r_wxContextMenu, :wxContextMenu, type: :undefined,
                                         pos: :undefined)
  Record.defrecord(:r_wxDate, :wxDate, type: :undefined,
                                  date: :undefined)
  Record.defrecord(:r_wxDisplayChanged, :wxDisplayChanged, type: :undefined)
  Record.defrecord(:r_wxDropFiles, :wxDropFiles, type: :undefined,
                                       pos: :undefined, files: :undefined)
  Record.defrecord(:r_wxErase, :wxErase, type: :undefined,
                                   dc: :undefined)
  Record.defrecord(:r_wxFileDirPicker, :wxFileDirPicker, type: :undefined,
                                           path: :undefined)
  Record.defrecord(:r_wxFocus, :wxFocus, type: :undefined,
                                   win: :undefined)
  Record.defrecord(:r_wxFontPicker, :wxFontPicker, type: :undefined,
                                        font: :undefined)
  Record.defrecord(:r_wxGrid, :wxGrid, type: :undefined,
                                  row: :undefined, col: :undefined,
                                  pos: :undefined, selecting: :undefined,
                                  control: :undefined, meta: :undefined,
                                  shift: :undefined, alt: :undefined)
  Record.defrecord(:r_wxHelp, :wxHelp, type: :undefined)
  Record.defrecord(:r_wxHtmlLink, :wxHtmlLink, type: :undefined,
                                      linkInfo: :undefined)
  Record.defrecord(:r_wxIconize, :wxIconize, type: :undefined,
                                     iconized: :undefined)
  Record.defrecord(:r_wxIdle, :wxIdle, type: :undefined)
  Record.defrecord(:r_wxInitDialog, :wxInitDialog, type: :undefined)
  Record.defrecord(:r_wxJoystick, :wxJoystick, type: :undefined,
                                      pos: :undefined, zPosition: :undefined,
                                      buttonChange: :undefined,
                                      buttonState: :undefined,
                                      joyStick: :undefined)
  Record.defrecord(:r_wxKey, :wxKey, type: :undefined,
                                 x: :undefined, y: :undefined,
                                 keyCode: :undefined, controlDown: :undefined,
                                 shiftDown: :undefined, altDown: :undefined,
                                 metaDown: :undefined, uniChar: :undefined,
                                 rawCode: :undefined, rawFlags: :undefined)
  Record.defrecord(:r_wxList, :wxList, type: :undefined,
                                  code: :undefined, oldItemIndex: :undefined,
                                  itemIndex: :undefined, col: :undefined,
                                  pointDrag: :undefined)
  Record.defrecord(:r_wxMaximize, :wxMaximize, type: :undefined)
  Record.defrecord(:r_wxMenu, :wxMenu, type: :undefined,
                                  menuId: :undefined, menu: :undefined)
  Record.defrecord(:r_wxMouseCaptureChanged, :wxMouseCaptureChanged, type: :undefined)
  Record.defrecord(:r_wxMouseCaptureLost, :wxMouseCaptureLost, type: :undefined)
  Record.defrecord(:r_wxMouse, :wxMouse, type: :undefined,
                                   x: :undefined, y: :undefined,
                                   leftDown: :undefined, middleDown: :undefined,
                                   rightDown: :undefined,
                                   controlDown: :undefined,
                                   shiftDown: :undefined, altDown: :undefined,
                                   metaDown: :undefined,
                                   wheelRotation: :undefined,
                                   wheelDelta: :undefined,
                                   linesPerAction: :undefined)
  Record.defrecord(:r_wxMove, :wxMove, type: :undefined,
                                  pos: :undefined, rect: :undefined)
  Record.defrecord(:r_wxNavigationKey, :wxNavigationKey, type: :undefined,
                                           dir: :undefined, focus: :undefined)
  Record.defrecord(:r_wxPaint, :wxPaint, type: :undefined)
  Record.defrecord(:r_wxPaletteChanged, :wxPaletteChanged, type: :undefined)
  Record.defrecord(:r_wxQueryNewPalette, :wxQueryNewPalette, type: :undefined)
  Record.defrecord(:r_wxSash, :wxSash, type: :undefined,
                                  edge: :undefined, dragRect: :undefined,
                                  dragStatus: :undefined)
  Record.defrecord(:r_wxScroll, :wxScroll, type: :undefined,
                                    commandInt: :undefined,
                                    extraLong: :undefined)
  Record.defrecord(:r_wxScrollWin, :wxScrollWin, type: :undefined,
                                       commandInt: :undefined,
                                       extraLong: :undefined)
  Record.defrecord(:r_wxSetCursor, :wxSetCursor, type: :undefined,
                                       x: :undefined, y: :undefined,
                                       cursor: :undefined)
  Record.defrecord(:r_wxShow, :wxShow, type: :undefined,
                                  show: :undefined)
  Record.defrecord(:r_wxSize, :wxSize, type: :undefined,
                                  size: :undefined, rect: :undefined)
  Record.defrecord(:r_wxSpin, :wxSpin, type: :undefined,
                                  commandInt: :undefined)
  Record.defrecord(:r_wxSplitter, :wxSplitter, type: :undefined)
  Record.defrecord(:r_wxStyledText, :wxStyledText, type: :undefined,
                                        position: :undefined, key: :undefined,
                                        modifiers: :undefined,
                                        modificationType: :undefined,
                                        text: :undefined, length: :undefined,
                                        linesAdded: :undefined,
                                        line: :undefined,
                                        foldLevelNow: :undefined,
                                        foldLevelPrev: :undefined,
                                        margin: :undefined, message: :undefined,
                                        wParam: :undefined, lParam: :undefined,
                                        listType: :undefined, x: :undefined,
                                        y: :undefined, dragText: :undefined,
                                        dragAllowMove: :undefined,
                                        dragResult: :undefined)
  Record.defrecord(:r_wxSysColourChanged, :wxSysColourChanged, type: :undefined)
  Record.defrecord(:r_wxTaskBarIcon, :wxTaskBarIcon, type: :undefined)
  Record.defrecord(:r_wxTree, :wxTree, type: :undefined,
                                  item: :undefined, itemOld: :undefined,
                                  pointDrag: :undefined)
  Record.defrecord(:r_wxUpdateUI, :wxUpdateUI, type: :undefined)
  Record.defrecord(:r_wxWebView, :wxWebView, type: :undefined,
                                     string: :undefined, int: :undefined,
                                     target: :undefined, url: :undefined)
  Record.defrecord(:r_wxWindowCreate, :wxWindowCreate, type: :undefined)
  Record.defrecord(:r_wxWindowDestroy, :wxWindowDestroy, type: :undefined)
  Record.defrecord(:r_wxMouseState, :wxMouseState, x: :undefined,
                                        y: :undefined, leftDown: :undefined,
                                        middleDown: :undefined,
                                        rightDown: :undefined,
                                        controlDown: :undefined,
                                        shiftDown: :undefined,
                                        altDown: :undefined,
                                        metaDown: :undefined,
                                        cmdDown: :undefined)
  Record.defrecord(:r_wxHtmlLinkInfo, :wxHtmlLinkInfo, href: :undefined,
                                          target: :undefined)
  Record.defrecord(:r_match_spec, :match_spec, name: '', term: [],
                                      str: [], func: '')
  Record.defrecord(:r_tpattern, :tpattern, m: :undefined,
                                    fa: :undefined, ms: :undefined)
  Record.defrecord(:r_traced_func, :traced_func, func_name: :undefined,
                                       arity: :undefined,
                                       match_spec: :EFE_TODO_NESTED_RECORD)
  Record.defrecord(:r_create_menu, :create_menu, id: :undefined,
                                       text: :undefined, help: [],
                                       type: :append, check: false)
  Record.defrecord(:r_colors, :colors, fg: :undefined,
                                  even: :undefined, odd: :undefined)
  Record.defrecord(:r_attrs, :attrs, even: :undefined,
                                 odd: :undefined, searched: :undefined,
                                 deleted: :undefined, changed_odd: :undefined,
                                 changed_even: :undefined, new_odd: :undefined,
                                 new_even: :undefined)
  Record.defrecord(:r_ti, :ti, tick: 0, disp: 10 / 2,
                              fetch: 2, secs: 60)
  Record.defrecord(:r_win, :win, name: :undefined,
                               panel: :undefined, size: :undefined,
                               geom: :undefined, graphs: [], no_samples: 0,
                               max: :undefined, state: :undefined, info: [])
  Record.defrecord(:r_state, :state, parent: :undefined,
                                 panel: :undefined, app: :undefined,
                                 expand_table: :undefined, expand_wins: [],
                                 delayed_fetch: :undefined, trunc_warn: [])
  def start_link(parentWin, info) do
    :wx_object.start_link(:cdv_html_wx, [parentWin, info],
                            [])
  end

  def init([parentWin, callback]) when is_atom(callback) do
    init(parentWin, callback)
  end

  def init([parentWin, {app, fun}]) when is_function(fun) do
    init([parentWin, {app, fun.()}])
  end

  def init([parentWin, {:expand, htmlText, tab}]) do
    init(parentWin, htmlText, tab, :cdv)
  end

  def init([parentWin, {app, {:expand, htmlText, tab}}]) do
    init(parentWin, htmlText, tab, app)
  end

  def init([parentWin, {app, htmlText}]) do
    init(parentWin, htmlText, :undefined, app)
  end

  def init([parentWin, htmlText]) do
    init(parentWin, htmlText, :undefined, :cdv)
  end

  defp init(parentWin, htmlText, tab, app) do
    :observer_lib.destroy_progress_dialog()
    :wx_misc.beginBusyCursor()
    htmlWin = :observer_lib.html_window(parentWin)
    :wxHtmlWindow.setPage(htmlWin, htmlText)
    :wx_misc.endBusyCursor()
    {htmlWin,
       r_state(parent: parentWin, panel: htmlWin, expand_table: tab,
           app: app)}
  end

  defp init(parentWin, callback) do
    {htmlWin, state} = init(parentWin, '', :undefined, :cdv)
    {htmlWin, r_state(state, delayed_fetch: callback)}
  end

  def handle_info(:active,
           r_state(parent: parent, panel: htmlWin,
               delayed_fetch: callback) = state)
      when callback !== :undefined do
    :observer_lib.display_progress_dialog(htmlWin, 'Crashdump Viewer', 'Reading data')
    {{:expand, title, info, tab}, tW} = callback.get_info()
    cs = :observer_lib.colors(parent)
    htmlText = :observer_html_lib.expandable_term(title,
                                                    info, tab, cs)
    :observer_lib.sync_destroy_progress_dialog()
    :wx_misc.beginBusyCursor()
    :wxHtmlWindow.setPage(htmlWin, htmlText)
    cdv_wx_set_status(state, tW)
    :wx_misc.endBusyCursor()
    {:noreply,
       r_state(state, expand_table: tab,  delayed_fetch: :undefined, 
                  trunc_warn: tW)}
  end

  def handle_info(:active, state) do
    cdv_wx_set_status(state, r_state(state, :trunc_warn))
    {:noreply, state}
  end

  def handle_info(info, state) do
    :io.format('~p:~p: Unhandled info: ~tp~n', [:cdv_html_wx, 97, info])
    {:noreply, state}
  end

  def terminate(_Reason, _State) do
    :ok
  end

  def code_change(_, _, state) do
    {:ok, state}
  end

  def handle_call(msg, _From, state) do
    :io.format('~p~p: Unhandled Call ~tp~n', [:cdv_html_wx, 107, msg])
    {:reply, :ok, state}
  end

  def handle_cast({:detail_win_closed, id},
           r_state(expand_wins: opened0) = state) do
    opened = :lists.keydelete(id, 1, opened0)
    {:noreply, r_state(state, expand_wins: opened)}
  end

  def handle_cast(msg, state) do
    :io.format('~p~p: Unhandled cast ~tp~n', [:cdv_html_wx, 115, msg])
    {:noreply, state}
  end

  def handle_event(r_wx(event: r_wxHtmlLink(type: :command_html_link_clicked,
                      linkInfo: r_wxHtmlLinkInfo(href: target))),
           r_state(expand_table: tab, app: app) = state) do
    newState = (case (target) do
                  '#Binary?' ++ binSpec ->
                    [{'offset', off}, {'size', size}, {'pos',
                                             pos}] = :uri_string.dissect_query(binSpec)
                    id = {:cdv,
                            {:erlang.list_to_integer(off),
                               :erlang.list_to_integer(size),
                               :erlang.list_to_integer(pos)}}
                    expand(id, :cdv_bin_cb, state)
                  '#OBSBinary?' ++ binSpec ->
                    [{'key1', preview}, {'key2', size}, {'key3',
                                                 hash}] = :uri_string.dissect_query(binSpec)
                    id = {:obs,
                            {tab,
                               {:erlang.list_to_integer(preview),
                                  :erlang.list_to_integer(size),
                                  :erlang.list_to_integer(hash)}}}
                    expand(id, :cdv_bin_cb, state)
                  '#Term?' ++ termKeys ->
                    [{'key1', key1}, {'key2', key2}, {'key3',
                                              key3}] = :uri_string.dissect_query(termKeys)
                    id = {:cdv,
                            {tab,
                               {:erlang.list_to_integer(key1),
                                  :erlang.list_to_integer(key2),
                                  :erlang.list_to_integer(key3)}}}
                    expand(id, :cdv_term_cb, state)
                  _ when app === :obs ->
                    send(:observer, {:open_link, target})
                    state
                  _ ->
                    :cdv_virtual_list_wx.start_detail_win(target)
                    state
                end)
    {:noreply, newState}
  end

  def handle_event(event, state) do
    :io.format('~p:~p: Unhandled event ~tp\n', [:cdv_html_wx, 154, event])
    {:noreply, state}
  end

  defp expand(id, callback,
            r_state(expand_wins: opened0, app: app) = state) do
    opened = (case (:lists.keyfind(id, 1, opened0)) do
                false ->
                  eW = :cdv_detail_wx.start_link(id, [], r_state(state, :panel),
                                                   callback, app)
                  send(:wx_object.get_pid(eW), :active)
                  [{id, eW} | opened0]
                {_, eW} ->
                  :wxFrame.raise(eW)
                  opened0
              end)
    r_state(state, expand_wins: opened)
  end

  defp cdv_wx_set_status(r_state(app: :cdv), status) do
    :cdv_wx.set_status(status)
  end

  defp cdv_wx_set_status(_, _) do
    :ok
  end

end