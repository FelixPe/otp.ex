defmodule :m_cdv_proc_cb do
  use Bitwise
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
    cmdDown: :undefined,
    aux1Down: :undefined,
    aux2Down: :undefined
  )

  Record.defrecord(:r_wxHtmlLinkInfo, :wxHtmlLinkInfo,
    href: :undefined,
    target: :undefined
  )

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

  def col_to_elem(:id) do
    col_to_elem(0)
  end

  def col_to_elem(0) do
    r_proc(:pid)
  end

  def col_to_elem(1) do
    r_proc(:name)
  end

  def col_to_elem(2) do
    r_proc(:state)
  end

  def col_to_elem(4) do
    r_proc(:memory)
  end

  def col_to_elem(3) do
    r_proc(:reds)
  end

  def col_to_elem(5) do
    r_proc(:msg_q_len)
  end

  def col_spec() do
    [
      {~c"Pid", 2, 120},
      {~c"Name or Initial Func", 0, 250},
      {~c"State", 0, 100},
      {~c"Reds", 1, 80},
      {~c"Memory", 1, 80},
      {~c"MsgQ", 1, 50}
    ]
  end

  def get_info(_) do
    {:ok, info, tW} = :crashdump_viewer.processes()
    {info, tW}
  end

  def get_detail_cols(_) do
    {[{:process, 0}], true}
  end

  def get_details(id, _) do
    case :crashdump_viewer.proc_details(id) do
      {:ok, info, tW} ->
        tab = :ets.new(:cdv_expand, [:set, :public])

        proplist0 =
          :crashdump_viewer.to_proplist(
            Keyword.keys(r_proc(r_proc())),
            info
          )

        proplist = [{:expand_table, tab} | proplist0]
        title = :io_lib.format(~c"~ts (~s)", [r_proc(info, :name), id])
        {:ok, {title, proplist, tW}}

      {:error, {:other_node, nodeId}} ->
        info =
          ~c"The process you are searching for was residing on a remote node. No process information is available. Show information about the remote node?"

        fun = fn ->
          :cdv_virtual_list_wx.start_detail_win(nodeId, :node)
        end

        {:yes_no, info, fun}

      {:error, :not_found} ->
        info = ~c"The process you are searching for could not be found."
        {:info, info}
    end
  end

  def detail_pages() do
    [
      {~c"General Information", &init_gen_page/2},
      {~c"Messages", &init_message_page/2},
      {~c"Dictionary", &init_dict_page/2},
      {~c"Stack Dump", &init_stack_page/2},
      {~c"ETS tables", &init_ets_page/2},
      {~c"Timers", &init_timer_page/2}
    ]
  end

  defp init_gen_page(parent, info) do
    fields = info_fields()
    :cdv_info_wx.start_link(parent, {fields, info, []})
  end

  defp init_message_page(parent, info) do
    init_memory_page(parent, info, :msg_q, ~c"MsgQueue")
  end

  defp init_dict_page(parent, info) do
    init_memory_page(parent, info, :dict, ~c"Dictionary")
  end

  defp init_stack_page(parent, info) do
    init_memory_page(parent, info, :stack_dump, ~c"StackDump")
  end

  defp init_memory_page(parent, info0, tag, heading) do
    info = :proplists.get_value(tag, info0)
    tab = :proplists.get_value(:expand_table, info0)
    html = :observer_html_lib.expandable_term(heading, info, tab, :observer_lib.colors(parent))
    :cdv_html_wx.start_link(parent, {:expand, html, tab})
  end

  defp init_ets_page(parent, info) do
    pid = :proplists.get_value(:pid, info)
    :cdv_virtual_list_wx.start_link(parent, :cdv_ets_cb, pid)
  end

  defp init_timer_page(parent, info) do
    pid = :proplists.get_value(:pid, info)
    :cdv_virtual_list_wx.start_link(parent, :cdv_timer_cb, pid)
  end

  defp info_fields() do
    [
      {~c"Overview",
       [
         {~c"Initial Call", :init_func},
         {:dynamic, :current_func},
         {~c"Registered Name", :name},
         {~c"Status", :state},
         {~c"Internal State", :int_state},
         {~c"Started", :start_time},
         {~c"Parent", {:click, :parent}},
         {~c"Message Queue Len", :msg_q_len},
         {~c"Run queue", :run_queue},
         {~c"Reductions", :reds},
         {~c"Program counter", :prog_count},
         {~c"Continuation pointer", :cp},
         {~c"Arity", :arity}
       ]},
      {:scroll_boxes, [{~c"Last Calls", 1, {:plain, :last_calls}}]},
      {:scroll_boxes,
       [
         {~c"Links", 1, {:click, :links}},
         {~c"Monitors", 2, {:click, :monitors}},
         {~c"Monitored By", 2, {:click, :mon_by}}
       ]},
      {~c"Memory and Garbage Collection",
       [
         {~c"Memory", :memory},
         {~c"Stack and Heap", :stack_heap},
         {~c"Old Heap", :old_heap},
         {~c"Heap Unused", :heap_unused},
         {~c"Old Heap Unused", :old_heap_unused},
         {~c"Binary vheap", :bin_vheap},
         {~c"Old Binary vheap", :old_bin_vheap},
         {~c"Binary vheap unused", :bin_vheap_unused},
         {~c"Old Binary vheap unused", :old_bin_vheap_unused},
         {~c"Number of Heap Fragments", :num_heap_frag},
         {~c"Heap Fragment Data", :heap_frag_data},
         {~c"New Heap Start", :new_heap_start},
         {~c"New Heap Top", :new_heap_top},
         {~c"Stack Top", :stack_top},
         {~c"Stack End", :stack_end},
         {~c"Old Heap Start", :old_heap_start},
         {~c"Old Heap Top", :old_heap_top},
         {~c"Old Heap End", :old_heap_end}
       ]}
    ]
  end
end
