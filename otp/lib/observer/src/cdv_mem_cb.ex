defmodule :m_cdv_mem_cb do
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

  def get_info() do
    :observer_lib.report_progress({:ok, ~c"Processing memory info"})
    memInfo = get_mem_info()
    :observer_lib.report_progress({:ok, 33})
    {allocInfo, allocTW} = get_alloc_info()
    :observer_lib.report_progress({:ok, 66})
    areaInfo = get_area_info()
    :observer_lib.report_progress({:ok, 100})

    [
      {~c"Memory", :cdv_info_wx, memInfo}
      | for {title, cols, data} <- allocInfo do
          {title, :cdv_table_wx, {cols, data, allocTW}}
        end
    ] ++ [{~c"Allocated Areas", :cdv_table_wx, areaInfo}]
  end

  defp get_mem_info() do
    {:ok, info, tW} = :crashdump_viewer.memory()
    {[{~c"Memory Information", gen_mem_info_fields(info)}], info, tW}
  end

  defp gen_mem_info_fields([{key, _} | t]) do
    [
      {upper(:erlang.atom_to_list(key)), {:bytes, key}}
      | gen_mem_info_fields(t)
    ]
  end

  defp gen_mem_info_fields([]) do
    []
  end

  defp upper(key) do
    :lists.join(
      ~c" ",
      for word <- :string.split(key, ~c"_", :all) do
        :string.titlecase(word)
      end
    )
  end

  defp get_area_info() do
    {:ok, info0, tW} = :crashdump_viewer.allocated_areas()

    info =
      for r <- info0 do
        :erlang.tuple_to_list(r)
      end

    {area_columns(), info, tW}
  end

  defp area_columns() do
    [{~c"", 0, 150}, {~c"Allocated (bytes)", 1, 150}, {~c"Used (bytes)", 1, 150}]
  end

  defp get_alloc_info() do
    {:ok, info, tW} = :crashdump_viewer.allocator_info()
    {fix_alloc(info), tW}
  end

  defp fix_alloc([{title, columns, data} | tables]) do
    [
      {title, alloc_columns(columns),
       for {key, values} <- data do
         [key | values]
       end}
      | fix_alloc(tables)
    ]
  end

  defp fix_alloc([{title, [{_, v} | _] = data} | tables]) do
    fix_alloc([
      {title, :lists.duplicate(length(v), []), data}
      | tables
    ])
  end

  defp fix_alloc([{~c"", []} | tables]) do
    fix_alloc(tables)
  end

  defp fix_alloc([{title, [] = data} | tables]) do
    fix_alloc([{title, [], data} | tables])
  end

  defp fix_alloc([]) do
    []
  end

  defp alloc_columns(columns) do
    [
      {~c"", 0, 180}
      | for column <- columns do
          {column, 1, 140}
        end
    ]
  end
end
