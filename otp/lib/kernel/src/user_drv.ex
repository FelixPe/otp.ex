defmodule :m_user_drv do
  use Bitwise
  @behaviour :gen_statem
  require Record
  Record.defrecord(:r_editor, :editor, port: :undefined,
                                  file: :undefined, requester: :undefined)
  Record.defrecord(:r_state, :state, tty: :undefined,
                                 write: :undefined, read: :undefined,
                                 shell_started: :new, editor: :undefined,
                                 user: :undefined, current_group: :undefined,
                                 groups: :undefined, queue: :undefined)
  def start() do
    case (:init.get_argument(:remsh)) do
      {:ok, [[node]]} ->
        start(%{initial_shell: {:remote, node}})
      {:ok, [[node] | _]} ->
        case (:logger.allow(:warning, :user_drv)) do
          true ->
            :erlang.apply(:logger, :macro_log,
                            [%{mfa: {:user_drv, :start, 0}, line: 124, file: 'otp/lib/kernel/src/user_drv.erl'},
                                 :warning, 'Multiple -remsh given to erl, using the first, ~p', [node]])
          false ->
            :ok
        end
        start(%{initial_shell: {:remote, node}})
      e when e === :error or e === {:ok, [[]]} ->
        start(%{})
    end
  end

  def start_shell() do
    start_shell(%{})
  end

  def start_shell(args) do
    :gen_statem.call(:user_drv, {:start_shell, args})
  end

  def whereis_group() do
    {:dictionary,
       dict} = :erlang.process_info(:erlang.whereis(:user_drv),
                                      :dictionary)
    :proplists.get_value(:current_group, dict)
  end

  def start([:"tty_sl -c -e", shell]) do
    start(%{initial_shell: shell})
  end

  def start(args) when is_map(args) do
    case (:gen_statem.start({:local, :user_drv}, :user_drv,
                              args, [])) do
      {:ok, pid} ->
        pid
      {:error, reason} ->
        {:error, reason}
    end
  end

  def callback_mode() do
    :state_functions
  end

  def init(args) do
    :erlang.process_flag(:trap_exit, true)
    isTTY = :prim_tty.isatty(:stdin) === true and :prim_tty.isatty(:stdout) === true
    startShell = :maps.get(:initial_shell, args,
                             :undefined) !== :noshell
    oldShell = :maps.get(:initial_shell, args,
                           :undefined) === :oldshell
    try do
      cond do
        not isTTY and startShell or oldShell ->
          :erlang.error(:enotsup)
        (isTTY and startShell) ->
          tTYState = :prim_tty.init(%{})
          init_standard_error(tTYState, true)
          {:ok, :init, {args, r_state(user: start_user())},
             {:next_event, :internal, tTYState}}
        true ->
          tTYState = :prim_tty.init(%{input:
                                      :maps.get(:input, args, true),
                                        tty: false})
          init_standard_error(tTYState, false)
          {:ok, :init, {args, r_state(user: start_user())},
             {:next_event, :internal, tTYState}}
      end
    catch
      :error, :enotsup ->
        catchTTYState = :prim_tty.init(%{tty: false})
        init_standard_error(catchTTYState, false)
        {:ok, :init,
           {args, r_state(shell_started: :old, user: start_user())},
           {:next_event, :internal, catchTTYState}}
    end
  end

  defp init_standard_error(tTY, newlineCarriageReturn) do
    encoding = (case (:prim_tty.unicode(tTY)) do
                  true ->
                    :unicode
                  false ->
                    :latin1
                end)
    :ok = :io.setopts(:standard_error,
                        [{:encoding, encoding}, {:onlcr,
                                                   newlineCarriageReturn}])
  end

  def init(:internal, tTYState,
           {args, state = r_state(user: user)}) do
    :erlang.put(:"$ancestors", [user | :erlang.get(:"$ancestors")])
    %{read: readHandle,
        write: writeHandle} = :prim_tty.handles(tTYState)
    newState = r_state(state, tty: tTYState,  read: readHandle, 
                          write: writeHandle,  user: user, 
                          queue: {false, :queue.new()}, 
                          groups: gr_add_cur(gr_new(), user, {}))
    case (args) do
      %{initial_shell: :noshell} ->
        init_noshell(newState)
      %{initial_shell: {:remote, node}} ->
        initialShell = {:shell, :start, []}
        exit_on_remote_shell_error(node, initialShell,
                                     init_remote_shell(newState, node,
                                                         initialShell))
      %{initial_shell: {:remote, node, initialShell}} ->
        exit_on_remote_shell_error(node, initialShell,
                                     init_remote_shell(newState, node,
                                                         initialShell))
      %{initial_shell: :oldshell} ->
        :old = r_state(state, :shell_started)
        init_local_shell(newState, {:shell, :start, []})
      %{initial_shell: initialShell} ->
        init_local_shell(newState, initialShell)
      _ ->
        init_local_shell(newState, {:shell, :start, [:init]})
    end
  end

  defp exit_on_remote_shell_error(remoteNode, _, {:error, :noconnection}) do
    :io.format(:standard_error, 'Could not connect to ~p\n', [remoteNode])
    :erlang.halt(1)
  end

  defp exit_on_remote_shell_error(remoteNode, {m, _, _}, {:error, reason}) do
    :io.format(:standard_error, 'Could not load ~p on ~p (~p)\n', [remoteNode, m, reason])
    :erlang.halt(1)
  end

  defp exit_on_remote_shell_error(_, _, result) do
    result
  end

  defp init_noshell(state) do
    init_shell(r_state(state, shell_started: false), '')
  end

  defp init_remote_shell(state, node, {m, f, a}) do
    case (:net_kernel.get_state()) do
      %{started: :no} ->
        {:ok, _} = :net_kernel.start([:undefined, :shortnames])
        :ok
      _ ->
        :ok
    end
    localNode = (case (:net_kernel.get_state()) do
                   %{name_type: :dynamic} ->
                     :net_kernel.nodename()
                   %{name_type: :static} ->
                     node()
                 end)
    remoteNode = (case (:string.find(node, '@')) do
                    :nomatch ->
                      :erlang.list_to_atom(node ++ :string.find(:erlang.atom_to_list(localNode),
                                                                  '@'))
                    _ ->
                      :erlang.list_to_atom(node)
                  end)
    case (:net_kernel.connect_node(remoteNode)) do
      true ->
        case (:erpc.call(remoteNode, :code, :ensure_loaded,
                           [m])) do
          {:error, reason} when reason !== :embedded ->
            {:error, reason}
          _ ->
            case (:erpc.call(remoteNode, :net_kernel,
                               :get_net_ticktime, [])) do
              {:ongoing_change_to, netTickTime} ->
                _ = :net_kernel.set_net_ticktime(netTickTime)
                :ok
              netTickTime ->
                _ = :net_kernel.set_net_ticktime(netTickTime)
                :ok
            end
            rShell = {remoteNode, m, f, a}
            slogan = (case (:erpc.call(remoteNode, :application,
                                         :get_env,
                                         [:stdlib, :shell_slogan,
                                                       :erpc.call(remoteNode,
                                                                    :erlang,
                                                                    :system_info,
                                                                    [:system_version])])) do
                        fun when is_function(fun, 0) ->
                          :erpc.call(remoteNode, fun)
                        sloganEnv ->
                          sloganEnv
                      end)
            group = :group.start(self(), rShell,
                                   [{:echo,
                                       (r_state(state, :shell_started) === :new)}] ++ group_opts(remoteNode))
            gr = gr_add_cur(r_state(state, :groups), group, rShell)
            init_shell(r_state(state, groups: gr), [slogan, ?\n])
        end
      false ->
        {:error, :noconnection}
    end
  end

  defp init_local_shell(state, initialShell) do
    slogan = (case (:application.get_env(:stdlib,
                                           :shell_slogan,
                                           fn () ->
                                                :erlang.system_info(:system_version)
                                           end)) do
                fun when is_function(fun, 0) ->
                  fun.()
                sloganEnv ->
                  sloganEnv
              end)
    gr = gr_add_cur(r_state(state, :groups),
                      :group.start(self(), initialShell,
                                     group_opts() ++ [{:echo,
                                                         (r_state(state, :shell_started) === :new)}]),
                      initialShell)
    init_shell(r_state(state, groups: gr), [slogan, ?\n])
  end

  defp init_shell(state, slogan) do
    init_standard_error(r_state(state, :tty),
                          r_state(state, :shell_started) === :new)
    curr = gr_cur_pid(r_state(state, :groups))
    :erlang.put(:current_group, curr)
    {:next_state, :server,
       r_state(state, current_group: gr_cur_pid(r_state(state, :groups))),
       {:next_event, :info,
          {gr_cur_pid(r_state(state, :groups)),
             {:put_chars, :unicode,
                :unicode.characters_to_binary(:io_lib.format('~ts',
                                                               [slogan]))}}}}
  end

  defp start_user() do
    case (:erlang.whereis(:user)) do
      :undefined ->
        user = :group.start(self(), {}, [{:echo, false}])
        :erlang.register(:user, user)
        user
      user ->
        user
    end
  end

  def server({:call, from}, {:start_shell, args},
           state = r_state(tty: tTY, shell_started: false)) do
    isTTY = :prim_tty.isatty(:stdin) === true and :prim_tty.isatty(:stdout) === true
    startShell = :maps.get(:initial_shell, args,
                             :undefined) !== :noshell
    oldShell = :maps.get(:initial_shell, args,
                           :undefined) === :oldshell
    newState = (try do
                  cond do
                    not isTTY and startShell or oldShell ->
                      :erlang.error(:enotsup)
                    (isTTY and startShell) ->
                      newTTY = :prim_tty.reinit(tTY, %{})
                      r_state(state, tty: newTTY,  shell_started: :new)
                    true ->
                      newTTY = :prim_tty.reinit(tTY, %{tty: false})
                      r_state(state, tty: newTTY,  shell_started: false)
                  end
                catch
                  :error, :enotsup ->
                    newTTYState = :prim_tty.reinit(tTY, %{tty: false})
                    r_state(state, tty: newTTYState,  shell_started: :old)
                end)
    %{read: readHandle,
        write:
        writeHandle} = :prim_tty.handles(r_state(newState, :tty))
    newHandleState = r_state(newState, read: readHandle, 
                                   write: writeHandle)
    {result, reply} = (case (:maps.get(:initial_shell, args,
                                         :undefined)) do
                         :noshell ->
                           {init_noshell(newHandleState), :ok}
                         {:remote, node} ->
                           case (init_remote_shell(newHandleState, node,
                                                     {:shell, :start, []})) do
                             {:error, _} = error ->
                               {init_noshell(newHandleState), error}
                             r ->
                               {r, :ok}
                           end
                         {:remote, node, initialShell} ->
                           case (init_remote_shell(newHandleState, node,
                                                     initialShell)) do
                             {:error, _} = error ->
                               {init_noshell(newHandleState), error}
                             r ->
                               {r, :ok}
                           end
                         :undefined ->
                           case (r_state(newHandleState, :shell_started)) do
                             :old ->
                               {init_local_shell(newHandleState,
                                                   {:shell, :start, []}),
                                  :ok}
                             :new ->
                               {init_local_shell(newHandleState,
                                                   {:shell, :start, [:init]}),
                                  :ok}
                             false ->
                               {:keep_state_and_data, :ok}
                           end
                         initialShell ->
                           {init_local_shell(newHandleState, initialShell), :ok}
                       end)
    :gen_statem.reply(from, reply)
    result
  end

  def server({:call, from}, {:start_shell, _Args}, _State) do
    :gen_statem.reply(from, {:error, :already_started})
    :keep_state_and_data
  end

  def server(:info, {readHandle, {:data, uTF8Binary}},
           state = r_state(read: readHandle))
      when r_state(state, :current_group) === r_state(state, :user) do
    send(r_state(state, :current_group), {self(),
                                      {:data, uTF8Binary}})
    :keep_state_and_data
  end

  def server(:info, {readHandle, {:data, uTF8Binary}},
           state = r_state(read: readHandle)) do
    case (contains_ctrl_g_or_ctrl_c(uTF8Binary)) do
      :ctrl_g ->
        {:next_state, :switch_loop, state,
           {:next_event, :internal, :init}}
      :ctrl_c ->
        case (gr_get_info(r_state(state, :groups),
                            r_state(state, :current_group))) do
          :undefined ->
            :ok
          _ ->
            :erlang.exit(r_state(state, :current_group), :interrupt)
        end
        :keep_state_and_data
      :none ->
        send(r_state(state, :current_group), {self(),
                                          {:data, uTF8Binary}})
        :keep_state_and_data
    end
  end

  def server(:info, {readHandle, :eof},
           state = r_state(read: readHandle)) do
    send(r_state(state, :current_group), {self(), :eof})
    :keep_state_and_data
  end

  def server(:info, {readHandle, {:signal, signal}},
           state = r_state(tty: tTYState, read: readHandle)) do
    {:keep_state,
       r_state(state, tty: :prim_tty.handle_signal(tTYState,
                                               signal))}
  end

  def server(:info, {requester, :tty_geometry},
           r_state(tty: tTYState)) do
    case (:prim_tty.window_size(tTYState)) do
      {:ok, geometry} ->
        send(requester, {self(), :tty_geometry, geometry})
        :ok
      error ->
        send(requester, {self(), :tty_geometry, error})
        :ok
    end
    :keep_state_and_data
  end

  def server(:info, {requester, :get_unicode_state},
           r_state(tty: tTYState)) do
    send(requester, {self(), :get_unicode_state,
                       :prim_tty.unicode(tTYState)})
    :keep_state_and_data
  end

  def server(:info, {requester, :set_unicode_state, bool},
           r_state(tty: tTYState) = state) do
    oldUnicode = :prim_tty.unicode(tTYState)
    newTTYState = :prim_tty.unicode(tTYState, bool)
    :ok = :io.setopts(:standard_error,
                        [{:encoding,
                            cond do
                              bool ->
                                :unicode
                              true ->
                                :latin1
                            end}])
    send(requester, {self(), :set_unicode_state,
                       oldUnicode})
    {:keep_state, r_state(state, tty: newTTYState)}
  end

  def server(:info, {requester, :get_terminal_state},
           _State) do
    send(requester, {self(), :get_terminal_state,
                       :prim_tty.isatty(:stdout)})
    :keep_state_and_data
  end

  def server(:info, {requester, {:open_editor, buffer}},
           r_state(tty: tTYState) = state) do
    case (open_editor(tTYState, buffer)) do
      false ->
        send(requester, {self(), {:editor_data, buffer}})
        :keep_state_and_data
      {editorPort, tmpPath} ->
        {:keep_state,
           r_state(state, editor: r_editor(port: editorPort, file: tmpPath,
                                requester: requester))}
    end
  end

  def server(:info, req,
           state = r_state(user: user, current_group: curr,
                       editor: :undefined))
      when (:erlang.element(1,
                              req) === user or :erlang.element(1,
                                                                 req) === curr and
              tuple_size(req) === 2 or tuple_size(req) === 3) do
    {newTTYState, newQueue} = handle_req(req,
                                           r_state(state, :tty), r_state(state, :queue))
    {:keep_state,
       r_state(state, tty: newTTYState,  queue: newQueue)}
  end

  def server(:info, {writeRef, :ok},
           state = r_state(write: writeRef,
                       queue: {{origin, monitorRef, reply}, iOQ})) do
    send(origin, {:reply, reply, :ok})
    :erlang.demonitor(monitorRef, [:flush])
    {newTTYState, newQueue} = handle_req(:next,
                                           r_state(state, :tty), {false, iOQ})
    {:keep_state,
       r_state(state, tty: newTTYState,  queue: newQueue)}
  end

  def server(:info, {:DOWN, monitorRef, _, _, reason},
           r_state(queue: {{origin, monitorRef, reply}, _IOQ})) do
    send(origin, {:reply, reply, {:error, reason}})
    case (:logger.allow(:info, :user_drv)) do
      true ->
        :erlang.apply(:logger, :macro_log,
                        [%{mfa: {:user_drv, :server, 3}, line: 500, file: 'otp/lib/kernel/src/user_drv.erl'},
                             :info, 'Failed to write to standard out (~p)', [reason]])
      false ->
        :ok
    end
    :stop
  end

  def server(:info,
           {requester, {:put_chars_sync, _, _, reply}}, _State) do
    send(requester, {:reply, reply, :ok})
    :keep_state_and_data
  end

  def server(:info, {:EXIT, user, :shutdown},
           r_state(user: user)) do
    :keep_state_and_data
  end

  def server(:info, {:EXIT, user, _Reason},
           state = r_state(user: user)) do
    newUser = start_user()
    {:keep_state,
       r_state(state, user: newUser, 
                  groups: gr_set_num(r_state(state, :groups), 1, newUser, {}))}
  end

  def server(:info, {:EXIT, editorPort, _R},
           state = r_state(tty: tTYState,
                       editor: r_editor(requester: requester, port: editorPort,
                                   file: pathTmp))) do
    {:ok, content} = :file.read_file(pathTmp)
    _ = :file.del_dir_r(pathTmp)
    unicode = (case (:unicode.characters_to_list(content,
                                                   :unicode)) do
                 {:error, _, _} ->
                   :unicode.characters_to_list(:unicode.characters_to_list(content,
                                                                             :latin1),
                                                 :unicode)
                 u ->
                   u
               end)
    send(requester, {self(),
                       {:editor_data, :string.chomp(unicode)}})
    :ok = :prim_tty.enable_reader(tTYState)
    {:keep_state, r_state(state, editor: :undefined)}
  end

  def server(:info, {:EXIT, group, reason}, state) do
    case (gr_cur_pid(r_state(state, :groups))) do
      ^group when (reason !== :die and reason !== :terminated)
                  ->
        reqs = [cond do
                  reason !== :normal ->
                    {:put_chars, :unicode, "*** ERROR: "}
                  true ->
                    {:put_chars, :unicode, "*** "}
                end,
                    {:put_chars, :unicode, "Shell process terminated! "}]
        gr1 = gr_del_pid(r_state(state, :groups), group)
        case (gr_get_info(r_state(state, :groups), group)) do
          {ix, {:shell, :start, params}} ->
            newTTyState = io_requests(reqs ++ [{:put_chars,
                                                  :unicode, "***\n"}],
                                        r_state(state, :tty))
            newGroup = :group.start(self(),
                                      {:shell, :start, params})
            {:ok, gr2} = gr_set_cur(gr_set_num(gr1, ix, newGroup,
                                                 {:shell, :start, params}),
                                      ix)
            {:keep_state,
               r_state(state, tty: newTTyState,  current_group: newGroup, 
                          groups: gr2)}
          _ ->
            newTTYState = io_requests(reqs ++ [{:put_chars,
                                                  :unicode, "(^G to start new job) ***\n"}],
                                        r_state(state, :tty))
            {:keep_state, r_state(state, tty: newTTYState,  groups: gr1)}
        end
      _ ->
        {:keep_state,
           r_state(state, groups: gr_del_pid(r_state(state, :groups), group))}
    end
  end

  def server(_, _, _) do
    :keep_state_and_data
  end

  defp contains_ctrl_g_or_ctrl_c(<<?\a, _ :: binary>>) do
    :ctrl_g
  end

  defp contains_ctrl_g_or_ctrl_c(<<3, _ :: binary>>) do
    :ctrl_c
  end

  defp contains_ctrl_g_or_ctrl_c(<<_ :: utf8, t :: binary>>) do
    contains_ctrl_g_or_ctrl_c(t)
  end

  defp contains_ctrl_g_or_ctrl_c(<<>>) do
    :none
  end

  def switch_loop(:internal, :init, state) do
    case (:application.get_env(:stdlib, :shell_esc,
                                 :jcl)) do
      :abort ->
        currGroup = gr_cur_pid(r_state(state, :groups))
        :erlang.exit(currGroup, :die)
        gr1 = (case (gr_get_info(r_state(state, :groups),
                                   currGroup)) do
                 {_Ix, {}} ->
                   r_state(state, :groups)
                 _ ->
                   receive do
                     {:EXIT, ^currGroup, _} ->
                       gr_del_pid(r_state(state, :groups), currGroup)
                   after 1000 ->
                     r_state(state, :groups)
                   end
               end)
        newGroup = :group.start(self(), {:shell, :start, []})
        newTTYState = io_requests([{:insert_chars, :unicode,
                                      "\n"}],
                                    r_state(state, :tty))
        {:next_state, :server,
           r_state(state, tty: newTTYState, 
                      groups: gr_add_cur(gr1, newGroup,
                                           {:shell, :start, []}))}
      :jcl ->
        newTTYState = io_requests([{:insert_chars, :unicode,
                                      "\nUser switch command (type h for help)\n"}],
                                    r_state(state, :tty))
        :edlin.init(gr_cur_pid(r_state(state, :groups)))
        {:keep_state, r_state(state, tty: newTTYState),
           {:next_event, :internal, :line}}
    end
  end

  def switch_loop(:internal, :line, state) do
    {:more_chars, cont, rs} = :edlin.start(' --> ')
    {:keep_state,
       {cont, r_state(state, tty: io_requests(rs, r_state(state, :tty)))}}
  end

  def switch_loop(:internal, {:line, line}, state) do
    case (:erl_scan.string(line)) do
      {:ok, tokens, _} ->
        case (switch_cmd(tokens, r_state(state, :groups))) do
          {:ok, groups} ->
            curr = gr_cur_pid(groups)
            :erlang.put(:current_group, curr)
            send(curr, {self(), :activate})
            {:next_state, :server,
               r_state(state, current_group: curr,  groups: groups, 
                          tty: io_requests([{:insert_chars, :unicode, "\n"},
                                                :new_prompt],
                                             r_state(state, :tty)))}
          {:retry, requests} ->
            {:keep_state,
               r_state(state, tty: io_requests([{:insert_chars, :unicode, "\n"},
                                              :new_prompt | requests],
                                           r_state(state, :tty))),
               {:next_event, :internal, :line}}
          {:retry, requests, groups} ->
            curr = gr_cur_pid(groups)
            :erlang.put(:current_group, curr)
            {:keep_state,
               r_state(state, tty: io_requests([{:insert_chars, :unicode, "\n"},
                                              :new_prompt | requests],
                                           r_state(state, :tty)), 
                          current_group: curr,  groups: groups),
               {:next_event, :internal, :line}}
        end
      {:error, _, _} ->
        newTTYState = io_requests([{:insert_chars, :unicode,
                                      "Illegal input\n"}],
                                    r_state(state, :tty))
        {:keep_state, r_state(state, tty: newTTYState),
           {:next_event, :internal, :line}}
    end
  end

  def switch_loop(:info, {readHandle, {:data, cs}},
           {cont, r_state(read: readHandle) = state}) do
    case (:edlin.edit_line(:unicode.characters_to_list(cs),
                             cont)) do
      {:done, {[line], _, _}, _Rest, rs} ->
        {:keep_state,
           r_state(state, tty: io_requests(rs, r_state(state, :tty))),
           {:next_event, :internal, {:line, line}}}
      {:more_chars, newCont, rs} ->
        {:keep_state,
           {newCont,
              r_state(state, tty: io_requests(rs, r_state(state, :tty)))}}
      {:blink, newCont, rs} ->
        {:keep_state,
           {newCont,
              r_state(state, tty: io_requests(rs, r_state(state, :tty)))},
           1000}
    end
  end

  def switch_loop(:timeout, _, {_Cont, state}) do
    {:keep_state_and_data,
       {:next_event, :info, {r_state(state, :read), {:data, []}}}}
  end

  def switch_loop(:info, _Unknown, _State) do
    {:keep_state_and_data, :postpone}
  end

  defp switch_cmd([{:atom, _, key}, {type, _, value}], gr)
      when type === :atom or type === :integer do
    switch_cmd({key, value}, gr)
  end

  defp switch_cmd([{:atom, _, key}, {:atom, _, v1}, {:atom, _,
                                               v2}],
            gr) do
    switch_cmd({key, v1, v2}, gr)
  end

  defp switch_cmd([{:atom, _, key}], gr) do
    switch_cmd(key, gr)
  end

  defp switch_cmd([{:"?", _}], gr) do
    switch_cmd(:h, gr)
  end

  defp switch_cmd(cmd, gr) when cmd === :c or cmd === :i or
                          cmd === :k do
    switch_cmd({cmd, gr_cur_index(gr)}, gr)
  end

  defp switch_cmd({:c, i}, gr0) do
    case (gr_set_cur(gr0, i)) do
      {:ok, gr} ->
        {:ok, gr}
      :undefined ->
        unknown_group()
    end
  end

  defp switch_cmd({:i, i}, gr) do
    case (gr_get_num(gr, i)) do
      {:pid, pid} ->
        :erlang.exit(pid, :interrupt)
        {:retry, []}
      :undefined ->
        unknown_group()
    end
  end

  defp switch_cmd({:k, i}, gr) do
    case (gr_get_num(gr, i)) do
      {:pid, pid} ->
        :erlang.exit(pid, :die)
        case (gr_get_info(gr, pid)) do
          {_Ix, {}} ->
            :retry
          _ ->
            receive do
              {:EXIT, ^pid, _} ->
                {:retry, [], gr_del_pid(gr, pid)}
            after 1000 ->
              {:retry, [], gr}
            end
        end
      :undefined ->
        unknown_group()
    end
  end

  defp switch_cmd(:j, gr) do
    {:retry, gr_list(gr)}
  end

  defp switch_cmd({:s, shell}, gr0) when is_atom(shell) do
    pid = :group.start(self(), {shell, :start, []})
    gr = gr_add_cur(gr0, pid, {shell, :start, []})
    {:retry, [], gr}
  end

  defp switch_cmd(:s, gr) do
    switch_cmd({:s, :shell}, gr)
  end

  defp switch_cmd(:r, gr0) do
    case (:erlang.is_alive()) do
      true ->
        node = :pool.get_node()
        pid = :group.start(self(), {node, :shell, :start, []},
                             group_opts(node))
        gr = gr_add_cur(gr0, pid, {node, :shell, :start, []})
        {:retry, [], gr}
      false ->
        {:retry, [{:put_chars, :unicode, "Node is not alive\n"}]}
    end
  end

  defp switch_cmd({:r, node}, gr) when is_atom(node) do
    switch_cmd({:r, node, :shell}, gr)
  end

  defp switch_cmd({:r, node, shell}, gr0) when (is_atom(node) and
                                          is_atom(shell)) do
    case (:erlang.is_alive()) do
      true ->
        pid = :group.start(self(), {node, shell, :start, []},
                             group_opts(node))
        gr = gr_add_cur(gr0, pid, {node, shell, :start, []})
        {:retry, [], gr}
      false ->
        {:retry, [{:put_chars, :unicode, 'Node is not alive\n'}]}
    end
  end

  defp switch_cmd(:q, _Gr) do
    case (:erlang.system_info(:break_ignored)) do
      true ->
        {:retry, [{:put_chars, :unicode, "Unknown command\n"}]}
      false ->
        :erlang.halt()
    end
  end

  defp switch_cmd(:h, _Gr) do
    {:retry, list_commands()}
  end

  defp switch_cmd([], _Gr) do
    {:retry, []}
  end

  defp switch_cmd(_Ts, _Gr) do
    {:retry, [{:put_chars, :unicode, "Unknown command\n"}]}
  end

  defp unknown_group() do
    {:retry, [{:put_chars, :unicode, "Unknown job\n"}]}
  end

  defp list_commands() do
    quitReq = (case (:erlang.system_info(:break_ignored)) do
                 true ->
                   []
                 false ->
                   [{:put_chars, :unicode, "  q                 - quit erlang\n"}]
               end)
    [{:put_chars, :unicode, "  c [nn]            - connect to job\n"}, {:put_chars, :unicode, "  i [nn]            - interrupt job\n"},
                                    {:put_chars, :unicode, "  k [nn]            - kill job\n"}, {:put_chars,
                                                                  :unicode, "  j                 - list all jobs\n"},
                                                                   {:put_chars,
                                                                      :unicode,
                                                                      "  s [shell]         - start local shell\n"},
                                                                       {:put_chars,
                                                                          :unicode,
                                                                          "  r [node [shell]]  - start remote shell\n"}] ++ quitReq ++ [{:put_chars,
                                                                                                :unicode,
                                                                                                "  ? | h             - this message\n"}]
  end

  defp group_opts(node) do
    versionString = :erpc.call(node, :erlang, :system_info,
                                 [:otp_release])
    version = :erlang.list_to_integer(versionString)
    expandFun = (case (version > 25) do
                   true ->
                     [{:expand_fun,
                         fn b, opts ->
                              :erpc.call(node, :edlin_expand, :expand,
                                           [b, opts])
                         end}]
                   false ->
                     [{:expand_fun,
                         fn b, _ ->
                              :erpc.call(node, :edlin_expand, :expand, [b])
                         end}]
                 end)
    group_opts() ++ expandFun
  end

  defp group_opts() do
    [{:expand_below,
        :application.get_env(:stdlib, :shell_expand_location,
                               :below) === :below}]
  end

  defp io_request({:requests, rs}, tTY) do
    {:noreply, io_requests(rs, tTY)}
  end

  defp io_request(:redraw_prompt, tTY) do
    write(:prim_tty.handle_request(tTY, :redraw_prompt))
  end

  defp io_request({:redraw_prompt, pbs, pbs2, lineState}, tTY) do
    write(:prim_tty.handle_request(tTY,
                                     {:redraw_prompt, pbs, pbs2, lineState}))
  end

  defp io_request(:new_prompt, tTY) do
    write(:prim_tty.handle_request(tTY, :new_prompt))
  end

  defp io_request(:delete_after_cursor, tTY) do
    write(:prim_tty.handle_request(tTY,
                                     :delete_after_cursor))
  end

  defp io_request(:delete_line, tTY) do
    write(:prim_tty.handle_request(tTY, :delete_line))
  end

  defp io_request({:put_chars, :unicode, chars}, tTY) do
    write(:prim_tty.handle_request(tTY,
                                     {:putc,
                                        :unicode.characters_to_binary(chars)}))
  end

  defp io_request({:put_chars_sync, :unicode, chars, reply},
            tTY) do
    {output, newTTY} = :prim_tty.handle_request(tTY,
                                                  {:putc,
                                                     :unicode.characters_to_binary(chars)})
    {:ok, monitorRef} = :prim_tty.write(newTTY, output,
                                          self())
    {reply, monitorRef, newTTY}
  end

  defp io_request({:put_expand, :unicode, chars}, tTY) do
    write(:prim_tty.handle_request(tTY,
                                     {:expand_with_trim,
                                        :unicode.characters_to_binary(chars)}))
  end

  defp io_request({:put_expand_no_trim, :unicode, chars}, tTY) do
    write(:prim_tty.handle_request(tTY,
                                     {:expand,
                                        :unicode.characters_to_binary(chars)}))
  end

  defp io_request({:move_rel, n}, tTY) do
    write(:prim_tty.handle_request(tTY, {:move, n}))
  end

  defp io_request({:move_line, r}, tTY) do
    write(:prim_tty.handle_request(tTY, {:move_line, r}))
  end

  defp io_request({:move_combo, v1, r, v2}, tTY) do
    write(:prim_tty.handle_request(tTY,
                                     {:move_combo, v1, r, v2}))
  end

  defp io_request({:insert_chars, :unicode, chars}, tTY) do
    write(:prim_tty.handle_request(tTY,
                                     {:insert,
                                        :unicode.characters_to_binary(chars)}))
  end

  defp io_request({:insert_chars_over, :unicode, chars}, tTY) do
    write(:prim_tty.handle_request(tTY,
                                     {:insert_over,
                                        :unicode.characters_to_binary(chars)}))
  end

  defp io_request({:delete_chars, n}, tTY) do
    write(:prim_tty.handle_request(tTY, {:delete, n}))
  end

  defp io_request(:clear, tTY) do
    write(:prim_tty.handle_request(tTY, :clear))
  end

  defp io_request(:beep, tTY) do
    write(:prim_tty.handle_request(tTY, :beep))
  end

  defp write({output, tTY}) do
    :ok = :prim_tty.write(tTY, output)
    {:noreply, tTY}
  end

  defp io_requests([{:insert_chars, :unicode, c1}, {:insert_chars,
                                             :unicode, c2} |
                                              rs],
            tTY) do
    io_requests([{:insert_chars, :unicode, [c1, c2]} | rs],
                  tTY)
  end

  defp io_requests([{:put_chars, :unicode, c1}, {:put_chars,
                                          :unicode, c2} |
                                           rs],
            tTY) do
    io_requests([{:put_chars, :unicode, [c1, c2]} | rs],
                  tTY)
  end

  defp io_requests([{:move_rel, n}, {:move_line, r}, {:move_rel,
                                               m} |
                                                rs],
            tTY) do
    io_requests([{:move_combo, n, r, m} | rs], tTY)
  end

  defp io_requests([{:move_rel, n}, {:move_line, r} | rs], tTY) do
    io_requests([{:move_combo, n, r, 0} | rs], tTY)
  end

  defp io_requests([{:move_line, r}, {:move_rel, m} | rs], tTY) do
    io_requests([{:move_combo, 0, r, m} | rs], tTY)
  end

  defp io_requests([r | rs], tTY) do
    {:noreply, newTTY} = io_request(r, tTY)
    io_requests(rs, newTTY)
  end

  defp io_requests([], tTY) do
    tTY
  end

  defp open_editor(tTY, buffer) do
    defaultEditor = (case (:os.type()) do
                       {:win32, _} ->
                         'notepad'
                       {:unix, _} ->
                         'nano'
                     end)
    editor = :os.getenv('VISUAL', :os.getenv('EDITOR', defaultEditor))
    tmpFile = :string.chomp(mktemp()) ++ '.erl'
    _ = :file.write_file(tmpFile,
                           :unicode.characters_to_binary(buffer, :unicode))
    case (:filelib.is_file(tmpFile)) do
      true ->
        :ok = :prim_tty.disable_reader(tTY)
        try do
          editorPort = (case (:os.type()) do
                          {:win32, _} ->
                            [cmd | args] = :string.split(editor, ' ', :all)
                            :erlang.open_port({:spawn_executable,
                                                 :os.find_executable(cmd)},
                                                [{:args, args ++ [tmpFile]},
                                                     :nouse_stdio])
                          {:unix, _} ->
                            :erlang.open_port({:spawn, editor ++ ' ' ++ tmpFile},
                                                [:nouse_stdio])
                        end)
          {editorPort, tmpFile}
        catch
          :error, :enoent ->
            :ok = :prim_tty.enable_reader(tTY)
            :io.format(:standard_error, 'Could not find EDITOR \'~ts\'.~n', [editor])
            false
        end
      false ->
        :io.format(:standard_error, 'Could not find create temp file \'~ts\'.~n', [tmpFile])
        false
    end
  end

  defp mktemp() do
    case (:os.type()) do
      {:win32, _} ->
        :os.cmd('powershell "write-host (& New-TemporaryFile | Select-Object -ExpandProperty FullName)"')
      {:unix, _} ->
        :os.cmd('mktemp')
    end
  end

  defp handle_req(:next, tTYState, {false, iOQ} = iOQueue) do
    case (:queue.out(iOQ)) do
      {:empty, _} ->
        {tTYState, iOQueue}
      {{:value, {origin, req}}, execQ} ->
        case (io_request(req, tTYState)) do
          {:noreply, newTTYState} ->
            handle_req(:next, newTTYState, {false, execQ})
          {reply, monitorRef, newTTYState} ->
            {newTTYState, {{origin, monitorRef, reply}, execQ}}
        end
    end
  end

  defp handle_req(msg, tTYState, {false, iOQ} = iOQueue) do
    :empty = :queue.peek(iOQ)
    {origin, req} = msg
    case (io_request(req, tTYState)) do
      {:noreply, newTTYState} ->
        {newTTYState, iOQueue}
      {reply, monitorRef, newTTYState} ->
        {newTTYState, {{origin, monitorRef, reply}, iOQ}}
    end
  end

  defp handle_req(msg, tTYState, {resp, iOQ}) do
    {tTYState, {resp, :queue.in(msg, iOQ)}}
  end

  Record.defrecord(:r_group, :group, index: :undefined,
                                 pid: :undefined, shell: :undefined)
  Record.defrecord(:r_gr, :gr, next: 0, current: 0,
                              pid: :none, groups: [])
  defp gr_new() do
    r_gr()
  end

  defp gr_new_group(i, p, s) do
    r_group(index: i, pid: p, shell: s)
  end

  defp gr_get_num(r_gr(groups: gs), i) do
    case (:lists.keyfind(i, r_group(:index), gs)) do
      false ->
        :undefined
      r_group(shell: {}) ->
        :undefined
      r_group(pid: pid) ->
        {:pid, pid}
    end
  end

  defp gr_get_info(r_gr(groups: gs), pid) do
    case (:lists.keyfind(pid, r_group(:pid), gs)) do
      false ->
        :undefined
      r_group(index: i, shell: s) ->
        {i, s}
    end
  end

  defp gr_add_cur(r_gr(next: next, groups: gs), pid, shell) do
    :erlang.put(:current_group, pid)
    r_gr(next: next + 1, current: next, pid: pid,
        groups: gs ++ [gr_new_group(next, pid, shell)])
  end

  defp gr_set_cur(gr, i) do
    case (gr_get_num(gr, i)) do
      {:pid, pid} ->
        :erlang.put(:current_group, pid)
        {:ok, r_gr(gr, current: i,  pid: pid)}
      :undefined ->
        :undefined
    end
  end

  defp gr_set_num(gr = r_gr(groups: groups), i, pid, shell) do
    newGroups = :lists.keystore(i, r_group(:index), groups,
                                  gr_new_group(i, pid, shell))
    r_gr(gr, groups: newGroups)
  end

  defp gr_del_pid(gr = r_gr(groups: groups), pid) do
    r_gr(gr, groups: :lists.keydelete(pid, r_group(:pid), groups))
  end

  defp gr_cur_pid(r_gr(pid: pid)) do
    pid
  end

  defp gr_cur_index(r_gr(current: index)) do
    index
  end

  defp gr_list(r_gr(current: current, groups: groups)) do
    :lists.flatmap(fn r_group(shell: {}) ->
                        []
                      r_group(index: i, shell: s) ->
                        marker = (for _ <- [:EFE_DUMMY_GEN], current === i do
                                    '*'
                                  end)
                        [{:put_chars, :unicode,
                            :unicode.characters_to_binary(:io_lib.format('~4w~.1ts ~w\n',
                                                                           [i,
                                                                                marker,
                                                                                    s]))}]
                   end,
                     groups)
  end

end