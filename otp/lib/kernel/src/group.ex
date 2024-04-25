defmodule :m_group do
  use Bitwise

  def start(drv, shell) do
    start(drv, shell, [])
  end

  def start(drv, shell, options) do
    ancestors = [
      self()
      | case :erlang.get(:"$ancestors") do
          :undefined ->
            []

          anc ->
            anc
        end
    ]

    spawn_link(:group, :server, [ancestors, drv, shell, options])
  end

  def server(ancestors, drv, shell, options) do
    :erlang.process_flag(:trap_exit, true)

    _ =
      for _ <- [:EFE_DUMMY_GEN], shell !== {} do
        :erlang.put(:"$ancestors", ancestors)
      end

    :edlin.init()

    :erlang.put(
      :line_buffer,
      :proplists.get_value(:line_buffer, options, :group_history.load())
    )

    :erlang.put(:read_mode, :list)
    :erlang.put(:user_drv, drv)

    expandFun =
      normalize_expand_fun(
        options,
        &:edlin_expand.expand/2
      )

    :erlang.put(:expand_fun, expandFun)
    echo = :proplists.get_value(:echo, options, true)
    :erlang.put(:echo, echo)
    dumb = :proplists.get_value(:dumb, options, false)
    :erlang.put(:dumb, dumb)

    :erlang.put(
      :expand_below,
      :proplists.get_value(:expand_below, options, true)
    )

    server_loop(drv, start_shell(shell), [])
  end

  def whereis_shell() do
    case node(:erlang.group_leader()) do
      node when node === node() ->
        case :user_drv.whereis_group() do
          :undefined ->
            :undefined

          groupPid ->
            {:dictionary, dict} =
              :erlang.process_info(
                groupPid,
                :dictionary
              )

            :proplists.get_value(:shell, dict)
        end

      otherNode ->
        :erpc.call(otherNode, :group, :whereis_shell, [])
    end
  end

  defp start_shell({mod, func, args}) do
    start_shell1(mod, func, args)
  end

  defp start_shell({node, mod, func, args}) do
    start_shell1(:rpc, :call, [node, mod, func, args])
  end

  defp start_shell(shell) when is_atom(shell) do
    start_shell1(shell, :start, [])
  end

  defp start_shell(shell) when is_function(shell) do
    start_shell1(shell)
  end

  defp start_shell(shell) when is_pid(shell) do
    :erlang.group_leader(self(), shell)
    :erlang.link(shell)
    :erlang.put(:shell, shell)
    shell
  end

  defp start_shell(_Shell) do
    :ok
  end

  defp start_shell1(m, f, args) do
    g = :erlang.group_leader()
    :erlang.group_leader(self(), self())

    case (try do
            apply(m, f, args)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      shell when is_pid(shell) ->
        :erlang.group_leader(g, self())
        :erlang.link(shell)
        :erlang.put(:shell, shell)
        shell

      error ->
        exit(error)
    end
  end

  defp start_shell1(fun) do
    g = :erlang.group_leader()
    :erlang.group_leader(self(), self())

    case (try do
            fun.()
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      shell when is_pid(shell) ->
        :erlang.group_leader(g, self())
        :erlang.link(shell)
        :erlang.put(:shell, shell)
        shell

      error ->
        exit(error)
    end
  end

  def server_loop(drv, shell, buf0) do
    receive do
      {:io_request, from, replyAs, req} when is_pid(from) ->
        buf = io_request(req, from, replyAs, drv, shell, buf0)
        :group.server_loop(drv, shell, buf)

      {:reply, {from, replyAs}, reply} ->
        io_reply(from, replyAs, reply)
        :group.server_loop(drv, shell, buf0)

      {:driver_id, replyTo} ->
        send(replyTo, {self(), :driver_id, drv})
        :group.server_loop(drv, shell, buf0)

      {^drv, :echo, bool} ->
        :erlang.put(:echo, bool)
        :group.server_loop(drv, shell, buf0)

      {:EXIT, ^drv, :interrupt} ->
        exit_shell(:interrupt)
        :group.server_loop(drv, shell, buf0)

      {:EXIT, ^drv, r} ->
        exit(r)

      {:EXIT, ^shell, r} ->
        exit(r)

      notDrvTuple
      when not is_tuple(notDrvTuple) or tuple_size(notDrvTuple) !== 2 or
             :erlang.element(
               1,
               notDrvTuple
             ) !== drv ->
        :group.server_loop(drv, shell, buf0)
    end
  end

  defp exit_shell(reason) do
    case :erlang.get(:shell) do
      :undefined ->
        true

      pid ->
        :erlang.exit(pid, reason)
    end
  end

  defp get_tty_geometry(drv) do
    send(drv, {self(), :tty_geometry})

    receive do
      {^drv, :tty_geometry, geometry} ->
        geometry
    after
      2000 ->
        :timeout
    end
  end

  defp get_unicode_state(drv) do
    send(drv, {self(), :get_unicode_state})

    receive do
      {^drv, :get_unicode_state, uniState} ->
        uniState

      {^drv, :get_unicode_state, :error} ->
        {:error, :internal}
    after
      2000 ->
        {:error, :timeout}
    end
  end

  defp set_unicode_state(drv, bool) do
    send(drv, {self(), :set_unicode_state, bool})

    receive do
      {^drv, :set_unicode_state, _OldUniState} ->
        :ok
    after
      2000 ->
        :timeout
    end
  end

  defp get_terminal_state(drv) do
    send(drv, {self(), :get_terminal_state})

    receive do
      {^drv, :get_terminal_state, uniState} ->
        uniState

      {^drv, :get_terminal_state, :error} ->
        {:error, :internal}
    after
      2000 ->
        {:error, :timeout}
    end
  end

  defp io_request(req, from, replyAs, drv, shell, buf0) do
    case io_request(req, drv, shell, {from, replyAs}, buf0) do
      {:ok, reply, buf} ->
        io_reply(from, replyAs, reply)
        buf

      {:noreply, buf} ->
        buf

      {:error, reply, buf} ->
        io_reply(from, replyAs, reply)
        buf

      {:exit, r} ->
        exit_shell(:kill)
        exit(r)
    end
  end

  defp io_request({:put_chars, :unicode, chars}, drv, _Shell, from, buf) do
    case (try do
            :unicode.characters_to_binary(chars, :utf8)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      binary when is_binary(binary) ->
        send_drv(drv, {:put_chars_sync, :unicode, binary, from})
        {:noreply, buf}

      _ ->
        {:error, {:error, {:put_chars, :unicode, chars}}, buf}
    end
  end

  defp io_request({:put_chars, :unicode, m, f, as}, drv, _Shell, from, buf) do
    case (try do
            apply(m, f, as)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      binary when is_binary(binary) ->
        send_drv(drv, {:put_chars_sync, :unicode, binary, from})
        {:noreply, buf}

      chars ->
        case (try do
                :unicode.characters_to_binary(chars, :utf8)
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end) do
          b when is_binary(b) ->
            send_drv(drv, {:put_chars_sync, :unicode, b, from})
            {:noreply, buf}

          _ ->
            {:error, {:error, f}, buf}
        end
    end
  end

  defp io_request({:put_chars, :latin1, binary}, drv, _Shell, from, buf)
       when is_binary(binary) do
    send_drv(
      drv,
      {:put_chars_sync, :unicode, :unicode.characters_to_binary(binary, :latin1), from}
    )

    {:noreply, buf}
  end

  defp io_request({:put_chars, :latin1, chars}, drv, _Shell, from, buf) do
    case (try do
            :unicode.characters_to_binary(chars, :latin1)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      binary when is_binary(binary) ->
        send_drv(drv, {:put_chars_sync, :unicode, binary, from})
        {:noreply, buf}

      _ ->
        {:error, {:error, {:put_chars, :latin1, chars}}, buf}
    end
  end

  defp io_request({:put_chars, :latin1, m, f, as}, drv, _Shell, from, buf) do
    case (try do
            apply(m, f, as)
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      binary when is_binary(binary) ->
        send_drv(
          drv,
          {:put_chars_sync, :unicode, :unicode.characters_to_binary(binary, :latin1), from}
        )

        {:noreply, buf}

      chars ->
        case (try do
                :unicode.characters_to_binary(chars, :latin1)
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end) do
          b when is_binary(b) ->
            send_drv(drv, {:put_chars_sync, :unicode, b, from})
            {:noreply, buf}

          _ ->
            {:error, {:error, f}, buf}
        end
    end
  end

  defp io_request({:get_chars, encoding, prompt, n}, drv, shell, _From, buf) do
    get_chars_n(prompt, :io_lib, :collect_chars, n, drv, shell, buf, encoding)
  end

  defp io_request({:get_line, encoding, prompt}, drv, shell, _From, buf) do
    get_chars_line(prompt, :io_lib, :collect_line, [], drv, shell, buf, encoding)
  end

  defp io_request({:get_until, encoding, prompt, m, f, as}, drv, shell, _From, buf) do
    get_chars_line(prompt, :io_lib, :get_until, {m, f, as}, drv, shell, buf, encoding)
  end

  defp io_request({:get_password, _Encoding}, drv, shell, _From, buf) do
    get_password_chars(drv, shell, buf)
  end

  defp io_request({:setopts, opts}, drv, _Shell, _From, buf)
       when is_list(opts) do
    setopts(opts, drv, buf)
  end

  defp io_request(:getopts, drv, _Shell, _From, buf) do
    getopts(drv, buf)
  end

  defp io_request({:requests, reqs}, drv, shell, from, buf) do
    io_requests(reqs, {:ok, :ok, buf}, from, drv, shell)
  end

  defp io_request({:get_geometry, :columns}, drv, _Shell, _From, buf) do
    case get_tty_geometry(drv) do
      {w, _H} ->
        {:ok, w, buf}

      _ ->
        {:error, {:error, :enotsup}, buf}
    end
  end

  defp io_request({:get_geometry, :rows}, drv, _Shell, _From, buf) do
    case get_tty_geometry(drv) do
      {_W, h} ->
        {:ok, h, buf}

      _ ->
        {:error, {:error, :enotsup}, buf}
    end
  end

  defp io_request({:put_chars, chars}, drv, shell, from, buf) do
    io_request({:put_chars, :latin1, chars}, drv, shell, from, buf)
  end

  defp io_request({:put_chars, m, f, as}, drv, shell, from, buf) do
    io_request({:put_chars, :latin1, m, f, as}, drv, shell, from, buf)
  end

  defp io_request({:get_chars, prompt, n}, drv, shell, from, buf) do
    io_request({:get_chars, :latin1, prompt, n}, drv, shell, from, buf)
  end

  defp io_request({:get_line, prompt}, drv, shell, from, buf) do
    io_request({:get_line, :latin1, prompt}, drv, shell, from, buf)
  end

  defp io_request({:get_until, prompt, m, f, as}, drv, shell, from, buf) do
    io_request({:get_until, :latin1, prompt, m, f, as}, drv, shell, from, buf)
  end

  defp io_request(:get_password, drv, shell, from, buf) do
    io_request({:get_password, :latin1}, drv, shell, from, buf)
  end

  defp io_request(_, _Drv, _Shell, _From, buf) do
    {:error, {:error, :request}, buf}
  end

  defp io_requests([r | rs], {:noreply, buf}, from, drv, shell) do
    reqFrom =
      cond do
        rs === [] ->
          from

        true ->
          :undefined
      end

    io_requests(rs, io_request(r, drv, shell, reqFrom, buf), from, drv, shell)
  end

  defp io_requests([r | rs], {:ok, :ok, buf}, from, drv, shell) do
    reqFrom =
      cond do
        rs === [] ->
          from

        true ->
          :undefined
      end

    io_requests(rs, io_request(r, drv, shell, reqFrom, buf), from, drv, shell)
  end

  defp io_requests([_ | _], error, _From, _Drv, _Shell) do
    error
  end

  defp io_requests([], stat, _From, _, _Shell) do
    stat
  end

  defp io_reply(:undefined, _ReplyAs, _Reply) do
    :ok
  end

  defp io_reply(from, replyAs, reply) do
    send(from, {:io_reply, replyAs, reply})
    :ok
  end

  defp send_drv(drv, msg) do
    send(drv, {self(), msg})
    :ok
  end

  defp send_drv_reqs(_Drv, []) do
    :ok
  end

  defp send_drv_reqs(drv, rs) do
    send_drv(drv, {:requests, rs})
  end

  defp expand_encoding([]) do
    []
  end

  defp expand_encoding([:latin1 | t]) do
    [{:encoding, :latin1} | expand_encoding(t)]
  end

  defp expand_encoding([:unicode | t]) do
    [{:encoding, :unicode} | expand_encoding(t)]
  end

  defp expand_encoding([h | t]) do
    [h | expand_encoding(t)]
  end

  defp setopts(opts0, drv, buf) do
    opts =
      :proplists.unfold(
        :proplists.substitute_negations(
          [{:list, :binary}],
          expand_encoding(opts0)
        )
      )

    case check_valid_opts(opts) do
      true ->
        do_setopts(opts, drv, buf)

      false ->
        {:error, {:error, :enotsup}, buf}
    end
  end

  defp check_valid_opts([]) do
    true
  end

  defp check_valid_opts([{:binary, flag} | t]) when is_boolean(flag) do
    check_valid_opts(t)
  end

  defp check_valid_opts([{:encoding, valid} | t])
       when valid === :unicode or valid === :utf8 or
              valid === :latin1 do
    check_valid_opts(t)
  end

  defp check_valid_opts([{:echo, flag} | t]) when is_boolean(flag) do
    check_valid_opts(t)
  end

  defp check_valid_opts([{:expand_fun, fun} | t])
       when is_function(
              fun,
              1
            ) or
              is_function(fun, 2) do
    check_valid_opts(t)
  end

  defp check_valid_opts(_) do
    false
  end

  defp do_setopts(opts, drv, buf) do
    :erlang.put(
      :expand_fun,
      normalize_expand_fun(opts, :erlang.get(:expand_fun))
    )

    :erlang.put(
      :echo,
      :proplists.get_value(:echo, opts, :erlang.get(:echo))
    )

    case :proplists.get_value(:encoding, opts) do
      valid when valid === :unicode or valid === :utf8 ->
        set_unicode_state(drv, true)

      :latin1 ->
        set_unicode_state(drv, false)

      :undefined ->
        :ok
    end

    case :proplists.get_value(
           :binary,
           opts,
           case :erlang.get(:read_mode) do
             :binary ->
               true

             _ ->
               false
           end
         ) do
      true ->
        :erlang.put(:read_mode, :binary)
        {:ok, :ok, buf}

      false ->
        :erlang.put(:read_mode, :list)
        {:ok, :ok, buf}
    end
  end

  defp normalize_expand_fun(options, default) do
    case :proplists.get_value(:expand_fun, options, default) do
      fun when is_function(fun, 1) ->
        fn x, _ ->
          fun.(x)
        end

      fun ->
        fun
    end
  end

  defp getopts(drv, buf) do
    exp =
      {:expand_fun,
       case :erlang.get(:expand_fun) do
         func when is_function(func) ->
           func

         _ ->
           false
       end}

    echo =
      {:echo,
       case :erlang.get(:echo) do
         bool when bool === true or bool === false ->
           bool

         _ ->
           false
       end}

    bin =
      {:binary,
       case :erlang.get(:read_mode) do
         :binary ->
           true

         _ ->
           false
       end}

    uni =
      {:encoding,
       case get_unicode_state(drv) do
         true ->
           :unicode

         _ ->
           :latin1
       end}

    tty = {:terminal, get_terminal_state(drv)}
    {:ok, [exp, echo, bin, uni, tty], buf}
  end

  defp get_password_chars(drv, shell, buf) do
    case :erlang.get(:echo) do
      true ->
        case get_password_line(buf, drv, shell) do
          {:done, line, buf1} ->
            {:ok, line, buf1}

          :interrupted ->
            {:error, {:error, :interrupted}, []}

          :terminated ->
            {:exit, :terminated}
        end

      false ->
        {:error, {:error, :enotsup}, []}
    end
  end

  defp get_chars_n(prompt, m, f, xa, drv, shell, buf, encoding) do
    pbs = prompt_bytes(prompt, encoding)

    case :erlang.get(:echo) do
      true ->
        get_chars_loop(pbs, m, f, xa, drv, shell, buf, :start, [], encoding)

      false ->
        get_chars_n_loop(pbs, m, f, xa, drv, shell, buf, :start, encoding)
    end
  end

  defp get_chars_line(prompt, m, f, xa, drv, shell, buf, encoding) do
    pbs = prompt_bytes(prompt, encoding)
    get_chars_loop(pbs, m, f, xa, drv, shell, buf, :start, [], encoding)
  end

  defp get_chars_loop(pbs, m, f, xa, drv, shell, buf0, state, lineCont0, encoding) do
    result =
      case not :erlang.get(:dumb) and :erlang.get(:echo) do
        true ->
          get_line(buf0, pbs, lineCont0, drv, shell, encoding)

        false ->
          get_line_echo_off(buf0, encoding, pbs, drv, shell)
      end

    case result do
      {:done, lineCont1, buf} ->
        get_chars_apply(
          pbs,
          m,
          f,
          xa,
          drv,
          shell,
          append(buf, [], encoding),
          state,
          lineCont1,
          encoding
        )

      {:no_translation, :unicode, :latin1} ->
        {:error, {:error, {:no_translation, :unicode, :latin1}}, []}

      :interrupted ->
        {:error, {:error, :interrupted}, []}

      :terminated ->
        {:exit, :terminated}
    end
  end

  defp get_chars_apply(pbs, m, f, xa, drv, shell, buf, state0, lineCont, encoding) do
    {state, line} =
      case not :erlang.get(:dumb) and :erlang.get(:echo) do
        true ->
          {:start, :edlin.current_line(lineCont)}

        false ->
          {state0, lineCont}
      end

    case (try do
            apply(m, f, [state, cast(line, :erlang.get(:read_mode), encoding), encoding, xa])
          catch
            :error, e -> {:EXIT, {e, __STACKTRACE__}}
            :exit, e -> {:EXIT, e}
            e -> e
          end) do
      {:stop, :eof, _} ->
        {:ok, :eof, :eof}

      {:stop, result, :eof} ->
        {:ok, result, :eof}

      {:stop, result, rest} ->
        case lineCont do
          {[cL | lB], _, _} ->
            lineCont1 = {lB, {:lists.reverse(cL ++ ~c"\n"), []}, []}

            multiLinePrompt =
              :lists.duplicate(
                :prim_tty.npwcwidthstring(pbs),
                ?\s
              )

            send_drv_reqs(
              drv,
              [{:redraw_prompt, pbs, multiLinePrompt, lineCont1}, :new_prompt]
            )

          _ ->
            :skip
        end

        _ =
          case {m, f} do
            {:io_lib, :get_until} ->
              save_line_buffer(
                :string.trim(line, :both) ++ ~c"\n",
                get_lines(new_stack(:erlang.get(:line_buffer)))
              )

            _ ->
              :skip
          end

        {:ok, result, append(rest, buf, encoding)}

      {:EXIT, _} ->
        {:error, {:error, err_func(m, f, xa)}, []}

      state1 ->
        get_chars_loop(pbs, m, f, xa, drv, shell, buf, state1, lineCont, encoding)
    end
  end

  defp get_chars_n_loop(pbs, m, f, xa, drv, shell, buf0, state, encoding) do
    case check_encoding(buf0, encoding) do
      false ->
        {:error, {:error, {:no_translation, :unicode, encoding}}, []}

      true ->
        try do
          apply(m, f, [state, cast(buf0, :erlang.get(:read_mode), encoding), encoding, xa])
        catch
          _, _ ->
            {:error, {:error, err_func(m, f, xa)}, []}
        else
          {:stop, :eof, _} ->
            {:ok, :eof, :eof}

          {:stop, result, rest} ->
            {:ok, result, append(rest, [], encoding)}

          state1 ->
            case get_chars_echo_off(pbs, drv, shell) do
              :interrupted ->
                {:error, {:error, :interrupted}, []}

              :terminated ->
                {:exit, :terminated}

              buf ->
                get_chars_n_loop(pbs, m, f, xa, drv, shell, buf, state1, encoding)
            end
        end
    end
  end

  defp err_func(:io_lib, :get_until, {_, f, _}) do
    f
  end

  defp err_func(_, f, _) do
    f
  end

  defp get_line(chars, pbs, cont, drv, shell, encoding) do
    {:more_chars, cont1, rs} =
      case cont do
        [] ->
          :edlin.start(pbs)

        _ ->
          :edlin.start(pbs, cont)
      end

    send_drv_reqs(drv, rs)

    get_line1(
      :edlin.edit_line(chars, cont1),
      drv,
      shell,
      new_stack(:erlang.get(:line_buffer)),
      encoding
    )
  end

  defp get_line1({:done, cont, rest, rs}, drv, _Shell, _Ls, _Encoding) do
    send_drv_reqs(drv, rs)
    {:done, cont, rest}
  end

  defp get_line1({:open_editor, _Cs, cont, rs}, drv, shell, ls0, encoding) do
    send_drv_reqs(drv, rs)
    buffer = :edlin.current_line(cont)
    send_drv(drv, {:open_editor, buffer})

    receive do
      {^drv, {:editor_data, cs1}} ->
        send_drv_reqs(drv, :edlin.erase_line())
        {:more_chars, newCont, newRs} = :edlin.start(:edlin.prompt(cont))
        send_drv_reqs(drv, newRs)
        get_line1(:edlin.edit_line(cs1, newCont), drv, shell, ls0, encoding)
    end
  end

  defp get_line1({:history_up, cs, cont, rs}, drv, shell, ls0, encoding) do
    send_drv_reqs(drv, rs)

    case up_stack(
           save_line(
             ls0,
             :edlin.current_line(cont)
           )
         ) do
      {:none, _Ls} ->
        send_drv(drv, :beep)
        get_line1(:edlin.edit_line(cs, cont), drv, shell, ls0, encoding)

      {lcs, ls} ->
        send_drv_reqs(drv, :edlin.erase_line())
        {:more_chars, ncont, nrs} = :edlin.start(:edlin.prompt(cont))
        send_drv_reqs(drv, nrs)

        get_line1(
          :edlin.edit_line1(
            :string.to_graphemes(
              :lists.sublist(
                lcs,
                1,
                length(lcs) - 1
              )
            ),
            ncont
          ),
          drv,
          shell,
          ls,
          encoding
        )
    end
  end

  defp get_line1({:history_down, cs, cont, rs}, drv, shell, ls0, encoding) do
    send_drv_reqs(drv, rs)

    case down_stack(
           save_line(
             ls0,
             :edlin.current_line(cont)
           )
         ) do
      {:none, _Ls} ->
        send_drv(drv, :beep)
        get_line1(:edlin.edit_line(cs, cont), drv, shell, ls0, encoding)

      {lcs, ls} ->
        send_drv_reqs(drv, :edlin.erase_line())
        {:more_chars, ncont, nrs} = :edlin.start(:edlin.prompt(cont))
        send_drv_reqs(drv, nrs)

        get_line1(
          :edlin.edit_line1(
            :string.to_graphemes(
              :lists.sublist(
                lcs,
                1,
                length(lcs) - 1
              )
            ),
            ncont
          ),
          drv,
          shell,
          ls,
          encoding
        )
    end
  end

  defp get_line1({:search, cs, cont, rs}, drv, shell, ls, encoding) do
    send_drv_reqs(drv, rs)
    :erlang.put(:search_quit_prompt, cont)
    pbs = prompt_bytes(~c"\e[;1;4msearch:\e[0m ", encoding)

    {:more_chars, ncont, _Nrs} =
      :edlin.start(
        pbs,
        {:search, :none}
      )

    get_line1(:edlin.edit_line1(cs, ncont), drv, shell, ls, encoding)
  end

  defp get_line1({expand, before, cs0, cont, rs}, drv, shell, ls0, encoding)
       when expand === :expand or expand === :expand_full do
    send_drv_reqs(drv, rs)
    expandFun = :erlang.get(:expand_fun)
    {found, completeChars, matches} = expandFun.(before, [])

    case found do
      :no ->
        send_drv(drv, :beep)

      _ ->
        :ok
    end

    {width, _Height} = get_tty_geometry(drv)
    cs1 = append(completeChars, cs0, encoding)

    matchStr =
      case matches do
        [] ->
          []

        _ ->
          :edlin_expand.format_matches(matches, width)
      end

    cs =
      case {cs1, matchStr} do
        {_, []} ->
          cs1

        {^cs1, _} when cs1 !== [] ->
          cs1

        _ ->
          nlMatchStr = :unicode.characters_to_binary(~c"\n" ++ matchStr)

          case :erlang.get(:expand_below) do
            true ->
              lines = :string.split(:string.trim(matchStr), ~c"\n", :all)
              noLines = length(lines)

              cond do
                noLines > 5 and expand === :expand ->
                  [l1, l2, l3, l4, l5 | _] = lines

                  string =
                    :lists.join(
                      ?\n,
                      [
                        l1,
                        l2,
                        l3,
                        l4,
                        l5,
                        :io_lib.format(
                          ~c"Press tab to see all ~p expansions",
                          [:edlin_expand.number_matches(matches)]
                        )
                      ]
                    )

                  send_drv(
                    drv,
                    {:put_expand, :unicode, :unicode.characters_to_binary(string)}
                  )

                  cs1

                true ->
                  case get_tty_geometry(drv) do
                    {_, rows} when rows > noLines ->
                      send_drv(drv, {:put_expand, :unicode, nlMatchStr})
                      cs1

                    _ ->
                      send_drv_reqs(
                        drv,
                        [{:put_chars, :unicode, nlMatchStr}]
                      )

                      [?\e, ?l | cs1]
                  end
              end

            false ->
              send_drv(drv, {:put_chars, :unicode, nlMatchStr})
              [?\e, ?l | cs1]
          end
      end

    get_line1(:edlin.edit_line(cs, cont), drv, shell, ls0, encoding)
  end

  defp get_line1({:search_found, _Cs, _, rs}, drv, shell, ls0, encoding) do
    searchResult = :erlang.get(:search_result)

    lineCont =
      case searchResult do
        [] ->
          {[], {[], []}, []}

        _ ->
          [last | lB] = :lists.reverse(searchResult)
          {lB, {:lists.reverse(last), []}, []}
      end

    prompt = :edlin.prompt(:erlang.get(:search_quit_prompt))
    send_drv_reqs(drv, rs)
    send_drv_reqs(drv, :edlin.erase_line())

    send_drv_reqs(
      drv,
      :edlin.redraw_line({:line, prompt, lineCont, {:normal, :none}})
    )

    :erlang.put(:search_result, [])
    get_line1({:done, lineCont, ~c"\n", rs}, drv, shell, ls0, encoding)
  end

  defp get_line1({:search_quit, _Cs, _, rs}, drv, shell, ls, encoding) do
    case :edlin.prompt(:erlang.get(:search_quit_prompt)) do
      prompt ->
        searchResult = :erlang.get(:search_result)

        l =
          case searchResult do
            [] ->
              {[], {[], []}, []}

            _ ->
              [last | lB] = :lists.reverse(searchResult)
              {lB, {:lists.reverse(last), []}, []}
          end

        nCont = {:line, prompt, l, {:normal, :none}}
        :erlang.put(:search_result, [])
        send_drv_reqs(drv, [:delete_line | rs])
        send_drv_reqs(drv, :edlin.redraw_line(nCont))
        get_line1({:more_chars, nCont, []}, drv, shell, pad_stack(ls), encoding)
    end
  end

  defp get_line1({:search_cancel, _Cs, _, rs}, drv, shell, ls, encoding) do
    nCont = :erlang.get(:search_quit_prompt)
    :erlang.put(:search_result, [])
    send_drv_reqs(drv, [:delete_line | rs])
    send_drv_reqs(drv, :edlin.redraw_line(nCont))
    get_line1({:more_chars, nCont, []}, drv, shell, ls, encoding)
  end

  defp get_line1(
         {what, {:line, prompt, {_, {revCmd0, _}, _}, {:search, :none}}, _Rs},
         drv,
         shell,
         ls0,
         encoding
       ) do
    {search, ls1, revCmd} =
      case revCmd0 do
        [19 | revCmd1] ->
          {&search_down_stack/2, ls0, revCmd1}

        [18 | revCmd1] ->
          {&search_up_stack/2, ls0, revCmd1}

        _ ->
          {&search_up_stack/2, new_stack(get_lines(ls0)), revCmd0}
      end

    cmd = :lists.reverse(revCmd)

    {ls, newStack} =
      case search.(ls1, cmd) do
        {:none, ls2} ->
          send_drv(drv, :beep)
          :erlang.put(:search_result, [])
          send_drv(drv, :delete_line)

          send_drv(
            drv,
            {:insert_chars, :unicode, :unicode.characters_to_binary(prompt ++ cmd)}
          )

          {ls2, {[], {revCmd, []}, []}}

        {line, ls2} ->
          lines = :string.split(:string.to_graphemes(line), ~c"\n", :all)

          output =
            cond do
              length(lines) > 5 ->
                [a, b, c, d, e | _] = lines

                for line1 <- [a, b, c, d, e] do
                  ~c"\n  " ++ line1
                end ++
                  [
                    :io_lib.format(
                      ~c"~n  ... (~w lines omitted)",
                      [length(lines) - 5]
                    )
                  ]

              true ->
                for line1 <- lines do
                  ~c"\n  " ++ line1
                end
            end

          :erlang.put(:search_result, lines)
          send_drv(drv, :delete_line)

          send_drv(
            drv,
            {:insert_chars, :unicode, :unicode.characters_to_binary(prompt ++ cmd)}
          )

          send_drv(
            drv,
            {:put_expand_no_trim, :unicode, :unicode.characters_to_binary(output)}
          )

          {ls2, {[], {revCmd, []}, []}}
      end

    cont = {:line, prompt, newStack, {:search, :none}}
    more_data(what, cont, drv, shell, ls, encoding)
  end

  defp get_line1({what, cont0, rs}, drv, shell, ls, encoding) do
    send_drv_reqs(drv, rs)
    more_data(what, cont0, drv, shell, ls, encoding)
  end

  defp more_data(what, cont0, drv, shell, ls, encoding) do
    receive do
      {^drv, :activate} ->
        send_drv_reqs(drv, :edlin.redraw_line(cont0))
        more_data(what, cont0, drv, shell, ls, encoding)

      {^drv, {:data, cs}} ->
        res = :edlin.edit_line(cast(cs, :list), cont0)
        get_line1(res, drv, shell, ls, encoding)

      {^drv, :eof} ->
        get_line1(:edlin.edit_line(:eof, cont0), drv, shell, ls, encoding)

      {:io_request, from, replyAs, req} when is_pid(from) ->
        {:more_chars, cont, _More} = :edlin.edit_line([], cont0)
        send_drv_reqs(drv, :edlin.erase_line())
        io_request(req, from, replyAs, drv, shell, [])
        send_drv_reqs(drv, :edlin.redraw_line(cont))
        get_line1({:more_chars, cont, []}, drv, shell, ls, encoding)

      {:reply, {from, replyAs}, reply} ->
        io_reply(from, replyAs, reply)
        more_data(what, cont0, drv, shell, ls, encoding)

      {:EXIT, ^drv, :interrupt} ->
        :interrupted

      {:EXIT, ^drv, _} ->
        :terminated

      {:EXIT, ^shell, r} ->
        exit(r)
    after
      get_line_timeout(what) ->
        get_line1(:edlin.edit_line([], cont0), drv, shell, ls, encoding)
    end
  end

  defp get_line_echo_off(chars, toEnc, pbs, drv, shell) do
    send_drv_reqs(drv, [{:put_chars, :unicode, pbs}])

    case get_line_echo_off1(edit_line(chars, []), drv, shell) do
      {:done, line, _Rest} = res when toEnc === :latin1 ->
        case check_encoding(line, toEnc) do
          false ->
            {:no_translation, :unicode, toEnc}

          true ->
            res
        end

      res ->
        res
    end
  end

  defp get_line_echo_off1({chars, [], rs}, drv, shell) do
    case :erlang.get(:echo) do
      true ->
        send_drv_reqs(drv, rs)

      false ->
        :skip
    end

    receive do
      {^drv, {:data, cs}} ->
        get_line_echo_off1(edit_line(cast(cs, :list), chars), drv, shell)

      {^drv, :eof} ->
        get_line_echo_off1(edit_line(:eof, chars), drv, shell)

      {:io_request, from, replyAs, req} when is_pid(from) ->
        io_request(req, from, replyAs, drv, shell, [])
        get_line_echo_off1({chars, [], []}, drv, shell)

      {:reply, {from, replyAs}, reply}
      when from !== :undefined ->
        io_reply(from, replyAs, reply)
        get_line_echo_off1({chars, [], []}, drv, shell)

      {:EXIT, ^drv, :interrupt} ->
        :interrupted

      {:EXIT, ^drv, _} ->
        :terminated

      {:EXIT, ^shell, r} ->
        exit(r)
    end
  end

  defp get_line_echo_off1(:eof, _Drv, _Shell) do
    {:done, :eof, :eof}
  end

  defp get_line_echo_off1({chars, rest, rs}, drv, _Shell) do
    case :erlang.get(:echo) do
      true ->
        send_drv_reqs(drv, rs)

      false ->
        :skip
    end

    {:done, :lists.reverse(chars),
     case rest do
       :done ->
         []

       _ ->
         rest
     end}
  end

  defp get_chars_echo_off(pbs, drv, shell) do
    send_drv_reqs(drv, [{:insert_chars, :unicode, pbs}])
    get_chars_echo_off1(drv, shell)
  end

  defp get_chars_echo_off1(drv, shell) do
    receive do
      {^drv, {:data, cs}} ->
        cast(cs, :list)

      {^drv, :eof} ->
        :eof

      {:io_request, from, replyAs, req} when is_pid(from) ->
        io_request(req, from, replyAs, drv, shell, [])
        get_chars_echo_off1(drv, shell)

      {:reply, {from, replyAs}, reply}
      when from !== :undefined ->
        io_reply(from, replyAs, reply)
        get_chars_echo_off1(drv, shell)

      {:EXIT, ^drv, :interrupt} ->
        :interrupted

      {:EXIT, ^drv, _} ->
        :terminated

      {:EXIT, ^shell, r} ->
        exit(r)
    end
  end

  defp edit_line(input, state) do
    edit_line(input, state, [])
  end

  defp edit_line(:eof, [], _) do
    :eof
  end

  defp edit_line(:eof, chars, rs) do
    {chars, :eof, :lists.reverse(rs)}
  end

  defp edit_line([], chars, rs) do
    {chars, [], :lists.reverse(rs)}
  end

  defp edit_line([?\r, ?\n | cs], chars, rs) do
    {[?\n | chars], remainder_after_nl(cs), :lists.reverse([{:put_chars, :unicode, ~c"\n"} | rs])}
  end

  defp edit_line([nL | cs], chars, rs)
       when nL === ?\r or
              nL === ?\n do
    {[?\n | chars], remainder_after_nl(cs), :lists.reverse([{:put_chars, :unicode, ~c"\n"} | rs])}
  end

  defp edit_line([erase | cs], [], rs)
       when erase === ?\d or
              erase === ?\b do
    edit_line(cs, [], rs)
  end

  defp edit_line([erase | cs], [_ | chars], rs)
       when erase === ?\d or erase === ?\b do
    edit_line(cs, chars, [{:delete_chars, -1} | rs])
  end

  defp edit_line([ctrlChar | cs], chars, rs)
       when ctrlChar < 32 do
    edit_line(cs, chars, rs)
  end

  defp edit_line([char | cs], chars, rs) do
    edit_line(cs, [char | chars], [{:put_chars, :unicode, [char]} | rs])
  end

  defp remainder_after_nl(~c"") do
    :done
  end

  defp remainder_after_nl(cs) do
    cs
  end

  defp get_line_timeout(:blink) do
    1000
  end

  defp get_line_timeout(:more_chars) do
    :infinity
  end

  defp new_stack(ls) do
    {:stack, ls, {}, []}
  end

  defp up_stack({:stack, [l | u], {}, d}) do
    {l, {:stack, u, l, d}}
  end

  defp up_stack({:stack, [], {}, d}) do
    {:none, {:stack, [], {}, d}}
  end

  defp up_stack({:stack, u, c, d}) do
    up_stack({:stack, u, {}, [c | d]})
  end

  defp down_stack({:stack, u, {}, [l | d]}) do
    {l, {:stack, u, l, d}}
  end

  defp down_stack({:stack, u, {}, []}) do
    {:none, {:stack, u, {}, []}}
  end

  defp down_stack({:stack, u, c, d}) do
    down_stack({:stack, [c | u], {}, d})
  end

  defp save_line({:stack, u, {}, []}, line) do
    {:stack, u, {}, [line]}
  end

  defp save_line({:stack, u, _L, d}, line) do
    {:stack, u, line, d}
  end

  defp get_lines(ls) do
    get_all_lines(ls)
  end

  defp get_all_lines({:stack, u, {}, []}) do
    u
  end

  defp get_all_lines({:stack, u, {}, d}) do
    case :lists.reverse(d, u) do
      [~c"\n" | lines] ->
        lines

      lines ->
        lines
    end
  end

  defp get_all_lines({:stack, u, l, d}) do
    get_all_lines({:stack, u, {}, [l | d]})
  end

  defp pad_stack({:stack, u, l, d}) do
    {:stack, u, l, d ++ [~c"\n"]}
  end

  defp save_line_buffer(~c"\n", lines) do
    save_line_buffer(lines)
  end

  defp save_line_buffer(line, [line | _Lines] = lines) do
    save_line_buffer(lines)
  end

  defp save_line_buffer(line, lines) do
    :group_history.add(line)
    save_line_buffer([line | lines])
  end

  defp save_line_buffer(lines) do
    :erlang.put(:line_buffer, lines)
  end

  defp search_up_stack(stack, substr) do
    case up_stack(stack) do
      {:none, newStack} ->
        {:none, newStack}

      {l, newStack} ->
        case :string.find(l, substr) do
          :nomatch ->
            search_up_stack(newStack, substr)

          _ ->
            {:string.trim(l, :trailing, ~c"$\n"), newStack}
        end
    end
  end

  defp search_down_stack(stack, substr) do
    case down_stack(stack) do
      {:none, newStack} ->
        {:none, newStack}

      {l, newStack} ->
        case :string.find(l, substr) do
          :nomatch ->
            search_down_stack(newStack, substr)

          _ ->
            {:string.trim(l, :trailing, ~c"$\n"), newStack}
        end
    end
  end

  defp get_password_line(chars, drv, shell) do
    get_password1(edit_password(chars, []), drv, shell)
  end

  defp get_password1({chars, []}, drv, shell) do
    receive do
      {^drv, {:data, cs}} ->
        get_password1(edit_password(cast(cs, :list), chars), drv, shell)

      {:io_request, from, replyAs, req} when is_pid(from) ->
        io_request(req, from, replyAs, drv, shell, [])
        get_password1({chars, []}, drv, shell)

      {:reply, {from, replyAs}, reply} ->
        io_reply(from, replyAs, reply)
        get_password1({chars, []}, drv, shell)

      {:EXIT, ^drv, :interrupt} ->
        :interrupted

      {:EXIT, ^drv, _} ->
        :terminated

      {:EXIT, ^shell, r} ->
        exit(r)
    end
  end

  defp get_password1({chars, rest}, drv, _Shell) do
    send_drv_reqs(drv, [{:insert_chars, :unicode, ~c"\n"}])

    {:done, :lists.reverse(chars),
     case rest do
       :done ->
         []

       _ ->
         rest
     end}
  end

  defp edit_password([], chars) do
    {chars, []}
  end

  defp edit_password([?\r], chars) do
    {chars, :done}
  end

  defp edit_password([?\r | cs], chars) do
    {chars, cs}
  end

  defp edit_password([?\d | cs], []) do
    edit_password(cs, [])
  end

  defp edit_password([?\d | cs], [_ | chars]) do
    edit_password(cs, chars)
  end

  defp edit_password([char | cs], chars) do
    edit_password(cs, [char | chars])
  end

  defp prompt_bytes(prompt, encoding) do
    :lists.flatten(:io_lib.format_prompt(prompt, encoding))
  end

  defp cast(buf, type) do
    cast(buf, type, :utf8)
  end

  defp cast(:eof, _, _) do
    :eof
  end

  defp cast(l, :binary, toEnc) do
    :unicode.characters_to_binary(l, :utf8, toEnc)
  end

  defp cast(l, :list, _ToEnc) when is_list(l) do
    l
  end

  defp cast(l, :list, _ToEnc) do
    :unicode.characters_to_list(l, :utf8)
  end

  defp append(:eof, [], _) do
    :eof
  end

  defp append(:eof, l, _) do
    l
  end

  defp append(l, [], _) when is_list(l) do
    l
  end

  defp append(l, a, _) when is_list(l) do
    l ++ a
  end

  defp append(b, l, fromEnc) do
    append(:unicode.characters_to_list(b, fromEnc), l, fromEnc)
  end

  defp check_encoding(:eof, _) do
    true
  end

  defp check_encoding(listOrBinary, :unicode)
       when is_list(listOrBinary) or is_binary(listOrBinary) do
    true
  end

  defp check_encoding(list, :latin1) when is_list(list) do
    is_latin1(list)
  end

  defp is_latin1([h | t]) when 0 <= h and h <= 255 do
    is_latin1(t)
  end

  defp is_latin1([]) do
    true
  end

  defp is_latin1(_) do
    false
  end
end
