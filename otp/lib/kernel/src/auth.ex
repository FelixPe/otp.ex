defmodule :m_auth do
  use Bitwise
  @behaviour :gen_server
  require Record
  Record.defrecord(:r_state, :state, our_cookie: :undefined,
                                 other_cookies: :undefined)
  Record.defrecord(:r_file_info, :file_info, size: :undefined,
                                     type: :undefined, access: :undefined,
                                     atime: :undefined, mtime: :undefined,
                                     ctime: :undefined, mode: :undefined,
                                     links: :undefined,
                                     major_device: :undefined,
                                     minor_device: :undefined,
                                     inode: :undefined, uid: :undefined,
                                     gid: :undefined)
  Record.defrecord(:r_file_descriptor, :file_descriptor, module: :undefined,
                                           data: :undefined)
  def start_link() do
    :gen_server.start_link({:local, :auth}, :auth, [], [])
  end

  def is_auth(node) do
    case (:net_adm.ping(node)) do
      :pong ->
        :yes
      :pang ->
        :no
    end
  end

  def cookie() do
    get_cookie()
  end

  def cookie([cookie]) do
    set_cookie(cookie)
  end

  def cookie(cookie) do
    set_cookie(cookie)
  end

  def node_cookie([node, cookie]) do
    node_cookie(node, cookie)
  end

  def node_cookie(node, cookie) do
    set_cookie(node, cookie)
    is_auth(node)
  end

  def get_cookie() do
    case (:erlang.whereis(:auth)) do
      :undefined ->
        :nocookie
      authPid ->
        :gen_server.call(authPid, :get_our_cookie, :infinity)
    end
  end

  def get_cookie(node) when node === node() do
    get_cookie()
  end

  def get_cookie(node) do
    case (:erlang.whereis(:auth)) do
      :undefined ->
        :nocookie
      authPid ->
        :gen_server.call(authPid, {:get_cookie, node},
                           :infinity)
    end
  end

  def set_cookie(cookie) do
    case (:erlang.whereis(:auth)) do
      :undefined ->
        :erlang.error(:distribution_not_started)
      authPid ->
        :gen_server.call(authPid, {:set_our_cookie, cookie},
                           :infinity)
    end
  end

  def set_cookie(node, cookie) when node === node() do
    set_cookie(cookie)
  end

  def set_cookie(node, cookie) do
    case (:erlang.whereis(:auth)) do
      :undefined ->
        :erlang.error(:distribution_not_started)
      authPid ->
        :gen_server.call(authPid, {:set_cookie, node, cookie},
                           :infinity)
    end
  end

  def sync_cookie() do
    :gen_server.call(:auth, :sync_cookie, :infinity)
  end

  def print(node, format, args) do
    (try do
      :gen_server.cast({:auth, node}, {:print, format, args})
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end)
  end

  def init([]) do
    :erlang.process_flag(:trap_exit, true)
    {:ok, init_cookie()}
  end

  def handle_call(:get_our_cookie, {_From, _Tag}, state) do
    {:reply, r_state(state, :our_cookie), state}
  end

  def handle_call({:get_cookie, node}, {_From, _Tag}, state) do
    case (:ets.lookup(r_state(state, :other_cookies), node)) do
      [{^node, cookie}] ->
        {:reply, cookie, state}
      [] ->
        {:reply, r_state(state, :our_cookie), state}
    end
  end

  def handle_call({:set_our_cookie, cookie}, {_From, _Tag},
           state) do
    {:reply, true, r_state(state, our_cookie: cookie)}
  end

  def handle_call({:set_cookie, node, cookie}, {_From, _Tag},
           state) do
    :ets.insert(r_state(state, :other_cookies), {node, cookie})
    {:reply, true, state}
  end

  def handle_call(:sync_cookie, _From, state) do
    case (:ets.lookup(r_state(state, :other_cookies), node())) do
      [{_N, c}] ->
        :ets.delete(r_state(state, :other_cookies), node())
        {:reply, true, r_state(state, our_cookie: c)}
      [] ->
        {:reply, true, state}
    end
  end

  def handle_call(:echo, _From, o) do
    {:reply, :hello, o}
  end

  def handle_cast({:print, what, args}, o) do
    :error_logger.error_msg(what, args)
    {:noreply, o}
  end

  def handle_info({from, :badcookie, :net_kernel,
            {from, :spawn, _M, _F, _A, _Gleader}},
           o) do
    :auth.print(node(from), '~n** Unauthorized spawn attempt to ~w **~n', [node()])
    :erlang.disconnect_node(node(from))
    {:noreply, o}
  end

  def handle_info({from, :badcookie, :net_kernel,
            {from, :spawn_link, _M, _F, _A, _Gleader}},
           o) do
    :auth.print(node(from), '~n** Unauthorized spawn_link attempt to ~w **~n', [node()])
    :erlang.disconnect_node(node(from))
    {:noreply, o}
  end

  def handle_info({_From, :badcookie, :ddd_server, _Mess}, o) do
    {:noreply, o}
  end

  def handle_info({from, :badcookie, :rex, _Msg}, o) do
    :auth.print(getnode(from), '~n** Unauthorized rpc attempt to ~w **~n', [node()])
    :erlang.disconnect_node(node(from))
    {:noreply, o}
  end

  def handle_info({from, :badcookie, :net_kernel,
            {:"$gen_call", {from, tag}, {:is_auth, _Node}}},
           o) do
    send(from, {tag, :no})
    {:noreply, o}
  end

  def handle_info({_From, :badcookie, to, {{:auth_reply, n}, r}},
           o) do
    (try do
      send(to, {{:auth_reply, n}, r})
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end)
    {:noreply, o}
  end

  def handle_info({from, :badcookie, name, mess}, opened) do
    case (:lists.member(name, opened)) do
      true ->
        (try do
          send(name, mess)
        catch
          :error, e -> {:EXIT, {e, __STACKTRACE__}}
          :exit, e -> {:EXIT, e}
          e -> e
        end)
      false ->
        case ((try do
                :lists.member(:erlang.element(1, mess), opened)
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end)) do
          true ->
            (try do
              send(name, mess)
            catch
              :error, e -> {:EXIT, {e, __STACKTRACE__}}
              :exit, e -> {:EXIT, e}
              e -> e
            end)
          _ ->
            :auth.print(getnode(from), '~n** Unauthorized send attempt ~w to ~w **~n', [mess, node()])
            :erlang.disconnect_node(getnode(from))
        end
    end
    {:noreply, opened}
  end

  def handle_info(_, o) do
    {:noreply, o}
  end

  def code_change(_OldVsn, state, _Extra) do
    {:ok, state}
  end

  def terminate(_Reason, _State) do
    :ok
  end

  defp getnode(p) when is_pid(p) do
    node(p)
  end

  defp getnode(p) do
    p
  end

  defp init_cookie() do
    case (:init.get_argument(:setcookie)) do
      :error ->
        init_no_setcookie()
      {:ok, setcookie} ->
        init_setcookie(setcookie, [], %{})
    end
  end

  defp init_no_setcookie() do
    case (:init.get_argument(:nocookie)) do
      :error ->
        case (read_cookie()) do
          {:error, error} ->
            :error_logger.error_msg(error, [])
            :erlang.error(error)
          {:ok, co} ->
            r_state(our_cookie: :erlang.list_to_atom(co),
                other_cookies: ets_new_cookies())
        end
      {:ok, nocookie} when is_list(nocookie) ->
        r_state(our_cookie: :nocookie,
            other_cookies: ets_new_cookies())
    end
  end

  defp init_setcookie([setCo | setcookie], ourCookies,
            otherCookies) do
    case (setCo) do
      [] ->
        init_setcookie(setcookie, [setCo | ourCookies],
                         otherCookies)
      [_] ->
        init_setcookie(setcookie, [setCo | ourCookies],
                         otherCookies)
      [node, co] ->
        init_setcookie(setcookie, ourCookies,
                         case (otherCookies) do
                           %{^node => _} ->
                             %{otherCookies | node => :undefined}
                           %{} ->
                             Map.put(otherCookies, node, co)
                         end)
      _ when is_list(setCo) ->
        init_setcookie(setcookie, ourCookies, otherCookies)
    end
  end

  defp init_setcookie([], ourCookies, otherCookies) do
    state = (case (ourCookies) do
               [[co]] ->
                 r_state(our_cookie: :erlang.list_to_atom(co),
                     other_cookies: ets_new_cookies())
               _ when is_list(ourCookies) ->
                 init_no_setcookie()
             end)
    :ets.insert(r_state(state, :other_cookies),
                  for {node, co} <- :maps.to_list(otherCookies),
                        co !== :undefined do
                    {:erlang.list_to_atom(node), :erlang.list_to_atom(co)}
                  end)
    state
  end

  defp ets_new_cookies() do
    :ets.new(:cookies, [:protected])
  end

  defp read_cookie() do
    xDGPath = :filename.join(:filename.basedir(:user_config,
                                                 'erlang'),
                               '.erlang.cookie')
    case (:init.get_argument(:home)) do
      {:ok, [[home]]} ->
        homePath = :filename.join(home, '.erlang.cookie')
        case (read_cookie(homePath)) do
          {:error, :enoent} ->
            case (read_cookie(xDGPath)) do
              {:error, :enoent} ->
                case (create_cookie(homePath)) do
                  :ok ->
                    {:ok, cookie} = read_cookie(homePath)
                    cookie
                  error ->
                    error
                end
              {:ok, cookie} ->
                cookie
              error ->
                error
            end
          {:ok, cookie} ->
            cookie
          error ->
            error
        end
      _ ->
        case (read_cookie(xDGPath)) do
          {:error, :enoent} ->
            case (create_cookie(xDGPath)) do
              :ok ->
                {:ok, cookie} = read_cookie(xDGPath)
                cookie
              error ->
                error
            end
          {:ok, cookie} ->
            cookie
          _Error ->
            {:error, 'No home for cookie file'}
        end
    end
  end

  defp read_cookie(name) do
    case (:file.raw_read_file_info(name)) do
      {:ok, r_file_info(type: type, mode: mode, size: size)} ->
        case (check_attributes(name, type, mode, :os.type())) do
          :ok ->
            {:ok, read_cookie(name, size)}
          error ->
            error
        end
      {:error, :enoent} ->
        {:error, :enoent}
      {:error, reason} ->
        {:error, make_error(name, reason)}
    end
  end

  defp read_cookie(name, size) do
    case (:file.open(name, [:raw, :read])) do
      {:ok, file} ->
        case (:file.read(file, size)) do
          {:ok, list} ->
            :ok = :file.close(file)
            check_cookie(list, [])
          {:error, reason} ->
            make_error(name, reason)
        end
      {:error, reason} ->
        make_error(name, reason)
    end
  end

  defp make_error(name, reason) do
    {:error, 'Error when reading ' ++ name ++ ': ' ++ :erlang.atom_to_list(reason)}
  end

  defp check_attributes(name, type, _Mode, _Os)
      when type !== :regular do
    {:error, 'Cookie file ' ++ name ++ ' is of type ' ++ type}
  end

  defp check_attributes(name, _Type, mode, {:unix, _})
      when mode &&& 63 !== 0 do
    {:error, 'Cookie file ' ++ name ++ ' must be accessible by owner only'}
  end

  defp check_attributes(_Name, _Type, _Mode, _Os) do
    :ok
  end

  defp check_cookie([letter | rest], result) when (?\s <= letter and
                                           letter <= ?~) do
    check_cookie(rest, [letter | result])
  end

  defp check_cookie([x | rest], result) do
    check_cookie1([x | rest], result)
  end

  defp check_cookie([], result) do
    check_cookie1([], result)
  end

  defp check_cookie1([?\n | rest], result) do
    check_cookie1(rest, result)
  end

  defp check_cookie1([?\r | rest], result) do
    check_cookie1(rest, result)
  end

  defp check_cookie1([?\s | rest], result) do
    check_cookie1(rest, result)
  end

  defp check_cookie1([_ | _], _Result) do
    {:error, 'Bad characters in cookie'}
  end

  defp check_cookie1([], []) do
    {:error, 'Too short cookie string'}
  end

  defp check_cookie1([], result) do
    {:ok, :lists.reverse(result)}
  end

  defp create_cookie(name) do
    seed = abs(:erlang.monotonic_time() ^^^ :erlang.unique_integer())
    cookie = random_cookie(20, seed, [])
    case (:file.open(name, [:write, :raw])) do
      {:ok, file} ->
        r1 = :file.write(file, cookie)
        :ok = :file.close(file)
        r2 = :file.raw_write_file_info(name, make_info(name))
        case ({r1, r2}) do
          {:ok, :ok} ->
            :ok
          {{:error, reason}, _} ->
            {:error,
               :lists.flatten(:io_lib.format('Failed to write to cookie file \'~ts\': ~p', [name, reason]))}
          {:ok, {:error, reason}} ->
            {:error, 'Failed to change mode: ' ++ :erlang.atom_to_list(reason)}
        end
      {:error, reason} ->
        {:error,
           :lists.flatten(:io_lib.format('Failed to create cookie file \'~ts\': ~p', [name, reason]))}
    end
  end

  defp random_cookie(0, _, result) do
    result
  end

  defp random_cookie(count, x0, result) do
    x = next_random(x0)
    letter = div(x * (?Z - ?A + 1), 68719476736) + ?A
    random_cookie(count - 1, x, [letter | result])
  end

  defp make_info(name) do
    midnight = (case (:file.raw_read_file_info(name)) do
                  {:ok, r_file_info(atime: {date, _})} ->
                    {date, {0, 0, 0}}
                  _ ->
                    {{1990, 1, 1}, {0, 0, 0}}
                end)
    r_file_info(mode: 256, atime: midnight, mtime: midnight,
        ctime: midnight)
  end

  defp next_random(x) do
    (x * 17059465 + 1) &&& 68719476735
  end

end