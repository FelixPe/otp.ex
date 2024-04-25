defmodule :m_user_sup do
  use Bitwise
  @behaviour :supervisor_bridge
  def start() do
    :supervisor_bridge.start_link(:user_sup, [])
  end

  def init([]) do
    init(:init.get_arguments())
  end

  def init(flags) do
    case get_user(flags) do
      :nouser ->
        :ignore

      {:master, master} ->
        pid = start_relay(master)
        {:ok, pid, pid}

      {m, f, a} ->
        case start_user(m, f, a) do
          {:ok, pid} ->
            {:ok, pid, pid}

          error ->
            error
        end
    end
  end

  defp start_relay(master) do
    case :rpc.call(master, :erlang, :whereis, [:user]) do
      user when is_pid(user) ->
        spawn(:user_sup, :relay, [user])

      _ ->
        :error_logger.error_msg(~c"Cannot get remote user", [])

        receive do
        after
          1000 ->
            true
        end

        :erlang.halt()
    end
  end

  def relay(pid) do
    :erlang.register(:user, self())
    relay1(pid)
  end

  defp relay1(pid) do
    receive do
      x ->
        send(pid, x)
        relay1(pid)
    end
  end

  def terminate(_Reason, userPid) do
    receive do
    after
      1000 ->
        :ok
    end

    :erlang.exit(userPid, :kill)
    :ok
  end

  defp start_user(mod, func, a) do
    apply(mod, func, a)
    wait_for_user_p(100)
  end

  defp wait_for_user_p(0) do
    {:error, :nouser}
  end

  defp wait_for_user_p(n) do
    case :erlang.whereis(:user) do
      pid when is_pid(pid) ->
        :erlang.link(pid)
        {:ok, pid}

      _ ->
        receive do
        after
          100 ->
            :ok
        end

        wait_for_user_p(n - 1)
    end
  end

  defp get_user(flags) do
    check_flags(
      flags,
      :lists.keymember(:detached, 1, flags),
      {:user_drv, :start, []}
    )
  end

  defp check_flags([{:nouser, []} | t], attached, _) do
    check_flags(t, attached, :nouser)
  end

  defp check_flags([{:user, [user]} | t], attached, _) do
    check_flags(t, attached, {:erlang.list_to_atom(user), :start, []})
  end

  defp check_flags([{:noshell, []} | t], attached, _) do
    check_flags(t, attached, {:user_drv, :start, [%{initial_shell: :noshell}]})
  end

  defp check_flags([{:oldshell, []} | t], false, _) do
    check_flags(t, false, {:user_drv, :start, [%{initial_shell: :oldshell}]})
  end

  defp check_flags([{:noinput, []} | t], attached, _) do
    check_flags(t, attached, {:user_drv, :start, [%{initial_shell: :noshell, input: false}]})
  end

  defp check_flags([{:master, [node]} | t], attached, _) do
    check_flags(t, attached, {:master, :erlang.list_to_atom(node)})
  end

  defp check_flags([_H | t], attached, user) do
    check_flags(t, attached, user)
  end

  defp check_flags([], _Attached, user) do
    user
  end
end
