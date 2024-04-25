defmodule :m_unix_telnet do
  use Bitwise
  import :ct_telnet, only: [end_gen_log: 0, log: 4, start_gen_log: 1]

  def get_prompt_regexp() do
    ~c"login: |Password: |\\$ |> "
  end

  def connect(connName, ip, port, timeout, keepAlive, tCPNoDelay, extra) do
    case extra do
      {username, password} ->
        connect1(connName, ip, port, timeout, keepAlive, tCPNoDelay, username, password)

      keyOrName ->
        case get_username_and_password(keyOrName) do
          {:ok, {username, password}} ->
            connect1(connName, ip, port, timeout, keepAlive, tCPNoDelay, username, password)

          error ->
            error
        end
    end
  end

  defp connect1(name, ip, port, timeout, keepAlive, tCPNoDelay, username, password) do
    start_gen_log(~c"unix_telnet connect")

    result =
      case :ct_telnet_client.open(ip, port, timeout, keepAlive, tCPNoDelay, name) do
        {:ok, pid} ->
          case :ct_telnet.silent_teln_expect(
                 name,
                 pid,
                 [],
                 [:prompt],
                 ~c"login: |Password: |\\$ |> ",
                 []
               ) do
            {:ok, {:prompt, ~c"login: "}, _} ->
              log(name, :send, ~c"Logging in to ~p:~p", [ip, port])
              :ok = :ct_telnet_client.send_data(pid, username)
              log(name, :send, ~c"Username: ~ts", [username])

              case :ct_telnet.silent_teln_expect(
                     name,
                     pid,
                     [],
                     :prompt,
                     ~c"login: |Password: |\\$ |> ",
                     []
                   ) do
                {:ok, {:prompt, ~c"Password: "}, _} ->
                  :ok = :ct_telnet_client.send_data(pid, password)
                  stars = :lists.duplicate(:string.length(password), ?*)
                  log(name, :send, ~c"Password: ~s", [stars])

                  case :ct_telnet.silent_teln_expect(
                         name,
                         pid,
                         [],
                         :prompt,
                         ~c"login: |Password: |\\$ |> ",
                         []
                       ) do
                    {:ok, {:prompt, prompt}, _}
                    when prompt !== ~c"login: " and
                           prompt !== ~c"Password: " ->
                      {:ok, pid}

                    error ->
                      log(name, :recv, ~c"Password failed\n~tp\n", [error])
                      {:error, error}
                  end

                error ->
                  log(name, :recv, ~c"Login to ~p:~p failed\n~tp\n", [ip, port, error])
                  {:error, error}
              end

            {:ok, [{:prompt, _OtherPrompt1}, {:prompt, _OtherPrompt2}], _} ->
              {:ok, pid}

            error ->
              log(name, :conn_error, ~c"Did not get expected prompt from ~p:~p\n~tp\n", [
                ip,
                port,
                error
              ])

              {:error, error}
          end

        error ->
          log(name, :conn_error, ~c"Could not open telnet connection to ~p:~p\n~tp\n", [
            ip,
            port,
            error
          ])

          error
      end

    end_gen_log()
    result
  end

  defp get_username_and_password(name) do
    case :ct.get_config({name, :username}) do
      :undefined ->
        {:error, {:no_username, name}}

      username ->
        case :ct.get_config({name, :password}) do
          :undefined ->
            {:error, {:no_password, name}}

          password ->
            {:ok, {username, password}}
        end
    end
  end
end
