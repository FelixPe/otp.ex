defmodule :m_erl_distribution do
  use Bitwise
  @behaviour :supervisor
  def start_link() do
    do_start_link([{:sname, :shortnames}, {:name, :longnames}])
  end

  def start(opts) do
    c = %{
      id: :net_sup_dynamic,
      start:
        {:erl_distribution, :start_link,
         [Map.merge(opts, %{clean_halt: false, supervisor: :net_sup_dynamic})]},
      restart: :permanent,
      shutdown: 1000,
      type: :supervisor,
      modules: [:erl_distribution]
    }

    :supervisor.start_child(:kernel_sup, c)
  end

  def stop() do
    case :supervisor.terminate_child(
           :kernel_sup,
           :net_sup_dynamic
         ) do
      :ok ->
        :supervisor.delete_child(:kernel_sup, :net_sup_dynamic)

      error ->
        case :erlang.whereis(:net_sup) do
          pid when is_pid(pid) ->
            {:error, :not_allowed}

          _ ->
            error
        end
    end
  end

  def start_link(opts) do
    :supervisor.start_link({:local, :net_sup}, :erl_distribution, [opts])
  end

  def init(netArgs) do
    epmd =
      case :init.get_argument(:no_epmd) do
        {:ok, [[]]} ->
          []

        _ ->
          epmdMod = :net_kernel.epmd_module()

          [
            %{
              id: epmdMod,
              start: {epmdMod, :start_link, []},
              restart: :permanent,
              shutdown: 2000,
              type: :worker,
              modules: [epmdMod]
            }
          ]
      end

    auth = %{
      id: :auth,
      start: {:auth, :start_link, []},
      restart: :permanent,
      shutdown: 2000,
      type: :worker,
      modules: [:auth]
    }

    kernel = %{
      id: :net_kernel,
      start: {:net_kernel, :start_link, netArgs},
      restart: :permanent,
      shutdown: 2000,
      type: :worker,
      modules: [:net_kernel]
    }

    earlySpecs = :net_kernel.protocol_childspecs()
    supFlags = %{strategy: :one_for_all, intensity: 0, period: 1}
    {:ok, {supFlags, earlySpecs ++ epmd ++ [auth, kernel]}}
  end

  defp do_start_link([{arg, flag} | t]) do
    case :init.get_argument(arg) do
      {:ok, [[name]]} ->
        start_link(%{
          name: :erlang.list_to_atom(name),
          name_domain: flag,
          clean_halt: true,
          supervisor: :net_sup
        })

      {:ok, [[name] | _Rest]} ->
        case :logger.allow(:warning, :erl_distribution) do
          true ->
            :erlang.apply(:logger, :macro_log, [
              %{
                mfa: {:erl_distribution, :do_start_link, 1},
                line: 113,
                file: ~c"otp/lib/kernel/src/erl_distribution.erl"
              },
              :warning,
              ~c"Multiple -~p given to erl, using the first, ~p",
              [arg, name]
            ])

          false ->
            :ok
        end

        start_link(%{
          name: :erlang.list_to_atom(name),
          name_domain: flag,
          clean_halt: true,
          supervisor: :net_sup
        })

      {:ok, [invalid | _]} ->
        case :logger.allow(:error, :erl_distribution) do
          true ->
            :erlang.apply(:logger, :macro_log, [
              %{
                mfa: {:erl_distribution, :do_start_link, 1},
                line: 120,
                file: ~c"otp/lib/kernel/src/erl_distribution.erl"
              },
              :error,
              ~c"Invalid -~p given to erl, ~ts",
              [arg, :lists.join(~c" ", invalid)]
            ])

          false ->
            :ok
        end

        do_start_link(t)

      _ ->
        do_start_link(t)
    end
  end

  defp do_start_link([]) do
    :ignore
  end
end
