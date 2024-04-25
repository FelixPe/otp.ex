defmodule :m_ssl_dist_sup do
  use Bitwise
  @behaviour :supervisor
  def start_link() do
    case :init.get_argument(:ssl_dist_optfile) do
      {:ok, [file]} ->
        distOpts = consult(file)
        tabOpts = [:set, :protected, :named_table]
        tab = :ets.new(:ssl_dist_opts, tabOpts)
        true = :ets.insert(tab, distOpts)
        :supervisor.start_link({:local, :ssl_dist_sup}, :ssl_dist_sup, [])

      {:ok, badArg} ->
        :erlang.error({:bad_ssl_dist_optfile, badArg})

      :error ->
        :supervisor.start_link({:local, :ssl_dist_sup}, :ssl_dist_sup, [])
    end
  end

  def init([]) do
    supFlags = %{strategy: :one_for_all, intensity: 10, period: 3600}
    childSpecs = [ssl_admin_child_spec(), ssl_connection_sup()]
    {:ok, {supFlags, childSpecs}}
  end

  defp ssl_admin_child_spec() do
    %{
      id: :ssl_dist_admin_sup,
      start: {:ssl_dist_admin_sup, :start_link, []},
      restart: :permanent,
      shutdown: 4000,
      modules: [:ssl_dist_admin_sup],
      type: :supervisor
    }
  end

  defp ssl_connection_sup() do
    %{
      id: :tls_dist_sup,
      start: {:tls_dist_sup, :start_link, []},
      restart: :permanent,
      shutdown: 4000,
      modules: [:tls_dist_sup],
      type: :supervisor
    }
  end

  def consult(file) do
    case :erl_prim_loader.get_file(file) do
      {:ok, binary, _FullName} ->
        encoding =
          case :epp.read_encoding_from_binary(binary) do
            :none ->
              :latin1

            enc ->
              enc
          end

        case :unicode.characters_to_list(binary, encoding) do
          {:error, _String, rest} ->
            :erlang.error({:bad_ssl_dist_optfile, {:encoding_error, rest}})

          {:incomplete, _String, rest} ->
            :erlang.error({:bad_ssl_dist_optfile, {:encoding_incomplete, rest}})

          string when is_list(string) ->
            consult_string(string)
        end

      :error ->
        :erlang.error({:bad_ssl_dist_optfile, file})
    end
  end

  defp consult_string(string) do
    case :erl_scan.string(string) do
      {:error, info, location} ->
        :erlang.error({:bad_ssl_dist_optfile, {:scan_error, info, location}})

      {:ok, tokens, _EndLocation} ->
        consult_tokens(tokens)
    end
  end

  defp consult_tokens(tokens) do
    case :erl_parse.parse_exprs(tokens) do
      {:error, info} ->
        :erlang.error({:bad_ssl_dist_optfile, {:parse_error, info}})

      {:ok, [expr]} ->
        consult_expr(expr)

      {:ok, other} ->
        :erlang.error({:bad_ssl_dist_optfile, {:parse_error, other}})
    end
  end

  defp consult_expr(expr) do
    {:value, value, bs} =
      :erl_eval.expr(
        expr,
        :erl_eval.new_bindings()
      )

    case :erl_eval.bindings(bs) do
      [] ->
        value

      other ->
        :erlang.error({:bad_ssl_dist_optfile, {:bindings, other}})
    end
  end
end
