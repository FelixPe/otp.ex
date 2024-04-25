defmodule :m_ssh_app do
  use Bitwise
  @behaviour :application
  @behaviour :supervisor
  def start(_Type, _State) do
    :supervisor.start_link({:local, :ssh_sup}, :ssh_app,
                             [:ssh_sup])
  end

  def stop(_State) do
    :ok
  end

  def init([:ssh_sup]) do
    add_logger_filter()
    supFlags = %{strategy: :one_for_one, intensity: 10,
                   period: 3600}
    childSpecs = (for supName <- [:sshd_sup, :sshc_sup] do
                    %{id: supName,
                        start:
                        {:supervisor, :start_link,
                           [{:local, supName}, :ssh_app, [:sshX_sup]]},
                        type: :supervisor}
                  end)
    {:ok, {supFlags, childSpecs}}
  end

  def init([:sshX_sup]) do
    supFlags = %{strategy: :one_for_one, intensity: 10,
                   period: 3600}
    childSpecs = []
    {:ok, {supFlags, childSpecs}}
  end

  defp add_logger_filter() do
    defAct = :application.get_env(:ssh, :default_filter,
                                    :rm)
    defF = :start_link
    modulesActions = :lists.map(fn m when is_atom(m) ->
                                     {m, {defF, defAct}}
                                   {m, act} when (is_atom(m) and
                                                    act == :rm or act == :filter)
                                                 ->
                                     {m, {defF, act}}
                                   {m, f} when (is_atom(m) and is_atom(f)) ->
                                     {m, {f, defAct}}
                                   {m, f, act} when (is_atom(m) and
                                                       is_atom(f) and
                                                       act == :rm or act == :filter)
                                                    ->
                                     {m, {f, act}}
                                end,
                                  :application.get_env(:ssh, :filter_modules,
                                                         []))
    :logger.add_primary_filter(:ssh_filter,
                                 {&ssh_filter/2, modulesActions})
  end

  defp ssh_filter(ev = %{msg: {:report, r = %{report: rep}}},
            modulesActions = [_ | _])
      when is_list(rep) do
    try do
      %{ev
        |
        msg:
        {:report,
           %{r | report: remove_sensitive(rep, modulesActions)}}}
    catch
      {:ssh_filter_return, ret} ->
        ret
      _C, _E ->
        :stop
    end
  end

  defp ssh_filter(otherEv, _) do
    otherEv
  end

  defp remove_sensitive(l, modActs) when is_list(l) do
    rs(l, modActs)
  end

  defp remove_sensitive(_, _) do
    throw({:ssh_filter_return, :ignore})
  end

  defp rs([{k, v0} | t], modActs) when is_list(v0) do
    case (:proplists.get_value(:mfargs, v0)) do
      {m, f, a} ->
        mFA1 = filter(:proplists.get_value(m, modActs),
                        {m, f, a})
        v = :lists.keyreplace(:mfargs, 1, v0, {:mfargs, mFA1})
        [{k, v} | t]
      _ ->
        [{k, v0} | rs(t, modActs)]
    end
  end

  defp rs([h | t], modActs) do
    [h | rs(t, modActs)]
  end

  defp rs(other, _) do
    other
  end

  defp filter({f, act}, {m, f, a}) do
    {m, f, :ssh_options.no_sensitive(act, a)}
  end

  defp filter(:stop, _) do
    throw({:ssh_filter_return, :stop})
  end

  defp filter(_, _) do
    throw({:ssh_filter_return, :ignore})
  end

end