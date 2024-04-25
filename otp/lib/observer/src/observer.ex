defmodule :m_observer do
  use Bitwise
  def start() do
    :observer_wx.start()
  end

  def start(node) when is_atom(node) do
    start([node])
  end

  def start([node]) do
    node1 = to_atom(node)
    case (:net_kernel.connect_node(node1)) do
      true ->
        case (:observer_wx.start()) do
          :ok ->
            :observer_wx.set_node(node1)
            :ok
          err ->
            err
        end
      _ ->
        {:error, :failed_to_connect}
    end
  end

  def start_and_wait() do
    :ok = start()
    monitorRef = :erlang.monitor(:process, :observer)
    receive do
      {:DOWN, ^monitorRef, :process, _, _} ->
        :ok
    end
  end

  def start_and_wait(node) when is_atom(node) do
    start_and_wait([node])
  end

  def start_and_wait(list) when is_list(list) do
    :ok = start(list)
    monitorRef = :erlang.monitor(:process, :observer)
    receive do
      {:DOWN, ^monitorRef, :process, _, _} ->
        :ok
    end
  end

  def stop() do
    :observer_wx.stop()
  end

  defp to_atom(node) when is_atom(node) do
    node
  end

  defp to_atom(node) when is_list(node) do
    :erlang.list_to_atom(node)
  end

end