defmodule :m_ssl_server_session_cache_db do
  use Bitwise
  @behaviour :ssl_session_cache_api
  def init(_Options) do
    :gb_trees.empty()
  end

  def lookup(cache, key) do
    case (:gb_trees.lookup(key, cache)) do
      {:value, session} ->
        session
      :none ->
        :undefined
    end
  end

  def update(cache, key, session) do
    :gb_trees.insert(key, session, cache)
  end

  def delete(cache, key) do
    :gb_trees.delete(key, cache)
  end

  def size(cache) do
    :gb_trees.size(cache)
  end

  def terminate(_) do
    :ok
  end

end