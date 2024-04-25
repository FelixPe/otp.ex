defmodule :m_inet6_tls_dist do
  use Bitwise

  def childspecs() do
    :inet_tls_dist.childspecs()
  end

  def select(node) do
    :inet_tls_dist.fam_select(:inet6, node)
  end

  def address() do
    :inet_tls_dist.fam_address(:inet6)
  end

  def listen(name, host) do
    :inet_tls_dist.fam_listen(:inet6, name, host)
  end

  def accept(listen) do
    :inet_tls_dist.fam_accept(:inet6, listen)
  end

  def accept_connection(acceptPid, socket, myNode, allowed, setupTime) do
    :inet_tls_dist.fam_accept_connection(:inet6, acceptPid, socket, myNode, allowed, setupTime)
  end

  def setup(node, type, myNode, longOrShortNames, setupTime) do
    :inet_tls_dist.fam_setup(:inet6, node, type, myNode, longOrShortNames, setupTime)
  end

  def close(socket) do
    :inet_tls_dist.close(socket)
  end
end
