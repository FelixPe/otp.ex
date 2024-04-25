defmodule :m_ftp do
  use Bitwise
  import Kernel, except: [send: 2]

  def start() do
    :application.start(:ftp)
  end

  def stop() do
    :application.stop(:ftp)
  end

  def open({:option_list, options}) when is_list(options) do
    :ftp_internal.start_service(options)
  end

  def open(host) do
    :ftp_internal.open(host)
  end

  def open(host, port) do
    :ftp_internal.open(host, port)
  end

  def user(pid, user, pass) do
    :ftp_internal.user(pid, user, pass)
  end

  def user(pid, user, pass, account) do
    :ftp_internal.user(pid, user, pass, account)
  end

  def account(pid, acc) do
    :ftp_internal.account(pid, acc)
  end

  def pwd(pid) do
    :ftp_internal.pwd(pid)
  end

  def lpwd(pid) do
    :ftp_internal.lpwd(pid)
  end

  def cd(pid, dir) do
    :ftp_internal.cd(pid, dir)
  end

  def lcd(pid, dir) do
    :ftp_internal.lcd(pid, dir)
  end

  def ls(pid) do
    ls(pid, ~c"")
  end

  def ls(pid, dir) do
    :ftp_internal.ls(pid, dir)
  end

  def nlist(pid) do
    nlist(pid, ~c"")
  end

  def nlist(pid, dir) do
    :ftp_internal.nlist(pid, dir)
  end

  def rename(pid, old, new) do
    :ftp_internal.rename(pid, old, new)
  end

  def delete(pid, file) do
    :ftp_internal.delete(pid, file)
  end

  def mkdir(pid, dir) do
    :ftp_internal.mkdir(pid, dir)
  end

  def rmdir(pid, dir) do
    :ftp_internal.rmdir(pid, dir)
  end

  def type(pid, type) do
    :ftp_internal.type(pid, type)
  end

  def recv(pid, remoteFileName) do
    :ftp_internal.recv(pid, remoteFileName)
  end

  def recv(pid, remoteFileName, localFileName) do
    :ftp_internal.recv(pid, remoteFileName, localFileName)
  end

  def recv_bin(pid, remoteFile) do
    :ftp_internal.recv_bin(pid, remoteFile)
  end

  def recv_chunk_start(pid, remoteFile) do
    :ftp_internal.recv_chunk_start(pid, remoteFile)
  end

  def recv_chunk(pid) do
    :ftp_internal.recv_chunk(pid)
  end

  def send(pid, localFileName) do
    send(pid, localFileName, localFileName)
  end

  def send(pid, localFileName, remotFileName) do
    :ftp_internal.send(pid, localFileName, remotFileName)
  end

  def send_bin(pid, bin, remoteFile) do
    :ftp_internal.send_bin(pid, bin, remoteFile)
  end

  def send_chunk_start(pid, remoteFile) do
    :ftp_internal.send_chunk_start(pid, remoteFile)
  end

  def append_chunk_start(pid, remoteFile) do
    :ftp_internal.append_chunk_start(pid, remoteFile)
  end

  def send_chunk(pid, bin) do
    :ftp_internal.send_chunk(pid, bin)
  end

  def append_chunk(pid, bin) do
    :ftp_internal.append_chunk(pid, bin)
  end

  def send_chunk_end(pid) do
    :ftp_internal.send_chunk_end(pid)
  end

  def append_chunk_end(pid) do
    :ftp_internal.append_chunk_end(pid)
  end

  def append(pid, localFileName) do
    append(pid, localFileName, localFileName)
  end

  def append(pid, localFileName, remotFileName) do
    :ftp_internal.append(pid, localFileName, remotFileName)
  end

  def append_bin(pid, bin, remoteFile) do
    :ftp_internal.append_bin(pid, bin, remoteFile)
  end

  def quote(pid, cmd) when is_list(cmd) do
    :ftp_internal.quote(pid, cmd)
  end

  def close(pid) do
    :ftp_internal.close(pid)
  end

  def formaterror(tag) do
    :ftp_response.error_string(tag)
  end

  def info(pid) do
    :ftp_internal.info(pid)
  end

  def latest_ctrl_response(pid) do
    :ftp_internal.latest_ctrl_response(pid)
  end
end
