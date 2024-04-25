defmodule :m_ssh_lib do
  use Bitwise
  require Record
  Record.defrecord(:r_address, :address, address: :undefined,
                                   port: :undefined, profile: :undefined)
  Record.defrecord(:r_ssh, :ssh, role: :undefined,
                               peer: :undefined, local: :undefined,
                               c_vsn: :undefined, s_vsn: :undefined,
                               c_version: :undefined, s_version: :undefined,
                               c_keyinit: :undefined, s_keyinit: :undefined,
                               send_ext_info: :undefined,
                               recv_ext_info: :undefined,
                               kex_strict_negotiated: false,
                               algorithms: :undefined, send_mac: :none,
                               send_mac_key: :undefined, send_mac_size: 0,
                               recv_mac: :none, recv_mac_key: :undefined,
                               recv_mac_size: 0, encrypt: :none,
                               encrypt_cipher: :undefined,
                               encrypt_keys: :undefined, encrypt_block_size: 8,
                               encrypt_ctx: :undefined, decrypt: :none,
                               decrypt_cipher: :undefined,
                               decrypt_keys: :undefined, decrypt_block_size: 8,
                               decrypt_ctx: :undefined, compress: :none,
                               compress_ctx: :undefined, decompress: :none,
                               decompress_ctx: :undefined, c_lng: :none,
                               s_lng: :none, user_ack: true, timeout: :infinity,
                               shared_secret: :undefined,
                               exchanged_hash: :undefined,
                               session_id: :undefined, opts: [],
                               send_sequence: 0, recv_sequence: 0,
                               keyex_key: :undefined, keyex_info: :undefined,
                               random_length_padding: 15, user: :undefined,
                               service: :undefined,
                               userauth_quiet_mode: :undefined,
                               userauth_methods: :undefined,
                               userauth_supported_methods: :undefined,
                               userauth_pubkeys: :undefined, kb_tries_left: 0,
                               userauth_preference: :undefined,
                               available_host_keys: :undefined,
                               pwdfun_user_state: :undefined,
                               authenticated: false)
  Record.defrecord(:r_alg, :alg, kex: :undefined,
                               hkey: :undefined, send_mac: :undefined,
                               recv_mac: :undefined, encrypt: :undefined,
                               decrypt: :undefined, compress: :undefined,
                               decompress: :undefined, c_lng: :undefined,
                               s_lng: :undefined, send_ext_info: :undefined,
                               recv_ext_info: :undefined,
                               kex_strict_negotiated: false)
  Record.defrecord(:r_ssh_pty, :ssh_pty, c_version: '', term: '',
                                   width: 80, height: 25, pixel_width: 1024,
                                   pixel_height: 768, modes: <<>>)
  Record.defrecord(:r_circ_buf_entry, :circ_buf_entry, module: :undefined,
                                          line: :undefined,
                                          function: :undefined, pid: self(),
                                          value: :undefined)
  def format_address_port({iP, port}) when is_integer(port) do
    format_address_port(iP, port)
  end

  def format_address_port(x) do
    :io_lib.format('~p', [x])
  end

  def format_address_port(address, port) do
    try do
      :lists.concat([format_address(address), ':', port])
    catch
      _, _ ->
        :io_lib.format('~p:~p', [address, port])
    end
  end

  def format_address(r_address(address: a, port: p)) do
    format_address_port(a, p)
  end

  def format_address(a) do
    try do
      :inet.ntoa(a)
    catch
      _, _ when is_list(a) ->
        a
      _, _ ->
        :io_lib.format(:"~p", [a])
    end
  end

  def format_time_ms(t) when is_integer(t) do
    cond do
      t < 60000 ->
        :io_lib.format('~.3f sec', [t / 1000])
      true ->
        :io_lib.format('~p min ~s',
                         [div(t, 60000), format_time_ms(rem(t, 60000))])
    end
  end

  def comp(x1, x2) do
    comp(x1, x2, true)
  end

  defp comp(<<b1, r1 :: binary>>, <<b2, r2 :: binary>>,
            truth) do
    comp(r1, r2, :erlang.and(truth, b1 == b2))
  end

  defp comp(<<_, r1 :: binary>>, <<>>, truth) do
    comp(r1, <<>>, :erlang.and(truth, false))
  end

  defp comp(<<>>, <<>>, truth) do
    truth
  end

  defp comp([h1 | t1], [h2 | t2], truth) do
    comp(t1, t2, :erlang.and(truth, h1 == h2))
  end

  defp comp([_ | t1], [], truth) do
    comp(t1, [], :erlang.and(truth, false))
  end

  defp comp([], [], truth) do
    truth
  end

  defp comp(_, _, _) do
    false
  end

end