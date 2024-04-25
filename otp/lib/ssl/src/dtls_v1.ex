defmodule :m_dtls_v1 do
  use Bitwise
  require Record

  Record.defrecord(:r_stateless_ticket, :stateless_ticket,
    hash: :undefined,
    pre_shared_key: :undefined,
    ticket_age_add: :undefined,
    lifetime: :undefined,
    timestamp: :undefined,
    certificate: :undefined
  )

  Record.defrecord(:r_change_cipher_spec, :change_cipher_spec, type: 1)

  Record.defrecord(:r_cipher_state, :cipher_state,
    iv: :undefined,
    key: :undefined,
    finished_key: :undefined,
    state: :undefined,
    nonce: :undefined,
    tag_len: :undefined
  )

  Record.defrecord(:r_security_parameters, :security_parameters,
    cipher_suite: :undefined,
    connection_end: :undefined,
    bulk_cipher_algorithm: :undefined,
    cipher_type: :undefined,
    iv_size: :undefined,
    key_material_length: :undefined,
    mac_algorithm: :undefined,
    prf_algorithm: :undefined,
    hash_size: :undefined,
    compression_algorithm: :undefined,
    master_secret: :undefined,
    resumption_master_secret: :undefined,
    application_traffic_secret: :undefined,
    client_early_data_secret: :undefined,
    client_random: :undefined,
    server_random: :undefined
  )

  Record.defrecord(:r_compression_state, :compression_state,
    method: :undefined,
    state: :undefined
  )

  Record.defrecord(:r_generic_stream_cipher, :generic_stream_cipher,
    content: :undefined,
    mac: :undefined
  )

  Record.defrecord(:r_generic_block_cipher, :generic_block_cipher,
    iv: :undefined,
    content: :undefined,
    mac: :undefined,
    padding: :undefined,
    padding_length: :undefined,
    next_iv: :undefined
  )

  def suites(version) do
    :lists.filter(
      fn cipher ->
        is_acceptable_cipher(:ssl_cipher_format.suite_bin_to_map(cipher))
      end,
      :tls_v1.suites(corresponding_tls_version(version))
    )
  end

  def all_suites(version) do
    :lists.filter(
      fn cipher ->
        is_acceptable_cipher(:ssl_cipher_format.suite_bin_to_map(cipher))
      end,
      :ssl_cipher.all_suites(corresponding_tls_version(version))
    )
  end

  def anonymous_suites(version) do
    :lists.filter(
      fn cipher ->
        is_acceptable_cipher(:ssl_cipher_format.suite_bin_to_map(cipher))
      end,
      :ssl_cipher.anonymous_suites(corresponding_tls_version(version))
    )
  end

  def exclusive_suites(version) do
    :lists.filter(
      fn cipher ->
        is_acceptable_cipher(:ssl_cipher_format.suite_bin_to_map(cipher))
      end,
      :tls_v1.exclusive_suites(corresponding_tls_version(version))
    )
  end

  def exclusive_anonymous_suites(version) do
    :lists.filter(
      fn cipher ->
        is_acceptable_cipher(:ssl_cipher_format.suite_bin_to_map(cipher))
      end,
      :tls_v1.exclusive_anonymous_suites(corresponding_tls_version(version))
    )
  end

  def hmac_hash(macAlg, macSecret, value) do
    :tls_v1.hmac_hash(macAlg, macSecret, value)
  end

  def ecc_curves(version) do
    :tls_v1.ecc_curves(corresponding_tls_version(version))
  end

  def corresponding_tls_version({254, 255}) do
    {3, 2}
  end

  def corresponding_tls_version({254, 253}) do
    {3, 3}
  end

  def cookie_secret() do
    :crypto.strong_rand_bytes(32)
  end

  def cookie_timeout() do
    round(:rand.uniform() * 30000 / 2)
  end

  def corresponding_dtls_version({3, 2}) do
    {254, 255}
  end

  def corresponding_dtls_version({3, 3}) do
    {254, 253}
  end

  defp is_acceptable_cipher(suite) do
    not :ssl_cipher.is_stream_ciphersuite(suite)
  end
end
