defmodule :m_public_key do
  use Bitwise
  import Kernel, except: [to_string: 1]
  require Record

  Record.defrecord(:r_SubjectPublicKeyInfoAlgorithm, :SubjectPublicKeyInfoAlgorithm,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_path_validation_state, :path_validation_state,
    valid_policy_tree: :undefined,
    user_initial_policy_set: :undefined,
    explicit_policy: :undefined,
    inhibit_any_policy: :undefined,
    inhibit_policy_mapping: :undefined,
    policy_mapping_ext: :undefined,
    policy_constraint_ext: :undefined,
    policy_inhibitany_ext: :undefined,
    policy_ext_present: :undefined,
    policy_ext_any: :undefined,
    current_any_policy_qualifiers: :undefined,
    cert_num: :undefined,
    last_cert: false,
    permitted_subtrees: :no_constraints,
    excluded_subtrees: [],
    working_public_key_algorithm: :undefined,
    working_public_key: :undefined,
    working_public_key_parameters: :undefined,
    working_issuer_name: :undefined,
    max_path_length: :undefined,
    verify_fun: :undefined,
    user_state: :undefined
  )

  Record.defrecord(:r_revoke_state, :revoke_state,
    reasons_mask: :undefined,
    cert_status: :undefined,
    interim_reasons_mask: :undefined,
    valid_ext: :undefined,
    details: :undefined
  )

  Record.defrecord(:r_ECPoint, :ECPoint, point: :undefined)

  Record.defrecord(:r_cert, :cert,
    der: :undefined,
    otp: :undefined
  )

  def pem_decode(pemBin) when is_binary(pemBin) do
    :pubkey_pem.decode(pemBin)
  end

  def pem_encode(pemEntries) when is_list(pemEntries) do
    :erlang.iolist_to_binary(:pubkey_pem.encode(pemEntries))
  end

  def pem_entry_decode({:SubjectPublicKeyInfo, der, _}) do
    {_, {:AlgorithmIdentifier, algId, params}, key0} = der_decode(:SubjectPublicKeyInfo, der)
    keyType = :pubkey_cert_records.supportedPublicKeyAlgorithms(algId)

    case keyType do
      :RSAPublicKey ->
        der_decode(keyType, key0)

      :DSAPublicKey ->
        {:params, dssParams} = der_decode(:DSAParams, params)
        {der_decode(keyType, key0), dssParams}

      :ECPoint ->
        eCCParams = der_decode(:EcpkParameters, params)
        {r_ECPoint(point: key0), eCCParams}
    end
  end

  def pem_entry_decode({asn1Type, der, :not_encrypted})
      when is_atom(asn1Type) and is_binary(der) do
    der_decode(asn1Type, der)
  end

  def pem_entry_decode(pemEntry, passwordFun)
      when is_function(passwordFun) do
    pem_entry_decode(pemEntry, passwordFun.())
  end

  def pem_entry_decode({asn1Type, der, :not_encrypted}, _)
      when is_atom(asn1Type) and is_binary(der) do
    der_decode(asn1Type, der)
  end

  def pem_entry_decode(
        {asn1Type, cryptDer, {cipher, r_PBES2_params()}} = pemEntry,
        password
      )
      when is_atom(asn1Type) and is_binary(cryptDer) and is_list(cipher) do
    do_pem_entry_decode(pemEntry, password)
  end

  def pem_entry_decode(
        {asn1Type, cryptDer, {cipher, {r_PBEParameter(), _}}} = pemEntry,
        password
      )
      when is_atom(asn1Type) and is_binary(cryptDer) and is_list(cipher) and is_list(password) do
    do_pem_entry_decode(pemEntry, password)
  end

  def pem_entry_decode(
        {asn1Type, cryptDer, {cipher, salt}} = pemEntry,
        password
      )
      when is_atom(asn1Type) and is_binary(cryptDer) and is_list(cipher) and is_binary(salt) and
             (:erlang.byte_size(salt) == 8 or :erlang.byte_size(salt) == 16) and is_list(password) do
    do_pem_entry_decode(pemEntry, password)
  end

  def pem_entry_encode(asn1Type, entity, {{cipher, r_PBES2_params()} = cipherInfo, password})
      when is_atom(asn1Type) and is_list(password) and is_list(cipher) do
    do_pem_entry_encode(asn1Type, entity, cipherInfo, password)
  end

  def pem_entry_encode(asn1Type, entity, {{cipher, {r_PBEParameter(), _}} = cipherInfo, password})
      when is_atom(asn1Type) and is_list(password) and is_list(cipher) do
    do_pem_entry_encode(asn1Type, entity, cipherInfo, password)
  end

  def pem_entry_encode(asn1Type, entity, {{cipher, salt} = cipherInfo, password})
      when is_atom(asn1Type) and is_list(password) and is_list(cipher) and is_binary(salt) and
             (:erlang.byte_size(salt) == 8 or :erlang.byte_size(salt) == 16) do
    do_pem_entry_encode(asn1Type, entity, cipherInfo, password)
  end

  def der_decode(asn1Type, der)
      when (asn1Type == :PrivateKeyInfo or asn1Type == :EncryptedPrivateKeyInfo) and
             is_binary(der) do
    try do
      {:ok, decoded} = :PKCS - FRAME.decode(asn1Type, der)
      der_priv_key_decode(decoded)
    catch
      :error, {:badmatch, {:error, _}} = error ->
        handle_pkcs_frame_error(asn1Type, der, error)
    end
  end

  def der_decode(asn1Type, der)
      when is_atom(asn1Type) and
             is_binary(der) do
    try do
      {:ok, decoded} = :OTP - PUB - KEY.decode(asn1Type, der)
      decoded
    catch
      :error, {:badmatch, {:error, _}} = error ->
        :erlang.error(error)
    end
  end

  defp handle_pkcs_frame_error(:PrivateKeyInfo, der, _) do
    try do
      {:ok, decoded} =
        :PKCS -
          FRAME.decode(
            :OneAsymmetricKey,
            der
          )

      der_priv_key_decode(decoded)
    catch
      :error, {:badmatch, {:error, _}} = error ->
        :erlang.error(error)
    end
  end

  defp handle_pkcs_frame_error(_, _, error) do
    :erlang.error(error)
  end

  def pkix_decode_cert(derCert, :plain) when is_binary(derCert) do
    der_decode(:Certificate, derCert)
  end

  def pkix_decode_cert(derCert, :otp) when is_binary(derCert) do
    try do
      {:ok, r_OTPCertificate() = cert} = :pubkey_cert_records.decode_cert(derCert)
      cert
    catch
      :error, {:badmatch, {:error, _}} = error ->
        :erlang.error(error)
    end
  end

  def pkix_encode(asn1Type, term, :plain) when is_atom(asn1Type) do
    der_encode(asn1Type, term)
  end

  def pkix_encode(asn1Type, term0, :otp) when is_atom(asn1Type) do
    term = :pubkey_cert_records.transform(term0, :encode)
    der_encode(asn1Type, term)
  end

  def decrypt_private(cipherText, key) do
    decrypt_private(cipherText, key, [])
  end

  def decrypt_private(cipherText, r_RSAPrivateKey() = key, options)
      when is_binary(cipherText) and is_list(options) do
    :crypto.private_decrypt(
      :rsa,
      cipherText,
      format_rsa_private_key(key),
      default_options(options)
    )
  end

  def decrypt_public(cipherText, key) do
    decrypt_public(cipherText, key, [])
  end

  def decrypt_public(cipherText, r_RSAPublicKey(modulus: n, publicExponent: e), options)
      when is_binary(cipherText) and is_list(options) do
    :crypto.public_decrypt(:rsa, cipherText, [e, n], default_options(options))
  end

  def encrypt_public(plainText, key) do
    encrypt_public(plainText, key, [])
  end

  def encrypt_public(plainText, r_RSAPublicKey(modulus: n, publicExponent: e), options)
      when is_binary(plainText) and is_list(options) do
    :crypto.public_encrypt(:rsa, plainText, [e, n], default_options(options))
  end

  def encrypt_private(plainText, key) do
    encrypt_private(plainText, key, [])
  end

  def encrypt_private(
        plainText,
        r_RSAPrivateKey(modulus: n, publicExponent: e, privateExponent: d) = key,
        options
      )
      when is_binary(plainText) and is_integer(n) and
             is_integer(e) and is_integer(d) and is_list(options) do
    :crypto.private_encrypt(
      :rsa,
      plainText,
      format_rsa_private_key(key),
      default_options(options)
    )
  end

  def dh_gex_group_sizes() do
    :pubkey_ssh.dh_gex_group_sizes()
  end

  def dh_gex_group(min, n, max, groups) do
    :pubkey_ssh.dh_gex_group(min, n, max, groups)
  end

  def generate_key(r_DHParameter(prime: p, base: g)) do
    :crypto.generate_key(:dh, [p, g])
  end

  def generate_key({:namedCurve, _} = params) do
    ec_generate_key(params)
  end

  def generate_key({:ecParameters, _} = params) do
    ec_generate_key(params)
  end

  def generate_key(r_ECParameters() = params) do
    ec_generate_key(params)
  end

  def generate_key({:rsa, modulusSize, publicExponent}) do
    case :crypto.generate_key(
           :rsa,
           {modulusSize, publicExponent}
         ) do
      {[e, n], [e, n, d, p, q, d_mod_P_1, d_mod_Q_1, invQ_mod_P]} ->
        nint = :crypto.bytes_to_integer(n)
        eint = :crypto.bytes_to_integer(e)

        r_RSAPrivateKey(
          version: :"two-prime",
          modulus: nint,
          publicExponent: eint,
          privateExponent: :crypto.bytes_to_integer(d),
          prime1: :crypto.bytes_to_integer(p),
          prime2: :crypto.bytes_to_integer(q),
          exponent1: :crypto.bytes_to_integer(d_mod_P_1),
          exponent2: :crypto.bytes_to_integer(d_mod_Q_1),
          coefficient: :crypto.bytes_to_integer(invQ_mod_P)
        )

      {[e, n], [e, n, d]} ->
        nint = :crypto.bytes_to_integer(n)
        eint = :crypto.bytes_to_integer(e)

        r_RSAPrivateKey(
          version: :"two-prime",
          modulus: nint,
          publicExponent: eint,
          privateExponent: :crypto.bytes_to_integer(d),
          prime1: :"?",
          prime2: :"?",
          exponent1: :"?",
          exponent2: :"?",
          coefficient: :"?"
        )

      other ->
        other
    end
  end

  def compute_key(pubKey, privKey, r_DHParameter(prime: p, base: g)) do
    :crypto.compute_key(:dh, pubKey, privKey, [p, g])
  end

  def sign(digestOrPlainText, digestType, key) do
    sign(digestOrPlainText, digestType, key, [])
  end

  def sign(digest, :none, key = r_DSAPrivateKey(), options)
      when is_binary(digest) do
    sign({:digest, digest}, :sha, key, options)
  end

  def sign(digestOrPlainText, digestType, key, options) do
    case format_sign_key(key) do
      :badarg ->
        :erlang.error(
          :badarg,
          [digestOrPlainText, digestType, key, options]
        )

      {algorithm, cryptoKey} ->
        try do
          :crypto.sign(algorithm, digestType, digestOrPlainText, cryptoKey, options)
        catch
          :error, {:notsup, _, _} ->
            :erlang.error(:notsup)

          :error, {:error, _, _} ->
            :erlang.error(:error)

          :error, {:badarg, _, _} ->
            :erlang.error(:badarg)
        end
    end
  end

  def verify(digestOrPlainText, digestType, signature, key) do
    verify(digestOrPlainText, digestType, signature, key, [])
  end

  def verify(digest, :none, signature, key = {_, r_Dss_Parms()}, options)
      when is_binary(digest) do
    verify({:digest, digest}, :sha, signature, key, options)
  end

  def verify(digestOrPlainText, digestType, signature, key, options)
      when is_binary(signature) do
    case format_verify_key(key) do
      :badarg ->
        :erlang.error(
          :badarg,
          [digestOrPlainText, digestType, signature, key, options]
        )

      {algorithm, cryptoKey} ->
        try do
          :crypto.verify(algorithm, digestType, digestOrPlainText, signature, cryptoKey, options)
        catch
          :error, {:notsup, _, _} ->
            :erlang.error(:notsup)

          :error, {:error, _, _} ->
            :erlang.error(:error)

          :error, {:badarg, _, _} ->
            :erlang.error(:badarg)
        end
    end
  end

  def verify(_, _, _, _, _) do
    false
  end

  def pkix_dist_points(otpCert) when is_binary(otpCert) do
    pkix_dist_points(pkix_decode_cert(otpCert, :otp))
  end

  def pkix_dist_points(otpCert) do
    value = :pubkey_cert.distribution_points(otpCert)

    :lists.foldl(
      fn point, acc0 ->
        distPoint =
          :pubkey_cert_records.transform(
            point,
            :decode
          )

        [distPoint | acc0]
      end,
      [],
      value
    )
  end

  def pkix_sign(r_OTPTBSCertificate(signature: r_SignatureAlgorithm() = sigAlg) = tBSCert, key) do
    msg = pkix_encode(:OTPTBSCertificate, tBSCert, :otp)
    {digestType, _, opts} = :pubkey_cert.x509_pkix_sign_types(sigAlg)
    signature = sign(msg, digestType, format_pkix_sign_key(key), opts)

    cert =
      r_OTPCertificate(tbsCertificate: tBSCert, signatureAlgorithm: sigAlg, signature: signature)

    pkix_encode(:OTPCertificate, cert, :otp)
  end

  def pkix_crl_verify(cRL, cert) when is_binary(cRL) do
    pkix_crl_verify(der_decode(:CertificateList, cRL), cert)
  end

  def pkix_crl_verify(cRL, cert) when is_binary(cert) do
    pkix_crl_verify(cRL, pkix_decode_cert(cert, :otp))
  end

  def pkix_crl_verify(r_CertificateList() = cRL, r_OTPCertificate() = cert) do
    tBSCert = r_OTPCertificate(cert, :tbsCertificate)
    publicKeyInfo = r_OTPTBSCertificate(tBSCert, :subjectPublicKeyInfo)
    publicKey = r_OTPSubjectPublicKeyInfo(publicKeyInfo, :subjectPublicKey)
    algInfo = r_OTPSubjectPublicKeyInfo(publicKeyInfo, :algorithm)
    publicKeyParams = r_PublicKeyAlgorithm(algInfo, :parameters)

    :pubkey_crl.verify_crl_signature(
      cRL,
      der_encode(:CertificateList, cRL),
      publicKey,
      publicKeyParams
    )
  end

  def pkix_is_issuer(cert, issuerCert) when is_binary(cert) do
    otpCert = pkix_decode_cert(cert, :otp)
    pkix_is_issuer(otpCert, issuerCert)
  end

  def pkix_is_issuer(cert, issuerCert) when is_binary(issuerCert) do
    otpIssuerCert = pkix_decode_cert(issuerCert, :otp)
    pkix_is_issuer(cert, otpIssuerCert)
  end

  def pkix_is_issuer(
        r_OTPCertificate(tbsCertificate: tBSCert),
        r_OTPCertificate(tbsCertificate: candidate)
      ) do
    :pubkey_cert.is_issuer(
      r_OTPTBSCertificate(tBSCert, :issuer),
      r_OTPTBSCertificate(candidate, :subject)
    )
  end

  def pkix_is_issuer(
        r_CertificateList(tbsCertList: tBSCRL),
        r_OTPCertificate(tbsCertificate: candidate)
      ) do
    :pubkey_cert.is_issuer(
      r_OTPTBSCertificate(candidate, :subject),
      :pubkey_cert_records.transform(
        r_TBSCertList(tBSCRL, :issuer),
        :decode
      )
    )
  end

  def pkix_is_self_signed(r_OTPCertificate() = oTPCert) do
    :pubkey_cert.is_self_signed(oTPCert)
  end

  def pkix_is_self_signed(cert) when is_binary(cert) do
    otpCert = pkix_decode_cert(cert, :otp)
    pkix_is_self_signed(otpCert)
  end

  def pkix_is_fixed_dh_cert(r_OTPCertificate() = oTPCert) do
    :pubkey_cert.is_fixed_dh_cert(oTPCert)
  end

  def pkix_is_fixed_dh_cert(cert) when is_binary(cert) do
    otpCert = pkix_decode_cert(cert, :otp)
    pkix_is_fixed_dh_cert(otpCert)
  end

  def pkix_issuer_id(r_OTPCertificate() = otpCert, signed)
      when signed == :self or signed == :other do
    :pubkey_cert.issuer_id(otpCert, signed)
  end

  def pkix_issuer_id(cert, signed) when is_binary(cert) do
    otpCert = pkix_decode_cert(cert, :otp)
    pkix_issuer_id(otpCert, signed)
  end

  def pkix_subject_id(r_OTPCertificate() = otpCert) do
    :pubkey_cert.subject_id(otpCert)
  end

  def pkix_subject_id(cert) when is_binary(cert) do
    otpCert = pkix_decode_cert(cert, :otp)
    pkix_subject_id(otpCert)
  end

  def pkix_crl_issuer(cRL) when is_binary(cRL) do
    pkix_crl_issuer(der_decode(:CertificateList, cRL))
  end

  def pkix_crl_issuer(r_CertificateList() = cRL) do
    :pubkey_cert_records.transform(
      r_TBSCertList(r_CertificateList(cRL, :tbsCertList), :issuer),
      :decode
    )
  end

  def pkix_normalize_name(issuer) when is_binary(issuer) do
    plainGenName = der_decode(:Name, issuer)

    genName =
      :pubkey_cert_records.transform(
        plainGenName,
        :decode
      )

    pkix_normalize_name(genName)
  end

  def pkix_normalize_name(issuer) do
    :pubkey_cert.normalize_general_name(issuer)
  end

  def pkix_path_validation(trustedCert, certChain, options)
      when is_binary(trustedCert) do
    otpCert = pkix_decode_cert(trustedCert, :otp)
    pkix_path_validation(otpCert, certChain, options)
  end

  def pkix_path_validation(r_OTPCertificate() = trustedCert, certChain, options)
      when is_list(certChain) and is_list(options) do
    maxPathDefault = length(certChain)

    {verifyFun, userState0} =
      :proplists.get_value(
        :verify_fun,
        options,
        {fn
           _, {:bad_cert, _} = reason, _ ->
             {:fail, reason}

           _, {:extension, _}, userState ->
             {:unknown, userState}

           _, :valid, userState ->
             {:valid, userState}

           _, :valid_peer, userState ->
             {:valid, userState}
         end, []}
      )

    try do
      :pubkey_cert.validate_time(trustedCert, userState0, verifyFun)
    catch
      {:bad_cert, _} = result ->
        {:error, result}
    else
      userState1 ->
        validationState =
          :pubkey_cert.init_validation_state(
            trustedCert,
            maxPathDefault,
            [
              {:verify_fun, {verifyFun, userState1}}
              | :proplists.delete(
                  :verify_fun,
                  options
                )
            ]
          )

        case exists_duplicate_cert(certChain) do
          true ->
            {:error, {:bad_cert, :duplicate_cert_in_path}}

          false ->
            path_validation(certChain, validationState)
        end
    end
  end

  def pkix_path_validation(pathErr, [cert | chain], options0)
      when is_atom(pathErr) do
    {verifyFun, userstat0} =
      :proplists.get_value(
        :verify_fun,
        options0,
        {fn
           _, {:bad_cert, _} = reason, _ ->
             {:fail, reason}

           _, {:extension, _}, userState ->
             {:unknown, userState}

           _, :valid, userState ->
             {:valid, userState}

           _, :valid_peer, userState ->
             {:valid, userState}
         end, []}
      )

    otpcert = otp_cert(cert)
    reason = {:bad_cert, pathErr}

    try do
      verifyFun.(otpcert, reason, userstat0)
    catch
      _, _ ->
        {:error, reason}
    else
      {:valid, userstate} ->
        options = :proplists.delete(:verify_fun, options0)

        pkix_path_validation(otpcert, chain, [
          {:verify_fun, {verifyFun, userstate}}
          | options
        ])

      {:fail, userReason} ->
        {:error, userReason}
    end
  end

  def pkix_crls_validate(otpCert, [{_, _, _} | _] = dPAndCRLs, options) do
    pkix_crls_validate(
      otpCert,
      dPAndCRLs,
      dPAndCRLs,
      options,
      :pubkey_crl.init_revokation_state()
    )
  end

  def pkix_crls_validate(otpCert, dPAndCRLs0, options) do
    callBack =
      :proplists.get_value(:update_crl, options, fn _, currCRL ->
        currCRL
      end)

    dPAndCRLs = sort_dp_crls(dPAndCRLs0, callBack)

    pkix_crls_validate(
      otpCert,
      dPAndCRLs,
      dPAndCRLs,
      options,
      :pubkey_crl.init_revokation_state()
    )
  end

  def pkix_verify_hostname(cert, referenceIDs) do
    pkix_verify_hostname(cert, referenceIDs, [])
  end

  def pkix_verify_hostname_match_fun(:https) do
    fn
      {:dns_id, fQDN = [_ | _]}, {:dNSName, name = [_ | _]} ->
        verify_hostname_match_wildcard(fQDN, name)

      _, _ ->
        :default
    end
  end

  def short_name_hash({:rdnSequence, _Attributes} = name) do
    hashThis = encode_name_for_short_hash(name)
    <<hashValue::size(32)-little, _::binary>> = :crypto.hash(:sha, hashThis)

    :string.to_lower(
      :string.right(
        :erlang.integer_to_list(
          hashValue,
          16
        ),
        8,
        ?0
      )
    )
  end

  def pkix_test_data(%{client_chain: clientChain0, server_chain: serverChain0}) do
    default = %{intermediates: []}
    clientChain = :maps.merge(default, clientChain0)
    serverChain = :maps.merge(default, serverChain0)
    :pubkey_cert.gen_test_certs(%{client_chain: clientChain, server_chain: serverChain})
  end

  def pkix_test_data(%{} = chain) do
    default = %{intermediates: []}
    :pubkey_cert.gen_test_certs(:maps.merge(default, chain))
  end

  def pkix_test_root_cert(name, opts) do
    :pubkey_cert.root_cert(name, opts)
  end

  def pkix_ocsp_validate(derCert, issuerCert, ocspRespDer, responderCerts, nonceExt)
      when is_binary(derCert) do
    pkix_ocsp_validate(
      pkix_decode_cert(derCert, :otp),
      issuerCert,
      ocspRespDer,
      responderCerts,
      nonceExt
    )
  end

  def pkix_ocsp_validate(cert, derIssuerCert, ocspRespDer, responderCerts, nonceExt)
      when is_binary(derIssuerCert) do
    pkix_ocsp_validate(
      cert,
      pkix_decode_cert(derIssuerCert, :otp),
      ocspRespDer,
      responderCerts,
      nonceExt
    )
  end

  def pkix_ocsp_validate(cert, issuerCert, ocspRespDer, responderCerts, nonceExt) do
    ocspResponse = :pubkey_ocsp.decode_ocsp_response(ocspRespDer)

    ocspCertResponses =
      case ocspResponse do
        {:ok, basicOcspResponse = r_BasicOCSPResponse(certs: certs)} ->
          ocspResponseCerts =
            for c <- certs do
              otp_cert(c)
            end

          userResponderCerts =
            for c <- responderCerts do
              otp_cert(
                pkix_decode_cert(
                  c,
                  :plain
                )
              )
            end

          :pubkey_ocsp.verify_ocsp_response(
            basicOcspResponse,
            ocspResponseCerts ++ userResponderCerts,
            nonceExt
          )

        {:error, _} = error ->
          error
      end

    case ocspCertResponses do
      {:ok, responses} ->
        case :pubkey_ocsp.find_single_response(
               otp_cert(cert),
               otp_cert(issuerCert),
               responses
             ) do
          {:ok, r_SingleResponse(certStatus: certStatus)} ->
            :pubkey_ocsp.ocsp_status(certStatus)

          {:error, :no_matched_response = reason} ->
            {:bad_cert, {:revocation_status_undetermined, reason}}
        end

      {:error, reason} ->
        {:bad_cert, {:revocation_status_undetermined, reason}}
    end
  end

  def ocsp_extensions(nonce) do
    for extn <- [
          :pubkey_ocsp.get_nonce_extn(nonce),
          :pubkey_ocsp.get_acceptable_response_types_extn()
        ],
        :erlang.is_record(extn, :Extension) do
      extn
    end
  end

  def ocsp_responder_id(certDer) do
    :pubkey_ocsp.get_ocsp_responder_id(
      pkix_decode_cert(
        certDer,
        :plain
      )
    )
  end

  def cacerts_get() do
    :pubkey_os_cacerts.get()
  end

  def cacerts_load() do
    :pubkey_os_cacerts.load()
  end

  def cacerts_load(file) do
    :pubkey_os_cacerts.load([file])
  end

  def cacerts_clear() do
    :pubkey_os_cacerts.clear()
  end

  defp default_options([]) do
    [{:rsa_padding, :rsa_pkcs1_padding}]
  end

  defp default_options(opts) do
    case :proplists.get_value(:rsa_pad, opts) do
      :undefined ->
        case :proplists.get_value(:rsa_padding, opts) do
          :undefined ->
            case :lists.dropwhile(&:erlang.is_tuple/1, opts) do
              [pad | _] ->
                set_padding(pad, opts)

              [] ->
                set_padding(:rsa_pkcs1_padding, opts)
            end

          pad ->
            set_padding(pad, opts)
        end

      pad ->
        set_padding(pad, opts)
    end
  end

  defp set_padding(pad, opts) do
    [
      {:rsa_padding, pad}
      | for {t, v} <- opts, t !== :rsa_padding, t !== :rsa_pad do
          {t, v}
        end
    ]
  end

  defp format_pkix_sign_key({r_RSAPrivateKey() = key, _}) do
    key
  end

  defp format_pkix_sign_key(key) do
    key
  end

  defp do_pem_entry_encode(asn1Type, entity, cipherInfo, password) do
    der = der_encode(asn1Type, entity)
    decryptDer = :pubkey_pem.cipher(der, cipherInfo, password)
    {asn1Type, decryptDer, cipherInfo}
  end

  defp do_pem_entry_decode({asn1Type, _, _} = pemEntry, password) do
    der = :pubkey_pem.decipher(pemEntry, password)
    der_decode(asn1Type, der)
  end

  defp exists_duplicate_cert([]) do
    false
  end

  defp exists_duplicate_cert([cert, cert | _]) do
    true
  end

  defp exists_duplicate_cert([_ | rest]) do
    exists_duplicate_cert(rest)
  end

  defp path_validation(
         [],
         r_path_validation_state(
           working_public_key_algorithm: algorithm,
           working_public_key: publicKey,
           working_public_key_parameters: publicKeyParams,
           valid_policy_tree: tree
         )
       ) do
    validPolicyNodeSet0 = :pubkey_policy_tree.constrained_policy_node_set(tree)

    collectQualifiers = fn %{expected_policy_set: policySet} = node ->
      qF = fn policy ->
        :pubkey_policy_tree.collect_qualifiers(
          tree,
          policy
        )
      end

      qualifiers = :lists.flatmap(qF, policySet)
      Map.put(node, :qualifier_set, qualifiers)
    end

    validPolicyNodeSet =
      :lists.map(
        collectQualifiers,
        validPolicyNodeSet0
      )

    {:ok, {{algorithm, publicKey, publicKeyParams}, validPolicyNodeSet}}
  end

  defp path_validation(
         [derCert | rest],
         validationState = r_path_validation_state(max_path_length: len)
       )
       when len >= 0 do
    try do
      validate(
        derCert,
        r_path_validation_state(validationState, last_cert: rest === [])
      )
    catch
      reason ->
        {:error, reason}
    else
      r_path_validation_state() = newValidationState ->
        path_validation(rest, newValidationState)
    end
  end

  defp path_validation(
         [cert | _] = path,
         r_path_validation_state(
           user_state: userState0,
           verify_fun: verifyFun
         ) = validationState
       ) do
    reason = {:bad_cert, :max_path_length_reached}
    otpCert = otp_cert(cert)

    try do
      verifyFun.(otpCert, reason, userState0)
    catch
      _, _ ->
        {:error, reason}
    else
      {:valid, userState} ->
        path_validation(
          path,
          r_path_validation_state(validationState,
            max_path_length: 0,
            user_state: userState
          )
        )

      {:fail, _} ->
        {:error, reason}
    end
  end

  defp validate(
         cert,
         r_path_validation_state(
           working_issuer_name: issuer,
           working_public_key: key,
           working_public_key_parameters: keyParams,
           permitted_subtrees: permit,
           excluded_subtrees: exclude,
           last_cert: last,
           user_state: userState0,
           verify_fun: verifyFun
         ) = validationState0
       ) do
    otpCert = otp_cert(cert)

    {validationState1, userState1} =
      :pubkey_cert.validate_extensions(otpCert, validationState0, userState0, verifyFun)

    userState2 = :pubkey_cert.validate_time(otpCert, userState1, verifyFun)
    userState3 = :pubkey_cert.validate_issuer(otpCert, issuer, userState2, verifyFun)

    userState4 =
      :pubkey_cert.validate_names(otpCert, permit, exclude, last, userState3, verifyFun)

    userState5 =
      :pubkey_cert.validate_signature(
        otpCert,
        der_cert(cert),
        key,
        keyParams,
        userState4,
        verifyFun
      )

    userState =
      case last do
        false ->
          :pubkey_cert.verify_fun(otpCert, :valid, userState5, verifyFun)

        true ->
          :pubkey_cert.verify_fun(otpCert, :valid_peer, userState5, verifyFun)
      end

    validationState = r_path_validation_state(validationState1, user_state: userState)

    :pubkey_cert.prepare_for_next_cert(
      otpCert,
      validationState
    )
  end

  defp otp_cert(der) when is_binary(der) do
    pkix_decode_cert(der, :otp)
  end

  defp otp_cert(r_OTPCertificate() = cert) do
    cert
  end

  defp otp_cert(r_cert(otp: otpCert)) do
    otpCert
  end

  defp otp_cert(r_Certificate() = cert) do
    pkix_decode_cert(der_encode(:Certificate, cert), :otp)
  end

  defp der_cert(r_OTPCertificate() = cert) do
    pkix_encode(:OTPCertificate, cert, :otp)
  end

  defp der_cert(der) when is_binary(der) do
    der
  end

  defp der_cert(r_cert(der: derCert)) do
    derCert
  end

  defp pkix_crls_validate(_, [], _, options, r_revoke_state(details: details)) do
    case :proplists.get_value(:undetermined_details, options, false) do
      false ->
        {:bad_cert, :revocation_status_undetermined}

      true ->
        {:bad_cert, {:revocation_status_undetermined, {:bad_crls, format_details(details)}}}
    end
  end

  defp pkix_crls_validate(otpCert, [{dP, cRL, deltaCRL} | rest], all, options, revokedState0) do
    callBack =
      :proplists.get_value(:update_crl, options, fn _, currCRL ->
        currCRL
      end)

    case :pubkey_crl.fresh_crl(dP, cRL, callBack) do
      {:fresh, ^cRL} ->
        do_pkix_crls_validate(otpCert, [{dP, cRL, deltaCRL} | rest], all, options, revokedState0)

      {:fresh, newCRL} ->
        newAll = [{dP, newCRL, deltaCRL} | all -- [{dP, cRL, deltaCRL}]]

        do_pkix_crls_validate(
          otpCert,
          [{dP, newCRL, deltaCRL} | rest],
          newAll,
          options,
          revokedState0
        )

      :no_fresh_crl ->
        pkix_crls_validate(otpCert, rest, all, options, revokedState0)
    end
  end

  defp do_pkix_crls_validate(otpCert, [{dP, cRL, deltaCRL} | rest], all, options, revokedState0) do
    otherDPCRLs = all -- [{dP, cRL, deltaCRL}]

    case :pubkey_crl.validate(otpCert, otherDPCRLs, dP, cRL, deltaCRL, options, revokedState0) do
      {:undetermined, :unrevoked, r_revoke_state(details: details)}
      when rest == [] ->
        case :proplists.get_value(:undetermined_details, options, false) do
          false ->
            {:bad_cert, :revocation_status_undetermined}

          true ->
            {:bad_cert, {:revocation_status_undetermined, {:bad_crls, details}}}
        end

      {:undetermined, :unrevoked, revokedState}
      when rest !== [] ->
        pkix_crls_validate(otpCert, rest, all, options, revokedState)

      {:finished, :unrevoked} ->
        :valid

      {:finished, status} ->
        {:bad_cert, status}
    end
  end

  defp sort_dp_crls(dpsAndCrls, freshCB) do
    sort_crls(:maps.to_list(:lists.foldl(&group_dp_crls/2, %{}, dpsAndCrls)), freshCB, [])
  end

  defp group_dp_crls({dP, cRL}, m) do
    case m do
      %{^dP => cRLs} ->
        %{m | dP => [cRL | cRLs]}

      _ ->
        Map.put(m, dP, [cRL])
    end
  end

  defp sort_crls([], _, acc) do
    acc
  end

  defp sort_crls([{dP, allCRLs} | rest], freshCB, acc) do
    {deltaCRLs, cRLs} = do_sort_crls(allCRLs)
    dpsAndCRLs = combine(cRLs, deltaCRLs, dP, freshCB, [])
    sort_crls(rest, freshCB, dpsAndCRLs ++ acc)
  end

  defp do_sort_crls(cRLs) do
    :lists.partition(
      fn {_, cRL} ->
        :pubkey_crl.is_delta_crl(cRL)
      end,
      cRLs
    )
  end

  defp combine([], _, _, _, acc) do
    acc
  end

  defp combine([{_, cRL} = entry | cRLs], deltaCRLs, dP, freshCB, acc) do
    deltaCRL = combine(cRL, deltaCRLs)

    case :pubkey_crl.fresh_crl(dP, deltaCRL, freshCB) do
      :no_fresh_crl ->
        combine(cRLs, deltaCRLs, dP, freshCB, [{dP, entry, {:undefined, :undefined}} | acc])

      {:fresh, newDeltaCRL} ->
        combine(cRLs, deltaCRLs, dP, freshCB, [{dP, entry, newDeltaCRL} | acc])
    end
  end

  defp combine(cRL, deltaCRLs) do
    deltas =
      :lists.filter(
        fn {_, deltaCRL} ->
          :pubkey_crl.combines(cRL, deltaCRL)
        end,
        deltaCRLs
      )

    case deltas do
      [] ->
        {:undefined, :undefined}

      [delta] ->
        delta

      [_, _ | _] ->
        fun = fn {_, r_CertificateList(tbsCertList: firstTBSCRL)} = cRL1,
                 {_, r_CertificateList(tbsCertList: secondTBSCRL)} = cRL2 ->
          time1 = :pubkey_cert.time_str_2_gregorian_sec(r_TBSCertList(firstTBSCRL, :thisUpdate))
          time2 = :pubkey_cert.time_str_2_gregorian_sec(r_TBSCertList(secondTBSCRL, :thisUpdate))

          case time1 > time2 do
            true ->
              cRL1

            false ->
              cRL2
          end
        end

        :lists.foldl(fun, hd(deltas), tl(deltas))
    end
  end

  defp format_rsa_private_key(
         r_RSAPrivateKey(
           modulus: n,
           publicExponent: e,
           privateExponent: d,
           prime1: p1,
           prime2: p2,
           exponent1: e1,
           exponent2: e2,
           coefficient: c
         )
       )
       when is_integer(n) and is_integer(e) and
              is_integer(d) and is_integer(p1) and is_integer(p2) and
              is_integer(e1) and is_integer(e2) and is_integer(c) do
    [e, n, d, p1, p2, e1, e2, c]
  end

  defp format_rsa_private_key(r_RSAPrivateKey(modulus: n, publicExponent: e, privateExponent: d))
       when is_integer(n) and is_integer(e) and
              is_integer(d) do
    [e, n, d]
  end

  defp ec_generate_key(params) do
    curve = ec_curve_spec(params)
    curveType = ec_curve_type(curve)
    term = :crypto.generate_key(curveType, curve)
    normParams = ec_normalize_params(params)
    ec_key(term, normParams)
  end

  defp ec_normalize_params({:namedCurve, name}) when is_atom(name) do
    {:namedCurve, :pubkey_cert_records.namedCurves(name)}
  end

  defp ec_normalize_params(r_ECParameters() = eCParams) do
    {:ecParameters, eCParams}
  end

  defp ec_normalize_params(other) do
    other
  end

  defp ec_curve_spec(
         r_ECParameters(
           fieldID:
             r_FieldID(
               fieldType: type,
               parameters: params
             ),
           curve: pCurve,
           base: base,
           order: order,
           cofactor: coFactor
         )
       ) do
    field =
      format_field(
        :pubkey_cert_records.supportedCurvesTypes(type),
        params
      )

    curve = {r_Curve(pCurve, :a), r_Curve(pCurve, :b), :none}
    {field, curve, base, order, coFactor}
  end

  defp ec_curve_spec({:ecParameters, eCParams}) do
    ec_curve_spec(eCParams)
  end

  defp ec_curve_spec({:namedCurve, oID})
       when is_tuple(oID) and
              is_integer(:erlang.element(1, oID)) do
    ec_curve_spec({:namedCurve, :pubkey_cert_records.namedCurves(oID)})
  end

  defp ec_curve_spec({:namedCurve, :x25519 = name}) do
    name
  end

  defp ec_curve_spec({:namedCurve, :x448 = name}) do
    name
  end

  defp ec_curve_spec({:namedCurve, :ed25519 = name}) do
    name
  end

  defp ec_curve_spec({:namedCurve, :ed448 = name}) do
    name
  end

  defp ec_curve_spec({:namedCurve, name}) when is_atom(name) do
    name
  end

  defp ec_curve_type(:ed25519) do
    :eddsa
  end

  defp ec_curve_type(:ed448) do
    :eddsa
  end

  defp ec_curve_type(:x25519) do
    :eddh
  end

  defp ec_curve_type(:x448) do
    :eddh
  end

  defp ec_curve_type(_) do
    :ecdh
  end

  defp format_field(:characteristic_two_field = type, params0) do
    r_Characteristic_two(m: m, basis: basisOid, parameters: params) =
      der_decode(:"Characteristic-two", params0)

    {type, m, field_param_decode(basisOid, params)}
  end

  defp format_field(:prime_field, params0) do
    prime = der_decode(:"Prime-p", params0)
    {:prime_field, prime}
  end

  defp ec_key({pubKey, privateKey}, params) do
    r_ECPrivateKey(version: 1, privateKey: privateKey, parameters: params, publicKey: pubKey)
  end

  defp encode_name_for_short_hash({:rdnSequence, attributes0}) do
    attributes =
      :lists.map(
        &normalise_attribute/1,
        attributes0
      )

    {encoded, _} =
      :OTP - PUB -
        KEY.enc_RDNSequence(
          attributes,
          []
        )

    encoded
  end

  defp normalise_attribute([r_AttributeTypeAndValue(type: _Type, value: binary) = aTV])
       when is_binary(binary) do
    case :pubkey_cert_records.transform(aTV, :decode) do
      r_AttributeTypeAndValue(value: ^binary) ->
        [aTV]

      decodedATV = r_AttributeTypeAndValue() ->
        normalise_attribute([decodedATV])
    end
  end

  defp normalise_attribute([
         r_AttributeTypeAndValue(
           type: _Type,
           value: {encoding, string}
         ) = aTV
       ])
       when encoding === :utf8String or
              encoding === :printableString or
              encoding === :teletexString or
              encoding === :ia5String do
    newValue = normalise_attribute_value(string)
    [r_AttributeTypeAndValue(aTV, value: newValue)]
  end

  defp normalise_attribute([r_AttributeTypeAndValue(type: _Type, value: string) = aTV])
       when is_list(string) do
    newValue = normalise_attribute_value(string)
    [r_AttributeTypeAndValue(aTV, value: newValue)]
  end

  defp normalise_attribute_value(string) do
    converted = :unicode.characters_to_binary(string)
    normalisedString = normalise_string(converted)

    {newBinary, _} =
      :OTP - PUB -
        KEY.enc_X520CommonName(
          {:utf8String, normalisedString},
          []
        )

    newBinary
  end

  defp normalise_string(string) do
    trimmedLeft = :re.replace(string, ~c"^[ \f\n\r\t\v]+", ~c"", [:unicode, :global])
    trimmedRight = :re.replace(trimmedLeft, ~c"[ \f\n\r\t\v]+$", ~c"", [:unicode, :global])
    collapsed = :re.replace(trimmedRight, ~c"[ \f\n\r\t\v]+", ~c" ", [:unicode, :global])
    lower = ascii_to_lower(collapsed)
    lower
  end

  defp ascii_to_lower(string) do
    for <<(<<c>> <- :erlang.iolist_to_binary(string))>>, into: <<>> do
      <<cond do
          ?A <= c and c <= ?Z ->
            c + (?a - ?A)

          true ->
            c
        end>>
    end
  end

  defp verify_hostname_extract_fqdn_default({:dns_id, s}) do
    s
  end

  defp verify_hostname_extract_fqdn_default({:uri_id, uRI}) do
    %{scheme: ~c"https", host: host} =
      :uri_string.normalize(
        uRI,
        [:return_map]
      )

    host
  end

  defp verify_hostname_fqnds(l, fqdnFun) do
    for e0 <- l,
        e <- [
          try do
            case fqdnFun.(e0) do
              :default ->
                verify_hostname_extract_fqdn_default(e0)

              :undefined ->
                :undefined

              other ->
                other
            end
          catch
            _, _ ->
              :undefined
          end
        ],
        is_list(e),
        e !== ~c"",
        {:error, :einval} == :inet.parse_address(e) do
      e
    end
  end

  defp verify_hostname_match_default(ref, pres) do
    verify_hostname_match_default0(
      to_lower_ascii(ref),
      to_lower_ascii(pres)
    )
  end

  defp verify_hostname_match_default0(fQDN = [_ | _], {:cn, fQDN}) do
    not :lists.member(?*, fQDN)
  end

  defp verify_hostname_match_default0(fQDN = [_ | _], {:cn, name = [_ | _]}) do
    verify_hostname_match_wildcard(fQDN, name)
  end

  defp verify_hostname_match_default0({:dns_id, r}, {:dNSName, p}) do
    r == p
  end

  defp verify_hostname_match_default0(
         {:uri_id, r},
         {:uniformResourceIdentifier, p}
       ) do
    r == p
  end

  defp verify_hostname_match_default0({:ip, r}, {:iPAddress, p})
       when length(p) == 4 do
    try do
      :erlang.list_to_tuple(p) ==
        cond do
          tuple_size(r) == 4 ->
            r

          is_list(r) ->
            ok(:inet.parse_ipv4strict_address(r))
        end
    catch
      _, _ ->
        false
    end
  end

  defp verify_hostname_match_default0({:ip, r}, {:iPAddress, p})
       when length(p) == 16 do
    try do
      l16_to_tup(p) ==
        cond do
          tuple_size(r) == 8 ->
            r

          is_list(r) ->
            ok(:inet.parse_ipv6strict_address(r))
        end
    catch
      _, _ ->
        false
    end
  end

  defp verify_hostname_match_default0({:srv_id, r}, {:srvName, p}) do
    r == p
  end

  defp verify_hostname_match_default0(
         {:srv_id, r},
         {{1, 3, 6, 1, 4, 1, 434, 2, 2, 1, 37, 0}, p}
       ) do
    r == p
  end

  defp verify_hostname_match_default0(_, _) do
    false
  end

  defp verify_hostname_match_wildcard(fQDN, name) do
    [f1 | fs] = :string.split(to_lower_ascii(fQDN), ~c".")
    [n1 | ns] = :string.split(to_lower_ascii(name), ~c".")
    match_wild(f1, n1) and fs == ns
  end

  defp ok({:ok, x}) do
    x
  end

  defp l16_to_tup(l) do
    :erlang.list_to_tuple(l16_to_tup(l, []))
  end

  defp l16_to_tup([a, b | t], acc) do
    l16_to_tup(t, [a <<< 8 ||| b | acc])
  end

  defp l16_to_tup([], acc) do
    :lists.reverse(acc)
  end

  defp match_wild(a, [?* | b]) do
    match_wild_suffixes(a, b)
  end

  defp match_wild([c | a], [c | b]) do
    match_wild(a, b)
  end

  defp match_wild([], []) do
    true
  end

  defp match_wild(_, _) do
    false
  end

  defp match_wild_suffixes(a, b) do
    match_wild_sfx(:lists.reverse(a), :lists.reverse(b))
  end

  defp match_wild_sfx([?* | _], _) do
    false
  end

  defp match_wild_sfx(_, [?* | _]) do
    false
  end

  defp match_wild_sfx([a | ar], [a | br]) do
    match_wild_sfx(ar, br)
  end

  defp match_wild_sfx(ar, []) do
    not :lists.member(?*, ar)
  end

  defp match_wild_sfx(_, _) do
    false
  end

  defp verify_hostname_match_loop(refs0, pres0, :undefined, failCB, cert) do
    pres = :lists.map(&to_lower_ascii/1, pres0)
    refs = :lists.map(&to_lower_ascii/1, refs0)

    :lists.any(
      fn r ->
        :lists.any(
          fn p ->
            verify_hostname_match_default(
              r,
              p
            ) or failCB.(cert)
          end,
          pres
        )
      end,
      refs
    )
  end

  defp verify_hostname_match_loop(refs, pres, matchFun, failCB, cert) do
    :lists.any(
      fn r ->
        :lists.any(
          fn p ->
            case matchFun.(r, p) do
              :default ->
                verify_hostname_match_default(r, p)

              bool ->
                bool
            end or failCB.(cert)
          end,
          pres
        )
      end,
      refs
    )
  end

  defp to_lower_ascii({:ip, _} = x) do
    x
  end

  defp to_lower_ascii({:iPAddress, _} = x) do
    x
  end

  defp to_lower_ascii(s) when is_list(s) do
    :lists.map(&to_lower_ascii/1, s)
  end

  defp to_lower_ascii({t, s}) do
    {t, to_lower_ascii(s)}
  end

  defp to_lower_ascii(c) when ?A <= c and c <= ?Z do
    c + (?a - ?A)
  end

  defp to_lower_ascii(c) do
    c
  end

  defp to_string(s) when is_list(s) do
    s
  end

  defp to_string(b) when is_binary(b) do
    :erlang.binary_to_list(b)
  end

  defp to_string(x) do
    x
  end

  defp format_details([]) do
    :no_relevant_crls
  end

  defp format_details(details) do
    details
  end

  defp subject_public_key_info(alg, pubKey) do
    r_OTPSubjectPublicKeyInfo(algorithm: alg, subjectPublicKey: pubKey)
  end

  def handle_trace(
        :csp,
        {:call, {:public_key, :ocsp_responder_id, [cert]}},
        stack
      ) do
    {:io_lib.format(~c"pkix_decode_cert(Cert, plain) = ~W", [cert, 5]), stack}
  end

  def handle_trace(
        :csp,
        {:return_from, {:public_key, :ocsp_responder_id, 1}, return},
        stack
      ) do
    {:io_lib.format(~c"OCSP Responder ID = ~P", [return, 10]), stack}
  end

  def handle_trace(
        :crt,
        {:call, {:public_key, :pkix_decode_cert, [cert, _Type]}},
        stack
      ) do
    {:io_lib.format(~c"Cert = ~W", [cert, 5]), stack}
  end

  def handle_trace(
        :csp,
        {:call, {:public_key, :pkix_ocsp_validate, [cert, issuerCert | _]}},
        stack
      ) do
    {:io_lib.format(~c"#2 OCSP validation started~nCert = ~W IssuerCert = ~W", [
       cert,
       7,
       issuerCert,
       7
     ]), stack}
  end

  def handle_trace(:csp, {:call, {:public_key, :otp_cert, [cert]}}, stack) do
    {:io_lib.format(~c"Cert = ~W", [cert, 5]), stack}
  end

  def handle_trace(
        :csp,
        {:return_from, {:public_key, :pkix_ocsp_validate, 5}, return},
        stack
      ) do
    {:io_lib.format(~c"#2 OCSP validation result = ~p", [return]), stack}
  end
end
