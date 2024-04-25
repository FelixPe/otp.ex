defmodule :m_pubkey_ocsp do
  use Bitwise
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

  def get_ocsp_responder_id(r_Certificate(tbsCertificate: tbsCert)) do
    :public_key.der_encode(
      :ResponderID,
      {:byName, r_TBSCertificate(tbsCert, :subject)}
    )
  end

  def verify_ocsp_response(oCSPResponse, responderCerts, nonce) do
    do_verify_ocsp_response(oCSPResponse, responderCerts, nonce)
  end

  def find_single_response(cert, issuerCert, singleResponseList) do
    issuerName = get_subject_name(issuerCert)
    issuerKey = get_public_key(issuerCert)
    serialNum = get_serial_num(cert)
    match_single_response(issuerName, issuerKey, serialNum, singleResponseList)
  end

  def ocsp_status({:good, _}) do
    :valid
  end

  def ocsp_status({:unknown, reason}) do
    {:bad_cert, {:revocation_status_undetermined, reason}}
  end

  def ocsp_status({:revoked, reason}) do
    {:bad_cert, {:revoked, reason}}
  end

  def decode_ocsp_response(responseDer) do
    resp =
      :public_key.der_decode(
        :OCSPResponse,
        responseDer
      )

    case r_OCSPResponse(resp, :responseStatus) do
      :successful ->
        decode_response_bytes(r_OCSPResponse(resp, :responseBytes))

      error ->
        {:error, error}
    end
  end

  defp match_single_response(_IssuerName, _IssuerKey, _SerialNum, []) do
    {:error, :no_matched_response}
  end

  defp match_single_response(issuerName, issuerKey, serialNum, [
         r_SingleResponse(certID: r_CertID(hashAlgorithm: algo) = certID) = response
         | responses
       ]) do
    hashType = :public_key.pkix_hash_type(r_AlgorithmIdentifier(algo, :algorithm))

    case serialNum == r_CertID(certID, :serialNumber) and
           :crypto.hash(
             hashType,
             issuerName
           ) == r_CertID(certID, :issuerNameHash) and
           :crypto.hash(
             hashType,
             issuerKey
           ) == r_CertID(certID, :issuerKeyHash) do
      true ->
        {:ok, response}

      false ->
        match_single_response(issuerName, issuerKey, serialNum, responses)
    end
  end

  defp get_serial_num(r_OTPCertificate(tbsCertificate: tbsCert)) do
    r_OTPTBSCertificate(tbsCert, :serialNumber)
  end

  defp do_verify_ocsp_response(
         r_BasicOCSPResponse(
           tbsResponseData: responseData,
           signatureAlgorithm: signatureAlgo,
           signature: signature
         ),
         responderCerts,
         nonce
       ) do
    r_ResponseData(responderID: responderID) = responseData

    case verify_ocsp_signature(
           :public_key.der_encode(
             :ResponseData,
             responseData
           ),
           r_AlgorithmIdentifier(signatureAlgo, :algorithm),
           signature,
           responderCerts,
           responderID
         ) do
      :ok ->
        verify_ocsp_nonce(responseData, nonce)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp verify_ocsp_nonce(responseData, nonce) do
    r_ResponseData(
      responses: responses,
      responseExtensions: responseExtns
    ) = responseData

    case get_nonce_value(responseExtns) do
      ^nonce ->
        {:ok, responses}

      _Other ->
        {:error, :nonce_mismatch}
    end
  end

  defp verify_ocsp_signature(responseDataDer, signatureAlgo, signature, certs, responderID) do
    case find_responder_cert(responderID, certs) do
      {:ok, cert} ->
        do_verify_ocsp_signature(responseDataDer, signature, signatureAlgo, cert)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp find_responder_cert(_ResponderID, []) do
    {:error, :ocsp_responder_cert_not_found}
  end

  defp find_responder_cert(responderID, [cert | tCerts]) do
    case is_responder(responderID, cert) do
      true ->
        {:ok, cert}

      false ->
        find_responder_cert(responderID, tCerts)
    end
  end

  defp do_verify_ocsp_signature(responseDataDer, signature, algorithmID, cert) do
    {digestType, _SignatureType} = :public_key.pkix_sign_types(algorithmID)

    case :public_key.verify(responseDataDer, digestType, signature, get_public_key_rec(cert)) do
      true ->
        :ok

      false ->
        {:error, :ocsp_response_bad_signature}
    end
  end

  defp get_public_key_rec(r_OTPCertificate(tbsCertificate: tbsCert)) do
    pKInfo = r_OTPTBSCertificate(tbsCert, :subjectPublicKeyInfo)
    r_OTPSubjectPublicKeyInfo(pKInfo, :subjectPublicKey)
  end

  defp is_responder({:byName, name}, cert) do
    :public_key.der_encode(
      :Name,
      name
    ) == get_subject_name(cert)
  end

  defp is_responder({:byKey, key}, cert) do
    key == :crypto.hash(:sha, get_public_key(cert))
  end

  defp get_subject_name(r_OTPCertificate(tbsCertificate: tbsCert)) do
    :public_key.pkix_encode(:Name, r_OTPTBSCertificate(tbsCert, :subject), :otp)
  end

  defp get_public_key(r_OTPCertificate(tbsCertificate: tbsCert)) do
    pKInfo = r_OTPTBSCertificate(tbsCert, :subjectPublicKeyInfo)
    enc_pub_key(r_OTPSubjectPublicKeyInfo(pKInfo, :subjectPublicKey))
  end

  defp enc_pub_key(key = r_RSAPublicKey()) do
    :public_key.der_encode(:RSAPublicKey, key)
  end

  defp enc_pub_key({dsaInt, r_Dss_Parms()}) when is_integer(dsaInt) do
    :public_key.der_encode(:DSAPublicKey, dsaInt)
  end

  defp enc_pub_key({r_ECPoint(point: key), _ECParam}) do
    key
  end

  def handle_trace(
        :csp,
        {:call, {:pubkey_ocsp, :do_verify_ocsp_response, [basicOcspResponse | _]}},
        stack
      ) do
    r_BasicOCSPResponse(
      tbsResponseData:
        r_ResponseData(
          responderID: responderID,
          producedAt: producedAt
        )
    ) = basicOcspResponse

    {:io_lib.format(~c"ResponderId = ~W producedAt = ~p", [responderID, 5, producedAt]), stack}
  end

  def handle_trace(
        :csp,
        {:call,
         {:pubkey_ocsp, :match_single_response,
          [
            _IssuerName,
            _IssuerKey,
            _SerialNum,
            [
              r_SingleResponse(
                thisUpdate: thisUpdate,
                nextUpdate: nextUpdate
              )
            ]
          ]}},
        stack
      ) do
    {:io_lib.format(~c"ThisUpdate = ~p NextUpdate = ~p", [thisUpdate, nextUpdate]), stack}
  end

  def handle_trace(
        :csp,
        {:call, {:pubkey_ocsp, :is_responder, [id, cert]}},
        stack
      ) do
    {:io_lib.format(~c"~nId = ~P~nCert = ~P", [id, 10, cert, 10]), stack}
  end

  def handle_trace(
        :csp,
        {:call, {:pubkey_ocsp, :find_single_response, [cert, issuerCert | _]}},
        stack
      ) do
    {:io_lib.format(~c"#2 OCSP validation started~nCert = ~W IssuerCert = ~W", [
       cert,
       7,
       issuerCert,
       7
     ]), stack}
  end

  def handle_trace(
        :csp,
        {:return_from, {:pubkey_ocsp, :is_responder, 2}, return},
        stack
      ) do
    {:io_lib.format(~c"Return = ~p", [return]), stack}
  end
end
