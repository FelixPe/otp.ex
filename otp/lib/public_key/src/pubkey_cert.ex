defmodule :m_pubkey_cert do
  use Bitwise
  require Record
  Record.defrecord(:r_SubjectPublicKeyInfoAlgorithm, :SubjectPublicKeyInfoAlgorithm, algorithm: :undefined,
                                                         parameters: :asn1_NOVALUE)
  Record.defrecord(:r_path_validation_state, :path_validation_state, valid_policy_tree: :undefined,
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
                                                 user_state: :undefined)
  Record.defrecord(:r_revoke_state, :revoke_state, reasons_mask: :undefined,
                                        cert_status: :undefined,
                                        interim_reasons_mask: :undefined,
                                        valid_ext: :undefined,
                                        details: :undefined)
  Record.defrecord(:r_ECPoint, :ECPoint, point: :undefined)
  Record.defrecord(:r_cert, :cert, der: :undefined,
                                otp: :undefined)
  def validate_extensions(otpCert, validationState0, userState0,
           verifyFun) do
    tBSCert = r_OTPCertificate(otpCert, :tbsCertificate)
    case (r_OTPTBSCertificate(tBSCert, :version)) do
      n when n >= 3 ->
        extensions = r_OTPTBSCertificate(tBSCert, :extensions)
        validate_extensions(otpCert, extensions,
                              validationState0, :no_basic_constraint,
                              is_self_signed(otpCert), userState0, verifyFun)
      _ ->
        {validationState0, userState0}
    end
  end

  defp validate_policy_tree(otpCert,
            r_path_validation_state(explicit_policy: explicitPolicyConstraint,
                valid_policy_tree: tree, user_state: userState0,
                verify_fun: verifyFun) = validationState) do
    case (explicitPolicyConstraint > 0 or not
                                          :pubkey_policy_tree.is_empty(tree)) do
      true ->
        validationState
      false ->
        userState = verify_fun(otpCert,
                                 {:bad_cert,
                                    {:policy_requirement_not_met,
                                       {{:explicit_policy,
                                           explicitPolicyConstraint},
                                          {:policy_set,
                                             :pubkey_policy_tree.constrained_policy_node_set(tree)}}}},
                                 userState0, verifyFun)
        r_path_validation_state(validationState, user_state: userState)
    end
  end

  def validate_time(otpCert, userState, verifyFun) do
    case (parse_and_check_validity_dates(otpCert)) do
      :expired ->
        verify_fun(otpCert, {:bad_cert, :cert_expired},
                     userState, verifyFun)
      :error ->
        verify_fun(otpCert,
                     {:bad_cert, :invalid_validity_dates}, userState,
                     verifyFun)
      :ok ->
        userState
    end
  end

  defp parse_and_check_validity_dates(otpCert) do
    tBSCert = r_OTPCertificate(otpCert, :tbsCertificate)
    {:Validity, notBeforeStr,
       notAfterStr} = r_OTPTBSCertificate(tBSCert, :validity)
    now = :calendar.datetime_to_gregorian_seconds(:calendar.universal_time())
    try do
      notBefore = time_str_2_gregorian_sec(:notBefore,
                                             notBeforeStr)
      notAfter = time_str_2_gregorian_sec(:notAfter,
                                            notAfterStr)
      cond do
        notBefore <= now and now <= notAfter ->
          :ok
        true ->
          :expired
      end
    catch
      :error, :function_clause ->
        :error
    end
  end

  def validate_issuer(otpCert, issuer, userState, verifyFun) do
    tBSCert = r_OTPCertificate(otpCert, :tbsCertificate)
    case (is_issuer(issuer, r_OTPTBSCertificate(tBSCert, :issuer))) do
      true ->
        userState
      _ ->
        verify_fun(otpCert, {:bad_cert, :invalid_issuer},
                     userState, verifyFun)
    end
  end

  def validate_signature(otpCert, derCert, key, keyParams, userState,
           verifyFun) do
    case (verify_signature(otpCert, derCert, key,
                             keyParams)) do
      true ->
        userState
      false ->
        verify_fun(otpCert, {:bad_cert, :invalid_signature},
                     userState, verifyFun)
    end
  end

  def verify_data(derCert) do
    {:ok,
       otpCert} = :pubkey_cert_records.decode_cert(derCert)
    extract_verify_data(otpCert, derCert)
  end

  def verify_fun(otpcert, result, userState0, verifyFun) do
    case (verifyFun.(otpcert, result, userState0)) do
      {:valid, userState} ->
        userState
      {:valid_peer, userState} ->
        userState
      {:fail, reason} ->
        case (reason) do
          {:bad_cert, _} ->
            throw(reason)
          _ ->
            throw({:bad_cert, reason})
        end
      {:unknown, userState} ->
        case (result) do
          {:extension, r_Extension(critical: true)} ->
            throw({:bad_cert, :unknown_critical_extension})
          _ ->
            userState
        end
    end
  end

  def prepare_for_next_cert(otpCert,
           r_path_validation_state(policy_mapping_ext: ext) = validationState0)
      when ext !== :undefined do
    validationState1 = handle_policy_mappings(otpCert,
                                                validationState0)
    validationState = r_path_validation_state(validationState1, policy_mapping_ext: :undefined, 
                                            current_any_policy_qualifiers: :undefined)
    prepare_for_next_cert(otpCert, validationState)
  end

  def prepare_for_next_cert(otpCert,
           r_path_validation_state(working_public_key_algorithm: prevAlgo,
               working_public_key_parameters: prevParams,
               cert_num: certNum,
               explicit_policy: explicitPolicyConstraint,
               inhibit_policy_mapping: policyMappingConstraint,
               inhibit_any_policy: anyPolicyConstraint) = validationState0) do
    tBSCert = r_OTPCertificate(otpCert, :tbsCertificate)
    issuer = r_OTPTBSCertificate(tBSCert, :subject)
    {algorithm, publicKey,
       publicKeyParams0} = public_key_info(r_OTPTBSCertificate(tBSCert, :subjectPublicKeyInfo),
                                             validationState0)
    publicKeyParams = (case (publicKeyParams0) do
                         :NULL when algorithm === prevAlgo ->
                           prevParams
                         :asn1_NOVALUE when algorithm === prevAlgo ->
                           prevParams
                         _ ->
                           publicKeyParams0
                       end)
    isSelfSigned = is_self_signed(otpCert)
    validationState1 = r_path_validation_state(validationState0, working_public_key_algorithm: algorithm, 
                                             working_public_key: publicKey, 
                                             working_public_key_parameters: publicKeyParams, 
                                             working_issuer_name: issuer, 
                                             cert_num: certNum + 1, 
                                             policy_ext_present: false, 
                                             valid_policy_tree: assert_valid_policy_tree(r_path_validation_state(validationState0, :explicit_policy),
                                                                                           r_path_validation_state(validationState0, :policy_ext_present),
                                                                                           r_path_validation_state(validationState0, :valid_policy_tree)), 
                                             current_any_policy_qualifiers: :undefined, 
                                             policy_ext_any: :undefined, 
                                             explicit_policy: maybe_decrement(explicitPolicyConstraint,
                                                                                isSelfSigned), 
                                             inhibit_policy_mapping: maybe_decrement(policyMappingConstraint,
                                                                                       isSelfSigned), 
                                             inhibit_any_policy: maybe_decrement(anyPolicyConstraint,
                                                                                   isSelfSigned))
    validationState2 = handle_policy_constraints(validationState1)
    validationState = handle_inhibit_anypolicy(validationState2)
    handle_last_cert(otpCert, validationState)
  end

  def normalize_general_name({:rdnSequence, issuer}) do
    normIssuer = do_normalize_general_name(issuer)
    {:rdnSequence, normIssuer}
  end

  def is_self_signed(r_OTPCertificate(tbsCertificate: r_OTPTBSCertificate(issuer: issuer,
                               subject: subject))) do
    is_issuer(issuer, subject)
  end

  def is_issuer({:rdnSequence, _} = issuer,
           {:rdnSequence, _} = candidate) do
    {:rdnSequence,
       issuerDirName} = normalize_general_name(issuer)
    {:rdnSequence,
       candidateDirName} = normalize_general_name(candidate)
    is_dir_name(issuerDirName, candidateDirName, true)
  end

  def subject_id(otpcert) do
    tBSCert = r_OTPCertificate(otpcert, :tbsCertificate)
    subject = r_OTPTBSCertificate(tBSCert, :subject)
    serialNr = r_OTPTBSCertificate(tBSCert, :serialNumber)
    {serialNr, normalize_general_name(subject)}
  end

  def is_fixed_dh_cert(r_OTPCertificate(tbsCertificate: r_OTPTBSCertificate(subjectPublicKeyInfo: subjectPublicKeyInfo,
                               extensions: extensions))) do
    is_fixed_dh_cert(subjectPublicKeyInfo,
                       extensions_list(extensions))
  end

  def match_name(:rfc822Name, name, [permittedName | rest]) do
    match_name(&is_valid_host_or_domain/2, name,
                 permittedName, rest)
  end

  def match_name(:directoryName, dirName,
           [permittedName | rest]) do
    match_name(&is_rdnSeq/2, dirName, permittedName, rest)
  end

  def match_name(:uniformResourceIdentifier, uRI,
           [permittedName | rest]) do
    case (:uri_string.normalize(uRI, [:return_map])) do
      %{host: host} ->
        pN = (case (:uri_string.normalize(permittedName,
                                            [:return_map])) do
                %{host: pNhost} ->
                  pNhost
                _X ->
                  permittedName
              end)
        match_name(&is_valid_host_or_domain/2, host, pN, rest)
      _ ->
        false
    end
  end

  def match_name(:emailAddress, name, [permittedName | rest]) do
    fun = fn email, permittedEmail ->
               is_valid_email_address(email, permittedEmail,
                                        :string.tokens(permittedEmail, '@'))
          end
    match_name(fun, name, permittedName, rest)
  end

  def match_name(:dNSName, name, [permittedName | rest]) do
    fun = fn domain, [?. | domain] ->
               true
             name1, name2 ->
               is_suffix(name2, name1)
          end
    match_name(fun, name, [?. | permittedName], rest)
  end

  def match_name(:x400Address, orAddress,
           [permittedAddr | rest]) do
    match_name(&is_or_address/2, orAddress, permittedAddr,
                 rest)
  end

  def match_name(:ipAdress, iP, [permittedIP | rest]) do
    fun = fn [iP1, iP2, iP3, iP4],
               [iP5, iP6, iP7, iP8, m1, m2, m3, m4] ->
               is_permitted_ip([iP1, iP2, iP3, iP4],
                                 [iP5, iP6, iP7, iP8], [m1, m2, m3, m4])
             [iP1, iP2, iP3, iP4, iP5, iP6, iP7, iP8, iP9, iP10,
                                                               iP11, iP12, iP13,
                                                                               iP14,
                                                                                   iP15,
                                                                                       iP16],
               [iP17, iP18, iP19, iP20, iP21, iP22, iP23, iP24, iP25,
                                                                    iP26, iP27,
                                                                              iP28,
                                                                                  iP29,
                                                                                      iP30,
                                                                                          iP31,
                                                                                              iP32,
                                                                                                  m1,
                                                                                                      m2,
                                                                                                          m3,
                                                                                                              m4,
                                                                                                                  m5,
                                                                                                                      m6,
                                                                                                                          m7,
                                                                                                                              m8,
                                                                                                                                  m9,
                                                                                                                                      m10,
                                                                                                                                          m11,
                                                                                                                                              m12,
                                                                                                                                                  m13,
                                                                                                                                                      m14,
                                                                                                                                                          m15,
                                                                                                                                                              m16] ->
               is_permitted_ip([iP1, iP2, iP3, iP4, iP5, iP6, iP7, iP8,
                                                                       iP9,
                                                                           iP10,
                                                                               iP11,
                                                                                   iP12,
                                                                                       iP13,
                                                                                           iP14,
                                                                                               iP15,
                                                                                                   iP16],
                                 [iP17, iP18, iP19, iP20, iP21, iP22, iP23,
                                                                          iP24,
                                                                              iP25,
                                                                                  iP26,
                                                                                      iP27,
                                                                                          iP28,
                                                                                              iP29,
                                                                                                  iP30,
                                                                                                      iP31,
                                                                                                          iP32],
                                 [m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11,
                                                                               m12,
                                                                                   m13,
                                                                                       m14,
                                                                                           m15,
                                                                                               m16])
             _, _ ->
               false
          end
    match_name(fun, iP, permittedIP, rest)
  end

  def gen_test_certs(%{client_chain:
           %{root: clientRoot, intermediates: clientCAs,
               peer: clientPeer},
             server_chain:
             %{root: serverRoot, intermediates: serverCAs,
                 peer: serverPeer}}) do
    %{cert: serverRootCert,
        key: serverRootKey} = (case (serverRoot) do
                                 %{} ->
                                   serverRoot
                                 serverRootConf when is_list(serverRootConf) ->
                                   root_cert('SERVER ROOT CA', serverRootConf)
                               end)
    %{cert: clientRootCert,
        key: clientRootKey} = (case (clientRoot) do
                                 %{} ->
                                   clientRoot
                                 clientRootConf when is_list(clientRootConf) ->
                                   root_cert('CLIENT ROOT CA', clientRootConf)
                               end)
    [{serverDERCert, serverDERKey} |
         serverCAsKeys] = config(:server, serverRootCert,
                                   serverRootKey,
                                   :lists.reverse([serverPeer |
                                                       :lists.reverse(serverCAs)]))
    [{clientDERCert, clientDERKey} |
         clientCAsKeys] = config(:client, clientRootCert,
                                   clientRootKey,
                                   :lists.reverse([clientPeer |
                                                       :lists.reverse(clientCAs)]))
    serverDERCA = ca_config(clientRootCert, serverCAsKeys)
    clientDERCA = ca_config(serverRootCert, clientCAsKeys)
    %{server_config:
      [{:cert, serverDERCert}, {:key, serverDERKey},
                                   {:cacerts, serverDERCA}],
        client_config:
        [{:cert, clientDERCert}, {:key, clientDERKey},
                                     {:cacerts, clientDERCA}]}
  end

  def gen_test_certs(%{root: root, intermediates: cAs, peer: peer}) do
    %{cert: rootCert, key: rootKey} = (case (root) do
                                         %{} ->
                                           root
                                         rootConf when is_list(rootConf) ->
                                           root_cert('SERVER ROOT CA', rootConf)
                                       end)
    [{dERCert, dERKey} | cAsKeys] = config(:server,
                                             rootCert, rootKey,
                                             :lists.reverse([peer |
                                                                 :lists.reverse(cAs)]))
    dERCAs = ca_config(rootCert, cAsKeys)
    [{:cert, dERCert}, {:key, dERKey}, {:cacerts, dERCAs}]
  end

  def root_cert(name, opts) do
    privKey = gen_key(:proplists.get_value(:key, opts,
                                             default_key_gen()))
    tBS = cert_template()
    issuer = subject('root', name)
    signatureId = sign_algorithm(privKey, opts)
    sPI = public_key(privKey, signatureId)
    oTPTBS = r_OTPTBSCertificate(tBS, signature: signatureId, 
                      issuer: issuer,  validity: validity(opts), 
                      subject: issuer,  subjectPublicKeyInfo: sPI, 
                      extensions: extensions(:undefined, :ca, opts))
    %{cert: :public_key.pkix_sign(oTPTBS, privKey),
        key: privKey}
  end

  defp policy_indicator(_, true) do
    0
  end

  defp policy_indicator(n, false) do
    n + 1
  end

  defp policy_set(opts, default) do
    case (:proplists.get_value(:policy_set, opts,
                                 :undefined)) do
      :undefined ->
        default
      set ->
        for oidStr <- set do
          oidify(oidStr)
        end
    end
  end

  defp oidify(oid) when is_tuple(oid) do
    oid
  end

  defp oidify(oid) when is_list(oid) do
    tokens = :string.tokens(oid, '$.')
    oidList = (for strInt <- tokens do
                 :erlang.list_to_integer(strInt)
               end)
    :erlang.list_to_tuple(oidList)
  end

  defp assert_valid_policy_tree(0, presentPolicyExtension, tree) do
    assert_valid_policy_tree(presentPolicyExtension, tree)
  end

  defp assert_valid_policy_tree(_, _, tree) do
    tree
  end

  defp assert_valid_policy_tree(:undefined, tree) do
    tree
  end

  defp assert_valid_policy_tree(true, tree) do
    tree
  end

  defp assert_valid_policy_tree(false, _Tree) do
    :pubkey_policy_tree.empty()
  end

  defp process_policy_tree(policyInformation, selfSigned,
            r_path_validation_state(valid_policy_tree: tree0) = validationState) do
    case (:pubkey_policy_tree.is_empty(tree0)) do
      true ->
        tree0
      false ->
        tree = add_policy_children(policyInformation,
                                     selfSigned, validationState)
        :pubkey_policy_tree.prune_tree(tree)
    end
  end

  defp policy_children(expPolicySet, policyInfoList) do
    :lists.foldl(fn r_PolicyInformation(policyIdentifier: policy,
                        policyQualifiers: qualifiers),
                      acc0 ->
                      case (:lists.member(policy, expPolicySet)) do
                        true ->
                          [:pubkey_policy_tree.policy_node(policy, qualifiers,
                                                             [policy]) |
                               acc0]
                        false ->
                          acc0
                      end
                 end,
                   [], policyInfoList)
  end

  defp any_policy_children([], policyInfoList) do
    :lists.foldl(fn r_PolicyInformation(policyIdentifier: policy,
                        policyQualifiers: qualifiers),
                      acc0 ->
                      node = :pubkey_policy_tree.policy_node(policy,
                                                               qualifiers,
                                                               [policy])
                      [node | acc0]
                 end,
                   [], policyInfoList)
  end

  defp any_policy_children(_, _) do
    :no_sibling
  end

  defp any_ext_policy_children(%{expected_policy_set: expPolicySet},
            qualifiers, allLeaves) do
    for policy <- expPolicySet,
          not :pubkey_policy_tree.in_set(policy, allLeaves) do
      :pubkey_policy_tree.policy_node(policy, qualifiers,
                                        [policy])
    end
  end

  defp handle_policy_mappings([], _, tree, _) do
    {:tree, tree}
  end

  defp handle_policy_mappings([mappings | rest], otpCert, tree0,
            validationState) do
    case (handle_policy_mapping(mappings, otpCert, tree0,
                                  validationState)) do
      {:tree, tree} ->
        handle_policy_mappings(rest, otpCert, tree,
                                 validationState)
      other ->
        other
    end
  end

  defp policy_constraint(current, :asn1_NOVALUE) do
    current
  end

  defp policy_constraint(current, new) do
    :erlang.min(current, new)
  end

  defp maybe_decrement(0, _) do
    0
  end

  defp maybe_decrement(n, false) do
    n - 1
  end

  defp maybe_decrement(n, true) do
    n
  end

  defp time_str_2_gregorian_sec(:notBefore,
            {:utcTime, [firstDigitYear | _] = utcTime}) do
    y1 = :erlang.list_to_integer([firstDigitYear])
    yearPrefix = (case (y1 > 4 and y1 <= 9) do
                    true ->
                      [?1, ?9]
                    false ->
                      {y, _M, _D} = :erlang.date()
                      :erlang.integer_to_list(div(y, 100))
                  end)
    time_str_2_gregorian_sec({:generalTime,
                                yearPrefix ++ utcTime})
  end

  defp time_str_2_gregorian_sec(:notAfter, {:utcTime, utcTime}) do
    slidingDate = sliding_year_window(utcTime)
    time_str_2_gregorian_sec({:generalTime, slidingDate})
  end

  defp time_str_2_gregorian_sec(_, {:generalTime, _Time} = generalTime) do
    time_str_2_gregorian_sec(generalTime)
  end

  def time_str_2_gregorian_sec({:utcTime, utcTime}) do
    time_str_2_gregorian_sec(:notAfter, {:utcTime, utcTime})
  end

  def time_str_2_gregorian_sec({:generalTime,
            [y1, y2, y3, y4, m1, m2, d1, d2, h1, h2, m3, m4, s1, s2,
                                                                     ?Z]}) do
    year = :erlang.list_to_integer([y1, y2, y3, y4])
    month = :erlang.list_to_integer([m1, m2])
    day = :erlang.list_to_integer([d1, d2])
    hour = :erlang.list_to_integer([h1, h2])
    min = :erlang.list_to_integer([m3, m4])
    sec = :erlang.list_to_integer([s1, s2])
    :calendar.datetime_to_gregorian_seconds({{year, month,
                                                day},
                                               {hour, min, sec}})
  end

  defp sliding_year_window([y1, y2, m1, m2, d1, d2, h1, h2, m3, m4, s1, s2,
                                                           z]) do
    {{currentYear, _, _}, _} = :calendar.universal_time()
    lastTwoDigitYear = rem(currentYear, 100)
    minYear = mod(lastTwoDigitYear - 50, 100)
    yearWindow = (case (:erlang.list_to_integer([y1,
                                                     y2])) do
                    n when n < minYear ->
                      currentYear + 50
                    n when n >= minYear ->
                      currentYear - 49
                  end)
    [year1,
         year2] = :erlang.integer_to_list(div(yearWindow, 100))
    [year1, year2, y1, y2, m1, m2, d1, d2, h1, h2, m3, m4,
                                                           s1, s2, z]
  end

  defp mod(a, b) when a > 0 do
    rem(a, b)
  end

  defp mod(a, b) when a < 0 do
    mod(a + b, b)
  end

  defp mod(0, _) do
    0
  end

  defp match_name(fun, name, permittedName, []) do
    fun.(name, permittedName)
  end

  defp match_name(fun, name, permittedName, [head | tail]) do
    case (fun.(name, permittedName)) do
      true ->
        true
      false ->
        match_name(fun, name, head, tail)
    end
  end

  defp do_normalize_general_name(issuer) do
    normalize = fn [{description, type,
                       {:printableString, value}}] ->
                     newValue = :string.casefold(strip_spaces(value, false))
                     [{description, type, {:printableString, newValue}}]
                   atter ->
                     atter
                end
    :lists.map(normalize, issuer)
  end

  defp extract_email({:rdnSequence, list}) do
    extract_email2(list)
  end

  defp is_dir_name([], [], _Exact) do
    true
  end

  defp is_dir_name([h | r1], [h | r2], exact) do
    is_dir_name(r1, r2, exact)
  end

  defp is_dir_name([[{:AttributeTypeAndValue, type, what1}] |
               rest1],
            [[{:AttributeTypeAndValue, type, what2}] | rest2],
            exact) do
    case (is_dir_name2(what1, what2)) do
      true ->
        is_dir_name(rest1, rest2, exact)
      false ->
        false
    end
  end

  defp is_dir_name(_, [], false) do
    true
  end

  defp is_dir_name(_, _, _) do
    false
  end

  defp is_dir_name2(str, str) do
    true
  end

  defp is_dir_name2({t1, str1}, str2) when t1 == :printableString or
                                   t1 == :utf8String do
    is_dir_name2(str1, str2)
  end

  defp is_dir_name2(str1, {t2, str2}) when t2 == :printableString or
                                   t2 == :utf8String do
    is_dir_name2(str1, str2)
  end

  defp is_dir_name2(str1, str2)
      when (is_list(str1) or is_binary(str1)) and (is_list(str2) or is_binary(str2)) do
    :string.equal(strip_spaces(str1, true),
                    strip_spaces(str2, true), true)
  end

  defp is_dir_name2(_, _) do
    false
  end

  defp strip_spaces(string0, keepDeep) do
    trimmed = :string.trim(string0)
    strip_many_spaces(:string.split(trimmed, '  ', :all),
                        keepDeep)
  end

  defp strip_many_spaces([onlySingleSpace], _) do
    onlySingleSpace
  end

  defp strip_many_spaces(strings, keepDeep) do
    split = (for str <- strings, str != [] do
               :string.trim(str, :leading, ' ')
             end)
    deepList = :lists.join(' ', split)
    case (keepDeep) do
      true ->
        deepList
      false ->
        :unicode.characters_to_list(deepList)
    end
  end

  defp decode_general_name([{:directoryName, issuer}]) do
    normalize_general_name(issuer)
  end

  defp decode_general_name([{_, issuer}]) do
    issuer
  end

  def cert_auth_key_id(r_AuthorityKeyIdentifier(authorityCertIssuer: :asn1_NOVALUE)) do
    {:error, :issuer_not_found}
  end

  def cert_auth_key_id(r_AuthorityKeyIdentifier(authorityCertIssuer: authCertIssuer,
             authorityCertSerialNumber: serialNr)) do
    {:ok, {serialNr, decode_general_name(authCertIssuer)}}
  end

  defp validate_subject_alt_names([]) do
    false
  end

  defp validate_subject_alt_names([altName | rest]) do
    case (is_valid_subject_alt_name(altName)) do
      true ->
        true
      false ->
        validate_subject_alt_names(rest)
    end
  end

  defp is_valid_subject_alt_name({name, value}) when name == :rfc822Name or
                                name == :dNSName do
    case (value) do
      '' ->
        false
      _ ->
        true
    end
  end

  defp is_valid_subject_alt_name({:iPAdress, addr}) do
    case (length(addr)) do
      4 ->
        true
      16 ->
        true
      _ ->
        false
    end
  end

  defp is_valid_subject_alt_name({:uniformResourceIdentifier, uRI}) do
    is_valid_uri(uRI)
  end

  defp is_valid_subject_alt_name({:directoryName, _}) do
    true
  end

  defp is_valid_subject_alt_name({_, [_ | _]}) do
    true
  end

  defp is_valid_subject_alt_name({:otherName, r_AnotherName()}) do
    false
  end

  defp is_valid_subject_alt_name({_, _}) do
    false
  end

  defp is_valid_uri(absURI) do
    case (:uri_string.normalize(absURI, [:return_map])) do
      %{scheme: _} ->
        true
      _ ->
        false
    end
  end

  defp is_rdnSeq({:rdnSequence, []}, {:rdnSequence, [:none]}) do
    true
  end

  defp is_rdnSeq({:rdnSequence, dirName},
            {:rdnSequence, permitted}) do
    is_dir_name(dirName, permitted, false)
  end

  defp is_permitted(_, :no_constraints) do
    true
  end

  defp is_permitted(names, constraints) do
    is_valid_name(names, constraints, true)
  end

  defp is_excluded([], _) do
    false
  end

  defp is_excluded(names, constraints) do
    is_valid_name(names, constraints, false)
  end

  defp is_valid_name([], _, default) do
    default
  end

  defp is_valid_name([{type, name} | rest], constraints, default) do
    case (type_subtree_names(type, constraints)) do
      [_ | _] = constraintNames ->
        case (match_name(type, name, constraintNames)) do
          ^default ->
            is_valid_name(rest, constraints, default)
          fail ->
            fail
        end
      [] ->
        is_valid_name(rest, constraints, default)
    end
  end

  defp add_name_constraints(newPermittedTrees, newExcludedTrees,
            r_path_validation_state(permitted_subtrees: permittedTrees,
                excluded_subtrees: excludedTrees) = validationState) do
    newPermitted = subtree_intersection(newPermittedTrees,
                                          permittedTrees)
    newExcluded = subtree_union(newExcludedTrees,
                                  excludedTrees)
    r_path_validation_state(validationState, permitted_subtrees: newPermitted, 
                         excluded_subtrees: newExcluded)
  end

  defp subtree_union(:asn1_NOVALUE, trees) do
    trees
  end

  defp subtree_union(trees1, trees2) do
    trees1 ++ trees2
  end

  defp subtree_intersection(:asn1_NOVALUE, trees) do
    trees
  end

  defp subtree_intersection(list, :no_constraints) do
    list
  end

  defp subtree_intersection([tree | trees1], trees2) do
    trees = is_in_intersection(tree, trees2)
    subtree_intersection(trees1, trees)
  end

  defp subtree_intersection([], treesInt) do
    treesInt
  end

  defp is_in_intersection(r_GeneralSubtree(base: {:directoryName,
                     {:rdnSequence, name1}}) = name,
            [r_GeneralSubtree(base: {:directoryName, {:rdnSequence, name2}}) |
                 trees]) do
    case (is_dir_name(name1, name2, false)) do
      true ->
        [name | trees]
      false ->
        [r_GeneralSubtree(name, base: {:directoryName,
                          {:rdnSequence, [:none]}}) |
             trees]
    end
  end

  defp is_in_intersection(r_GeneralSubtree(base: {:ipAdress, ip}),
            trees = [r_GeneralSubtree(base: {:ipAdress, ip}) | _]) do
    trees
  end

  defp is_in_intersection(r_GeneralSubtree(base: {:x400Address, orAddr1}) = addr,
            [r_GeneralSubtree(base: {:x400Address, orAddr2}) | trees]) do
    case (is_or_address(orAddr1, orAddr2)) do
      true ->
        [addr | trees]
      false ->
        [r_GeneralSubtree(base: {:x400Address, ''}) | trees]
    end
  end

  defp is_in_intersection(r_GeneralSubtree(base: {type, name1}) = name,
            [r_GeneralSubtree(base: {type, name2}) | trees]) do
    case (case_insensitive_match(name1, name2)) do
      true ->
        [name | trees]
      false ->
        [r_GeneralSubtree(base: {type, ''}) | trees]
    end
  end

  defp is_in_intersection(new, []) do
    [new]
  end

  defp is_in_intersection(name, [other | intCandidates]) do
    [other | is_in_intersection(name, intCandidates)]
  end

  defp type_subtree_names(type, subTrees) do
    for r_GeneralSubtree(base: {treeType, name}) <- subTrees,
          treeType === type do
      name
    end
  end

  defp is_permitted_ip([], [], []) do
    true
  end

  defp is_permitted_ip([candidatIp | candidatIpRest],
            [permittedIp | permittedIpRest], [mask | maskRest]) do
    case (mask_cmp(candidatIp, permittedIp, mask)) do
      true ->
        is_permitted_ip(candidatIpRest, permittedIpRest,
                          maskRest)
      false ->
        false
    end
  end

  defp mask_cmp(canditate, permitted, mask) do
    canditate &&& mask == permitted
  end

  defp is_valid_host_or_domain([], _) do
    false
  end

  defp is_valid_host_or_domain(canditate, [?. | _] = permitted) do
    is_suffix(permitted, canditate)
  end

  defp is_valid_host_or_domain(canditate, permitted) do
    case (:string.tokens(canditate, '@')) do
      [canditateHost] ->
        case_insensitive_match(canditateHost, permitted)
      [_, canditateHost] ->
        case_insensitive_match(canditateHost, permitted)
    end
  end

  defp is_valid_email_address(canditate, [?. | permitted], [_]) do
    is_suffix(permitted, canditate)
  end

  defp is_valid_email_address(canditate, permittedHost, [_]) do
    [_, canditateHost] = :string.tokens(canditate, '@')
    case_insensitive_match(canditateHost, permittedHost)
  end

  defp is_valid_email_address(canditate, permitted, [_, _]) do
    case_insensitive_match(canditate, permitted)
  end

  defp is_suffix(suffix, str) do
    :lists.suffix(:string.casefold(suffix),
                    :string.casefold(str))
  end

  defp case_insensitive_match(str1, str2) do
    :string.equal(str1, str2, true)
  end

  defp is_or_address(address, canditate) do
    is_double_quoted(address) and is_double_quoted(canditate) and case_insensitive_match(address,
                                                                                           canditate)
  end

  defp is_double_quoted(['"' | tail]) do
    is_double_quote(:lists.last(tail))
  end

  defp is_double_quoted('%22' ++ tail) do
    case (:lists.reverse(tail)) do
      [a, b, c | _] ->
        is_double_quote([c, b, a])
      _ ->
        false
    end
  end

  defp is_double_quoted(_) do
    false
  end

  defp is_double_quote('%22') do
    true
  end

  defp is_double_quote('"') do
    true
  end

  defp is_double_quote(_) do
    false
  end

  defp extract_verify_data(otpCert, derCert) do
    signature = r_OTPCertificate(otpCert, :signature)
    sigAlg = r_OTPCertificate(otpCert, :signatureAlgorithm)
    plainText = encoded_tbs_cert(derCert)
    {digestType, _, _} = x509_pkix_sign_types(sigAlg)
    {digestType, plainText, signature}
  end

  defp verify_signature(otpCert, derCert, key, keyParams) do
    {digestType, plainText,
       signature} = extract_verify_data(otpCert, derCert)
    case (key) do
      r_RSAPublicKey() ->
        case (keyParams) do
          r_RSASSA_PSS_params() ->
            :public_key.verify(plainText, digestType, signature,
                                 key, verify_options(keyParams))
          :NULL ->
            :public_key.verify(plainText, digestType, signature,
                                 key)
        end
      _ ->
        :public_key.verify(plainText, digestType, signature,
                             {key, keyParams})
    end
  end

  defp encoded_tbs_cert(cert) do
    {:ok,
       pKIXCert} = :OTP-PUB-KEY.decode_TBSCert_exclusive(cert)
    {:Certificate,
       {:Certificate_tbsCertificate, encodedTBSCert}, _,
       _} = pKIXCert
    encodedTBSCert
  end

  def extensions_list(:asn1_NOVALUE) do
    []
  end

  def extensions_list(extensions) do
    extensions
  end

  defp missing_basic_constraints(otpCert, selfSigned, validationState, verifyFun,
            userState0, len) do
    userState = verify_fun(otpCert,
                             {:bad_cert, :missing_basic_constraint}, userState0,
                             verifyFun)
    case (selfSigned) do
      true ->
        {validationState, userState}
      false ->
        {r_path_validation_state(validationState, max_path_length: len - 1),
           userState}
    end
  end

  defp is_valid_key_usage(keyUse, use) do
    :lists.member(use, keyUse)
  end

  defp gen_key(keyGen) do
    case (is_key(keyGen)) do
      true ->
        keyGen
      false ->
        :public_key.generate_key(keyGen)
    end
  end

  defp is_key(r_DSAPrivateKey()) do
    true
  end

  defp is_key(r_RSAPrivateKey()) do
    true
  end

  defp is_key({r_RSAPrivateKey(), _}) do
    true
  end

  defp is_key(r_ECPrivateKey()) do
    true
  end

  defp is_key(_) do
    false
  end

  defp cert_template() do
    r_OTPTBSCertificate(version: :v3,
        serialNumber: :erlang.unique_integer([:positive,
                                                  :monotonic]),
        issuerUniqueID: :asn1_NOVALUE,
        subjectUniqueID: :asn1_NOVALUE)
  end

  defp subject(contact, name) do
    opts = [{:email, contact ++ '@example.org'}, {:name, name}, {:city,
                                                      'Stockholm'},
                                                       {:country, 'SE'}, {:org, 'erlang'},
                                                                          {:org_unit,
                                                                             'automated testing'}]
    subject(opts)
  end

  defp subject(subjectOpts) when is_list(subjectOpts) do
    encode = fn opt ->
                  {type, value} = subject_enc(opt)
                  [r_AttributeTypeAndValue(type: type, value: value)]
             end
    {:rdnSequence,
       for opt <- subjectOpts do
         encode.(opt)
       end}
  end

  defp validity(opts) do
    defFrom0 = :calendar.gregorian_days_to_date(:calendar.date_to_gregorian_days(:erlang.date()) - 1)
    defTo0 = :calendar.gregorian_days_to_date(:calendar.date_to_gregorian_days(:erlang.date()) + 7)
    {defFrom, defTo} = :proplists.get_value(:validity, opts,
                                              {defFrom0, defTo0})
    genFormat = fn {y, m, d} ->
                     :lists.flatten(:io_lib.format('~4..0w~2..0w~2..0w130000Z', [y, m, d]))
                end
    uTCFormat = fn {y, m, d} ->
                     [_, _, y3, y4] = :erlang.integer_to_list(y)
                     :lists.flatten(:io_lib.format('~s~2..0w~2..0w130000Z', [[y3, y4], m, d]))
                end
    r_Validity(notBefore: validity_format(defFrom, genFormat,
                                   uTCFormat),
        notAfter: validity_format(defTo, genFormat, uTCFormat))
  end

  defp validity_format({year, _, _} = validity, genFormat, _UTCFormat)
      when year >= 2049 do
    {:generalTime, genFormat.(validity)}
  end

  defp validity_format(validity, _GenFormat, uTCFormat) do
    {:utcTime, uTCFormat.(validity)}
  end

  defp config(role, root, key, opts) do
    cert_chain(role, root, key, opts)
  end

  defp cert_chain(role, root, rootKey, opts) do
    cert_chain(role, root, rootKey, opts, 0, [])
  end

  defp cert_chain(role, issuerCert, issuerKey, [peerOpts], _,
            acc) do
    key = gen_key(:proplists.get_value(:key, peerOpts,
                                         default_key_gen()))
    cert = cert(role,
                  :public_key.pkix_decode_cert(issuerCert, :otp),
                  issuerKey, key, 'admin', ' Peer cert', peerOpts, :peer)
    [{cert, encode_key(key)}, {issuerCert,
                                 encode_key(issuerKey)} |
                                  acc]
  end

  defp cert_chain(role, issuerCert, issuerKey, [cAOpts | rest], n,
            acc) do
    key = gen_key(:proplists.get_value(:key, cAOpts,
                                         default_key_gen()))
    cert = cert(role,
                  :public_key.pkix_decode_cert(issuerCert, :otp),
                  issuerKey, key, 'webadmin', ' Intermediate CA ' ++ :erlang.integer_to_list(n),
                  cAOpts, :ca)
    cert_chain(role, cert, key, rest, n + 1,
                 [{issuerCert, encode_key(issuerKey)} | acc])
  end

  defp cert(role, r_OTPCertificate(tbsCertificate: r_OTPTBSCertificate(subject: issuer)),
            privKey, key, contact, name, opts, type) do
    tBS = cert_template()
    signAlgoId = sign_algorithm(privKey, opts)
    oTPTBS = r_OTPTBSCertificate(tBS, signature: signAlgoId,  issuer: issuer, 
                      validity: validity(opts), 
                      subject: subject(contact,
                                         :erlang.atom_to_list(role) ++ name), 
                      subjectPublicKeyInfo: public_key(key, signAlgoId), 
                      extensions: extensions(role, type, opts))
    :public_key.pkix_sign(oTPTBS, privKey)
  end

  defp ca_config(root, cAsKeys) do
    [root | for {cA, _} <- cAsKeys do
              cA
            end]
  end

  defp default_key_gen() do
    case (:crypto.ec_curves()) do
      [] ->
        {:rsa, 2048, 17}
      [curve | _] ->
        oid = :pubkey_cert_records.namedCurves(curve)
        {:namedCurve, oid}
    end
  end

  defp extensions(role, type, opts) do
    exts = :proplists.get_value(:extensions, opts, [])
    add_default_extensions(role, type, exts)
  end

  defp add_default_extensions(defaults0, exts) do
    defaults = :lists.filtermap(fn r_Extension(extnID: iD) = ext ->
                                     case (:lists.keymember(iD, 2, exts)) do
                                       true ->
                                         false
                                       false ->
                                         {true, ext}
                                     end
                                end,
                                  defaults0)
    exts ++ defaults
  end

  defp encode_key({r_RSAPrivateKey(), r_RSASSA_PSS_params()} = key) do
    {asn1Type, dER,
       _} = :public_key.pem_entry_encode(:PrivateKeyInfo, key)
    {asn1Type, dER}
  end

  defp encode_key(r_RSAPrivateKey() = key) do
    {:RSAPrivateKey,
       :public_key.der_encode(:RSAPrivateKey, key)}
  end

  defp encode_key(r_ECPrivateKey() = key) do
    {:ECPrivateKey,
       :public_key.der_encode(:ECPrivateKey, key)}
  end

  defp encode_key(r_DSAPrivateKey() = key) do
    {:DSAPrivateKey,
       :public_key.der_encode(:DSAPrivateKey, key)}
  end

end