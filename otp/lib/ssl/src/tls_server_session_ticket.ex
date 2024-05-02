defmodule :m_tls_server_session_ticket do
  use Bitwise
  @behaviour :gen_server
  require Record

  Record.defrecord(:r_AlgorithmIdentifier_PKCS1, :"AlgorithmIdentifier-PKCS1",
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_AttributePKCS_7, :"AttributePKCS-7",
    type: :undefined,
    values: :undefined
  )

  Record.defrecord(:r_AlgorithmIdentifierPKCS_7, :"AlgorithmIdentifierPKCS-7",
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_AlgorithmIdentifierPKCS_10, :"AlgorithmIdentifierPKCS-10",
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_AttributePKCS_10, :"AttributePKCS-10",
    type: :undefined,
    values: :undefined
  )

  Record.defrecord(:r_SubjectPublicKeyInfo_PKCS_10, :"SubjectPublicKeyInfo-PKCS-10",
    algorithm: :undefined,
    subjectPublicKey: :undefined
  )

  Record.defrecord(:r_ECPrivateKey, :ECPrivateKey,
    version: :undefined,
    privateKey: :undefined,
    parameters: :asn1_NOVALUE,
    publicKey: :asn1_NOVALUE,
    attributes: :asn1_NOVALUE
  )

  Record.defrecord(:r_DSAPrivateKey, :DSAPrivateKey,
    version: :undefined,
    p: :undefined,
    q: :undefined,
    g: :undefined,
    y: :undefined,
    x: :undefined
  )

  Record.defrecord(:r_DHParameter, :DHParameter,
    prime: :undefined,
    base: :undefined,
    privateValueLength: :asn1_NOVALUE
  )

  Record.defrecord(:r_DigestAlgorithm, :DigestAlgorithm,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_DigestInfoPKCS_1, :"DigestInfoPKCS-1",
    digestAlgorithm: :undefined,
    digest: :undefined
  )

  Record.defrecord(:r_RSASSA_AlgorithmIdentifier, :"RSASSA-AlgorithmIdentifier",
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_RSASSA_PSS_params, :"RSASSA-PSS-params",
    hashAlgorithm: :asn1_DEFAULT,
    maskGenAlgorithm: :asn1_DEFAULT,
    saltLength: :asn1_DEFAULT,
    trailerField: :asn1_DEFAULT
  )

  Record.defrecord(:r_RSAES_AlgorithmIdentifier, :"RSAES-AlgorithmIdentifier",
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_RSAES_OAEP_params, :"RSAES-OAEP-params",
    hashAlgorithm: :asn1_DEFAULT,
    maskGenAlgorithm: :asn1_DEFAULT,
    pSourceAlgorithm: :asn1_DEFAULT
  )

  Record.defrecord(:r_OtherPrimeInfo, :OtherPrimeInfo,
    prime: :undefined,
    exponent: :undefined,
    coefficient: :undefined
  )

  Record.defrecord(:r_RSAPrivateKey, :RSAPrivateKey,
    version: :undefined,
    modulus: :undefined,
    publicExponent: :undefined,
    privateExponent: :undefined,
    prime1: :undefined,
    prime2: :undefined,
    exponent1: :undefined,
    exponent2: :undefined,
    coefficient: :undefined,
    otherPrimeInfos: :asn1_NOVALUE
  )

  Record.defrecord(:r_RSAPublicKey, :RSAPublicKey,
    modulus: :undefined,
    publicExponent: :undefined
  )

  Record.defrecord(:r_PSourceAlgorithm, :PSourceAlgorithm,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_MaskGenAlgorithm, :MaskGenAlgorithm,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_HashAlgorithm, :HashAlgorithm,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_Curve, :Curve, a: :undefined, b: :undefined, seed: :asn1_NOVALUE)

  Record.defrecord(:r_ECParameters, :ECParameters,
    version: :undefined,
    fieldID: :undefined,
    curve: :undefined,
    base: :undefined,
    order: :undefined,
    cofactor: :asn1_NOVALUE
  )

  Record.defrecord(:r_Pentanomial, :Pentanomial, k1: :undefined, k2: :undefined, k3: :undefined)

  Record.defrecord(:r_Characteristic_two, :"Characteristic-two",
    m: :undefined,
    basis: :undefined,
    parameters: :undefined
  )

  Record.defrecord(:r_ECDSA_Sig_Value, :"ECDSA-Sig-Value", r: :undefined, s: :undefined)

  Record.defrecord(:r_FieldID, :FieldID,
    fieldType: :undefined,
    parameters: :undefined
  )

  Record.defrecord(:r_ValidationParms, :ValidationParms,
    seed: :undefined,
    pgenCounter: :undefined
  )

  Record.defrecord(:r_DomainParameters, :DomainParameters,
    p: :undefined,
    g: :undefined,
    q: :undefined,
    j: :asn1_NOVALUE,
    validationParms: :asn1_NOVALUE
  )

  Record.defrecord(:r_Dss_Sig_Value, :"Dss-Sig-Value", r: :undefined, s: :undefined)
  Record.defrecord(:r_Dss_Parms, :"Dss-Parms", p: :undefined, q: :undefined, g: :undefined)

  Record.defrecord(:r_ACClearAttrs, :ACClearAttrs,
    acIssuer: :undefined,
    acSerial: :undefined,
    attrs: :undefined
  )

  Record.defrecord(:r_AAControls, :AAControls,
    pathLenConstraint: :asn1_NOVALUE,
    permittedAttrs: :asn1_NOVALUE,
    excludedAttrs: :asn1_NOVALUE,
    permitUnSpecified: :asn1_DEFAULT
  )

  Record.defrecord(:r_SecurityCategory, :SecurityCategory,
    type: :undefined,
    value: :undefined
  )

  Record.defrecord(:r_Clearance, :Clearance,
    policyId: :undefined,
    classList: :asn1_DEFAULT,
    securityCategories: :asn1_NOVALUE
  )

  Record.defrecord(:r_RoleSyntax, :RoleSyntax,
    roleAuthority: :asn1_NOVALUE,
    roleName: :undefined
  )

  Record.defrecord(:r_SvceAuthInfo, :SvceAuthInfo,
    service: :undefined,
    ident: :undefined,
    authInfo: :asn1_NOVALUE
  )

  Record.defrecord(:r_IetfAttrSyntax, :IetfAttrSyntax,
    policyAuthority: :asn1_NOVALUE,
    values: :undefined
  )

  Record.defrecord(:r_TargetCert, :TargetCert,
    targetCertificate: :undefined,
    targetName: :asn1_NOVALUE,
    certDigestInfo: :asn1_NOVALUE
  )

  Record.defrecord(:r_AttCertValidityPeriod, :AttCertValidityPeriod,
    notBeforeTime: :undefined,
    notAfterTime: :undefined
  )

  Record.defrecord(:r_IssuerSerial, :IssuerSerial,
    issuer: :undefined,
    serial: :undefined,
    issuerUID: :asn1_NOVALUE
  )

  Record.defrecord(:r_V2Form, :V2Form,
    issuerName: :asn1_NOVALUE,
    baseCertificateID: :asn1_NOVALUE,
    objectDigestInfo: :asn1_NOVALUE
  )

  Record.defrecord(:r_ObjectDigestInfo, :ObjectDigestInfo,
    digestedObjectType: :undefined,
    otherObjectTypeID: :asn1_NOVALUE,
    digestAlgorithm: :undefined,
    objectDigest: :undefined
  )

  Record.defrecord(:r_Holder, :Holder,
    baseCertificateID: :asn1_NOVALUE,
    entityName: :asn1_NOVALUE,
    objectDigestInfo: :asn1_NOVALUE
  )

  Record.defrecord(:r_AttributeCertificateInfo, :AttributeCertificateInfo,
    version: :undefined,
    holder: :undefined,
    issuer: :undefined,
    signature: :undefined,
    serialNumber: :undefined,
    attrCertValidityPeriod: :undefined,
    attributes: :undefined,
    issuerUniqueID: :asn1_NOVALUE,
    extensions: :asn1_NOVALUE
  )

  Record.defrecord(:r_AttributeCertificate, :AttributeCertificate,
    acinfo: :undefined,
    signatureAlgorithm: :undefined,
    signatureValue: :undefined
  )

  Record.defrecord(:r_IssuingDistributionPoint, :IssuingDistributionPoint,
    distributionPoint: :asn1_NOVALUE,
    onlyContainsUserCerts: :asn1_DEFAULT,
    onlyContainsCACerts: :asn1_DEFAULT,
    onlySomeReasons: :asn1_NOVALUE,
    indirectCRL: :asn1_DEFAULT,
    onlyContainsAttributeCerts: :asn1_DEFAULT
  )

  Record.defrecord(:r_AccessDescription, :AccessDescription,
    accessMethod: :undefined,
    accessLocation: :undefined
  )

  Record.defrecord(:r_DistributionPoint, :DistributionPoint,
    distributionPoint: :asn1_NOVALUE,
    reasons: :asn1_NOVALUE,
    cRLIssuer: :asn1_NOVALUE
  )

  Record.defrecord(:r_PolicyConstraints, :PolicyConstraints,
    requireExplicitPolicy: :asn1_NOVALUE,
    inhibitPolicyMapping: :asn1_NOVALUE
  )

  Record.defrecord(:r_GeneralSubtree, :GeneralSubtree,
    base: :undefined,
    minimum: :asn1_DEFAULT,
    maximum: :asn1_NOVALUE
  )

  Record.defrecord(:r_NameConstraints, :NameConstraints,
    permittedSubtrees: :asn1_NOVALUE,
    excludedSubtrees: :asn1_NOVALUE
  )

  Record.defrecord(:r_BasicConstraints, :BasicConstraints,
    cA: :asn1_DEFAULT,
    pathLenConstraint: :asn1_NOVALUE
  )

  Record.defrecord(:r_EDIPartyName, :EDIPartyName,
    nameAssigner: :asn1_NOVALUE,
    partyName: :undefined
  )

  Record.defrecord(:r_AnotherName, :AnotherName,
    "type-id": :undefined,
    value: :undefined
  )

  Record.defrecord(:r_PolicyMappings_SEQOF, :PolicyMappings_SEQOF,
    issuerDomainPolicy: :undefined,
    subjectDomainPolicy: :undefined
  )

  Record.defrecord(:r_NoticeReference, :NoticeReference,
    organization: :undefined,
    noticeNumbers: :undefined
  )

  Record.defrecord(:r_UserNotice, :UserNotice,
    noticeRef: :asn1_NOVALUE,
    explicitText: :asn1_NOVALUE
  )

  Record.defrecord(:r_PolicyQualifierInfo, :PolicyQualifierInfo,
    policyQualifierId: :undefined,
    qualifier: :undefined
  )

  Record.defrecord(:r_PolicyInformation, :PolicyInformation,
    policyIdentifier: :undefined,
    policyQualifiers: :asn1_NOVALUE
  )

  Record.defrecord(:r_PrivateKeyUsagePeriod, :PrivateKeyUsagePeriod,
    notBefore: :asn1_NOVALUE,
    notAfter: :asn1_NOVALUE
  )

  Record.defrecord(:r_AuthorityKeyIdentifier, :AuthorityKeyIdentifier,
    keyIdentifier: :asn1_NOVALUE,
    authorityCertIssuer: :asn1_NOVALUE,
    authorityCertSerialNumber: :asn1_NOVALUE
  )

  Record.defrecord(:r_EncryptedData, :EncryptedData,
    version: :undefined,
    encryptedContentInfo: :undefined
  )

  Record.defrecord(:r_DigestedData, :DigestedData,
    version: :undefined,
    digestAlgorithm: :undefined,
    contentInfo: :undefined,
    digest: :undefined
  )

  Record.defrecord(:r_SignedAndEnvelopedData, :SignedAndEnvelopedData,
    version: :undefined,
    recipientInfos: :undefined,
    digestAlgorithms: :undefined,
    encryptedContentInfo: :undefined,
    certificates: :asn1_NOVALUE,
    crls: :asn1_NOVALUE,
    signerInfos: :undefined
  )

  Record.defrecord(:r_RecipientInfo, :RecipientInfo,
    version: :undefined,
    issuerAndSerialNumber: :undefined,
    keyEncryptionAlgorithm: :undefined,
    encryptedKey: :undefined
  )

  Record.defrecord(:r_EncryptedContentInfo, :EncryptedContentInfo,
    contentType: :undefined,
    contentEncryptionAlgorithm: :undefined,
    encryptedContent: :asn1_NOVALUE
  )

  Record.defrecord(:r_EnvelopedData, :EnvelopedData,
    version: :undefined,
    recipientInfos: :undefined,
    encryptedContentInfo: :undefined
  )

  Record.defrecord(:r_DigestInfoPKCS_7, :"DigestInfoPKCS-7",
    digestAlgorithm: :undefined,
    digest: :undefined
  )

  Record.defrecord(:r_SignerInfo, :SignerInfo,
    version: :undefined,
    issuerAndSerialNumber: :undefined,
    digestAlgorithm: :undefined,
    authenticatedAttributes: :asn1_NOVALUE,
    digestEncryptionAlgorithm: :undefined,
    encryptedDigest: :undefined,
    unauthenticatedAttributes: :asn1_NOVALUE
  )

  Record.defrecord(
    :r_SignerInfo_unauthenticatedAttributes_uaSet_SETOF,
    :SignerInfo_unauthenticatedAttributes_uaSet_SETOF,
    type: :undefined,
    values: :undefined
  )

  Record.defrecord(
    :r_SignerInfo_unauthenticatedAttributes_uaSequence_SEQOF,
    :SignerInfo_unauthenticatedAttributes_uaSequence_SEQOF,
    type: :undefined,
    values: :undefined
  )

  Record.defrecord(:r_SignedData, :SignedData,
    version: :undefined,
    digestAlgorithms: :undefined,
    contentInfo: :undefined,
    certificates: :asn1_NOVALUE,
    crls: :asn1_NOVALUE,
    signerInfos: :undefined
  )

  Record.defrecord(:r_ContentInfo, :ContentInfo,
    contentType: :undefined,
    content: :asn1_NOVALUE
  )

  Record.defrecord(:r_KeyEncryptionAlgorithmIdentifier, :KeyEncryptionAlgorithmIdentifier,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_IssuerAndSerialNumber, :IssuerAndSerialNumber,
    issuer: :undefined,
    serialNumber: :undefined
  )

  Record.defrecord(:r_DigestEncryptionAlgorithmIdentifier, :DigestEncryptionAlgorithmIdentifier,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_DigestAlgorithmIdentifier, :DigestAlgorithmIdentifier,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_ContentEncryptionAlgorithmIdentifier, :ContentEncryptionAlgorithmIdentifier,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(
    :r_SignerInfoAuthenticatedAttributes_aaSet_SETOF,
    :SignerInfoAuthenticatedAttributes_aaSet_SETOF,
    type: :undefined,
    values: :undefined
  )

  Record.defrecord(
    :r_SignerInfoAuthenticatedAttributes_aaSequence_SEQOF,
    :SignerInfoAuthenticatedAttributes_aaSequence_SEQOF,
    type: :undefined,
    values: :undefined
  )

  Record.defrecord(:r_CertificationRequest, :CertificationRequest,
    certificationRequestInfo: :undefined,
    signatureAlgorithm: :undefined,
    signature: :undefined
  )

  Record.defrecord(
    :r_CertificationRequest_signatureAlgorithm,
    :CertificationRequest_signatureAlgorithm,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_CertificationRequestInfo, :CertificationRequestInfo,
    version: :undefined,
    subject: :undefined,
    subjectPKInfo: :undefined,
    attributes: :undefined
  )

  Record.defrecord(
    :r_CertificationRequestInfo_subjectPKInfo,
    :CertificationRequestInfo_subjectPKInfo,
    algorithm: :undefined,
    subjectPublicKey: :undefined
  )

  Record.defrecord(
    :r_CertificationRequestInfo_subjectPKInfo_algorithm,
    :CertificationRequestInfo_subjectPKInfo_algorithm,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(
    :r_CertificationRequestInfo_attributes_SETOF,
    :CertificationRequestInfo_attributes_SETOF,
    type: :undefined,
    values: :undefined
  )

  Record.defrecord(:r_PreferredSignatureAlgorithm, :PreferredSignatureAlgorithm,
    sigIdentifier: :undefined,
    certIdentifier: :asn1_NOVALUE
  )

  Record.defrecord(:r_CrlID, :CrlID,
    crlUrl: :asn1_NOVALUE,
    crlNum: :asn1_NOVALUE,
    crlTime: :asn1_NOVALUE
  )

  Record.defrecord(:r_ServiceLocator, :ServiceLocator,
    issuer: :undefined,
    locator: :undefined
  )

  Record.defrecord(:r_RevokedInfo, :RevokedInfo,
    revocationTime: :undefined,
    revocationReason: :asn1_NOVALUE
  )

  Record.defrecord(:r_SingleResponse, :SingleResponse,
    certID: :undefined,
    certStatus: :undefined,
    thisUpdate: :undefined,
    nextUpdate: :asn1_NOVALUE,
    singleExtensions: :asn1_NOVALUE
  )

  Record.defrecord(:r_ResponseData, :ResponseData,
    version: :asn1_DEFAULT,
    responderID: :undefined,
    producedAt: :undefined,
    responses: :undefined,
    responseExtensions: :asn1_NOVALUE
  )

  Record.defrecord(:r_BasicOCSPResponse, :BasicOCSPResponse,
    tbsResponseData: :undefined,
    signatureAlgorithm: :undefined,
    signature: :undefined,
    certs: :asn1_NOVALUE
  )

  Record.defrecord(:r_ResponseBytes, :ResponseBytes,
    responseType: :undefined,
    response: :undefined
  )

  Record.defrecord(:r_OCSPResponse, :OCSPResponse,
    responseStatus: :undefined,
    responseBytes: :asn1_NOVALUE
  )

  Record.defrecord(:r_CertID, :CertID,
    hashAlgorithm: :undefined,
    issuerNameHash: :undefined,
    issuerKeyHash: :undefined,
    serialNumber: :undefined
  )

  Record.defrecord(:r_Request, :Request,
    reqCert: :undefined,
    singleRequestExtensions: :asn1_NOVALUE
  )

  Record.defrecord(:r_Signature, :Signature,
    signatureAlgorithm: :undefined,
    signature: :undefined,
    certs: :asn1_NOVALUE
  )

  Record.defrecord(:r_TBSRequest, :TBSRequest,
    version: :asn1_DEFAULT,
    requestorName: :asn1_NOVALUE,
    requestList: :undefined,
    requestExtensions: :asn1_NOVALUE
  )

  Record.defrecord(:r_OCSPRequest, :OCSPRequest,
    tbsRequest: :undefined,
    optionalSignature: :asn1_NOVALUE
  )

  Record.defrecord(:r_TeletexDomainDefinedAttribute, :TeletexDomainDefinedAttribute,
    type: :undefined,
    value: :undefined
  )

  Record.defrecord(:r_PresentationAddress, :PresentationAddress,
    pSelector: :asn1_NOVALUE,
    sSelector: :asn1_NOVALUE,
    tSelector: :asn1_NOVALUE,
    nAddresses: :undefined
  )

  Record.defrecord(
    :r_ExtendedNetworkAddress_e163_4_address,
    :"ExtendedNetworkAddress_e163-4-address",
    number: :undefined,
    "sub-address": :asn1_NOVALUE
  )

  Record.defrecord(:r_PDSParameter, :PDSParameter,
    "printable-string": :asn1_NOVALUE,
    "teletex-string": :asn1_NOVALUE
  )

  Record.defrecord(:r_UnformattedPostalAddress, :UnformattedPostalAddress,
    "printable-address": :asn1_NOVALUE,
    "teletex-string": :asn1_NOVALUE
  )

  Record.defrecord(:r_TeletexPersonalName, :TeletexPersonalName,
    surname: :undefined,
    "given-name": :asn1_NOVALUE,
    initials: :asn1_NOVALUE,
    "generation-qualifier": :asn1_NOVALUE
  )

  Record.defrecord(:r_ExtensionAttribute, :ExtensionAttribute,
    "extension-attribute-type": :undefined,
    "extension-attribute-value": :undefined
  )

  Record.defrecord(:r_BuiltInDomainDefinedAttribute, :BuiltInDomainDefinedAttribute,
    type: :undefined,
    value: :undefined
  )

  Record.defrecord(:r_PersonalName, :PersonalName,
    surname: :undefined,
    "given-name": :asn1_NOVALUE,
    initials: :asn1_NOVALUE,
    "generation-qualifier": :asn1_NOVALUE
  )

  Record.defrecord(:r_BuiltInStandardAttributes, :BuiltInStandardAttributes,
    "country-name": :asn1_NOVALUE,
    "administration-domain-name": :asn1_NOVALUE,
    "network-address": :asn1_NOVALUE,
    "terminal-identifier": :asn1_NOVALUE,
    "private-domain-name": :asn1_NOVALUE,
    "organization-name": :asn1_NOVALUE,
    "numeric-user-identifier": :asn1_NOVALUE,
    "personal-name": :asn1_NOVALUE,
    "organizational-unit-names": :asn1_NOVALUE
  )

  Record.defrecord(:r_ORAddress, :ORAddress,
    "built-in-standard-attributes": :undefined,
    "built-in-domain-defined-attributes": :asn1_NOVALUE,
    "extension-attributes": :asn1_NOVALUE
  )

  Record.defrecord(:r_AlgorithmIdentifier, :AlgorithmIdentifier,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_TBSCertList, :TBSCertList,
    version: :asn1_NOVALUE,
    signature: :undefined,
    issuer: :undefined,
    thisUpdate: :undefined,
    nextUpdate: :asn1_NOVALUE,
    revokedCertificates: :asn1_NOVALUE,
    crlExtensions: :asn1_NOVALUE
  )

  Record.defrecord(
    :r_TBSCertList_revokedCertificates_SEQOF,
    :TBSCertList_revokedCertificates_SEQOF,
    userCertificate: :undefined,
    revocationDate: :undefined,
    crlEntryExtensions: :asn1_NOVALUE
  )

  Record.defrecord(:r_CertificateList, :CertificateList,
    tbsCertList: :undefined,
    signatureAlgorithm: :undefined,
    signature: :undefined
  )

  Record.defrecord(:r_Extension, :Extension,
    extnID: :undefined,
    critical: :asn1_DEFAULT,
    extnValue: :undefined
  )

  Record.defrecord(:r_SubjectPublicKeyInfo, :SubjectPublicKeyInfo,
    algorithm: :undefined,
    subjectPublicKey: :undefined
  )

  Record.defrecord(:r_Validity, :Validity,
    notBefore: :undefined,
    notAfter: :undefined
  )

  Record.defrecord(:r_TBSCertificate, :TBSCertificate,
    version: :asn1_DEFAULT,
    serialNumber: :undefined,
    signature: :undefined,
    issuer: :undefined,
    validity: :undefined,
    subject: :undefined,
    subjectPublicKeyInfo: :undefined,
    issuerUniqueID: :asn1_NOVALUE,
    subjectUniqueID: :asn1_NOVALUE,
    extensions: :asn1_NOVALUE
  )

  Record.defrecord(:r_Certificate, :Certificate,
    tbsCertificate: :undefined,
    signatureAlgorithm: :undefined,
    signature: :undefined
  )

  Record.defrecord(:r_AttributeTypeAndValue, :AttributeTypeAndValue,
    type: :undefined,
    value: :undefined
  )

  Record.defrecord(:r_Attribute, :Attribute,
    type: :undefined,
    values: :undefined
  )

  Record.defrecord(:r_OTPNoticeReference, :OTPNoticeReference,
    organization: :undefined,
    noticeNumbers: :undefined
  )

  Record.defrecord(:r_OTPUserNotice, :OTPUserNotice,
    noticeRef: :asn1_NOVALUE,
    explicitText: :asn1_NOVALUE
  )

  Record.defrecord(:r_Extension_Any, :"Extension-Any",
    extnID: :undefined,
    critical: :asn1_DEFAULT,
    extnValue: :undefined
  )

  Record.defrecord(:r_OTPExtension, :OTPExtension,
    extnID: :undefined,
    critical: :asn1_DEFAULT,
    extnValue: :undefined
  )

  Record.defrecord(:r_OTPExtensionAttribute, :OTPExtensionAttribute,
    extensionAttributeType: :undefined,
    extensionAttributeValue: :undefined
  )

  Record.defrecord(:r_OTPCharacteristic_two, :"OTPCharacteristic-two",
    m: :undefined,
    basis: :undefined,
    parameters: :undefined
  )

  Record.defrecord(:r_OTPFieldID, :OTPFieldID,
    fieldType: :undefined,
    parameters: :undefined
  )

  Record.defrecord(:r_PublicKeyAlgorithm, :PublicKeyAlgorithm,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_SignatureAlgorithm_Any, :"SignatureAlgorithm-Any",
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_SignatureAlgorithm, :SignatureAlgorithm,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_OTPSubjectPublicKeyInfo_Any, :"OTPSubjectPublicKeyInfo-Any",
    algorithm: :undefined,
    subjectPublicKey: :undefined
  )

  Record.defrecord(:r_OTPSubjectPublicKeyInfo, :OTPSubjectPublicKeyInfo,
    algorithm: :undefined,
    subjectPublicKey: :undefined
  )

  Record.defrecord(:r_OTPOLDSubjectPublicKeyInfo, :OTPOLDSubjectPublicKeyInfo,
    algorithm: :undefined,
    subjectPublicKey: :undefined
  )

  Record.defrecord(:r_OTPOLDSubjectPublicKeyInfo_algorithm, :OTPOLDSubjectPublicKeyInfo_algorithm,
    algo: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_OTPAttributeTypeAndValue, :OTPAttributeTypeAndValue,
    type: :undefined,
    value: :undefined
  )

  Record.defrecord(:r_OTPTBSCertificate, :OTPTBSCertificate,
    version: :asn1_DEFAULT,
    serialNumber: :undefined,
    signature: :undefined,
    issuer: :undefined,
    validity: :undefined,
    subject: :undefined,
    subjectPublicKeyInfo: :undefined,
    issuerUniqueID: :asn1_NOVALUE,
    subjectUniqueID: :asn1_NOVALUE,
    extensions: :asn1_NOVALUE
  )

  Record.defrecord(:r_OTPCertificate, :OTPCertificate,
    tbsCertificate: :undefined,
    signatureAlgorithm: :undefined,
    signature: :undefined
  )

  Record.defrecord(:r_AlgorithmIdentifierPKCS5v2_0, :"AlgorithmIdentifierPKCS5v2-0",
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_PKAttribute, :PKAttribute,
    type: :undefined,
    values: :undefined,
    valuesWithContext: :asn1_NOVALUE
  )

  Record.defrecord(:r_PKAttribute_valuesWithContext_SETOF, :PKAttribute_valuesWithContext_SETOF,
    value: :undefined,
    contextList: :undefined
  )

  Record.defrecord(:r_AlgorithmIdentifierPKCS_8, :"AlgorithmIdentifierPKCS-8",
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_RC5_CBC_Parameters, :"RC5-CBC-Parameters",
    version: :undefined,
    rounds: :undefined,
    blockSizeInBits: :undefined,
    iv: :asn1_NOVALUE
  )

  Record.defrecord(:r_RC2_CBC_Parameter, :"RC2-CBC-Parameter",
    rc2ParameterVersion: :asn1_NOVALUE,
    iv: :undefined
  )

  Record.defrecord(:r_PBMAC1_params, :"PBMAC1-params",
    keyDerivationFunc: :undefined,
    messageAuthScheme: :undefined
  )

  Record.defrecord(:r_PBMAC1_params_keyDerivationFunc, :"PBMAC1-params_keyDerivationFunc",
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_PBMAC1_params_messageAuthScheme, :"PBMAC1-params_messageAuthScheme",
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_PBES2_params, :"PBES2-params",
    keyDerivationFunc: :undefined,
    encryptionScheme: :undefined
  )

  Record.defrecord(:r_PBES2_params_keyDerivationFunc, :"PBES2-params_keyDerivationFunc",
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_PBES2_params_encryptionScheme, :"PBES2-params_encryptionScheme",
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_PBEParameter, :PBEParameter,
    salt: :undefined,
    iterationCount: :undefined
  )

  Record.defrecord(:r_PBKDF2_params, :"PBKDF2-params",
    salt: :undefined,
    iterationCount: :undefined,
    keyLength: :asn1_NOVALUE,
    prf: :asn1_DEFAULT
  )

  Record.defrecord(:r_PBKDF2_params_salt_otherSource, :"PBKDF2-params_salt_otherSource",
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_PBKDF2_params_prf, :"PBKDF2-params_prf",
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_Context, :Context,
    contextType: :undefined,
    contextValues: :undefined,
    fallback: :asn1_DEFAULT
  )

  Record.defrecord(:r_EncryptedPrivateKeyInfo, :EncryptedPrivateKeyInfo,
    encryptionAlgorithm: :undefined,
    encryptedData: :undefined
  )

  Record.defrecord(
    :r_EncryptedPrivateKeyInfo_encryptionAlgorithm,
    :EncryptedPrivateKeyInfo_encryptionAlgorithm,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_Attributes_SETOF, :Attributes_SETOF,
    type: :undefined,
    values: :undefined,
    valuesWithContext: :asn1_NOVALUE
  )

  Record.defrecord(
    :r_Attributes_SETOF_valuesWithContext_SETOF,
    :Attributes_SETOF_valuesWithContext_SETOF,
    value: :undefined,
    contextList: :undefined
  )

  Record.defrecord(:r_OneAsymmetricKey, :OneAsymmetricKey,
    version: :undefined,
    privateKeyAlgorithm: :undefined,
    privateKey: :undefined,
    attributes: :asn1_NOVALUE,
    publicKey: :asn1_NOVALUE
  )

  Record.defrecord(:r_OneAsymmetricKey_privateKeyAlgorithm, :OneAsymmetricKey_privateKeyAlgorithm,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

  Record.defrecord(:r_PrivateKeyInfo, :PrivateKeyInfo,
    version: :undefined,
    privateKeyAlgorithm: :undefined,
    privateKey: :undefined,
    attributes: :asn1_NOVALUE
  )

  Record.defrecord(:r_PrivateKeyInfo_privateKeyAlgorithm, :PrivateKeyInfo_privateKeyAlgorithm,
    algorithm: :undefined,
    parameters: :asn1_NOVALUE
  )

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

  Record.defrecord(:r_session, :session,
    session_id: :undefined,
    internal_id: :undefined,
    peer_certificate: :undefined,
    own_certificates: :undefined,
    private_key: :undefined,
    compression_method: :undefined,
    cipher_suite: :undefined,
    master_secret: :undefined,
    srp_username: :undefined,
    is_resumable: :undefined,
    time_stamp: :undefined,
    ecc: :undefined,
    sign_alg: :undefined,
    dh_public_value: :undefined
  )

  Record.defrecord(:r_random, :random,
    gmt_unix_time: :undefined,
    random_bytes: :undefined
  )

  Record.defrecord(:r_hello_extensions, :hello_extensions,
    renegotiation_info: :undefined,
    signature_algs: :undefined,
    alpn: :undefined,
    next_protocol_negotiation: :undefined,
    srp: :undefined,
    ec_point_formats: :undefined,
    elliptic_curves: :undefined,
    sni: :undefined,
    client_hello_versions: :undefined,
    server_hello_selected_version: :undefined,
    signature_algs_cert: :undefined,
    key_share: :undefined
  )

  Record.defrecord(:r_server_hello, :server_hello,
    server_version: :undefined,
    random: :undefined,
    session_id: :undefined,
    cipher_suite: :undefined,
    compression_method: :undefined,
    extensions: :undefined
  )

  Record.defrecord(:r_certificate, :certificate, asn1_certificates: :undefined)

  Record.defrecord(:r_server_rsa_params, :server_rsa_params,
    rsa_modulus: :undefined,
    rsa_exponent: :undefined
  )

  Record.defrecord(:r_server_dh_params, :server_dh_params,
    dh_p: :undefined,
    dh_g: :undefined,
    dh_y: :undefined
  )

  Record.defrecord(:r_server_ecdh_params, :server_ecdh_params,
    curve: :undefined,
    public: :undefined
  )

  Record.defrecord(:r_server_psk_params, :server_psk_params, hint: :undefined)

  Record.defrecord(:r_server_dhe_psk_params, :server_dhe_psk_params,
    hint: :undefined,
    dh_params: :undefined
  )

  Record.defrecord(:r_server_ecdhe_psk_params, :server_ecdhe_psk_params,
    hint: :undefined,
    dh_params: :undefined
  )

  Record.defrecord(:r_server_srp_params, :server_srp_params,
    srp_n: :undefined,
    srp_g: :undefined,
    srp_s: :undefined,
    srp_b: :undefined
  )

  Record.defrecord(:r_server_key_exchange, :server_key_exchange, exchange_keys: :undefined)

  Record.defrecord(:r_server_key_params, :server_key_params,
    params: :undefined,
    params_bin: :undefined,
    hashsign: :undefined,
    signature: :undefined
  )

  Record.defrecord(:r_hello_request, :hello_request, [])
  Record.defrecord(:r_server_hello_done, :server_hello_done, [])

  Record.defrecord(:r_certificate_request, :certificate_request,
    certificate_types: :undefined,
    hashsign_algorithms: :undefined,
    certificate_authorities: :undefined
  )

  Record.defrecord(:r_client_key_exchange, :client_key_exchange, exchange_keys: :undefined)

  Record.defrecord(:r_pre_master_secret, :pre_master_secret,
    client_version: :undefined,
    random: :undefined
  )

  Record.defrecord(:r_encrypted_premaster_secret, :encrypted_premaster_secret,
    premaster_secret: :undefined
  )

  Record.defrecord(:r_client_diffie_hellman_public, :client_diffie_hellman_public,
    dh_public: :undefined
  )

  Record.defrecord(:r_client_ec_diffie_hellman_public, :client_ec_diffie_hellman_public,
    dh_public: :undefined
  )

  Record.defrecord(:r_client_psk_identity, :client_psk_identity, identity: :undefined)

  Record.defrecord(:r_client_dhe_psk_identity, :client_dhe_psk_identity,
    identity: :undefined,
    dh_public: :undefined
  )

  Record.defrecord(:r_client_ecdhe_psk_identity, :client_ecdhe_psk_identity,
    identity: :undefined,
    dh_public: :undefined
  )

  Record.defrecord(:r_client_rsa_psk_identity, :client_rsa_psk_identity,
    identity: :undefined,
    exchange_keys: :undefined
  )

  Record.defrecord(:r_client_srp_public, :client_srp_public, srp_a: :undefined)

  Record.defrecord(:r_certificate_verify, :certificate_verify,
    hashsign_algorithm: :undefined,
    signature: :undefined
  )

  Record.defrecord(:r_finished, :finished, verify_data: :undefined)

  Record.defrecord(:r_renegotiation_info, :renegotiation_info,
    renegotiated_connection: :undefined
  )

  Record.defrecord(:r_srp, :srp, username: :undefined)
  Record.defrecord(:r_hash_sign_algos, :hash_sign_algos, hash_sign_algos: :undefined)

  Record.defrecord(:r_signature_algorithms, :signature_algorithms,
    signature_scheme_list: :undefined
  )

  Record.defrecord(:r_alpn, :alpn, extension_data: :undefined)

  Record.defrecord(:r_next_protocol_negotiation, :next_protocol_negotiation,
    extension_data: :undefined
  )

  Record.defrecord(:r_next_protocol, :next_protocol, selected_protocol: :undefined)
  Record.defrecord(:r_elliptic_curves, :elliptic_curves, elliptic_curve_list: :undefined)
  Record.defrecord(:r_supported_groups, :supported_groups, supported_groups: :undefined)
  Record.defrecord(:r_ec_point_formats, :ec_point_formats, ec_point_format_list: :undefined)

  Record.defrecord(:r_use_srtp, :use_srtp,
    protection_profiles: :undefined,
    mki: :undefined
  )

  Record.defrecord(:r_sni, :sni, hostname: :undefined)
  Record.defrecord(:r_max_frag_enum, :max_frag_enum, enum: :undefined)

  Record.defrecord(:r_certificate_status_request, :certificate_status_request,
    status_type: :undefined,
    request: :undefined
  )

  Record.defrecord(:r_ocsp_status_request, :ocsp_status_request,
    responder_id_list: [],
    request_extensions: []
  )

  Record.defrecord(:r_certificate_status, :certificate_status,
    status_type: :undefined,
    response: :undefined
  )

  Record.defrecord(:r_client_hello_versions, :client_hello_versions, versions: :undefined)

  Record.defrecord(:r_server_hello_selected_version, :server_hello_selected_version,
    selected_version: :undefined
  )

  Record.defrecord(:r_signature_algorithms_cert, :signature_algorithms_cert,
    signature_scheme_list: :undefined
  )

  Record.defrecord(:r_client_hello, :client_hello,
    client_version: :undefined,
    random: :undefined,
    session_id: :undefined,
    cookie: :undefined,
    cipher_suites: :undefined,
    compression_methods: :undefined,
    extensions: :undefined
  )

  Record.defrecord(:r_key_share_entry, :key_share_entry,
    group: :undefined,
    key_exchange: :undefined
  )

  Record.defrecord(:r_key_share_client_hello, :key_share_client_hello, client_shares: :undefined)

  Record.defrecord(:r_key_share_hello_retry_request, :key_share_hello_retry_request,
    selected_group: :undefined
  )

  Record.defrecord(:r_key_share_server_hello, :key_share_server_hello, server_share: :undefined)

  Record.defrecord(:r_uncompressed_point_representation, :uncompressed_point_representation,
    legacy_form: 4,
    x: :undefined,
    y: :undefined
  )

  Record.defrecord(:r_psk_key_exchange_modes, :psk_key_exchange_modes, ke_modes: :undefined)
  Record.defrecord(:r_empty, :empty, [])
  Record.defrecord(:r_early_data_indication, :early_data_indication, [])

  Record.defrecord(:r_early_data_indication_nst, :early_data_indication_nst,
    indication: :undefined
  )

  Record.defrecord(:r_psk_identity, :psk_identity,
    identity: :undefined,
    obfuscated_ticket_age: :undefined
  )

  Record.defrecord(:r_offered_psks, :offered_psks,
    identities: :undefined,
    binders: :undefined
  )

  Record.defrecord(:r_pre_shared_key_client_hello, :pre_shared_key_client_hello,
    offered_psks: :undefined
  )

  Record.defrecord(:r_pre_shared_key_server_hello, :pre_shared_key_server_hello,
    selected_identity: :undefined
  )

  Record.defrecord(:r_cookie, :cookie, cookie: :undefined)
  Record.defrecord(:r_named_group_list, :named_group_list, named_group_list: :undefined)
  Record.defrecord(:r_certificate_authorities, :certificate_authorities, authorities: :undefined)

  Record.defrecord(:r_oid_filter, :oid_filter,
    certificate_extension_oid: :undefined,
    certificate_extension_values: :undefined
  )

  Record.defrecord(:r_oid_filter_extension, :oid_filter_extension, filters: :undefined)
  Record.defrecord(:r_post_handshake_auth, :post_handshake_auth, [])
  Record.defrecord(:r_encrypted_extensions, :encrypted_extensions, extensions: :undefined)

  Record.defrecord(:r_certificate_request_1_3, :certificate_request_1_3,
    certificate_request_context: :undefined,
    extensions: :undefined
  )

  Record.defrecord(:r_certificate_entry, :certificate_entry,
    data: :undefined,
    extensions: :undefined
  )

  Record.defrecord(:r_certificate_1_3, :certificate_1_3,
    certificate_request_context: :undefined,
    certificate_list: :undefined
  )

  Record.defrecord(:r_certificate_verify_1_3, :certificate_verify_1_3,
    algorithm: :undefined,
    signature: :undefined
  )

  Record.defrecord(:r_new_session_ticket, :new_session_ticket,
    ticket_lifetime: :undefined,
    ticket_age_add: :undefined,
    ticket_nonce: :undefined,
    ticket: :undefined,
    extensions: :undefined
  )

  Record.defrecord(:r_end_of_early_data, :end_of_early_data, [])
  Record.defrecord(:r_key_update, :key_update, request_update: :undefined)

  Record.defrecord(:r_socket_options, :socket_options,
    mode: :list,
    packet: 0,
    packet_size: 0,
    header: 0,
    active: true
  )

  Record.defrecord(:r_config, :config,
    ssl: :undefined,
    inet_user: :undefined,
    emulated: :undefined,
    trackers: :undefined,
    dtls_handler: :undefined,
    inet_ssl: :undefined,
    transport_info: :undefined,
    connection_cb: :undefined
  )

  Record.defrecord(:r_ticket_data, :ticket_data,
    key: :undefined,
    pos: :undefined,
    identity: :undefined,
    psk: :undefined,
    nonce: :undefined,
    cipher_suite: :undefined,
    max_size: :undefined
  )

  Record.defrecord(:r_alert, :alert,
    level: :undefined,
    description: :undefined,
    where: :undefined,
    role: :undefined,
    reason: :undefined
  )

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

  Record.defrecord(:r_state, :state,
    stateless: :undefined,
    stateful: :undefined,
    nonce: :undefined,
    lifetime: :undefined,
    max_early_data_size: :undefined,
    listen_monitor: :undefined
  )

  def start_link(listener, mode1, lifetime, ticketStoreSize, maxEarlyDataSize, antiReplay, seed) do
    mode =
      case mode1 do
        :stateful_with_cert ->
          :stateful

        :stateless_with_cert ->
          :stateless

        _ ->
          mode1
      end

    :gen_server.start_link(
      :tls_server_session_ticket,
      [listener, mode, lifetime, ticketStoreSize, maxEarlyDataSize, antiReplay, seed],
      []
    )
  end

  def new(pid, prf, masterSecret, peerCert) do
    :gen_server.call(
      pid,
      {:new_session_ticket, prf, masterSecret, peerCert},
      :infinity
    )
  end

  def use(pid, identifiers, prf, handshakeHist) do
    :gen_server.call(
      pid,
      {:use_ticket, identifiers, prf, handshakeHist},
      :infinity
    )
  end

  def init([listener | args]) do
    :erlang.process_flag(:trap_exit, true)
    monitor = :inet.monitor(listener)
    state = initial_state(args)
    {:ok, r_state(state, listen_monitor: monitor)}
  end

  def handle_call(
        {:new_session_ticket, prf, masterSecret, peerCert},
        _From,
        r_state(
          nonce: nonce,
          lifetime: lifeTime,
          max_early_data_size: maxEarlyDataSize,
          stateful: %{id_generator: idGen}
        ) = state0
      ) do
    id = stateful_psk_ticket_id(idGen)
    pSK = :tls_v1.pre_shared_key(masterSecret, ticket_nonce(nonce), prf)
    sessionTicket = new_session_ticket(id, nonce, lifeTime, maxEarlyDataSize)
    state = stateful_ticket_store(id, sessionTicket, prf, pSK, peerCert, state0)
    {:reply, sessionTicket, state}
  end

  def handle_call(
        {:new_session_ticket, prf, masterSecret, peerCert},
        _From,
        r_state(nonce: nonce, stateless: %{}) = state
      ) do
    baseSessionTicket = new_session_ticket_base(state)

    sessionTicket =
      generate_stateless_ticket(baseSessionTicket, prf, masterSecret, peerCert, state)

    {:reply, sessionTicket, r_state(state, nonce: nonce + 1)}
  end

  def handle_call(
        {:use_ticket, identifiers, prf, handshakeHist},
        _From,
        r_state(stateful: %{}) = state0
      ) do
    {result, state} = stateful_use(identifiers, prf, handshakeHist, state0)
    {:reply, result, state}
  end

  def handle_call(
        {:use_ticket, identifiers, prf, handshakeHist},
        _From,
        r_state(stateless: %{}) = state0
      ) do
    {result, state} = stateless_use(identifiers, prf, handshakeHist, state0)
    {:reply, result, state}
  end

  def handle_cast(_Request, state) do
    {:noreply, state}
  end

  def handle_info(
        :rotate_bloom_filters,
        r_state(
          stateless:
            %{bloom_filter: bloomFilter0, warm_up_windows_remaining: warmUp0, window: window} =
              stateless
        ) = state
      ) do
    bloomFilter = :tls_bloom_filter.rotate(bloomFilter0)
    :erlang.send_after(window * 1000, self(), :rotate_bloom_filters)
    warmUp = max(warmUp0 - 1, 0)

    {:noreply,
     r_state(state,
       stateless:
         Map.merge(stateless, %{bloom_filter: bloomFilter, warm_up_windows_remaining: warmUp})
     )}
  end

  def handle_info(
        {:DOWN, monitor, _, _, _},
        r_state(listen_monitor: monitor) = state
      ) do
    {:stop, :normal, state}
  end

  def handle_info(_Info, state) do
    {:noreply, state}
  end

  def terminate(_Reason, _State) do
    :ok
  end

  def code_change(_OldVsn, state, _Extra) do
    {:ok, state}
  end

  def format_status(_Opt, status) do
    status
  end

  defp initial_state([:stateless, lifetime, _, maxEarlyDataSize, :undefined, seed]) do
    r_state(
      nonce: 0,
      stateless: %{seed: stateless_seed(seed), window: :undefined},
      lifetime: lifetime,
      max_early_data_size: maxEarlyDataSize
    )
  end

  defp initial_state([:stateless, lifetime, _, maxEarlyDataSize, {window, k, m}, seed]) do
    :erlang.send_after(window * 1000, self(), :rotate_bloom_filters)

    r_state(
      nonce: 0,
      stateless: %{
        bloom_filter: :tls_bloom_filter.new(k, m),
        warm_up_windows_remaining: warm_up_windows(seed),
        seed: stateless_seed(seed),
        window: window
      },
      lifetime: lifetime,
      max_early_data_size: maxEarlyDataSize
    )
  end

  defp initial_state([:stateful, lifetime, ticketStoreSize, maxEarlyDataSize | _]) do
    r_state(
      lifetime: lifetime,
      max_early_data_size: maxEarlyDataSize,
      nonce: 0,
      stateful: %{
        db: stateful_store(),
        max: ticketStoreSize,
        ref_index: %{},
        id_generator: :crypto.strong_rand_bytes(16)
      }
    )
  end

  defp ticket_age_add() do
    maxTicketAge = 7 * 24 * 3600 * 1000
    intMax = round(:math.pow(2, 32)) - 1
    maxAgeAdd = intMax - maxTicketAge
    <<i::size(32)-unsigned-big-integer>> = :crypto.strong_rand_bytes(4)

    case i > maxAgeAdd do
      true ->
        i - maxTicketAge

      false ->
        i
    end
  end

  defp ticket_nonce(i) do
    <<i::size(64)-unsigned-big-integer>>
  end

  defp new_session_ticket_base(
         r_state(nonce: nonce, lifetime: lifetime, max_early_data_size: maxEarlyDataSize)
       ) do
    new_session_ticket(:undefined, nonce, lifetime, maxEarlyDataSize)
  end

  defp new_session_ticket(id, nonce, lifetime, maxEarlyDataSize) do
    ticketAgeAdd = ticket_age_add()
    extensions = %{early_data: r_early_data_indication_nst(indication: maxEarlyDataSize)}

    r_new_session_ticket(
      ticket: id,
      ticket_lifetime: lifetime,
      ticket_age_add: ticketAgeAdd,
      ticket_nonce: ticket_nonce(nonce),
      extensions: extensions
    )
  end

  defp validate_binder(binder, handshakeHist, pSK, prf, alertDetail) do
    case :tls_handshake_1_3.is_valid_binder(binder, handshakeHist, pSK, prf) do
      true ->
        true

      false ->
        {:error,
         r_alert(
           level: 2,
           description: 47,
           where: %{
             mfa: {:tls_server_session_ticket, :validate_binder, 5},
             line: 236,
             file: ~c"otp/lib/ssl/src/tls_server_session_ticket.erl"
           },
           reason: alertDetail
         )}
    end
  end

  defp stateful_store() do
    :gb_trees.empty()
  end

  defp stateful_ticket_store(
         ref,
         newSessionTicket,
         hash,
         psk,
         peerCert,
         r_state(
           nonce: nonce,
           stateful: %{db: tree0, max: max, ref_index: index0} = stateful
         ) = state0
       ) do
    id = {:erlang.monotonic_time(), :erlang.unique_integer([:monotonic])}
    statefulTicket = {newSessionTicket, hash, psk, peerCert}

    case :gb_trees.size(tree0) do
      ^max ->
        {_, {r_new_session_ticket(ticket: oldRef), _, _, _}, tree1} =
          :gb_trees.take_smallest(tree0)

        tree = :gb_trees.insert(id, statefulTicket, tree1)
        index = :maps.without([oldRef], index0)

        r_state(state0,
          nonce: nonce + 1,
          stateful: Map.merge(stateful, %{db: tree, ref_index: Map.put(index, ref, id)})
        )

      _ ->
        tree = :gb_trees.insert(id, statefulTicket, tree0)

        r_state(state0,
          nonce: nonce + 1,
          stateful: Map.merge(stateful, %{db: tree, ref_index: Map.put(index0, ref, id)})
        )
    end
  end

  defp stateful_use(
         r_offered_psks(identities: identities, binders: binders),
         prf,
         handshakeHist,
         state
       ) do
    stateful_use(identities, binders, prf, handshakeHist, 0, state)
  end

  defp stateful_use([], [], _, _, _, state) do
    {{:ok, :undefined}, state}
  end

  defp stateful_use(
         [r_psk_identity(identity: ref) | refs],
         [binder | binders],
         prf,
         handshakeHist,
         index,
         r_state(stateful: %{db: tree0, ref_index: refIndex0} = stateful) = state
       ) do
    try do
      :maps.get(ref, refIndex0)
    catch
      _, {:badkey, ^ref} ->
        stateful_use(refs, binders, prf, handshakeHist, index + 1, state)
    else
      key ->
        case stateful_usable_ticket(key, prf, binder, handshakeHist, tree0) do
          true ->
            refIndex = :maps.without([ref], refIndex0)

            {{_, _, pSK, peerCert}, tree} =
              :gb_trees.take(
                key,
                tree0
              )

            {{:ok, {index, pSK, peerCert}},
             r_state(state, stateful: Map.merge(stateful, %{db: tree, ref_index: refIndex}))}

          false ->
            stateful_use(refs, binders, prf, handshakeHist, index + 1, state)

          {:error, _} = error ->
            {error, state}
        end
    end
  end

  defp stateful_usable_ticket(key, prf, binder, handshakeHist, tree) do
    case :gb_trees.lookup(key, tree) do
      :none ->
        false

      {:value, {newSessionTicket, ^prf, pSK, _PeerCert}} ->
        case stateful_living_ticket(key, newSessionTicket) do
          true ->
            validate_binder(binder, handshakeHist, pSK, prf, :stateful)

          _ ->
            false
        end

      _ ->
        false
    end
  end

  defp stateful_living_ticket({timeStamp, _}, r_new_session_ticket(ticket_lifetime: lifeTime)) do
    now = :erlang.monotonic_time()
    lived = :erlang.convert_time_unit(now - timeStamp, :native, :seconds)
    lived < lifeTime
  end

  defp stateful_psk_ticket_id(key) do
    unique = :erlang.unique_integer()
    :crypto.crypto_one_time(:aes_128_ecb, key, <<unique::size(128)>>, true)
  end

  defp generate_stateless_ticket(
         r_new_session_ticket(
           ticket_nonce: nonce,
           ticket_age_add: ticketAgeAdd,
           ticket_lifetime: lifetime
         ) = ticket,
         prf,
         masterSecret,
         peerCert,
         r_state(stateless: %{seed: {iV, shard}})
       ) do
    pSK = :tls_v1.pre_shared_key(masterSecret, nonce, prf)
    timestamp = :erlang.system_time(:second)

    encrypted =
      :ssl_cipher.encrypt_ticket(
        r_stateless_ticket(
          hash: prf,
          pre_shared_key: pSK,
          ticket_age_add: ticketAgeAdd,
          lifetime: lifetime,
          timestamp: timestamp,
          certificate: peerCert
        ),
        shard,
        iV
      )

    r_new_session_ticket(ticket, ticket: encrypted)
  end

  defp stateless_use(
         r_offered_psks(identities: identities, binders: binders),
         prf,
         handshakeHist,
         state
       ) do
    stateless_use(identities, binders, prf, handshakeHist, 0, state)
  end

  defp stateless_use([], [], _, _, _, state) do
    {{:ok, :undefined}, state}
  end

  defp stateless_use(
         [
           r_psk_identity(
             identity: encrypted,
             obfuscated_ticket_age: obfAge
           )
           | ids
         ],
         [binder | binders],
         prf,
         handshakeHist,
         index,
         r_state(stateless: %{seed: {iV, shard}, window: window}) = state
       ) do
    case :ssl_cipher.decrypt_ticket(encrypted, shard, iV) do
      r_stateless_ticket(hash: ^prf, pre_shared_key: pSK, certificate: peerCert) = ticket ->
        case stateless_usable_ticket(ticket, obfAge, binder, handshakeHist, window) do
          true ->
            stateless_anti_replay(index, pSK, binder, peerCert, state)

          false ->
            stateless_use(ids, binders, prf, handshakeHist, index + 1, state)

          {:error, _} = error ->
            {error, state}
        end

      _ ->
        stateless_use(ids, binders, prf, handshakeHist, index + 1, state)
    end
  end

  defp stateless_usable_ticket(
         r_stateless_ticket(
           hash: prf,
           ticket_age_add: ticketAgeAdd,
           lifetime: lifetime,
           timestamp: timestamp,
           pre_shared_key: pSK
         ),
         obfAge,
         binder,
         handshakeHist,
         window
       ) do
    case stateless_living_ticket(obfAge, ticketAgeAdd, lifetime, timestamp, window) do
      true ->
        validate_binder(binder, handshakeHist, pSK, prf, :stateless)

      false ->
        false
    end
  end

  defp stateless_living_ticket(0, _, _, _, _) do
    true
  end

  defp stateless_living_ticket(obfAge, ticketAgeAdd, lifetime, timestamp, window) do
    realAge = :erlang.system_time(:second) - timestamp
    reportedAge = obfAge - ticketAgeAdd
    deltaAge = abs(realAge - reportedAge / 1000)

    reportedAge <= lifetime * 1000 and realAge <= lifetime and
      in_window(
        deltaAge,
        window
      )
  end

  defp in_window(_, :undefined) do
    true
  end

  defp in_window(age, window) when is_integer(window) do
    age <= window
  end

  defp stateless_anti_replay(
         _Index,
         _PSK,
         _Binder,
         _PeerCert,
         r_state(stateless: %{warm_up_windows_remaining: warmUpRemaining}) = state
       )
       when warmUpRemaining > 0 do
    {{:ok, :undefined}, state}
  end

  defp stateless_anti_replay(
         index,
         pSK,
         binder,
         peerCert,
         r_state(stateless: %{bloom_filter: bloomFilter0} = stateless) = state
       ) do
    case :tls_bloom_filter.contains(
           bloomFilter0,
           binder
         ) do
      true ->
        {{:ok, :undefined}, state}

      false ->
        bloomFilter =
          :tls_bloom_filter.add_elem(
            bloomFilter0,
            binder
          )

        {{:ok, {index, pSK, peerCert}},
         r_state(state, stateless: Map.put(stateless, :bloom_filter, bloomFilter))}
    end
  end

  defp stateless_anti_replay(index, pSK, _Binder, peerCert, state) do
    {{:ok, {index, pSK, peerCert}}, state}
  end

  defp stateless_seed(:undefined) do
    {:crypto.strong_rand_bytes(16), :crypto.strong_rand_bytes(32)}
  end

  defp stateless_seed(seed) do
    <<iV::size(16)-binary, shard::size(32)-binary, _::binary>> = :crypto.hash(:sha512, seed)
    {iV, shard}
  end

  defp warm_up_windows(:undefined) do
    0
  end

  defp warm_up_windows(_) do
    2
  end

  def handle_trace(
        :rle,
        {:call,
         {:tls_server_session_ticket, :init, [[listenSocket, mode, lifetime, storeSize | _T]]}},
        stack
      ) do
    {:io_lib.format(
       ~c"(*server) ([ListenSocket = ~w Mode = ~w Lifetime = ~w StoreSize = ~w, ...])",
       [listenSocket, mode, lifetime, storeSize]
     ), [{:role, :server} | stack]}
  end

  def handle_trace(
        :ssn,
        {:call, {:tls_server_session_ticket, :terminate, [reason, _State]}},
        stack
      ) do
    {:io_lib.format(~c"(Reason ~w)", [reason]), stack}
  end

  def handle_trace(
        :ssn,
        {:call, {:tls_server_session_ticket, :handle_call, [callTuple, _From, _State]}},
        stack
      ) do
    {:io_lib.format(~c"(Call = ~w)", [:erlang.element(1, callTuple)]), stack}
  end

  def handle_trace(
        :ssn,
        {:call,
         {:tls_server_session_ticket, :handle_call,
          [
            {call = :use_ticket,
             {:offered_psks, [{:psk_identity, pskIdentity, _ObfAge}], [binder]}, _Prf,
             _HandshakeHist},
            _From,
            _State
          ]}},
        stack
      ) do
    {:io_lib.format(~c"(Call = ~w PskIdentity = ~W Binder = ~W)", [
       call,
       pskIdentity,
       5,
       binder,
       5
     ]), stack}
  end

  def handle_trace(
        :ssn,
        {:call,
         {:tls_server_session_ticket, :validate_binder,
          [binder, _HandshakeHist, pSK, _Prf, _AlertDetail]}},
        stack
      ) do
    {:io_lib.format(~c"(Binder = ~W PSK = ~W)", [binder, 5, pSK, 5]), stack}
  end

  def handle_trace(
        :ssn,
        {:call,
         {:tls_server_session_ticket, :initial_state,
          [[mode, _Lifetime, _StoreSize, _MaxEarlyDataSize, window, seed]]}},
        stack
      ) do
    {:io_lib.format(~c"(Mode = ~w Window = ~w Seed = ~W)", [mode, window, seed, 5]), stack}
  end

  def handle_trace(
        :ssn,
        {:call,
         {:tls_server_session_ticket, :generate_stateless_ticket,
          [_BaseTicket, _Prf, masterSecret, _State]}},
        stack
      ) do
    {:io_lib.format(~c"(MasterSecret = ~W)", [masterSecret, 5]), stack}
  end

  def handle_trace(
        :ssn,
        {:call,
         {:tls_server_session_ticket, :stateless_use,
          [
            [{:psk_identity, encrypted, _ObfAge} | _],
            [
              binder
              | _
            ],
            _Prf,
            _HandshakeHist,
            _Index,
            _State
          ]}},
        stack
      ) do
    {:io_lib.format(~c"(Encrypted = ~W Binder = ~W)", [encrypted, 5, binder, 5]), stack}
  end

  def handle_trace(
        :ssn,
        {:call, {:tls_server_session_ticket, :in_window, [realAge, window]}},
        stack
      ) do
    {:io_lib.format(~c"(RealAge = ~w Window = ~w)", [realAge, window]), stack}
  end

  def handle_trace(
        :ssn,
        {:call,
         {:tls_server_session_ticket, :stateless_usable_ticket,
          [
            {:stateless_ticket, _Prf, _PreSharedKey, _TicketAgeAdd, _Lifetime, _Timestamp},
            _ObfAge,
            binder,
            _HandshakeHist,
            window
          ]}},
        stack
      ) do
    {:io_lib.format(~c"(Binder = ~W Window = ~w)", [binder, 5, window]), stack}
  end

  def handle_trace(
        :ssn,
        {:call,
         {:tls_server_session_ticket, :stateless_anti_replay, [_Index, pSK, _Binder, _State]}},
        stack
      ) do
    {:io_lib.format(~c"(PSK = ~W)", [pSK, 5]), stack}
  end

  def handle_trace(
        :ssn,
        {:return_from, {:tls_server_session_ticket, :stateless_use, 6},
         {{:ok, {_Index, pSK}}, _State}},
        stack
      ) do
    {:io_lib.format(~c"PSK = ~W", [pSK, 5]), stack}
  end

  def handle_trace(
        :ssn,
        {:return_from, {:tls_server_session_ticket, :generate_stateless_ticket, 4},
         {:new_session_ticket, _LifeTime, _AgeAdd, _Nonce, ticket, _Extensions}},
        stack
      ) do
    {:io_lib.format(~c"Ticket = ~W", [ticket, 5]), stack}
  end

  def handle_trace(
        :ssn,
        {:return_from, {:tls_server_session_ticket, :initial_state, 1},
         {:state, _Stateless = %{seed: {iV, shard}, window: window}, _Stateful = :undefined,
          _Nonce, _Lifetime, _MaxEarlyDataSize, listenMonitor}},
        stack
      ) do
    {:io_lib.format(
       ~c"IV = ~W Shard = ~W Window = ~w ListenMonitor = ~w",
       [iV, 5, shard, 5, window, listenMonitor]
     ), stack}
  end

  def handle_trace(
        :ssn,
        {:return_from, {:tls_server_session_ticket, :stateless_anti_replay, 4},
         {{:ok, {_Index, pSK}}, _State}},
        stack
      ) do
    {:io_lib.format(~c"ticket OK ~W", [pSK, 5]), stack}
  end

  def handle_trace(
        :ssn,
        {:return_from, {:tls_server_session_ticket, :stateless_anti_replay, 4}, return},
        stack
      ) do
    {:io_lib.format(~c"ticket REJECTED ~W", [return, 5]), stack}
  end
end
