defmodule :m_tls_client_connection_1_3 do
  use Bitwise
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

  Record.defrecord(:r_alert, :alert,
    level: :undefined,
    description: :undefined,
    where: :undefined,
    role: :undefined,
    reason: :undefined
  )

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

  Record.defrecord(:r_srp_user, :srp_user,
    generator: :undefined,
    prime: :undefined,
    salt: :undefined,
    verifier: :undefined
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

  Record.defrecord(:r_static_env, :static_env,
    role: :undefined,
    transport_cb: :undefined,
    protocol_cb: :undefined,
    data_tag: :undefined,
    close_tag: :undefined,
    error_tag: :undefined,
    passive_tag: :undefined,
    host: :undefined,
    port: :undefined,
    socket: :undefined,
    cert_db: :undefined,
    session_cache: :undefined,
    session_cache_cb: :undefined,
    crl_db: :undefined,
    file_ref_db: :undefined,
    cert_db_ref: :undefined,
    trackers: :undefined
  )

  Record.defrecord(:r_handshake_env, :handshake_env,
    client_hello_version: :undefined,
    unprocessed_handshake_events: 0,
    tls_handshake_history: :undefined,
    expecting_finished: false,
    renegotiation: :undefined,
    resumption: false,
    change_cipher_spec_sent: false,
    sni_guided_cert_selection: false,
    early_data_accepted: false,
    allow_renegotiate: true,
    continue_status: :undefined,
    sni_hostname: :undefined,
    max_frag_enum: :undefined,
    expecting_next_protocol_negotiation: false,
    next_protocol: :undefined,
    alpn: :undefined,
    negotiated_protocol: :undefined,
    hashsign_algorithm: {:undefined, :undefined},
    cert_hashsign_algorithm: {:undefined, :undefined},
    kex_algorithm: :undefined,
    kex_keys: :undefined,
    diffie_hellman_params: :undefined,
    srp_params: :undefined,
    public_key_info: :undefined,
    premaster_secret: :undefined,
    server_psk_identity: :undefined,
    cookie_iv_shard: :undefined,
    ocsp_stapling_state: %{ocsp_stapling: false, ocsp_expect: :no_staple}
  )

  Record.defrecord(:r_connection_env, :connection_env,
    user_application: :undefined,
    downgrade: :undefined,
    socket_terminated: false,
    socket_tls_closed: false,
    negotiated_version: :undefined,
    erl_dist_handle: :undefined,
    cert_key_alts: :undefined
  )

  Record.defrecord(:r_state, :state,
    static_env: :undefined,
    connection_env: :undefined,
    ssl_options: :undefined,
    socket_options: :undefined,
    handshake_env: :undefined,
    flight_buffer: [],
    client_certificate_status: :not_requested,
    protocol_specific: %{},
    session: :undefined,
    key_share: :undefined,
    connection_states: :undefined,
    protocol_buffers: :undefined,
    user_data_buffer: :undefined,
    bytes_to_read: :undefined,
    start_or_recv_from: :undefined,
    log_level: :undefined
  )

  Record.defrecord(:r_ssl_tls, :ssl_tls,
    type: :undefined,
    version: :undefined,
    fragment: :undefined,
    early_data: false
  )

  Record.defrecord(:r_protocol_buffers, :protocol_buffers,
    tls_record_buffer: <<>>,
    tls_handshake_buffer: <<>>,
    tls_cipher_texts: []
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
  @behaviour :gen_statem
  def callback_mode() do
    [:state_functions, :state_enter]
  end

  def init([:client, sender, host, port, socket, options, user, cbInfo]) do
    state0 =
      r_state(protocol_specific: map) =
      :tls_gen_connection_1_3.initial_state(
        :client,
        sender,
        host,
        port,
        socket,
        options,
        user,
        cbInfo
      )

    try do
      state = :ssl_gen_statem.init_ssl_config(r_state(state0, :ssl_options), :client, state0)
      :tls_gen_connection.initialize_tls_sender(state)
      :gen_statem.enter_loop(:tls_client_connection_1_3, [], :initial_hello, state)
    catch
      error ->
        eState = r_state(state0, protocol_specific: Map.put(map, :error, error))
        :gen_statem.enter_loop(:tls_client_connection_1_3, [], :config_error, eState)
    end
  end

  def terminate(
        {:shutdown, {:sender_died, reason}},
        _StateName,
        r_state(
          static_env:
            r_static_env(
              socket: socket,
              transport_cb: transport
            )
        ) = state
      ) do
    :ssl_gen_statem.handle_trusted_certs_db(state)
    :tls_gen_connection.close(reason, socket, transport, :undefined)
  end

  def terminate(reason, stateName, state) do
    :ssl_gen_statem.terminate(reason, stateName, state)
  end

  def format_status(type, data) do
    :ssl_gen_statem.format_status(type, data)
  end

  def code_change(_OldVsn, stateName, state, _) do
    {:ok, stateName, state}
  end

  def initial_hello(:enter, _, state) do
    {:keep_state, state}
  end

  def initial_hello(type, event, state) do
    :ssl_gen_statem.initial_hello(type, event, state)
  end

  def config_error(:enter, _, state) do
    {:keep_state, state}
  end

  def config_error(type, event, state) do
    :ssl_gen_statem.config_error(type, event, state)
  end

  def user_hello(:enter, _, state) do
    {:keep_state, state}
  end

  def user_hello({:call, from}, :cancel, state) do
    :gen_statem.reply(from, :ok)

    :ssl_gen_statem.handle_own_alert(
      r_alert(
        level: 2,
        description: 90,
        where: %{
          mfa: {:tls_client_connection_1_3, :user_hello, 3},
          line: 177,
          file: ~c"otp/lib/ssl/src/tls_client_connection_1_3.erl"
        },
        reason: :user_canceled
      ),
      :user_hello,
      state
    )
  end

  def user_hello(
        {:call, from},
        {:handshake_continue, newOptions, timeout},
        r_state(
          handshake_env: r_handshake_env(continue_status: :pause) = hSEnv,
          ssl_options: options0
        ) = state0
      ) do
    try do
      :ssl.update_options(newOptions, :client, options0)
    catch
      {:error, reason} ->
        :gen_statem.reply(from, {:error, reason})

        :ssl_gen_statem.handle_own_alert(
          r_alert(
            level: 2,
            description: 80,
            where: %{
              mfa: {:tls_client_connection_1_3, :user_hello, 3},
              line: 195,
              file: ~c"otp/lib/ssl/src/tls_client_connection_1_3.erl"
            },
            reason: reason
          ),
          :user_hello,
          state0
        )
    else
      options ->
        state = :ssl_gen_statem.ssl_config(options, :client, state0)

        {:next_state, :wait_sh,
         r_state(state,
           start_or_recv_from: from,
           handshake_env: r_handshake_env(hSEnv, continue_status: :continue)
         ), [{{:timeout, :handshake}, timeout, :close}]}
    end
  end

  def user_hello(type, msg, state) do
    :tls_gen_connection_1_3.user_hello(type, msg, state)
  end

  def start(:enter, _, state0) do
    state = :tls_gen_connection_1_3.handle_middlebox(state0)
    {:next_state, :start, state, []}
  end

  def start(:internal = type, r_change_cipher_spec() = msg, state) do
    :tls_gen_connection_1_3.handle_change_cipher_spec(type, msg, :start, state)
  end

  def start(
        :internal,
        r_server_hello(
          extensions: %{
            server_hello_selected_version:
              r_server_hello_selected_version(selected_version: version)
          }
        ) = serverHello,
        r_state(ssl_options: %{handshake: :full, versions: supportedVersions}) = state
      ) do
    case :tls_record.is_acceptable_version(
           version,
           supportedVersions
         ) do
      true ->
        handle_exlusive_1_3_hello_or_hello_retry_request(
          serverHello,
          state
        )

      false ->
        :ssl_gen_statem.handle_own_alert(
          r_alert(
            level: 2,
            description: 70,
            where: %{
              mfa: {:tls_client_connection_1_3, :start, 3},
              line: 224,
              file: ~c"otp/lib/ssl/src/tls_client_connection_1_3.erl"
            }
          ),
          :start,
          state
        )
    end
  end

  def start(
        :internal,
        r_server_hello(
          extensions:
            %{
              server_hello_selected_version:
                r_server_hello_selected_version(selected_version: version)
            } = extensions
        ),
        r_state(
          ssl_options: %{versions: supportedVersions},
          start_or_recv_from: from,
          handshake_env: r_handshake_env(continue_status: :pause)
        ) = state
      ) do
    case :tls_record.is_acceptable_version(
           version,
           supportedVersions
         ) do
      true ->
        {:next_state, :user_hello, r_state(state, start_or_recv_from: :undefined),
         [{:postpone, true}, {:reply, from, {:ok, extensions}}]}

      false ->
        :ssl_gen_statem.handle_own_alert(
          r_alert(
            level: 2,
            description: 70,
            where: %{
              mfa: {:tls_client_connection_1_3, :start, 3},
              line: 243,
              file: ~c"otp/lib/ssl/src/tls_client_connection_1_3.erl"
            }
          ),
          :start,
          state
        )
    end
  end

  def start(
        :internal,
        r_server_hello() = serverHello,
        r_state(handshake_env: r_handshake_env(continue_status: :continue)) = state
      ) do
    handle_exlusive_1_3_hello_or_hello_retry_request(
      serverHello,
      state
    )
  end

  def start(:internal, r_server_hello(), state0) do
    :ssl_gen_statem.handle_own_alert(
      r_alert(
        level: 2,
        description: 70,
        where: %{
          mfa: {:tls_client_connection_1_3, :start, 3},
          line: 253,
          file: ~c"otp/lib/ssl/src/tls_client_connection_1_3.erl"
        }
      ),
      :start,
      state0
    )
  end

  def start(:info, msg, state) do
    :tls_gen_connection.handle_info(msg, :start, state)
  end

  def start(type, msg, state) do
    :ssl_gen_statem.handle_common_event(type, msg, :start, state)
  end

  def wait_sh(:enter, _, state0) do
    state = :tls_gen_connection_1_3.handle_middlebox(state0)
    {:next_state, :wait_sh, state, []}
  end

  def wait_sh(:internal = type, r_change_cipher_spec() = msg, state) do
    :tls_gen_connection_1_3.handle_change_cipher_spec(type, msg, :wait_sh, state)
  end

  def wait_sh(
        :internal,
        r_server_hello(extensions: extensions),
        r_state(
          handshake_env: r_handshake_env(continue_status: :pause),
          start_or_recv_from: from
        ) = state
      ) do
    {:next_state, :user_hello, r_state(state, start_or_recv_from: :undefined),
     [{:postpone, true}, {:reply, from, {:ok, extensions}}]}
  end

  def wait_sh(
        :internal,
        r_server_hello(session_id: <<>>) = hello,
        r_state(
          session: r_session(session_id: <<>>),
          ssl_options: %{middlebox_comp_mode: false}
        ) = state0
      ) do
    case handle_server_hello(hello, state0) do
      r_alert() = alert ->
        :ssl_gen_statem.handle_own_alert(alert, :wait_sh, state0)

      {state1, :start, serverHello} ->
        {:next_state, :start, state1, [{:next_event, :internal, serverHello}]}

      {state1, :wait_ee} ->
        :tls_gen_connection.next_event(:wait_ee, :no_record, state1)
    end
  end

  def wait_sh(
        :internal,
        r_server_hello() = hello,
        r_state(protocol_specific: pS, ssl_options: sSLOpts) = state0
      )
      when not :erlang.is_map_key(:middlebox_comp_mode, sSLOpts) do
    isRetry = :maps.get(:hello_retry, pS, false)

    case handle_server_hello(hello, state0) do
      r_alert() = alert ->
        :ssl_gen_statem.handle_own_alert(alert, :wait_sh, state0)

      {state1 = r_state(), :start, serverHello} ->
        {:next_state, :start, state1, [{:next_event, :internal, serverHello}]}

      {state1, :wait_ee} when isRetry == true ->
        :tls_gen_connection.next_event(:wait_ee, :no_record, state1)

      {state1, :wait_ee} when isRetry == false ->
        :tls_gen_connection.next_event(:hello_middlebox_assert, :no_record, state1)
    end
  end

  def wait_sh(:info, msg, state) do
    :tls_gen_connection.handle_info(msg, :wait_sh, state)
  end

  def wait_sh(type, msg, state) do
    :ssl_gen_statem.handle_common_event(type, msg, :wait_sh, state)
  end

  def hello_middlebox_assert(:enter, _, state) do
    {:keep_state, state}
  end

  def hello_middlebox_assert(:internal, r_change_cipher_spec(), state) do
    :tls_gen_connection.next_event(:wait_ee, :no_record, state)
  end

  def hello_middlebox_assert(
        :internal = type,
        r_encrypted_extensions() = msg,
        r_state(ssl_options: %{log_level: level}) = state
      ) do
    :ssl_logger.log(
      :warning,
      level,
      %{
        description: ~c"Failed to assert middlebox server message",
        reason: [{:missing, r_change_cipher_spec()}]
      },
      %{
        mfa: {:tls_client_connection_1_3, :hello_middlebox_assert, 3},
        line: 321,
        file: ~c"otp/lib/ssl/src/tls_client_connection_1_3.erl"
      }
    )

    :ssl_gen_statem.handle_common_event(type, msg, :hello_middlebox_assert, state)
  end

  def hello_middlebox_assert(:info, msg, state) do
    :tls_gen_connection.handle_info(msg, :hello_middlebox_assert, state)
  end

  def hello_middlebox_assert(type, msg, state) do
    :ssl_gen_statem.handle_common_event(type, msg, :hello_middlebox_assert, state)
  end

  def hello_retry_middlebox_assert(:enter, _, state) do
    {:keep_state, state}
  end

  def hello_retry_middlebox_assert(:internal, r_change_cipher_spec(), state) do
    :tls_gen_connection.next_event(:wait_sh, :no_record, state)
  end

  def hello_retry_middlebox_assert(
        :internal = type,
        r_server_hello() = msg,
        r_state(ssl_options: %{log_level: level}) = state
      ) do
    :ssl_logger.log(
      :warning,
      level,
      %{
        description: ~c"Failed to assert middlebox server message",
        reason: [{:missing, r_change_cipher_spec()}]
      },
      %{
        mfa: {:tls_client_connection_1_3, :hello_retry_middlebox_assert, 3},
        line: 340,
        file: ~c"otp/lib/ssl/src/tls_client_connection_1_3.erl"
      }
    )

    :ssl_gen_statem.handle_common_event(type, msg, :hello_retry_middlebox_assert, state)
  end

  def hello_retry_middlebox_assert(:info, msg, state) do
    :tls_gen_connection.handle_info(msg, :hello_retry_middlebox_assert, state)
  end

  def hello_retry_middlebox_assert(type, msg, state) do
    :ssl_gen_statem.handle_common_event(type, msg, :hello_retry_middlebox_assert, state)
  end

  def wait_ee(:enter, _, state0) do
    state = :tls_gen_connection_1_3.handle_middlebox(state0)
    {:next_state, :wait_ee, state, []}
  end

  def wait_ee(:internal = type, r_change_cipher_spec() = msg, state) do
    :tls_gen_connection_1_3.handle_change_cipher_spec(type, msg, :wait_ee, state)
  end

  def wait_ee(:internal, r_encrypted_extensions(extensions: extensions), state0) do
    case handle_encrypted_extensions(
           extensions,
           state0
         ) do
      r_alert() = alert ->
        :ssl_gen_statem.handle_own_alert(alert, :wait_ee, state0)

      {state, nextState} ->
        :tls_gen_connection.next_event(nextState, :no_record, state)
    end
  end

  def wait_ee(:info, msg, state) do
    :tls_gen_connection.handle_info(msg, :wait_ee, state)
  end

  def wait_ee(type, msg, state) do
    :ssl_gen_statem.handle_common_event(type, msg, :wait_ee, state)
  end

  def wait_cert_cr(:enter, _, state0) do
    state = :tls_gen_connection_1_3.handle_middlebox(state0)
    {:next_state, :wait_cert_cr, state, []}
  end

  def wait_cert_cr(:internal = type, r_change_cipher_spec() = msg, state) do
    :tls_gen_connection_1_3.handle_change_cipher_spec(type, msg, :wait_cert_cr, state)
  end

  def wait_cert_cr(:internal, r_certificate_1_3() = certificate, state0) do
    case handle_certificate(certificate, state0) do
      {r_alert() = alert, state} ->
        :ssl_gen_statem.handle_own_alert(alert, :wait_cert_cr, state)

      {state1, nextState} ->
        :tls_gen_connection.next_event(nextState, :no_record, state1)
    end
  end

  def wait_cert_cr(:internal, r_certificate_request_1_3() = certificateRequest, state0) do
    case handle_certificate_request(
           certificateRequest,
           state0
         ) do
      r_alert() = alert ->
        :ssl_gen_statem.handle_own_alert(alert, :wait_cert_cr, state0)

      {state1, nextState} ->
        :tls_gen_connection.next_event(nextState, :no_record, state1)
    end
  end

  def wait_cert_cr(:info, msg, state) do
    :tls_gen_connection.handle_info(msg, :wait_cert_cr, state)
  end

  def wait_cert_cr(type, msg, state) do
    :ssl_gen_statem.handle_common_event(type, msg, :wait_cert_cr, state)
  end

  def wait_cert(type, msg, state) do
    :tls_gen_connection_1_3.wait_cert(type, msg, state)
  end

  def wait_cv(:internal, r_certificate_verify_1_3() = certificateVerify, state0) do
    {ref, maybe} = :tls_gen_connection_1_3.do_maybe()

    try do
      {state, nextState} =
        maybe.(
          :tls_handshake_1_3.verify_certificate_verify(
            state0,
            certificateVerify
          )
        )

      :tls_gen_connection.next_event(nextState, :no_record, state)
    catch
      {^ref, {r_alert() = alert, aState}} ->
        :ssl_gen_statem.handle_own_alert(alert, :wait_cv, aState)
    end
  end

  def wait_cv(type, msg, state) do
    :tls_gen_connection_1_3.wait_cv(type, msg, state)
  end

  def wait_finished(:enter, _, state0) do
    state = :tls_gen_connection_1_3.handle_middlebox(state0)
    {:next_state, :wait_finished, state, []}
  end

  def wait_finished(:internal = type, r_change_cipher_spec() = msg, state) do
    :tls_gen_connection_1_3.handle_change_cipher_spec(type, msg, :wait_finished, state)
  end

  def wait_finished(
        :internal,
        r_finished(verify_data: verifyData),
        r_state(static_env: r_static_env(protocol_cb: connection)) = state0
      ) do
    {ref, maybe} = :tls_gen_connection_1_3.do_maybe()

    try do
      maybe.(
        :tls_handshake_1_3.validate_finished(
          state0,
          verifyData
        )
      )

      state1 =
        :tls_gen_connection_1_3.maybe_queue_change_cipher_spec(
          state0,
          :first
        )

      state2 = maybe_send_end_of_early_data(state1)
      state3 = maybe.(maybe_queue_cert_cert_cv(state2))
      finished = :tls_handshake_1_3.finished(state3)
      state4 = connection.queue_handshake(finished, state3)
      {state5, _} = connection.send_handshake_flight(state4)
      state6 = :tls_handshake_1_3.calculate_traffic_secrets(state5)
      state7 = :tls_handshake_1_3.maybe_calculate_resumption_master_secret(state6)
      exporterMasterSecret = :tls_handshake_1_3.calculate_exporter_master_secret(state7)
      state8 = :tls_handshake_1_3.forget_master_secret(state7)
      state9 = :ssl_record.step_encryption_state(state8)

      {record, r_state(protocol_specific: pS) = state} =
        :ssl_gen_statem.prepare_connection(
          state9,
          :tls_gen_connection
        )

      :tls_gen_connection.next_event(
        :connection,
        record,
        r_state(state,
          protocol_specific: Map.put(pS, :exporter_master_secret, exporterMasterSecret)
        ),
        [{{:timeout, :handshake}, :cancel}]
      )
    catch
      {^ref, r_alert() = alert} ->
        :ssl_gen_statem.handle_own_alert(alert, :wait_finished, state0)
    end
  end

  def wait_finished(:info, msg, state) do
    :tls_gen_connection.handle_info(msg, :wait_finished, state)
  end

  def wait_finished(type, msg, state) do
    :ssl_gen_statem.handle_common_event(type, msg, :wait_finished, state)
  end

  def connection(type, msg, state) do
    :tls_gen_connection_1_3.connection(type, msg, state)
  end

  def downgrade(type, msg, state) do
    :tls_gen_connection_1_3.downgrade(type, msg, state)
  end

  defp handle_exlusive_1_3_hello_or_hello_retry_request(serverHello, state0) do
    case do_handle_exlusive_1_3_hello_or_hello_retry_request(
           serverHello,
           state0
         ) do
      r_alert() = alert ->
        :ssl_gen_statem.handle_own_alert(alert, :start, state0)

      {state, nextState} ->
        {:next_state, nextState, state, []}
    end
  end

  defp do_handle_exlusive_1_3_hello_or_hello_retry_request(
         r_server_hello(
           cipher_suite: selectedCipherSuite,
           random: random,
           session_id: sessionId,
           extensions: extensions
         ),
         r_state(
           static_env:
             r_static_env(
               host: host,
               port: port,
               cert_db: certDbHandle,
               cert_db_ref: certDbRef,
               protocol_cb: connection,
               transport_cb: transport,
               socket: socket
             ),
           handshake_env:
             r_handshake_env(
               renegotiation: {renegotiation, _},
               ocsp_stapling_state: ocspState
             ),
           connection_env: r_connection_env(negotiated_version: negotiatedVersion),
           protocol_specific: pS,
           ssl_options:
             %{
               ciphers: clientCiphers,
               supported_groups: clientGroups0,
               use_ticket: useTicket,
               session_tickets: sessionTickets,
               log_level: logLevel
             } = sslOpts,
           session: session0,
           connection_states: connectionStates0
         ) = state0
       ) do
    {ref, maybe} = :tls_gen_connection_1_3.do_maybe()

    try do
      clientGroups = maybe.(:tls_handshake_1_3.get_supported_groups(clientGroups0))
      cookie = :maps.get(:cookie, extensions, :undefined)
      keyShare = :maps.get(:key_share, extensions, :undefined)
      selectedGroup = server_group(keyShare)

      case keyShare do
        r_key_share_hello_retry_request() ->
          maybe.(
            validate_selected_group(
              selectedGroup,
              clientGroups
            )
          )

        _ ->
          :ok
      end

      maybe.(
        validate_cipher_suite(
          selectedCipherSuite,
          clientCiphers
        )
      )

      clientKeyShare = :ssl_cipher.generate_client_shares([selectedGroup])

      ticketData =
        :tls_handshake_1_3.get_ticket_data(
          self(),
          sessionTickets,
          useTicket
        )

      ocspNonce = :maps.get(:ocsp_nonce, ocspState, :undefined)

      hello0 =
        :tls_handshake.client_hello(
          host,
          port,
          connectionStates0,
          sslOpts,
          sessionId,
          renegotiation,
          clientKeyShare,
          ticketData,
          ocspNonce,
          certDbHandle,
          certDbRef
        )

      hello1 =
        :tls_handshake_1_3.maybe_add_cookie_extension(
          cookie,
          hello0
        )

      state1 =
        :tls_handshake_1_3.update_start_state(
          state0,
          %{
            cipher: selectedCipherSuite,
            key_share: clientKeyShare,
            session_id: sessionId,
            group: selectedGroup,
            random: random
          }
        )

      state2 = :tls_handshake_1_3.replace_ch1_with_message_hash(state1)
      r_state(handshake_env: r_handshake_env(tls_handshake_history: hHistory0)) = state2

      hello =
        :tls_handshake_1_3.maybe_add_binders(hello1, hHistory0, ticketData, negotiatedVersion)

      {binMsg0, connectionStates, hHistory} =
        connection.encode_handshake(hello, negotiatedVersion, connectionStates0, hHistory0)

      {r_state(handshake_env: hsEnv) = state3, binMsg} =
        :tls_gen_connection_1_3.maybe_prepend_change_cipher_spec(
          state2,
          binMsg0
        )

      :tls_socket.send(transport, socket, binMsg)
      :ssl_logger.debug(logLevel, :outbound, :handshake, hello)
      :ssl_logger.debug(logLevel, :outbound, :record, binMsg)

      state =
        r_state(state3,
          connection_states: connectionStates,
          session: r_session(session0, session_id: r_client_hello(hello, :session_id)),
          handshake_env: r_handshake_env(hsEnv, tls_handshake_history: hHistory),
          key_share: clientKeyShare
        )

      case :maps.get(:hello_retry, pS, false) and :maps.get(:middlebox_comp_mode, sslOpts, true) do
        true ->
          {state, :hello_retry_middlebox_assert}

        false ->
          {state, :wait_sh}
      end
    catch
      {^ref, r_alert() = alert} ->
        alert
    end
  end

  defp handle_server_hello(
         r_server_hello(
           cipher_suite: selectedCipherSuite,
           random: random,
           session_id: sessionId,
           extensions: extensions
         ) = serverHello,
         r_state(
           key_share: clientKeyShare,
           ssl_options: %{
             ciphers: clientCiphers,
             supported_groups: clientGroups0,
             session_tickets: sessionTickets,
             use_ticket: useTicket
           }
         ) = state0
       ) do
    {ref, maybe} = :tls_gen_connection_1_3.do_maybe()

    try do
      clientGroups = maybe.(:tls_handshake_1_3.get_supported_groups(clientGroups0))

      serverKeyShare =
        server_share(
          :maps.get(
            :key_share,
            extensions
          )
        )

      serverPreSharedKey = :maps.get(:pre_shared_key, extensions, :undefined)

      maybe.(
        :tls_handshake_1_3.maybe_hello_retry_request(
          serverHello,
          state0
        )
      )

      state1 =
        :tls_gen_connection_1_3.handle_resumption(
          state0,
          serverPreSharedKey
        )

      maybe.(
        validate_cipher_suite(
          selectedCipherSuite,
          clientCiphers
        )
      )

      maybe.(
        validate_server_key_share(
          clientGroups,
          serverKeyShare
        )
      )

      r_key_share_entry(
        group: selectedGroup,
        key_exchange: serverPublicKey
      ) = serverKeyShare

      clientPrivateKey =
        client_private_key(
          selectedGroup,
          r_key_share_client_hello(clientKeyShare, :client_shares)
        )

      state2 =
        :tls_handshake_1_3.update_start_state(
          state1,
          %{
            cipher: selectedCipherSuite,
            key_share: clientKeyShare,
            session_id: sessionId,
            group: selectedGroup,
            peer_public_key: serverPublicKey,
            random: random
          }
        )

      r_state(connection_states: connectionStates) = state2

      %{security_parameters: secParamsR} =
        :ssl_record.pending_connection_state(
          connectionStates,
          :read
        )

      r_security_parameters(prf_algorithm: hKDFAlgo) = secParamsR

      pSK =
        maybe.(
          :tls_handshake_1_3.get_pre_shared_key(
            sessionTickets,
            useTicket,
            hKDFAlgo,
            serverPreSharedKey
          )
        )

      state3 =
        :tls_handshake_1_3.calculate_handshake_secrets(
          serverPublicKey,
          clientPrivateKey,
          selectedGroup,
          pSK,
          state2
        )

      state4 = :ssl_record.step_encryption_state_read(state3)
      {state4, :wait_ee}
    catch
      {^ref, {state, stateName, ^serverHello}} ->
        {state, stateName, serverHello}

      {^ref, r_alert() = alert} ->
        alert
    end
  end

  defp handle_encrypted_extensions(extensions, state0) do
    {ref, maybe} = :tls_gen_connection_1_3.do_maybe()

    try do
      aLPNProtocol0 = :maps.get(:alpn, extensions, :undefined)
      aLPNProtocol = decode_alpn(aLPNProtocol0)
      earlyDataIndication = :maps.get(:early_data, extensions, :undefined)
      maybe.(maybe_max_fragment_length(extensions, state0))

      state1 =
        maybe_check_early_data_indication(
          earlyDataIndication,
          state0
        )

      maybe.(maybe_resumption(state1))
      r_state(handshake_env: hsEnv) = state1
      state2 = r_state(state1, handshake_env: r_handshake_env(hsEnv, alpn: aLPNProtocol))
      {state2, :wait_cert_cr}
    catch
      {^ref, r_alert() = alert} ->
        alert

      {^ref, {_, _} = next} ->
        next
    end
  end

  defp handle_certificate(r_certificate_1_3() = certificate, state0) do
    {ref, maybe} = :tls_gen_connection_1_3.do_maybe()

    try do
      maybe.(
        :tls_handshake_1_3.process_certificate(
          certificate,
          state0
        )
      )
    catch
      {^ref, r_alert() = alert} ->
        {alert, state0}

      {^ref, {r_alert() = alert, state}} ->
        {alert, state}
    end
  end

  defp handle_certificate_request(r_certificate_request_1_3() = certificateRequest, state0) do
    {ref, maybe} = :tls_gen_connection_1_3.do_maybe()

    try do
      maybe.(
        :tls_handshake_1_3.process_certificate_request(
          certificateRequest,
          state0
        )
      )
    catch
      {^ref, r_alert() = alert} ->
        {alert, state0}
    end
  end

  def maybe_send_early_data(
        r_state(
          handshake_env: r_handshake_env(tls_handshake_history: {hist, _}),
          protocol_specific: %{sender: _Sender},
          ssl_options:
            %{
              versions: [{3, 4} | _],
              use_ticket: useTicket,
              session_tickets: sessionTickets,
              early_data: earlyData
            } = _SslOpts0
        ) = state0
      )
      when useTicket !== [:undefined] and earlyData !== :undefined do
    state1 =
      :tls_gen_connection_1_3.maybe_queue_change_cipher_spec(
        state0,
        :last
      )

    earlyDataSize = :tls_handshake_1_3.early_data_size(earlyData)

    case :tls_handshake_1_3.get_pre_shared_key_early_data(
           sessionTickets,
           useTicket
         ) do
      {:ok, {pSK, cipher, hKDF, maxSize}}
      when earlyDataSize <= maxSize ->
        state2 =
          :tls_handshake_1_3.calculate_client_early_traffic_secret(
            hist,
            pSK,
            cipher,
            hKDF,
            state1
          )

        state3 = :ssl_record.step_encryption_state_write(state2)
        {:ok, :tls_handshake_1_3.encode_early_data(cipher, state3)}

      {:ok, {_, _, _, maxSize}} ->
        {:error,
         r_alert(
           level: 2,
           description: 47,
           where: %{
             mfa: {:tls_client_connection_1_3, :maybe_send_early_data, 1},
             line: 777,
             file: ~c"otp/lib/ssl/src/tls_client_connection_1_3.erl"
           },
           reason: {:too_much_early_data, {:max, maxSize}}
         )}

      {:error, alert} ->
        {:error, alert}
    end
  end

  def maybe_send_early_data(state) do
    {:ok, state}
  end

  defp maybe_send_end_of_early_data(
         r_state(
           handshake_env: r_handshake_env(early_data_accepted: true),
           protocol_specific: %{sender: _Sender},
           ssl_options: %{versions: [{3, 4} | _], use_ticket: useTicket, early_data: earlyData},
           static_env: r_static_env(protocol_cb: connection)
         ) = state0
       )
       when useTicket !== [:undefined] and earlyData !== :undefined do
    state1 = connection.queue_handshake(r_end_of_early_data(), state0)
    :ssl_record.step_encryption_state_write(state1)
  end

  defp maybe_send_end_of_early_data(state) do
    state
  end

  def maybe_automatic_session_resumption(
        r_state(
          ssl_options:
            %{
              versions: [version | _],
              ciphers: userSuites,
              early_data: earlyData,
              session_tickets: sessionTickets,
              server_name_indication: sNI
            } = sslOpts0
        ) = state0
      )
      when version >= {3, 4} and sessionTickets === :auto do
    availableCipherSuites =
      :ssl_handshake.available_suites(
        userSuites,
        version
      )

    hashAlgos = cipher_hash_algos(availableCipherSuites)
    ciphers = :tls_handshake_1_3.ciphers_for_early_data(availableCipherSuites)
    earlyDataSize = :tls_handshake_1_3.early_data_size(earlyData)
    keyPair = :tls_client_ticket_store.find_ticket(self(), ciphers, hashAlgos, sNI, earlyDataSize)

    useTicket =
      :tls_handshake_1_3.choose_ticket(
        keyPair,
        earlyData
      )

    :tls_client_ticket_store.lock_tickets(
      self(),
      [useTicket]
    )

    state = r_state(state0, ssl_options: Map.put(sslOpts0, :use_ticket, [useTicket]))
    {[useTicket], state}
  end

  def maybe_automatic_session_resumption(r_state(ssl_options: %{use_ticket: useTicket}) = state) do
    {useTicket, state}
  end

  defp maybe_resumption(r_state(handshake_env: r_handshake_env(resumption: true)) = state) do
    {:error, {state, :wait_finished}}
  end

  defp maybe_resumption(_) do
    :ok
  end

  defp server_group(:undefined) do
    :undefined
  end

  defp server_group(r_key_share_server_hello(server_share: r_key_share_entry(group: group))) do
    group
  end

  defp server_group(r_key_share_hello_retry_request(selected_group: group)) do
    group
  end

  defp server_share(r_key_share_server_hello(server_share: share)) do
    share
  end

  defp server_share(r_key_share_hello_retry_request(selected_group: share)) do
    share
  end

  defp client_private_key(group, clientShares) do
    case :lists.keysearch(group, 2, clientShares) do
      {:value, r_key_share_entry(key_exchange: clientPrivateKey = r_ECPrivateKey())} ->
        clientPrivateKey

      {:value, r_key_share_entry(key_exchange: {_, clientPrivateKey})} ->
        clientPrivateKey

      false ->
        :no_suitable_key
    end
  end

  defp maybe_check_early_data_indication(
         earlyDataIndication,
         r_state(
           handshake_env: hsEnv,
           ssl_options: %{versions: [{3, 4} | _], use_ticket: useTicket, early_data: earlyData}
         ) = state
       )
       when useTicket !== [:undefined] and earlyData !== :undefined and
              earlyDataIndication !== :undefined do
    signal_user_early_data(state, :accepted)
    r_state(state, handshake_env: r_handshake_env(hsEnv, early_data_accepted: true))
  end

  defp maybe_check_early_data_indication(
         earlyDataIndication,
         r_state(
           protocol_specific: %{sender: _Sender},
           ssl_options:
             %{versions: [{3, 4} | _], use_ticket: useTicket, early_data: earlyData} = _SslOpts0
         ) = state
       )
       when useTicket !== [:undefined] and earlyData !== :undefined and
              earlyDataIndication === :undefined do
    signal_user_early_data(state, :rejected)
    :ssl_record.step_encryption_state_write(state)
  end

  defp maybe_check_early_data_indication(_, state) do
    :ssl_record.step_encryption_state_write(state)
  end

  defp signal_user_early_data(
         r_state(
           connection_env: r_connection_env(user_application: {_, user}),
           static_env:
             r_static_env(
               socket: socket,
               protocol_cb: connection,
               transport_cb: transport,
               trackers: trackers
             )
         ) = state,
         result
       ) do
    cPids = connection.pids(state)
    sslSocket = connection.socket(cPids, transport, socket, trackers)
    send(user, {:ssl, sslSocket, {:early_data, result}})
  end

  defp maybe_max_fragment_length(extensions, state) do
    serverMaxFragEnum = :maps.get(:max_frag_enum, extensions, :undefined)

    clientMaxFragEnum =
      :ssl_handshake.max_frag_enum(
        :maps.get(
          :max_fragment_length,
          r_state(state, :ssl_options),
          :undefined
        )
      )

    cond do
      serverMaxFragEnum == clientMaxFragEnum ->
        :ok

      true ->
        {:error,
         r_alert(
           level: 2,
           description: 47,
           where: %{
             mfa: {:tls_client_connection_1_3, :maybe_max_fragment_length, 2},
             line: 916,
             file: ~c"otp/lib/ssl/src/tls_client_connection_1_3.erl"
           }
         )}
    end
  end

  defp cipher_hash_algos(ciphers) do
    fun = fn cipher ->
      %{prf: hash} = :ssl_cipher_format.suite_bin_to_map(cipher)
      hash
    end

    :lists.map(fun, ciphers)
  end

  defp maybe_queue_cert_cert_cv(r_state(client_certificate_status: :not_requested) = state) do
    {:ok, state}
  end

  defp maybe_queue_cert_cert_cv(
         r_state(
           connection_states: _ConnectionStates0,
           session:
             r_session(
               session_id: _SessionId,
               own_certificates: ownCerts
             ),
           ssl_options: %{} = _SslOpts,
           key_share: _KeyShare,
           handshake_env: r_handshake_env(tls_handshake_history: _HHistory0),
           static_env:
             r_static_env(
               protocol_cb: connection,
               cert_db: certDbHandle,
               cert_db_ref: certDbRef,
               socket: _Socket,
               transport_cb: _Transport
             )
         ) = state0
       ) do
    {ref, maybe} = :tls_gen_connection_1_3.do_maybe()

    try do
      certificate =
        maybe.(:tls_handshake_1_3.certificate(ownCerts, certDbHandle, certDbRef, <<>>, :client))

      state1 = connection.queue_handshake(certificate, state0)

      state =
        maybe.(
          maybe_queue_cert_verify(
            certificate,
            state1
          )
        )

      {:ok, state}
    catch
      {^ref, r_alert() = alert} ->
        {:error, alert}
    end
  end

  defp maybe_queue_cert_verify(r_certificate_1_3(certificate_list: []), state) do
    {:ok, state}
  end

  defp maybe_queue_cert_verify(
         _Certificate,
         r_state(
           connection_states: _ConnectionStates0,
           session:
             r_session(
               sign_alg: signatureScheme,
               private_key: certPrivateKey
             ),
           static_env: r_static_env(protocol_cb: connection)
         ) = state
       ) do
    {ref, maybe} = :tls_gen_connection_1_3.do_maybe()

    try do
      certificateVerify =
        maybe.(
          :tls_handshake_1_3.certificate_verify(
            certPrivateKey,
            signatureScheme,
            state,
            :client
          )
        )

      {:ok, connection.queue_handshake(certificateVerify, state)}
    catch
      {^ref, r_alert() = alert} ->
        {:error, alert}
    end
  end

  defp decode_alpn(:undefined) do
    :undefined
  end

  defp decode_alpn(encoded) do
    [decoded] = :ssl_handshake.decode_alpn(encoded)
    decoded
  end

  defp validate_server_key_share([], _) do
    {:error,
     r_alert(
       level: 2,
       description: 47,
       where: %{
         mfa: {:tls_client_connection_1_3, :validate_server_key_share, 1},
         line: 992,
         file: ~c"otp/lib/ssl/src/tls_client_connection_1_3.erl"
       }
     )}
  end

  defp validate_server_key_share([group | _ClientGroups], r_key_share_entry(group: group)) do
    :ok
  end

  defp validate_server_key_share([_ | clientGroups], r_key_share_entry() = serverKeyShare) do
    validate_server_key_share(clientGroups, serverKeyShare)
  end

  defp validate_selected_group(selectedGroup, [selectedGroup | _]) do
    {:error,
     r_alert(
       level: 2,
       description: 47,
       where: %{
         mfa: {:tls_client_connection_1_3, :validate_selected_group, 2},
         line: 1000,
         file: ~c"otp/lib/ssl/src/tls_client_connection_1_3.erl"
       },
       reason:
         ~c"Selected group sent by the server shall not correspond to a group which was provided in the key_share extension"
     )}
  end

  defp validate_selected_group(selectedGroup, clientGroups) do
    case :lists.member(selectedGroup, clientGroups) do
      true ->
        :ok

      false ->
        {:error,
         r_alert(
           level: 2,
           description: 47,
           where: %{
             mfa: {:tls_client_connection_1_3, :validate_selected_group, 2},
             line: 1008,
             file: ~c"otp/lib/ssl/src/tls_client_connection_1_3.erl"
           },
           reason:
             ~c"Selected group sent by the server shall correspond to a group which was provided in the supported_groups extension"
         )}
    end
  end

  defp validate_cipher_suite(cipher, clientCiphers) do
    case :lists.member(cipher, clientCiphers) do
      true ->
        :ok

      false ->
        {:error,
         r_alert(
           level: 2,
           description: 47,
           where: %{
             mfa: {:tls_client_connection_1_3, :validate_cipher_suite, 2},
             line: 1021,
             file: ~c"otp/lib/ssl/src/tls_client_connection_1_3.erl"
           }
         )}
    end
  end
end
