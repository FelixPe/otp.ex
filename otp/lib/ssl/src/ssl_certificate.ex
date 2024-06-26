defmodule :m_ssl_certificate do
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

  def trusted_cert_and_paths([peer], certDbHandle, certDbRef, partialChainHandler) do
    otpCert = :public_key.pkix_decode_cert(peer, :otp)
    chain = [r_cert(der: peer, otp: otpCert)]

    case :public_key.pkix_is_self_signed(otpCert) do
      true ->
        [{:selfsigned_peer, chain}]

      false ->
        [
          handle_incomplete_chain(
            chain,
            partialChainHandler,
            {:unknown_ca, chain},
            certDbHandle,
            certDbRef
          )
        ]
    end
  end

  def trusted_cert_and_paths(chain0, certDbHandle, certDbRef, partialChainHandler) do
    chain =
      for der <- chain0 do
        r_cert(
          der: der,
          otp: :public_key.pkix_decode_cert(der, :otp)
        )
      end

    paths = paths(chain, certDbHandle)

    :lists.map(
      fn path ->
        case handle_partial_chain(path, partialChainHandler, certDbHandle, certDbRef) do
          {:unknown_ca, _} = result ->
            handle_incomplete_chain(chain, partialChainHandler, result, certDbHandle, certDbRef)

          {_Root, _NewChain} = result ->
            result
        end
      end,
      paths
    )
  end

  def certificate_chain([], _, _) do
    {:error, :no_cert}
  end

  def certificate_chain(derCert, certDbHandle, certsDbRef)
      when is_binary(derCert) do
    erlCert = :public_key.pkix_decode_cert(derCert, :otp)
    cert = r_cert(der: derCert, otp: erlCert)
    {:ok, root, chain} = build_certificate_chain(cert, certDbHandle, certsDbRef, [cert], [])
    chain_result(root, chain, :encoded)
  end

  def certificate_chain(r_OTPCertificate() = otpCert, certDbHandle, certsDbRef) do
    derCert = :public_key.pkix_encode(:OTPCertificate, otpCert, :otp)
    cert = r_cert(der: derCert, otp: otpCert)
    {:ok, root, chain} = build_certificate_chain(cert, certDbHandle, certsDbRef, [cert], [])
    chain_result(root, chain, :encoded)
  end

  def certificate_chain(r_cert() = cert, certDbHandle, certsDbRef) do
    {:ok, root, chain} = build_certificate_chain(cert, certDbHandle, certsDbRef, [cert], [])
    chain_result(root, chain, :encoded)
  end

  def certificate_chain(derCert, certDbHandle, certsDbRef, candidates, type)
      when is_binary(derCert) do
    erlCert = :public_key.pkix_decode_cert(derCert, :otp)
    cert = r_cert(der: derCert, otp: erlCert)

    {:ok, root, chain} =
      build_certificate_chain(cert, certDbHandle, certsDbRef, [cert], candidates)

    chain_result(root, chain, type)
  end

  def certificate_chain(r_OTPCertificate() = otpCert, certDbHandle, certsDbRef, candidates, type) do
    derCert = :public_key.pkix_encode(:OTPCertificate, otpCert, :otp)
    cert = r_cert(der: derCert, otp: otpCert)

    {:ok, root, chain} =
      build_certificate_chain(cert, certDbHandle, certsDbRef, [cert], candidates)

    chain_result(root, chain, type)
  end

  def certificate_chain(r_cert() = cert, certDbHandle, certsDbRef, candidates, type) do
    {:ok, root, chain} =
      build_certificate_chain(cert, certDbHandle, certsDbRef, [cert], candidates)

    chain_result(root, chain, type)
  end

  def file_to_certificats(file, dbHandle) do
    {:ok, list} =
      :ssl_manager.cache_pem_file(
        file,
        dbHandle
      )

    for {:Certificate, bin, :not_encrypted} <- list do
      bin
    end
  end

  def file_to_crls(file, dbHandle) do
    {:ok, list} =
      :ssl_manager.cache_pem_file(
        file,
        dbHandle
      )

    for {:CertificateList, bin, :not_encrypted} <- list do
      bin
    end
  end

  def validate(
        _,
        {:extension, r_Extension(extnID: {2, 5, 29, 37}, critical: critical, extnValue: keyUse)},
        %{path_len: 1} = userState
      ) do
    case is_valid_extkey_usage(keyUse, critical, userState) do
      true ->
        {:valid, userState}

      false ->
        {:unknown, userState}
    end
  end

  def validate(_, {:extension, _}, userState) do
    {:unknown, userState}
  end

  def validate(issuer, {:bad_cert, :cert_expired}, %{issuer: issuer}) do
    {:fail, {:bad_cert, :root_cert_expired}}
  end

  def validate(_, {:bad_cert, _} = reason, _) do
    {:fail, reason}
  end

  def validate(cert, :valid, %{path_len: n} = userState) do
    case verify_sign(cert, userState) do
      true ->
        case :maps.get(:cert_ext, userState, :undefined) do
          :undefined ->
            {:valid, Map.put(userState, :path_len, n - 1)}

          _ ->
            verify_cert_extensions(
              cert,
              Map.put(userState, :path_len, n - 1)
            )
        end

      false ->
        {:fail, {:bad_cert, :invalid_signature}}
    end
  end

  def validate(
        cert,
        :valid_peer,
        userState = %{role: :client, server_name: hostname, customize_hostname_check: customize}
      )
      when hostname !== :disable do
    case verify_hostname(hostname, customize, cert, userState) do
      {:valid, ^userState} ->
        validate(cert, :valid, userState)

      error ->
        error
    end
  end

  def validate(cert, :valid_peer, userState) do
    validate(cert, :valid, userState)
  end

  def is_valid_key_usage(keyUse, use) do
    :lists.member(use, keyUse)
  end

  def select_extension(_, []) do
    :undefined
  end

  def select_extension(id, [r_Extension(extnID: id) = extension | _]) do
    extension
  end

  def select_extension(id, [_ | extensions]) do
    select_extension(id, extensions)
  end

  def extensions_list(:asn1_NOVALUE) do
    []
  end

  def extensions_list(extensions) do
    extensions
  end

  def public_key_type({1, 2, 840, 113_549, 1, 1, 10}) do
    :rsa_pss_pss
  end

  def public_key_type({1, 2, 840, 113_549, 1, 1, 1}) do
    :rsa
  end

  def public_key_type({1, 2, 840, 10040, 4, 1}) do
    :dsa
  end

  def public_key_type({1, 2, 840, 10045, 2, 1}) do
    :ecdsa
  end

  def public_key_type(oid) do
    {_, sign} = :public_key.pkix_sign_types(oid)
    sign
  end

  def foldl_db(isIssuerFun, certDbHandle, []) do
    :ssl_pkix_db.foldl(isIssuerFun, :issuer_not_found, certDbHandle)
  end

  def foldl_db(isIssuerFun, _, [_ | _] = listDb) do
    :lists.foldl(isIssuerFun, :issuer_not_found, listDb)
  end

  def find_cross_sign_root_paths([], _CertDbHandle, _CertDbRef, _InvalidatedList) do
    []
  end

  def find_cross_sign_root_paths([_ | rest] = path, certDbHandle, certDbRef, invalidatedList) do
    case find_alternative_root(path, certDbHandle, certDbRef, invalidatedList) do
      :unknown_ca ->
        find_cross_sign_root_paths(rest, certDbHandle, certDbRef, invalidatedList)

      root ->
        [{root, path}]
    end
  end

  def handle_cert_auths(chain, [], _, _) do
    {:ok, chain}
  end

  def handle_cert_auths([cert], certAuths, certDbHandle, certDbRef) do
    case certificate_chain(cert, certDbHandle, certDbRef, [], :both) do
      {:ok, {_, [^cert | _] = eChain}, {_, [_ | dCerts]}} ->
        case cert_auth_member(
               cert_issuers(dCerts),
               certAuths
             ) do
          true ->
            {:ok, eChain}

          false ->
            {:error, eChain, :not_in_auth_domain}
        end

      _ ->
        {:ok, [cert]}
    end
  end

  def handle_cert_auths([_ | certs] = eChain, certAuths, _, _) do
    case cert_auth_member(
           cert_issuers(certs),
           certAuths
         ) do
      true ->
        {:ok, eChain}

      false ->
        {:error, eChain, :not_in_auth_domain}
    end
  end

  def available_cert_key_pairs(certKeyGroups) do
    revAlgos = [:dsa, :rsa, :rsa_pss_pss, :ecdsa]
    cert_key_group_to_list(revAlgos, certKeyGroups, [])
  end

  def available_cert_key_pairs(certKeyGroups, {3, 4}) do
    revAlgos = [:rsa, :rsa_pss_pss, :ecdsa, :eddsa]
    cert_key_group_to_list(revAlgos, certKeyGroups, [])
  end

  def available_cert_key_pairs(certKeyGroups, {3, 3}) do
    revAlgos = [:dsa, :rsa, :rsa_pss_pss, :ecdsa]
    cert_key_group_to_list(revAlgos, certKeyGroups, [])
  end

  def available_cert_key_pairs(certKeyGroups, version) when version < {3, 3} do
    revAlgos = [:dsa, :rsa, :ecdsa]
    cert_key_group_to_list(revAlgos, certKeyGroups, [])
  end

  defp cert_key_group_to_list([], _, acc) do
    final_group_list(acc)
  end

  defp cert_key_group_to_list([algo | rest], certKeyGroups, acc) do
    certKeyPairs = :maps.get(algo, certKeyGroups, [])
    cert_key_group_to_list(rest, certKeyGroups, certKeyPairs ++ acc)
  end

  defp final_group_list([]) do
    [%{certs: [[]], private_key: %{}}]
  end

  defp final_group_list(list) do
    list
  end

  defp encoded_chain(r_cert(der: cert), certs) do
    {cert,
     for r_cert(der: c) <- certs do
       c
     end}
  end

  defp encoded_chain(res, certs) do
    {res,
     for r_cert(der: otpC) <- certs do
       otpC
     end}
  end

  defp decoded_chain(r_cert(otp: otpCert), certs) do
    {otpCert,
     for r_cert(otp: otpC) <- certs do
       otpC
     end}
  end

  defp decoded_chain(res, certs) do
    {res,
     for r_cert(otp: otpC) <- certs do
       otpC
     end}
  end

  defp chain_result(root0, chain0, :encoded) do
    {root, chain} = encoded_chain(root0, chain0)
    {:ok, root, chain}
  end

  defp chain_result(root0, chain0, :decoded) do
    {root, chain} = decoded_chain(root0, chain0)
    {:ok, root, chain}
  end

  defp chain_result(root0, chain0, :both) do
    {eRoot, eChain} = encoded_chain(root0, chain0)
    {dRoot, dChain} = decoded_chain(root0, chain0)
    {:ok, {eRoot, eChain}, {dRoot, dChain}}
  end

  defp build_certificate_chain(
         r_cert(otp: otpCert) = cert,
         certDbHandle,
         certsDbRef,
         chain,
         listDb
       ) do
    issuerAndSelfSigned =
      case :public_key.pkix_is_self_signed(otpCert) do
        true ->
          {:public_key.pkix_issuer_id(otpCert, :self), true}

        false ->
          {:public_key.pkix_issuer_id(otpCert, :other), false}
      end

    case issuerAndSelfSigned do
      {_, true = selfSigned} ->
        do_certificate_chain(
          certDbHandle,
          certsDbRef,
          chain,
          :ignore,
          :ignore,
          selfSigned,
          listDb
        )

      {{:error, :issuer_not_found}, selfSigned} ->
        case find_issuer(cert, certDbHandle, certsDbRef, listDb, []) do
          {:ok, {serialNr, issuer}} ->
            do_certificate_chain(
              certDbHandle,
              certsDbRef,
              chain,
              serialNr,
              issuer,
              selfSigned,
              listDb
            )

          _Err ->
            {:ok, :undefined, :lists.reverse(chain)}
        end

      {{:ok, {serialNr, issuer}}, selfSigned} ->
        do_certificate_chain(
          certDbHandle,
          certsDbRef,
          chain,
          serialNr,
          issuer,
          selfSigned,
          listDb
        )
    end
  end

  defp do_certificate_chain(_, _, [rootCert | _] = chain, _, _, true, _) do
    {:ok, rootCert, :lists.reverse(chain)}
  end

  defp do_certificate_chain(certDbHandle, certsDbRef, chain, serialNr, issuer, _, listDb) do
    case :ssl_manager.lookup_trusted_cert(certDbHandle, certsDbRef, serialNr, issuer) do
      {:ok, cert} ->
        build_certificate_chain(cert, certDbHandle, certsDbRef, [cert | chain], listDb)

      _ ->
        {:ok, :undefined, :lists.reverse(chain)}
    end
  end

  defp find_alternative_root([cert | _], certDbHandle, certDbRef, invalidatedList) do
    case find_issuer(cert, certDbHandle, certDbRef, [], invalidatedList) do
      {:error, :issuer_not_found} ->
        :unknown_ca

      {:ok, {serialNr, issuerId}} ->
        case :ssl_manager.lookup_trusted_cert(certDbHandle, certDbRef, serialNr, issuerId) do
          :undefined ->
            :unknown_ca

          {:ok, r_cert(otp: otpIssuer)} ->
            case :public_key.pkix_is_self_signed(otpIssuer) do
              true ->
                otpIssuer

              false ->
                :unknown_ca
            end
        end
    end
  end

  defp find_issuer(
         r_cert(der: derCert, otp: otpCert),
         certDbHandle,
         certsDbRef,
         listDb,
         invalidatedList
       ) do
    isIssuerFun = fn
      {_Key, r_cert(otp: erlCertCandidate)}, acc ->
        case :public_key.pkix_is_issuer(
               otpCert,
               erlCertCandidate
             ) do
          true ->
            case verify_cert_signer(
                   derCert,
                   r_OTPCertificate(erlCertCandidate, :tbsCertificate)
                 ) and
                   not :lists.member(
                     erlCertCandidate,
                     invalidatedList
                   ) do
              true ->
                throw(
                  :public_key.pkix_issuer_id(
                    erlCertCandidate,
                    :self
                  )
                )

              false ->
                acc
            end

          false ->
            acc
        end

      _, acc ->
        acc
    end

    result =
      case is_reference(certsDbRef) do
        true when listDb == [] ->
          certEntryList =
            :ssl_pkix_db.select_certentries_by_ref(
              certsDbRef,
              certDbHandle
            )

          do_find_issuer(isIssuerFun, certDbHandle, certEntryList)

        false when listDb == [] ->
          {:extracted, certsData} = certsDbRef

          certEntryList =
            for {:decoded, entry} <- certsData do
              entry
            end

          do_find_issuer(isIssuerFun, certDbHandle, certEntryList)

        _ ->
          do_find_issuer(isIssuerFun, certDbHandle, listDb)
      end

    case result do
      :issuer_not_found ->
        {:error, :issuer_not_found}

      ^result ->
        result
    end
  end

  defp do_find_issuer(issuerFun, certDbHandle, certDb) do
    try do
      foldl_db(issuerFun, certDbHandle, certDb)
    catch
      {:ok, _} = return ->
        return
    end
  end

  defp is_valid_extkey_usage(keyUse, true, %{role: role})
       when is_list(keyUse) do
    is_valid_key_usage(keyUse, ext_keysage(role))
  end

  defp is_valid_extkey_usage(keyUse, true, %{role: role}) do
    is_valid_key_usage([keyUse], ext_keysage(role))
  end

  defp is_valid_extkey_usage(_, false, _) do
    false
  end

  defp ext_keysage(:client) do
    {1, 3, 6, 1, 5, 5, 7, 3, 1}
  end

  defp ext_keysage(:server) do
    {1, 3, 6, 1, 5, 5, 7, 3, 2}
  end

  defp verify_cert_signer(binCert, signerTBSCert) do
    publicKey = public_key(r_OTPTBSCertificate(signerTBSCert, :subjectPublicKeyInfo))
    :public_key.pkix_verify(binCert, publicKey)
  end

  defp public_key(
         r_OTPSubjectPublicKeyInfo(
           algorithm:
             r_PublicKeyAlgorithm(
               algorithm: {1, 2, 840, 10045, 2, 1},
               parameters: params
             ),
           subjectPublicKey: point
         )
       ) do
    {point, params}
  end

  defp public_key(
         r_OTPSubjectPublicKeyInfo(
           algorithm: r_PublicKeyAlgorithm(algorithm: {1, 3, 101, 112}),
           subjectPublicKey: point
         )
       ) do
    {point, {:namedCurve, {1, 3, 101, 112}}}
  end

  defp public_key(
         r_OTPSubjectPublicKeyInfo(
           algorithm: r_PublicKeyAlgorithm(algorithm: {1, 3, 101, 113}),
           subjectPublicKey: point
         )
       ) do
    {point, {:namedCurve, {1, 3, 101, 113}}}
  end

  defp public_key(
         r_OTPSubjectPublicKeyInfo(
           algorithm: r_PublicKeyAlgorithm(algorithm: {1, 2, 840, 113_549, 1, 1, 1}),
           subjectPublicKey: key
         )
       ) do
    key
  end

  defp public_key(
         r_OTPSubjectPublicKeyInfo(
           algorithm:
             r_PublicKeyAlgorithm(
               algorithm: {1, 2, 840, 113_549, 1, 1, 10},
               parameters: params
             ),
           subjectPublicKey: key
         )
       ) do
    {key, params}
  end

  defp public_key(
         r_OTPSubjectPublicKeyInfo(
           algorithm:
             r_PublicKeyAlgorithm(
               algorithm: {1, 2, 840, 10040, 4, 1},
               parameters: {:params, params}
             ),
           subjectPublicKey: key
         )
       ) do
    {key, params}
  end

  defp other_issuer(r_cert(otp: otpCert) = cert, certDbHandle, certDbRef) do
    case :public_key.pkix_issuer_id(otpCert, :other) do
      {:ok, issuerId} ->
        {:other, issuerId}

      {:error, :issuer_not_found} ->
        case find_issuer(cert, certDbHandle, certDbRef, [], []) do
          {:ok, issuerId} ->
            {:other, issuerId}

          other ->
            other
        end
    end
  end

  defp verify_hostname(hostname, customize, cert, userState)
       when is_tuple(hostname) do
    case :public_key.pkix_verify_hostname(cert, [{:ip, hostname}], customize) do
      true ->
        {:valid, userState}

      false ->
        {:fail, {:bad_cert, :hostname_check_failed}}
    end
  end

  defp verify_hostname(hostname, customize, cert, userState) do
    hostId =
      case :inet.parse_strict_address(hostname) do
        {:ok, iP} ->
          {:ip, iP}

        _ ->
          {:dns_id, hostname}
      end

    case :public_key.pkix_verify_hostname(cert, [hostId], customize) do
      true ->
        {:valid, userState}

      false ->
        {:fail, {:bad_cert, :hostname_check_failed}}
    end
  end

  defp verify_cert_extensions(cert, %{cert_ext: certExts} = userState) do
    id = :public_key.pkix_subject_id(cert)
    extensions = :maps.get(id, certExts, [])
    verify_cert_extensions(cert, userState, extensions, %{})
  end

  defp verify_cert_extensions(cert, userState, [], _) do
    {:valid, Map.put(userState, :issuer, cert)}
  end

  defp verify_cert_extensions(
         cert,
         %{ocsp_responder_certs: responderCerts, ocsp_state: oscpState, issuer: issuer} =
           userState,
         [r_certificate_status(response: ocspResponsDer) | exts],
         context
       ) do
    %{ocsp_nonce: nonce} = oscpState

    case :public_key.pkix_ocsp_validate(cert, issuer, ocspResponsDer, responderCerts, nonce) do
      :valid ->
        verify_cert_extensions(cert, userState, exts, context)

      {:bad_cert, _} = status ->
        {:fail, status}
    end
  end

  defp verify_cert_extensions(cert, userState, [_ | exts], context) do
    verify_cert_extensions(cert, userState, exts, context)
  end

  defp verify_sign(_, %{version: version}) when version < {3, 3} do
    true
  end

  defp verify_sign(
         cert,
         %{version: {3, 3}, signature_algs: signAlgs, signature_algs_cert: :undefined}
       ) do
    is_supported_signature_algorithm_1_2(cert, signAlgs)
  end

  defp verify_sign(
         cert,
         %{version: {3, 3}, signature_algs_cert: signAlgs}
       ) do
    is_supported_signature_algorithm_1_2(cert, signAlgs)
  end

  defp verify_sign(
         cert,
         %{version: {3, 4}, signature_algs: signAlgs, signature_algs_cert: :undefined}
       ) do
    is_supported_signature_algorithm_1_3(cert, signAlgs)
  end

  defp verify_sign(
         cert,
         %{version: {3, 4}, signature_algs_cert: signAlgs}
       ) do
    is_supported_signature_algorithm_1_3(cert, signAlgs)
  end

  defp is_supported_signature_algorithm_1_2(
         r_OTPCertificate(
           signatureAlgorithm: r_SignatureAlgorithm(algorithm: {1, 2, 840, 10040, 4, 3})
         ),
         signAlgs
       ) do
    :lists.member({:sha, :dsa}, signAlgs)
  end

  defp is_supported_signature_algorithm_1_2(
         r_OTPCertificate(
           signatureAlgorithm: r_SignatureAlgorithm(algorithm: {1, 2, 840, 113_549, 1, 1, 10})
         ) = cert,
         signAlgs
       ) do
    is_supported_signature_algorithm_1_3(cert, signAlgs)
  end

  defp is_supported_signature_algorithm_1_2(
         r_OTPCertificate(signatureAlgorithm: signAlg),
         signAlgs
       ) do
    scheme = :ssl_cipher.signature_algorithm_to_scheme(signAlg)
    {hash, sign, _} = :ssl_cipher.scheme_to_components(scheme)

    :ssl_cipher.is_supported_sign(
      {hash, pre_1_3_sign(sign)},
      :ssl_cipher.signature_schemes_1_2(signAlgs)
    )
  end

  defp is_supported_signature_algorithm_1_3(
         r_OTPCertificate(signatureAlgorithm: signAlg),
         signAlgs
       ) do
    scheme = :ssl_cipher.signature_algorithm_to_scheme(signAlg)
    :ssl_cipher.is_supported_sign(scheme, signAlgs)
  end

  defp pre_1_3_sign(:rsa_pkcs1) do
    :rsa
  end

  defp pre_1_3_sign(other) do
    other
  end

  defp paths(chain, certDbHandle) do
    paths(chain, chain, certDbHandle, [])
  end

  defp paths([root], _, _, path) do
    [[root | path]]
  end

  defp paths([r_cert(otp: c1) = cert1, r_cert(otp: c2) = cert2 | rest], chain, certDbHandle, path) do
    case :public_key.pkix_is_issuer(c1, c2) do
      true ->
        paths([cert2 | rest], chain, certDbHandle, [cert1 | path])

      false ->
        unorded_or_extraneous(chain, certDbHandle)
    end
  end

  defp unorded_or_extraneous([peer | unorderedChain], certDbHandle) do
    chainCandidates = extraneous_chains(unorderedChain)

    :lists.map(
      fn candidate ->
        path_candidate(peer, candidate, certDbHandle)
      end,
      chainCandidates
    )
  end

  defp path_candidate(cert, chainCandidateCAs, certDbHandle) do
    {:ok, extractedCerts} = :ssl_pkix_db.extract_trusted_certs({:der_otp, chainCandidateCAs})

    case build_certificate_chain(cert, certDbHandle, extractedCerts, [cert], []) do
      {:ok, :undefined, chain} ->
        :lists.reverse(chain)

      {:ok, root, chain} ->
        [root | :lists.reverse(chain)]
    end
  end

  defp handle_partial_chain(
         [
           r_cert(
             der: dERIssuerCert,
             otp: otpIssuerCert
           ) = cert
           | rest
         ] = path,
         partialChainHandler,
         certDbHandle,
         certDbRef
       ) do
    case :public_key.pkix_is_self_signed(otpIssuerCert) do
      true ->
        {:ok, {serialNr, issuerId}} =
          :public_key.pkix_issuer_id(
            otpIssuerCert,
            :self
          )

        case :ssl_manager.lookup_trusted_cert(certDbHandle, certDbRef, serialNr, issuerId) do
          {:ok, r_cert(der: ^dERIssuerCert)} ->
            maybe_shorten_path(path, partialChainHandler, {cert, rest})

          {:ok, _} ->
            maybe_shorten_path(path, partialChainHandler, {:invalid_issuer, path})

          _ ->
            maybe_shorten_path(path, partialChainHandler, {:unknown_ca, path})
        end

      false ->
        case other_issuer(cert, certDbHandle, certDbRef) do
          {:other, {serialNr, issuerId}} ->
            case :ssl_manager.lookup_trusted_cert(certDbHandle, certDbRef, serialNr, issuerId) do
              {:ok, r_cert(otp: newOtp) = newCert} ->
                case :public_key.pkix_is_self_signed(newOtp) do
                  true ->
                    maybe_shorten_path([newCert | path], partialChainHandler, {newCert, path})

                  false ->
                    maybe_shorten_path(
                      [newCert | path],
                      partialChainHandler,
                      {:unknown_ca, [newCert | path]}
                    )
                end

              _ ->
                maybe_shorten_path(path, partialChainHandler, {:unknown_ca, path})
            end

          {:error, :issuer_not_found} ->
            maybe_shorten_path(path, partialChainHandler, {:unknown_ca, path})
        end
    end
  end

  defp maybe_shorten_path(path, partialChainHandler, default) do
    derCerts =
      for r_cert(der: der) <- path do
        der
      end

    try do
      partialChainHandler.(derCerts)
    catch
      _, _ ->
        default
    else
      {:trusted_ca, root} ->
        new_trusted_path(root, path, default)

      :unknown_ca ->
        default
    end
  end

  defp new_trusted_path(derCert, [r_cert(der: derCert) = cert | path], _) do
    {cert, path}
  end

  defp new_trusted_path(derCert, [_ | rest], default) do
    new_trusted_path(derCert, rest, default)
  end

  defp new_trusted_path(_, [], default) do
    default
  end

  defp handle_incomplete_chain(
         [r_cert() = peer | _] = chain0,
         partialChainHandler,
         default,
         certDbHandle,
         certDbRef
       ) do
    case build_certificate_chain(peer, certDbHandle, certDbRef, [peer], []) do
      {:ok, _, [^peer | _] = chainCandidate}
      when chainCandidate !== chain0 ->
        case :lists.prefix(chain0, chainCandidate) do
          true ->
            {root, chain} =
              handle_partial_chain(
                :lists.reverse(chainCandidate),
                partialChainHandler,
                certDbHandle,
                certDbRef
              )

            {root, chain}

          false ->
            default
        end

      _ ->
        default
    end
  end

  defp extraneous_chains(certs) do
    subjects =
      for r_cert(otp: oTP) = cert <- certs do
        {subject(oTP), cert}
      end

    duplicates = find_duplicates(subjects)
    build_candidates(duplicates, 4, 16)
  end

  defp build_candidates(map, duplicates, combinations) do
    subjects = :maps.keys(map)
    build_candidates(subjects, map, duplicates, 1, combinations, [])
  end

  defp build_candidates([], _, _, _, _, acc) do
    acc
  end

  defp build_candidates([h | t], map, duplicates, combinations, max, acc0) do
    case :maps.get(h, map) do
      {certs, counter}
      when counter > 1 and duplicates > 0 and counter * combinations <= max ->
        case acc0 do
          [] ->
            acc =
              for cert <- certs do
                [cert]
              end

            build_candidates(t, map, duplicates - 1, combinations * counter, max, acc)

          _Else ->
            acc =
              for cert <- certs, l <- acc0 do
                [cert | l]
              end

            build_candidates(t, map, duplicates - 1, combinations * counter, max, acc)
        end

      {[cert | _Throw], _Counter} ->
        case acc0 do
          [] ->
            acc = [[cert]]
            build_candidates(t, map, duplicates, combinations, max, acc)

          _Else ->
            acc =
              for l <- acc0 do
                [cert | l]
              end

            build_candidates(t, map, duplicates, combinations, max, acc)
        end
    end
  end

  defp find_duplicates(chain) do
    find_duplicates(chain, %{})
  end

  defp find_duplicates([], acc) do
    acc
  end

  defp find_duplicates([{subject, cert} | t], acc) do
    case :maps.get(subject, acc, :none) do
      :none ->
        find_duplicates(t, Map.put(acc, subject, {[cert], 1}))

      {certs, counter} ->
        find_duplicates(
          t,
          Map.put(acc, subject, {[cert | certs], counter + 1})
        )
    end
  end

  defp subject(cert) do
    {_Serial, subject} = :public_key.pkix_subject_id(cert)
    subject
  end

  defp issuer(cert) do
    case :public_key.pkix_is_self_signed(cert) do
      true ->
        subject(cert)

      false ->
        case is_binary(cert) do
          true ->
            r_OTPCertificate(tbsCertificate: tBSCert) =
              :public_key.pkix_decode_cert(
                cert,
                :otp
              )

            :public_key.pkix_normalize_name(r_OTPTBSCertificate(tBSCert, :issuer))

          false ->
            r_OTPCertificate(tbsCertificate: tBSCert) = cert
            :public_key.pkix_normalize_name(r_OTPTBSCertificate(tBSCert, :issuer))
        end
    end
  end

  defp cert_issuers([], acc) do
    acc
  end

  defp cert_issuers([cert | rest], acc) do
    cert_issuers(rest, [issuer(cert) | acc])
  end

  defp cert_issuers(oTPCerts) do
    cert_issuers(oTPCerts, [])
  end

  defp cert_auth_member(chainSubjects, certAuths) do
    commonAuthorities =
      :sets.intersection(
        :sets.from_list(chainSubjects),
        :sets.from_list(certAuths)
      )

    not :sets.is_empty(commonAuthorities)
  end

  def handle_trace(
        :crt,
        {:call, {:ssl_certificate, :validate, [cert, statusOrExt | _]}},
        stack
      ) do
    {:io_lib.format(~c"[~W] StatusOrExt = ~W", [cert, 3, statusOrExt, 10]), stack}
  end

  def handle_trace(
        :crt,
        {:call, {:ssl_certificate, :verify_cert_extensions, [cert, _UserState, [], _Context]}},
        stack
      ) do
    {:io_lib.format(~c" no more extensions [~W]", [cert, 3]), stack}
  end

  def handle_trace(
        :crt,
        {:call,
         {:ssl_certificate, :verify_cert_extensions,
          [
            cert,
            %{ocsp_responder_certs: _ResponderCerts, ocsp_state: ocspState, issuer: issuer} =
              _UserState,
            [r_certificate_status(response: ocspResponsDer) | _Exts],
            _Context
          ]}},
        stack
      ) do
    {:io_lib.format(
       ~c"#2 OcspState = ~W Issuer = [~W] OcspResponsDer = ~W [~W]",
       [ocspState, 10, issuer, 3, ocspResponsDer, 2, cert, 3]
     ), stack}
  end

  def handle_trace(
        :crt,
        {:return_from, {:ssl_certificate, :verify_cert_extensions, 4},
         {:valid, %{issuer: issuer}}},
        stack
      ) do
    {:io_lib.format(~c" extensions valid Issuer = ~W", [issuer, 3]), stack}
  end
end
