defmodule :m_tls_handshake_1_3 do
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
    explicit_policy: :undefined,
    inhibit_any_policy: :undefined,
    policy_mapping: :undefined,
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

  Record.defrecord(:r_policy_tree_node, :policy_tree_node,
    valid_policy: :undefined,
    qualifier_set: :undefined,
    criticality_indicator: :undefined,
    expected_policy_set: :undefined
  )

  Record.defrecord(:r_revoke_state, :revoke_state,
    reasons_mask: :undefined,
    cert_status: :undefined,
    interim_reasons_mask: :undefined,
    valid_ext: :undefined,
    details: :undefined
  )

  Record.defrecord(:r_ECPoint, :ECPoint, point: :undefined)

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

  Record.defrecord(:r_srp_user, :srp_user,
    generator: :undefined,
    prime: :undefined,
    salt: :undefined,
    verifier: :undefined
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

  Record.defrecord(:r_inner_plaintext, :inner_plaintext,
    content: :undefined,
    type: :undefined,
    zeros: :undefined
  )

  Record.defrecord(:r_tls_cipher_text, :tls_cipher_text,
    opaque_type: 23,
    legacy_version: {3, 3},
    encoded_record: :undefined
  )

  def server_hello(msgType, sessionId, keyShare, pSK, connectionStates) do
    %{security_parameters: secParams} =
      :ssl_record.pending_connection_state(
        connectionStates,
        :read
      )

    extensions = server_hello_extensions(msgType, keyShare, pSK)

    r_server_hello(
      server_version: {3, 3},
      cipher_suite: r_security_parameters(secParams, :cipher_suite),
      compression_method: 0,
      random: server_hello_random(msgType, secParams),
      session_id: sessionId,
      extensions: extensions
    )
  end

  defp server_hello_extensions(:hello_retry_request = msgType, keyShare, _) do
    extensions = server_hello_extensions_versions()
    :ssl_handshake.add_server_share(msgType, extensions, keyShare)
  end

  defp server_hello_extensions(msgType, keyShare, :undefined) do
    extensions = server_hello_extensions_versions()
    :ssl_handshake.add_server_share(msgType, extensions, keyShare)
  end

  defp server_hello_extensions(msgType, keyShare, {selectedIdentity, _}) do
    extensions = server_hello_extensions_versions()
    preSharedKey = r_pre_shared_key_server_hello(selected_identity: selectedIdentity)

    :ssl_handshake.add_server_share(
      msgType,
      Map.put(extensions, :pre_shared_key, preSharedKey),
      keyShare
    )
  end

  defp server_hello_extensions_versions() do
    supportedVersions = r_server_hello_selected_version(selected_version: {3, 4})
    %{server_hello_selected_version: supportedVersions}
  end

  defp server_hello_random(:server_hello, r_security_parameters(server_random: random)) do
    random
  end

  defp server_hello_random(:hello_retry_request, _) do
    <<207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22,
      122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156>>
  end

  def maybe_add_cookie_extension(
        r_state(ssl_options: %{cookie: false}) = state,
        serverHello
      ) do
    {state, serverHello}
  end

  def maybe_add_cookie_extension(
        r_state(
          connection_states: connectionStates,
          ssl_options: %{cookie: true},
          handshake_env: r_handshake_env(tls_handshake_history: {[cH1 | _], _}) = hsEnv0
        ) = state,
        r_server_hello(extensions: extensions0) = serverHello
      ) do
    hKDFAlgo = get_hkdf_algorithm(connectionStates)
    messageHash0 = message_hash(cH1, hKDFAlgo)
    messageHash = :erlang.iolist_to_binary(messageHash0)
    iV = :crypto.strong_rand_bytes(16)
    shard = :crypto.strong_rand_bytes(32)
    cookie = :ssl_cipher.encrypt_data("cookie", messageHash, shard, iV)
    hsEnv = r_handshake_env(hsEnv0, cookie_iv_shard: {iV, shard})
    extensions = Map.put(extensions0, :cookie, r_cookie(cookie: cookie))
    {r_state(state, handshake_env: hsEnv), r_server_hello(serverHello, extensions: extensions)}
  end

  def maybe_add_cookie_extension(:undefined, clientHello) do
    clientHello
  end

  def maybe_add_cookie_extension(
        cookie,
        r_client_hello(extensions: extensions0) = clientHello
      ) do
    extensions = Map.put(extensions0, :cookie, cookie)
    r_client_hello(clientHello, extensions: extensions)
  end

  def encrypted_extensions(r_state(handshake_env: handshakeEnv)) do
    e0 = %{}

    e1 =
      case r_handshake_env(handshakeEnv, :alpn) do
        :undefined ->
          e0

        aLPNProtocol ->
          :ssl_handshake.add_alpn(%{}, aLPNProtocol)
      end

    e2 =
      case r_handshake_env(handshakeEnv, :max_frag_enum) do
        :undefined ->
          e1

        maxFragEnum ->
          Map.put(e1, :max_frag_enum, maxFragEnum)
      end

    e3 =
      case r_handshake_env(handshakeEnv, :sni_guided_cert_selection) do
        false ->
          e2

        true ->
          Map.put(e2, :sni, r_sni(hostname: ~c""))
      end

    e =
      case r_handshake_env(handshakeEnv, :early_data_accepted) do
        false ->
          e3

        true ->
          Map.put(e3, :early_data, r_early_data_indication())
      end

    r_encrypted_extensions(extensions: e)
  end

  def certificate_request(signAlgs0, signAlgsCert0, certDbHandle, certDbRef, certAuthBool) do
    signAlgs = filter_tls13_algs(signAlgs0)
    signAlgsCert = filter_tls13_algs(signAlgsCert0)
    extensions0 = add_signature_algorithms(%{}, signAlgs)

    extensions1 =
      add_signature_algorithms_cert(
        extensions0,
        signAlgsCert
      )

    extensions =
      cond do
        certAuthBool === true ->
          auths =
            :ssl_handshake.certificate_authorities(
              certDbHandle,
              certDbRef
            )

          Map.put(
            extensions1,
            :certificate_authorities,
            r_certificate_authorities(authorities: auths)
          )

        true ->
          extensions1
      end

    r_certificate_request_1_3(
      certificate_request_context: <<>>,
      extensions: extensions
    )
  end

  defp add_signature_algorithms(extensions, signAlgs) do
    Map.put(
      extensions,
      :signature_algorithms,
      r_signature_algorithms(signature_scheme_list: signAlgs)
    )
  end

  defp add_signature_algorithms_cert(extensions, :undefined) do
    extensions
  end

  defp add_signature_algorithms_cert(extensions, signAlgsCert) do
    Map.put(
      extensions,
      :signature_algorithms_cert,
      r_signature_algorithms_cert(signature_scheme_list: signAlgsCert)
    )
  end

  defp filter_tls13_algs(:undefined) do
    :undefined
  end

  defp filter_tls13_algs(algo) do
    :lists.foldl(
      fn
        atom, acc when is_atom(atom) ->
          [atom | acc]

        {:sha512, :rsa}, acc ->
          [:rsa_pkcs1_sha512 | acc]

        {:sha384, :rsa}, acc ->
          [:rsa_pkcs1_sha384 | acc]

        {:sha256, :rsa}, acc ->
          [:rsa_pkcs1_sha256 | acc]

        {:sha, :rsa}, acc ->
          [:rsa_pkcs1_sha1 | acc]

        {:sha, :ecdsa}, acc ->
          [:ecdsa_sha1 | acc]

        _, acc ->
          acc
      end,
      [],
      algo
    )
  end

  def certificate(:undefined, _, _, _, :client) do
    {:ok,
     r_certificate_1_3(
       certificate_request_context: <<>>,
       certificate_list: []
     )}
  end

  def certificate([ownCert], certDbHandle, certDbRef, _CRContext, role) do
    case :ssl_certificate.certificate_chain(ownCert, certDbHandle, certDbRef) do
      {:ok, _, chain} ->
        certList = chain_to_cert_list(chain)

        {:ok,
         r_certificate_1_3(
           certificate_request_context: <<>>,
           certificate_list: certList
         )}

      {:error, error} when role === :server ->
        {:error,
         r_alert(
           level: 2,
           description: 80,
           where: %{
             mfa: {:tls_handshake_1_3, :certificate, 5},
             line: 300,
             file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
           },
           reason: {:no_suitable_certificates, error}
         )}

      {:error, _Error} when role === :client ->
        {:ok,
         r_certificate_1_3(
           certificate_request_context: <<>>,
           certificate_list: []
         )}
    end
  end

  def certificate([_, _ | _] = chain, _, _, _, _) do
    certList = chain_to_cert_list(chain)

    {:ok,
     r_certificate_1_3(
       certificate_request_context: <<>>,
       certificate_list: certList
     )}
  end

  def certificate_verify(
        privateKey,
        signatureScheme,
        r_state(
          connection_states: connectionStates,
          handshake_env: r_handshake_env(tls_handshake_history: {messages, _})
        ),
        role
      ) do
    %{security_parameters: secParamsR} =
      :ssl_record.pending_connection_state(
        connectionStates,
        :write
      )

    r_security_parameters(prf_algorithm: hKDFAlgo) = secParamsR
    {hashAlgo, signAlgo, _} = :ssl_cipher.scheme_to_components(signatureScheme)
    context = :lists.reverse(messages)
    tHash = :tls_v1.transcript_hash(context, hKDFAlgo)
    contextString = context_string(role)

    case sign(tHash, contextString, hashAlgo, privateKey, signAlgo) do
      {:ok, signature} ->
        {:ok, r_certificate_verify_1_3(algorithm: signatureScheme, signature: signature)}

      {:error, r_alert() = alert} ->
        {:error, alert}
    end
  end

  def maybe_hello_retry_request(
        r_server_hello(
          random:
            <<207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162,
              17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156>>
        ) = serverHello,
        r_state(protocol_specific: pS) = state0
      ) do
    {:error,
     {r_state(state0, protocol_specific: Map.put(pS, :hello_retry, true)), :start, serverHello}}
  end

  def maybe_hello_retry_request(_, _) do
    :ok
  end

  def finished(
        r_state(
          connection_states: connectionStates,
          handshake_env: r_handshake_env(tls_handshake_history: {messages, _})
        )
      ) do
    %{security_parameters: secParamsR, cipher_state: r_cipher_state(finished_key: finishedKey)} =
      :ssl_record.current_connection_state(
        connectionStates,
        :write
      )

    r_security_parameters(prf_algorithm: hKDFAlgo) = secParamsR
    verifyData = :tls_v1.finished_verify_data(finishedKey, hKDFAlgo, messages)
    r_finished(verify_data: verifyData)
  end

  def key_update(type) do
    r_key_update(request_update: type)
  end

  def create_change_cipher_spec(r_state(ssl_options: %{log_level: logLevel})) do
    connectionStates = %{
      current_write: %{
        compression_state: :undefined,
        cipher_state: :undefined,
        sequence_number: 1,
        security_parameters:
          r_security_parameters(
            bulk_cipher_algorithm: 0,
            compression_algorithm: 0,
            mac_algorithm: 0
          ),
        mac_secret: :undefined
      }
    }

    {binChangeCipher, _} =
      :tls_record.encode_change_cipher_spec(
        {3, 3},
        connectionStates
      )

    :ssl_logger.debug(logLevel, :outbound, :record, binChangeCipher)
    [binChangeCipher]
  end

  def process_certificate_request(
        r_certificate_request_1_3(extensions: extensions),
        r_state(
          ssl_options: %{signature_algs: clientSignAlgs},
          connection_env:
            r_connection_env(
              cert_key_alts: certKeyAlts,
              negotiated_version: version
            ),
          static_env:
            r_static_env(
              cert_db: certDbHandle,
              cert_db_ref: certDbRef
            ),
          session: session0
        ) = state
      ) do
    serverSignAlgs =
      get_signature_scheme_list(
        :maps.get(
          :signature_algs,
          extensions,
          :undefined
        )
      )

    serverSignAlgsCert =
      get_signature_scheme_list(
        :maps.get(
          :signature_algs_cert,
          extensions,
          :undefined
        )
      )

    certAuths =
      get_certificate_authorities(:maps.get(:certificate_authorities, extensions, :undefined))

    certKeyPairs =
      :ssl_certificate.available_cert_key_pairs(
        certKeyAlts,
        version
      )

    session =
      select_client_cert_key_pair(
        session0,
        certKeyPairs,
        serverSignAlgs,
        serverSignAlgsCert,
        clientSignAlgs,
        certDbHandle,
        certDbRef,
        certAuths,
        :undefined
      )

    {:ok,
     {r_state(state,
        client_certificate_status: :requested,
        session: session
      ), :wait_cert}}
  end

  def process_certificate(
        r_certificate_1_3(
          certificate_request_context: <<>>,
          certificate_list: []
        ),
        r_state(ssl_options: %{fail_if_no_peer_cert: false}) = state
      ) do
    {:ok, {state, :wait_finished}}
  end

  def process_certificate(
        r_certificate_1_3(
          certificate_request_context: <<>>,
          certificate_list: []
        ),
        r_state(ssl_options: %{fail_if_no_peer_cert: true}) = state0
      ) do
    state1 = calculate_traffic_secrets(state0)
    state = :ssl_record.step_encryption_state(state1)

    {:error,
     {r_alert(
        level: 2,
        description: 116,
        where: %{
          mfa: {:tls_handshake_1_3, :process_certificate, 2},
          line: 444,
          file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
        },
        reason: :certificate_required
      ), state}}
  end

  def process_certificate(
        r_certificate_1_3(certificate_list: certEntries),
        r_state(
          ssl_options: sslOptions,
          static_env:
            r_static_env(
              role: role,
              host: host,
              cert_db: certDbHandle,
              cert_db_ref: certDbRef,
              crl_db: cRLDbHandle
            ),
          handshake_env: r_handshake_env(ocsp_stapling_state: ocspState)
        ) = state0
      ) do
    case validate_certificate_chain(
           certEntries,
           certDbHandle,
           certDbRef,
           sslOptions,
           cRLDbHandle,
           role,
           host,
           ocspState
         ) do
      r_alert() = alert ->
        state = update_encryption_state(role, state0)
        {:error, {alert, state}}

      {peerCert, publicKeyInfo} ->
        state = store_peer_cert(state0, peerCert, publicKeyInfo)
        {:ok, {state, :wait_cv}}
    end
  end

  def verify_certificate_verify(
        r_state(
          static_env: r_static_env(role: role),
          connection_states: connectionStates,
          handshake_env:
            r_handshake_env(
              public_key_info: publicKeyInfo,
              tls_handshake_history: hHistory
            )
        ) = state0,
        r_certificate_verify_1_3(algorithm: signatureScheme, signature: signature)
      ) do
    %{security_parameters: secParamsR} =
      :ssl_record.pending_connection_state(
        connectionStates,
        :write
      )

    r_security_parameters(prf_algorithm: hKDFAlgo) = secParamsR
    {hashAlgo, signAlg, _} = :ssl_cipher.scheme_to_components(signatureScheme)
    messages = get_handshake_context_cv(hHistory)
    context = :lists.reverse(messages)
    tHash = :tls_v1.transcript_hash(context, hKDFAlgo)
    contextString = peer_context_string(role)

    case verify(tHash, contextString, hashAlgo, signAlg, signature, publicKeyInfo) do
      {:ok, true} ->
        {:ok, {state0, :wait_finished}}

      {:ok, false} ->
        state1 = calculate_traffic_secrets(state0)
        state = :ssl_record.step_encryption_state(state1)

        {:error,
         {r_alert(
            level: 2,
            description: 40,
            where: %{
              mfa: {:tls_handshake_1_3, :verify_certificate_verify, 2},
              line: 500,
              file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
            },
            reason: ~c"Failed to verify CertificateVerify"
          ), state}}

      {:error, r_alert() = alert} ->
        state1 = calculate_traffic_secrets(state0)
        state = :ssl_record.step_encryption_state(state1)
        {:error, {alert, state}}
    end
  end

  def validate_finished(
        r_state(
          connection_states: connectionStates,
          handshake_env: r_handshake_env(tls_handshake_history: {messages0, _})
        ),
        verifyData
      ) do
    %{security_parameters: secParamsR, cipher_state: r_cipher_state(finished_key: finishedKey)} =
      :ssl_record.current_connection_state(
        connectionStates,
        :read
      )

    r_security_parameters(prf_algorithm: hKDFAlgo) = secParamsR
    [_ | messages] = messages0
    controlData = :tls_v1.finished_verify_data(finishedKey, hKDFAlgo, messages)
    compare_verify_data(controlData, verifyData)
  end

  defp compare_verify_data(data, data) do
    :ok
  end

  defp compare_verify_data(_, _) do
    {:error,
     r_alert(
       level: 2,
       description: 51,
       where: %{
         mfa: {:tls_handshake_1_3, :compare_verify_data, 2},
         line: 531,
         file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
       },
       reason: :decrypt_error
     )}
  end

  def encode_handshake(
        r_certificate_request_1_3(
          certificate_request_context: context,
          extensions: exts
        )
      ) do
    encContext = encode_cert_req_context(context)
    binExts = encode_extensions(exts)
    {13, <<encContext::binary, binExts::binary>>}
  end

  def encode_handshake(
        r_certificate_1_3(
          certificate_request_context: context,
          certificate_list: entries
        )
      ) do
    encContext = encode_cert_req_context(context)
    encEntries = encode_cert_entries(entries)
    {11, <<encContext::binary, encEntries::binary>>}
  end

  def encode_handshake(r_certificate_verify_1_3(algorithm: algorithm, signature: signature)) do
    encAlgo = encode_algorithm(algorithm)
    encSign = encode_signature(signature)
    {15, <<encAlgo::binary, encSign::binary>>}
  end

  def encode_handshake(r_encrypted_extensions(extensions: exts)) do
    {8, encode_extensions(exts)}
  end

  def encode_handshake(
        r_new_session_ticket(
          ticket_lifetime: lifeTime,
          ticket_age_add: age,
          ticket_nonce: nonce,
          ticket: ticket,
          extensions: exts
        )
      ) do
    ticketSize = byte_size(ticket)
    nonceSize = byte_size(nonce)
    binExts = encode_extensions(exts)

    {4,
     <<lifeTime::size(32)-unsigned-big-integer, age::size(32)-unsigned-big-integer,
       nonceSize::size(8)-unsigned-big-integer, nonce::binary,
       ticketSize::size(16)-unsigned-big-integer, ticket::binary, binExts::binary>>}
  end

  def encode_handshake(r_end_of_early_data()) do
    {5, <<>>}
  end

  def encode_handshake(r_key_update(request_update: update)) do
    encUpdate = encode_key_update(update)
    {24, <<encUpdate::binary>>}
  end

  def encode_handshake(handshakeMsg) do
    :ssl_handshake.encode_handshake(handshakeMsg, {3, 4})
  end

  def encode_early_data(
        cipher,
        r_state(
          flight_buffer: flight0,
          protocol_specific: %{sender: _Sender},
          ssl_options: %{versions: [version | _], early_data: earlyData} = _SslOpts0
        ) = state0
      ) do
    r_state(
      connection_states:
        %{current_write: %{security_parameters: securityParameters0} = write0} = connectionStates0
    ) = state0

    bulkCipherAlgo = :ssl_cipher.bulk_cipher_algorithm(cipher)

    securityParameters =
      r_security_parameters(securityParameters0,
        cipher_type: 2,
        bulk_cipher_algorithm: bulkCipherAlgo
      )

    write = Map.put(write0, :security_parameters, securityParameters)
    connectionStates1 = Map.put(connectionStates0, :current_write, write)

    {binEarlyData, connectionStates} =
      :tls_record.encode_data([earlyData], version, connectionStates1)

    r_state(state0,
      connection_states: connectionStates,
      flight_buffer: flight0 ++ [binEarlyData]
    )
  end

  def decode_handshake(
        2,
        <<major::size(8)-unsigned-big-integer, minor::size(8)-unsigned-big-integer,
          random::size(32)-binary, sID_length::size(8)-unsigned-big-integer,
          session_ID::size(sID_length)-binary, cipher_suite::size(2)-binary,
          comp_method::size(8)-unsigned-big-integer, extLen::size(16)-unsigned-big-integer,
          extensions::size(extLen)-binary>>
      )
      when random ===
             <<207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162,
               17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156>> do
    helloExtensions =
      :ssl_handshake.decode_hello_extensions(
        extensions,
        {3, 4},
        {major, minor},
        :hello_retry_request
      )

    r_server_hello(
      server_version: {major, minor},
      random: random,
      session_id: session_ID,
      cipher_suite: cipher_suite,
      compression_method: comp_method,
      extensions: helloExtensions
    )
  end

  def decode_handshake(
        13,
        <<0::size(8)-unsigned-big-integer, size::size(16)-unsigned-big-integer,
          encExts::size(size)-binary>>
      ) do
    exts = decode_extensions(encExts, :certificate_request)
    r_certificate_request_1_3(certificate_request_context: <<>>, extensions: exts)
  end

  def decode_handshake(
        13,
        <<cSize::size(8)-unsigned-big-integer, context::size(cSize)-binary,
          size::size(16)-unsigned-big-integer, encExts::size(size)-binary>>
      ) do
    exts = decode_extensions(encExts, :certificate_request)

    r_certificate_request_1_3(
      certificate_request_context: context,
      extensions: exts
    )
  end

  def decode_handshake(
        11,
        <<0::size(8)-unsigned-big-integer, size::size(24)-unsigned-big-integer,
          certs::size(size)-binary>>
      ) do
    certList = decode_cert_entries(certs)

    r_certificate_1_3(
      certificate_request_context: <<>>,
      certificate_list: certList
    )
  end

  def decode_handshake(
        11,
        <<cSize::size(8)-unsigned-big-integer, context::size(cSize)-binary,
          size::size(24)-unsigned-big-integer, certs::size(size)-binary>>
      ) do
    certList = decode_cert_entries(certs)

    r_certificate_1_3(
      certificate_request_context: context,
      certificate_list: certList
    )
  end

  def decode_handshake(
        15,
        <<encAlgo::size(16)-unsigned-big-integer, size::size(16)-unsigned-big-integer,
          signature::size(size)-binary>>
      ) do
    algorithm = :ssl_cipher.signature_scheme(encAlgo)
    r_certificate_verify_1_3(algorithm: algorithm, signature: signature)
  end

  def decode_handshake(
        8,
        <<size::size(16)-unsigned-big-integer, encExts::size(size)-binary>>
      ) do
    r_encrypted_extensions(
      extensions:
        decode_extensions(
          encExts,
          :encrypted_extensions
        )
    )
  end

  def decode_handshake(
        4,
        <<lifeTime::size(32)-unsigned-big-integer, age::size(32)-unsigned-big-integer,
          nonceSize::size(8)-unsigned-big-integer, nonce::size(nonceSize)-binary,
          ticketSize::size(16)-unsigned-big-integer, ticket::size(ticketSize)-binary,
          binExtSize::size(16)-unsigned-big-integer, binExts::size(binExtSize)-binary>>
      ) do
    exts = decode_extensions(binExts, :encrypted_extensions)

    r_new_session_ticket(
      ticket_lifetime: lifeTime,
      ticket_age_add: age,
      ticket_nonce: nonce,
      ticket: ticket,
      extensions: exts
    )
  end

  def decode_handshake(5, _) do
    r_end_of_early_data()
  end

  def decode_handshake(
        24,
        <<update::size(8)-unsigned-big-integer>>
      ) do
    r_key_update(request_update: decode_key_update(update))
  end

  def decode_handshake(tag, handshakeMsg) do
    :ssl_handshake.decode_handshake({3, 4}, tag, handshakeMsg)
  end

  def is_valid_binder(binder, hHistory, pSK, hash) do
    case hHistory do
      [clientHello2, hRR, messageHash | _] ->
        truncated = truncate_client_hello(clientHello2)
        finishedKey = calculate_finished_key(pSK, hash)
        binder == calculate_binder(finishedKey, hash, [messageHash, hRR, truncated])

      [clientHello1 | _] ->
        truncated = truncate_client_hello(clientHello1)
        finishedKey = calculate_finished_key(pSK, hash)
        binder == calculate_binder(finishedKey, hash, truncated)
    end
  end

  defp encode_cert_req_context(<<>>) do
    <<0::size(8)-unsigned-big-integer>>
  end

  defp encode_cert_req_context(bin) do
    size = byte_size(bin)
    <<size::size(8)-unsigned-big-integer, bin::binary>>
  end

  defp encode_cert_entries(entries) do
    certEntryList = encode_cert_entries(entries, [])
    size = byte_size(certEntryList)
    <<size::size(24)-unsigned-big-integer, certEntryList::binary>>
  end

  defp encode_cert_entries([], acc) do
    :erlang.iolist_to_binary(:lists.reverse(acc))
  end

  defp encode_cert_entries(
         [r_certificate_entry(data: data, extensions: exts) | rest],
         acc
       ) do
    dSize = byte_size(data)
    binExts = encode_extensions(exts)

    encode_cert_entries(
      rest,
      [
        <<dSize::size(24)-unsigned-big-integer, data::binary, binExts::binary>>
        | acc
      ]
    )
  end

  defp encode_algorithm(algo) do
    scheme = :ssl_cipher.signature_scheme(algo)
    <<scheme::size(16)-unsigned-big-integer>>
  end

  defp encode_signature(signature) do
    size = byte_size(signature)
    <<size::size(16)-unsigned-big-integer, signature::binary>>
  end

  defp encode_key_update(:update_not_requested) do
    <<0::size(8)-unsigned-big-integer>>
  end

  defp encode_key_update(:update_requested) do
    <<1::size(8)-unsigned-big-integer>>
  end

  defp decode_key_update(0) do
    :update_not_requested
  end

  defp decode_key_update(1) do
    :update_requested
  end

  defp decode_key_update(n) do
    throw(
      r_alert(
        level: 2,
        description: 47,
        where: %{
          mfa: {:tls_handshake_1_3, :decode_key_update, 1},
          line: 729,
          file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
        },
        reason: {:request_update, n}
      )
    )
  end

  defp decode_cert_entries(entries) do
    for <<(<<dSize::size(24)-unsigned-big-integer, data::size(dSize)-binary,
             esize::size(16)-unsigned-big-integer, binExts::size(esize)-binary>> <- entries)>> do
      r_certificate_entry(
        data: data,
        extensions:
          decode_extensions(
            binExts,
            :certificate_request
          )
      )
    end
  end

  defp encode_extensions(exts) do
    :ssl_handshake.encode_extensions(extensions_list(exts))
  end

  defp decode_extensions(exts, messageType) do
    :ssl_handshake.decode_extensions(exts, {3, 4}, messageType)
  end

  defp extensions_list(extensions) do
    for {_, ext} <- :maps.to_list(extensions) do
      ext
    end
  end

  defp chain_to_cert_list(l) do
    chain_to_cert_list(l, [])
  end

  defp chain_to_cert_list([], acc) do
    :lists.reverse(acc)
  end

  defp chain_to_cert_list([h | t], acc) do
    chain_to_cert_list(t, [certificate_entry(h) | acc])
  end

  defp certificate_entry(dER) do
    r_certificate_entry(data: dER, extensions: %{})
  end

  defp sign(tHash, context, hashAlgo, privateKey, signAlgo) do
    content = build_content(context, tHash)

    try do
      {:ok, :ssl_handshake.digitally_signed({3, 4}, content, hashAlgo, privateKey, signAlgo)}
    catch
      alert ->
        {:error, alert}
    end
  end

  defp verify(tHash, context, hashAlgo, signAlgo, signature, publicKeyInfo) do
    content = build_content(context, tHash)

    try do
      :ssl_handshake.verify_signature(
        {3, 4},
        content,
        {hashAlgo, signAlgo},
        signature,
        publicKeyInfo
      )
    catch
      :error, reason ->
        (fn ->
           case :erlang.get(:log_level) do
             :undefined ->
               :ssl_logger.log(
                 :debug,
                 :debug,
                 %{
                   description: :handshake_error,
                   reason: [{:reason, reason}, {:stacktrace, __STACKTRACE__}]
                 },
                 %{
                   mfa: {:tls_handshake_1_3, :verify, 6},
                   line: 791,
                   file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
                 }
               )

             __LogLevel__ ->
               :ssl_logger.log(
                 :debug,
                 __LogLevel__,
                 %{
                   description: :handshake_error,
                   reason: [{:reason, reason}, {:stacktrace, __STACKTRACE__}]
                 },
                 %{
                   mfa: {:tls_handshake_1_3, :verify, 6},
                   line: 791,
                   file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
                 }
               )
           end
         end).()

        {:error,
         r_alert(
           level: 2,
           description: 80,
           where: %{
             mfa: {:tls_handshake_1_3, :verify, 6},
             line: 792,
             file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
           },
           reason: :badarg
         )}
    else
      result ->
        {:ok, result}
    end
  end

  defp build_content(context, tHash) do
    prefix = :binary.copy(<<32>>, 64)
    <<prefix::binary, context::binary, 0::size(8)-unsigned-big-integer, tHash::binary>>
  end

  defp update_encryption_state(:server, state0) do
    state1 = calculate_traffic_secrets(state0)
    :ssl_record.step_encryption_state(state1)
  end

  defp update_encryption_state(:client, state) do
    state
  end

  defp validate_certificate_chain(
         certEntries,
         certDbHandle,
         certDbRef,
         sslOptions,
         cRLDbHandle,
         role,
         host,
         ocspState0
       ) do
    {certs, certExt, ocspState} = split_cert_entries(certEntries, ocspState0)

    ocspResponderCerts =
      case :maps.get(:ocsp_stapling, sslOptions, :disabled) do
        %{ocsp_responder_certs: v} ->
          v

        :disabled ->
          []
      end

    :ssl_handshake.certify(
      r_certificate(asn1_certificates: certs),
      certDbHandle,
      certDbRef,
      sslOptions,
      cRLDbHandle,
      role,
      host,
      {3, 4},
      %{cert_ext: certExt, ocsp_state: ocspState, ocsp_responder_certs: ocspResponderCerts}
    )
  end

  defp store_peer_cert(
         r_state(
           session: session,
           handshake_env: hsEnv
         ) = state,
         peerCert,
         publicKeyInfo
       ) do
    r_state(state,
      session: r_session(session, peer_certificate: peerCert),
      handshake_env: r_handshake_env(hsEnv, public_key_info: publicKeyInfo)
    )
  end

  defp split_cert_entries(certEntries, ocspState) do
    split_cert_entries(certEntries, ocspState, [], %{})
  end

  defp split_cert_entries([], ocspState, chain, ext) do
    {:lists.reverse(chain), ext, ocspState}
  end

  defp split_cert_entries(
         [
           r_certificate_entry(data: derCert, extensions: extensions0)
           | certEntries
         ],
         ocspState0,
         chain,
         ext
       ) do
    id = :public_key.pkix_subject_id(derCert)

    extensions =
      for {_, extValue} <- :maps.to_list(extensions0) do
        extValue
      end

    ocspState =
      case :maps.get(:status_request, extensions0, :undefined) do
        :undefined ->
          ocspState0

        _ ->
          Map.put(ocspState0, :ocsp_expect, :stapled)
      end

    split_cert_entries(certEntries, ocspState, [derCert | chain], Map.put(ext, id, extensions))
  end

  def replace_ch1_with_message_hash(
        r_state(
          connection_states: connectionStates,
          handshake_env:
            r_handshake_env(
              tls_handshake_history:
                {[
                   hRR,
                   cH1
                   | hHistory
                 ], lM}
            ) = hSEnv
        ) = state0
      ) do
    %{security_parameters: secParamsR} =
      :ssl_record.pending_connection_state(
        connectionStates,
        :read
      )

    r_security_parameters(prf_algorithm: hKDFAlgo) = secParamsR
    messageHash = message_hash(cH1, hKDFAlgo)

    r_state(state0,
      handshake_env:
        r_handshake_env(hSEnv,
          tls_handshake_history:
            {[
               hRR,
               messageHash
               | hHistory
             ], lM}
        )
    )
  end

  defp get_hkdf_algorithm(connectionStates) do
    %{security_parameters: secParamsR} =
      :ssl_record.pending_connection_state(
        connectionStates,
        :read
      )

    r_security_parameters(prf_algorithm: hKDFAlgo) = secParamsR
    hKDFAlgo
  end

  defp message_hash(clientHello1, hKDFAlgo) do
    [254, 0, 0, :ssl_cipher.hash_size(hKDFAlgo), :crypto.hash(hKDFAlgo, clientHello1)]
  end

  def calculate_handshake_secrets(
        publicKey,
        privateKey,
        selectedGroup,
        pSK,
        r_state(
          connection_states: connectionStates,
          handshake_env: r_handshake_env(tls_handshake_history: hHistory)
        ) = state0
      ) do
    %{security_parameters: secParamsR} =
      :ssl_record.pending_connection_state(
        connectionStates,
        :read
      )

    r_security_parameters(
      prf_algorithm: hKDFAlgo,
      cipher_suite: cipherSuite
    ) = secParamsR

    earlySecret = :tls_v1.key_schedule(:early_secret, hKDFAlgo, {:psk, pSK})
    iKM = calculate_shared_secret(publicKey, privateKey, selectedGroup)
    handshakeSecret = :tls_v1.key_schedule(:handshake_secret, hKDFAlgo, iKM, earlySecret)
    {messages, _} = hHistory

    clientHSTrafficSecret =
      :tls_v1.client_handshake_traffic_secret(
        hKDFAlgo,
        handshakeSecret,
        :lists.reverse(messages)
      )

    serverHSTrafficSecret =
      :tls_v1.server_handshake_traffic_secret(
        hKDFAlgo,
        handshakeSecret,
        :lists.reverse(messages)
      )

    keyLength = :tls_v1.key_length(cipherSuite)

    {readKey, readIV} =
      :tls_v1.calculate_traffic_keys(
        hKDFAlgo,
        keyLength,
        clientHSTrafficSecret
      )

    {writeKey, writeIV} =
      :tls_v1.calculate_traffic_keys(
        hKDFAlgo,
        keyLength,
        serverHSTrafficSecret
      )

    readFinishedKey =
      :tls_v1.finished_key(
        clientHSTrafficSecret,
        hKDFAlgo
      )

    writeFinishedKey =
      :tls_v1.finished_key(
        serverHSTrafficSecret,
        hKDFAlgo
      )

    state1 =
      maybe_store_handshake_traffic_secret(
        state0,
        clientHSTrafficSecret,
        serverHSTrafficSecret
      )

    update_pending_connection_states(
      state1,
      handshakeSecret,
      :undefined,
      :undefined,
      :undefined,
      readKey,
      readIV,
      readFinishedKey,
      writeKey,
      writeIV,
      writeFinishedKey
    )
  end

  def calculate_client_early_traffic_secret(
        r_state(
          connection_states: connectionStates,
          handshake_env: r_handshake_env(tls_handshake_history: {hist, _})
        ) = state,
        pSK
      ) do
    %{security_parameters: secParamsR} =
      :ssl_record.pending_connection_state(
        connectionStates,
        :read
      )

    r_security_parameters(cipher_suite: cipherSuite) = secParamsR
    %{cipher: cipher, prf: hKDF} = :ssl_cipher_format.suite_bin_to_map(cipherSuite)
    calculate_client_early_traffic_secret(hist, pSK, cipher, hKDF, state)
  end

  def calculate_client_early_traffic_secret(
        clientHello,
        pSK,
        cipher,
        hKDFAlgo,
        r_state(
          connection_states: connectionStates,
          ssl_options: opts,
          static_env: r_static_env(role: role)
        ) = state0
      ) do
    earlySecret = :tls_v1.key_schedule(:early_secret, hKDFAlgo, {:psk, pSK})

    clientEarlyTrafficSecret =
      :tls_v1.client_early_traffic_secret(
        hKDFAlgo,
        earlySecret,
        clientHello
      )

    keyLength = :ssl_cipher.key_material(cipher)

    {key, iV} =
      :tls_v1.calculate_traffic_keys(
        hKDFAlgo,
        keyLength,
        clientEarlyTrafficSecret
      )

    case role do
      :client ->
        pendingWrite0 =
          :ssl_record.pending_connection_state(
            connectionStates,
            :write
          )

        pendingWrite1 =
          maybe_store_early_data_secret(
            opts,
            clientEarlyTrafficSecret,
            pendingWrite0
          )

        pendingWrite =
          update_connection_state(
            pendingWrite1,
            :undefined,
            :undefined,
            :undefined,
            key,
            iV,
            :undefined
          )

        r_state(state0,
          connection_states: Map.put(connectionStates, :pending_write, pendingWrite)
        )

      :server ->
        pendingRead0 =
          :ssl_record.pending_connection_state(
            connectionStates,
            :read
          )

        pendingRead1 =
          maybe_store_early_data_secret(
            opts,
            clientEarlyTrafficSecret,
            pendingRead0
          )

        pendingRead =
          update_connection_state(
            pendingRead1,
            :undefined,
            :undefined,
            :undefined,
            key,
            iV,
            :undefined
          )

        r_state(state0, connection_states: Map.put(connectionStates, :pending_read, pendingRead))
    end
  end

  defp maybe_store_early_data_secret(%{keep_secrets: true}, earlySecret, state) do
    %{security_parameters: secParams0} = state
    secParams = r_security_parameters(secParams0, client_early_data_secret: earlySecret)
    %{state | security_parameters: secParams}
  end

  defp maybe_store_early_data_secret(_, _, state) do
    state
  end

  def get_pre_shared_key(:undefined, hKDFAlgo) do
    :binary.copy(<<0>>, :ssl_cipher.hash_size(hKDFAlgo))
  end

  def get_pre_shared_key({_, pSK}, _) do
    pSK
  end

  def get_pre_shared_key(_, _, hKDFAlgo, :undefined) do
    {:ok, :binary.copy(<<0>>, :ssl_cipher.hash_size(hKDFAlgo))}
  end

  def get_pre_shared_key(:undefined, _, hKDFAlgo, _) do
    {:ok, :binary.copy(<<0>>, :ssl_cipher.hash_size(hKDFAlgo))}
  end

  def get_pre_shared_key(_, :undefined, hKDFAlgo, _) do
    {:ok, :binary.copy(<<0>>, :ssl_cipher.hash_size(hKDFAlgo))}
  end

  def get_pre_shared_key(:manual = sessionTickets, useTicket, hKDFAlgo, serverPSK) do
    ticketData = get_ticket_data(self(), sessionTickets, useTicket)

    case choose_psk(ticketData, serverPSK) do
      :undefined ->
        {:ok, :binary.copy(<<0>>, :ssl_cipher.hash_size(hKDFAlgo))}

      :illegal_parameter ->
        {:error,
         r_alert(
           level: 2,
           description: 47,
           where: %{
             mfa: {:tls_handshake_1_3, :get_pre_shared_key, 4},
             line: 1008,
             file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
           }
         )}

      {_, pSK, _, _, _} ->
        {:ok, pSK}
    end
  end

  def get_pre_shared_key(:auto = sessionTickets, useTicket, hKDFAlgo, serverPSK) do
    ticketData = get_ticket_data(self(), sessionTickets, useTicket)

    case choose_psk(ticketData, serverPSK) do
      :undefined ->
        :tls_client_ticket_store.unlock_tickets(
          self(),
          useTicket
        )

        {:ok, :binary.copy(<<0>>, :ssl_cipher.hash_size(hKDFAlgo))}

      :illegal_parameter ->
        :tls_client_ticket_store.unlock_tickets(
          self(),
          useTicket
        )

        {:error,
         r_alert(
           level: 2,
           description: 47,
           where: %{
             mfa: {:tls_handshake_1_3, :get_pre_shared_key, 4},
             line: 1020,
             file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
           }
         )}

      {key, pSK, _, _, _} ->
        :tls_client_ticket_store.remove_tickets([key])

        :tls_client_ticket_store.unlock_tickets(
          self(),
          useTicket -- [key]
        )

        {:ok, pSK}
    end
  end

  def get_pre_shared_key_early_data(sessionTickets, useTicket) do
    ticketData = get_ticket_data(self(), sessionTickets, useTicket)

    case choose_psk(
           ticketData,
           r_pre_shared_key_server_hello(selected_identity: 0)
         ) do
      :undefined ->
        {:error,
         r_alert(
           level: 2,
           description: 47,
           where: %{
             mfa: {:tls_handshake_1_3, :get_pre_shared_key_early_data, 2},
             line: 1032,
             file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
           }
         )}

      :illegal_parameter ->
        {:error,
         r_alert(
           level: 2,
           description: 47,
           where: %{
             mfa: {:tls_handshake_1_3, :get_pre_shared_key_early_data, 2},
             line: 1034,
             file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
           }
         )}

      {_Key, pSK, cipher, hKDF, maxSize} ->
        {:ok, {pSK, cipher, hKDF, maxSize}}
    end
  end

  def get_supported_groups(:undefined = groups) do
    {:error,
     r_alert(
       level: 2,
       description: 47,
       where: %{
         mfa: {:tls_handshake_1_3, :get_supported_groups, 1},
         line: 1040,
         file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
       },
       reason: {:supported_groups, groups}
     )}
  end

  def get_supported_groups(r_supported_groups(supported_groups: groups)) do
    {:ok, groups}
  end

  defp choose_psk(:undefined, _) do
    :undefined
  end

  defp choose_psk([], _) do
    :illegal_parameter
  end

  defp choose_psk(
         [
           r_ticket_data(
             key: key,
             pos: selectedIdentity,
             psk: pSK,
             cipher_suite: {cipher, hKDF},
             max_size: maxSize
           )
           | _
         ],
         r_pre_shared_key_server_hello(selected_identity: selectedIdentity)
       ) do
    {key, pSK, cipher, hKDF, maxSize}
  end

  defp choose_psk([_ | t], selectedIdentity) do
    choose_psk(t, selectedIdentity)
  end

  def calculate_traffic_secrets(
        r_state(
          static_env: r_static_env(role: role),
          connection_states: connectionStates,
          handshake_env: r_handshake_env(tls_handshake_history: hHistory)
        ) = state0
      ) do
    %{security_parameters: secParamsR} =
      :ssl_record.pending_connection_state(
        connectionStates,
        :read
      )

    r_security_parameters(
      prf_algorithm: hKDFAlgo,
      cipher_suite: cipherSuite,
      master_secret: handshakeSecret
    ) = secParamsR

    masterSecret = :tls_v1.key_schedule(:master_secret, hKDFAlgo, handshakeSecret)
    messages = get_handshake_context(role, hHistory)

    clientAppTrafficSecret0 =
      :tls_v1.client_application_traffic_secret_0(
        hKDFAlgo,
        masterSecret,
        :lists.reverse(messages)
      )

    serverAppTrafficSecret0 =
      :tls_v1.server_application_traffic_secret_0(
        hKDFAlgo,
        masterSecret,
        :lists.reverse(messages)
      )

    keyLength = :tls_v1.key_length(cipherSuite)

    {readKey, readIV} =
      :tls_v1.calculate_traffic_keys(
        hKDFAlgo,
        keyLength,
        clientAppTrafficSecret0
      )

    {writeKey, writeIV} =
      :tls_v1.calculate_traffic_keys(
        hKDFAlgo,
        keyLength,
        serverAppTrafficSecret0
      )

    update_pending_connection_states(
      state0,
      masterSecret,
      :undefined,
      clientAppTrafficSecret0,
      serverAppTrafficSecret0,
      readKey,
      readIV,
      :undefined,
      writeKey,
      writeIV,
      :undefined
    )
  end

  defp calculate_shared_secret(othersKey, myKey, group)
       when is_binary(othersKey) and is_binary(myKey) and (group === :x25519 or group === :x448) do
    :crypto.compute_key(:ecdh, othersKey, myKey, group)
  end

  defp calculate_shared_secret(othersKey, myKey, group)
       when is_binary(othersKey) and is_binary(myKey) do
    params = r_DHParameter(prime: p) = :ssl_dh_groups.dh_params(group)
    s = :public_key.compute_key(othersKey, myKey, params)
    size = byte_size(:binary.encode_unsigned(p))
    :ssl_cipher.add_zero_padding(s, size)
  end

  defp calculate_shared_secret(othersKey, myKey = r_ECPrivateKey(), _Group)
       when is_binary(othersKey) do
    point = r_ECPoint(point: othersKey)
    :public_key.compute_key(point, myKey)
  end

  def maybe_calculate_resumption_master_secret(
        r_state(ssl_options: %{session_tickets: :disabled}) = state
      ) do
    state
  end

  def maybe_calculate_resumption_master_secret(
        r_state(
          ssl_options: %{session_tickets: sessionTickets},
          connection_states: connectionStates,
          handshake_env: r_handshake_env(tls_handshake_history: hHistory)
        ) = state
      )
      when sessionTickets !== :disabled do
    %{security_parameters: secParamsR} =
      :ssl_record.pending_connection_state(
        connectionStates,
        :read
      )

    r_security_parameters(
      master_secret: masterSecret,
      prf_algorithm: hKDFAlgo
    ) = secParamsR

    {messages0, _} = hHistory

    rMS =
      :tls_v1.resumption_master_secret(
        hKDFAlgo,
        masterSecret,
        :lists.reverse(messages0)
      )

    update_resumption_master_secret(state, rMS)
  end

  def calculate_exporter_master_secret(
        r_state(
          static_env: r_static_env(role: role),
          connection_states: connectionStates,
          handshake_env: r_handshake_env(tls_handshake_history: hHistory)
        )
      ) do
    %{security_parameters: secParamsR} =
      :ssl_record.pending_connection_state(
        connectionStates,
        :read
      )

    r_security_parameters(
      prf_algorithm: hKDFAlgo,
      master_secret: masterSecret
    ) = secParamsR

    messages = get_handshake_context(role, hHistory)
    :tls_v1.exporter_master_secret(hKDFAlgo, masterSecret, :lists.reverse(messages))
  end

  def forget_master_secret(
        r_state(
          connection_states:
            %{
              pending_read: pendingRead,
              pending_write: pendingWrite,
              current_read: currentRead,
              current_write: currentWrite
            } = cS
        ) = state
      ) do
    r_state(state,
      connection_states:
        Map.merge(cS, %{
          pending_read: overwrite_master_secret(pendingRead),
          pending_write: overwrite_master_secret(pendingWrite),
          current_read: overwrite_master_secret(currentRead),
          current_write: overwrite_master_secret(currentWrite)
        })
    )
  end

  defp overwrite_master_secret(connectionState = %{security_parameters: securityParameters0}) do
    securityParameters =
      r_security_parameters(securityParameters0, master_secret: {:master_secret, <<0>>})

    Map.put(connectionState, :security_parameters, securityParameters)
  end

  def set_client_random(
        r_state(
          connection_states:
            %{
              pending_read: pendingRead,
              pending_write: pendingWrite,
              current_read: currentRead,
              current_write: currentWrite
            } = cS
        ) = state,
        clientRandom
      ) do
    r_state(state,
      connection_states:
        Map.merge(cS, %{
          pending_read:
            overwrite_client_random(
              pendingRead,
              clientRandom
            ),
          pending_write:
            overwrite_client_random(
              pendingWrite,
              clientRandom
            ),
          current_read:
            overwrite_client_random(
              currentRead,
              clientRandom
            ),
          current_write:
            overwrite_client_random(
              currentWrite,
              clientRandom
            )
        })
    )
  end

  defp overwrite_client_random(
         connectionState = %{security_parameters: securityParameters0},
         clientRandom
       ) do
    securityParameters = r_security_parameters(securityParameters0, client_random: clientRandom)
    Map.put(connectionState, :security_parameters, securityParameters)
  end

  defp maybe_store_handshake_traffic_secret(
         r_state(
           connection_states: %{pending_read: pendingRead} = cS,
           ssl_options: %{keep_secrets: true}
         ) = state,
         clientHSTrafficSecret,
         serverHSTrafficSecret
       ) do
    pendingRead1 =
      store_handshake_traffic_secret(
        pendingRead,
        clientHSTrafficSecret,
        serverHSTrafficSecret
      )

    r_state(state, connection_states: Map.put(cS, :pending_read, pendingRead1))
  end

  defp maybe_store_handshake_traffic_secret(state, _, _) do
    state
  end

  defp store_handshake_traffic_secret(
         connectionState,
         clientHSTrafficSecret,
         serverHSTrafficSecret
       ) do
    Map.merge(connectionState, %{
      client_handshake_traffic_secret: clientHSTrafficSecret,
      server_handshake_traffic_secret: serverHSTrafficSecret
    })
  end

  defp update_pending_connection_states(
         r_state(
           static_env: r_static_env(role: :server),
           connection_states: cS = %{pending_read: pendingRead0, pending_write: pendingWrite0}
         ) = state,
         handshakeSecret,
         resumptionMasterSecret,
         clientAppTrafficSecret,
         serverAppTrafficSecret,
         readKey,
         readIV,
         readFinishedKey,
         writeKey,
         writeIV,
         writeFinishedKey
       ) do
    pendingRead =
      update_connection_state(
        pendingRead0,
        handshakeSecret,
        resumptionMasterSecret,
        clientAppTrafficSecret,
        readKey,
        readIV,
        readFinishedKey
      )

    pendingWrite =
      update_connection_state(
        pendingWrite0,
        handshakeSecret,
        resumptionMasterSecret,
        serverAppTrafficSecret,
        writeKey,
        writeIV,
        writeFinishedKey
      )

    r_state(state,
      connection_states: Map.merge(cS, %{pending_read: pendingRead, pending_write: pendingWrite})
    )
  end

  defp update_pending_connection_states(
         r_state(
           static_env: r_static_env(role: :client),
           connection_states: cS = %{pending_read: pendingRead0, pending_write: pendingWrite0}
         ) = state,
         handshakeSecret,
         resumptionMasterSecret,
         clientAppTrafficSecret,
         serverAppTrafficSecret,
         readKey,
         readIV,
         readFinishedKey,
         writeKey,
         writeIV,
         writeFinishedKey
       ) do
    pendingRead =
      update_connection_state(
        pendingRead0,
        handshakeSecret,
        resumptionMasterSecret,
        serverAppTrafficSecret,
        writeKey,
        writeIV,
        writeFinishedKey
      )

    pendingWrite =
      update_connection_state(
        pendingWrite0,
        handshakeSecret,
        resumptionMasterSecret,
        clientAppTrafficSecret,
        readKey,
        readIV,
        readFinishedKey
      )

    r_state(state,
      connection_states: Map.merge(cS, %{pending_read: pendingRead, pending_write: pendingWrite})
    )
  end

  defp update_connection_state(
         connectionState = %{security_parameters: securityParameters0},
         handshakeSecret,
         resumptionMasterSecret,
         applicationTrafficSecret,
         key,
         iV,
         finishedKey
       ) do
    securityParameters =
      r_security_parameters(securityParameters0,
        master_secret: handshakeSecret,
        resumption_master_secret: resumptionMasterSecret,
        application_traffic_secret: applicationTrafficSecret
      )

    bulkCipherAlgo = r_security_parameters(securityParameters, :bulk_cipher_algorithm)

    Map.merge(connectionState, %{
      security_parameters: securityParameters,
      cipher_state: cipher_init(bulkCipherAlgo, key, iV, finishedKey)
    })
  end

  def update_start_state(state, map) do
    cipher = :maps.get(:cipher, map, :undefined)
    keyShare = :maps.get(:key_share, map, :undefined)
    sessionId = :maps.get(:session_id, map, :undefined)
    group = :maps.get(:group, map, :undefined)
    selectedSignAlg = :maps.get(:sign_alg, map, :undefined)
    peerPublicKey = :maps.get(:peer_public_key, map, :undefined)
    aLPNProtocol = :maps.get(:alpn, map, :undefined)
    random = :maps.get(:random, map)

    update_start_state(
      state,
      cipher,
      keyShare,
      sessionId,
      group,
      selectedSignAlg,
      peerPublicKey,
      aLPNProtocol,
      random
    )
  end

  defp update_start_state(
         r_state(
           connection_states: connectionStates0,
           handshake_env: r_handshake_env() = hsEnv,
           static_env: r_static_env(role: role),
           connection_env: cEnv,
           session: session
         ) = state,
         cipher,
         keyShare,
         sessionId,
         group,
         selectedSignAlg,
         peerPublicKey,
         aLPNProtocol,
         random
       ) do
    %{security_parameters: secParamsR0} =
      pendingRead =
      :maps.get(
        :pending_read,
        connectionStates0
      )

    %{security_parameters: secParamsW0} =
      pendingWrite =
      :maps.get(
        :pending_write,
        connectionStates0
      )

    secParamsR1 =
      :ssl_cipher.security_parameters_1_3(
        secParamsR0,
        cipher
      )

    secParamsW1 =
      :ssl_cipher.security_parameters_1_3(
        secParamsW0,
        cipher
      )

    secParamsR = update_random(role, secParamsR1, random)
    secParamsW = update_random(role, secParamsW1, random)

    connectionStates =
      Map.merge(connectionStates0, %{
        pending_read: Map.put(pendingRead, :security_parameters, secParamsR),
        pending_write: Map.put(pendingWrite, :security_parameters, secParamsW)
      })

    r_state(state,
      connection_states: connectionStates,
      handshake_env: r_handshake_env(hsEnv, alpn: aLPNProtocol),
      key_share: keyShare,
      session:
        r_session(session,
          session_id: sessionId,
          ecc: group,
          sign_alg: selectedSignAlg,
          dh_public_value: peerPublicKey,
          cipher_suite: cipher
        ),
      connection_env: r_connection_env(cEnv, negotiated_version: {3, 4})
    )
  end

  defp update_random(:server, sParams, random) do
    r_security_parameters(sParams, client_random: random)
  end

  defp update_random(:client, sParams, random) do
    r_security_parameters(sParams, server_random: random)
  end

  defp update_resumption_master_secret(
         r_state(connection_states: connectionStates0) = state,
         resumptionMasterSecret
       ) do
    %{security_parameters: secParamsR0} =
      pendingRead =
      :maps.get(
        :pending_read,
        connectionStates0
      )

    %{security_parameters: secParamsW0} =
      pendingWrite =
      :maps.get(
        :pending_write,
        connectionStates0
      )

    secParamsR =
      r_security_parameters(secParamsR0, resumption_master_secret: resumptionMasterSecret)

    secParamsW =
      r_security_parameters(secParamsW0, resumption_master_secret: resumptionMasterSecret)

    connectionStates =
      Map.merge(connectionStates0, %{
        pending_read: Map.put(pendingRead, :security_parameters, secParamsR),
        pending_write: Map.put(pendingWrite, :security_parameters, secParamsW)
      })

    r_state(state, connection_states: connectionStates)
  end

  defp cipher_init(11, key, iV, finishedKey) do
    r_cipher_state(key: key, iv: iV, finished_key: finishedKey, tag_len: 8)
  end

  defp cipher_init(_BulkCipherAlgo, key, iV, finishedKey) do
    r_cipher_state(key: key, iv: iV, finished_key: finishedKey, tag_len: 16)
  end

  defp get_handshake_context_cv({[<<15, _::binary>> | messages], _}) do
    messages
  end

  defp get_handshake_context(:server, {messages, _}) do
    get_handshake_context_server(messages)
  end

  defp get_handshake_context(:client, {messages, _}) do
    get_handshake_context_client(messages)
  end

  defp get_handshake_context_server([h | t]) when is_binary(h) do
    get_handshake_context_server(t)
  end

  defp get_handshake_context_server(l) do
    l
  end

  defp get_handshake_context_client([h | t]) when is_list(h) do
    get_handshake_context_client(t)
  end

  defp get_handshake_context_client(l) do
    l
  end

  def verify_signature_algorithm(
        r_state(
          static_env: r_static_env(role: role),
          ssl_options: %{signature_algs: localSignAlgs}
        ) = state0,
        r_certificate_verify_1_3(algorithm: peerSignAlg)
      ) do
    case :lists.member(
           peerSignAlg,
           filter_tls13_algs(localSignAlgs)
         ) do
      true ->
        {:ok, maybe_update_selected_sign_alg(state0, peerSignAlg, role)}

      false ->
        state1 = calculate_traffic_secrets(state0)
        state = :ssl_record.step_encryption_state(state1)

        {:error,
         {r_alert(
            level: 2,
            description: 40,
            where: %{
              mfa: {:tls_handshake_1_3, :verify_signature_algorithm, 2},
              line: 1400,
              file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
            },
            reason: ~c"CertificateVerify uses unsupported signature algorithm"
          ), state}}
    end
  end

  defp maybe_update_selected_sign_alg(r_state(session: session) = state, signAlg, :client) do
    r_state(state, session: r_session(session, sign_alg: signAlg))
  end

  defp maybe_update_selected_sign_alg(state, _, _) do
    state
  end

  defp context_string(:server) do
    "TLS 1.3, server CertificateVerify"
  end

  defp context_string(:client) do
    "TLS 1.3, client CertificateVerify"
  end

  defp peer_context_string(:server) do
    "TLS 1.3, client CertificateVerify"
  end

  defp peer_context_string(:client) do
    "TLS 1.3, server CertificateVerify"
  end

  def select_common_groups(_, []) do
    {:error,
     r_alert(
       level: 2,
       description: 71,
       where: %{
         mfa: {:tls_handshake_1_3, :select_common_groups, 2},
         line: 1432,
         file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
       },
       reason: :no_suitable_groups
     )}
  end

  def select_common_groups(serverGroups, clientGroups) do
    fun = fn e ->
      :lists.member(e, clientGroups)
    end

    case :lists.filter(fun, serverGroups) do
      [] ->
        select_common_groups(serverGroups, [])

      l ->
        {:ok, l}
    end
  end

  def check_cert_sign_algo(signAlgo, signHash, clientSignAlgs, :undefined) do
    do_check_cert_sign_algo(signAlgo, signHash, clientSignAlgs)
  end

  def check_cert_sign_algo(signAlgo, signHash, _, clientSignAlgsCert) do
    do_check_cert_sign_algo(signAlgo, signHash, clientSignAlgsCert)
  end

  def select_sign_algo(:dsa, _RSAKeySize, _CertSignAlg, _OwnSignAlgs, _Curve) do
    {:error,
     r_alert(
       level: 2,
       description: 71,
       where: %{
         mfa: {:tls_handshake_1_3, :select_sign_algo, 5},
         line: 1464,
         file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
       },
       reason: :no_suitable_public_key
     )}
  end

  def select_sign_algo(_, _RSAKeySize, [], _, _) do
    {:error,
     r_alert(
       level: 2,
       description: 71,
       where: %{
         mfa: {:tls_handshake_1_3, :select_sign_algo, 5},
         line: 1466,
         file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
       },
       reason: :no_suitable_signature_algorithm
     )}
  end

  def select_sign_algo(_, _RSAKeySize, :undefined, _OwnSignAlgs, _) do
    {:error,
     r_alert(
       level: 2,
       description: 71,
       where: %{
         mfa: {:tls_handshake_1_3, :select_sign_algo, 5},
         line: 1468,
         file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
       },
       reason: :no_suitable_public_key
     )}
  end

  def select_sign_algo(
        publicKeyAlgo,
        rSAKeySize,
        [certSignAlg | certSignAlgs],
        ownSignAlgs,
        curve
      ) do
    {_, s, _} = :ssl_cipher.scheme_to_components(certSignAlg)

    case ((publicKeyAlgo === :rsa and s === :rsa_pss_rsae) or
            (publicKeyAlgo === :rsa_pss_pss and s === :rsa_pss_pss) or
            (publicKeyAlgo === :ecdsa and s === :ecdsa) or
            (publicKeyAlgo === :eddsa and s === :eddsa)) and
           :lists.member(
             certSignAlg,
             ownSignAlgs
           ) do
      true ->
        validate_key_compatibility(
          publicKeyAlgo,
          rSAKeySize,
          [certSignAlg | certSignAlgs],
          ownSignAlgs,
          curve
        )

      false ->
        select_sign_algo(publicKeyAlgo, rSAKeySize, certSignAlgs, ownSignAlgs, curve)
    end
  end

  defp validate_key_compatibility(
         publicKeyAlgo,
         rSAKeySize,
         [certSignAlg | certSignAlgs],
         ownSignAlgs,
         curve
       )
       when publicKeyAlgo === :rsa or publicKeyAlgo === :rsa_pss_pss do
    {hash, sign, _} = :ssl_cipher.scheme_to_components(certSignAlg)

    case (sign === :rsa_pss_rsae or sign === :rsa_pss_pss) and
           is_rsa_key_compatible(
             rSAKeySize,
             hash
           ) do
      true ->
        {:ok, certSignAlg}

      false ->
        select_sign_algo(publicKeyAlgo, rSAKeySize, certSignAlgs, ownSignAlgs, curve)
    end
  end

  defp validate_key_compatibility(
         publicKeyAlgo,
         rSAKeySize,
         [certSignAlg | certSignAlgs],
         ownSignAlgs,
         curve
       )
       when publicKeyAlgo === :ecdsa do
    {_, sign, peerCurve} = :ssl_cipher.scheme_to_components(certSignAlg)

    case sign === :ecdsa and curve === peerCurve do
      true ->
        {:ok, certSignAlg}

      false ->
        select_sign_algo(publicKeyAlgo, rSAKeySize, certSignAlgs, ownSignAlgs, curve)
    end
  end

  defp validate_key_compatibility(_, _, [certSignAlg | _], _, _) do
    {:ok, certSignAlg}
  end

  defp is_rsa_key_compatible(keySize, hash) do
    hashSize = :ssl_cipher.hash_size(hash)

    cond do
      keySize < hashSize + 2 ->
        false

      hashSize > keySize - hashSize - 2 ->
        false

      true ->
        true
    end
  end

  defp do_check_cert_sign_algo(_, _, :undefined) do
    {:error,
     r_alert(
       level: 2,
       description: 71,
       where: %{
         mfa: {:tls_handshake_1_3, :do_check_cert_sign_algo, 3},
         line: 1535,
         file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
       },
       reason: :no_suitable_signature_algorithm
     )}
  end

  defp do_check_cert_sign_algo(_, _, []) do
    {:error,
     r_alert(
       level: 2,
       description: 71,
       where: %{
         mfa: {:tls_handshake_1_3, :do_check_cert_sign_algo, 3},
         line: 1537,
         file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
       },
       reason: :no_suitable_signature_algorithm
     )}
  end

  defp do_check_cert_sign_algo(signAlgo, signHash, [scheme | t]) do
    {hash, sign, _Curve} = :ssl_cipher.scheme_to_components(scheme)

    case compare_sign_algos(signAlgo, signHash, sign, hash) do
      true ->
        :ok

      _Else ->
        do_check_cert_sign_algo(signAlgo, signHash, t)
    end
  end

  defp compare_sign_algos(:rsa_pss_pss, hash, :rsa_pss_pss, hash) do
    true
  end

  defp compare_sign_algos(:rsa, hash, algo, hash)
       when algo === :rsa_pss_rsae or algo === :rsa_pkcs1 do
    true
  end

  defp compare_sign_algos(algo, hash, algo, hash) do
    true
  end

  defp compare_sign_algos(_, _, _, _) do
    false
  end

  def get_certificate_params(cert) do
    {signAlgo0, param, subjectPublicKeyAlgo0, rSAKeySize, curve} =
      :ssl_handshake.get_cert_params(cert)

    {signHash, signAlgo} = oids_to_atoms(signAlgo0, param)
    subjectPublicKeyAlgo = public_key_algo(subjectPublicKeyAlgo0)
    {subjectPublicKeyAlgo, signAlgo, signHash, rSAKeySize, curve}
  end

  defp oids_to_atoms(
         {1, 2, 840, 113_549, 1, 1, 10},
         r_RSASSA_PSS_params(
           maskGenAlgorithm:
             r_MaskGenAlgorithm(
               algorithm: {1, 2, 840, 113_549, 1, 1, 8},
               parameters: r_HashAlgorithm(algorithm: hashOid)
             )
         )
       ) do
    hash = :public_key.pkix_hash_type(hashOid)
    {hash, :rsa_pss_pss}
  end

  defp oids_to_atoms(signAlgo, _) do
    :public_key.pkix_sign_types(signAlgo)
  end

  defp public_key_algo({1, 2, 840, 113_549, 1, 1, 10}) do
    :rsa_pss_pss
  end

  defp public_key_algo({1, 2, 840, 113_549, 1, 1, 1}) do
    :rsa
  end

  defp public_key_algo({1, 2, 840, 10045, 2, 1}) do
    :ecdsa
  end

  defp public_key_algo({1, 3, 101, 112}) do
    :eddsa
  end

  defp public_key_algo({1, 3, 101, 113}) do
    :eddsa
  end

  defp public_key_algo({1, 2, 840, 10040, 4, 1}) do
    :dsa
  end

  def get_signature_scheme_list(:undefined) do
    :undefined
  end

  def get_signature_scheme_list(r_hash_sign_algos()) do
    []
  end

  def get_signature_scheme_list(
        r_signature_algorithms_cert(signature_scheme_list: clientSignatureSchemes)
      ) do
    clientSignatureSchemes
  end

  def get_signature_scheme_list(
        r_signature_algorithms(signature_scheme_list: clientSignatureSchemes)
      ) do
    :lists.filter(
      fn e ->
        is_atom(e) and e !== :unassigned
      end,
      clientSignatureSchemes
    )
  end

  def get_certificate_authorities(r_certificate_authorities(authorities: auths)) do
    auths
  end

  def get_certificate_authorities(:undefined) do
    []
  end

  def handle_pre_shared_key(_, :undefined, _) do
    {:ok, :undefined}
  end

  def handle_pre_shared_key(r_state(ssl_options: %{session_tickets: :disabled}), _, _) do
    {:ok, :undefined}
  end

  def handle_pre_shared_key(
        r_state(
          ssl_options: %{session_tickets: tickets},
          handshake_env: r_handshake_env(tls_handshake_history: {hHistory, _}),
          static_env: r_static_env(trackers: trackers)
        ),
        r_pre_shared_key_client_hello(offered_psks: offeredPreSharedKeys),
        cipher
      )
      when tickets !== :disabled do
    tracker =
      :proplists.get_value(
        :session_tickets_tracker,
        trackers
      )

    %{prf: cipherHash} = :ssl_cipher_format.suite_bin_to_map(cipher)
    :tls_server_session_ticket.use(tracker, offeredPreSharedKeys, cipherHash, hHistory)
  end

  def maybe_add_binders(hello, :undefined, _) do
    hello
  end

  def maybe_add_binders(hello0, ticketData, {3, 4} = version) do
    helloBin0 =
      :tls_handshake.encode_handshake(
        hello0,
        version
      )

    helloBin1 = :erlang.iolist_to_binary(helloBin0)
    truncated = truncate_client_hello(helloBin1)
    binders = create_binders([truncated], ticketData)
    update_binders(hello0, binders)
  end

  def maybe_add_binders(hello, _, version) when version <= {3, 3} do
    hello
  end

  def maybe_add_binders(hello, _, :undefined, _) do
    hello
  end

  def maybe_add_binders(hello0, {[hRR, messageHash | _], _}, ticketData, {3, 4} = version) do
    helloBin0 =
      :tls_handshake.encode_handshake(
        hello0,
        version
      )

    helloBin1 = :erlang.iolist_to_binary(helloBin0)
    truncated = truncate_client_hello(helloBin1)

    binders =
      create_binders(
        [messageHash, hRR, truncated],
        ticketData
      )

    update_binders(hello0, binders)
  end

  def maybe_add_binders(hello, _, _, version) when version <= {3, 3} do
    hello
  end

  defp create_binders(context, ticketData) do
    create_binders(context, ticketData, [])
  end

  defp create_binders(_, [], acc) do
    :lists.reverse(acc)
  end

  defp create_binders(context, [r_ticket_data(psk: pSK, cipher_suite: {_, hKDF}) | t], acc) do
    finishedKey = calculate_finished_key(pSK, hKDF)
    binder = calculate_binder(finishedKey, hKDF, context)
    create_binders(context, t, [binder | acc])
  end

  defp truncate_client_hello(helloBin0) do
    <<type::size(8)-unsigned-big-integer, _Length::size(24)-unsigned-big-integer, body::binary>> =
      helloBin0

    cH0 =
      r_client_hello(extensions: %{pre_shared_key: pSK0} = extensions0) =
      :tls_handshake.decode_handshake(
        {3, 4},
        type,
        body
      )

    r_pre_shared_key_client_hello(offered_psks: offeredPsks0) = pSK0
    offeredPsks = r_offered_psks(offeredPsks0, binders: [])
    pSK = r_pre_shared_key_client_hello(pSK0, offered_psks: offeredPsks)
    extensions = Map.put(extensions0, :pre_shared_key, pSK)
    cH = r_client_hello(cH0, extensions: extensions)

    truncatedSize =
      :erlang.iolist_size(
        :tls_handshake.encode_handshake(
          cH,
          {3, 4}
        )
      )

    refSize =
      :erlang.iolist_size(
        :tls_handshake.encode_handshake(
          cH0,
          {3, 4}
        )
      )

    bindersSize = refSize - truncatedSize

    {truncated, _} =
      :erlang.split_binary(
        helloBin0,
        byte_size(helloBin0) - bindersSize - 2
      )

    truncated
  end

  def maybe_add_early_data_indication(
        r_client_hello(extensions: extensions0) = clientHello,
        earlyData,
        {3, 4}
      )
      when is_binary(earlyData) and byte_size(earlyData) > 0 do
    extensions = Map.put(extensions0, :early_data, r_early_data_indication())
    r_client_hello(clientHello, extensions: extensions)
  end

  def maybe_add_early_data_indication(clientHello, _, _) do
    clientHello
  end

  def supported_groups_from_extensions(extensions) do
    case :maps.get(:elliptic_curves, extensions, :undefined) do
      r_supported_groups() = groups ->
        {:ok, groups}

      r_elliptic_curves() ->
        {:error,
         r_alert(
           level: 2,
           description: 47,
           where: %{
             mfa: {:tls_handshake_1_3, :supported_groups_from_extensions, 1},
             line: 1741,
             file: ~c"otp/lib/ssl/src/tls_handshake_1_3.erl"
           }
         )}

      :undefined ->
        {:ok, :undefined}
    end
  end

  defp calculate_finished_key(pSK, hKDFAlgo) do
    earlySecret = :tls_v1.key_schedule(:early_secret, hKDFAlgo, {:psk, pSK})

    pRK =
      :tls_v1.resumption_binder_key(
        hKDFAlgo,
        earlySecret
      )

    :tls_v1.finished_key(pRK, hKDFAlgo)
  end

  defp calculate_binder(binderKey, hKDF, truncated) do
    :tls_v1.finished_verify_data(binderKey, hKDF, [truncated])
  end

  defp update_binders(
         r_client_hello(extensions: %{pre_shared_key: preSharedKey0} = extensions0) = hello,
         binders
       ) do
    r_pre_shared_key_client_hello(offered_psks: r_offered_psks(identities: identities)) =
      preSharedKey0

    preSharedKey =
      r_pre_shared_key_client_hello(
        offered_psks:
          r_offered_psks(
            identities: identities,
            binders: binders
          )
      )

    extensions = Map.put(extensions0, :pre_shared_key, preSharedKey)
    r_client_hello(hello, extensions: extensions)
  end

  def early_data_size(:undefined) do
    :undefined
  end

  def early_data_size(earlyData) when is_binary(earlyData) do
    byte_size(earlyData)
  end

  def choose_ticket({key, _}, _) when key !== :undefined do
    key
  end

  def choose_ticket({_, key}, earlyData)
      when earlyData === :undefined do
    key
  end

  def choose_ticket(_, _) do
    :undefined
  end

  def ciphers_for_early_data(cipherSuites0) do
    :lists.filtermap(
      &ciphers_for_early_data0/1,
      cipherSuites0
    )
  end

  defp ciphers_for_early_data0(cipherSuite) do
    case :lists.member(
           cipherSuite,
           :tls_v1.exclusive_suites({3, 4})
         ) do
      true ->
        {true,
         :maps.get(
           :cipher,
           :ssl_cipher_format.suite_bin_to_map(cipherSuite)
         )}

      false ->
        false
    end
  end

  def get_ticket_data(_, :undefined, _) do
    :undefined
  end

  def get_ticket_data(_, _, :undefined) do
    :undefined
  end

  def get_ticket_data(_, :manual, useTicket) do
    process_user_tickets(useTicket)
  end

  def get_ticket_data(pid, :auto, useTicket) do
    :tls_client_ticket_store.get_tickets(pid, useTicket)
  end

  defp process_user_tickets(useTicket) do
    process_user_tickets(useTicket, [], 0)
  end

  defp process_user_tickets([], acc, _) do
    :lists.reverse(acc)
  end

  defp process_user_tickets([h | t], acc, n) do
    case process_ticket(h, n) do
      :error ->
        process_user_tickets(t, acc, n + 1)

      ticketData ->
        process_user_tickets(t, [ticketData | acc], n + 1)
    end
  end

  defp process_ticket(
         %{
           cipher_suite: cipherSuite,
           sni: _SNI,
           psk: pSK,
           timestamp: timestamp,
           ticket: newSessionTicket
         },
         n
       ) do
    r_new_session_ticket(
      ticket_lifetime: _LifeTime,
      ticket_age_add: ageAdd,
      ticket_nonce: nonce,
      ticket: ticket,
      extensions: extensions
    ) = newSessionTicket

    ticketAge = :erlang.system_time(:millisecond) - timestamp

    obfuscatedTicketAge =
      obfuscate_ticket_age(
        ticketAge,
        ageAdd
      )

    identity =
      r_psk_identity(
        identity: ticket,
        obfuscated_ticket_age: obfuscatedTicketAge
      )

    maxEarlyData = get_max_early_data(extensions)

    r_ticket_data(
      key: :undefined,
      pos: n,
      identity: identity,
      psk: pSK,
      nonce: nonce,
      cipher_suite: cipherSuite,
      max_size: maxEarlyData
    )
  end

  defp process_ticket(_, _) do
    :error
  end

  def get_max_early_data(extensions) do
    earlyDataIndication = :maps.get(:early_data, extensions, :undefined)

    case earlyDataIndication do
      :undefined ->
        :undefined

      r_early_data_indication_nst(indication: maxSize) ->
        maxSize
    end
  end

  defp obfuscate_ticket_age(ticketAge, ageAdd) do
    rem(ticketAge + ageAdd, round(:math.pow(2, 32)))
  end

  def path_validation(
        trustedCert,
        path,
        serverName,
        role,
        certDbHandle,
        certDbRef,
        cRLDbHandle,
        version,
        %{
          verify_fun: verifyFun,
          customize_hostname_check: customizeHostnameCheck,
          crl_check: crlCheck,
          log_level: logLevel,
          signature_algs: signAlgos,
          signature_algs_cert: signAlgosCert
        } = opts,
        %{cert_ext: certExt, ocsp_responder_certs: ocspResponderCerts, ocsp_state: ocspState}
      ) do
    validationFunAndState =
      :ssl_handshake.validation_fun_and_state(
        verifyFun,
        %{
          role: role,
          certdb: certDbHandle,
          certdb_ref: certDbRef,
          server_name: serverName,
          customize_hostname_check: customizeHostnameCheck,
          crl_check: crlCheck,
          crl_db: cRLDbHandle,
          signature_algs: filter_tls13_algs(signAlgos),
          signature_algs_cert: filter_tls13_algs(signAlgosCert),
          version: version,
          issuer: trustedCert,
          cert_ext: certExt,
          ocsp_responder_certs: ocspResponderCerts,
          ocsp_state: ocspState,
          path_len: length(path)
        },
        path,
        logLevel
      )

    options = [
      {:max_path_length, :maps.get(:depth, opts, 10)},
      {:verify_fun, validationFunAndState}
    ]

    :public_key.pkix_path_validation(trustedCert, path, options)
  end

  defp select_client_cert_key_pair(
         session0,
         [%{private_key: noKey, certs: [[]] = noCerts}],
         _,
         _,
         _,
         _,
         _,
         _,
         _
       ) do
    r_session(session0,
      own_certificates: noCerts,
      private_key: noKey
    )
  end

  defp select_client_cert_key_pair(session, [], _, _, _, _, _, _, :undefined) do
    r_session(session, own_certificates: [[]], private_key: %{})
  end

  defp select_client_cert_key_pair(_, [], _, _, _, _, _, _, r_session() = plausible) do
    plausible
  end

  defp select_client_cert_key_pair(
         session0,
         [%{private_key: key, certs: [cert | _] = certs} | rest],
         serverSignAlgs,
         serverSignAlgsCert,
         clientSignAlgs,
         certDbHandle,
         certDbRef,
         certAuths,
         plausible0
       ) do
    {publicKeyAlgo, signAlgo, signHash, maybeRSAKeySize, curve} = get_certificate_params(cert)

    case select_sign_algo(publicKeyAlgo, maybeRSAKeySize, serverSignAlgs, clientSignAlgs, curve) do
      {:ok, selectedSignAlg} ->
        case check_cert_sign_algo(signAlgo, signHash, serverSignAlgs, serverSignAlgsCert) do
          :ok ->
            case :ssl_certificate.handle_cert_auths(certs, certAuths, certDbHandle, certDbRef) do
              {:ok, encodedChain} ->
                r_session(session0,
                  sign_alg: selectedSignAlg,
                  own_certificates: encodedChain,
                  private_key: key
                )

              {:error, encodedChain, :not_in_auth_domain} ->
                plausible =
                  plausible_missing_chain(
                    encodedChain,
                    plausible0,
                    selectedSignAlg,
                    key,
                    session0
                  )

                select_client_cert_key_pair(
                  session0,
                  rest,
                  serverSignAlgs,
                  serverSignAlgsCert,
                  clientSignAlgs,
                  certDbHandle,
                  certDbRef,
                  certAuths,
                  plausible
                )
            end

          _ ->
            select_client_cert_key_pair(
              session0,
              rest,
              serverSignAlgs,
              serverSignAlgsCert,
              clientSignAlgs,
              certDbHandle,
              certDbRef,
              certAuths,
              plausible0
            )
        end

      {:error, _} ->
        select_client_cert_key_pair(
          session0,
          rest,
          serverSignAlgsCert,
          serverSignAlgsCert,
          clientSignAlgs,
          certDbHandle,
          certDbRef,
          certAuths,
          plausible0
        )
    end
  end

  defp plausible_missing_chain([_] = encodedChain, :undefined, signAlg, key, session0) do
    r_session(session0, sign_alg: signAlg, own_certificates: encodedChain, private_key: key)
  end

  defp plausible_missing_chain(_, plausible, _, _, _) do
    plausible
  end
end
