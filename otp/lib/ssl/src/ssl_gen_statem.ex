defmodule :m_ssl_gen_statem do
  use Bitwise
  import Kernel, except: [send: 2]
  require Record
  Record.defrecord(:r_sslsocket, :sslsocket, fd: nil, pid: nil)

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

  Record.defrecord(:r_alert, :alert,
    level: :undefined,
    description: :undefined,
    where: :undefined,
    role: :undefined,
    reason: :undefined
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

  def start_link(role, sender, host, port, socket, {sslOpts, _, _} = options, user, cbInfo) do
    receiverOpts = :maps.get(:receiver_spawn_opts, sslOpts, [])
    opts = [:link | :proplists.delete(:link, receiverOpts)]

    pid =
      :proc_lib.spawn_opt(
        :ssl_gen_statem,
        :init,
        [[role, sender, host, port, socket, options, user, cbInfo]],
        opts
      )

    {:ok, pid}
  end

  def start_link(role, host, port, socket, {sslOpts, _, _} = options, user, cbInfo) do
    receiverOpts = :maps.get(:receiver_spawn_opts, sslOpts, [])
    opts = [:link | :proplists.delete(:link, receiverOpts)]

    pid =
      :proc_lib.spawn_opt(
        :ssl_gen_statem,
        :init,
        [[role, host, port, socket, options, user, cbInfo]],
        opts
      )

    {:ok, pid}
  end

  def init([role, _Sender, _Host, _Port, _Socket, {tLSOpts, _, _}, _User, _CbInfo] = initArgs) do
    :erlang.process_flag(:trap_exit, true)

    case :maps.get(:erl_dist, tLSOpts, false) do
      true ->
        :erlang.process_flag(:priority, :max)

      _ ->
        :ok
    end

    case {role, tLSOpts} do
      {:client, %{versions: [{3, 4}]}} ->
        :tls_client_connection_1_3.init(initArgs)

      {:server, %{versions: [{3, 4}]}} ->
        :tls_server_connection_1_3.init(initArgs)

      {_, _} ->
        :tls_connection.init(initArgs)
    end
  end

  def init([_Role, _Host, _Port, _Socket, _TLSOpts, _User, _CbInfo] = initArgs) do
    :erlang.process_flag(:trap_exit, true)
    :dtls_connection.init(initArgs)
  end

  def init_ssl_config(
        opts,
        role,
        r_state(
          ssl_options: %{handshake: handshake},
          handshake_env: hsEnv
        ) = state0
      ) do
    continueStatus =
      case handshake do
        :hello ->
          :pause

        :full ->
          handshake
      end

    ssl_config(
      opts,
      role,
      r_state(state0, handshake_env: r_handshake_env(hsEnv, continue_status: continueStatus))
    )
  end

  def ssl_config(
        opts,
        role,
        r_state(static_env: initStatEnv0, handshake_env: hsEnv, connection_env: cEnv) = state0
      ) do
    {:ok,
     %{
       cert_db_ref: ref,
       cert_db_handle: certDbHandle,
       fileref_db_handle: fileRefHandle,
       session_cache: cacheHandle,
       crl_db_info: cRLDbHandle,
       cert_key_alts: certKeyAlts,
       dh_params: dHParams
     }} = :ssl_config.init(opts, role)

    timeStamp = :erlang.monotonic_time()
    session = r_state(state0, :session)

    r_state(state0,
      session: r_session(session, time_stamp: timeStamp),
      static_env:
        r_static_env(initStatEnv0,
          file_ref_db: fileRefHandle,
          cert_db_ref: ref,
          cert_db: certDbHandle,
          crl_db: cRLDbHandle,
          session_cache: cacheHandle
        ),
      handshake_env: r_handshake_env(hsEnv, diffie_hellman_params: dHParams),
      connection_env: r_connection_env(cEnv, cert_key_alts: certKeyAlts),
      ssl_options: opts
    )
  end

  def connect(connection, host, port, socket, options, user, cbInfo, timeout) do
    try do
      connection.start_fsm(:client, host, port, socket, options, user, cbInfo, timeout)
    catch
      :exit, {:noproc, _} ->
        {:error, :ssl_not_started}
    end
  end

  def handshake(connection, port, socket, opts, user, cbInfo, timeout) do
    try do
      connection.start_fsm(:server, ~c"localhost", port, socket, opts, user, cbInfo, timeout)
    catch
      :exit, {:noproc, _} ->
        {:error, :ssl_not_started}
    end
  end

  def handshake(r_sslsocket(pid: [pid | _]) = socket, timeout) do
    case call(pid, {:start, timeout}) do
      :connected ->
        {:ok, socket}

      {:ok, ext} ->
        {:ok, socket, no_records(ext)}

      error ->
        error
    end
  end

  def handshake(r_sslsocket(pid: [pid | _]) = socket, sslOptions, timeout) do
    case call(pid, {:start, sslOptions, timeout}) do
      :connected ->
        {:ok, socket}

      error ->
        error
    end
  end

  def handshake_continue(r_sslsocket(pid: [pid | _]) = socket, sslOptions, timeout) do
    case call(
           pid,
           {:handshake_continue, sslOptions, timeout}
         ) do
      :connected ->
        {:ok, socket}

      error ->
        error
    end
  end

  def handshake_cancel(r_sslsocket(pid: [pid | _])) do
    case call(pid, :cancel) do
      :closed ->
        :ok

      error ->
        error
    end
  end

  def socket_control(connection, socket, pid, transport) do
    socket_control(connection, socket, pid, transport, :undefined)
  end

  def socket_control(:dtls_gen_connection, socket, pids, transport, :udp_listener) do
    {:ok, :dtls_gen_connection.socket(pids, transport, socket, :undefined)}
  end

  def socket_control(:tls_gen_connection, socket, [pid | _] = pids, transport, trackers) do
    case transport.controlling_process(socket, pid) do
      :ok ->
        {:ok, :tls_gen_connection.socket(pids, transport, socket, trackers)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def socket_control(
        :dtls_gen_connection,
        {peerAddrPort, socket},
        [pid | _] = pids,
        transport,
        trackers
      ) do
    case transport.controlling_process(socket, pid) do
      :ok ->
        {:ok, :dtls_gen_connection.socket(pids, transport, {peerAddrPort, socket}, trackers)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def prepare_connection(
        r_state(
          handshake_env: r_handshake_env(renegotiation: renegotiate),
          start_or_recv_from: recvFrom
        ) = state0,
        connection
      )
      when renegotiate !== {false, :first} and
             recvFrom !== :undefined do
    state = connection.reinit(state0)
    {:no_record, ack_connection(state)}
  end

  def prepare_connection(state0, connection) do
    state = connection.reinit(state0)
    {:no_record, ack_connection(state)}
  end

  def send(pid, data) do
    call(
      pid,
      {:application_data, :erlang.iolist_to_iovec(data)}
    )
  end

  def recv(pid, length, timeout) do
    call(pid, {:recv, length, timeout})
  end

  def connection_information(pid, includeSecrityInfo) when is_pid(pid) do
    case call(
           pid,
           {:connection_information, includeSecrityInfo}
         ) do
      {:ok, info} when includeSecrityInfo == true ->
        {:ok, maybe_add_keylog(info)}

      other ->
        other
    end
  end

  def close(connectionPid, how) do
    case call(connectionPid, how) do
      {:error, :closed} ->
        :ok

      other ->
        other
    end
  end

  def shutdown(connectionPid, how) do
    call(connectionPid, {:shutdown, how})
  end

  def new_user(connectionPid, user) do
    call(connectionPid, {:new_user, user})
  end

  def get_opts(connectionPid, optTags) do
    call(connectionPid, {:get_opts, optTags})
  end

  def set_opts(connectionPid, options) do
    call(connectionPid, {:set_opts, options})
  end

  def peer_certificate(connectionPid) do
    call(connectionPid, :peer_certificate)
  end

  def negotiated_protocol(connectionPid) do
    call(connectionPid, :negotiated_protocol)
  end

  def ktls_handover(connectionPid) do
    call(connectionPid, :ktls_handover)
  end

  def dist_handshake_complete(connectionPid, dHandle) do
    :gen_statem.cast(
      connectionPid,
      {:dist_handshake_complete, dHandle}
    )
  end

  def handle_sni_extension(:undefined, state) do
    {:ok, state}
  end

  def handle_sni_extension(r_sni(hostname: hostname), state0) do
    case check_hostname(hostname) do
      :ok ->
        {:ok, handle_sni_hostname(hostname, state0)}

      r_alert() = alert ->
        {:error, alert}
    end
  end

  def initial_hello(
        {:call, from},
        {:start, timeout},
        r_state(
          static_env:
            r_static_env(
              role: :client = role,
              host: host,
              port: port,
              cert_db: certDbHandle,
              cert_db_ref: certDbRef,
              protocol_cb: connection
            ),
          handshake_env:
            r_handshake_env(
              renegotiation: {renegotiation, _},
              ocsp_stapling_state: ocspState0
            ),
          connection_env: cEnv,
          ssl_options:
            %{
              versions: [helloVersion | _] = versions,
              session_tickets: sessionTickets,
              early_data: earlyData
            } = sslOpts,
          session: session,
          connection_states: connectionStates0
        ) = state0
      ) do
    keyShare = maybe_generate_client_shares(sslOpts)
    {useTicket, state1} = :tls_client_connection_1_3.maybe_automatic_session_resumption(state0)
    ticketData = :tls_handshake_1_3.get_ticket_data(self(), sessionTickets, useTicket)
    ocspNonce = :tls_handshake.ocsp_nonce(sslOpts)

    hello0 =
      :tls_handshake.client_hello(
        host,
        port,
        connectionStates0,
        sslOpts,
        r_session(session, :session_id),
        renegotiation,
        keyShare,
        ticketData,
        ocspNonce,
        certDbHandle,
        certDbRef
      )

    hello1 =
      :tls_handshake_1_3.maybe_add_early_data_indication(
        hello0,
        earlyData,
        helloVersion
      )

    hello2 = :tls_handshake_1_3.maybe_add_binders(hello1, ticketData, helloVersion)
    maxFragEnum = :maps.get(:max_frag_enum, r_client_hello(hello1, :extensions), :undefined)

    connectionStates1 =
      :ssl_record.set_max_fragment_length(
        maxFragEnum,
        connectionStates0
      )

    state2 =
      r_state(state1,
        connection_states: connectionStates1,
        connection_env: r_connection_env(cEnv, negotiated_version: helloVersion)
      )

    state3 = connection.queue_handshake(hello2, state2)
    requestedVersion = :tls_record.hello_version(versions)
    {ref, maybe} = :tls_gen_connection_1_3.do_maybe()

    try do
      state4 = maybe.(:tls_client_connection_1_3.maybe_send_early_data(state3))
      {r_state(handshake_env: hsEnv1) = state5, _} = connection.send_handshake_flight(state4)

      ocspStaplingKeyPresent =
        :maps.is_key(
          :ocsp_stapling,
          sslOpts
        )

      state =
        r_state(state5,
          connection_env: r_connection_env(cEnv, negotiated_version: requestedVersion),
          session: session,
          handshake_env:
            r_handshake_env(hsEnv1,
              ocsp_stapling_state:
                Map.merge(ocspState0, %{
                  ocsp_nonce: ocspNonce,
                  ocsp_stapling: ocspStaplingKeyPresent
                })
            ),
          start_or_recv_from: from,
          key_share: keyShare
        )

      nextState = next_statem_state(versions, role)

      connection.next_event(nextState, :no_record, state, [
        {{:timeout, :handshake}, timeout, :close}
      ])
    catch
      {^ref, r_alert() = alert} ->
        handle_own_alert(alert, :init, r_state(state0, start_or_recv_from: from))
    end
  end

  def initial_hello(
        {:call, from},
        {:start, timeout},
        r_state(
          static_env: r_static_env(role: role, protocol_cb: connection),
          ssl_options: %{versions: versions}
        ) = state0
      ) do
    nextState = next_statem_state(versions, role)

    connection.next_event(nextState, :no_record, r_state(state0, start_or_recv_from: from), [
      {{:timeout, :handshake}, timeout, :close}
    ])
  end

  def initial_hello(
        {:call, from},
        {:start, {opts, emOpts}, timeout},
        r_state(
          static_env: r_static_env(role: role),
          ssl_options: origSSLOptions,
          socket_options: sockOpts
        ) = state0
      ) do
    try do
      sslOpts = :ssl.update_options(opts, role, origSSLOptions)
      state = ssl_config(sslOpts, role, state0)

      initial_hello(
        {:call, from},
        {:start, timeout},
        r_state(state,
          ssl_options: sslOpts,
          socket_options:
            new_emulated(
              emOpts,
              sockOpts
            )
        )
      )
    catch
      error ->
        {:stop_and_reply, {:shutdown, :normal}, {:reply, from, {:error, error}}, state0}
    end
  end

  def initial_hello({:call, from}, {:new_user, _} = msg, state) do
    handle_call(msg, from, :initial_hello, state)
  end

  def initial_hello({:call, from}, _Msg, _State) do
    {:keep_state_and_data, [{:reply, from, {:error, :notsup_on_transport_accept_socket}}]}
  end

  def initial_hello(:info, {:DOWN, _, _, _, _} = event, state) do
    handle_info(event, :initial_hello, state)
  end

  def initial_hello(_Type, _Event, _State) do
    {:keep_state_and_data, [:postpone]}
  end

  def config_error(
        {:call, from},
        {:start, _Timeout},
        r_state(protocol_specific: %{error: error}) = state
      ) do
    {:stop_and_reply, {:shutdown, :normal}, [{:reply, from, {:error, error}}], state}
  end

  def config_error({:call, from}, {:close, _}, state) do
    {:stop_and_reply, {:shutdown, :normal}, {:reply, from, :ok}, state}
  end

  def config_error({:call, from}, _Msg, state) do
    {:next_state, :config_error, state, [{:reply, from, {:error, :closed}}]}
  end

  def config_error(:info, {:DOWN, _, _, _, _} = event, state) do
    handle_info(event, :config_error, state)
  end

  def config_error(_Type, _Event, _State) do
    {:keep_state_and_data, [:postpone]}
  end

  def connection(
        {:call, recvFrom},
        {:recv, n, timeout},
        r_state(
          static_env: r_static_env(protocol_cb: connection),
          socket_options: r_socket_options(active: false)
        ) = state0
      ) do
    passive_receive(
      r_state(state0,
        bytes_to_read: n,
        start_or_recv_from: recvFrom
      ),
      :connection,
      connection,
      [{{:timeout, :recv}, timeout, :timeout}]
    )
  end

  def connection(
        {:call, from},
        :peer_certificate,
        r_state(session: r_session(peer_certificate: cert)) = state
      ) do
    hibernate_after(:connection, state, [{:reply, from, {:ok, cert}}])
  end

  def connection({:call, from}, {:connection_information, true}, state) do
    info = connection_info(state) ++ security_info(state)
    hibernate_after(:connection, state, [{:reply, from, {:ok, info}}])
  end

  def connection({:call, from}, {:connection_information, false}, state) do
    info = connection_info(state)
    hibernate_after(:connection, state, [{:reply, from, {:ok, info}}])
  end

  def connection(
        {:call, from},
        :negotiated_protocol,
        r_state(
          handshake_env:
            r_handshake_env(
              alpn: :undefined,
              negotiated_protocol: :undefined
            )
        ) = state
      ) do
    hibernate_after(:connection, state, [{:reply, from, {:error, :protocol_not_negotiated}}])
  end

  def connection(
        {:call, from},
        :negotiated_protocol,
        r_state(
          handshake_env:
            r_handshake_env(
              alpn: :undefined,
              negotiated_protocol: selectedProtocol
            )
        ) = state
      ) do
    hibernate_after(:connection, state, [{:reply, from, {:ok, selectedProtocol}}])
  end

  def connection(
        {:call, from},
        :negotiated_protocol,
        r_state(
          handshake_env:
            r_handshake_env(
              alpn: selectedProtocol,
              negotiated_protocol: :undefined
            )
        ) = state
      ) do
    hibernate_after(:connection, state, [{:reply, from, {:ok, selectedProtocol}}])
  end

  def connection(
        {:call, from},
        {:close, {newController, timeout}},
        r_state(
          connection_states: connectionStates,
          static_env: r_static_env(protocol_cb: connection),
          protocol_specific: %{sender: sender} = pS,
          connection_env: r_connection_env(socket_tls_closed: peerClosedTLS) = cEnv
        ) = state0
      ) do
    action =
      case peerClosedTLS do
        true ->
          [
            {:next_event, :internal,
             r_alert(
               level: 1,
               description: 0,
               where: %{
                 mfa: {:ssl_gen_statem, :connection, 3},
                 line: 652,
                 file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
               }
             )}
          ]

        false ->
          [{:timeout, timeout, :downgrade}]
      end

    case :tls_sender.downgrade(sender, timeout) do
      {:ok, write} ->
        state =
          connection.send_alert(
            r_alert(
              level: 1,
              description: 0,
              where: %{
                mfa: {:ssl_gen_statem, :connection, 3},
                line: 663,
                file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
              }
            ),
            r_state(state0, connection_states: Map.put(connectionStates, :current_write, write))
          )

        {:next_state, :downgrade,
         r_state(state,
           connection_env: r_connection_env(cEnv, downgrade: {newController, from}),
           protocol_specific: Map.merge(pS, %{active_n_toggle: true, active_n: 1})
         ), action}

      {:error, :timeout} ->
        {:stop_and_reply, {:shutdown, :downgrade_fail}, [{:reply, from, {:error, :timeout}}]}
    end
  end

  def connection(
        {:call, from},
        :ktls_handover,
        r_state(
          static_env:
            r_static_env(
              transport_cb: transport,
              socket: socket
            ),
          connection_env:
            r_connection_env(
              user_application: {_Mon, pid},
              negotiated_version: tlsVersion
            ),
          ssl_options: %{ktls: true},
          socket_options: socketOpts,
          connection_states: %{
            current_write: %{
              security_parameters: r_security_parameters(cipher_suite: cipherSuite),
              cipher_state: writeState,
              sequence_number: writeSeq
            },
            current_read: %{cipher_state: readState, sequence_number: readSeq}
          }
        )
      ) do
    reply =
      case transport.controlling_process(
             socket,
             pid
           ) do
        :ok ->
          {:ok,
           %{
             socket: socket,
             tls_version: tlsVersion,
             cipher_suite: cipherSuite,
             socket_options: socketOpts,
             write_state: writeState,
             write_seq: writeSeq,
             read_state: readState,
             read_seq: readSeq
           }}

        {:error, reason} ->
          {:error, reason}
      end

    {:stop_and_reply, {:shutdown, :ktls}, [{:reply, from, reply}]}
  end

  def connection({:call, from}, msg, state) do
    handle_call(msg, from, :connection, state)
  end

  def connection(
        :cast,
        {:dist_handshake_complete, dHandle},
        r_state(
          ssl_options: %{erl_dist: true},
          static_env: r_static_env(protocol_cb: connection),
          connection_env: cEnv,
          socket_options: sockOpts
        ) = state0
      ) do
    :erlang.process_flag(:priority, :normal)

    state1 =
      r_state(state0,
        socket_options: r_socket_options(sockOpts, active: true),
        connection_env: r_connection_env(cEnv, erl_dist_handle: dHandle),
        bytes_to_read: :undefined
      )

    {record, state} = read_application_data(<<>>, state1)
    connection.next_event(:connection, record, state)
  end

  def connection(:info, msg, r_state(static_env: r_static_env(protocol_cb: connection)) = state) do
    connection.handle_info(msg, :connection, state)
  end

  def connection(
        :internal,
        {:recv, recvFrom},
        r_state(
          start_or_recv_from: recvFrom,
          static_env: r_static_env(protocol_cb: connection)
        ) = state
      ) do
    passive_receive(state, :connection, connection, [])
  end

  def connection(type, msg, state) do
    handle_common_event(type, msg, :connection, state)
  end

  def downgrade(
        :internal,
        r_alert(description: 0),
        r_state(
          static_env:
            r_static_env(
              transport_cb: transport,
              socket: socket
            ),
          connection_env: r_connection_env(downgrade: {pid, from}),
          protocol_buffers: r_protocol_buffers(tls_record_buffer: tlsRecordBuffer)
        ) = state
      ) do
    :tls_socket.setopts(transport, socket, [{:active, false}, {:packet, 0}, {:mode, :binary}])
    transport.controlling_process(socket, pid)

    returnValue =
      case tlsRecordBuffer do
        {:undefined, {[bin] = _Front, _Size, []}} ->
          {:ok, socket, bin}

        _ ->
          {:ok, socket}
      end

    {:stop_and_reply, {:shutdown, :downgrade}, [{:reply, from, returnValue}], state}
  end

  def downgrade(
        :timeout,
        :downgrade,
        r_state(connection_env: r_connection_env(downgrade: {_, from})) = state
      ) do
    {:stop_and_reply, {:shutdown, :normal}, [{:reply, from, {:error, :timeout}}], state}
  end

  def downgrade(
        :info,
        {closeTag, socket},
        r_state(
          static_env: r_static_env(socket: socket, close_tag: closeTag),
          connection_env: r_connection_env(downgrade: {_, from})
        ) = state
      ) do
    {:stop_and_reply, {:shutdown, :normal}, [{:reply, from, {:error, closeTag}}], state}
  end

  def downgrade(:info, info, state) do
    :tls_gen_connection.handle_info(info, :downgrade, state)
  end

  def downgrade(type, event, state) do
    try do
      :tls_dtls_connection.downgrade(type, event, state)
    catch
      r_alert() = alert ->
        handle_own_alert(alert, :downgrade, state)
    end
  end

  def handle_common_event(
        :internal,
        {:handshake, {handshake, raw}},
        stateName,
        r_state(
          handshake_env: r_handshake_env(tls_handshake_history: hist0) = hsEnv,
          connection_env: r_connection_env(negotiated_version: _Version)
        ) = state0
      ) do
    hist =
      :ssl_handshake.update_handshake_history(
        hist0,
        raw
      )

    {:next_state, stateName,
     r_state(state0, handshake_env: r_handshake_env(hsEnv, tls_handshake_history: hist)),
     [{:next_event, :internal, handshake}]}
  end

  def handle_common_event(
        :internal,
        {:protocol_record, tLSorDTLSRecord},
        stateName,
        r_state(static_env: r_static_env(protocol_cb: connection)) = state
      ) do
    connection.handle_protocol_record(tLSorDTLSRecord, stateName, state)
  end

  def handle_common_event(:timeout, :hibernate, _, _) do
    {:keep_state_and_data, [:hibernate]}
  end

  def handle_common_event(
        {:timeout, :handshake},
        :close,
        _StateName,
        r_state(start_or_recv_from: startFrom) = state
      ) do
    {:stop_and_reply, {:shutdown, :user_timeout}, {:reply, startFrom, {:error, :timeout}},
     r_state(state, start_or_recv_from: :undefined)}
  end

  def handle_common_event(
        {:timeout, :recv},
        :timeout,
        stateName,
        r_state(start_or_recv_from: recvFrom) = state
      ) do
    {:next_state, stateName,
     r_state(state,
       start_or_recv_from: :undefined,
       bytes_to_read: :undefined
     ), [{:reply, recvFrom, {:error, :timeout}}]}
  end

  def handle_common_event(
        :internal,
        {:recv, recvFrom},
        stateName,
        r_state(start_or_recv_from: recvFrom)
      )
      when stateName !== :connection do
    {:keep_state_and_data, [:postpone]}
  end

  def handle_common_event(:internal, :new_connection, stateName, state) do
    {:next_state, stateName, state}
  end

  def handle_common_event(type, msg, stateName, state) do
    alert =
      r_alert(
        level: 2,
        description: 10,
        where: %{
          mfa: {:ssl_gen_statem, :handle_common_event, 4},
          line: 803,
          file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
        },
        reason: {:unexpected_msg, {type, msg}}
      )

    handle_own_alert(alert, stateName, state)
  end

  def handle_call({:application_data, _Data}, _, _, _) do
    {:keep_state_and_data, [:postpone]}
  end

  def handle_call({:close, _} = close, from, stateName, r_state(connection_env: cEnv) = state) do
    result = terminate(close, stateName, state)

    {:stop_and_reply, {:shutdown, :normal}, {:reply, from, result},
     r_state(state, connection_env: r_connection_env(cEnv, socket_terminated: true))}
  end

  def handle_call(
        {:shutdown, :read_write = how},
        from,
        stateName,
        r_state(
          static_env:
            r_static_env(
              transport_cb: transport,
              socket: socket
            ),
          connection_env: cEnv
        ) = state
      ) do
    try do
      send_alert(
        r_alert(
          level: 1,
          description: 0,
          where: %{
            mfa: {:ssl_gen_statem, :handle_call, 4},
            line: 820,
            file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
          }
        ),
        stateName,
        state
      )
    catch
      return ->
        return
    else
      _ ->
        try do
          transport.shutdown(socket, how)
        catch
          :error, {:undef, _} ->
            {:stop_and_reply, {:shutdown, :normal}, {:reply, from, {:error, :notsup}},
             r_state(state, connection_env: r_connection_env(cEnv, socket_terminated: true))}
        else
          :ok ->
            {:next_state, stateName,
             r_state(state, connection_env: r_connection_env(cEnv, socket_terminated: true)),
             [{:reply, from, :ok}]}

          error ->
            {:stop_and_reply, {:shutdown, :normal}, {:reply, from, error},
             r_state(state, connection_env: r_connection_env(cEnv, socket_terminated: true))}
        end
    end
  end

  def handle_call(
        {:shutdown, how0},
        from,
        stateName,
        r_state(
          static_env:
            r_static_env(
              transport_cb: transport,
              socket: socket
            )
        ) = state
      ) do
    case transport.shutdown(socket, how0) do
      :ok ->
        {:next_state, stateName, state, [{:reply, from, :ok}]}

      error ->
        {:stop_and_reply, {:shutdown, :normal}, {:reply, from, error}, state}
    end
  end

  def handle_call(
        {:recv, _N, _Timeout},
        from,
        _,
        r_state(socket_options: r_socket_options(active: active))
      )
      when active !== false do
    {:keep_state_and_data, [{:reply, from, {:error, :einval}}]}
  end

  def handle_call({:recv, n, timeout}, recvFrom, stateName, state) do
    {:next_state, stateName,
     r_state(state,
       bytes_to_read: n,
       start_or_recv_from: recvFrom
     ), [{:next_event, :internal, {:recv, recvFrom}}, {{:timeout, :recv}, timeout, :timeout}]}
  end

  def handle_call(
        {:new_user, user},
        from,
        stateName,
        state = r_state(connection_env: r_connection_env(user_application: {oldMon, _}) = cEnv)
      ) do
    newMon = :erlang.monitor(:process, user)
    :erlang.demonitor(oldMon, [:flush])

    {:next_state, stateName,
     r_state(state, connection_env: r_connection_env(cEnv, user_application: {newMon, user})),
     [{:reply, from, :ok}]}
  end

  def handle_call(
        {:get_opts, optTags},
        from,
        _,
        r_state(
          static_env:
            r_static_env(protocol_cb: connection, socket: socket, transport_cb: transport),
          socket_options: sockOpts
        )
      ) do
    optsReply = get_socket_opts(connection, transport, socket, optTags, sockOpts, [])
    {:keep_state_and_data, [{:reply, from, optsReply}]}
  end

  def handle_call(
        {:set_opts, opts0},
        from,
        stateName,
        r_state(
          static_env:
            r_static_env(
              protocol_cb: connection,
              socket: socket,
              transport_cb: transport,
              trackers: trackers
            ),
          connection_env: r_connection_env(user_application: {_Mon, pid}),
          socket_options: opts1
        ) = state0
      ) do
    {reply, opts} = set_socket_opts(connection, transport, socket, opts0, opts1, [])

    case {:proplists.lookup(:active, opts0), opts} do
      {{_, n}, r_socket_options(active: false)} when is_integer(n) ->
        send_user(
          pid,
          format_passive(connection.pids(state0), transport, socket, trackers, connection)
        )

      _ ->
        :ok
    end

    state = r_state(state0, socket_options: opts)
    handle_active_option(r_socket_options(opts, :active), stateName, from, reply, state)
  end

  def handle_call(:renegotiate, from, stateName, _)
      when stateName !== :connection do
    {:keep_state_and_data, [{:reply, from, {:error, :already_renegotiating}}]}
  end

  def handle_call(_, _, _, _) do
    {:keep_state_and_data, [:postpone]}
  end

  def handle_info(
        {errorTag, socket, :econnaborted},
        stateName,
        r_state(
          static_env:
            r_static_env(
              role: role,
              host: host,
              port: port,
              socket: socket,
              transport_cb: transport,
              error_tag: errorTag,
              trackers: trackers,
              protocol_cb: connection
            ),
          handshake_env: r_handshake_env(renegotiation: type),
          connection_env: r_connection_env(negotiated_version: version),
          session: session,
          start_or_recv_from: startFrom
        ) = state
      )
      when stateName !== :connection do
    maybe_invalidate_session(version, type, role, host, port, session)
    pids = connection.pids(state)

    alert_user(
      pids,
      transport,
      trackers,
      socket,
      startFrom,
      r_alert(
        level: 2,
        description: 0,
        where: %{
          mfa: {:ssl_gen_statem, :handle_info, 3},
          line: 916,
          file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
        }
      ),
      role,
      stateName,
      connection
    )

    {:stop, {:shutdown, :normal}, state}
  end

  def handle_info(
        {errorTag, socket, reason},
        stateName,
        r_state(static_env: r_static_env(role: role, socket: socket, error_tag: errorTag)) = state
      ) do
    (fn ->
       case :erlang.get(:log_level) do
         :undefined ->
           :ssl_logger.log(
             :info,
             :debug,
             %{
               description: ~c"Socket error",
               reason: [{:error_tag, errorTag}, {:description, reason}]
             },
             %{
               mfa: {:ssl_gen_statem, :handle_info, 3},
               line: 924,
               file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
             }
           )

         __LogLevel__ ->
           :ssl_logger.log(
             :info,
             __LogLevel__,
             %{
               description: ~c"Socket error",
               reason: [{:error_tag, errorTag}, {:description, reason}]
             },
             %{
               mfa: {:ssl_gen_statem, :handle_info, 3},
               line: 924,
               file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
             }
           )
       end
     end).()

    alert =
      r_alert(
        level: 2,
        description: 0,
        where: %{
          mfa: {:ssl_gen_statem, :handle_info, 3},
          line: 925,
          file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
        },
        reason: {:transport_error, reason}
      )

    handle_normal_shutdown(r_alert(alert, role: role), stateName, state)
    {:stop, {:shutdown, :normal}, state}
  end

  def handle_info(
        {:DOWN, monitorRef, _, _, reason},
        _,
        r_state(
          connection_env: r_connection_env(user_application: {monitorRef, _Pid}),
          ssl_options: %{erl_dist: true}
        )
      ) do
    {:stop, {:shutdown, reason}}
  end

  def handle_info(
        {:DOWN, monitorRef, _, _, _},
        _,
        r_state(connection_env: r_connection_env(user_application: {monitorRef, _Pid}))
      ) do
    {:stop, {:shutdown, :normal}}
  end

  def handle_info(
        {:EXIT, pid, _Reason},
        stateName,
        r_state(connection_env: r_connection_env(user_application: {_MonitorRef, pid})) = state
      ) do
    {:next_state, stateName, state}
  end

  def handle_info({:EXIT, _Sup, :shutdown}, _StateName, state) do
    {:stop, :shutdown, state}
  end

  def handle_info(
        {:EXIT, socket, :normal},
        _StateName,
        r_state(static_env: r_static_env(socket: socket)) = state
      ) do
    {:stop, {:shutdown, :transport_closed}, state}
  end

  def handle_info(
        {:EXIT, socket, reason},
        _StateName,
        r_state(static_env: r_static_env(socket: socket)) = state
      ) do
    {:stop, {:shutdown, reason}, state}
  end

  def handle_info(:allow_renegotiate, stateName, r_state(handshake_env: hsEnv) = state) do
    {:next_state, stateName,
     r_state(state, handshake_env: r_handshake_env(hsEnv, allow_renegotiate: true))}
  end

  def handle_info(
        msg,
        stateName,
        r_state(
          static_env:
            r_static_env(
              socket: socket,
              error_tag: errorTag
            )
        ) = state
      ) do
    (fn ->
       case :erlang.get(:log_level) do
         :undefined ->
           :ssl_logger.log(
             :notice,
             :debug,
             %{
               description: ~c"Unexpected INFO message",
               reason: [{:message, msg}, {:socket, socket}, {:error_tag, errorTag}]
             },
             %{
               mfa: {:ssl_gen_statem, :handle_info, 3},
               line: 953,
               file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
             }
           )

         __LogLevel__ ->
           :ssl_logger.log(
             :notice,
             __LogLevel__,
             %{
               description: ~c"Unexpected INFO message",
               reason: [{:message, msg}, {:socket, socket}, {:error_tag, errorTag}]
             },
             %{
               mfa: {:ssl_gen_statem, :handle_info, 3},
               line: 953,
               file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
             }
           )
       end
     end).()

    {:next_state, stateName, state}
  end

  def read_application_data(
        data,
        r_state(
          user_data_buffer: {front0, bufferSize0, rear0},
          connection_env: r_connection_env(erl_dist_handle: dHandle)
        ) = state
      ) do
    front = front0
    bufferSize = bufferSize0 + byte_size(data)
    rear = [data | rear0]

    case dHandle do
      :undefined ->
        read_application_data(state, front, bufferSize, rear)

      _ ->
        try do
          read_application_dist_data(dHandle, front, bufferSize, rear)
        catch
          :error, :notsup ->
            {:stop, {:shutdown, :dist_closed},
             r_state(state, user_data_buffer: {front, bufferSize, rear})}

          :error, reason ->
            {:stop, {:disconnect, {:error, reason, __STACKTRACE__}},
             r_state(state, user_data_buffer: {front, bufferSize, rear})}
        else
          buffer ->
            {:no_record, r_state(state, user_data_buffer: buffer)}
        end
    end
  end

  defp passive_receive(
         r_state(
           user_data_buffer: {front, bufferSize, rear},
           connection_env: r_connection_env(erl_dist_handle: :undefined)
         ) = state0,
         stateName,
         connection,
         startTimerAction
       ) do
    case bufferSize do
      0 ->
        connection.next_event(stateName, :no_record, state0, startTimerAction)

      _ ->
        case read_application_data(state0, front, bufferSize, rear) do
          {:stop, _, _} = shutdownError ->
            shutdownError

          {record, state} ->
            case r_state(state, :start_or_recv_from) do
              :undefined ->
                connection.next_event(stateName, record, state, [
                  {{:timeout, :recv}, :infinity, :timeout}
                ])

              _ ->
                connection.next_event(stateName, record, state, startTimerAction)
            end
        end
    end
  end

  def hibernate_after(:connection = stateName, r_state(ssl_options: sslOpts) = state, actions) do
    hibernateAfter = :maps.get(:hibernate_after, sslOpts, :infinity)
    {:next_state, stateName, state, [{:timeout, hibernateAfter, :hibernate} | actions]}
  end

  def hibernate_after(stateName, state, actions) do
    {:next_state, stateName, state, actions}
  end

  def send_alert(
        alert,
        :connection,
        r_state(static_env: r_static_env(protocol_cb: connection)) = state
      ) do
    connection.send_alert_in_connection(alert, state)
  end

  def send_alert(alert, _, r_state(static_env: r_static_env(protocol_cb: connection)) = state) do
    connection.send_alert(alert, state)
  end

  def handle_own_alert(
        alert0,
        stateName,
        r_state(
          static_env: r_static_env(role: role, protocol_cb: connection),
          ssl_options: %{log_level: logLevel}
        ) = state
      ) do
    try do
      send_alert(alert0, stateName, state)
    catch
      _, _ ->
        :ignore
    end

    try do
      alert = r_alert(alert0, role: role)
      log_alert(logLevel, role, connection.protocol_name(), stateName, alert)
      handle_normal_shutdown(alert, stateName, state)
    catch
      _, _ ->
        :ok
    end

    {:stop, {:shutdown, :own_alert}, state}
  end

  def handle_normal_shutdown(
        alert,
        stateName,
        r_state(
          static_env:
            r_static_env(
              role: role,
              socket: socket,
              transport_cb: transport,
              protocol_cb: connection,
              trackers: trackers
            ),
          handshake_env: r_handshake_env(renegotiation: {false, :first}),
          start_or_recv_from: startFrom
        ) = state
      ) do
    pids = connection.pids(state)
    alert_user(pids, transport, trackers, socket, startFrom, alert, role, stateName, connection)
  end

  def handle_normal_shutdown(
        alert,
        stateName,
        r_state(
          static_env:
            r_static_env(
              role: role,
              socket: socket,
              transport_cb: transport,
              protocol_cb: connection,
              trackers: trackers
            ),
          connection_env: r_connection_env(user_application: {_Mon, pid}),
          handshake_env: r_handshake_env(renegotiation: type),
          socket_options: opts,
          start_or_recv_from: recvFrom
        ) = state
      ) do
    pids = connection.pids(state)

    alert_user(
      pids,
      transport,
      trackers,
      socket,
      type,
      opts,
      pid,
      recvFrom,
      alert,
      role,
      stateName,
      connection
    )
  end

  def handle_alert(r_alert(level: 2) = alert, stateName, state) do
    handle_fatal_alert(alert, stateName, state)
  end

  def handle_alert(r_alert(level: 1, description: 0) = alert, :downgrade = stateName, state) do
    {:next_state, stateName, state, [{:next_event, :internal, alert}]}
  end

  def handle_alert(
        r_alert(level: 1, description: 0) = alert0,
        stateName,
        r_state(static_env: r_static_env(role: role)) = state
      ) do
    alert = r_alert(alert0, role: opposite_role(role))
    handle_normal_shutdown(alert, stateName, state)
    {:stop, {:shutdown, :peer_close}, state}
  end

  def handle_alert(
        r_alert(level: 1, description: 100) = alert,
        stateName,
        r_state(
          static_env:
            r_static_env(
              role: :server = role,
              protocol_cb: connection
            ),
          handshake_env: r_handshake_env(renegotiation: {false, :first}),
          ssl_options: %{log_level: logLevel}
        ) = state
      )
      when stateName == :intial_hello or
             stateName == :hello or stateName == :certify or
             stateName == :abbreviated or stateName == :cipher do
    log_alert(
      logLevel,
      role,
      connection.protocol_name(),
      stateName,
      r_alert(alert, role: opposite_role(role))
    )

    ownAlert =
      r_alert(
        level: 2,
        description: 10,
        where: %{
          mfa: {:ssl_gen_statem, :handle_alert, 3},
          line: 1101,
          file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
        },
        reason: :unexpected_renegotiate_alert_during_initial_handshake
      )

    handle_own_alert(ownAlert, stateName, state)
  end

  def handle_alert(
        r_alert() = alert,
        stateName,
        r_state(
          static_env:
            r_static_env(
              role: :server = role,
              protocol_cb: connection
            ),
          handshake_env: r_handshake_env(renegotiation: {false, :first}),
          ssl_options: %{log_level: logLevel}
        ) = state
      )
      when stateName == :start or
             stateName == :intial_hello or stateName == :hello do
    log_alert(
      logLevel,
      role,
      connection.protocol_name(),
      stateName,
      r_alert(alert, role: opposite_role(role))
    )

    ownAlert =
      r_alert(
        level: 2,
        description: 10,
        where: %{
          mfa: {:ssl_gen_statem, :handle_alert, 3},
          line: 1112,
          file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
        },
        reason: :unexpected_alert
      )

    handle_own_alert(ownAlert, stateName, state)
  end

  def handle_alert(
        r_alert(level: 1, description: 100) = alert0,
        stateName,
        r_state(
          static_env: r_static_env(role: role, protocol_cb: connection),
          handshake_env: r_handshake_env(renegotiation: {true, :internal}),
          ssl_options: %{log_level: logLevel}
        ) = state
      ) do
    alert = r_alert(alert0, role: opposite_role(role))
    log_alert(logLevel, role, connection.protocol_name(), stateName, alert)
    handle_normal_shutdown(alert, stateName, state)
    {:stop, {:shutdown, :peer_close}, state}
  end

  def handle_alert(
        r_alert(level: 1, description: 100) = alert,
        :connection = stateName,
        r_state(
          static_env: r_static_env(role: role, protocol_cb: connection),
          handshake_env: r_handshake_env(renegotiation: {true, from}) = hsEnv,
          ssl_options: %{log_level: logLevel}
        ) = state0
      ) do
    log_alert(
      logLevel,
      role,
      connection.protocol_name(),
      stateName,
      r_alert(alert, role: opposite_role(role))
    )

    :gen_statem.reply(
      from,
      {:error, :renegotiation_rejected}
    )

    state = connection.reinit_handshake_data(state0)

    connection.next_event(
      :connection,
      :no_record,
      r_state(state, handshake_env: r_handshake_env(hsEnv, renegotiation: :undefined))
    )
  end

  def handle_alert(
        r_alert(level: 1, description: 100) = alert,
        stateName,
        r_state(
          static_env: r_static_env(role: role, protocol_cb: connection),
          handshake_env: r_handshake_env(renegotiation: {true, from}) = hsEnv,
          ssl_options: %{log_level: logLevel}
        ) = state0
      ) do
    log_alert(
      logLevel,
      role,
      connection.protocol_name(),
      stateName,
      r_alert(alert, role: opposite_role(role))
    )

    :gen_statem.reply(
      from,
      {:error, :renegotiation_rejected}
    )

    state =
      connection.reinit(
        r_state(state0, handshake_env: r_handshake_env(hsEnv, renegotiation: :undefined))
      )

    connection.next_event(:connection, :no_record, state)
  end

  def handle_alert(
        r_alert(level: 1, description: 90) = alert,
        stateName,
        r_state(
          static_env: r_static_env(role: role, protocol_cb: connection),
          ssl_options: %{log_level: logLevel}
        ) = state
      )
      when stateName !== :connection do
    log_alert(
      logLevel,
      role,
      connection.protocol_name(),
      stateName,
      r_alert(alert, role: opposite_role(role))
    )

    connection.next_event(stateName, :no_record, state)
  end

  def handle_alert(
        r_alert(level: 1) = alert,
        stateName,
        r_state(
          static_env: r_static_env(role: role, protocol_cb: connection),
          connection_env: r_connection_env(negotiated_version: version),
          ssl_options: %{log_level: logLevel}
        ) = state
      )
      when version < {3, 4} do
    log_alert(
      logLevel,
      role,
      connection.protocol_name(),
      stateName,
      r_alert(alert, role: opposite_role(role))
    )

    connection.next_event(stateName, :no_record, state)
  end

  def handle_alert(alert, stateName, state) do
    handle_fatal_alert(alert, stateName, state)
  end

  defp handle_fatal_alert(
         alert0,
         stateName,
         r_state(
           static_env:
             r_static_env(
               role: role,
               socket: socket,
               host: host,
               port: port,
               trackers: trackers,
               transport_cb: transport,
               protocol_cb: connection
             ),
           connection_env: r_connection_env(user_application: {_Mon, pid}),
           ssl_options: %{log_level: logLevel},
           start_or_recv_from: from,
           session: session,
           socket_options: opts
         ) = state
       ) do
    invalidate_session(role, host, port, session)
    alert = r_alert(alert0, role: opposite_role(role))
    log_alert(logLevel, role, connection.protocol_name(), stateName, alert)
    pids = connection.pids(state)

    alert_user(
      pids,
      transport,
      trackers,
      socket,
      stateName,
      opts,
      pid,
      from,
      alert,
      role,
      stateName,
      connection
    )

    {:stop, {:shutdown, :normal}, state}
  end

  def handle_trusted_certs_db(r_state(ssl_options: %{cacerts: []} = opts))
      when not :erlang.is_map_key(
             :cacertfile,
             opts
           ) do
    :ok
  end

  def handle_trusted_certs_db(
        r_state(
          static_env:
            r_static_env(
              cert_db_ref: ref,
              cert_db: certDb
            ),
          ssl_options: opts
        )
      )
      when certDb !== :undefined and
             not :erlang.is_map_key(:cacertfile, opts) do
    :ssl_pkix_db.remove_trusted_certs(ref, certDb)
  end

  def handle_trusted_certs_db(r_state(static_env: r_static_env(file_ref_db: :undefined))) do
    :ok
  end

  def handle_trusted_certs_db(
        r_state(
          static_env:
            r_static_env(
              cert_db_ref: ref,
              file_ref_db: refDb
            ),
          ssl_options: %{cacertfile: file}
        )
      ) do
    case :ssl_pkix_db.ref_count(ref, refDb, -1) do
      0 ->
        :ssl_manager.clean_cert_db(ref, file)

      _ ->
        :ok
    end
  end

  def maybe_invalidate_session({3, 4}, _, _, _, _, _) do
    :ok
  end

  def maybe_invalidate_session(version, type, role, host, port, session)
      when version < {3, 4} do
    maybe_invalidate_session(type, role, host, port, session)
  end

  def maybe_invalidate_session({false, :first}, :server = role, host, port, session) do
    invalidate_session(role, host, port, session)
  end

  def maybe_invalidate_session(_, _, _, _, _) do
    :ok
  end

  def terminate({:shutdown, :ktls}, :connection, state) do
    handle_trusted_certs_db(state)
  end

  def terminate({:shutdown, :downgrade}, :downgrade, state) do
    handle_trusted_certs_db(state)
  end

  def terminate(_, _, r_state(connection_env: r_connection_env(socket_terminated: true))) do
    :ok
  end

  def terminate(
        {:shutdown, :transport_closed} = reason,
        _StateName,
        r_state(
          static_env:
            r_static_env(protocol_cb: connection, socket: socket, transport_cb: transport)
        ) = state
      ) do
    handle_trusted_certs_db(state)
    connection.close(reason, socket, transport, :undefined)
  end

  def terminate(
        {:shutdown, :own_alert},
        _StateName,
        r_state(
          static_env:
            r_static_env(protocol_cb: connection, socket: socket, transport_cb: transport)
        ) = state
      ) do
    handle_trusted_certs_db(state)

    case :application.get_env(:ssl, :alert_timeout) do
      {:ok, timeout} when is_integer(timeout) ->
        connection.close({:timeout, timeout}, socket, transport, :undefined)

      _ ->
        connection.close({:timeout, 5000}, socket, transport, :undefined)
    end
  end

  def terminate(
        reason,
        :connection,
        r_state(
          static_env:
            r_static_env(protocol_cb: connection, transport_cb: transport, socket: socket),
          connection_states: connectionStates
        ) = state
      ) do
    handle_trusted_certs_db(state)
    alert = terminate_alert(reason)

    try do
      connection.send_alert_in_connection(alert, state)
    catch
      :error, e -> {:EXIT, {e, __STACKTRACE__}}
      :exit, e -> {:EXIT, e}
      e -> e
    end

    connection.close({:timeout, 5000}, socket, transport, connectionStates)
  end

  def terminate(
        reason,
        _StateName,
        r_state(
          static_env:
            r_static_env(
              transport_cb: transport,
              protocol_cb: connection,
              socket: socket
            )
        ) = state
      ) do
    handle_trusted_certs_db(state)
    connection.close(reason, socket, transport, :undefined)
  end

  def format_status(:normal, [_, stateName, state]) do
    [{:data, [{~c"State", {stateName, state}}]}]
  end

  def format_status(:terminate, [_, stateName, state]) do
    sslOptions = r_state(state, :ssl_options)

    newOptions =
      Map.merge(sslOptions, %{
        certs_keys: ~c"***",
        cacerts: ~c"***",
        dh: ~c"***",
        psk_identity: ~c"***",
        srp_identity: ~c"***"
      })

    [
      {:data,
       [
         {~c"State",
          {stateName,
           r_state(state,
             connection_states: ~c"***",
             protocol_buffers: ~c"***",
             user_data_buffer: ~c"***",
             handshake_env: ~c"***",
             connection_env: ~c"***",
             session: ~c"***",
             ssl_options: newOptions,
             flight_buffer: ~c"***"
           )}}
       ]}
    ]
  end

  defp next_statem_state([version], :client) do
    case :ssl.tls_version(version) do
      {3, 4} ->
        :wait_sh

      _ ->
        :hello
    end
  end

  defp next_statem_state([version], :server) do
    case :ssl.tls_version(version) do
      {3, 4} ->
        :start

      _ ->
        :hello
    end
  end

  defp next_statem_state(_, _) do
    :hello
  end

  def call(fsmPid, event) do
    try do
      :gen_statem.call(fsmPid, event)
    catch
      :exit, {:noproc, _} ->
        {:error, :closed}

      :exit, {:normal, _} ->
        {:error, :closed}

      :exit, {:shutdown, _} ->
        {:error, :closed}

      :exit, {{:shutdown, _}, _} ->
        {:error, :closed}
    end
  end

  defp check_hostname(~c"") do
    r_alert(
      level: 2,
      description: 112,
      where: %{
        mfa: {:ssl_gen_statem, :check_hostname, 1},
        line: 1332,
        file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
      },
      reason: :empty_sni
    )
  end

  defp check_hostname(hostname) do
    case :lists.reverse(hostname) do
      [?. | _] ->
        r_alert(
          level: 2,
          description: 112,
          where: %{
            mfa: {:ssl_gen_statem, :check_hostname, 1},
            line: 1336,
            file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
          },
          reason: {:sni_included_trailing_dot, hostname}
        )

      _ ->
        :ok
    end
  end

  defp handle_sni_hostname(
         hostname,
         r_state(
           static_env: initStatEnv0,
           handshake_env: hsEnv,
           connection_env: cEnv,
           ssl_options: opts
         ) = state0
       ) do
    case update_ssl_options_from_sni(opts, hostname) do
      :undefined ->
        r_state(state0, handshake_env: r_handshake_env(hsEnv, sni_hostname: hostname))

      newOptions ->
        {:ok,
         %{
           cert_db_ref: ref,
           cert_db_handle: certDbHandle,
           fileref_db_handle: fileRefHandle,
           session_cache: cacheHandle,
           crl_db_info: cRLDbHandle,
           cert_key_alts: certKeyAlts,
           dh_params: dHParams
         }} =
          :ssl_config.init(
            newOptions,
            :server
          )

        r_state(state0,
          static_env:
            r_static_env(initStatEnv0,
              file_ref_db: fileRefHandle,
              cert_db_ref: ref,
              cert_db: certDbHandle,
              crl_db: cRLDbHandle,
              session_cache: cacheHandle
            ),
          connection_env: r_connection_env(cEnv, cert_key_alts: certKeyAlts),
          ssl_options: newOptions,
          handshake_env:
            r_handshake_env(hsEnv,
              sni_hostname: hostname,
              sni_guided_cert_selection: true,
              diffie_hellman_params: dHParams
            )
        )
    end
  end

  defp update_ssl_options_from_sni(
         %{sni_fun: sNIFun} = origSSLOptions,
         sNIHostname
       ) do
    case sNIFun.(sNIHostname) do
      :undefined ->
        :undefined

      sSLOptions ->
        versionsOpt = :proplists.get_value(:versions, sSLOptions, [])

        fallBackOptions =
          filter_for_versions(
            versionsOpt,
            origSSLOptions
          )

        :ssl.update_options(sSLOptions, :server, fallBackOptions)
    end
  end

  defp filter_for_versions([], origSSLOptions) do
    origSSLOptions
  end

  defp filter_for_versions([:"tlsv1.3"], origSSLOptions) do
    opts =
      [
        :client_renegotiation,
        :dh_file,
        :eccs,
        :fallback,
        :secure_renegotiate,
        :psk_identity,
        :reuse_session,
        :reuse_sessions,
        :srp_identity,
        :user_lookup_fun
      ] ++ [:padding_check, :beast_mitigation]

    :maps.without(opts, origSSLOptions)
  end

  defp filter_for_versions([:"tlsv1.3", :"tlsv1.2" | rest], origSSLOptions) do
    maybe_exclude_tlsv1(rest, origSSLOptions)
  end

  defp filter_for_versions([:"tlsv1.2"], origSSLOptions) do
    opts =
      [
        :anti_replay,
        :certificate_authorities,
        :cookie,
        :early_data,
        :key_update_at,
        :middlebox_comp_mode,
        :session_tickets,
        :supported_groups,
        :use_ticket
      ] ++ [:padding_check, :beast_mitigation]

    :maps.without(opts, origSSLOptions)
  end

  defp filter_for_versions([:"tlsv1.2" | rest], origSSLOptions) do
    opts = [
      :anti_replay,
      :certificate_authorities,
      :cookie,
      :early_data,
      :key_update_at,
      :middlebox_comp_mode,
      :session_tickets,
      :supported_groups,
      :use_ticket
    ]

    maybe_exclude_tlsv1(
      rest,
      :maps.without(opts, origSSLOptions)
    )
  end

  defp filter_for_versions([:"tlsv1.1"], origSSLOptions) do
    opts =
      [
        :anti_replay,
        :certificate_authorities,
        :cookie,
        :early_data,
        :key_update_at,
        :middlebox_comp_mode,
        :session_tickets,
        :supported_groups,
        :use_ticket
      ] ++ [:signature_algs, :signature_algs_cert] ++ [:padding_check, :beast_mitigation]

    :maps.without(opts, origSSLOptions)
  end

  defp filter_for_versions([:"tlsv1.1" | rest], origSSLOptions) do
    opts =
      [
        :anti_replay,
        :certificate_authorities,
        :cookie,
        :early_data,
        :key_update_at,
        :middlebox_comp_mode,
        :session_tickets,
        :supported_groups,
        :use_ticket
      ] ++ [:signature_algs, :signature_algs_cert]

    maybe_exclude_tlsv1(
      rest,
      :maps.without(opts, origSSLOptions)
    )
  end

  defp filter_for_versions([:tlsv1], origSSLOptions) do
    origSSLOptions
  end

  defp maybe_exclude_tlsv1(versions, options) do
    case :lists.member(:tlsv1, versions) do
      false ->
        opts = [:padding_check, :beast_mitigation]
        :maps.without(opts, options)

      true ->
        options
    end
  end

  defp ack_connection(
         r_state(handshake_env: r_handshake_env(renegotiation: {true, initiater}) = hsEnv) = state
       )
       when initiater == :peer or initiater == :internal do
    r_state(state, handshake_env: r_handshake_env(hsEnv, renegotiation: :undefined))
  end

  defp ack_connection(
         r_state(handshake_env: r_handshake_env(renegotiation: {true, from}) = hsEnv) = state
       ) do
    :gen_statem.reply(from, :ok)
    r_state(state, handshake_env: r_handshake_env(hsEnv, renegotiation: :undefined))
  end

  defp ack_connection(
         r_state(
           handshake_env: r_handshake_env(renegotiation: {false, :first}) = hsEnv,
           start_or_recv_from: startFrom
         ) = state
       )
       when startFrom !== :undefined do
    :gen_statem.reply(startFrom, :connected)

    r_state(state,
      handshake_env: r_handshake_env(hsEnv, renegotiation: :undefined),
      start_or_recv_from: :undefined
    )
  end

  defp ack_connection(state) do
    state
  end

  defp no_records(extensions) do
    :maps.map(
      fn _, value ->
        :ssl_handshake.extension_value(value)
      end,
      extensions
    )
  end

  defp handle_active_option(false, :connection = stateName, to, reply, state) do
    hibernate_after(stateName, state, [{:reply, to, reply}])
  end

  defp handle_active_option(
         _,
         :connection = stateName,
         to,
         reply,
         r_state(
           static_env: r_static_env(role: role),
           connection_env: r_connection_env(socket_tls_closed: true),
           user_data_buffer: {_, 0, _}
         ) = state
       ) do
    alert =
      r_alert(
        level: 2,
        description: 0,
        where: %{
          mfa: {:ssl_gen_statem, :handle_active_option, 5},
          line: 1444,
          file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
        },
        reason: :all_data_delivered
      )

    handle_normal_shutdown(r_alert(alert, role: role), stateName, state)
    {:stop_and_reply, {:shutdown, :peer_close}, [{:reply, to, reply}]}
  end

  defp handle_active_option(
         _,
         :connection = stateName0,
         to,
         reply,
         r_state(
           static_env: r_static_env(protocol_cb: connection),
           user_data_buffer: {_, 0, _}
         ) = state0
       ) do
    case connection.next_event(stateName0, :no_record, state0) do
      {:next_state, stateName, state} ->
        hibernate_after(stateName, state, [{:reply, to, reply}])

      {:next_state, stateName, state, actions} ->
        hibernate_after(stateName, state, [{:reply, to, reply} | actions])

      {:stop, _, _} = stop ->
        stop
    end
  end

  defp handle_active_option(_, stateName, to, reply, r_state(user_data_buffer: {_, 0, _}) = state) do
    {:next_state, stateName, state, [{:reply, to, reply}]}
  end

  defp handle_active_option(
         _,
         stateName0,
         to,
         reply,
         r_state(static_env: r_static_env(protocol_cb: connection)) = state0
       ) do
    case read_application_data(<<>>, state0) do
      {:stop, _, _} = stop ->
        stop

      {record, state1} ->
        case connection.next_event(stateName0, record, state1) do
          {:next_state, stateName, state} ->
            hibernate_after(stateName, state, [{:reply, to, reply}])

          {:next_state, stateName, state, actions} ->
            hibernate_after(stateName, state, [{:reply, to, reply} | actions])

          {:stop, _, _} = stop ->
            stop
        end
    end
  end

  defp read_application_data(
         r_state(
           socket_options: socketOpts,
           bytes_to_read: bytesToRead,
           start_or_recv_from: recvFrom
         ) = state,
         front,
         bufferSize,
         rear
       ) do
    read_application_data(state, front, bufferSize, rear, socketOpts, recvFrom, bytesToRead)
  end

  defp read_application_data(
         state,
         [bin | front],
         bufferSize,
         rear,
         socketOpts,
         recvFrom,
         bytesToRead
       ) do
    read_application_data_bin(
      state,
      front,
      bufferSize,
      rear,
      socketOpts,
      recvFrom,
      bytesToRead,
      bin
    )
  end

  defp read_application_data(
         state,
         [] = front,
         bufferSize,
         [] = rear,
         socketOpts,
         recvFrom,
         bytesToRead
       ) do
    0 = bufferSize

    {:no_record,
     r_state(state,
       socket_options: socketOpts,
       bytes_to_read: bytesToRead,
       start_or_recv_from: recvFrom,
       user_data_buffer: {front, bufferSize, rear}
     )}
  end

  defp read_application_data(state, [], bufferSize, rear, socketOpts, recvFrom, bytesToRead) do
    [bin | front] = :lists.reverse(rear)

    read_application_data_bin(
      state,
      front,
      bufferSize,
      [],
      socketOpts,
      recvFrom,
      bytesToRead,
      bin
    )
  end

  defp read_application_data_bin(
         state,
         front,
         bufferSize,
         rear,
         socketOpts,
         recvFrom,
         bytesToRead,
         <<>>
       ) do
    read_application_data(state, front, bufferSize, rear, socketOpts, recvFrom, bytesToRead)
  end

  defp read_application_data_bin(
         state,
         front0,
         bufferSize0,
         rear0,
         socketOpts0,
         recvFrom,
         bytesToRead,
         bin0
       ) do
    case get_data(socketOpts0, bytesToRead, bin0) do
      {:ok, data, bin} ->
        bufferSize = bufferSize0 - (byte_size(bin0) - byte_size(bin))

        read_application_data_deliver(
          state,
          [bin | front0],
          bufferSize,
          rear0,
          socketOpts0,
          recvFrom,
          data
        )

      {:more, :undefined} ->
        cond do
          byte_size(bin0) < bufferSize0 ->
            bin =
              :erlang.iolist_to_binary([
                bin0,
                front0
                | :lists.reverse(rear0)
              ])

            read_application_data_bin(
              state,
              [],
              bufferSize0,
              [],
              socketOpts0,
              recvFrom,
              bytesToRead,
              bin
            )

          true ->
            {:no_record,
             r_state(state,
               socket_options: socketOpts0,
               bytes_to_read: bytesToRead,
               start_or_recv_from: recvFrom,
               user_data_buffer: {[bin0 | front0], bufferSize0, rear0}
             )}
        end

      {:more, size} when size <= bufferSize0 ->
        {data, front, rear} = iovec_from_front(size - byte_size(bin0), front0, rear0, [bin0])
        bin = :erlang.iolist_to_binary(data)

        read_application_data_bin(
          state,
          front,
          bufferSize0,
          rear,
          socketOpts0,
          recvFrom,
          bytesToRead,
          bin
        )

      {:more, _Size} ->
        {:no_record,
         r_state(state,
           socket_options: socketOpts0,
           bytes_to_read: bytesToRead,
           start_or_recv_from: recvFrom,
           user_data_buffer: {[bin0 | front0], bufferSize0, rear0}
         )}

      :passive ->
        {:no_record,
         r_state(state,
           socket_options: socketOpts0,
           bytes_to_read: bytesToRead,
           start_or_recv_from: recvFrom,
           user_data_buffer: {[bin0 | front0], bufferSize0, rear0}
         )}

      {:error, _Reason} ->
        r_state(
          static_env:
            r_static_env(
              socket: socket,
              protocol_cb: connection,
              transport_cb: transport,
              trackers: trackers
            ),
          connection_env: r_connection_env(user_application: {_Mon, pid})
        ) = state

        buffer =
          :erlang.iolist_to_binary([
            bin0,
            front0
            | :lists.reverse(rear0)
          ])

        deliver_packet_error(
          connection.pids(state),
          transport,
          socket,
          socketOpts0,
          buffer,
          pid,
          recvFrom,
          trackers,
          connection
        )

        {:stop, {:shutdown, :normal},
         r_state(state,
           socket_options: socketOpts0,
           bytes_to_read: bytesToRead,
           start_or_recv_from: recvFrom,
           user_data_buffer: {[buffer], bufferSize0, []}
         )}
    end
  end

  defp read_application_data_deliver(state, front, bufferSize, rear, socketOpts0, recvFrom, data) do
    r_state(
      static_env:
        r_static_env(
          socket: socket,
          protocol_cb: connection,
          transport_cb: transport,
          trackers: trackers
        ),
      connection_env: r_connection_env(user_application: {_Mon, pid})
    ) = state

    socketOpts =
      deliver_app_data(
        connection.pids(state),
        transport,
        socket,
        socketOpts0,
        data,
        pid,
        recvFrom,
        trackers,
        connection
      )

    cond do
      r_socket_options(socketOpts, :active) === false ->
        {:no_record,
         r_state(state,
           user_data_buffer: {front, bufferSize, rear},
           start_or_recv_from: :undefined,
           bytes_to_read: :undefined,
           socket_options: socketOpts
         )}

      true ->
        case r_handshake_env(r_state(state, :handshake_env), :early_data_accepted) do
          false ->
            read_application_data(
              state,
              front,
              bufferSize,
              rear,
              socketOpts,
              :undefined,
              :undefined
            )

          true ->
            read_application_data(
              state,
              front,
              bufferSize,
              rear,
              socketOpts,
              recvFrom,
              :undefined
            )
        end
    end
  end

  defp read_application_dist_data(dHandle, [bin | front], bufferSize, rear) do
    read_application_dist_data(dHandle, front, bufferSize, rear, bin)
  end

  defp read_application_dist_data(_DHandle, [] = front, bufferSize, [] = rear) do
    ^bufferSize = 0
    {front, bufferSize, rear}
  end

  defp read_application_dist_data(dHandle, [], bufferSize, rear) do
    [bin | front] = :lists.reverse(rear)
    read_application_dist_data(dHandle, front, bufferSize, [], bin)
  end

  defp read_application_dist_data(dHandle, front0, bufferSize, rear0, bin0) do
    case bin0 do
      <<sizeA::size(32), dataA::size(sizeA)-binary, sizeB::size(32), dataB::size(sizeB)-binary,
        sizeC::size(32), dataC::size(sizeC)-binary, sizeD::size(32), dataD::size(sizeD)-binary,
        rest::binary>>
      when 0 < sizeA and 0 < sizeB and 0 < sizeC and
             0 < sizeD ->
        :erlang.dist_ctrl_put_data(dHandle, dataA)
        :erlang.dist_ctrl_put_data(dHandle, dataB)
        :erlang.dist_ctrl_put_data(dHandle, dataC)
        :erlang.dist_ctrl_put_data(dHandle, dataD)

        read_application_dist_data(
          dHandle,
          front0,
          bufferSize - (4 * 4 + sizeA + sizeB + sizeC + sizeD),
          rear0,
          rest
        )

      <<sizeA::size(32), dataA::size(sizeA)-binary, sizeB::size(32), dataB::size(sizeB)-binary,
        sizeC::size(32), dataC::size(sizeC)-binary, rest::binary>>
      when 0 < sizeA and 0 < sizeB and 0 < sizeC ->
        :erlang.dist_ctrl_put_data(dHandle, dataA)
        :erlang.dist_ctrl_put_data(dHandle, dataB)
        :erlang.dist_ctrl_put_data(dHandle, dataC)

        read_application_dist_data(
          dHandle,
          front0,
          bufferSize - (3 * 4 + sizeA + sizeB + sizeC),
          rear0,
          rest
        )

      <<sizeA::size(32), dataA::size(sizeA)-binary, sizeB::size(32), dataB::size(sizeB)-binary,
        rest::binary>>
      when 0 < sizeA and 0 < sizeB ->
        :erlang.dist_ctrl_put_data(dHandle, dataA)
        :erlang.dist_ctrl_put_data(dHandle, dataB)

        read_application_dist_data(
          dHandle,
          front0,
          bufferSize - (2 * 4 + sizeA + sizeB),
          rear0,
          rest
        )

      <<size::size(32), data::size(size)-binary, rest::binary>> ->
        0 < size and :erlang.dist_ctrl_put_data(dHandle, data)
        read_application_dist_data(dHandle, front0, bufferSize - (4 + size), rear0, rest)

      <<size::size(32), firstData::binary>>
      when 4 + size <= bufferSize ->
        {data, front, rear} =
          iovec_from_front(size - byte_size(firstData), front0, rear0, [firstData])

        0 < size and :erlang.dist_ctrl_put_data(dHandle, data)
        read_application_dist_data(dHandle, front, bufferSize - (4 + size), rear)

      <<bin::binary>> ->
        case bin do
          <<_Size::size(32), _InsufficientData::binary>> ->
            {[bin | front0], bufferSize, rear0}

          <<incompleteLengthField::binary>> when 4 < bufferSize ->
            {lengthField, front, rear} =
              case incompleteLengthField do
                <<>> ->
                  iovec_from_front(4, front0, rear0, [])

                _ ->
                  iovec_from_front(4 - byte_size(incompleteLengthField), front0, rear0, [
                    incompleteLengthField
                  ])
              end

            lengthBin = :erlang.iolist_to_binary(lengthField)
            read_application_dist_data(dHandle, front, bufferSize, rear, lengthBin)

          <<incompleteLengthField::binary>> ->
            case incompleteLengthField do
              <<>> ->
                {front0, bufferSize, rear0}

              _ ->
                {[incompleteLengthField | front0], bufferSize, rear0}
            end
        end
    end
  end

  defp iovec_from_front(0, front, rear, acc) do
    {:lists.reverse(acc), front, rear}
  end

  defp iovec_from_front(size, [], rear, acc) do
    case rear do
      [_] ->
        iovec_from_front(size, rear, [], acc)

      [bin2, bin1] ->
        iovec_from_front(size, [bin1, bin2], [], acc)

      [bin3, bin2, bin1] ->
        iovec_from_front(size, [bin1, bin2, bin3], [], acc)

      [_, _, _ | _] = ^rear ->
        iovec_from_front(size, :lists.reverse(rear), [], acc)
    end
  end

  defp iovec_from_front(size, [bin | front], rear, []) do
    case bin do
      <<last::size(size)-binary>> ->
        {[last], front, rear}

      <<last::size(size)-binary, rest::binary>> ->
        {[last], [rest | front], rear}

      <<>> ->
        iovec_from_front(size, front, rear, [])

      <<_::binary>> ->
        binSize = byte_size(bin)
        iovec_from_front(size - binSize, front, rear, [bin])
    end
  end

  defp iovec_from_front(size, [bin | front], rear, acc) do
    case bin do
      <<last::size(size)-binary>> ->
        {:lists.reverse(acc, [last]), front, rear}

      <<last::size(size)-binary, rest::binary>> ->
        {:lists.reverse(acc, [last]), [rest | front], rear}

      <<>> ->
        iovec_from_front(size, front, rear, acc)

      <<_::binary>> ->
        binSize = byte_size(bin)
        iovec_from_front(size - binSize, front, rear, [bin | acc])
    end
  end

  defp get_data(r_socket_options(active: false), :undefined, _Bin) do
    :passive
  end

  defp get_data(r_socket_options(active: active, packet: raw), bytesToRead, bin)
       when raw === :raw or raw === 0 do
    case bin do
      <<_::binary>>
      when active !== false or bytesToRead === 0 ->
        {:ok, bin, <<>>}

      <<data::size(bytesToRead)-binary, rest::binary>> ->
        {:ok, data, rest}

      <<_::binary>> ->
        {:more, bytesToRead}
    end
  end

  defp get_data(r_socket_options(packet: type, packet_size: size), _, bin) do
    packetOpts = [{:packet_size, size}]
    decode_packet(type, bin, packetOpts)
  end

  defp decode_packet({:http, :headers}, buffer, packetOpts) do
    decode_packet(:httph, buffer, packetOpts)
  end

  defp decode_packet({:http_bin, :headers}, buffer, packetOpts) do
    decode_packet(:httph_bin, buffer, packetOpts)
  end

  defp decode_packet(type, buffer, packetOpts) do
    :erlang.decode_packet(type, buffer, packetOpts)
  end

  defp deliver_app_data(
         cPids,
         transport,
         socket,
         r_socket_options(active: active, packet: type) = sOpts,
         data,
         pid,
         from,
         trackers,
         connection
       ) do
    send_or_reply(
      active,
      pid,
      from,
      format_reply(cPids, transport, socket, sOpts, data, trackers, connection)
    )

    sO =
      case data do
        {p, _, _, _}
        when p === :http_request or
               (p === :http_response and
                  type === :http) or type === :http_bin ->
          r_socket_options(sOpts, packet: {type, :headers})

        :http_eoh when tuple_size(type) === 2 ->
          {type1, :headers} = type
          r_socket_options(sOpts, packet: type1)

        _ ->
          sOpts
      end

    case active do
      :once ->
        r_socket_options(sO, active: false)

      1 ->
        send_user(
          pid,
          format_passive(cPids, transport, socket, trackers, connection)
        )

        r_socket_options(sO, active: false)

      n when is_integer(n) ->
        r_socket_options(sO, active: n - 1)

      _ ->
        sO
    end
  end

  defp format_reply(
         _,
         _,
         _,
         r_socket_options(active: false, mode: mode, packet: packet, header: header),
         data,
         _,
         _
       ) do
    {:ok, do_format_reply(mode, packet, header, data)}
  end

  defp format_reply(
         cPids,
         transport,
         socket,
         r_socket_options(active: _, mode: mode, packet: packet, header: header),
         data,
         trackers,
         connection
       ) do
    {:ssl, connection.socket(cPids, transport, socket, trackers),
     do_format_reply(mode, packet, header, data)}
  end

  defp deliver_packet_error(
         cPids,
         transport,
         socket,
         sO = r_socket_options(active: active),
         data,
         pid,
         from,
         trackers,
         connection
       ) do
    send_or_reply(
      active,
      pid,
      from,
      format_packet_error(cPids, transport, socket, sO, data, trackers, connection)
    )
  end

  defp format_packet_error(_, _, _, r_socket_options(active: false, mode: mode), data, _, _) do
    {:error, {:invalid_packet, do_format_reply(mode, :raw, 0, data)}}
  end

  defp format_packet_error(
         cPids,
         transport,
         socket,
         r_socket_options(active: _, mode: mode),
         data,
         trackers,
         connection
       ) do
    {:ssl_error, connection.socket(cPids, transport, socket, trackers),
     {:invalid_packet, do_format_reply(mode, :raw, 0, data)}}
  end

  defp do_format_reply(:binary, _, n, data) when n > 0 do
    header(n, data)
  end

  defp do_format_reply(:binary, _, _, data) do
    data
  end

  defp do_format_reply(:list, packet, _, data)
       when packet == :http or
              packet == {:http, :headers} or
              packet == :http_bin or
              packet == {:http_bin, :headers} or
              packet == :httph or
              packet == :httph_bin do
    data
  end

  defp do_format_reply(:list, _, _, data) do
    :erlang.binary_to_list(data)
  end

  defp format_passive(cPids, transport, socket, trackers, connection) do
    {:ssl_passive, connection.socket(cPids, transport, socket, trackers)}
  end

  defp header(0, <<>>) do
    <<>>
  end

  defp header(_, <<>>) do
    []
  end

  defp header(0, binary) do
    binary
  end

  defp header(n, binary) do
    <<byteN::size(8)-unsigned-big-integer, newBinary::binary>> = binary
    [byteN | header(n - 1, newBinary)]
  end

  defp send_or_reply(false, _Pid, from, data)
       when from !== :undefined do
    :gen_statem.reply(from, data)
  end

  defp send_or_reply(false, pid, :undefined, _) when is_pid(pid) do
    :ok
  end

  defp send_or_reply(_, :no_pid, _, _) do
    :ok
  end

  defp send_or_reply(_, pid, _, data) do
    send_user(pid, data)
  end

  defp send_user(pid, msg) do
    send(pid, msg)
    :ok
  end

  defp alert_user(
         pids,
         transport,
         trackers,
         socket,
         _,
         opts,
         pid,
         from,
         alert,
         role,
         :connection = stateName,
         connection
       ) do
    alert_user(
      pids,
      transport,
      trackers,
      socket,
      r_socket_options(opts, :active),
      pid,
      from,
      alert,
      role,
      stateName,
      connection
    )
  end

  defp alert_user(
         pids,
         transport,
         trackers,
         socket,
         {true, :internal},
         opts,
         pid,
         from,
         alert,
         role,
         stateName,
         connection
       ) do
    alert_user(
      pids,
      transport,
      trackers,
      socket,
      r_socket_options(opts, :active),
      pid,
      from,
      alert,
      role,
      stateName,
      connection
    )
  end

  defp alert_user(
         pids,
         transport,
         trackers,
         socket,
         _,
         _,
         _,
         from,
         alert,
         role,
         stateName,
         connection
       ) do
    alert_user(pids, transport, trackers, socket, from, alert, role, stateName, connection)
  end

  defp alert_user(pids, transport, trackers, socket, from, alert, role, stateName, connection) do
    alert_user(
      pids,
      transport,
      trackers,
      socket,
      false,
      :no_pid,
      from,
      alert,
      role,
      stateName,
      connection
    )
  end

  defp alert_user(_, _, _, _, false = active, pid, from, alert, role, stateName, connection)
       when from !== :undefined do
    reasonCode = :ssl_alert.reason_code(alert, role, connection.protocol_name(), stateName)
    send_or_reply(active, pid, from, {:error, reasonCode})
  end

  defp alert_user(
         pids,
         transport,
         trackers,
         socket,
         active,
         pid,
         from,
         alert,
         role,
         stateName,
         connection
       ) do
    case :ssl_alert.reason_code(alert, role, connection.protocol_name(), stateName) do
      :closed ->
        send_or_reply(
          active,
          pid,
          from,
          {:ssl_closed, connection.socket(pids, transport, socket, trackers)}
        )

      reasonCode ->
        send_or_reply(
          active,
          pid,
          from,
          {:ssl_error, connection.socket(pids, transport, socket, trackers), reasonCode}
        )
    end
  end

  defp log_alert(level, role, protocolName, stateName, r_alert(role: role) = alert) do
    :ssl_logger.log(
      :notice,
      level,
      %{protocol: protocolName, role: role, statename: stateName, alert: alert, alerter: :own},
      r_alert(alert, :where)
    )
  end

  defp log_alert(level, role, protocolName, stateName, alert) do
    :ssl_logger.log(
      :notice,
      level,
      %{protocol: protocolName, role: role, statename: stateName, alert: alert, alerter: :peer},
      r_alert(alert, :where)
    )
  end

  defp terminate_alert(:normal) do
    r_alert(
      level: 1,
      description: 0,
      where: %{
        mfa: {:ssl_gen_statem, :terminate_alert, 1},
        line: 1892,
        file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
      }
    )
  end

  defp terminate_alert({reason, _})
       when reason == :close or
              reason == :shutdown do
    r_alert(
      level: 1,
      description: 0,
      where: %{
        mfa: {:ssl_gen_statem, :terminate_alert, 1},
        line: 1895,
        file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
      }
    )
  end

  defp terminate_alert(_) do
    r_alert(
      level: 2,
      description: 80,
      where: %{
        mfa: {:ssl_gen_statem, :terminate_alert, 1},
        line: 1897,
        file: ~c"otp/lib/ssl/src/ssl_gen_statem.erl"
      }
    )
  end

  defp invalidate_session(:client, host, port, session) do
    :ssl_manager.invalidate_session(host, port, session)
  end

  defp invalidate_session(:server, _, _, _) do
    :ok
  end

  defp opposite_role(:client) do
    :server
  end

  defp opposite_role(:server) do
    :client
  end

  defp connection_info(
         r_state(
           handshake_env:
             r_handshake_env(
               sni_hostname: sNIHostname,
               resumption: resumption
             ),
           session:
             r_session(
               session_id: sessionId,
               cipher_suite: cipherSuite,
               srp_username: srpUsername,
               ecc: eCCCurve
             ) = session,
           connection_states: %{current_write: currentWrite},
           connection_env: r_connection_env(negotiated_version: {_, _} = version),
           ssl_options: %{protocol: protocol} = opts
         )
       ) do
    recordCB = record_cb(protocol)
    cipherSuiteDef = %{key_exchange: kexAlg} = :ssl_cipher_format.suite_bin_to_map(cipherSuite)

    isNamedCurveSuite =
      :lists.member(
        kexAlg,
        [:ecdh_ecdsa, :ecdhe_ecdsa, :ecdh_rsa, :ecdhe_rsa, :ecdh_anon]
      )

    curveInfo =
      case eCCCurve do
        {:namedCurve, curve} when isNamedCurveSuite ->
          [{:ecc, {:named_curve, :pubkey_cert_records.namedCurves(curve)}}]

        _ ->
          []
      end

    mFLInfo =
      case :maps.get(:max_fragment_length, currentWrite, :undefined) do
        maxFragmentLength when is_integer(maxFragmentLength) ->
          [{:max_fragment_length, maxFragmentLength}]

        _ ->
          []
      end

    [
      {:protocol, recordCB.protocol_version(version)},
      {:session_id, sessionId},
      {:session_data, :erlang.term_to_binary(session)},
      {:session_resumption, resumption},
      {:selected_cipher_suite, cipherSuiteDef},
      {:sni_hostname, sNIHostname},
      {:srp_username, srpUsername}
      | curveInfo
    ] ++ mFLInfo ++ ssl_options_list(opts)
  end

  defp security_info(
         r_state(
           connection_states: connectionStates,
           static_env: r_static_env(role: role),
           ssl_options: opts,
           protocol_specific: protocolSpecific
         )
       ) do
    readState =
      :ssl_record.current_connection_state(
        connectionStates,
        :read
      )

    %{
      security_parameters:
        r_security_parameters(
          client_random: clientRand,
          server_random: serverRand,
          master_secret: masterSecret,
          application_traffic_secret: appTrafSecretRead,
          client_early_data_secret: serverEarlyData
        )
    } = readState

    baseSecurityInfo = [
      {:client_random, clientRand},
      {:server_random, serverRand},
      {:master_secret, masterSecret}
    ]

    keepSecrets = :maps.get(:keep_secrets, opts, false)

    cond do
      keepSecrets !== true ->
        baseSecurityInfo

      true ->
        %{
          security_parameters:
            r_security_parameters(
              application_traffic_secret: appTrafSecretWrite0,
              client_early_data_secret: clientEarlyData
            )
        } =
          :ssl_record.current_connection_state(
            connectionStates,
            :write
          )

        sender = :maps.get(:sender, protocolSpecific, :undefined)
        appTrafSecretWrite = {sender, appTrafSecretWrite0}

        cond do
          role == :server ->
            cond do
              serverEarlyData !== :undefined ->
                [
                  {:server_traffic_secret_0, appTrafSecretWrite},
                  {:client_traffic_secret_0, appTrafSecretRead},
                  {:client_early_data_secret, serverEarlyData}
                ]

              true ->
                [
                  {:server_traffic_secret_0, appTrafSecretWrite},
                  {:client_traffic_secret_0, appTrafSecretRead}
                ]
            end

          true ->
            cond do
              clientEarlyData !== :undefined ->
                [
                  {:client_traffic_secret_0, appTrafSecretWrite},
                  {:server_traffic_secret_0, appTrafSecretRead},
                  {:client_early_data_secret, clientEarlyData}
                ]

              true ->
                [
                  {:client_traffic_secret_0, appTrafSecretWrite},
                  {:server_traffic_secret_0, appTrafSecretRead}
                ]
            end
        end ++
          case readState do
            %{
              client_handshake_traffic_secret: clientHSTrafficSecret,
              server_handshake_traffic_secret: serverHSTrafficSecret
            } ->
              [
                {:client_handshake_traffic_secret, clientHSTrafficSecret},
                {:server_handshake_traffic_secret, serverHSTrafficSecret}
              ]

            _ ->
              []
          end ++ baseSecurityInfo
    end
  end

  defp record_cb(:tls) do
    :tls_record
  end

  defp record_cb(:dtls) do
    :dtls_record
  end

  defp get_socket_opts(_, _, _, [], _, acc) do
    {:ok, acc}
  end

  defp get_socket_opts(connection, transport, socket, [:mode | tags], sockOpts, acc) do
    get_socket_opts(connection, transport, socket, tags, sockOpts, [
      {:mode, r_socket_options(sockOpts, :mode)} | acc
    ])
  end

  defp get_socket_opts(connection, transport, socket, [:packet | tags], sockOpts, acc) do
    case r_socket_options(sockOpts, :packet) do
      {type, :headers} ->
        get_socket_opts(connection, transport, socket, tags, sockOpts, [{:packet, type} | acc])

      type ->
        get_socket_opts(connection, transport, socket, tags, sockOpts, [{:packet, type} | acc])
    end
  end

  defp get_socket_opts(connection, transport, socket, [:header | tags], sockOpts, acc) do
    get_socket_opts(connection, transport, socket, tags, sockOpts, [
      {:header, r_socket_options(sockOpts, :header)} | acc
    ])
  end

  defp get_socket_opts(connection, transport, socket, [:active | tags], sockOpts, acc) do
    get_socket_opts(connection, transport, socket, tags, sockOpts, [
      {:active, r_socket_options(sockOpts, :active)} | acc
    ])
  end

  defp get_socket_opts(connection, transport, socket, [:packet_size | tags], sockOpts, acc) do
    get_socket_opts(connection, transport, socket, tags, sockOpts, [
      {:packet_size, r_socket_options(sockOpts, :packet_size)} | acc
    ])
  end

  defp get_socket_opts(connection, transport, socket, [tag | tags], sockOpts, acc) do
    case connection.getopts(transport, socket, [tag]) do
      {:ok, [opt]} ->
        get_socket_opts(connection, transport, socket, tags, sockOpts, [opt | acc])

      {:ok, []} ->
        get_socket_opts(connection, transport, socket, tags, sockOpts, acc)

      {:error, reason} ->
        {:error, {:options, {:socket_options, tag, reason}}}
    end
  end

  defp get_socket_opts(_, _, _, opts, _, _) do
    {:error, {:options, {:socket_options, opts, :function_clause}}}
  end

  defp set_socket_opts(_, _, _, [], sockOpts, []) do
    {:ok, sockOpts}
  end

  defp set_socket_opts(connectionCb, transport, socket, [], sockOpts, other) do
    try do
      connectionCb.setopts(transport, socket, other)
    catch
      _, error ->
        {{:error, {:options, {:socket_options, other, error}}}, sockOpts}
    else
      :ok ->
        {:ok, sockOpts}

      {:error, inetError} ->
        {{:error, {:options, {:socket_options, other, inetError}}}, sockOpts}
    end
  end

  defp set_socket_opts(connectionCb, transport, socket, [{:mode, mode} | opts], sockOpts, other)
       when mode == :list or mode == :binary do
    set_socket_opts(
      connectionCb,
      transport,
      socket,
      opts,
      r_socket_options(sockOpts, mode: mode),
      other
    )
  end

  defp set_socket_opts(_, _, _, [{:mode, _} = opt | _], sockOpts, _) do
    {{:error, {:options, {:socket_options, opt}}}, sockOpts}
  end

  defp set_socket_opts(
         connectionCb,
         transport,
         socket,
         [{:packet, packet} | opts],
         sockOpts,
         other
       )
       when packet == :raw or packet == 0 or packet == 1 or
              packet == 2 or packet == 4 or packet == :asn1 or
              packet == :cdr or packet == :sunrm or packet == :fcgi or
              packet == :tpkt or packet == :line or packet == :http or
              packet == :httph or packet == :http_bin or
              packet == :httph_bin do
    set_socket_opts(
      connectionCb,
      transport,
      socket,
      opts,
      r_socket_options(sockOpts, packet: packet),
      other
    )
  end

  defp set_socket_opts(_, _, _, [{:packet, _} = opt | _], sockOpts, _) do
    {{:error, {:options, {:socket_options, opt}}}, sockOpts}
  end

  defp set_socket_opts(
         connectionCb,
         transport,
         socket,
         [{:header, header} | opts],
         sockOpts,
         other
       )
       when is_integer(header) do
    set_socket_opts(
      connectionCb,
      transport,
      socket,
      opts,
      r_socket_options(sockOpts, header: header),
      other
    )
  end

  defp set_socket_opts(_, _, _, [{:header, _} = opt | _], sockOpts, _) do
    {{:error, {:options, {:socket_options, opt}}}, sockOpts}
  end

  defp set_socket_opts(
         connectionCb,
         transport,
         socket,
         [{:active, active} | opts],
         sockOpts,
         other
       )
       when active == :once or active == true or
              active == false do
    set_socket_opts(
      connectionCb,
      transport,
      socket,
      opts,
      r_socket_options(sockOpts, active: active),
      other
    )
  end

  defp set_socket_opts(
         connectionCb,
         transport,
         socket,
         [{:active, active1} = opt | opts],
         sockOpts = r_socket_options(active: active0),
         other
       )
       when active1 >= -32768 and active1 <= 32767 do
    active =
      cond do
        is_integer(active0) and active0 + active1 < -32768 ->
          :error

        is_integer(active0) and active0 + active1 <= 0 ->
          false

        is_integer(active0) and active0 + active1 > 32767 ->
          :error

        active1 <= 0 ->
          false

        is_integer(active0) ->
          active0 + active1

        true ->
          active1
      end

    case active do
      :error ->
        {{:error, {:options, {:socket_options, opt}}}, sockOpts}

      _ ->
        set_socket_opts(
          connectionCb,
          transport,
          socket,
          opts,
          r_socket_options(sockOpts, active: active),
          other
        )
    end
  end

  defp set_socket_opts(_, _, _, [{:active, _} = opt | _], sockOpts, _) do
    {{:error, {:options, {:socket_options, opt}}}, sockOpts}
  end

  defp set_socket_opts(
         connectionCb,
         transport,
         socket,
         [{:packet_size, size} | opts],
         sockOpts,
         other
       )
       when is_integer(size) do
    set_socket_opts(
      connectionCb,
      transport,
      socket,
      opts,
      r_socket_options(sockOpts, packet_size: size),
      other
    )
  end

  defp set_socket_opts(_, _, _, [{:packet_size, _} = opt | _], sockOpts, _) do
    {{:error, {:options, {:socket_options, opt}}}, sockOpts}
  end

  defp set_socket_opts(connectionCb, transport, socket, [opt | opts], sockOpts, other) do
    set_socket_opts(connectionCb, transport, socket, opts, sockOpts, [opt | other])
  end

  defp ssl_options_list(sslOptions) do
    l = :maps.to_list(sslOptions)
    ssl_options_list(l, [])
  end

  defp new_emulated([], emOpts) do
    emOpts
  end

  defp new_emulated(newEmOpts, _) do
    newEmOpts
  end

  defp ssl_options_list([], acc) do
    :lists.reverse(acc)
  end

  defp ssl_options_list([{:protocol, _} | t], acc) do
    ssl_options_list(t, acc)
  end

  defp ssl_options_list([{:erl_dist, _} | t], acc) do
    ssl_options_list(t, acc)
  end

  defp ssl_options_list([{:renegotiate_at, _} | t], acc) do
    ssl_options_list(t, acc)
  end

  defp ssl_options_list([{:max_fragment_length, _} | t], acc) do
    ssl_options_list(t, acc)
  end

  defp ssl_options_list([{:ciphers = key, value} | t], acc) do
    ssl_options_list(
      t,
      [
        {key,
         :lists.map(
           fn suite ->
             :ssl_cipher_format.suite_bin_to_map(suite)
           end,
           value
         )}
        | acc
      ]
    )
  end

  defp ssl_options_list([{key, value} | t], acc) do
    ssl_options_list(t, [{key, value} | acc])
  end

  defp maybe_add_keylog(info) do
    maybe_add_keylog(
      :lists.keyfind(:protocol, 1, info),
      info
    )
  end

  defp maybe_add_keylog({_, :"tlsv1.3"}, info) do
    try do
      {:client_random, clientRandomBin} = :lists.keyfind(:client_random, 1, info)

      maybeUpdateTrafficSecret = fn
        {direction, {sender, trafficSecret0}} ->
          trafficSecret =
            case call(
                   sender,
                   :get_application_traffic_secret
                 ) do
              {:ok, senderAppTrafSecretWrite} ->
                senderAppTrafSecretWrite

              _ ->
                trafficSecret0
            end

          {direction, trafficSecret}

        trafficSecret0 ->
          trafficSecret0
      end

      {:client_traffic_secret_0, clientTrafficSecret0Bin} =
        maybeUpdateTrafficSecret.(
          :lists.keyfind(
            :client_traffic_secret_0,
            1,
            info
          )
        )

      {:server_traffic_secret_0, serverTrafficSecret0Bin} =
        maybeUpdateTrafficSecret.(
          :lists.keyfind(
            :server_traffic_secret_0,
            1,
            info
          )
        )

      {:client_handshake_traffic_secret, clientHSecretBin} =
        :lists.keyfind(:client_handshake_traffic_secret, 1, info)

      {:server_handshake_traffic_secret, serverHSecretBin} =
        :lists.keyfind(:server_handshake_traffic_secret, 1, info)

      {:selected_cipher_suite, %{prf: prf}} = :lists.keyfind(:selected_cipher_suite, 1, info)
      clientRandom = :binary.decode_unsigned(clientRandomBin)

      clientTrafficSecret0 =
        keylog_secret(
          clientTrafficSecret0Bin,
          prf
        )

      serverTrafficSecret0 =
        keylog_secret(
          serverTrafficSecret0Bin,
          prf
        )

      clientHSecret = keylog_secret(clientHSecretBin, prf)
      serverHSecret = keylog_secret(serverHSecretBin, prf)

      keylog0 = [
        :io_lib.format(
          ~c"CLIENT_HANDSHAKE_TRAFFIC_SECRET ~64.16.0B ",
          [clientRandom]
        ) ++ clientHSecret,
        :io_lib.format(~c"SERVER_HANDSHAKE_TRAFFIC_SECRET ~64.16.0B ", [clientRandom]) ++
          serverHSecret,
        :io_lib.format(
          ~c"CLIENT_TRAFFIC_SECRET_0 ~64.16.0B ",
          [clientRandom]
        ) ++ clientTrafficSecret0,
        :io_lib.format(
          ~c"SERVER_TRAFFIC_SECRET_0 ~64.16.0B ",
          [clientRandom]
        ) ++ serverTrafficSecret0
      ]

      keylog =
        case :lists.keyfind(:client_early_data_secret, 1, info) do
          {:client_early_data_secret, earlySecret} ->
            clientEarlySecret = keylog_secret(earlySecret, prf)

            [
              :io_lib.format(
                ~c"CLIENT_EARLY_TRAFFIC_SECRET ~64.16.0B ",
                [clientRandom]
              ) ++ clientEarlySecret
              | keylog0
            ]

          _ ->
            keylog0
        end

      info ++ [{:keylog, keylog}]
    catch
      _Cxx, _Exx ->
        info
    end
  end

  defp maybe_add_keylog({_, _}, info) do
    try do
      {:client_random, clientRandomBin} = :lists.keyfind(:client_random, 1, info)
      {:master_secret, masterSecretBin} = :lists.keyfind(:master_secret, 1, info)
      clientRandom = :binary.decode_unsigned(clientRandomBin)
      masterSecret = :binary.decode_unsigned(masterSecretBin)

      keylog = [
        :io_lib.format(
          ~c"CLIENT_RANDOM ~64.16.0B ~96.16.0B",
          [clientRandom, masterSecret]
        )
      ]

      info ++ [{:keylog, keylog}]
    catch
      _Cxx, _Exx ->
        info
    end
  end

  defp maybe_add_keylog(_, info) do
    info
  end

  defp keylog_secret(secretBin, :sha256) do
    :io_lib.format(~c"~64.16.0B", [:binary.decode_unsigned(secretBin)])
  end

  defp keylog_secret(secretBin, :sha384) do
    :io_lib.format(~c"~96.16.0B", [:binary.decode_unsigned(secretBin)])
  end

  defp keylog_secret(secretBin, :sha512) do
    :io_lib.format(~c"~128.16.0B", [:binary.decode_unsigned(secretBin)])
  end

  defp maybe_generate_client_shares(%{
         versions: [{3, 4} | _],
         supported_groups: r_supported_groups(supported_groups: [group | _])
       }) do
    :ssl_cipher.generate_client_shares([group])
  end

  defp maybe_generate_client_shares(_) do
    :undefined
  end

  def handle_trace(
        :api,
        {:call, {:ssl_gen_statem, :connect, [connection | _]}},
        stack0
      ) do
    {:io_lib.format(~c"Connection = ~w", [connection]), stack0}
  end

  def handle_trace(
        :rle,
        {:call, {:ssl_gen_statem, :init, args = [[role | _]]}},
        stack0
      ) do
    {:io_lib.format(~c"(*~w) Args = ~W", [role, args, 3]), [{:role, role} | stack0]}
  end

  def handle_trace(
        :hbn,
        {:call, {:ssl_gen_statem, :hibernate_after, [_StateName = :connection, state, actions]}},
        stack
      ) do
    r_state(ssl_options: %{hibernate_after: hibernateAfter}) = state

    {:io_lib.format(~c"* * * maybe hibernating in ~w ms * * * Actions = ~W ", [
       hibernateAfter,
       actions,
       10
     ]), stack}
  end

  def handle_trace(
        :hbn,
        {:return_from, {:ssl_gen_statem, :hibernate_after, 3}, {cmd, arg, _State, actions}},
        stack
      ) do
    {:io_lib.format(~c"Cmd = ~w Arg = ~w Actions = ~W", [cmd, arg, actions, 10]), stack}
  end

  def handle_trace(
        :hbn,
        {:call, {:ssl_gen_statem, :handle_common_event, [:timeout, :hibernate, :connection | _]}},
        stack
      ) do
    {:io_lib.format(~c"* * * hibernating * * *", []), stack}
  end
end
