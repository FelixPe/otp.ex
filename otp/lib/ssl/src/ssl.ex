defmodule :m_ssl do
  use Bitwise
  import Kernel, except: [send: 2]
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

  Record.defrecord(:r_sslsocket, :sslsocket, fd: nil, pid: nil)

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

  def start() do
    start(:temporary)
  end

  def start(type) do
    case :application.ensure_all_started(:ssl, type) do
      {:ok, _} ->
        :ok

      other ->
        other
    end
  end

  def stop() do
    :application.stop(:ssl)
  end

  def connect(socket, sslOptions) do
    connect(socket, sslOptions, :infinity)
  end

  def connect(socket, sslOptions0, timeout)
      when is_list(sslOptions0) and
             ((is_integer(timeout) and timeout >= 0) or timeout == :infinity) do
    try do
      cbInfo = handle_option_cb_info(sslOptions0, :tls)
      transport = :erlang.element(1, cbInfo)
      {:ok, config} = handle_options(transport, socket, sslOptions0, :client, :undefined)
      :tls_socket.upgrade(socket, config, timeout)
    catch
      _, {:error, reason} ->
        {:error, reason}
    end
  end

  def connect(host, port, options) do
    connect(host, port, options, :infinity)
  end

  def connect(host, port, options, timeout)
      when (is_integer(timeout) and timeout >= 0) or timeout == :infinity do
    try do
      {:ok, config} = handle_options(options, :client, host)

      case r_config(config, :connection_cb) do
        :tls_gen_connection ->
          :tls_socket.connect(host, port, config, timeout)

        :dtls_gen_connection ->
          :dtls_socket.connect(host, port, config, timeout)
      end
    catch
      error ->
        error
    end
  end

  def listen(_Port, []) do
    {:error, :nooptions}
  end

  def listen(port, options0) do
    try do
      {:ok, config} = handle_options(options0, :server, :undefined)
      do_listen(port, config, r_config(config, :connection_cb))
    catch
      error = {:error, _} ->
        error
    end
  end

  def transport_accept(listenSocket) do
    transport_accept(listenSocket, :infinity)
  end

  def transport_accept(
        r_sslsocket(pid: {listenSocket, r_config(connection_cb: connectionCb) = config}),
        timeout
      )
      when (is_integer(timeout) and timeout >= 0) or timeout == :infinity do
    case connectionCb do
      :tls_gen_connection ->
        :tls_socket.accept(listenSocket, config, timeout)

      :dtls_gen_connection ->
        :dtls_socket.accept(listenSocket, config, timeout)
    end
  end

  def handshake(listenSocket) do
    handshake(listenSocket, :infinity)
  end

  def handshake(r_sslsocket() = socket, timeout)
      when (is_integer(timeout) and timeout >= 0) or timeout == :infinity do
    :ssl_gen_statem.handshake(socket, timeout)
  end

  def handshake(listenSocket, sslOptions) do
    handshake(listenSocket, sslOptions, :infinity)
  end

  def handshake(r_sslsocket() = socket, [], timeout)
      when (is_integer(timeout) and timeout >= 0) or timeout == :infinity do
    handshake(socket, timeout)
  end

  def handshake(r_sslsocket(fd: {_, _, _, trackers}) = socket, sslOpts, timeout)
      when (is_integer(timeout) and timeout >= 0) or timeout == :infinity do
    try do
      tracker =
        :proplists.get_value(
          :option_tracker,
          trackers
        )

      {:ok, emOpts, _} = :tls_socket.get_all_opts(tracker)

      :ssl_gen_statem.handshake(
        socket,
        {sslOpts,
         :tls_socket.emulated_socket_options(
           emOpts,
           r_socket_options()
         )},
        timeout
      )
    catch
      error = {:error, _Reason} ->
        error
    end
  end

  def handshake(r_sslsocket(pid: [pid | _], fd: {_, _, _}) = socket, sslOpts, timeout)
      when (is_integer(timeout) and timeout >= 0) or timeout == :infinity do
    try do
      {:ok, emOpts, _} = :dtls_packet_demux.get_all_opts(pid)

      :ssl_gen_statem.handshake(
        socket,
        {sslOpts,
         :tls_socket.emulated_socket_options(
           emOpts,
           r_socket_options()
         )},
        timeout
      )
    catch
      error = {:error, _Reason} ->
        error
    end
  end

  def handshake(socket, sslOptions, timeout)
      when (is_integer(timeout) and timeout >= 0) or timeout == :infinity do
    try do
      cbInfo = handle_option_cb_info(sslOptions, :tls)
      transport = :erlang.element(1, cbInfo)
      connetionCb = connection_cb(sslOptions)

      {:ok, r_config(transport_info: ^cbInfo, ssl: sslOpts, emulated: emOpts)} =
        handle_options(transport, socket, sslOptions, :server, :undefined)

      :ok = :tls_socket.setopts(transport, socket, :tls_socket.internal_inet_values())
      {:ok, port} = :tls_socket.port(transport, socket)

      {:ok, sessionIdHandle} =
        :tls_socket.session_id_tracker(
          :ssl_unknown_listener,
          sslOpts
        )

      :ssl_gen_statem.handshake(
        connetionCb,
        port,
        socket,
        {sslOpts,
         :tls_socket.emulated_socket_options(
           emOpts,
           r_socket_options()
         ), [{:session_id_tracker, sessionIdHandle}]},
        self(),
        cbInfo,
        timeout
      )
    catch
      error = {:error, _Reason} ->
        error
    end
  end

  def handshake_continue(socket, sSLOptions) do
    handshake_continue(socket, sSLOptions, :infinity)
  end

  def handshake_continue(socket, sSLOptions, timeout) do
    :ssl_gen_statem.handshake_continue(socket, sSLOptions, timeout)
  end

  def handshake_cancel(socket) do
    :ssl_gen_statem.handshake_cancel(socket)
  end

  def close(r_sslsocket(pid: [pid | _])) when is_pid(pid) do
    :ssl_gen_statem.close(pid, {:close, 5000})
  end

  def close(r_sslsocket(pid: {:dtls, r_config(dtls_handler: {_, _})}) = dTLSListen) do
    :dtls_socket.close(dTLSListen)
  end

  def close(r_sslsocket(pid: {listenSocket, r_config(transport_info: {transport, _, _, _, _})})) do
    transport.close(listenSocket)
  end

  def close(r_sslsocket(pid: [tLSPid | _]), {pid, timeout} = downGrade)
      when (is_pid(tLSPid) and is_pid(pid) and
              is_integer(timeout) and timeout >= 0) or timeout == :infinity do
    case :ssl_gen_statem.close(
           tLSPid,
           {:close, downGrade}
         ) do
      :ok ->
        {:error, :closed}

      other ->
        other
    end
  end

  def close(r_sslsocket(pid: [tLSPid | _]), timeout)
      when (is_pid(tLSPid) and
              is_integer(timeout) and timeout >= 0) or timeout == :infinity do
    :ssl_gen_statem.close(tLSPid, {:close, timeout})
  end

  def close(
        r_sslsocket(pid: {:dtls, r_config(dtls_handler: {_, _})}) = dTLSListen,
        _
      ) do
    :dtls_socket.close(dTLSListen)
  end

  def close(
        r_sslsocket(pid: {listenSocket, r_config(transport_info: {transport, _, _, _, _})}),
        _
      ) do
    :tls_socket.close(transport, listenSocket)
  end

  def send(r_sslsocket(pid: [pid]), data) when is_pid(pid) do
    :ssl_gen_statem.send(pid, data)
  end

  def send(r_sslsocket(pid: [_, pid]), data) when is_pid(pid) do
    :tls_sender.send_data(
      pid,
      :erlang.iolist_to_iovec(data)
    )
  end

  def send(
        r_sslsocket(pid: {_, r_config(transport_info: {_, :udp, _, _})}),
        _
      ) do
    {:error, :enotconn}
  end

  def send(r_sslsocket(pid: {:dtls, _}), _) do
    {:error, :enotconn}
  end

  def send(
        r_sslsocket(pid: {listenSocket, r_config(transport_info: info)}),
        data
      ) do
    transport = :erlang.element(1, info)
    :tls_socket.send(transport, listenSocket, data)
  end

  def recv(socket, length) do
    recv(socket, length, :infinity)
  end

  def recv(r_sslsocket(pid: [pid | _]), length, timeout)
      when is_pid(pid) and (is_integer(length) and length >= 0) and
             ((is_integer(timeout) and timeout >= 0) or timeout == :infinity) do
    :ssl_gen_statem.recv(pid, length, timeout)
  end

  def recv(r_sslsocket(pid: {:dtls, _}), _, _) do
    {:error, :enotconn}
  end

  def recv(r_sslsocket(pid: {listen, r_config(transport_info: info)}), _, _) do
    transport = :erlang.element(1, info)
    transport.recv(listen, 0)
  end

  def controlling_process(r_sslsocket(pid: [pid | _]), newOwner)
      when is_pid(pid) and is_pid(newOwner) do
    :ssl_gen_statem.new_user(pid, newOwner)
  end

  def controlling_process(r_sslsocket(pid: {:dtls, _}), newOwner)
      when is_pid(newOwner) do
    :ok
  end

  def controlling_process(
        r_sslsocket(pid: {listen, r_config(transport_info: {transport, _, _, _, _})}),
        newOwner
      )
      when is_pid(newOwner) do
    transport.controlling_process(listen, newOwner)
  end

  def connection_information(r_sslsocket(pid: [pid | _])) when is_pid(pid) do
    case :ssl_gen_statem.connection_information(
           pid,
           false
         ) do
      {:ok, info} ->
        {:ok,
         for item = {_Key, value} <- info,
             value !== :undefined do
           item
         end}

      error ->
        error
    end
  end

  def connection_information(r_sslsocket(pid: {_Listen, r_config()})) do
    {:error, :enotconn}
  end

  def connection_information(r_sslsocket(pid: [pid | _]), items) when is_pid(pid) do
    case :ssl_gen_statem.connection_information(
           pid,
           include_security_info(items)
         ) do
      {:ok, info} ->
        {:ok,
         for item = {key, value} <- info, :lists.member(key, items), value !== :undefined do
           item
         end}

      error ->
        error
    end
  end

  def peername(r_sslsocket(pid: [pid | _], fd: {transport, socket, _}))
      when is_pid(pid) do
    :dtls_socket.peername(transport, socket)
  end

  def peername(r_sslsocket(pid: [pid | _], fd: {transport, socket, _, _}))
      when is_pid(pid) do
    :tls_socket.peername(transport, socket)
  end

  def peername(r_sslsocket(pid: {:dtls, r_config(dtls_handler: {_Pid, _})})) do
    :dtls_socket.peername(:dtls, :undefined)
  end

  def peername(
        r_sslsocket(pid: {listenSocket, r_config(transport_info: {transport, _, _, _, _})})
      ) do
    :tls_socket.peername(transport, listenSocket)
  end

  def peername(r_sslsocket(pid: {:dtls, _})) do
    {:error, :enotconn}
  end

  def peercert(r_sslsocket(pid: [pid | _])) when is_pid(pid) do
    case :ssl_gen_statem.peer_certificate(pid) do
      {:ok, :undefined} ->
        {:error, :no_peercert}

      result ->
        result
    end
  end

  def peercert(r_sslsocket(pid: {:dtls, _})) do
    {:error, :enotconn}
  end

  def peercert(r_sslsocket(pid: {_Listen, r_config()})) do
    {:error, :enotconn}
  end

  def negotiated_protocol(r_sslsocket(pid: [pid | _])) when is_pid(pid) do
    :ssl_gen_statem.negotiated_protocol(pid)
  end

  def cipher_suites(description, version)
      when version == :"tlsv1.3" or
             version == :"tlsv1.2" or version == :"tlsv1.1" or
             version == :tlsv1 do
    cipher_suites(
      description,
      :tls_record.protocol_version_name(version)
    )
  end

  def cipher_suites(description, version)
      when version == :"dtlsv1.2" or
             version == :dtlsv1 do
    cipher_suites(
      description,
      :dtls_record.protocol_version_name(version)
    )
  end

  def cipher_suites(description, version) do
    for suite <- supported_suites(description, version) do
      :ssl_cipher_format.suite_bin_to_map(suite)
    end
  end

  def cipher_suites(description, version, stringType)
      when version == :"tlsv1.3" or version == :"tlsv1.2" or version == :"tlsv1.1" or
             version == :tlsv1 do
    cipher_suites(description, :tls_record.protocol_version_name(version), stringType)
  end

  def cipher_suites(description, version, stringType)
      when version == :"dtlsv1.2" or version == :dtlsv1 do
    cipher_suites(description, :dtls_record.protocol_version_name(version), stringType)
  end

  def cipher_suites(description, version, :rfc) do
    for suite <- supported_suites(description, version) do
      :ssl_cipher_format.suite_map_to_str(:ssl_cipher_format.suite_bin_to_map(suite))
    end
  end

  def cipher_suites(description, version, :openssl) do
    for suite <- supported_suites(description, version) do
      :ssl_cipher_format.suite_map_to_openssl_str(:ssl_cipher_format.suite_bin_to_map(suite))
    end
  end

  def filter_cipher_suites(suites, filters0) do
    %{key_exchange_filters: kexF, cipher_filters: cipherF, mac_filters: macF, prf_filters: prfF} =
      :ssl_cipher.crypto_support_filters()

    filters = %{
      key_exchange_filters:
        add_filter(
          :proplists.get_value(
            :key_exchange,
            filters0
          ),
          kexF
        ),
      cipher_filters:
        add_filter(
          :proplists.get_value(:cipher, filters0),
          cipherF
        ),
      mac_filters: add_filter(:proplists.get_value(:mac, filters0), macF),
      prf_filters: add_filter(:proplists.get_value(:prf, filters0), prfF)
    }

    :ssl_cipher.filter_suites(suites, filters)
  end

  def prepend_cipher_suites([first | _] = preferred, suites0)
      when is_map(first) do
    suites = preferred ++ (suites0 -- preferred)
    suites
  end

  def prepend_cipher_suites(filters, suites) do
    preferred = filter_cipher_suites(suites, filters)
    preferred ++ (suites -- preferred)
  end

  def append_cipher_suites([first | _] = deferred, suites0)
      when is_map(first) do
    suites = (suites0 -- deferred) ++ deferred
    suites
  end

  def append_cipher_suites(filters, suites) do
    deferred = filter_cipher_suites(suites, filters)
    (suites -- deferred) ++ deferred
  end

  def signature_algs(:default, :"tlsv1.3") do
    :tls_v1.default_signature_algs([
      :tls_record.protocol_version_name(:"tlsv1.3"),
      :tls_record.protocol_version_name(:"tlsv1.2")
    ])
  end

  def signature_algs(:default, :"tlsv1.2") do
    :tls_v1.default_signature_algs([:tls_record.protocol_version_name(:"tlsv1.2")])
  end

  def signature_algs(:all, :"tlsv1.3") do
    :tls_v1.default_signature_algs([
      :tls_record.protocol_version_name(:"tlsv1.3"),
      :tls_record.protocol_version_name(:"tlsv1.2")
    ]) ++ :tls_v1.legacy_signature_algs_pre_13()
  end

  def signature_algs(:all, :"tlsv1.2") do
    :tls_v1.default_signature_algs([:tls_record.protocol_version_name(:"tlsv1.2")]) ++
      :tls_v1.legacy_signature_algs_pre_13()
  end

  def signature_algs(:exclusive, :"tlsv1.3") do
    :tls_v1.default_signature_algs([:tls_record.protocol_version_name(:"tlsv1.3")])
  end

  def signature_algs(:exclusive, :"tlsv1.2") do
    algs = :tls_v1.default_signature_algs([:tls_record.protocol_version_name(:"tlsv1.2")])
    algs ++ :tls_v1.legacy_signature_algs_pre_13()
  end

  def signature_algs(description, :"dtlsv1.2") do
    signature_algs(description, :"tlsv1.2")
  end

  def signature_algs(description, version)
      when description == :default or description == :all or
             description == :exclusive do
    :erlang.error({:signature_algs_not_supported_in_protocol_version, version})
  end

  def signature_algs(description, version) do
    :erlang.error(:badarg, [description, version])
  end

  def eccs() do
    :tls_v1.ec_curves(:all, :"tlsv1.2")
  end

  def eccs(:dtlsv1) do
    eccs(:"tlsv1.1")
  end

  def eccs(:"dtlsv1.2") do
    eccs(:"tlsv1.2")
  end

  def eccs(version)
      when version == :"tlsv1.2" or version == :"tlsv1.1" or
             version == :tlsv1 do
    :tls_v1.ec_curves(:default, version)
  end

  def eccs(:"tlsv1.3") do
    :erlang.error({:badarg, :not_sup_in, :"tlsv1.3"})
  end

  def eccs(other) do
    :erlang.error({:badarg, other})
  end

  def groups() do
    :tls_v1.groups()
  end

  def groups(:default) do
    :tls_v1.default_groups()
  end

  def getopts(r_sslsocket(pid: [pid | _]), optionTags)
      when is_pid(pid) and is_list(optionTags) do
    :ssl_gen_statem.get_opts(pid, optionTags)
  end

  def getopts(
        r_sslsocket(pid: {:dtls, r_config(transport_info: {transport, _, _, _, _})}) =
          listenSocket,
        optionTags
      )
      when is_list(optionTags) do
    try do
      :dtls_socket.getopts(transport, listenSocket, optionTags)
    catch
      _, error ->
        {:error, {:options, {:socket_options, optionTags, error}}}
    else
      {:ok, _} = result ->
        result

      {:error, inetError} ->
        {:error, {:options, {:socket_options, optionTags, inetError}}}
    end
  end

  def getopts(
        r_sslsocket(pid: {_, r_config(transport_info: {transport, _, _, _, _})}) = listenSocket,
        optionTags
      )
      when is_list(optionTags) do
    try do
      :tls_socket.getopts(transport, listenSocket, optionTags)
    catch
      _, error ->
        {:error, {:options, {:socket_options, optionTags, error}}}
    else
      {:ok, _} = result ->
        result

      {:error, inetError} ->
        {:error, {:options, {:socket_options, optionTags, inetError}}}
    end
  end

  def getopts(r_sslsocket(), optionTags) do
    {:error, {:options, {:socket_options, optionTags}}}
  end

  def setopts(r_sslsocket(pid: [pid, sender]), options0)
      when is_pid(pid) and is_list(options0) do
    try do
      :proplists.expand(
        [{:binary, [{:mode, :binary}]}, {:list, [{:mode, :list}]}],
        options0
      )
    catch
      _, _ ->
        {:error, {:options, {:not_a_proplist, options0}}}
    else
      options ->
        case :proplists.get_value(:packet, options, :undefined) do
          :undefined ->
            :ssl_gen_statem.set_opts(pid, options)

          packetOpt ->
            case :tls_sender.setopts(
                   sender,
                   [{:packet, packetOpt}]
                 ) do
              :ok ->
                :ssl_gen_statem.set_opts(pid, options)

              error ->
                error
            end
        end
    end
  end

  def setopts(r_sslsocket(pid: [pid | _]), options0)
      when is_pid(pid) and is_list(options0) do
    try do
      :proplists.expand(
        [{:binary, [{:mode, :binary}]}, {:list, [{:mode, :list}]}],
        options0
      )
    catch
      _, _ ->
        {:error, {:options, {:not_a_proplist, options0}}}
    else
      options ->
        :ssl_gen_statem.set_opts(pid, options)
    end
  end

  def setopts(
        r_sslsocket(pid: {:dtls, r_config(transport_info: {transport, _, _, _, _})}) =
          listenSocket,
        options
      )
      when is_list(options) do
    try do
      :dtls_socket.setopts(transport, listenSocket, options)
    catch
      _, error ->
        {:error, {:options, {:socket_options, options, error}}}
    else
      :ok ->
        :ok

      {:error, inetError} ->
        {:error, {:options, {:socket_options, options, inetError}}}
    end
  end

  def setopts(
        r_sslsocket(pid: {_, r_config(transport_info: {transport, _, _, _, _})}) = listenSocket,
        options
      )
      when is_list(options) do
    try do
      :tls_socket.setopts(transport, listenSocket, options)
    catch
      _, error ->
        {:error, {:options, {:socket_options, options, error}}}
    else
      :ok ->
        :ok

      {:error, inetError} ->
        {:error, {:options, {:socket_options, options, inetError}}}
    end
  end

  def setopts(r_sslsocket(), options) do
    {:error, {:options, {:not_a_proplist, options}}}
  end

  def getstat(socket) do
    getstat(socket, :inet.stats())
  end

  def getstat(
        r_sslsocket(pid: {:dtls, r_config(transport_info: info, dtls_handler: {listener, _})}),
        options
      )
      when is_list(options) do
    transport = :erlang.element(1, info)
    :dtls_socket.getstat(transport, listener, options)
  end

  def getstat(
        r_sslsocket(pid: {listen, r_config(transport_info: info)}),
        options
      )
      when is_list(options) do
    transport = :erlang.element(1, info)
    :tls_socket.getstat(transport, listen, options)
  end

  def getstat(
        r_sslsocket(pid: [pid | _], fd: {transport, socket, _, _}),
        options
      )
      when is_pid(pid) and is_list(options) do
    :tls_socket.getstat(transport, socket, options)
  end

  def getstat(
        r_sslsocket(pid: [pid | _], fd: {transport, socket, _}),
        options
      )
      when is_pid(pid) and is_list(options) do
    :dtls_socket.getstat(transport, socket, options)
  end

  def shutdown(r_sslsocket(pid: {:dtls, r_config(transport_info: info)}), _) do
    transport = :erlang.element(1, info)

    case transport do
      :gen_udp ->
        {:error, :notsup}

      :gen_sctp ->
        {:error, :notsup}

      _ ->
        {:error, :enotconn}
    end
  end

  def shutdown(
        r_sslsocket(pid: {listen, r_config(transport_info: info)}),
        how
      ) do
    transport = :erlang.element(1, info)
    transport.shutdown(listen, how)
  end

  def shutdown(r_sslsocket(pid: [pid | _]), how) when is_pid(pid) do
    :ssl_gen_statem.shutdown(pid, how)
  end

  def sockname(r_sslsocket(pid: {:dtls, r_config(dtls_handler: {pid, _})})) do
    :dtls_packet_demux.sockname(pid)
  end

  def sockname(r_sslsocket(pid: {listen, r_config(transport_info: info)})) do
    transport = :erlang.element(1, info)
    :tls_socket.sockname(transport, listen)
  end

  def sockname(r_sslsocket(pid: [pid | _], fd: {transport, socket, _}))
      when is_pid(pid) do
    :dtls_socket.sockname(transport, socket)
  end

  def sockname(r_sslsocket(pid: [pid | _], fd: {transport, socket, _, _}))
      when is_pid(pid) do
    :tls_socket.sockname(transport, socket)
  end

  def versions() do
    confTLSVsns = :tls_record.supported_protocol_versions()
    confDTLSVsns = :dtls_record.supported_protocol_versions()
    implementedTLSVsns = [:"tlsv1.3", :"tlsv1.2", :"tlsv1.1", :tlsv1]
    implementedDTLSVsns = [:"dtlsv1.2", :dtlsv1]

    tLSCryptoSupported = fn vsn ->
      :tls_record.sufficient_crypto_support(vsn)
    end

    dTLSCryptoSupported = fn vsn ->
      :tls_record.sufficient_crypto_support(:dtls_v1.corresponding_tls_version(vsn))
    end

    supportedTLSVsns =
      for vsn <- confTLSVsns,
          tLSCryptoSupported.(vsn) do
        :tls_record.protocol_version(vsn)
      end

    supportedDTLSVsns =
      for vsn <- confDTLSVsns,
          dTLSCryptoSupported.(vsn) do
        :dtls_record.protocol_version(vsn)
      end

    availableTLSVsns =
      for vsn <- implementedTLSVsns,
          tLSCryptoSupported.(:tls_record.protocol_version_name(vsn)) do
        vsn
      end

    availableDTLSVsns =
      for vsn <- implementedDTLSVsns,
          dTLSCryptoSupported.(:dtls_record.protocol_version_name(vsn)) do
        vsn
      end

    [
      {:ssl_app, :EFE_TODO_VSN_MACRO},
      {:supported, supportedTLSVsns},
      {:supported_dtls, supportedDTLSVsns},
      {:available, availableTLSVsns},
      {:available_dtls, availableDTLSVsns},
      {:implemented, implementedTLSVsns},
      {:implemented_dtls, implementedDTLSVsns}
    ]
  end

  def renegotiate(r_sslsocket(pid: [pid, sender | _]) = socket)
      when is_pid(pid) and is_pid(sender) do
    case :ssl.connection_information(
           socket,
           [:protocol]
         ) do
      {:ok, [{:protocol, :"tlsv1.3"}]} ->
        {:error, :notsup}

      _ ->
        case :tls_sender.renegotiate(sender) do
          {:ok, write} ->
            :tls_dtls_connection.renegotiation(pid, write)

          error ->
            error
        end
    end
  end

  def renegotiate(r_sslsocket(pid: [pid | _])) when is_pid(pid) do
    :tls_dtls_connection.renegotiation(pid)
  end

  def renegotiate(r_sslsocket(pid: {:dtls, _})) do
    {:error, :enotconn}
  end

  def renegotiate(r_sslsocket(pid: {_Listen, r_config()})) do
    {:error, :enotconn}
  end

  def update_keys(r_sslsocket(pid: [pid, sender | _]), type0)
      when is_pid(pid) and is_pid(sender) and (type0 === :write or type0 === :read_write) do
    type =
      case type0 do
        :write ->
          :update_not_requested

        :read_write ->
          :update_requested
      end

    :tls_gen_connection_1_3.send_key_update(sender, type)
  end

  def update_keys(_, type) do
    {:error, {:illegal_parameter, type}}
  end

  def export_key_materials(r_sslsocket(pid: [pid | _]), labels, contexts, wantedLengths)
      when is_pid(pid) do
    :ssl_gen_statem.call(
      pid,
      {:export_key_materials, labels, contexts, wantedLengths, true}
    )
  end

  def export_key_materials(r_sslsocket(pid: {_Listen, r_config()}), _, _, _) do
    {:error, :enotconn}
  end

  def export_key_materials(
        r_sslsocket(pid: [pid | _]),
        labels,
        contexts,
        wantedLengths,
        consumeSecret
      )
      when is_pid(pid) do
    :ssl_gen_statem.call(
      pid,
      {:export_key_materials, labels, contexts, wantedLengths, consumeSecret}
    )
  end

  def export_key_materials(r_sslsocket(pid: {_Listen, r_config()}), _, _, _, _) do
    {:error, :enotconn}
  end

  def prf(
        r_sslsocket(pid: [pid | _]) = socket,
        :master_secret,
        label,
        [:client_random, :server_random],
        wantedLength
      )
      when is_pid(pid) do
    case export_key_materials(socket, [label], [:no_context], [wantedLength], true) do
      {:ok, [keyMaterial]} ->
        {:ok, keyMaterial}

      error ->
        error
    end
  end

  def prf(
        r_sslsocket(pid: [pid | _]) = socket,
        :master_secret,
        label,
        [:client_random, :server_random, context],
        wantedLength
      )
      when is_pid(pid) and is_binary(context) do
    case export_key_materials(socket, [label], [context], [wantedLength], true) do
      {:ok, [keyMaterial]} ->
        {:ok, keyMaterial}

      error ->
        error
    end
  end

  def prf(r_sslsocket(pid: {_Listen, r_config()}), _, _, _, _) do
    {:error, :enotconn}
  end

  def prf(socket, secret, label, context, wantedLength) do
    {:ok, [{:selected_cipher_suite, %{prf: pRFAlg}}]} =
      connection_information(
        socket,
        [:selected_cipher_suite]
      )

    {:ok, :tls_v1.prf(pRFAlg, secret, label, :erlang.iolist_to_binary(context), wantedLength)}
  end

  def clear_pem_cache() do
    :ssl_pem_cache.clear()
  end

  def format_error({:error, reason}) do
    do_format_error(reason)
  end

  def format_error(reason) do
    do_format_error(reason)
  end

  def tls_version(version) when :erlang.element(1, version) == 3 do
    version
  end

  def tls_version(version)
      when :erlang.element(
             1,
             version
           ) == 254 do
    :dtls_v1.corresponding_tls_version(version)
  end

  def suite_to_str(cipher) do
    :ssl_cipher_format.suite_map_to_str(cipher)
  end

  def suite_to_openssl_str(cipher) do
    :ssl_cipher_format.suite_map_to_openssl_str(cipher)
  end

  def str_to_suite(cipherSuiteName) do
    try do
      :ssl_cipher_format.suite_openssl_str_to_map(cipherSuiteName)
    catch
      _, _ ->
        {:error, {:not_recognized, cipherSuiteName}}
    end
  end

  defp supported_suites(:exclusive, version)
       when :erlang.element(
              1,
              version
            ) == 3 do
    :tls_v1.exclusive_suites(version)
  end

  defp supported_suites(:exclusive, version)
       when :erlang.element(
              1,
              version
            ) == 254 do
    :dtls_v1.exclusive_suites(version)
  end

  defp supported_suites(:default, version) do
    :ssl_cipher.suites(version)
  end

  defp supported_suites(:all, version) do
    :ssl_cipher.all_suites(version)
  end

  defp supported_suites(:anonymous, version) do
    :ssl_cipher.anonymous_suites(version)
  end

  defp supported_suites(:exclusive_anonymous, version)
       when :erlang.element(1, version) == 3 do
    :tls_v1.exclusive_anonymous_suites(version)
  end

  defp supported_suites(:exclusive_anonymous, version)
       when :erlang.element(1, version) == 254 do
    :dtls_v1.exclusive_anonymous_suites(version)
  end

  defp do_listen(
         port,
         r_config(transport_info: {transport, _, _, _, _}) = config,
         :tls_gen_connection
       ) do
    :tls_socket.listen(transport, port, config)
  end

  defp do_listen(port, config, :dtls_gen_connection) do
    :dtls_socket.listen(port, config)
  end

  defp ssl_options() do
    [
      :alpn_advertised_protocols,
      :alpn_preferred_protocols,
      :anti_replay,
      :beast_mitigation,
      :cacertfile,
      :cacerts,
      :cert,
      :certs_keys,
      :certfile,
      :certificate_authorities,
      :ciphers,
      :client_renegotiation,
      :cookie,
      :crl_cache,
      :crl_check,
      :customize_hostname_check,
      :depth,
      :dh,
      :dhfile,
      :early_data,
      :eccs,
      :erl_dist,
      :fail_if_no_peer_cert,
      :fallback,
      :handshake,
      :hibernate_after,
      :honor_cipher_order,
      :honor_ecc_order,
      :keep_secrets,
      :key,
      :keyfile,
      :key_update_at,
      :ktls,
      :log_level,
      :max_handshake_size,
      :middlebox_comp_mode,
      :max_fragment_length,
      :next_protocol_selector,
      :next_protocols_advertised,
      :ocsp_stapling,
      :ocsp_responder_certs,
      :ocsp_nonce,
      :padding_check,
      :partial_chain,
      :password,
      :protocol,
      :psk_identity,
      :receiver_spawn_opts,
      :renegotiate_at,
      :reuse_session,
      :reuse_sessions,
      :secure_renegotiate,
      :sender_spawn_opts,
      :server_name_indication,
      :session_tickets,
      :stateless_tickets_seed,
      :signature_algs,
      :signature_algs_cert,
      :sni_fun,
      :sni_hosts,
      :srp_identity,
      :supported_groups,
      :use_ticket,
      :use_srtp,
      :user_lookup_fun,
      :verify,
      :verify_fun,
      :versions
    ]
  end

  def update_options(opts, role, inheritedSslOpts)
      when is_map(inheritedSslOpts) do
    {userSslOpts, _} = split_options(opts, ssl_options())
    process_options(userSslOpts, inheritedSslOpts, %{role: role})
  end

  defp process_options(userSslOpts, sslOpts0, env) do
    userSslOptsMap = :proplists.to_map(:lists.reverse(userSslOpts))
    sslOpts1 = opt_protocol_versions(userSslOptsMap, sslOpts0, env)
    sslOpts2 = opt_verification(userSslOptsMap, sslOpts1, env)
    sslOpts3 = opt_certs(userSslOptsMap, sslOpts2, env)
    sslOpts4 = opt_tickets(userSslOptsMap, sslOpts3, env)
    sslOpts5 = opt_ocsp(userSslOptsMap, sslOpts4, env)
    sslOpts6 = opt_sni(userSslOptsMap, sslOpts5, env)
    sslOpts7 = opt_signature_algs(userSslOptsMap, sslOpts6, env)
    sslOpts8 = opt_alpn(userSslOptsMap, sslOpts7, env)
    sslOpts9 = opt_mitigation(userSslOptsMap, sslOpts8, env)
    sslOpts10 = opt_server(userSslOptsMap, sslOpts9, env)
    sslOpts11 = opt_client(userSslOptsMap, sslOpts10, env)
    sslOpts12 = opt_renegotiate(userSslOptsMap, sslOpts11, env)
    sslOpts13 = opt_reuse_sessions(userSslOptsMap, sslOpts12, env)
    sslOpts14 = opt_identity(userSslOptsMap, sslOpts13, env)
    sslOpts15 = opt_supported_groups(userSslOptsMap, sslOpts14, env)
    sslOpts16 = opt_crl(userSslOptsMap, sslOpts15, env)
    sslOpts17 = opt_handshake(userSslOptsMap, sslOpts16, env)
    sslOpts18 = opt_use_srtp(userSslOptsMap, sslOpts17, env)
    sslOpts = opt_process(userSslOptsMap, sslOpts18, env)
    sslOpts
  end

  def handle_options(opts, role, host) do
    handle_options(:undefined, :undefined, opts, role, host)
  end

  defp handle_options(transport, socket, opts0, role, host) do
    {userSslOptsList, sockOpts0} =
      split_options(
        opts0,
        ssl_options()
      )

    env = %{role: role, host: host}
    sslOpts = process_options(userSslOptsList, %{}, env)
    %{protocol: protocol} = sslOpts
    {sock, emulated} = emulated_options(transport, socket, protocol, sockOpts0)
    connetionCb = connection_cb(protocol)
    cbInfo = handle_option_cb_info(opts0, protocol)

    {:ok,
     r_config(
       ssl: sslOpts,
       emulated: emulated,
       inet_ssl: sock,
       inet_user: sock,
       transport_info: cbInfo,
       connection_cb: connetionCb
     )}
  end

  defp opt_protocol_versions(userOpts, opts, env) do
    {_, pRC} = get_opt_of(:protocol, [:tls, :dtls], :tls, userOpts, opts)

    logLevels = [
      :none,
      :all,
      :emergency,
      :alert,
      :critical,
      :error,
      :warning,
      :notice,
      :info,
      :debug
    ]

    defaultLevel =
      case :logger.get_module_level(:ssl) do
        [] ->
          :notice

        [{:ssl, level}] ->
          level
      end

    {_, lL} = get_opt_of(:log_level, logLevels, defaultLevel, userOpts, opts)
    opts1 = set_opt_bool(:keep_secrets, false, userOpts, opts)
    {distW, dist} = get_opt_bool(:erl_dist, false, userOpts, opts1)

    option_incompatible(
      pRC === :dtls and dist,
      [{:protocol, pRC}, {:erl_dist, dist}]
    )

    opts2 = set_opt_new(distW, :erl_dist, false, dist, opts1)
    {ktlsW, ktls} = get_opt_bool(:ktls, false, userOpts, opts1)

    option_incompatible(
      pRC === :dtls and ktls,
      [{:protocol, pRC}, {:ktls, ktls}]
    )

    opts3 = set_opt_new(ktlsW, :ktls, false, ktls, opts2)
    opt_versions(userOpts, Map.merge(opts3, %{protocol: pRC, log_level: lL}), env)
  end

  defp opt_versions(userOpts, %{protocol: protocol} = opts, _Env) do
    versions =
      case get_opt(:versions, :unbound, userOpts, opts) do
        {:default, :unbound} ->
          default_versions(protocol)

        {:new, vs} ->
          validate_versions(protocol, vs)

        {:old, vs} ->
          vs
      end

    {where, mCM} = get_opt_bool(:middlebox_comp_mode, true, userOpts, opts)
    assert_version_dep(where === :new, :middlebox_comp_mode, versions, [:"tlsv1.3"])
    opts1 = set_opt_new(where, :middlebox_comp_mode, true, mCM, opts)
    Map.put(opts1, :versions, versions)
  end

  defp default_versions(:tls) do
    vsns0 = :tls_record.supported_protocol_versions()
    :lists.sort(&:tls_record.is_higher/2, vsns0)
  end

  defp default_versions(:dtls) do
    vsns0 = :dtls_record.supported_protocol_versions()
    :lists.sort(&:dtls_record.is_higher/2, vsns0)
  end

  defp validate_versions(:tls, vsns0) do
    validate = fn version ->
      try do
        :tls_record.sufficient_crypto_support(version)
      catch
        :error, :function_clause ->
          option_error(version, {:versions, vsns0})
      else
        true ->
          :tls_record.protocol_version_name(version)

        false ->
          option_error(
            :insufficient_crypto_support,
            {version, {:versions, vsns0}}
          )
      end
    end

    vsns =
      for v <- vsns0 do
        validate.(v)
      end

    tls_validate_version_gap(vsns0)
    option_error([] === vsns, :versions, vsns0)
    :lists.sort(&:tls_record.is_higher/2, vsns)
  end

  defp validate_versions(:dtls, vsns0) do
    validate = fn version ->
      try do
        :tls_record.sufficient_crypto_support(
          :dtls_v1.corresponding_tls_version(:dtls_record.protocol_version_name(version))
        )
      catch
        :error, :function_clause ->
          option_error(version, {:versions, vsns0})
      else
        true ->
          :dtls_record.protocol_version_name(version)

        false ->
          option_error(
            :insufficient_crypto_support,
            {version, {:versions, vsns0}}
          )
      end
    end

    vsns =
      for v <- vsns0 do
        validate.(v)
      end

    option_error([] === vsns, :versions, vsns0)
    :lists.sort(&:dtls_record.is_higher/2, vsns)
  end

  defp opt_verification(userOpts, opts0, %{role: role} = env) do
    {verify, opts1} =
      case get_opt_of(
             :verify,
             [:verify_none, :verify_peer],
             default_verify(role),
             userOpts,
             opts0
           ) do
        {:old, val} ->
          {val, opts0}

        {_, :verify_none} ->
          {:verify_none,
           Map.merge(opts0, %{verify: :verify_none, verify_fun: {none_verify_fun(), []}})}

        {_, :verify_peer} ->
          temp = Map.merge(opts0, %{verify: :verify_peer, verify_fun: :undefined})
          {:verify_peer, :maps.remove(:fail_if_no_peer_cert, temp)}
      end

    opts2 = opt_cacerts(userOpts, opts1, env)

    {_, partialChain} =
      get_opt_fun(
        :partial_chain,
        1,
        fn _ ->
          :unknown_ca
        end,
        userOpts,
        opts2
      )

    defFailNoPeer = role === :server and verify === :verify_peer
    {_, failNoPeerCert} = get_opt_bool(:fail_if_no_peer_cert, defFailNoPeer, userOpts, opts2)
    assert_server_only(role, failNoPeerCert, :fail_if_no_peer_cert)

    option_incompatible(
      failNoPeerCert and verify === :verify_none,
      [{:verify, :verify_none}, {:fail_if_no_peer_cert, true}]
    )

    opts = set_opt_int(:depth, 0, 255, 10, userOpts, opts2)

    case role do
      :client ->
        opt_verify_fun(userOpts, Map.put(opts, :partial_chain, partialChain), env)

      :server ->
        opt_verify_fun(
          userOpts,
          Map.merge(opts, %{partial_chain: partialChain, fail_if_no_peer_cert: failNoPeerCert}),
          env
        )
    end
  end

  defp default_verify(:client) do
    :verify_peer
  end

  defp default_verify(:server) do
    :verify_none
  end

  defp opt_verify_fun(userOpts, opts, _Env) do
    verifyFun =
      case get_opt(:verify_fun, :undefined, userOpts, opts) do
        {_, {f, _} = fA}
        when is_function(f, 3) or
               is_function(f, 4) ->
          fA

        {_, userFun} when is_function(userFun, 1) ->
          {convert_verify_fun(), userFun}

        {_, :undefined} ->
          :undefined

        {_, value} ->
          option_error(:verify_fun, value)
      end

    Map.put(opts, :verify_fun, verifyFun)
  end

  defp none_verify_fun() do
    fn
      _, {:bad_cert, _}, userState ->
        {:valid, userState}

      _, {:extension, r_Extension(critical: true)}, userState ->
        {:valid, userState}

      _, {:extension, _}, userState ->
        {:unknown, userState}

      _, :valid, userState ->
        {:valid, userState}

      _, :valid_peer, userState ->
        {:valid, userState}
    end
  end

  defp convert_verify_fun() do
    fn
      _, {:bad_cert, _} = reason, oldFun ->
        case oldFun.([reason]) do
          true ->
            {:valid, oldFun}

          false ->
            {:fail, reason}
        end

      _, {:extension, _}, userState ->
        {:unknown, userState}

      _, :valid, userState ->
        {:valid, userState}

      _, :valid_peer, userState ->
        {:valid, userState}
    end
  end

  defp opt_certs(userOpts, %{log_level: logLevel} = opts0, env) do
    case get_opt_list(:certs_keys, [], userOpts, opts0) do
      {where, []} when where !== :new ->
        opt_old_certs(userOpts, %{}, opts0, env)

      {:old, [certKey]} ->
        opt_old_certs(userOpts, certKey, opts0, env)

      {where, cKs} when is_list(cKs) ->
        warn_override(
          where,
          userOpts,
          :certs_keys,
          [:cert, :certfile, :key, :keyfile, :password],
          logLevel
        )

        Map.put(
          opts0,
          :certs_keys,
          for cK <- cKs do
            check_cert_key(cK, %{}, logLevel)
          end
        )
    end
  end

  defp opt_old_certs(userOpts, certKeys, %{log_level: logLevel} = sSLOpts, _Env) do
    cK = check_cert_key(userOpts, certKeys, logLevel)

    case :maps.keys(cK) === [] do
      true ->
        Map.put(sSLOpts, :certs_keys, [])

      false ->
        Map.put(sSLOpts, :certs_keys, [cK])
    end
  end

  defp check_cert_key(userOpts, certKeys, logLevel) do
    certKeys0 =
      case get_opt(:cert, :undefined, userOpts, certKeys) do
        {where, cert} when is_binary(cert) ->
          warn_override(where, userOpts, :cert, [:certfile], logLevel)
          Map.put(certKeys, :cert, [cert])

        {where, [c0 | _] = certs} when is_binary(c0) ->
          warn_override(where, userOpts, :cert, [:certfile], logLevel)
          Map.put(certKeys, :cert, certs)

        {:new, err0} ->
          option_error(:cert, err0)

        {_, :undefined} ->
          case get_opt_file(:certfile, :unbound, userOpts, certKeys) do
            {:default, :unbound} ->
              certKeys

            {_, certFile} ->
              Map.put(certKeys, :certfile, certFile)
          end
      end

    certKeys1 =
      case get_opt(:key, :undefined, userOpts, certKeys) do
        {_, :undefined} ->
          case get_opt_file(:keyfile, <<>>, userOpts, certKeys) do
            {:new, keyFile} ->
              Map.put(certKeys0, :keyfile, keyFile)

            {_, <<>>} ->
              case :maps.get(:certfile, certKeys0, :unbound) do
                :unbound ->
                  certKeys0

                cF ->
                  Map.put(certKeys0, :keyfile, cF)
              end

            {:old, _} ->
              certKeys0
          end

        {_, {kF, k0} = key}
        when (is_binary(k0) and
                kF === :rsa) or
               kF === :dsa or
               kF == :RSAPrivateKey or
               kF == :DSAPrivateKey or
               kF == :ECPrivateKey or
               kF == :PrivateKeyInfo ->
          Map.put(certKeys0, :key, key)

        {_, %{engine: _, key_id: _, algorithm: _} = key} ->
          Map.put(certKeys0, :key, key)

        {:new, err1} ->
          option_error(:key, err1)
      end

    certKeys2 =
      case get_opt(:password, :unbound, userOpts, certKeys) do
        {:default, _} ->
          certKeys1

        {_, pwd} when is_binary(pwd) or is_list(pwd) ->
          Map.put(certKeys1, :password, fn ->
            pwd
          end)

        {_, pwd} when is_function(pwd, 0) ->
          Map.put(certKeys1, :password, pwd)

        {_, err2} ->
          option_error(:password, err2)
      end

    certKeys2
  end

  defp opt_cacerts(
         userOpts,
         %{verify: verify, log_level: logLevel, versions: versions} = opts,
         %{role: role}
       ) do
    {_, caCerts} = get_opt_list(:cacerts, :undefined, userOpts, opts)

    caCertFile =
      case get_opt_file(:cacertfile, <<>>, userOpts, opts) do
        {where1, _FileName} when caCerts !== :undefined ->
          warn_override(where1, userOpts, :cacerts, [:cacertfile], logLevel)
          <<>>

        {:new, fileName} ->
          unambiguous_path(fileName)

        {_, fileName} ->
          fileName
      end

    option_incompatible(
      caCertFile === <<>> and caCerts === :undefined and verify === :verify_peer,
      [{:verify, :verify_peer}, {:cacerts, :undefined}]
    )

    {where2, cA} = get_opt_bool(:certificate_authorities, role === :server, userOpts, opts)
    assert_version_dep(where2 === :new, :certificate_authorities, versions, [:"tlsv1.3"])
    opts1 = set_opt_new(:new, :cacertfile, <<>>, caCertFile, opts)
    opts2 = set_opt_new(where2, :certificate_authorities, role === :server, cA, opts1)
    Map.put(opts2, :cacerts, caCerts)
  end

  defp opt_tickets(userOpts, %{versions: versions} = opts, %{role: :client}) do
    {_, sessionTickets} =
      get_opt_of(:session_tickets, [:disabled, :manual, :auto], :disabled, userOpts, opts)

    assert_version_dep(sessionTickets !== :disabled, :session_tickets, versions, [:"tlsv1.3"])
    {_, useTicket} = get_opt_list(:use_ticket, :undefined, userOpts, opts)
    option_error(useTicket === [], :use_ticket, useTicket)

    option_incompatible(
      useTicket !== :undefined and sessionTickets !== :manual,
      [{:use_ticket, useTicket}, {:session_tickets, sessionTickets}]
    )

    {_, earlyData} = get_opt_bin(:early_data, :undefined, userOpts, opts)

    option_incompatible(
      is_binary(earlyData) and sessionTickets === :disabled,
      [:early_data, {:session_tickets, :disabled}]
    )

    option_incompatible(
      is_binary(earlyData) and sessionTickets === :manual and useTicket === :undefined,
      [:early_data, {:session_tickets, :manual}, {:use_ticket, :undefined}]
    )

    assert_server_only(:anti_replay, userOpts)
    assert_server_only(:stateless_tickets_seed, userOpts)

    Map.merge(opts, %{
      session_tickets: sessionTickets,
      use_ticket: useTicket,
      early_data: earlyData
    })
  end

  defp opt_tickets(userOpts, %{versions: versions} = opts, %{role: :server}) do
    {_, sessionTickets} =
      get_opt_of(
        :session_tickets,
        [:disabled, :stateful, :stateless, :stateful_with_cert, :stateless_with_cert],
        :disabled,
        userOpts,
        opts
      )

    assert_version_dep(sessionTickets !== :disabled, :session_tickets, versions, [:"tlsv1.3"])
    {_, earlyData} = get_opt_of(:early_data, [:enabled, :disabled], :disabled, userOpts, opts)

    option_incompatible(
      sessionTickets === :disabled and earlyData === :enabled,
      [:early_data, {:session_tickets, :disabled}]
    )

    stateless =
      :lists.member(
        sessionTickets,
        [:stateless, :stateless_with_cert]
      )

    antiReplay =
      case get_opt(:anti_replay, :undefined, userOpts, opts) do
        {_, :undefined} ->
          :undefined

        {_, aR} when not stateless ->
          option_incompatible([{:anti_replay, aR}, {:session_tickets, sessionTickets}])

        {_, :"10k"} ->
          {10, 5, 72985}

        {_, :"100k"} ->
          {10, 5, 729_845}

        {_, {_, _, _} = aR} ->
          aR

        {_, aR} ->
          option_error(:anti_replay, aR)
      end

    {_, sTS} = get_opt_bin(:stateless_tickets_seed, :undefined, userOpts, opts)

    option_incompatible(
      sTS !== :undefined and not stateless,
      [:stateless_tickets_seed, {:session_tickets, sessionTickets}]
    )

    assert_client_only(:use_ticket, userOpts)

    Map.merge(opts, %{
      session_tickets: sessionTickets,
      early_data: earlyData,
      anti_replay: antiReplay,
      stateless_tickets_seed: sTS
    })
  end

  defp opt_ocsp(userOpts, %{versions: _Versions} = opts, %{role: role}) do
    {stapling, sMap} =
      case get_opt(:ocsp_stapling, false, userOpts, opts) do
        {:old, map} when is_map(map) ->
          {true, map}

        {_, bool} when is_boolean(bool) ->
          {bool, %{}}

        {_, value} ->
          option_error(:ocsp_stapling, value)
      end

    assert_client_only(role, stapling, :ocsp_stapling)
    {_, nonce} = get_opt_bool(:ocsp_nonce, true, userOpts, sMap)

    option_incompatible(
      stapling === false and nonce === false,
      [{:ocsp_nonce, false}, {:ocsp_stapling, false}]
    )

    {_, oRC} = get_opt_list(:ocsp_responder_certs, [], userOpts, sMap)

    checkBinary = fn
      cert when is_binary(cert) ->
        :ok

      _Cert ->
        option_error(:ocsp_responder_certs, oRC)
    end

    for c <- oRC do
      checkBinary.(c)
    end

    option_incompatible(
      stapling === false and oRC !== [],
      [:ocsp_responder_certs, {:ocsp_stapling, false}]
    )

    case stapling do
      true ->
        Map.put(opts, :ocsp_stapling, %{ocsp_nonce: nonce, ocsp_responder_certs: oRC})

      false ->
        opts
    end
  end

  defp opt_sni(userOpts, %{versions: _Versions} = opts, %{role: :server}) do
    {_, sniHosts} = get_opt_list(:sni_hosts, [], userOpts, opts)

    check = fn
      {[_ | _], sO} when is_list(sO) ->
        case :proplists.get_value(:sni_hosts, sO, :undefined) do
          :undefined ->
            :ok

          recursive ->
            option_error(:sni_hosts, recursive)
        end

      hostOpts ->
        option_error(:sni_hosts, hostOpts)
    end

    for e <- sniHosts do
      check.(e)
    end

    {where, sniFun0} = get_opt_fun(:sni_fun, 1, :undefined, userOpts, opts)

    option_incompatible(
      is_function(sniFun0) and sniHosts !== [] and where === :new,
      [:sni_fun, :sni_hosts]
    )

    assert_client_only(:server_name_indication, userOpts)

    sniFun =
      case sniFun0 === :undefined do
        true ->
          fn host ->
            :proplists.get_value(host, sniHosts)
          end

        false ->
          sniFun0
      end

    Map.put(opts, :sni_fun, sniFun)
  end

  defp opt_sni(userOpts, %{versions: _Versions} = opts, %{role: :client} = env) do
    sNI =
      case get_opt(:server_name_indication, :unbound, userOpts, opts) do
        {_, :unbound} ->
          server_name_indication_default(:maps.get(:host, env, :undefined))

        {_, [_ | _] = sN} ->
          sN

        {_, :disable} ->
          :disable

        {_, sN} ->
          option_error(:server_name_indication, sN)
      end

    assert_server_only(:sni_fun, userOpts)
    assert_server_only(:sni_hosts, userOpts)
    Map.put(opts, :server_name_indication, sNI)
  end

  defp server_name_indication_default(host) when is_list(host) do
    :string.strip(host, :right, ?.)
  end

  defp server_name_indication_default(_) do
    :undefined
  end

  defp opt_signature_algs(userOpts, %{versions: versions} = opts, _Env) do
    [tlsVersion | _] =
      tlsVsns =
      for v <- versions do
        tls_version(v)
      end

    sA =
      case get_opt_list(:signature_algs, :undefined, userOpts, opts) do
        {:default, :undefined} when tlsVersion >= {3, 3} ->
          defAlgs = :tls_v1.default_signature_algs(tlsVsns)
          handle_hashsigns_option(defAlgs, tlsVersion)

        {:new, algs} ->
          assert_version_dep(:signature_algs, versions, [:"tlsv1.2", :"tlsv1.3"])
          sA0 = handle_hashsigns_option(algs, tlsVersion)
          option_error(sA0 === [], :no_supported_algorithms, {:signature_algs, algs})
          sA0

        {_, algs} ->
          algs
      end

    sAC =
      case get_opt_list(:signature_algs_cert, :undefined, userOpts, opts) do
        {:new, schemes} ->
          assert_version_dep(:signature_algs_cert, versions, [:"tlsv1.2", :"tlsv1.3"])

          sAC0 =
            handle_signature_algorithms_option(
              schemes,
              tlsVersion
            )

          option_error(
            sAC0 === [],
            :no_supported_signature_schemes,
            {:signature_algs_cert, schemes}
          )

          sAC0

        {_, schemes} ->
          schemes
      end

    Map.merge(opts, %{signature_algs: sA, signature_algs_cert: sAC})
  end

  defp opt_alpn(userOpts, %{versions: versions} = opts, %{role: :server}) do
    {_, aPP} = get_opt_list(:alpn_preferred_protocols, :undefined, userOpts, opts)
    validate_protocols(is_list(aPP), :alpn_preferred_protocols, aPP)
    {where, nPA} = get_opt_list(:next_protocols_advertised, :undefined, userOpts, opts)
    validate_protocols(is_list(nPA), :next_protocols_advertised, nPA)

    assert_version_dep(is_list(nPA), :next_protocols_advertised, versions, [
      :tlsv1,
      :"tlsv1.1",
      :"tlsv1.2"
    ])

    assert_client_only(:alpn_advertised_protocols, userOpts)

    assert_client_only(
      :client_preferred_next_protocols,
      userOpts
    )

    opts1 = set_opt_new(where, :next_protocols_advertised, :undefined, nPA, opts)
    Map.put(opts1, :alpn_preferred_protocols, aPP)
  end

  defp opt_alpn(userOpts, %{versions: versions} = opts, %{role: :client}) do
    {_, aAP} = get_opt_list(:alpn_advertised_protocols, :undefined, userOpts, opts)
    validate_protocols(is_list(aAP), :alpn_advertised_protocols, aAP)

    {where, nPS} =
      case get_opt(:client_preferred_next_protocols, :undefined, userOpts, opts) do
        {:new, cPNP} ->
          assert_version_dep(:client_preferred_next_protocols, versions, [
            :tlsv1,
            :"tlsv1.1",
            :"tlsv1.2"
          ])

          {:new, make_next_protocol_selector(cPNP)}

        cPNP ->
          cPNP
      end

    validate_protocols(is_list(nPS), :client_preferred_next_protocols, nPS)
    assert_server_only(:alpn_preferred_protocols, userOpts)
    assert_server_only(:next_protocols_advertised, userOpts)
    opts1 = set_opt_new(where, :next_protocol_selector, :undefined, nPS, opts)
    Map.put(opts1, :alpn_advertised_protocols, aAP)
  end

  defp validate_protocols(false, _Opt, _List) do
    :ok
  end

  defp validate_protocols(true, opt, list) do
    check = fn bin ->
      isOK = is_binary(bin) and byte_size(bin) > 0 and byte_size(bin) < 256
      option_error(not isOK, opt, {:invalid_protocol, bin})
    end

    :lists.foreach(check, list)
  end

  defp opt_mitigation(userOpts, %{versions: versions} = opts, _Env) do
    defBeast =
      case :lists.last(versions) > {3, 1} do
        true ->
          :disabled

        false ->
          :one_n_minus_one
      end

    {where1, bM} =
      get_opt_of(
        :beast_mitigation,
        [:disabled, :one_n_minus_one, :zero_n],
        defBeast,
        userOpts,
        opts
      )

    assert_version_dep(where1 === :new, :beast_mitigation, versions, [:tlsv1])
    {where2, pC} = get_opt_bool(:padding_check, true, userOpts, opts)
    assert_version_dep(where2 === :new, :padding_check, versions, [:tlsv1])
    opts1 = set_opt_new(:new, :beast_mitigation, :disabled, bM, opts)
    set_opt_new(where2, :padding_check, true, pC, opts1)
  end

  defp opt_server(
         userOpts,
         %{versions: versions, log_level: logLevel} = opts,
         %{role: :server}
       ) do
    {_, eCC} = get_opt_bool(:honor_ecc_order, false, userOpts, opts)
    {_, cipher} = get_opt_bool(:honor_cipher_order, false, userOpts, opts)
    {where1, cookie} = get_opt_bool(:cookie, true, userOpts, opts)
    assert_version_dep(where1 === :new, :cookie, versions, [:"tlsv1.3"])
    {where2, reNeg} = get_opt_bool(:client_renegotiation, true, userOpts, opts)

    assert_version_dep(where2 === :new, :client_renegotiation, versions, [
      :tlsv1,
      :"tlsv1.1",
      :"tlsv1.2"
    ])

    opts1 =
      case get_opt(:dh, :undefined, userOpts, opts) do
        {where, dH} when is_binary(dH) ->
          warn_override(where, userOpts, :dh, [:dhfile], logLevel)
          Map.put(opts, :dh, dH)

        {:new, dH} ->
          option_error(:dh, dH)

        {_, :undefined} ->
          case get_opt_file(:dhfile, :unbound, userOpts, opts) do
            {:default, :unbound} ->
              opts

            {_, dHFile} ->
              Map.put(opts, :dhfile, dHFile)
          end
      end

    Map.merge(opts1, %{
      honor_ecc_order: eCC,
      honor_cipher_order: cipher,
      cookie: cookie,
      client_renegotiation: reNeg
    })
  end

  defp opt_server(userOpts, opts, %{role: :client}) do
    assert_server_only(:honor_ecc_order, userOpts)
    assert_server_only(:honor_cipher_order, userOpts)
    assert_server_only(:cookie, userOpts)
    assert_server_only(:client_renegotiation, userOpts)
    assert_server_only(:dh, userOpts)
    assert_server_only(:dhfile, userOpts)
    opts
  end

  defp opt_client(userOpts, %{versions: versions} = opts, %{role: :client}) do
    {where, fB} = get_opt_bool(:fallback, false, userOpts, opts)
    assert_version_dep(where === :new, :fallback, versions, [:tlsv1, :"tlsv1.1", :"tlsv1.2"])
    {_, cHC} = get_opt_list(:customize_hostname_check, [], userOpts, opts)
    validMFL = [:undefined, 512, 1024, 2048, 4096]
    {_, mFL} = get_opt_of(:max_fragment_length, validMFL, :undefined, userOpts, opts)
    Map.merge(opts, %{fallback: fB, customize_hostname_check: cHC, max_fragment_length: mFL})
  end

  defp opt_client(userOpts, opts, %{role: :server}) do
    assert_client_only(:fallback, userOpts)
    assert_client_only(:customize_hostname_check, userOpts)
    assert_client_only(:max_fragment_length, userOpts)
    Map.put(opts, :customize_hostname_check, [])
  end

  defp opt_renegotiate(userOpts, %{versions: versions} = opts, _Env) do
    {where1, kUA} = get_opt_pos_int(:key_update_at, 388_736_063_997, userOpts, opts)
    assert_version_dep(where1 === :new, :key_update_at, versions, [:"tlsv1.3"])
    {_, rA0} = get_opt_pos_int(:renegotiate_at, 268_435_456, userOpts, opts)
    rA = min(rA0, 268_435_456)
    {where3, sR} = get_opt_bool(:secure_renegotiate, true, userOpts, opts)

    assert_version_dep(where3 === :new, :secure_renegotiate, versions, [
      :tlsv1,
      :"tlsv1.1",
      :"tlsv1.2"
    ])

    Map.merge(opts, %{secure_renegotiate: sR, key_update_at: kUA, renegotiate_at: rA})
  end

  defp opt_reuse_sessions(userOpts, %{versions: versions} = opts, %{role: :client}) do
    {where1, rUSS} = get_opt_of(:reuse_sessions, [true, false, :save], true, userOpts, opts)
    {where2, rS} = rST = get_opt(:reuse_session, :undefined, userOpts, opts)

    case rST do
      {:new, bin} when is_binary(bin) ->
        :ok

      {:new, {b1, b2}} when is_binary(b1) and is_binary(b2) ->
        :ok

      {:new, bad} ->
        option_error(:reuse_session, bad)

      {_, _} ->
        :ok
    end

    assert_version_dep(where1 === :new, :reuse_sessions, versions, [
      :tlsv1,
      :"tlsv1.1",
      :"tlsv1.2"
    ])

    assert_version_dep(where2 === :new, :reuse_session, versions, [:tlsv1, :"tlsv1.1", :"tlsv1.2"])

    Map.merge(opts, %{reuse_sessions: rUSS, reuse_session: rS})
  end

  defp opt_reuse_sessions(userOpts, %{versions: versions} = opts, %{role: :server}) do
    {where1, rUSS} = get_opt_bool(:reuse_sessions, true, userOpts, opts)

    defRS = fn _, _, _, _ ->
      true
    end

    {where2, rS} = get_opt_fun(:reuse_session, 4, defRS, userOpts, opts)

    assert_version_dep(where1 === :new, :reuse_sessions, versions, [
      :tlsv1,
      :"tlsv1.1",
      :"tlsv1.2"
    ])

    assert_version_dep(where2 === :new, :reuse_session, versions, [:tlsv1, :"tlsv1.1", :"tlsv1.2"])

    Map.merge(opts, %{reuse_sessions: rUSS, reuse_session: rS})
  end

  defp opt_identity(userOpts, %{versions: versions} = opts, _Env) do
    pSK =
      case get_opt_list(:psk_identity, :undefined, userOpts, opts) do
        {:new, pSK0} ->
          pSK1 = :unicode.characters_to_binary(pSK0)
          pSKSize = byte_size(pSK1)
          assert_version_dep(:psk_identity, versions, [:tlsv1, :"tlsv1.1", :"tlsv1.2"])

          option_error(
            not (0 < pSKSize and pSKSize < 65536),
            :psk_identity,
            {:psk_identity, pSK0}
          )

          pSK1

        {_, pSK0} ->
          pSK0
      end

    sRP =
      case get_opt(:srp_identity, :undefined, userOpts, opts) do
        {:new, {s1, s2}} when is_list(s1) and is_list(s2) ->
          user = :unicode.characters_to_binary(s1)
          userSize = byte_size(user)
          assert_version_dep(:srp_identity, versions, [:tlsv1, :"tlsv1.1", :"tlsv1.2"])

          option_error(
            not (0 < userSize and userSize < 65536),
            :srp_identity,
            {:srp_identity, pSK0}
          )

          {user, :unicode.characters_to_binary(s2)}

        {:new, err} ->
          option_error(:srp_identity, err)

        {_, sRP0} ->
          sRP0
      end

    uLF =
      case get_opt(:user_lookup_fun, :undefined, userOpts, opts) do
        {:new, {fun, _} = uLF0} when is_function(fun, 3) ->
          assert_version_dep(:user_lookup_fun, versions, [:tlsv1, :"tlsv1.1", :"tlsv1.2"])
          uLF0

        {:new, uLF0} ->
          option_error(:user_lookup_fun, uLF0)

        {_, uLF0} ->
          uLF0
      end

    Map.merge(opts, %{psk_identity: pSK, srp_identity: sRP, user_lookup_fun: uLF})
  end

  defp opt_supported_groups(userOpts, %{versions: tlsVsns} = opts, _Env) do
    sG =
      case get_opt_list(:supported_groups, :undefined, userOpts, opts) do
        {:default, :undefined} ->
          handle_supported_groups_option(groups(:default))

        {:new, sG0} ->
          assert_version_dep(:supported_groups, tlsVsns, [:"tlsv1.3"])
          handle_supported_groups_option(sG0)

        {:old, sG0} ->
          sG0
      end

    cPHS =
      case get_opt_list(:ciphers, [], userOpts, opts) do
        {:old, cPS0} ->
          cPS0

        {_, cPS0} ->
          handle_cipher_option(cPS0, tlsVsns)
      end

    eCCS =
      try do
        assert_version_dep(:eccs, tlsVsns, [:"tlsv1.2", :"tlsv1.1", :tlsv1])
      catch
        _ ->
          []
      else
        _ ->
          case get_opt_list(:eccs, :undefined, userOpts, opts) do
            {:old, eCCS0} ->
              eCCS0

            {:default, _} ->
              handle_eccs_option(:tls_v1.ec_curves(:default, :"tlsv1.2"))

            {:new, eCCS0} ->
              handle_eccs_option(eCCS0)
          end
      end

    Map.merge(opts, %{ciphers: cPHS, eccs: eCCS, supported_groups: sG})
  end

  defp opt_crl(userOpts, opts, _Env) do
    {_, check} = get_opt_of(:crl_check, [:best_effort, :peer, true, false], false, userOpts, opts)

    cache =
      case get_opt(:crl_cache, {:ssl_crl_cache, {:internal, []}}, userOpts, opts) do
        {_, {cb, {_Handle, options}} = value}
        when is_atom(cb) and is_list(options) ->
          value

        {_, err} ->
          option_error(:crl_cache, err)
      end

    Map.merge(opts, %{crl_check: check, crl_cache: cache})
  end

  defp opt_handshake(userOpts, opts, _Env) do
    {_, hS} = get_opt_of(:handshake, [:hello, :full], :full, userOpts, opts)
    {_, mHSS} = get_opt_int(:max_handshake_size, 1, 8_388_607, div(256 * 1024, 2), userOpts, opts)
    Map.merge(opts, %{handshake: hS, max_handshake_size: mHSS})
  end

  defp opt_use_srtp(userOpts, %{protocol: protocol} = opts, _Env) do
    useSRTP =
      case get_opt_map(:use_srtp, :undefined, userOpts, opts) do
        {:old, useSRTP0} ->
          useSRTP0

        {:default, :undefined} ->
          :undefined

        {:new, useSRTP1} ->
          assert_protocol_dep(:use_srtp, protocol, [:dtls])
          validate_use_srtp(useSRTP1)
      end

    case useSRTP do
      %{} ->
        Map.put(opts, :use_srtp, useSRTP)

      _ ->
        opts
    end
  end

  defp validate_use_srtp(%{protection_profiles: [_ | _] = pPs} = useSRTP) do
    case :maps.keys(useSRTP) -- [:protection_profiles, :mki] do
      [] ->
        :ok

      extra ->
        option_error(:use_srtp, {:unknown_parameters, extra})
    end

    isValidProfile = fn
      <<_, _>> ->
        true

      _ ->
        false
    end

    case :lists.all(isValidProfile, pPs) do
      true ->
        :ok

      false ->
        option_error(
          :use_srtp,
          {:invalid_protection_profiles, pPs}
        )
    end

    case useSRTP do
      %{mki: mKI} when not is_binary(mKI) ->
        option_error(:use_srtp, {:invalid_mki, mKI})

      %{mki: _} ->
        useSRTP

      %{} ->
        Map.put(useSRTP, :mki, <<>>)
    end
  end

  defp validate_use_srtp(%{} = useSRTP) do
    option_error(
      :use_srtp,
      {:no_protection_profiles, useSRTP}
    )
  end

  defp opt_process(userOpts, opts0, _Env) do
    opts1 = set_opt_list(:receiver_spawn_opts, [], userOpts, opts0)
    opts2 = set_opt_list(:sender_spawn_opts, [], userOpts, opts1)
    set_opt_int(:hibernate_after, 0, :infinity, :infinity, userOpts, opts2)
  end

  defp get_opt(opt, default, userOpts, opts) do
    case :maps.get(opt, userOpts, :unbound) do
      :unbound ->
        case :maps.get(maybe_map_key_internal(opt), opts, :unbound) do
          :unbound ->
            {:default, default}

          value ->
            {:old, value}
        end

      value ->
        {:new, value}
    end
  end

  defp get_opt_of(opt, valid, default, userOpts, opts) do
    case get_opt(opt, default, userOpts, opts) do
      {:new, value} = res ->
        case :lists.member(value, valid) do
          true ->
            res

          false ->
            option_error(opt, value)
        end

      res ->
        res
    end
  end

  defp get_opt_bool(opt, default, userOpts, opts) do
    case get_opt(opt, default, userOpts, opts) do
      {_, value} = res when is_boolean(value) ->
        res

      {_, value} ->
        option_error(opt, value)
    end
  end

  defp get_opt_pos_int(opt, default, userOpts, opts) do
    get_opt_int(opt, 1, :infinity, default, userOpts, opts)
  end

  defp get_opt_int(opt, min, max, default, userOpts, opts) do
    case get_opt(opt, default, userOpts, opts) do
      {_, value} = res
      when is_integer(value) and
             min <= value and value <= max ->
        res

      {_, value} = res
      when value === :infinity and
             max === :infinity ->
        res

      {_, value} ->
        option_error(opt, value)
    end
  end

  defp get_opt_fun(opt, arity, default, userOpts, opts) do
    case get_opt(opt, default, userOpts, opts) do
      {_, fun} = res when is_function(fun, arity) ->
        res

      {:new, err} ->
        option_error(opt, err)

      res ->
        res
    end
  end

  defp get_opt_list(opt, default, userOpts, opts) do
    case get_opt(opt, default, userOpts, opts) do
      {:new, err} when not is_list(err) ->
        option_error(opt, err)

      res ->
        res
    end
  end

  defp get_opt_bin(opt, default, userOpts, opts) do
    case get_opt(opt, default, userOpts, opts) do
      {:new, err} when not is_binary(err) ->
        option_error(opt, err)

      res ->
        res
    end
  end

  defp get_opt_file(opt, default, userOpts, opts) do
    case get_opt(opt, default, userOpts, opts) do
      {:new, file} ->
        {:new, validate_filename(file, opt)}

      res ->
        res
    end
  end

  defp set_opt_bool(opt, default, userOpts, opts) do
    case :maps.get(opt, userOpts, default) do
      ^default ->
        opts

      value when is_boolean(value) ->
        Map.put(opts, opt, value)

      value ->
        option_error(opt, value)
    end
  end

  defp get_opt_map(opt, default, userOpts, opts) do
    case get_opt(opt, default, userOpts, opts) do
      {:new, err} when not is_map(err) ->
        option_error(opt, err)

      res ->
        res
    end
  end

  defp set_opt_int(opt, min, max, default, userOpts, opts) do
    case :maps.get(opt, userOpts, default) do
      ^default ->
        opts

      value
      when is_integer(value) and min <= value and
             value <= max ->
        Map.put(opts, opt, value)

      value when value === :infinity and max === :infinity ->
        Map.put(opts, opt, value)

      value ->
        option_error(opt, value)
    end
  end

  defp set_opt_list(opt, default, userOpts, opts) do
    case :maps.get(opt, userOpts, []) do
      ^default ->
        opts

      list when is_list(list) ->
        Map.put(opts, opt, list)

      value ->
        option_error(opt, value)
    end
  end

  defp set_opt_new(:new, opt, default, value, opts)
       when default !== value do
    Map.put(opts, opt, value)
  end

  defp set_opt_new(_, _, _, _, opts) do
    opts
  end

  defp default_cb_info(:tls) do
    {:gen_tcp, :tcp, :tcp_closed, :tcp_error, :tcp_passive}
  end

  defp default_cb_info(:dtls) do
    {:gen_udp, :udp, :udp_closed, :udp_error, :udp_passive}
  end

  defp handle_cb_info({v1, v2, v3, v4}) do
    {v1, v2, v3, v4, :erlang.list_to_atom(:erlang.atom_to_list(v2) ++ ~c"_passive")}
  end

  defp handle_cb_info(cbInfo) when tuple_size(cbInfo) === 5 do
    cbInfo
  end

  defp handle_cb_info(cbInfo) do
    option_error(:cb_info, cbInfo)
  end

  defp handle_option_cb_info(options, protocol) do
    cbInfo = :proplists.get_value(:cb_info, options, default_cb_info(protocol))
    handle_cb_info(cbInfo)
  end

  defp maybe_map_key_internal(:client_preferred_next_protocols) do
    :next_protocol_selector
  end

  defp maybe_map_key_internal(k) do
    k
  end

  defp split_options(opts0, allOptions) do
    opts1 =
      :proplists.expand(
        [{:binary, [{:mode, :binary}]}, {:list, [{:mode, :list}]}],
        opts0
      )

    opts2 = handle_option_format(opts1, [])
    opts = :proplists.delete(:ssl_imp, opts2)

    deleteUserOpts = fn key, propList ->
      :proplists.delete(key, propList)
    end

    allOpts = [:cb_info, :client_preferred_next_protocols] ++ allOptions
    sockOpts = :lists.foldl(deleteUserOpts, opts, allOpts)
    {opts -- sockOpts, sockOpts}
  end

  defp assert_server_only(option, opts) do
    value = :maps.get(option, opts, :undefined)
    role_error(value !== :undefined, :server_only, option)
  end

  defp assert_client_only(option, opts) do
    value = :maps.get(option, opts, :undefined)
    role_error(value !== :undefined, :client_only, option)
  end

  defp assert_server_only(:client, bool, option) do
    role_error(bool, :server_only, option)
  end

  defp assert_server_only(_, _, _) do
    :ok
  end

  defp assert_client_only(:server, bool, option) do
    role_error(bool, :client_only, option)
  end

  defp assert_client_only(_, _, _) do
    :ok
  end

  defp role_error(false, _ErrorDesc, _Option) do
    :ok
  end

  defp role_error(true, errorDesc, option)
       when errorDesc === :client_only or
              errorDesc === :server_only do
    throw_error({:option, errorDesc, option})
  end

  defp option_incompatible(false, _Options) do
    :ok
  end

  defp option_incompatible(true, options) do
    option_incompatible(options)
  end

  defp option_incompatible(options) do
    throw_error({:options, :incompatible, options})
  end

  defp option_error(false, _, _What) do
    true
  end

  defp option_error(true, tag, what) do
    option_error(tag, what)
  end

  defp option_error(tag, what) do
    throw_error({:options, {tag, what}})
  end

  defp throw_error(err) do
    throw({:error, err})
  end

  defp assert_protocol_dep(option, protocol, allowedProtos) do
    case :lists.member(protocol, allowedProtos) do
      true ->
        :ok

      false ->
        option_incompatible([option, {:protocol, protocol}])
    end
  end

  defp assert_version_dep(option, vsns, allowedVsn) do
    assert_version_dep(true, option, vsns, allowedVsn)
  end

  defp assert_version_dep(false, _, _, _) do
    true
  end

  defp assert_version_dep(true, option, sSLVsns, allowedVsn) do
    case is_dtls_configured(sSLVsns) do
      true ->
        true

      false ->
        aPIVsns =
          :lists.map(
            &:tls_record.protocol_version/1,
            sSLVsns
          )

        set1 = :sets.from_list(aPIVsns)
        set2 = :sets.from_list(allowedVsn)

        case :sets.size(:sets.intersection(set1, set2)) > 0 do
          true ->
            :ok

          false ->
            option_incompatible([option, {:versions, aPIVsns}])
        end
    end
  end

  defp warn_override(:new, userOpts, newOpt, oldOpts, logLevel) do
    check = fn key ->
      :maps.is_key(key, userOpts)
    end

    case :lists.filter(check, oldOpts) do
      [] ->
        :ok

      ignored ->
        desc = :lists.flatten(:io_lib.format(~c"Options ~w are ignored", [ignored]))
        reas = :lists.flatten(:io_lib.format(~c"Option ~w is set", [newOpt]))

        :ssl_logger.log(:notice, logLevel, %{description: desc, reason: reas}, %{
          mfa: {:ssl, :warn_override, 5},
          line: 2651,
          file: ~c"otp/lib/ssl/src/ssl.erl"
        })
    end
  end

  defp warn_override(_, _UserOpts, _NewOpt, _OldOpts, _LogLevel) do
    :ok
  end

  defp is_dtls_configured(versions) do
    :lists.any(
      fn ver ->
        :erlang.element(1, ver) == 254
      end,
      versions
    )
  end

  defp handle_hashsigns_option(value, version) do
    try do
      cond do
        version >= {3, 4} ->
          :tls_v1.signature_schemes(version, value)

        version === {3, 3} ->
          :tls_v1.signature_algs(version, value)

        true ->
          :undefined
      end
    catch
      :error, :function_clause ->
        option_error(:signature_algs, value)
    end
  end

  defp handle_signature_algorithms_option(value, version) do
    try do
      :tls_v1.signature_schemes(version, value)
    catch
      :error, :function_clause ->
        option_error(:signature_algs_cert, value)
    end
  end

  defp validate_filename(fN, _Option)
       when is_binary(fN) and
              fN !== <<>> do
    fN
  end

  defp validate_filename([_ | _] = fN, _Option) do
    enc = :file.native_name_encoding()
    :unicode.characters_to_binary(fN, :unicode, enc)
  end

  defp validate_filename(fN, option) do
    option_error(option, fN)
  end

  defp tls_validate_version_gap(versions) do
    case :lists.member(:"tlsv1.3", versions) do
      true when length(versions) >= 2 ->
        case :lists.member(:"tlsv1.2", versions) do
          true ->
            versions

          false ->
            throw({:error, {:options, :missing_version, {:"tlsv1.2", {:versions, versions}}}})
        end

      _ ->
        versions
    end
  end

  defp emulated_options(:undefined, :undefined, protocol, opts) do
    case protocol do
      :tls ->
        :tls_socket.emulated_options(opts)

      :dtls ->
        :dtls_socket.emulated_options(opts)
    end
  end

  defp emulated_options(transport, socket, protocol, opts) do
    emulatedOptions = :tls_socket.emulated_options()
    {:ok, original} = :tls_socket.getopts(transport, socket, emulatedOptions)
    {inet, emulated0} = emulated_options(:undefined, :undefined, protocol, opts)
    {inet, :lists.ukeymerge(1, emulated0, original)}
  end

  defp handle_cipher_option(value, versions) when is_list(value) do
    try do
      binary_cipher_suites(versions, value)
    catch
      :exit, _ ->
        option_error(:ciphers, value)

      :error, _ ->
        option_error(:ciphers, value)
    else
      suites ->
        suites
    end
  end

  defp binary_cipher_suites([{3, 4}], []) do
    default_binary_suites(:exclusive, {3, 4})
  end

  defp binary_cipher_suites([version | _], []) do
    default_binary_suites(:default, version)
  end

  defp binary_cipher_suites(versions, [map | _] = ciphers0)
       when is_map(map) do
    ciphers =
      for c <- ciphers0 do
        :ssl_cipher_format.suite_map_to_bin(c)
      end

    binary_cipher_suites(versions, ciphers)
  end

  defp binary_cipher_suites(versions, [tuple | _] = ciphers0)
       when is_tuple(tuple) do
    ciphers =
      for c <- ciphers0 do
        :ssl_cipher_format.suite_map_to_bin(tuple_to_map(c))
      end

    binary_cipher_suites(versions, ciphers)
  end

  defp binary_cipher_suites(versions, [cipher0 | _] = ciphers0)
       when is_binary(cipher0) do
    all = all_suites(versions)

    case (for cipher <- ciphers0,
              :lists.member(cipher, all) do
            cipher
          end) do
      [] ->
        binary_cipher_suites(versions, [])

      ciphers ->
        ciphers
    end
  end

  defp binary_cipher_suites(versions, [head | _] = ciphers0)
       when is_list(head) do
    ciphers =
      for c <- ciphers0 do
        :ssl_cipher_format.suite_openssl_str_to_map(c)
      end

    binary_cipher_suites(versions, ciphers)
  end

  defp binary_cipher_suites(versions, ciphers0) do
    ciphers =
      for c <- :string.lexemes(ciphers0, ~c":") do
        :ssl_cipher_format.suite_openssl_str_to_map(c)
      end

    binary_cipher_suites(versions, ciphers)
  end

  defp default_binary_suites(:exclusive, version) do
    :ssl_cipher.filter_suites(:tls_v1.exclusive_suites(version))
  end

  defp default_binary_suites(:default, version) do
    :ssl_cipher.filter_suites(:ssl_cipher.suites(version))
  end

  defp all_suites([{3, 4}]) do
    :tls_v1.exclusive_suites({3, 4})
  end

  defp all_suites([{3, 4}, version1 | _]) do
    all_suites([{3, 4}]) ++
      :ssl_cipher.all_suites(version1) ++ :ssl_cipher.anonymous_suites(version1)
  end

  defp all_suites([version | _]) do
    :ssl_cipher.all_suites(version) ++ :ssl_cipher.anonymous_suites(version)
  end

  defp tuple_to_map({kex, cipher, mac}) do
    %{key_exchange: kex, cipher: cipher, mac: mac, prf: :default_prf}
  end

  defp tuple_to_map({kex, cipher, mac, prf}) do
    %{key_exchange: kex, cipher: cipher, mac: tuple_to_map_mac(cipher, mac), prf: prf}
  end

  defp tuple_to_map_mac(:aes_128_gcm, _) do
    :aead
  end

  defp tuple_to_map_mac(:aes_256_gcm, _) do
    :aead
  end

  defp tuple_to_map_mac(:chacha20_poly1305, _) do
    :aead
  end

  defp tuple_to_map_mac(_, mAC) do
    mAC
  end

  defp handle_eccs_option(value) when is_list(value) do
    try do
      :tls_v1.ecc_curves(value)
    catch
      :exit, _ ->
        option_error(:eccs, value)

      :error, _ ->
        option_error(:eccs, value)
    else
      curves ->
        option_error(curves === [], :eccs, :none_valid)
        r_elliptic_curves(elliptic_curve_list: curves)
    end
  end

  defp handle_supported_groups_option(value) when is_list(value) do
    try do
      :tls_v1.groups(value)
    catch
      :exit, _ ->
        option_error(:supported_groups, value)

      :error, _ ->
        option_error(:supported_groups, value)
    else
      groups ->
        option_error(groups === [], :supported_groups, :none_valid)
        r_supported_groups(supported_groups: groups)
    end
  end

  defp do_format_error(reason) when is_list(reason) do
    reason
  end

  defp do_format_error(:closed) do
    ~c"TLS connection is closed"
  end

  defp do_format_error({:tls_alert, {_, description}}) do
    description
  end

  defp do_format_error({:options, {fileType, file, reason}})
       when fileType == :cacertfile or fileType == :certfile or
              fileType == :keyfile or fileType == :dhfile do
    error = file_error_format(reason)
    file_desc(fileType) ++ file ++ ~c": " ++ error
  end

  defp do_format_error({:options, {:socket_options, option, error}}) do
    :lists.flatten(
      :io_lib.format(
        ~c"Invalid transport socket option ~p: ~s",
        [option, do_format_error(error)]
      )
    )
  end

  defp do_format_error({:options, {:socket_options, option}}) do
    :lists.flatten(:io_lib.format(~c"Invalid socket option: ~p", [option]))
  end

  defp do_format_error({:options, :incompatible, opts}) do
    :lists.flatten(:io_lib.format(~c"Options (or their values) can not be combined: ~p", [opts]))
  end

  defp do_format_error({:option, reason, opts}) do
    :lists.flatten(:io_lib.format(~c"Invalid option ~w ~w", [opts, reason]))
  end

  defp do_format_error({:options, reason, opts}) do
    :lists.flatten(:io_lib.format(~c"Invalid option ~w ~w", [opts, reason]))
  end

  defp do_format_error({:options, {:missing_version = r, opts}}) do
    :lists.flatten(:io_lib.format(~c"Invalid option ~w ~w", [opts, r]))
  end

  defp do_format_error({:options, {:option_not_a_key_value_tuple = r, opts}}) do
    :lists.flatten(:io_lib.format(~c"Invalid option ~w ~w", [opts, r]))
  end

  defp do_format_error({:options, {:no_supported_algorithms = r, opts}}) do
    :lists.flatten(:io_lib.format(~c"Invalid option ~w ~w", [opts, r]))
  end

  defp do_format_error({:options, {:no_supported_signature_schemes = r, opts}}) do
    :lists.flatten(:io_lib.format(~c"Invalid option ~w ~w", [opts, r]))
  end

  defp do_format_error({:options, {:insufficient_crypto_support = r, opts}}) do
    :lists.flatten(:io_lib.format(~c"Invalid option ~w ~w", [opts, r]))
  end

  defp do_format_error({:options, options}) do
    :lists.flatten(:io_lib.format(~c"Invalid TLS option: ~p", [options]))
  end

  defp do_format_error(error) do
    case :inet.format_error(error) do
      ~c"unknown POSIX" ++ _ ->
        unexpected_format(error)

      other ->
        other
    end
  end

  defp unexpected_format(error) do
    :lists.flatten(:io_lib.format(~c"Unexpected error: ~p", [error]))
  end

  defp file_error_format({:error, error}) do
    case :file.format_error(error) do
      ~c"unknown POSIX error" ++ _ ->
        ~c"decoding error"

      str ->
        str
    end
  end

  defp file_error_format(_) do
    ~c"decoding error"
  end

  defp file_desc(:cacertfile) do
    ~c"Invalid CA certificate file "
  end

  defp file_desc(:certfile) do
    ~c"Invalid certificate file "
  end

  defp file_desc(:keyfile) do
    ~c"Invalid key file "
  end

  defp file_desc(:dhfile) do
    ~c"Invalid DH params file "
  end

  defp make_next_protocol_selector(:undefined) do
    :undefined
  end

  defp make_next_protocol_selector({precedence, prefProtcol} = v) do
    option_error(not is_list(prefProtcol), :client_preferred_next_protocols, v)
    make_next_protocol_selector({precedence, prefProtcol, <<>>})
  end

  defp make_next_protocol_selector({precedence, allProtocols, defP} = v) do
    option_error(not is_list(allProtocols), :client_preferred_next_protocols, v)

    option_error(
      not (is_binary(defP) and byte_size(defP) < 256),
      :client_preferred_next_protocols,
      v
    )

    validate_protocols(true, :client_preferred_next_protocols, allProtocols)

    case precedence do
      :client ->
        fn advertised ->
          search = fn p ->
            :lists.member(p, advertised)
          end

          case :lists.search(search, allProtocols) do
            false ->
              defP

            {:value, preferred} ->
              preferred
          end
        end

      :server ->
        fn advertised ->
          search = fn p ->
            :lists.member(p, allProtocols)
          end

          case :lists.search(search, advertised) do
            false ->
              defP

            {:value, preferred} ->
              preferred
          end
        end

      value ->
        option_error(
          :client_preferred_next_protocols,
          {:invalid_precedence, value}
        )
    end
  end

  defp make_next_protocol_selector(what) do
    option_error(:client_preferred_next_protocols, what)
  end

  defp connection_cb(:tls) do
    :tls_gen_connection
  end

  defp connection_cb(:dtls) do
    :dtls_gen_connection
  end

  defp connection_cb(opts) do
    connection_cb(:proplists.get_value(:protocol, opts, :tls))
  end

  defp handle_option_format([], acc) do
    :lists.reverse(acc)
  end

  defp handle_option_format([{:log_alert, bool} | rest], acc)
       when is_boolean(bool) do
    case :proplists.get_value(:log_level, acc ++ rest, :undefined) do
      :undefined ->
        handle_option_format(
          rest,
          [{:log_level, map_log_level(bool)} | acc]
        )

      _ ->
        handle_option_format(rest, acc)
    end
  end

  defp handle_option_format([{key, _} = opt | rest], acc)
       when is_atom(key) do
    handle_option_format(rest, [opt | acc])
  end

  defp handle_option_format([{:raw, _, _, _} = opt | rest], acc) do
    handle_option_format(rest, [opt | acc])
  end

  defp handle_option_format([:inet = opt | rest], acc) do
    handle_option_format(rest, [opt | acc])
  end

  defp handle_option_format([:inet6 = opt | rest], acc) do
    handle_option_format(rest, [opt | acc])
  end

  defp handle_option_format([value | _], _) do
    option_error(:option_not_a_key_value_tuple, value)
  end

  defp map_log_level(true) do
    :notice
  end

  defp map_log_level(false) do
    :none
  end

  defp include_security_info([]) do
    false
  end

  defp include_security_info([item | items]) do
    case :lists.member(
           item,
           [:client_random, :server_random, :master_secret, :keylog]
         ) do
      true ->
        true

      false ->
        include_security_info(items)
    end
  end

  defp add_filter(:undefined, filters) do
    filters
  end

  defp add_filter(filter, filters) do
    [filter | filters]
  end

  defp unambiguous_path(value) do
    absName = :filename.absname(value)

    uP =
      case :file.read_link(absName) do
        {:ok, pathWithNoLink} ->
          case :filename.pathtype(pathWithNoLink) do
            :relative ->
              dirname = :filename.dirname(absName)
              :filename.join([dirname, pathWithNoLink])

            _ ->
              pathWithNoLink
          end

        _ ->
          absName
      end

    validate_filename(uP, :cacertfile)
  end

  def handle_trace(:csp, {:call, {:ssl, :opt_ocsp, [userOpts | _]}}, stack) do
    {format_ocsp_params(userOpts), stack}
  end

  def handle_trace(:csp, {:return_from, {:ssl, :opt_ocsp, 3}, return}, stack) do
    {format_ocsp_params(return), stack}
  end

  def handle_trace(:rle, {:call, {:ssl, :listen, args}}, stack0) do
    role = :server
    {:io_lib.format(~c"(*~w) Args = ~W", [role, args, 10]), [{:role, role} | stack0]}
  end

  def handle_trace(:rle, {:call, {:ssl, :connect, args}}, stack0) do
    role = :client
    {:io_lib.format(~c"(*~w) Args = ~W", [role, args, 10]), [{:role, role} | stack0]}
  end

  defp format_ocsp_params(map) do
    stapling = :maps.get(:ocsp_stapling, map, :"?")
    nonce = :maps.get(:ocsp_nonce, map, :"?")
    certs = :maps.get(:ocsp_responder_certs, map, :"?")
    :io_lib.format(~c"Stapling = ~W Nonce = ~W Certs = ~W", [stapling, 5, nonce, 5, certs, 5])
  end
end
