defmodule :m_tls_connection_1_3 do
  use Bitwise
  require Record
  Record.defrecord(:r_alert, :alert, level: :undefined,
                                 description: :undefined, where: :undefined,
                                 role: :undefined, reason: :undefined)
  Record.defrecord(:r_AlgorithmIdentifier_PKCS1, :"AlgorithmIdentifier-PKCS1", algorithm: :undefined,
                             parameters: :asn1_NOVALUE)
  Record.defrecord(:r_AttributePKCS_7, :"AttributePKCS-7", type: :undefined,
                             values: :undefined)
  Record.defrecord(:r_AlgorithmIdentifierPKCS_7, :"AlgorithmIdentifierPKCS-7", algorithm: :undefined,
                             parameters: :asn1_NOVALUE)
  Record.defrecord(:r_AlgorithmIdentifierPKCS_10, :"AlgorithmIdentifierPKCS-10", algorithm: :undefined,
                             parameters: :asn1_NOVALUE)
  Record.defrecord(:r_AttributePKCS_10, :"AttributePKCS-10", type: :undefined,
                             values: :undefined)
  Record.defrecord(:r_SubjectPublicKeyInfo_PKCS_10, :"SubjectPublicKeyInfo-PKCS-10", algorithm: :undefined,
                             subjectPublicKey: :undefined)
  Record.defrecord(:r_ECPrivateKey, :ECPrivateKey, version: :undefined,
                                        privateKey: :undefined,
                                        parameters: :asn1_NOVALUE,
                                        publicKey: :asn1_NOVALUE,
                                        attributes: :asn1_NOVALUE)
  Record.defrecord(:r_DSAPrivateKey, :DSAPrivateKey, version: :undefined,
                                         p: :undefined, q: :undefined,
                                         g: :undefined, y: :undefined,
                                         x: :undefined)
  Record.defrecord(:r_DHParameter, :DHParameter, prime: :undefined,
                                       base: :undefined,
                                       privateValueLength: :asn1_NOVALUE)
  Record.defrecord(:r_DigestAlgorithm, :DigestAlgorithm, algorithm: :undefined,
                                           parameters: :asn1_NOVALUE)
  Record.defrecord(:r_DigestInfoPKCS_1, :"DigestInfoPKCS-1", digestAlgorithm: :undefined,
                             digest: :undefined)
  Record.defrecord(:r_RSASSA_AlgorithmIdentifier, :"RSASSA-AlgorithmIdentifier", algorithm: :undefined,
                             parameters: :asn1_NOVALUE)
  Record.defrecord(:r_RSASSA_PSS_params, :"RSASSA-PSS-params", hashAlgorithm: :asn1_DEFAULT,
                             maskGenAlgorithm: :asn1_DEFAULT,
                             saltLength: :asn1_DEFAULT,
                             trailerField: :asn1_DEFAULT)
  Record.defrecord(:r_RSAES_AlgorithmIdentifier, :"RSAES-AlgorithmIdentifier", algorithm: :undefined,
                             parameters: :asn1_NOVALUE)
  Record.defrecord(:r_RSAES_OAEP_params, :"RSAES-OAEP-params", hashAlgorithm: :asn1_DEFAULT,
                             maskGenAlgorithm: :asn1_DEFAULT,
                             pSourceAlgorithm: :asn1_DEFAULT)
  Record.defrecord(:r_OtherPrimeInfo, :OtherPrimeInfo, prime: :undefined,
                                          exponent: :undefined,
                                          coefficient: :undefined)
  Record.defrecord(:r_RSAPrivateKey, :RSAPrivateKey, version: :undefined,
                                         modulus: :undefined,
                                         publicExponent: :undefined,
                                         privateExponent: :undefined,
                                         prime1: :undefined, prime2: :undefined,
                                         exponent1: :undefined,
                                         exponent2: :undefined,
                                         coefficient: :undefined,
                                         otherPrimeInfos: :asn1_NOVALUE)
  Record.defrecord(:r_RSAPublicKey, :RSAPublicKey, modulus: :undefined,
                                        publicExponent: :undefined)
  Record.defrecord(:r_PSourceAlgorithm, :PSourceAlgorithm, algorithm: :undefined,
                                            parameters: :asn1_NOVALUE)
  Record.defrecord(:r_MaskGenAlgorithm, :MaskGenAlgorithm, algorithm: :undefined,
                                            parameters: :asn1_NOVALUE)
  Record.defrecord(:r_HashAlgorithm, :HashAlgorithm, algorithm: :undefined,
                                         parameters: :asn1_NOVALUE)
  Record.defrecord(:r_Curve, :Curve, a: :undefined,
                                 b: :undefined, seed: :asn1_NOVALUE)
  Record.defrecord(:r_ECParameters, :ECParameters, version: :undefined,
                                        fieldID: :undefined, curve: :undefined,
                                        base: :undefined, order: :undefined,
                                        cofactor: :asn1_NOVALUE)
  Record.defrecord(:r_Pentanomial, :Pentanomial, k1: :undefined,
                                       k2: :undefined, k3: :undefined)
  Record.defrecord(:r_Characteristic_two, :"Characteristic-two", m: :undefined,
                             basis: :undefined, parameters: :undefined)
  Record.defrecord(:r_ECDSA_Sig_Value, :"ECDSA-Sig-Value", r: :undefined, s: :undefined)
  Record.defrecord(:r_FieldID, :FieldID, fieldType: :undefined,
                                   parameters: :undefined)
  Record.defrecord(:r_ValidationParms, :ValidationParms, seed: :undefined,
                                           pgenCounter: :undefined)
  Record.defrecord(:r_DomainParameters, :DomainParameters, p: :undefined,
                                            g: :undefined, q: :undefined,
                                            j: :asn1_NOVALUE,
                                            validationParms: :asn1_NOVALUE)
  Record.defrecord(:r_Dss_Sig_Value, :"Dss-Sig-Value", r: :undefined, s: :undefined)
  Record.defrecord(:r_Dss_Parms, :"Dss-Parms", p: :undefined, q: :undefined,
                             g: :undefined)
  Record.defrecord(:r_ACClearAttrs, :ACClearAttrs, acIssuer: :undefined,
                                        acSerial: :undefined, attrs: :undefined)
  Record.defrecord(:r_AAControls, :AAControls, pathLenConstraint: :asn1_NOVALUE,
                                      permittedAttrs: :asn1_NOVALUE,
                                      excludedAttrs: :asn1_NOVALUE,
                                      permitUnSpecified: :asn1_DEFAULT)
  Record.defrecord(:r_SecurityCategory, :SecurityCategory, type: :undefined,
                                            value: :undefined)
  Record.defrecord(:r_Clearance, :Clearance, policyId: :undefined,
                                     classList: :asn1_DEFAULT,
                                     securityCategories: :asn1_NOVALUE)
  Record.defrecord(:r_RoleSyntax, :RoleSyntax, roleAuthority: :asn1_NOVALUE,
                                      roleName: :undefined)
  Record.defrecord(:r_SvceAuthInfo, :SvceAuthInfo, service: :undefined,
                                        ident: :undefined,
                                        authInfo: :asn1_NOVALUE)
  Record.defrecord(:r_IetfAttrSyntax, :IetfAttrSyntax, policyAuthority: :asn1_NOVALUE,
                                          values: :undefined)
  Record.defrecord(:r_TargetCert, :TargetCert, targetCertificate: :undefined,
                                      targetName: :asn1_NOVALUE,
                                      certDigestInfo: :asn1_NOVALUE)
  Record.defrecord(:r_AttCertValidityPeriod, :AttCertValidityPeriod, notBeforeTime: :undefined,
                                                 notAfterTime: :undefined)
  Record.defrecord(:r_IssuerSerial, :IssuerSerial, issuer: :undefined,
                                        serial: :undefined,
                                        issuerUID: :asn1_NOVALUE)
  Record.defrecord(:r_V2Form, :V2Form, issuerName: :asn1_NOVALUE,
                                  baseCertificateID: :asn1_NOVALUE,
                                  objectDigestInfo: :asn1_NOVALUE)
  Record.defrecord(:r_ObjectDigestInfo, :ObjectDigestInfo, digestedObjectType: :undefined,
                                            otherObjectTypeID: :asn1_NOVALUE,
                                            digestAlgorithm: :undefined,
                                            objectDigest: :undefined)
  Record.defrecord(:r_Holder, :Holder, baseCertificateID: :asn1_NOVALUE,
                                  entityName: :asn1_NOVALUE,
                                  objectDigestInfo: :asn1_NOVALUE)
  Record.defrecord(:r_AttributeCertificateInfo, :AttributeCertificateInfo, version: :undefined,
                                                    holder: :undefined,
                                                    issuer: :undefined,
                                                    signature: :undefined,
                                                    serialNumber: :undefined,
                                                    attrCertValidityPeriod: :undefined,
                                                    attributes: :undefined,
                                                    issuerUniqueID: :asn1_NOVALUE,
                                                    extensions: :asn1_NOVALUE)
  Record.defrecord(:r_AttributeCertificate, :AttributeCertificate, acinfo: :undefined,
                                                signatureAlgorithm: :undefined,
                                                signatureValue: :undefined)
  Record.defrecord(:r_IssuingDistributionPoint, :IssuingDistributionPoint, distributionPoint: :asn1_NOVALUE,
                                                    onlyContainsUserCerts: :asn1_DEFAULT,
                                                    onlyContainsCACerts: :asn1_DEFAULT,
                                                    onlySomeReasons: :asn1_NOVALUE,
                                                    indirectCRL: :asn1_DEFAULT,
                                                    onlyContainsAttributeCerts: :asn1_DEFAULT)
  Record.defrecord(:r_AccessDescription, :AccessDescription, accessMethod: :undefined,
                                             accessLocation: :undefined)
  Record.defrecord(:r_DistributionPoint, :DistributionPoint, distributionPoint: :asn1_NOVALUE,
                                             reasons: :asn1_NOVALUE,
                                             cRLIssuer: :asn1_NOVALUE)
  Record.defrecord(:r_PolicyConstraints, :PolicyConstraints, requireExplicitPolicy: :asn1_NOVALUE,
                                             inhibitPolicyMapping: :asn1_NOVALUE)
  Record.defrecord(:r_GeneralSubtree, :GeneralSubtree, base: :undefined,
                                          minimum: :asn1_DEFAULT,
                                          maximum: :asn1_NOVALUE)
  Record.defrecord(:r_NameConstraints, :NameConstraints, permittedSubtrees: :asn1_NOVALUE,
                                           excludedSubtrees: :asn1_NOVALUE)
  Record.defrecord(:r_BasicConstraints, :BasicConstraints, cA: :asn1_DEFAULT,
                                            pathLenConstraint: :asn1_NOVALUE)
  Record.defrecord(:r_EDIPartyName, :EDIPartyName, nameAssigner: :asn1_NOVALUE,
                                        partyName: :undefined)
  Record.defrecord(:r_AnotherName, :AnotherName, "type-id": :undefined,
                                       value: :undefined)
  Record.defrecord(:r_PolicyMappings_SEQOF, :PolicyMappings_SEQOF, issuerDomainPolicy: :undefined,
                                                subjectDomainPolicy: :undefined)
  Record.defrecord(:r_NoticeReference, :NoticeReference, organization: :undefined,
                                           noticeNumbers: :undefined)
  Record.defrecord(:r_UserNotice, :UserNotice, noticeRef: :asn1_NOVALUE,
                                      explicitText: :asn1_NOVALUE)
  Record.defrecord(:r_PolicyQualifierInfo, :PolicyQualifierInfo, policyQualifierId: :undefined,
                                               qualifier: :undefined)
  Record.defrecord(:r_PolicyInformation, :PolicyInformation, policyIdentifier: :undefined,
                                             policyQualifiers: :asn1_NOVALUE)
  Record.defrecord(:r_PrivateKeyUsagePeriod, :PrivateKeyUsagePeriod, notBefore: :asn1_NOVALUE,
                                                 notAfter: :asn1_NOVALUE)
  Record.defrecord(:r_AuthorityKeyIdentifier, :AuthorityKeyIdentifier, keyIdentifier: :asn1_NOVALUE,
                                                  authorityCertIssuer: :asn1_NOVALUE,
                                                  authorityCertSerialNumber: :asn1_NOVALUE)
  Record.defrecord(:r_EncryptedData, :EncryptedData, version: :undefined,
                                         encryptedContentInfo: :undefined)
  Record.defrecord(:r_DigestedData, :DigestedData, version: :undefined,
                                        digestAlgorithm: :undefined,
                                        contentInfo: :undefined,
                                        digest: :undefined)
  Record.defrecord(:r_SignedAndEnvelopedData, :SignedAndEnvelopedData, version: :undefined,
                                                  recipientInfos: :undefined,
                                                  digestAlgorithms: :undefined,
                                                  encryptedContentInfo: :undefined,
                                                  certificates: :asn1_NOVALUE,
                                                  crls: :asn1_NOVALUE,
                                                  signerInfos: :undefined)
  Record.defrecord(:r_RecipientInfo, :RecipientInfo, version: :undefined,
                                         issuerAndSerialNumber: :undefined,
                                         keyEncryptionAlgorithm: :undefined,
                                         encryptedKey: :undefined)
  Record.defrecord(:r_EncryptedContentInfo, :EncryptedContentInfo, contentType: :undefined,
                                                contentEncryptionAlgorithm: :undefined,
                                                encryptedContent: :asn1_NOVALUE)
  Record.defrecord(:r_EnvelopedData, :EnvelopedData, version: :undefined,
                                         recipientInfos: :undefined,
                                         encryptedContentInfo: :undefined)
  Record.defrecord(:r_DigestInfoPKCS_7, :"DigestInfoPKCS-7", digestAlgorithm: :undefined,
                             digest: :undefined)
  Record.defrecord(:r_SignerInfo, :SignerInfo, version: :undefined,
                                      issuerAndSerialNumber: :undefined,
                                      digestAlgorithm: :undefined,
                                      authenticatedAttributes: :asn1_NOVALUE,
                                      digestEncryptionAlgorithm: :undefined,
                                      encryptedDigest: :undefined,
                                      unauthenticatedAttributes: :asn1_NOVALUE)
  Record.defrecord(:r_SignerInfo_unauthenticatedAttributes_uaSet_SETOF, :SignerInfo_unauthenticatedAttributes_uaSet_SETOF, type: :undefined,
                                                                            values: :undefined)
  Record.defrecord(:r_SignerInfo_unauthenticatedAttributes_uaSequence_SEQOF, :SignerInfo_unauthenticatedAttributes_uaSequence_SEQOF, type: :undefined,
                                                                                 values: :undefined)
  Record.defrecord(:r_SignedData, :SignedData, version: :undefined,
                                      digestAlgorithms: :undefined,
                                      contentInfo: :undefined,
                                      certificates: :asn1_NOVALUE,
                                      crls: :asn1_NOVALUE,
                                      signerInfos: :undefined)
  Record.defrecord(:r_ContentInfo, :ContentInfo, contentType: :undefined,
                                       content: :asn1_NOVALUE)
  Record.defrecord(:r_KeyEncryptionAlgorithmIdentifier, :KeyEncryptionAlgorithmIdentifier, algorithm: :undefined,
                                                            parameters: :asn1_NOVALUE)
  Record.defrecord(:r_IssuerAndSerialNumber, :IssuerAndSerialNumber, issuer: :undefined,
                                                 serialNumber: :undefined)
  Record.defrecord(:r_DigestEncryptionAlgorithmIdentifier, :DigestEncryptionAlgorithmIdentifier, algorithm: :undefined,
                                                               parameters: :asn1_NOVALUE)
  Record.defrecord(:r_DigestAlgorithmIdentifier, :DigestAlgorithmIdentifier, algorithm: :undefined,
                                                     parameters: :asn1_NOVALUE)
  Record.defrecord(:r_ContentEncryptionAlgorithmIdentifier, :ContentEncryptionAlgorithmIdentifier, algorithm: :undefined,
                                                                parameters: :asn1_NOVALUE)
  Record.defrecord(:r_SignerInfoAuthenticatedAttributes_aaSet_SETOF, :SignerInfoAuthenticatedAttributes_aaSet_SETOF, type: :undefined,
                                                                         values: :undefined)
  Record.defrecord(:r_SignerInfoAuthenticatedAttributes_aaSequence_SEQOF, :SignerInfoAuthenticatedAttributes_aaSequence_SEQOF, type: :undefined,
                                                                              values: :undefined)
  Record.defrecord(:r_CertificationRequest, :CertificationRequest, certificationRequestInfo: :undefined,
                                                signatureAlgorithm: :undefined,
                                                signature: :undefined)
  Record.defrecord(:r_CertificationRequest_signatureAlgorithm, :CertificationRequest_signatureAlgorithm, algorithm: :undefined,
                                                                   parameters: :asn1_NOVALUE)
  Record.defrecord(:r_CertificationRequestInfo, :CertificationRequestInfo, version: :undefined,
                                                    subject: :undefined,
                                                    subjectPKInfo: :undefined,
                                                    attributes: :undefined)
  Record.defrecord(:r_CertificationRequestInfo_subjectPKInfo, :CertificationRequestInfo_subjectPKInfo, algorithm: :undefined,
                                                                  subjectPublicKey: :undefined)
  Record.defrecord(:r_CertificationRequestInfo_subjectPKInfo_algorithm, :CertificationRequestInfo_subjectPKInfo_algorithm, algorithm: :undefined,
                                                                            parameters: :asn1_NOVALUE)
  Record.defrecord(:r_CertificationRequestInfo_attributes_SETOF, :CertificationRequestInfo_attributes_SETOF, type: :undefined,
                                                                     values: :undefined)
  Record.defrecord(:r_PreferredSignatureAlgorithm, :PreferredSignatureAlgorithm, sigIdentifier: :undefined,
                                                       certIdentifier: :asn1_NOVALUE)
  Record.defrecord(:r_CrlID, :CrlID, crlUrl: :asn1_NOVALUE,
                                 crlNum: :asn1_NOVALUE, crlTime: :asn1_NOVALUE)
  Record.defrecord(:r_ServiceLocator, :ServiceLocator, issuer: :undefined,
                                          locator: :undefined)
  Record.defrecord(:r_RevokedInfo, :RevokedInfo, revocationTime: :undefined,
                                       revocationReason: :asn1_NOVALUE)
  Record.defrecord(:r_SingleResponse, :SingleResponse, certID: :undefined,
                                          certStatus: :undefined,
                                          thisUpdate: :undefined,
                                          nextUpdate: :asn1_NOVALUE,
                                          singleExtensions: :asn1_NOVALUE)
  Record.defrecord(:r_ResponseData, :ResponseData, version: :asn1_DEFAULT,
                                        responderID: :undefined,
                                        producedAt: :undefined,
                                        responses: :undefined,
                                        responseExtensions: :asn1_NOVALUE)
  Record.defrecord(:r_BasicOCSPResponse, :BasicOCSPResponse, tbsResponseData: :undefined,
                                             signatureAlgorithm: :undefined,
                                             signature: :undefined,
                                             certs: :asn1_NOVALUE)
  Record.defrecord(:r_ResponseBytes, :ResponseBytes, responseType: :undefined,
                                         response: :undefined)
  Record.defrecord(:r_OCSPResponse, :OCSPResponse, responseStatus: :undefined,
                                        responseBytes: :asn1_NOVALUE)
  Record.defrecord(:r_CertID, :CertID, hashAlgorithm: :undefined,
                                  issuerNameHash: :undefined,
                                  issuerKeyHash: :undefined,
                                  serialNumber: :undefined)
  Record.defrecord(:r_Request, :Request, reqCert: :undefined,
                                   singleRequestExtensions: :asn1_NOVALUE)
  Record.defrecord(:r_Signature, :Signature, signatureAlgorithm: :undefined,
                                     signature: :undefined,
                                     certs: :asn1_NOVALUE)
  Record.defrecord(:r_TBSRequest, :TBSRequest, version: :asn1_DEFAULT,
                                      requestorName: :asn1_NOVALUE,
                                      requestList: :undefined,
                                      requestExtensions: :asn1_NOVALUE)
  Record.defrecord(:r_OCSPRequest, :OCSPRequest, tbsRequest: :undefined,
                                       optionalSignature: :asn1_NOVALUE)
  Record.defrecord(:r_TeletexDomainDefinedAttribute, :TeletexDomainDefinedAttribute, type: :undefined,
                                                         value: :undefined)
  Record.defrecord(:r_PresentationAddress, :PresentationAddress, pSelector: :asn1_NOVALUE,
                                               sSelector: :asn1_NOVALUE,
                                               tSelector: :asn1_NOVALUE,
                                               nAddresses: :undefined)
  Record.defrecord(:r_ExtendedNetworkAddress_e163_4_address, :"ExtendedNetworkAddress_e163-4-address", number: :undefined,
                             "sub-address": :asn1_NOVALUE)
  Record.defrecord(:r_PDSParameter, :PDSParameter, "printable-string": :asn1_NOVALUE,
                                        "teletex-string": :asn1_NOVALUE)
  Record.defrecord(:r_UnformattedPostalAddress, :UnformattedPostalAddress, "printable-address": :asn1_NOVALUE,
                                                    "teletex-string": :asn1_NOVALUE)
  Record.defrecord(:r_TeletexPersonalName, :TeletexPersonalName, surname: :undefined,
                                               "given-name": :asn1_NOVALUE,
                                               initials: :asn1_NOVALUE,
                                               "generation-qualifier": :asn1_NOVALUE)
  Record.defrecord(:r_ExtensionAttribute, :ExtensionAttribute, "extension-attribute-type": :undefined,
                                              "extension-attribute-value": :undefined)
  Record.defrecord(:r_BuiltInDomainDefinedAttribute, :BuiltInDomainDefinedAttribute, type: :undefined,
                                                         value: :undefined)
  Record.defrecord(:r_PersonalName, :PersonalName, surname: :undefined,
                                        "given-name": :asn1_NOVALUE,
                                        initials: :asn1_NOVALUE,
                                        "generation-qualifier": :asn1_NOVALUE)
  Record.defrecord(:r_BuiltInStandardAttributes, :BuiltInStandardAttributes, "country-name": :asn1_NOVALUE,
                                                     "administration-domain-name": :asn1_NOVALUE,
                                                     "network-address": :asn1_NOVALUE,
                                                     "terminal-identifier": :asn1_NOVALUE,
                                                     "private-domain-name": :asn1_NOVALUE,
                                                     "organization-name": :asn1_NOVALUE,
                                                     "numeric-user-identifier": :asn1_NOVALUE,
                                                     "personal-name": :asn1_NOVALUE,
                                                     "organizational-unit-names": :asn1_NOVALUE)
  Record.defrecord(:r_ORAddress, :ORAddress, "built-in-standard-attributes": :undefined,
                                     "built-in-domain-defined-attributes": :asn1_NOVALUE, "extension-attributes": :asn1_NOVALUE)
  Record.defrecord(:r_AlgorithmIdentifier, :AlgorithmIdentifier, algorithm: :undefined,
                                               parameters: :asn1_NOVALUE)
  Record.defrecord(:r_TBSCertList, :TBSCertList, version: :asn1_NOVALUE,
                                       signature: :undefined,
                                       issuer: :undefined,
                                       thisUpdate: :undefined,
                                       nextUpdate: :asn1_NOVALUE,
                                       revokedCertificates: :asn1_NOVALUE,
                                       crlExtensions: :asn1_NOVALUE)
  Record.defrecord(:r_TBSCertList_revokedCertificates_SEQOF, :TBSCertList_revokedCertificates_SEQOF, userCertificate: :undefined,
                                                                 revocationDate: :undefined,
                                                                 crlEntryExtensions: :asn1_NOVALUE)
  Record.defrecord(:r_CertificateList, :CertificateList, tbsCertList: :undefined,
                                           signatureAlgorithm: :undefined,
                                           signature: :undefined)
  Record.defrecord(:r_Extension, :Extension, extnID: :undefined,
                                     critical: :asn1_DEFAULT,
                                     extnValue: :undefined)
  Record.defrecord(:r_SubjectPublicKeyInfo, :SubjectPublicKeyInfo, algorithm: :undefined,
                                                subjectPublicKey: :undefined)
  Record.defrecord(:r_Validity, :Validity, notBefore: :undefined,
                                    notAfter: :undefined)
  Record.defrecord(:r_TBSCertificate, :TBSCertificate, version: :asn1_DEFAULT,
                                          serialNumber: :undefined,
                                          signature: :undefined,
                                          issuer: :undefined,
                                          validity: :undefined,
                                          subject: :undefined,
                                          subjectPublicKeyInfo: :undefined,
                                          issuerUniqueID: :asn1_NOVALUE,
                                          subjectUniqueID: :asn1_NOVALUE,
                                          extensions: :asn1_NOVALUE)
  Record.defrecord(:r_Certificate, :Certificate, tbsCertificate: :undefined,
                                       signatureAlgorithm: :undefined,
                                       signature: :undefined)
  Record.defrecord(:r_AttributeTypeAndValue, :AttributeTypeAndValue, type: :undefined,
                                                 value: :undefined)
  Record.defrecord(:r_Attribute, :Attribute, type: :undefined,
                                     values: :undefined)
  Record.defrecord(:r_Extension_Any, :"Extension-Any", extnID: :undefined,
                             critical: :asn1_DEFAULT, extnValue: :undefined)
  Record.defrecord(:r_OTPExtension, :OTPExtension, extnID: :undefined,
                                        critical: :asn1_DEFAULT,
                                        extnValue: :undefined)
  Record.defrecord(:r_OTPExtensionAttribute, :OTPExtensionAttribute, extensionAttributeType: :undefined,
                                                 extensionAttributeValue: :undefined)
  Record.defrecord(:r_OTPCharacteristic_two, :"OTPCharacteristic-two", m: :undefined,
                             basis: :undefined, parameters: :undefined)
  Record.defrecord(:r_OTPFieldID, :OTPFieldID, fieldType: :undefined,
                                      parameters: :undefined)
  Record.defrecord(:r_PublicKeyAlgorithm, :PublicKeyAlgorithm, algorithm: :undefined,
                                              parameters: :asn1_NOVALUE)
  Record.defrecord(:r_SignatureAlgorithm_Any, :"SignatureAlgorithm-Any", algorithm: :undefined,
                             parameters: :asn1_NOVALUE)
  Record.defrecord(:r_SignatureAlgorithm, :SignatureAlgorithm, algorithm: :undefined,
                                              parameters: :asn1_NOVALUE)
  Record.defrecord(:r_OTPSubjectPublicKeyInfo_Any, :"OTPSubjectPublicKeyInfo-Any", algorithm: :undefined,
                             subjectPublicKey: :undefined)
  Record.defrecord(:r_OTPSubjectPublicKeyInfo, :OTPSubjectPublicKeyInfo, algorithm: :undefined,
                                                   subjectPublicKey: :undefined)
  Record.defrecord(:r_OTPOLDSubjectPublicKeyInfo, :OTPOLDSubjectPublicKeyInfo, algorithm: :undefined,
                                                      subjectPublicKey: :undefined)
  Record.defrecord(:r_OTPOLDSubjectPublicKeyInfo_algorithm, :OTPOLDSubjectPublicKeyInfo_algorithm, algo: :undefined,
                                                                parameters: :asn1_NOVALUE)
  Record.defrecord(:r_OTPAttributeTypeAndValue, :OTPAttributeTypeAndValue, type: :undefined,
                                                    value: :undefined)
  Record.defrecord(:r_OTPTBSCertificate, :OTPTBSCertificate, version: :asn1_DEFAULT,
                                             serialNumber: :undefined,
                                             signature: :undefined,
                                             issuer: :undefined,
                                             validity: :undefined,
                                             subject: :undefined,
                                             subjectPublicKeyInfo: :undefined,
                                             issuerUniqueID: :asn1_NOVALUE,
                                             subjectUniqueID: :asn1_NOVALUE,
                                             extensions: :asn1_NOVALUE)
  Record.defrecord(:r_OTPCertificate, :OTPCertificate, tbsCertificate: :undefined,
                                          signatureAlgorithm: :undefined,
                                          signature: :undefined)
  Record.defrecord(:r_AlgorithmIdentifierPKCS5v2_0, :"AlgorithmIdentifierPKCS5v2-0", algorithm: :undefined,
                             parameters: :asn1_NOVALUE)
  Record.defrecord(:r_PKAttribute, :PKAttribute, type: :undefined,
                                       values: :undefined,
                                       valuesWithContext: :asn1_NOVALUE)
  Record.defrecord(:r_PKAttribute_valuesWithContext_SETOF, :PKAttribute_valuesWithContext_SETOF, value: :undefined,
                                                               contextList: :undefined)
  Record.defrecord(:r_AlgorithmIdentifierPKCS_8, :"AlgorithmIdentifierPKCS-8", algorithm: :undefined,
                             parameters: :asn1_NOVALUE)
  Record.defrecord(:r_RC5_CBC_Parameters, :"RC5-CBC-Parameters", version: :undefined,
                             rounds: :undefined, blockSizeInBits: :undefined,
                             iv: :asn1_NOVALUE)
  Record.defrecord(:r_RC2_CBC_Parameter, :"RC2-CBC-Parameter", rc2ParameterVersion: :asn1_NOVALUE,
                             iv: :undefined)
  Record.defrecord(:r_PBMAC1_params, :"PBMAC1-params", keyDerivationFunc: :undefined,
                             messageAuthScheme: :undefined)
  Record.defrecord(:r_PBMAC1_params_keyDerivationFunc, :"PBMAC1-params_keyDerivationFunc", algorithm: :undefined,
                             parameters: :asn1_NOVALUE)
  Record.defrecord(:r_PBMAC1_params_messageAuthScheme, :"PBMAC1-params_messageAuthScheme", algorithm: :undefined,
                             parameters: :asn1_NOVALUE)
  Record.defrecord(:r_PBES2_params, :"PBES2-params", keyDerivationFunc: :undefined,
                             encryptionScheme: :undefined)
  Record.defrecord(:r_PBES2_params_keyDerivationFunc, :"PBES2-params_keyDerivationFunc", algorithm: :undefined,
                             parameters: :asn1_NOVALUE)
  Record.defrecord(:r_PBES2_params_encryptionScheme, :"PBES2-params_encryptionScheme", algorithm: :undefined,
                             parameters: :asn1_NOVALUE)
  Record.defrecord(:r_PBEParameter, :PBEParameter, salt: :undefined,
                                        iterationCount: :undefined)
  Record.defrecord(:r_PBKDF2_params, :"PBKDF2-params", salt: :undefined,
                             iterationCount: :undefined,
                             keyLength: :asn1_NOVALUE, prf: :asn1_DEFAULT)
  Record.defrecord(:r_PBKDF2_params_salt_otherSource, :"PBKDF2-params_salt_otherSource", algorithm: :undefined,
                             parameters: :asn1_NOVALUE)
  Record.defrecord(:r_PBKDF2_params_prf, :"PBKDF2-params_prf", algorithm: :undefined,
                             parameters: :asn1_NOVALUE)
  Record.defrecord(:r_Context, :Context, contextType: :undefined,
                                   contextValues: :undefined,
                                   fallback: :asn1_DEFAULT)
  Record.defrecord(:r_EncryptedPrivateKeyInfo, :EncryptedPrivateKeyInfo, encryptionAlgorithm: :undefined,
                                                   encryptedData: :undefined)
  Record.defrecord(:r_EncryptedPrivateKeyInfo_encryptionAlgorithm, :EncryptedPrivateKeyInfo_encryptionAlgorithm, algorithm: :undefined,
                                                                       parameters: :asn1_NOVALUE)
  Record.defrecord(:r_Attributes_SETOF, :Attributes_SETOF, type: :undefined,
                                            values: :undefined,
                                            valuesWithContext: :asn1_NOVALUE)
  Record.defrecord(:r_Attributes_SETOF_valuesWithContext_SETOF, :Attributes_SETOF_valuesWithContext_SETOF, value: :undefined,
                                                                    contextList: :undefined)
  Record.defrecord(:r_OneAsymmetricKey, :OneAsymmetricKey, version: :undefined,
                                            privateKeyAlgorithm: :undefined,
                                            privateKey: :undefined,
                                            attributes: :asn1_NOVALUE,
                                            publicKey: :asn1_NOVALUE)
  Record.defrecord(:r_OneAsymmetricKey_privateKeyAlgorithm, :OneAsymmetricKey_privateKeyAlgorithm, algorithm: :undefined,
                                                                parameters: :asn1_NOVALUE)
  Record.defrecord(:r_PrivateKeyInfo, :PrivateKeyInfo, version: :undefined,
                                          privateKeyAlgorithm: :undefined,
                                          privateKey: :undefined,
                                          attributes: :asn1_NOVALUE)
  Record.defrecord(:r_PrivateKeyInfo_privateKeyAlgorithm, :PrivateKeyInfo_privateKeyAlgorithm, algorithm: :undefined,
                                                              parameters: :asn1_NOVALUE)
  Record.defrecord(:r_SubjectPublicKeyInfoAlgorithm, :SubjectPublicKeyInfoAlgorithm, algorithm: :undefined,
                                                         parameters: :asn1_NOVALUE)
  Record.defrecord(:r_path_validation_state, :path_validation_state, valid_policy_tree: :undefined,
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
                                                 user_state: :undefined)
  Record.defrecord(:r_policy_tree_node, :policy_tree_node, valid_policy: :undefined,
                                            qualifier_set: :undefined,
                                            criticality_indicator: :undefined,
                                            expected_policy_set: :undefined)
  Record.defrecord(:r_revoke_state, :revoke_state, reasons_mask: :undefined,
                                        cert_status: :undefined,
                                        interim_reasons_mask: :undefined,
                                        valid_ext: :undefined,
                                        details: :undefined)
  Record.defrecord(:r_ECPoint, :ECPoint, point: :undefined)
  Record.defrecord(:r_socket_options, :socket_options, mode: :list,
                                          packet: 0, packet_size: 0, header: 0,
                                          active: true)
  Record.defrecord(:r_config, :config, ssl: :undefined,
                                  inet_user: :undefined, emulated: :undefined,
                                  trackers: :undefined,
                                  dtls_handler: :undefined,
                                  inet_ssl: :undefined,
                                  transport_info: :undefined,
                                  connection_cb: :undefined)
  Record.defrecord(:r_ticket_data, :ticket_data, key: :undefined,
                                       pos: :undefined, identity: :undefined,
                                       psk: :undefined, nonce: :undefined,
                                       cipher_suite: :undefined,
                                       max_size: :undefined)
  Record.defrecord(:r_security_parameters, :security_parameters, cipher_suite: :undefined,
                                               connection_end: :undefined,
                                               bulk_cipher_algorithm: :undefined,
                                               cipher_type: :undefined,
                                               iv_size: :undefined,
                                               key_size: :undefined,
                                               key_material_length: :undefined,
                                               expanded_key_material_length: :undefined,
                                               mac_algorithm: :undefined,
                                               prf_algorithm: :undefined,
                                               hash_size: :undefined,
                                               compression_algorithm: :undefined,
                                               master_secret: :undefined,
                                               resumption_master_secret: :undefined,
                                               application_traffic_secret: :undefined,
                                               client_early_data_secret: :undefined,
                                               client_random: :undefined,
                                               server_random: :undefined,
                                               exportable: :undefined)
  Record.defrecord(:r_compression_state, :compression_state, method: :undefined,
                                             state: :undefined)
  Record.defrecord(:r_generic_stream_cipher, :generic_stream_cipher, content: :undefined,
                                                 mac: :undefined)
  Record.defrecord(:r_generic_block_cipher, :generic_block_cipher, iv: :undefined,
                                                content: :undefined,
                                                mac: :undefined,
                                                padding: :undefined,
                                                padding_length: :undefined,
                                                next_iv: :undefined)
  Record.defrecord(:r_session, :session, session_id: :undefined,
                                   internal_id: :undefined,
                                   peer_certificate: :undefined,
                                   own_certificates: :undefined,
                                   private_key: :undefined,
                                   compression_method: :undefined,
                                   cipher_suite: :undefined,
                                   master_secret: :undefined,
                                   srp_username: :undefined,
                                   is_resumable: :undefined,
                                   time_stamp: :undefined, ecc: :undefined,
                                   sign_alg: :undefined,
                                   dh_public_value: :undefined)
  Record.defrecord(:r_random, :random, gmt_unix_time: :undefined,
                                  random_bytes: :undefined)
  Record.defrecord(:r_hello_extensions, :hello_extensions, renegotiation_info: :undefined,
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
                                            key_share: :undefined)
  Record.defrecord(:r_server_hello, :server_hello, server_version: :undefined,
                                        random: :undefined,
                                        session_id: :undefined,
                                        cipher_suite: :undefined,
                                        compression_method: :undefined,
                                        extensions: :undefined)
  Record.defrecord(:r_certificate, :certificate, asn1_certificates: :undefined)
  Record.defrecord(:r_server_rsa_params, :server_rsa_params, rsa_modulus: :undefined,
                                             rsa_exponent: :undefined)
  Record.defrecord(:r_server_dh_params, :server_dh_params, dh_p: :undefined,
                                            dh_g: :undefined, dh_y: :undefined)
  Record.defrecord(:r_server_ecdh_params, :server_ecdh_params, curve: :undefined,
                                              public: :undefined)
  Record.defrecord(:r_server_psk_params, :server_psk_params, hint: :undefined)
  Record.defrecord(:r_server_dhe_psk_params, :server_dhe_psk_params, hint: :undefined,
                                                 dh_params: :undefined)
  Record.defrecord(:r_server_ecdhe_psk_params, :server_ecdhe_psk_params, hint: :undefined,
                                                   dh_params: :undefined)
  Record.defrecord(:r_server_srp_params, :server_srp_params, srp_n: :undefined,
                                             srp_g: :undefined,
                                             srp_s: :undefined,
                                             srp_b: :undefined)
  Record.defrecord(:r_server_key_exchange, :server_key_exchange, exchange_keys: :undefined)
  Record.defrecord(:r_server_key_params, :server_key_params, params: :undefined,
                                             params_bin: :undefined,
                                             hashsign: :undefined,
                                             signature: :undefined)
  Record.defrecord(:r_hello_request, :hello_request, [])
  Record.defrecord(:r_server_hello_done, :server_hello_done, [])
  Record.defrecord(:r_certificate_request, :certificate_request, certificate_types: :undefined,
                                               hashsign_algorithms: :undefined,
                                               certificate_authorities: :undefined)
  Record.defrecord(:r_client_key_exchange, :client_key_exchange, exchange_keys: :undefined)
  Record.defrecord(:r_pre_master_secret, :pre_master_secret, client_version: :undefined,
                                             random: :undefined)
  Record.defrecord(:r_encrypted_premaster_secret, :encrypted_premaster_secret, premaster_secret: :undefined)
  Record.defrecord(:r_client_diffie_hellman_public, :client_diffie_hellman_public, dh_public: :undefined)
  Record.defrecord(:r_client_ec_diffie_hellman_public, :client_ec_diffie_hellman_public, dh_public: :undefined)
  Record.defrecord(:r_client_psk_identity, :client_psk_identity, identity: :undefined)
  Record.defrecord(:r_client_dhe_psk_identity, :client_dhe_psk_identity, identity: :undefined,
                                                   dh_public: :undefined)
  Record.defrecord(:r_client_ecdhe_psk_identity, :client_ecdhe_psk_identity, identity: :undefined,
                                                     dh_public: :undefined)
  Record.defrecord(:r_client_rsa_psk_identity, :client_rsa_psk_identity, identity: :undefined,
                                                   exchange_keys: :undefined)
  Record.defrecord(:r_client_srp_public, :client_srp_public, srp_a: :undefined)
  Record.defrecord(:r_certificate_verify, :certificate_verify, hashsign_algorithm: :undefined,
                                              signature: :undefined)
  Record.defrecord(:r_finished, :finished, verify_data: :undefined)
  Record.defrecord(:r_renegotiation_info, :renegotiation_info, renegotiated_connection: :undefined)
  Record.defrecord(:r_srp, :srp, username: :undefined)
  Record.defrecord(:r_hash_sign_algos, :hash_sign_algos, hash_sign_algos: :undefined)
  Record.defrecord(:r_signature_algorithms, :signature_algorithms, signature_scheme_list: :undefined)
  Record.defrecord(:r_alpn, :alpn, extension_data: :undefined)
  Record.defrecord(:r_next_protocol_negotiation, :next_protocol_negotiation, extension_data: :undefined)
  Record.defrecord(:r_next_protocol, :next_protocol, selected_protocol: :undefined)
  Record.defrecord(:r_elliptic_curves, :elliptic_curves, elliptic_curve_list: :undefined)
  Record.defrecord(:r_supported_groups, :supported_groups, supported_groups: :undefined)
  Record.defrecord(:r_ec_point_formats, :ec_point_formats, ec_point_format_list: :undefined)
  Record.defrecord(:r_sni, :sni, hostname: :undefined)
  Record.defrecord(:r_max_frag_enum, :max_frag_enum, enum: :undefined)
  Record.defrecord(:r_certificate_status_request, :certificate_status_request, status_type: :undefined,
                                                      request: :undefined)
  Record.defrecord(:r_ocsp_status_request, :ocsp_status_request, responder_id_list: [],
                                               request_extensions: [])
  Record.defrecord(:r_certificate_status, :certificate_status, status_type: :undefined,
                                              response: :undefined)
  Record.defrecord(:r_client_hello_versions, :client_hello_versions, versions: :undefined)
  Record.defrecord(:r_server_hello_selected_version, :server_hello_selected_version, selected_version: :undefined)
  Record.defrecord(:r_signature_algorithms_cert, :signature_algorithms_cert, signature_scheme_list: :undefined)
  Record.defrecord(:r_srp_user, :srp_user, generator: :undefined,
                                    prime: :undefined, salt: :undefined,
                                    verifier: :undefined)
  Record.defrecord(:r_stateless_ticket, :stateless_ticket, hash: :undefined,
                                            pre_shared_key: :undefined,
                                            ticket_age_add: :undefined,
                                            lifetime: :undefined,
                                            timestamp: :undefined)
  Record.defrecord(:r_change_cipher_spec, :change_cipher_spec, type: 1)
  Record.defrecord(:r_cipher_state, :cipher_state, iv: :undefined,
                                        key: :undefined,
                                        finished_key: :undefined,
                                        state: :undefined, nonce: :undefined,
                                        tag_len: :undefined)
  Record.defrecord(:r_static_env, :static_env, role: :undefined,
                                      transport_cb: :undefined,
                                      protocol_cb: :undefined,
                                      data_tag: :undefined,
                                      close_tag: :undefined,
                                      error_tag: :undefined,
                                      passive_tag: :undefined, host: :undefined,
                                      port: :undefined, socket: :undefined,
                                      cert_db: :undefined,
                                      session_cache: :undefined,
                                      session_cache_cb: :undefined,
                                      crl_db: :undefined,
                                      file_ref_db: :undefined,
                                      cert_db_ref: :undefined,
                                      trackers: :undefined)
  Record.defrecord(:r_handshake_env, :handshake_env, client_hello_version: :undefined,
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
                                         hashsign_algorithm: {:undefined,
                                                                :undefined},
                                         cert_hashsign_algorithm: {:undefined,
                                                                     :undefined},
                                         kex_algorithm: :undefined,
                                         kex_keys: :undefined,
                                         diffie_hellman_params: :undefined,
                                         srp_params: :undefined,
                                         public_key_info: :undefined,
                                         premaster_secret: :undefined,
                                         server_psk_identity: :undefined,
                                         cookie_iv_shard: :undefined,
                                         ocsp_stapling_state: %{ocsp_stapling:
                                                                false,
                                                                  ocsp_expect:
                                                                  :no_staple})
  Record.defrecord(:r_connection_env, :connection_env, user_application: :undefined,
                                          downgrade: :undefined,
                                          socket_terminated: false,
                                          socket_tls_closed: false,
                                          negotiated_version: :undefined,
                                          erl_dist_handle: :undefined,
                                          cert_key_alts: :undefined)
  Record.defrecord(:r_state, :state, static_env: :undefined,
                                 connection_env: :undefined,
                                 ssl_options: :undefined,
                                 socket_options: :undefined,
                                 handshake_env: :undefined, flight_buffer: [],
                                 client_certificate_status: :not_requested,
                                 protocol_specific: %{}, session: :undefined,
                                 key_share: :undefined,
                                 connection_states: :undefined,
                                 protocol_buffers: :undefined,
                                 user_data_buffer: :undefined,
                                 bytes_to_read: :undefined,
                                 start_or_recv_from: :undefined,
                                 log_level: :undefined)
  Record.defrecord(:r_ssl_tls, :ssl_tls, type: :undefined,
                                   version: :undefined, fragment: :undefined,
                                   early_data: false)
  Record.defrecord(:r_protocol_buffers, :protocol_buffers, tls_record_buffer: <<>>,
                                            tls_handshake_buffer: <<>>,
                                            tls_cipher_texts: [])
  Record.defrecord(:r_client_hello, :client_hello, client_version: :undefined,
                                        random: :undefined,
                                        session_id: :undefined,
                                        cookie: :undefined,
                                        cipher_suites: :undefined,
                                        compression_methods: :undefined,
                                        extensions: :undefined)
  Record.defrecord(:r_key_share_entry, :key_share_entry, group: :undefined,
                                           key_exchange: :undefined)
  Record.defrecord(:r_key_share_client_hello, :key_share_client_hello, client_shares: :undefined)
  Record.defrecord(:r_key_share_hello_retry_request, :key_share_hello_retry_request, selected_group: :undefined)
  Record.defrecord(:r_key_share_server_hello, :key_share_server_hello, server_share: :undefined)
  Record.defrecord(:r_uncompressed_point_representation, :uncompressed_point_representation, legacy_form: 4,
                                                             x: :undefined,
                                                             y: :undefined)
  Record.defrecord(:r_psk_key_exchange_modes, :psk_key_exchange_modes, ke_modes: :undefined)
  Record.defrecord(:r_empty, :empty, [])
  Record.defrecord(:r_early_data_indication, :early_data_indication, [])
  Record.defrecord(:r_early_data_indication_nst, :early_data_indication_nst, indication: :undefined)
  Record.defrecord(:r_psk_identity, :psk_identity, identity: :undefined,
                                        obfuscated_ticket_age: :undefined)
  Record.defrecord(:r_offered_psks, :offered_psks, identities: :undefined,
                                        binders: :undefined)
  Record.defrecord(:r_pre_shared_key_client_hello, :pre_shared_key_client_hello, offered_psks: :undefined)
  Record.defrecord(:r_pre_shared_key_server_hello, :pre_shared_key_server_hello, selected_identity: :undefined)
  Record.defrecord(:r_cookie, :cookie, cookie: :undefined)
  Record.defrecord(:r_named_group_list, :named_group_list, named_group_list: :undefined)
  Record.defrecord(:r_certificate_authorities, :certificate_authorities, authorities: :undefined)
  Record.defrecord(:r_oid_filter, :oid_filter, certificate_extension_oid: :undefined,
                                      certificate_extension_values: :undefined)
  Record.defrecord(:r_oid_filter_extension, :oid_filter_extension, filters: :undefined)
  Record.defrecord(:r_post_handshake_auth, :post_handshake_auth, [])
  Record.defrecord(:r_encrypted_extensions, :encrypted_extensions, extensions: :undefined)
  Record.defrecord(:r_certificate_request_1_3, :certificate_request_1_3, certificate_request_context: :undefined,
                                                   extensions: :undefined)
  Record.defrecord(:r_certificate_entry, :certificate_entry, data: :undefined,
                                             extensions: :undefined)
  Record.defrecord(:r_certificate_1_3, :certificate_1_3, certificate_request_context: :undefined,
                                           certificate_list: :undefined)
  Record.defrecord(:r_certificate_verify_1_3, :certificate_verify_1_3, algorithm: :undefined,
                                                  signature: :undefined)
  Record.defrecord(:r_new_session_ticket, :new_session_ticket, ticket_lifetime: :undefined,
                                              ticket_age_add: :undefined,
                                              ticket_nonce: :undefined,
                                              ticket: :undefined,
                                              extensions: :undefined)
  Record.defrecord(:r_end_of_early_data, :end_of_early_data, [])
  Record.defrecord(:r_key_update, :key_update, request_update: :undefined)
  @behaviour :gen_statem
  def setopts(transport, socket, other) do
    :tls_socket.setopts(transport, socket, other)
  end

  def getopts(transport, socket, tag) do
    :tls_socket.getopts(transport, socket, tag)
  end

  def send_key_update(sender, type) do
    keyUpdate = :tls_handshake_1_3.key_update(type)
    :tls_sender.send_post_handshake(sender, keyUpdate)
  end

  def update_cipher_key(connStateName,
           r_state(connection_states: cS0) = state0) do
    cS = update_cipher_key(connStateName, cS0)
    r_state(state0, connection_states: cS)
  end

  def update_cipher_key(connStateName, cS0) do
    %{security_parameters: secParams0,
        cipher_state:
        cipherState0} = (connState0 = :maps.get(connStateName,
                                                  cS0))
    hKDF = r_security_parameters(secParams0, :prf_algorithm)
    cipherSuite = r_security_parameters(secParams0, :cipher_suite)
    applicationTrafficSecret0 = r_security_parameters(secParams0, :application_traffic_secret)
    applicationTrafficSecret = :tls_v1.update_traffic_secret(hKDF,
                                                               applicationTrafficSecret0)
    keyLength = :tls_v1.key_length(cipherSuite)
    {key, iV} = :tls_v1.calculate_traffic_keys(hKDF,
                                                 keyLength,
                                                 applicationTrafficSecret)
    secParams = r_security_parameters(secParams0, application_traffic_secret: applicationTrafficSecret)
    cipherState = r_cipher_state(cipherState0, key: key,  iv: iV)
    connState = Map.merge(connState0, %{security_parameters:
                                        secParams,
                                          cipher_state: cipherState,
                                          sequence_number: 0})
    Map.put(cS0, connStateName, connState)
  end

  def callback_mode() do
    [:state_functions, :state_enter]
  end

  def init([role, sender, host, port, socket, options, user,
                                                         cbInfo]) do
    state0 = (r_state(protocol_specific: map) = initial_state(role,
                                                          sender, host, port,
                                                          socket, options, user,
                                                          cbInfo))
    try do
      state = :ssl_gen_statem.ssl_config(r_state(state0, :ssl_options),
                                           role, state0)
      :tls_gen_connection.initialize_tls_sender(state)
      :gen_statem.enter_loop(:tls_connection_1_3, [],
                               :initial_hello, state)
    catch
      error ->
        eState = r_state(state0, protocol_specific: Map.put(map, :error,
                                                             error))
        :gen_statem.enter_loop(:tls_connection_1_3, [],
                                 :config_error, eState)
    end
  end

  def terminate({:shutdown, {:sender_died, reason}}, _StateName,
           r_state(static_env: r_static_env(socket: socket,
                             transport_cb: transport)) = state) do
    :ssl_gen_statem.handle_trusted_certs_db(state)
    :tls_gen_connection.close(reason, socket, transport,
                                :undefined)
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
    :ssl_gen_statem.handle_own_alert(r_alert(level: 2,
                                         description: 90,
                                         where: %{mfa:
                                                  {:tls_connection_1_3,
                                                     :user_hello, 3},
                                                    line: 244, file: 'otp/lib/ssl/src/tls_connection_1_3.erl'},
                                         reason: :user_canceled),
                                       :user_hello, state)
  end

  def user_hello({:call, from},
           {:handshake_continue, newOptions, timeout},
           r_state(static_env: r_static_env(role: :client = role),
               handshake_env: hSEnv,
               ssl_options: options0) = state0) do
    options = :ssl.handle_options(newOptions, role,
                                    options0)
    state = :ssl_gen_statem.ssl_config(options, role,
                                         state0)
    {:next_state, :wait_sh,
       r_state(state, start_or_recv_from: from, 
                  handshake_env: r_handshake_env(hSEnv, continue_status: :continue)),
       [{{:timeout, :handshake}, timeout, :close}]}
  end

  def user_hello({:call, from},
           {:handshake_continue, newOptions, timeout},
           r_state(static_env: r_static_env(role: :server = role),
               handshake_env: r_handshake_env(continue_status: {:pause,
                                                    clientVersions}) = hSEnv,
               ssl_options: options0) = state0) do
    options = (%{versions:
                 versions} = :ssl.handle_options(newOptions, role,
                                                   options0))
    state = :ssl_gen_statem.ssl_config(options, role,
                                         state0)
    case (:ssl_handshake.select_supported_version(clientVersions,
                                                    versions)) do
      {3, 4} ->
        {:next_state, :start,
           r_state(state, start_or_recv_from: from, 
                      handshake_env: r_handshake_env(hSEnv, continue_status: :continue)),
           [{{:timeout, :handshake}, timeout, :close}]}
      :undefined ->
        :ssl_gen_statem.handle_own_alert(r_alert(level: 2,
                                             description: 70,
                                             where: %{mfa:
                                                      {:tls_connection_1_3,
                                                         :user_hello, 3},
                                                        line: 267, file: 'otp/lib/ssl/src/tls_connection_1_3.erl'}),
                                           :user_hello, state)
      _Else ->
        {:next_state, :hello,
           r_state(state, start_or_recv_from: from, 
                      handshake_env: r_handshake_env(hSEnv, continue_status: :continue)),
           [{:change_callback_module, :tls_connection}, {{:timeout,
                                                            :handshake},
                                                           timeout, :close}]}
    end
  end

  def user_hello(:info, {:DOWN, _, _, _, _} = event, state) do
    :ssl_gen_statem.handle_info(event, :user_hello, state)
  end

  def user_hello(_, _, _) do
    {:keep_state_and_data, [:postpone]}
  end

  def start(:enter, _, state0) do
    state = handle_middlebox(state0)
    {:next_state, :start, state, []}
  end

  def start(:internal = type, r_change_cipher_spec() = msg,
           r_state(static_env: r_static_env(role: :server),
               handshake_env: r_handshake_env(tls_handshake_history: hist)) = state) do
    case (:ssl_handshake.init_handshake_history()) do
      ^hist ->
        :ssl_gen_statem.handle_common_event(type, msg, :start,
                                              state)
      _ ->
        handle_change_cipher_spec(type, msg, :start, state)
    end
  end

  def start(:internal = type, r_change_cipher_spec() = msg, state) do
    handle_change_cipher_spec(type, msg, :start, state)
  end

  def start(:internal,
           r_client_hello(extensions: %{client_hello_versions:
                           r_client_hello_versions(versions: clientVersions)}) = hello,
           r_state(ssl_options: %{handshake: :full}) = state) do
    case (:tls_record.is_acceptable_version({3, 4},
                                              clientVersions)) do
      true ->
        do_server_start(hello, state)
      false ->
        :ssl_gen_statem.handle_own_alert(r_alert(level: 2,
                                             description: 70,
                                             where: %{mfa:
                                                      {:tls_connection_1_3,
                                                         :start, 3},
                                                        line: 301, file: 'otp/lib/ssl/src/tls_connection_1_3.erl'}),
                                           :start, state)
    end
  end

  def start(:internal,
           r_client_hello(extensions: %{client_hello_versions:
                           r_client_hello_versions(versions: clientVersions)} = extensions),
           r_state(start_or_recv_from: from,
               handshake_env: r_handshake_env(continue_status: :pause) = hSEnv) = state) do
    {:next_state, :user_hello,
       r_state(state, start_or_recv_from: :undefined, 
                  handshake_env: r_handshake_env(hSEnv, continue_status: {:pause,
                                                              clientVersions})),
       [{:postpone, true}, {:reply, from, {:ok, extensions}}]}
  end

  def start(:internal, r_client_hello() = hello,
           r_state(handshake_env: r_handshake_env(continue_status: :continue)) = state) do
    do_server_start(hello, state)
  end

  def start(:internal, r_client_hello(), state0) do
    :ssl_gen_statem.handle_own_alert(r_alert(level: 2,
                                         description: 70,
                                         where: %{mfa:
                                                  {:tls_connection_1_3, :start,
                                                     3},
                                                    line: 315, file: 'otp/lib/ssl/src/tls_connection_1_3.erl'}),
                                       :start, state0)
  end

  def start(:internal,
           r_server_hello(extensions: %{server_hello_selected_version:
                           r_server_hello_selected_version(selected_version: version)}) = serverHello,
           r_state(ssl_options: %{handshake: :full,
                              versions: supportedVersions}) = state) do
    case (:tls_record.is_acceptable_version(version,
                                              supportedVersions)) do
      true ->
        do_client_start(serverHello, state)
      false ->
        :ssl_gen_statem.handle_own_alert(r_alert(level: 2,
                                             description: 70,
                                             where: %{mfa:
                                                      {:tls_connection_1_3,
                                                         :start, 3},
                                                        line: 324, file: 'otp/lib/ssl/src/tls_connection_1_3.erl'}),
                                           :start, state)
    end
  end

  def start(:internal,
           r_server_hello(extensions: %{server_hello_selected_version:
                           r_server_hello_selected_version(selected_version: version)} = extensions),
           r_state(ssl_options: %{versions: supportedVersions},
               start_or_recv_from: from,
               handshake_env: r_handshake_env(continue_status: :pause)) = state) do
    case (:tls_record.is_acceptable_version(version,
                                              supportedVersions)) do
      true ->
        {:next_state, :user_hello,
           r_state(state, start_or_recv_from: :undefined),
           [{:postpone, true}, {:reply, from, {:ok, extensions}}]}
      false ->
        :ssl_gen_statem.handle_own_alert(r_alert(level: 2,
                                             description: 70,
                                             where: %{mfa:
                                                      {:tls_connection_1_3,
                                                         :start, 3},
                                                        line: 338, file: 'otp/lib/ssl/src/tls_connection_1_3.erl'}),
                                           :start, state)
    end
  end

  def start(:internal, r_server_hello() = serverHello,
           r_state(handshake_env: r_handshake_env(continue_status: :continue)) = state) do
    do_client_start(serverHello, state)
  end

  def start(:internal, r_server_hello(), state0) do
    :ssl_gen_statem.handle_own_alert(r_alert(level: 2,
                                         description: 70,
                                         where: %{mfa:
                                                  {:tls_connection_1_3, :start,
                                                     3},
                                                    line: 344, file: 'otp/lib/ssl/src/tls_connection_1_3.erl'}),
                                       :start, state0)
  end

  def start(:info, msg, state) do
    :tls_gen_connection.handle_info(msg, :start, state)
  end

  def start(type, msg, state) do
    :ssl_gen_statem.handle_common_event(type, msg, :start,
                                          state)
  end

  def negotiated(:enter, _, state0) do
    state = handle_middlebox(state0)
    {:next_state, :negotiated, state, []}
  end

  def negotiated(:internal = type, r_change_cipher_spec() = msg, state) do
    handle_change_cipher_spec(type, msg, :negotiated, state)
  end

  def negotiated(:internal, message, state0) do
    case (:tls_handshake_1_3.do_negotiated(message,
                                             state0)) do
      r_alert() = alert ->
        :ssl_gen_statem.handle_own_alert(alert, :negotiated,
                                           state0)
      {state, nextState} ->
        {:next_state, nextState, state, []}
    end
  end

  def negotiated(:info, msg, state) do
    :tls_gen_connection.handle_info(msg, :negotiated, state)
  end

  def wait_cert(:enter, _, state0) do
    state = handle_middlebox(state0)
    {:next_state, :wait_cert, state, []}
  end

  def wait_cert(:internal = type, r_change_cipher_spec() = msg, state) do
    handle_change_cipher_spec(type, msg, :wait_cert, state)
  end

  def wait_cert(:internal, r_certificate_1_3() = certificate, state0) do
    case (:tls_handshake_1_3.do_wait_cert(certificate,
                                            state0)) do
      {r_alert() = alert, state} ->
        :ssl_gen_statem.handle_own_alert(alert, :wait_cert,
                                           state)
      {state, nextState} ->
        :tls_gen_connection.next_event(nextState, :no_record,
                                         state)
    end
  end

  def wait_cert(:info, msg, state) do
    :tls_gen_connection.handle_info(msg, :wait_cert, state)
  end

  def wait_cert(type, msg, state) do
    :ssl_gen_statem.handle_common_event(type, msg,
                                          :wait_cert, state)
  end

  def wait_cv(:enter, _, state0) do
    state = handle_middlebox(state0)
    {:next_state, :wait_cv, state, []}
  end

  def wait_cv(:internal = type, r_change_cipher_spec() = msg, state) do
    handle_change_cipher_spec(type, msg, :wait_cv, state)
  end

  def wait_cv(:internal, r_certificate_verify_1_3() = certificateVerify, state0) do
    case (:tls_handshake_1_3.do_wait_cv(certificateVerify,
                                          state0)) do
      {r_alert() = alert, state} ->
        :ssl_gen_statem.handle_own_alert(alert, :wait_cv, state)
      {state, nextState} ->
        :tls_gen_connection.next_event(nextState, :no_record,
                                         state)
    end
  end

  def wait_cv(:info, msg, state) do
    :tls_gen_connection.handle_info(msg, :wait_cv, state)
  end

  def wait_cv(type, msg, state) do
    :ssl_gen_statem.handle_common_event(type, msg, :wait_cv,
                                          state)
  end

  def wait_finished(:enter, _, state0) do
    state = handle_middlebox(state0)
    {:next_state, :wait_finished, state, []}
  end

  def wait_finished(:internal = type, r_change_cipher_spec() = msg, state) do
    handle_change_cipher_spec(type, msg, :wait_finished,
                                state)
  end

  def wait_finished(:internal, r_finished() = finished, state0) do
    case (:tls_handshake_1_3.do_wait_finished(finished,
                                                state0)) do
      r_alert() = alert ->
        :ssl_gen_statem.handle_own_alert(alert, :finished,
                                           state0)
      state1 ->
        {record,
           state} = :ssl_gen_statem.prepare_connection(state1,
                                                         :tls_gen_connection)
        :tls_gen_connection.next_event(:connection, record,
                                         state,
                                         [{{:timeout, :handshake}, :cancel}])
    end
  end

  def wait_finished(:info, msg, state) do
    :tls_gen_connection.handle_info(msg, :wait_finished,
                                      state)
  end

  def wait_finished(type, msg, state) do
    :ssl_gen_statem.handle_common_event(type, msg,
                                          :wait_finished, state)
  end

  def wait_sh(:enter, _, state0) do
    state = handle_middlebox(state0)
    {:next_state, :wait_sh, state, []}
  end

  def wait_sh(:internal = type, r_change_cipher_spec() = msg, state) do
    handle_change_cipher_spec(type, msg, :wait_sh, state)
  end

  def wait_sh(:internal, r_server_hello(extensions: extensions),
           r_state(handshake_env: r_handshake_env(continue_status: :pause),
               start_or_recv_from: from) = state) do
    {:next_state, :user_hello,
       r_state(state, start_or_recv_from: :undefined),
       [{:postpone, true}, {:reply, from, {:ok, extensions}}]}
  end

  def wait_sh(:internal, r_server_hello(session_id: <<>>) = hello,
           r_state(session: r_session(session_id: <<>>),
               ssl_options: %{middlebox_comp_mode: false}) = state0) do
    case (:tls_handshake_1_3.do_wait_sh(hello, state0)) do
      r_alert() = alert ->
        :ssl_gen_statem.handle_own_alert(alert, :wait_sh,
                                           state0)
      {state1, :start, serverHello} ->
        {:next_state, :start, state1,
           [{:next_event, :internal, serverHello}]}
      {state1, :wait_ee} ->
        :tls_gen_connection.next_event(:wait_ee, :no_record,
                                         state1)
    end
  end

  def wait_sh(:internal, r_server_hello() = hello,
           r_state(protocol_specific: pS,
               ssl_options: %{middlebox_comp_mode: true}) = state0) do
    isRetry = :maps.get(:hello_retry, pS, false)
    case (:tls_handshake_1_3.do_wait_sh(hello, state0)) do
      r_alert() = alert ->
        :ssl_gen_statem.handle_own_alert(alert, :wait_sh,
                                           state0)
      {state1 = r_state(), :start, serverHello} ->
        {:next_state, :start, state1,
           [{:next_event, :internal, serverHello}]}
      {state1, :wait_ee} when isRetry == true ->
        :tls_gen_connection.next_event(:wait_ee, :no_record,
                                         state1)
      {state1, :wait_ee} when isRetry == false ->
        :tls_gen_connection.next_event(:hello_middlebox_assert,
                                         :no_record, state1)
    end
  end

  def wait_sh(:info, msg, state) do
    :tls_gen_connection.handle_info(msg, :wait_sh, state)
  end

  def wait_sh(type, msg, state) do
    :ssl_gen_statem.handle_common_event(type, msg, :wait_sh,
                                          state)
  end

  def hello_middlebox_assert(:enter, _, state) do
    {:keep_state, state}
  end

  def hello_middlebox_assert(:internal, r_change_cipher_spec(), state) do
    :tls_gen_connection.next_event(:wait_ee, :no_record,
                                     state)
  end

  def hello_middlebox_assert(:info, msg, state) do
    :tls_gen_connection.handle_info(msg,
                                      :hello_middlebox_assert, state)
  end

  def hello_middlebox_assert(type, msg, state) do
    :ssl_gen_statem.handle_common_event(type, msg,
                                          :hello_middlebox_assert, state)
  end

  def hello_retry_middlebox_assert(:enter, _, state) do
    {:keep_state, state}
  end

  def hello_retry_middlebox_assert(:internal, r_change_cipher_spec(), state) do
    :tls_gen_connection.next_event(:wait_sh, :no_record,
                                     state)
  end

  def hello_retry_middlebox_assert(:internal, r_server_hello(), state) do
    :tls_gen_connection.next_event(:hello_retry_middlebox_assert,
                                     :no_record, state, [:postpone])
  end

  def hello_retry_middlebox_assert(:info, msg, state) do
    :tls_gen_connection.handle_info(msg,
                                      :hello_retry_middlebox_assert, state)
  end

  def hello_retry_middlebox_assert(type, msg, state) do
    :ssl_gen_statem.handle_common_event(type, msg,
                                          :hello_retry_middlebox_assert, state)
  end

  def wait_ee(:enter, _, state0) do
    state = handle_middlebox(state0)
    {:next_state, :wait_ee, state, []}
  end

  def wait_ee(:internal = type, r_change_cipher_spec() = msg, state) do
    handle_change_cipher_spec(type, msg, :wait_ee, state)
  end

  def wait_ee(:internal, r_encrypted_extensions() = eE, state0) do
    case (:tls_handshake_1_3.do_wait_ee(eE, state0)) do
      r_alert() = alert ->
        :ssl_gen_statem.handle_own_alert(alert, :wait_ee,
                                           state0)
      {state1, nextState} ->
        :tls_gen_connection.next_event(nextState, :no_record,
                                         state1)
    end
  end

  def wait_ee(:info, msg, state) do
    :tls_gen_connection.handle_info(msg, :wait_ee, state)
  end

  def wait_ee(type, msg, state) do
    :ssl_gen_statem.handle_common_event(type, msg, :wait_ee,
                                          state)
  end

  def wait_cert_cr(:enter, _, state0) do
    state = handle_middlebox(state0)
    {:next_state, :wait_cert_cr, state, []}
  end

  def wait_cert_cr(:internal = type, r_change_cipher_spec() = msg, state) do
    handle_change_cipher_spec(type, msg, :wait_cert_cr,
                                state)
  end

  def wait_cert_cr(:internal, r_certificate_1_3() = certificate, state0) do
    case (:tls_handshake_1_3.do_wait_cert_cr(certificate,
                                               state0)) do
      {r_alert() = alert, state} ->
        :ssl_gen_statem.handle_own_alert(alert, :wait_cert_cr,
                                           state)
      {state1, nextState} ->
        :tls_gen_connection.next_event(nextState, :no_record,
                                         state1)
    end
  end

  def wait_cert_cr(:internal, r_certificate_request_1_3() = certificateRequest, state0) do
    case (:tls_handshake_1_3.do_wait_cert_cr(certificateRequest,
                                               state0)) do
      r_alert() = alert ->
        :ssl_gen_statem.handle_own_alert(alert, :wait_cert_cr,
                                           state0)
      {state1, nextState} ->
        :tls_gen_connection.next_event(nextState, :no_record,
                                         state1)
    end
  end

  def wait_cert_cr(:info, msg, state) do
    :tls_gen_connection.handle_info(msg, :wait_cert_cr,
                                      state)
  end

  def wait_cert_cr(type, msg, state) do
    :ssl_gen_statem.handle_common_event(type, msg,
                                          :wait_cert_cr, state)
  end

  def wait_eoed(:enter, _, state0) do
    state = handle_middlebox(state0)
    {:next_state, :wait_eoed, state, []}
  end

  def wait_eoed(:internal = type, r_change_cipher_spec() = msg, state) do
    handle_change_cipher_spec(type, msg, :wait_eoed, state)
  end

  def wait_eoed(:internal, r_end_of_early_data() = eOED, state0) do
    case (:tls_handshake_1_3.do_wait_eoed(eOED, state0)) do
      {r_alert() = alert, state} ->
        :ssl_gen_statem.handle_own_alert(alert, :wait_eoed,
                                           state)
      {state1, nextState} ->
        :tls_gen_connection.next_event(nextState, :no_record,
                                         state1)
    end
  end

  def wait_eoed(:info, msg, state) do
    :tls_gen_connection.handle_info(msg, :wait_eoed, state)
  end

  def wait_eoed(type, msg, state) do
    :ssl_gen_statem.handle_common_event(type, msg,
                                          :wait_eoed, state)
  end

  def connection(:enter, _, state) do
    {:keep_state, state}
  end

  def connection(:internal, r_new_session_ticket() = newSessionTicket, state) do
    handle_new_session_ticket(newSessionTicket, state)
    :tls_gen_connection.next_event(:connection, :no_record,
                                     state)
  end

  def connection(:internal, r_key_update() = keyUpdate, state0) do
    case (handle_key_update(keyUpdate, state0)) do
      {:ok, state} ->
        :tls_gen_connection.next_event(:connection, :no_record,
                                         state)
      {:error, state, alert} ->
        :ssl_gen_statem.handle_own_alert(alert, :connection,
                                           state)
        :tls_gen_connection.next_event(:connection, :no_record,
                                         state)
    end
  end

  def connection({:call, from}, :negotiated_protocol,
           r_state(handshake_env: r_handshake_env(alpn: :undefined)) = state) do
    :ssl_gen_statem.hibernate_after(:connection, state,
                                      [{:reply, from,
                                          {:error, :protocol_not_negotiated}}])
  end

  def connection({:call, from}, :negotiated_protocol,
           r_state(handshake_env: r_handshake_env(alpn: selectedProtocol,
                                negotiated_protocol: :undefined)) = state) do
    :ssl_gen_statem.hibernate_after(:connection, state,
                                      [{:reply, from, {:ok, selectedProtocol}}])
  end

  def connection(type, event, state) do
    :ssl_gen_statem.connection(type, event, state)
  end

  def downgrade(:enter, _, state) do
    {:keep_state, state}
  end

  def downgrade(:internal, r_new_session_ticket() = newSessionTicket, state) do
    _ = handle_new_session_ticket(newSessionTicket, state)
    {:next_state, :downgrade, state}
  end

  def downgrade(type, event, state) do
    :ssl_gen_statem.downgrade(type, event, state)
  end

  defp do_server_start(clientHello, state0) do
    case (:tls_handshake_1_3.do_start(clientHello,
                                        state0)) do
      r_alert() = alert ->
        :ssl_gen_statem.handle_own_alert(alert, :start, state0)
      {state, :start} ->
        {:next_state, :start, state, []}
      {state, :negotiated} ->
        {:next_state, :negotiated, state,
           [{:next_event, :internal,
               {:start_handshake, :undefined}}]}
      {state, :negotiated, pSK} ->
        {:next_state, :negotiated, state,
           [{:next_event, :internal, {:start_handshake, pSK}}]}
    end
  end

  defp do_client_start(serverHello, state0) do
    case (:tls_handshake_1_3.do_start(serverHello,
                                        state0)) do
      r_alert() = alert ->
        :ssl_gen_statem.handle_own_alert(alert, :start, state0)
      {state, nextState} ->
        {:next_state, nextState, state, []}
    end
  end

  defp initial_state(role, sender, host, port, socket,
            {sSLOptions, socketOptions, trackers}, user,
            {cbModule, dataTag, closeTag, errorTag, passiveTag}) do
    :erlang.put(:log_level,
                  :maps.get(:log_level, sSLOptions))
    %{erl_dist: isErlDist, versions: [version | _],
        client_renegotiation: clientRenegotiation} = sSLOptions
    maxEarlyDataSize = init_max_early_data_size(role)
    connectionStates = :tls_record.init_connection_states(role,
                                                            version, :disabled,
                                                            maxEarlyDataSize)
    userMonitor = :erlang.monitor(:process, user)
    initStatEnv = r_static_env(role: role, transport_cb: cbModule,
                      protocol_cb: :tls_gen_connection, data_tag: dataTag,
                      close_tag: closeTag, error_tag: errorTag,
                      passive_tag: passiveTag, host: host, port: port,
                      socket: socket, trackers: trackers)
    r_state(static_env: initStatEnv,
        handshake_env: r_handshake_env(tls_handshake_history: :ssl_handshake.init_handshake_history(),
                           renegotiation: {false, :first},
                           allow_renegotiate: clientRenegotiation),
        connection_env: r_connection_env(user_application: {userMonitor,
                                               user}),
        socket_options: socketOptions, ssl_options: sSLOptions,
        session: r_session(is_resumable: false,
                     session_id: :ssl_session.legacy_session_id(sSLOptions)),
        connection_states: connectionStates,
        protocol_buffers: r_protocol_buffers(), user_data_buffer: {[], 0, []},
        start_or_recv_from: :undefined, flight_buffer: [],
        protocol_specific: %{sender: sender,
                               active_n: internal_active_n(isErlDist),
                               active_n_toggle: true})
  end

  defp internal_active_n(true) do
    rem(:erlang.system_time(), 100) + 1
  end

  defp internal_active_n(false) do
    case (:application.get_env(:ssl, :internal_active_n)) do
      {:ok, n} when is_integer(n) ->
        n
      _ ->
        100
    end
  end

  defp handle_new_session_ticket(_,
            r_state(ssl_options: %{session_tickets: :disabled})) do
    :ok
  end

  defp handle_new_session_ticket(r_new_session_ticket(ticket_nonce: nonce) = newSessionTicket,
            r_state(connection_states: connectionStates,
                ssl_options: %{session_tickets: sessionTickets,
                                 server_name_indication: sNI},
                connection_env: r_connection_env(user_application: {_, user})))
      when sessionTickets === :manual do
    %{security_parameters:
      secParams} = :ssl_record.current_connection_state(connectionStates,
                                                          :read)
    cipherSuite = r_security_parameters(secParams, :cipher_suite)
    %{cipher:
      cipher} = :ssl_cipher_format.suite_bin_to_map(cipherSuite)
    hKDF = r_security_parameters(secParams, :prf_algorithm)
    rMS = r_security_parameters(secParams, :resumption_master_secret)
    pSK = :tls_v1.pre_shared_key(rMS, nonce, hKDF)
    send_ticket_data(user, newSessionTicket, {cipher, hKDF},
                       sNI, pSK)
  end

  defp handle_new_session_ticket(r_new_session_ticket(ticket_nonce: nonce) = newSessionTicket,
            r_state(connection_states: connectionStates,
                ssl_options: %{session_tickets: sessionTickets,
                                 server_name_indication: sNI}))
      when sessionTickets === :auto do
    %{security_parameters:
      secParams} = :ssl_record.current_connection_state(connectionStates,
                                                          :read)
    cipherSuite = r_security_parameters(secParams, :cipher_suite)
    %{cipher:
      cipher} = :ssl_cipher_format.suite_bin_to_map(cipherSuite)
    hKDF = r_security_parameters(secParams, :prf_algorithm)
    rMS = r_security_parameters(secParams, :resumption_master_secret)
    pSK = :tls_v1.pre_shared_key(rMS, nonce, hKDF)
    :tls_client_ticket_store.store_ticket(newSessionTicket,
                                            {cipher, hKDF}, sNI, pSK)
  end

  defp send_ticket_data(user, newSessionTicket, cipherSuite, sNI,
            pSK) do
    timestamp = :erlang.system_time(:millisecond)
    ticketData = %{cipher_suite: cipherSuite, sni: sNI,
                     psk: pSK, timestamp: timestamp,
                     ticket: newSessionTicket}
    send(user, {:ssl, :session_ticket, ticketData})
  end

  defp handle_key_update(r_key_update(request_update: :update_not_requested),
            state0) do
    {:ok, update_cipher_key(:current_read, state0)}
  end

  defp handle_key_update(r_key_update(request_update: :update_requested),
            r_state(protocol_specific: %{sender: sender}) = state0) do
    state1 = update_cipher_key(:current_read, state0)
    case (send_key_update(sender, :update_not_requested)) do
      :ok ->
        {:ok, state1}
      {:error, reason} ->
        {:error, state1,
           r_alert(level: 2, description: 80,
               where: %{mfa:
                        {:tls_connection_1_3, :handle_key_update, 2},
                          line: 714, file: 'otp/lib/ssl/src/tls_connection_1_3.erl'},
               reason: reason)}
    end
  end

  defp init_max_early_data_size(:client) do
    0
  end

  defp init_max_early_data_size(:server) do
    :ssl_config.get_max_early_data_size()
  end

  defp handle_middlebox(r_state(protocol_specific: pS) = state0) do
    r_state(state0, protocol_specific: Map.put(pS, :change_cipher_spec,
                                               :ignore))
  end

  defp handle_change_cipher_spec(type, msg, stateName,
            r_state(protocol_specific: pS0) = state) do
    case (:maps.get(:change_cipher_spec, pS0)) do
      :ignore ->
        pS = Map.put(pS0, :change_cipher_spec, :fail)
        :tls_gen_connection.next_event(stateName, :no_record,
                                         r_state(state, protocol_specific: pS))
      :fail ->
        :ssl_gen_statem.handle_common_event(type, msg,
                                              stateName, state)
    end
  end

end