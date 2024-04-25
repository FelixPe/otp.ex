defmodule :m_tls_dtls_connection do
  use Bitwise
  require Record
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
  Record.defrecord(:r_sslsocket, :sslsocket, fd: nil, pid: nil)
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
                                               server_random: :undefined)
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
  Record.defrecord(:r_use_srtp, :use_srtp, protection_profiles: :undefined,
                                    mki: :undefined)
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
                                            timestamp: :undefined,
                                            certificate: :undefined)
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
  Record.defrecord(:r_alert, :alert, level: :undefined,
                                 description: :undefined, where: :undefined,
                                 role: :undefined, reason: :undefined)
  def internal_renegotiation(connectionPid, %{current_write: writeState}) do
    :gen_statem.cast(connectionPid,
                       {:internal_renegotiate, writeState})
  end

  def renegotiation(connectionPid) do
    :ssl_gen_statem.call(connectionPid, :renegotiate)
  end

  def renegotiation(pid, writeState) do
    :ssl_gen_statem.call(pid,
                           {:user_renegotiate, writeState})
  end

  def handle_session(r_server_hello(cipher_suite: cipherSuite,
             compression_method: compression),
           version, newId, connectionStates, protoExt, protocol0,
           r_state(session: session,
               handshake_env: r_handshake_env(negotiated_protocol: currentProtocol) = hsEnv,
               connection_env: r_connection_env(negotiated_version: reqVersion) = cEnv) = state0) do
    %{key_exchange:
      keyAlgorithm} = :ssl_cipher_format.suite_bin_to_map(cipherSuite)
    premasterSecret = make_premaster_secret(reqVersion,
                                              keyAlgorithm)
    {expectNPN, protocol} = (case (protocol0) do
                               :undefined ->
                                 {false, currentProtocol}
                               _ ->
                                 {protoExt === :npn, protocol0}
                             end)
    state = r_state(state0, connection_states: connectionStates, 
                        handshake_env: r_handshake_env(hsEnv, kex_algorithm: keyAlgorithm, 
                                                  premaster_secret: premasterSecret, 
                                                  expecting_next_protocol_negotiation: expectNPN, 
                                                  negotiated_protocol: protocol), 
                        connection_env: r_connection_env(cEnv, negotiated_version: version))
    case (:ssl_session.is_new(session, newId)) do
      true ->
        handle_new_session(newId, cipherSuite, compression,
                             r_state(state, connection_states: connectionStates))
      false ->
        handle_resumed_session(newId,
                                 r_state(state, connection_states: connectionStates))
    end
  end

  def hello({:call, from}, msg, state) do
    handle_call(msg, from, :hello, state)
  end

  def hello(:internal,
           {:common_client_hello, type, serverHelloExt}, state) do
    do_server_hello(type, serverHelloExt, state)
  end

  def hello(:info, msg, state) do
    handle_info(msg, :hello, state)
  end

  def hello(:internal, r_hello_request(), _) do
    :keep_state_and_data
  end

  def hello(type, event, state) do
    :ssl_gen_statem.handle_common_event(type, event, :hello,
                                          state)
  end

  def user_hello({:call, from}, :cancel, _State) do
    :gen_statem.reply(from, :ok)
    throw(r_alert(level: 2, description: 90,
              where: %{mfa: {:tls_dtls_connection, :user_hello, 3},
                         line: 163, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'},
              reason: :user_canceled))
  end

  def user_hello({:call, from},
           {:handshake_continue, newOptions, timeout},
           r_state(static_env: r_static_env(role: role), handshake_env: hSEnv,
               ssl_options: options0) = state0) do
    try do
      :ssl.update_options(newOptions, role, options0)
    catch
      {:error, reason} ->
        :gen_statem.reply(from, {:error, reason})
        :ssl_gen_statem.handle_own_alert(r_alert(level: 2,
                                             description: 80,
                                             where: %{mfa:
                                                      {:tls_dtls_connection,
                                                         :user_hello, 3},
                                                        line: 178, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'},
                                             reason: reason),
                                           :user_hello, state0)
    else
      options ->
        state = :ssl_gen_statem.ssl_config(options, role,
                                             state0)
        {:next_state, :hello,
           r_state(state, start_or_recv_from: from, 
                      handshake_env: r_handshake_env(hSEnv, continue_status: :continue)),
           [{{:timeout, :handshake}, timeout, :close}]}
    end
  end

  def user_hello(:info, {:DOWN, _, _, _, _} = event, state) do
    :ssl_gen_statem.handle_info(event, :user_hello, state)
  end

  def user_hello(_, _, _) do
    {:keep_state_and_data, [:postpone]}
  end

  def abbreviated({:call, from}, msg, state) do
    handle_call(msg, from, :abbreviated, state)
  end

  def abbreviated(:internal, r_finished(verify_data: data) = finished,
           r_state(static_env: r_static_env(role: :server, protocol_cb: connection),
               handshake_env: r_handshake_env(tls_handshake_history: hist,
                                  expecting_finished: true) = hsEnv,
               connection_env: r_connection_env(negotiated_version: version),
               session: r_session(master_secret: masterSecret),
               connection_states: connectionStates0) = state0) do
    case (:ssl_handshake.verify_connection(:ssl.tls_version(version),
                                             finished, :client,
                                             get_current_prf(connectionStates0,
                                                               :write),
                                             masterSecret, hist)) do
      :verified ->
        connectionStates = :ssl_record.set_client_verify_data(:current_both,
                                                                data,
                                                                connectionStates0)
        {record,
           state} = :ssl_gen_statem.prepare_connection(r_state(state0, connection_states: connectionStates, 
                                                                   handshake_env: r_handshake_env(hsEnv, expecting_finished: false)),
                                                         connection)
        connection.next_event(:connection, record, state,
                                [{{:timeout, :handshake}, :infinity, :close}])
      r_alert() = alert ->
        throw(alert)
    end
  end

  def abbreviated(:internal, r_finished(verify_data: data) = finished,
           r_state(static_env: r_static_env(role: :client, protocol_cb: connection),
               handshake_env: r_handshake_env(tls_handshake_history: hist0),
               connection_env: r_connection_env(negotiated_version: version),
               session: r_session(master_secret: masterSecret),
               connection_states: connectionStates0) = state0) do
    case (:ssl_handshake.verify_connection(:ssl.tls_version(version),
                                             finished, :server,
                                             get_pending_prf(connectionStates0,
                                                               :write),
                                             masterSecret, hist0)) do
      :verified ->
        connectionStates1 = :ssl_record.set_server_verify_data(:current_read,
                                                                 data,
                                                                 connectionStates0)
        {r_state(handshake_env: hsEnv) = state1,
           actions} = finalize_handshake(r_state(state0, connection_states: connectionStates1),
                                           :abbreviated, connection)
        {record,
           state} = :ssl_gen_statem.prepare_connection(r_state(state1, handshake_env: r_handshake_env(hsEnv, expecting_finished: false)),
                                                         connection)
        connection.next_event(:connection, record, state,
                                [{{:timeout, :handshake}, :infinity, :close} |
                                     actions])
      r_alert() = alert ->
        throw(alert)
    end
  end

  def abbreviated(:internal,
           r_next_protocol(selected_protocol: selectedProtocol),
           r_state(static_env: r_static_env(role: :server, protocol_cb: connection),
               handshake_env: r_handshake_env(expecting_next_protocol_negotiation: true) = hsEnv) = state) do
    connection.next_event(:abbreviated, :no_record,
                            r_state(state, handshake_env: r_handshake_env(hsEnv, negotiated_protocol: selectedProtocol, 
                                                               expecting_next_protocol_negotiation: false)))
  end

  def abbreviated(:internal, r_change_cipher_spec(type: <<1>>),
           r_state(static_env: r_static_env(protocol_cb: connection),
               connection_states: connectionStates0,
               handshake_env: hsEnv) = state) do
    connectionStates1 = :ssl_record.activate_pending_connection_state(connectionStates0,
                                                                        :read,
                                                                        connection)
    connection.next_event(:abbreviated, :no_record,
                            r_state(state, connection_states: connectionStates1, 
                                       handshake_env: r_handshake_env(hsEnv, expecting_finished: true)))
  end

  def abbreviated(:info, msg, state) do
    handle_info(msg, :abbreviated, state)
  end

  def abbreviated(:internal, r_hello_request(), _) do
    :keep_state_and_data
  end

  def abbreviated(type, event, state) do
    :ssl_gen_statem.handle_common_event(type, event,
                                          :abbreviated, state)
  end

  def wait_ocsp_stapling(:internal, r_certificate(),
           r_state(static_env: r_static_env(protocol_cb: _Connection)) = state) do
    {:next_state, :wait_ocsp_stapling, state,
       [{:postpone, true}]}
  end

  def wait_ocsp_stapling(:internal, r_certificate_status() = certStatus,
           r_state(static_env: r_static_env(protocol_cb: _Connection),
               handshake_env: r_handshake_env(ocsp_stapling_state: ocspState) = hsEnv) = state) do
    {:next_state, :certify,
       r_state(state, handshake_env: r_handshake_env(hsEnv, ocsp_stapling_state: Map.merge(ocspState, %{ocsp_expect:
                                                                                    :stapled,
                                                                                      ocsp_response:
                                                                                      certStatus})))}
  end

  def wait_ocsp_stapling(:internal, msg,
           r_state(static_env: r_static_env(protocol_cb: _Connection),
               handshake_env: r_handshake_env(ocsp_stapling_state: ocspState) = hsEnv) = state)
      when elem(msg, 0) === :server_key_exchange or elem(msg, 0) === :hello_request or elem(msg, 0) === :certificate_request or elem(msg, 0) === :server_hello_done or elem(msg, 0) === :client_key_exchange do
    {:next_state, :certify,
       r_state(state, handshake_env: r_handshake_env(hsEnv, ocsp_stapling_state: Map.put(ocspState, :ocsp_expect,
                                                                                  :undetermined))),
       [{:postpone, true}]}
  end

  def wait_ocsp_stapling(:internal, r_hello_request(), _) do
    :keep_state_and_data
  end

  def wait_ocsp_stapling(type, event, state) do
    :ssl_gen_statem.handle_common_event(type, event,
                                          :wait_ocsp_stapling, state)
  end

  def certify({:call, from}, msg, state) do
    handle_call(msg, from, :certify, state)
  end

  def certify(:info, msg, state) do
    handle_info(msg, :certify, state)
  end

  def certify(:internal, r_certificate(asn1_certificates: []),
           r_state(static_env: r_static_env(role: :server),
               ssl_options: %{verify: :verify_peer,
                                fail_if_no_peer_cert: true})) do
    throw(r_alert(level: 2, description: 40,
              where: %{mfa: {:tls_dtls_connection, :certify, 3},
                         line: 320, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'},
              reason: :no_client_certificate_provided))
  end

  def certify(:internal, r_certificate(asn1_certificates: []),
           r_state(static_env: r_static_env(role: :server, protocol_cb: connection),
               ssl_options: %{verify: :verify_peer,
                                fail_if_no_peer_cert: false}) = state0) do
    connection.next_event(:certify, :no_record,
                            r_state(state0, client_certificate_status: :empty))
  end

  def certify(:internal, r_certificate(),
           r_state(static_env: r_static_env(role: :server),
               ssl_options: %{verify: :verify_none})) do
    throw(r_alert(level: 2, description: 10,
              where: %{mfa: {:tls_dtls_connection, :certify, 3},
                         line: 331, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'},
              reason: :unrequested_certificate))
  end

  def certify(:internal, r_certificate(),
           r_state(static_env: r_static_env(protocol_cb: connection),
               handshake_env: r_handshake_env(ocsp_stapling_state: %{ocsp_expect:
                                                       :staple})) = state) do
    connection.next_event(:wait_ocsp_stapling, :no_record,
                            state, [{:postpone, true}])
  end

  def certify(:internal,
           r_certificate(asn1_certificates: [peer | _]) = cert,
           r_state(static_env: r_static_env(role: role, host: host,
                             protocol_cb: connection, cert_db: certDbHandle,
                             cert_db_ref: certDbRef, crl_db: cRLDbInfo),
               handshake_env: r_handshake_env(ocsp_stapling_state: %{ocsp_expect:
                                                       status} = ocspState),
               connection_env: r_connection_env(negotiated_version: version),
               ssl_options: opts) = state0)
      when status !== :staple do
    ocspInfo = ocsp_info(ocspState, opts, peer)
    case (:ssl_handshake.certify(cert, certDbHandle,
                                   certDbRef, opts, cRLDbInfo, role, host,
                                   ensure_tls(version), ocspInfo)) do
      {peerCert, publicKeyInfo} ->
        state = (case (role) do
                   :server ->
                     r_state(state0, client_certificate_status: :needs_verifying)
                   :client ->
                     state0
                 end)
        handle_peer_cert(role, peerCert, publicKeyInfo, state,
                           connection, [])
      r_alert() = alert ->
        throw(alert)
    end
  end

  def certify(:internal, r_server_key_exchange(exchange_keys: keys),
           r_state(static_env: r_static_env(role: :client, protocol_cb: connection),
               handshake_env: r_handshake_env(kex_algorithm: kexAlg,
                                  public_key_info: pubKeyInfo) = hsEnv,
               connection_env: r_connection_env(negotiated_version: version),
               session: session,
               connection_states: connectionStates) = state)
      when kexAlg == :dhe_dss or kexAlg == :dhe_rsa or
             kexAlg == :ecdhe_rsa or kexAlg == :ecdhe_ecdsa or
             kexAlg == :dh_anon or kexAlg == :ecdh_anon or
             kexAlg == :psk or kexAlg == :dhe_psk or
             kexAlg == :ecdhe_psk or kexAlg == :rsa_psk or
             kexAlg == :srp_dss or kexAlg == :srp_rsa or
             kexAlg == :srp_anon do
    params = :ssl_handshake.decode_server_key(keys, kexAlg,
                                                :ssl.tls_version(version))
    hashSign = negotiated_hashsign(r_server_key_params(params, :hashsign),
                                     kexAlg, pubKeyInfo,
                                     :ssl.tls_version(version))
    case (is_anonymous(kexAlg)) do
      true ->
        calculate_secret(r_server_key_params(params, :params),
                           r_state(state, handshake_env: r_handshake_env(hsEnv, hashsign_algorithm: hashSign)),
                           connection)
      false ->
        case (:ssl_handshake.verify_server_key(params, hashSign,
                                                 connectionStates,
                                                 :ssl.tls_version(version),
                                                 pubKeyInfo)) do
          true ->
            calculate_secret(r_server_key_params(params, :params),
                               r_state(state, handshake_env: r_handshake_env(hsEnv, hashsign_algorithm: hashSign), 
                                          session: session_handle_params(r_server_key_params(params, :params),
                                                                           session)),
                               connection)
          false ->
            throw(r_alert(level: 2, description: 51,
                      where: %{mfa: {:tls_dtls_connection, :certify, 3},
                                 line: 405, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'}))
        end
    end
  end

  def certify(:internal, r_certificate_request(),
           r_state(static_env: r_static_env(role: :client),
               handshake_env: r_handshake_env(kex_algorithm: kexAlg)))
      when kexAlg == :dh_anon or kexAlg == :ecdh_anon or
             kexAlg == :psk or kexAlg == :dhe_psk or
             kexAlg == :ecdhe_psk or kexAlg == :rsa_psk or
             kexAlg == :srp_dss or kexAlg == :srp_rsa or
             kexAlg == :srp_anon do
    throw(r_alert(level: 2, description: 40,
              where: %{mfa: {:tls_dtls_connection, :certify, 3},
                         line: 420, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'}))
  end

  def certify(:internal, r_certificate_request(),
           r_state(static_env: r_static_env(role: :client, protocol_cb: connection),
               session: session0,
               connection_env: r_connection_env(cert_key_alts: [%{certs:
                                                   [[]]}])) = state) do
    connection.next_event(:certify, :no_record,
                            r_state(state, client_certificate_status: :requested, 
                                       session: r_session(session0, own_certificates: [[]], 
                                                              private_key: %{})))
  end

  def certify(:internal, r_certificate_request() = certRequest,
           r_state(static_env: r_static_env(role: :client, protocol_cb: connection,
                             cert_db: certDbHandle, cert_db_ref: certDbRef),
               connection_env: r_connection_env(negotiated_version: version,
                                   cert_key_alts: certKeyAlts),
               session: session0,
               ssl_options: %{signature_algs:
                              supportedHashSigns}) = state) do
    tLSVersion = :ssl.tls_version(version)
    certKeyPairs = :ssl_certificate.available_cert_key_pairs(certKeyAlts,
                                                               :ssl.tls_version(version))
    session = select_client_cert_key_pair(session0,
                                            certRequest, certKeyPairs,
                                            supportedHashSigns, tLSVersion,
                                            certDbHandle, certDbRef)
    connection.next_event(:certify, :no_record,
                            r_state(state, client_certificate_status: :requested, 
                                       session: session))
  end

  def certify(:internal, r_server_hello_done(),
           r_state(static_env: r_static_env(role: :client, protocol_cb: connection),
               session: r_session(master_secret: :undefined),
               handshake_env: r_handshake_env(kex_algorithm: kexAlg,
                                  premaster_secret: :undefined,
                                  server_psk_identity: pSKIdentity) = hsEnv,
               ssl_options: %{user_lookup_fun: pSKLookup}) = state0)
      when kexAlg == :psk do
    case (:ssl_handshake.premaster_secret({kexAlg,
                                             pSKIdentity},
                                            pSKLookup)) do
      r_alert() = alert ->
        throw(alert)
      premasterSecret ->
        state = master_secret(premasterSecret,
                                r_state(state0, handshake_env: r_handshake_env(hsEnv, premaster_secret: premasterSecret)))
        client_certify_and_key_exchange(state, connection)
    end
  end

  def certify(:internal, r_server_hello_done(),
           r_state(static_env: r_static_env(role: :client, protocol_cb: connection),
               connection_env: r_connection_env(negotiated_version: {major, minor}),
               handshake_env: r_handshake_env(kex_algorithm: kexAlg,
                                  premaster_secret: :undefined,
                                  server_psk_identity: pSKIdentity) = hsEnv,
               session: r_session(master_secret: :undefined),
               ssl_options: %{user_lookup_fun: pSKLookup}) = state0)
      when kexAlg == :rsa_psk do
    rand = :ssl_cipher.random_bytes(48 - 2)
    rSAPremasterSecret = <<major
                           ::
                           size(8) - unsigned - big - integer,
                             minor :: size(8) - unsigned - big - integer,
                             rand :: binary>>
    case (:ssl_handshake.premaster_secret({kexAlg,
                                             pSKIdentity},
                                            pSKLookup, rSAPremasterSecret)) do
      r_alert() = alert ->
        throw(alert)
      premasterSecret ->
        state = master_secret(premasterSecret,
                                r_state(state0, handshake_env: r_handshake_env(hsEnv, premaster_secret: rSAPremasterSecret)))
        client_certify_and_key_exchange(state, connection)
    end
  end

  def certify(:internal, r_server_hello_done(),
           r_state(static_env: r_static_env(role: :client, protocol_cb: connection),
               connection_env: r_connection_env(negotiated_version: version),
               handshake_env: r_handshake_env(premaster_secret: :undefined),
               session: r_session(master_secret: masterSecret) = session,
               connection_states: connectionStates0) = state0) do
    case (:ssl_handshake.master_secret(:ssl.tls_version(version),
                                         session, connectionStates0,
                                         :client)) do
      {^masterSecret, connectionStates} ->
        state = r_state(state0, connection_states: connectionStates)
        client_certify_and_key_exchange(state, connection)
      r_alert() = alert ->
        throw(alert)
    end
  end

  def certify(:internal, r_server_hello_done(),
           r_state(static_env: r_static_env(role: :client, protocol_cb: connection),
               connection_env: r_connection_env(negotiated_version: version),
               handshake_env: r_handshake_env(premaster_secret: premasterSecret),
               session: session0,
               connection_states: connectionStates0) = state0) do
    case (:ssl_handshake.master_secret(:ssl.tls_version(version),
                                         premasterSecret, connectionStates0,
                                         :client)) do
      {masterSecret, connectionStates} ->
        session = r_session(session0, master_secret: masterSecret)
        state = r_state(state0, connection_states: connectionStates, 
                            session: session)
        client_certify_and_key_exchange(state, connection)
      r_alert() = alert ->
        throw(alert)
    end
  end

  def certify(:internal = type, r_client_key_exchange() = msg,
           r_state(static_env: r_static_env(role: :server),
               client_certificate_status: :requested,
               ssl_options: %{fail_if_no_peer_cert: true})) do
    throw(r_alert(level: 2, description: 10,
              where: %{mfa: {:tls_dtls_connection, :certify, 3},
                         line: 530, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'},
              reason: {:unexpected_msg, {type, msg}}))
  end

  def certify(:internal, r_client_key_exchange(exchange_keys: keys),
           state = r_state(handshake_env: r_handshake_env(kex_algorithm: keyAlg),
                       static_env: r_static_env(protocol_cb: connection),
                       connection_env: r_connection_env(negotiated_version: version))) do
    try do
      certify_client_key_exchange(:ssl_handshake.decode_client_key(keys,
                                                                     keyAlg,
                                                                     :ssl.tls_version(version)),
                                    state, connection)
    catch
      r_alert() = alert ->
        throw(alert)
    end
  end

  def certify(:internal, r_hello_request(), _) do
    :keep_state_and_data
  end

  def certify(type, event, state) do
    :ssl_gen_statem.handle_common_event(type, event,
                                          :certify, state)
  end

  def wait_cert_verify(:internal,
           r_certificate_verify(signature: signature,
               hashsign_algorithm: certHashSign),
           r_state(static_env: r_static_env(role: :server, protocol_cb: connection),
               client_certificate_status: :needs_verifying,
               handshake_env: r_handshake_env(tls_handshake_history: hist,
                                  kex_algorithm: kexAlg,
                                  public_key_info: pubKeyInfo),
               connection_env: r_connection_env(negotiated_version: version),
               session: r_session(master_secret: masterSecret) = session0) = state) do
    tLSVersion = :ssl.tls_version(version)
    hashSign = negotiated_hashsign(certHashSign, kexAlg,
                                     pubKeyInfo, tLSVersion)
    case (:ssl_handshake.certificate_verify(signature,
                                              pubKeyInfo, tLSVersion, hashSign,
                                              masterSecret, hist)) do
      :valid ->
        connection.next_event(:cipher, :no_record,
                                r_state(state, client_certificate_status: :verified, 
                                           session: r_session(session0, sign_alg: hashSign)))
      r_alert() = alert ->
        throw(alert)
    end
  end

  def wait_cert_verify(:internal, r_hello_request(), _) do
    :keep_state_and_data
  end

  def wait_cert_verify(type, event, state) do
    :ssl_gen_statem.handle_common_event(type, event,
                                          :wait_cert_verify, state)
  end

  def cipher({:call, from}, msg, state) do
    handle_call(msg, from, :cipher, state)
  end

  def cipher(:info, msg, state) do
    handle_info(msg, :cipher, state)
  end

  def cipher(:internal, r_finished(verify_data: data) = finished,
           r_state(static_env: r_static_env(role: role, host: host, port: port,
                             trackers: trackers),
               handshake_env: r_handshake_env(tls_handshake_history: hist,
                                  expecting_finished: true) = hsEnv,
               connection_env: r_connection_env(negotiated_version: version),
               session: r_session(master_secret: masterSecret) = session0,
               ssl_options: sslOpts,
               connection_states: connectionStates0) = state) do
    case (:ssl_handshake.verify_connection(:ssl.tls_version(version),
                                             finished, opposite_role(role),
                                             get_current_prf(connectionStates0,
                                                               :read),
                                             masterSecret, hist)) do
      :verified ->
        session = handle_session(role, sslOpts, host, port,
                                   trackers, session0)
        cipher_role(role, data, session,
                      r_state(state, handshake_env: r_handshake_env(hsEnv, expecting_finished: false)))
      r_alert() = alert ->
        throw(alert)
    end
  end

  def cipher(:internal,
           r_next_protocol(selected_protocol: selectedProtocol),
           r_state(static_env: r_static_env(role: :server, protocol_cb: connection),
               handshake_env: r_handshake_env(expecting_finished: true,
                                  expecting_next_protocol_negotiation: true) = hsEnv) = state) do
    connection.next_event(:cipher, :no_record,
                            r_state(state, handshake_env: r_handshake_env(hsEnv, negotiated_protocol: selectedProtocol, 
                                                               expecting_next_protocol_negotiation: false)))
  end

  def cipher(:internal, r_change_cipher_spec(type: <<1>>),
           r_state(handshake_env: hsEnv,
               static_env: r_static_env(protocol_cb: connection),
               connection_states: connectionStates0) = state) do
    connectionStates = :ssl_record.activate_pending_connection_state(connectionStates0,
                                                                       :read,
                                                                       connection)
    connection.next_event(:cipher, :no_record,
                            r_state(state, handshake_env: r_handshake_env(hsEnv, expecting_finished: true), 
                                       connection_states: connectionStates))
  end

  def cipher(:internal, r_hello_request(), _) do
    :keep_state_and_data
  end

  def cipher(type, event, state) do
    :ssl_gen_statem.handle_common_event(type, event,
                                          :cipher, state)
  end

  def connection({:call, from}, :renegotiate,
           r_state(static_env: r_static_env(protocol_cb: :tls_gen_connection),
               handshake_env: hsEnv) = state) do
    :tls_connection.renegotiate(r_state(state, handshake_env: r_handshake_env(hsEnv, renegotiation: {true,
                                                                                   from})),
                                  [])
  end

  def connection({:call, from}, :renegotiate,
           r_state(static_env: r_static_env(protocol_cb: :dtls_gen_connection),
               handshake_env: hsEnv) = state) do
    :dtls_connection.renegotiate(r_state(state, handshake_env: r_handshake_env(hsEnv, renegotiation: {true,
                                                                                    from})),
                                   [])
  end

  def connection({:call, from}, :negotiated_protocol,
           r_state(handshake_env: r_handshake_env(alpn: :undefined,
                                negotiated_protocol: :undefined)) = state) do
    :ssl_gen_statem.hibernate_after(:connection, state,
                                      [{:reply, from,
                                          {:error, :protocol_not_negotiated}}])
  end

  def connection({:call, from}, :negotiated_protocol,
           r_state(handshake_env: r_handshake_env(alpn: :undefined,
                                negotiated_protocol: selectedProtocol)) = state) do
    :ssl_gen_statem.hibernate_after(:connection, state,
                                      [{:reply, from, {:ok, selectedProtocol}}])
  end

  def connection({:call, from}, :negotiated_protocol,
           r_state(handshake_env: r_handshake_env(alpn: selectedProtocol,
                                negotiated_protocol: :undefined)) = state) do
    :ssl_gen_statem.hibernate_after(:connection, state,
                                      [{:reply, from, {:ok, selectedProtocol}}])
  end

  def connection({:call, from}, msg, state)
      when :erlang.element(1,
                             msg) === :export_key_materials do
    handle_call(msg, from, :connection, state)
  end

  def connection(:cast, {:internal_renegotiate, writeState},
           r_state(static_env: r_static_env(protocol_cb: :tls_gen_connection),
               handshake_env: hsEnv,
               connection_states: connectionStates) = state) do
    :tls_connection.renegotiate(r_state(state, handshake_env: r_handshake_env(hsEnv, renegotiation: {true,
                                                                                   :internal}), 
                                           connection_states: Map.put(connectionStates, :current_write,
                                                                                          writeState)),
                                  [])
  end

  def connection(:cast, {:internal_renegotiate, writeState},
           r_state(static_env: r_static_env(protocol_cb: :dtls_gen_connection),
               handshake_env: hsEnv,
               connection_states: connectionStates) = state) do
    :dtls_connection.renegotiate(r_state(state, handshake_env: r_handshake_env(hsEnv, renegotiation: {true,
                                                                                    :internal}), 
                                            connection_states: Map.put(connectionStates, :current_write,
                                                                                           writeState)),
                                   [])
  end

  def connection(:internal, {:handshake, {r_hello_request() = handshake, _}},
           r_state(handshake_env: hsEnv) = state) do
    {:next_state, :connection,
       r_state(state, handshake_env: r_handshake_env(hsEnv, renegotiation: {true,
                                                          :peer})),
       [{:next_event, :internal, handshake}]}
  end

  def connection(type, event, state) do
    :ssl_gen_statem.connection(type, event, state)
  end

  def downgrade(type, event, state) do
    :ssl_gen_statem.handle_common_event(type, event,
                                          :downgrade, state)
  end

  def gen_handshake(stateName, type, event, state) do
    try do
      apply(:tls_dtls_connection, stateName,
              [type, event, state])
    catch
      :error, reason ->
        (fn () ->
              case (:erlang.get(:log_level)) do
                :undefined ->
                  :ssl_logger.log(:info, :debug,
                                    %{description: :handshake_error,
                                        reason:
                                        [{:error, reason}, {:stacktrace,
                                                              __STACKTRACE__}]},
                                    %{mfa:
                                      {:tls_dtls_connection, :gen_handshake, 4},
                                        line: 695, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'})
                __LogLevel__ ->
                  :ssl_logger.log(:info, __LogLevel__,
                                    %{description: :handshake_error,
                                        reason:
                                        [{:error, reason}, {:stacktrace,
                                                              __STACKTRACE__}]},
                                    %{mfa:
                                      {:tls_dtls_connection, :gen_handshake, 4},
                                        line: 695, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'})
              end
         end).()
        throw(r_alert(level: 2, description: 40,
                  where: %{mfa: {:tls_dtls_connection, :gen_handshake, 4},
                             line: 696, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'},
                  reason: :malformed_handshake_data))
    end
  end

  def handle_call(:renegotiate, from, stateName, _)
      when stateName !== :connection do
    {:keep_state_and_data,
       [{:reply, from, {:error, :already_renegotiating}}]}
  end

  def handle_call({:export_key_materials, [label], [context0],
            [wantedLength], _},
           from, _, r_state(connection_states: connectionStates)) do
    %{security_parameters:
      secParams} = :ssl_record.current_connection_state(connectionStates,
                                                          :read)
    r_security_parameters(master_secret: masterSecret,
        client_random: clientRandom,
        server_random: serverRandom,
        prf_algorithm: pRFAlgorithm) = secParams
    seed = (case (context0) do
              :no_context ->
                <<clientRandom :: binary, serverRandom :: binary>>
              _ ->
                size = :erlang.byte_size(context0)
                <<clientRandom :: binary, serverRandom :: binary,
                    size :: size(16) - unsigned - big - integer,
                    context0 :: binary>>
            end)
    reply = (try do
               {:ok,
                  :tls_v1.prf(pRFAlgorithm, masterSecret, label, seed,
                                wantedLength)}
             catch
               :exit, reason ->
                 (fn () ->
                       case (:erlang.get(:log_level)) do
                         :undefined ->
                           :ssl_logger.log(:info, :debug,
                                             %{description: :handshake_error,
                                                 reason:
                                                 [{:error, reason},
                                                      {:stacktrace,
                                                         __STACKTRACE__}]},
                                             %{mfa:
                                               {:tls_dtls_connection,
                                                  :handle_call, 4},
                                                 line: 727, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'})
                         __LogLevel__ ->
                           :ssl_logger.log(:info, __LogLevel__,
                                             %{description: :handshake_error,
                                                 reason:
                                                 [{:error, reason},
                                                      {:stacktrace,
                                                         __STACKTRACE__}]},
                                             %{mfa:
                                               {:tls_dtls_connection,
                                                  :handle_call, 4},
                                                 line: 727, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'})
                       end
                  end).()
                 {:error, :badarg}
               :error, reason ->
                 (fn () ->
                       case (:erlang.get(:log_level)) do
                         :undefined ->
                           :ssl_logger.log(:info, :debug,
                                             %{description: :handshake_error,
                                                 reason:
                                                 [{:error, reason},
                                                      {:stacktrace,
                                                         __STACKTRACE__}]},
                                             %{mfa:
                                               {:tls_dtls_connection,
                                                  :handle_call, 4},
                                                 line: 730, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'})
                         __LogLevel__ ->
                           :ssl_logger.log(:info, __LogLevel__,
                                             %{description: :handshake_error,
                                                 reason:
                                                 [{:error, reason},
                                                      {:stacktrace,
                                                         __STACKTRACE__}]},
                                             %{mfa:
                                               {:tls_dtls_connection,
                                                  :handle_call, 4},
                                                 line: 730, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'})
                       end
                  end).()
                 {:error, reason}
             end)
    {:keep_state_and_data, [{:reply, from, reply}]}
  end

  def handle_call(msg, from, stateName, state) do
    :ssl_gen_statem.handle_call(msg, from, stateName, state)
  end

  defp handle_info(msg, stateName, state) do
    :ssl_gen_statem.handle_info(msg, stateName, state)
  end

  defp do_server_hello(type,
            %{next_protocol_negotiation:
              nextProtocols} = serverHelloExt,
            r_state(connection_env: r_connection_env(negotiated_version: version),
                static_env: r_static_env(protocol_cb: connection),
                handshake_env: hsEnv, session: r_session(session_id: sessId),
                connection_states: connectionStates0,
                ssl_options: %{versions:
                               [highestVersion | _]}) = state0)
      when is_atom(type) do
    connectionStates1 = update_server_random(connectionStates0,
                                               version, highestVersion)
    state1 = r_state(state0, connection_states: connectionStates1)
    serverHello = :ssl_handshake.server_hello(sessId,
                                                :ssl.tls_version(version),
                                                connectionStates1,
                                                serverHelloExt)
    state = server_hello(serverHello,
                           r_state(state1, handshake_env: r_handshake_env(hsEnv, expecting_next_protocol_negotiation: nextProtocols !== :undefined)),
                           connection)
    case (type) do
      :new ->
        new_server_hello(serverHello, state, connection)
      :resumed ->
        resumed_server_hello(state, connection)
    end
  end

  defp update_server_random(%{pending_read:
            %{security_parameters: readSecParams0} = readState0,
              pending_write:
              %{security_parameters:
                writeSecParams0} = writeState0} = connectionStates,
            version, highestVersion) do
    readRandom = override_server_random(r_security_parameters(readSecParams0, :server_random),
                                          version, highestVersion)
    writeRandom = override_server_random(r_security_parameters(writeSecParams0, :server_random),
                                           version, highestVersion)
    readSecParams = r_security_parameters(readSecParams0, server_random: readRandom)
    writeSecParams = r_security_parameters(writeSecParams0, server_random: writeRandom)
    readState = Map.put(readState0, :security_parameters,
                                      readSecParams)
    writeState = Map.put(writeState0, :security_parameters,
                                        writeSecParams)
    Map.merge(connectionStates, %{pending_read: readState,
                                    pending_write: writeState})
  end

  defp override_server_random(<<random0 :: size(24) - binary,
              _ :: size(8) - binary>> = random,
            {m, n}, {major, minor})
      when major > 3 or major === 3 and minor >= 4 do
    cond do
      m === 3 and n === 3 ->
        down = <<68, 79, 87, 78, 71, 82, 68, 1>>
        <<random0 :: binary, down :: binary>>
      m === 3 and n < 3 ->
        down = <<68, 79, 87, 78, 71, 82, 68, 0>>
        <<random0 :: binary, down :: binary>>
      true ->
        random
    end
  end

  defp override_server_random(<<random0 :: size(24) - binary,
              _ :: size(8) - binary>> = random,
            {m, n}, {major, minor})
      when major === 3 and minor === 3 do
    cond do
      m === 3 and n < 3 ->
        down = <<68, 79, 87, 78, 71, 82, 68, 0>>
        <<random0 :: binary, down :: binary>>
      true ->
        random
    end
  end

  defp override_server_random(random, _, _) do
    random
  end

  defp new_server_hello(r_server_hello(cipher_suite: cipherSuite,
              compression_method: compression, session_id: sessionId),
            r_state(session: session0,
                static_env: r_static_env(protocol_cb: connection)) = state0,
            connection) do
    r_state() = (state1 = server_certify_and_key_exchange(state0,
                                                      connection))
    {state, actions} = server_hello_done(state1, connection)
    session = r_session(session0, session_id: sessionId, 
                            cipher_suite: cipherSuite, 
                            compression_method: compression)
    connection.next_event(:certify, :no_record,
                            r_state(state, session: session), actions)
  end

  defp resumed_server_hello(r_state(session: session,
              connection_states: connectionStates0,
              static_env: r_static_env(protocol_cb: connection),
              connection_env: r_connection_env(negotiated_version: version)) = state0,
            connection) do
    case (:ssl_handshake.master_secret(:ssl.tls_version(version),
                                         session, connectionStates0,
                                         :server)) do
      {_, connectionStates1} ->
        state1 = r_state(state0, connection_states: connectionStates1, 
                             session: session)
        {state, actions} = finalize_handshake(state1,
                                                :abbreviated, connection)
        connection.next_event(:abbreviated, :no_record, state,
                                actions)
      r_alert() = alert ->
        throw(alert)
    end
  end

  defp server_hello(serverHello, state0, connection) do
    cipherSuite = r_server_hello(serverHello, :cipher_suite)
    %{key_exchange:
      keyAlgorithm} = :ssl_cipher_format.suite_bin_to_map(cipherSuite)
    r_state(handshake_env: hsEnv) = (state = connection.queue_handshake(serverHello,
                                                                    state0))
    r_state(state, handshake_env: r_handshake_env(hsEnv, kex_algorithm: keyAlgorithm))
  end

  defp server_hello_done(state, connection) do
    helloDone = :ssl_handshake.server_hello_done()
    connection.send_handshake(helloDone, state)
  end

  defp handle_peer_cert(role, peerCert, publicKeyInfo,
            r_state(handshake_env: hsEnv,
                static_env: r_static_env(protocol_cb: connection),
                session: r_session(cipher_suite: cipherSuite) = session) = state0,
            connection, actions) do
    state1 = r_state(state0, handshake_env: r_handshake_env(hsEnv, public_key_info: publicKeyInfo), 
                         session: r_session(session, peer_certificate: peerCert))
    %{key_exchange:
      keyAlgorithm} = :ssl_cipher_format.suite_bin_to_map(cipherSuite)
    state = handle_peer_cert_key(role, peerCert,
                                   publicKeyInfo, keyAlgorithm, state1)
    connection.next_event(:certify, :no_record, state,
                            actions)
  end

  defp handle_peer_cert_key(:client, _,
            {{1, 2, 840, 10045, 2, 1},
               r_ECPoint(point: _ECPoint) = publicKey, publicKeyParams},
            keyAlg,
            r_state(handshake_env: hsEnv, session: session) = state)
      when keyAlg == :ecdh_rsa or keyAlg == :ecdh_ecdsa do
    eCDHKey = :public_key.generate_key(publicKeyParams)
    premasterSecret = :ssl_handshake.premaster_secret(publicKey,
                                                        eCDHKey)
    master_secret(premasterSecret,
                    r_state(state, handshake_env: r_handshake_env(hsEnv, kex_keys: eCDHKey), 
                               session: r_session(session, ecc: publicKeyParams)))
  end

  defp handle_peer_cert_key(_, _, _, _, state) do
    state
  end

  defp certify_client(r_state(static_env: r_static_env(role: :client,
                            cert_db: certDbHandle, cert_db_ref: certDbRef),
              client_certificate_status: :requested,
              session: r_session(own_certificates: ownCerts)) = state,
            connection) do
    certificate = :ssl_handshake.certificate(ownCerts,
                                               certDbHandle, certDbRef, :client)
    connection.queue_handshake(certificate, state)
  end

  defp certify_client(r_state(client_certificate_status: :not_requested) = state,
            _) do
    state
  end

  defp verify_client_cert(r_state(static_env: r_static_env(role: :client),
              handshake_env: r_handshake_env(tls_handshake_history: hist),
              connection_env: r_connection_env(negotiated_version: version),
              client_certificate_status: :requested,
              session: r_session(sign_alg: hashSign,
                           master_secret: masterSecret, private_key: privateKey,
                           own_certificates: ownCerts)) = state,
            connection) do
    case (:ssl_handshake.client_certificate_verify(ownCerts,
                                                     masterSecret,
                                                     :ssl.tls_version(version),
                                                     hashSign, privateKey,
                                                     hist)) do
      r_certificate_verify() = verified ->
        connection.queue_handshake(verified, state)
      :ignore ->
        state
      r_alert() = alert ->
        throw(alert)
    end
  end

  defp verify_client_cert(r_state(client_certificate_status: :not_requested) = state,
            _) do
    state
  end

  defp client_certify_and_key_exchange(state0, connection) do
    state1 = do_client_certify_and_key_exchange(state0,
                                                  connection)
    {state2, actions} = finalize_handshake(state1, :certify,
                                             connection)
    state = r_state(state2, client_certificate_status: :not_requested)
    connection.next_event(:cipher, :no_record, state,
                            actions)
  end

  defp do_client_certify_and_key_exchange(state0, connection) do
    state1 = certify_client(state0, connection)
    state2 = key_exchange(state1, connection)
    verify_client_cert(state2, connection)
  end

  defp server_certify_and_key_exchange(state0, connection) do
    state1 = certify_server(state0, connection)
    state2 = key_exchange(state1, connection)
    request_client_cert(state2, connection)
  end

  defp certify_client_key_exchange(r_encrypted_premaster_secret(premaster_secret: encPMS),
            r_state(session: r_session(private_key: privateKey),
                handshake_env: r_handshake_env(client_hello_version: {major,
                                                          minor} = version),
                client_certificate_status: cCStatus) = state,
            connection) do
    fakeSecret = make_premaster_secret(version, :rsa)
    premasterSecret = (try do
                         :ssl_handshake.premaster_secret(encPMS, privateKey)
                       catch
                         r_alert(description: 51) ->
                           fakeSecret
                       else
                         secret when :erlang.byte_size(secret) == 48 ->
                           case (secret) do
                             <<^major :: size(8) - unsigned - big - integer,
                                 ^minor :: size(8) - unsigned - big - integer,
                                 rest :: binary>> ->
                               <<major :: size(8) - unsigned - big - integer,
                                   minor :: size(8) - unsigned - big - integer,
                                   rest :: binary>>
                             <<_ :: size(8) - unsigned - big - integer,
                                 _ :: size(8) - unsigned - big - integer,
                                 rest :: binary>> ->
                               <<major :: size(8) - unsigned - big - integer,
                                   minor :: size(8) - unsigned - big - integer,
                                   rest :: binary>>
                           end
                         _ ->
                           fakeSecret
                       end)
    calculate_master_secret(premasterSecret, state,
                              connection, :certify,
                              client_kex_next_state(cCStatus))
  end

  defp certify_client_key_exchange(r_client_diffie_hellman_public(dh_public: clientPublicDhKey),
            r_state(handshake_env: r_handshake_env(diffie_hellman_params: r_DHParameter() = params,
                                 kex_keys: {_, serverDhPrivateKey}),
                client_certificate_status: cCStatus) = state,
            connection) do
    premasterSecret = :ssl_handshake.premaster_secret(clientPublicDhKey,
                                                        serverDhPrivateKey,
                                                        params)
    calculate_master_secret(premasterSecret, state,
                              connection, :certify,
                              client_kex_next_state(cCStatus))
  end

  defp certify_client_key_exchange(r_client_ec_diffie_hellman_public(dh_public: clientPublicEcDhPoint),
            r_state(handshake_env: r_handshake_env(kex_keys: eCDHKey),
                client_certificate_status: cCStatus) = state,
            connection) do
    premasterSecret = :ssl_handshake.premaster_secret(r_ECPoint(point: clientPublicEcDhPoint),
                                                        eCDHKey)
    calculate_master_secret(premasterSecret, state,
                              connection, :certify,
                              client_kex_next_state(cCStatus))
  end

  defp certify_client_key_exchange(r_client_psk_identity() = clientKey,
            r_state(ssl_options: %{user_lookup_fun: pSKLookup},
                client_certificate_status: cCStatus) = state0,
            connection) do
    premasterSecret = :ssl_handshake.premaster_secret(clientKey,
                                                        pSKLookup)
    calculate_master_secret(premasterSecret, state0,
                              connection, :certify,
                              client_kex_next_state(cCStatus))
  end

  defp certify_client_key_exchange(r_client_dhe_psk_identity() = clientKey,
            r_state(handshake_env: r_handshake_env(diffie_hellman_params: r_DHParameter() = params,
                                 kex_keys: {_, serverDhPrivateKey}),
                ssl_options: %{user_lookup_fun: pSKLookup},
                client_certificate_status: cCStatus) = state0,
            connection) do
    premasterSecret = :ssl_handshake.premaster_secret(clientKey,
                                                        serverDhPrivateKey,
                                                        params, pSKLookup)
    calculate_master_secret(premasterSecret, state0,
                              connection, :certify,
                              client_kex_next_state(cCStatus))
  end

  defp certify_client_key_exchange(r_client_ecdhe_psk_identity() = clientKey,
            r_state(handshake_env: r_handshake_env(kex_keys: serverEcDhPrivateKey),
                ssl_options: %{user_lookup_fun: pSKLookup},
                client_certificate_status: cCStatus) = state,
            connection) do
    premasterSecret = :ssl_handshake.premaster_secret(clientKey,
                                                        serverEcDhPrivateKey,
                                                        pSKLookup)
    calculate_master_secret(premasterSecret, state,
                              connection, :certify,
                              client_kex_next_state(cCStatus))
  end

  defp certify_client_key_exchange(r_client_rsa_psk_identity() = clientKey,
            r_state(session: r_session(private_key: privateKey),
                ssl_options: %{user_lookup_fun: pSKLookup},
                client_certificate_status: cCStatus) = state0,
            connection) do
    premasterSecret = :ssl_handshake.premaster_secret(clientKey,
                                                        privateKey, pSKLookup)
    calculate_master_secret(premasterSecret, state0,
                              connection, :certify,
                              client_kex_next_state(cCStatus))
  end

  defp certify_client_key_exchange(r_client_srp_public() = clientKey,
            r_state(handshake_env: r_handshake_env(srp_params: params, kex_keys: key),
                client_certificate_status: cCStatus) = state0,
            connection) do
    premasterSecret = :ssl_handshake.premaster_secret(clientKey,
                                                        key, params)
    calculate_master_secret(premasterSecret, state0,
                              connection, :certify,
                              client_kex_next_state(cCStatus))
  end

  defp client_kex_next_state(:needs_verifying) do
    :wait_cert_verify
  end

  defp client_kex_next_state(:empty) do
    :cipher
  end

  defp client_kex_next_state(:not_requested) do
    :cipher
  end

  defp certify_server(r_state(handshake_env: r_handshake_env(kex_algorithm: kexAlg)) = state,
            _)
      when kexAlg == :dh_anon or kexAlg == :ecdh_anon or
             kexAlg == :psk or kexAlg == :dhe_psk or
             kexAlg == :ecdhe_psk or kexAlg == :srp_anon do
    state
  end

  defp certify_server(r_state(static_env: r_static_env(cert_db: certDbHandle,
                            cert_db_ref: certDbRef),
              session: r_session(own_certificates: ownCerts)) = state,
            connection) do
    cert = :ssl_handshake.certificate(ownCerts,
                                        certDbHandle, certDbRef, :server)
    r_certificate() = cert
    connection.queue_handshake(cert, state)
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :server),
              handshake_env: r_handshake_env(kex_algorithm: :rsa)) = state,
            _) do
    state
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :server),
              handshake_env: r_handshake_env(kex_algorithm: kexAlg,
                                 diffie_hellman_params: r_DHParameter() = params,
                                 hashsign_algorithm: hashSignAlgo),
              connection_env: r_connection_env(negotiated_version: version),
              session: r_session(private_key: privateKey),
              connection_states: connectionStates0) = state0,
            connection)
      when kexAlg == :dhe_dss or kexAlg == :dhe_rsa or
             kexAlg == :dh_anon do
    dHKeys = :public_key.generate_key(params)
    %{security_parameters:
      secParams} = :ssl_record.pending_connection_state(connectionStates0,
                                                          :read)
    r_security_parameters(client_random: clientRandom,
        server_random: serverRandom) = secParams
    msg = :ssl_handshake.key_exchange(:server,
                                        :ssl.tls_version(version),
                                        {:dh, dHKeys, params, hashSignAlgo,
                                           clientRandom, serverRandom,
                                           privateKey})
    r_state(handshake_env: hsEnv) = (state = connection.queue_handshake(msg,
                                                                    state0))
    r_state(state, handshake_env: r_handshake_env(hsEnv, kex_keys: dHKeys))
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :server),
              handshake_env: r_handshake_env(kex_algorithm: kexAlg) = hsEnv,
              session: r_session(private_key: r_ECPrivateKey(parameters: eCCurve) = key) = session) = state,
            _)
      when kexAlg == :ecdh_ecdsa or kexAlg == :ecdh_rsa do
    r_state(state, handshake_env: r_handshake_env(hsEnv, kex_keys: key), 
               session: r_session(session, ecc: eCCurve))
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :server),
              handshake_env: r_handshake_env(kex_algorithm: kexAlg,
                                 hashsign_algorithm: hashSignAlgo),
              connection_env: r_connection_env(negotiated_version: version),
              session: r_session(ecc: eCCCurve, private_key: privateKey),
              connection_states: connectionStates0) = state0,
            connection)
      when kexAlg == :ecdhe_ecdsa or kexAlg == :ecdhe_rsa or
             kexAlg == :ecdh_anon do
    assert_curve(eCCCurve)
    eCDHKeys = :public_key.generate_key(eCCCurve)
    %{security_parameters:
      secParams} = :ssl_record.pending_connection_state(connectionStates0,
                                                          :read)
    r_security_parameters(client_random: clientRandom,
        server_random: serverRandom) = secParams
    msg = :ssl_handshake.key_exchange(:server,
                                        :ssl.tls_version(version),
                                        {:ecdh, eCDHKeys, hashSignAlgo,
                                           clientRandom, serverRandom,
                                           privateKey})
    r_state(handshake_env: hsEnv) = (state = connection.queue_handshake(msg,
                                                                    state0))
    r_state(state, handshake_env: r_handshake_env(hsEnv, kex_keys: eCDHKeys))
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :server),
              handshake_env: r_handshake_env(kex_algorithm: :psk),
              ssl_options: %{psk_identity: :undefined}) = state,
            _) do
    state
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :server),
              ssl_options: %{psk_identity: pskIdentityHint},
              handshake_env: r_handshake_env(kex_algorithm: :psk,
                                 hashsign_algorithm: hashSignAlgo),
              connection_env: r_connection_env(negotiated_version: version),
              session: r_session(private_key: privateKey),
              connection_states: connectionStates0) = state0,
            connection) do
    %{security_parameters:
      secParams} = :ssl_record.pending_connection_state(connectionStates0,
                                                          :read)
    r_security_parameters(client_random: clientRandom,
        server_random: serverRandom) = secParams
    msg = :ssl_handshake.key_exchange(:server,
                                        :ssl.tls_version(version),
                                        {:psk, pskIdentityHint, hashSignAlgo,
                                           clientRandom, serverRandom,
                                           privateKey})
    connection.queue_handshake(msg, state0)
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :server),
              ssl_options: %{psk_identity: pskIdentityHint},
              handshake_env: r_handshake_env(kex_algorithm: :dhe_psk,
                                 diffie_hellman_params: r_DHParameter() = params,
                                 hashsign_algorithm: hashSignAlgo),
              connection_env: r_connection_env(negotiated_version: version),
              session: r_session(private_key: privateKey),
              connection_states: connectionStates0) = state0,
            connection) do
    dHKeys = :public_key.generate_key(params)
    %{security_parameters:
      secParams} = :ssl_record.pending_connection_state(connectionStates0,
                                                          :read)
    r_security_parameters(client_random: clientRandom,
        server_random: serverRandom) = secParams
    msg = :ssl_handshake.key_exchange(:server,
                                        :ssl.tls_version(version),
                                        {:dhe_psk, pskIdentityHint, dHKeys,
                                           params, hashSignAlgo, clientRandom,
                                           serverRandom, privateKey})
    r_state(handshake_env: hsEnv) = (state = connection.queue_handshake(msg,
                                                                    state0))
    r_state(state, handshake_env: r_handshake_env(hsEnv, kex_keys: dHKeys))
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :server),
              ssl_options: %{psk_identity: pskIdentityHint},
              handshake_env: r_handshake_env(kex_algorithm: :ecdhe_psk,
                                 hashsign_algorithm: hashSignAlgo),
              connection_env: r_connection_env(negotiated_version: version),
              session: r_session(ecc: eCCCurve, private_key: privateKey),
              connection_states: connectionStates0) = state0,
            connection) do
    assert_curve(eCCCurve)
    eCDHKeys = :public_key.generate_key(eCCCurve)
    %{security_parameters:
      secParams} = :ssl_record.pending_connection_state(connectionStates0,
                                                          :read)
    r_security_parameters(client_random: clientRandom,
        server_random: serverRandom) = secParams
    msg = :ssl_handshake.key_exchange(:server,
                                        :ssl.tls_version(version),
                                        {:ecdhe_psk, pskIdentityHint, eCDHKeys,
                                           hashSignAlgo, clientRandom,
                                           serverRandom, privateKey})
    r_state(handshake_env: hsEnv) = (state = connection.queue_handshake(msg,
                                                                    state0))
    r_state(state, handshake_env: r_handshake_env(hsEnv, kex_keys: eCDHKeys))
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :server),
              handshake_env: r_handshake_env(kex_algorithm: :rsa_psk),
              ssl_options: %{psk_identity: :undefined}) = state,
            _) do
    state
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :server),
              ssl_options: %{psk_identity: pskIdentityHint},
              handshake_env: r_handshake_env(kex_algorithm: :rsa_psk,
                                 hashsign_algorithm: hashSignAlgo),
              connection_env: r_connection_env(negotiated_version: version),
              session: r_session(private_key: privateKey),
              connection_states: connectionStates0) = state0,
            connection) do
    %{security_parameters:
      secParams} = :ssl_record.pending_connection_state(connectionStates0,
                                                          :read)
    r_security_parameters(client_random: clientRandom,
        server_random: serverRandom) = secParams
    msg = :ssl_handshake.key_exchange(:server,
                                        :ssl.tls_version(version),
                                        {:psk, pskIdentityHint, hashSignAlgo,
                                           clientRandom, serverRandom,
                                           privateKey})
    connection.queue_handshake(msg, state0)
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :server),
              ssl_options: %{user_lookup_fun: lookupFun},
              handshake_env: r_handshake_env(kex_algorithm: kexAlg,
                                 hashsign_algorithm: hashSignAlgo),
              connection_env: r_connection_env(negotiated_version: version),
              session: r_session(srp_username: username,
                           private_key: privateKey),
              connection_states: connectionStates0) = state0,
            connection)
      when kexAlg == :srp_dss or kexAlg == :srp_rsa or
             kexAlg == :srp_anon do
    srpParams = handle_srp_identity(username, lookupFun)
    keys = generate_srp_server_keys(srpParams, 0)
    %{security_parameters:
      secParams} = :ssl_record.pending_connection_state(connectionStates0,
                                                          :read)
    r_security_parameters(client_random: clientRandom,
        server_random: serverRandom) = secParams
    msg = :ssl_handshake.key_exchange(:server,
                                        :ssl.tls_version(version),
                                        {:srp, keys, srpParams, hashSignAlgo,
                                           clientRandom, serverRandom,
                                           privateKey})
    r_state(handshake_env: hsEnv) = (state = connection.queue_handshake(msg,
                                                                    state0))
    r_state(state, handshake_env: r_handshake_env(hsEnv, srp_params: srpParams, 
                                       kex_keys: keys))
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :client),
              handshake_env: r_handshake_env(kex_algorithm: :rsa,
                                 public_key_info: publicKeyInfo,
                                 premaster_secret: premasterSecret),
              connection_env: r_connection_env(negotiated_version: version)) = state0,
            connection) do
    msg = rsa_key_exchange(:ssl.tls_version(version),
                             premasterSecret, publicKeyInfo)
    connection.queue_handshake(msg, state0)
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :client),
              handshake_env: r_handshake_env(kex_algorithm: kexAlg,
                                 kex_keys: {dhPubKey, _}),
              connection_env: r_connection_env(negotiated_version: version)) = state0,
            connection)
      when kexAlg == :dhe_dss or kexAlg == :dhe_rsa or
             kexAlg == :dh_anon do
    msg = :ssl_handshake.key_exchange(:client,
                                        :ssl.tls_version(version),
                                        {:dh, dhPubKey})
    connection.queue_handshake(msg, state0)
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :client),
              handshake_env: r_handshake_env(kex_algorithm: kexAlg,
                                 kex_keys: r_ECPrivateKey(parameters: eCCurve) = key),
              connection_env: r_connection_env(negotiated_version: version),
              session: session) = state0,
            connection)
      when kexAlg == :ecdhe_ecdsa or kexAlg == :ecdhe_rsa or
             kexAlg == :ecdh_ecdsa or kexAlg == :ecdh_rsa or
             kexAlg == :ecdh_anon do
    msg = :ssl_handshake.key_exchange(:client,
                                        :ssl.tls_version(version), {:ecdh, key})
    connection.queue_handshake(msg,
                                 r_state(state0, session: r_session(session, ecc: eCCurve)))
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :client),
              handshake_env: r_handshake_env(kex_algorithm: :psk),
              connection_env: r_connection_env(negotiated_version: version),
              ssl_options: %{psk_identity: pSKIdentity}) = state0,
            connection) do
    msg = :ssl_handshake.key_exchange(:client,
                                        :ssl.tls_version(version),
                                        {:psk, pSKIdentity})
    connection.queue_handshake(msg, state0)
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :client),
              handshake_env: r_handshake_env(kex_algorithm: :dhe_psk,
                                 kex_keys: {dhPubKey, _}),
              connection_env: r_connection_env(negotiated_version: version),
              ssl_options: %{psk_identity: pSKIdentity}) = state0,
            connection) do
    msg = :ssl_handshake.key_exchange(:client,
                                        :ssl.tls_version(version),
                                        {:dhe_psk, pSKIdentity, dhPubKey})
    connection.queue_handshake(msg, state0)
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :client),
              handshake_env: r_handshake_env(kex_algorithm: :ecdhe_psk,
                                 kex_keys: eCDHKeys),
              connection_env: r_connection_env(negotiated_version: version),
              ssl_options: %{psk_identity: pSKIdentity}) = state0,
            connection) do
    msg = :ssl_handshake.key_exchange(:client,
                                        :ssl.tls_version(version),
                                        {:ecdhe_psk, pSKIdentity, eCDHKeys})
    connection.queue_handshake(msg, state0)
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :client),
              handshake_env: r_handshake_env(kex_algorithm: :rsa_psk,
                                 public_key_info: publicKeyInfo,
                                 premaster_secret: premasterSecret),
              connection_env: r_connection_env(negotiated_version: version),
              ssl_options: %{psk_identity: pSKIdentity}) = state0,
            connection) do
    msg = rsa_psk_key_exchange(:ssl.tls_version(version),
                                 pSKIdentity, premasterSecret, publicKeyInfo)
    connection.queue_handshake(msg, state0)
  end

  defp key_exchange(r_state(static_env: r_static_env(role: :client),
              handshake_env: r_handshake_env(kex_algorithm: kexAlg,
                                 kex_keys: {clientPubKey, _}),
              connection_env: r_connection_env(negotiated_version: version)) = state0,
            connection)
      when kexAlg == :srp_dss or kexAlg == :srp_rsa or
             kexAlg == :srp_anon do
    msg = :ssl_handshake.key_exchange(:client,
                                        :ssl.tls_version(version),
                                        {:srp, clientPubKey})
    connection.queue_handshake(msg, state0)
  end

  defp rsa_key_exchange(version, premasterSecret,
            publicKeyInfo = {algorithm, _, _})
      when algorithm == {1, 2, 840, 113549, 1, 1, 1} or
             algorithm == {1, 2, 840, 113549, 1, 1, 2} or
             algorithm == {1, 2, 840, 113549, 1, 1, 4} or
             algorithm == {1, 2, 840, 113549, 1, 1, 5} or
             algorithm == {1, 2, 840, 113549, 1, 1, 14} or
             algorithm == {1, 2, 840, 113549, 1, 1, 11} or
             algorithm == {1, 2, 840, 113549, 1, 1, 12} or
             algorithm == {1, 2, 840, 113549, 1, 1, 13} do
    :ssl_handshake.key_exchange(:client,
                                  :ssl.tls_version(version),
                                  {:premaster_secret, premasterSecret,
                                     publicKeyInfo})
  end

  defp rsa_key_exchange(_, _, _) do
    throw(r_alert(level: 2, description: 40,
              where: %{mfa:
                       {:tls_dtls_connection, :rsa_key_exchange, 3},
                         line: 1302, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'},
              reason: :pub_key_is_not_rsa))
  end

  defp rsa_psk_key_exchange(version, pskIdentity, premasterSecret,
            publicKeyInfo = {algorithm, _, _})
      when algorithm == {1, 2, 840, 113549, 1, 1, 1} or
             algorithm == {1, 2, 840, 113549, 1, 1, 2} or
             algorithm == {1, 2, 840, 113549, 1, 1, 4} or
             algorithm == {1, 2, 840, 113549, 1, 1, 5} or
             algorithm == {1, 2, 840, 113549, 1, 1, 14} or
             algorithm == {1, 2, 840, 113549, 1, 1, 11} or
             algorithm == {1, 2, 840, 113549, 1, 1, 12} or
             algorithm == {1, 2, 840, 113549, 1, 1, 13} do
    :ssl_handshake.key_exchange(:client,
                                  :ssl.tls_version(version),
                                  {:psk_premaster_secret, pskIdentity,
                                     premasterSecret, publicKeyInfo})
  end

  defp rsa_psk_key_exchange(_, _, _, _) do
    throw(r_alert(level: 2, description: 40,
              where: %{mfa:
                       {:tls_dtls_connection, :rsa_psk_key_exchange, 4},
                         line: 1319, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'},
              reason: :pub_key_is_not_rsa))
  end

  defp request_client_cert(r_state(handshake_env: r_handshake_env(kex_algorithm: alg)) = state,
            _)
      when alg == :dh_anon or alg == :ecdh_anon or
             alg == :psk or alg == :dhe_psk or alg == :ecdhe_psk or
             alg == :rsa_psk or alg == :srp_dss or alg == :srp_rsa or
             alg == :srp_anon do
    state
  end

  defp request_client_cert(r_state(static_env: r_static_env(cert_db: certDbHandle,
                            cert_db_ref: certDbRef),
              connection_env: r_connection_env(negotiated_version: version),
              ssl_options: %{verify: :verify_peer} = opts) = state0,
            connection) do
    supportedHashSigns = :maps.get(:signature_algs, opts,
                                     :undefined)
    tLSVersion = :ssl.tls_version(version)
    hashSigns = :ssl_handshake.available_signature_algs(supportedHashSigns,
                                                          tLSVersion)
    msg = :ssl_handshake.certificate_request(certDbHandle,
                                               certDbRef, hashSigns, tLSVersion)
    state = connection.queue_handshake(msg, state0)
    r_state(state, client_certificate_status: :requested)
  end

  defp request_client_cert(r_state(ssl_options: %{verify: :verify_none}) = state,
            _) do
    state
  end

  defp calculate_master_secret(premasterSecret,
            r_state(connection_env: r_connection_env(negotiated_version: version),
                connection_states: connectionStates0,
                session: session0) = state0,
            connection, _Current, next) do
    case (:ssl_handshake.master_secret(:ssl.tls_version(version),
                                         premasterSecret, connectionStates0,
                                         :server)) do
      {masterSecret, connectionStates} ->
        session = r_session(session0, master_secret: masterSecret)
        state = r_state(state0, connection_states: connectionStates, 
                            session: session)
        connection.next_event(next, :no_record, state)
      r_alert() = alert ->
        throw(alert)
    end
  end

  defp finalize_handshake(state0, stateName, connection) do
    r_state(connection_states: connectionStates0) = (state1 = cipher_protocol(state0,
                                                                          connection))
    connectionStates = :ssl_record.activate_pending_connection_state(connectionStates0,
                                                                       :write,
                                                                       connection)
    state2 = r_state(state1, connection_states: connectionStates)
    state = next_protocol(state2, connection)
    finished(state, stateName, connection)
  end

  defp next_protocol(r_state(static_env: r_static_env(role: :server)) = state, _) do
    state
  end

  defp next_protocol(r_state(handshake_env: r_handshake_env(negotiated_protocol: :undefined)) = state,
            _) do
    state
  end

  defp next_protocol(r_state(handshake_env: r_handshake_env(expecting_next_protocol_negotiation: false)) = state,
            _) do
    state
  end

  defp next_protocol(r_state(handshake_env: r_handshake_env(negotiated_protocol: nextProtocol)) = state0,
            connection) do
    nextProtocolMessage = :ssl_handshake.next_protocol(nextProtocol)
    connection.queue_handshake(nextProtocolMessage, state0)
  end

  defp cipher_protocol(state, connection) do
    connection.queue_change_cipher(r_change_cipher_spec(), state)
  end

  defp finished(r_state(static_env: r_static_env(role: role),
              handshake_env: r_handshake_env(tls_handshake_history: hist),
              connection_env: r_connection_env(negotiated_version: version),
              session: session,
              connection_states: connectionStates0) = state0,
            stateName, connection) do
    masterSecret = r_session(session, :master_secret)
    finished = :ssl_handshake.finished(:ssl.tls_version(version),
                                         role,
                                         get_current_prf(connectionStates0,
                                                           :write),
                                         masterSecret, hist)
    connectionStates = save_verify_data(role, finished,
                                          connectionStates0, stateName)
    connection.send_handshake(finished,
                                r_state(state0, connection_states: connectionStates))
  end

  defp save_verify_data(:client, r_finished(verify_data: data), connectionStates,
            :certify) do
    :ssl_record.set_client_verify_data(:current_write, data,
                                         connectionStates)
  end

  defp save_verify_data(:server, r_finished(verify_data: data), connectionStates,
            :cipher) do
    :ssl_record.set_server_verify_data(:current_both, data,
                                         connectionStates)
  end

  defp save_verify_data(:client, r_finished(verify_data: data), connectionStates,
            :abbreviated) do
    :ssl_record.set_client_verify_data(:current_both, data,
                                         connectionStates)
  end

  defp save_verify_data(:server, r_finished(verify_data: data), connectionStates,
            :abbreviated) do
    :ssl_record.set_server_verify_data(:current_write, data,
                                         connectionStates)
  end

  defp calculate_secret(r_server_dh_params(dh_p: prime, dh_g: base,
              dh_y: serverPublicDhKey) = params,
            r_state(handshake_env: hsEnv) = state, connection) do
    keys = ({_, privateDhKey} = :crypto.generate_key(:dh,
                                                       [prime, base]))
    premasterSecret = :ssl_handshake.premaster_secret(serverPublicDhKey,
                                                        privateDhKey, params)
    calculate_master_secret(premasterSecret,
                              r_state(state, handshake_env: r_handshake_env(hsEnv, kex_keys: keys)),
                              connection, :certify, :certify)
  end

  defp calculate_secret(r_server_ecdh_params(curve: eCCurve, public: eCServerPubKey),
            r_state(handshake_env: hsEnv, session: session) = state,
            connection) do
    eCDHKeys = :public_key.generate_key(eCCurve)
    premasterSecret = :ssl_handshake.premaster_secret(r_ECPoint(point: eCServerPubKey),
                                                        eCDHKeys)
    calculate_master_secret(premasterSecret,
                              r_state(state, handshake_env: r_handshake_env(hsEnv, kex_keys: eCDHKeys), 
                                         session: r_session(session, ecc: eCCurve)),
                              connection, :certify, :certify)
  end

  defp calculate_secret(r_server_psk_params(hint: identityHint),
            r_state(handshake_env: hsEnv) = state, connection) do
    connection.next_event(:certify, :no_record,
                            r_state(state, handshake_env: r_handshake_env(hsEnv, server_psk_identity: identityHint)))
  end

  defp calculate_secret(r_server_dhe_psk_params(dh_params: r_server_dh_params(dh_p: prime,
                           dh_g: base)) = serverKey,
            r_state(handshake_env: hsEnv,
                ssl_options: %{user_lookup_fun: pSKLookup}) = state,
            connection) do
    keys = ({_, privateDhKey} = :crypto.generate_key(:dh,
                                                       [prime, base]))
    premasterSecret = :ssl_handshake.premaster_secret(serverKey,
                                                        privateDhKey, pSKLookup)
    calculate_master_secret(premasterSecret,
                              r_state(state, handshake_env: r_handshake_env(hsEnv, kex_keys: keys)),
                              connection, :certify, :certify)
  end

  defp calculate_secret(r_server_ecdhe_psk_params(dh_params: r_server_ecdh_params(curve: eCCurve)) = serverKey,
            r_state(ssl_options: %{user_lookup_fun:
                             pSKLookup}) = (r_state(handshake_env: hsEnv,
                                                session: session) = state),
            connection) do
    eCDHKeys = :public_key.generate_key(eCCurve)
    premasterSecret = :ssl_handshake.premaster_secret(serverKey,
                                                        eCDHKeys, pSKLookup)
    calculate_master_secret(premasterSecret,
                              r_state(state, handshake_env: r_handshake_env(hsEnv, kex_keys: eCDHKeys), 
                                         session: r_session(session, ecc: eCCurve)),
                              connection, :certify, :certify)
  end

  defp calculate_secret(r_server_srp_params(srp_n: prime, srp_g: generator) = serverKey,
            r_state(handshake_env: hsEnv,
                ssl_options: %{srp_identity: sRPId}) = state,
            connection) do
    keys = generate_srp_client_keys(generator, prime, 0)
    premasterSecret = :ssl_handshake.premaster_secret(serverKey,
                                                        keys, sRPId)
    calculate_master_secret(premasterSecret,
                              r_state(state, handshake_env: r_handshake_env(hsEnv, kex_keys: keys)),
                              connection, :certify, :certify)
  end

  defp master_secret(r_alert() = alert, _) do
    throw(alert)
  end

  defp master_secret(premasterSecret,
            r_state(static_env: r_static_env(role: role),
                connection_env: r_connection_env(negotiated_version: version),
                session: session,
                connection_states: connectionStates0) = state) do
    case (:ssl_handshake.master_secret(:ssl.tls_version(version),
                                         premasterSecret, connectionStates0,
                                         role)) do
      {masterSecret, connectionStates} ->
        r_state(state, session: r_session(session, master_secret: masterSecret), 
                   connection_states: connectionStates)
      r_alert() = alert ->
        throw(alert)
    end
  end

  defp generate_srp_server_keys(_SrpParams, 10) do
    throw(r_alert(level: 2, description: 47,
              where: %{mfa:
                       {:tls_dtls_connection, :generate_srp_server_keys, 2},
                         line: 1494, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'}))
  end

  defp generate_srp_server_keys(srpParams = r_srp_user(generator: generator,
                          prime: prime, verifier: verifier),
            n) do
    try do
      :crypto.generate_key(:srp,
                             {:host, [verifier, generator, prime, :"6a"]})
    catch
      :error, reason ->
        (fn () ->
              case (:erlang.get(:log_level)) do
                :undefined ->
                  :ssl_logger.log(:debug, :debug,
                                    %{description: :crypto_error,
                                        reason:
                                        [{:error, reason}, {:stacktrace,
                                                              __STACKTRACE__}]},
                                    %{mfa:
                                      {:tls_dtls_connection,
                                         :generate_srp_server_keys, 2},
                                        line: 1501, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'})
                __LogLevel__ ->
                  :ssl_logger.log(:debug, __LogLevel__,
                                    %{description: :crypto_error,
                                        reason:
                                        [{:error, reason}, {:stacktrace,
                                                              __STACKTRACE__}]},
                                    %{mfa:
                                      {:tls_dtls_connection,
                                         :generate_srp_server_keys, 2},
                                        line: 1501, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'})
              end
         end).()
        generate_srp_server_keys(srpParams, n + 1)
    end
  end

  defp generate_srp_client_keys(_Generator, _Prime, 10) do
    throw(r_alert(level: 2, description: 47,
              where: %{mfa:
                       {:tls_dtls_connection, :generate_srp_client_keys, 3},
                         line: 1506, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'}))
  end

  defp generate_srp_client_keys(generator, prime, n) do
    try do
      :crypto.generate_key(:srp,
                             {:user, [generator, prime, :"6a"]})
    catch
      :error, reason ->
        (fn () ->
              case (:erlang.get(:log_level)) do
                :undefined ->
                  :ssl_logger.log(:debug, :debug,
                                    %{description: :crypto_error,
                                        reason:
                                        [{:error, reason}, {:stacktrace,
                                                              __STACKTRACE__}]},
                                    %{mfa:
                                      {:tls_dtls_connection,
                                         :generate_srp_client_keys, 3},
                                        line: 1511, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'})
                __LogLevel__ ->
                  :ssl_logger.log(:debug, __LogLevel__,
                                    %{description: :crypto_error,
                                        reason:
                                        [{:error, reason}, {:stacktrace,
                                                              __STACKTRACE__}]},
                                    %{mfa:
                                      {:tls_dtls_connection,
                                         :generate_srp_client_keys, 3},
                                        line: 1511, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'})
              end
         end).()
        generate_srp_client_keys(generator, prime, n + 1)
    end
  end

  defp handle_srp_identity(username, {fun, userState}) do
    case (fun.(:srp, username, userState)) do
      {:ok, {sRPParams, salt, derivedKey}}
          when (is_atom(sRPParams) and is_binary(salt) and
                  is_binary(derivedKey))
               ->
        {generator,
           prime} = :ssl_srp_primes.get_srp_params(sRPParams)
        verifier = :crypto.mod_pow(generator, derivedKey, prime)
        r_srp_user(generator: generator, prime: prime, salt: salt,
            verifier: verifier)
      r_alert() = alert ->
        throw(alert)
      _ ->
        throw(r_alert(level: 2, description: 47,
                  where: %{mfa:
                           {:tls_dtls_connection, :handle_srp_identity, 2},
                             line: 1526, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'}))
    end
  end

  defp cipher_role(:client, data, session,
            r_state(static_env: r_static_env(protocol_cb: connection),
                connection_states: connectionStates0) = state0) do
    connectionStates = :ssl_record.set_server_verify_data(:current_both,
                                                            data,
                                                            connectionStates0)
    {record,
       state} = :ssl_gen_statem.prepare_connection(r_state(state0, session: session, 
                                                               connection_states: connectionStates),
                                                     connection)
    connection.next_event(:connection, record, state,
                            [{{:timeout, :handshake}, :infinity, :close}])
  end

  defp cipher_role(:server, data, session,
            r_state(static_env: r_static_env(protocol_cb: connection),
                connection_states: connectionStates0) = state0) do
    connectionStates1 = :ssl_record.set_client_verify_data(:current_read,
                                                             data,
                                                             connectionStates0)
    {state1,
       actions} = finalize_handshake(r_state(state0, connection_states: connectionStates1, 
                                                 session: session),
                                       :cipher, connection)
    {record,
       state} = :ssl_gen_statem.prepare_connection(state1,
                                                     connection)
    connection.next_event(:connection, record, state,
                            [{{:timeout, :handshake}, :infinity, :close} |
                                 actions])
  end

  defp is_anonymous(kexAlg) when kexAlg == :dh_anon or
                         kexAlg == :ecdh_anon or kexAlg == :psk or
                         kexAlg == :dhe_psk or kexAlg == :ecdhe_psk or
                         kexAlg == :rsa_psk or kexAlg == :srp_anon do
    true
  end

  defp is_anonymous(_) do
    false
  end

  defp get_current_prf(cStates, direction) do
    %{security_parameters:
      secParams} = :ssl_record.current_connection_state(cStates,
                                                          direction)
    r_security_parameters(secParams, :prf_algorithm)
  end

  defp get_pending_prf(cStates, direction) do
    %{security_parameters:
      secParams} = :ssl_record.pending_connection_state(cStates,
                                                          direction)
    r_security_parameters(secParams, :prf_algorithm)
  end

  defp opposite_role(:client) do
    :server
  end

  defp opposite_role(:server) do
    :client
  end

  defp session_handle_params(r_server_ecdh_params(curve: eCCurve), session) do
    r_session(session, ecc: eCCurve)
  end

  defp session_handle_params(_, session) do
    session
  end

  defp handle_session(:server, %{reuse_sessions: true}, _Host, _Port,
            trackers, r_session(is_resumable: false) = session) do
    tracker = :proplists.get_value(:session_id_tracker,
                                     trackers)
    server_register_session(tracker,
                              r_session(session, is_resumable: true))
  end

  defp handle_session(role = :client,
            %{verify: :verify_peer,
                reuse_sessions: reuse} = sslOpts,
            host, port, _, r_session(is_resumable: false) = session)
      when reuse !== false do
    client_register_session(host_id(role, host, sslOpts),
                              port, r_session(session, is_resumable: true),
                              reg_type(reuse))
  end

  defp handle_session(_, _, _, _, _, session) do
    session
  end

  defp reg_type(:save) do
    true
  end

  defp reg_type(true) do
    :unique
  end

  defp client_register_session(host, port, session, save) do
    :ssl_manager.register_session(host, port, session, save)
    session
  end

  defp server_register_session(tracker, session) do
    :ssl_server_session_cache.register_session(tracker,
                                                 session)
    session
  end

  defp host_id(:client, _Host,
            %{server_name_indication: hostname})
      when is_list(hostname) do
    hostname
  end

  defp host_id(_, host, _) do
    host
  end

  defp handle_new_session(newId, cipherSuite, compression,
            r_state(static_env: r_static_env(protocol_cb: connection),
                session: session0) = state0) do
    session = r_session(session0, session_id: newId, 
                            cipher_suite: cipherSuite, 
                            compression_method: compression)
    connection.next_event(:certify, :no_record,
                            r_state(state0, session: session))
  end

  defp handle_resumed_session(sessId,
            r_state(static_env: r_static_env(host: host, port: port,
                              protocol_cb: connection, session_cache: cache,
                              session_cache_cb: cacheCb),
                connection_env: r_connection_env(negotiated_version: version),
                connection_states: connectionStates0,
                ssl_options: opts) = state) do
    session = (case (:maps.get(:reuse_session, opts,
                                 :undefined)) do
                 {^sessId, sessionData} when (is_binary(sessId) and
                                                is_binary(sessionData))
                                             ->
                   :erlang.binary_to_term(sessionData, [:safe])
                 _Else ->
                   cacheCb.lookup(cache, {{host, port}, sessId})
               end)
    case (:ssl_handshake.master_secret(:ssl.tls_version(version),
                                         session, connectionStates0,
                                         :client)) do
      {_, connectionStates} ->
        connection.next_event(:abbreviated, :no_record,
                                r_state(state, connection_states: connectionStates, 
                                           session: session))
      r_alert() = alert ->
        throw(alert)
    end
  end

  defp make_premaster_secret(version, :rsa) do
    rand = :ssl_cipher.random_bytes(48 - 2)
    {majVer, minVer} = version
    <<majVer :: size(8) - unsigned - big - integer,
        minVer :: size(8) - unsigned - big - integer,
        rand :: binary>>
  end

  defp make_premaster_secret(_, _) do
    :undefined
  end

  defp negotiated_hashsign(:undefined, kexAlg, pubKeyInfo, version) do
    case (is_anonymous(kexAlg)) do
      true ->
        {:null, :anon}
      false ->
        {pubAlg, _, _} = pubKeyInfo
        :ssl_handshake.select_hashsign_algs(:undefined, pubAlg,
                                              version)
    end
  end

  defp negotiated_hashsign(hashSign = {_, _}, _, _, _) do
    hashSign
  end

  def handle_sni_extension(r_state(static_env: r_static_env(protocol_cb: connection)) = state0,
           hello) do
    possibleSNI = connection.select_sni_extension(hello)
    case (:ssl_gen_statem.handle_sni_extension(possibleSNI,
                                                 state0)) do
      {:ok, state} ->
        state
      {:error, r_alert() = alert} ->
        throw(alert)
    end
  end

  defp ensure_tls(version) when :erlang.element(1,
                                          version) == 254 do
    :dtls_v1.corresponding_tls_version(version)
  end

  defp ensure_tls(version) do
    version
  end

  defp ocsp_info(%{ocsp_expect: :stapled,
              ocsp_response: certStatus} = ocspState,
            %{ocsp_stapling: ocspStapling} = _SslOpts, peerCert) do
    %{ocsp_responder_certs:
      ocspResponderCerts} = ocspStapling
    %{cert_ext:
      %{:public_key.pkix_subject_id(peerCert)
        =>
        [certStatus]},
        ocsp_responder_certs: ocspResponderCerts,
        ocsp_state: ocspState}
  end

  defp ocsp_info(%{ocsp_expect: :no_staple} = ocspState, _,
            peerCert) do
    %{cert_ext:
      %{:public_key.pkix_subject_id(peerCert) => []},
        ocsp_responder_certs: [], ocsp_state: ocspState}
  end

  defp select_client_cert_key_pair(session0, _,
            [%{private_key: noKey, certs: [[]] = noCerts}], _, _, _,
            _) do
    r_session(session0, own_certificates: noCerts, 
                  private_key: noKey)
  end

  defp select_client_cert_key_pair(session0, certRequest, certKeyPairs,
            supportedHashSigns, tLSVersion, certDbHandle,
            certDbRef) do
    select_client_cert_key_pair(session0, certRequest,
                                  certKeyPairs, supportedHashSigns, tLSVersion,
                                  certDbHandle, certDbRef, :undefined)
  end

  defp select_client_cert_key_pair(session0, _, [], _, _, _, _, :undefined) do
    r_session(session0, own_certificates: [[]],  private_key: %{})
  end

  defp select_client_cert_key_pair(_, _, [], _, _, _, _, r_session() = session) do
    session
  end

  defp select_client_cert_key_pair(session0,
            r_certificate_request(certificate_authorities: certAuths) = certRequest,
            [%{private_key: privateKey, certs: [cert | _] = certs} |
                 rest],
            supportedHashSigns, tLSVersion, certDbHandle, certDbRef,
            default) do
    case (:ssl_handshake.select_hashsign(certRequest, cert,
                                           supportedHashSigns, tLSVersion)) do
      r_alert() ->
        select_client_cert_key_pair(session0, certRequest, rest,
                                      supportedHashSigns, tLSVersion,
                                      certDbHandle, certDbRef, default)
      selectedHashSign ->
        case (:ssl_certificate.handle_cert_auths(certs,
                                                   certAuths, certDbHandle,
                                                   certDbRef)) do
          {:ok, encodedChain} ->
            r_session(session0, sign_alg: selectedHashSign, 
                          own_certificates: encodedChain, 
                          private_key: privateKey)
          {:error, encodedChain, :not_in_auth_domain} ->
            session = r_session(session0, sign_alg: selectedHashSign, 
                                    own_certificates: encodedChain, 
                                    private_key: privateKey)
            select_client_cert_key_pair(session0, certRequest, rest,
                                          supportedHashSigns, tLSVersion,
                                          certDbHandle, certDbRef,
                                          default_cert_key_pair_return(default,
                                                                         session))
        end
    end
  end

  defp default_cert_key_pair_return(:undefined, session) do
    session
  end

  defp default_cert_key_pair_return(default, _) do
    default
  end

  defp assert_curve(eCCCurve) do
    case (eCCCurve) do
      :no_curve ->
        throw(r_alert(level: 2, description: 71,
                  where: %{mfa: {:tls_dtls_connection, :assert_curve, 1},
                             line: 1736, file: 'otp/lib/ssl/src/tls_dtls_connection.erl'},
                  reason: :no_suitable_elliptic_curve))
      _ ->
        :ok
    end
  end

  def handle_trace(:csp,
           {:call,
              {:tls_dtls_connection, :wait_ocsp_stapling,
                 [type, msg | _]}},
           stack) do
    {:io_lib.format('Type = ~w Msg = ~W', [type, msg, 10]), stack}
  end

end