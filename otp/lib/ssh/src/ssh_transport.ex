defmodule :m_ssh_transport do
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
  Record.defrecord(:r_hostent, :hostent, h_name: :undefined,
                                   h_aliases: [], h_addrtype: :undefined,
                                   h_length: :undefined, h_addr_list: [])
  Record.defrecord(:r_ssh_msg_disconnect, :ssh_msg_disconnect, code: :undefined,
                                              description: :undefined,
                                              language: :undefined)
  Record.defrecord(:r_ssh_msg_ignore, :ssh_msg_ignore, data: :undefined)
  Record.defrecord(:r_ssh_msg_unimplemented, :ssh_msg_unimplemented, sequence: :undefined)
  Record.defrecord(:r_ssh_msg_debug, :ssh_msg_debug, always_display: :undefined,
                                         message: :undefined,
                                         language: :undefined)
  Record.defrecord(:r_ssh_msg_service_request, :ssh_msg_service_request, name: :undefined)
  Record.defrecord(:r_ssh_msg_service_accept, :ssh_msg_service_accept, name: :undefined)
  Record.defrecord(:r_ssh_msg_ext_info, :ssh_msg_ext_info, nr_extensions: :undefined,
                                            data: :undefined)
  Record.defrecord(:r_ssh_msg_kexinit, :ssh_msg_kexinit, cookie: :undefined,
                                           kex_algorithms: :undefined,
                                           server_host_key_algorithms: :undefined,
                                           encryption_algorithms_client_to_server: :undefined,
                                           encryption_algorithms_server_to_client: :undefined,
                                           mac_algorithms_client_to_server: :undefined,
                                           mac_algorithms_server_to_client: :undefined,
                                           compression_algorithms_client_to_server: :undefined,
                                           compression_algorithms_server_to_client: :undefined,
                                           languages_client_to_server: :undefined,
                                           languages_server_to_client: :undefined,
                                           first_kex_packet_follows: false,
                                           reserved: 0)
  Record.defrecord(:r_ssh_msg_kexdh_init, :ssh_msg_kexdh_init, e: :undefined)
  Record.defrecord(:r_ssh_msg_kexdh_reply, :ssh_msg_kexdh_reply, public_host_key: :undefined,
                                               f: :undefined, h_sig: :undefined)
  Record.defrecord(:r_ssh_msg_newkeys, :ssh_msg_newkeys, [])
  Record.defrecord(:r_ssh_msg_kex_dh_gex_request, :ssh_msg_kex_dh_gex_request, min: :undefined,
                                                      n: :undefined,
                                                      max: :undefined)
  Record.defrecord(:r_ssh_msg_kex_dh_gex_request_old, :ssh_msg_kex_dh_gex_request_old, n: :undefined)
  Record.defrecord(:r_ssh_msg_kex_dh_gex_group, :ssh_msg_kex_dh_gex_group, p: :undefined,
                                                    g: :undefined)
  Record.defrecord(:r_ssh_msg_kex_dh_gex_init, :ssh_msg_kex_dh_gex_init, e: :undefined)
  Record.defrecord(:r_ssh_msg_kex_dh_gex_reply, :ssh_msg_kex_dh_gex_reply, public_host_key: :undefined,
                                                    f: :undefined,
                                                    h_sig: :undefined)
  Record.defrecord(:r_ssh_msg_kex_ecdh_init, :ssh_msg_kex_ecdh_init, q_c: :undefined)
  Record.defrecord(:r_ssh_msg_kex_ecdh_reply, :ssh_msg_kex_ecdh_reply, public_host_key: :undefined,
                                                  q_s: :undefined,
                                                  h_sig: :undefined)
  Record.defrecord(:r_address, :address, address: :undefined,
                                   port: :undefined, profile: :undefined)
  Record.defrecord(:r_ssh, :ssh, role: :undefined,
                               peer: :undefined, local: :undefined,
                               c_vsn: :undefined, s_vsn: :undefined,
                               c_version: :undefined, s_version: :undefined,
                               c_keyinit: :undefined, s_keyinit: :undefined,
                               send_ext_info: :undefined,
                               recv_ext_info: :undefined,
                               kex_strict_negotiated: false,
                               algorithms: :undefined, send_mac: :none,
                               send_mac_key: :undefined, send_mac_size: 0,
                               recv_mac: :none, recv_mac_key: :undefined,
                               recv_mac_size: 0, encrypt: :none,
                               encrypt_cipher: :undefined,
                               encrypt_keys: :undefined, encrypt_block_size: 8,
                               encrypt_ctx: :undefined, decrypt: :none,
                               decrypt_cipher: :undefined,
                               decrypt_keys: :undefined, decrypt_block_size: 8,
                               decrypt_ctx: :undefined, compress: :none,
                               compress_ctx: :undefined, decompress: :none,
                               decompress_ctx: :undefined, c_lng: :none,
                               s_lng: :none, user_ack: true, timeout: :infinity,
                               shared_secret: :undefined,
                               exchanged_hash: :undefined,
                               session_id: :undefined, opts: [],
                               send_sequence: 0, recv_sequence: 0,
                               keyex_key: :undefined, keyex_info: :undefined,
                               random_length_padding: 15, user: :undefined,
                               service: :undefined,
                               userauth_quiet_mode: :undefined,
                               userauth_methods: :undefined,
                               userauth_supported_methods: :undefined,
                               userauth_pubkeys: :undefined, kb_tries_left: 0,
                               userauth_preference: :undefined,
                               available_host_keys: :undefined,
                               pwdfun_user_state: :undefined,
                               authenticated: false)
  Record.defrecord(:r_alg, :alg, kex: :undefined,
                               hkey: :undefined, send_mac: :undefined,
                               recv_mac: :undefined, encrypt: :undefined,
                               decrypt: :undefined, compress: :undefined,
                               decompress: :undefined, c_lng: :undefined,
                               s_lng: :undefined, send_ext_info: :undefined,
                               recv_ext_info: :undefined,
                               kex_strict_negotiated: false)
  Record.defrecord(:r_ssh_pty, :ssh_pty, c_version: '', term: '',
                                   width: 80, height: 25, pixel_width: 1024,
                                   pixel_height: 768, modes: <<>>)
  Record.defrecord(:r_circ_buf_entry, :circ_buf_entry, module: :undefined,
                                          line: :undefined,
                                          function: :undefined, pid: self(),
                                          value: :undefined)
  @behaviour :ssh_dbg
  def clear_default_algorithms_env() do
    :application.unset_env(:ssh, :"$def-algs$")
  end

  def default_algorithms() do
    fipsMode = :crypto.info_fips()
    case (:application.get_env(:ssh, :"$def-algs$")) do
      :undefined ->
        algs = build_cache()
        :application.set_env(:ssh, :"$def-algs$", {fipsMode, algs})
        algs
      {:ok, {^fipsMode, algs}} ->
        algs
      {:ok, {_OtherFipsMode, _Algs}} ->
        algs = build_cache()
        :application.set_env(:ssh, :"$def-algs$", {fipsMode, algs})
        algs
    end
  end

  defp build_cache() do
    opts = get_alg_conf()
    algs1 = (case (:proplists.get_value(:preferred_algorithms,
                                          opts)) do
               :undefined ->
                 for k <- algo_classes() do
                   {k, default_algorithms1(k)}
                 end
               algs0 ->
                 {true,
                    algs01} = :ssh_options.check_preferred_algorithms(algs0)
                 algs01
             end)
    algs = (case (:proplists.get_value(:modify_algorithms,
                                         opts)) do
              :undefined ->
                algs1
              modifications ->
                :ssh_options.initial_default_algorithms(algs1,
                                                          modifications)
            end)
    algs
  end

  defp get_alg_conf() do
    for t <- [:preferred_algorithms, :modify_algorithms],
          l <- [:application.get_env(:ssh, t, [])], l !== [] do
      {t, l}
    end
  end

  def algo_classes() do
    [:kex, :public_key, :cipher, :mac, :compression]
  end

  def algo_class(:kex) do
    true
  end

  def algo_class(:public_key) do
    true
  end

  def algo_class(:cipher) do
    true
  end

  def algo_class(:mac) do
    true
  end

  def algo_class(:compression) do
    true
  end

  def algo_class(_) do
    false
  end

  def algo_two_spec_classes() do
    [:cipher, :mac, :compression]
  end

  def algo_two_spec_class(:cipher) do
    true
  end

  def algo_two_spec_class(:mac) do
    true
  end

  def algo_two_spec_class(:compression) do
    true
  end

  def algo_two_spec_class(_) do
    false
  end

  def default_algorithms(tag) do
    fipsMode = :crypto.info_fips()
    case (:application.get_env(:ssh, :"$def-algs$")) do
      :undefined ->
        default_algorithms1(tag)
      {:ok, {^fipsMode, algs}} ->
        :proplists.get_value(tag, algs, [])
      {:ok, {_OtherFipsMode, _Algs}} ->
        algs = build_cache()
        :application.set_env(:ssh, :"$def-algs$", {fipsMode, algs})
        :proplists.get_value(tag, algs, [])
    end
  end

  defp default_algorithms1(:kex) do
    supported_algorithms(:kex, [:"diffie-hellman-group1-sha1", :"diffie-hellman-group14-sha1", :"diffie-hellman-group-exchange-sha1"])
  end

  defp default_algorithms1(:cipher) do
    supported_algorithms(:cipher,
                           same([:AEAD_AES_128_GCM, :AEAD_AES_256_GCM]))
  end

  defp default_algorithms1(:mac) do
    supported_algorithms(:mac,
                           same([:AEAD_AES_128_GCM, :AEAD_AES_256_GCM, :"hmac-sha1-96"]))
  end

  defp default_algorithms1(:public_key) do
    supported_algorithms(:public_key, [:"ssh-rsa", :"ssh-dss"])
  end

  defp default_algorithms1(alg) do
    supported_algorithms(alg, [])
  end

  def supported_algorithms() do
    for k <- algo_classes() do
      {k, supported_algorithms(k)}
    end
  end

  def supported_algorithms(:kex) do
    select_crypto_supported([{:"curve25519-sha256",
                                [{:public_keys, :ecdh}, {:curves, :x25519},
                                                            {:hashs, :sha256}]},
                                 {:"curve25519-sha256@libssh.org",
                                    [{:public_keys, :ecdh}, {:curves, :x25519},
                                                                {:hashs,
                                                                   :sha256}]},
                                     {:"curve448-sha512",
                                        [{:public_keys, :ecdh}, {:curves,
                                                                   :x448},
                                                                    {:hashs,
                                                                       :sha512}]},
                                         {:"ecdh-sha2-nistp521",
                                            [{:public_keys, :ecdh}, {:curves,
                                                                       :secp521r1},
                                                                        {:hashs,
                                                                           :sha512}]},
                                             {:"ecdh-sha2-nistp384",
                                                [{:public_keys, :ecdh},
                                                     {:curves, :secp384r1},
                                                         {:hashs, :sha384}]},
                                                 {:"ecdh-sha2-nistp256",
                                                    [{:public_keys, :ecdh},
                                                         {:curves, :secp256r1},
                                                             {:hashs,
                                                                :sha256}]},
                                                     {:"diffie-hellman-group-exchange-sha256",
                                                        [{:public_keys, :dh},
                                                             {:hashs,
                                                                :sha256}]},
                                                         {:"diffie-hellman-group16-sha512",
                                                            [{:public_keys,
                                                                :dh},
                                                                 {:hashs,
                                                                    :sha512}]},
                                                             {:"diffie-hellman-group18-sha512",
                                                                [{:public_keys,
                                                                    :dh},
                                                                     {:hashs,
                                                                        :sha512}]},
                                                                 {:"diffie-hellman-group14-sha256",
                                                                    [{:public_keys,
                                                                        :dh},
                                                                         {:hashs,
                                                                            :sha256}]},
                                                                     {:"diffie-hellman-group14-sha1",
                                                                        [{:public_keys,
                                                                            :dh},
                                                                             {:hashs,
                                                                                :sha}]},
                                                                         {:"diffie-hellman-group-exchange-sha1",
                                                                            [{:public_keys,
                                                                                :dh},
                                                                                 {:hashs,
                                                                                    :sha}]},
                                                                             {:"diffie-hellman-group1-sha1",
                                                                                [{:public_keys,
                                                                                    :dh},
                                                                                     {:hashs,
                                                                                        :sha}]}])
  end

  def supported_algorithms(:public_key) do
    select_crypto_supported([{:"ssh-ed25519",
                                [{:public_keys, :eddsa}, {:curves, :ed25519}]},
                                 {:"ssh-ed448",
                                    [{:public_keys, :eddsa}, {:curves,
                                                                :ed448}]},
                                     {:"ecdsa-sha2-nistp521",
                                        [{:public_keys, :ecdsa}, {:hashs,
                                                                    :sha512},
                                                                     {:curves,
                                                                        :secp521r1}]},
                                         {:"ecdsa-sha2-nistp384",
                                            [{:public_keys, :ecdsa}, {:hashs,
                                                                        :sha384},
                                                                         {:curves,
                                                                            :secp384r1}]},
                                             {:"ecdsa-sha2-nistp256",
                                                [{:public_keys, :ecdsa},
                                                     {:hashs, :sha256},
                                                         {:curves,
                                                            :secp256r1}]},
                                                 {:"rsa-sha2-512",
                                                    [{:public_keys, :rsa},
                                                         {:hashs, :sha512}]},
                                                     {:"rsa-sha2-256",
                                                        [{:public_keys, :rsa},
                                                             {:hashs,
                                                                :sha256}]},
                                                         {:"ssh-rsa",
                                                            [{:public_keys,
                                                                :rsa},
                                                                 {:hashs,
                                                                    :sha}]},
                                                             {:"ssh-dss",
                                                                [{:public_keys,
                                                                    :dss},
                                                                     {:hashs,
                                                                        :sha}]}])
  end

  def supported_algorithms(:cipher) do
    same(select_crypto_supported([{:"aes256-gcm@openssh.com",
                                     [{:ciphers, :aes_256_gcm}]},
                                      {:"aes256-ctr", [{:ciphers, :aes_256_ctr}]}, {:"aes192-ctr",
                                                                           [{:ciphers,
                                                                               :aes_192_ctr}]},
                                                                            {:"aes128-gcm@openssh.com",
                                                                               [{:ciphers,
                                                                                   :aes_128_gcm}]},
                                                                                {:"aes128-ctr",
                                                                                   [{:ciphers,
                                                                                       :aes_128_ctr}]},
                                                                                    {:AEAD_AES_256_GCM,
                                                                                       [{:ciphers,
                                                                                           :aes_256_gcm}]},
                                                                                        {:AEAD_AES_128_GCM,
                                                                                           [{:ciphers,
                                                                                               :aes_128_gcm}]},
                                                                                            {:"chacha20-poly1305@openssh.com",
                                                                                               [{:ciphers,
                                                                                                   :chacha20},
                                                                                                    {:macs,
                                                                                                       :poly1305}]},
                                                                                                {:"aes256-cbc",
                                                                                                   [{:ciphers,
                                                                                                       :aes_256_cbc}]},
                                                                                                    {:"aes192-cbc",
                                                                                                       [{:ciphers,
                                                                                                           :aes_192_cbc}]},
                                                                                                        {:"aes128-cbc",
                                                                                                           [{:ciphers,
                                                                                                               :aes_128_cbc}]},
                                                                                                            {:"3des-cbc",
                                                                                                               [{:ciphers,
                                                                                                                   :des_ede3_cbc}]}]))
  end

  def supported_algorithms(:mac) do
    same(select_crypto_supported([{:"hmac-sha2-512-etm@openssh.com",
                                     [{:macs, :hmac}, {:hashs, :sha256}]},
                                      {:"hmac-sha2-256-etm@openssh.com", [{:macs, :hmac}, {:hashs, :sha256}]},
                                          {:"hmac-sha2-512",
                                             [{:macs, :hmac}, {:hashs,
                                                                 :sha512}]},
                                              {:"hmac-sha2-256",
                                                 [{:macs, :hmac}, {:hashs,
                                                                     :sha256}]},
                                                  {:"hmac-sha1-etm@openssh.com",
                                                     [{:macs, :hmac}, {:hashs,
                                                                         :sha256}]},
                                                      {:"hmac-sha1",
                                                         [{:macs, :hmac},
                                                              {:hashs, :sha}]},
                                                          {:"hmac-sha1-96",
                                                             [{:macs, :hmac},
                                                                  {:hashs,
                                                                     :sha}]},
                                                              {:AEAD_AES_256_GCM,
                                                                 [{:ciphers,
                                                                     :aes_256_gcm}]},
                                                                  {:AEAD_AES_128_GCM,
                                                                     [{:ciphers,
                                                                         :aes_128_gcm}]}]))
  end

  def supported_algorithms(:compression) do
    same([:none, :"zlib@openssh.com", :zlib])
  end

  def versions(:client, options) do
    vsn = :ssh_options.get_value(:internal_options, :vsn,
                                   options,
                                   fn () ->
                                        {2, 0}
                                   end,
                                   :ssh_transport, 273)
    {vsn, format_version(vsn, software_version(options))}
  end

  def versions(:server, options) do
    vsn = :ssh_options.get_value(:internal_options, :vsn,
                                   options,
                                   fn () ->
                                        {2, 0}
                                   end,
                                   :ssh_transport, 276)
    {vsn, format_version(vsn, software_version(options))}
  end

  defp format_version({major, minor}, '') do
    :lists.concat(['SSH-', major, '.', minor])
  end

  defp format_version({major, minor}, softwareVersion) do
    :lists.concat(['SSH-', major, '.', minor, '-', softwareVersion])
  end

  defp software_version(options) do
    case (:ssh_options.get_value(:user_options, :id_string,
                                   options, :ssh_transport, 285)) do
      {:random, nlo, nup} ->
        random_id(nlo, nup)
      iD ->
        iD
    end
  end

  defp random_id(nlo, nup) do
    for _ <- :lists.duplicate(nlo + :rand.uniform((nup - nlo + 1)) - 1,
                                :x) do
      ?a + :rand.uniform((?z - ?a + 1)) - 1
    end
  end

  def hello_version_msg(data) do
    [data, '\r\n']
  end

  def next_seqnum(seqNum) do
    (seqNum + 1) &&& 4294967295
  end

  defp is_valid_mac(_, _, r_ssh(recv_mac_size: 0)) do
    true
  end

  defp is_valid_mac(mac, data,
            r_ssh(recv_mac: algorithm, recv_mac_key: key,
                recv_sequence: seqNum)) do
    :ssh_lib.comp(mac, mac(algorithm, key, seqNum, data))
  end

  def handle_hello_version(version) do
    try do
      strVersion = trim_tail(version)
      case (:string.tokens(version, '-')) do
        [_, '2.0' | _] ->
          {{2, 0}, strVersion}
        [_, '1.99' | _] ->
          {{2, 0}, strVersion}
        [_, '1.3' | _] ->
          {{1, 3}, strVersion}
        [_, '1.5' | _] ->
          {{1, 5}, strVersion}
      end
    catch
      :error, _ ->
        {:undefined, 'unknown version'}
    end
  end

  def key_exchange_init_msg(ssh0) do
    msg = kex_init(ssh0)
    {sshPacket, ssh} = ssh_packet(msg, ssh0)
    {msg, sshPacket, ssh}
  end

  defp kex_init(r_ssh(role: role, opts: opts,
              available_host_keys: hostKeyAlgs) = ssh) do
    random = :ssh_bits.random(16)
    prefAlgs = adjust_algs_for_peer_version(role,
                                              :ssh_options.get_value(:user_options,
                                                                       :preferred_algorithms,
                                                                       opts,
                                                                       :ssh_transport,
                                                                       332),
                                              ssh)
    kexinit_message(role, random, prefAlgs, hostKeyAlgs,
                      opts)
  end

  def key_init(:client, ssh, value) do
    r_ssh(ssh, c_keyinit: value)
  end

  def key_init(:server, ssh, value) do
    r_ssh(ssh, s_keyinit: value)
  end

  defp adjust_algs_for_peer_version(:client, prefAlgs, r_ssh(s_version: v)) do
    adjust_algs_for_peer_version(v, prefAlgs)
  end

  defp adjust_algs_for_peer_version(:server, prefAlgs, r_ssh(c_version: v)) do
    adjust_algs_for_peer_version(v, prefAlgs)
  end

  def adjust_algs_for_peer_version('SSH-2.0-OpenSSH_6.2' ++ _, prefAlgs) do
    c0 = :proplists.get_value(:cipher, prefAlgs, same([]))
    c = (for d <- [:client2server, :server2client],
               l <- [for k <- :proplists.get_value(d, c0, []),
                           k !== :"aes256-gcm@openssh.com", k !== :"aes128-gcm@openssh.com" do
                       k
                     end] do
           {d, l}
         end)
    :lists.keyreplace(:cipher, 1, prefAlgs, {:cipher, c})
  end

  def adjust_algs_for_peer_version(_, prefAlgs) do
    prefAlgs
  end

  defp kexinit_message(role, random, algs, hostKeyAlgs, opts) do
    r_ssh_msg_kexinit(cookie: random,
        kex_algorithms: to_strings(get_algs(:kex,
                                              algs)) ++ kex_ext_info(role,
                                                                       opts) ++ kex_strict_alg(role),
        server_host_key_algorithms: hostKeyAlgs,
        encryption_algorithms_client_to_server: c2s(:cipher,
                                                      algs),
        encryption_algorithms_server_to_client: s2c(:cipher,
                                                      algs),
        mac_algorithms_client_to_server: c2s(:mac, algs),
        mac_algorithms_server_to_client: s2c(:mac, algs),
        compression_algorithms_client_to_server: c2s(:compression,
                                                       algs),
        compression_algorithms_server_to_client: s2c(:compression,
                                                       algs),
        languages_client_to_server: [],
        languages_server_to_client: [])
  end

  defp c2s(key, algs) do
    x2y(:client2server, key, algs)
  end

  defp s2c(key, algs) do
    x2y(:server2client, key, algs)
  end

  defp x2y(directionKey, key, algs) do
    to_strings(:proplists.get_value(directionKey,
                                      get_algs(key, algs)))
  end

  defp get_algs(key, {_FipsMode, algs}) when is_list(algs) do
    :proplists.get_value(key, algs, default_algorithms(key))
  end

  defp get_algs(key, algs) when is_list(algs) do
    :proplists.get_value(key, algs, default_algorithms(key))
  end

  defp to_strings(l) do
    :lists.map(&:erlang.atom_to_list/1, l)
  end

  def new_keys_message(ssh0) do
    {sshPacket, ssh1} = ssh_packet(r_ssh_msg_newkeys(), ssh0)
    ssh = install_alg(:snd, ssh1)
    {:ok, sshPacket, ssh}
  end

  def handle_kexinit_msg(r_ssh_msg_kexinit() = counterPart, r_ssh_msg_kexinit() = own,
           r_ssh(role: :client) = ssh, reNeg) do
    try do
      {:ok, algorithms} = select_algorithm(:client, own,
                                             counterPart, ssh, reNeg)
      true = verify_algorithm(algorithms)
      true = verify_kexinit_is_first_msg(algorithms, ssh,
                                           reNeg)
      algorithms
    catch
      class, error ->
        msg = kexinit_error(class, error, :client, own,
                              counterPart)
        :ssh_connection_handler.disconnect(3, msg,
                                             :ssh_transport, 404)
    else
      algos ->
        key_exchange_first_msg(r_alg(algos, :kex),
                                 r_ssh(ssh, algorithms: algos))
    end
  end

  def handle_kexinit_msg(r_ssh_msg_kexinit() = counterPart, r_ssh_msg_kexinit() = own,
           r_ssh(role: :server) = ssh, reNeg) do
    try do
      {:ok, algorithms} = select_algorithm(:server,
                                             counterPart, own, ssh, reNeg)
      true = verify_algorithm(algorithms)
      true = verify_kexinit_is_first_msg(algorithms, ssh,
                                           reNeg)
      algorithms
    catch
      class, error ->
        msg = kexinit_error(class, error, :server, own,
                              counterPart)
        :ssh_connection_handler.disconnect(3, msg,
                                             :ssh_transport, 421)
    else
      algos ->
        {:ok, r_ssh(ssh, algorithms: algos)}
    end
  end

  defp kexinit_error(class, error, role, own, counterPart) do
    {fmt, args} = (case ({class, error}) do
                     {:error, {:badmatch, {false, alg}}} ->
                       {txt, w, c} = alg_info(role, alg)
                       {'No common ~s algorithm,~n  we have:~n    ~s~n  peer have:~n    ~s~n',
                          [txt, :lists.join(', ', :erlang.element(w, own)),
                                    :lists.join(', ',
                                                  :erlang.element(c,
                                                                    counterPart))]}
                     _ ->
                       {'Kexinit failed in ~p: ~p:~p', [role, class, error]}
                   end)
    try do
      :io_lib.format(fmt, args)
    catch
      _, _ ->
        :io_lib.format('Kexinit failed in ~p: ~p:~p', [role, class, error])
    else
      r ->
        r
    end
  end

  defp alg_info(:client, alg) do
    alg_info(alg)
  end

  defp alg_info(:server, alg) do
    {txt, c2s, s2c} = alg_info(alg)
    {txt, s2c, c2s}
  end

  defp alg_info('kex') do
    {'key exchange', r_ssh_msg_kexinit(:kex_algorithms), r_ssh_msg_kexinit(:kex_algorithms)}
  end

  defp alg_info('hkey') do
    {'key', r_ssh_msg_kexinit(:server_host_key_algorithms),
       r_ssh_msg_kexinit(:server_host_key_algorithms)}
  end

  defp alg_info('send_mac') do
    {'mac', r_ssh_msg_kexinit(:mac_algorithms_client_to_server),
       r_ssh_msg_kexinit(:mac_algorithms_server_to_client)}
  end

  defp alg_info('recv_mac') do
    {'mac', r_ssh_msg_kexinit(:mac_algorithms_client_to_server),
       r_ssh_msg_kexinit(:mac_algorithms_server_to_client)}
  end

  defp alg_info('encrypt') do
    {'cipher', r_ssh_msg_kexinit(:encryption_algorithms_client_to_server),
       r_ssh_msg_kexinit(:encryption_algorithms_server_to_client)}
  end

  defp alg_info('decrypt') do
    {'cipher', r_ssh_msg_kexinit(:encryption_algorithms_client_to_server),
       r_ssh_msg_kexinit(:encryption_algorithms_server_to_client)}
  end

  defp alg_info('compress') do
    {'compress', r_ssh_msg_kexinit(:compression_algorithms_client_to_server),
       r_ssh_msg_kexinit(:compression_algorithms_server_to_client)}
  end

  defp alg_info('decompress') do
    {'compress', r_ssh_msg_kexinit(:compression_algorithms_client_to_server),
       r_ssh_msg_kexinit(:compression_algorithms_server_to_client)}
  end

  defp verify_algorithm(r_alg(kex: :undefined)) do
    {false, 'kex'}
  end

  defp verify_algorithm(r_alg(hkey: :undefined)) do
    {false, 'hkey'}
  end

  defp verify_algorithm(r_alg(send_mac: :undefined)) do
    {false, 'send_mac'}
  end

  defp verify_algorithm(r_alg(recv_mac: :undefined)) do
    {false, 'recv_mac'}
  end

  defp verify_algorithm(r_alg(encrypt: :undefined)) do
    {false, 'encrypt'}
  end

  defp verify_algorithm(r_alg(decrypt: :undefined)) do
    {false, 'decrypt'}
  end

  defp verify_algorithm(r_alg(compress: :undefined)) do
    {false, 'compress'}
  end

  defp verify_algorithm(r_alg(decompress: :undefined)) do
    {false, 'decompress'}
  end

  defp verify_algorithm(r_alg(kex: kex)) do
    case (:lists.member(kex, supported_algorithms(:kex))) do
      true ->
        true
      false ->
        {false, 'kex'}
    end
  end

  defp verify_kexinit_is_first_msg(r_alg(kex_strict_negotiated: false), _, _) do
    true
  end

  defp verify_kexinit_is_first_msg(r_alg(kex_strict_negotiated: true), _,
            :renegotiate) do
    true
  end

  defp verify_kexinit_is_first_msg(r_alg(kex_strict_negotiated: true),
            r_ssh(send_sequence: 1, recv_sequence: 1), :init) do
    true
  end

  defp verify_kexinit_is_first_msg(r_alg(kex_strict_negotiated: true),
            r_ssh(send_sequence: sendSequence,
                recv_sequence: recvSequence),
            :init) do
    :error_logger.warning_report(:lists.concat(['KEX strict violation (',
                                                    sendSequence, ', ',
                                                                      recvSequence,
                                                                          ').']))
    {false, 'kex_strict'}
  end

  defp key_exchange_first_msg(kex, ssh0) when kex == :"diffie-hellman-group1-sha1" or kex == :"diffie-hellman-group14-sha1" or
                            kex == :"diffie-hellman-group14-sha256" or kex == :"diffie-hellman-group16-sha512" or kex == :"diffie-hellman-group18-sha512" do
    {g, p} = dh_group(kex)
    sz = dh_bits(r_ssh(ssh0, :algorithms))
    {public, private} = generate_key(:dh, [p, g, 2 * sz])
    {sshPacket, ssh1} = ssh_packet(r_ssh_msg_kexdh_init(e: public), ssh0)
    {:ok, sshPacket,
       r_ssh(ssh1, keyex_key: {{private, public}, {g, p}})}
  end

  defp key_exchange_first_msg(kex, ssh0 = r_ssh(opts: opts)) when kex == :"diffie-hellman-group-exchange-sha1" or
                                            kex == :"diffie-hellman-group-exchange-sha256" do
    {min, nBits0,
       max} = :ssh_options.get_value(:user_options,
                                       :dh_gex_limits, opts, :ssh_transport,
                                       528)
    dhBits = dh_bits(r_ssh(ssh0, :algorithms))
    nBits1 = (cond do
                dhBits <= 112 ->
                  2048
                dhBits <= 128 ->
                  3072
                dhBits <= 192 ->
                  7680
                true ->
                  8192
              end)
    nBits = min(max(max(nBits0, nBits1), min), max)
    {sshPacket, ssh1} = ssh_packet(r_ssh_msg_kex_dh_gex_request(min: min, n: nBits,
                                       max: max),
                                     ssh0)
    {:ok, sshPacket, r_ssh(ssh1, keyex_info: {min, max, nBits})}
  end

  defp key_exchange_first_msg(kex, ssh0) when kex == :"ecdh-sha2-nistp256" or kex == :"ecdh-sha2-nistp384" or
                            kex == :"ecdh-sha2-nistp521" or kex == :"curve25519-sha256" or kex == :"curve25519-sha256@libssh.org" or kex == :"curve448-sha512" do
    curve = ecdh_curve(kex)
    {public, private} = generate_key(:ecdh, curve)
    {sshPacket, ssh1} = ssh_packet(r_ssh_msg_kex_ecdh_init(q_c: public), ssh0)
    {:ok, sshPacket,
       r_ssh(ssh1, keyex_key: {{public, private}, curve})}
  end

  def handle_kexdh_init(r_ssh_msg_kexdh_init(e: e),
           ssh0 = r_ssh(algorithms: r_alg(kex: kex, hkey: signAlg) = algs,
                      opts: opts)) do
    {g, p} = dh_group(kex)
    cond do
      (1 <= e and e <= p - 1) ->
        sz = dh_bits(algs)
        {public, private} = generate_key(:dh, [p, g, 2 * sz])
        k = compute_key(:dh, e, private, [p, g])
        myPrivHostKey = get_host_key(signAlg, opts)
        myPubHostKey = :ssh_file.extract_public_key(myPrivHostKey)
        h = kex_hash(ssh0, myPubHostKey, sha(kex),
                       {e, public, k})
        case (sign(h, signAlg, myPrivHostKey, ssh0)) do
          {:ok, h_SIG} ->
            {sshPacket,
               ssh1} = ssh_packet(r_ssh_msg_kexdh_reply(public_host_key: {myPubHostKey,
                                                        signAlg},
                                      f: public, h_sig: h_SIG),
                                    ssh0)
            {:ok, sshPacket,
               r_ssh(ssh1, keyex_key: {{private, public}, {g, p}}, 
                         shared_secret: :ssh_bits.mpint(k),  exchanged_hash: h, 
                         session_id: sid(ssh1, h))}
          {:error, :unsupported_sign_alg} ->
            :ssh_connection_handler.disconnect(3,
                                                 :io_lib.format('Unsupported algorithm ~p', [signAlg]),
                                                 :ssh_transport, 595)
        end
      true ->
        :ssh_connection_handler.disconnect(3,
                                             :io_lib.format('Kexdh init failed, received \'e\' out of bounds~n  E=~p~n  P=~p', [e, p]),
                                             :ssh_transport, 601)
    end
  end

  def handle_kexdh_reply(r_ssh_msg_kexdh_reply(public_host_key: peerPubHostKey, f: f,
             h_sig: h_SIG),
           r_ssh(keyex_key: {{private, public}, {g, p}},
               algorithms: r_alg(kex: kex)) = ssh0) do
    cond do
      (1 <= f and f <= p - 1) ->
        k = compute_key(:dh, f, private, [p, g])
        h = kex_hash(ssh0, peerPubHostKey, sha(kex),
                       {public, f, k})
        case (verify_host_key(ssh0, peerPubHostKey, h,
                                h_SIG)) do
          :ok ->
            {sshPacket, ssh} = ssh_packet(r_ssh_msg_newkeys(), ssh0)
            {:ok, sshPacket,
               install_alg(:snd,
                             r_ssh(ssh, shared_secret: :ssh_bits.mpint(k), 
                                      exchanged_hash: h, 
                                      session_id: sid(ssh, h)))}
          error ->
            :ssh_connection_handler.disconnect(3,
                                                 :io_lib.format('Kexdh init failed. Verify host key: ~p', [error]),
                                                 :ssh_transport, 623)
        end
      true ->
        :ssh_connection_handler.disconnect(3,
                                             :io_lib.format('Kexdh init failed, received \'f\' out of bounds~n  F=~p~n  P=~p', [f, p]),
                                             :ssh_transport, 630)
    end
  end

  def handle_kex_dh_gex_request(r_ssh_msg_kex_dh_gex_request(min: min0, n: nBits, max: max0),
           ssh0 = r_ssh(opts: opts))
      when (min0 <= nBits and nBits <= max0) do
    {min, max} = adjust_gex_min_max(min0, max0, opts)
    case (:public_key.dh_gex_group(min, nBits, max,
                                     :ssh_options.get_value(:user_options,
                                                              :dh_gex_groups,
                                                              opts,
                                                              :ssh_transport,
                                                              646))) do
      {:ok, {_, {g, p}}} ->
        {sshPacket, ssh} = ssh_packet(r_ssh_msg_kex_dh_gex_group(p: p, g: g), ssh0)
        {:ok, sshPacket,
           r_ssh(ssh, keyex_key: {:x, {g, p}}, 
                    keyex_info: {min0, max0, nBits})}
      {:error, _} ->
        :ssh_connection_handler.disconnect(3,
                                             :io_lib.format('No possible diffie-hellman-group-exchange group found', []),
                                             :ssh_transport, 656)
    end
  end

  def handle_kex_dh_gex_request(r_ssh_msg_kex_dh_gex_request_old(n: nBits), ssh0 = r_ssh(opts: opts)) do
    min0 = nBits
    max0 = 8192
    {min, max} = adjust_gex_min_max(min0, max0, opts)
    case (:public_key.dh_gex_group(min, nBits, max,
                                     :ssh_options.get_value(:user_options,
                                                              :dh_gex_groups,
                                                              opts,
                                                              :ssh_transport,
                                                              678))) do
      {:ok, {_, {g, p}}} ->
        {sshPacket, ssh} = ssh_packet(r_ssh_msg_kex_dh_gex_group(p: p, g: g), ssh0)
        {:ok, sshPacket,
           r_ssh(ssh, keyex_key: {:x, {g, p}}, 
                    keyex_info: {- 1, - 1, nBits})}
      {:error, _} ->
        :ssh_connection_handler.disconnect(3,
                                             :io_lib.format('No possible diffie-hellman-group-exchange group found', []),
                                             :ssh_transport, 688)
    end
  end

  def handle_kex_dh_gex_request(_, _) do
    :ssh_connection_handler.disconnect(3, 'Key exchange failed, bad values in ssh_msg_kex_dh_gex_request', :ssh_transport,
                                         694)
  end

  defp adjust_gex_min_max(min0, max0, opts) do
    {min1, max1} = :ssh_options.get_value(:user_options,
                                            :dh_gex_limits, opts,
                                            :ssh_transport, 697)
    min2 = max(min0, min1)
    max2 = min(max0, max1)
    cond do
      min2 <= max2 ->
        {min2, max2}
      max2 < min2 ->
        :ssh_connection_handler.disconnect(2, 'No possible diffie-hellman-group-exchange group possible', :ssh_transport,
                                             705)
    end
  end

  def handle_kex_dh_gex_group(r_ssh_msg_kex_dh_gex_group(p: p, g: g), ssh0) do
    sz = dh_bits(r_ssh(ssh0, :algorithms))
    {public, private} = generate_key(:dh, [p, g, 2 * sz])
    {sshPacket, ssh1} = ssh_packet(r_ssh_msg_kex_dh_gex_init(e: public), ssh0)
    {:ok, sshPacket,
       r_ssh(ssh1, keyex_key: {{private, public}, {g, p}})}
  end

  def handle_kex_dh_gex_init(r_ssh_msg_kex_dh_gex_init(e: e),
           r_ssh(keyex_key: {{private, public}, {g, p}},
               keyex_info: {min, max, nBits},
               algorithms: r_alg(kex: kex, hkey: signAlg),
               opts: opts) = ssh0) do
    cond do
      (1 <= e and e <= p - 1) ->
        k = compute_key(:dh, e, private, [p, g])
        cond do
          (1 < k and k < p - 1) ->
            myPrivHostKey = get_host_key(signAlg, opts)
            myPubHostKey = :ssh_file.extract_public_key(myPrivHostKey)
            h = kex_hash(ssh0, myPubHostKey, sha(kex),
                           {min, nBits, max, p, g, e, public, k})
            case (sign(h, signAlg, myPrivHostKey, ssh0)) do
              {:ok, h_SIG} ->
                {sshPacket,
                   ssh} = ssh_packet(r_ssh_msg_kex_dh_gex_reply(public_host_key: {myPubHostKey,
                                                           signAlg},
                                         f: public, h_sig: h_SIG),
                                       ssh0)
                {:ok, sshPacket,
                   r_ssh(ssh, shared_secret: :ssh_bits.mpint(k), 
                            exchanged_hash: h,  session_id: sid(ssh, h))}
              {:error, :unsupported_sign_alg} ->
                :ssh_connection_handler.disconnect(3,
                                                     :io_lib.format('Unsupported algorithm ~p',
                                                                      [signAlg]),
                                                     :ssh_transport, 746)
            end
          true ->
            :ssh_connection_handler.disconnect(3, 'Kexdh init failed, received \'k\' out of bounds', :ssh_transport,
                                                 751)
        end
      true ->
        :ssh_connection_handler.disconnect(3,
                                             :io_lib.format('Kexdh gex init failed, received \'e\' out of bounds~n  E=~p~n  P=~p', [e, p]),
                                             :ssh_transport, 757)
    end
  end

  def handle_kex_dh_gex_reply(r_ssh_msg_kex_dh_gex_reply(public_host_key: peerPubHostKey, f: f,
             h_sig: h_SIG),
           r_ssh(keyex_key: {{private, public}, {g, p}},
               keyex_info: {min, max, nBits},
               algorithms: r_alg(kex: kex)) = ssh0) do
    cond do
      (1 <= f and f <= p - 1) ->
        k = compute_key(:dh, f, private, [p, g])
        cond do
          (1 < k and k < p - 1) ->
            h = kex_hash(ssh0, peerPubHostKey, sha(kex),
                           {min, nBits, max, p, g, public, f, k})
            case (verify_host_key(ssh0, peerPubHostKey, h,
                                    h_SIG)) do
              :ok ->
                {sshPacket, ssh} = ssh_packet(r_ssh_msg_newkeys(), ssh0)
                {:ok, sshPacket,
                   install_alg(:snd,
                                 r_ssh(ssh, shared_secret: :ssh_bits.mpint(k), 
                                          exchanged_hash: h, 
                                          session_id: sid(ssh, h)))}
              error ->
                :ssh_connection_handler.disconnect(3,
                                                     :io_lib.format('Kexdh gex reply failed. Verify host key: ~p', [error]),
                                                     :ssh_transport, 783)
            end
          true ->
            :ssh_connection_handler.disconnect(3, 'Kexdh gex init failed, \'K\' out of bounds', :ssh_transport,
                                                 789)
        end
      true ->
        :ssh_connection_handler.disconnect(3,
                                             :io_lib.format('Kexdh gex init failed, received \'f\' out of bounds~n  F=~p~n  P=~p', [f, p]),
                                             :ssh_transport, 795)
    end
  end

  def handle_kex_ecdh_init(r_ssh_msg_kex_ecdh_init(q_c: peerPublic),
           ssh0 = r_ssh(algorithms: r_alg(kex: kex, hkey: signAlg),
                      opts: opts)) do
    curve = ecdh_curve(kex)
    {myPublic, myPrivate} = generate_key(:ecdh, curve)
    try do
      compute_key(:ecdh, peerPublic, myPrivate, curve)
    catch
      class, error ->
        :ssh_connection_handler.disconnect(3,
                                             :io_lib.format('ECDH compute key failed in server: ~p:~p~nKex: ~p, Curve: ~p~nPeerPublic: ~p',
                                                              [class, error,
                                                                          kex,
                                                                              curve,
                                                                                  peerPublic]),
                                             :ssh_transport, 839)
    else
      k ->
        myPrivHostKey = get_host_key(signAlg, opts)
        myPubHostKey = :ssh_file.extract_public_key(myPrivHostKey)
        h = kex_hash(ssh0, myPubHostKey, sha(curve),
                       {peerPublic, myPublic, k})
        case (sign(h, signAlg, myPrivHostKey, ssh0)) do
          {:ok, h_SIG} ->
            {sshPacket,
               ssh1} = ssh_packet(r_ssh_msg_kex_ecdh_reply(public_host_key: {myPubHostKey,
                                                        signAlg},
                                      q_s: myPublic, h_sig: h_SIG),
                                    ssh0)
            {:ok, sshPacket,
               r_ssh(ssh1, keyex_key: {{myPublic, myPrivate}, curve}, 
                         shared_secret: :ssh_bits.mpint(k),  exchanged_hash: h, 
                         session_id: sid(ssh1, h))}
          {:error, :unsupported_sign_alg} ->
            :ssh_connection_handler.disconnect(3,
                                                 :io_lib.format('Unsupported algorithm ~p', [signAlg]),
                                                 :ssh_transport, 830)
        end
    end
  end

  def handle_kex_ecdh_reply(r_ssh_msg_kex_ecdh_reply(public_host_key: peerPubHostKey,
             q_s: peerPublic, h_sig: h_SIG),
           r_ssh(keyex_key: {{myPublic, myPrivate}, curve}) = ssh0) do
    try do
      compute_key(:ecdh, peerPublic, myPrivate, curve)
    catch
      class, error ->
        :ssh_connection_handler.disconnect(3,
                                             :io_lib.format('Peer ECDH public key seem invalid: ~p:~p', [class, error]),
                                             :ssh_transport, 870)
    else
      k ->
        h = kex_hash(ssh0, peerPubHostKey, sha(curve),
                       {myPublic, peerPublic, k})
        case (verify_host_key(ssh0, peerPubHostKey, h,
                                h_SIG)) do
          :ok ->
            {sshPacket, ssh} = ssh_packet(r_ssh_msg_newkeys(), ssh0)
            {:ok, sshPacket,
               install_alg(:snd,
                             r_ssh(ssh, shared_secret: :ssh_bits.mpint(k), 
                                      exchanged_hash: h, 
                                      session_id: sid(ssh, h)))}
          error ->
            :ssh_connection_handler.disconnect(3,
                                                 :io_lib.format('ECDH reply failed. Verify host key: ~p', [error]),
                                                 :ssh_transport, 863)
        end
    end
  end

  def handle_new_keys(r_ssh_msg_newkeys(), ssh0) do
    try do
      install_alg(:rcv, ssh0)
    catch
      class, error ->
        :ssh_connection_handler.disconnect(2,
                                             :io_lib.format('Install alg failed: ~p:~p', [class, error]),
                                             :ssh_transport, 884)
    else
      r_ssh() = ssh ->
        {:ok, ssh}
    end
  end

  defp kex_strict_alg(:client) do
    ['kex-strict-c-v00@openssh.com']
  end

  defp kex_strict_alg(:server) do
    ['kex-strict-s-v00@openssh.com']
  end

  defp kex_ext_info(role, opts) do
    case (:ssh_options.get_value(:user_options,
                                   :recv_ext_info, opts, :ssh_transport,
                                   894)) do
      true when role == :client ->
        ['ext-info-c']
      true when role == :server ->
        ['ext-info-s']
      false ->
        []
    end
  end

  def ext_info_message(r_ssh(role: :client, send_ext_info: true,
             opts: opts) = ssh0) do
    case (:proplists.get_value(:ext_info_client,
                                 :ssh_options.get_value(:user_options, :tstflg,
                                                          opts, :ssh_transport,
                                                          906))) do
      true ->
        msg = r_ssh_msg_ext_info(nr_extensions: 1, data: [{'test@erlang.org', 'Testing,PleaseIgnore'}])
        {sshPacket, ssh} = ssh_packet(msg, ssh0)
        {:ok, sshPacket, ssh}
      _ ->
        {:ok, '', ssh0}
    end
  end

  def ext_info_message(r_ssh(role: :server, send_ext_info: true,
             opts: opts) = ssh0) do
    algsList = :lists.map(&:erlang.atom_to_list/1,
                            :ssh_options.get_value(:user_options,
                                                     :pref_public_key_algs,
                                                     opts, :ssh_transport, 921))
    msg = r_ssh_msg_ext_info(nr_extensions: 1,
              data: [{'server-sig-algs', :string.join(algsList, ',')}])
    {sshPacket, ssh} = ssh_packet(msg, ssh0)
    {:ok, sshPacket, ssh}
  end

  def ext_info_message(ssh0) do
    {:ok, '', ssh0}
  end

  defp sid(r_ssh(session_id: :undefined), h) do
    h
  end

  defp sid(r_ssh(session_id: id), _) do
    id
  end

  def get_host_key(signAlg, opts) do
    case (call_KeyCb(:host_key, [signAlg], opts)) do
      {:ok, privHostKey} ->
        case (valid_key_sha_alg(:private, privHostKey,
                                  signAlg)) do
          true ->
            privHostKey
          false ->
            exit({:error, :bad_hostkey})
        end
      result ->
        exit({:error, {result, :unsupported_key_type}})
    end
  end

  def call_KeyCb(f, args, opts) do
    {keyCb,
       keyCbOpts} = :ssh_options.get_value(:user_options,
                                             :key_cb, opts, :ssh_transport, 952)
    userOpts = :ssh_options.get_value(:user_options,
                                        :key_cb_options, opts, :ssh_transport,
                                        953)
    apply(keyCb, f,
            args ++ [[{:key_cb_private, keyCbOpts} | userOpts]])
  end

  defp verify_host_key(r_ssh(algorithms: alg) = sSH, publicKey, digest,
            {algStr, signature}) do
    case (:erlang.atom_to_list(r_alg(alg, :hkey))) do
      ^algStr ->
        case (verify(digest, r_alg(alg, :hkey), signature,
                       publicKey, sSH)) do
          false ->
            {:error, :bad_signature}
          true ->
            known_host_key(sSH, publicKey, public_algo(publicKey))
        end
      _ ->
        {:error, :bad_signature_name}
    end
  end

  defp accepted_host(ssh, peerName, port, public, opts) do
    portStr = (case (port) do
                 22 ->
                   ''
                 _ ->
                   :lists.concat([':', port])
               end)
    case (:ssh_options.get_value(:user_options,
                                   :silently_accept_hosts, opts, :ssh_transport,
                                   977)) do
      false ->
        :yes == yes_no(ssh, 'New host ' ++ peerName ++ portStr ++ ' accept')
      true ->
        true
      {false, alg} ->
        hostKeyAlg = r_alg(r_ssh(ssh, :algorithms), :hkey)
        prompt = :io_lib.format('The authenticity of the host can\'t be established.~n~s host key fingerprint is ~s.~nNew host ~p~p accept',
                                  [fmt_hostkey(hostKeyAlg),
                                       :ssh.hostkey_fingerprint(alg, public),
                                           peerName, portStr])
        :yes == yes_no(ssh, prompt)
      f when is_function(f, 2) ->
        case ((try do
                f.(peerName, :ssh.hostkey_fingerprint(public))
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end)) do
          true ->
            true
          _ ->
            {:error, :fingerprint_check_failed}
        end
      f when is_function(f, 3) ->
        case ((try do
                f.(peerName, port, :ssh.hostkey_fingerprint(public))
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end)) do
          true ->
            true
          _ ->
            {:error, :fingerprint_check_failed}
        end
      {digestAlg, f} when is_function(f, 2) ->
        case ((try do
                f.(peerName,
                     :ssh.hostkey_fingerprint(digestAlg, public))
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end)) do
          true ->
            true
          _ ->
            {:error, {:fingerprint_check_failed, digestAlg}}
        end
      {digestAlg, f} when is_function(f, 3) ->
        case ((try do
                f.(peerName, port,
                     :ssh.hostkey_fingerprint(digestAlg, public))
              catch
                :error, e -> {:EXIT, {e, __STACKTRACE__}}
                :exit, e -> {:EXIT, e}
                e -> e
              end)) do
          true ->
            true
          _ ->
            {:error, {:fingerprint_check_failed, digestAlg}}
        end
    end
  end

  defp yes_no(r_ssh(opts: opts), prompt) do
    ioCb = :ssh_options.get_value(:internal_options, :io_cb,
                                    opts,
                                    fn () ->
                                         :ssh_io
                                    end,
                                    :ssh_transport, 1022)
    ioCb.yes_no(prompt, opts)
  end

  defp fmt_hostkey(:"ssh-rsa") do
    'RSA'
  end

  defp fmt_hostkey(:"ssh-dss") do
    'DSA'
  end

  defp fmt_hostkey(:"ssh-ed25519") do
    'ED25519'
  end

  defp fmt_hostkey(:"ssh-ed448") do
    'ED448'
  end

  defp fmt_hostkey(a) when is_atom(a) do
    fmt_hostkey(:erlang.atom_to_list(a))
  end

  defp fmt_hostkey('ecdsa' ++ _) do
    'ECDSA'
  end

  defp fmt_hostkey(x) do
    x
  end

  defp known_host_key(r_ssh(opts: opts,
              peer: {peerName, {iP, port}}) = ssh,
            public, alg) do
    isHostKey = (try do
                   call_KeyCb(:is_host_key,
                                [public, [peerName, iP], port, alg], opts)
                 catch
                   :error, :undef ->
                     call_KeyCb(:is_host_key, [public, peerName, alg], opts)
                 end)
    case (isHostKey) do
      true ->
        :ok
      false ->
        doAdd = :ssh_options.get_value(:user_options,
                                         :save_accepted_host, opts,
                                         :ssh_transport, 1052)
        case (accepted_host(ssh, peerName, port, public,
                              opts)) do
          true when doAdd == true ->
            try do
              call_KeyCb(:add_host_key,
                           [[peerName, iP], port, public], opts)
            catch
              :error, :undef ->
                call_KeyCb(:add_host_key, [peerName, public], opts)
            end
          true when doAdd == false ->
            :ok
          false ->
            {:error, :rejected_by_user}
          {:error, e} ->
            {:error, e}
        end
      {:error, error} ->
        {:error, error}
    end
  end

  defp select_algorithm(role, client, server,
            r_ssh(opts: opts,
                kex_strict_negotiated: kexStrictNegotiated0),
            reNeg) do
    kexStrictNegotiated = (case (reNeg) do
                             :init ->
                               result = (case (role) do
                                           :server ->
                                             :lists.member('kex-strict-c-v00@openssh.com',
                                                             r_ssh_msg_kexinit(client, :kex_algorithms))
                                           :client ->
                                             :lists.member('kex-strict-s-v00@openssh.com',
                                                             r_ssh_msg_kexinit(server, :kex_algorithms))
                                         end)
                               case (result) do
                                 true ->
                                   :logger.debug(:lists.concat([role, ' will use strict KEX ordering']))
                                 _ ->
                                   :ok
                               end
                               result
                             _ ->
                               kexStrictNegotiated0
                           end)
    {encrypt0, decrypt0} = select_encrypt_decrypt(role,
                                                    client, server)
    {sendMac0, recvMac0} = select_send_recv_mac(role,
                                                  client, server)
    {encrypt, sendMac} = aead_gcm_simultan(encrypt0,
                                             sendMac0)
    {decrypt, recvMac} = aead_gcm_simultan(decrypt0,
                                             recvMac0)
    {compression,
       decompression} = select_compression_decompression(role,
                                                           client, server)
    c_Lng = select(r_ssh_msg_kexinit(client, :languages_client_to_server),
                     r_ssh_msg_kexinit(server, :languages_client_to_server))
    s_Lng = select(r_ssh_msg_kexinit(client, :languages_server_to_client),
                     r_ssh_msg_kexinit(server, :languages_server_to_client))
    hKey = select_all(r_ssh_msg_kexinit(client, :server_host_key_algorithms),
                        r_ssh_msg_kexinit(server, :server_host_key_algorithms))
    hK = (case (hKey) do
            [] ->
              :undefined
            [hK0 | _] ->
              hK0
          end)
    kex = select(r_ssh_msg_kexinit(client, :kex_algorithms),
                   r_ssh_msg_kexinit(server, :kex_algorithms))
    sendExtInfo = :ssh_options.get_value(:user_options,
                                           :send_ext_info, opts, :ssh_transport,
                                           1135) and (case (role) do
                                                        :server ->
                                                          :lists.member('ext-info-c',
                                                                          r_ssh_msg_kexinit(client, :kex_algorithms))
                                                        :client ->
                                                          :lists.member('ext-info-s',
                                                                          r_ssh_msg_kexinit(server, :kex_algorithms))
                                                      end)
    recvExtInfo = :ssh_options.get_value(:user_options,
                                           :recv_ext_info, opts, :ssh_transport,
                                           1146)
    {:ok,
       r_alg(kex: kex, hkey: hK, encrypt: encrypt,
           decrypt: decrypt, send_mac: sendMac, recv_mac: recvMac,
           compress: compression, decompress: decompression,
           c_lng: c_Lng, s_lng: s_Lng, send_ext_info: sendExtInfo,
           recv_ext_info: recvExtInfo,
           kex_strict_negotiated: kexStrictNegotiated)}
  end

  defp aead_gcm_simultan(:"aes128-gcm@openssh.com", _) do
    {:AEAD_AES_128_GCM, :AEAD_AES_128_GCM}
  end

  defp aead_gcm_simultan(:"aes256-gcm@openssh.com", _) do
    {:AEAD_AES_256_GCM, :AEAD_AES_256_GCM}
  end

  defp aead_gcm_simultan(:AEAD_AES_128_GCM = c, _) do
    {c, c}
  end

  defp aead_gcm_simultan(:AEAD_AES_256_GCM = c, _) do
    {c, c}
  end

  defp aead_gcm_simultan(_, :AEAD_AES_128_GCM = c) do
    {c, c}
  end

  defp aead_gcm_simultan(_, :AEAD_AES_256_GCM = c) do
    {c, c}
  end

  defp aead_gcm_simultan(:"chacha20-poly1305@openssh.com" = c, _) do
    {c, c}
  end

  defp aead_gcm_simultan(cipher, mac) do
    {cipher, mac}
  end

  defp select_encrypt_decrypt(:client, client, server) do
    encrypt = select(r_ssh_msg_kexinit(client, :encryption_algorithms_client_to_server),
                       r_ssh_msg_kexinit(server, :encryption_algorithms_client_to_server))
    decrypt = select(r_ssh_msg_kexinit(client, :encryption_algorithms_server_to_client),
                       r_ssh_msg_kexinit(server, :encryption_algorithms_server_to_client))
    {encrypt, decrypt}
  end

  defp select_encrypt_decrypt(:server, client, server) do
    decrypt = select(r_ssh_msg_kexinit(client, :encryption_algorithms_client_to_server),
                       r_ssh_msg_kexinit(server, :encryption_algorithms_client_to_server))
    encrypt = select(r_ssh_msg_kexinit(client, :encryption_algorithms_server_to_client),
                       r_ssh_msg_kexinit(server, :encryption_algorithms_server_to_client))
    {encrypt, decrypt}
  end

  defp select_send_recv_mac(:client, client, server) do
    sendMac = select(r_ssh_msg_kexinit(client, :mac_algorithms_client_to_server),
                       r_ssh_msg_kexinit(server, :mac_algorithms_client_to_server))
    recvMac = select(r_ssh_msg_kexinit(client, :mac_algorithms_server_to_client),
                       r_ssh_msg_kexinit(server, :mac_algorithms_server_to_client))
    {sendMac, recvMac}
  end

  defp select_send_recv_mac(:server, client, server) do
    recvMac = select(r_ssh_msg_kexinit(client, :mac_algorithms_client_to_server),
                       r_ssh_msg_kexinit(server, :mac_algorithms_client_to_server))
    sendMac = select(r_ssh_msg_kexinit(client, :mac_algorithms_server_to_client),
                       r_ssh_msg_kexinit(server, :mac_algorithms_server_to_client))
    {sendMac, recvMac}
  end

  defp select_compression_decompression(:client, client, server) do
    compression = select(r_ssh_msg_kexinit(client, :compression_algorithms_client_to_server),
                           r_ssh_msg_kexinit(server, :compression_algorithms_client_to_server))
    decompression = select(r_ssh_msg_kexinit(client, :compression_algorithms_server_to_client),
                             r_ssh_msg_kexinit(server, :compression_algorithms_server_to_client))
    {compression, decompression}
  end

  defp select_compression_decompression(:server, client, server) do
    decompression = select(r_ssh_msg_kexinit(client, :compression_algorithms_client_to_server),
                             r_ssh_msg_kexinit(server, :compression_algorithms_client_to_server))
    compression = select(r_ssh_msg_kexinit(client, :compression_algorithms_server_to_client),
                           r_ssh_msg_kexinit(server, :compression_algorithms_server_to_client))
    {compression, decompression}
  end

  defp install_alg(dir, sSH) do
    sSH1 = alg_final(dir, sSH)
    sSH2 = alg_setup(dir, sSH1)
    alg_init(dir, sSH2)
  end

  defp alg_setup(:snd, sSH) do
    aLG = r_ssh(sSH, :algorithms)
    r_ssh(sSH, encrypt: r_alg(aLG, :encrypt), 
             send_mac: r_alg(aLG, :send_mac), 
             send_mac_size: mac_digest_size(r_alg(aLG, :send_mac)), 
             compress: r_alg(aLG, :compress),  c_lng: r_alg(aLG, :c_lng), 
             s_lng: r_alg(aLG, :s_lng), 
             send_ext_info: r_alg(aLG, :send_ext_info), 
             recv_ext_info: r_alg(aLG, :recv_ext_info), 
             kex_strict_negotiated: r_alg(aLG, :kex_strict_negotiated))
  end

  defp alg_setup(:rcv, sSH) do
    aLG = r_ssh(sSH, :algorithms)
    r_ssh(sSH, decrypt: r_alg(aLG, :decrypt), 
             recv_mac: r_alg(aLG, :recv_mac), 
             recv_mac_size: mac_digest_size(r_alg(aLG, :recv_mac)), 
             decompress: r_alg(aLG, :decompress), 
             c_lng: r_alg(aLG, :c_lng),  s_lng: r_alg(aLG, :s_lng), 
             send_ext_info: r_alg(aLG, :send_ext_info), 
             recv_ext_info: r_alg(aLG, :recv_ext_info), 
             kex_strict_negotiated: r_alg(aLG, :kex_strict_negotiated))
  end

  defp alg_init(dir = :snd, sSH0) do
    {:ok, sSH1} = send_mac_init(sSH0)
    {:ok, sSH2} = encrypt_init(sSH1)
    {:ok, sSH3} = compress_init(sSH2)
    {:ok, sSH4} = maybe_reset_sequence(dir, sSH3)
    sSH4
  end

  defp alg_init(dir = :rcv, sSH0) do
    {:ok, sSH1} = recv_mac_init(sSH0)
    {:ok, sSH2} = decrypt_init(sSH1)
    {:ok, sSH3} = decompress_init(sSH2)
    {:ok, sSH4} = maybe_reset_sequence(dir, sSH3)
    sSH4
  end

  defp alg_final(:snd, sSH0) do
    {:ok, sSH1} = send_mac_final(sSH0)
    {:ok, sSH2} = encrypt_final(sSH1)
    {:ok, sSH3} = compress_final(sSH2)
    sSH3
  end

  defp alg_final(:rcv, sSH0) do
    {:ok, sSH1} = recv_mac_final(sSH0)
    {:ok, sSH2} = decrypt_final(sSH1)
    {:ok, sSH3} = decompress_final(sSH2)
    sSH3
  end

  defp select_all(cL, sL) when length(cL) + length(sL) < 200 do
    cLonly = cL -- sL
    :lists.foldr(fn aLG, acc ->
                      try do
                        [:erlang.list_to_existing_atom(aLG) | acc]
                      catch
                        _, _ ->
                          acc
                      end
                 end,
                   [], cL -- cLonly)
  end

  defp select_all(cL, sL) do
    error = :lists.concat(['Received too many algorithms (', length(cL), '+', length(sL), ' >= ',
                                                             200, ').'])
    :ssh_connection_handler.disconnect(2, error,
                                         :ssh_transport, 1321)
  end

  defp select([], []) do
    :none
  end

  defp select(cL, sL) do
    c = (case (select_all(cL, sL)) do
           [] ->
             :undefined
           [aLG | _] ->
             aLG
         end)
    c
  end

  def ssh_packet(r_ssh_msg_kexinit() = msg, ssh0) do
    binMsg = :ssh_message.encode(msg)
    ssh = key_init(r_ssh(ssh0, :role), ssh0, binMsg)
    pack(binMsg, ssh)
  end

  def ssh_packet(msg, ssh) do
    binMsg = :ssh_message.encode(msg)
    pack(binMsg, ssh)
  end

  def pack(data, ssh = r_ssh()) do
    pack(data, ssh, 0)
  end

  def pack(plainText,
           r_ssh(send_sequence: seqNum, send_mac: macAlg,
               encrypt: cryptoAlg) = ssh0,
           packetLenDeviationForTests)
      when is_binary(plainText) do
    {ssh1, compressedPlainText} = compress(ssh0, plainText)
    {finalPacket, ssh2} = pack(pkt_type(cryptoAlg),
                                 mac_type(macAlg), compressedPlainText,
                                 packetLenDeviationForTests, ssh1)
    ssh = r_ssh(ssh2, send_sequence: (seqNum + 1) &&& 4294967295)
    {finalPacket, ssh}
  end

  defp pack(:common, :rfc4253, plainText, deltaLenTst,
            r_ssh(send_sequence: seqNum, send_mac: macAlg,
                send_mac_key: macKey) = ssh0) do
    padLen = padding_length(4 + 1 + byte_size(plainText),
                              ssh0)
    pad = :ssh_bits.random(padLen)
    textLen = 1 + byte_size(plainText) + padLen + deltaLenTst
    plainPkt = <<textLen
                 ::
                 size(32) - unsigned - big - integer,
                   padLen :: size(8) - unsigned - big - integer,
                   plainText :: binary, pad :: binary>>
    {ssh1, cipherPkt} = encrypt(ssh0, plainPkt)
    mAC0 = mac(macAlg, macKey, seqNum, plainPkt)
    {<<cipherPkt :: binary, mAC0 :: binary>>, ssh1}
  end

  defp pack(:common, :enc_then_mac, plainText, deltaLenTst,
            r_ssh(send_sequence: seqNum, send_mac: macAlg,
                send_mac_key: macKey) = ssh0) do
    padLen = padding_length(1 + byte_size(plainText), ssh0)
    pad = :ssh_bits.random(padLen)
    plainLen = 1 + byte_size(plainText) + padLen + deltaLenTst
    plainPkt = <<padLen
                 ::
                 size(8) - unsigned - big - integer,
                   plainText :: binary, pad :: binary>>
    {ssh1, cipherPkt} = encrypt(ssh0, plainPkt)
    encPacketPkt = <<plainLen
                     ::
                     size(32) - unsigned - big - integer,
                       cipherPkt :: binary>>
    mAC0 = mac(macAlg, macKey, seqNum, encPacketPkt)
    {<<plainLen :: size(32) - unsigned - big - integer,
         cipherPkt :: binary, mAC0 :: binary>>,
       ssh1}
  end

  defp pack(:aead, _, plainText, deltaLenTst, ssh0) do
    padLen = padding_length(1 + byte_size(plainText), ssh0)
    pad = :ssh_bits.random(padLen)
    plainLen = 1 + byte_size(plainText) + padLen + deltaLenTst
    plainPkt = <<padLen
                 ::
                 size(8) - unsigned - big - integer,
                   plainText :: binary, pad :: binary>>
    {ssh1, {cipherPkt, mAC0}} = encrypt(ssh0,
                                          <<plainLen
                                            ::
                                            size(32) - unsigned - big - integer,
                                              plainPkt :: binary>>)
    {<<cipherPkt :: binary, mAC0 :: binary>>, ssh1}
  end

  def handle_packet_part(<<>>, encrypted0, aEAD0, :undefined,
           r_ssh(decrypt: cryptoAlg, recv_mac: macAlg) = ssh0) do
    case (get_length(pkt_type(cryptoAlg), mac_type(macAlg),
                       encrypted0, ssh0)) do
      :get_more ->
        {:get_more, <<>>, encrypted0, aEAD0, :undefined, ssh0}
      {:ok, packetLen, _, _, _, _} when packetLen > 256 * 1024
                                        ->
        {:error, {:exceeds_max_size, packetLen}}
      {:ok, packetLen, decrypted, encrypted1, aEAD,
         r_ssh(recv_mac_size: macSize) = ssh1} ->
        totalNeeded = 4 + packetLen + macSize
        handle_packet_part(decrypted, encrypted1, aEAD,
                             totalNeeded, ssh1)
    end
  end

  def handle_packet_part(decryptedPfx, encryptedBuffer, aEAD, totalNeeded,
           ssh0)
      when byte_size(decryptedPfx) + byte_size(encryptedBuffer) < totalNeeded do
    {:get_more, decryptedPfx, encryptedBuffer, aEAD,
       totalNeeded, ssh0}
  end

  def handle_packet_part(decryptedPfx, encryptedBuffer, aEAD, totalNeeded,
           r_ssh(decrypt: cryptoAlg, recv_mac: macAlg) = ssh0) do
    case (unpack(pkt_type(cryptoAlg), mac_type(macAlg),
                   decryptedPfx, encryptedBuffer, aEAD, totalNeeded,
                   ssh0)) do
      {:ok, payload, nextPacketBytes, ssh1} ->
        {ssh, decompressedPayload} = decompress(ssh1, payload)
        {:packet_decrypted, decompressedPayload,
           nextPacketBytes, ssh}
      other ->
        other
    end
  end

  defp unpack(:common, :rfc4253, decryptedPfx,
            encryptedBuffer, _AEAD, totalNeeded,
            r_ssh(recv_mac_size: macSize) = ssh0) do
    moreNeeded = totalNeeded - byte_size(decryptedPfx) - macSize
    <<encryptedSfx :: size(moreNeeded) - binary,
        mac :: size(macSize) - binary,
        nextPacketBytes :: binary>> = encryptedBuffer
    {ssh1, decryptedSfx} = decrypt(ssh0, encryptedSfx)
    plainPkt = <<decryptedPfx :: binary,
                   decryptedSfx :: binary>>
    case (is_valid_mac(mac, plainPkt, ssh1)) do
      true ->
        {:ok, payload(plainPkt), nextPacketBytes, ssh1}
      false ->
        {:bad_mac, ssh1}
    end
  end

  defp unpack(:common, :enc_then_mac,
            <<plainLen :: size(32) - unsigned - big - integer>>,
            encryptedBuffer, _AEAD, _TotalNeeded,
            r_ssh(recv_mac_size: macSize) = ssh0) do
    <<payload :: size(plainLen) - binary,
        mAC0 :: size(macSize) - binary,
        nextPacketBytes :: binary>> = encryptedBuffer
    case (is_valid_mac(mAC0,
                         <<plainLen :: size(32) - unsigned - big - integer,
                             payload :: binary>>,
                         ssh0)) do
      true ->
        {ssh1,
           <<paddingLen :: size(8) - unsigned - big - integer,
               plainRest :: binary>>} = decrypt(ssh0, payload)
        compressedPlainTextLen = byte_size(plainRest) - paddingLen
        <<compressedPlainText
          ::
          size(compressedPlainTextLen) - binary,
            _Padding :: binary>> = plainRest
        {:ok, compressedPlainText, nextPacketBytes, ssh1}
      false ->
        {:bad_mac, ssh0}
    end
  end

  defp unpack(:aead, _, decryptedPfx, encryptedBuffer, aEAD,
            totalNeeded, r_ssh(recv_mac_size: macSize) = ssh0) do
    moreNeeded = totalNeeded - byte_size(decryptedPfx) - macSize
    <<encryptedSfx :: size(moreNeeded) - binary,
        mac :: size(macSize) - binary,
        nextPacketBytes :: binary>> = encryptedBuffer
    case (decrypt(ssh0, {aEAD, encryptedSfx, mac})) do
      {ssh1, :error} ->
        {:bad_mac, ssh1}
      {ssh1, decryptedSfx} ->
        decryptedPacket = <<decryptedPfx :: binary,
                              decryptedSfx :: binary>>
        {:ok, payload(decryptedPacket), nextPacketBytes, ssh1}
    end
  end

  defp get_length(:common, :rfc4253, encryptedBuffer,
            r_ssh(decrypt_block_size: blockSize) = ssh0) do
    case (byte_size(encryptedBuffer) >= :erlang.max(8,
                                                      blockSize)) do
      true ->
        <<encBlock :: size(blockSize) - binary,
            encryptedRest :: binary>> = encryptedBuffer
        {ssh,
           <<packetLen :: size(32) - unsigned - big - integer,
               _ :: binary>> = decrypted} = decrypt(ssh0, encBlock)
        {:ok, packetLen, decrypted, encryptedRest, <<>>, ssh}
      false ->
        :get_more
    end
  end

  defp get_length(:common, :enc_then_mac, encryptedBuffer, ssh) do
    case (encryptedBuffer) do
      <<decrypted :: size(4) - binary,
          encryptedRest :: binary>> ->
        <<packetLen
          ::
          size(32) - unsigned - big - integer>> = decrypted
        {:ok, packetLen, decrypted, encryptedRest, <<>>, ssh}
      _ ->
        :get_more
    end
  end

  defp get_length(:aead, _, encryptedBuffer, ssh) do
    case ({byte_size(encryptedBuffer) >= 4,
             r_ssh(ssh, :decrypt)}) do
      {true, :"chacha20-poly1305@openssh.com"} ->
        <<encryptedLen :: size(4) - binary,
            encryptedRest :: binary>> = encryptedBuffer
        {ssh1, packetLenBin} = decrypt(ssh,
                                         {:length, encryptedLen})
        <<packetLen
          ::
          size(32) - unsigned - big - integer>> = packetLenBin
        {:ok, packetLen, packetLenBin, encryptedRest,
           encryptedLen, ssh1}
      {true, _} ->
        <<packetLen :: size(32) - unsigned - big - integer,
            encryptedRest :: binary>> = encryptedBuffer
        {:ok, packetLen,
           <<packetLen :: size(32) - unsigned - big - integer>>,
           encryptedRest,
           <<packetLen :: size(32) - unsigned - big - integer>>,
           ssh}
      {false, _} ->
        :get_more
    end
  end

  defp padding_length(size,
            r_ssh(encrypt_block_size: blockSize,
                random_length_padding: randomLengthPad)) do
    pL = rem(blockSize - rem(size, blockSize), blockSize)
    minPadLen = (cond do
                   pL < 4 ->
                     pL + blockSize
                   true ->
                     pL
                 end)
    padBlockSize = max(blockSize, 4)
    maxExtraBlocks = div(max(randomLengthPad,
                               minPadLen) - minPadLen, padBlockSize)
    extraPadLen = (try do
                     (:rand.uniform(maxExtraBlocks + 1) - 1) * padBlockSize
                   catch
                     _, _ ->
                       0
                   end)
    minPadLen + extraPadLen
  end

  defp payload(<<packetLen :: size(32), paddingLen :: size(8),
              payloadAndPadding :: binary>>) do
    payloadLen = packetLen - paddingLen - 1
    <<payload :: size(payloadLen) - binary,
        _ :: binary>> = payloadAndPadding
    payload
  end

  def sign(sigData, signAlg, key, r_ssh(opts: opts))
      when is_atom(signAlg) do
    case (:lists.member(signAlg,
                          :proplists.get_value(:public_key,
                                                 :ssh_options.get_value(:user_options,
                                                                          :preferred_algorithms,
                                                                          opts,
                                                                          fn () ->
                                                                               []
                                                                          end,
                                                                          :ssh_transport,
                                                                          1534)))) do
      true ->
        {:ok, sign(sigData, sha(signAlg), key)}
      false ->
        {:error, :unsupported_sign_alg}
    end
  end

  def sign(sigData, hashAlg, %{algorithm: :dss} = key) do
    mk_dss_sig(:crypto.sign(:dss, hashAlg, sigData, key))
  end

  def sign(sigData, hashAlg, %{algorithm: sigAlg} = key) do
    :crypto.sign(sigAlg, hashAlg, sigData, key)
  end

  def sign(sigData, hashAlg, r_DSAPrivateKey() = key) do
    mk_dss_sig(:public_key.sign(sigData, hashAlg, key))
  end

  def sign(sigData, hashAlg,
           key = r_ECPrivateKey(parameters: {:namedCurve, curve}))
      when curve == {1, 3, 101, 112} or curve == {1, 3, 101,
                                                    113} do
    :public_key.sign(sigData, hashAlg, key)
  end

  def sign(sigData, hashAlg, key = r_ECPrivateKey()) do
    derEncodedSign = :public_key.sign(sigData, hashAlg, key)
    r_ECDSA_Sig_Value(r: r, s: s) = :public_key.der_decode(:"ECDSA-Sig-Value",
                                             derEncodedSign)
    <<:ssh_bits.mpint(r) :: binary,
        :ssh_bits.mpint(s) :: binary>>
  end

  def sign(sigData, hashAlg, key) do
    :public_key.sign(sigData, hashAlg, key)
  end

  defp mk_dss_sig(derSignature) do
    r_Dss_Sig_Value(r: r, s: s) = :public_key.der_decode(:"Dss-Sig-Value", derSignature)
    <<r :: size(160) - big - unsigned - integer,
        s :: size(160) - big - unsigned - integer>>
  end

  def verify(plainText, alg, sig, key, ssh) do
    do_verify(plainText, sha(alg), sig, key, ssh)
  end

  defp do_verify(plainText, hashAlg, sig, {_, r_Dss_Parms()} = key, _) do
    case (sig) do
      <<r :: size(160) - big - unsigned - integer,
          s :: size(160) - big - unsigned - integer>> ->
        signature = :public_key.der_encode(:"Dss-Sig-Value", r_Dss_Sig_Value(r: r, s: s))
        :public_key.verify(plainText, hashAlg, signature, key)
      _ ->
        false
    end
  end

  defp do_verify(plainText, hashAlg, sig, {r_ECPoint(), _} = key, _)
      when hashAlg !== :undefined do
    case (sig) do
      <<rlen :: size(32) - unsigned - big - integer,
          r :: size(rlen) - big - signed - integer - unit(8),
          slen :: size(32) - unsigned - big - integer,
          s :: size(slen) - big - signed - integer - unit(8)>> ->
        sval = r_ECDSA_Sig_Value(r: r, s: s)
        derEncodedSig = :public_key.der_encode(:"ECDSA-Sig-Value", sval)
        :public_key.verify(plainText, hashAlg, derEncodedSig,
                             key)
      _ ->
        false
    end
  end

  defp do_verify(plainText, hashAlg, sig, r_RSAPublicKey() = key,
            r_ssh(role: :server, c_version: 'SSH-2.0-OpenSSH_7.' ++ _))
      when hashAlg == :sha256 or hashAlg == :sha512 do
    :public_key.verify(plainText, hashAlg, sig,
                         key) or :public_key.verify(plainText, :sha, sig, key)
  end

  defp do_verify(plainText, hashAlg, sig, key, _) do
    :public_key.verify(plainText, hashAlg, sig, key)
  end

  Record.defrecord(:r_cipher, :cipher, impl: :undefined,
                                  key_bytes: :undefined, iv_bytes: :undefined,
                                  block_bytes: :undefined, pkt_type: :common)
  defp cipher(:AEAD_AES_128_GCM) do
    r_cipher(impl: :aes_128_gcm, key_bytes: 16, iv_bytes: 12,
        block_bytes: 16, pkt_type: :aead)
  end

  defp cipher(:AEAD_AES_256_GCM) do
    r_cipher(impl: :aes_256_gcm, key_bytes: 32, iv_bytes: 12,
        block_bytes: 16, pkt_type: :aead)
  end

  defp cipher(:"3des-cbc") do
    r_cipher(impl: :des_ede3_cbc, key_bytes: 24, iv_bytes: 8,
        block_bytes: 8)
  end

  defp cipher(:"aes128-cbc") do
    r_cipher(impl: :aes_128_cbc, key_bytes: 16, iv_bytes: 16,
        block_bytes: 16)
  end

  defp cipher(:"aes192-cbc") do
    r_cipher(impl: :aes_192_cbc, key_bytes: 24, iv_bytes: 16,
        block_bytes: 16)
  end

  defp cipher(:"aes256-cbc") do
    r_cipher(impl: :aes_256_cbc, key_bytes: 32, iv_bytes: 16,
        block_bytes: 16)
  end

  defp cipher(:"aes128-ctr") do
    r_cipher(impl: :aes_128_ctr, key_bytes: 16, iv_bytes: 16,
        block_bytes: 16)
  end

  defp cipher(:"aes192-ctr") do
    r_cipher(impl: :aes_192_ctr, key_bytes: 24, iv_bytes: 16,
        block_bytes: 16)
  end

  defp cipher(:"aes256-ctr") do
    r_cipher(impl: :aes_256_ctr, key_bytes: 32, iv_bytes: 16,
        block_bytes: 16)
  end

  defp cipher(:"chacha20-poly1305@openssh.com") do
    r_cipher(impl: :chacha20_poly1305, key_bytes: 32, iv_bytes: 12,
        block_bytes: 8, pkt_type: :aead)
  end

  defp cipher(_) do
    r_cipher()
  end

  defp pkt_type(sshCipher) do
    r_cipher(cipher(sshCipher), :pkt_type)
  end

  defp mac_type(:"hmac-sha2-256-etm@openssh.com") do
    :enc_then_mac
  end

  defp mac_type(:"hmac-sha2-512-etm@openssh.com") do
    :enc_then_mac
  end

  defp mac_type(:"hmac-sha1-etm@openssh.com") do
    :enc_then_mac
  end

  defp mac_type(_) do
    :rfc4253
  end

  defp decrypt_magic(:server) do
    {'A', 'C'}
  end

  defp decrypt_magic(:client) do
    {'B', 'D'}
  end

  defp encrypt_magic(:client) do
    decrypt_magic(:server)
  end

  defp encrypt_magic(:server) do
    decrypt_magic(:client)
  end

  defp encrypt_init(r_ssh(encrypt: :none) = ssh) do
    {:ok, ssh}
  end

  defp encrypt_init(r_ssh(encrypt: :"chacha20-poly1305@openssh.com", role: role) = ssh) do
    {_, keyMagic} = encrypt_magic(role)
    <<k2 :: size(32) - binary,
        k1 :: size(32) - binary>> = hash(ssh, keyMagic, 8 * 64)
    {:ok, r_ssh(ssh, encrypt_keys: {k1, k2})}
  end

  defp encrypt_init(r_ssh(encrypt: sshCipher, role: role) = ssh)
      when sshCipher == :AEAD_AES_128_GCM or
             sshCipher == :AEAD_AES_256_GCM do
    {ivMagic, keyMagic} = encrypt_magic(role)
    r_cipher(impl: cryptoCipher, key_bytes: keyBytes,
        iv_bytes: ivBytes,
        block_bytes: blockBytes) = cipher(sshCipher)
    iV = hash(ssh, ivMagic, 8 * ivBytes)
    k = hash(ssh, keyMagic, 8 * keyBytes)
    {:ok,
       r_ssh(ssh, encrypt_cipher: cryptoCipher,  encrypt_keys: k, 
                encrypt_block_size: blockBytes,  encrypt_ctx: iV)}
  end

  defp encrypt_init(r_ssh(encrypt: sshCipher, role: role) = ssh) do
    {ivMagic, keyMagic} = encrypt_magic(role)
    r_cipher(impl: cryptoCipher, key_bytes: keyBytes,
        iv_bytes: ivBytes,
        block_bytes: blockBytes) = cipher(sshCipher)
    iV = hash(ssh, ivMagic, 8 * ivBytes)
    k = hash(ssh, keyMagic, 8 * keyBytes)
    ctx0 = :crypto.crypto_init(cryptoCipher, k, iV, true)
    {:ok,
       r_ssh(ssh, encrypt_cipher: cryptoCipher, 
                encrypt_block_size: blockBytes,  encrypt_ctx: ctx0)}
  end

  defp encrypt_final(ssh) do
    {:ok,
       r_ssh(ssh, encrypt: :none,  encrypt_keys: :undefined, 
                encrypt_block_size: 8,  encrypt_ctx: :undefined)}
  end

  defp encrypt(r_ssh(encrypt: :none) = ssh, data) do
    {ssh, data}
  end

  defp encrypt(r_ssh(encrypt: :"chacha20-poly1305@openssh.com", encrypt_keys: {k1, k2},
              send_sequence: seq) = ssh,
            <<lenData :: size(4) - binary,
                payloadData :: binary>>) do
    iV1 = <<0 :: size(8) - unit(8),
              seq :: size(8) - unit(8)>>
    encLen = :crypto.crypto_one_time(:chacha20, k1, iV1,
                                       lenData, true)
    iV2 = <<1 :: size(8) - little - unit(8),
              seq :: size(8) - unit(8)>>
    encPayloadData = :crypto.crypto_one_time(:chacha20, k2,
                                               iV2, payloadData, true)
    polyKey = :crypto.crypto_one_time(:chacha20, k2,
                                        <<0 :: size(8) - unit(8),
                                            seq :: size(8) - unit(8)>>,
                                        <<0 :: size(32) - unit(8)>>, true)
    encBytes = <<encLen :: binary,
                   encPayloadData :: binary>>
    ctag = :crypto.mac(:poly1305, polyKey, encBytes)
    {ssh, {encBytes, ctag}}
  end

  defp encrypt(r_ssh(encrypt: sshCipher,
              encrypt_cipher: cryptoCipher, encrypt_keys: k,
              encrypt_ctx: iV0) = ssh,
            <<lenData :: size(4) - binary, payloadData :: binary>>)
      when sshCipher == :AEAD_AES_128_GCM or
             sshCipher == :AEAD_AES_256_GCM do
    {ctext,
       ctag} = :crypto.crypto_one_time_aead(cryptoCipher, k,
                                              iV0, payloadData, lenData, true)
    iV = next_gcm_iv(iV0)
    {r_ssh(ssh, encrypt_ctx: iV),
       {<<lenData :: binary, ctext :: binary>>, ctag}}
  end

  defp encrypt(r_ssh(encrypt_ctx: ctx0) = ssh, data) do
    enc = :crypto.crypto_update(ctx0, data)
    {ssh, enc}
  end

  defp decrypt_init(r_ssh(decrypt: :none) = ssh) do
    {:ok, ssh}
  end

  defp decrypt_init(r_ssh(decrypt: :"chacha20-poly1305@openssh.com", role: role) = ssh) do
    {_, keyMagic} = decrypt_magic(role)
    <<k2 :: size(32) - binary,
        k1 :: size(32) - binary>> = hash(ssh, keyMagic, 8 * 64)
    {:ok, r_ssh(ssh, decrypt_keys: {k1, k2})}
  end

  defp decrypt_init(r_ssh(decrypt: sshCipher, role: role) = ssh)
      when sshCipher == :AEAD_AES_128_GCM or
             sshCipher == :AEAD_AES_256_GCM do
    {ivMagic, keyMagic} = decrypt_magic(role)
    r_cipher(impl: cryptoCipher, key_bytes: keyBytes,
        iv_bytes: ivBytes,
        block_bytes: blockBytes) = cipher(sshCipher)
    iV = hash(ssh, ivMagic, 8 * ivBytes)
    k = hash(ssh, keyMagic, 8 * keyBytes)
    {:ok,
       r_ssh(ssh, decrypt_cipher: cryptoCipher,  decrypt_keys: k, 
                decrypt_block_size: blockBytes,  decrypt_ctx: iV)}
  end

  defp decrypt_init(r_ssh(decrypt: sshCipher, role: role) = ssh) do
    {ivMagic, keyMagic} = decrypt_magic(role)
    r_cipher(impl: cryptoCipher, key_bytes: keyBytes,
        iv_bytes: ivBytes,
        block_bytes: blockBytes) = cipher(sshCipher)
    iV = hash(ssh, ivMagic, 8 * ivBytes)
    k = hash(ssh, keyMagic, 8 * keyBytes)
    ctx0 = :crypto.crypto_init(cryptoCipher, k, iV, false)
    {:ok,
       r_ssh(ssh, decrypt_cipher: cryptoCipher, 
                decrypt_block_size: blockBytes,  decrypt_ctx: ctx0)}
  end

  defp decrypt_final(ssh) do
    {:ok,
       r_ssh(ssh, decrypt: :none,  decrypt_keys: :undefined, 
                decrypt_ctx: :undefined,  decrypt_block_size: 8)}
  end

  defp decrypt(ssh, <<>>) do
    {ssh, <<>>}
  end

  defp decrypt(r_ssh(decrypt: :"chacha20-poly1305@openssh.com", decrypt_keys: {k1, k2},
              recv_sequence: seq) = ssh,
            data) do
    case (data) do
      {:length, encryptedLen} ->
        packetLenBin = :crypto.crypto_one_time(:chacha20, k1,
                                                 <<0 :: size(8) - unit(8),
                                                     seq :: size(8) - unit(8)>>,
                                                 encryptedLen, false)
        {ssh, packetLenBin}
      {aAD, ctext, ctag} ->
        polyKey = :crypto.crypto_one_time(:chacha20, k2,
                                            <<0 :: size(8) - unit(8),
                                                seq :: size(8) - unit(8)>>,
                                            <<0 :: size(32) - unit(8)>>, false)
        case (:ssh_lib.comp(ctag,
                              :crypto.mac(:poly1305, polyKey,
                                            <<aAD :: binary,
                                                ctext :: binary>>))) do
          true ->
            iV2 = <<1 :: size(8) - little - unit(8),
                      seq :: size(8) - unit(8)>>
            plainText = :crypto.crypto_one_time(:chacha20, k2, iV2,
                                                  ctext, false)
            {ssh, plainText}
          false ->
            {ssh, :error}
        end
    end
  end

  defp decrypt(r_ssh(decrypt: :none) = ssh, data) do
    {ssh, data}
  end

  defp decrypt(r_ssh(decrypt: sshCipher,
              decrypt_cipher: cryptoCipher, decrypt_keys: k,
              decrypt_ctx: iV0) = ssh,
            {aAD, ctext, ctag})
      when sshCipher == :AEAD_AES_128_GCM or
             sshCipher == :AEAD_AES_256_GCM do
    dec = :crypto.crypto_one_time_aead(cryptoCipher, k, iV0,
                                         ctext, aAD, ctag, false)
    iV = next_gcm_iv(iV0)
    {r_ssh(ssh, decrypt_ctx: iV), dec}
  end

  defp decrypt(r_ssh(decrypt_ctx: ctx0) = ssh, data) do
    dec = :crypto.crypto_update(ctx0, data)
    {ssh, dec}
  end

  defp next_gcm_iv(<<fixed :: size(32), invCtr :: size(64)>>) do
    <<fixed :: size(32), invCtr + 1 :: size(64)>>
  end

  defp compress_init(sSH) do
    compress_init(sSH, 1)
  end

  defp compress_init(r_ssh(compress: :none) = ssh, _) do
    {:ok, ssh}
  end

  defp compress_init(r_ssh(compress: :zlib) = ssh, level) do
    zlib = :zlib.open()
    :ok = :zlib.deflateInit(zlib, level)
    {:ok, r_ssh(ssh, compress_ctx: zlib)}
  end

  defp compress_init(r_ssh(compress: :"zlib@openssh.com") = ssh, level) do
    zlib = :zlib.open()
    :ok = :zlib.deflateInit(zlib, level)
    {:ok, r_ssh(ssh, compress_ctx: zlib)}
  end

  defp compress_final(r_ssh(compress: :none) = ssh) do
    {:ok, ssh}
  end

  defp compress_final(r_ssh(compress: :zlib,
              compress_ctx: context) = ssh) do
    :zlib.close(context)
    {:ok,
       r_ssh(ssh, compress: :none,  compress_ctx: :undefined)}
  end

  defp compress_final(r_ssh(compress: :"zlib@openssh.com", authenticated: false) = ssh) do
    {:ok, ssh}
  end

  defp compress_final(r_ssh(compress: :"zlib@openssh.com", compress_ctx: context,
              authenticated: true) = ssh) do
    :zlib.close(context)
    {:ok,
       r_ssh(ssh, compress: :none,  compress_ctx: :undefined)}
  end

  defp compress(r_ssh(compress: :none) = ssh, data) do
    {ssh, data}
  end

  defp compress(r_ssh(compress: :zlib, compress_ctx: context) = ssh,
            data) do
    compressed = :zlib.deflate(context, data, :sync)
    {ssh, :erlang.list_to_binary(compressed)}
  end

  defp compress(r_ssh(compress: :"zlib@openssh.com", authenticated: false) = ssh,
            data) do
    {ssh, data}
  end

  defp compress(r_ssh(compress: :"zlib@openssh.com", compress_ctx: context,
              authenticated: true) = ssh,
            data) do
    compressed = :zlib.deflate(context, data, :sync)
    {ssh, :erlang.list_to_binary(compressed)}
  end

  defp decompress_init(r_ssh(decompress: :none) = ssh) do
    {:ok, ssh}
  end

  defp decompress_init(r_ssh(decompress: :zlib) = ssh) do
    zlib = :zlib.open()
    :ok = :zlib.inflateInit(zlib)
    {:ok, r_ssh(ssh, decompress_ctx: zlib)}
  end

  defp decompress_init(r_ssh(decompress: :"zlib@openssh.com") = ssh) do
    zlib = :zlib.open()
    :ok = :zlib.inflateInit(zlib)
    {:ok, r_ssh(ssh, decompress_ctx: zlib)}
  end

  defp decompress_final(r_ssh(decompress: :none) = ssh) do
    {:ok, ssh}
  end

  defp decompress_final(r_ssh(decompress: :zlib,
              decompress_ctx: context) = ssh) do
    :zlib.close(context)
    {:ok,
       r_ssh(ssh, decompress: :none,  decompress_ctx: :undefined)}
  end

  defp decompress_final(r_ssh(decompress: :"zlib@openssh.com",
              authenticated: false) = ssh) do
    {:ok, ssh}
  end

  defp decompress_final(r_ssh(decompress: :"zlib@openssh.com", decompress_ctx: context,
              authenticated: true) = ssh) do
    :zlib.close(context)
    {:ok,
       r_ssh(ssh, decompress: :none,  decompress_ctx: :undefined)}
  end

  defp decompress(r_ssh(decompress: :none) = ssh, data) do
    {ssh, data}
  end

  defp decompress(r_ssh(decompress: :zlib,
              decompress_ctx: context) = ssh,
            data) do
    decompressed = :zlib.inflate(context, data)
    {ssh, :erlang.list_to_binary(decompressed)}
  end

  defp decompress(r_ssh(decompress: :"zlib@openssh.com", authenticated: false) = ssh,
            data) do
    {ssh, data}
  end

  defp decompress(r_ssh(decompress: :"zlib@openssh.com", decompress_ctx: context,
              authenticated: true) = ssh,
            data) do
    decompressed = :zlib.inflate(context, data)
    {ssh, :erlang.list_to_binary(decompressed)}
  end

  defp send_mac_init(sSH) do
    case (pkt_type(r_ssh(sSH, :send_mac))) do
      :common ->
        case (r_ssh(sSH, :role)) do
          :client ->
            keySize = 8 * mac_key_bytes(r_ssh(sSH, :send_mac))
            key = hash(sSH, 'E', keySize)
            {:ok, r_ssh(sSH, send_mac_key: key)}
          :server ->
            keySize = 8 * mac_key_bytes(r_ssh(sSH, :send_mac))
            key = hash(sSH, 'F', keySize)
            {:ok, r_ssh(sSH, send_mac_key: key)}
        end
      _ ->
        {:ok, sSH}
    end
  end

  defp send_mac_final(sSH) do
    {:ok,
       r_ssh(sSH, send_mac: :none,  send_mac_key: :undefined)}
  end

  defp recv_mac_init(sSH) do
    case (pkt_type(r_ssh(sSH, :recv_mac))) do
      :common ->
        case (r_ssh(sSH, :role)) do
          :client ->
            key = hash(sSH, 'F', 8 * mac_key_bytes(r_ssh(sSH, :recv_mac)))
            {:ok, r_ssh(sSH, recv_mac_key: key)}
          :server ->
            key = hash(sSH, 'E', 8 * mac_key_bytes(r_ssh(sSH, :recv_mac)))
            {:ok, r_ssh(sSH, recv_mac_key: key)}
        end
      _ ->
        {:ok, sSH}
    end
  end

  defp recv_mac_final(sSH) do
    {:ok,
       r_ssh(sSH, recv_mac: :none,  recv_mac_key: :undefined)}
  end

  defp mac(:none, _, _, _) do
    <<>>
  end

  defp mac(:"hmac-sha1", key, seqNum, data) do
    :crypto.mac(:hmac, :sha, key,
                  [<<seqNum :: size(32) - unsigned - big - integer>>,
                       data])
  end

  defp mac(:"hmac-sha1-96", key, seqNum, data) do
    :crypto.macN(:hmac, :sha, key,
                   [<<seqNum :: size(32) - unsigned - big - integer>>,
                        data],
                   mac_digest_size(:"hmac-sha1-96"))
  end

  defp mac(:"hmac-md5", key, seqNum, data) do
    :crypto.mac(:hmac, :md5, key,
                  [<<seqNum :: size(32) - unsigned - big - integer>>,
                       data])
  end

  defp mac(:"hmac-md5-96", key, seqNum, data) do
    :crypto.macN(:hmac, :md5, key,
                   [<<seqNum :: size(32) - unsigned - big - integer>>,
                        data],
                   mac_digest_size(:"hmac-md5-96"))
  end

  defp mac(:"hmac-sha2-256", key, seqNum, data) do
    :crypto.mac(:hmac, :sha256, key,
                  [<<seqNum :: size(32) - unsigned - big - integer>>,
                       data])
  end

  defp mac(:"hmac-sha2-512", key, seqNum, data) do
    :crypto.mac(:hmac, :sha512, key,
                  [<<seqNum :: size(32) - unsigned - big - integer>>,
                       data])
  end

  defp mac(:"hmac-sha1-etm@openssh.com", key, seqNum, data) do
    mac(:"hmac-sha1", key, seqNum, data)
  end

  defp mac(:"hmac-sha2-256-etm@openssh.com", key, seqNum, data) do
    mac(:"hmac-sha2-256", key, seqNum, data)
  end

  defp mac(:"hmac-sha2-512-etm@openssh.com", key, seqNum, data) do
    mac(:"hmac-sha2-512", key, seqNum, data)
  end

  defp hash(_SSH, _Char, 0) do
    <<>>
  end

  defp hash(sSH, char, n) do
    hashAlg = sha(r_alg(r_ssh(sSH, :algorithms), :kex))
    k = r_ssh(sSH, :shared_secret)
    h = r_ssh(sSH, :exchanged_hash)
    k1 = :crypto.hash(hashAlg,
                        [k, h, char, r_ssh(sSH, :session_id)])
    sz = div(n, 8)
    <<key :: size(sz) - binary, _ :: binary>> = hash(k, h,
                                                       k1, n - 128, hashAlg)
    key
  end

  defp hash(_K, _H, ki, n, _HashAlg) when n <= 0 do
    ki
  end

  defp hash(k, h, ki, n, hashAlg) do
    kj = :crypto.hash(hashAlg, [k, h, ki])
    hash(k, h, <<ki :: binary, kj :: binary>>, n - 128,
           hashAlg)
  end

  defp kex_hash(sSH, key, hashAlg, args) do
    :crypto.hash(hashAlg, kex_plaintext(sSH, key, args))
  end

  defp kex_plaintext(sSH, key, args) do
    encodedKey = :ssh_message.ssh2_pubkey_encode(key)
    <<byte_size(cond do
                  is_binary(r_ssh(sSH, :c_version)) ->
                    r_ssh(sSH, :c_version)
                  is_list(r_ssh(sSH, :c_version)) ->
                    :erlang.list_to_binary(r_ssh(sSH, :c_version))
                  r_ssh(sSH, :c_version) == :undefined ->
                    <<>>
                end)
      ::
      size(32) - unsigned - big - integer,
        cond do
          is_binary(r_ssh(sSH, :c_version)) ->
            r_ssh(sSH, :c_version)
          is_list(r_ssh(sSH, :c_version)) ->
            :erlang.list_to_binary(r_ssh(sSH, :c_version))
          r_ssh(sSH, :c_version) == :undefined ->
            <<>>
        end
        ::
        binary,
        byte_size(cond do
                    is_binary(r_ssh(sSH, :s_version)) ->
                      r_ssh(sSH, :s_version)
                    is_list(r_ssh(sSH, :s_version)) ->
                      :erlang.list_to_binary(r_ssh(sSH, :s_version))
                    r_ssh(sSH, :s_version) == :undefined ->
                      <<>>
                  end)
        ::
        size(32) - unsigned - big - integer,
        cond do
          is_binary(r_ssh(sSH, :s_version)) ->
            r_ssh(sSH, :s_version)
          is_list(r_ssh(sSH, :s_version)) ->
            :erlang.list_to_binary(r_ssh(sSH, :s_version))
          r_ssh(sSH, :s_version) == :undefined ->
            <<>>
        end
        ::
        binary,
        byte_size(r_ssh(sSH, :c_keyinit))
        ::
        size(32) - unsigned - big - integer,
        r_ssh(sSH, :c_keyinit) :: binary,
        byte_size(r_ssh(sSH, :s_keyinit))
        ::
        size(32) - unsigned - big - integer,
        r_ssh(sSH, :s_keyinit) :: binary,
        byte_size(encodedKey)
        ::
        size(32) - unsigned - big - integer,
        encodedKey :: binary,
        kex_alg_dependent(args) :: binary>>
  end

  defp kex_alg_dependent({q_c, q_s, k}) when (is_binary(q_c) and
                                 is_binary(q_s)) do
    <<byte_size(q_c) :: size(32) - unsigned - big - integer,
        q_c :: binary,
        byte_size(q_s) :: size(32) - unsigned - big - integer,
        q_s :: binary, :ssh_bits.mpint(k) :: binary>>
  end

  defp kex_alg_dependent({e, f, k}) do
    <<:ssh_bits.mpint(e) :: binary,
        :ssh_bits.mpint(f) :: binary,
        :ssh_bits.mpint(k) :: binary>>
  end

  defp kex_alg_dependent({-1, nBits, -1, prime, gen, e, f, k}) do
    <<nBits :: size(32) - unsigned - big - integer,
        :ssh_bits.mpint(prime) :: binary,
        :ssh_bits.mpint(gen) :: binary,
        :ssh_bits.mpint(e) :: binary,
        :ssh_bits.mpint(f) :: binary,
        :ssh_bits.mpint(k) :: binary>>
  end

  defp kex_alg_dependent({min, nBits, max, prime, gen, e, f, k}) do
    <<min :: size(32) - unsigned - big - integer,
        nBits :: size(32) - unsigned - big - integer,
        max :: size(32) - unsigned - big - integer,
        :ssh_bits.mpint(prime) :: binary,
        :ssh_bits.mpint(gen) :: binary,
        :ssh_bits.mpint(e) :: binary,
        :ssh_bits.mpint(f) :: binary,
        :ssh_bits.mpint(k) :: binary>>
  end

  def valid_key_sha_alg(_, %{engine: _, key_id: _}, _Alg) do
    true
  end

  def valid_key_sha_alg(:public, r_RSAPublicKey(), :"rsa-sha2-512") do
    true
  end

  def valid_key_sha_alg(:public, r_RSAPublicKey(), :"rsa-sha2-384") do
    true
  end

  def valid_key_sha_alg(:public, r_RSAPublicKey(), :"rsa-sha2-256") do
    true
  end

  def valid_key_sha_alg(:public, r_RSAPublicKey(), :"ssh-rsa") do
    true
  end

  def valid_key_sha_alg(:private, r_RSAPrivateKey(), :"rsa-sha2-512") do
    true
  end

  def valid_key_sha_alg(:private, r_RSAPrivateKey(), :"rsa-sha2-384") do
    true
  end

  def valid_key_sha_alg(:private, r_RSAPrivateKey(), :"rsa-sha2-256") do
    true
  end

  def valid_key_sha_alg(:private, r_RSAPrivateKey(), :"ssh-rsa") do
    true
  end

  def valid_key_sha_alg(:public, {_, r_Dss_Parms()}, :"ssh-dss") do
    true
  end

  def valid_key_sha_alg(:private, r_DSAPrivateKey(), :"ssh-dss") do
    true
  end

  def valid_key_sha_alg(:public, {r_ECPoint(), {:namedCurve, oID}}, alg) do
    valid_key_sha_alg_ec(oID, alg)
  end

  def valid_key_sha_alg(:private, r_ECPrivateKey(parameters: {:namedCurve, oID}),
           alg) do
    valid_key_sha_alg_ec(oID, alg)
  end

  def valid_key_sha_alg(_, _, _) do
    false
  end

  defp valid_key_sha_alg_ec(oID, alg) when is_tuple(oID) do
    {sshCurveType, _} = :ssh_message.oid2ssh_curvename(oID)
    alg == binary_to_atom(sshCurveType)
  end

  defp valid_key_sha_alg_ec(_, _) do
    false
  end

  def public_algo(r_RSAPublicKey()) do
    :"ssh-rsa"
  end

  def public_algo({_, r_Dss_Parms()}) do
    :"ssh-dss"
  end

  def public_algo({r_ECPoint(), {:namedCurve, oID}}) when is_tuple(oID) do
    {sshCurveType, _} = :ssh_message.oid2ssh_curvename(oID)
    binary_to_atom(sshCurveType)
  end

  def sha(:"ssh-rsa") do
    :sha
  end

  def sha(:"rsa-sha2-256") do
    :sha256
  end

  def sha(:"rsa-sha2-384") do
    :sha384
  end

  def sha(:"rsa-sha2-512") do
    :sha512
  end

  def sha(:"ssh-dss") do
    :sha
  end

  def sha(:"ecdsa-sha2-nistp256") do
    sha(:secp256r1)
  end

  def sha(:"ecdsa-sha2-nistp384") do
    sha(:secp384r1)
  end

  def sha(:"ecdsa-sha2-nistp521") do
    sha(:secp521r1)
  end

  def sha(:"ssh-ed25519") do
    :undefined
  end

  def sha(:"ssh-ed448") do
    :undefined
  end

  def sha(:secp256r1) do
    :sha256
  end

  def sha(:secp384r1) do
    :sha384
  end

  def sha(:secp521r1) do
    :sha512
  end

  def sha(:"diffie-hellman-group1-sha1") do
    :sha
  end

  def sha(:"diffie-hellman-group14-sha1") do
    :sha
  end

  def sha(:"diffie-hellman-group14-sha256") do
    :sha256
  end

  def sha(:"diffie-hellman-group16-sha512") do
    :sha512
  end

  def sha(:"diffie-hellman-group18-sha512") do
    :sha512
  end

  def sha(:"diffie-hellman-group-exchange-sha1") do
    :sha
  end

  def sha(:"diffie-hellman-group-exchange-sha256") do
    :sha256
  end

  def sha({1, 2, 840, 10045, 3, 1, 7}) do
    sha(:secp256r1)
  end

  def sha({1, 3, 132, 0, 34}) do
    sha(:secp384r1)
  end

  def sha({1, 3, 132, 0, 35}) do
    sha(:secp521r1)
  end

  def sha(:"ecdh-sha2-nistp256") do
    sha(:secp256r1)
  end

  def sha(:"ecdh-sha2-nistp384") do
    sha(:secp384r1)
  end

  def sha(:"ecdh-sha2-nistp521") do
    sha(:secp521r1)
  end

  def sha(:"curve25519-sha256") do
    :sha256
  end

  def sha(:"curve25519-sha256@libssh.org") do
    :sha256
  end

  def sha(:"curve448-sha512") do
    :sha512
  end

  def sha(:x25519) do
    :sha256
  end

  def sha(:x448) do
    :sha512
  end

  def sha(str) when (is_list(str) and length(str) < 50) do
    sha(:erlang.list_to_existing_atom(str))
  end

  defp mac_key_bytes(:"hmac-sha1") do
    20
  end

  defp mac_key_bytes(:"hmac-sha1-etm@openssh.com") do
    20
  end

  defp mac_key_bytes(:"hmac-sha1-96") do
    20
  end

  defp mac_key_bytes(:"hmac-md5") do
    16
  end

  defp mac_key_bytes(:"hmac-md5-96") do
    16
  end

  defp mac_key_bytes(:"hmac-sha2-256") do
    32
  end

  defp mac_key_bytes(:"hmac-sha2-256-etm@openssh.com") do
    32
  end

  defp mac_key_bytes(:"hmac-sha2-512") do
    64
  end

  defp mac_key_bytes(:"hmac-sha2-512-etm@openssh.com") do
    64
  end

  defp mac_key_bytes(:AEAD_AES_128_GCM) do
    0
  end

  defp mac_key_bytes(:AEAD_AES_256_GCM) do
    0
  end

  defp mac_key_bytes(:"chacha20-poly1305@openssh.com") do
    0
  end

  defp mac_key_bytes(:none) do
    0
  end

  defp mac_digest_size(:"hmac-sha1") do
    20
  end

  defp mac_digest_size(:"hmac-sha1-etm@openssh.com") do
    20
  end

  defp mac_digest_size(:"hmac-sha1-96") do
    12
  end

  defp mac_digest_size(:"hmac-md5") do
    20
  end

  defp mac_digest_size(:"hmac-md5-96") do
    12
  end

  defp mac_digest_size(:"hmac-sha2-256") do
    32
  end

  defp mac_digest_size(:"hmac-sha2-256-etm@openssh.com") do
    32
  end

  defp mac_digest_size(:"hmac-sha2-512") do
    64
  end

  defp mac_digest_size(:"hmac-sha2-512-etm@openssh.com") do
    64
  end

  defp mac_digest_size(:AEAD_AES_128_GCM) do
    16
  end

  defp mac_digest_size(:AEAD_AES_256_GCM) do
    16
  end

  defp mac_digest_size(:"chacha20-poly1305@openssh.com") do
    16
  end

  defp mac_digest_size(:none) do
    0
  end

  defp dh_group(:"diffie-hellman-group1-sha1") do
    {2,
       179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007}
  end

  defp dh_group(:"diffie-hellman-group14-sha1") do
    {2,
       32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559}
  end

  defp dh_group(:"diffie-hellman-group14-sha256") do
    {2,
       32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559}
  end

  defp dh_group(:"diffie-hellman-group16-sha512") do
    {2,
       1044388881413152506679602719846529545831269060992135009022588756444338172022322690710444046669809783930111585737890362691860127079270495454517218673016928427459146001866885779762982229321192368303346235204368051010309155674155697460347176946394076535157284994895284821633700921811716738972451834979455897010306333468590751358365138782250372269117968985194322444535687415522007151638638141456178420621277822674995027990278673458629544391736919766299005511505446177668154446234882665961680796576903199116089347634947187778906528008004756692571666922964122566174582776707332452371001272163776841229318324903125740713574141005124561965913888899753461735347970011693256316751660678950830027510255804846105583465055446615090444309583050775808509297040039680057435342253926566240898195863631588888936364129920059308455669454034010391478238784189888594672336242763795138176353222845524644040094258962433613354036104643881925238489224010194193088911666165584229424668165441688927790460608264864204237717002054744337988941974661214699689706521543006262604535890998125752275942608772174376107314217749233048217904944409836238235772306749874396760463376480215133461333478395682746608242585133953883882226786118030184028136755970045385534758453247}
  end

  defp dh_group(:"diffie-hellman-group18-sha512") do
    {2,
       1090748135619415929450294929359784500348155124953172211774101106966150168922785639028532473848836817769712164169076432969224698752674677662739994265785437233596157045970922338040698100507861033047312331823982435279475700199860971612732540528796554502867919746776983759391475987142521315878719577519148811830879919426939958487087540965716419167467499326156226529675209172277001377591248147563782880558861083327174154014975134893125116015776318890295960698011614157721282527539468816519319333337503114777192360412281721018955834377615480468479252748867320362385355596601795122806756217713579819870634321561907813255153703950795271232652404894983869492174481652303803498881366210508647263668376514131031102336837488999775744046733651827239395353540348414872854639719294694323450186884189822544540647226987292160693184734654941906936646576130260972193280317171696418971553954161446191759093719524951116705577362073481319296041201283516154269044389257727700289684119460283480452306204130024913879981135908026983868205969318167819680850998649694416907952712904962404937775789698917207356355227455066183815847669135530549755439819480321732925869069136146085326382334628745456398071603058051634209386708703306545903199608523824513729625136659128221100967735450519952404248198262813831097374261650380017277916975324134846574681307337017380830353680623216336949471306191686438249305686413380231046096450953594089375540285037292470929395114028305547452584962074309438151825437902976012891749355198678420603722034900311364893046495761404333938686140037848030916292543273684533640032637639100774502371542479302473698388692892420946478947733800387782741417786484770190108867879778991633218628640533982619322466154883011452291890252336487236086654396093853898628805813177559162076363154436494477507871294119841637867701722166609831201845484078070518041336869808398454625586921201308185638888082699408686536045192649569198110353659943111802300636106509865023943661829436426563007917282050894429388841748885398290707743052973605359277515749619730823773215894755121761467887865327707115573804264519206349215850195195364813387526811742474131549802130246506341207020335797706780705406945275438806265978516209706795702579244075380490231741030862614968783306207869687868108423639971983209077624758080499988275591392787267627182442892809646874228263172435642368588260139161962836121481966092745325488641054238839295138992979335446110090325230955276870524611359124918392740353154294858383359}
  end

  def parallell_gen_key(ssh = r_ssh(keyex_key: {:x, {g, p}},
                   algorithms: algs)) do
    sz = dh_bits(algs)
    {public, private} = generate_key(:dh, [p, g, 2 * sz])
    r_ssh(ssh, keyex_key: {{private, public}, {g, p}})
  end

  defp generate_key(:ecdh, args) do
    :crypto.generate_key(:ecdh, args)
  end

  defp generate_key(:dh, [p, g, sz2]) do
    {public, private} = :crypto.generate_key(:dh,
                                               [p, g, max(sz2, 400)])
    {:crypto.bytes_to_integer(public),
       :crypto.bytes_to_integer(private)}
  end

  defp compute_key(algorithm, othersPublic, myPrivate, args) do
    shared = :crypto.compute_key(algorithm, othersPublic,
                                   myPrivate, args)
    :crypto.bytes_to_integer(shared)
  end

  defp dh_bits(r_alg(encrypt: encrypt, send_mac: sendMac)) do
    c = cipher(encrypt)
    8 * :lists.max([r_cipher(c, :key_bytes), r_cipher(c, :block_bytes),
                                          r_cipher(c, :iv_bytes),
                                              mac_key_bytes(sendMac)])
  end

  defp ecdh_curve(:"ecdh-sha2-nistp256") do
    :secp256r1
  end

  defp ecdh_curve(:"ecdh-sha2-nistp384") do
    :secp384r1
  end

  defp ecdh_curve(:"ecdh-sha2-nistp521") do
    :secp521r1
  end

  defp ecdh_curve(:"curve448-sha512") do
    :x448
  end

  defp ecdh_curve(:"curve25519-sha256") do
    :x25519
  end

  defp ecdh_curve(:"curve25519-sha256@libssh.org") do
    :x25519
  end

  defp supported_algorithms(key,
            [{:client2server, bL1}, {:server2client, bL2}]) do
    [{:client2server, as1}, {:server2client,
                               as2}] = supported_algorithms(key)
    [{:client2server, as1 -- bL1}, {:server2client,
                                      as2 -- bL2}]
  end

  defp supported_algorithms(key, blackList) do
    supported_algorithms(key) -- blackList
  end

  defp select_crypto_supported(l) do
    sup = :crypto.supports()
    for {name, cryptoRequires} <- l,
          crypto_supported(cryptoRequires, sup) do
      name
    end
  end

  defp crypto_supported(conditions, supported) do
    :lists.all(fn {tag, cryptoName} when is_atom(cryptoName)
                                         ->
                    crypto_name_supported(tag, cryptoName, supported)
               end,
                 conditions)
  end

  defp crypto_name_supported(tag, cryptoName, supported) do
    vs = :proplists.get_value(tag, supported, [])
    :lists.member(cryptoName, vs)
  end

  defp same(algs) do
    [{:client2server, algs}, {:server2client, algs}]
  end

  defp maybe_reset_sequence(:snd, ssh = r_ssh(kex_strict_negotiated: true)) do
    {:ok, r_ssh(ssh, send_sequence: 0)}
  end

  defp maybe_reset_sequence(:rcv, ssh = r_ssh(kex_strict_negotiated: true)) do
    {:ok, r_ssh(ssh, recv_sequence: 0)}
  end

  defp maybe_reset_sequence(_Dir, ssh) do
    {:ok, ssh}
  end

  defp trim_tail(str) do
    :lists.takewhile(fn c ->
                          c !== ?\r and c !== ?\n
                     end,
                       str)
  end

  def ssh_dbg_trace_points() do
    [:alg, :ssh_messages, :raw_messages, :hello]
  end

  def ssh_dbg_flags(:alg) do
    [:c]
  end

  def ssh_dbg_flags(:hello) do
    [:c]
  end

  def ssh_dbg_flags(:raw_messages) do
    ssh_dbg_flags(:hello)
  end

  def ssh_dbg_flags(:ssh_messages) do
    ssh_dbg_flags(:hello)
  end

  def ssh_dbg_on(:alg) do
    :dbg.tpl(:ssh_transport, :select_algorithm, 5, :x)
  end

  def ssh_dbg_on(:hello) do
    :dbg.tp(:ssh_transport, :hello_version_msg, 1, :x)
    :dbg.tp(:ssh_transport, :handle_hello_version, 1, :x)
  end

  def ssh_dbg_on(:raw_messages) do
    ssh_dbg_on(:hello)
  end

  def ssh_dbg_on(:ssh_messages) do
    ssh_dbg_on(:hello)
  end

  def ssh_dbg_off(:alg) do
    :dbg.ctpl(:ssh_transport, :select_algorithm, 5)
  end

  def ssh_dbg_off(:hello) do
    :dbg.ctpg(:ssh_transport, :hello_version_msg, 1)
    :dbg.ctpg(:ssh_transport, :handle_hello_version, 1)
  end

  def ssh_dbg_off(:raw_messages) do
    ssh_dbg_off(:hello)
  end

  def ssh_dbg_off(:ssh_messages) do
    ssh_dbg_off(:hello)
  end

  def ssh_dbg_format(:hello,
           {:call, {:ssh_transport, :hello_version_msg, [_]}}) do
    :skip
  end

  def ssh_dbg_format(:hello,
           {:return_from, {:ssh_transport, :hello_version_msg, 1},
              hello}) do
    ['Going to send hello message:\n', hello]
  end

  def ssh_dbg_format(:hello,
           {:call,
              {:ssh_transport, :handle_hello_version, [hello]}}) do
    ['Received hello message:\n', hello]
  end

  def ssh_dbg_format(:hello,
           {:return_from,
              {:ssh_transport, :handle_hello_version, 1}, _Ret}) do
    :skip
  end

  def ssh_dbg_format(:alg,
           {:call,
              {:ssh_transport, :select_algorithm,
                 [_, _, _, _, _]}}) do
    :skip
  end

  def ssh_dbg_format(:alg,
           {:return_from, {:ssh_transport, :select_algorithm, 5},
              {:ok, alg}}) do
    ['Negotiated algorithms:\n', wr_record(alg)]
  end

  def ssh_dbg_format(:raw_messages, x) do
    ssh_dbg_format(:hello, x)
  end

  def ssh_dbg_format(:ssh_messages, x) do
    ssh_dbg_format(:hello, x)
  end

  defp wr_record(r = r_alg()) do
    :ssh_dbg.wr_record(r, Keyword.keys(r_alg(r_alg())), [])
  end

end