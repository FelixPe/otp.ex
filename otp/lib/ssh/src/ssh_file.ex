defmodule :m_ssh_file do
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
  Record.defrecord(:r_file_info, :file_info, size: :undefined,
                                     type: :undefined, access: :undefined,
                                     atime: :undefined, mtime: :undefined,
                                     ctime: :undefined, mode: :undefined,
                                     links: :undefined,
                                     major_device: :undefined,
                                     minor_device: :undefined,
                                     inode: :undefined, uid: :undefined,
                                     gid: :undefined)
  Record.defrecord(:r_file_descriptor, :file_descriptor, module: :undefined,
                                           data: :undefined)
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
  @behaviour :ssh_server_key_api
  @behaviour :ssh_client_key_api
  def host_key(algorithm, opts) do
    read_ssh_key_file(:system, :private, algorithm, opts)
  end

  def is_auth_key(key0, user, opts) do
    dir = ssh_dir({:remoteuser, user}, opts)
    :ok = assure_file_mode(dir, :user_read)
    keyType = normalize_alg(:erlang.atom_to_binary(:ssh_transport.public_algo(key0),
                                                     :latin1))
    key = encode_key(key0)
    lookup_auth_keys(keyType, key, :filename.join(dir, 'authorized_keys'),
                       opts) or lookup_auth_keys(keyType, key,
                                                   :filename.join(dir, 'authorized_keys2'), opts)
  end

  def user_key(algorithm, opts) do
    read_ssh_key_file(:user, :private, algorithm, opts)
  end

  def is_host_key(key0, hosts0, port, algorithm, opts) do
    dir = ssh_dir(:user, opts)
    file = :filename.join(dir, 'known_hosts')
    hosts = (for h <- normalize_hosts_list(hosts0, port) do
               :erlang.list_to_binary(h)
             end)
    keyType = normalize_alg(:erlang.atom_to_binary(algorithm,
                                                     :latin1))
    key = encode_key(key0)
    :ok = assure_file_mode(file, :user_read)
    lookup_host_keys(hosts, keyType, key, file, opts)
  end

  def add_host_key(hosts0, port, key, opts) do
    file = file_name(:user, 'known_hosts', opts)
    assure_file_mode(file, :user_write)
    case (:file.open(file, [:write, :append])) do
      {:ok, fd} ->
        keyType = :erlang.atom_to_binary(:ssh_transport.public_algo(key),
                                           :latin1)
        encKey = :ssh_message.ssh2_pubkey_encode(key)
        hosts1 = normalize_hosts_list(hosts0, port)
        sshBin = :erlang.iolist_to_binary([:lists.join(',',
                                                         hosts1),
                                               ' ', keyType, ' ',
                                                               :base64.encode(:erlang.iolist_to_binary(encKey)),
                                                                   '\n'])
        res = :file.write(fd, sshBin)
        :file.close(fd)
        res
      {:error, error} ->
        {:error, {:add_host_key, error}}
    end
  end

  def decode(keyBin, :ssh2_pubkey) when is_binary(keyBin) do
    :ssh_message.ssh2_pubkey_decode(keyBin)
  end

  def decode(keyBin, :public_key) when is_binary(keyBin) do
    type = (case (keyBin) do
              <<"-----BEGIN OPENSSH", _ :: binary>> ->
                :openssh_key_v1
              <<"----", _ :: binary>> ->
                :rfc4716_key
              _ ->
                :openssh_key
            end)
    decode(keyBin, type)
  end

  def decode(keyBin, type)
      when is_binary(keyBin) and (type == :rfc4716_key or type == :openssh_key_v1) do
    case (decode_ssh_file(:public, :any, keyBin,
                            :ignore)) do
      {:ok, keys} ->
        for {key, attrs} <- keys do
          {key,
             cond do
               attrs !== [] ->
                 [{:headers,
                     for {k, v} <- attrs do
                       {:erlang.binary_to_list(k), :erlang.binary_to_list(v)}
                     end}]
               attrs == [] ->
                 []
             end}
        end
      {:error, error} ->
        {:error, error}
    end
  end

  def decode(keyBin0, :openssh_key) when is_binary(keyBin0) do
    try do
      for line <- split_in_nonempty_lines(keyBin0) do
        (
          [_, k | rest] = :binary.split(line, " ",
                                          [:global, :trim_all])
          key = :ssh_message.ssh2_pubkey_decode(:base64.decode(k))
          case (rest) do
            [comment] ->
              {key, [{:comment, :erlang.binary_to_list(comment)}]}
            [] ->
              {key, []}
          end
        )
      end
    catch
      _, _ ->
        {:error, :key_decode_failed}
    end
  end

  def decode(bin, :known_hosts) when is_binary(bin) do
    for l <- split_in_nonempty_lines(bin),
          [hostPort, _KeyType, keyBin |
                                   comment] <- [:binary.split(l, " ",
                                                                [:global,
                                                                     :trim_all])] do
      (
        attrs = (for _ <- [:EFE_DUMMY_GEN], comment !== [] do
                   {:comment,
                      :erlang.binary_to_list(:erlang.iolist_to_binary(:lists.join(' ',
                                                                                    comment)))}
                 end) ++ [{:hostnames,
                             for hP <- :binary.split(hostPort, ",",
                                                       [:global, :trim_all]) do
                               :erlang.binary_to_list(hP)
                             end}]
        {:ssh_message.ssh2_pubkey_decode(:base64.decode(keyBin)),
           attrs}
      )
    end
  end

  def decode(bin, :auth_keys) when is_binary(bin) do
    for l <- split_in_nonempty_lines(bin),
          [options, _KeyType, keyBin |
                                  comment] <- (case (:binary.match(l,
                                                                     ["ssh-rsa", "rsa-sha2-", "ssh-dss",
                                                                                "ecdsa-sha2-nistp",
                                                                                    "ssh-ed"])) do
                                                 :nomatch ->
                                                   []
                                                 {0, len} when is_integer(len)
                                                               ->
                                                   [[[] | :binary.split(l, " ",
                                                                          [:global,
                                                                               :trim_all])]]
                                                 {pos, len}
                                                     when (is_integer(pos) and
                                                             is_integer(len))
                                                          ->
                                                   [[:binary.split(:binary.part(l,
                                                                                  0,
                                                                                  pos - 1),
                                                                     ",",
                                                                     [:global,
                                                                          :trim_all]) |
                                                         :binary.split(:binary.part(l,
                                                                                      pos,
                                                                                      byte_size(l) - pos),
                                                                         " ",
                                                                         [:global,
                                                                              :trim_all])]]
                                               end) do
      (
        attrs = (for _ <- [:EFE_DUMMY_GEN], comment !== [] do
                   {:comment,
                      :erlang.binary_to_list(:erlang.iolist_to_binary(:lists.join(' ',
                                                                                    comment)))}
                 end) ++ (for _ <- [:EFE_DUMMY_GEN], options !== [] do
                            {:options,
                               :lists.map(&:erlang.binary_to_list/1, options)}
                          end)
        {:ssh_message.ssh2_pubkey_decode(:base64.decode(keyBin)),
           attrs}
      )
    end
  end

  def decode(_KeyBin, _Type) do
    :erlang.error(:badarg)
  end

  def encode(key, :ssh2_pubkey) do
    :ssh_message.ssh2_pubkey_encode(key)
  end

  def encode(keyAttrs, type) when type == :rfc4716_key or
                                type == :openssh_key_v1 do
    {begin, end__, f} = (case (type) do
                           :rfc4716_key ->
                             {'---- BEGIN SSH2 PUBLIC KEY ----\n', '---- END SSH2 PUBLIC KEY ----\n', &:ssh_message.ssh2_pubkey_encode/1}
                           :openssh_key_v1 ->
                             {'-----BEGIN OPENSSH PRIVATE KEY-----\n', '-----END OPENSSH PRIVATE KEY-----\n', &openssh_key_v1_encode/1}
                         end)
    :erlang.iolist_to_binary(for {key, attrs} <- keyAttrs do
                               [begin, for h <- :proplists.get_value(:headers,
                                                                       attrs,
                                                                       []) do
                                         rfc4716_encode_header(h)
                                       end,
                                           split_long_lines(:base64.encode(f.(key))),
                                               '\n', end__]
                             end)
  end

  def encode(keyAttrs, type) when type == :known_hosts or
                                type == :auth_keys or type == :openssh_key do
    firstArgTag = (case (type) do
                     :known_hosts ->
                       :hostnames
                     :auth_keys ->
                       :options
                     :openssh_key ->
                       :"*no tag*"
                   end)
    :erlang.iolist_to_binary(for {key,
                                    attributes} <- keyAttrs do
                               (
                                 <<__0 :: size(32) - unsigned - big - integer,
                                     keyType :: size(__0) - binary,
                                     _
                                     ::
                                     binary>> = (enc = :ssh_message.ssh2_pubkey_encode(key))
                                 [case (:lists.join(',',
                                                      :proplists.get_value(firstArgTag,
                                                                             attributes,
                                                                             []))) do
                                    [] ->
                                      ''
                                    c ->
                                      [c, ' ']
                                  end,
                                      keyType, ' ', :base64.encode(enc), ' ',
                                                                           case (:proplists.get_value(:comment,
                                                                                                        attributes,
                                                                                                        [])) do
                                                                             [] ->
                                                                               ''
                                                                             c ->
                                                                               c
                                                                           end,
                                                                               '\n']
                               )
                             end)
  end

  def encode(_KeyBin, _Type) do
    :erlang.error(:badarg)
  end

  def extract_public_key(r_RSAPrivateKey(modulus: n, publicExponent: e)) do
    r_RSAPublicKey(modulus: n, publicExponent: e)
  end

  def extract_public_key(r_DSAPrivateKey(y: y, p: p, q: q, g: g)) do
    {y, r_Dss_Parms(p: p, q: q, g: g)}
  end

  def extract_public_key(r_ECPrivateKey(parameters: {:namedCurve, oID},
             publicKey: pub0, privateKey: priv))
      when oID == {1, 3, 101, 112} or oID == {1, 3, 101,
                                                113} do
    case ({:pubkey_cert_records.namedCurves(oID), pub0}) do
      {alg, :asn1_NOVALUE} ->
        {pub, ^priv} = :crypto.generate_key(:eddsa, alg, priv)
        {r_ECPoint(point: pub), {:namedCurve, oID}}
      {_Alg, pub} ->
        {r_ECPoint(point: pub), {:namedCurve, oID}}
    end
  end

  def extract_public_key(r_ECPrivateKey(parameters: {:namedCurve, oID}, publicKey: q))
      when is_tuple(oID) do
    {r_ECPoint(point: q), {:namedCurve, oID}}
  end

  def extract_public_key(%{engine: _, key_id: _, algorithm: alg} = m) do
    case ({alg, :crypto.privkey_to_pubkey(alg, m)}) do
      {:rsa, [e, n]} ->
        r_RSAPublicKey(modulus: n, publicExponent: e)
      {:dss, [p, q, g, y]} ->
        {y, r_Dss_Parms(p: p, q: q, g: g)}
    end
  end

  defp lookup_auth_keys(keyType, key, file, opts) do
    case (get_kb_option(:optimize, opts, :time)) do
      :time ->
        case (:file.read_file(file)) do
          {:ok, bin} ->
            lines = split_in_lines(bin)
            find_key(keyType, key, lines)
          _ ->
            false
        end
      :space ->
        case (:file.open(file, [:read, :binary])) do
          {:ok, fd} ->
            result = read_test_loop(fd,
                                      fn line ->
                                           find_key(keyType, key, [line])
                                      end)
            :file.close(fd)
            result
          {:error, _Error} ->
            false
        end
      other ->
        {:error, {:is_auth_key, {:opt, other}}}
    end
  end

  defp find_key(keyType, key, [<<"#", _ :: binary>> | lines]) do
    find_key(keyType, key, lines)
  end

  defp find_key(keyType, key, [line | lines]) do
    try do
      [e1, e2 | es] = :binary.split(line, " ",
                                      [:global, :trim_all])
      [normalize_alg(e1), normalize_alg(e2) | es]
    catch
      _, _ ->
        find_key(keyType, key, lines)
    else
      [_Options, ^keyType, ^key | _Comment] ->
        true
      [^keyType, ^key | _Comment] ->
        true
      _ ->
        find_key(keyType, key, lines)
    end
  end

  defp find_key(_, _, _) do
    false
  end

  defp normalize_alg(<<"rsa-sha2-", _ :: binary>>) do
    "ssh-rsa"
  end

  defp normalize_alg(x) do
    x
  end

  defp normalize_hosts_list(hosts, port) when is_list(hd(hosts)) do
    :lists.reverse(:lists.foldl(fn h0, acc ->
                                     h1s = add_ip(replace_localhost(h0))
                                     hs = (case (port) do
                                             22 ->
                                               h1s
                                             _ ->
                                               for hx <- h1s do
                                                 :lists.concat(['[', hx, ']:', port])
                                               end
                                           end)
                                     :lists.foldl(fn hy, acc2 ->
                                                       case (:lists.member(hy,
                                                                             acc2)) do
                                                         true ->
                                                           acc2
                                                         false ->
                                                           [hy | acc2]
                                                       end
                                                  end,
                                                    acc, hs)
                                end,
                                  [], hosts))
  end

  defp normalize_hosts_list(hosts, port) do
    normalize_hosts_list([hosts], port)
  end

  defp replace_localhost(:any) do
    replace_localhost('localhost')
  end

  defp replace_localhost(:loopback) do
    replace_localhost('localhost')
  end

  defp replace_localhost('localhost') do
    {:ok, hostname} = :inet.gethostname()
    hostname
  end

  defp replace_localhost(h) when is_atom(h) do
    replace_localhost(:erlang.atom_to_list(h))
  end

  defp replace_localhost(host) do
    host
  end

  defp add_ip(iP) when is_tuple(iP) do
    [:ssh_connection.encode_ip(iP)]
  end

  defp add_ip(host) do
    case (:inet.getaddr(host, :inet)) do
      {:ok, addr} ->
        case (:ssh_connection.encode_ip(addr)) do
          false ->
            [host]
          ^host ->
            [host]
          iPString ->
            [host, iPString]
        end
      _ ->
        [host]
    end
  end

  defp encode_key(key) do
    :base64.encode(:erlang.iolist_to_binary(:ssh_message.ssh2_pubkey_encode(key)))
  end

  defp read_test_loop(fd, test) do
    case (:io.get_line(fd, :"")) do
      :eof ->
        :file.close(fd)
        false
      {:error, error} ->
        {:error, error}
      line0 ->
        case (split_in_lines(line0)) do
          [line] ->
            case (test.(line)) do
              false ->
                read_test_loop(fd, test)
              other ->
                other
            end
          _ ->
            read_test_loop(fd, test)
        end
    end
  end

  defp lookup_host_keys(hosts, keyType, key, file, opts) do
    case (get_kb_option(:optimize, opts, :time)) do
      :time ->
        case (:file.read_file(file)) do
          {:ok, bin} ->
            lines = split_in_lines(bin)
            case (find_host_key(hosts, keyType, key, lines)) do
              {true, restLines} ->
                case (revoked_key(hosts, keyType, key, restLines)) do
                  true ->
                    {:error, :revoked_key}
                  false ->
                    true
                end
              false ->
                false
            end
          {:error, :enoent} ->
            false
          {:error, error} ->
            {:error, {:is_host_key, error}}
        end
      :space ->
        case (:file.open(file, [:read, :binary])) do
          {:ok, fd} ->
            result = (case (read_test_loop(fd,
                                             fn line ->
                                                  find_host_key(hosts, keyType,
                                                                  key, [line])
                                             end)) do
                        {true, _} ->
                          case (read_test_loop(fd,
                                                 fn line ->
                                                      revoked_key(hosts,
                                                                    keyType,
                                                                    key, [line])
                                                 end)) do
                            true ->
                              {:error, :revoked_key}
                            false ->
                              true
                          end
                        {:error, error} ->
                          {:error, {:is_host_key, error}}
                        other ->
                          other
                      end)
            :file.close(fd)
            result
          {:error, error} ->
            {:error, error}
        end
      other ->
        {:error, {:is_host_key, {:opt, other}}}
    end
  end

  defp find_host_key(hosts, keyType, encKey,
            [<<"#", _ :: binary>> | patternLines]) do
    find_host_key(hosts, keyType, encKey, patternLines)
  end

  defp find_host_key(hosts, keyType, encKey,
            [line | patternLines]) do
    splitLine = :binary.split(line, " ", [:global, :trim_all])
    case (known_key_in_line(hosts, keyType, encKey,
                              splitLine)) do
      true ->
        {true, patternLines}
      false ->
        find_host_key(hosts, keyType, encKey, patternLines)
    end
  end

  defp find_host_key(_, _, _, []) do
    false
  end

  defp revoked_key(hosts, keyType, encKey,
            [<<"@revoked ", restLine :: binary>> | lines]) do
    case (:binary.split(restLine, " ",
                          [:global, :trim_all])) do
      [patterns, ^keyType, ^encKey | _Comment] ->
        case (host_match(hosts, patterns)) do
          true ->
            true
          false ->
            revoked_key(hosts, keyType, encKey, lines)
        end
      _ ->
        revoked_key(hosts, keyType, encKey, lines)
    end
  end

  defp revoked_key(hosts, keyType, encKey, [_ | lines]) do
    revoked_key(hosts, keyType, encKey, lines)
  end

  defp revoked_key(_, _, _, _) do
    false
  end

  defp known_key_in_line(hosts, keyType, encKey,
            fullLine = [option | rest]) do
    case (line_match(hosts, keyType, encKey, rest)) do
      true ->
        case (option) do
          "@revoked" ->
            {:error, :revoked_key}
          _ ->
            false
        end
      false ->
        line_match(hosts, keyType, encKey, fullLine)
    end
  end

  defp known_key_in_line(_, _, _, _) do
    false
  end

  defp line_match(hosts, keyType, encKey,
            [patterns, keyType0, encKey0 | _Comment]) do
    keyType == normalize_alg(keyType0) and encKey == encKey0 and host_match(hosts,
                                                                              patterns)
  end

  defp line_match(_, _, _, _) do
    false
  end

  defp host_match(hosts, patterns) do
    patternList = :binary.split(patterns, ",", [:global])
    host_matchL(hosts, patternList)
  end

  defp host_matchL([h | hosts], patterns) do
    case (one_host_match(h, patterns)) do
      true ->
        true
      false ->
        host_matchL(hosts, patterns)
    end
  end

  defp host_matchL(_, _) do
    false
  end

  defp one_host_match(h, [pat | patterns]) do
    case (pos_match(h, pat)) do
      true ->
        not
        :lists.any(fn p ->
                        neg_match(h, p)
                   end,
                     patterns)
      false ->
        one_host_match(h, patterns)
    end
  end

  defp one_host_match(_, _) do
    false
  end

  defp neg_match(h, <<"!", p :: binary>>) do
    pos_match(h, p)
  end

  defp neg_match(_, _) do
    false
  end

  defp pos_match(_, "*") do
    true
  end

  defp pos_match(_, "*:*") do
    true
  end

  defp pos_match(_, "[*]:*") do
    true
  end

  defp pos_match(h, <<"!", p :: binary>>) do
    not pos_match(h, p)
  end

  defp pos_match(h, h) do
    true
  end

  defp pos_match(h, p) do
    case ({:binary.split(h, ":"), :binary.split(p, ":")}) do
      {[hh, _], [ph, "*"]} ->
        ph == hh
      {[hh], [ph, "*"]} ->
        sz = byte_size(hh)
        ph == <<"[", hh :: size(sz) - binary, "]">>
      {[hh], [ph, "22"]} ->
        sz = byte_size(hh)
        ph == <<"[", hh :: size(sz) - binary, "]">>
      _ ->
        false
    end
  end

  defp rfc4716_encode_header({tag, value}) do
    tagLen = length(tag)
    valueLen = length(value)
    case (tagLen + 1 + valueLen) do
      n when n > 68 ->
        numOfChars = 68 - (tagLen + 1)
        {first, rest} = :lists.split(numOfChars, value)
        [tag, ': ', first, [?\\], '\n', rfc4716_encode_value(rest), '\n']
      _ ->
        [tag, ': ', value, '\n']
    end
  end

  defp rfc4716_encode_value(value) do
    case (length(value)) do
      n when n > 68 ->
        {first, rest} = :lists.split(68, value)
        [first, [?\\], '\n', rfc4716_encode_value(rest)]
      _ ->
        value
    end
  end

  defp split_long_lines(<<text :: size(68) - binary, rest :: binary>>)
      when rest !== "" do
    [text, ?\n | split_long_lines(rest)]
  end

  defp split_long_lines(bin) do
    [bin]
  end

  defp assure_file_mode(file, :user_write) do
    assure_file_mode(file, 128)
  end

  defp assure_file_mode(file, :user_read) do
    assure_file_mode(file, 256)
  end

  defp assure_file_mode(file, mode) do
    case (:file.read_file_info(file)) do
      {:ok, r_file_info(mode: fileMode)} ->
        case (fileMode &&& mode) do
          ^mode ->
            :ok
          _ ->
            :file.change_mode(file, fileMode ||| mode)
        end
      {:error, :enoent} ->
        :ok
      {:error, error} ->
        {:error, error}
    end
  end

  defp get_kb_option(key, opts, default) do
    try do
      :proplists.get_value(key,
                             :proplists.get_value(:key_cb_private, opts, []),
                             default)
    catch
      _, _ ->
        default
    end
  end

  defp read_ssh_key_file(role, privPub, algorithm, opts) do
    file = file_name(role, file_base_name(role, algorithm),
                       opts)
    password = :proplists.get_value(identity_pass_phrase(algorithm),
                                      opts, :ignore)
    :ok = assure_file_mode(file, :user_read)
    case (:file.read_file(file)) do
      {:ok, pem} ->
        try do
          decode_ssh_file(privPub, algorithm, pem, password)
        catch
          reason ->
            {:error, reason}
          :error, reason ->
            {:error, reason}
        else
          {:ok, [{key, _Attrs} | _Keys]} ->
            {:ok, key}
          {:error, reason} ->
            {:error, reason}
        end
      {:error, reason} ->
        {:error, reason}
    end
  end

  def decode_ssh_file(privPub, algorithm, pem, password) do
    try do
      decode_pem_keys(pem, password)
    catch
      _, _ ->
        {:error, :key_decode_failed}
    else
      {:ok, keys} when algorithm == :any ->
        {:ok, keys}
      {:ok, keys0} ->
        case (for {key, attrs} <- keys0,
                    :ssh_transport.valid_key_sha_alg(privPub, key,
                                                       algorithm) do
                {key, attrs}
              end) do
          [] ->
            {:error, :no_key_found}
          keys ->
            {:ok, keys}
        end
      {:error, error} ->
        {:error, error}
    end
  end

  defp decode_pem_keys(rawBin, password) do
    pemLines = split_in_lines(:binary.replace(rawBin,
                                                ["\\\n", "\\\r\\\n"], "", [:global]))
    decode_pem_keys(pemLines, password, [])
  end

  defp decode_pem_keys([], _, acc) do
    {:ok, :lists.reverse(acc)}
  end

  defp decode_pem_keys(pemLines, password, acc) do
    try do
      get_key_part(pemLines)
    catch
      _, _ ->
        :erlang.error(:bad_or_unsupported_key_format)
    else
      {:"openssh-key-v1", bin, attrs, restLines} ->
        keyPairs = openssh_key_v1_decode(bin, password)
        keys = (for {pub, priv} <- keyPairs,
                      key <- [pub, priv] do
                  {key, attrs}
                end)
        decode_pem_keys(restLines, password, keys ++ acc)
      {:rfc4716, bin, attrs, restLines} ->
        key = :ssh_message.ssh2_pubkey_decode(bin)
        decode_pem_keys(restLines, password,
                          [{key, attrs} | acc])
      {type, bin, attrs, restLines} ->
        case (get_encrypt_hdrs(attrs)) do
          :not_encrypted ->
            key = :public_key.pem_entry_decode({type, bin,
                                                  :not_encrypted})
            decode_pem_keys(restLines, password,
                              [{key, attrs} | acc])
          [cipher, salt] when (is_binary(cipher) and
                                 is_binary(salt) and password !== :ignore)
                              ->
            cryptInfo = {:erlang.binary_to_list(cipher),
                           unhex(:erlang.binary_to_list(salt))}
            key = :public_key.pem_entry_decode({type, bin,
                                                  cryptInfo},
                                                 password)
            decode_pem_keys(restLines, password,
                              [{key, attrs} | acc])
          _X ->
            {:error, :no_pass_phrase}
        end
    end
  end

  defp get_encrypt_hdrs(kVs) do
    :lists.foldl(fn {"Proc-Type", <<"4,ENCRYPTED", _ :: binary>>}, _Acc ->
                      {:proc_type, "4,ENCRYPTED"}
                    {"DEK-Info", dEKinfo}, {:proc_type, _} ->
                      :binary.split(dEKinfo, ",")
                    _, acc ->
                      acc
                 end,
                   :not_encrypted, kVs)
  end

  defp unhex(s) do
    :erlang.list_to_binary(:lists.foldr(fn d2, {d1, acc} ->
                                             [:erlang.list_to_integer([d2, d1],
                                                                        16) |
                                                  acc]
                                           d1, acc when is_list(acc) ->
                                             {d1, acc}
                                        end,
                                          [], s))
  end

  defp file_base_name(:user, :"ecdsa-sha2-nistp256") do
    'id_ecdsa'
  end

  defp file_base_name(:user, :"ecdsa-sha2-nistp384") do
    'id_ecdsa'
  end

  defp file_base_name(:user, :"ecdsa-sha2-nistp521") do
    'id_ecdsa'
  end

  defp file_base_name(:user, :"rsa-sha2-256") do
    'id_rsa'
  end

  defp file_base_name(:user, :"rsa-sha2-384") do
    'id_rsa'
  end

  defp file_base_name(:user, :"rsa-sha2-512") do
    'id_rsa'
  end

  defp file_base_name(:user, :"ssh-dss") do
    'id_dsa'
  end

  defp file_base_name(:user, :"ssh-ed25519") do
    'id_ed25519'
  end

  defp file_base_name(:user, :"ssh-ed448") do
    'id_ed448'
  end

  defp file_base_name(:user, :"ssh-rsa") do
    'id_rsa'
  end

  defp file_base_name(:system, :"ecdsa-sha2-nistp256") do
    'ssh_host_ecdsa_key'
  end

  defp file_base_name(:system, :"ecdsa-sha2-nistp384") do
    'ssh_host_ecdsa_key'
  end

  defp file_base_name(:system, :"ecdsa-sha2-nistp521") do
    'ssh_host_ecdsa_key'
  end

  defp file_base_name(:system, :"rsa-sha2-256") do
    'ssh_host_rsa_key'
  end

  defp file_base_name(:system, :"rsa-sha2-384") do
    'ssh_host_rsa_key'
  end

  defp file_base_name(:system, :"rsa-sha2-512") do
    'ssh_host_rsa_key'
  end

  defp file_base_name(:system, :"ssh-dss") do
    'ssh_host_dsa_key'
  end

  defp file_base_name(:system, :"ssh-ed25519") do
    'ssh_host_ed25519_key'
  end

  defp file_base_name(:system, :"ssh-ed448") do
    'ssh_host_ed448_key'
  end

  defp file_base_name(:system, :"ssh-rsa") do
    'ssh_host_rsa_key'
  end

  defp file_base_name(:system, _) do
    'ssh_host_key'
  end

  defp identity_pass_phrase(:"ssh-dss") do
    :dsa_pass_phrase
  end

  defp identity_pass_phrase(:"ssh-rsa") do
    :rsa_pass_phrase
  end

  defp identity_pass_phrase(:"rsa-sha2-256") do
    :rsa_pass_phrase
  end

  defp identity_pass_phrase(:"rsa-sha2-384") do
    :rsa_pass_phrase
  end

  defp identity_pass_phrase(:"rsa-sha2-512") do
    :rsa_pass_phrase
  end

  defp identity_pass_phrase(:"ecdsa-sha2-nistp256") do
    :ecdsa_pass_phrase
  end

  defp identity_pass_phrase(:"ecdsa-sha2-nistp384") do
    :ecdsa_pass_phrase
  end

  defp identity_pass_phrase(:"ecdsa-sha2-nistp521") do
    :ecdsa_pass_phrase
  end

  defp identity_pass_phrase(_) do
    :undefined
  end

  defp file_name(type, name, opts) do
    :filename.join(ssh_dir(type, opts), name)
  end

  defp ssh_dir({:remoteuser, user}, opts) do
    case (:proplists.get_value(:user_dir_fun, opts)) do
      :undefined ->
        ssh_dir(:user, opts)
      fUN ->
        fUN.(user)
    end
  end

  defp ssh_dir(:user, opts) do
    case (:proplists.get_value(:user_dir, opts, false)) do
      false ->
        default_user_dir()
      d ->
        d
    end
  end

  defp ssh_dir(:system, opts) do
    :proplists.get_value(:system_dir, opts, '/etc/ssh')
  end

  defp default_user_dir() do
    try do
      default_user_dir(:os.getenv('HOME'))
    catch
      _, _ ->
        default_user_dir(:init.get_argument(:home))
    end
  end

  defp default_user_dir({:ok, [[home | _]]}) do
    default_user_dir(home)
  end

  defp default_user_dir(home) when is_list(home) do
    userDir = :filename.join(home, '.ssh')
    :ok = :filelib.ensure_dir(:filename.join(userDir, 'dummy'))
    userDir
  end

  defp get_key_part(["---- BEGIN SSH2 PUBLIC KEY ----" | lines0]) do
    {keyValues, lines} = get_hdr_lines(lines0, [])
    expectedEndLine = "---- END SSH2 PUBLIC KEY ----"
    {key, restLines} = get_body(lines, expectedEndLine)
    {:rfc4716, key, keyValues, restLines}
  end

  defp get_key_part([<<"-----BEGIN ", rest :: binary>> | lines0]) do
    expectedEndLine = <<"-----END ", rest :: binary>>
    [middlePart, <<>>] = :binary.split(rest, " KEY-----")
    {keyValues, lines} = get_hdr_lines(lines0, [])
    {key, restLines} = get_body(lines, expectedEndLine)
    {asn1_type(middlePart), key, keyValues, restLines}
  end

  defp get_hdr_lines(lines, acc) do
    line1 = hd(lines)
    case (:binary.split(line1, ":")) do
      [^line1] ->
        {:lists.reverse(acc), lines}
      [key, value] ->
        get_hdr_lines(tl(lines),
                        [{trim(key), trim(value)} | acc])
    end
  end

  defp get_body(lines, expectedEndLine) do
    {keyPart,
       [^expectedEndLine |
            restLines]} = :lists.splitwith(fn l ->
                                                l !== expectedEndLine
                                           end,
                                             lines)
    {:base64.mime_decode(:erlang.iolist_to_binary(keyPart)),
       restLines}
  end

  defp trim(<<" ", b :: binary>>) do
    trim(b)
  end

  defp trim(b) do
    b
  end

  defp asn1_type("RSA PRIVATE") do
    :RSAPrivateKey
  end

  defp asn1_type("RSA PUBLIC") do
    :RSAPublicKey
  end

  defp asn1_type("DSA PRIVATE") do
    :DSAPrivateKey
  end

  defp asn1_type("EC PRIVATE") do
    :ECPrivateKey
  end

  defp asn1_type("OPENSSH PRIVATE") do
    :"openssh-key-v1"
  end

  defp asn1_type("PRIVATE") do
    :PrivateKeyInfo
  end

  defp asn1_type(_) do
    :undefined
  end

  defp openssh_key_v1_decode(<<"openssh-key-v1", 0,
              _L1 :: size(32) - unsigned - big - integer,
              cipherName :: size(_L1) - binary,
              _L2 :: size(32) - unsigned - big - integer,
              kdfName :: size(_L2) - binary,
              _L3 :: size(32) - unsigned - big - integer,
              kdfOptions :: size(_L3) - binary,
              n :: size(32) - unsigned - big - integer,
              rest :: binary>>,
            pwd) do
    openssh_key_v1_decode(rest, n, pwd, cipherName, kdfName,
                            kdfOptions, n, [])
  end

  defp openssh_key_v1_decode(<<_L1 :: size(32) - unsigned - big - integer,
              binKey :: size(_L1) - binary, rest :: binary>>,
            i, pwd, cipherName, kdfName, kdfOptions, n, pubKeyAcc)
      when i > 0 do
    publicKey = :ssh_message.ssh2_pubkey_decode(binKey)
    openssh_key_v1_decode(rest, i - 1, pwd, cipherName,
                            kdfName, kdfOptions, n, [publicKey | pubKeyAcc])
  end

  defp openssh_key_v1_decode(<<_L :: size(32) - unsigned - big - integer,
              encrypted :: size(_L) - binary>>,
            0, pwd, cipherName, kdfName, kdfOptions, n,
            pubKeyAccRev) do
    pubKeys = :lists.reverse(pubKeyAccRev)
    try do
      plain = decrypt_openssh_key_v1(encrypted, kdfName,
                                       kdfOptions, cipherName, pwd)
      openssh_key_v1_decode_priv_keys(plain, n, n, [], [])
    catch
      :error, {:decryption, decryptError} ->
        :erlang.error({:decryption, decryptError})
    else
      {privKeys, _Comments} ->
        :lists.zip(pubKeys, privKeys)
    end
  end

  defp openssh_key_v1_decode_priv_keys(bin, i, n, keyAcc, cmntAcc) when i > 0 do
    {privKey,
       <<_Lc :: size(32) - unsigned - big - integer,
           comment :: size(_Lc) - binary,
           rest
           ::
           binary>>} = :ssh_message.ssh2_privkey_decode2(bin)
    openssh_key_v1_decode_priv_keys(rest, i - 1, n,
                                      [privKey | keyAcc], [comment | cmntAcc])
  end

  defp openssh_key_v1_decode_priv_keys(_Padding, 0, _N, privKeyAccRev,
            commentAccRev) do
    {:lists.reverse(privKeyAccRev),
       :lists.reverse(commentAccRev)}
  end

  defp decrypt_openssh_key_v1(encrypted, "none", <<>>, _CipherName, _Pwd) do
    check_valid_decryption(encrypted, 8)
  end

  defp decrypt_openssh_key_v1(encrypted, <<>>, <<>>, _CipherName, _Pwd) do
    check_valid_decryption(encrypted, 8)
  end

  defp decrypt_openssh_key_v1(_Encrypted, "bcrypt",
            <<_L :: size(32) - unsigned - big - integer,
                _Salt :: size(_L) - binary,
                _Rounds :: size(32) - unsigned - big - integer>>,
            _CipherName, _Pwd) do
    :erlang.error({:decryption, {:not_supported, :bcrypt}})
  end

  defp decrypt_openssh_key_v1(_Encrypted, kdfName, _KdfOpts, _CipherName,
            _Pwd) do
    :erlang.error({:decryption, {:not_supported, kdfName}})
  end

  defp check_valid_decryption(<<checkint1
            ::
            size(32) - unsigned - big - integer,
              checkint2 :: size(32) - unsigned - big - integer,
              plain :: binary>>,
            blockSize)
      when checkint2 == checkint1 do
    case (check_padding(plain, blockSize)) do
      true ->
        plain
      false ->
        :erlang.error({:decryption, :bad_padding})
    end
  end

  defp check_valid_decryption(_, _) do
    :erlang.error({:decryption, :bad_result})
  end

  defp check_padding(bin, blockSize) do
    n = :binary.last(bin)
    cond do
      n < blockSize ->
        padding = :binary.part(bin, {byte_size(bin), - n})
        expectedPadding = :erlang.list_to_binary(:lists.seq(1,
                                                              n))
        padding == expectedPadding
      true ->
        true
    end
  end

  defp openssh_key_v1_encode(keyPairs) do
    cipherName = "none"
    blockSize = 8
    kdfName = "none"
    kdfOptions = <<>>
    numKeys = length(keyPairs)
    checkInt = :crypto.strong_rand_bytes(4)
    unEncrypted0 = <<checkInt :: binary, checkInt :: binary,
                       openssh_key_v1_encode_priv_keys_cmnts(keyPairs)
                       ::
                       binary>>
    unEncrypted = <<unEncrypted0 :: binary,
                      pad(byte_size(unEncrypted0), blockSize) :: binary>>
    encrypted = encrypt_openssh_key_v1(unEncrypted, kdfName,
                                         kdfOptions, cipherName, :ignore)
    <<"openssh-key-v1", 0,
        byte_size(cipherName)
        ::
        size(32) - unsigned - big - integer,
        cipherName :: binary,
        byte_size(kdfName)
        ::
        size(32) - unsigned - big - integer,
        kdfName :: binary,
        byte_size(kdfOptions)
        ::
        size(32) - unsigned - big - integer,
        kdfOptions :: binary,
        numKeys :: size(32) - unsigned - big - integer,
        openssh_key_v1_encode_pub_keys(keyPairs) :: binary,
        byte_size(encrypted)
        ::
        size(32) - unsigned - big - integer,
        encrypted :: binary>>
  end

  defp openssh_key_v1_encode_pub_keys(keyPairs) do
    openssh_key_v1_encode_pub_keys(keyPairs, [])
  end

  defp openssh_key_v1_encode_pub_keys([{priv = r_ECPrivateKey(), _Cmnt} | ks], acc) do
    pub = extract_public_key(priv)
    bk = :ssh_message.ssh2_pubkey_encode(pub)
    openssh_key_v1_encode_pub_keys(ks,
                                     [<<byte_size(bk)
                                        ::
                                        size(32) - unsigned - big - integer,
                                          bk :: binary>> |
                                          acc])
  end

  defp openssh_key_v1_encode_pub_keys([{k, _, _C} | ks], acc) do
    bk = :ssh_message.ssh2_pubkey_encode(k)
    openssh_key_v1_encode_pub_keys(ks,
                                     [<<byte_size(bk)
                                        ::
                                        size(32) - unsigned - big - integer,
                                          bk :: binary>> |
                                          acc])
  end

  defp openssh_key_v1_encode_pub_keys([], acc) do
    :erlang.list_to_binary(:lists.reverse(acc))
  end

  defp openssh_key_v1_encode_priv_keys_cmnts(keyPairs) do
    openssh_key_v1_encode_priv_keys_cmnts(keyPairs, [])
  end

  defp openssh_key_v1_encode_priv_keys_cmnts([{k = r_ECPrivateKey(), c} | ks], acc) do
    bk = :ssh_message.ssh2_privkey_encode(k)
    openssh_key_v1_encode_priv_keys_cmnts(ks,
                                            [<<bk :: binary,
                                                 byte_size(c)
                                                 ::
                                                 size(32) - unsigned - big -
                                                   integer,
                                                 c :: binary>> |
                                                 acc])
  end

  defp openssh_key_v1_encode_priv_keys_cmnts([{_, k, c} | ks], acc) do
    bk = :ssh_message.ssh2_privkey_encode(k)
    openssh_key_v1_encode_priv_keys_cmnts(ks,
                                            [<<bk :: binary,
                                                 byte_size(c)
                                                 ::
                                                 size(32) - unsigned - big -
                                                   integer,
                                                 c :: binary>> |
                                                 acc])
  end

  defp openssh_key_v1_encode_priv_keys_cmnts([], acc) do
    :erlang.list_to_binary(:lists.reverse(acc))
  end

  defp encrypt_openssh_key_v1(unEncrypted, "none", <<>>, _CipherName, _Pwd) do
    unEncrypted
  end

  defp encrypt_openssh_key_v1(_UnEncrypted, kdfName, _KdfOptions, _CipherName,
            _Pwd) do
    :erlang.error({:decryption, {:not_supported, kdfName}})
  end

  defp pad(n, blockSize) when n > blockSize do
    pad(rem(n, blockSize), blockSize)
  end

  defp pad(n, blockSize) do
    :erlang.list_to_binary(:lists.seq(1, blockSize - n))
  end

  defp split_in_nonempty_lines(bin) do
    skip_blank_lines_and_comments(split_in_lines(bin))
  end

  defp split_in_lines(bin) do
    :binary.split(bin, ["\n", "\r\n"], [:global, :trim_all])
  end

  defp skip_blank_lines_and_comments(lines) do
    :lists.filter(fn <<"#", _ :: binary>> ->
                       false
                     l ->
                       :re.run(l, '^(\t| )+$') == :nomatch
                  end,
                    lines)
  end

end