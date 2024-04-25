defmodule :m_inet_tls_dist do
  use Bitwise
  require Record
  Record.defrecord(:r_net_address, :net_address, address: :undefined,
                                       host: :undefined, protocol: :undefined,
                                       family: :undefined)
  Record.defrecord(:r_hs_data, :hs_data, kernel_pid: :undefined,
                                   other_node: :undefined,
                                   this_node: :undefined, socket: :undefined,
                                   timer: :undefined, this_flags: :undefined,
                                   allowed: :undefined,
                                   other_version: :undefined,
                                   other_flags: :undefined,
                                   other_started: :undefined,
                                   f_send: :undefined, f_recv: :undefined,
                                   f_setopts_pre_nodeup: :undefined,
                                   f_setopts_post_nodeup: :undefined,
                                   f_getll: :undefined, f_address: :undefined,
                                   mf_tick: :undefined, mf_getstat: :undefined,
                                   request_type: :normal,
                                   mf_setopts: :undefined,
                                   mf_getopts: :undefined,
                                   f_handshake_complete: :undefined,
                                   add_flags: :undefined,
                                   reject_flags: :undefined,
                                   require_flags: :undefined,
                                   this_creation: :undefined,
                                   other_creation: :undefined)
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
  def childspecs() do
    {:ok,
       [{:ssl_dist_sup, {:ssl_dist_sup, :start_link, []},
           :permanent, :infinity, :supervisor, [:ssl_dist_sup]}]}
  end

  def select(node) do
    fam_select(:inet, node)
  end

  def fam_select(family, node) do
    :inet_tcp_dist.fam_select(family, node)
  end

  def address() do
    fam_address(:inet)
  end

  def fam_address(family) do
    netAddress = :inet_tcp_dist.fam_address(family)
    r_net_address(netAddress, protocol: :tls)
  end

  def is_node_name(node) do
    :dist_util.is_node_name(node)
  end

  defp f_send(sslSocket, packet) do
    :ssl.send(sslSocket, packet)
  end

  defp f_recv(sslSocket, length, timeout) do
    case (:ssl.recv(sslSocket, length, timeout)) do
      {:ok, bin} when is_binary(bin) ->
        {:ok, :erlang.binary_to_list(bin)}
      other ->
        other
    end
  end

  defp f_setopts_pre_nodeup(_SslSocket) do
    :ok
  end

  defp f_setopts_post_nodeup(sslSocket) do
    :ssl.setopts(sslSocket, [:inet_tcp_dist.nodelay()])
  end

  defp f_getll(distCtrl) do
    {:ok, distCtrl}
  end

  defp f_address(family, address, node) do
    case (:dist_util.split_node(node)) do
      {:node, _, host} ->
        r_net_address(address: address, host: host, protocol: :tls,
            family: family)
      _ ->
        {:error, :no_node}
    end
  end

  defp mf_tick(distCtrl) do
    send(distCtrl, :tick)
    :ok
  end

  defp mf_getstat(sslSocket) do
    case (:ssl.getstat(sslSocket,
                         [:recv_cnt, :send_cnt, :send_pend])) do
      {:ok, stat} ->
        split_stat(stat, 0, 0, 0)
      error ->
        error
    end
  end

  defp mf_setopts(sslSocket, opts) do
    case (setopts_filter(opts)) do
      [] ->
        :ssl.setopts(sslSocket, opts)
      opts1 ->
        {:error, {:badopts, opts1}}
    end
  end

  defp mf_getopts(sslSocket, opts) do
    :ssl.getopts(sslSocket, opts)
  end

  defp f_handshake_complete(distCtrl, node, dHandle) do
    :tls_sender.dist_handshake_complete(distCtrl, node,
                                          dHandle)
  end

  defp setopts_filter(opts) do
    for ({k, _} = opt) <- opts,
          k === :active or k === :deliver or k === :packet do
      opt
    end
  end

  defp split_stat([{:recv_cnt, r} | stat], _, w, p) do
    split_stat(stat, r, w, p)
  end

  defp split_stat([{:send_cnt, w} | stat], r, _, p) do
    split_stat(stat, r, w, p)
  end

  defp split_stat([{:send_pend, p} | stat], r, w, _) do
    split_stat(stat, r, w, p)
  end

  defp split_stat([], r, w, p) do
    {:ok, r, w, p}
  end

  def listen(name, host) do
    fam_listen(:inet, name, host)
  end

  defp listen_loop(first, last, listenOptions)
      when first <= last do
    case (:gen_tcp.listen(first, listenOptions)) do
      {:error, :eaddrinuse} ->
        listen_loop(first + 1, last, listenOptions)
      result ->
        result
    end
  end

  defp listen_loop(_, _, _) do
    {:error, :eaddrinuse}
  end

  def accept(listenSocket) do
    fam_accept(:inet, listenSocket)
  end

  def fam_accept(family, listenSocket) do
    netKernel = self()
    monitor_pid(:erlang.spawn_opt(fn () ->
                                       :erlang.process_flag(:trap_exit, true)
                                       maxPending = :erlang.system_info(:schedulers_online)
                                       continue = make_ref()
                                       fLNC = {family, listenSocket, netKernel,
                                                 continue}
                                       pending = %{}
                                       accept_loop(fLNC, continue,
                                                     spawn_accept(fLNC),
                                                     maxPending, pending)
                                  end,
                                    :dist_util.net_ticker_spawn_options()))
  end

  defp accept_loop(fLNC, continue, :undefined, maxPending, pending)
      when map_size(pending) < maxPending do
    accept_loop(fLNC, continue, spawn_accept(fLNC),
                  maxPending, pending)
  end

  defp accept_loop({_, _, netKernelPid, _} = fLNC, continue,
            handshakePid, maxPending, pending) do
    receive do
      {^continue, ^handshakePid} when is_pid(handshakePid) ->
        accept_loop(fLNC, continue, :undefined, maxPending,
                      Map.put(pending, handshakePid, true))
      {:EXIT, pid, reason} when :erlang.is_map_key(pid,
                                                     pending)
                                ->
        reason !== :normal and (case (:logger.allow(:error,
                                                      :inet_tls_dist)) do
                                  true ->
                                    :erlang.apply(:logger, :macro_log,
                                                    [%{mfa:
                                                       {:inet_tls_dist,
                                                          :accept_loop, 5},
                                                         line: 301, file: 'otp/lib/ssl/src/inet_tls_dist.erl'},
                                                         :error, 'TLS distribution handshake failed: ~p~n', [reason]])
                                  false ->
                                    :ok
                                end)
        accept_loop(fLNC, continue, handshakePid, maxPending,
                      :maps.remove(pid, pending))
      {:EXIT, ^handshakePid, reason} when is_pid(handshakePid)
                                          ->
        exit(reason)
      {:EXIT, ^netKernelPid, reason} ->
        exit(reason)
      unexpected ->
        case (:logger.allow(:warning, :inet_tls_dist)) do
          true ->
            :erlang.apply(:logger, :macro_log,
                            [%{mfa: {:inet_tls_dist, :accept_loop, 5},
                                 line: 313, file: 'otp/lib/ssl/src/inet_tls_dist.erl'},
                                 :warning, 'TLS distribution: unexpected message: ~p~n', [unexpected]])
          false ->
            :ok
        end
        accept_loop(fLNC, continue, handshakePid, maxPending,
                      pending)
    end
  end

  defp spawn_accept({family, listenSocket, netKernel, continue}) do
    acceptLoop = self()
    spawn_link(fn () ->
                    case (:gen_tcp.accept(listenSocket)) do
                      {:ok, socket} ->
                        send(acceptLoop, {continue, self()})
                        case (check_ip(socket)) do
                          true ->
                            accept_one(family, socket, netKernel)
                          {false, iP} ->
                            case (:logger.allow(:error, :inet_tls_dist)) do
                              true ->
                                :erlang.apply(:logger, :macro_log,
                                                [%{mfa:
                                                   {:inet_tls_dist,
                                                      :spawn_accept, 1},
                                                     line: 329, file: 'otp/lib/ssl/src/inet_tls_dist.erl'},
                                                     :error, '** Connection attempt from disallowed IP ~w ** ~n', [iP]])
                              false ->
                                :ok
                            end
                            trace({:disallowed, iP})
                        end
                      error ->
                        exit(error)
                    end
               end)
  end

  defp accept_one(family, socket, netKernel) do
    opts = setup_verify_client(socket,
                                 get_ssl_options(:server))
    kTLS = :proplists.get_value(:ktls, opts, false)
    case (:ssl.handshake(socket,
                           trace([{:active, false}, {:packet, 4} | opts]),
                           :net_kernel.connecttime())) do
      {:ok, sslSocket} ->
        receiver = hd(r_sslsocket(sslSocket, :pid))
        case (kTLS) do
          true ->
            {:ok,
               ktlsInfo} = :ssl_gen_statem.ktls_handover(receiver)
            case (inet_set_ktls(ktlsInfo)) do
              :ok ->
                accept_one(family, :maps.get(:socket, ktlsInfo),
                             netKernel, &:gen_tcp.controlling_process/2)
              {:error, ktlsReason} ->
                case (:logger.allow(:error, :inet_tls_dist)) do
                  true ->
                    :erlang.apply(:logger, :macro_log,
                                    [%{mfa: {:inet_tls_dist, :accept_one, 3},
                                         line: 359, file: 'otp/lib/ssl/src/inet_tls_dist.erl'},
                                         :error, [{:slogan, :set_ktls_failed},
                                                      {:reason, ktlsReason},
                                                          {:pid, self()}]])
                  false ->
                    :ok
                end
                close(socket)
                trace({:ktls_error, ktlsReason})
            end
          false ->
            accept_one(family, sslSocket, netKernel,
                         &:ssl.controlling_process/2)
        end
      {:error, {:options, _}} = error ->
        case (:logger.allow(:error, :inet_tls_dist)) do
          true ->
            :erlang.apply(:logger, :macro_log,
                            [%{mfa: {:inet_tls_dist, :accept_one, 3}, line: 374,
                                 file: 'otp/lib/ssl/src/inet_tls_dist.erl'},
                                 :error, 'Cannot accept TLS distribution connection: ~s~n', [:ssl.format_error(error)]])
          false ->
            :ok
        end
        close(socket)
        trace(error)
      other ->
        close(socket)
        trace(other)
    end
  end

  defp accept_one(family, distSocket, netKernel,
            controllingProcessFun) do
    trace(send(netKernel, {:accept, self(), distSocket,
                             family, :tls}))
    receive do
      {^netKernel, :controller, pid} ->
        case (controllingProcessFun.(distSocket, pid)) do
          :ok ->
            trace(send(pid, {self(), :controller}))
          {:error, reason} ->
            trace(send(pid, {self(), :exit}))
            case (:logger.allow(:error, :inet_tls_dist)) do
              true ->
                :erlang.apply(:logger, :macro_log,
                                [%{mfa: {:inet_tls_dist, :accept_one, 4},
                                     line: 394, file: 'otp/lib/ssl/src/inet_tls_dist.erl'},
                                     :error, [{:slogan,
                                                 :controlling_process_failed},
                                                  {:reason, reason}, {:pid,
                                                                        self()}]])
              false ->
                :ok
            end
        end
      {^netKernel, :unsupported_protocol} ->
        trace(:unsupported_protocol)
    end
  end

  defp setup_verify_client(socket, opts) do
    setup_verify_client(socket, opts, true, [])
  end

  defp setup_verify_client(_Socket, [], _, optsR) do
    :lists.reverse(optsR)
  end

  defp setup_verify_client(socket, [opt | opts], first, optsR) do
    case (opt) do
      {:verify_fun, {fun, _}} ->
        case (fun === &:inet_tls_dist.verify_client/3) do
          true ->
            cond do
              first ->
                case (:inet.peername(socket)) do
                  {:ok, {peerIP, _Port}} ->
                    {:ok, allowed} = :net_kernel.allowed()
                    allowedHosts = allowed_hosts(allowed)
                    setup_verify_client(socket, opts, false,
                                          [{:verify_fun,
                                              {fun, {allowedHosts, peerIP}}} |
                                               optsR])
                  {:error, reason} ->
                    exit(trace({:no_peername, reason}))
                end
              true ->
                setup_verify_client(socket, opts, first, optsR)
            end
          false ->
            setup_verify_client(socket, opts, first, [opt | optsR])
        end
      _ ->
        setup_verify_client(socket, opts, first, [opt | optsR])
    end
  end

  defp allowed_hosts(allowed) do
    :lists.usort(allowed_node_hosts(allowed))
  end

  defp allowed_node_hosts([]) do
    []
  end

  defp allowed_node_hosts([node | allowed]) do
    case (:dist_util.split_node(node)) do
      {:node, _, host} ->
        [host | allowed_node_hosts(allowed)]
      {:host, host} ->
        [host | allowed_node_hosts(allowed)]
      _ ->
        allowed_node_hosts(allowed)
    end
  end

  def verify_client(_, {:bad_cert, _} = reason, _) do
    {:fail, reason}
  end

  def verify_client(_, {:extension, _}, s) do
    {:unknown, s}
  end

  def verify_client(_, :valid, s) do
    {:valid, s}
  end

  def verify_client(_, :valid_peer, {[], _} = s) do
    {:valid, s}
  end

  def verify_client(peerCert, :valid_peer,
           {allowedHosts, peerIP} = s) do
    case (:public_key.pkix_verify_hostname(peerCert,
                                             [{:ip, peerIP} |
                                                  for host <- allowedHosts do
                                                    {:dns_id, host}
                                                  end])) do
      true ->
        {:valid, s}
      false ->
        {:fail, :cert_no_hostname_nor_ip_match}
    end
  end

  def accept_connection(acceptPid, distSocket, myNode, allowed,
           setupTime) do
    fam_accept_connection(:inet, acceptPid, distSocket,
                            myNode, allowed, setupTime)
  end

  def fam_accept_connection(family, acceptPid, distSocket, myNode, allowed,
           setupTime) do
    kernel = self()
    monitor_pid(:erlang.spawn_opt(fn () ->
                                       do_accept(family, acceptPid, distSocket,
                                                   myNode, allowed, setupTime,
                                                   kernel)
                                  end,
                                    :dist_util.net_ticker_spawn_options()))
  end

  defp do_accept(family, acceptPid, distSocket, myNode, allowed,
            setupTime, kernel) do
    mRef = :erlang.monitor(:process, acceptPid)
    receive do
      {^acceptPid, :controller} ->
        :erlang.demonitor(mRef, [:flush])
        timer = :dist_util.start_timer(setupTime)
        {hSData0, newAllowed} = (case (distSocket) do
                                   sslSocket = r_sslsocket(pid: [_Receiver, sender |
                                                                      _]) ->
                                     :erlang.link(sender)
                                     {hs_data_ssl(family, sslSocket),
                                        allowed_nodes(sslSocket, allowed)}
                                   portSocket when is_port(distSocket) ->
                                     driver = :erlang.port_get_data(portSocket)
                                     {hs_data_inet_tcp(driver, portSocket),
                                        allowed}
                                 end)
        hSData = r_hs_data(hSData0, kernel_pid: kernel, 
                              this_node: myNode,  timer: timer,  this_flags: 0, 
                              allowed: newAllowed)
        :dist_util.handshake_other_started(trace(hSData))
      {^acceptPid, :exit} ->
        :dist_util.shutdown(:inet_tls_dist, 535, myNode,
                              :connection_setup_failed)
      {:DOWN, ^mRef, _, _, _Reason} ->
        :dist_util.shutdown(:inet_tls_dist, 540, myNode,
                              :connection_setup_failed)
    end
  end

  defp allowed_nodes(_SslSocket, []) do
    []
  end

  defp allowed_nodes(sslSocket, allowed) do
    case (:ssl.peercert(sslSocket)) do
      {:ok, peerCertDER} ->
        case (:ssl.peername(sslSocket)) do
          {:ok, {peerIP, _Port}} ->
            peerCert = :public_key.pkix_decode_cert(peerCertDER,
                                                      :otp)
            case (allowed_nodes(peerCert, allowed_hosts(allowed),
                                  peerIP)) do
              [] ->
                case (:logger.allow(:error, :inet_tls_dist)) do
                  true ->
                    :erlang.apply(:logger, :macro_log,
                                    [%{mfa: {:inet_tls_dist, :allowed_nodes, 2},
                                         line: 558, file: 'otp/lib/ssl/src/inet_tls_dist.erl'},
                                         :error, '** Connection attempt from disallowed node(s) ~p ** ~n', [peerIP]])
                  false ->
                    :ok
                end
                :dist_util.shutdown(:inet_tls_dist, 561, peerIP,
                                      trace({:is_allowed, :not_allowed}))
              allowedNodes ->
                allowedNodes
            end
          error1 ->
            :dist_util.shutdown(:inet_tls_dist, 567, :no_peer_ip,
                                  trace(error1))
        end
      {:error, :no_peercert} ->
        allowed
      error2 ->
        :dist_util.shutdown(:inet_tls_dist, 572, :no_peer_cert,
                              trace(error2))
    end
  end

  defp allowed_nodes(peerCert, [], peerIP) do
    case (:public_key.pkix_verify_hostname(peerCert,
                                             [{:ip, peerIP}])) do
      true ->
        host = :inet.ntoa(peerIP)
        true = is_list(host)
        [host]
      false ->
        []
    end
  end

  defp allowed_nodes(peerCert, [node | allowed], peerIP) do
    case (:dist_util.split_node(node)) do
      {:node, _, host} ->
        allowed_nodes(peerCert, allowed, peerIP, node, host)
      {:host, host} ->
        allowed_nodes(peerCert, allowed, peerIP, node, host)
      _ ->
        allowed_nodes(peerCert, allowed, peerIP)
    end
  end

  defp allowed_nodes(peerCert, allowed, peerIP, node, host) do
    case (:public_key.pkix_verify_hostname(peerCert,
                                             [{:dns_id, host}])) do
      true ->
        [node | allowed_nodes(peerCert, allowed, peerIP)]
      false ->
        allowed_nodes(peerCert, allowed, peerIP)
    end
  end

  def setup(node, type, myNode, longOrShortNames,
           setupTime) do
    fam_setup(:inet, node, type, myNode, longOrShortNames,
                setupTime)
  end

  def fam_setup(family, node, type, myNode, longOrShortNames,
           setupTime) do
    netKernel = self()
    monitor_pid(:erlang.spawn_opt(setup_fun(family, node,
                                              type, myNode, longOrShortNames,
                                              setupTime, netKernel),
                                    :dist_util.net_ticker_spawn_options()))
  end

  defp setup_fun(family, node, type, myNode, longOrShortNames,
            setupTime, netKernel) do
    fn () ->
         do_setup(family, node, type, myNode, longOrShortNames,
                    setupTime, netKernel)
    end
  end

  def close(socket) do
    :gen_tcp.close(socket)
  end

  defp find_netmask(iP, [{_Name, items} | ifaddrs]) do
    find_netmask(iP, ifaddrs, items)
  end

  defp find_netmask(_, []) do
    {:error, :no_netmask}
  end

  defp find_netmask(iP, _Ifaddrs,
            [{:addr, iP}, {:netmask, netmask} | _]) do
    {:ok, netmask}
  end

  defp find_netmask(iP, ifaddrs, [_ | items]) do
    find_netmask(iP, ifaddrs, items)
  end

  defp find_netmask(iP, ifaddrs, []) do
    find_netmask(iP, ifaddrs)
  end

  defp mask(addr, mask) do
    :erlang.list_to_tuple(mask(addr, mask, 1))
  end

  defp mask(addr, mask, n) when n <= tuple_size(addr) do
    [:erlang.element(n, addr) &&& :erlang.element(n, mask) |
         mask(addr, mask, n + 1)]
  end

  defp mask(_, _, _) do
    []
  end

  def cert_nodes(r_OTPCertificate(tbsCertificate: r_OTPTBSCertificate(extensions: extensions))) do
    parse_extensions(extensions)
  end

  defp parse_extensions(extensions) when is_list(extensions) do
    parse_extensions(extensions, [], [])
  end

  defp parse_extensions(:asn1_NOVALUE) do
    :undefined
  end

  defp parse_extensions([], [], []) do
    :undefined
  end

  defp parse_extensions([], hosts, []) do
    :lists.reverse(hosts)
  end

  defp parse_extensions([], [], names) do
    for name <- :lists.reverse(names) do
      name ++ '@'
    end
  end

  defp parse_extensions([], hosts, names) do
    for host <- :lists.reverse(hosts),
          name <- :lists.reverse(names) do
      name ++ '@' ++ host
    end
  end

  defp parse_extensions([r_Extension(extnID: {2, 5, 29, 17},
               extnValue: altNames) |
               extensions],
            hosts, names) do
    case (parse_subject_altname(altNames)) do
      :none ->
        parse_extensions(extensions, hosts, names)
      {:host, host} ->
        parse_extensions(extensions, [host | hosts], names)
      {:name, name} ->
        parse_extensions(extensions, hosts, [name | names])
    end
  end

  defp parse_extensions([_ | extensions], hosts, names) do
    parse_extensions(extensions, hosts, names)
  end

  defp parse_subject_altname([]) do
    :none
  end

  defp parse_subject_altname([{:dNSName, host} | _AltNames]) do
    {:host, host}
  end

  defp parse_subject_altname([{:directoryName, {:rdnSequence, [rdn | _]}} |
               altNames]) do
    case (parse_rdn(rdn)) do
      :none ->
        parse_subject_altname(altNames)
      name ->
        {:name, name}
    end
  end

  defp parse_subject_altname([_ | altNames]) do
    parse_subject_altname(altNames)
  end

  defp parse_rdn([]) do
    :none
  end

  defp parse_rdn([r_AttributeTypeAndValue(type: {2, 5, 4, 3},
               value: {:utf8String, commonName}) |
               _]) do
    :unicode.characters_to_list(commonName)
  end

  defp parse_rdn([_ | rdn]) do
    parse_rdn(rdn)
  end

  defp get_ssl_options(type) do
    [{:erl_dist, true} |
         case ((case (:init.get_argument(:ssl_dist_opt)) do
                  {:ok, args} ->
                    ssl_options(type, :lists.append(args))
                  _ ->
                    []
                end) ++ (try do
                           :ets.lookup(:ssl_dist_opts, type)
                         catch
                           :error, :badarg ->
                             []
                         else
                           [{^type, opts0}] ->
                             opts0
                           _ ->
                             []
                         end)) do
           [] ->
             []
           opts1 ->
             dist_defaults(opts1)
         end]
  end

  defp dist_defaults(opts) do
    case (:proplists.get_value(:versions, opts,
                                 :undefined)) do
      :undefined ->
        [{:versions, [:"tlsv1.2"]} | opts]
      _ ->
        opts
    end
  end

  defp ssl_options(_Type, []) do
    []
  end

  defp ssl_options(:client, ['client_' ++ opt, value | t] = opts) do
    ssl_options(:client, t, opts, opt, value)
  end

  defp ssl_options(:server, ['server_' ++ opt, value | t] = opts) do
    ssl_options(:server, t, opts, opt, value)
  end

  defp ssl_options(type, [_Opt, _Value | t]) do
    ssl_options(type, t)
  end

  defp ssl_options(type, t, opts, opt, value) do
    case (ssl_option(type, opt)) do
      :error ->
        :erlang.error(:malformed_ssl_dist_opt, [type, opts])
      fun ->
        [{:erlang.list_to_atom(opt), fun.(value)} |
             ssl_options(type, t)]
    end
  end

  defp ssl_option(:server, opt) do
    case (opt) do
      'dhfile' ->
        &listify/1
      'fail_if_no_peer_cert' ->
        &atomize/1
      _ ->
        ssl_option(:client, opt)
    end
  end

  defp ssl_option(:client, opt) do
    case (opt) do
      'certfile' ->
        &listify/1
      'cacertfile' ->
        &listify/1
      'keyfile' ->
        &listify/1
      'password' ->
        &listify/1
      'verify' ->
        &atomize/1
      'verify_fun' ->
        &verify_fun/1
      'crl_check' ->
        &atomize/1
      'crl_cache' ->
        &termify/1
      'reuse_sessions' ->
        &atomize/1
      'secure_renegotiate' ->
        &atomize/1
      'depth' ->
        &:erlang.list_to_integer/1
      'hibernate_after' ->
        &:erlang.list_to_integer/1
      'ciphers' ->
        fn val ->
             [listify(val)]
        end
      'versions' ->
        fn val ->
             [atomize(val)]
        end
      'ktls' ->
        &atomize/1
      _ ->
        :error
    end
  end

  defp listify(list) when is_list(list) do
    list
  end

  defp atomize(list) when is_list(list) do
    :erlang.list_to_atom(list)
  end

  defp atomize(atom) when is_atom(atom) do
    atom
  end

  defp termify(string) when is_list(string) do
    {:ok, tokens, _} = :erl_scan.string(string ++ '.')
    {:ok, term} = :erl_parse.parse_term(tokens)
    term
  end

  defp verify_fun(value) do
    case (termify(value)) do
      {mod, func, state} when (is_atom(mod) and is_atom(func))
                              ->
        fun = Function.capture(mod, func, 3)
        {fun, state}
      _ ->
        :erlang.error(:malformed_ssl_dist_opt, [value])
    end
  end

  def inet_ktls_setopt(socket, {level, opt}, value)
      when (is_integer(level) and is_integer(opt) and
              is_binary(value)) do
    :inet.setopts(socket, [{:raw, level, opt, value}])
  end

  def inet_ktls_getopt(socket, {level, opt}, size)
      when (is_integer(level) and is_integer(opt) and
              is_integer(size)) do
    case (:inet.getopts(socket,
                          [{:raw, level, opt, size}])) do
      {:ok, [{:raw, ^level, ^opt, value}]} ->
        {:ok, value}
      {:ok, _} = error ->
        {:error, error}
      {:error, _} = error ->
        error
    end
  end

  def set_ktls_ulp(%{socket: socket, setopt_fun: setoptFun,
             getopt_fun: getoptFun},
           oS) do
    {option, value} = ktls_opt_ulp(oS)
    size = byte_size(value)
    _ = setoptFun.(socket, option, value)
    case (getoptFun.(socket, option, size + 1)) do
      {:ok, <<^value :: size(size) - binary, 0>>} ->
        :ok
      other ->
        {:error, {:ktls_set_ulp_failed, option, value, other}}
    end
  end

  def ktls_os() do
    oS = {:os.type(), :os.version()}
    case (oS) do
      {{:unix, :linux}, osVersion} when {5, 2, 0} <= osVersion
                                        ->
        {:ok, oS}
      _ ->
        {:error, {:ktls_notsup, {:os, oS}}}
    end
  end

  def ktls_opt_ulp(_OS) do
    sOL_TCP = 6
    tCP_ULP = 31
    ktlsMod = "tls"
    {{sOL_TCP, tCP_ULP}, ktlsMod}
  end

  def ktls_opt_cipher(_OS, _TLS_version = {3, 4},
           _CipherSpec = <<19
                           ::
                           size(8) - unsigned - big - integer,
                             2 :: size(8) - unsigned - big - integer>>,
           r_cipher_state(key: <<key :: size(32) - bytes>>,
               iv: <<salt :: size(4) - bytes, iV :: size(8) - bytes>>),
           cipherSeq, txRx)
      when is_integer(cipherSeq) do
    tLS_1_3_VERSION_MAJOR = 3
    tLS_1_3_VERSION_MINOR = 4
    tLS_1_3_VERSION = tLS_1_3_VERSION_MAJOR <<< 8 ||| tLS_1_3_VERSION_MINOR
    tLS_CIPHER_AES_GCM_256 = 52
    sOL_TLS = 282
    tLS_TX = 1
    tLS_RX = 2
    value = <<tLS_1_3_VERSION :: size(16) - native,
                tLS_CIPHER_AES_GCM_256 :: size(16) - native,
                iV :: bytes, key :: bytes, salt :: bytes,
                cipherSeq :: size(64) - native>>
    ^sOL_TLS = 282
    ^tLS_TX = 1
    ^tLS_RX = 2
    tLS_TxRx = (case (txRx) do
                  :tx ->
                    tLS_TX
                  :rx ->
                    tLS_RX
                end)
    {:ok, {{sOL_TLS, tLS_TxRx}, value}}
  end

  def ktls_opt_cipher(_OS, tLS_version, cipherSpec, _CipherState,
           _CipherSeq, _TxRx) do
    {:error,
       {:ktls_notsup,
          {:cipher, tLS_version, cipherSpec, _CipherState}}}
  end

  defp trace(term) do
    term
  end

  defp monitor_pid(pid) do
    pid
  end

  def dbg() do
    :dbg.stop()
    :dbg.tracer()
    :dbg.p(:all, :c)
    :dbg.tpl(:inet_tls_dist, :cx)
    :dbg.tpl(:erlang, :dist_ctrl_get_data_notification, :cx)
    :dbg.tpl(:erlang, :dist_ctrl_get_data, :cx)
    :dbg.tpl(:erlang, :dist_ctrl_put_data, :cx)
    :ok
  end

end