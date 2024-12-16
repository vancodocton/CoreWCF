// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Threading.Tasks;
using System.Xml;
using CoreWCF.Channels;
using CoreWCF.Description;
using CoreWCF.IdentityModel;
using CoreWCF.IdentityModel.Policy;
using CoreWCF.IdentityModel.Selectors;
using CoreWCF.IdentityModel.Tokens;
using CoreWCF.Security.Tokens;

namespace CoreWCF.Security
{
    internal class WSSecurityOneDotZeroReceiveSecurityHeader : ReceiveSecurityHeader
    {
        private KeyedHashAlgorithm _signingKey;
        private SignedXml _pendingSignature;
        private const string SIGNED_XML_HEADER = "signed_xml_header";
        public WSSecurityOneDotZeroReceiveSecurityHeader(Message message, string actor, bool mustUnderstand, bool relay,
            SecurityStandardsManager standardsManager,
            SecurityAlgorithmSuite algorithmSuite,
            int headerIndex,
            MessageDirection transferDirection)
            : base(message, actor, mustUnderstand, relay, standardsManager, algorithmSuite, headerIndex, transferDirection)
        {
        }

        protected override bool IsReaderAtReferenceList(XmlDictionaryReader reader)
        {
            return reader.IsStartElement(ReferenceList.ElementName, ReferenceList.NamespaceUri);
        }

        protected override bool IsReaderAtSignature(XmlDictionaryReader reader)
        {
            return reader.IsStartElement(XD.XmlSignatureDictionary.Signature, XD.XmlSignatureDictionary.Namespace);
        }

        protected override void EnsureDecryptionComplete()
        {
            // noop
        }

        protected override bool IsReaderAtEncryptedKey(XmlDictionaryReader reader)
        {
            return reader.IsStartElement(XD.XmlEncryptionDictionary.EncryptedKey, XD.XmlEncryptionDictionary.Namespace);
        }

        protected override bool IsReaderAtEncryptedData(XmlDictionaryReader reader)
        {
            bool encrypted = reader.IsStartElement(XD.XmlEncryptionDictionary.EncryptedData, XD.XmlEncryptionDictionary.Namespace);

            if (encrypted == true)
            {
                throw new PlatformNotSupportedException();
            }

            return encrypted;
        }

        protected override bool IsReaderAtSecurityTokenReference(XmlDictionaryReader reader)
        {
            return reader.IsStartElement(XD.SecurityJan2004Dictionary.SecurityTokenReference, XD.SecurityJan2004Dictionary.Namespace);
        }

        protected override EncryptedData ReadSecurityHeaderEncryptedItem(XmlDictionaryReader reader, bool readXmlreferenceKeyInfoClause)
        {
            throw new PlatformNotSupportedException();
        }

        protected override byte[] DecryptSecurityHeaderElement(EncryptedData encryptedData, WrappedKeySecurityToken wrappedKeyToken, out SecurityToken encryptionToken)
        {
            throw new PlatformNotSupportedException();
        }

        protected override WrappedKeySecurityToken DecryptWrappedKey(XmlDictionaryReader reader)
        {
            throw new PlatformNotSupportedException();
        }

        private bool EnsureDigestValidityIfIdMatches(
            SignedInfo signedInfo,
            string id, XmlDictionaryReader reader, bool doSoapAttributeChecks,
            MessagePartSpecification signatureParts, MessageHeaderInfo info, bool checkForTokensAtHeaders)
        {
            if (signedInfo == null)
            {
                return false;
            }
            if (doSoapAttributeChecks)
            {
                //VerifySoapAttributeMatchForHeader(info, signatureParts, reader);
                throw new PlatformNotSupportedException();
            }

            bool signed = false;
            bool isRecognizedSecurityToken = checkForTokensAtHeaders && this.StandardsManager.SecurityTokenSerializer.CanReadToken(reader);

            try
            {
                //signed = signedInfo.EnsureDigestValidityIfIdMatches(id, reader);
                // There is no public API to validate partially reference by id in signature.
                // It is impposible to extend this function because SignedXml is closed to extend.
                // Only CheckSignature is expose to validate all references. In our current
                // use case, only body is signed. The following is the workaround.

                using XmlReader subReader = reader.ReadSubtree();
                XmlDocument doc = new XmlDocument();
                doc.Load(subReader);
                var signedXml = new SignedXMLInternal(doc);
                signedXml.LoadXml(_pendingSignature.Signature.GetXml());

                AlgorithmSuite.GetSignatureAlgorithmAndKey(SignatureToken, out string signatureAlgorithm, out SecurityKey signatureKey, out XmlDictionaryString signatureAlgorithmDictionaryString);
                GetSigningAlgorithm(signatureKey, signatureAlgorithm, out _signingKey, out AsymmetricAlgorithm asymmetricAlgorithm);
                if (_signingKey != null)
                {
                    if (!signedXml.CheckSignature(_signingKey))
                    {
                        throw new CryptographicException("Signature not valid.");
                    }
                }
                else
                {
                    if (!signedXml.CheckSignature(asymmetricAlgorithm))
                    {
                        throw new CryptographicException("Signature not valid.");
                    }
                }
                signed = true;
            }
            catch (CryptographicException exception)
            {
                //
                // Wrap the crypto exception here so that the perf couter can be updated correctly
                //
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new MessageSecurityException(SR.FailedSignatureVerification, exception));
            }

            if (signed && isRecognizedSecurityToken)
            {
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new MessageSecurityException(SR.Format(SR.SecurityTokenFoundOutsideSecurityHeader, info.Namespace, info.Name)));
            }

            return signed;
        }

        protected override void OnDecryptionOfSecurityHeaderItemRequiringReferenceListEntry(string id)
        {
            throw new PlatformNotSupportedException();
        }

        protected override void ExecuteMessageProtectionPass(bool hasAtLeastOneSupportingTokenExpectedToBeSigned)
        {
            SignatureTargetIdManager idManager = this.StandardsManager.IdManager;
            MessagePartSpecification encryptionParts = this.RequiredEncryptionParts ?? MessagePartSpecification.NoParts;
            MessagePartSpecification signatureParts = this.RequiredSignatureParts ?? MessagePartSpecification.NoParts;

            //bool checkForTokensAtHeaders = hasAtLeastOneSupportingTokenExpectedToBeSigned;
            //bool doSoapAttributeChecks = !signatureParts.IsBodyIncluded;
            bool encryptBeforeSign = this.EncryptBeforeSignMode;
            SignedInfo signedInfo = this._pendingSignature != null ? this._pendingSignature.Signature.SignedInfo : null;

            SignatureConfirmations signatureConfirmations = this.GetSentSignatureConfirmations();
            if (signatureConfirmations != null && signatureConfirmations.Count > 0 && signatureConfirmations.IsMarkedForEncryption)
            {
                // If Signature Confirmations are encrypted then the signature should
                // be encrypted as well.
                this.VerifySignatureEncryption();
            }

            MessageHeaders headers = this.SecurityVerifiedMessage.Headers;
            XmlDictionaryReader reader = this.SecurityVerifiedMessage.GetReaderAtFirstHeader();

            bool atLeastOneHeaderOrBodyEncrypted = false;

            for (int i = 0; i < headers.Count; i++)
            {
                if (reader.NodeType != XmlNodeType.Element)
                {
                    reader.MoveToContent();
                }

                if (i == this.HeaderIndex)
                {
                    reader.Skip();
                    continue;
                }

                bool isHeaderEncrypted = false;

                string id = idManager.ExtractId(reader);

                if (id != null)
                {
                    isHeaderEncrypted = TryDeleteReferenceListEntry(id);
                }

                if (!isHeaderEncrypted && reader.IsStartElement(SecurityXXX2005Strings.EncryptedHeader, SecurityXXX2005Strings.Namespace))
                {
                    XmlDictionaryReader localreader = headers.GetReaderAtHeader(i);
                    localreader.ReadStartElement(SecurityXXX2005Strings.EncryptedHeader, SecurityXXX2005Strings.Namespace);

                    if (localreader.IsStartElement(EncryptedData.ElementName, XD.XmlEncryptionDictionary.Namespace))
                    {
                        string encryptedDataId = localreader.GetAttribute(XD.XmlEncryptionDictionary.Id, null);

                        if (encryptedDataId != null && TryDeleteReferenceListEntry(encryptedDataId))
                        {
                            isHeaderEncrypted = true;
                        }
                    }
                }

                this.ElementManager.VerifyUniquenessAndSetHeaderId(id, i);

                MessageHeaderInfo info = headers[i];

                if (!isHeaderEncrypted && encryptionParts.IsHeaderIncluded(info.Name, info.Namespace))
                {
                    this.SecurityVerifiedMessage.OnUnencryptedPart(info.Name, info.Namespace);
                }

                bool headerSigned;
                if ((!isHeaderEncrypted || encryptBeforeSign) && id != null)
                {
                    throw new PlatformNotSupportedException();
                    //headerSigned = EnsureDigestValidityIfIdMatches(signedInfo, id, reader, doSoapAttributeChecks, signatureParts, info, checkForTokensAtHeaders);
                }
                else
                {
                    headerSigned = false;
                }

                if (isHeaderEncrypted)
                {
                    throw new PlatformNotSupportedException();
                    /*
                    XmlDictionaryReader decryptionReader = headerSigned ? headers.GetReaderAtHeader(i) : reader;
                    DecryptedHeader decryptedHeader = DecryptHeader(decryptionReader, this.pendingDecryptionToken);
                    info = decryptedHeader;
                    id = decryptedHeader.Id;
                    this.ElementManager.VerifyUniquenessAndSetDecryptedHeaderId(id, i);
                    headers.ReplaceAt(i, decryptedHeader);
                    if (!ReferenceEquals(decryptionReader, reader))
                    {
                        decryptionReader.Close();
                    }

                    if (!encryptBeforeSign && id != null)
                    {
                        XmlDictionaryReader decryptedHeaderReader = decryptedHeader.GetHeaderReader();
                        headerSigned = EnsureDigestValidityIfIdMatches(signedInfo, id, decryptedHeaderReader, doSoapAttributeChecks, signatureParts, info, checkForTokensAtHeaders);
                        decryptedHeaderReader.Close();
                    }
                    */
                }

                if (!headerSigned && signatureParts.IsHeaderIncluded(info.Name, info.Namespace))
                {
                    this.SecurityVerifiedMessage.OnUnsignedPart(info.Name, info.Namespace);
                }

                if (headerSigned && isHeaderEncrypted)
                {
                    // We have a header that is signed and encrypted. So the accompanying primary signature
                    // should be encrypted as well.
                    this.VerifySignatureEncryption();
                }

                if (isHeaderEncrypted && !headerSigned)
                {
                    // We require all encrypted headers (outside the security header) to be signed.
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new MessageSecurityException(SR.Format(SR.EncryptedHeaderNotSigned, info.Name, info.Namespace)));
                }

                if (!headerSigned && !isHeaderEncrypted)
                {
                    reader.Skip();
                }

                atLeastOneHeaderOrBodyEncrypted |= isHeaderEncrypted;
            }

            reader.ReadEndElement();

            if (reader.NodeType != XmlNodeType.Element)
            {
                reader.MoveToContent();
            }

            string bodyId = idManager.ExtractId(reader);
            this.ElementManager.VerifyUniquenessAndSetBodyId(bodyId);
            this.SecurityVerifiedMessage.SetBodyPrefixAndAttributes(reader);

            bool expectBodyEncryption = encryptionParts.IsBodyIncluded /*|| HasPendingDecryptionItem()*/;

            bool bodySigned;
            if ((!expectBodyEncryption || encryptBeforeSign) && bodyId != null)
            {
                bodySigned = EnsureDigestValidityIfIdMatches(signedInfo, bodyId, reader, false, null, null, false);
            }
            else
            {
                bodySigned = false;
            }

            bool bodyEncrypted;
            if (expectBodyEncryption)
            {
                throw new PlatformNotSupportedException();
                /*
                XmlDictionaryReader bodyReader = bodySigned ? this.SecurityVerifiedMessage.CreateFullBodyReader() : reader;
                bodyReader.ReadStartElement();
                string bodyContentId = idManager.ExtractId(bodyReader);
                this.ElementManager.VerifyUniquenessAndSetBodyContentId(bodyContentId);
                bodyEncrypted = bodyContentId != null && TryDeleteReferenceListEntry(bodyContentId);
                if (bodyEncrypted)
                {
                    DecryptBody(bodyReader, this.pendingDecryptionToken);
                }
                if (!ReferenceEquals(bodyReader, reader))
                {
                    bodyReader.Close();
                }
                if (!encryptBeforeSign && signedInfo != null && signedInfo.HasUnverifiedReference(bodyId))
                {
                    bodyReader = this.SecurityVerifiedMessage.CreateFullBodyReader();
                    bodySigned = EnsureDigestValidityIfIdMatches(signedInfo, bodyId, bodyReader, false, null, null, false);
                    bodyReader.Close();
                }
                */
            }
            else
            {
                bodyEncrypted = false;
            }

            if (bodySigned && bodyEncrypted)
            {
                this.VerifySignatureEncryption();
            }

            reader.Close();

            if (this._pendingSignature != null)
            {
                //this._pendingSignature.CompleteSignatureVerification();
                this._pendingSignature = null;
            }
            //this.pendingDecryptionToken = null;
            atLeastOneHeaderOrBodyEncrypted |= bodyEncrypted;

            if (!bodySigned && signatureParts.IsBodyIncluded)
            {
                this.SecurityVerifiedMessage.OnUnsignedPart(XD.MessageDictionary.Body.Value, this.Version.Envelope.Namespace);
            }

            if (!bodyEncrypted && encryptionParts.IsBodyIncluded)
            {
                this.SecurityVerifiedMessage.OnUnencryptedPart(XD.MessageDictionary.Body.Value, this.Version.Envelope.Namespace);
            }

            this.SecurityVerifiedMessage.OnMessageProtectionPassComplete(atLeastOneHeaderOrBodyEncrypted);
        }

        protected override ReferenceList ReadReferenceListCore(XmlDictionaryReader reader)
        {
            throw new PlatformNotSupportedException();
        }

        protected override void ProcessReferenceListCore(ReferenceList referenceList, WrappedKeySecurityToken wrappedKeyToken)
        {
            throw new PlatformNotSupportedException();
        }

        protected override void ReadSecurityTokenReference(XmlDictionaryReader reader)
        {
            throw new PlatformNotSupportedException();
        }

        protected override SignedXml ReadSignatureCore(XmlDictionaryReader signatureReader)
        {
            XmlDocument doc = new XmlDocument();
            using (XmlWriter writer = doc.CreateNavigator().AppendChild())
            {
                writer.WriteStartDocument();
                writer.WriteStartElement(SIGNED_XML_HEADER);
                MessageHeaders headers = Message.Headers;
                for (int i = 0; i < headers.Count; i++)
                {
                    headers.WriteHeader(i, writer);
                }

                writer.WriteEndElement();
                writer.WriteEndDocument();
            }
            SignedXMLInternal signedXml = new SignedXMLInternal(doc);
            XmlNodeList nodeList = doc.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);
            signedXml.LoadXml((XmlElement)nodeList[0]);
            if (signedXml.SignedInfo.CanonicalizationMethodObject is XmlDsigExcC14NTransform xmlDsigExcC14NTransform)
            {
                string[] inclusivePrefixes = XmlHelper.TokenizeInclusiveNamespacesPrefixList(xmlDsigExcC14NTransform.InclusiveNamespacesPrefixList);
                if (inclusivePrefixes != null)
                {
                    for (int i = 0; i < inclusivePrefixes.Length; i++)
                    {
                        string ns = signatureReader.LookupNamespace(inclusivePrefixes[i]);
                        if (ns != null)
                        {
                            XmlAttribute nsAttribute = doc.CreateAttribute("xmlns", inclusivePrefixes[i], "http://www.w3.org/2000/xmlns/");
                            nsAttribute.Value = ns;
                            doc.DocumentElement.SetAttributeNode(nsAttribute);
                        }
                    }
                }
            }
            using (XmlReader tempReader = signatureReader.ReadSubtree())
            {
                tempReader.Read();//move the reader to next
            }
            return signedXml;
        }

        protected override async ValueTask<SecurityToken> VerifySignatureAsync(SignedXml signedXml, bool isPrimarySignature, SecurityHeaderTokenResolver resolver, object signatureTarget, string id)
        {
            SecurityKeyIdentifier securityKeyIdentifier = null;
            string keyInfoString = signedXml.Signature.KeyInfo.GetXml().OuterXml;
            using (var strReader = new StringReader(keyInfoString))
            {
                XmlReader xmlReader = XmlReader.Create(strReader);
                securityKeyIdentifier = StandardsManager.SecurityTokenSerializer.ReadKeyIdentifier(xmlReader);
            }
            if (securityKeyIdentifier == null)
            {
                throw new Exception("SecurityKeyIdentifier is missing");
            }

            SecurityToken token = await ResolveSignatureTokenAsync(securityKeyIdentifier, resolver, isPrimarySignature);
            if (isPrimarySignature)
            {
                RecordSignatureToken(token);
            }
            ReadOnlyCollection<SecurityKey> keys = token.SecurityKeys;
            SecurityKey securityKey = (keys != null && keys.Count > 0) ? keys[0] : null;
            if (securityKey == null)
            {
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new MessageSecurityException(
                    SR.Format(SR.UnableToCreateICryptoFromTokenForSignatureVerification, token)));
            }

            AlgorithmSuite.EnsureAcceptableSignatureKeySize(securityKey, token);
            AlgorithmSuite.EnsureAcceptableSignatureAlgorithm(securityKey, signedXml.Signature.SignedInfo.SignatureMethod);

            // signedXml.SigningKey = securityKey;

            // signedXml.StartSignatureVerification(securityKey);
            // StandardSignedInfo signedInfo = (StandardSignedInfo)signedXml.Signature.SignedInfo;

            // ValidateDigestsOfTargetsInSecurityHeader(signedInfo, this.Timestamp, isPrimarySignature, signatureTarget, id);

            if (!isPrimarySignature)
            {
                //TODO securityKey is AsymmetricSecurityKey
                //if ((!this.RequireMessageProtection) && (securityKey is AsymmetricSecurityKey) && (this.Version.Addressing != AddressingVersion.None))
                //{
                //    // For Transport Security using Asymmetric Keys verify that 
                //    // the 'To' header is signed.
                //    int headerIndex = this.Message.Headers.FindHeader(XD.AddressingDictionary.To.Value, this.Message.Version.Addressing.Namespace);
                //    if (headerIndex == -1)
                //        throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new MessageSecurityException(SR.GetString(SR.TransportSecuredMessageMissingToHeader)));
                //    XmlDictionaryReader toHeaderReader = this.Message.Headers.GetReaderAtHeader(headerIndex);
                //    id = toHeaderReader.GetAttribute(XD.UtilityDictionary.IdAttribute, XD.UtilityDictionary.Namespace);

                //    // DevDiv:938534 - We added a flag that allow unsigned headers. If this is set, we do not throw an Exception but move on to CompleteSignatureVerification()
                //    if (LocalAppContextSwitches.AllowUnsignedToHeader)
                //    {
                //        // The lack of an id indicates that the sender did not wish to sign the header. We can safely assume that null indicates this header is not signed.
                //        // If id is not null, then we need to validate the Digest and ensure signature is valid. The exception is thrown deeper in the System.IdentityModel stack.
                //        if (id != null)
                //        {
                //            signedXml.EnsureDigestValidityIfIdMatches(id, toHeaderReader);
                //        }
                //    }
                //    else
                //    {
                //        // default behavior for all platforms
                //        if (id == null)
                //        {
                //            // 
                //            throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new MessageSecurityException(SR.GetString(SR.UnsignedToHeaderInTransportSecuredMessage)));
                //        }
                //        signedXml.EnsureDigestValidity(id, toHeaderReader);
                //    }
                //}
                // signedXml.CompleteSignatureVerification();

                SecurityAlgorithmSuite suite = AlgorithmSuite;
                string canonicalizationAlgorithm = suite.DefaultCanonicalizationAlgorithm;
                suite.GetSignatureAlgorithmAndKey(token, out string signatureAlgorithm, out SecurityKey signatureKey, out XmlDictionaryString signatureAlgorithmDictionaryString);
                GetSigningAlgorithm(signatureKey, signatureAlgorithm, out _signingKey, out AsymmetricAlgorithm asymmetricAlgorithm);
                if (_signingKey != null)
                {
                    if (!signedXml.CheckSignature(_signingKey))
                    {
                        throw new Exception("Signature not valid.");
                    }
                }
                else
                {
                    if (!signedXml.CheckSignature(asymmetricAlgorithm))
                    {
                        throw new Exception("Signature not valid.");
                    }
                }
                return token;
            }
            this._pendingSignature = signedXml;

            //if (TD.SignatureVerificationSuccessIsEnabled())
            //{
            //    TD.SignatureVerificationSuccess(this.EventTraceActivity);
            //}

            return token;
        }

        private void GetSigningAlgorithm(SecurityKey signatureKey, string algorithmName, out KeyedHashAlgorithm symmetricAlgorithm, out AsymmetricAlgorithm asymmetricAlgorithm)
        {
            symmetricAlgorithm = null;
            asymmetricAlgorithm = null;
            if (signatureKey is SymmetricSecurityKey symmetricKey)
            {
                _signingKey = symmetricKey.GetKeyedHashAlgorithm(algorithmName);
                if (_signingKey == null)
                {
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new InvalidOperationException(
                        SR.Format(SR.UnableToCreateKeyedHashAlgorithm, symmetricKey, algorithmName)));
                }
            }
            else
            {
                if (!(signatureKey is AsymmetricSecurityKey asymmetricKey))
                {
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new InvalidOperationException(
                        SR.Format(SR.UnknownICryptoType, _signingKey)));
                }

                //On server we validate using Public Key.... (check with Matt)
                asymmetricAlgorithm = asymmetricKey.GetAsymmetricAlgorithm(algorithmName, false);
                if (asymmetricAlgorithm == null)
                {
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new InvalidOperationException(
                        SR.Format(SR.UnableToCreateKeyedHashAlgorithm, algorithmName,
                            asymmetricKey)));
                }
            }
        }

        private async ValueTask<SecurityToken> ResolveSignatureTokenAsync(SecurityKeyIdentifier keyIdentifier, SecurityTokenResolver resolver, bool isPrimarySignature)
        {
            TryResolveKeyIdentifier(keyIdentifier, resolver, true, out SecurityToken token);
            if (token == null && !isPrimarySignature)
            {
                // check if there is a rsa key token authenticator
                if (keyIdentifier.Count == 1)
                {
                    if (keyIdentifier.TryFind<RsaKeyIdentifierClause>(out RsaKeyIdentifierClause rsaClause))
                    {
                        RsaSecurityTokenAuthenticator rsaAuthenticator = FindAllowedAuthenticator<RsaSecurityTokenAuthenticator>(false);
                        if (rsaAuthenticator != null)
                        {
                            token = new RsaSecurityToken(rsaClause.Rsa);
                            ReadOnlyCollection<IAuthorizationPolicy> authorizationPolicies = await rsaAuthenticator.ValidateTokenAsync(token);
                            TokenTracker rsaTracker = GetSupportingTokenTracker(rsaAuthenticator, out SupportingTokenAuthenticatorSpecification spec);
                            if (rsaTracker == null)
                            {
                                throw DiagnosticUtility.ExceptionUtility.ThrowHelperWarning(new MessageSecurityException(SR.Format(SR.UnknownTokenAuthenticatorUsedInTokenProcessing, rsaAuthenticator)));
                            }
                            rsaTracker.RecordToken(token);
                            SecurityTokenAuthorizationPoliciesMapping.Add(token, authorizationPolicies);
                        }
                    }
                }
            }
            if (token == null)
            {
                throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new MessageSecurityException(
                        SR.Format(SR.UnableToResolveKeyInfoForVerifyingSignature, keyIdentifier, resolver)));
            }
            return token;
        }

        protected static bool TryResolveKeyIdentifier(
         SecurityKeyIdentifier keyIdentifier, SecurityTokenResolver resolver, bool isFromSignature, out SecurityToken token)
        {
            if (keyIdentifier == null)
            {
                if (isFromSignature)
                {
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new MessageSecurityException(SR.Format(SR.NoKeyInfoInSignatureToFindVerificationToken)));
                }
                else
                {
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new MessageSecurityException(SR.Format(SR.NoKeyInfoInEncryptedItemToFindDecryptingToken)));
                }
            }
            return resolver.TryResolveToken(keyIdentifier, out token);
        }
        protected override bool TryDeleteReferenceListEntry(string id)
        {
            throw new NotImplementedException();
        }
    }
}
