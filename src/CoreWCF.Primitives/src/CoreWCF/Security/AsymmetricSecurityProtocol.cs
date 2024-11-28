// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using CoreWcf.Security;
using CoreWCF.Channels;
using CoreWCF.Description;
using CoreWCF.IdentityModel.Policy;
using CoreWCF.IdentityModel.Selectors;
using CoreWCF.IdentityModel.Tokens;
using CoreWCF.Runtime;
using CoreWCF.Security.Tokens;

namespace CoreWCF.Security
{
    internal sealed class AsymmetricSecurityProtocol : MessageSecurityProtocol
    {
        SecurityTokenAuthenticator initiatorAsymmetricTokenAuthenticator;
        SecurityTokenProvider initiatorAsymmetricTokenProvider;
        SecurityTokenProvider initiatorCryptoTokenProvider;

        public AsymmetricSecurityProtocol(AsymmetricSecurityProtocolFactory factory,
           EndpointAddress target, Uri via)
            : base(factory, target, via)
        {
        }

        protected override bool DoAutomaticEncryptionMatch
        {
            get { return false; }
        }

        AsymmetricSecurityProtocolFactory Factory
        {
            get { return (AsymmetricSecurityProtocolFactory)base.MessageSecurityProtocolFactory; }
        }

        public SecurityTokenProvider InitiatorCryptoTokenProvider
        {
            get
            {
                this.CommunicationObject.ThrowIfNotOpened();
                return this.initiatorCryptoTokenProvider;
            }
        }

        public SecurityTokenAuthenticator InitiatorAsymmetricTokenAuthenticator
        {
            get
            {
                this.CommunicationObject.ThrowIfNotOpened();
                return this.initiatorAsymmetricTokenAuthenticator;
            }
        }

        public SecurityTokenProvider InitiatorAsymmetricTokenProvider
        {
            get
            {
                this.CommunicationObject.ThrowIfNotOpened();
                return this.initiatorAsymmetricTokenProvider;
            }
        }

        public override async Task OnOpenAsync(TimeSpan timeout)
        {
            TimeoutHelper timeoutHelper = new TimeoutHelper(timeout);
            await base.OnOpenAsync(timeoutHelper.RemainingTime());
            if (this.Factory.ActAsInitiator)
            {
                if (this.Factory.ApplyIntegrity)
                {
                    InitiatorServiceModelSecurityTokenRequirement requirement = CreateInitiatorSecurityTokenRequirement();
                    this.Factory.CryptoTokenParameters.InitializeSecurityTokenRequirement(requirement);
                    requirement.KeyUsage = SecurityKeyUsage.Signature;
                    requirement.Properties[ServiceModelSecurityTokenRequirement.MessageDirectionProperty] = MessageDirection.Output;
                    this.initiatorCryptoTokenProvider = this.Factory.SecurityTokenManager.CreateSecurityTokenProvider(requirement);
                    await SecurityUtils.OpenTokenProviderIfRequiredAsync(this.initiatorCryptoTokenProvider, timeoutHelper.GetCancellationToken());
                }
                if (this.Factory.RequireIntegrity || this.Factory.ApplyConfidentiality)
                {
                    InitiatorServiceModelSecurityTokenRequirement providerRequirement = CreateInitiatorSecurityTokenRequirement();
                    this.Factory.AsymmetricTokenParameters.InitializeSecurityTokenRequirement(providerRequirement);
                    providerRequirement.KeyUsage = SecurityKeyUsage.Exchange;
                    providerRequirement.Properties[ServiceModelSecurityTokenRequirement.MessageDirectionProperty] = (this.Factory.ApplyConfidentiality) ? MessageDirection.Output : MessageDirection.Input;
                    this.initiatorAsymmetricTokenProvider = this.Factory.SecurityTokenManager.CreateSecurityTokenProvider(providerRequirement);
                    await SecurityUtils.OpenTokenProviderIfRequiredAsync(this.initiatorAsymmetricTokenProvider, timeoutHelper.GetCancellationToken());

                    InitiatorServiceModelSecurityTokenRequirement authenticatorRequirement = CreateInitiatorSecurityTokenRequirement();
                    this.Factory.AsymmetricTokenParameters.InitializeSecurityTokenRequirement(authenticatorRequirement);
                    authenticatorRequirement.IsOutOfBandToken = !this.Factory.AllowSerializedSigningTokenOnReply;
                    authenticatorRequirement.KeyUsage = SecurityKeyUsage.Exchange;
                    authenticatorRequirement.Properties[ServiceModelSecurityTokenRequirement.MessageDirectionProperty] = (this.Factory.ApplyConfidentiality) ? MessageDirection.Output : MessageDirection.Input;
                    // Create authenticator (we dont support out of band resolvers on the client side
                    SecurityTokenResolver outOfBandTokenResolver;
                    this.initiatorAsymmetricTokenAuthenticator = this.Factory.SecurityTokenManager.CreateSecurityTokenAuthenticator(authenticatorRequirement, out outOfBandTokenResolver);
                    await SecurityUtils.OpenTokenAuthenticatorIfRequiredAsync(this.initiatorAsymmetricTokenAuthenticator, timeoutHelper.GetCancellationToken());
                }
            }
        }

        public override void OnAbort()
        {
            if (this.Factory.ActAsInitiator)
            {
                if (this.initiatorCryptoTokenProvider != null)
                {
                    SecurityUtils.AbortTokenProviderIfRequired(this.initiatorCryptoTokenProvider);
                }
                if (this.initiatorAsymmetricTokenProvider != null)
                {
                    SecurityUtils.AbortTokenProviderIfRequired(this.initiatorAsymmetricTokenProvider);
                }
                if (this.initiatorAsymmetricTokenAuthenticator != null)
                {
                    SecurityUtils.AbortTokenAuthenticatorIfRequired(this.initiatorAsymmetricTokenAuthenticator);
                }
            }
            base.OnAbort();
        }


        public override async Task OnCloseAsync(TimeSpan timeout)
        {
            TimeoutHelper timeoutHelper = new TimeoutHelper(timeout);
            if (this.Factory.ActAsInitiator)
            {
                if (this.initiatorCryptoTokenProvider != null)
                {
                    await SecurityUtils.CloseTokenProviderIfRequiredAsync(this.initiatorCryptoTokenProvider, timeoutHelper.GetCancellationToken());
                }
                if (this.initiatorAsymmetricTokenProvider != null)
                {
                    await SecurityUtils.CloseTokenProviderIfRequiredAsync(this.initiatorAsymmetricTokenProvider, timeoutHelper.GetCancellationToken());
                }
                if (this.initiatorAsymmetricTokenAuthenticator != null)
                {
                    await SecurityUtils.CloseTokenAuthenticatorIfRequiredAsync(this.initiatorAsymmetricTokenAuthenticator, timeoutHelper.GetCancellationToken());
                }
            }
            await base.OnCloseAsync(timeoutHelper.RemainingTime());
        }

        /*
        protected override IAsyncResult BeginSecureOutgoingMessageCore(Message message, TimeSpan timeout, SecurityProtocolCorrelationState correlationState, AsyncCallback callback, object state)
        {
            SecurityToken encryptingToken;
            SecurityToken signingToken;
            SecurityProtocolCorrelationState newCorrelationState;
            IList<SupportingTokenSpecification> supportingTokens;
            TimeoutHelper timeoutHelper = new TimeoutHelper(timeout);
            if (TryGetTokenSynchronouslyForOutgoingSecurity(message, correlationState, false, timeoutHelper.RemainingTime(), out encryptingToken, out signingToken, out supportingTokens, out newCorrelationState))
            {
                SetUpDelayedSecurityExecution(ref message, encryptingToken, signingToken, supportingTokens, GetSignatureConfirmationCorrelationState(correlationState, newCorrelationState));
                return new CompletedAsyncResult<Message, SecurityProtocolCorrelationState>(message, newCorrelationState, callback, state);
            }
            else
            {
                if (this.Factory.ActAsInitiator == false)
                {
                    Fx.Assert("Unexpected code path for server security application");
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new InvalidOperationException(SR.GetString(SR.SendingOutgoingmessageOnRecipient)));
                }
                AsymmetricSecurityProtocolFactory factory = this.Factory;
                SecurityTokenProvider encProvider = factory.ApplyConfidentiality ? this.initiatorAsymmetricTokenProvider : null;
                SecurityTokenProvider sigProvider = factory.ApplyIntegrity ? this.initiatorCryptoTokenProvider : null;
                return new SecureOutgoingMessageAsyncResult(message, this,
                   encProvider, sigProvider, factory.ApplyConfidentiality, this.initiatorAsymmetricTokenAuthenticator, correlationState, timeoutHelper.RemainingTime(), callback, state);
            }
        }

        protected override void EndSecureOutgoingMessageCore(IAsyncResult result, out Message message, out SecurityProtocolCorrelationState newCorrelationState)
        {
            if (result is CompletedAsyncResult<Message, SecurityProtocolCorrelationState>)
            {
                message = CompletedAsyncResult<Message, SecurityProtocolCorrelationState>.End(result, out newCorrelationState);
            }
            else
            {
                message = SecureOutgoingMessageAsyncResult.End(result, out newCorrelationState);
            }
        }
        */

        protected override (SecurityProtocolCorrelationState, Message) SecureOutgoingMessageCore(Message message, CancellationToken token, SecurityProtocolCorrelationState correlationState)
        {
            SecurityToken encryptingToken;
            SecurityToken signingToken;
            SecurityProtocolCorrelationState newCorrelationState;
            IList<SupportingTokenSpecification> supportingTokens;
            TryGetTokenSynchronouslyForOutgoingSecurity(message, correlationState, true, token, out encryptingToken, out signingToken, out supportingTokens, out newCorrelationState);
            SetUpDelayedSecurityExecution(ref message, encryptingToken, signingToken, supportingTokens, GetSignatureConfirmationCorrelationState(correlationState, newCorrelationState));
            return (newCorrelationState, message);
        }

        void SetUpDelayedSecurityExecution(ref Message message, SecurityToken encryptingToken, SecurityToken signingToken,
            IList<SupportingTokenSpecification> supportingTokens, SecurityProtocolCorrelationState correlationState)
        {
            AsymmetricSecurityProtocolFactory factory = this.Factory;
            string actor = string.Empty;
            SendSecurityHeader securityHeader = ConfigureSendSecurityHeader(message, actor, supportingTokens, correlationState);
            SecurityTokenParameters signingTokenParameters = (this.Factory.ActAsInitiator) ? this.Factory.CryptoTokenParameters : this.Factory.AsymmetricTokenParameters;
            SecurityTokenParameters encryptionTokenParameters = (this.Factory.ActAsInitiator) ? this.Factory.AsymmetricTokenParameters : this.Factory.CryptoTokenParameters;
            if (this.Factory.ApplyIntegrity || securityHeader.HasSignedTokens)
            {
                if (!this.Factory.ApplyIntegrity)
                {
                    securityHeader.SignatureParts = MessagePartSpecification.NoParts;
                }
                securityHeader.SetSigningToken(signingToken, signingTokenParameters);
            }
            if (Factory.ApplyConfidentiality || securityHeader.HasEncryptedTokens)
            {
                if (!this.Factory.ApplyConfidentiality)
                {
                    securityHeader.EncryptionParts = MessagePartSpecification.NoParts;
                }
                securityHeader.SetEncryptionToken(encryptingToken, encryptionTokenParameters);
            }
            message = securityHeader.SetupExecution();
        }

        void AttachRecipientSecurityProperty(Message message, SecurityToken initiatorToken, SecurityToken recipientToken, IList<SecurityToken> basicTokens, IList<SecurityToken> endorsingTokens,
           IList<SecurityToken> signedEndorsingTokens, IList<SecurityToken> signedTokens, Dictionary<SecurityToken, ReadOnlyCollection<IAuthorizationPolicy>> tokenPoliciesMapping)
        {
            SecurityMessageProperty security = SecurityMessageProperty.GetOrCreate(message);
            security.InitiatorToken = (initiatorToken != null) ? new SecurityTokenSpecification(initiatorToken, tokenPoliciesMapping[initiatorToken]) : null;
            security.RecipientToken = (recipientToken != null) ? new SecurityTokenSpecification(recipientToken, EmptyReadOnlyCollection<IAuthorizationPolicy>.Instance) : null;
            AddSupportingTokenSpecification(security, basicTokens, endorsingTokens, signedEndorsingTokens, signedTokens, tokenPoliciesMapping);
            security.ServiceSecurityContext = new ServiceSecurityContext(security.GetInitiatorTokenAuthorizationPolicies());
        }

        void DoIdentityCheckAndAttachInitiatorSecurityProperty(Message message, SecurityToken initiatorToken, SecurityToken recipientToken, ReadOnlyCollection<IAuthorizationPolicy> recipientTokenPolicies)
        {
            AuthorizationContext recipientAuthorizationContext = base.EnsureIncomingIdentity(message, recipientToken, recipientTokenPolicies);
            SecurityMessageProperty security = SecurityMessageProperty.GetOrCreate(message);
            security.InitiatorToken = (initiatorToken != null) ? new SecurityTokenSpecification(initiatorToken, EmptyReadOnlyCollection<IAuthorizationPolicy>.Instance) : null;
            security.RecipientToken = new SecurityTokenSpecification(recipientToken, recipientTokenPolicies);
            security.ServiceSecurityContext = new ServiceSecurityContext(recipientAuthorizationContext, recipientTokenPolicies ?? EmptyReadOnlyCollection<IAuthorizationPolicy>.Instance);
        }

        protected override async Task<(Message, SecurityProtocolCorrelationState)> VerifyIncomingMessageCoreAsync(Message message, string actor, TimeSpan timeout, SecurityProtocolCorrelationState[] correlationStates)
        {
            AsymmetricSecurityProtocolFactory factory = this.Factory;
            IList<SupportingTokenAuthenticatorSpecification> supportingAuthenticators;
            TimeoutHelper timeoutHelper = new TimeoutHelper(timeout);
            ReceiveSecurityHeader securityHeader = ConfigureReceiveSecurityHeader(message, string.Empty, correlationStates, out supportingAuthenticators);
            SecurityToken requiredReplySigningToken = null;
            if (factory.ActAsInitiator)
            {
                SecurityToken encryptionToken = null;
                SecurityToken receiverToken = null;
                if (factory.RequireIntegrity)
                {
                    receiverToken = await GetTokenAsync(this.initiatorAsymmetricTokenProvider, null, timeoutHelper.GetCancellationToken());
                    requiredReplySigningToken = receiverToken;
                }
                if (factory.RequireConfidentiality)
                {
                    encryptionToken = GetCorrelationToken(correlationStates);
                    if (!SecurityUtils.HasSymmetricSecurityKey(encryptionToken))
                    {
                        securityHeader.WrappedKeySecurityTokenAuthenticator = this.Factory.WrappedKeySecurityTokenAuthenticator;
                    }
                }
                SecurityTokenAuthenticator primaryTokenAuthenticator;
                if (factory.AllowSerializedSigningTokenOnReply)
                {
                    primaryTokenAuthenticator = this.initiatorAsymmetricTokenAuthenticator;
                    requiredReplySigningToken = null;
                }
                else
                {
                    primaryTokenAuthenticator = null;
                }

                securityHeader.ConfigureAsymmetricBindingClientReceiveHeader(receiverToken,
                    factory.AsymmetricTokenParameters, encryptionToken, factory.CryptoTokenParameters,
                    primaryTokenAuthenticator);
            }
            else
            {
                SecurityToken wrappingToken;
                if (this.Factory.RecipientAsymmetricTokenProvider != null && this.Factory.RequireConfidentiality)
                {
                    wrappingToken = await GetTokenAsync(factory.RecipientAsymmetricTokenProvider, null, timeoutHelper.GetCancellationToken());
                }
                else
                {
                    wrappingToken = null;
                }
                securityHeader.ConfigureAsymmetricBindingServerReceiveHeader(this.Factory.RecipientCryptoTokenAuthenticator,
                    this.Factory.CryptoTokenParameters, wrappingToken, this.Factory.AsymmetricTokenParameters, supportingAuthenticators);
                securityHeader.WrappedKeySecurityTokenAuthenticator = this.Factory.WrappedKeySecurityTokenAuthenticator;

                securityHeader.ConfigureOutOfBandTokenResolver(MergeOutOfBandResolvers(supportingAuthenticators, this.Factory.RecipientOutOfBandTokenResolverList));
            }

            message = await ProcessSecurityHeaderAsync(securityHeader, message, requiredReplySigningToken, timeoutHelper.RemainingTime(), correlationStates);
            SecurityToken signingToken = securityHeader.SignatureToken;
            SecurityToken encryptingToken = securityHeader.EncryptionToken;
            if (factory.RequireIntegrity)
            {
                if (factory.ActAsInitiator)
                {
                    ReadOnlyCollection<IAuthorizationPolicy> signingTokenPolicies = this.initiatorAsymmetricTokenAuthenticator.ValidateToken(signingToken);
                    EnsureNonWrappedToken(signingToken, message);
                    DoIdentityCheckAndAttachInitiatorSecurityProperty(message, encryptingToken, signingToken, signingTokenPolicies);
                }
                else
                {
                    EnsureNonWrappedToken(signingToken, message);
                    AttachRecipientSecurityProperty(message, signingToken, encryptingToken, securityHeader.BasicSupportingTokens, securityHeader.EndorsingSupportingTokens, securityHeader.SignedEndorsingSupportingTokens,
                        securityHeader.SignedSupportingTokens, securityHeader.SecurityTokenAuthorizationPoliciesMapping);
                }
            }

            var state = GetCorrelationState(signingToken, securityHeader);

            return (message, state);
        }

        bool TryGetTokenSynchronouslyForOutgoingSecurity(Message message, SecurityProtocolCorrelationState correlationState, bool isBlockingCall, CancellationToken cancellationToken,
            out SecurityToken encryptingToken, out SecurityToken signingToken, out IList<SupportingTokenSpecification> supportingTokens, out SecurityProtocolCorrelationState newCorrelationState)
        {
            AsymmetricSecurityProtocolFactory factory = this.Factory;
            encryptingToken = null;
            signingToken = null;
            newCorrelationState = null;
            supportingTokens = null;
            if (factory.ActAsInitiator)
            {
                if (!isBlockingCall)
                {
                    return false;
                }
                else
                {
                    supportingTokens = TryGetSupportingTokensAsync(this.Factory, this.Target, this.Via, message, cancellationToken).GetAwaiter().GetResult();
                }
                if (factory.ApplyConfidentiality)
                {
                    encryptingToken = GetTokenAndEnsureOutgoingIdentityAsync(this.initiatorAsymmetricTokenProvider, true, cancellationToken, this.initiatorAsymmetricTokenAuthenticator)
                        .GetAwaiter().GetResult();
                }
                if (factory.ApplyIntegrity)
                {
                    signingToken = GetTokenAsync(this.initiatorCryptoTokenProvider, this.Target, cancellationToken)
                        .GetAwaiter().GetResult();
                    newCorrelationState = GetCorrelationState(signingToken);
                }
            }
            else
            {
                if (factory.ApplyConfidentiality)
                {
                    encryptingToken = GetCorrelationToken(correlationState);
                }
                if (factory.ApplyIntegrity)
                {
                    signingToken = GetTokenAsync(factory.RecipientAsymmetricTokenProvider, null, cancellationToken)
                        .GetAwaiter().GetResult();
                }
            }
            return true;
        }

        /*
        sealed class SecureOutgoingMessageAsyncResult : GetTwoTokensAndSetUpSecurityAsyncResult
        {
            public SecureOutgoingMessageAsyncResult(Message m, AsymmetricSecurityProtocol binding,
                SecurityTokenProvider primaryProvider, SecurityTokenProvider secondaryProvider, bool doIdentityChecks, SecurityTokenAuthenticator identityCheckAuthenticator,
                SecurityProtocolCorrelationState correlationState, TimeSpan timeout, AsyncCallback callback, object state)
                : base(m, binding, primaryProvider, secondaryProvider, doIdentityChecks, identityCheckAuthenticator, correlationState, timeout, callback, state)
            {
                Start();
            }

            protected override void OnBothGetTokenCallsDone(ref Message message, SecurityToken primaryToken, SecurityToken secondaryToken, TimeSpan timeout)
            {
                AsymmetricSecurityProtocol binding = (AsymmetricSecurityProtocol)this.Binding;
                if (secondaryToken != null)
                    this.SetCorrelationToken(secondaryToken);
                binding.SetUpDelayedSecurityExecution(ref message, primaryToken, secondaryToken, this.SupportingTokens, binding.GetSignatureConfirmationCorrelationState(OldCorrelationState, NewCorrelationState));
            }
        }
        */
    }
}
