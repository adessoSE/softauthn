package com.github.johnnyjayjay.jafido;

import COSE.AlgorithmID;
import com.github.johnnyjayjay.jafido.counter.PerCredentialSignatureCounter;
import com.github.johnnyjayjay.jafido.counter.SignatureCounter;
import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;

import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Set;
import java.util.function.Function;

public class WebAuthnAuthenticatorBuilder {
    private byte[] aaguid = new byte[16];
    private AuthenticatorAttachment attachment = AuthenticatorAttachment.CROSS_PLATFORM;
    private Collection<COSEAlgorithmIdentifier> supportedAlgorithms = EnumSet.of(COSEAlgorithmIdentifier.ES256, COSEAlgorithmIdentifier.EdDSA);
    private boolean supportsClientSideDiscoverablePublicKeyCredentialSources = true;
    private boolean supportsUserVerification = true;
    private SignatureCounter signatureCounter = new PerCredentialSignatureCounter(1);
    private Function<? super Set<PublicKeyCredentialSource>, PublicKeyCredentialSource> credentialSelection
            = creds -> creds.iterator().next();

    public WebAuthnAuthenticatorBuilder aaguid(byte[] aaguid) {
        this.aaguid = aaguid;
        return this;
    }

    public WebAuthnAuthenticatorBuilder attachment(AuthenticatorAttachment attachment) {
        this.attachment = attachment;
        return this;
    }

    public WebAuthnAuthenticatorBuilder supportAlgorithms(COSEAlgorithmIdentifier... algorithms) {
        return supportAlgorithms(Arrays.asList(algorithms));
    }

    public WebAuthnAuthenticatorBuilder supportAlgorithms(Collection<COSEAlgorithmIdentifier> supportedAlgorithms) {
        this.supportedAlgorithms = supportedAlgorithms;
        return this;
    }

    public WebAuthnAuthenticatorBuilder supportClientSideDiscoverablePublicKeyCredentialSources(boolean supportsClientSideDiscoverablePublicKeyCredentialSources) {
        this.supportsClientSideDiscoverablePublicKeyCredentialSources = supportsClientSideDiscoverablePublicKeyCredentialSources;
        return this;
    }

    public WebAuthnAuthenticatorBuilder supportUserVerification(boolean supportsUserVerification) {
        this.supportsUserVerification = supportsUserVerification;
        return this;
    }

    public WebAuthnAuthenticatorBuilder signatureCounter(SignatureCounter signatureCounter) {
        this.signatureCounter = signatureCounter;
        return this;
    }

    public WebAuthnAuthenticatorBuilder credentialSelection(Function<? super Set<PublicKeyCredentialSource>, PublicKeyCredentialSource> credentialSelection) {
        this.credentialSelection = credentialSelection;
        return this;
    }

    public WebAuthnAuthenticator build() {
        return new WebAuthnAuthenticator(aaguid, attachment, supportedAlgorithms, supportsClientSideDiscoverablePublicKeyCredentialSources, supportsUserVerification, signatureCounter, credentialSelection);
    }
}