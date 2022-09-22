package de.adesso.softauthn.authenticator;

import de.adesso.softauthn.PublicKeyCredentialSource;
import de.adesso.softauthn.counter.PerCredentialSignatureCounter;
import de.adesso.softauthn.counter.SignatureCounter;
import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;

import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Set;
import java.util.function.Function;

/**
 * Builder class for {@link WebAuthnAuthenticator}.
 */
public class WebAuthnAuthenticatorBuilder {
    private byte[] aaguid = new byte[16];
    private AuthenticatorAttachment attachment = AuthenticatorAttachment.CROSS_PLATFORM;
    private Collection<COSEAlgorithmIdentifier> supportedAlgorithms = EnumSet.of(COSEAlgorithmIdentifier.ES256, COSEAlgorithmIdentifier.EdDSA);
    private boolean supportsClientSideDiscoverablePublicKeyCredentialSources = true;
    private boolean supportsUserVerification = true;
    private SignatureCounter signatureCounter = new PerCredentialSignatureCounter();
    private Function<? super Set<PublicKeyCredentialSource>, PublicKeyCredentialSource> credentialSelection
            = creds -> creds.iterator().next();

    /**
     * The aaguid of the resulting authenticator.
     *
     * @param aaguid a length-16 byte array identifying the authenticator model. Default: 16 0-bytes.
     * @return this.
     */
    public WebAuthnAuthenticatorBuilder aaguid(byte[] aaguid) {
        this.aaguid = aaguid;
        return this;
    }

    /**
     * Set the attachment of this authenticator.
     *
     * @param attachment the attachment. Default: {@link AuthenticatorAttachment#CROSS_PLATFORM}.
     * @return this.
     */
    public WebAuthnAuthenticatorBuilder attachment(AuthenticatorAttachment attachment) {
        this.attachment = attachment;
        return this;
    }

    /**
     * Set the list of supported cryptographic algorithms for this authenticator. Will overwrite previous settings.
     *
     * @param algorithms The list of algorithms. Default: All supported algorithms.
     * @return this.
     */
    public WebAuthnAuthenticatorBuilder supportAlgorithms(COSEAlgorithmIdentifier... algorithms) {
        return supportAlgorithms(Arrays.asList(algorithms));
    }

    /**
     * Set the list of supported cryptographic algorithms for this authenticator. Will overwrite previous settings.
     *
     * @param supportedAlgorithms The new collection of algorithms. Default: All supported algorithms.
     * @return this.
     */
    public WebAuthnAuthenticatorBuilder supportAlgorithms(Collection<COSEAlgorithmIdentifier> supportedAlgorithms) {
        this.supportedAlgorithms = supportedAlgorithms;
        return this;
    }

    /**
     * Set whether this authenticator should support client side discoverable credentials aka resident keys,
     * i.e. whether it can store credentials internally.
     *
     * @param supportsClientSideDiscoverablePublicKeyCredentialSources The setting. Default: true.
     * @return this.
     */
    public WebAuthnAuthenticatorBuilder supportClientSideDiscoverablePublicKeyCredentialSources(boolean supportsClientSideDiscoverablePublicKeyCredentialSources) {
        this.supportsClientSideDiscoverablePublicKeyCredentialSources = supportsClientSideDiscoverablePublicKeyCredentialSources;
        return this;
    }

    /**
     * Set whether this authenticator should support user verification.
     *
     * @param supportsUserVerification The setting. Default: true.
     * @return this.
     */
    public WebAuthnAuthenticatorBuilder supportUserVerification(boolean supportsUserVerification) {
        this.supportsUserVerification = supportsUserVerification;
        return this;
    }

    /**
     * Set the signature counter style that should be used by the authenticator.
     *
     * @param signatureCounter the signature counter object. Default: {@link PerCredentialSignatureCounter new PerCredentialSignatureCounter()}.
     * @return this.
     */
    public WebAuthnAuthenticatorBuilder signatureCounter(SignatureCounter signatureCounter) {
        this.signatureCounter = signatureCounter;
        return this;
    }

    /**
     * Set the function that will be called if multiple credentials have been found that match the requirements set by the relying party.
     * @param credentialSelection A function that takes a set of credential sources and emulates the selection of one by the user.
     *                           Default: always select the first authenticator in the set (i.e., no defined priority)
     * @return this.
     */
    public WebAuthnAuthenticatorBuilder credentialSelection(Function<? super Set<PublicKeyCredentialSource>, PublicKeyCredentialSource> credentialSelection) {
        this.credentialSelection = credentialSelection;
        return this;
    }

    /**
     * Build the {@link WebAuthnAuthenticator} object using the parameters configured in this builder.
     *
     * @return the new authenticator object.
     */
    public WebAuthnAuthenticator build() {
        return new WebAuthnAuthenticator(aaguid, attachment, supportedAlgorithms, supportsClientSideDiscoverablePublicKeyCredentialSources, supportsUserVerification, signatureCounter, credentialSelection);
    }
}