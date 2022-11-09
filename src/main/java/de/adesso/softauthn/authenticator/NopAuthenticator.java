package de.adesso.softauthn.authenticator;

import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import de.adesso.softauthn.Authenticator;
import de.adesso.softauthn.AuthenticatorAssertionData;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;

/**
 * Authenticator implementation that does nothing except throw an exception
 * when asked to create an attestation or an assertion.
 * <p>This results in it being ignored by {@link de.adesso.softauthn.CredentialsContainer} instances.
 */
public class NopAuthenticator implements Authenticator {

    private final AuthenticatorAttachment attachment;

    public NopAuthenticator(AuthenticatorAttachment attachment) {
        this.attachment = attachment;
    }

    /**
     * Implementation that <strong>always</strong> throws an {@code UnsupportedOperationException}.
     * {@inheritDoc}
     */
    @Override
    public CBORObject makeCredential(
            byte[] hash, RelyingPartyIdentity rpEntity, UserIdentity userEntity, boolean requireResidentKey,
            boolean requireUserVerification, List<PublicKeyCredentialParameters> credTypesAndPubKeyAlgs,
            Set<PublicKeyCredentialDescriptor> excludeCredentials, boolean enterpriseAttestationPossible,
            byte[] extensions
    ) throws IllegalArgumentException, UnsupportedOperationException, IllegalStateException {
        throw new UnsupportedOperationException("I don't do anything");
    }

    /**
     * Implementation that <strong>always</strong> throws an {@code UnsupportedOperationException}.
     * {@inheritDoc}
     */
    @Override
    public AuthenticatorAssertionData getAssertion(
            String rpId, byte[] hash, List<PublicKeyCredentialDescriptor> allowedCredentialDescriptorList,
            boolean requireUserVerification, byte[] extensions
    ) throws IllegalArgumentException, NoSuchElementException {
        throw new UnsupportedOperationException("I don't do anything");
    }

    @Override
    public AuthenticatorAttachment getAttachment() {
        return attachment;
    }

    @Override
    public boolean supportsClientSideDiscoverablePublicKeyCredentialSources() {
        return true;
    }

    @Override
    public boolean supportsUserVerification() {
        return true;
    }
}
