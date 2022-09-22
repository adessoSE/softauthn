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
 * Authenticator implementation that can be configured to respond to certain requests,
 * but always return an invalid signature.
 */
public class BrokenAuthenticator implements Authenticator {
    @Override
    public CBORObject makeCredential(byte[] hash, RelyingPartyIdentity rpEntity, UserIdentity userEntity, boolean requireResidentKey, boolean requireUserVerification, List<PublicKeyCredentialParameters> credTypesAndPubKeyAlgs, Set<PublicKeyCredentialDescriptor> excludeCredentials, boolean enterpriseAttestationPossible, byte[] extensions) throws IllegalArgumentException, UnsupportedOperationException, IllegalStateException {
        return null;
    }

    @Override
    public AuthenticatorAssertionData getAssertion(String rpId, byte[] hash, List<PublicKeyCredentialDescriptor> allowedCredentialDescriptorList, boolean requireUserVerification, byte[] extensions) throws IllegalArgumentException, NoSuchElementException {
        return null;
    }

    @Override
    public AuthenticatorAttachment getAttachment() {
        return null;
    }

    @Override
    public boolean supportsClientSideDiscoverablePublicKeyCredentialSources() {
        return false;
    }

    @Override
    public boolean supportsUserVerification() {
        return false;
    }
}
