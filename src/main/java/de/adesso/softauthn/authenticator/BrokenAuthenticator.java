package de.adesso.softauthn.authenticator;

import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import de.adesso.softauthn.Authenticator;
import de.adesso.softauthn.AuthenticatorAssertionData;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Authenticator implementation that behaves like some other kind of {@link Authenticator} but always computes an
 * invalid signature when {@link #getAssertion(String, byte[], List, boolean, byte[]) creating an assertion}.
 */
public class BrokenAuthenticator implements Authenticator {

    private final Authenticator basis;

    /**
     * Create a new broken authenticator. The resulting authenticator will behave
     * like the one passed as a parameter except that it returns invalid assertion signatures.
     *
     * @param basis The authenticator that will be used as the basis/delegate of this one.
     */
    public BrokenAuthenticator(Authenticator basis) {
        this.basis = basis;
    }

    /**
     * @implNote This implementation simply delegates to the authenticator set
     * {@link #BrokenAuthenticator(Authenticator) at creation time}.
     * @inheritDoc
     */
    @Override
    public CBORObject makeCredential(
            byte[] hash, RelyingPartyIdentity rpEntity, UserIdentity userEntity,
            boolean requireResidentKey, boolean requireUserVerification,
            List<PublicKeyCredentialParameters> credTypesAndPubKeyAlgs,
            Set<PublicKeyCredentialDescriptor> excludeCredentials,
            boolean enterpriseAttestationPossible,
            byte[] extensions
    ) throws IllegalArgumentException, UnsupportedOperationException, IllegalStateException {
        return basis.makeCredential(hash, rpEntity, userEntity, requireResidentKey, requireUserVerification,
                credTypesAndPubKeyAlgs, excludeCredentials, enterpriseAttestationPossible, extensions);
    }


    /**
     * Implementation that creates invalid assertions. See <em>Implementation Note</em> for details.
     *
     * @implNote This implementation does the following:
     * <ol>
     *     <li>Delegate to the {@link #BrokenAuthenticator(Authenticator) authenticator set at creation time}</li>
     *     <li>Replace the signature in the returned assertion data with random bytes (same length)</li>
     *     <li>Return the modified assertion data.</li>
     * </ol>
     * @inheritDoc
     */
    @Override
    public AuthenticatorAssertionData getAssertion(
            String rpId, byte[] hash, List<PublicKeyCredentialDescriptor> allowedCredentialDescriptorList,
            boolean requireUserVerification, byte[] extensions
    ) throws IllegalArgumentException, NoSuchElementException {
        AuthenticatorAssertionData data = basis.getAssertion(rpId, hash, allowedCredentialDescriptorList, requireUserVerification, extensions);
        byte[] fakeSignature = new byte[data.getSignature().size()];
        ThreadLocalRandom.current().nextBytes(fakeSignature);
        return new AuthenticatorAssertionData(data.getCredentialId(), data.getAuthenticatorData(),
                new ByteArray(fakeSignature), data.getUserHandle());
    }

    /**
     * @implNote Delegates to the underlying authenticator.
     * @inheritDoc
     */
    @Override
    public AuthenticatorAttachment getAttachment() {
        return basis.getAttachment();
    }

    /**
     * @implNote Delegates to the underlying authenticator.
     * @inheritDoc
     */
    @Override
    public boolean supportsClientSideDiscoverablePublicKeyCredentialSources() {
        return basis.supportsClientSideDiscoverablePublicKeyCredentialSources();
    }

    /**
     * @implNote Delegates to the underlying authenticator.
     * @inheritDoc
     */
    @Override
    public boolean supportsUserVerification() {
        return basis.supportsUserVerification();
    }
}
