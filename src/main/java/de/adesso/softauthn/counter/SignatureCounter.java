package de.adesso.softauthn.counter;

import com.yubico.webauthn.data.ByteArray;

/**
 * An interface that allows {@link de.adesso.softauthn.Authenticator authenticators} to keep track of the number
 * of signatures they have performed.
 * <p>This is done via a decoupled interface to enable authenticator implementations to support multiple styles
 * of signature counting without implementing the logic for all of them at the same time.
 *
 * @see GlobalSignatureCounter
 * @see NoSignatureCounter
 * @see PerCredentialSignatureCounter
 */
public interface SignatureCounter {

    /**
     * Increment the signature count associated with the given credential ID.
     * <p><strong>Note:</strong> This does not imply that there must be a one-to-one mapping between credential IDs
     * and signature counts.
     * <p>{@link #initialize(ByteArray)} must have been called for the given credential ID
     * before invoking this method for the first time.
     *
     * @param credentialId The credential ID that was just used to sign something.
     * @return the new signature count.
     */
    int increment(ByteArray credentialId);

    /**
     * Initialize the signature count for a given credential ID.
     * <p>What <em>Initialization</em> entails exactly is implementation-defined.
     *
     * @param credentialId The credential ID.
     * @return the initial signature count for the credential ID.
     */
    int initialize(ByteArray credentialId);
}
