package de.adesso.softauthn.counter;

import com.yubico.webauthn.data.ByteArray;

/**
 * A signature counter implementation that always returns {@code 0} and effectively does nothing.
 * This is the behaviour that should be employed by authenticators that don't support signature counting.
 */
public class NoSignatureCounter implements SignatureCounter {

    @Override
    public int increment(ByteArray credentialId) {
        return 0;
    }

    @Override
    public int initialize(ByteArray credentialId) {
        return 0;
    }
}
