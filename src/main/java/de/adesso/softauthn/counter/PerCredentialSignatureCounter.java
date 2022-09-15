package de.adesso.softauthn.counter;

import com.yubico.webauthn.data.ByteArray;

import java.util.HashMap;
import java.util.Map;

/**
 * An implementation of {@link SignatureCounter} that maintains a separate signature count for each credential ID.
 * <p>This is the <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-sign-counter">recommended signature
 * counting style</a> for real-world implementations.
 */
public class PerCredentialSignatureCounter implements SignatureCounter {

    private final Map<ByteArray, Integer> signatureCounts;
    private final int increment;

    /**
     * Creates a counter that will increment the signature count of a credential by {@code 1}
     * when {@link #increment(ByteArray)} is called.
     */
    public PerCredentialSignatureCounter() {
        this(1);
    }

    /**
     * Creates a counter that will increment the signature count of a credential by the specified amount
     * when {@link #increment(ByteArray)} is called.
     *
     * @param increment the amount that should be added to a signature count when it is incremented.
     */
    public PerCredentialSignatureCounter(int increment) {
        this.increment = increment;
        this.signatureCounts = new HashMap<>();
    }

    @Override
    public int increment(ByteArray credentialId) {
        return signatureCounts.computeIfPresent(credentialId, (id, c) -> c + increment);
    }

    @Override
    public int initialize(ByteArray credentialId) {
        signatureCounts.put(credentialId, 0);
        return 0;
    }
}
