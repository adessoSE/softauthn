package de.adesso.softauthn.counter;

import com.yubico.webauthn.data.ByteArray;

import java.util.HashMap;
import java.util.Map;

public class PerCredentialSignatureCounter implements SignatureCounter {

    private final Map<ByteArray, Integer> signatureCounts;
    private final int increment;

    public PerCredentialSignatureCounter() {
        this(1);
    }

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
