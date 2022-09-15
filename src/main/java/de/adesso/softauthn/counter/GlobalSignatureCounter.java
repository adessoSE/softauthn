package de.adesso.softauthn.counter;

import com.yubico.webauthn.data.ByteArray;

/**
 * A signature counter implementation that counts the total number of performed signatures rather than maintaining
 * a separate count for each known credential.
 */
public class GlobalSignatureCounter implements SignatureCounter {

    private final int increment;
    private int globalCount;

    /**
     * Creates a global signature counter with the initial value 0 and an increment of 1.
     */
    public GlobalSignatureCounter() {
        this(0, 1);
    }

    /**
     * Creates a global signature counter with the given initial value and increment.
     *
     * @param initialValue The initial total amount of signatures.
     * @param increment The amount added to the count when {@link #increment(ByteArray)} is called.
     */
    public GlobalSignatureCounter(int initialValue, int increment) {
        this.increment = increment;
        this.globalCount = initialValue;
    }

    @Override
    public int increment(ByteArray credentialId) {
        globalCount += increment;
        return globalCount;
    }

    @Override
    public int initialize(ByteArray credentialId) {
        return globalCount;
    }
}
