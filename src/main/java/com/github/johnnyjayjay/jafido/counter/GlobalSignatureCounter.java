package com.github.johnnyjayjay.jafido.counter;

import com.yubico.webauthn.data.ByteArray;

public class GlobalSignatureCounter implements SignatureCounter {

    private final int increment;
    private int globalCount;

    public GlobalSignatureCounter() {
        this(0, 1);
    }

    public GlobalSignatureCounter(int initialValue, int increment) {
        this.increment = increment;
        this.globalCount = initialValue;
    }

    @Override
    public int increment(ByteArray credentialId) {
        return ++globalCount;
    }

    @Override
    public int initialize(ByteArray credentialId) {
        return globalCount;
    }
}
