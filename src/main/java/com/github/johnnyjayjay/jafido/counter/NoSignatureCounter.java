package com.github.johnnyjayjay.jafido.counter;

import com.yubico.webauthn.data.ByteArray;

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
