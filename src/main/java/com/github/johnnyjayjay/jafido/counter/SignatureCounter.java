package com.github.johnnyjayjay.jafido.counter;

import com.yubico.webauthn.data.ByteArray;

public interface SignatureCounter {

    int increment(ByteArray credentialId);

    int initialize(ByteArray credentialId);
}
