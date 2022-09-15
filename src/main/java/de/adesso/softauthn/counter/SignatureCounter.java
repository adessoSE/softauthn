package de.adesso.softauthn.counter;

import com.yubico.webauthn.data.ByteArray;

public interface SignatureCounter {

    int increment(ByteArray credentialId);

    int initialize(ByteArray credentialId);
}
