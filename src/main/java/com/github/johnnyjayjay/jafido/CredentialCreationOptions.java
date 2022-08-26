package com.github.johnnyjayjay.jafido;

import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;

public class CredentialCreationOptions {

    private final PublicKeyCredentialCreationOptions publicKey;

    public CredentialCreationOptions(PublicKeyCredentialCreationOptions publicKey) {
        this.publicKey = publicKey;
    }
}
