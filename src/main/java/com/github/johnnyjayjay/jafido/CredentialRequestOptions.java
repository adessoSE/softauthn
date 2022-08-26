package com.github.johnnyjayjay.jafido;

import com.yubico.webauthn.AssertionRequest;

public class CredentialRequestOptions {

    private final AssertionRequest publicKey;

    public CredentialRequestOptions(AssertionRequest publicKey) {
        this.publicKey = publicKey;
    }
}
