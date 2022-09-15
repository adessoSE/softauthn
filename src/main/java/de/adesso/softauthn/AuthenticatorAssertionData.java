package de.adesso.softauthn;

import com.yubico.webauthn.data.ByteArray;

public class AuthenticatorAssertionData {

    private final ByteArray credentialId;
    private final ByteArray authenticatorData;
    private final ByteArray signature;
    private final ByteArray userHandle;

    public AuthenticatorAssertionData(ByteArray credentialId, ByteArray authenticatorData, ByteArray signature, ByteArray userHandle) {
        this.credentialId = credentialId;
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.userHandle = userHandle;
    }

    public ByteArray getCredentialId() {
        return credentialId;
    }

    public ByteArray getAuthenticatorData() {
        return authenticatorData;
    }

    public ByteArray getSignature() {
        return signature;
    }

    public ByteArray getUserHandle() {
        return userHandle;
    }
}
