package de.adesso.softauthn;

import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.HexException;
import de.adesso.softauthn.authenticator.WebAuthnAuthenticator;
import de.adesso.softauthn.authenticator.WebAuthnAuthenticatorBuilder;
import de.adesso.softauthn.counter.NoSignatureCounter;
import de.adesso.softauthn.counter.PerCredentialSignatureCounter;

public final class Authenticators {

    private Authenticators() {
    }

    public static WebAuthnAuthenticatorBuilder yubikey5Nfc() {
        try {
            return WebAuthnAuthenticator.builder()
                    .attachment(AuthenticatorAttachment.CROSS_PLATFORM)
                    .supportClientSideDiscoverablePublicKeyCredentialSources(true)
                    .supportUserVerification(true)
                    .signatureCounter(new PerCredentialSignatureCounter())
                    .aaguid(ByteArray.fromHex("2fc0579f811347eab116bb5a8db9202a").getBytes());
        } catch (HexException e) {
            throw new AssertionError(e);
        }
    }

    public static WebAuthnAuthenticatorBuilder platform() {
        return WebAuthnAuthenticator.builder()
                .attachment(AuthenticatorAttachment.PLATFORM)
                .supportUserVerification(true)
                .supportClientSideDiscoverablePublicKeyCredentialSources(true)
                .signatureCounter(new PerCredentialSignatureCounter());
    }

    public static WebAuthnAuthenticatorBuilder u2f() {
        return WebAuthnAuthenticator.builder()
                .attachment(AuthenticatorAttachment.CROSS_PLATFORM)
                .supportClientSideDiscoverablePublicKeyCredentialSources(false)
                .signatureCounter(new NoSignatureCounter());
    }

    public static Authenticator broken() {
        // TODO: 14/09/2022 implementation of authenticator that returns bogus data
        return null;
    }


}
