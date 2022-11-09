package de.adesso.softauthn;

import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.HexException;
import de.adesso.softauthn.authenticator.WebAuthnAuthenticator;
import de.adesso.softauthn.authenticator.WebAuthnAuthenticatorBuilder;
import de.adesso.softauthn.counter.NoSignatureCounter;
import de.adesso.softauthn.counter.PerCredentialSignatureCounter;

/**
 * Utility class that provides definitions for commonly seen types of authenticators.
 */
public final class Authenticators {

    private Authenticators() {
    }

    /**
     * Creates an authenticator configuration that behaves like a Yubikey 5 NFC
     * (cross-platform attachment, support for resident keys, support for user verification,
     * per-credential signature counter and the model's AAGUID).
     *
     * @return a {@link WebAuthnAuthenticatorBuilder} with the defaults described above that can be configured further.
     */
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

    /**
     * Creates an authenticator configuration that uses platform attachment, supports user verification and
     * resident keys. It also has a per-credential signature counter.
     *
     * @return a {@link WebAuthnAuthenticatorBuilder} with the defaults described above that can be configured further.
     */
    public static WebAuthnAuthenticatorBuilder platform() {
        return WebAuthnAuthenticator.builder()
                .attachment(AuthenticatorAttachment.PLATFORM)
                .supportUserVerification(true)
                .supportClientSideDiscoverablePublicKeyCredentialSources(true)
                .signatureCounter(new PerCredentialSignatureCounter());
    }

    /**
     * Creates an authenticator configuration that imitates a "legacy" U2F authenticator that doesn't support
     * the new WebAuthn features. Its attachment is cross-platform, it does not support resident keys and does not
     * have a signature counting mechanism.
     *
     * @return a {@link WebAuthnAuthenticatorBuilder} with the defaults described above that can be configured further.
     */
    public static WebAuthnAuthenticatorBuilder u2f() {
        return WebAuthnAuthenticator.builder()
                .attachment(AuthenticatorAttachment.CROSS_PLATFORM)
                .supportClientSideDiscoverablePublicKeyCredentialSources(false)
                .signatureCounter(new NoSignatureCounter());
    }


}
