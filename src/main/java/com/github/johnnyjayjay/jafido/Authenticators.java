package com.github.johnnyjayjay.jafido;

public final class Authenticators {

    private Authenticators() {

    }

    public static WebAuthnAuthenticator yubikey5() {
        // TODO: 14/09/2022 return authenticator that behaves like a new yubikey
        return null;
    }

    public static WebAuthnAuthenticator platform() {
        // TODO: 14/09/2022 return authenticator of type platform
        return null;
    }

    public static WebAuthnAuthenticator u2f() {
        // TODO: 14/09/2022 return "U2F" style authenticator (no resident keys, no signature counter)
        return null;
    }

    public static Authenticator broken() {
        // TODO: 14/09/2022 implementation of authenticator that returns bogus data
        return null;
    }


}
