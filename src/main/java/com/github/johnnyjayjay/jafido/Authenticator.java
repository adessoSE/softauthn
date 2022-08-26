package com.github.johnnyjayjay.jafido;

import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;

import java.util.List;
import java.util.Set;

public class Authenticator {

    private final AuthenticatorAttachment attachment;
    private final boolean residentKey;

    private final boolean canPerformUserVerification;


    public Authenticator(AuthenticatorAttachment attachment, boolean residentKey, boolean canPerformUserVerification) {
        this.attachment = attachment;
        this.residentKey = residentKey;
        this.canPerformUserVerification = canPerformUserVerification;
    }

    public void makeCredential(
            byte[] hash, RelyingPartyIdentity rpEntity, UserIdentity userEntity, boolean requireResidentKey,
            boolean requireUserPresence, boolean requireUserVerification, List<PublicKeyCredentialParameters> credTypesAndPubKeyAlgs,
            Set<PublicKeyCredentialDescriptor> excludeCredentials, boolean enterpriseAttestationPossible, Object extensions
    ) {

    }

    public AuthenticatorAttachment getAttachment() {
        return attachment;
    }

    public boolean isResidentKey() {
        return residentKey;
    }

    public boolean canPerformUserVerification() {
        return canPerformUserVerification;
    }
}
