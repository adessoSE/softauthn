package com.github.johnnyjayjay.jafido;

import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Authenticator {

    private final SecureRandom random;
    private final Map<ByteArray, PublicKeyCredentialSource> storedSources;
    private final AuthenticatorAttachment attachment;
    private final boolean residentKey;

    private final boolean canPerformUserVerification;


    public Authenticator(AuthenticatorAttachment attachment, boolean residentKey, boolean canPerformUserVerification) {
        this.attachment = attachment;
        this.residentKey = residentKey;
        this.canPerformUserVerification = canPerformUserVerification;
        this.storedSources = new HashMap<>();
        random = new SecureRandom();
    }

    public AttestationObject makeCredential(
            byte[] hash, RelyingPartyIdentity rpEntity, UserIdentity userEntity, boolean requireResidentKey,
            boolean requireUserVerification, List<PublicKeyCredentialParameters> credTypesAndPubKeyAlgs,
            Set<PublicKeyCredentialDescriptor> excludeCredentials, boolean enterpriseAttestationPossible, Object extensions
    ) throws NoSuchAlgorithmException {
        for (PublicKeyCredentialDescriptor descriptor : excludeCredentials) {
            PublicKeyCredentialSource source = lookup(descriptor.getId());
            if (source == null) {
                continue;
            }

            if (source.getRpId().equals(rpEntity.getId()) && source.getType() == descriptor.getType()) {
                throw new IllegalStateException("Can't create new credential: this credential is excluded");
            }

        }

        if (requireResidentKey && !residentKey) {
            throw new UnsupportedOperationException(
                "Authenticator cannot store client-side discoverable public key credential sources");
        }

        if (requireUserVerification && !canPerformUserVerification) {
            throw new UnsupportedOperationException(
                "Authenticator cannot perform user verification");
        }

        // TODO: 26/08/2022 don't use fixed algorithm
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EdDSA");
        KeyPair keyPair = generator.generateKeyPair();
        ByteArray userHandle = userEntity.getId();
        PublicKeyCredentialSource credentialSource = new PublicKeyCredentialSource(
            PublicKeyCredentialType.PUBLIC_KEY,
            keyPair.getPrivate(),
            rpEntity.getId(),
            userHandle
        );

        if (requireResidentKey) {
            byte[] credentialId = new byte[64];
            random.nextBytes(credentialId);

        } else {

        }

    }

    private PublicKeyCredentialSource lookup(ByteArray credentialId) {

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
