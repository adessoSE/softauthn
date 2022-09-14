package com.github.johnnyjayjay.jafido;

import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;

import java.util.List;
import java.util.Set;
import java.util.function.Function;

public interface Authenticator {

    CBORObject makeCredential(
            byte[] hash, RelyingPartyIdentity rpEntity, UserIdentity userEntity, boolean requireResidentKey,
            boolean requireUserVerification, List<PublicKeyCredentialParameters> credTypesAndPubKeyAlgs,
            Set<PublicKeyCredentialDescriptor> excludeCredentials, boolean enterpriseAttestationPossible, byte[] extensions
    );

    AuthenticatorAssertionData getAssertion(
            String rpId, byte[] hash,
            List<PublicKeyCredentialDescriptor> allowedCredentialDescriptorList,
            boolean requireUserVerification, byte[] extensions
    );

    AuthenticatorAttachment getAttachment();

    boolean supportsClientSideDiscoverablePublicKeyCredentialSources();

    boolean supportsUserVerification();
}
