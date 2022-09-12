package com.github.johnnyjayjay.jafido;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.data.exception.Base64UrlException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static com.github.johnnyjayjay.jafido.Checks.check;

// navigator.credentials simulator
public class Credentials {

    private final String origin;
    private final List<Authenticator> authenticators;

    private final ObjectMapper mapper;

    public Credentials(String origin, List<Authenticator> authenticators) {
        this.origin = origin;
        this.authenticators = new ArrayList<>(authenticators);
        this.mapper = new ObjectMapper();
    }

    // following https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-createCredential
    public PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> create(
            Origin origin,
            PublicKeyCredentialCreationOptions options,
            boolean sameOriginWithAncestors
    ) throws JsonProcessingException, NoSuchAlgorithmException {
        // 2.
        check(sameOriginWithAncestors, "NotAllowedError (sameOriginWithAncestors)");
        // 4. skip irrelevant timeout steps
        // 5. skip irrelevant user id check
        // 6.
        check(origin != null, "NotAllowedError (opaque origin)");
        // 7.
        String effectiveDomain = origin.effectiveDomain();
        // TODO: 25/08/2022 validate domain
        // 8. skip rpId check, it's always set by Relying Party
        // 9-10.
        List<PublicKeyCredentialParameters> credTypesAndPubKeyAlgs = options.getPubKeyCredParams().isEmpty()
                ? Arrays.asList(PublicKeyCredentialParameters.builder().alg(COSEAlgorithmIdentifier.ES256).build(),
                PublicKeyCredentialParameters.builder().alg(COSEAlgorithmIdentifier.RS256).build())
                : options.getPubKeyCredParams();
        // TODO: 25/08/2022 handle extensions

        // 13.
        ObjectNode collectedClientData = mapper.createObjectNode()
                .put("type", "webauthn.create")
                .put("challenge", options.getChallenge().getBase64Url())
                .put("origin", origin.serialized())
                .put("crossOrigin", !sameOriginWithAncestors);

        // 14.
        String clientDataJson = mapper.writeValueAsString(collectedClientData);
        // 15.
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] clientDataHash = digest.digest(clientDataJson.getBytes(StandardCharsets.UTF_8));

        for (Authenticator authenticator : authenticators) {
            if (options.getAuthenticatorSelection()
                    .flatMap(AuthenticatorSelectionCriteria::getAuthenticatorAttachment)
                    .map(authenticator.getAttachment()::equals)
                    .orElse(false)) {
                continue;
            }

            if (!authenticator.supportsClientSideDiscoverablePublicKeyCredentialSources() && options.getAuthenticatorSelection().flatMap(AuthenticatorSelectionCriteria::getResidentKey).map(req -> req == ResidentKeyRequirement.REQUIRED).orElse(false)) {
                continue;
            }

            boolean requireResidentKey = options.getAuthenticatorSelection().flatMap(AuthenticatorSelectionCriteria::getResidentKey)
                    .map(req -> req == ResidentKeyRequirement.REQUIRED || (req == ResidentKeyRequirement.PREFERRED && authenticator.supportsClientSideDiscoverablePublicKeyCredentialSources()))
                    .orElse(false);

            boolean userVerification = options.getAuthenticatorSelection().flatMap(AuthenticatorSelectionCriteria::getUserVerification)
                    .map(req -> req == UserVerificationRequirement.REQUIRED || (req == UserVerificationRequirement.PREFERRED && authenticator.supportsUserVerification()))
                    .orElse(false);

            // skip handling this for now
            boolean enterpriseAttestationPossible = false;

            Set<PublicKeyCredentialDescriptor> excludeCredentials = options.getExcludeCredentials()
                    .orElse(Collections.emptySet());

            CBORObject attestationObject = authenticator.makeCredential(
                    clientDataHash, options.getRp(), options.getUser(),
                    requireResidentKey, userVerification, credTypesAndPubKeyAlgs,
                    excludeCredentials, enterpriseAttestationPossible, null
            );
            try {
                return constructCredentialAlg(
                        attestationObject,
                        clientDataJson.getBytes(StandardCharsets.UTF_8),
                        options.getAttestation(),
                        ClientRegistrationExtensionOutputs.builder().build()
                );
            } catch (Base64UrlException | IOException e) {
                throw new RuntimeException("Error while constructing credential response", e);
            }
        }
        return null;
    }

    private PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> constructCredentialAlg(
            CBORObject attestationObjectResult,
            byte[] clientDataJsonResult,
            AttestationConveyancePreference preference,
            ClientRegistrationExtensionOutputs clientExtensionResults
    ) throws Base64UrlException, IOException {
        if (preference == AttestationConveyancePreference.NONE) {
            byte[] aaguid = extractAaguid(attestationObjectResult);
            if (!Arrays.equals(aaguid, new byte[16])
                    || !attestationObjectResult.get("fmt").AsString().equals("packed")
                    || attestationObjectResult.get("x5c") != null) {
                censorAaguid(attestationObjectResult);
                attestationObjectResult.Set("fmt", "none");
                attestationObjectResult.Set("attStmt", CBORObject.NewMap());
            }
        }
        return PublicKeyCredential.<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>builder()
                .id(new ByteArray(extractCredentialId(attestationObjectResult)))
                .response(AuthenticatorAttestationResponse.builder()
                        .attestationObject(new ByteArray(attestationObjectResult.EncodeToBytes()))
                        .clientDataJSON(new ByteArray(clientDataJsonResult))
                        .transports(Collections.emptySet())
                        .build())
                .clientExtensionResults(clientExtensionResults)
                .build();
    }

    private byte[] extractAaguid(CBORObject attestationObject) {
        ByteBuffer authenticatorData = ByteBuffer.wrap(attestationObject.get("authData").GetByteString());
        authenticatorData.position(37);
        byte[] aaguid = new byte[16];
        authenticatorData.get(aaguid);
        return aaguid;
    }

    private void censorAaguid(CBORObject attestationObject) {
        ByteBuffer authenticatorData = ByteBuffer.wrap(attestationObject.get("authData").GetByteString());
        authenticatorData.position(37);
        authenticatorData.put(new byte[16]);
    }

    private byte[] extractCredentialId(CBORObject attestationObject) {
        ByteBuffer authenticatorData = ByteBuffer.wrap(attestationObject.get("authData").GetByteString());
        // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticator-data 37 bytes before attestedCredentialData part, then 16 bytes aaguid
        authenticatorData.position(37 + 16);
        authenticatorData.order(ByteOrder.BIG_ENDIAN);
        short credentialIdLength = authenticatorData.getShort();
        byte[] credentialId = new byte[credentialIdLength];
        authenticatorData.get(credentialId);
        return credentialId;
    }

    public PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> get(
            AssertionRequest publicKey
    ) {
        return null;
    }

}
