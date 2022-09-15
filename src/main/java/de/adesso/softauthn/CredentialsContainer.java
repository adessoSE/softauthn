package de.adesso.softauthn;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttachment;
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
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.data.exception.Base64UrlException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

// TODO: 14/09/2022 remove yubico dependency, write own required data structures with json serialisation support
// navigator.credentials simulator
public class CredentialsContainer {

    private final Origin origin;
    private final List<Authenticator> authenticators;

    private final ObjectMapper mapper;

    public CredentialsContainer(Origin origin, List<? extends Authenticator> authenticators) {
        this.origin = origin;
        this.authenticators = new ArrayList<>(authenticators);
        this.mapper = new ObjectMapper();
    }

    public boolean isUserVerifyingPlatformAuthenticatorAvailable() {
        return authenticators.stream()
                .anyMatch(auth -> auth.supportsUserVerification()
                        && auth.getAttachment() == AuthenticatorAttachment.PLATFORM);
    }

    public PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> create(
            PublicKeyCredentialCreationOptions publicKey
    ) {
        return create(origin, publicKey, true);
    }

    // following https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-createCredential
    public PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> create(
            Origin origin,
            PublicKeyCredentialCreationOptions options,
            boolean sameOriginWithAncestors
    ) {
        
        checkParameters(options.getRp().getId(), origin, sameOriginWithAncestors);
        // 9-10.
        List<PublicKeyCredentialParameters> credTypesAndPubKeyAlgs = options.getPubKeyCredParams().isEmpty()
                ? Arrays.asList(PublicKeyCredentialParameters.builder().alg(COSEAlgorithmIdentifier.ES256).build(),
                PublicKeyCredentialParameters.builder().alg(COSEAlgorithmIdentifier.RS256).build())
                : options.getPubKeyCredParams();

        ClientData clientData = collectClientData("webauthn.create", options.getChallenge(), origin, sameOriginWithAncestors);

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

            CBORObject attestationObject;
            try {
                attestationObject = authenticator.makeCredential(
                        clientData.clientDataHash, options.getRp(), options.getUser(),
                        requireResidentKey, userVerification, credTypesAndPubKeyAlgs,
                        excludeCredentials, enterpriseAttestationPossible, null
                );
            } catch (IllegalStateException e) {
                throw e;
            } catch (RuntimeException e) {
                continue;
            }

            try {
                return constructCredentialAlg(
                        attestationObject,
                        clientData.clientDataJson,
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
            PublicKeyCredentialRequestOptions publicKey
    ) {
        return discoverFromExternalSource(origin, publicKey, true);
    }

    private PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> discoverFromExternalSource(
            Origin origin, PublicKeyCredentialRequestOptions options, boolean sameOriginWithAncestors
    ) {
        checkParameters(options.getRpId(), origin, sameOriginWithAncestors);
        ClientData clientData = collectClientData("webauthn.get", options.getChallenge(), origin, sameOriginWithAncestors);
        for (Authenticator authenticator : authenticators) {
            if (options.getUserVerification()
                    .map(UserVerificationRequirement.REQUIRED::equals)
                    .orElse(false) && !authenticator.supportsUserVerification()) {
                continue;
            }

            boolean userVerification = !options.getUserVerification()
                    .map(UserVerificationRequirement.DISCOURAGED::equals).orElse(false)
                    && authenticator.supportsUserVerification();

            // skip narrowing this list down to this specific authenticator
            List<PublicKeyCredentialDescriptor> allowCredentials = options.getAllowCredentials().orElse(Collections.emptyList());

            // skip temporarily saving credential id if there is only one available - authenticator will always return the id that was used.
            // this is technically a deviation from the spec, but in software context there is no reason to not return the credential id every time

            // skip transport handling (also not relevant for software authenticators)


            AuthenticatorAssertionData assertionData;
            try {
                assertionData = authenticator.getAssertion(
                        options.getRpId(),
                        clientData.clientDataHash,
                        allowCredentials.isEmpty() ? null : allowCredentials,
                        userVerification,
                        null
                );
            } catch (RuntimeException e) {
                continue;
            }

            try {
                return constructAssertionAlg(assertionData, clientData);
            } catch (Base64UrlException | IOException e) {
                throw new RuntimeException("Error while creating assertion", e);
            }
        }
        return null;
    }

    private PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> constructAssertionAlg(
            AuthenticatorAssertionData assertionData,
            ClientData clientData
    ) throws Base64UrlException, IOException {
        return PublicKeyCredential.<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>builder()
                .id(assertionData.getCredentialId())
                .response(AuthenticatorAssertionResponse.builder()
                        .authenticatorData(assertionData.getAuthenticatorData())
                        .clientDataJSON(new ByteArray(clientData.clientDataJson))
                        .signature(assertionData.getSignature())
                        .userHandle(Optional.ofNullable(assertionData.getUserHandle()))
                        .build())
                .clientExtensionResults(ClientAssertionExtensionOutputs.builder().build())
                .build();
    }

    private void checkParameters(String rpId, Origin origin, boolean sameOriginWithAncestors) {
        // 2.
        Checks.check(sameOriginWithAncestors, "NotAllowedError (sameOriginWithAncestors)");
        // 4. skip irrelevant timeout steps
        // 5. skip irrelevant user id check
        // 6.
        Checks.check(origin != null, "NotAllowedError (opaque origin)");
        // 7.
        String effectiveDomain = origin.effectiveDomain();
        // TODO: 25/08/2022 validate domain
        // 8. skip rpId check, it's always set by Relying Party
    }
    
    private Map<String, String> processExtensions() {
        // TODO: 25/08/2022 handle extensions
        return new HashMap<>();
    }

    private ClientData collectClientData(String type, ByteArray challenge, Origin origin, boolean sameOriginWithAncestors) {

        ObjectNode collectedClientData = mapper.createObjectNode()
                .put("type", type)
                .put("challenge", challenge.getBase64Url())
                .put("origin", origin.serialized())
                .put("crossOrigin", !sameOriginWithAncestors);

        byte[] clientDataJson;
        try {
            clientDataJson = mapper.writeValueAsBytes(collectedClientData);
        } catch (JsonProcessingException e) {
            throw new AssertionError(e);
        }
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Required algorithm unavailable", e);
        }
        byte[] clientDataHash = digest.digest(clientDataJson);
        return new ClientData(clientDataJson, clientDataHash);
    }

    private static final class ClientData {
        private final byte[] clientDataJson;
        private final byte[] clientDataHash;

        private ClientData(byte[] clientDataJson, byte[] clientDataHash) {
            this.clientDataJson = clientDataJson;
            this.clientDataHash = clientDataHash;
        }
    }

}
