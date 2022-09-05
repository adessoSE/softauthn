package com.github.johnnyjayjay.jafido;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.CollectedClientData;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserVerificationRequirement;

import java.net.URL;
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
        // TODO: 25/08/2022 handle extensions?

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

            if (!authenticator.isResidentKey() && options.getAuthenticatorSelection().flatMap(AuthenticatorSelectionCriteria::getResidentKey).map(req -> req == ResidentKeyRequirement.REQUIRED).orElse(false)) {
                continue;
            }

            boolean requireResidentKey = options.getAuthenticatorSelection().flatMap(AuthenticatorSelectionCriteria::getResidentKey)
                    .map(req -> req == ResidentKeyRequirement.REQUIRED || (req == ResidentKeyRequirement.PREFERRED && authenticator.isResidentKey()))
                    .orElse(false);

            boolean userVerification = options.getAuthenticatorSelection().flatMap(AuthenticatorSelectionCriteria::getUserVerification)
                    .map(req -> req == UserVerificationRequirement.REQUIRED || (req == UserVerificationRequirement.PREFERRED && authenticator.canPerformUserVerification()))
                    .orElse(false);

            // skip handling this for now
            boolean enterpriseAttestationPossible = false;

            Set<PublicKeyCredentialDescriptor> excludeCredentials = options.getExcludeCredentials()
                    .orElse(Collections.emptySet());

            //authenticator.makeCredential();

        }
        return null;
    }

    public PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> get(
            AssertionRequest publicKey
    ) {
        return null;
    }

}
