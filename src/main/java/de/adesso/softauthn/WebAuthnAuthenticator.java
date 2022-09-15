package de.adesso.softauthn;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;
import de.adesso.softauthn.counter.SignatureCounter;
import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * An implementation of {@link Authenticator} that attempts to cover most of the
 * <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-model">WebAuthn specification for authenticators</a>.
 * <p>The idea behind this implementation is that it can represent many kinds of authenticators by behaving
 * in ways that depend on the configuration of the specific instance.<br>
 * I.e., you can configure what capabilities should be emulated by instances of this implementation. One instance could
 * support resident keys and user verification while another could not, for example.
 *
 * @see #builder()
 * @see Authenticators
 */
public class WebAuthnAuthenticator implements Authenticator {

    private static final Set<COSEAlgorithmIdentifier> COSE_LIB_SUPPORT = EnumSet.of(COSEAlgorithmIdentifier.ES256, COSEAlgorithmIdentifier.EdDSA);
    private static final Map<AlgorithmID, String> JAVA_ALGORITHM_NAMES = new HashMap<>();

    static {
        Security.addProvider(new EdDSASecurityProvider());
        JAVA_ALGORITHM_NAMES.put(AlgorithmID.ECDSA_256, "SHA256withECDSA");
        JAVA_ALGORITHM_NAMES.put(AlgorithmID.ECDSA_384, "SHA384withECDSA");
        JAVA_ALGORITHM_NAMES.put(AlgorithmID.ECDSA_512, "SHA512withECDSA");
        JAVA_ALGORITHM_NAMES.put(AlgorithmID.EDDSA, "NONEwithEdDSA");
        // FIXME: 15/09/2022 these below don't actually exist, that is an issue in the COSE library. Can be fixed by using "RSASSA-PSS" with additional PSSParameterSpecs instead.
        JAVA_ALGORITHM_NAMES.put(AlgorithmID.RSA_PSS_256, "SHA256withRSA/PSS");
        JAVA_ALGORITHM_NAMES.put(AlgorithmID.RSA_PSS_384, "SHA384withRSA/PSS");
        JAVA_ALGORITHM_NAMES.put(AlgorithmID.RSA_PSS_512, "SHA512withRSA/PSS");
    }

    private final SecureRandom random;
    private final Map<SourceKey, PublicKeyCredentialSource> storedSources;

    private final byte[] aaguid;
    private final AuthenticatorAttachment attachment;
    private final Set<COSEAlgorithmIdentifier> supportedAlgorithms;
    private final boolean supportsClientSideDiscoverablePublicKeyCredentialSources;

    private final boolean supportsUserVerification;

    private final SignatureCounter signatureCounter;

    private Function<? super Set<PublicKeyCredentialSource>, PublicKeyCredentialSource> credentialSelection;

    protected WebAuthnAuthenticator(
            byte[] aaguid,
            AuthenticatorAttachment attachment,
            Collection<COSEAlgorithmIdentifier> supportedAlgorithms,
            boolean supportsClientSideDiscoverablePublicKeyCredentialSources,
            boolean supportsUserVerification,
            SignatureCounter signatureCounter,
            Function<? super Set<PublicKeyCredentialSource>, PublicKeyCredentialSource> credentialSelection
    ) {
        if (aaguid.length != 16) {
            throw new IllegalArgumentException("aaguid must be 16 bytes");
        }
        this.aaguid = aaguid;
        this.attachment = Objects.requireNonNull(attachment);;
        this.supportedAlgorithms = EnumSet.copyOf(Objects.requireNonNull(supportedAlgorithms));
        this.supportsClientSideDiscoverablePublicKeyCredentialSources = supportsClientSideDiscoverablePublicKeyCredentialSources;
        this.supportsUserVerification = supportsUserVerification;
        this.signatureCounter = Objects.requireNonNull(signatureCounter);
        this.credentialSelection = Objects.requireNonNull(credentialSelection);
        this.storedSources = new HashMap<>();
        this.random = new SecureRandom();
    }

    /**
     * Creates a new builder that can be used to configure instances of this class.
     *
     * @return a new {@link WebAuthnAuthenticatorBuilder} object.
     */
    public static WebAuthnAuthenticatorBuilder builder() {
        return new WebAuthnAuthenticatorBuilder();
    }

    @Override
    public CBORObject makeCredential(
            byte[] hash, RelyingPartyIdentity rpEntity, UserIdentity userEntity, boolean requireResidentKey,
            boolean requireUserVerification, List<PublicKeyCredentialParameters> credTypesAndPubKeyAlgs,
            Set<PublicKeyCredentialDescriptor> excludeCredentials, boolean enterpriseAttestationPossible, byte[] extensions
    ) {
        for (PublicKeyCredentialDescriptor descriptor : excludeCredentials) {
            PublicKeyCredentialSource source = lookup(descriptor.getId()).orElse(null);
            if (source == null) {
                continue;
            }

            if (source.getRpId().equals(rpEntity.getId()) && source.getType() == descriptor.getType()) {
                throw new IllegalStateException("Can't create new credential: this credential is excluded");
            }

        }

        if (requireResidentKey && !supportsClientSideDiscoverablePublicKeyCredentialSources) {
            throw new UnsupportedOperationException(
                    "Authenticator cannot store client-side discoverable public key credential sources");
        }

        if (requireUserVerification && !supportsUserVerification) {
            throw new UnsupportedOperationException(
                    "Authenticator cannot perform user verification");
        }


        COSEAlgorithmIdentifier algId = credTypesAndPubKeyAlgs.stream()
                .map(PublicKeyCredentialParameters::getAlg)
                .filter(supportedAlgorithms::contains)
                .findFirst()
                .orElseThrow(() -> new UnsupportedOperationException("Authenticator does not support any of the available algorithms"));


        OneKey key;
        try {
            // TODO: 15/09/2022 support RS256 and RS1 here
            key = OneKey.generateKey(AlgorithmID.FromCBOR(CBORObject.FromObject((int) algId.getId())));
        } catch (CoseException e) {
            throw new UnsupportedOperationException("Algorithm " + algId + " not supported", e);
        }

        ByteArray userHandle = userEntity.getId();
        PublicKeyCredentialSource credentialSource = new PublicKeyCredentialSource(
                PublicKeyCredentialType.PUBLIC_KEY,
                key,
                rpEntity.getId(),
                userHandle
        );

        byte[] credentialId;
        if (requireResidentKey) {
            // section 7.3 of
            // https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-uaf-authnr-cmds-v1.1-id-20170202.html
            credentialId = new byte[32];
            random.nextBytes(credentialId);
            credentialSource.setId(new ByteArray(credentialId));
            storedSources.put(new SourceKey(rpEntity.getId(), userHandle), credentialSource);
        } else {
            credentialId = credentialSource.serialize();
        }

        byte[] cosePublicKey = key.PublicKey().EncodeToBytes();

        byte[] attestedCredentialData = createAttestedCredentialData(credentialId, cosePublicKey);
        // TODO: 12/09/2022 handle extensions
        byte[] processedExtensions = null;
        int signatureCount = signatureCounter.initialize(new ByteArray(credentialId));
        byte[] authenticatorData = createAuthenticatorData(
                rpEntity.getId(), true,
                requireUserVerification, signatureCount,
                attestedCredentialData, processedExtensions
        );

        // TODO: 09/09/2022 support different attestation formats

        return CBORObject.NewMap()
                .Add("fmt", "none")
                .Add("attStmt", CBORObject.NewMap())
                .Add("authData", authenticatorData);
    }

    private byte[] createAttestedCredentialData(byte[] credentialId, byte[] cosePublicKey) {
        int attestedCredentialDataLength = 16 + 2 + credentialId.length + cosePublicKey.length;
        return ByteBuffer.allocate(attestedCredentialDataLength)
                .order(ByteOrder.BIG_ENDIAN)
                .put(aaguid, 0, 16)
                .putShort((short) credentialId.length)
                .put(credentialId)
                .put(cosePublicKey)
                .array();
    }


    // see https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-get-assertion
    @Override
    public AuthenticatorAssertionData getAssertion(
            String rpId, byte[] hash,
            List<PublicKeyCredentialDescriptor> allowedCredentialDescriptorList,
            boolean requireUserVerification, byte[] extensions
    ) {
        Set<PublicKeyCredentialSource> credentialOptions = new HashSet<>();
        if (allowedCredentialDescriptorList != null) {
            for (PublicKeyCredentialDescriptor descriptor : allowedCredentialDescriptorList) {
                lookup(descriptor.getId()).ifPresent(credentialOptions::add);
            }
        } else {
            credentialOptions.addAll(storedSources.values());
        }
        credentialOptions.removeIf(source -> !rpId.equals(source.getRpId()));
        if (credentialOptions.isEmpty()) {
            throw new NoSuchElementException("No credential source matches input parameters");
        }

        if (requireUserVerification && !supportsUserVerification()) {
            throw new UnsupportedOperationException("Authenticator does not support user verification");
        }

        PublicKeyCredentialSource selectedCredential
                = credentialSelection.apply(Collections.unmodifiableSet(credentialOptions));

        // TODO: 12/09/2022 handle extensions
        byte[] processedExtensions = null;
        int signatureCount = signatureCounter.increment(selectedCredential.getId());
        byte[] authenticatorData = createAuthenticatorData(
                rpId, true, requireUserVerification,
                signatureCount, null, processedExtensions
        );


        OneKey key = selectedCredential.getKey();
        AlgorithmID algId;
        try {
            algId = AlgorithmID.FromCBOR(key.get(KeyKeys.Algorithm));
        } catch (CoseException e) {
            throw new UnsupportedOperationException("Unsupported signature algorithm", e);
        }
        byte[] signData = new byte[authenticatorData.length + hash.length];
        System.arraycopy(authenticatorData, 0, signData, 0, authenticatorData.length);
        System.arraycopy(hash, 0, signData, authenticatorData.length, hash.length);

        byte[] signature = computeSignature(algId, signData, key);
        return new AuthenticatorAssertionData(selectedCredential.getId(),
                new ByteArray(authenticatorData), new ByteArray(signature),
                selectedCredential.getUserHandle());

    }

    private Optional<PublicKeyCredentialSource> lookup(ByteArray credentialId) {
        return PublicKeyCredentialSource.deserialize(credentialId)
                .map(Optional::of)
                .orElseGet(() -> storedSources.values().stream().filter(source -> source.getId().equals(credentialId)).findFirst());
    }

    private byte[] computeSignature(AlgorithmID alg, byte[] rgbToBeSigned, OneKey cnKey) {
        String algName = JAVA_ALGORITHM_NAMES.get(alg);

        if (algName == null) {
            throw new UnsupportedOperationException("Unsupported Algorithm Specified");
        }
        PrivateKey privKey;
        try {
            privKey = cnKey.AsPrivateKey();
        } catch (CoseException e) {
            throw new AssertionError(e);
        }

        byte[] result;
        try {
            Signature sig = Signature.getInstance(algName);
            // FIXME: 15/09/2022 provide algorithm parameter spec if required
            sig.initSign(privKey);
            sig.update(rgbToBeSigned);
            result = sig.sign();
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Required algorithm not available. Did you forget to register a provider?", ex);
        } catch (SignatureException | InvalidKeyException e) {
            throw new RuntimeException("Signature failed", e);
        }

        return result;
    }

    private byte[] createAuthenticatorData(
            String rpId, boolean userPresence, boolean userVerification,
            int signatureCounter, byte[] attestedCredentialData, byte[] extensions
    ) {
        MessageDigest sha256;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 is not available", e);
        }
        byte[] rpIdHash = sha256.digest(rpId.getBytes(StandardCharsets.UTF_8));


        boolean ed = extensions != null;
        boolean at = attestedCredentialData != null;
        byte flags = generateAuthenticatorDataFlags(ed, at, userVerification, userPresence);
        ByteBuffer authenticatorData = ByteBuffer.allocate(32 + 1 + 4 + (at ? attestedCredentialData.length : 0) + (ed ? extensions.length : 0))
                .order(ByteOrder.BIG_ENDIAN)
                .put(rpIdHash, 0, 32)
                .put(flags)
                .putInt(signatureCounter);
        if (at) {
            authenticatorData.put(attestedCredentialData);
        }
        if (ed) {
            authenticatorData.put(extensions);
        }
        return authenticatorData.array();
    }

    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticator-data-perform-the-following-steps-to-generate-an-authenticator-data-structure
    private byte generateAuthenticatorDataFlags(boolean ed, boolean at, boolean uv, boolean up) {
        int flags = 0;
        if (ed) {
            flags++;
        }
        flags <<= 1;
        if (at) {
            flags++;
        }
        flags <<= 4;
        if (uv) {
            flags++;
        }
        flags <<= 2;
        if (up) {
            flags++;
        }
        return (byte) flags;
    }

    private AlgorithmID convertAlgId(COSEAlgorithmIdentifier id) {
        try {
            return AlgorithmID.FromCBOR(CBORObject.FromObject(id.getId()));
        } catch (CoseException e) {
            return null;
        }
    }

    @Override
    public AuthenticatorAttachment getAttachment() {
        return attachment;
    }

    @Override
    public boolean supportsClientSideDiscoverablePublicKeyCredentialSources() {
        return supportsClientSideDiscoverablePublicKeyCredentialSources;
    }

    @Override
    public boolean supportsUserVerification() {
        return supportsUserVerification;
    }

    private static final class SourceKey {
        final String rpId;
        final ByteArray userHandle;

        SourceKey(String rpId, ByteArray userHandle) {
            this.rpId = rpId;
            this.userHandle = userHandle;
        }
    }
}
