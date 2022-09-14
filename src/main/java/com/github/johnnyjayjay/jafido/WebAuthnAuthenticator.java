package com.github.johnnyjayjay.jafido;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.KeyKeys;
import COSE.OneKey;
import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.exception.Base64UrlException;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
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

public class WebAuthnAuthenticator implements Authenticator {

    private static final Map<AlgorithmID, String> JAVA_ALGORITHM_NAMES = new HashMap<>();

    static {
        JAVA_ALGORITHM_NAMES.put(AlgorithmID.EDDSA, "EDDSA");
        JAVA_ALGORITHM_NAMES.put(AlgorithmID.ECDSA_256, "SHA256withECDSA");
    }

    private final SecureRandom random;
    private final Map<SourceKey, PublicKeyCredentialSource> storedSources;


    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, CoseException, Base64UrlException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = gen.generateKeyPair();
        System.out.println(pair);

        KeyPairGenerator gen2 = KeyPairGenerator.getInstance("EdDSA");
        gen2.initialize(new EdDSAParameterSpec("Ed25519"));
        gen2.generateKeyPair();

        KeyPairGenerator gen3 = KeyPairGenerator.getInstance("RSASSA-PSS");

        //gen3.initialize(new RSAKeyGenParameterSpec());
        //gen3.initialize(new PSSParameterSpec("SHA-256", "mgf1SHA256", new MGF1ParameterSpec("SHA-256"), 20, 1));
        KeyPair pair1 = gen3.generateKeyPair();
        System.out.println(pair1.getPublic());

        AlgorithmID algId = AlgorithmID.FromCBOR(CBORObject.FromObject(-7));
        OneKey key = OneKey.generateKey(algId);
        key.PublicKey().AsCBOR();

        ByteArray att = ByteArray.fromBase64Url("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAwAAAAAAAAAAAAAAAAAAAAAAQPSCpdq1Dh_cC3G4zrGY_MX2wRQZ7jOHMk8MoEynIU9cS6VyK1AHjF61tTzw2QRdJrfDt9q05RxsU6JIgHg91falAQIDJiABIVggt42LGWVN8uek4h77CbC1GKP9BIdiaM3VETWC2zienk4iWCCCtOHlkw0T4BmtLB3i3e7vbF44Z5fZCr_IhZ6PIRzWdA");
        CBORObject cborObject = CBORObject.DecodeFromBytes(att.getBytes());
        System.out.println(cborObject);
    }

    private final byte[] aaguid;
    private final AuthenticatorAttachment attachment;
    private final Set<AlgorithmID> supportedAlgorithms;
    private final boolean supportsClientSideDiscoverablePublicKeyCredentialSources;

    private final boolean supportsUserVerification;

    private Function<? super Set<PublicKeyCredentialSource>, PublicKeyCredentialSource> credentialSelection;


    public WebAuthnAuthenticator(
            byte[] aaguid,
            AuthenticatorAttachment attachment,
            Collection<AlgorithmID> supportedAlgorithms,
            boolean supportsClientSideDiscoverablePublicKeyCredentialSources,
            boolean supportsUserVerification,
            Function<? super Set<PublicKeyCredentialSource>, PublicKeyCredentialSource> credentialSelection
    ) {
        this.aaguid = aaguid;
        this.attachment = attachment;
        this.supportedAlgorithms = EnumSet.copyOf(supportedAlgorithms);
        this.supportsClientSideDiscoverablePublicKeyCredentialSources = supportsClientSideDiscoverablePublicKeyCredentialSources;
        this.supportsUserVerification = supportsUserVerification;
        this.credentialSelection = credentialSelection;
        this.storedSources = new HashMap<>();
        random = new SecureRandom();
    }

    // see https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-make-cred
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


        AlgorithmID algId = credTypesAndPubKeyAlgs.stream()
                .map(PublicKeyCredentialParameters::getAlg)
                .map(this::convertAlgId)
                .filter(Objects::nonNull)
                .filter(supportedAlgorithms::contains)
                .findFirst()
                .orElseThrow(() -> new UnsupportedOperationException("Authenticator does not support any of the available algorithms"));


        OneKey key;
        try {
            key = OneKey.generateKey(algId);
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
            credentialId = credentialSource.encrypt();
        }

        byte[] cosePublicKey = key.PublicKey().EncodeToBytes();

        byte[] attestedCredentialData = createAttestedCredentialData(credentialId, cosePublicKey);
        // TODO: 12/09/2022 handle extensions
        byte[] processedExtensions = null;
        // TODO: 08/09/2022 support different signature counter styles
        int signatureCounter = 0;
        byte[] authenticatorData = createAuthenticatorData(
                rpEntity.getId(), true,
                requireUserVerification, signatureCounter,
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

    private byte[] createAuthenticatorData(
            String rpId, boolean userPresence, boolean userVerification,
            int signatureCounter, byte[] attestedCredentialData, byte[] extensions
    ) {
        MessageDigest sha256 = null;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
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
        flags <<= 3;
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

    private Optional<PublicKeyCredentialSource> lookup(ByteArray credentialId) {
        return PublicKeyCredentialSource.decrypt(credentialId)
                .map(Optional::of)
                .orElseGet(() -> storedSources.values().stream().filter(source -> source.getId().equals(credentialId)).findFirst());
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
        // TODO: 12/09/2022 signature counter
        int signatureCounter = 0;
        byte[] authenticatorData = createAuthenticatorData(
                rpId, true, requireUserVerification,
                signatureCounter, null, processedExtensions
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

        try {
            byte[] signature = computeSignature(algId, signData, key);
            return new AuthenticatorAssertionData(selectedCredential.getId(),
                    new ByteArray(authenticatorData), new ByteArray(signature),
                    selectedCredential.getUserHandle());
        } catch (CoseException e) {
            throw new RuntimeException("Signature failed", e);
        }
    }

    private byte[] computeSignature(AlgorithmID alg, byte[] rgbToBeSigned, OneKey cnKey) throws CoseException {
        String algName;
        String provider = null;

        switch (alg) {
            case ECDSA_256:
                algName = "SHA256withECDSA";
                break;
            case ECDSA_384:
                algName = "SHA384withECDSA";
                break;
            case ECDSA_512:
                algName = "SHA512withECDSA";
                break;
            case EDDSA:
                algName = "NonewithEdDSA";
                provider = "EdDSA";
                break;

            case RSA_PSS_256:
                algName = "SHA256withRSA/PSS";
                break;

            case RSA_PSS_384:
                algName = "SHA384withRSA/PSS";
                break;

            case RSA_PSS_512:
                algName = "SHA512withRSA/PSS";
                break;

            default:
                throw new CoseException("Unsupported Algorithm Specified");
        }

        if (cnKey == null) {
            throw new NullPointerException();
        }

        PrivateKey privKey = cnKey.AsPrivateKey();
        if (privKey == null) {
            throw new CoseException("Private key required to sign");
        }

        byte[] result;
        try {
            Signature sig = provider == null ? Signature.getInstance(algName) :
                    Signature.getInstance(algName, provider);
            sig.initSign(privKey);
            sig.update(rgbToBeSigned);
            result = sig.sign();

        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Signature failure", ex);
        }

        return result;
    }

    private static final class SourceKey {
        final String rpId;
        final ByteArray userHandle;

        SourceKey(String rpId, ByteArray userHandle) {
            this.rpId = rpId;
            this.userHandle = userHandle;
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

    public enum SignatureCounterStyle {
        GLOBAL,
        PER_CREDENTIAL,
        NONE
    }
}
