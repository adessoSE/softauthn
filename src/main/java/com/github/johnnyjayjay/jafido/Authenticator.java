package com.github.johnnyjayjay.jafido;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.OneKey;
import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AttestedCredentialData;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

public class Authenticator {

    private final SecureRandom random;
    private final Map<SourceKey, PublicKeyCredentialSource> storedSources;

    private static final Map<COSEAlgorithmIdentifier, KeyGenParams> generatorMappings = new HashMap<>();

    static {
        Security.addProvider(new BouncyCastleProvider());
        generatorMappings.put(COSEAlgorithmIdentifier.ES256, new KeyGenParams("EC", new ECGenParameterSpec("secp256r1")));
        generatorMappings.put(COSEAlgorithmIdentifier.EdDSA, new KeyGenParams("EdDSA", new EdDSAParameterSpec("Ed25519")));
        generatorMappings.put(COSEAlgorithmIdentifier.RS256, new KeyGenParams("RSASSA-PSS", null));
        generatorMappings.put(COSEAlgorithmIdentifier.RS1, new KeyGenParams("RSASSA-PSS", null));
    }

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

        byte[] handle = new byte[48];
        ThreadLocalRandom.current().nextBytes(handle);
        PublicKeyCredentialSource source = new PublicKeyCredentialSource(PublicKeyCredentialType.PUBLIC_KEY, pair.getPrivate(), "localhost", new ByteArray(handle));
        ByteArray encrypted = source.encrypt();
        System.out.println(encrypted.getBase64().length());
        PublicKeyCredentialSource decrypted = PublicKeyCredentialSource.decrypt(encrypted).get();
        System.out.println(decrypted);

        AlgorithmID algId = AlgorithmID.FromCBOR(CBORObject.FromObject(-7));
        OneKey key = OneKey.generateKey(algId);
        key.PublicKey().AsCBOR();

        ByteArray att = ByteArray.fromBase64Url("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAwAAAAAAAAAAAAAAAAAAAAAAQPSCpdq1Dh_cC3G4zrGY_MX2wRQZ7jOHMk8MoEynIU9cS6VyK1AHjF61tTzw2QRdJrfDt9q05RxsU6JIgHg91falAQIDJiABIVggt42LGWVN8uek4h77CbC1GKP9BIdiaM3VETWC2zienk4iWCCCtOHlkw0T4BmtLB3i3e7vbF44Z5fZCr_IhZ6PIRzWdA");
        CBORObject cborObject = CBORObject.DecodeFromBytes(att.getBytes());
        System.out.println(cborObject);
    }

    private final byte[] aaguid;
    private final AuthenticatorAttachment attachment;
    private final boolean supportsClientSideDiscoverablePublicKeyCredentialSources;

    private final boolean supportsUserVerification;


    public Authenticator(
            byte[] aaguid,
            AuthenticatorAttachment attachment,
            boolean supportsClientSideDiscoverablePublicKeyCredentialSources,
            boolean supportsUserVerification
    ) {
        this.aaguid = aaguid;
        this.attachment = attachment;
        this.supportsClientSideDiscoverablePublicKeyCredentialSources = supportsClientSideDiscoverablePublicKeyCredentialSources;
        this.supportsUserVerification = supportsUserVerification;
        this.storedSources = new HashMap<>();
        random = new SecureRandom();
    }

    // see https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-make-cred
    public CBORObject makeCredential(
            byte[] hash, RelyingPartyIdentity rpEntity, UserIdentity userEntity, boolean requireResidentKey,
            boolean requireUserVerification, List<PublicKeyCredentialParameters> credTypesAndPubKeyAlgs,
            Set<PublicKeyCredentialDescriptor> excludeCredentials, boolean enterpriseAttestationPossible, byte[] extensions
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

        if (requireResidentKey && !supportsClientSideDiscoverablePublicKeyCredentialSources) {
            throw new UnsupportedOperationException(
                "Authenticator cannot store client-side discoverable public key credential sources");
        }

        if (requireUserVerification && !supportsUserVerification) {
            throw new UnsupportedOperationException(
                "Authenticator cannot perform user verification");
        }

        PublicKeyCredentialParameters params = credTypesAndPubKeyAlgs.stream()
                .filter(p -> generatorMappings.containsKey(p.getAlg()))
                .findFirst()
                .orElseThrow(() -> new UnsupportedOperationException("Authenticator does not support any of the available algorithms"));


        OneKey key;
        PrivateKey privateKey;
        try {
            AlgorithmID algId = AlgorithmID.FromCBOR(CBORObject.FromObject(params.getAlg().getId()));
            key = OneKey.generateKey(algId);
            privateKey = key.AsPrivateKey();
        } catch (CoseException e) {
            throw new UnsupportedOperationException("Algorithm " + params.getAlg() + " not supported", e);
        }

        ByteArray userHandle = userEntity.getId();
        PublicKeyCredentialSource credentialSource = new PublicKeyCredentialSource(
                params.getType(),
                privateKey,
                rpEntity.getId(),
                userHandle
        );

        byte[] credentialId;
        if (requireResidentKey) {
            credentialId = new byte[64];
            random.nextBytes(credentialId);
            credentialSource.setId(new ByteArray(credentialId));
            storedSources.put(new SourceKey(rpEntity.getId(), userHandle), credentialSource);
        } else {
            credentialId = credentialSource.encrypt().getBytes();
        }

        byte[] cosePublicKey = key.PublicKey().EncodeToBytes();
        int attestedCredentialDataLength = 16 + 2 + credentialId.length + cosePublicKey.length;
        ByteBuffer attestedCredentialData = ByteBuffer.allocate(attestedCredentialDataLength)
                .order(ByteOrder.BIG_ENDIAN)
                .put(aaguid, 0, 16)
                .putShort((short) credentialId.length)
                .put(credentialId)
                .put(cosePublicKey);

        attestedCredentialData.rewind();
        // TODO: 08/09/2022 support different signature counter styles
        // TODO: 08/09/2022 extract to helper method for use in assertion method
        int signatureCounter = 0;
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] rpIdHash = sha256.digest(rpEntity.getId().getBytes(StandardCharsets.UTF_8));
        byte flags = 0b01000101;
        ByteBuffer authenticatorData = ByteBuffer.allocate(32 + 1 + 4 + attestedCredentialDataLength)
                .order(ByteOrder.BIG_ENDIAN)
                .put(rpIdHash, 0, 32)
                .put(flags)
                .putInt(signatureCounter)
                .put(attestedCredentialData);

        // TODO: 09/09/2022 support different attestation formats

        return CBORObject.NewMap()
                .Add("fmt", "none")
                .Add("attStmt", CBORObject.NewMap())
                .Add("authData", authenticatorData.array());
    }

    private PublicKeyCredentialSource lookup(ByteArray credentialId) {
        return null;
    }

    private static final class KeyGenParams {
        final String keyGeneratorAlgorithm;
        final AlgorithmParameterSpec algSpec;

        KeyGenParams(String keyGeneratorAlgorithm, AlgorithmParameterSpec algSpec) {
            this.keyGeneratorAlgorithm = keyGeneratorAlgorithm;
            this.algSpec = algSpec;
        }
    }

    private static final class SourceKey {
        final String rpId;
        final ByteArray userHandle;

        SourceKey(String rpId, ByteArray userHandle) {
            this.rpId = rpId;
            this.userHandle = userHandle;
        }
    }

    public AuthenticatorAttachment getAttachment() {
        return attachment;
    }

    public boolean supportsClientSideDiscoverablePublicKeyCredentialSources() {
        return supportsClientSideDiscoverablePublicKeyCredentialSources;
    }

    public boolean supportsUserVerification() {
        return supportsUserVerification;
    }
}
