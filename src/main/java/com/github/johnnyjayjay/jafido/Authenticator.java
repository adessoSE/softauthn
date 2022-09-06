package com.github.johnnyjayjay.jafido;

import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Authenticator {

    private final SecureRandom random;
    private final Map<ByteArray, PublicKeyCredentialSource> storedSources;
    // EdDSA =
    // ESXXX = EC + secpXXXr1 ?



    private static final Map<COSEAlgorithmIdentifier, KeyGenParams> generatorMappings = new HashMap<>();

    static {
        Security.addProvider(new BouncyCastleProvider());
        generatorMappings.put(COSEAlgorithmIdentifier.ES256, new KeyGenParams("EC", new ECGenParameterSpec("secp256r1")));
        generatorMappings.put(COSEAlgorithmIdentifier.EdDSA, new KeyGenParams("EdDSA", new EdDSAParameterSpec("Ed25519")));
        generatorMappings.put(COSEAlgorithmIdentifier.RS256, new KeyGenParams("RSASSA-PSS", null));
        generatorMappings.put(COSEAlgorithmIdentifier.RS1, new KeyGenParams("RSASSA-PSS", null));
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
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
    }

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

    static final class KeyGenParams {
        final String keyGeneratorAlgorithm;
        final AlgorithmParameterSpec algSpec;

        KeyGenParams(String keyGeneratorAlgorithm, AlgorithmParameterSpec algSpec) {
            this.keyGeneratorAlgorithm = keyGeneratorAlgorithm;
            this.algSpec = algSpec;
        }
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
