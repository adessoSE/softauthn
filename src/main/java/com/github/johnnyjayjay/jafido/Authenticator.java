package com.github.johnnyjayjay.jafido;

import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Authenticator {

    // EdDSA =
    // ESXXX = EC + secpXXXr1 ?



    private static final Map<COSEAlgorithmIdentifier, KeyGenParams> generatorMappings = new HashMap<>();

    static {
        Security.addProvider(new BouncyCastleProvider());
        generatorMappings.put(COSEAlgorithmIdentifier.ES256, new KeyGenParams("EC", new ECGenParameterSpec("secp256r1")));
        // or maybe just "Ed25519" as alg name and no parameter spec
        generatorMappings.put(COSEAlgorithmIdentifier.EdDSA, new KeyGenParams("EdDSA", new EdDSAParameterSpec("Ed25519"))); // EdDSA keyparameter spec
        //generatorMappings.put(COSEAlgorithmIdentifier.RS256, new KeyGenParams("RSASSA-PSS", null)); // RSASSA-PSS keyparameter spec (bouncycastle?)
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = gen.generateKeyPair();
        System.out.println(pair);

        KeyPairGenerator gen2 = KeyPairGenerator.getInstance("EdDSA");
        gen2.initialize(new EdDSAParameterSpec("Ed25519"));
        gen2.generateKeyPair();
    }

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
