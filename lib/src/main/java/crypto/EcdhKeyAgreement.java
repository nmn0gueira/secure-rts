package crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

public class EcdhKeyAgreement implements CustomKeyAgreement {

    private static final String EC_CURVE = "secp256r1";

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }


    private final KeyPair keyPair;
    private final KeyAgreement keyAgreement;

    public EcdhKeyAgreement() {
        try {
            KeyPairGenerator gen= KeyPairGenerator.getInstance("EC", "BC");
            gen.initialize(new ECGenParameterSpec(EC_CURVE));
            keyPair = gen.generateKeyPair();

            keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
            keyAgreement.init(keyPair.getPrivate());
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void doPhase(PublicKey publicKey) throws InvalidKeyException {
        keyAgreement.doPhase(publicKey, true);
    }

    @Override
    public byte[] generateSecret() {
        return keyAgreement.generateSecret();
    }

    @Override
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

}
