package crypto;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.*;

public class DhKeyAgreement implements CustomKeyAgreement {

    // Pre-computed 512-bit DH parameters (G and P)
    private static final BigInteger G_512 = new BigInteger(
            "153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7"
                    + "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b"
                    + "410b7a0f12ca1cb9a428cc", 16);

    private static final BigInteger P_512 = new BigInteger(
            "9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387"
                    + "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b"
                    + "f0573bf047a3aca98cdf3b", 16);

    private static final DHParameterSpec DH_PARAMS = new DHParameterSpec(P_512, G_512);

    private final KeyPair keyPair;
    private final KeyAgreement keyAgreement;

    public DhKeyAgreement() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("DH", "BC");
            gen.initialize(DH_PARAMS);
            keyPair = gen.generateKeyPair();
            keyAgreement = KeyAgreement.getInstance("DH", "BC");
            keyAgreement.init(keyPair.getPrivate());
        } catch (NoSuchAlgorithmException | NoSuchProviderException |
                 InvalidAlgorithmParameterException | InvalidKeyException e) {
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
