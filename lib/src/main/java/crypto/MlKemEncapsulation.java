package crypto;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.params.MLKEMParameters;

import common.Utils;

public class MlKemEncapsulation {

    private final MLKEMPublicKeyParameters publicKey;
    private final MLKEMPrivateKeyParameters privateKey;

    public MlKemEncapsulation() {
        MLKEMKeyPairGenerator gen = new MLKEMKeyPairGenerator();
        gen.init(new MLKEMKeyGenerationParameters(Utils.SECURE_RANDOM, MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        this.publicKey = (MLKEMPublicKeyParameters) kp.getPublic();
        this.privateKey = (MLKEMPrivateKeyParameters) kp.getPrivate();
    }

    public byte[] getPublicKeyBytes() {
        return publicKey.getEncoded();
    }

    public byte[] decapsulate(byte[] ciphertext) {
        return new MLKEMExtractor(privateKey).extractSecret(ciphertext);
    }

    public static KemResult encapsulate(byte[] recipientPublicKeyBytes) {
        MLKEMPublicKeyParameters recipientPubKey =
                new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, recipientPublicKeyBytes);
        SecretWithEncapsulation result =
                new MLKEMGenerator(Utils.SECURE_RANDOM).generateEncapsulated(recipientPubKey);
        return new KemResult(result.getEncapsulation(), result.getSecret());
    }

    public record KemResult(byte[] ciphertext, byte[] sharedSecret) {}
}
