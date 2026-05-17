package crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;

// ML-DSA-65 (FIPS 204) via JDK's native provider (Java 24+), compatible with keytool-generated keys.
public class MlDsaSignature implements DigitalSignature {

    private static final String ALGORITHM = "ML-DSA-65";

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public byte[] sign(PrivateKey privateKey, byte[] data) throws InvalidKeyException, SignatureException {
        try {
            Signature sig = Signature.getInstance(ALGORITHM);
            sig.initSign(privateKey);
            sig.update(data);
            return sig.sign();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean verify(PublicKey publicKey, byte[] data, byte[] signature) throws InvalidKeyException, SignatureException {
        try {
            Signature sig = Signature.getInstance(ALGORITHM);
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
