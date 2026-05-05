package crypto;

import java.security.*;

public class EcdsaSignature implements DigitalSignature {

    private final Signature signature;

    public EcdsaSignature() {
        try {
            signature = Signature.getInstance("SHA256withECDSA", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] sign(PrivateKey privateKey, byte[] data) throws InvalidKeyException, SignatureException {
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    @Override
    public boolean verify(PublicKey publicKey, byte[] data, byte[] sig) throws InvalidKeyException, SignatureException {
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(sig);
    }
}
