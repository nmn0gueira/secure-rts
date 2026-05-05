package crypto;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

public interface DigitalSignature {

    byte[] sign(PrivateKey privateKey, byte[] message) throws InvalidKeyException, SignatureException;

    boolean verify(PublicKey publicKey, byte[] message, byte[] signature) throws InvalidKeyException, SignatureException;
}
