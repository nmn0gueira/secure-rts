package crypto;

import java.security.InvalidKeyException;
import java.security.PublicKey;

public interface CustomKeyAgreement {

    void doPhase(PublicKey publicKey) throws InvalidKeyException;

    byte[] generateSecret();

    PublicKey getPublicKey();
}
