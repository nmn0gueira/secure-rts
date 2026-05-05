package crypto;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

public interface IntegrityCheck {

    byte[] createIntegrityProof(byte[] data, byte[] nonce) throws GeneralSecurityException;

    int getIntegrityProofSize();

    default boolean verifyIntegrity(byte[] data, byte[] nonce, byte[] integrityProof) throws GeneralSecurityException {
        return MessageDigest.isEqual(createIntegrityProof(data, nonce), integrityProof);
    }

    boolean isMac();
}
