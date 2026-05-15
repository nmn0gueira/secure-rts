package crypto;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

public interface IntegrityCheck {

    byte[] createIntegrityProof(byte[] data) throws GeneralSecurityException;

    int getIntegrityProofSize();

    default boolean verifyIntegrity(byte[] data, byte[] integrityProof) throws GeneralSecurityException {
        return MessageDigest.isEqual(createIntegrityProof(data), integrityProof);
    }

    boolean isMac();
}
