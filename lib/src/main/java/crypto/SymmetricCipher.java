package crypto;

import java.security.GeneralSecurityException;

public interface SymmetricCipher {

    byte[] encrypt(byte[] data) throws GeneralSecurityException;

    byte[] decrypt(byte[] encryptedData) throws GeneralSecurityException;
}