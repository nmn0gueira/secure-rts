package common.crypto;

import java.security.*;

public interface SymmetricCipher {

    byte[] encrypt(byte[] data) throws GeneralSecurityException;
    byte[] decrypt(byte[] encryptedData) throws GeneralSecurityException;
}