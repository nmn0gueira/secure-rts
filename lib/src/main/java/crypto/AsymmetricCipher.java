package crypto;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface AsymmetricCipher {

    byte[] encrypt(byte[] data, PublicKey publicKey) throws GeneralSecurityException;

    byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) throws GeneralSecurityException;
}
