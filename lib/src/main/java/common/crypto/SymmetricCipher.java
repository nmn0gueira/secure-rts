package common.crypto;

import java.security.*;

public interface SymmetricCipher {

    byte[] encrypt(byte[] data) throws GeneralSecurityException;
    byte[] decrypt(byte[] encryptedData) throws GeneralSecurityException;

    static SymmetricCipher getInstance(String algorithm) {
        return switch (algorithm) {
            case "aes" -> new AesGcmCipher();
            case "chacha" -> new ChaCha20Poly1305Cipher();
            case "dprg" -> new MyStreamCipher();
            default ->
                    throw new RuntimeException("Algorithm incorrectly specified. Try \"aes\", \"chacha\" or \"dprg\"");
        };
    }
}