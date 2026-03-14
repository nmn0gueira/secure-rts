package common.crypto;

import common.Utils;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

public class ChaCha20Poly1305Cipher implements SymmetricCipher {
    private static final int NONCE_SIZE_BYTES = 12;

    private final Cipher cipher;
    private final SecretKeySpec keySpec;

    public ChaCha20Poly1305Cipher() {
        byte[] key =  "0123456789abcdef0123456789abcdef".getBytes();
        this(key);
    }

    public ChaCha20Poly1305Cipher(byte[] key) {
        try {
            cipher = Cipher.getInstance("ChaCha20-Poly1305");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        this.keySpec = new SecretKeySpec(key, "ChaCha20-Poly1305");
    }


    @Override
    public byte[] encrypt(byte[] data) throws GeneralSecurityException {
        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        Utils.SECURE_RANDOM.nextBytes(nonce);

        IvParameterSpec spec = new IvParameterSpec(nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);

        byte[] ciphertext = cipher.doFinal(data);
        byte[] combined = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, combined, 0, nonce.length);
        System.arraycopy(ciphertext, 0, combined, nonce.length, ciphertext.length);
        return combined;
    }

    @Override
    public byte[] decrypt(byte[] encryptedData) throws GeneralSecurityException {
        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        System.arraycopy(encryptedData, 0, nonce, 0, nonce.length);

        byte[] ciphertext = new byte[encryptedData.length - nonce.length];
        System.arraycopy(encryptedData, nonce.length, ciphertext, 0, ciphertext.length);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(nonce));

        return cipher.doFinal(ciphertext);
    }
}
