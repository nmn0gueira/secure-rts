package common.crypto;

import common.Utils;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

public class AesGcmCipher implements SymmetricCipher{

    private static final int TAG_SIZE_BYTES = 16;
    private static final int TAG_SIZE_BITS = TAG_SIZE_BYTES * 8;
    private static final int NONCE_SIZE_BYTES = 12;

    private final Cipher cipher;
    private final SecretKeySpec keySpec;

    public AesGcmCipher() {
        byte[] key =  "0123456789abcdef".getBytes();
        this(key);
    }

    public AesGcmCipher(byte[] key) {
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        this.keySpec = new SecretKeySpec(key, "AES");
    }


    @Override
    public byte[] encrypt(byte[] data) throws GeneralSecurityException {
        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        Utils.SECURE_RANDOM.nextBytes(nonce);

        GCMParameterSpec spec = new GCMParameterSpec(TAG_SIZE_BITS, nonce);
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
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(TAG_SIZE_BITS, nonce));

        return cipher.doFinal(ciphertext);
    }
}
