package crypto;

import common.Utils;
import crypto.prng.AesCtrKeystreamGenerator;

import java.security.GeneralSecurityException;

public class MyStreamCipher implements SymmetricCipher {

    private static final int TAG_SIZE_BYTES = 16;
    private static final int TAG_SIZE_BITS = TAG_SIZE_BYTES * 8;
    private static final int NONCE_SIZE_BYTES = 12;

    private final AesCtrKeystreamGenerator keyStream;

    public MyStreamCipher() {
        byte[] key =  "0123456789abcdef".getBytes();
        this(key);
    }

    public MyStreamCipher(byte[] key) {
        this.keyStream = new AesCtrKeystreamGenerator(key);
    }


    @Override
    public byte[] encrypt(byte[] data) throws GeneralSecurityException {
        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        Utils.SECURE_RANDOM.nextBytes(nonce);

        byte[] key = keyStream.evaluate(nonce, data.length);
        byte[] ciphertext = new byte[data.length];

        for (int i = 0; i < data.length; i++) {
            ciphertext[i] = (byte) (key[i] ^ data[i]);
        }

        byte[] combined = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, combined, 0, nonce.length);
        System.arraycopy(ciphertext, 0, combined, nonce.length, ciphertext.length);
        return combined;
    }

    @Override
    public byte[] decrypt(byte[] data) throws GeneralSecurityException {
        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        System.arraycopy(data, 0, nonce, 0, nonce.length);

        byte[] ciphertext = new byte[data.length - nonce.length];
        System.arraycopy(data, nonce.length, ciphertext, 0, ciphertext.length);

        byte[] key = keyStream.evaluate(nonce, ciphertext.length);
        byte[] decrypted = new byte[ciphertext.length];

        for (int i = 0; i < ciphertext.length; i++) {
            decrypted[i] = (byte) (key[i] ^ ciphertext[i]);
        }

        return decrypted;
    }
}
