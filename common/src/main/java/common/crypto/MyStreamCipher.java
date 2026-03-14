package common.crypto;

import common.Utils;
import common.crypto.prng.AesCtrKeystreamGenerator;

import java.security.GeneralSecurityException;
import java.util.Arrays;

public class MyStreamCipher implements SymmetricCipher {

    private static final int TAG_SIZE_BYTES = 16;
    private static final int NONCE_SIZE_BYTES = 12;

    private final AesCtrKeystreamGenerator keystreamGenerator;

    public MyStreamCipher() {
        byte[] key =  "0123456789abcdef".getBytes();
        this(key);
    }

    public MyStreamCipher(byte[] key) {
        this.keystreamGenerator = new AesCtrKeystreamGenerator(key);
    }


    @Override
    public byte[] encrypt(byte[] data) throws GeneralSecurityException {
        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        Utils.SECURE_RANDOM.nextBytes(nonce);

        byte[] keystream = keystreamGenerator.evaluate(nonce, data.length + 32);

        byte[] polyKey = Arrays.copyOfRange(keystream, 0, 32);
        byte[] encKey   = Arrays.copyOfRange(keystream, 32, 32 + data.length);

        byte[] ciphertext = new byte[data.length];

        for (int i = 0; i < data.length; i++) {
            ciphertext[i] = (byte) (encKey[i] ^ data[i]);
        }

        byte[] macInput = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, macInput, 0, nonce.length);
        System.arraycopy(ciphertext, 0, macInput, nonce.length, ciphertext.length);
        byte[] tag = Poly1305.computeTag(polyKey, macInput);

        byte[] out = new byte[nonce.length + ciphertext.length + TAG_SIZE_BYTES];
        System.arraycopy(nonce, 0, out, 0, nonce.length);
        System.arraycopy(ciphertext, 0, out, nonce.length, ciphertext.length);
        System.arraycopy(tag, 0, out, nonce.length + ciphertext.length, TAG_SIZE_BYTES);
        return out;
    }

    @Override
    public byte[] decrypt(byte[] data) throws GeneralSecurityException {
        if (data.length < NONCE_SIZE_BYTES + TAG_SIZE_BYTES) {
            throw new GeneralSecurityException("Ciphertext too short");
        }

        int ciphertextLen = data.length - NONCE_SIZE_BYTES - TAG_SIZE_BYTES;

        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        System.arraycopy(data, 0, nonce, 0, nonce.length);

        byte[] ciphertext = new byte[ciphertextLen];
        System.arraycopy(data, nonce.length, ciphertext, 0, ciphertext.length);

        byte[] receivedTag = new byte[TAG_SIZE_BYTES];

        byte[] keystream = keystreamGenerator.evaluate(nonce, ciphertext.length + 32);
        byte[] polyKey = Arrays.copyOfRange(keystream, 0, 32);
        byte[] encKey  = Arrays.copyOfRange(keystream, 32, 32 + ciphertextLen);

        byte[] macInput = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, macInput, 0, nonce.length);
        System.arraycopy(ciphertext, 0, macInput, nonce.length, ciphertext.length);
        byte[] expectedTag = Poly1305.computeTag(polyKey, macInput);

        if (!Poly1305.verifyTag(expectedTag, receivedTag)) {
            throw new GeneralSecurityException("Invalid authentication tag");
        }

        byte[] plaintext = new byte[ciphertext.length];

        for (int i = 0; i < ciphertext.length; i++) {
            plaintext[i] = (byte) (encKey[i] ^ ciphertext[i]);
        }

        return plaintext;
    }
}
