package crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SymmetricCipherTest {

    private static final byte[] PLAINTEXT = "Hello, secure world!".getBytes();

    @Test
    void aesGcmRoundtrip() throws Exception {
        var cipher = new AesGcmCipher();
        assertArrayEquals(PLAINTEXT, cipher.decrypt(cipher.encrypt(PLAINTEXT)));
    }

    @Test
    void aesGcmRoundtripWithExplicitKey() throws Exception {
        byte[] key = new byte[32];
        var cipher = new AesGcmCipher(key);
        assertArrayEquals(PLAINTEXT, cipher.decrypt(cipher.encrypt(PLAINTEXT)));
    }

    @Test
    void aesGcmCiphertextDiffersFromPlaintext() throws Exception {
        var cipher = new AesGcmCipher();
        byte[] encrypted = cipher.encrypt(PLAINTEXT);
        assertFalse(java.util.Arrays.equals(PLAINTEXT, encrypted));
    }

    @Test
    void chacha20Roundtrip() throws Exception {
        var cipher = new ChaCha20Poly1305Cipher();
        assertArrayEquals(PLAINTEXT, cipher.decrypt(cipher.encrypt(PLAINTEXT)));
    }

    @Test
    void chacha20RoundtripWithExplicitKey() throws Exception {
        byte[] key = new byte[32];
        var cipher = new ChaCha20Poly1305Cipher(key);
        assertArrayEquals(PLAINTEXT, cipher.decrypt(cipher.encrypt(PLAINTEXT)));
    }

    @Test
    void myStreamCipherRoundtrip() throws Exception {
        var cipher = new MyStreamCipher();
        assertArrayEquals(PLAINTEXT, cipher.decrypt(cipher.encrypt(PLAINTEXT)));
    }

    @Test
    void myStreamCipherRoundtripWithExplicitKey() throws Exception {
        byte[] key = new byte[16];
        var cipher = new MyStreamCipher(key);
        assertArrayEquals(PLAINTEXT, cipher.decrypt(cipher.encrypt(PLAINTEXT)));
    }

    @Test
    void twoAesGcmEncryptionsOfSamePlaintextProduceDifferentCiphertexts() throws Exception {
        var cipher = new AesGcmCipher();
        byte[] c1 = cipher.encrypt(PLAINTEXT);
        byte[] c2 = cipher.encrypt(PLAINTEXT);
        assertFalse(java.util.Arrays.equals(c1, c2), "AEAD cipher should use a fresh nonce each time");
    }
}
