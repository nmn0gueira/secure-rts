package crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

class ConfigurableCipherTest {

    // 32-byte AES-256 key (64 hex chars)
    private static final String AES_KEY_HEX =
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    // 32-byte ChaCha20 key
    private static final String CHACHA_KEY_HEX =
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    private static final byte[] PLAINTEXT = "Configurable cipher roundtrip".getBytes();

    @BeforeAll
    static void setupBc() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void aesGcmRoundtripSeed() throws Exception {
        var cipher = new ConfigurableCipher("AES/GCM/NoPadding", AES_KEY_HEX.getBytes(), new SecureRandom());
        assertArrayEquals(PLAINTEXT, cipher.decrypt(cipher.encrypt(PLAINTEXT)));
    }

    @Test
    void chacha20Poly1305RoundtripSeed() throws Exception {
        var cipher = new ConfigurableCipher("ChaCha20-Poly1305", CHACHA_KEY_HEX.getBytes(), new SecureRandom());
        assertArrayEquals(PLAINTEXT, cipher.decrypt(cipher.encrypt(PLAINTEXT)));
    }

    @Test
    void aesGcmRoundtripSharedSecret() throws Exception {
        byte[] secret = "shared-secret-bytes-32pad!!!!!!!".getBytes();
        var cipher = new ConfigurableCipher("AES/GCM/NoPadding", secret, new SecureRandom());
        assertArrayEquals(PLAINTEXT, cipher.decrypt(cipher.encrypt(PLAINTEXT)));
    }

    @Test
    void chacha20Poly1305RoundtripSharedSecret() throws Exception {
        byte[] secret = "shared-secret-bytes-32pad!!!!!!!".getBytes();
        var cipher = new ConfigurableCipher("ChaCha20-Poly1305", secret, new SecureRandom());
        assertArrayEquals(PLAINTEXT, cipher.decrypt(cipher.encrypt(PLAINTEXT)));
    }

    @Test
    void ciphertextDiffersFromPlaintext() throws Exception {
        var cipher = new ConfigurableCipher("AES/GCM/NoPadding", AES_KEY_HEX.getBytes(), new SecureRandom());
        byte[] encrypted = cipher.encrypt(PLAINTEXT);
        assertFalse(java.util.Arrays.equals(PLAINTEXT, encrypted));
    }

    @Test
    void twoEncryptionsProduceDifferentCiphertexts() throws Exception {
        var cipher = new ConfigurableCipher("AES/GCM/NoPadding", AES_KEY_HEX.getBytes(), new SecureRandom());
        byte[] c1 = cipher.encrypt(PLAINTEXT);
        byte[] c2 = cipher.encrypt(PLAINTEXT);
        assertFalse(java.util.Arrays.equals(c1, c2));
    }
}
