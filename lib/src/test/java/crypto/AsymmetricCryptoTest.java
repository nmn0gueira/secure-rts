package crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.*;

class AsymmetricCryptoTest {

    private static KeyPair ecKeyPair1;
    private static KeyPair ecKeyPair2;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        ecKeyPair1 = gen.generateKeyPair();
        ecKeyPair2 = gen.generateKeyPair();
    }

    // --- EciesCipher ---

    @Test
    void eciesEncryptDecryptRoundtrip() throws Exception {
        byte[] plaintext = "ECIES roundtrip test".getBytes();
        var cipher = new EciesCipher();
        byte[] encrypted = cipher.encrypt(plaintext, ecKeyPair1.getPublic());
        byte[] decrypted = cipher.decrypt(encrypted, ecKeyPair1.getPrivate());
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void eciesCrossKeyRoundtrip() throws Exception {
        byte[] plaintext = "cross-key ECIES".getBytes();
        var cipher = new EciesCipher();
        byte[] encrypted = cipher.encrypt(plaintext, ecKeyPair2.getPublic());
        byte[] decrypted = cipher.decrypt(encrypted, ecKeyPair2.getPrivate());
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void eciesDecryptWithWrongKeyFails() {
        byte[] plaintext = "wrong key test".getBytes();
        var cipher = new EciesCipher();
        assertThrows(Exception.class, () -> {
            byte[] encrypted = cipher.encrypt(plaintext, ecKeyPair1.getPublic());
            cipher.decrypt(encrypted, ecKeyPair2.getPrivate());
        });
    }

    @Test
    void eciesCiphertextDiffersFromPlaintext() throws Exception {
        byte[] plaintext = "ECIES plaintext".getBytes();
        var cipher = new EciesCipher();
        byte[] encrypted = cipher.encrypt(plaintext, ecKeyPair1.getPublic());
        assertFalse(java.util.Arrays.equals(plaintext, encrypted));
    }

    // --- EcdsaSignature ---

    @Test
    void ecdsaSignAndVerify() throws Exception {
        byte[] data = "data to sign".getBytes();
        var sig = new EcdsaSignature();
        byte[] signature = sig.sign(ecKeyPair1.getPrivate(), data);
        assertTrue(sig.verify(ecKeyPair1.getPublic(), data, signature));
    }

    @Test
    void ecdsaVerifyTamperedDataFails() throws Exception {
        byte[] data = "original data".getBytes();
        var sig = new EcdsaSignature();
        byte[] signature = sig.sign(ecKeyPair1.getPrivate(), data);
        assertFalse(sig.verify(ecKeyPair1.getPublic(), "tampered data".getBytes(), signature));
    }

    @Test
    void ecdsaVerifyWithWrongKeyFails() throws Exception {
        byte[] data = "signed data".getBytes();
        var sig = new EcdsaSignature();
        byte[] signature = sig.sign(ecKeyPair1.getPrivate(), data);
        assertFalse(sig.verify(ecKeyPair2.getPublic(), data, signature));
    }

    @Test
    void ecdsaSignatureIsNotEmpty() throws Exception {
        var sig = new EcdsaSignature();
        byte[] signature = sig.sign(ecKeyPair1.getPrivate(), "test".getBytes());
        assertNotNull(signature);
        assertTrue(signature.length > 0);
    }
}
