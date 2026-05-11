package shp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyFactory;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.*;

class ShpCryptoSpecTest {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void signAndVerifyWithOwnKey() throws Exception {
        var spec = new ShpCryptoSpec();
        byte[] data = "data to sign".getBytes();
        byte[] sig = spec.sign(data);
        assertTrue(spec.verifySignature(spec.getEcPublicKey(), data, sig));
    }

    @Test
    void verifyFailsForTamperedData() throws Exception {
        var spec = new ShpCryptoSpec();
        byte[] sig = spec.sign("original".getBytes());
        assertFalse(spec.verifySignature(spec.getEcPublicKey(), "tampered".getBytes(), sig));
    }

    @Test
    void verifyFailsWithWrongPublicKey() throws Exception {
        var spec1 = new ShpCryptoSpec();
        var spec2 = new ShpCryptoSpec();
        byte[] data = "signed by spec1".getBytes();
        byte[] sig = spec1.sign(data);
        assertFalse(spec2.verifySignature(spec2.getEcPublicKey(), data, sig));
    }

    @Test
    void asymmetricEncryptDecryptSameInstance() throws Exception {
        var spec = new ShpCryptoSpec();
        byte[] plaintext = "ECIES test".getBytes();
        byte[] encrypted = spec.asymmetricEncrypt(plaintext, spec.getEcPublicKey());
        byte[] decrypted = spec.asymmetricDecrypt(encrypted);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void asymmetricEncryptDecryptCrossInstance() throws Exception {
        var sender = new ShpCryptoSpec();
        var receiver = new ShpCryptoSpec();
        byte[] plaintext = "cross-instance ECIES".getBytes();
        byte[] encrypted = sender.asymmetricEncrypt(plaintext, receiver.getEcPublicKey());
        byte[] decrypted = receiver.asymmetricDecrypt(encrypted);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void ecdhSharedSecretsMatch() throws Exception {
        var spec1 = new ShpCryptoSpec();
        var spec2 = new ShpCryptoSpec();

        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        var pub1 = kf.generatePublic(new X509EncodedKeySpec(spec1.getEcdhPublicKeyBytes()));
        var pub2 = kf.generatePublic(new X509EncodedKeySpec(spec2.getEcdhPublicKeyBytes()));

        byte[] secret1 = spec1.generateSharedSecret(pub2);
        byte[] secret2 = spec2.generateSharedSecret(pub1);

        assertArrayEquals(secret1, secret2);
    }

    @Test
    void generateNonceHasCorrectSize() {
        byte[] nonce = ShpCryptoSpec.generateNonce();
        assertEquals(ShpCryptoSpec.NONCE_SIZE, nonce.length);
    }

    @Test
    void generateIterationBytesHasFourBytes() {
        byte[] iter = ShpCryptoSpec.generateIterationBytes();
        assertEquals(4, iter.length);
    }

    @Test
    void loadPublicKeyRoundtrip() throws Exception {
        var spec = new ShpCryptoSpec();
        byte[] encoded = spec.getEcPublicKeyBytes();
        var loaded = ShpCryptoSpec.loadPublicKey(encoded);
        assertArrayEquals(encoded, loaded.getEncoded());
    }

    @Test
    void ecPublicKeyEncodingIsNotEmpty() {
        var spec = new ShpCryptoSpec();
        byte[] encoded = spec.getEcPublicKeyBytes();
        assertNotNull(encoded);
        assertTrue(encoded.length > 0);
    }

    @Test
    void certificateBytesFallbackToPublicKeyWhenNoCertificate() throws Exception {
        var spec = new ShpCryptoSpec();
        assertArrayEquals(spec.getEcPublicKeyBytes(), spec.getCertificateBytes());
    }

    @Test
    void ecdhPublicKeyBytesAreNotEmpty() {
        var spec = new ShpCryptoSpec();
        byte[] ecdh = spec.getEcdhPublicKeyBytes();
        assertNotNull(ecdh);
        assertTrue(ecdh.length > 0);
    }
}
