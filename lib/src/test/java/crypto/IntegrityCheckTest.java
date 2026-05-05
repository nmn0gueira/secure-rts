package crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

class IntegrityCheckTest {

    private static final String HMAC_KEY_HEX = "0102030405060708090a0b0c0d0e0f10";
    private static final byte[] DATA = "integrity check test data".getBytes();
    private static final byte[] NONCE = new byte[16];

    @BeforeAll
    static void setupBc() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void hmacSha256ProofIsCorrectSize() throws Exception {
        var ic = new ConfigurableIntegrityCheck(true, null, "HmacSHA256", HMAC_KEY_HEX);
        assertEquals(32, ic.getIntegrityProofSize());
        assertEquals(32, ic.createIntegrityProof(DATA, NONCE).length);
    }

    @Test
    void hmacIsMac() throws Exception {
        var ic = new ConfigurableIntegrityCheck(true, null, "HmacSHA256", HMAC_KEY_HEX);
        assertTrue(ic.isMac());
    }

    @Test
    void hmacSha256IsDeterministic() throws Exception {
        var ic = new ConfigurableIntegrityCheck(true, null, "HmacSHA256", HMAC_KEY_HEX);
        byte[] p1 = ic.createIntegrityProof(DATA, NONCE);
        byte[] p2 = ic.createIntegrityProof(DATA, NONCE);
        assertArrayEquals(p1, p2);
    }

    @Test
    void hmacSha256DiffersOnDifferentData() throws Exception {
        var ic = new ConfigurableIntegrityCheck(true, null, "HmacSHA256", HMAC_KEY_HEX);
        byte[] p1 = ic.createIntegrityProof(DATA, NONCE);
        byte[] p2 = ic.createIntegrityProof("other data".getBytes(), NONCE);
        assertFalse(java.util.Arrays.equals(p1, p2));
    }

    @Test
    void sha256HashProofIsCorrectSize() throws Exception {
        var ic = new ConfigurableIntegrityCheck(false, "SHA-256", null, (String) null);
        assertEquals(32, ic.getIntegrityProofSize());
        assertEquals(32, ic.createIntegrityProof(DATA, NONCE).length);
    }

    @Test
    void sha256HashIsNotMac() throws Exception {
        var ic = new ConfigurableIntegrityCheck(false, "SHA-256", null, (String) null);
        assertFalse(ic.isMac());
    }

    @Test
    void sha256HashIsDeterministic() throws Exception {
        var ic = new ConfigurableIntegrityCheck(false, "SHA-256", null, (String) null);
        byte[] p1 = ic.createIntegrityProof(DATA, NONCE);
        byte[] p2 = ic.createIntegrityProof(DATA, NONCE);
        assertArrayEquals(p1, p2);
    }

    @Test
    void sha256HashDiffersOnDifferentData() throws Exception {
        var ic = new ConfigurableIntegrityCheck(false, "SHA-256", null, (String) null);
        byte[] p1 = ic.createIntegrityProof(DATA, NONCE);
        byte[] p2 = ic.createIntegrityProof("other".getBytes(), NONCE);
        assertFalse(java.util.Arrays.equals(p1, p2));
    }

    @Test
    void hmacWithSharedSecretRoundtrip() throws Exception {
        byte[] secret = "a shared secret for hmac".getBytes();
        var ic = new ConfigurableIntegrityCheck(true, null, "HmacSHA256", secret);
        byte[] proof = ic.createIntegrityProof(DATA, NONCE);
        assertEquals(32, proof.length);
    }

    @Test
    void verifyIntegrityPassesForMatchingProof() throws Exception {
        var ic = new ConfigurableIntegrityCheck(true, null, "HmacSHA256", HMAC_KEY_HEX);
        byte[] proof = ic.createIntegrityProof(DATA, NONCE);
        assertTrue(ic.verifyIntegrity(DATA, NONCE, proof));
    }

    @Test
    void verifyIntegrityFailsForTamperedData() throws Exception {
        var ic = new ConfigurableIntegrityCheck(true, null, "HmacSHA256", HMAC_KEY_HEX);
        byte[] proof = ic.createIntegrityProof(DATA, NONCE);
        assertFalse(ic.verifyIntegrity("tampered".getBytes(), NONCE, proof));
    }
}
