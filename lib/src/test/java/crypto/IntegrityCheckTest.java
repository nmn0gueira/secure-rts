package crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

class IntegrityCheckTest {

    private static final String HMAC_KEY_HEX = "0102030405060708090a0b0c0d0e0f10";
    private static final byte[] DATA = "integrity check test data".getBytes();

    @BeforeAll
    static void setupBc() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void hmacSha256ProofIsCorrectSize() throws Exception {
        var ic = new ConfigurableIntegrityCheck(true, null, "HmacSHA256", HMAC_KEY_HEX.getBytes());
        assertEquals(32, ic.getIntegrityProofSize());
        assertEquals(32, ic.createIntegrityProof(DATA).length);
    }

    @Test
    void hmacIsMac() throws Exception {
        var ic = new ConfigurableIntegrityCheck(true, null, "HmacSHA256", HMAC_KEY_HEX.getBytes());
        assertTrue(ic.isMac());
    }

    @Test
    void hmacSha256IsDeterministic() throws Exception {
        var ic = new ConfigurableIntegrityCheck(true, null, "HmacSHA256", HMAC_KEY_HEX.getBytes());
        byte[] p1 = ic.createIntegrityProof(DATA);
        byte[] p2 = ic.createIntegrityProof(DATA);
        assertArrayEquals(p1, p2);
    }

    @Test
    void hmacSha256DiffersOnDifferentData() throws Exception {
        var ic = new ConfigurableIntegrityCheck(true, null, "HmacSHA256", HMAC_KEY_HEX.getBytes());
        byte[] p1 = ic.createIntegrityProof(DATA);
        byte[] p2 = ic.createIntegrityProof("other data".getBytes());
        assertFalse(java.util.Arrays.equals(p1, p2));
    }

    @Test
    void sha256HashProofIsCorrectSize() throws Exception {
        var ic = new ConfigurableIntegrityCheck(false, "SHA-256", null, (byte[]) null);
        assertEquals(32, ic.getIntegrityProofSize());
        assertEquals(32, ic.createIntegrityProof(DATA).length);
    }

    @Test
    void sha256HashIsNotMac() throws Exception {
        var ic = new ConfigurableIntegrityCheck(false, "SHA-256", null, (byte[]) null);
        assertFalse(ic.isMac());
    }

    @Test
    void sha256HashIsDeterministic() throws Exception {
        var ic = new ConfigurableIntegrityCheck(false, "SHA-256", null, (byte[]) null);
        byte[] p1 = ic.createIntegrityProof(DATA);
        byte[] p2 = ic.createIntegrityProof(DATA);
        assertArrayEquals(p1, p2);
    }

    @Test
    void sha256HashDiffersOnDifferentData() throws Exception {
        var ic = new ConfigurableIntegrityCheck(false, "SHA-256", null, (byte[]) null);
        byte[] p1 = ic.createIntegrityProof(DATA);
        byte[] p2 = ic.createIntegrityProof("other".getBytes());
        assertFalse(java.util.Arrays.equals(p1, p2));
    }

    @Test
    void hmacWithSharedSecretRoundtrip() throws Exception {
        byte[] secret = "a shared secret for hmac".getBytes();
        var ic = new ConfigurableIntegrityCheck(true, null, "HmacSHA256", secret);
        byte[] proof = ic.createIntegrityProof(DATA);
        assertEquals(32, proof.length);
    }

    @Test
    void verifyIntegrityPassesForMatchingProof() throws Exception {
        var ic = new ConfigurableIntegrityCheck(true, null, "HmacSHA256", HMAC_KEY_HEX.getBytes());
        byte[] proof = ic.createIntegrityProof(DATA);
        assertTrue(ic.verifyIntegrity(DATA, proof));
    }

    @Test
    void verifyIntegrityFailsForTamperedData() throws Exception {
        var ic = new ConfigurableIntegrityCheck(true, null, "HmacSHA256", HMAC_KEY_HEX.getBytes());
        byte[] proof = ic.createIntegrityProof(DATA);
        assertFalse(ic.verifyIntegrity("tampered".getBytes(), proof));
    }
}
