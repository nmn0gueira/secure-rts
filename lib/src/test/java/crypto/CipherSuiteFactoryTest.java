package crypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class CipherSuiteFactoryTest {

    private static final String AES_KEY_HEX =
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    private static final String HMAC_KEY_HEX = "0102030405060708090a0b0c0d0e0f10";
    private static final byte[] PLAINTEXT = "factory test plaintext".getBytes();

    @Test
    void fromConfigAesGcmNoIntegrityRoundtrip() throws Exception {
        String config = "CONFIDENTIALITY:AES/GCM/NoPadding\n"
                + "SYMMETRIC_KEY:" + AES_KEY_HEX + "\n"
                + "INTEGRITY:NULL\n";
        CipherSuite suite = CipherSuiteFactory.fromConfig(config, null);

        assertNotNull(suite.cipher());
        assertFalse(suite.hasIntegrityCheck());
        assertArrayEquals(PLAINTEXT, suite.cipher().decrypt(suite.cipher().encrypt(PLAINTEXT)));
    }

    @Test
    void fromConfigChaCha20NoIntegrityRoundtrip() throws Exception {
        String config = "CONFIDENTIALITY:ChaCha20-Poly1305\n"
                + "SYMMETRIC_KEY:" + AES_KEY_HEX + "\n"
                + "INTEGRITY:NULL\n";
        CipherSuite suite = CipherSuiteFactory.fromConfig(config, null);

        assertNotNull(suite.cipher());
        assertFalse(suite.hasIntegrityCheck());
        assertArrayEquals(PLAINTEXT, suite.cipher().decrypt(suite.cipher().encrypt(PLAINTEXT)));
    }

    @Test
    void fromConfigDprgRoundtrip() throws Exception {
        String config = "CONFIDENTIALITY:DPRG\n"
                + "SYMMETRIC_KEY:0102030405060708090a0b0c0d0e0f10\n"
                + "INTEGRITY:NULL\n";
        CipherSuite suite = CipherSuiteFactory.fromConfig(config, null);

        assertNotNull(suite.cipher());
        assertFalse(suite.hasIntegrityCheck());
        assertArrayEquals(PLAINTEXT, suite.cipher().decrypt(suite.cipher().encrypt(PLAINTEXT)));
    }

    @Test
    void fromConfigWithHmacIntegrity() throws Exception {
        String config = "CONFIDENTIALITY:AES/GCM/NoPadding\n"
                + "SYMMETRIC_KEY:" + AES_KEY_HEX + "\n"
                + "INTEGRITY:MAC\n"
                + "MAC:HmacSHA256\n"
                + "MAC_KEY:" + HMAC_KEY_HEX + "\n";
        CipherSuite suite = CipherSuiteFactory.fromConfig(config, null);

        assertTrue(suite.hasIntegrityCheck());
        assertTrue(suite.usesMac());
        assertEquals(32, suite.integrityProofSize());
    }

    @Test
    void fromConfigAcceptsAssignmentFormatWithHmacNames() throws Exception {
        String config = "<cars.dat.encrypted>\n"
                + "ciphersuite: AES/GCM/NoPadding\n"
                + "key: " + AES_KEY_HEX + "\n"
                + "integrity: MAC\n"
                + "hmac: HMACSHA256\n"
                + "mackey: " + HMAC_KEY_HEX + "\n"
                + "</cars.dat.encrypted>\n";
        CipherSuite suite = CipherSuiteFactory.fromConfig(config, null);

        assertNotNull(suite.cipher());
        assertTrue(suite.hasIntegrityCheck());
        assertTrue(suite.usesMac());
        assertEquals(32, suite.integrityProofSize());
        assertArrayEquals(PLAINTEXT, suite.cipher().decrypt(suite.cipher().encrypt(PLAINTEXT)));
    }

    @Test
    void fromConfigAcceptsNullConfidentialityWithHashIntegrity() {
        String config = "<cars.dat.hash>\n"
                + "ciphersuite: NULL\n"
                + "integrity: H\n"
                + "hash: SHA-256\n"
                + "</cars.dat.hash>\n";
        CipherSuite suite = CipherSuiteFactory.fromConfig(config, null);

        assertNull(suite.cipher());
        assertTrue(suite.hasIntegrityCheck());
        assertFalse(suite.usesMac());
        assertEquals(32, suite.integrityProofSize());
    }

    @Test
    void fromConfigWithHashIntegrity() throws Exception {
        String config = "CONFIDENTIALITY:AES/GCM/NoPadding\n"
                + "SYMMETRIC_KEY:" + AES_KEY_HEX + "\n"
                + "INTEGRITY:H\n"
                + "H:SHA-256\n";
        CipherSuite suite = CipherSuiteFactory.fromConfig(config, null);

        assertTrue(suite.hasIntegrityCheck());
        assertFalse(suite.usesMac());
        assertEquals(32, suite.integrityProofSize());
    }

    @Test
    void fromConfigWithSharedSecretDerivesKey() throws Exception {
        byte[] secret = "test-shared-secret-32-bytes!!!!".getBytes();
        String config = "CONFIDENTIALITY:AES/GCM/NoPadding\nINTEGRITY:NULL\n";
        CipherSuite suite = CipherSuiteFactory.fromConfig(config, secret);

        assertNotNull(suite.cipher());
        assertArrayEquals(PLAINTEXT, suite.cipher().decrypt(suite.cipher().encrypt(PLAINTEXT)));
    }

    @Test
    void fromConfigDprgWithSharedSecretDerivesKey() throws Exception {
        byte[] secret = "test-shared-secret-32-bytes!!!!".getBytes();
        String config = "CONFIDENTIALITY:DPRG\nINTEGRITY:NULL\n";
        CipherSuite suite = CipherSuiteFactory.fromConfig(config, secret);

        assertNotNull(suite.cipher());
        assertArrayEquals(PLAINTEXT, suite.cipher().decrypt(suite.cipher().encrypt(PLAINTEXT)));
    }

    @Test
    void fromFileRoundtrip(@TempDir Path tmpDir) throws Exception {
        Path configFile = tmpDir.resolve("test.properties");
        Files.writeString(configFile,
                "# test config\n"
                + "CONFIDENTIALITY:AES/GCM/NoPadding\n"
                + "SYMMETRIC_KEY:" + AES_KEY_HEX + "\n"
                + "INTEGRITY:NULL\n");

        CipherSuite suite = CipherSuiteFactory.fromFile(configFile.toString());

        assertNotNull(suite.cipher());
        assertFalse(suite.hasIntegrityCheck());
        assertArrayEquals(PLAINTEXT, suite.cipher().decrypt(suite.cipher().encrypt(PLAINTEXT)));
    }

    @Test
    void fromFileSkipsNetworkAddressLines(@TempDir Path tmpDir) throws Exception {
        Path configFile = tmpDir.resolve("proxy.properties");
        Files.writeString(configFile,
                "remote:localhost:8888\n"
                + "CONFIDENTIALITY:AES/GCM/NoPadding\n"
                + "SYMMETRIC_KEY:" + AES_KEY_HEX + "\n"
                + "INTEGRITY:NULL\n");

        CipherSuite suite = CipherSuiteFactory.fromFile(configFile.toString());
        assertNotNull(suite.cipher());
    }

    @Test
    void sharedKeyCipherRoundtrip() throws Exception {
        byte[] key = new byte[32];
        SymmetricCipher cipher = CipherSuiteFactory.sharedKeyCipher(key);
        assertArrayEquals(PLAINTEXT, cipher.decrypt(cipher.encrypt(PLAINTEXT)));
    }

    @Test
    void hmacSha256StandaloneRoundtrip() throws Exception {
        byte[] key = new byte[32];
        IntegrityCheck ic = CipherSuiteFactory.hmacSha256(key);
        byte[] proof = ic.createIntegrityProof(PLAINTEXT);
        assertEquals(32, proof.length);
        assertTrue(ic.verifyIntegrity(PLAINTEXT, proof));
    }
}
