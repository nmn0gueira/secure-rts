package crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

class DhKeyAgreementTest {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void twoPartiesComputeSameSharedSecret() throws Exception {
        var alice = new DhKeyAgreement();
        var bob = new DhKeyAgreement();

        alice.doPhase(bob.getPublicKey());
        bob.doPhase(alice.getPublicKey());

        byte[] secretAlice = alice.generateSecret();
        byte[] secretBob = bob.generateSecret();

        assertArrayEquals(secretAlice, secretBob);
    }

    @Test
    void publicKeyIsNotNull() {
        var dh = new DhKeyAgreement();
        assertNotNull(dh.getPublicKey());
    }

    @Test
    void publicKeyEncodingIsNotEmpty() {
        var dh = new DhKeyAgreement();
        byte[] encoded = dh.getPublicKey().getEncoded();
        assertNotNull(encoded);
        assertTrue(encoded.length > 0);
    }

    @Test
    void differentInstancesHaveDifferentPublicKeys() {
        var a = new DhKeyAgreement();
        var b = new DhKeyAgreement();
        assertFalse(java.util.Arrays.equals(
                a.getPublicKey().getEncoded(),
                b.getPublicKey().getEncoded()));
    }

    @Test
    void sharedSecretIsNotEmpty() throws Exception {
        var alice = new DhKeyAgreement();
        var bob = new DhKeyAgreement();
        alice.doPhase(bob.getPublicKey());
        byte[] secret = alice.generateSecret();
        assertNotNull(secret);
        assertTrue(secret.length > 0);
    }
}
