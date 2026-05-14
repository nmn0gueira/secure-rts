package shp;

import crypto.CertificateUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.*;

class ShpCryptoSpecTest {

    private static CertificateUtils.Identity identity1;
    private static CertificateUtils.Identity identity2;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        Path tempDir = Files.createTempDirectory("shp-crypto-spec-test");
        identity1 = generateIdentity(tempDir, "entity1");
        identity2 = generateIdentity(tempDir, "entity2");
    }

    private static CertificateUtils.Identity generateIdentity(Path tempDir, String name) throws Exception {
        String ksPath = tempDir.resolve(name + ".p12").toAbsolutePath().toString();
        String kt = System.getProperty("java.home") + "/bin/keytool";
        String pw = "changeit";
        new ProcessBuilder(kt, "-genkeypair", "-alias", name,
                "-keyalg", "EC", "-groupname", "secp256r1", "-sigalg", "SHA256withECDSA",
                "-validity", "3650", "-storetype", "PKCS12",
                "-keystore", ksPath, "-storepass", pw, "-keypass", pw,
                "-dname", "CN=" + name, "-noprompt")
                .redirectErrorStream(true).start().waitFor();
        return CertificateUtils.loadIdentity(ksPath, pw.toCharArray());
    }

    private static ShpCryptoSpec testSpec(CertificateUtils.Identity identity) {
        return new ShpCryptoSpec(identity.privateKey(), identity.certificate());
    }

    @Test
    void signAndVerifyWithOwnKey() throws Exception {
        var spec = testSpec(identity1);
        byte[] data = "data to sign".getBytes();
        byte[] sig = spec.sign(data);
        assertTrue(spec.verifySignature(spec.getEcPublicKey(), data, sig));
    }

    @Test
    void verifyFailsForTamperedData() throws Exception {
        var spec = testSpec(identity1);
        byte[] sig = spec.sign("original".getBytes());
        assertFalse(spec.verifySignature(spec.getEcPublicKey(), "tampered".getBytes(), sig));
    }

    @Test
    void verifyFailsWithWrongPublicKey() throws Exception {
        var spec1 = testSpec(identity1);
        var spec2 = testSpec(identity2);
        byte[] data = "signed by spec1".getBytes();
        byte[] sig = spec1.sign(data);
        assertFalse(spec2.verifySignature(spec2.getEcPublicKey(), data, sig));
    }

    @Test
    void ecdhSharedSecretsMatch() throws Exception {
        var spec1 = testSpec(identity1);
        var spec2 = testSpec(identity1);

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
    void loadPublicKeyRoundtrip() throws Exception {
        var spec = testSpec(identity1);
        byte[] encoded = spec.getEcPublicKeyBytes();
        var loaded = ShpCryptoSpec.loadPublicKey(encoded);
        assertArrayEquals(encoded, loaded.getEncoded());
    }

    @Test
    void ecPublicKeyEncodingIsNotEmpty() throws Exception {
        var spec = testSpec(identity1);
        byte[] encoded = spec.getEcPublicKeyBytes();
        assertNotNull(encoded);
        assertTrue(encoded.length > 0);
    }

    @Test
    void getCertificateBytesThrowsWhenNoCertificate() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        var spec = new ShpCryptoSpec(gen.generateKeyPair().getPrivate(), null);
        assertThrows(IllegalStateException.class, spec::getCertificateBytes);
    }

    @Test
    void ecdhPublicKeyBytesAreNotEmpty() throws Exception {
        var spec = testSpec(identity1);
        byte[] ecdh = spec.getEcdhPublicKeyBytes();
        assertNotNull(ecdh);
        assertTrue(ecdh.length > 0);
    }
}
