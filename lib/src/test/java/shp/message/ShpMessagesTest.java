package shp.message;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import shp.ShpCryptoSpec;

import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ShpMessagesTest {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static ShpCryptoSpec testSpec() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return new ShpCryptoSpec(gen.generateKeyPair().getPrivate(), null);
    }

    @Test
    void clientHelloRoundtrip() throws Exception {
        ShpClientHello hello = new ShpClientHello(
                "cars.dat",
                new byte[] { 1, 2 },
                new byte[] { 3, 4 },
                List.of("AES/GCM/NoPadding", "ChaCha20-Poly1305"),
                new byte[] { 5, 6 });
        ShpCryptoSpec spec = testSpec();
        hello.setSignature(spec.sign(hello.bytesToSign()));

        ShpClientHello parsed = ShpClientHello.from(hello.toShpMessage(new byte[] { 1, 0 }));

        assertEquals(hello.request(), parsed.request());
        assertEquals(hello.cipherSuites(), parsed.cipherSuites());
        assertArrayEquals(hello.clientCertificate(), parsed.clientCertificate());
        assertArrayEquals(hello.clientEcdhPublicKey(), parsed.clientEcdhPublicKey());
        assertArrayEquals(hello.clientNonce(), parsed.clientNonce());
        assertArrayEquals(hello.clientSignature(), parsed.clientSignature());
        assertArrayEquals(hello.bytesToSign(), parsed.bytesToSign());
    }

    @Test
    void serverHelloRoundtrip() throws Exception {
        ShpServerHello hello = new ShpServerHello(
                new byte[] { 1, 2 },
                new byte[] { 3, 4 },
                "SHP_AES_256_GCM",
                new byte[] { 5, 6 },
                new byte[] { 7, 8 });
        ShpCryptoSpec spec2 = testSpec();
        hello.setSignature(spec2.sign(hello.bytesToSign()));

        ShpServerHello parsed = ShpServerHello.from(hello.toShpMessage(new byte[] { 1, 1 }));

        assertEquals(hello.selectedSuiteName(), parsed.selectedSuiteName());
        assertArrayEquals(hello.serverCertificate(), parsed.serverCertificate());
        assertArrayEquals(hello.serverEcdhPublicKey(), parsed.serverEcdhPublicKey());
        assertArrayEquals(hello.serverNonce(), parsed.serverNonce());
        assertArrayEquals(hello.clientNonceResponse(), parsed.clientNonceResponse());
        assertArrayEquals(hello.serverSignature(), parsed.serverSignature());
        assertArrayEquals(hello.bytesToSign(), parsed.bytesToSign());
    }

    @Test
    void csspRoundtrip() {
        ShpCssp finish = new ShpCssp(
                new byte[] { 1, 2, 3 },
                new byte[] { 4, 5 });

        ShpCssp parsed = ShpCssp.from(finish.toShpMessage(new byte[] { 1, 2 }));

        assertArrayEquals(finish.encryptedPayload(), parsed.encryptedPayload());
        assertArrayEquals(finish.integrityProof(), parsed.integrityProof());
    }
}
