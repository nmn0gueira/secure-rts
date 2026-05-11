package shp.message;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ShpMessagesTest {

    @Test
    void clientHelloRoundtrip() {
        ShpClientHello hello = new ShpClientHello(
                "cars.dat",
                new byte[] { 1, 2 },
                new byte[] { 3, 4 },
                List.of("AES/GCM/NoPadding", "ChaCha20-Poly1305"),
                new byte[] { 5, 6 },
                new byte[] { 7, 8 });

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
    void serverHelloRoundtrip() {
        ShpServerHello hello = new ShpServerHello(
                "cars.dat",
                true,
                new byte[] { 1, 2 },
                new byte[] { 3, 4 },
                "ciphersuite: AES/GCM/NoPadding\nintegrity: NULL",
                new byte[] { 5, 6 },
                new byte[] { 7, 8 },
                new byte[] { 9, 10 });

        ShpServerHello parsed = ShpServerHello.from(hello.toShpMessage(new byte[] { 1, 1 }));

        assertEquals(hello.request(), parsed.request());
        assertEquals(hello.clientCertificateAccepted(), parsed.clientCertificateAccepted());
        assertEquals(hello.selectedCryptoConfig(), parsed.selectedCryptoConfig());
        assertArrayEquals(hello.serverCertificate(), parsed.serverCertificate());
        assertArrayEquals(hello.serverEcdhPublicKey(), parsed.serverEcdhPublicKey());
        assertArrayEquals(hello.serverNonce(), parsed.serverNonce());
        assertArrayEquals(hello.clientNonceResponse(), parsed.clientNonceResponse());
        assertArrayEquals(hello.serverSignature(), parsed.serverSignature());
        assertArrayEquals(hello.bytesToSign(), parsed.bytesToSign());
    }

    @Test
    void clientFinishRoundtrip() {
        ShpClientFinish finish = new ShpClientFinish(
                new byte[] { 1, 2, 3 },
                new byte[] { 4, 5 });

        ShpClientFinish parsed = ShpClientFinish.from(finish.toShpMessage(new byte[] { 1, 2 }));

        assertArrayEquals(finish.encryptedPayload(), parsed.encryptedPayload());
        assertArrayEquals(finish.integrityProof(), parsed.integrityProof());
    }
}
