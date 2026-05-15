package shp;

import crypto.CertificateUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import shp.client.ShpClient;
import shp.client.ShpClientOutput;
import shp.message.ShpClientHello;
import shp.message.ShpServerHello;
import shp.protocol.ShpProtocolResult;
import shp.protocol.ShpServerProtocol;
import shp.protocol.State;
import shp.server.ShpServer;
import shp.server.ShpServerOutput;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Security;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class ShpSuiteNegotiationTest {

    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final String TEST_REQUEST = "test-request";
    private static final byte[] CLIENT_HELLO_HEADER = {0x11, 0x00};
    private static final AtomicInteger PORT = new AtomicInteger(19000);

    private static String serverKsPath;
    private static String serverTsPath;
    private static String clientKsPath;
    private static String clientTsPath;
    private static Path tempDir;

    private static CertificateUtils.Identity serverIdentity;
    private static CertificateUtils.Identity clientIdentity;
    private static KeyStore serverTrustStore;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        tempDir = Files.createTempDirectory("shp-neg-test");
        String td = tempDir.toAbsolutePath().toString();

        serverKsPath = td + "/server-keystore.p12";
        serverTsPath = td + "/server-truststore.p12";
        clientKsPath = td + "/client-keystore.p12";
        clientTsPath = td + "/client-truststore.p12";
        String serverCert = td + "/server.crt";
        String clientCert = td + "/client.crt";

        String kt = System.getProperty("java.home") + "/bin/keytool";
        String pw = new String(PASSWORD);

        keytool(kt, "-genkeypair", "-alias", "server", "-keyalg", "EC",
                "-groupname", "secp256r1", "-sigalg", "SHA256withECDSA",
                "-validity", "3650", "-storetype", "PKCS12",
                "-keystore", serverKsPath, "-storepass", pw, "-keypass", pw,
                "-dname", "CN=server", "-noprompt");

        keytool(kt, "-genkeypair", "-alias", "client", "-keyalg", "EC",
                "-groupname", "secp256r1", "-sigalg", "SHA256withECDSA",
                "-validity", "3650", "-storetype", "PKCS12",
                "-keystore", clientKsPath, "-storepass", pw, "-keypass", pw,
                "-dname", "CN=client", "-noprompt");

        keytool(kt, "-exportcert", "-rfc", "-alias", "server",
                "-keystore", serverKsPath, "-storepass", pw, "-file", serverCert);

        keytool(kt, "-exportcert", "-rfc", "-alias", "client",
                "-keystore", clientKsPath, "-storepass", pw, "-file", clientCert);

        keytool(kt, "-importcert", "-noprompt", "-alias", "client",
                "-file", clientCert, "-storetype", "PKCS12",
                "-keystore", serverTsPath, "-storepass", pw);

        keytool(kt, "-importcert", "-noprompt", "-alias", "server",
                "-file", serverCert, "-storetype", "PKCS12",
                "-keystore", clientTsPath, "-storepass", pw);

        serverIdentity = CertificateUtils.loadIdentity(serverKsPath, PASSWORD);
        clientIdentity = CertificateUtils.loadIdentity(clientKsPath, PASSWORD);
        serverTrustStore = CertificateUtils.loadKeyStore(serverTsPath, PASSWORD);
    }

    private static void keytool(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        int exit = p.waitFor();
        if (exit != 0) throw new RuntimeException("keytool failed: " + Arrays.toString(cmd));
    }

    private ShpCryptoSpec freshServerSpec() {
        return new ShpCryptoSpec(serverIdentity.privateKey(), serverIdentity.certificate());
    }

    private ShpCryptoSpec freshClientSpec() {
        return new ShpCryptoSpec(clientIdentity.privateKey(), clientIdentity.certificate());
    }

    private ShpClientHello buildSignedClientHello(List<String> suites) throws Exception {
        ShpCryptoSpec spec = freshClientSpec();
        ShpClientHello hello = new ShpClientHello(
                TEST_REQUEST,
                spec.getCertificateBytes(),
                spec.getEcdhPublicKeyBytes(),
                suites,
                ShpCryptoSpec.generateNonce());
        hello.sign(spec);
        return hello;
    }

    private ShpServerProtocol newServerProtocol(LinkedHashMap<String, String> suites) {
        ShpServerProtocol p = new ShpServerProtocol(freshServerSpec(), serverTrustStore, null);
        p.setServerSuites(suites);
        return p;
    }

    @Test
    void serverPreferenceWinsOverClientOrder() throws Exception {
        LinkedHashMap<String, String> serverSuites = new LinkedHashMap<>();
        serverSuites.put("SHP_AES_256_GCM", "CONFIDENTIALITY:AES/GCM/NoPadding\nINTEGRITY:NULL\n");
        serverSuites.put("SHP_CHACHA20_POLY1305", "CONFIDENTIALITY:ChaCha20-Poly1305\nINTEGRITY:NULL\n");

        // Client advertises ChaCha first (client's preference), then GCM
        ShpClientHello hello = buildSignedClientHello(List.of("SHP_CHACHA20_POLY1305", "SHP_AES_256_GCM"));
        ShpProtocolResult result = newServerProtocol(serverSuites)
                .handle(hello.toShpMessage(CLIENT_HELLO_HEADER));

        assertEquals(State.WAITING, result.state());
        ShpServerHello serverHello = ShpServerHello.from(result.response().get());
        assertEquals("SHP_AES_256_GCM", serverHello.selectedSuiteName());
    }

    @Test
    void serverPicksFirstMatchingClientSuite() throws Exception {
        LinkedHashMap<String, String> serverSuites = new LinkedHashMap<>();
        serverSuites.put("SHP_AES_256_GCM", "CONFIDENTIALITY:AES/GCM/NoPadding\nINTEGRITY:NULL\n");
        serverSuites.put("SHP_CHACHA20_POLY1305", "CONFIDENTIALITY:ChaCha20-Poly1305\nINTEGRITY:NULL\n");
        serverSuites.put("SHP_AES_256_CBC_HMAC_SHA256",
                "CONFIDENTIALITY:AES/CBC/NoPadding\nINTEGRITY:MAC\nMAC:HmacSHA256\n");

        // Client only supports the third option on the server's list
        ShpClientHello hello = buildSignedClientHello(List.of("SHP_AES_256_CBC_HMAC_SHA256"));
        ShpProtocolResult result = newServerProtocol(serverSuites)
                .handle(hello.toShpMessage(CLIENT_HELLO_HEADER));

        assertEquals(State.WAITING, result.state());
        ShpServerHello serverHello = ShpServerHello.from(result.response().get());
        assertEquals("SHP_AES_256_CBC_HMAC_SHA256", serverHello.selectedSuiteName());
    }

    @Test
    void noCommonSuiteReturnsError() throws Exception {
        LinkedHashMap<String, String> serverSuites = new LinkedHashMap<>();
        serverSuites.put("SHP_AES_256_GCM", "CONFIDENTIALITY:AES/GCM/NoPadding\nINTEGRITY:NULL\n");

        ShpClientHello hello = buildSignedClientHello(List.of("SHP_CHACHA20_POLY1305"));
        ShpProtocolResult result = newServerProtocol(serverSuites)
                .handle(hello.toShpMessage(CLIENT_HELLO_HEADER));

        assertEquals(State.ERROR, result.state());
    }

    @Test
    void unknownSuiteNameReturnsError() throws Exception {
        LinkedHashMap<String, String> serverSuites = new LinkedHashMap<>();
        serverSuites.put("SHP_AES_256_GCM", "CONFIDENTIALITY:AES/GCM/NoPadding\nINTEGRITY:NULL\n");

        ShpClientHello hello = buildSignedClientHello(List.of("SHP_UNKNOWN_SUITE_XYZ"));
        ShpProtocolResult result = newServerProtocol(serverSuites)
                .handle(hello.toShpMessage(CLIENT_HELLO_HEADER));

        assertEquals(State.ERROR, result.state());
    }

    @Test
    void emptySuiteListReturnsError() throws Exception {
        LinkedHashMap<String, String> serverSuites = new LinkedHashMap<>();
        serverSuites.put("SHP_AES_256_GCM", "CONFIDENTIALITY:AES/GCM/NoPadding\nINTEGRITY:NULL\n");

        ShpClientHello hello = buildSignedClientHello(List.of());
        ShpProtocolResult result = newServerProtocol(serverSuites)
                .handle(hello.toShpMessage(CLIENT_HELLO_HEADER));

        assertEquals(State.ERROR, result.state());
    }


    static Stream<Arguments> suiteParameters() {
        return Stream.of(
                Arguments.of("SHP_AES_256_GCM",
                        "CONFIDENTIALITY:AES/GCM/NoPadding\nINTEGRITY:NULL\n"),
                Arguments.of("SHP_CHACHA20_POLY1305",
                        "CONFIDENTIALITY:ChaCha20-Poly1305\nINTEGRITY:NULL\n"),
                Arguments.of("SHP_AES_256_CBC_HMAC_SHA256",
                        "CONFIDENTIALITY:AES/CBC/NoPadding\nINTEGRITY:MAC\nMAC:HmacSHA256\n"),
                Arguments.of("SHP_CHACHA20_HMAC_SHA256",
                        "CONFIDENTIALITY:ChaCha20\nINTEGRITY:MAC\nMAC:HmacSHA256\n"),
                Arguments.of("SHP_DPRG_HMAC_SHA256",
                        "CONFIDENTIALITY:DPRG\nINTEGRITY:MAC\nMAC:HmacSHA256\n")
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("suiteParameters")
    void eachSuiteNegotiatesSuccessfully(String suiteName, String suiteBody) throws Exception {
        int port = PORT.getAndIncrement();

        Path suiteFile = tempDir.resolve(suiteName + ".conf");
        Files.writeString(suiteFile, "[" + suiteName + "]\n" + suiteBody);
        String suitePath = suiteFile.toAbsolutePath().toString();

        ShpServer server = new ShpServer(port, serverKsPath, serverTsPath, suitePath,
                Set.of(TEST_REQUEST), PASSWORD);
        CompletableFuture<ShpServerOutput> serverFuture = CompletableFuture.supplyAsync(() -> {
            try { return server.runProtocolServer(); }
            catch (Exception e) { throw new RuntimeException(e); }
        });

        Thread.sleep(500);

        byte[] udpPortBytes = ByteBuffer.allocate(4).putInt(54321).array();
        ShpClient client = new ShpClient("localhost", port, clientKsPath, clientTsPath,
                suitePath, PASSWORD);
        ShpClientOutput clientOut = client.runProtocolClient(TEST_REQUEST, udpPortBytes);
        ShpServerOutput serverOut = serverFuture.get(10, TimeUnit.SECONDS);

        assertNotNull(serverOut.cipherSuite(), "Server cipher suite not built for " + suiteName);
        assertNotNull(clientOut.cipherSuite(), "Client cipher suite not built for " + suiteName);
    }

    @Test
    void serverPreferenceWinsInFullHandshake() throws Exception {
        int port = PORT.getAndIncrement();

        // Server prefers GCM over ChaCha
        String serverConf =
                "[SHP_AES_256_GCM]\nCONFIDENTIALITY:AES/GCM/NoPadding\nINTEGRITY:NULL\n\n" +
                "[SHP_CHACHA20_POLY1305]\nCONFIDENTIALITY:ChaCha20-Poly1305\nINTEGRITY:NULL\n";

        String clientConf =
                "[SHP_CHACHA20_POLY1305]\nCONFIDENTIALITY:ChaCha20-Poly1305\nINTEGRITY:NULL\n\n" +
                "[SHP_AES_256_GCM]\nCONFIDENTIALITY:AES/GCM/NoPadding\nINTEGRITY:NULL\n";

        Path serverSuiteFile = tempDir.resolve("server-multi.conf");
        Path clientSuiteFile = tempDir.resolve("client-multi.conf");
        Files.writeString(serverSuiteFile, serverConf);
        Files.writeString(clientSuiteFile, clientConf);

        ShpServer server = new ShpServer(port, serverKsPath, serverTsPath,
                serverSuiteFile.toString(), Set.of(TEST_REQUEST), PASSWORD);
        CompletableFuture<ShpServerOutput> serverFuture = CompletableFuture.supplyAsync(() -> {
            try { return server.runProtocolServer(); }
            catch (Exception e) { throw new RuntimeException(e); }
        });

        Thread.sleep(500);

        byte[] udpPortBytes = ByteBuffer.allocate(4).putInt(54321).array();
        ShpClient client = new ShpClient("localhost", port, clientKsPath, clientTsPath,
                clientSuiteFile.toString(), PASSWORD);
        ShpClientOutput clientOut = client.runProtocolClient(TEST_REQUEST, udpPortBytes);
        ShpServerOutput serverOut = serverFuture.get(10, TimeUnit.SECONDS);

        assertNotNull(serverOut.cipherSuite());
        assertNotNull(clientOut.cipherSuite());
    }
}
