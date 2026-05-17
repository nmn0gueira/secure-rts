package shp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import shp.client.ShpClientOutput;
import shp.pq.client.HybridShpClient;
import shp.pq.client.PqShpClient;
import shp.pq.server.HybridShpServer;
import shp.pq.server.PqShpServer;
import shp.server.ShpServerOutput;

import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class PqShpTest {

    private static final int UDP_PORT = 9876;
    private static final char[] PASSWORD = "changeit".toCharArray();

    private static String serverKsPath;
    private static String serverTsPath;
    private static String clientKsPath;
    private static String clientTsPath;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());

        Path tempDir = Files.createTempDirectory("pq-shp-test");
        String td = tempDir.toAbsolutePath().toString();

        serverKsPath = td + "/server-ks.p12";
        serverTsPath = td + "/server-ts.p12";
        clientKsPath = td + "/client-ks.p12";
        clientTsPath = td + "/client-ts.p12";
        String serverCertPath = td + "/server.crt";
        String clientCertPath = td + "/client.crt";

        String kt = System.getProperty("java.home") + "/bin/keytool";
        String pw = new String(PASSWORD);

        keytool(kt, "-genkeypair", "-alias", "server", "-keyalg", "ML-DSA", "-sigalg", "ML-DSA-65",
                "-validity", "3650", "-storetype", "PKCS12",
                "-keystore", serverKsPath, "-storepass", pw, "-keypass", pw,
                "-dname", "CN=server", "-noprompt");

        keytool(kt, "-genkeypair", "-alias", "client", "-keyalg", "ML-DSA", "-sigalg", "ML-DSA-65",
                "-validity", "3650", "-storetype", "PKCS12",
                "-keystore", clientKsPath, "-storepass", pw, "-keypass", pw,
                "-dname", "CN=client", "-noprompt");

        keytool(kt, "-exportcert", "-rfc", "-alias", "server",
                "-keystore", serverKsPath, "-storepass", pw, "-file", serverCertPath);

        keytool(kt, "-exportcert", "-rfc", "-alias", "client",
                "-keystore", clientKsPath, "-storepass", pw, "-file", clientCertPath);

        keytool(kt, "-importcert", "-noprompt", "-alias", "client",
                "-file", clientCertPath, "-storetype", "PKCS12",
                "-keystore", serverTsPath, "-storepass", pw);

        keytool(kt, "-importcert", "-noprompt", "-alias", "server",
                "-file", serverCertPath, "-storetype", "PKCS12",
                "-keystore", clientTsPath, "-storepass", pw);
    }

    static Stream<Arguments> suiteConfigs() {
        return Stream.of(
            Arguments.of(
                "AES/GCM/NoPadding",
                "[SUITE]\nCONFIDENTIALITY:AES/GCM/NoPadding\nINTEGRITY:NULL\n"),
            Arguments.of(
                "ChaCha20-Poly1305",
                "[SUITE]\nCONFIDENTIALITY:ChaCha20-Poly1305\nINTEGRITY:NULL\n"),
            Arguments.of(
                "AES/CBC + HMAC-SHA256",
                "[SUITE]\nCONFIDENTIALITY:AES/CBC/PKCS5Padding\nINTEGRITY:MAC\nMAC:HmacSHA256\n")
        );
    }

    @ParameterizedTest(name = "Hybrid SHP - {0}")
    @MethodSource("suiteConfigs")
    void hybridHandshakeCompletes(String label, String suiteContent) throws Exception {
        int port = findFreePort();
        Path tempDir = Files.createTempDirectory("hybrid-shp-iter");
        Path serverSuites = tempDir.resolve("server.conf");
        Path clientSuites = tempDir.resolve("client.conf");
        Files.writeString(serverSuites, suiteContent);
        Files.writeString(clientSuites, suiteContent);

        HybridShpServer server = new HybridShpServer(port, serverKsPath, serverTsPath,
                serverSuites.toString(), Set.of("movie"), PASSWORD);

        CompletableFuture<ShpServerOutput> serverFuture = CompletableFuture.supplyAsync(() -> {
            try { return server.runProtocolServer(); }
            catch (Exception e) { throw new RuntimeException(e); }
        });

        Thread.sleep(300);

        HybridShpClient client = new HybridShpClient("localhost", port, clientKsPath, clientTsPath,
                clientSuites.toString(), PASSWORD);
        byte[] udpPortBytes = ByteBuffer.allocate(4).putInt(UDP_PORT).array();
        ShpClientOutput cOutput = client.runProtocolClient("movie", udpPortBytes);
        ShpServerOutput sOutput = serverFuture.get(10, TimeUnit.SECONDS);

        assertNotNull(cOutput.cipherSuite());
        assertNotNull(sOutput.cipherSuite());
        assertEquals("movie", sOutput.request());
        assertEquals(UDP_PORT, sOutput.udpPort());
    }

    @ParameterizedTest(name = "Full PQ SHP - {0}")
    @MethodSource("suiteConfigs")
    void fullPqHandshakeCompletes(String label, String suiteContent) throws Exception {
        int port = findFreePort();
        Path tempDir = Files.createTempDirectory("pq-shp-iter");
        Path serverSuites = tempDir.resolve("server.conf");
        Path clientSuites = tempDir.resolve("client.conf");
        Files.writeString(serverSuites, suiteContent);
        Files.writeString(clientSuites, suiteContent);

        PqShpServer server = new PqShpServer(port, serverKsPath, serverTsPath,
                serverSuites.toString(), Set.of("movie"), PASSWORD);

        CompletableFuture<ShpServerOutput> serverFuture = CompletableFuture.supplyAsync(() -> {
            try { return server.runProtocolServer(); }
            catch (Exception e) { throw new RuntimeException(e); }
        });

        Thread.sleep(300);

        PqShpClient client = new PqShpClient("localhost", port, clientKsPath, clientTsPath,
                clientSuites.toString(), PASSWORD);
        byte[] udpPortBytes = ByteBuffer.allocate(4).putInt(UDP_PORT).array();
        ShpClientOutput cOutput = client.runProtocolClient("movie", udpPortBytes);
        ShpServerOutput sOutput = serverFuture.get(10, TimeUnit.SECONDS);

        assertNotNull(cOutput.cipherSuite());
        assertNotNull(sOutput.cipherSuite());
        assertEquals("movie", sOutput.request());
        assertEquals(UDP_PORT, sOutput.udpPort());
    }

    private static void keytool(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        if (p.waitFor() != 0) throw new RuntimeException("keytool failed: " + Arrays.toString(cmd));
    }

    private static int findFreePort() throws Exception {
        try (ServerSocket s = new ServerSocket(0)) { return s.getLocalPort(); }
    }
}
