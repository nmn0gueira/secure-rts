package shp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import shp.client.ShpClient;
import shp.client.ShpClientOutput;
import shp.server.ShpServer;
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

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ShpHandshakeTimingTest {

    private static final int ITERATIONS = 20;
    private static final int UDP_PORT = 9999;
    private static final char[] PASSWORD = "changeit".toCharArray();

    private static String serverKsPath;
    private static String serverTsPath;
    private static String clientKsPath;
    private static String clientTsPath;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        Path tempDir = Files.createTempDirectory("shp-timing-test");
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
                "AES/CBC/PKCS5Padding + HMAC-SHA256",
                "[SUITE]\nCONFIDENTIALITY:AES/CBC/PKCS5Padding\nINTEGRITY:MAC\nMAC:HmacSHA256\n")
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("suiteConfigs")
    void handshakeTiming(String label, String suiteContent) throws Exception {
        long[] durations = new long[ITERATIONS];
        byte[] udpPortBytes = ByteBuffer.allocate(4).putInt(UDP_PORT).array();

        for (int i = 0; i < ITERATIONS; i++) {
            int port = findFreePort();

            Path tempDir = Files.createTempDirectory("shp-timing-iter");
            Path serverSuites = tempDir.resolve("server.conf");
            Path clientSuites = tempDir.resolve("client.conf");
            Files.writeString(serverSuites, suiteContent);
            Files.writeString(clientSuites, suiteContent);

            ShpServer server = new ShpServer(port, serverKsPath, serverTsPath,
                    serverSuites.toString(), Set.of("movie"), PASSWORD);

            CompletableFuture<ShpServerOutput> serverFuture = CompletableFuture.supplyAsync(() -> {
                try { return server.runProtocolServer(); }
                catch (Exception e) { throw new RuntimeException(e); }
            });

            Thread.sleep(200);

            ShpClient client = new ShpClient("localhost", port, clientKsPath, clientTsPath,
                    clientSuites.toString(), PASSWORD);

            long start = System.nanoTime();
            ShpClientOutput output = client.runProtocolClient("movie", udpPortBytes);
            durations[i] = System.nanoTime() - start;

            ShpServerOutput sOutput = serverFuture.get(5, TimeUnit.SECONDS);
            assertNotNull(output.cipherSuite());
            assertNotNull(sOutput.cipherSuite());
        }

        long minMs = Arrays.stream(durations).min().getAsLong() / 1_000_000;
        long maxMs = Arrays.stream(durations).max().getAsLong() / 1_000_000;
        long avgMs = (long) Arrays.stream(durations).average().getAsDouble() / 1_000_000;

        System.out.printf("%-40s  iterations=%d  min=%d ms  avg=%d ms  max=%d ms%n",
                label, ITERATIONS, minMs, avgMs, maxMs);
    }

    private static int findFreePort() throws Exception {
        try (ServerSocket s = new ServerSocket(0)) { return s.getLocalPort(); }
    }

    private static void keytool(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        if (p.waitFor() != 0) throw new RuntimeException("keytool failed: " + Arrays.toString(cmd));
    }
}
