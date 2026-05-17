package shp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import shp.client.ShpClient;
import shp.client.ShpClientOutput;
import shp.pq.client.HybridShpClient;
import shp.pq.client.PqShpClient;
import shp.pq.server.HybridShpServer;
import shp.pq.server.PqShpServer;
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

public class PqShpHandshakeTimingTest {

    private static final int ITERATIONS = 10;
    private static final int UDP_PORT = 19999;
    private static final char[] PASSWORD = "changeit".toCharArray();

    // Classic ECDSA/ECDH keystores
    private static String classicServerKsPath;
    private static String classicServerTsPath;
    private static String classicClientKsPath;
    private static String classicClientTsPath;

    // Dilithium keystores (shared by Hybrid and Full PQ)
    private static String pqServerKsPath;
    private static String pqServerTsPath;
    private static String pqClientKsPath;
    private static String pqClientTsPath;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());

        Path tempDir = Files.createTempDirectory("pq-timing-test");
        String td = tempDir.toAbsolutePath().toString();

        // Classic keystores via keytool
        classicServerKsPath = td + "/classic-server-ks.p12";
        classicServerTsPath = td + "/classic-server-ts.p12";
        classicClientKsPath = td + "/classic-client-ks.p12";
        classicClientTsPath = td + "/classic-client-ts.p12";
        String classicServerCertPath = td + "/classic-server.crt";
        String classicClientCertPath = td + "/classic-client.crt";

        String kt = System.getProperty("java.home") + "/bin/keytool";
        String pw = new String(PASSWORD);

        keytool(kt, "-genkeypair", "-alias", "server", "-keyalg", "EC",
                "-groupname", "secp256r1", "-sigalg", "SHA256withECDSA",
                "-validity", "3650", "-storetype", "PKCS12",
                "-keystore", classicServerKsPath, "-storepass", pw, "-keypass", pw,
                "-dname", "CN=server", "-noprompt");

        keytool(kt, "-genkeypair", "-alias", "client", "-keyalg", "EC",
                "-groupname", "secp256r1", "-sigalg", "SHA256withECDSA",
                "-validity", "3650", "-storetype", "PKCS12",
                "-keystore", classicClientKsPath, "-storepass", pw, "-keypass", pw,
                "-dname", "CN=client", "-noprompt");

        keytool(kt, "-exportcert", "-rfc", "-alias", "server",
                "-keystore", classicServerKsPath, "-storepass", pw, "-file", classicServerCertPath);

        keytool(kt, "-exportcert", "-rfc", "-alias", "client",
                "-keystore", classicClientKsPath, "-storepass", pw, "-file", classicClientCertPath);

        keytool(kt, "-importcert", "-noprompt", "-alias", "client",
                "-file", classicClientCertPath, "-storetype", "PKCS12",
                "-keystore", classicServerTsPath, "-storepass", pw);

        keytool(kt, "-importcert", "-noprompt", "-alias", "server",
                "-file", classicServerCertPath, "-storetype", "PKCS12",
                "-keystore", classicClientTsPath, "-storepass", pw);

        // PQ keystores via keytool (ML-DSA, Java 25)
        pqServerKsPath = td + "/pq-server-ks.p12";
        pqServerTsPath = td + "/pq-server-ts.p12";
        pqClientKsPath = td + "/pq-client-ks.p12";
        pqClientTsPath = td + "/pq-client-ts.p12";
        String pqServerCertPath = td + "/pq-server.crt";
        String pqClientCertPath = td + "/pq-client.crt";

        keytool(kt, "-genkeypair", "-alias", "server", "-keyalg", "ML-DSA", "-sigalg", "ML-DSA-65",
                "-validity", "3650", "-storetype", "PKCS12",
                "-keystore", pqServerKsPath, "-storepass", pw, "-keypass", pw,
                "-dname", "CN=server", "-noprompt");

        keytool(kt, "-genkeypair", "-alias", "client", "-keyalg", "ML-DSA", "-sigalg", "ML-DSA-65",
                "-validity", "3650", "-storetype", "PKCS12",
                "-keystore", pqClientKsPath, "-storepass", pw, "-keypass", pw,
                "-dname", "CN=client", "-noprompt");

        keytool(kt, "-exportcert", "-rfc", "-alias", "server",
                "-keystore", pqServerKsPath, "-storepass", pw, "-file", pqServerCertPath);

        keytool(kt, "-exportcert", "-rfc", "-alias", "client",
                "-keystore", pqClientKsPath, "-storepass", pw, "-file", pqClientCertPath);

        keytool(kt, "-importcert", "-noprompt", "-alias", "client",
                "-file", pqClientCertPath, "-storetype", "PKCS12",
                "-keystore", pqServerTsPath, "-storepass", pw);

        keytool(kt, "-importcert", "-noprompt", "-alias", "server",
                "-file", pqServerCertPath, "-storetype", "PKCS12",
                "-keystore", pqClientTsPath, "-storepass", pw);
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

    @ParameterizedTest(name = "Classic SHP (ECDSA + ECDH) - {0}")
    @MethodSource("suiteConfigs")
    void classicHandshakeTiming(String label, String suiteContent) throws Exception {
        long[] durations = runHandshakes(label, suiteContent, "classic");
        printTimings("Classic  (ECDSA+ECDH)  " + label, durations);
    }

    @ParameterizedTest(name = "Hybrid SHP (ML-DSA + ECDH) - {0}")
    @MethodSource("suiteConfigs")
    void hybridHandshakeTiming(String label, String suiteContent) throws Exception {
        long[] durations = runHandshakes(label, suiteContent, "hybrid");
        printTimings("Hybrid   (ML-DSA+ECDH) " + label, durations);
    }

    @ParameterizedTest(name = "Full PQ SHP (ML-DSA + ML-KEM) - {0}")
    @MethodSource("suiteConfigs")
    void fullPqHandshakeTiming(String label, String suiteContent) throws Exception {
        long[] durations = runHandshakes(label, suiteContent, "fullpq");
        printTimings("Full PQ  (ML-DSA+MLKEM)" + label, durations);
    }

    private long[] runHandshakes(String label, String suiteContent, String variant) throws Exception {
        long[] durations = new long[ITERATIONS];
        byte[] udpPortBytes = ByteBuffer.allocate(4).putInt(UDP_PORT).array();

        for (int i = 0; i < ITERATIONS; i++) {
            int port = findFreePort();

            Path tempDir = Files.createTempDirectory("pq-timing-iter");
            Path serverSuites = tempDir.resolve("server.conf");
            Path clientSuites = tempDir.resolve("client.conf");
            Files.writeString(serverSuites, suiteContent);
            Files.writeString(clientSuites, suiteContent);

            long start;
            ShpClientOutput cOutput;

            switch (variant) {
                case "classic" -> {
                    ShpServer server = new ShpServer(port, classicServerKsPath, classicServerTsPath,
                            serverSuites.toString(), Set.of("movie"), PASSWORD);
                    CompletableFuture<ShpServerOutput> sf = CompletableFuture.supplyAsync(() -> {
                        try { return server.runProtocolServer(); }
                        catch (Exception e) { throw new RuntimeException(e); }
                    });
                    Thread.sleep(200);
                    ShpClient client = new ShpClient("localhost", port, classicClientKsPath, classicClientTsPath,
                            clientSuites.toString(), PASSWORD);
                    start = System.nanoTime();
                    cOutput = client.runProtocolClient("movie", udpPortBytes);
                    durations[i] = System.nanoTime() - start;
                    assertNotNull(sf.get(5, TimeUnit.SECONDS).cipherSuite());
                }
                case "hybrid" -> {
                    HybridShpServer server = new HybridShpServer(port, pqServerKsPath, pqServerTsPath,
                            serverSuites.toString(), Set.of("movie"), PASSWORD);
                    CompletableFuture<ShpServerOutput> sf = CompletableFuture.supplyAsync(() -> {
                        try { return server.runProtocolServer(); }
                        catch (Exception e) { throw new RuntimeException(e); }
                    });
                    Thread.sleep(200);
                    HybridShpClient client = new HybridShpClient("localhost", port, pqClientKsPath, pqClientTsPath,
                            clientSuites.toString(), PASSWORD);
                    start = System.nanoTime();
                    cOutput = client.runProtocolClient("movie", udpPortBytes);
                    durations[i] = System.nanoTime() - start;
                    assertNotNull(sf.get(5, TimeUnit.SECONDS).cipherSuite());
                }
                default -> {
                    PqShpServer server = new PqShpServer(port, pqServerKsPath, pqServerTsPath,
                            serverSuites.toString(), Set.of("movie"), PASSWORD);
                    CompletableFuture<ShpServerOutput> sf = CompletableFuture.supplyAsync(() -> {
                        try { return server.runProtocolServer(); }
                        catch (Exception e) { throw new RuntimeException(e); }
                    });
                    Thread.sleep(200);
                    PqShpClient client = new PqShpClient("localhost", port, pqClientKsPath, pqClientTsPath,
                            clientSuites.toString(), PASSWORD);
                    start = System.nanoTime();
                    cOutput = client.runProtocolClient("movie", udpPortBytes);
                    durations[i] = System.nanoTime() - start;
                    assertNotNull(sf.get(5, TimeUnit.SECONDS).cipherSuite());
                }
            }
            assertNotNull(cOutput.cipherSuite());
        }
        return durations;
    }

    private static void printTimings(String label, long[] durations) {
        long minMs = Arrays.stream(durations).min().getAsLong() / 1_000_000;
        long maxMs = Arrays.stream(durations).max().getAsLong() / 1_000_000;
        long avgMs = (long) Arrays.stream(durations).average().getAsDouble() / 1_000_000;
        System.out.printf("%-46s  iterations=%d  min=%d ms  avg=%d ms  max=%d ms%n",
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
