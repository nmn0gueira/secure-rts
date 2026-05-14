package shp;

import common.Utils;
import crypto.CipherSuiteFactory;
import datagram.SecureDatagramSocket;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import shp.client.ShpClient;
import shp.client.ShpClientOutput;
import shp.server.ShpServer;
import shp.server.ShpServerOutput;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class ShpTest {

    private static final int SHP_TCP_PORT = 7777;
    private static final int SHP_DSTP_TCP_PORT = 7778;
    private static final int UDP_PORT = 8888;
    private static final char[] PASSWORD = "changeit".toCharArray();

    private static String serverKsPath;
    private static String serverTsPath;
    private static String clientKsPath;
    private static String clientTsPath;
    private static String serverSuitesPath;
    private static String clientSuitesPath;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        Path tempDir = Files.createTempDirectory("shp-test");
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

        String suitesContent = "[SHP_AES_256_GCM]\nCONFIDENTIALITY:AES/GCM/NoPadding\nINTEGRITY:NULL\n";
        serverSuitesPath = tempDir.resolve("server-suites.conf").toAbsolutePath().toString();
        clientSuitesPath = tempDir.resolve("client-suites.conf").toAbsolutePath().toString();
        Files.writeString(Path.of(serverSuitesPath), suitesContent);
        Files.writeString(Path.of(clientSuitesPath), suitesContent);
    }

    private static void keytool(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        int exit = p.waitFor();
        if (exit != 0) throw new RuntimeException("keytool failed: " + Arrays.toString(cmd));
    }

    @Test
    public void shpTest() throws Exception {
        Set<String> requests = new HashSet<>();
        requests.add("request");
        ShpServer shpServer = new ShpServer(SHP_TCP_PORT, serverKsPath, serverTsPath,
                serverSuitesPath, requests, PASSWORD);

        new Thread(() -> {
            try {
                ShpServerOutput sOutput = shpServer.runProtocolServer();
                System.out.println("User request received: " + sOutput.request());
                System.out.println("Udp port received: " + sOutput.udpPort());
                System.out.println("Shared key received:\n" + Utils.byteArrayToHexString(sOutput.sharedSecret()));
                System.out.println("Server thread finished");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();

        Thread.sleep(1000);

        ShpClient shpClient = new ShpClient("localhost", SHP_TCP_PORT, clientKsPath, clientTsPath,
                clientSuitesPath, PASSWORD);
        byte[] udpPortBytes = ByteBuffer.allocate(4).putInt(UDP_PORT).array();
        ShpClientOutput cOutput = shpClient.runProtocolClient("request", udpPortBytes);
        System.out.println("Crypto config received:\n" + cOutput.cryptoConfig());
        System.out.println("Shared key received:\n" + Utils.byteArrayToHexString(cOutput.sharedSecret()));
        System.out.println("Client thread finished");
    }

    @Test
    public void shpAndDstpTest() throws Exception {
        Set<String> requests = new HashSet<>();
        requests.add("request");
        ShpServer shpServer = new ShpServer(SHP_DSTP_TCP_PORT, serverKsPath, serverTsPath,
                serverSuitesPath, requests, PASSWORD);

        new Thread(() -> {
            try {
                ShpServerOutput sOutput = shpServer.runProtocolServer();
                SecureDatagramSocket dstpSender = new SecureDatagramSocket(
                        CipherSuiteFactory.fromConfig(sOutput.cryptoConfig(), sOutput.sharedSecret()));
                byte[] message = "Hello, Secure World!".getBytes();
                Thread.sleep(3000);
                DatagramPacket sendPacket = new DatagramPacket(message, message.length,
                        InetAddress.getLocalHost(), UDP_PORT);
                dstpSender.send(sendPacket);
                dstpSender.close();
                System.out.println("Server thread finished");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();

        Thread.sleep(1000);

        ShpClient shpClient = new ShpClient("localhost", SHP_DSTP_TCP_PORT, clientKsPath, clientTsPath,
                clientSuitesPath, PASSWORD);
        byte[] udpPortBytes = ByteBuffer.allocate(4).putInt(UDP_PORT).array();
        ShpClientOutput cOutput = shpClient.runProtocolClient("request", udpPortBytes);

        SecureDatagramSocket dstpReceiver = new SecureDatagramSocket(UDP_PORT,
                CipherSuiteFactory.fromConfig(cOutput.cryptoConfig(), cOutput.sharedSecret()));
        dstpReceiver.setSoTimeout(10000);

        DatagramPacket receivePacket = new DatagramPacket(new byte[1024], 1024);
        dstpReceiver.receive(receivePacket);

        byte[] receivedData = new byte[receivePacket.getLength()];
        System.arraycopy(receivePacket.getData(), receivePacket.getOffset(), receivedData, 0, receivePacket.getLength());
        System.out.println("Received message: " + new String(receivedData));
        dstpReceiver.close();
        System.out.println("Client thread finished");
    }
}
