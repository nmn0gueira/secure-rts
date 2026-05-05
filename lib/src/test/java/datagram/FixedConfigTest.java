package datagram;

import common.Utils;
import crypto.CipherSuiteFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;


import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * A test class for the SecureDatagramSocket class
 */
class TestSecureDatagramSocket extends SecureDatagramSocket {

    public TestSecureDatagramSocket(String cryptoConfigFile) throws Exception {
        super(CipherSuiteFactory.fromFile(cryptoConfigFile));
    }

    public TestSecureDatagramSocket(String cryptoConfig, byte[] sharedSecret) throws Exception {
        super(CipherSuiteFactory.fromConfig(cryptoConfig, sharedSecret));
    }

    public void tamperedSend(DatagramPacket packet) throws Exception {
        Field secureSocketBaseField = SecureDatagramSocket.class.getDeclaredField("secureSocketBase");
        secureSocketBaseField.setAccessible(true);
        Object secureSocketBase = secureSocketBaseField.get(this);
        Method preparePacketForSendMethod = secureSocketBase.getClass()
            .getDeclaredMethod("preparePacketForSend", DatagramPacket.class);
        preparePacketForSendMethod.setAccessible(true);
        preparePacketForSendMethod.invoke(secureSocketBase, packet);

        byte[] data = packet.getData();
        data[data.length / 2] = (byte) (data[data.length / 2] + 1);

        Class<?> superClass = this.getClass().getSuperclass().getSuperclass();
        Method sendMethod = superClass.getDeclaredMethod("send", DatagramPacket.class);
        DatagramSocket socket = new DatagramSocket();
        sendMethod.invoke(socket, packet);
        socket.close();
    }
}

/**
 * A test class for the SecureDatagramSocket class (since SecureMulticastSocket and SecureDataSocket share the same functionality apart
 * from unchanged underlying methods, we only test SecureDatagramSocket)
 */
public class FixedConfigTest {
    private SecureDatagramSocket serverSocket;
    private SecureDatagramSocket clientSocket;
    private static final long TIMEOUT_MS = 3000;
    private static final byte[] sharedSecret = Utils.hexStringToByteArray("90f2a9e2b7feb204dbed990f4c7d01db8ec3bee3169207199593bc9181f636356c112b02c229fb450b0c713069ddfc84e22e45cd3c7727b45a32c6d0269692a2");

    private int setup(String config) throws Exception {
        serverSocket = new SecureDatagramSocket(CipherSuiteFactory.fromFile(config));
        clientSocket = new SecureDatagramSocket(CipherSuiteFactory.fromFile(config));
        return serverSocket.getLocalPort();
    }

    @AfterEach
    public void teardown() {
        if (serverSocket != null && !serverSocket.isClosed()) {
            serverSocket.close();
        }
        if (clientSocket != null && !clientSocket.isClosed()) {
            clientSocket.close();
        }
    }


    @ParameterizedTest
    @MethodSource("configFilesProvider")
    public void testSendAndReceive(String config) throws Exception {
        int port = setup(config);
        byte[] message = "Hello, Secure World!".getBytes();
        DatagramPacket sendPacket = new DatagramPacket(
                message, message.length, InetAddress.getLocalHost(), port);

        // Send the packet from the client in a separate thread
        new Thread(() -> {
            try {
                clientSocket.send(sendPacket);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();

        // Prepare to receive the packet on the server
        byte[] buffer = new byte[1024];
        DatagramPacket receivePacket = new DatagramPacket(buffer, buffer.length);
        serverSocket.receive(receivePacket);

        // Verify received message
        byte[] receivedData = new byte[receivePacket.getLength()];
        System.arraycopy(receivePacket.getData(), receivePacket.getOffset(), receivedData, 0, receivePacket.getLength());

        assertArrayEquals(message, receivedData, "The received message should match the sent message");
    }

    @ParameterizedTest
    @MethodSource({"configFilesProvider"})
    public void testSendAndReceiveMultiple(String config) throws Exception {
        int port = setup(config);
        byte[] message = "Hello, Secure World!".getBytes();

        // Send the packet from the client in a separate thread
        new Thread(() -> {
            try {
                for (int i = 0; i < 10; i++) {
                    DatagramPacket sendPacket = new DatagramPacket(
                            message, message.length, InetAddress.getLocalHost(), port);
                    clientSocket.send(sendPacket);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();


        for (int i = 0; i < 10; i++) {
            // Prepare to receive the packet on the server
            byte[] buffer = new byte[1024];
            DatagramPacket receivePacket = new DatagramPacket(buffer, buffer.length);
            serverSocket.receive(receivePacket);
            Thread.sleep(100);
            // Verify received message
            byte[] receivedData = new byte[receivePacket.getLength()];
            System.arraycopy(receivePacket.getData(), receivePacket.getOffset(), receivedData, 0, receivePacket.getLength());

            assertArrayEquals(message, receivedData, "The received message should match the sent message");
        }
    }

    // Worth noting that test configs that use nonces based on the sequence number will fail (and that is okay)
    @ParameterizedTest
    @MethodSource("configFilesProvider")
    public void testMessageReplaying(String config) throws Exception {
        int port = setup(config);
        AtomicInteger numberOfProcessedPackets = new AtomicInteger();
        byte[] message = "Hello, Secure World!".getBytes();
        // Start server in a separate thread
        Thread receiver = new Thread(() -> {
            try {
                while (true) {
                    DatagramPacket receivePacket = new DatagramPacket(new byte[1024], 1024);
                    serverSocket.receive(receivePacket);

                    byte[] receivedData = new byte[receivePacket.getLength()];
                    System.arraycopy(receivePacket.getData(), receivePacket.getOffset(), receivedData, 0, receivePacket.getLength());
                    assertArrayEquals(message, receivedData, "The received message should match the sent message");
                    numberOfProcessedPackets.getAndIncrement();
                }

            } catch (Exception ignored) {
            }
        });

        receiver.start();
        long startTime = System.currentTimeMillis();

        // Send packet with the same sequence number within the timeout
        while (System.currentTimeMillis() - startTime < TIMEOUT_MS) {
            DatagramPacket sendPacket = new DatagramPacket(
                    message, message.length, InetAddress.getLocalHost(), port);

            // Get the secureSocketBase of the client to access the sequence number
            Field secureSocketBaseField = SecureDatagramSocket.class.getDeclaredField("secureSocketBase");
            secureSocketBaseField.setAccessible(true); // Make it accessible
            Object secureSocketBase = secureSocketBaseField.get(clientSocket);
            Field sequenceNumberField = secureSocketBase.getClass().getDeclaredField("sequenceNumber");
            sequenceNumberField.setAccessible(true); // Make it accessible

            // Set sequence number to simulate a message replay attack
            sequenceNumberField.setInt(secureSocketBase, 0);

            clientSocket.send(sendPacket);
        }

        // Force stop the receiver thread
        serverSocket.close();
        // Only one packet should be processed
        assert numberOfProcessedPackets.get() == 1;
    }

    @ParameterizedTest
    @MethodSource("configFilesProvider")
    public void testMessageTampering(String config) throws Exception {
        int port = setup(config);
        AtomicInteger numberOfProcessedPackets = new AtomicInteger();
        clientSocket = new TestSecureDatagramSocket(config);
        byte[] message = "Hello, Secure World!".getBytes();


        // Start server in a separate thread
        new Thread(() -> {
            try {
                while (true) {
                    DatagramPacket receivePacket = new DatagramPacket(new byte[1024], 1024);
                    serverSocket.receive(receivePacket);


                    byte[] receivedData = new byte[receivePacket.getLength()];
                    System.arraycopy(receivePacket.getData(), receivePacket.getOffset(), receivedData, 0, receivePacket.getLength());
                    System.out.println(new String(receivedData));
                    assertArrayEquals(message, receivedData, "The received message should match the sent message");
                    numberOfProcessedPackets.getAndIncrement();
                }

                // Verify received message
            } catch (Exception ignored) {
            }
        }).start();

        // Send the packet from the client
        long startTime = System.currentTimeMillis();

        while (System.currentTimeMillis() - startTime < TIMEOUT_MS) {
            DatagramPacket sendPacket = new DatagramPacket(
                    message, message.length, InetAddress.getLocalHost(), port);
            ((TestSecureDatagramSocket) clientSocket).tamperedSend(sendPacket);

        }

        // Force stop the receiver thread
        serverSocket.close();

        // Verify that the server did not receive the tampered packet
        assert numberOfProcessedPackets.get() == 0;

    }

    static Stream<String> configFilesProvider() throws IOException, URISyntaxException {
        // Directory where your config files are stored
        Path configDir = Paths.get(Objects.requireNonNull(FixedConfigTest.class.getClassLoader().getResource("test-configs/fixed")).toURI());
        return Files.walk(configDir)
                .filter(Files::isRegularFile)
                .map(Path::toString);
    }
}
