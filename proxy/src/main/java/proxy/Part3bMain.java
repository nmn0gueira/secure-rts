package proxy;

import crypto.CipherSuite;
import datagram.SecureDatagramSocket;
import datagram.StreamControl;
import shp.pq.client.PqShpClient;
import shp.client.ShpClientOutput;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

public class Part3bMain {

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("Usage: Part3bMain <server-host> <shp-port> <movie-name>");
            System.err.println();
            System.err.println("server-host   hostname or IP of the server");
            System.err.println("shp-port      TCP port the server listens on for SHP");
            System.err.println("movie-name    name of the movie to request");
            System.exit(1);
        }

        String serverHost = args[0];
        int shpPort = Integer.parseInt(args[1]);
        String movieName = args[2];

        Properties config = loadConfig("proxy/config.properties");
        String remote = config.getProperty("remote");
        String destinations = config.getProperty("localdelivery");
        String keystorePath = config.getProperty("pq.keystore");
        String truststorePath = config.getProperty("pq.truststore");
        char[] password = config.getProperty("pq.password").toCharArray();

        int localUdpPort = Integer.parseInt(remote.split(":")[1]);
        byte[] udpPortBytes = ByteBuffer.allocate(4).putInt(localUdpPort).array();

        PqShpClient shpClient = new PqShpClient(serverHost, shpPort, keystorePath, truststorePath,
                "proxy/cipher-suites.conf", password);
        ShpClientOutput out = shpClient.runProtocolClient(movieName, udpPortBytes);

        System.out.println("SHP complete. Receiving '" + movieName + "' on " + remote
                + ", forwarding to " + destinations + " ...");

        CipherSuite suite = out.cipherSuite();

        SocketAddress inAddr = parseSocketAddress(remote);
        Set<SocketAddress> outAddrs = Arrays.stream(destinations.split(","))
                .map(Part3bMain::parseSocketAddress)
                .collect(Collectors.toSet());

        try (SecureDatagramSocket inSocket = new SecureDatagramSocket(inAddr, suite);
             DatagramSocket outSocket = new DatagramSocket()) {
            byte[] buffer = new byte[4 * 1024];
            while (true) {
                DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
                inSocket.receive(inPacket);
                if (StreamControl.isFinishFrame(buffer, inPacket.getLength())) {
                    System.out.println("\nStream finished.");
                    break;
                }
                System.out.print(".");
                for (SocketAddress out2 : outAddrs) {
                    outSocket.send(new DatagramPacket(buffer, inPacket.getLength(), out2));
                }
            }
        }
    }

    private static Properties loadConfig(String path) throws IOException {
        Properties props = new Properties();
        try (InputStream in = new FileInputStream(path)) {
            props.load(in);
        }
        return props;
    }

    private static InetSocketAddress parseSocketAddress(String s) {
        String[] parts = s.trim().split(":");
        return new InetSocketAddress(parts[0], Integer.parseInt(parts[1]));
    }
}
