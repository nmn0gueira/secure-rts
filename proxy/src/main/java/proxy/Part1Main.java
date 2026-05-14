package proxy;

import crypto.CipherSuite;
import crypto.CipherSuiteFactory;
import datagram.SecureDatagramSocket;
import datagram.StreamControl;

import java.io.*;
import java.net.*;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

public class Part1Main {

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("Usage: Part1Main <server-host> <server-tcp-port> <movie-name>");
            System.err.println();
            System.err.println("server-host       hostname or IP of the server");
            System.err.println("server-tcp-port   TCP port the server listens on for requests");
            System.err.println("movie-name        name of the movie to request");
            System.exit(1);
        }

        String serverHost = args[0];
        int serverTcpPort = Integer.parseInt(args[1]);
        String movieName = args[2];

        Properties config = loadConfig("proxy/config.properties");
        String remote = config.getProperty("remote");
        String destinations = config.getProperty("localdelivery");

        String cryptoPath = "proxy/crypto/" + movieName + ".properties";
        CipherSuite suite;

        try (Socket tcpSocket = new Socket(serverHost, serverTcpPort)) {
            PrintWriter tcpOut = new PrintWriter(new OutputStreamWriter(tcpSocket.getOutputStream()), true);
            BufferedReader tcpIn = new BufferedReader(new InputStreamReader(tcpSocket.getInputStream()));

            tcpOut.println("REQUEST " + movieName);
            String response = tcpIn.readLine();
            if (response == null || !response.startsWith("OK ")) {
                System.err.println("Server rejected request: " + (response != null ? response : "no response"));
                System.exit(1);
            }
            System.out.println("Server confirmed: " + response);

            suite = CipherSuiteFactory.fromFile(cryptoPath);
            tcpOut.println("START " + movieName);
        }

        SocketAddress inAddr = parseSocketAddress(remote);
        Set<SocketAddress> outAddrs = Arrays.stream(destinations.split(","))
                .map(Part1Main::parseSocketAddress)
                .collect(Collectors.toSet());

        System.out.println("Receiving '" + movieName + "' on " + remote
                + ", forwarding to " + destinations + " ...");

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
                for (SocketAddress out : outAddrs) {
                    outSocket.send(new DatagramPacket(buffer, inPacket.getLength(), out));
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
