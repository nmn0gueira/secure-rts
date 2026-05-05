package proxy;

import crypto.CipherSuite;
import crypto.CipherSuiteFactory;
import datagram.SecureDatagramSocket;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.*;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

public class Main {

    static void main(String[] args) throws Exception {
        InputStream inputStream = new FileInputStream("proxy/config.properties");
        Properties properties = new Properties();
        properties.load(inputStream);

        String remote = properties.getProperty("remote");
        String destinations = properties.getProperty("localdelivery");

        SocketAddress inSocketAddress = parseSocketAddress(remote);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(","))
                .map(Main::parseSocketAddress)
                .collect(Collectors.toSet());

        CipherSuite suite = CipherSuiteFactory.fromFile("proxy/config.properties");

        SecureDatagramSocket inSocket = new SecureDatagramSocket(inSocketAddress, suite);
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[4 * 1024];

        while (true) {
            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            inSocket.receive(inPacket);
            System.out.print(".");
            for (SocketAddress outSocketAddress : outSocketAddressSet) {
                outSocket.send(new DatagramPacket(buffer, inPacket.getLength(), outSocketAddress));
            }
        }
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        return new InetSocketAddress(split[0], Integer.parseInt(split[1]));
    }
}
