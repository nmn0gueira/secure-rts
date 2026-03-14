package proxy;

/* hjUDPproxy, 20/Mar/18
 *
 * This is a very simple (transparent) UDP proxy
 * The proxy can listening on a remote source (server) UDP sender
 * and transparently forward received datagram packets in the
 * delivering endpoint
 *
 * Possible Remote listening endpoints:
 *    Unicast IP address and port: configurable in the file config.properties
 *    Multicast IP address and port: configurable in the code
 *  
 * Possible local listening endpoints:
 *    Unicast IP address and port
 *    Multicast IP address and port
 *       Both configurable in the file config.properties
 */

import common.datagram.SecureDatagramSocket;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

public class Main {
    static void main(String[] args) throws Exception {
        if (args.length != 1)
        {
            System.out.println("Usage: proxy [<encryption-alg>]");
            System.out.println("Encryption algorithm defaults to AES-GCM. Available options:");
            System.out.println("aes - AES-GCM");
            System.out.println("chacha - ChaCha20-Poly1305");
            System.out.println("dprg - Custom stream cipher from keystream generation based on AES-CTR");
            System.exit(-1);
        }

        InputStream inputStream = new FileInputStream("proxy/config.properties");
        if (inputStream == null) {
            System.err.println("Configuration file not found!");
            System.exit(1);
        }
        Properties properties = new Properties();
        properties.load(inputStream);
	    String remote = properties.getProperty("remote");
        String destinations = properties.getProperty("localdelivery");

        SocketAddress inSocketAddress = parseSocketAddress(remote);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(Main::parseSocketAddress).collect(Collectors.toSet());

        SecureDatagramSocket inSocket = new SecureDatagramSocket(inSocketAddress, args[0]);
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[4 * 1024];
       
        while (true) {

            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
    	    inSocket.receive(inPacket);  // if remote is unicast

            System.out.print(".");
            for (SocketAddress outSocketAddress : outSocketAddressSet) {
                outSocket.send(new DatagramPacket(buffer, inPacket.getLength(), outSocketAddress));
            }
        }
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) 
    {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }
}
