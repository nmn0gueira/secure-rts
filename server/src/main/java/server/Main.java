package server;

import crypto.CipherSuite;
import crypto.CipherSuiteFactory;
import datagram.SecureDatagramSocket;

import java.io.*;
import java.net.*;

public class Main {

    static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("Usage: server <movie> <ip-multicast-address> <port>");
            System.out.println("Crypto config is read from server/config.properties");
            System.exit(-1);
        }

        CipherSuite suite = CipherSuiteFactory.fromFile("server/config.properties");

        int size;
        int csize = 0;
        int count = 0;
        long time;
        DataInputStream g = new DataInputStream(new FileInputStream(args[0]));
        byte[] buff = new byte[4096];

        SecureDatagramSocket s = new SecureDatagramSocket(suite);
        InetSocketAddress addr = new InetSocketAddress(args[1], Integer.parseInt(args[2]));
        DatagramPacket p = new DatagramPacket(buff, buff.length, addr);
        long t0 = System.nanoTime();
        long q0 = 0;

        // Each frame: Short size || Long timestamp || byte[] encodedMP4Frame
        while (g.available() > 0) {
            size = g.readShort();
            csize += size;
            time = g.readLong();
            if (count == 0) q0 = time;
            count++;
            g.readFully(buff, 0, size);
            p.setData(buff, 0, size);
            p.setSocketAddress(addr);

            Thread.sleep(Math.max(0, ((time - q0) - (System.nanoTime() - t0)) / 1_000_000));

            s.send(p);
            System.out.print(":");
        }

        long tend = System.nanoTime();
        System.out.println();
        System.out.println("DONE! all frames sent: " + count);
        long duration = (tend - t0) / 1_000_000_000;
        System.out.println("Movie duration " + duration + " s");
        System.out.println("Throughput " + count / duration + " fps");
        System.out.println("Throughput " + (8L * csize / duration) / 1000 + " Kbps");
    }
}
