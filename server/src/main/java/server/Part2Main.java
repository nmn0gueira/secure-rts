package server;

import crypto.CipherSuite;
import crypto.CipherSuiteFactory;
import datagram.SecureDatagramSocket;
import datagram.StreamControl;
import shp.AbstractShpPeer;
import shp.server.ShpServer;
import shp.server.ShpServerOutput;

import java.io.*;
import java.net.*;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

public class Part2Main {

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("Usage: Part2Main <multicast-addr> <shp-tcp-port>");
            System.err.println();
            System.err.println("multicast-addr    address to stream to (e.g. 239.0.0.1 or localhost)");
            System.err.println("shp-tcp-port      TCP port for SHP handshakes");
            System.exit(1);
        }

        String multicastAddr = args[0];
        int shpPort = Integer.parseInt(args[1]);

        Properties config = loadConfig("server/config.properties");
        String moviesDir = config.getProperty("movies.dir");
        String keystorePath = config.getProperty("shp.keystore");
        String truststorePath = config.getProperty("shp.truststore");
        char[] password = config.getProperty("shp.password").toCharArray();

        Map<String, String> catalog = scanMovies(moviesDir);
        File catalogDir = new File(moviesDir).getAbsoluteFile().getParentFile();
        Set<String> validMovies = catalog.keySet();

        Map<String, LinkedHashMap<String, String>> movieSuites = new HashMap<>();
        for (String movieName : validMovies) {
            String suitesPath = new File(catalogDir, "server/suites/" + movieName + "-suites.conf").getPath();
            movieSuites.put(movieName, AbstractShpPeer.loadSuites(suitesPath));
        }

        System.out.println("Part 2 server ready. Movies: " + validMovies);
        System.out.println("Listening for SHP handshakes on TCP port " + shpPort + " ...");

        while (true) {
            ShpServer shpServer = new ShpServer(shpPort, keystorePath, truststorePath,
                    null, validMovies, password);
            shpServer.setPerMovieSuites(movieSuites);

            try {
                ShpServerOutput out = shpServer.runProtocolServer();
                String movieName = out.request();
                String movieFile = catalog.get(movieName);

                System.out.println("SHP complete. Streaming '" + movieName + "' → "
                        + multicastAddr + ":" + out.udpPort());

                CipherSuite suite = CipherSuiteFactory.fromConfig(out.cryptoConfig(), out.sharedSecret());
                streamMovie(movieFile, suite, multicastAddr, out.udpPort());

            } catch (Exception e) {
                System.err.println("Handshake or stream error: " + e.getMessage());
            }
        }
    }

    private static void streamMovie(String movieFilePath, CipherSuite suite,
                                    String addr, int port) throws Exception {
        int size, csize = 0, count = 0;
        long time, q0 = 0;
        byte[] buff = new byte[4096];

        try (DataInputStream movie = new DataInputStream(new FileInputStream(movieFilePath));
             SecureDatagramSocket socket = new SecureDatagramSocket(suite)) {

            InetSocketAddress dest = new InetSocketAddress(addr, port);
            DatagramPacket packet = new DatagramPacket(buff, buff.length, dest);
            long t0 = System.nanoTime();

            while (movie.available() > 0) {
                size = movie.readShort();
                csize += size;
                time = movie.readLong();
                if (count == 0) q0 = time;
                count++;
                movie.readFully(buff, 0, size);
                packet.setData(buff, 0, size);
                packet.setSocketAddress(dest);
                Thread.sleep(Math.max(0, ((time - q0) - (System.nanoTime() - t0)) / 1_000_000));
                socket.send(packet);
                System.out.print(":");
            }

            socket.send(new DatagramPacket(StreamControl.FINISH_FRAME, StreamControl.FINISH_FRAME.length, dest));

            System.out.println();
            System.out.println("DONE! all frames sent: " + count);
            long duration = Math.max(1, (System.nanoTime() - t0) / 1_000_000_000);
            System.out.println("Movie duration " + duration + " s");
            System.out.println("Throughput " + count / duration + " fps");
            System.out.println("Throughput " + (8L * csize / duration) / 1000 + " Kbps");
        }
    }

    private static Properties loadConfig(String path) throws IOException {
        Properties props = new Properties();
        try (InputStream in = new FileInputStream(path)) {
            props.load(in);
        }
        return props;
    }

    private static Map<String, String> scanMovies(String dirPath) {
        File dir = new File(dirPath);
        Map<String, String> map = new HashMap<>();
        File[] files = dir.listFiles((d, name) -> name.endsWith(".dat"));
        if (files != null) {
            for (File f : files) {
                String stem = f.getName().substring(0, f.getName().length() - 4);
                map.put(stem, f.getPath());
            }
        }
        return map;
    }
}
