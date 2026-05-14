package server;

import crypto.CipherSuite;
import crypto.CipherSuiteFactory;
import datagram.SecureDatagramSocket;
import datagram.StreamControl;

import java.io.*;
import java.net.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class Part1Main {

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("Usage: Part1Main <multicast-addr> <multicast-port> <tcp-request-port>");
            System.err.println();
            System.err.println("multicast-addr     address to stream to (e.g. 239.0.0.1 or localhost)");
            System.err.println("multicast-port     UDP port to stream on");
            System.err.println("tcp-request-port   TCP port to listen on for proxy movie requests");
            System.exit(1);
        }

        String multicastAddr = args[0];
        int multicastPort = Integer.parseInt(args[1]);
        int tcpPort = Integer.parseInt(args[2]);

        Properties config = loadConfig("server/config.properties");
        String moviesDir = config.getProperty("movies.dir");

        Map<String, String> catalog = scanMovies(moviesDir);
        File catalogDir = new File(moviesDir).getAbsoluteFile().getParentFile();

        System.out.println("Part 1 server ready. Movies: " + catalog.keySet());
        System.out.println("Listening for requests on TCP port " + tcpPort + " ...");

        try (ServerSocket serverSocket = new ServerSocket(tcpPort)) {
            while (true) {
                try (Socket client = serverSocket.accept()) {
                    handleRequest(client, catalog, catalogDir, multicastAddr, multicastPort);
                } catch (Exception e) {
                    System.err.println("Error handling request: " + e.getMessage());
                }
            }
        }
    }

    private static void handleRequest(Socket client, Map<String, String> catalog,
                                      File catalogDir, String multicastAddr, int multicastPort)
            throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream()));
        PrintWriter writer = new PrintWriter(new OutputStreamWriter(client.getOutputStream()), true);

        String line = reader.readLine();
        if (line == null || !line.startsWith("REQUEST ")) {
            writer.println("ERR bad request");
            return;
        }
        String movieName = line.substring("REQUEST ".length()).trim();

        String movieFile = catalog.get(movieName);
        if (movieFile == null) {
            writer.println("ERR unknown movie: " + movieName);
            System.err.println("Rejected request for unknown movie: " + movieName);
            return;
        }

        File cryptoConfig = new File(catalogDir, "server/crypto/" + movieName + ".properties");
        if (!cryptoConfig.exists()) {
            writer.println("ERR no crypto config for: " + movieName);
            System.err.println("Missing crypto config: " + cryptoConfig);
            return;
        }

        writer.println("OK " + multicastAddr + ":" + multicastPort);

        String startLine = reader.readLine();
        if (startLine == null || !startLine.startsWith("START ")) {
            writer.println("ERR expected START");
            System.err.println("Expected START from proxy, got: " + startLine);
            return;
        }

        System.out.println("Streaming '" + movieName + "' to " + multicastAddr + ":" + multicastPort
                + " (crypto: " + cryptoConfig.getName() + ")");

        streamMovie(movieFile, cryptoConfig.getPath(), multicastAddr, multicastPort);
    }

    private static void streamMovie(String movieFilePath, String cryptoConfigPath,
                                    String addr, int port) throws Exception {
        CipherSuite suite = CipherSuiteFactory.fromFile(cryptoConfigPath);

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

    private static Properties loadConfig(String path) throws IOException {
        Properties props = new Properties();
        try (InputStream in = new FileInputStream(path)) {
            props.load(in);
        }
        return props;
    }
}
