package shp.pq.server;

import crypto.CertificateUtils;
import shp.AbstractShpPeer;
import shp.ShpMessage;
import shp.protocol.ShpProtocolResult;
import shp.pq.PqShpCryptoSpec;
import shp.pq.protocol.PqShpServerProtocol;
import shp.server.ShpServerOutput;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class PqShpServer extends AbstractShpPeer {

    private final int listenPort;
    private final String keyStorePath;
    private final String trustStorePath;
    private final String serverSuitesPath;
    private final Set<String> validRequests;
    private final char[] keystorePassword;

    private Map<String, LinkedHashMap<String, String>> perMovieSuites;

    private PqShpServerProtocol protocol;
    private ServerSocket serverSocket;
    private Socket clientSocket;

    public PqShpServer(int listenPort, String keyStorePath, String trustStorePath,
                       String serverSuitesPath, Set<String> validRequests, char[] keystorePassword) {
        this.listenPort = listenPort;
        this.keyStorePath = keyStorePath;
        this.trustStorePath = trustStorePath;
        this.serverSuitesPath = serverSuitesPath;
        this.validRequests = validRequests;
        this.keystorePassword = keystorePassword;
    }

    public void setPerMovieSuites(Map<String, LinkedHashMap<String, String>> perMovieSuites) {
        this.perMovieSuites = perMovieSuites;
    }

    public ShpServerOutput runProtocolServer() throws Exception {
        var identity = CertificateUtils.loadIdentity(keyStorePath, keystorePassword);
        var trustStore = CertificateUtils.loadKeyStore(trustStorePath, keystorePassword);

        PqShpCryptoSpec cryptoSpec = new PqShpCryptoSpec(identity.privateKey(), identity.certificate());
        protocol = new PqShpServerProtocol(cryptoSpec, trustStore, validRequests);

        if (perMovieSuites != null) {
            protocol.setPerMovieSuites(perMovieSuites);
        } else {
            protocol.setServerSuites(loadSuites(serverSuitesPath));
        }

        startListening();
        acceptClientConnection();
        try {
            startReaderThread();
            ShpMessage first = receiveMessage();
            if (first == null)
                throw new RuntimeException("PQ SHP timeout waiting for client first message");
            runProtocol(first);
            return new ShpServerOutput(protocol.getUserRequest(), protocol.getUdpPort(), protocol.getCipherSuite());
        } finally {
            closeConnection();
        }
    }

    @Override
    protected ShpProtocolResult dispatch(ShpMessage message) throws Exception {
        return protocol.handle(message);
    }

    @Override
    public boolean isConnectionClosed() {
        return clientSocket == null || clientSocket.isClosed();
    }

    private void startListening() throws IOException {
        serverSocket = new ServerSocket(listenPort);
    }

    private void acceptClientConnection() throws Exception {
        clientSocket = serverSocket.accept();
        outputStream = new ObjectOutputStream(clientSocket.getOutputStream());
        outputStream.flush();
        inputStream = new ObjectInputStream(clientSocket.getInputStream());
    }

    private void closeConnection() {
        try { if (clientSocket != null) clientSocket.close(); } catch (Exception ignored) {}
        try { if (serverSocket != null) serverSocket.close(); } catch (Exception ignored) {}
    }
}
