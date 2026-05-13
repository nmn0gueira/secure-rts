package shp.server;

import crypto.CertificateLoader;
import shp.AbstractShpPeer;
import shp.ShpCryptoSpec;
import shp.ShpMessage;
import shp.protocol.ShpProtocolResult;
import shp.protocol.ShpServerProtocol;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ShpServer extends AbstractShpPeer {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final int listenPort;
    private final String keyStorePath;
    private final String trustStorePath;
    private final String cryptoConfigPath;
    private final Set<String> validRequests;

    private ShpServerProtocol protocol;
    private ServerSocket serverSocket;
    private Socket clientSocket;

    public ShpServer(int listenPort, String keyStorePath, String trustStorePath,
                     String cryptoConfigPath, Set<String> validRequests) {
        this.listenPort = listenPort;
        this.keyStorePath = keyStorePath;
        this.trustStorePath = trustStorePath;
        this.cryptoConfigPath = cryptoConfigPath;
        this.validRequests = validRequests;
    }

    public ShpServerOutput runProtocolServer() throws Exception {
        char[] password = "changeit".toCharArray();
        var identity = CertificateLoader.loadIdentity(keyStorePath, password, null, password);
        var trustStore = CertificateLoader.loadKeyStore(trustStorePath, password);

        ShpCryptoSpec cryptoSpec = new ShpCryptoSpec(identity.keyPair(), identity.certificate());
        byte[] cryptoConfigBytes = Files.readAllBytes(Path.of(cryptoConfigPath));

        protocol = new ShpServerProtocol(cryptoSpec, trustStore, validRequests);
        protocol.setCryptoConfigBytes(cryptoConfigBytes);

        startListening();
        acceptClientConnection();
        try {
            startReaderThread();
            ShpMessage first = receiveMessage();
            if (first == null) throw new RuntimeException("SHP timeout waiting for client first message");
            runProtocol(first);
            return new ShpServerOutput(
                    protocol.getUserRequest(),
                    protocol.getUdpPort(),
                    new String(cryptoConfigBytes),
                    protocol.getSharedSecret());
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
        try {
            if (clientSocket != null) clientSocket.close();
        } catch (Exception ignored) {}
        try {
            if (serverSocket != null) serverSocket.close();
        } catch (Exception ignored) {}
    }

}
