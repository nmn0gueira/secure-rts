package shp.pq.client;

import crypto.CertificateUtils;
import shp.AbstractShpPeer;
import shp.ShpMessage;
import shp.client.ShpClientOutput;
import shp.protocol.ShpProtocolResult;
import shp.pq.PqShpCryptoSpec;
import shp.pq.protocol.PqShpClientProtocol;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public class PqShpClient extends AbstractShpPeer {

    private final String serverHost;
    private final int serverPort;
    private final String keyStorePath;
    private final String trustStorePath;
    private final String clientSuitesPath;
    private final char[] keystorePassword;

    private PqShpClientProtocol protocol;
    private Socket socket;

    public PqShpClient(String serverHost, int serverPort, String keyStorePath,
                       String trustStorePath, String clientSuitesPath, char[] keystorePassword) {
        this.serverHost = serverHost;
        this.serverPort = serverPort;
        this.keyStorePath = keyStorePath;
        this.trustStorePath = trustStorePath;
        this.clientSuitesPath = clientSuitesPath;
        this.keystorePassword = keystorePassword;
    }

    public ShpClientOutput runProtocolClient(String request, byte[] udpPortBytes) throws Exception {
        setupConnection();
        try {
            var identity = CertificateUtils.loadIdentity(keyStorePath, keystorePassword);
            var trustStore = CertificateUtils.loadKeyStore(trustStorePath, keystorePassword);

            PqShpCryptoSpec cryptoSpec = new PqShpCryptoSpec(identity.privateKey(), identity.certificate());
            protocol = new PqShpClientProtocol(cryptoSpec, trustStore, loadSuites(clientSuitesPath));
            protocol.setInput(request, udpPortBytes);

            ShpMessage initial = protocol.buildClientHello();
            sendMessage(initial);
            startReaderThread();
            ShpMessage response = receiveMessage();
            if (response == null)
                throw new RuntimeException("PQ SHP timeout on initial server response");
            runProtocol(response);
            return new ShpClientOutput(protocol.getCipherSuite());
        } finally {
            closeConnection();
        }
    }

    @Override
    protected ShpProtocolResult dispatch(ShpMessage message) {
        return protocol.handle(message);
    }

    @Override
    public boolean isConnectionClosed() {
        return socket == null || socket.isClosed();
    }

    private void setupConnection() throws Exception {
        socket = new Socket(serverHost, serverPort);
        outputStream = new ObjectOutputStream(socket.getOutputStream());
        outputStream.flush();
        inputStream = new ObjectInputStream(socket.getInputStream());
    }

    private void closeConnection() {
        try { if (socket != null) socket.close(); } catch (Exception ignored) {}
    }
}
