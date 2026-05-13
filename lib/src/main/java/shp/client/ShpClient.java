package shp.client;

import shp.AbstractShpPeer;
import crypto.CertificateLoader;
import shp.ShpCryptoSpec;
import shp.ShpMessage;
import shp.protocol.ShpClientProtocol;
import shp.protocol.ShpProtocolResult;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public class ShpClient extends AbstractShpPeer {

    private final String serverHost;
    private final int serverPort;
    private final String keyStorePath;
    private final String trustStorePath;
    private final String clientSuitesPath;
    private final char[] keystorePassword;

    private ShpClientProtocol protocol;
    private Socket socket;

    public ShpClient(String serverHost, int serverPort, String keyStorePath, String trustStorePath,
                     String clientSuitesPath, char[] keystorePassword) {
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
            var identity = CertificateLoader.loadIdentity(keyStorePath, keystorePassword, null, keystorePassword);
            var trustStore = CertificateLoader.loadKeyStore(trustStorePath, keystorePassword);

            ShpCryptoSpec cryptoSpec = new ShpCryptoSpec(identity.keyPair(), identity.certificate());
            protocol = new ShpClientProtocol(cryptoSpec, trustStore, loadSuites(clientSuitesPath));

            protocol.setInput(request, udpPortBytes);

            ShpMessage initial = protocol.buildClientHello();
            sendMessage(initial);
            startReaderThread();
            ShpMessage response = receiveMessage();
            if (response == null)
                throw new RuntimeException("SHP timeout on initial server response");
            runProtocol(response);
            return new ShpClientOutput(protocol.getCryptoConfig(), protocol.getSharedSecret());
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
        try {
            if (socket != null)
                socket.close();
        } catch (Exception ignored) {
        }
    }
}
