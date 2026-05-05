package shp.client;

import shp.AbstractShpPeer;
import shp.ShpCryptoSpec;
import shp.ShpMessage;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public abstract class ShpClient extends AbstractShpPeer {

    private final String serverHost;
    private final int serverPort;
    private final String keyStorePath;
    private final String serverPublicKeyPath;

    protected ShpCryptoSpec cryptoSpec;
    private Socket socket;

    protected ShpClient(String serverHost, int serverPort, String keyStorePath, String serverPublicKeyPath) {
        this.serverHost = serverHost;
        this.serverPort = serverPort;
        this.keyStorePath = keyStorePath;
        this.serverPublicKeyPath = serverPublicKeyPath;
    }

    public ShpClientOutput runProtocolClient() throws Exception {
        setupConnection();
        try {
            cryptoSpec = new ShpCryptoSpec();
            ShpMessage initial = buildInitialMessage();
            sendMessage(initial);
            startReaderThread();
            ShpMessage response = receiveMessage();
            if (response == null) throw new RuntimeException("SHP timeout on initial server response");
            runProtocol(response);
            return buildOutput();
        } finally {
            closeConnection();
        }
    }

    private void setupConnection() throws Exception {
        socket = new Socket(serverHost, serverPort);
        outputStream = new ObjectOutputStream(socket.getOutputStream());
        outputStream.flush();
        inputStream = new ObjectInputStream(socket.getInputStream());
    }

    private void closeConnection() {
        try {
            if (socket != null) socket.close();
        } catch (Exception ignored) {}
    }

    @Override
    public boolean isConnectionClosed() {
        return socket == null || socket.isClosed();
    }

    protected String getKeyStorePath() {
        return keyStorePath;
    }

    protected String getServerPublicKeyPath() {
        return serverPublicKeyPath;
    }

    protected abstract ShpMessage buildInitialMessage() throws Exception;

    protected abstract ShpClientOutput buildOutput();
}
