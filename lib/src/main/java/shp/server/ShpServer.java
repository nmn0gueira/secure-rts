package shp.server;

import common.Utils;
import crypto.KeyLoader;
import shp.AbstractShpPeer;
import shp.ShpCryptoSpec;
import shp.ShpMessage;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public abstract class ShpServer extends AbstractShpPeer {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final int listenPort;
    private final String keyStorePath;
    private final String userDatabasePath;
    private final String cryptoConfigPath;

    protected ShpCryptoSpec cryptoSpec;
    protected KeyPair serverKeyPair;
    protected Map<String, User> userDatabase;

    private ServerSocket serverSocket;
    private Socket clientSocket;

    protected ShpServer(int listenPort, String keyStorePath, String userDatabasePath, String cryptoConfigPath) {
        this.listenPort = listenPort;
        this.keyStorePath = keyStorePath;
        this.userDatabasePath = userDatabasePath;
        this.cryptoConfigPath = cryptoConfigPath;
    }

    public ShpServerOutput runProtocolServer() throws Exception {
        cryptoSpec = new ShpCryptoSpec();
        serverKeyPair = loadServerKeyPair();
        userDatabase = loadUserDatabase(userDatabasePath);
        startListening();
        acceptClientConnection();
        try {
            startReaderThread();
            ShpMessage first = receiveMessage();
            if (first == null) throw new RuntimeException("SHP timeout waiting for client first message");
            runProtocol(first);
            return buildOutput();
        } finally {
            closeConnection();
        }
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

    @Override
    public boolean isConnectionClosed() {
        return clientSocket == null || clientSocket.isClosed();
    }

    private KeyPair loadServerKeyPair() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return KeyLoader.loadKeyPairFromFile(keyStorePath, kf);
    }

    protected Map<String, User> loadUserDatabase(String path) throws Exception {
        Map<String, User> db = new HashMap<>();
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
                // Format: userId:passwordHashHex:saltHex:publicKeyHex
                String[] parts = trimmed.split(":");
                if (parts.length < 4) continue;
                String userId = parts[0].trim();
                byte[] passwordHash = Utils.hexStringToByteArray(parts[1].trim());
                byte[] salt = Utils.hexStringToByteArray(parts[2].trim());
                byte[] pubKeyBytes = Utils.hexStringToByteArray(parts[3].trim());
                var pubKey = KeyLoader.loadPublicKey(pubKeyBytes, kf);
                db.put(userId, new User(userId, passwordHash, salt, pubKey));
            }
        }
        return db;
    }

    protected String getCryptoConfigPath() {
        return cryptoConfigPath;
    }

    protected abstract ShpServerOutput buildOutput();
}
