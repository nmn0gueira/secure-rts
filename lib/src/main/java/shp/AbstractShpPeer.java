package shp;

import shp.protocol.ShpProtocolResult;
import shp.protocol.State;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public abstract class AbstractShpPeer {

    protected static final int TIMEOUT_MS = 10000;

    protected ObjectInputStream inputStream;
    protected ObjectOutputStream outputStream;

    private final BlockingQueue<Object> messageQueue = new LinkedBlockingQueue<>();

    protected void startReaderThread() {
        Thread readerThread = new Thread(() -> {
            try {
                while (!isConnectionClosed()) {
                    Object obj = inputStream.readObject();
                    messageQueue.put(obj);
                }
            } catch (IOException | ClassNotFoundException | InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        readerThread.setDaemon(true);
        readerThread.start();
    }

    protected ShpMessage receiveMessage() throws InterruptedException {
        Object obj = messageQueue.poll(TIMEOUT_MS, TimeUnit.MILLISECONDS);
        if (obj instanceof ShpMessage msg) return msg;
        return null;
    }

    protected void sendMessage(ShpMessage message) throws IOException {
        outputStream.writeObject(message);
        outputStream.flush();
    }

    protected void runProtocol(ShpMessage firstMessage) throws Exception {
        ShpMessage incoming = firstMessage;
        
        while (true){
            ShpProtocolResult result = dispatch(incoming);

            if(result.state() == State.ERROR){
                throw new RuntimeException("SHP protocol error.");
            }

            if (result.response().isPresent()) {
                sendMessage(result.response().get());
            }

            if (result.state() == State.FINISHED) {
                break;
            }

            incoming = receiveMessage();
            if (incoming == null) {
                throw new RuntimeException("SHP timeout waiting for peer message");
            }
            
        }
    }

    protected abstract ShpProtocolResult dispatch(ShpMessage message) throws Exception;

    protected abstract boolean isConnectionClosed();

    public static LinkedHashMap<String, String> loadSuites(String suitesFilePath) throws IOException {
        LinkedHashMap<String, String> suites = new LinkedHashMap<>();
        String currentSuite = null;
        StringBuilder currentConfig = new StringBuilder();

        for (String line : Files.readAllLines(Path.of(suitesFilePath))) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;

            if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                if (currentSuite != null)
                    suites.put(currentSuite, currentConfig.toString());
                currentSuite = trimmed.substring(1, trimmed.length() - 1).trim();
                currentConfig = new StringBuilder();
            } else if (currentSuite != null) {
                currentConfig.append(trimmed).append("\n");
            }
        }

        if (currentSuite != null)
            suites.put(currentSuite, currentConfig.toString());

        return suites;
    }
}
