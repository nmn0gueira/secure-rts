package shp;

import shp.protocol.ShpProtocolResult;
import shp.protocol.State;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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
        while (true) {
            ShpProtocolResult result = dispatch(incoming);
            if (result.state() == State.ERROR) {
                throw new RuntimeException("SHP protocol error");
            }
            if (result.state() == State.FINISHED) {
                break;
            }
            result.response().ifPresent(msg -> {
                try {
                    sendMessage(msg);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            if (result.state() == State.WAITING) {
                incoming = receiveMessage();
                if (incoming == null) {
                    throw new RuntimeException("SHP timeout waiting for peer message");
                }
            }
        }
    }

    protected abstract ShpProtocolResult dispatch(ShpMessage message) throws Exception;

    protected abstract boolean isConnectionClosed();
}
