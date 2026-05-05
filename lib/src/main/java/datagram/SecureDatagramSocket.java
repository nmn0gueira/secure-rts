package datagram;

import crypto.CipherSuite;

import java.io.IOException;
import java.net.*;

public class SecureDatagramSocket extends DatagramSocket {

    private final SecureSocketBase secureSocketBase;

    public SecureDatagramSocket(CipherSuite suite) throws SocketException {
        super();
        secureSocketBase = new SecureSocketBase(suite);
    }

    public SecureDatagramSocket(int port, CipherSuite suite) throws SocketException {
        super(port);
        secureSocketBase = new SecureSocketBase(suite);
    }

    public SecureDatagramSocket(int port, InetAddress iAddr, CipherSuite suite) throws SocketException {
        super(port, iAddr);
        secureSocketBase = new SecureSocketBase(suite);
    }

    public SecureDatagramSocket(SocketAddress bindAddr, CipherSuite suite) throws SocketException {
        super(bindAddr);
        secureSocketBase = new SecureSocketBase(suite);
    }

    @Override
    public void send(DatagramPacket packet) throws IOException {
        secureSocketBase.preparePacketForSend(packet);
        super.send(packet);
    }

    @SuppressWarnings("DuplicatedCode")
    @Override
    public void receive(DatagramPacket packet) throws IOException {
        byte[] buffer = new byte[SecureSocketBase.UDP_MAX_SIZE];
        byte[] previousBuffer = packet.getData();
        while (true) {
            packet.setData(buffer);
            super.receive(packet);
            if (secureSocketBase.processReceivedPacket(packet)) {
                int receivedLength = packet.getLength();
                byte[] data = packet.getData();
                System.arraycopy(data, 0, previousBuffer, packet.getOffset(), receivedLength);
                packet.setData(previousBuffer);
                packet.setLength(receivedLength);
                return;
            }
        }
    }
}
