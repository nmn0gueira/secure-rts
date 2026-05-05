package datagram;

import crypto.CipherSuite;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.net.SocketAddress;

public class SecureMulticastSocket extends MulticastSocket {
    private final SecureSocketBase secureSocketBase;

    public SecureMulticastSocket(CipherSuite suite) throws IOException {
        super();
        secureSocketBase = new SecureSocketBase(suite);
    }

    public SecureMulticastSocket(int port, CipherSuite suite) throws IOException {
        super(port);
        secureSocketBase = new SecureSocketBase(suite);
    }

    public SecureMulticastSocket(SocketAddress bindAddr, CipherSuite suite) throws IOException {
        super(bindAddr);
        secureSocketBase = new SecureSocketBase(suite);
    }

    /**
     * Same as {@code SecureDatagramSocket.send(DatagramPacket)}, but for multicast sockets.
     * @param packet  the {@code DatagramPacket} to be sent.
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void send(DatagramPacket packet) throws IOException {
        secureSocketBase.preparePacketForSend(packet);
        super.send(packet);
    }

    /**
     * Same as {@code SecureDatagramSocket.receive(DatagramPacket)}, but for multicast sockets.
     * @param packet   the {@code DatagramPacket} into which to place
     *                 the incoming data.
     * @throws IOException  if an I/O error occurs.
     */
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
