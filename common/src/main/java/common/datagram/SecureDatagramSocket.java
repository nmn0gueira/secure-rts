package common.datagram;

import java.io.IOException;
import java.net.*;

public class SecureDatagramSocket extends DatagramSocket {

    private final SecureSocketBase secureSocketBase;

    public SecureDatagramSocket(String symmetricAlgorithm) throws SocketException {
        super();
        secureSocketBase = new SecureSocketBase(symmetricAlgorithm);
    }

    public SecureDatagramSocket(int port, String symmetricAlgorithm) throws SocketException {
        super(port);
        secureSocketBase = new SecureSocketBase(symmetricAlgorithm);
    }

    public SecureDatagramSocket(int port, InetAddress iAddr, String symmetricAlgorithm) throws SocketException {
        super(port, iAddr);
        secureSocketBase = new SecureSocketBase(symmetricAlgorithm);
    }

    public SecureDatagramSocket(SocketAddress bindAddr, String symmetricAlgorithm) throws SocketException {
        super(bindAddr);
        secureSocketBase = new SecureSocketBase(symmetricAlgorithm);
    }

    /**
     * Creates and sends DSTP packet from the provided datagram packet. A DSTP packet is composed
     * of a 5 byte header (DSTP version, release, and data length) and an encrypted payload
     * containing the sequence number, data, and integrity proof. The integrity proof may
     * be encrypted (in the case of hash function) or not (in the case of HMAC), in which
     * case it is appended to the end of the encrypted payload in plain text.
     * @param packet packet to be sent
     * @throws IOException if an I/O error occurs
     */
    @Override
    public void send(DatagramPacket packet) throws IOException {
        secureSocketBase.preparePacketForSend(packet);
        super.send(packet);
    }

    /**
     * Receives a DSTP packet. The payload of the packet is decrypted and the sequence number is checked. Packets
     * with duplicate sequence numbers are discarded. The integrity proof is verified to ensure the packet
     * was not tampered with. If the packet is valid, the decrypted data is copied to the datagram packet's buffer.
     * @param packet packet to which the received data is written
     * @throws IOException if an I/O error occurs
     */
    @SuppressWarnings("DuplicatedCode")
    @Override
    public void receive(DatagramPacket packet) throws IOException {
        byte[] buffer = new byte[SecureSocketBase.UDP_MAX_SIZE];
        byte[] previousBuffer = packet.getData();

        // Keep receiving packets until a valid packet is received
        while (true) {
            // Replace packet's buffer with a max size buffer to receive the packet
            packet.setData(buffer);
            super.receive(packet);
            if (secureSocketBase.processReceivedPacket(packet)) {
                // Copy the relevant data to the provided packet
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
