package common.datagram;

import common.crypto.SymmetricCipher;
import common.Utils;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import java.net.DatagramPacket;
import java.security.GeneralSecurityException;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

class SecureSocketBase {

    protected static final int UDP_MAX_SIZE = 65507;
    private static final short DSTP_VERSION = 0x0002;
    private static final byte DSTP_RELEASE = 0x01;
    private final SymmetricCipher symmetricCipher;
    private long timestamp;
    private int sequenceNumber;
    private final Set<Integer> receivedSequenceNumbers;
    private static final Logger LOGGER = Logger.getLogger(SecureSocketBase.class.getName());

    // Common header setup for DSTP packets
    private final byte[] header = new byte[]{
            (byte) (DSTP_VERSION >> 8),
            (byte) DSTP_VERSION,
            DSTP_RELEASE,
            0x00,   // Length of the data (high byte)
            0x00    // Length of the data (low byte)
    };

    protected SecureSocketBase(String algorithm) {
        symmetricCipher = SymmetricCipher.getInstance(algorithm);
        // Sequence number will be the first 4
        timestamp = System.currentTimeMillis();
        receivedSequenceNumbers = new HashSet<>();
        LOGGER.setLevel(Level.OFF);
    }

    /**
     * Creates a DSTP packet from the provided datagram packet. A DSTP packet is composed
     * of a 5 byte header (DSTP version, release, and data length) and an encrypted payload
     * containing the sequence number, data, and integrity proof. The integrity proof may
     * be encrypted (in the case of hash function) or not (in the case of HMAC), in which
     * case it is appended to the end of the encrypted payload in plain text.
     * @param packet - packet to be prepared for sending
     */
    protected void preparePacketForSend(DatagramPacket packet) {
        byte[] sequenceNumberBytes = new byte[]{(byte) timestamp, (byte) sequenceNumber};


        byte[] data = Utils.subArray(packet.getData(), packet.getOffset(), packet.getLength());
        sequenceNumber++;

        // Reset sequence number and increment timestamp
        if (sequenceNumber == 256) {
            sequenceNumber = 0;
            timestamp++;
        }

        byte[] payload;
        try {
            payload = symmetricCipher.encrypt(Utils.concat(
                    sequenceNumberBytes,
                    data));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }

        // Set the length of the data in the header
        header[3] = (byte) (payload.length >> 8);
        header[4] = (byte) payload.length;

        byte[] dstpPacket = Utils.concat(header, payload);
        packet.setData(dstpPacket);
    }

    /**
     * Processes a received DSTP packet. The packet is decrypted and the sequence number is checked. Packets
     * with duplicate sequence numbers are discarded. The integrity proof is verified to ensure the packet
     * was not tampered with. If the packet is valid, the decrypted data is copied to the datagram packet's buffer.
     * @param packet packet to be processed
     * @return true, if the packet was successfully processed; false, if the packet was invalid
     */
    protected boolean processReceivedPacket(DatagramPacket packet) {
        byte[] data = packet.getData();
        int payloadLength = ((data[3] & 0xFF) << 8) | (data[4] & 0xFF);
        byte[] payload = Utils.subArray(data, header.length, header.length + payloadLength);

        byte[] decryptedData;
        byte[] receivedMessage;

        // If the packet cannot be decrypted, return false (this may happen with tampered packets when using padding)
        try {
            decryptedData = symmetricCipher.decrypt(payload);
            receivedMessage = Utils.subArray(decryptedData, 2, decryptedData.length);
        }
        catch (AEADBadTagException e) {
            LOGGER.severe("AEADBadTagException: " + e.getMessage());
            return false;
        }
        catch (BadPaddingException e) {
            LOGGER.warning("Received packet with invalid padding, this may be due to tampering or a bad key");
            return false;
        }
        catch (GeneralSecurityException e) {
            LOGGER.severe("GeneralSecurityException: " + e.getMessage());
            return false;
        }

        // Extract sequence number from decrypted data
        byte[] sequenceNumBytes = Utils.subArray(decryptedData, 0, 2);
        int sequenceNum = ((sequenceNumBytes[0] & 0xFF) << 8) | (sequenceNumBytes[1] & 0xFF);

        // Do not process packets with duplicate sequence numbers
        if (!receivedSequenceNumbers.add(sequenceNum))
        {
            LOGGER.severe("Received packet with duplicate sequence number: " + sequenceNum);
            return false;
        }

        // Copy validated data to packet buffer
        System.arraycopy(receivedMessage, 0, packet.getData(), packet.getOffset(), receivedMessage.length);

        packet.setLength(receivedMessage.length);
        return true;
    }
}
