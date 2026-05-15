package datagram;

import common.Utils;
import crypto.CipherSuite;

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
    private static final short RTSSP_VERSION = 0x0003;
    private static final byte RTSSP_CONTENT_TYPE_APPLICATION_DATA = 0x17;
    private static final int RTSSP_HEADER_SIZE = 5;

    private final CipherSuite suite;
    private long timestamp;
    private int sequenceNumber;
    private final Set<Integer> receivedSequenceNumbers;
    private static final Logger LOGGER = Logger.getLogger(SecureSocketBase.class.getName());

    private final byte[] header = new byte[]{
            RTSSP_CONTENT_TYPE_APPLICATION_DATA,
            (byte) (RTSSP_VERSION >> 8),
            (byte) RTSSP_VERSION,
            0x00,
            0x00
    };

    protected SecureSocketBase(CipherSuite suite) {
        this.suite = suite;
        this.timestamp = System.currentTimeMillis();
        this.receivedSequenceNumbers = new HashSet<>();
        LOGGER.setLevel(Level.OFF);
    }

    protected void preparePacketForSend(DatagramPacket packet) {
        try {
            byte[] seqNumBytes = new byte[]{(byte) timestamp, (byte) sequenceNumber};
            byte[] data = Utils.subArray(packet.getData(), packet.getOffset(), packet.getLength());

            sequenceNumber++;
            if (sequenceNumber == 256) { sequenceNumber = 0; timestamp++; }

            byte[] payload;
            if (!suite.hasIntegrityCheck()) {
                payload = suite.cipher().encrypt(Utils.concat(seqNumBytes, data));
            } else if (suite.usesMac()) {
                byte[] ciphertext = suite.cipher().encrypt(Utils.concat(seqNumBytes, data));
                byte[] proof = suite.integrityCheck().createIntegrityProof(ciphertext);
                payload = Utils.concat(ciphertext, proof);
            } else {
                byte[] proof = suite.integrityCheck().createIntegrityProof(data);
                payload = suite.cipher().encrypt(Utils.concat(seqNumBytes, data, proof));
            }

            header[3] = (byte) (payload.length >> 8);
            header[4] = (byte) payload.length;
            packet.setData(Utils.concat(header, payload));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    protected boolean processReceivedPacket(DatagramPacket packet) {
        byte[] data = packet.getData();
        
        if (packet.getLength() < RTSSP_HEADER_SIZE) {
            LOGGER.warning("RTSSP packet too short");
            return false;
        }

        if (data[0] != RTSSP_CONTENT_TYPE_APPLICATION_DATA) {
            LOGGER.warning("Invalid RTSSP content type.");
            return false;
        }

        short version = (short) (((data[1] & 0xFF) << 8) | (data[2] & 0xFF));
        if (version != RTSSP_VERSION) {
            LOGGER.warning("Unsupported RTSSP version.");
            return false;
        }

        int payloadLength = ((data[3] & 0xFF) << 8) | (data[4] & 0xFF);
        if (payloadLength != packet.getLength() - RTSSP_HEADER_SIZE) {
            LOGGER.warning("Invalid RTSSP payload length");
            return false;
        }

        byte[] payload = Utils.subArray(data, RTSSP_HEADER_SIZE, RTSSP_HEADER_SIZE + payloadLength);

        byte[] decryptedData;
        byte[] receivedMessage;

        try {
            if (!suite.hasIntegrityCheck()) {
                decryptedData = suite.cipher().decrypt(payload);
                receivedMessage = Utils.subArray(decryptedData, 2, decryptedData.length);
            } else if (suite.usesMac()) {
                int macSize = suite.integrityProofSize();
                byte[] ciphertext = Utils.subArray(payload, 0, payload.length - macSize);
                byte[] proof = Utils.subArray(payload, payload.length - macSize, payload.length);
                if (!suite.integrityCheck().verifyIntegrity(ciphertext, proof)) {
                    LOGGER.severe("MAC verification failed");
                    return false;
                }
                decryptedData = suite.cipher().decrypt(ciphertext);
                receivedMessage = Utils.subArray(decryptedData, 2, decryptedData.length);
            } else {
                decryptedData = suite.cipher().decrypt(payload);
                int hashSize = suite.integrityProofSize();
                receivedMessage = Utils.subArray(decryptedData, 2, decryptedData.length - hashSize);
                byte[] seqNumBytes = Utils.subArray(decryptedData, 0, 2);
                byte[] proof = Utils.subArray(decryptedData, decryptedData.length - hashSize, decryptedData.length);
                if (!suite.integrityCheck().verifyIntegrity(receivedMessage, proof)) {
                    LOGGER.severe("Hash verification failed");
                    return false;
                }
            }
        } catch (AEADBadTagException e) {
            LOGGER.severe("AEAD tag check failed: " + e.getMessage());
            return false;
        } catch (BadPaddingException e) {
            LOGGER.warning("Invalid padding — possible tampering");
            return false;
        } catch (GeneralSecurityException e) {
            LOGGER.severe("GeneralSecurityException: " + e.getMessage());
            return false;
        }

        byte[] seqNumBytes = Utils.subArray(decryptedData, 0, 2);
        int seqNum = ((seqNumBytes[0] & 0xFF) << 8) | (seqNumBytes[1] & 0xFF);
        if (!receivedSequenceNumbers.add(seqNum)) {
            LOGGER.severe("Duplicate sequence number: " + seqNum);
            return false;
        }

        System.arraycopy(receivedMessage, 0, packet.getData(), packet.getOffset(), receivedMessage.length);
        packet.setLength(receivedMessage.length);
        return true;
    }
}
