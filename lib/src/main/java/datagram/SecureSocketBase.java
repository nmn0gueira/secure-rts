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
    private static final short DSTP_VERSION = 0x0002;
    private static final byte DSTP_RELEASE = 0x01;

    private final CipherSuite suite;
    private long timestamp;
    private int sequenceNumber;
    private final Set<Integer> receivedSequenceNumbers;
    private static final Logger LOGGER = Logger.getLogger(SecureSocketBase.class.getName());

    private final byte[] header = new byte[]{
            (byte) (DSTP_VERSION >> 8), (byte) DSTP_VERSION, DSTP_RELEASE,
            0x00, 0x00
    };

    protected SecureSocketBase(CipherSuite suite) {
        this.suite = suite;
        this.timestamp = System.currentTimeMillis();
        this.receivedSequenceNumbers = new HashSet<>();
        LOGGER.setLevel(Level.OFF);
    }

    /**
     * Wraps the datagram payload in a DSTP packet. Layout depends on the cipher suite:
     *   AEAD (no separate integrity):  header || encrypt(seqNum || data)
     *   MAC  (integrity outside):      header || ciphertext || mac(ciphertext)
     *   Hash (integrity inside):       header || encrypt(seqNum || data || hash)
     *
     */
    protected void preparePacketForSend(DatagramPacket packet) {
        try {
            byte[] seqNumBytes = new byte[]{(byte) timestamp, (byte) sequenceNumber};
            byte[] data = Utils.subArray(packet.getData(), packet.getOffset(), packet.getLength());

            sequenceNumber++;
            if (sequenceNumber == 256) { sequenceNumber = 0; timestamp++; }

            byte[] payload;
            if (!suite.hasIntegrityCheck()) { // (Generally), if we are using an AEAD cipher
                payload = suite.cipher().encrypt(Utils.concat(seqNumBytes, data));
            } else if (suite.usesMac()) { // MAC, over the ciphertext
                byte[] ciphertext = suite.cipher().encrypt(Utils.concat(seqNumBytes, data));
                byte[] nonce = Utils.subArray(ciphertext, 0, Math.min(12, ciphertext.length));
                byte[] proof = suite.integrityCheck().createIntegrityProof(ciphertext, nonce);
                payload = Utils.concat(ciphertext, proof);
            } else { // Hash included inside the ciphertext
                byte[] proof = suite.integrityCheck().createIntegrityProof(data, seqNumBytes);
                payload = suite.cipher().encrypt(Utils.concat(seqNumBytes, data, proof));
            }

            header[3] = (byte) (payload.length >> 8);
            header[4] = (byte) payload.length;
            packet.setData(Utils.concat(header, payload));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Decrypts and validates a received DSTP packet. Returns false (and discards) if the
     * packet fails authentication or has a duplicate sequence number.
     */
    protected boolean processReceivedPacket(DatagramPacket packet) {
        byte[] data = packet.getData();
        int payloadLength = ((data[3] & 0xFF) << 8) | (data[4] & 0xFF);
        byte[] payload = Utils.subArray(data, header.length, header.length + payloadLength);

        byte[] decryptedData;
        byte[] receivedMessage;

        try {
            if (!suite.hasIntegrityCheck()) { // AEAD: just decrypt; cipher verifies integrity internally
                decryptedData = suite.cipher().decrypt(payload);
                receivedMessage = Utils.subArray(decryptedData, 2, decryptedData.length);
            } else if (suite.usesMac()) { // Verify the MAC over the ciphertext before decrypting
                int macSize = suite.integrityProofSize();
                byte[] ciphertext = Utils.subArray(payload, 0, payload.length - macSize);
                byte[] proof = Utils.subArray(payload, payload.length - macSize, payload.length);
                byte[] nonce = Utils.subArray(ciphertext, 0, Math.min(12, ciphertext.length));
                if (!suite.integrityCheck().verifyIntegrity(ciphertext, nonce, proof)) {
                    LOGGER.severe("MAC verification failed");
                    return false;
                }
                decryptedData = suite.cipher().decrypt(ciphertext);
                receivedMessage = Utils.subArray(decryptedData, 2, decryptedData.length);
            } else { // Hash is included at the end of the decrypted plaintext
                decryptedData = suite.cipher().decrypt(payload);
                int hashSize = suite.integrityProofSize();
                receivedMessage = Utils.subArray(decryptedData, 2, decryptedData.length - hashSize);
                byte[] seqNumBytes = Utils.subArray(decryptedData, 0, 2);
                byte[] proof = Utils.subArray(decryptedData, decryptedData.length - hashSize, decryptedData.length);
                if (!suite.integrityCheck().verifyIntegrity(receivedMessage, seqNumBytes, proof)) {
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
