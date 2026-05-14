package datagram;

import crypto.CipherSuite;
import crypto.SymmetricCipher;
import org.junit.jupiter.api.Test;

import java.net.DatagramPacket;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class SecureSocketBaseTest {

    private static final byte[] MESSAGE = "hello rtssp".getBytes();

    @Test
    void preparePacketUsesRtsspHeader() {
        DatagramPacket packet = new DatagramPacket(MESSAGE.clone(), MESSAGE.length);
        new SecureSocketBase(identitySuite()).preparePacketForSend(packet);

        byte[] data = packet.getData();
        int payloadLength = ((data[3] & 0xFF) << 8) | (data[4] & 0xFF);

        assertEquals(0x17, data[0]);
        assertEquals(0x00, data[1]);
        assertEquals(0x03, data[2]);
        assertEquals(packet.getLength() - 5, payloadLength);
    }

    @Test
    void processReceivedPacketAcceptsRtsspHeader() {
        DatagramPacket packet = new DatagramPacket(MESSAGE.clone(), MESSAGE.length);

        new SecureSocketBase(identitySuite()).preparePacketForSend(packet);
        assertTrue(new SecureSocketBase(identitySuite()).processReceivedPacket(packet));

        assertArrayEquals(MESSAGE, Arrays.copyOf(packet.getData(), packet.getLength()));
    }

    private static CipherSuite identitySuite() {
        return new CipherSuite(new SymmetricCipher() {
            @Override
            public byte[] encrypt(byte[] data) throws GeneralSecurityException {
                return data;
            }

            @Override
            public byte[] decrypt(byte[] encryptedData) throws GeneralSecurityException {
                return encryptedData;
            }
        }, null);
    }
}
