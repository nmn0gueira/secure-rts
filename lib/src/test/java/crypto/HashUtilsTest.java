package crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HashUtilsTest {

    @Test
    void sha256OutputLength() {
        byte[] digest = HashUtils.SHA256.digest("test".getBytes());
        assertEquals(32, digest.length);
    }

    @Test
    void sha3_256OutputLength() {
        byte[] digest = HashUtils.SHA3_256.digest("test".getBytes());
        assertEquals(32, digest.length);
    }

    @Test
    void sha3_512OutputLength() {
        byte[] digest = HashUtils.SHA3_512.digest("test".getBytes());
        assertEquals(64, digest.length);
    }

    @Test
    void sha256KnownValue() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469348423f656b85ce38 (first byte: 0xba)
        byte[] digest = HashUtils.SHA256.digest("abc".getBytes());
        assertEquals((byte) 0xba, digest[0]);
        assertEquals((byte) 0x78, digest[1]);
        assertEquals((byte) 0x16, digest[2]);
    }

    @Test
    void sha256IsDeterministic() {
        byte[] d1 = HashUtils.SHA256.digest("hello".getBytes());
        byte[] d2 = HashUtils.SHA256.digest("hello".getBytes());
        assertArrayEquals(d1, d2);
    }

    @Test
    void sha3_512IsDeterministic() {
        byte[] d1 = HashUtils.SHA3_512.digest("hello".getBytes());
        byte[] d2 = HashUtils.SHA3_512.digest("hello".getBytes());
        assertArrayEquals(d1, d2);
    }

    @Test
    void differentInputsProduceDifferentHashes() {
        byte[] d1 = HashUtils.SHA256.digest("a".getBytes());
        byte[] d2 = HashUtils.SHA256.digest("b".getBytes());
        assertFalse(java.util.Arrays.equals(d1, d2));
    }
}
