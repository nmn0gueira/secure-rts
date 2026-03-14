/**
 * AES-CTR based pseudo random generator from labs that was re-purposed for keystream generation.
 * Changes include allowing instantiation with fixed key and having a counter isolated for each evaluate() call. This allows us to guarantee correct decryption even for out of order packets as the counter does not change between them.
 * Since the nonce is still unique every call we still ensure that the combo of key/nonce/counter is never the same
 */


package common.crypto.prng;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class AesCtrKeystreamGenerator {

    private final SecretKey key;
    private long counter = 0;

    public AesCtrKeystreamGenerator() {

        // Generate strong key using SecureRandom
        KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        keyGen.init(256);
        key = keyGen.generateKey();
    }

    public AesCtrKeystreamGenerator(byte[] key) {
        this.key = new SecretKeySpec(key, "AES");
    }

    private byte[] hashInput(byte[] input) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return digest.digest(input);
    }

    private byte[] nextCounterBlock(byte[] inputHash) {

        byte[] counterBlock = new byte[16];

        // first 8 bytes from input hash
        System.arraycopy(inputHash, 0, counterBlock, 0, 8);

        // last 8 bytes from internal counter
        for (int i = 0; i < 8; i++) {
            counterBlock[15 - i] = (byte)(counter >>> (8 * i));
        }

        counter++;

        return counterBlock;
    }

    public byte[] evaluate(byte[] input, int outputLength) throws InvalidAlgorithmParameterException, InvalidKeyException {
        counter = 0;
        byte[] inputHash = hashInput(input);

        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }

        byte[] iv = Arrays.copyOfRange(inputHash, 0, 16);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        byte[] result = new byte[outputLength];
        int generated = 0;

        while (generated < outputLength) {

            byte[] counterBlock = nextCounterBlock(inputHash);
            byte[] block = cipher.update(counterBlock);

            int copy = Math.min(block.length, outputLength - generated);
            System.arraycopy(block, 0, result, generated, copy);

            generated += copy;
        }

        return result;
    }
}
