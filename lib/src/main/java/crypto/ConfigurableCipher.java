package crypto;

import common.Utils;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

enum CipherMode {
    NO_AEAD("No AEAD"),
    MANUAL_PADDING_CBC("CBC/NoPadding"),
    MANUAL_PADDING_ECB("ECB/NoPadding"),
    GCM("GCM"),
    CHACHA20_POLY1305("ChaCha20-Poly1305"),
    CHACHA20("ChaCha20");

    private final String modeName;
    CipherMode(String algorithm) { this.modeName = algorithm; }
    public String getModeName() { return modeName; }
}

enum CipherParamSizes {
    AES("AES", 32, 16), BLOWFISH("BLOWFISH", 56, 8), CHACHA20("ChaCha20", 32, 0),
    CHACHA20_POLY1305("ChaCha20-Poly1305", 32, 0), DES("DES", 8, 8),
    TRIPLE_DES("DESede", 24, 8), IDEA("IDEA", 16, 8), RC4("RC4", 56, 0), RC6("RC6", 32, 16);

    private final String name;
    private final int keySize;
    private final int ivSize;

    CipherParamSizes(String name, int keySize, int ivSize) {
        this.name = name; this.keySize = keySize; this.ivSize = ivSize;
    }
    public String getName() { return name; }
    public int getKeySize() { return keySize; }
    public int getIvSize() { return ivSize; }

    public static CipherParamSizes permissiveValueOf(String name) {
        for (CipherParamSizes v : values()) {
            if (v.getName().equals(name)) return v;
        }
        return null;
    }
}

class ConfigurableCipher implements SymmetricCipher {

    private final Cipher cipher;
    private SecretKey key;
    private CipherMode cipherMode;
    private final SecureRandom secureRandom;

    ConfigurableCipher(String cipherAlgo, byte[] keyMaterial, SecureRandom secureRandom)
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        this(cipherAlgo, keyMaterial, 0, secureRandom);
    }

    ConfigurableCipher(String cipherAlgo, byte[] keyMaterial, int keySizeBytes, SecureRandom secureRandom)
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.cipher = Cipher.getInstance(cipherAlgo);
        setCipherMode(cipherAlgo);
        setCipherKey(keyMaterial, keySizeBytes);
        this.secureRandom = secureRandom;
    }

    private void setCipherMode(String value) {
        if (value.contains(CipherMode.GCM.getModeName())) cipherMode = CipherMode.GCM;
        else if (value.equals(CipherMode.CHACHA20_POLY1305.getModeName())) cipherMode = CipherMode.CHACHA20_POLY1305;
        else if (value.equals(CipherMode.CHACHA20.getModeName())) cipherMode = CipherMode.CHACHA20;
        else if (value.contains(CipherMode.MANUAL_PADDING_CBC.getModeName())) cipherMode = CipherMode.MANUAL_PADDING_CBC;
        else if (value.contains(CipherMode.MANUAL_PADDING_ECB.getModeName())) cipherMode = CipherMode.MANUAL_PADDING_ECB;
        else cipherMode = CipherMode.NO_AEAD;
    }

    private void setCipherKey(byte[] keyMaterial, int keySizeBytes) {
        String algorithm = getAlgorithm();
        CipherParamSizes params = CipherParamSizes.permissiveValueOf(algorithm);
        if (params == null) throw new IllegalStateException("Unsupported algorithm: " + algorithm);
        int size = keySizeBytes > 0 ? keySizeBytes : params.getKeySize();
        key = new SecretKeySpec(HashUtils.hkdf(keyMaterial, "cipher-key", size), algorithm);
    }

    private static byte[] manualPad(byte[] data, int blockSize) {
        int padding = blockSize - (data.length % blockSize);
        byte[] padded = new byte[data.length + padding];
        System.arraycopy(data, 0, padded, 0, data.length);
        for (int i = data.length; i < padded.length; i++) padded[i] = (byte) padding;
        return padded;
    }

    private static byte[] manualUnpad(byte[] data) {
        int padding = data[data.length - 1];
        return Utils.subArray(data, 0, data.length - padding);
    }

    private String getAlgorithm() { return cipher.getAlgorithm().split("/")[0]; }

    @Override
    public byte[] encrypt(byte[] data) throws GeneralSecurityException {
        return switch (cipherMode) {
            case GCM, CHACHA20_POLY1305, CHACHA20 -> {
                byte[] nonce = new byte[12];
                secureRandom.nextBytes(nonce);
                if (cipherMode == CipherMode.GCM)
                    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
                else if (cipherMode == CipherMode.CHACHA20_POLY1305)
                    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
                else
                    cipher.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
                yield Utils.concat(nonce, cipher.doFinal(data));
            }
            case MANUAL_PADDING_CBC -> {
                int blockSize = cipher.getBlockSize();
                byte[] iv = new byte[blockSize];
                secureRandom.nextBytes(iv);
                cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
                yield Utils.concat(iv, cipher.doFinal(manualPad(data, blockSize)));
            }
            case MANUAL_PADDING_ECB -> {
                int blockSize = cipher.getBlockSize();
                cipher.init(Cipher.ENCRYPT_MODE, key);
                yield cipher.doFinal(manualPad(data, blockSize));
            }
            case NO_AEAD -> {
                int blockSize = cipher.getBlockSize();
                if (blockSize > 0 && !cipher.getAlgorithm().contains("ECB")) {
                    byte[] iv = new byte[blockSize];
                    secureRandom.nextBytes(iv);
                    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
                    yield Utils.concat(iv, cipher.doFinal(data));
                } else {
                    cipher.init(Cipher.ENCRYPT_MODE, key);
                    yield cipher.doFinal(data);
                }
            }
        };
    }

    @Override
    public byte[] decrypt(byte[] encryptedData) throws GeneralSecurityException {
        return switch (cipherMode) {
            case GCM, CHACHA20_POLY1305, CHACHA20 -> {
                byte[] nonce = Utils.subArray(encryptedData, 0, 12);
                byte[] ciphertext = Utils.subArray(encryptedData, 12, encryptedData.length);
                if (cipherMode == CipherMode.GCM)
                    cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
                else if (cipherMode == CipherMode.CHACHA20_POLY1305)
                    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));
                else
                    cipher.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
                yield cipher.doFinal(ciphertext);
            }
            case MANUAL_PADDING_CBC -> {
                int blockSize = cipher.getBlockSize();
                byte[] iv = Utils.subArray(encryptedData, 0, blockSize);
                byte[] ciphertext = Utils.subArray(encryptedData, blockSize, encryptedData.length);
                cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                yield manualUnpad(cipher.doFinal(ciphertext));
            }
            case MANUAL_PADDING_ECB -> {
                cipher.init(Cipher.DECRYPT_MODE, key);
                yield manualUnpad(cipher.doFinal(encryptedData));
            }
            case NO_AEAD -> {
                int blockSize = cipher.getBlockSize();
                if (blockSize > 0 && !cipher.getAlgorithm().contains("ECB")) {
                    byte[] iv = Utils.subArray(encryptedData, 0, blockSize);
                    byte[] ciphertext = Utils.subArray(encryptedData, blockSize, encryptedData.length);
                    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                    yield cipher.doFinal(ciphertext);
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, key);
                    yield cipher.doFinal(encryptedData);
                }
            }
        };
    }
}
