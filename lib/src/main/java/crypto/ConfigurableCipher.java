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
    private IvParameterSpec staticIvSpec;
    private CipherMode cipherMode;
    private final SecureRandom secureRandom;

    ConfigurableCipher(String cipherAlgo, String hexKey, String hexIv, SecureRandom secureRandom)
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.cipher = Cipher.getInstance(cipherAlgo);
        setCipherMode(cipherAlgo);
        setCipherKey(hexKey);
        setCipherIv(hexIv);
        this.secureRandom = secureRandom;
    }

    ConfigurableCipher(String cipherAlgo, byte[] sharedSecret, SecureRandom secureRandom)
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.cipher = Cipher.getInstance(cipherAlgo);
        setCipherMode(cipherAlgo);
        setCipherKey(sharedSecret);
        setCipherIv(sharedSecret);
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

    private void setCipherKey(String hexValue) {
        this.key = new SecretKeySpec(Utils.hexStringToByteArray(hexValue), getAlgorithm());
    }

    private void setCipherIv(String hexValue) {
        if (hexValue != null) staticIvSpec = new IvParameterSpec(Utils.hexStringToByteArray(hexValue));
    }

    private void setCipherKey(byte[] sharedSecret) {
        byte[] digest = HashUtils.SHA3_512.digest(sharedSecret);
        String algorithm = getAlgorithm();
        switch (CipherParamSizes.permissiveValueOf(algorithm)) {
            case AES -> key = new SecretKeySpec(digest, 0, CipherParamSizes.AES.getKeySize(), algorithm);
            case BLOWFISH -> key = new SecretKeySpec(digest, 0, CipherParamSizes.BLOWFISH.getKeySize(), algorithm);
            case CHACHA20 -> key = new SecretKeySpec(digest, 0, CipherParamSizes.CHACHA20.getKeySize(), algorithm);
            case CHACHA20_POLY1305 -> key = new SecretKeySpec(digest, 0, CipherParamSizes.CHACHA20_POLY1305.getKeySize(), algorithm);
            case DES -> key = new SecretKeySpec(digest, 0, CipherParamSizes.DES.getKeySize(), algorithm);
            case TRIPLE_DES -> key = new SecretKeySpec(digest, 0, CipherParamSizes.TRIPLE_DES.getKeySize(), algorithm);
            case IDEA -> key = new SecretKeySpec(digest, 0, CipherParamSizes.IDEA.getKeySize(), algorithm);
            case RC4 -> key = new SecretKeySpec(digest, 0, CipherParamSizes.RC4.getKeySize(), algorithm);
            case RC6 -> key = new SecretKeySpec(digest, 0, CipherParamSizes.RC6.getKeySize(), algorithm);
            case null -> throw new IllegalStateException("Unsupported algorithm: " + algorithm);
        }
    }

    private void setCipherIv(byte[] sharedSecret) {
        byte[] digest = HashUtils.SHA3_256.digest(sharedSecret);
        if (cipher.getAlgorithm().contains("ECB")) { staticIvSpec = null; return; }
        String algorithm = getAlgorithm();
        switch (CipherParamSizes.permissiveValueOf(algorithm)) {
            case AES -> staticIvSpec = new IvParameterSpec(digest, 0, CipherParamSizes.AES.getIvSize());
            case BLOWFISH -> staticIvSpec = new IvParameterSpec(digest, 0, CipherParamSizes.BLOWFISH.getIvSize());
            case DES -> staticIvSpec = new IvParameterSpec(digest, 0, CipherParamSizes.DES.getIvSize());
            case TRIPLE_DES -> staticIvSpec = new IvParameterSpec(digest, 0, CipherParamSizes.TRIPLE_DES.getIvSize());
            case IDEA -> staticIvSpec = new IvParameterSpec(digest, 0, CipherParamSizes.IDEA.getIvSize());
            case RC6 -> staticIvSpec = new IvParameterSpec(digest, 0, CipherParamSizes.RC6.getIvSize());
            case CHACHA20, CHACHA20_POLY1305, RC4 -> staticIvSpec = null;
            case null -> throw new IllegalStateException("Unsupported algorithm: " + algorithm);
        }
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
                byte[] ciphertext = cipher.doFinal(data);
                byte[] combined = new byte[nonce.length + ciphertext.length];
                System.arraycopy(nonce, 0, combined, 0, nonce.length);
                System.arraycopy(ciphertext, 0, combined, nonce.length, ciphertext.length);
                yield combined;
            }
            case MANUAL_PADDING_CBC, MANUAL_PADDING_ECB -> {
                int blockSize = cipher.getBlockSize();
                int padding = blockSize - (data.length % blockSize);
                byte[] paddedData = new byte[data.length + padding];
                System.arraycopy(data, 0, paddedData, 0, data.length);
                for (int i = data.length; i < paddedData.length; i++) paddedData[i] = (byte) padding;
                if (cipherMode == CipherMode.MANUAL_PADDING_CBC) cipher.init(Cipher.ENCRYPT_MODE, key, staticIvSpec);
                else cipher.init(Cipher.ENCRYPT_MODE, key);
                yield cipher.doFinal(paddedData);
            }
            case NO_AEAD -> {
                if (staticIvSpec != null) cipher.init(Cipher.ENCRYPT_MODE, key, staticIvSpec);
                else cipher.init(Cipher.ENCRYPT_MODE, key);
                yield cipher.doFinal(data);
            }
        };
    }

    @Override
    public byte[] decrypt(byte[] encryptedData) throws GeneralSecurityException {
        return switch (cipherMode) {
            case GCM, CHACHA20_POLY1305, CHACHA20 -> {
                byte[] nonce = new byte[12];
                System.arraycopy(encryptedData, 0, nonce, 0, nonce.length);
                byte[] ciphertext = new byte[encryptedData.length - nonce.length];
                System.arraycopy(encryptedData, nonce.length, ciphertext, 0, ciphertext.length);
                if (cipherMode == CipherMode.GCM)
                    cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
                else if (cipherMode == CipherMode.CHACHA20_POLY1305)
                    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));
                else
                    cipher.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
                yield cipher.doFinal(ciphertext);
            }
            case MANUAL_PADDING_CBC, MANUAL_PADDING_ECB -> {
                if (cipherMode == CipherMode.MANUAL_PADDING_CBC) cipher.init(Cipher.DECRYPT_MODE, key, staticIvSpec);
                else cipher.init(Cipher.DECRYPT_MODE, key);
                byte[] decryptedData = cipher.doFinal(encryptedData);
                int padding = decryptedData[decryptedData.length - 1];
                yield Utils.subArray(decryptedData, 0, decryptedData.length - padding);
            }
            case NO_AEAD -> {
                if (staticIvSpec != null) cipher.init(Cipher.DECRYPT_MODE, key, staticIvSpec);
                else cipher.init(Cipher.DECRYPT_MODE, key);
                yield cipher.doFinal(encryptedData);
            }
        };
    }
}
