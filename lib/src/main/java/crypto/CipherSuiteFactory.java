package crypto;

import common.Utils;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Map;

public class CipherSuiteFactory {

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * Build a CipherSuite from a config file. Crypto keys are read directly from the file as hex strings.
     * Config format (one entry per line, colon-separated):
     *   CONFIDENTIALITY: JCE cipher string or DPRG
     *   SYMMETRIC_KEY:   hex key
     *   IV:              hex iv   (optional)
     *   INTEGRITY:       NULL | MAC | H
     *   MAC:             MAC algorithm
     *   MAC_KEY:         hex key
     *   H:               hash algorithm
     */
    public static CipherSuite fromFile(String configPath) {
        Map<CryptoConfigKey, String> config = CryptoConfigParser.parseFile(configPath);
        return buildFromMap(config, null, new SecureRandom());
    }

    /**
     * Build a CipherSuite from an inline config string with a shared secret for key derivation.
     */
    public static CipherSuite fromConfig(String config, byte[] sharedSecret) {
        Map<CryptoConfigKey, String> map = CryptoConfigParser.parseString(config);
        return buildFromMap(map, sharedSecret, new SecureRandom());
    }

    public static SymmetricCipher sharedKeyCipher(byte[] key) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            byte[] iv = new byte[16];
            System.arraycopy(key, 0, iv, 0, Math.min(key.length, 16));
            javax.crypto.spec.IvParameterSpec ivSpec = new javax.crypto.spec.IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            return new SymmetricCipher() {
                @Override
                public byte[] encrypt(byte[] data) throws GeneralSecurityException {
                    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                    return cipher.doFinal(data);
                }
                @Override
                public byte[] decrypt(byte[] encryptedData) throws GeneralSecurityException {
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
                    return cipher.doFinal(encryptedData);
                }
            };
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static IntegrityCheck hmacSha256(byte[] key) throws GeneralSecurityException {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return new IntegrityCheck() {
            @Override
            public byte[] createIntegrityProof(byte[] data, byte[] nonce) throws GeneralSecurityException {
                mac.update(data);
                return mac.doFinal();
            }
            @Override
            public int getIntegrityProofSize() { return mac.getMacLength(); }
            @Override
            public boolean isMac() { return true; }
        };
    }

    private static CipherSuite buildFromMap(Map<CryptoConfigKey, String> config, byte[] sharedSecret, SecureRandom random) {
        SymmetricCipher cipher = null;
        IntegrityCheck integrityCheck = null;

        String cipherAlgo = config.get(CryptoConfigKey.CONFIDENTIALITY);
        if (cipherAlgo != null) {
            try {
                if ("DPRG".equalsIgnoreCase(cipherAlgo)) {
                    byte[] keyBytes;
                    if (sharedSecret != null) {
                        keyBytes = Utils.subArray(HashUtils.SHA3_512.digest(sharedSecret), 0, 16);
                    } else {
                        keyBytes = Utils.hexStringToByteArray(config.get(CryptoConfigKey.SYMMETRIC_KEY));
                    }
                    cipher = new MyStreamCipher(keyBytes);
                } else {
                    if (sharedSecret != null) {
                        cipher = new ConfigurableCipher(cipherAlgo, sharedSecret, random);
                    } else {
                        String key = config.get(CryptoConfigKey.SYMMETRIC_KEY);
                        String iv = config.get(CryptoConfigKey.IV);
                        cipher = new ConfigurableCipher(cipherAlgo, key, iv, random);
                    }
                }
            } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        String integrityType = config.get(CryptoConfigKey.INTEGRITY);
        if (integrityType != null) {
            boolean isMac = !integrityType.equals("H");
            String hashAlgo = config.get(CryptoConfigKey.H);
            String macAlgo = config.get(CryptoConfigKey.MAC);
            try {
                if (sharedSecret != null) {
                    integrityCheck = new ConfigurableIntegrityCheck(isMac, hashAlgo, macAlgo, sharedSecret);
                } else {
                    String macKey = config.get(CryptoConfigKey.MAC_KEY);
                    integrityCheck = new ConfigurableIntegrityCheck(isMac, hashAlgo, macAlgo, macKey);
                }
            } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
            }
        }

        return new CipherSuite(cipher, integrityCheck);
    }
}
