package crypto;

import common.Utils;

import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyLoader {

    public static KeyPair loadKeyPairFromFile(String filePath, KeyFactory keyFactory) throws IOException {
        PrivateKey privateKey = null;
        PublicKey publicKey = null;

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(":");
                if (parts.length != 2) continue;
                String keyType = parts[0].trim();
                String keyData = parts[1].trim();
                if (keyType.equals("PublicKey"))
                    publicKey = loadPublicKey(Utils.hexStringToByteArray(keyData), keyFactory);
                else if (keyType.equals("PrivateKey"))
                    privateKey = loadPrivateKey(Utils.hexStringToByteArray(keyData), keyFactory);
            }
        }

        if (privateKey == null || publicKey == null)
            throw new IllegalStateException("Failed to load key pair from: " + filePath);
        return new KeyPair(publicKey, privateKey);
    }

    public static PublicKey loadPublicKeyFromFile(String filePath, KeyFactory keyFactory) throws IOException {
        PublicKey publicKey = null;

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(":");
                if (parts.length != 2) continue;
                if (parts[0].trim().equals("PublicKey"))
                    publicKey = loadPublicKey(Utils.hexStringToByteArray(parts[1].trim()), keyFactory);
            }
        }

        if (publicKey == null)
            throw new IllegalStateException("Failed to load public key from: " + filePath);
        return publicKey;
    }

    public static PrivateKey loadPrivateKey(byte[] privateKeyBytes, KeyFactory keyFactory) {
        try {
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static PublicKey loadPublicKey(byte[] publicKeyBytes, KeyFactory keyFactory) {
        try {
            return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
