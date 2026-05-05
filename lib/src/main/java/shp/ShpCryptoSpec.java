package shp;

import crypto.DhKeyAgreement;
import crypto.EcdsaSignature;
import crypto.EciesCipher;
import crypto.KeyLoader;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

public class ShpCryptoSpec {

    public static final int USER_ID_MAX_SIZE = 320;
    public static final int SALT_SIZE = 8;
    public static final int NONCE_SIZE = 16;

    public static final String REQUEST_CONFIRMATION = "OK";
    public static final String FINISH_PROTOCOL = "GO";

    private static final String EC_CURVE = "secp256r1";

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final KeyPair ecKeyPair;
    private final EcdsaSignature ecdsaSignature;
    private final EciesCipher eciesCipher;
    private final DhKeyAgreement dhKeyAgreement;

    public ShpCryptoSpec() {
        try {
            KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC", "BC");
            ecGen.initialize(new ECGenParameterSpec(EC_CURVE));
            ecKeyPair = ecGen.generateKeyPair();
            ecdsaSignature = new EcdsaSignature();
            eciesCipher = new EciesCipher();
            dhKeyAgreement = new DhKeyAgreement();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] sign(byte[] data) throws GeneralSecurityException {
        return ecdsaSignature.sign(ecKeyPair.getPrivate(), data);
    }

    public boolean verifySignature(PublicKey publicKey, byte[] data, byte[] signature) throws GeneralSecurityException {
        return ecdsaSignature.verify(publicKey, data, signature);
    }

    public byte[] asymmetricEncrypt(byte[] data, PublicKey publicKey) throws GeneralSecurityException {
        return eciesCipher.encrypt(data, publicKey);
    }

    public byte[] asymmetricDecrypt(byte[] encryptedData) throws GeneralSecurityException {
        return eciesCipher.decrypt(encryptedData, ecKeyPair.getPrivate());
    }

    public byte[] generateSharedSecret(PublicKey peerDhPublicKey) throws InvalidKeyException {
        dhKeyAgreement.doPhase(peerDhPublicKey);
        return dhKeyAgreement.generateSecret();
    }

    public byte[] getYdhBytes() {
        return dhKeyAgreement.getPublicKey().getEncoded();
    }

    public PublicKey getEcPublicKey() {
        return ecKeyPair.getPublic();
    }

    public byte[] getEcPublicKeyBytes() {
        return ecKeyPair.getPublic().getEncoded();
    }

    public static byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_SIZE];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static byte[] generateIterationBytes() {
        byte[] iter = new byte[4];
        new SecureRandom().nextBytes(iter);
        return iter;
    }

    public static PublicKey loadPublicKey(byte[] encoded) throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePublic(new X509EncodedKeySpec(encoded));
    }

    public static PublicKey loadPublicKeyFromFile(String path) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return KeyLoader.loadPublicKeyFromFile(path, kf);
    }
}
