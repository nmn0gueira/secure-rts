package shp;

import crypto.EcdhKeyAgreement;
import crypto.EcdsaSignature;
import crypto.KeyLoader;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.cert.X509Certificate;

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
    private final EcdhKeyAgreement ecdhKeyAgreement;

    private final X509Certificate certificate;

    public ShpCryptoSpec(KeyPair signingKeyPair, X509Certificate certificate) {
        this.ecKeyPair = signingKeyPair;
        this.certificate = certificate;
        ecdsaSignature = new EcdsaSignature();
        ecdhKeyAgreement = new EcdhKeyAgreement();
    }

    public byte[] getCertificateBytes() throws GeneralSecurityException {
        if (certificate == null)
            throw new IllegalStateException("No certificate loaded");
        return certificate.getEncoded();
    }

    public byte[] sign(byte[] data) throws GeneralSecurityException {
        return ecdsaSignature.sign(ecKeyPair.getPrivate(), data);
    }

    public boolean verifySignature(PublicKey publicKey, byte[] data, byte[] signature) throws GeneralSecurityException {
        return ecdsaSignature.verify(publicKey, data, signature);
    }

    public byte[] generateSharedSecret(PublicKey peerEcdhPublicKey) throws InvalidKeyException {
        ecdhKeyAgreement.doPhase(peerEcdhPublicKey);
        return ecdhKeyAgreement.generateSecret();
    }

    public byte[] getEcdhPublicKeyBytes() {
        return ecdhKeyAgreement.getPublicKey().getEncoded();
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
