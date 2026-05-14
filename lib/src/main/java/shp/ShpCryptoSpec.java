package shp;

import crypto.EcdhKeyAgreement;
import crypto.EcdsaSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.cert.X509Certificate;

public class ShpCryptoSpec {

    public static final int NONCE_SIZE = 16;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final PrivateKey signingKey;
    private final EcdsaSignature ecdsaSignature;
    private final EcdhKeyAgreement ecdhKeyAgreement;

    private final X509Certificate certificate;

    public ShpCryptoSpec(PrivateKey signingKey, X509Certificate certificate) {
        this.signingKey = signingKey;
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
        return ecdsaSignature.sign(signingKey, data);
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
        return certificate.getPublicKey();
    }

    public byte[] getEcPublicKeyBytes() {
        return certificate.getPublicKey().getEncoded();
    }

    public static byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_SIZE];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static PublicKey loadPublicKey(byte[] encoded) throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePublic(new X509EncodedKeySpec(encoded));
    }
}
