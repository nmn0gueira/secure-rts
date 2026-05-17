package shp.pq;

import common.Utils;
import crypto.MlDsaSignature;
import crypto.MlKemEncapsulation;

import java.security.*;
import java.security.cert.X509Certificate;

public class PqShpCryptoSpec {

    public static final int NONCE_SIZE = 16;

    private final PrivateKey signingKey;
    private final X509Certificate certificate;
    private final MlDsaSignature mlDsa;
    private final MlKemEncapsulation mlKem;

    public PqShpCryptoSpec(PrivateKey signingKey, X509Certificate certificate) {
        this.signingKey = signingKey;
        this.certificate = certificate;
        this.mlDsa = new MlDsaSignature();
        this.mlKem = new MlKemEncapsulation();
    }

    public byte[] getCertificateBytes() throws GeneralSecurityException {
        return certificate.getEncoded();
    }

    public byte[] sign(byte[] data) throws GeneralSecurityException {
        return mlDsa.sign(signingKey, data);
    }

    public boolean verifySignature(PublicKey publicKey, byte[] data, byte[] signature) throws GeneralSecurityException {
        return mlDsa.verify(publicKey, data, signature);
    }

    public byte[] getKemPublicKeyBytes() {
        return mlKem.getPublicKeyBytes();
    }

    public byte[] decapsulate(byte[] ciphertext) throws GeneralSecurityException {
        return mlKem.decapsulate(ciphertext);
    }

    public static MlKemEncapsulation.KemResult encapsulate(byte[] clientKemPublicKeyBytes)
            throws GeneralSecurityException {
        return MlKemEncapsulation.encapsulate(clientKemPublicKeyBytes);
    }

    public static byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_SIZE];
        Utils.SECURE_RANDOM.nextBytes(nonce);
        return nonce;
    }
}
