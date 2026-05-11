package crypto;

import java.io.FileInputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class CertificateLoader {

    public record Identity(KeyPair keyPair, X509Certificate certificate) {
    }

    public static KeyStore loadKeyStore(String path, char[] password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        try (FileInputStream input = new FileInputStream(path)) {
            keyStore.load(input, password);
        }

        return keyStore;
    }

    public static Identity loadIdentity(String path, char[] storePassword, String alias, char[] keyPassword)
            throws Exception {
        KeyStore keyStore = loadKeyStore(path, storePassword);

        String selectedAlias = alias;
        if (selectedAlias == null || selectedAlias.isBlank()) {
            selectedAlias = firstKeyAlias(keyStore);
        }

        Key key = keyStore.getKey(selectedAlias, keyPassword);
        if (!(key instanceof PrivateKey privateKey)) {
            throw new IllegalStateException("Alias does not contain a private key: " + selectedAlias);
        }

        Certificate certificate = keyStore.getCertificate(selectedAlias);
        if (!(certificate instanceof X509Certificate x509Certificate)) {
            throw new IllegalStateException("Alias does not contain an X509 certificate: " + selectedAlias);
        }

        return new Identity(
                new KeyPair(x509Certificate.getPublicKey(), privateKey),
                x509Certificate);
    }

    public static X509Certificate decodeCertificate(byte[] encoded) throws GeneralSecurityException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new java.io.ByteArrayInputStream(encoded));
    }

    public static boolean isTrusted(X509Certificate certificate, KeyStore trustStore) throws GeneralSecurityException {
        certificate.checkValidity();

        if (trustStore.getCertificateAlias(certificate) != null) {
            return true;
        }

        Enumeration<String> aliases = trustStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate trusted = trustStore.getCertificate(alias);

            if (trusted instanceof X509Certificate trustedCert) {
                try {
                    certificate.verify(trustedCert.getPublicKey());
                    return true;
                } catch (GeneralSecurityException ignored) {
                }
            }
        }

        return false;
    }

    private static String firstKeyAlias(KeyStore keyStore) throws Exception {
        Enumeration<String> aliases = keyStore.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            if (keyStore.isKeyEntry(alias)) {
                return alias;
            }
        }

        throw new IllegalStateException("Keystore does not contain a key entry");
    }
}
