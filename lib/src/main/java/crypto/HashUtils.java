package crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.nio.charset.StandardCharsets;
import java.security.*;

public class HashUtils {

    public static final MessageDigest SHA256;
    public static final MessageDigest SHA3_256;
    public static final MessageDigest SHA3_512;

    static {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            SHA256 = MessageDigest.getInstance("SHA-256", "BC");
            SHA3_256 = MessageDigest.getInstance("SHA3-256", "BC");
            SHA3_512 = MessageDigest.getInstance("SHA3-512", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] hkdf(byte[] ikm, String info, int outputLength) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(ikm, null, info.getBytes(StandardCharsets.UTF_8)));
        byte[] output = new byte[outputLength];
        hkdf.generateBytes(output, 0, outputLength);
        return output;
    }
}
