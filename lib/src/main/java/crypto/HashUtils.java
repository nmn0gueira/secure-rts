package crypto;

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
}
