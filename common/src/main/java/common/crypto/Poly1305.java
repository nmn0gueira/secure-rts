package common.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

public final class Poly1305 {

    private static final String MAC_ALGO = "Poly1305";

    public static byte[] computeTag(byte[] key32, byte[] data) throws GeneralSecurityException {
        try {
            Mac mac = Mac.getInstance(MAC_ALGO);
            mac.init(new SecretKeySpec(key32, MAC_ALGO));
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            return computeTagBouncyCastle(key32, data);
        }
    }

    private static byte[] computeTagBouncyCastle(byte[] key32, byte[] data) {
        org.bouncycastle.crypto.macs.Poly1305 mac = new org.bouncycastle.crypto.macs.Poly1305();
        mac.init(new org.bouncycastle.crypto.params.KeyParameter(key32));
        mac.update(data, 0, data.length);
        byte[] out = new byte[16];
        mac.doFinal(out, 0);
        return out;
    }

    public static boolean verifyTag(byte[] expected, byte[] actual) {
        if (expected.length != actual.length) return false;
        int diff = 0;
        for (int i = 0; i < expected.length; i++) {
            diff |= expected[i] ^ actual[i];
        }
        return diff == 0;
    }
}
