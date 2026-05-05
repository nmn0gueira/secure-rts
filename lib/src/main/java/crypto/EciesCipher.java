package crypto;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class EciesCipher implements AsymmetricCipher {

    private final Cipher cipher;

    public EciesCipher() {
        try {
            cipher = Cipher.getInstance("ECIES", "BC");
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] encrypt(byte[] data, PublicKey publicKey) throws GeneralSecurityException {
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) throws GeneralSecurityException {
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }
}
