package crypto;

import common.Utils;

import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

enum MacMode {
    AESGMAC("AESGMAC"), RC6GMAC("RC6GMAC"),
    AESGMACFAST("AES-GMAC"), RC6GMACFAST("RC6-GMAC"),
    HMAC("hmac");

    private final String modeName;
    MacMode(String modeName) { this.modeName = modeName; }
    public String getModeName() { return modeName; }
}

class ConfigurableIntegrityCheck implements IntegrityCheck {

    private MacMode macMode;
    private MessageDigest hash;
    private Mac mac;
    private Key hMacKey;
    private final boolean isMac;

    ConfigurableIntegrityCheck(boolean isMac, String hashAlgorithm, String macAlgorithm, byte[] keyMaterial)
            throws GeneralSecurityException {
        this.isMac = isMac;
        if (isMac) { mac = Mac.getInstance(macAlgorithm); setMacMode(macAlgorithm); setMacKey(keyMaterial); }
        else { hash = MessageDigest.getInstance(hashAlgorithm); }
    }

    @Override
    public byte[] createIntegrityProof(byte[] data, byte[] nonce) throws GeneralSecurityException {
        if (isMac) {
            return switch (macMode) {
                case HMAC -> mac.doFinal(data);
                case AESGMAC, RC6GMAC, AESGMACFAST, RC6GMACFAST -> {
                    Mac freshMac = Mac.getInstance(mac.getAlgorithm());
                    freshMac.init(hMacKey, new IvParameterSpec(Utils.fitToSize(nonce, 12)));
                    yield freshMac.doFinal(data);
                }
            };
        }
        return hash.digest(data);
    }

    private void setMacMode(String value) {
        if (value.equals(MacMode.AESGMAC.getModeName())) macMode = MacMode.AESGMAC;
        else if (value.equals(MacMode.AESGMACFAST.getModeName())) macMode = MacMode.AESGMACFAST;
        else if (value.equals(MacMode.RC6GMAC.getModeName())) macMode = MacMode.RC6GMAC;
        else if (value.equals(MacMode.RC6GMACFAST.getModeName())) macMode = MacMode.RC6GMACFAST;
        else macMode = MacMode.HMAC;
    }

    private void setMacKey(byte[] sharedSecret) throws InvalidKeyException {
        byte[] digest = HashUtils.SHA3_512.digest(sharedSecret);
        int keySize = getIntegrityProofSize();
        switch (macMode) {
            case HMAC -> { hMacKey = new SecretKeySpec(digest, 0, keySize, mac.getAlgorithm()); mac.init(hMacKey); }
            case AESGMAC, AESGMACFAST -> hMacKey = new SecretKeySpec(digest, 0, keySize, "AES");
            case RC6GMAC, RC6GMACFAST -> hMacKey = new SecretKeySpec(digest, 0, keySize, "RC6");
        }
    }

    @Override
    public int getIntegrityProofSize() { return isMac ? mac.getMacLength() : hash.getDigestLength(); }

    @Override
    public boolean isMac() { return isMac; }
}
