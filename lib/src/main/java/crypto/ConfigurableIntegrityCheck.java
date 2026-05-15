package crypto;

import common.Utils;

import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.SecureRandom;

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
    private final SecureRandom secureRandom = new SecureRandom();

    ConfigurableIntegrityCheck(boolean isMac, String hashAlgorithm, String macAlgorithm, byte[] keyMaterial)
            throws GeneralSecurityException {
        this.isMac = isMac;
        if (isMac) { mac = Mac.getInstance(macAlgorithm); setMacMode(macAlgorithm); setMacKey(keyMaterial); }
        else { hash = MessageDigest.getInstance(hashAlgorithm); }
    }

    @Override
    public byte[] createIntegrityProof(byte[] data) throws GeneralSecurityException {
        if (isMac) {
            return switch (macMode) {
                case HMAC -> mac.doFinal(data);
                case AESGMAC, RC6GMAC, AESGMACFAST, RC6GMACFAST -> {
                    byte[] gmacNonce = new byte[12];
                    secureRandom.nextBytes(gmacNonce);
                    Mac freshMac = Mac.getInstance(mac.getAlgorithm());
                    freshMac.init(hMacKey, new IvParameterSpec(gmacNonce));
                    yield Utils.concat(gmacNonce, freshMac.doFinal(data));
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

    @Override
    public boolean verifyIntegrity(byte[] data, byte[] integrityProof) throws GeneralSecurityException {
        if (isMac && macMode != MacMode.HMAC) {
            byte[] gmacNonce = Utils.subArray(integrityProof, 0, 12);
            byte[] tag = Utils.subArray(integrityProof, 12, integrityProof.length);
            Mac freshMac = Mac.getInstance(mac.getAlgorithm());
            freshMac.init(hMacKey, new IvParameterSpec(gmacNonce));
            return MessageDigest.isEqual(freshMac.doFinal(data), tag);
        }
        return MessageDigest.isEqual(createIntegrityProof(data), integrityProof);
    }

    private void setMacKey(byte[] keyMaterial) throws InvalidKeyException {
        byte[] derived = HashUtils.hkdf(keyMaterial, "mac-key", mac.getMacLength());
        switch (macMode) {
            case HMAC -> { hMacKey = new SecretKeySpec(derived, mac.getAlgorithm()); mac.init(hMacKey); }
            case AESGMAC, AESGMACFAST -> hMacKey = new SecretKeySpec(derived, "AES");
            case RC6GMAC, RC6GMACFAST -> hMacKey = new SecretKeySpec(derived, "RC6");
        }
    }

    @Override
    public int getIntegrityProofSize() {
        if (!isMac) return hash.getDigestLength();
        return macMode == MacMode.HMAC ? mac.getMacLength() : 12 + mac.getMacLength();
    }

    @Override
    public boolean isMac() { return isMac; }
}
