package crypto;

public record CipherSuite(SymmetricCipher cipher, IntegrityCheck integrityCheck) {

    public boolean hasIntegrityCheck() { return integrityCheck != null; }

    public boolean usesMac() { return integrityCheck != null && integrityCheck.isMac(); }

    public int integrityProofSize() { return integrityCheck != null ? integrityCheck.getIntegrityProofSize() : 0; }
}
