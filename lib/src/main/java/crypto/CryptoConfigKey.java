package crypto;

import java.util.Optional;
import java.util.Set;

enum CryptoConfigKey {
    CONFIDENTIALITY("ciphersuite", "confidentiality"),
    SYMMETRIC_KEY("key", "symmetric_key"),
    IV("iv"),
    INTEGRITY("integrity"),
    MAC("hmac", "mac"),
    MAC_KEY("mackey", "mac_key"),
    H("h", "hash");

    private final Set<String> aliases;

    CryptoConfigKey(String... aliases) {
        this.aliases = Set.of(aliases);
    }

    static Optional<CryptoConfigKey> fromAlias(String alias) {
        String lower = alias.toLowerCase();
        for (CryptoConfigKey k : values()) {
            if (k.aliases.contains(lower) || k.name().equalsIgnoreCase(lower))
                return Optional.of(k);
        }
        return Optional.empty();
    }
}