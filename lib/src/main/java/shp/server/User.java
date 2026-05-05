package shp.server;

import java.security.PublicKey;

public record User(String userId, byte[] passwordHash, byte[] salt, PublicKey publicKey) {
}
