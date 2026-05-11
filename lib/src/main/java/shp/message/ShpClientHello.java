package shp.message;

import common.Utils;
import shp.ShpMessage;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public record ShpClientHello(String request, byte[] clientCertificate, byte[] clientEcdhPublicKey,
        List<String> cipherSuites, byte[] clientNonce, byte[] clientSignature) {

    private static final int PAYLOAD_SIZE = 6;

    public ShpMessage toShpMessage(byte[] header) {
        return new ShpMessage(header, List.of(
                request.getBytes(StandardCharsets.UTF_8),
                clientCertificate,
                clientEcdhPublicKey,
                encodeCipherSuites(cipherSuites),
                clientNonce,
                clientSignature));
    }

    public static ShpClientHello from(ShpMessage message) {
        List<byte[]> payload = message.getPayload();

        if (payload.size() != PAYLOAD_SIZE) {
            throw new IllegalArgumentException("Invalid ClientHello payload size");
        }

        return new ShpClientHello(
                new String(payload.get(0), StandardCharsets.UTF_8),
                payload.get(1),
                payload.get(2),
                decodeCipherSuites(payload.get(3)),
                payload.get(4),
                payload.get(5));
    }

    public byte[] bytesToSign() {
        return Utils.concat(
                request.getBytes(StandardCharsets.UTF_8),
                clientCertificate,
                clientEcdhPublicKey,
                encodeCipherSuites(cipherSuites),
                clientNonce);
    }

    private static byte[] encodeCipherSuites(List<String> cipherSuites) {
        return String.join("\n", cipherSuites).getBytes(StandardCharsets.UTF_8);
    }

    private static List<String> decodeCipherSuites(byte[] encoded) {
        String value = new String(encoded, StandardCharsets.UTF_8);
        if (value.isEmpty()) {
            return List.of();
        }
        return Arrays.asList(value.split("\n"));
    }
}
