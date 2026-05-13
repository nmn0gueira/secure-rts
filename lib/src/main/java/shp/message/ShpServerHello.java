package shp.message;

import common.Utils;
import shp.ShpMessage;

import java.nio.charset.StandardCharsets;
import java.util.List;

public record ShpServerHello(String request, byte[] serverCertificate,
        byte[] serverEcdhPublicKey, String selectedSuiteName,
        byte[] serverNonce, byte[] clientNonceResponse, byte[] serverSignature) {

    private static final int PAYLOAD_SIZE = 7;

    public ShpMessage toShpMessage(byte[] header) {
        return new ShpMessage(header, List.of(
                request.getBytes(StandardCharsets.UTF_8),
                serverCertificate,
                serverEcdhPublicKey,
                selectedSuiteName.getBytes(StandardCharsets.UTF_8),
                serverNonce,
                clientNonceResponse,
                serverSignature));
    }

    public static ShpServerHello from(ShpMessage message) {
        List<byte[]> payload = message.getPayload();

        if (payload.size() != PAYLOAD_SIZE) {
            throw new IllegalArgumentException("Invalid ServerHello payload size");
        }

        return new ShpServerHello(
                new String(payload.get(0), StandardCharsets.UTF_8),
                payload.get(1),
                payload.get(2),
                new String(payload.get(3), StandardCharsets.UTF_8),
                payload.get(4),
                payload.get(5),
                payload.get(6));
    }

    public byte[] bytesToSign() {
        return Utils.concat(
                request.getBytes(StandardCharsets.UTF_8),
                serverCertificate,
                serverEcdhPublicKey,
                selectedSuiteName.getBytes(StandardCharsets.UTF_8),
                serverNonce,
                clientNonceResponse);
    }
}
