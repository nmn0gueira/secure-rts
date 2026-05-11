package shp.message;

import common.Utils;
import shp.ShpMessage;

import java.nio.charset.StandardCharsets;
import java.util.List;

public record ShpServerHello(String request, boolean clientCertificateAccepted, byte[] serverCertificate,
        byte[] serverEcdhPublicKey, String selectedCryptoConfig, byte[] serverNonce, byte[] clientNonceResponse,
        byte[] serverSignature) {

    private static final int PAYLOAD_SIZE = 8;

    public ShpMessage toShpMessage(byte[] header) {
        return new ShpMessage(header, List.of(
                request.getBytes(StandardCharsets.UTF_8),
                new byte[] { clientCertificateAccepted ? (byte) 1 : (byte) 0 },
                serverCertificate,
                serverEcdhPublicKey,
                selectedCryptoConfig.getBytes(StandardCharsets.UTF_8),
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
                payload.get(1)[0] != 0,
                payload.get(2),
                payload.get(3),
                new String(payload.get(4), StandardCharsets.UTF_8),
                payload.get(5),
                payload.get(6),
                payload.get(7));
    }

    public byte[] bytesToSign() {
        return Utils.concat(
                request.getBytes(StandardCharsets.UTF_8),
                new byte[] { clientCertificateAccepted ? (byte) 1 : (byte) 0 },
                serverCertificate,
                serverEcdhPublicKey,
                selectedCryptoConfig.getBytes(StandardCharsets.UTF_8),
                serverNonce,
                clientNonceResponse);
    }
}
