package shp.message;

import shp.ShpMessage;

import java.util.List;

public record ShpCssp(byte[] encryptedPayload, byte[] integrityProof) {

    private static final int PAYLOAD_SIZE = 2;

    public ShpMessage toShpMessage(byte[] header) {
        return new ShpMessage(header, List.of(
                encryptedPayload,
                integrityProof));
    }

    public static ShpCssp from(ShpMessage message) {
        List<byte[]> payload = message.getPayload();

        if (payload.size() != PAYLOAD_SIZE) {
            throw new IllegalArgumentException("Invalid CSSP payload size");
        }

        return new ShpCssp(
                payload.get(0),
                payload.get(1));
    }
}
