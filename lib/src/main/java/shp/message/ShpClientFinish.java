package shp.message;

import shp.ShpMessage;

import java.util.List;

public record ShpClientFinish(byte[] encryptedPayload, byte[] integrityProof) {

    private static final int PAYLOAD_SIZE = 2;

    public ShpMessage toShpMessage(byte[] header) {
        return new ShpMessage(header, List.of(
                encryptedPayload,
                integrityProof));
    }

    public static ShpClientFinish from(ShpMessage message) {
        List<byte[]> payload = message.getPayload();

        if (payload.size() != PAYLOAD_SIZE) {
            throw new IllegalArgumentException("Invalid ClientFinish payload size");
        }

        return new ShpClientFinish(
                payload.get(0),
                payload.get(1));
    }
}
