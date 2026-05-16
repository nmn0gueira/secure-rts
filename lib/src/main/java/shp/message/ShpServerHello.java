package shp.message;

import common.Utils;
import shp.ShpMessage;

import java.nio.charset.StandardCharsets;
import java.util.List;

public class ShpServerHello {

    private static final int PAYLOAD_SIZE = 6;

    private final byte[] serverCertificate;
    private final byte[] serverEcdhPublicKey;
    private final String selectedSuiteName;
    private final byte[] serverNonce;
    private final byte[] clientNonceResponse;
    private byte[] signature = new byte[0];

    public ShpServerHello(byte[] serverCertificate, byte[] serverEcdhPublicKey,
            String selectedSuiteName, byte[] serverNonce, byte[] clientNonceResponse) {
        this.serverCertificate = serverCertificate;
        this.serverEcdhPublicKey = serverEcdhPublicKey;
        this.selectedSuiteName = selectedSuiteName;
        this.serverNonce = serverNonce;
        this.clientNonceResponse = clientNonceResponse;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public byte[] serverCertificate() { return serverCertificate; }
    public byte[] serverEcdhPublicKey() { return serverEcdhPublicKey; }
    public String selectedSuiteName() { return selectedSuiteName; }
    public byte[] serverNonce() { return serverNonce; }
    public byte[] clientNonceResponse() { return clientNonceResponse; }
    public byte[] serverSignature() { return signature; }

    public ShpMessage toShpMessage(byte[] header) {
        return new ShpMessage(header, List.of(
                serverCertificate,
                serverEcdhPublicKey,
                selectedSuiteName.getBytes(StandardCharsets.UTF_8),
                serverNonce,
                clientNonceResponse,
                signature));
    }

    public static ShpServerHello from(ShpMessage message) {
        List<byte[]> payload = message.getPayload();

        if (payload.size() != PAYLOAD_SIZE) {
            throw new IllegalArgumentException("Invalid ServerHello payload size");
        }

        ShpServerHello hello = new ShpServerHello(
                payload.get(0),
                payload.get(1),
                new String(payload.get(2), StandardCharsets.UTF_8),
                payload.get(3),
                payload.get(4));
        hello.signature = payload.get(5);
        return hello;
    }

    public byte[] bytesToSign() {
        return Utils.concat(
                serverCertificate,
                serverEcdhPublicKey,
                selectedSuiteName.getBytes(StandardCharsets.UTF_8),
                serverNonce,
                clientNonceResponse);
    }
}
