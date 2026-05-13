package shp.message;

import common.Utils;
import shp.ShpCryptoSpec;
import shp.ShpMessage;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.List;

public class ShpServerHello {

    private static final int PAYLOAD_SIZE = 7;

    private final String request;
    private final byte[] serverCertificate;
    private final byte[] serverEcdhPublicKey;
    private final String selectedSuiteName;
    private final byte[] serverNonce;
    private final byte[] clientNonceResponse;
    private byte[] signature = new byte[0];

    public ShpServerHello(String request, byte[] serverCertificate, byte[] serverEcdhPublicKey,
            String selectedSuiteName, byte[] serverNonce, byte[] clientNonceResponse) {
        this.request = request;
        this.serverCertificate = serverCertificate;
        this.serverEcdhPublicKey = serverEcdhPublicKey;
        this.selectedSuiteName = selectedSuiteName;
        this.serverNonce = serverNonce;
        this.clientNonceResponse = clientNonceResponse;
    }

    public void sign(ShpCryptoSpec spec) throws GeneralSecurityException {
        this.signature = spec.sign(bytesToSign());
    }

    public String request() { return request; }
    public byte[] serverCertificate() { return serverCertificate; }
    public byte[] serverEcdhPublicKey() { return serverEcdhPublicKey; }
    public String selectedSuiteName() { return selectedSuiteName; }
    public byte[] serverNonce() { return serverNonce; }
    public byte[] clientNonceResponse() { return clientNonceResponse; }
    public byte[] serverSignature() { return signature; }

    public ShpMessage toShpMessage(byte[] header) {
        return new ShpMessage(header, List.of(
                request.getBytes(StandardCharsets.UTF_8),
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
                new String(payload.get(0), StandardCharsets.UTF_8),
                payload.get(1),
                payload.get(2),
                new String(payload.get(3), StandardCharsets.UTF_8),
                payload.get(4),
                payload.get(5));
        hello.signature = payload.get(6);
        return hello;
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
