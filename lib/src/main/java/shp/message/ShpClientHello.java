package shp.message;

import common.Utils;
import shp.ShpMessage;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public class ShpClientHello {

    private static final int PAYLOAD_SIZE = 6;

    private final String request;
    private final byte[] clientCertificate;
    private final byte[] clientEcdhPublicKey;
    private final List<String> cipherSuites;
    private final byte[] clientNonce;
    private byte[] signature = new byte[0];

    public ShpClientHello(String request, byte[] clientCertificate, byte[] clientEcdhPublicKey,
            List<String> cipherSuites, byte[] clientNonce) {
        this.request = request;
        this.clientCertificate = clientCertificate;
        this.clientEcdhPublicKey = clientEcdhPublicKey;
        this.cipherSuites = cipherSuites;
        this.clientNonce = clientNonce;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public String request() { return request; }
    public byte[] clientCertificate() { return clientCertificate; }
    public byte[] clientEcdhPublicKey() { return clientEcdhPublicKey; }
    public List<String> cipherSuites() { return cipherSuites; }
    public byte[] clientNonce() { return clientNonce; }
    public byte[] clientSignature() { return signature; }

    public ShpMessage toShpMessage(byte[] header) {
        return new ShpMessage(header, List.of(
                request.getBytes(StandardCharsets.UTF_8),
                clientCertificate,
                clientEcdhPublicKey,
                encodeCipherSuites(cipherSuites),
                clientNonce,
                signature));
    }

    public static ShpClientHello from(ShpMessage message) {
        List<byte[]> payload = message.getPayload();

        if (payload.size() != PAYLOAD_SIZE) {
            throw new IllegalArgumentException("Invalid ClientHello payload size");
        }

        ShpClientHello hello = new ShpClientHello(
                new String(payload.get(0), StandardCharsets.UTF_8),
                payload.get(1),
                payload.get(2),
                decodeCipherSuites(payload.get(3)),
                payload.get(4));
        hello.signature = payload.get(5);
        return hello;
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
        if (value.isEmpty()) return List.of();
        return Arrays.asList(value.split("\n"));
    }
}
