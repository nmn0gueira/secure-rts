package shp.protocol;

import common.Utils;
import crypto.CipherSuite;
import crypto.CipherSuiteFactory;
import crypto.CertificateLoader;
import shp.message.ShpClientHello;
import shp.message.ShpServerHello;
import shp.message.ShpClientFinish;
import shp.ShpCryptoSpec;
import shp.ShpMessage;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ShpServerProtocol {

    private static final Logger LOGGER = Logger.getLogger(ShpServerProtocol.class.getName());
    private static final short SHP_VERSION = 0x01;
    private static final byte SHP_RELEASE = 0x01;

    private final ShpCryptoSpec cryptoSpec;
    private final KeyStore trustStore;
    private final Set<String> validRequests;

    private final Set<ByteBuffer> noncesReceived = new HashSet<>();
    private byte[] serverNonce;

    private String userRequest;
    private int udpPort;
    private byte[] sharedSecret;
    private byte[] cryptoConfigBytes;

    public ShpServerProtocol(ShpCryptoSpec cryptoSpec, KeyStore trustStore, Set<String> validRequests) {
        this.cryptoSpec = cryptoSpec;
        this.trustStore = trustStore;
        this.validRequests = validRequests;
    }

    public void setCryptoConfigBytes(byte[] cryptoConfigBytes) {
        this.cryptoConfigBytes = cryptoConfigBytes;
    }

    public ShpProtocolResult handle(ShpMessage message) {
        MsgType type = MsgType.from(message.getHeader());

        return switch (type) {
            case CLIENT_HELLO -> handleClientHello(ShpClientHello.from(message));
            case CLIENT_FINISH -> handleClientFinish(ShpClientFinish.from(message));
            default -> {
                LOGGER.severe("Unexpected message type: " + type);
                yield ShpProtocolResult.error();
            }
        };
    }

    private ShpProtocolResult handleClientHello(ShpClientHello msg) {
        LOGGER.info("Received CLIENT_HELLO.");

        try {

            var clientCertificate = CertificateLoader.decodeCertificate(msg.clientCertificate());

            if (!CertificateLoader.isTrusted(clientCertificate, trustStore)) {
                LOGGER.severe("Untrusted client certificate.");
                return ShpProtocolResult.error();
            }

            PublicKey clientPublicKey = clientCertificate.getPublicKey();

            if (!cryptoSpec.verifySignature(clientPublicKey, msg.bytesToSign(), msg.clientSignature())) {
                LOGGER.severe("Invalid CLIENT_HELLO signature.");
                return ShpProtocolResult.error();
            }

            if (validRequests != null && !validRequests.contains(msg.request())) {
                LOGGER.severe("Invalid request: " + msg.request());
                return ShpProtocolResult.error();
            }

            if (!noncesReceived.add(ByteBuffer.wrap(msg.clientNonce()))) {
                LOGGER.severe("Repeated client nonce.");
                return ShpProtocolResult.error();
            }

            PublicKey clientEcdhPublicKey = ShpCryptoSpec.loadPublicKey(msg.clientEcdhPublicKey());
            sharedSecret = cryptoSpec.generateSharedSecret(clientEcdhPublicKey);

            userRequest = msg.request();

            String selectedCryptoConfig = new String(cryptoConfigBytes, StandardCharsets.UTF_8);
            serverNonce = ShpCryptoSpec.generateNonce();
            byte[] clientNonceResponse = Utils.getIncrementedBytes(msg.clientNonce());

            byte[] serverCertificate = cryptoSpec.getCertificateBytes();
            byte[] serverEcdhPublicKey = cryptoSpec.getEcdhPublicKeyBytes();

            ShpServerHello unsignedHello = new ShpServerHello(
                    msg.request(),
                    true,
                    serverCertificate,
                    serverEcdhPublicKey,
                    selectedCryptoConfig,
                    serverNonce,
                    clientNonceResponse,
                    new byte[0]);

            byte[] signature = cryptoSpec.sign(unsignedHello.bytesToSign());

            ShpServerHello signedHello = new ShpServerHello(
                    msg.request(),
                    true,
                    serverCertificate,
                    serverEcdhPublicKey,
                    selectedCryptoConfig,
                    serverNonce,
                    clientNonceResponse,
                    signature);

            LOGGER.info("Sent SERVER_HELLO.");
            return ShpProtocolResult.waiting(signedHello.toShpMessage(makeHeader(MsgType.SERVER_HELLO)));

        } catch (GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "Error handling CLIENT_HELLO.", e);
            return ShpProtocolResult.error();
        }
    }

    private ShpProtocolResult handleClientFinish(ShpClientFinish msg) {
        LOGGER.info("Received CLIENT_FINISH.");

        try {
            String selectedCryptoConfig = new String(cryptoConfigBytes, StandardCharsets.UTF_8);
            CipherSuite suite = CipherSuiteFactory.fromConfig(selectedCryptoConfig, sharedSecret);

            if (suite.hasIntegrityCheck()) {
                boolean validIntegrity = suite.integrityCheck()
                        .verifyIntegrity(msg.encryptedPayload(), serverNonce, msg.integrityProof());

                if (!validIntegrity) {
                    LOGGER.severe("CLIENT_FINISH integrity check failed.");
                    return ShpProtocolResult.error();
                }
            }

            byte[] decryptedPayload = suite.cipher().decrypt(msg.encryptedPayload());

            byte[] finishToken = ShpCryptoSpec.FINISH_PROTOCOL.getBytes(StandardCharsets.UTF_8);
            byte[][] parts = Utils.divideInParts(
                    decryptedPayload,
                    finishToken.length,
                    finishToken.length + ShpCryptoSpec.NONCE_SIZE);

            byte[] receivedFinishToken = parts[0];
            byte[] serverNonceResponse = parts[1];
            byte[] udpPortBytes = parts[2];

            if (!MessageDigest.isEqual(finishToken, receivedFinishToken)) {
                LOGGER.severe("Invalid finish token.");
                return ShpProtocolResult.error();
            }

            byte[] expectedServerNonceResponse = Utils.getIncrementedBytes(serverNonce);
            if (!MessageDigest.isEqual(expectedServerNonceResponse, serverNonceResponse)) {
                LOGGER.severe("Invalid server nonce response.");
                return ShpProtocolResult.error();
            }

            if (udpPortBytes.length != 4) {
                LOGGER.severe("Invalid UDP port length.");
                return ShpProtocolResult.error();
            }

            udpPort = ByteBuffer.wrap(udpPortBytes).getInt();

            LOGGER.info("SHP finished.");
            return ShpProtocolResult.finished();

        } catch (GeneralSecurityException | RuntimeException e) {
            LOGGER.log(Level.SEVERE, "Error handling CLIENT_FINISH.", e);
            return ShpProtocolResult.error();
        }
    }


    public String getUserRequest() {
        return userRequest;
    }

    public int getUdpPort() {
        return udpPort;
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }

    private byte[] makeHeader(MsgType type) {
        return new byte[] { (byte) (SHP_VERSION << 4 | SHP_RELEASE), (byte) type.ordinal() };
    }
}
