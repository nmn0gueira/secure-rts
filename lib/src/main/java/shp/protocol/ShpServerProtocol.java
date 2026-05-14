package shp.protocol;

import common.Utils;
import crypto.CipherSuite;
import crypto.CipherSuiteFactory;
import crypto.CertificateUtils;
import shp.message.ShpClientHello;
import shp.message.ShpServerHello;
import shp.message.ShpClientFinish;
import shp.ShpCryptoSpec;
import shp.ShpMessage;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
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

    private LinkedHashMap<String, String> serverSuites;
    private Map<String, LinkedHashMap<String, String>> perMovieSuites;

    private String selectedSuiteName;
    private String selectedSuiteConfig;

    public ShpServerProtocol(ShpCryptoSpec cryptoSpec, KeyStore trustStore, Set<String> validRequests) {
        this.cryptoSpec = cryptoSpec;
        this.trustStore = trustStore;
        this.validRequests = validRequests;
    }

    public void setServerSuites(LinkedHashMap<String, String> serverSuites) {
        this.serverSuites = serverSuites;
    }

    public void setPerMovieSuites(Map<String, LinkedHashMap<String, String>> perMovieSuites) {
        this.perMovieSuites = perMovieSuites;
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
            var clientCertificate = CertificateUtils.decodeCertificate(msg.clientCertificate());

            if (!CertificateUtils.isTrusted(clientCertificate, trustStore)) {
                return errorAndNotify("Untrusted client certificate");
            }

            PublicKey clientPublicKey = clientCertificate.getPublicKey();

            if (!cryptoSpec.verifySignature(clientPublicKey, msg.bytesToSign(), msg.clientSignature())) {
                return errorAndNotify("Invalid CLIENT_HELLO signature");
            }

            if (validRequests != null && !validRequests.contains(msg.request())) {
                return errorAndNotify("Unknown movie: " + msg.request());
            }

            if (!noncesReceived.add(ByteBuffer.wrap(msg.clientNonce()))) {
                return errorAndNotify("Repeated client nonce");
            }

            LinkedHashMap<String, String> suitesToSearch = serverSuites;
            if (perMovieSuites != null) {
                suitesToSearch = perMovieSuites.get(msg.request());
                if (suitesToSearch == null) {
                    return errorAndNotify("No cipher suites configured for movie: " + msg.request());
                }
            }

            selectedSuiteName = null;
            selectedSuiteConfig = null;
            for (var entry : suitesToSearch.entrySet()) {
                if (msg.cipherSuites().contains(entry.getKey())) {
                    selectedSuiteName = entry.getKey();
                    selectedSuiteConfig = entry.getValue();
                    break;
                }
            }
            if (selectedSuiteName == null) {
                return errorAndNotify("No common cipher suite");
            }

            PublicKey clientEcdhPublicKey = ShpCryptoSpec.loadPublicKey(msg.clientEcdhPublicKey());
            sharedSecret = cryptoSpec.generateSharedSecret(clientEcdhPublicKey);

            userRequest = msg.request();

            serverNonce = ShpCryptoSpec.generateNonce();
            byte[] clientNonceResponse = Utils.getIncrementedBytes(msg.clientNonce());

            byte[] serverCertificate = cryptoSpec.getCertificateBytes();
            byte[] serverEcdhPublicKey = cryptoSpec.getEcdhPublicKeyBytes();

            ShpServerHello hello = new ShpServerHello(
                    serverCertificate,
                    serverEcdhPublicKey,
                    selectedSuiteName,
                    serverNonce,
                    clientNonceResponse);
            hello.sign(cryptoSpec);

            LOGGER.info("Sent SERVER_HELLO with suite: " + selectedSuiteName);
            return ShpProtocolResult.waiting(hello.toShpMessage(makeHeader(MsgType.SERVER_HELLO)));

        } catch (GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "Unexpected error in CLIENT_HELLO.", e);
            return ShpProtocolResult.error();
        }
    }

    private ShpProtocolResult handleClientFinish(ShpClientFinish msg) {
        LOGGER.info("Received CLIENT_FINISH.");

        try {
            CipherSuite suite = CipherSuiteFactory.fromConfig(selectedSuiteConfig, sharedSecret);

            if (suite.hasIntegrityCheck()) {
                boolean validIntegrity = suite.integrityCheck()
                        .verifyIntegrity(msg.encryptedPayload(), serverNonce, msg.integrityProof());

                if (!validIntegrity) {
                    return errorAndNotify("CLIENT_FINISH integrity check failed");
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
                return errorAndNotify("Invalid finish token");
            }

            byte[] expectedServerNonceResponse = Utils.getIncrementedBytes(serverNonce);
            if (!MessageDigest.isEqual(expectedServerNonceResponse, serverNonceResponse)) {
                return errorAndNotify("Invalid server nonce response");
            }

            if (udpPortBytes.length != 4) {
                return errorAndNotify("Invalid UDP port length");
            }

            udpPort = ByteBuffer.wrap(udpPortBytes).getInt();

            LOGGER.info("SHP finished.");
            return ShpProtocolResult.finished();

        } catch (GeneralSecurityException | RuntimeException e) {
            LOGGER.log(Level.SEVERE, "Unexpected error in CLIENT_FINISH.", e);
            return ShpProtocolResult.error();
        }
    }

    private ShpProtocolResult errorAndNotify(String reason) {
        LOGGER.severe("SHP error: " + reason);
        ShpMessage errorMsg = new ShpMessage(
                makeHeader(MsgType.SERVER_ERROR),
                List.of(reason.getBytes(StandardCharsets.UTF_8)));
        return ShpProtocolResult.errorWith(errorMsg);
    }

    public String getUserRequest() { return userRequest; }
    public int getUdpPort() { return udpPort; }
    public byte[] getSharedSecret() { return sharedSecret; }
    public String getSelectedSuiteConfig() { return selectedSuiteConfig; }

    private byte[] makeHeader(MsgType type) {
        return new byte[] { (byte) (SHP_VERSION << 4 | SHP_RELEASE), (byte) type.ordinal() };
    }
}
