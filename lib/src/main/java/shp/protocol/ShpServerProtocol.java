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

            LinkedHashMap<String, String> suitesToSearch = serverSuites;
            if (perMovieSuites != null) {
                suitesToSearch = perMovieSuites.get(msg.request());
                if (suitesToSearch == null) {
                    LOGGER.severe("No cipher suites configured for movie: " + msg.request());
                    return ShpProtocolResult.error();
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
                LOGGER.severe("No common cipher suite with client.");
                return ShpProtocolResult.error();
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
            LOGGER.log(Level.SEVERE, "Error handling CLIENT_HELLO.", e);
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

    public String getUserRequest() { return userRequest; }
    public int getUdpPort() { return udpPort; }
    public byte[] getSharedSecret() { return sharedSecret; }
    public String getSelectedSuiteConfig() { return selectedSuiteConfig; }

    private byte[] makeHeader(MsgType type) {
        return new byte[] { (byte) (SHP_VERSION << 4 | SHP_RELEASE), (byte) type.ordinal() };
    }
}
