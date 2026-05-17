package shp.pq.protocol;

import common.Utils;
import crypto.CertificateUtils;
import crypto.CipherSuite;
import crypto.CipherSuiteFactory;
import crypto.MlKemEncapsulation;
import shp.ShpMessage;
import shp.message.ShpClientHello;
import shp.message.ShpCssp;
import shp.message.ShpServerHello;
import shp.protocol.MsgType;
import shp.protocol.ShpProtocolResult;
import shp.pq.PqShpCryptoSpec;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PqShpServerProtocol {

    private static final Logger LOGGER = Logger.getLogger(PqShpServerProtocol.class.getName());
    private static final short SHP_VERSION = 0x01;
    private static final byte SHP_RELEASE = 0x01;

    private final PqShpCryptoSpec cryptoSpec;
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
    private CipherSuite selectedCipherSuite;

    public PqShpServerProtocol(PqShpCryptoSpec cryptoSpec, KeyStore trustStore, Set<String> validRequests) {
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
            case CSSP -> handleCssp(ShpCssp.from(message));
            default -> {
                LOGGER.severe("Unexpected message type: " + type);
                yield ShpProtocolResult.error();
            }
        };
    }

    private ShpProtocolResult handleClientHello(ShpClientHello msg) {
        LOGGER.info("Received PQ CLIENT_HELLO.");
        try {
            var clientCertificate = CertificateUtils.decodeCertificate(msg.clientCertificate());
            if (!CertificateUtils.isTrusted(clientCertificate, trustStore)) {
                LOGGER.severe("Untrusted client certificate.");
                return ShpProtocolResult.error();
            }

            PublicKey clientSigningKey = clientCertificate.getPublicKey();
            if (!cryptoSpec.verifySignature(clientSigningKey, msg.bytesToSign(), msg.clientSignature())) {
                LOGGER.severe("Invalid CLIENT_HELLO signature.");
                return ShpProtocolResult.error();
            }

            if (validRequests != null && !validRequests.contains(msg.request())) {
                return errorAndNotify("Unknown movie: " + msg.request());
            }

            if (!noncesReceived.add(ByteBuffer.wrap(msg.clientNonce()))) {
                LOGGER.severe("Repeated client nonce.");
                return ShpProtocolResult.error();
            }

            LinkedHashMap<String, String> suitesToSearch = serverSuites;
            if (perMovieSuites != null) {
                suitesToSearch = perMovieSuites.get(msg.request());
                if (suitesToSearch == null)
                    return errorAndNotify("No cipher suites configured for movie: " + msg.request());
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
            if (selectedSuiteName == null)
                return errorAndNotify("No common cipher suite");

            // clientEcdhPublicKey field carries the client's ML-KEM public key;
            // encapsulate immediately to obtain shared secret + ciphertext
            MlKemEncapsulation.KemResult kem = PqShpCryptoSpec.encapsulate(msg.clientEcdhPublicKey());
            sharedSecret = kem.sharedSecret();
            byte[] kemCiphertext = kem.ciphertext();

            userRequest = msg.request();
            serverNonce = PqShpCryptoSpec.generateNonce();
            byte[] clientNonceResponse = Utils.getIncrementedBytes(msg.clientNonce());

            // reuse serverEcdhPublicKey field to carry the KEM ciphertext
            ShpServerHello hello = new ShpServerHello(
                    cryptoSpec.getCertificateBytes(), kemCiphertext,
                    selectedSuiteName, serverNonce, clientNonceResponse);
            hello.setSignature(cryptoSpec.sign(hello.bytesToSign()));

            LOGGER.info("Sent PQ SERVER_HELLO with suite: " + selectedSuiteName);
            return ShpProtocolResult.waiting(hello.toShpMessage(makeHeader(MsgType.SERVER_HELLO)));

        } catch (GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "Unexpected error in PQ CLIENT_HELLO.", e);
            return ShpProtocolResult.error();
        }
    }

    private ShpProtocolResult handleCssp(ShpCssp msg) {
        LOGGER.info("Received CSSP.");
        try {
            selectedCipherSuite = CipherSuiteFactory.fromConfig(selectedSuiteConfig, sharedSecret);

            byte[] decryptedPayload = null;
            if (selectedCipherSuite.hasIntegrityCheck()) {
                boolean validIntegrity;
                if (selectedCipherSuite.usesMac()) {
                    validIntegrity = selectedCipherSuite.integrityCheck()
                            .verifyIntegrity(msg.encryptedPayload(), msg.integrityProof());
                } else {
                    decryptedPayload = selectedCipherSuite.cipher().decrypt(msg.encryptedPayload());
                    validIntegrity = selectedCipherSuite.integrityCheck()
                            .verifyIntegrity(decryptedPayload, msg.integrityProof());
                }
                if (!validIntegrity) {
                    LOGGER.severe("CSSP integrity check failed.");
                    return ShpProtocolResult.error();
                }
            }

            if (decryptedPayload == null)
                decryptedPayload = selectedCipherSuite.cipher().decrypt(msg.encryptedPayload());

            byte[][] parts = Utils.divideInParts(decryptedPayload, PqShpCryptoSpec.NONCE_SIZE);
            byte[] serverNonceResponse = parts[0];
            byte[] udpPortBytes = parts[1];

            if (!MessageDigest.isEqual(Utils.getIncrementedBytes(serverNonce), serverNonceResponse)) {
                LOGGER.severe("Invalid server nonce response.");
                return ShpProtocolResult.error();
            }

            if (udpPortBytes.length != 4) {
                LOGGER.severe("Invalid UDP port length.");
                return ShpProtocolResult.error();
            }

            udpPort = ByteBuffer.wrap(udpPortBytes).getInt();
            LOGGER.info("PQ SHP finished.");
            return ShpProtocolResult.finished();

        } catch (GeneralSecurityException | RuntimeException e) {
            LOGGER.log(Level.SEVERE, "Unexpected error in CSSP.", e);
            return ShpProtocolResult.error();
        }
    }

    private ShpProtocolResult errorAndNotify(String reason) {
        LOGGER.severe("PQ SHP error: " + reason);
        ShpMessage errorMsg = new ShpMessage(
                makeHeader(MsgType.SERVER_ERROR),
                List.of(reason.getBytes(StandardCharsets.UTF_8)));
        return ShpProtocolResult.errorWith(errorMsg);
    }

    public String getUserRequest() { return userRequest; }
    public int getUdpPort() { return udpPort; }
    public CipherSuite getCipherSuite() { return selectedCipherSuite; }

    private byte[] makeHeader(MsgType type) {
        return new byte[]{ (byte) (SHP_VERSION << 4 | SHP_RELEASE), (byte) type.ordinal() };
    }
}
