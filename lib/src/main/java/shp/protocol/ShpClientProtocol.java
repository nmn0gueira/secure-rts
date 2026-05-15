package shp.protocol;

import common.Utils;
import crypto.CertificateUtils;
import crypto.CipherSuite;
import crypto.CipherSuiteFactory;
import shp.ShpCryptoSpec;
import shp.ShpMessage;
import shp.message.ShpClientHello;
import shp.message.ShpCssp;
import shp.message.ShpServerHello;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ShpClientProtocol {

    private static final Logger LOGGER = Logger.getLogger(ShpClientProtocol.class.getName());
    private static final short SHP_VERSION = 0x01;
    private static final byte SHP_RELEASE = 0x01;

    private final ShpCryptoSpec cryptoSpec;
    private final KeyStore trustStore;
    private final LinkedHashMap<String, String> supportedSuites;

    private String request;
    private byte[] udpPortBytes;

    private final Set<ByteBuffer> noncesReceived = new HashSet<>();

    private CipherSuite cipherSuite;
    private byte[] clientNonce;

    public ShpClientProtocol(ShpCryptoSpec cryptoSpec, KeyStore trustStore,
                             LinkedHashMap<String, String> supportedSuites) {
        this.cryptoSpec = cryptoSpec;
        this.trustStore = trustStore;
        this.supportedSuites = supportedSuites;
    }

    public void setInput(String request, byte[] udpPortBytes) {
        this.request = request;
        this.udpPortBytes = udpPortBytes;
    }

    public ShpMessage buildClientHello() throws GeneralSecurityException {
        clientNonce = ShpCryptoSpec.generateNonce();
        byte[] clientCertificate = cryptoSpec.getCertificateBytes();
        byte[] clientEcdhPublicKey = cryptoSpec.getEcdhPublicKeyBytes();

        ShpClientHello hello = new ShpClientHello(
            request,
            clientCertificate,
            clientEcdhPublicKey,
            new ArrayList<>(supportedSuites.keySet()),
            clientNonce
        );
        hello.sign(cryptoSpec);

        LOGGER.info("Sent CLIENT_HELLO with suites: " + new ArrayList<>(supportedSuites.keySet()));
        return hello.toShpMessage(makeHeader(MsgType.CLIENT_HELLO));
    }

    public ShpProtocolResult handle(ShpMessage message) {
        MsgType type = MsgType.from(message.getHeader());

        return switch (type) {
            case SERVER_HELLO -> handleServerHello(ShpServerHello.from(message));
            case SERVER_ERROR -> {
                String reason = new String(message.getPayload().get(0), StandardCharsets.UTF_8);
                throw new RuntimeException("Server rejected handshake: " + reason);
            }
            default -> {
                LOGGER.severe("Unexpected message type: " + type);
                yield ShpProtocolResult.error();
            }
        };
    }

    private ShpProtocolResult handleServerHello(ShpServerHello msg) {
        LOGGER.info("Received SERVER_HELLO.");
        try {
            String suiteName = msg.selectedSuiteName();
            if (!supportedSuites.containsKey(suiteName)) {
                LOGGER.severe("Server selected unsupported cipher suite: " + suiteName);
                return ShpProtocolResult.error();
            }
            String cryptoConfig = supportedSuites.get(suiteName);

            var serverCertificate = CertificateUtils.decodeCertificate(msg.serverCertificate());

            if (!CertificateUtils.isTrusted(serverCertificate, trustStore)) {
                LOGGER.severe("Untrusted server certificate.");
                return ShpProtocolResult.error();
            }

            PublicKey serverSigningKey = serverCertificate.getPublicKey();

            if (!cryptoSpec.verifySignature(serverSigningKey, msg.bytesToSign(), msg.serverSignature())) {
                LOGGER.severe("Invalid SERVER_HELLO signature.");
                return ShpProtocolResult.error();
            }

            byte[] expectedClientNonceResponse = Utils.getIncrementedBytes(clientNonce);
            if (!MessageDigest.isEqual(expectedClientNonceResponse, msg.clientNonceResponse())) {
                LOGGER.severe("Invalid client nonce response.");
                return ShpProtocolResult.error();
            }

            if (!noncesReceived.add(ByteBuffer.wrap(msg.serverNonce()))) {
                LOGGER.severe("Repeated server nonce.");
                return ShpProtocolResult.error();
            }

            PublicKey serverEcdhPublicKey = ShpCryptoSpec.loadPublicKey(msg.serverEcdhPublicKey());
            byte[] sharedSecret = cryptoSpec.generateSharedSecret(serverEcdhPublicKey);

            cipherSuite = CipherSuiteFactory.fromConfig(cryptoConfig, sharedSecret);

            byte[] serverNonceResponse = Utils.getIncrementedBytes(msg.serverNonce());
            byte[] plaintext = Utils.concat(serverNonceResponse, udpPortBytes);

            byte[] encryptedPayload = cipherSuite.cipher().encrypt(plaintext);
            byte[] integrityProof;
            if (cipherSuite.hasIntegrityCheck()) {
                integrityProof = cipherSuite.usesMac()
                        ? cipherSuite.integrityCheck().createIntegrityProof(encryptedPayload)
                        : cipherSuite.integrityCheck().createIntegrityProof(plaintext);
            }
            else
                integrityProof = new byte[0];

            ShpCssp finish = new ShpCssp(encryptedPayload, integrityProof);

            LOGGER.info("Sent CSSP.");
            return ShpProtocolResult.finished(finish.toShpMessage(makeHeader(MsgType.CSSP)));

        } catch (GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "Error handling SERVER_HELLO.", e);
            return ShpProtocolResult.error();
        }
    }

    public CipherSuite getCipherSuite() { return cipherSuite; }

    private byte[] makeHeader(MsgType type) {
        return new byte[]{ (byte) (SHP_VERSION << 4 | SHP_RELEASE), (byte) type.ordinal() };
    }
}
