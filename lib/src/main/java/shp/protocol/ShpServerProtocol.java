package shp.protocol;

import common.Utils;
import crypto.CipherSuite;
import crypto.CipherSuiteFactory;
import crypto.CertificateLoader;
import crypto.IntegrityCheck;
import crypto.SymmetricCipher;
import shp.message.ShpClientHello;
import shp.message.ShpServerHello;
import shp.message.ShpClientFinish;
import shp.ShpCryptoSpec;
import shp.ShpMessage;
import shp.server.User;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.util.HashSet;
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
    private final Map<String, User> userDatabase;
    private final Set<String> validRequests;

    private User currentUser;
    private IntegrityCheck hmac;
    private SymmetricCipher pbeCipher;
    private SymmetricCipher sharedKeyCipher;
    private final Set<ByteBuffer> noncesReceived = new HashSet<>();
    private byte[] serverNonce;

    private String userRequest;
    private int udpPort;
    private byte[] sharedSecret;
    private byte[] cryptoConfigBytes;

    public ShpServerProtocol(ShpCryptoSpec cryptoSpec, KeyStore trustStore, Map<String, User> userDatabase,
            Set<String> validRequests) {
        this.cryptoSpec = cryptoSpec;
        this.trustStore = trustStore;
        this.userDatabase = userDatabase;
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

    /*
     * public ShpProtocolResult handle(ShpMessage message) {
     * MsgType type = MsgType.from(message.getHeader());
     * return switch (type) {
     * case TYPE_1 -> handleType1(Type1Message.from(message.getPayload()));
     * case TYPE_3 -> handleType3(Type3Message.from(message.getPayload()));
     * case TYPE_5 -> handleType5(Type5Message.from(message.getPayload()));
     * default -> { LOGGER.severe("Unexpected message type: " + type); yield
     * ShpProtocolResult.error(); }
     * };
     * }
     */

    /*
     * private ShpProtocolResult handleType1(Type1Message msg) {
     * LOGGER.info("Received TYPE_1.");
     * String userId = new String(msg.userId());
     * currentUser = userDatabase.get(userId);
     * if (currentUser == null) { LOGGER.warning("User not found: " + userId);
     * return ShpProtocolResult.error(); }
     * 
     * byte[] salt = cryptoSpec.generateNonce();
     * byte[] iterationBytes = cryptoSpec.generateIterationBytes();
     * byte[] nonce = cryptoSpec.generateNonce();
     * 
     * int iterations = ((iterationBytes[0] & 0xFF) << 8) | (iterationBytes[1] &
     * 0xFF);
     * try {
     * this.hmac = CipherSuiteFactory.hmacSha256(currentUser.passwordHash());
     * this.pbeCipher = CipherSuiteFactory.pbeCipher(
     * new String(currentUser.passwordHash()),
     * Utils.fitToSize(salt, ShpCryptoSpec.SALT_SIZE),
     * iterations);
     * } catch (GeneralSecurityException e) {
     * LOGGER.log(Level.SEVERE, "Error initializing crypto for TYPE_1.", e);
     * return ShpProtocolResult.error();
     * }
     * 
     * ShpMessage response = new ShpMessage(makeHeader(MsgType.TYPE_2), salt,
     * iterationBytes, nonce);
     * LOGGER.info("Sent TYPE_2.");
     * return ShpProtocolResult.ongoing(response);
     * }
     */

    /*
     * private ShpProtocolResult handleType3(Type3Message msg) {
     * LOGGER.info("Received TYPE_3.");
     * try {
     * byte[] dataToVerify = Utils.concat(msg.passwordEncryptedData(),
     * msg.ydhClient(), msg.clientSignature());
     * if (!hmac.verifyIntegrity(dataToVerify, null, msg.integrityProof())) {
     * LOGGER.severe("TYPE_3 integrity check failed.");
     * return ShpProtocolResult.error();
     * }
     * 
     * byte[] decryptedData = pbeCipher.decrypt(msg.passwordEncryptedData());
     * PublicKey clientPublicKey = currentUser.publicKey();
     * 
     * int userIdLength = currentUser.userId().getBytes().length;
     * Type3Message.DecryptedContent content =
     * Type3Message.DecryptedContent.parse(decryptedData, userIdLength);
     * 
     * byte[] signatureData = Utils.concat(decryptedData, msg.ydhClient());
     * if (!cryptoSpec.verifySignature(clientPublicKey, signatureData,
     * msg.clientSignature())) {
     * LOGGER.severe("Invalid client signature.");
     * return ShpProtocolResult.error();
     * }
     * 
     * if (!new String(content.userId()).equals(currentUser.userId())) {
     * LOGGER.severe("User ID mismatch.");
     * return ShpProtocolResult.error();
     * }
     * 
     * if (validRequests != null && !validRequests.contains(new
     * String(content.request()))) {
     * LOGGER.severe("Invalid request.");
     * return ShpProtocolResult.error();
     * }
     * 
     * if (!noncesReceived.add(ByteBuffer.wrap(content.incrementedServerNonce())) ||
     * !noncesReceived.add(ByteBuffer.wrap(content.clientNonce()))) {
     * LOGGER.severe("Replay attack detected in TYPE_3.");
     * return ShpProtocolResult.error();
     * }
     * 
     * byte[] dhSecret = cryptoSpec.generateSharedSecret(msg.ydhClient());
     * this.sharedKeyCipher =
     * CipherSuiteFactory.sharedKeyCipher(HashUtils.SHA3_256.digest(dhSecret));
     * 
     * byte[] confirmation = ShpCryptoSpec.REQUEST_CONFIRMATION.getBytes();
     * byte[] incrementedClientNonce =
     * Utils.getIncrementedBytes(content.clientNonce());
     * byte[] newServerNonce = cryptoSpec.generateNonce();
     * 
     * byte[] publicKeyEncryptedData = cryptoSpec.asymmetricEncrypt(
     * Utils.concat(confirmation, incrementedClientNonce, newServerNonce,
     * cryptoConfigBytes),
     * clientPublicKey);
     * byte[] ydhServer = cryptoSpec.getYdhBytes();
     * byte[] digitalSignature = cryptoSpec.sign(Utils.concat(
     * confirmation, currentUser.userId().getBytes(),
     * incrementedClientNonce, newServerNonce, cryptoConfigBytes, ydhServer));
     * byte[] integrityProof = hmac.createIntegrityProof(
     * Utils.concat(publicKeyEncryptedData, ydhServer, digitalSignature), null);
     * 
     * this.userRequest = new String(content.request());
     * this.udpPort = ((content.udpPortBytes()[0] & 0xFF) << 24) |
     * ((content.udpPortBytes()[1] & 0xFF) << 16) |
     * ((content.udpPortBytes()[2] & 0xFF) << 8) |
     * (content.udpPortBytes()[3] & 0xFF);
     * this.sharedSecret = dhSecret;
     * 
     * ShpMessage response = new ShpMessage(makeHeader(MsgType.TYPE_4),
     * publicKeyEncryptedData, ydhServer, digitalSignature, integrityProof);
     * LOGGER.info("Sent TYPE_4.");
     * return ShpProtocolResult.ongoing(response);
     * 
     * } catch (GeneralSecurityException e) {
     * LOGGER.log(Level.SEVERE, "Error handling TYPE_3.", e);
     * return ShpProtocolResult.error();
     * }
     * }
     */

    /*
     * private ShpProtocolResult handleType5(Type5Message msg) {
     * LOGGER.info("Received TYPE_5.");
     * try {
     * if (!hmac.verifyIntegrity(msg.sharedKeyEncryptedData(), null,
     * msg.integrityProof())) {
     * LOGGER.severe("TYPE_5 integrity check failed.");
     * return ShpProtocolResult.error();
     * }
     * 
     * byte[] decryptedData = sharedKeyCipher.decrypt(msg.sharedKeyEncryptedData());
     * byte[][] parts = Utils.divideInParts(decryptedData,
     * ShpCryptoSpec.FINISH_PROTOCOL.getBytes().length);
     * byte[] finishProtocol = parts[0];
     * byte[] incrementedNonce = parts[1];
     * 
     * if (!new String(finishProtocol).equals(ShpCryptoSpec.FINISH_PROTOCOL)) {
     * LOGGER.severe("Invalid FINISH_PROTOCOL token.");
     * return ShpProtocolResult.error();
     * }
     * 
     * if (!noncesReceived.add(ByteBuffer.wrap(incrementedNonce))) {
     * LOGGER.severe("Replay attack detected in TYPE_5.");
     * return ShpProtocolResult.error();
     * }
     * 
     * return ShpProtocolResult.finished();
     * 
     * } catch (GeneralSecurityException e) {
     * LOGGER.log(Level.SEVERE, "Error handling TYPE_5.", e);
     * return ShpProtocolResult.error();
     * }
     * }
     */

    private byte[] makeHeader(MsgType type) {
        return new byte[] { (byte) (SHP_VERSION << 4 | SHP_RELEASE), (byte) type.ordinal() };
    }
}
