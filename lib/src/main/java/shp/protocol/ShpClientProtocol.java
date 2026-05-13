package shp.protocol;

import common.Utils;
import crypto.CertificateLoader;
import crypto.CipherSuite;
import crypto.CipherSuiteFactory;
import shp.ShpCryptoSpec;
import shp.ShpMessage;
import shp.message.ShpClientHello;
import shp.message.ShpClientFinish;
import shp.message.ShpServerHello;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Set;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ShpClientProtocol {


    private static final List<String> DEFAULT_SUPPORTED_CIPHER_SUITES = List.of(
            "AES/GCM/NoPadding:SHA256",
            "AES/CTR/NoPadding:HMAC-SHA512");
    
    private static final Logger LOGGER = Logger.getLogger(ShpClientProtocol.class.getName());
    private static final short SHP_VERSION = 0x01;
    private static final byte SHP_RELEASE = 0x01;

    private final ShpCryptoSpec cryptoSpec;
    private final KeyStore trustStore;

    private String request;
    private byte[] udpPortBytes;

    private final Set<ByteBuffer> noncesReceived = new HashSet<>();

    private String cryptoConfig;
    private byte[] sharedSecret;
    private byte[] clientNonce;

    public ShpClientProtocol(ShpCryptoSpec cryptoSpec, KeyStore trustStore) {
        this.cryptoSpec = cryptoSpec;
        this.trustStore = trustStore;
    }

    public void setInput(String request, byte[] udpPortBytes) {
        this.request = request;
        this.udpPortBytes = udpPortBytes;
    }

    public ShpMessage buildClientHello() throws GeneralSecurityException {
        clientNonce = ShpCryptoSpec.generateNonce();
        byte[] clientCertificate = cryptoSpec.getCertificateBytes();
        byte[] clientEcdhPublicKey = cryptoSpec.getEcdhPublicKeyBytes();

        ShpClientHello unsignedHello = new ShpClientHello(
            request,
            clientCertificate,
            clientEcdhPublicKey,
            DEFAULT_SUPPORTED_CIPHER_SUITES,
            clientNonce,
            new byte[0] 
        );

        byte[] signature = cryptoSpec.sign(unsignedHello.bytesToSign());

        ShpClientHello signedHello = new ShpClientHello(
            request,
            clientCertificate,
            clientEcdhPublicKey,
            DEFAULT_SUPPORTED_CIPHER_SUITES,
            clientNonce,
            signature
        );      

        LOGGER.info("Sent CLIENT_HELLO.");
        return signedHello.toShpMessage(makeHeader(MsgType.CLIENT_HELLO));
    }

    public ShpProtocolResult handle(ShpMessage message) {
        MsgType type = MsgType.from(message.getHeader());

        return switch (type) {
            case SERVER_HELLO -> handleServerHello(ShpServerHello.from(message));
            default -> {
                LOGGER.severe("Unexpected message type: " + type);
                yield ShpProtocolResult.error();
            }
        };
    }

    private ShpProtocolResult handleServerHello(ShpServerHello msg) {
        LOGGER.info("Received SERVER_HELLO.");
        try {

            if (!msg.clientCertificateAccepted()) {
                LOGGER.severe("Server rejected client certificate.");
                return ShpProtocolResult.error();
            }

            if (!request.equals(msg.request())) {
                LOGGER.severe("SERVER_HELLO request mismatch.");
                return ShpProtocolResult.error();
            }

            var serverCertificate = CertificateLoader.decodeCertificate(msg.serverCertificate());

            if (!CertificateLoader.isTrusted(serverCertificate, trustStore)) {
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
            sharedSecret = cryptoSpec.generateSharedSecret(serverEcdhPublicKey);
            cryptoConfig = msg.selectedCryptoConfig();

            CipherSuite suite = CipherSuiteFactory.fromConfig(cryptoConfig, sharedSecret);

            byte[] finishToken = ShpCryptoSpec.FINISH_PROTOCOL.getBytes(StandardCharsets.UTF_8);
            byte[] serverNonceResponse = Utils.getIncrementedBytes(msg.serverNonce());
            byte[] plaintext = Utils.concat(finishToken, serverNonceResponse, udpPortBytes);

            byte[] encryptedPayload = suite.cipher().encrypt(plaintext);
            byte[] integrityProof = suite.hasIntegrityCheck()
                    ? suite.integrityCheck().createIntegrityProof(encryptedPayload, msg.serverNonce())
                    : new byte[0];

            ShpClientFinish finish = new ShpClientFinish(encryptedPayload, integrityProof);

            LOGGER.info("Sent CLIENT_FINISH.");
            return ShpProtocolResult.finished(finish.toShpMessage(makeHeader(MsgType.CLIENT_FINISH)));

        } catch (GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "Error handling SERVER_HELLO.", e);
            return ShpProtocolResult.error();
        }
    }

    public String getCryptoConfig() { return cryptoConfig; }
    public byte[] getSharedSecret() { return sharedSecret; }

    private byte[] makeHeader(MsgType type) {
        return new byte[]{ (byte) (SHP_VERSION << 4 | SHP_RELEASE), (byte) type.ordinal() };
    }
}
