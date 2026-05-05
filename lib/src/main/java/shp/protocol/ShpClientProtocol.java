package shp.protocol;


import common.Utils;
import crypto.CipherSuiteFactory;
import crypto.IntegrityCheck;
import crypto.SymmetricCipher;
import shp.ShpCryptoSpec;
import shp.ShpMessage;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ShpClientProtocol {

    private static final Logger LOGGER = Logger.getLogger(ShpClientProtocol.class.getName());
    private static final short SHP_VERSION = 0x01;
    private static final byte SHP_RELEASE = 0x01;

    private final ShpCryptoSpec cryptoSpec;
    private final PublicKey serverPublicKey;

    private String userId;
    private byte[] passwordDigest;
    private String request;
    private byte[] udpPortBytes;

    private IntegrityCheck hmac;
    private final Set<ByteBuffer> noncesReceived = new HashSet<>();

    private String cryptoConfig;
    private byte[] sharedSecret;

    public ShpClientProtocol(ShpCryptoSpec cryptoSpec, PublicKey serverPublicKey) {
        this.cryptoSpec = cryptoSpec;
        this.serverPublicKey = serverPublicKey;
    }

    public void setInput(String userId, byte[] passwordDigest, String request, byte[] udpPortBytes)
            throws GeneralSecurityException {
        if (userId.getBytes().length > ShpCryptoSpec.USER_ID_MAX_SIZE)
            throw new IllegalArgumentException("User ID too long");
        this.userId = userId;
        this.passwordDigest = passwordDigest;
        this.request = request;
        this.udpPortBytes = udpPortBytes;
        this.hmac = CipherSuiteFactory.hmacSha256(passwordDigest);
    }

    public ShpMessage buildClientHello() {
        throw new UnsupportedOperationException("buildClientHello() not yet implemented");
    }

    public ShpProtocolResult handle(ShpMessage message) {
        throw new UnsupportedOperationException("handle() not yet implemented");
    }

    public String getCryptoConfig() { return cryptoConfig; }
    public byte[] getSharedSecret() { return sharedSecret; }

    /*public ShpProtocolResult handle(ShpMessage message) {
        MsgType type = MsgType.from(message.getHeader());
        return switch (type) {
            case TYPE_2 -> handleType2(Type2Message.from(message.getPayload()));
            case TYPE_4 -> handleType4(Type4Message.from(message.getPayload()));
            default -> { LOGGER.severe("Unexpected message type: " + type); yield ShpProtocolResult.error(); }
        };
    }*/

    /*private ShpProtocolResult handleType2(Type2Message msg) {
        LOGGER.info("Received TYPE_2.");
        byte[] salt = Utils.fitToSize(msg.salt(), ShpCryptoSpec.SALT_SIZE);
        byte[] iterationBytes = msg.iterationBytes();
        byte[] serverNonce = msg.nonce();

        if (!noncesReceived.add(ByteBuffer.wrap(salt)) ||
            !noncesReceived.add(ByteBuffer.wrap(iterationBytes)) ||
            !noncesReceived.add(ByteBuffer.wrap(serverNonce))) {
            LOGGER.severe("Repeated nonce in TYPE_2.");
            return ShpProtocolResult.error();
        }

        int iterationCount = ((iterationBytes[0] & 0xFF) << 8) | (iterationBytes[1] & 0xFF);
        byte[] incrementedServerNonce = Utils.getIncrementedBytes(serverNonce);
        byte[] clientNonce = cryptoSpec.generateNonce();

        byte[] data = Utils.concat(request.getBytes(), userId.getBytes(),
                incrementedServerNonce, clientNonce, udpPortBytes);

        try {
            SymmetricCipher pbe = CipherSuiteFactory.pbeCipher(new String(passwordDigest), salt, iterationCount);
            byte[] passwordEncryptedData = pbe.encrypt(data);
            byte[] ydhClient = cryptoSpec.getYdhBytes();
            byte[] digitalSig = cryptoSpec.sign(Utils.concat(data, ydhClient));
            byte[] integrityProof = hmac.createIntegrityProof(
                    Utils.concat(passwordEncryptedData, ydhClient, digitalSig), null);

            ShpMessage response = new ShpMessage(makeHeader(MsgType.TYPE_3),
                    passwordEncryptedData, ydhClient, digitalSig, integrityProof);
            LOGGER.info("Sent TYPE_3.");
            return ShpProtocolResult.ongoing(response);

        } catch (GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "Error handling TYPE_2.", e);
            return ShpProtocolResult.error();
        }
    }*/

    /*private ShpProtocolResult handleType4(Type4Message msg) {
        LOGGER.info("Received TYPE_4.");
        byte[] dataToVerify = Utils.concat(msg.publicKeyEncryptedData(), msg.ydhServer(), msg.serverSignature());
        try {
            if (!hmac.verifyIntegrity(dataToVerify, null, msg.integrityProof())) {
                LOGGER.severe("TYPE_4 integrity check failed.");
                return ShpProtocolResult.error();
            }

            byte[] decryptedData = cryptoSpec.asymmetricDecrypt(msg.publicKeyEncryptedData());
            Type4Message.DecryptedContent content = Type4Message.DecryptedContent.parse(decryptedData);

            if (!new String(content.response()).equals(ShpCryptoSpec.REQUEST_CONFIRMATION)) {
                LOGGER.severe("Server denied request.");
                return ShpProtocolResult.error();
            }

            if (!noncesReceived.add(ByteBuffer.wrap(content.firstNonce())) ||
                !noncesReceived.add(ByteBuffer.wrap(content.secondNonce()))) {
                LOGGER.severe("Replay attack detected in TYPE_4.");
                return ShpProtocolResult.error();
            }

            byte[] signatureMessage = Utils.concat(content.response(), userId.getBytes(),
                    content.firstNonce(), content.secondNonce(),
                    content.cryptoConfigBytes(), msg.ydhServer());
            if (!cryptoSpec.verifySignature(serverPublicKey, signatureMessage, msg.serverSignature())) {
                LOGGER.severe("Invalid server signature.");
                return ShpProtocolResult.error();
            }

            byte[] go = ShpCryptoSpec.FINISH_PROTOCOL.getBytes();
            byte[] incrementNonce = Utils.getIncrementedBytes(content.secondNonce());
            byte[] message = Utils.concat(go, incrementNonce);

            byte[] dhSecret = cryptoSpec.generateSharedSecret(msg.ydhServer());
            SymmetricCipher sharedKeyCipher = CipherSuiteFactory.sharedKeyCipher(HashUtils.SHA3_256.digest(dhSecret));
            byte[] encryptedMessage = sharedKeyCipher.encrypt(message);
            byte[] integrityProof = hmac.createIntegrityProof(encryptedMessage, null);

            this.cryptoConfig = new String(content.cryptoConfigBytes(), StandardCharsets.UTF_8);
            this.sharedSecret = dhSecret;

            ShpMessage response = new ShpMessage(makeHeader(MsgType.TYPE_5), encryptedMessage, integrityProof);
            LOGGER.info("Sent TYPE_5.");
            return new ShpProtocolResult(Optional.of(response), State.FINISHED);

        } catch (GeneralSecurityException e) {
            LOGGER.log(Level.SEVERE, "Error handling TYPE_4.", e);
            return ShpProtocolResult.error();
        }
    }*/

    private byte[] makeHeader(MsgType type) {
        return new byte[]{ (byte) (SHP_VERSION << 4 | SHP_RELEASE), (byte) type.ordinal() };
    }
}
