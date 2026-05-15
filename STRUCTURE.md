# Part Structur

This file should be used as a reference for the files/classes used for each part.

## Part 1 RTSSP: Secure Real-Time Streaming

Crypto config is loaded statically from `.properties` files.

### Entry points
| File | Role |
|---|---|
| `server/src/main/java/server/Part1Main.java` | Streams `.dat` files over secure multicast UDP |
| `proxy/src/main/java/proxy/Part1Main.java` | Receives, decrypts, and forwards to a media player |
| `client/run-vlc.sh` / `client/run-mpv.sh` | Player-side scripts (VLC / MPV) |

### Crypto layer (`lib/src/main/java/crypto/`)
| File | Role                                                                                                |
|---|-----------------------------------------------------------------------------------------------------|
| `CipherSuiteFactory.java` | Builds a `CipherSuite` from a `.properties` file (`fromFile`) or inline config string (`fromConfig`) |
| `ConfigurableCipher.java` | Selects and drives JCE ciphers depending on config                                                  |
| `ConfigurableIntegrityCheck.java` | Selects MACs or hash algorithms depending on config                                                 |
| `CipherSuite.java` | Bundles a `Cipher` + `IntegrityCheck`; records whether MAC or hash mode is used             |
| `IntegrityCheck.java` | Interface: `createIntegrityProof(byte[])` / `verifyIntegrity(byte[], byte[])`                       |
| `SymmetricCipher.java` | Interface for symmetric ciphers                                                                     |
| `HashUtils.java` | SHA-2 hashing and HKDF key derivation                                                               |
| `CryptoConfigParser.java` / `CryptoConfigKey.java` | `.properties` / INI config parsing                                                                  |

### Secure datagram layer (`lib/src/main/java/datagram/`)
| File | Role                                                                             |
|---|----------------------------------------------------------------------------------|
| `SecureSocketBase.java` | RTSSP framing: wraps/unwraps packets with encryption and integrity proof |
| `SecureDatagramSocket.java` | Unicast secure datagram socket                                                   |
| `SecureMulticastSocket.java` | Multicast secure datagram socket                                                 |
| `StreamControl.java` | Contains the unique frame sent upon finishing a stream                           |

### Configuration
| File | Role |
|---|---|
| `server/crypto/cars.properties` | Server-side crypto config for `cars.dat` |
| `server/crypto/monsters.properties` | Server-side crypto config for `monsters.dat` |
| `proxy/crypto/cars.properties` | Proxy-side crypto config for `cars.dat` |
| `proxy/crypto/monsters.properties` | Proxy-side crypto config for `monsters.dat` |

---

## Part 2 SHP: Secure Handshake Protocol

Output of SHP returns a cipher suite constructed in the same way as part 1 but from a derived ECDH secret.

```
Client                            Server
  |--- CLIENT_HELLO ------------> |  cert, ECDH pubkey, suite list, nonce, signature
  |<-- SERVER_HELLO ------------- |  cert, ECDH pubkey, selected suite, nonce, nonce+1, signature
  |--- CSSP -------------------> |  encrypt(serverNonce+1 | udpPort), [integrity proof]
```

### Entry points
| File | Role |
|---|---|
| `server/src/main/java/server/Part2Main.java` | SHP server: runs handshake then streams over secure multicast |
| `proxy/src/main/java/proxy/Part2Main.java` | SHP client: runs handshake then receives and forwards stream |

### SHP protocol (`lib/src/main/java/shp/`)
| File | Role |
|---|---|
| `ShpCryptoSpec.java` | Per-session bundle: ECDSA signing key + ephemeral ECDH key pair + X.509 certificate |
| `AbstractShpPeer.java` | TCP I/O and `runProtocol()` state-machine loop |
| `client/ShpClient.java` | Client TCP lifecycle; drives `ShpClientProtocol` |
| `client/ShpClientOutput.java` | Output record: negotiated `CipherSuite` |
| `server/ShpServer.java` | Server TCP lifecycle; drives `ShpServerProtocol` |
| `server/ShpServerOutput.java` | Output record: `request`, `udpPort`, negotiated `CipherSuite` |
| `protocol/ShpClientProtocol.java` | All client-side handshake logic and state |
| `protocol/ShpServerProtocol.java` | All server-side handshake logic, suite selection, and nonce tracking |
| `protocol/MsgType.java` | Message type enum (CLIENT_HELLO, SERVER_HELLO, CSSP, SERVER_ERROR) |
| `protocol/ShpProtocolResult.java` | Typed result: waiting / finished / error |
| `protocol/State.java` | Protocol state enum |
| `message/ShpClientHello.java` | CLIENT_HELLO: cert, ECDH key, suite list, nonce, signature |
| `message/ShpServerHello.java` | SERVER_HELLO: cert, ECDH key, selected suite, nonces, signature |
| `message/ShpCssp.java` | CSSP: encrypted payload + integrity proof |
| `ShpMessage.java` | Wire format: header + length-prefixed payload fields |

### PKI (`lib/src/main/java/crypto/`)
| File | Role |
|---|---|
| `CertificateUtils.java` | Load PKCS12 keystores/truststores, decode X.509 certs, trust verification |
| `EcdhKeyAgreement.java` | Ephemeral ECDH key agreement |
| `EcdsaSignature.java` | ECDSA sign / verify |
| `DigitalSignature.java` | Interface for digital signatures |
| `CustomKeyAgreement.java` | Key agreement interface |

### Configuration
| File | Role                                                              |
|---|-------------------------------------------------------------------|
| `server/suites/cars-suites.conf` | Ordered cipher suite list for `cars.dat` (by server preference)   |
| `server/suites/monsters-suites.conf` | Ordered cipher suite list for `monsters.dat` (by server preference)                     |
| `proxy/cipher-suites.conf` | Cipher suites advertised by the proxy client                      |
| `scripts/generate-shp-stores.sh` | Generates PKCS12 identity + truststore pairs for server and proxy |