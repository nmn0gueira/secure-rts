package shp.server;

import crypto.CipherSuite;

public record ShpServerOutput(String request, int udpPort, CipherSuite cipherSuite) {
}
