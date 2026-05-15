package shp.protocol;

public enum MsgType {
    CLIENT_HELLO,
    SERVER_HELLO,
    CSSP,
    SERVER_ERROR;

    public static MsgType from(byte[] header) {
        return values()[header[1]];
    }
}
