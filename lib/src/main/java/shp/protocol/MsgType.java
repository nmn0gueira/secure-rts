package shp.protocol;

public enum MsgType {
    CLIENT_HELLO,
    SERVER_HELLO,
    CLIENT_FINISH;

    public static MsgType from(byte[] header) {
        return values()[header[1]];
    }
}
