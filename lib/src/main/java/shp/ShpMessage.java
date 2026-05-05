package shp;

import java.io.Serializable;
import java.util.List;

public class ShpMessage implements Serializable {

    private final byte[] header;
    private final List<byte[]> payload;

    public ShpMessage(byte[] header, List<byte[]> payload) {
        this.header = header;
        this.payload = payload;
    }

    public byte[] getHeader() {
        return header;
    }

    public List<byte[]> getPayload() {
        return payload;
    }
}
