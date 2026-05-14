package datagram;

import java.nio.charset.StandardCharsets;

public final class StreamControl {

    public static final byte[] FINISH_FRAME = "SRTS-STREAM-FINISH".getBytes(StandardCharsets.US_ASCII);

    private StreamControl() {}

    public static boolean isFinishFrame(byte[] data, int length) {
        if (length != FINISH_FRAME.length) return false;
        for (int i = 0; i < FINISH_FRAME.length; i++) {
            if (data[i] != FINISH_FRAME[i]) return false;
        }
        return true;
    }
}
