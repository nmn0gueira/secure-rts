package common;

import java.security.SecureRandom;

/**
 * Common utility functions
 */
public class Utils
{
    private static final String digits = "0123456789abcdef";
    public static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Return string hexadecimal from byte array of certain size
     *
     * @param data : bytes to convert
     * @param length : nr of bytes in data block to be converted
     * @return  hex : hexadecimal representation of data
     */
    public static String byteArrayToHexString(byte[] data, int length)
    {
        StringBuilder buf = new StringBuilder();

        for (int i = 0; i != length; i++)
        {
            int	v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }

        return buf.toString();
    }

    /**
     * Return string hexadecimal from data in byte array from
     *
     * @param data : bytes to be converted
     * @return : hexadecimal representation of data
     */
    public static String byteArrayToHexString(byte[] data)
    {
        return byteArrayToHexString(data, data.length);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static byte[] concat(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }
        byte[] result = new byte[length];
        int pos = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, pos, array.length);
            pos += array.length;
        }
        return result;
    }

    /**
     *
     * @param array
     * @param start - the start index of the substring (inclusive)
     * @param end - the end index of the substring (exclusive)
     * @return
     */
    public static byte[] subArray(byte[] array, int start, int end) {
        byte[] result = new byte[end - start];
        System.arraycopy(array, start, result, 0, result.length);
        return result;
    }

    /**
     * Returns an array of byte arrays, each one being a subarray of the original array, delimited by the indices
     * @param array - the original array
     * @param indices - the indices that delimit the parts in which the array will be divided
     * @return - an array of byte arrays, each one being a subarray of the original array, delimited by the indices
     */
    public static byte[][] divideInParts(byte[] array, int... indices) {
        byte[][] result = getSubArrayNum(array, indices);

        int previousIndex = 0;
        for (int i = 0; i < indices.length; i++) {
            int currentIndex = indices[i];

            // Get subarray from previousIndex to currentIndex (exclusive)
            result[i] = subArray(array, previousIndex, currentIndex);

            // Update previousIndex to the current boundary index
            previousIndex = currentIndex;
        }

        // Get the remaining part of the array from the last index to the end
        result[indices.length] = subArray(array, previousIndex, array.length);

        return result;
    }

    private static byte[][] getSubArrayNum(byte[] array, int[] indices) {
        for (int i = 0; i < indices.length - 1; i++) {
            if (indices[i] > indices[i + 1]) {
                throw new IllegalArgumentException("Indexes must be in ascending order");
            }
        }

        if (indices[0] <= 0 || indices[indices.length - 1] >= array.length) {
            throw new IllegalArgumentException("Indexes must be within the bounds of the array");
        }

        // Calculate the number of subarrays to create (includes initial and final parts)
        int numParts = indices.length + 1;
        return new byte[numParts][];
    }

    /**
     * Returns the hexadecimal representation of the payload, with the header and data divided by a separator.
     * For visual purposes.
     * @param payload - the payload to be represented
     * @return - the hexadecimal representation of the payload
     */
    public static String getPayloadRepresentation(byte[] payload) {
        byte[] header = new byte[5];
        System.arraycopy(payload, 0, header, 0, 5);
        byte[] data = new byte[payload.length - 5];
        System.arraycopy(payload, 5, data, 0, data.length);
        return getHexRepresentation(header) + " || " + getHexRepresentation(data);
    }

    /**
     * Returns the hexadecimal representation of the data, with every byte being separated by a space.
     * For visual purposes.
     * @param data - the data to be represented
     * @return - the hexadecimal representation of the data
     */
    public static String getHexRepresentation(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            sb.append(Utils.byteArrayToHexString(new byte[]{data[i]}));
            if (i != data.length - 1) {
                sb.append(" ");
            }
        }
        return sb.toString();
    }

    /**
     * Transform a number of x bytes into y bytes (ex: 2 bytes into 4 bytes or 4 bytes into 2 bytes)
     * If the array size is smaller than x, the result will be the original array padded with 0s
     * If the array size is bigger than x, the result will be truncated to the first x bytes of the original array
     * @param data
     * @param x
     * @return
     */
    public static byte[] fitToSize(byte[] data, int x) {
        if (x > data.length) {
            byte[] result = new byte[x];
            System.arraycopy(data, 0, result, 0, data.length);
            return result;
        }
        else if (data.length == x) {
            return data;
        }
        else {
            return subArray(data, 0, x);
        }
    }

    public static byte[] getIncrementedBytes(byte[] bytes) {
        byte[] incrementedNonce = bytes.clone();
        for (int i = incrementedNonce.length - 1; i >= 0; i--) {
            if (++incrementedNonce[i] != 0) {
                break;
            }
        }
        return incrementedNonce;
    }
}



