package com.github.orogvany.bip32.crypto;

import com.github.orogvany.bip32.Pair;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * General Util class for defined functions.
 *
 * These will find new homes as development progresses.
 */
public class HdUtil {

    /**
     * point(p): returns the coordinate pair resulting from EC point multiplication (repeated application of the EC group operation) of the secp256k1 base point with the integer p.
     *
     * @param p
     */
    public static Pair point(int p) {

        //todo
        return null;
    }

    /**
     * ser32(i): serialize a 32-bit unsigned integer i as a 4-byte sequence, most significant byte first.
     *
     * @return
     */
    public static byte[] ser32(long i) {

        //todo
        return null;
    }

    /**
     * ser256(p): serializes the integer p as a 32-byte sequence, most significant byte first.
     *
     * @param p big integer
     * @return 32 byte sequence
     */
    public static byte[] ser256(BigInteger p) {
        byte[] byteArray = p.toByteArray();
        byte[] ret = new byte[32];

        //0 fill value
        Arrays.fill(ret, (byte) 0);

        //copy the bigint in
        if (byteArray.length <= ret.length) {
            System.arraycopy(byteArray, 0, ret, ret.length - byteArray.length, byteArray.length);
        } else {
            System.arraycopy(byteArray, byteArray.length - ret.length, ret, 0, ret.length);
        }

        return ret;
    }

    /**
     * serP(P): serializes the coordinate pair P = (x,y) as a byte sequence using SEC1's compressed form: (0x02 or 0x03) || ser256(x), where the header byte depends on the parity of the omitted y coordinate.
     *
     * @param p
     * @return
     */
    public static byte[] serp(Pair p) {
        //todo
        return null;
    }

    /**
     * parse256(p): interprets a 32-byte sequence as a 256-bit number, most significant byte first.
     *
     * @param p bytes
     * @return 256 bit number
     */
    public static BigInteger parse256(byte[] p) {
        return new BigInteger(1, p);
    }

    /**
     * Append two byte arrays
     *
     * @param a first byte array
     * @param b second byte array
     * @return bytes appended
     */
    public static byte[] append(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

}

