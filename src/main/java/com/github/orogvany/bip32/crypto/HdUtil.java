/**
 * Copyright (c) 2018 orogvany
 *
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package com.github.orogvany.bip32.crypto;

import org.apache.commons.lang3.ArrayUtils;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * General Util class for defined functions.
 */
public class HdUtil {

    /**
     * ser32(i): serialize a 32-bit unsigned integer i as a 4-byte sequence,
     * most significant byte first.
     * <p>
     * Prefer long type to hold unsigned ints.
     *
     * @return ser32(i)
     */
    public static byte[] ser32(long i) {

        byte[] ser = new byte[4];
        ser[0] = (byte) (i >> 24);
        ser[1] = (byte) (i >> 16);
        ser[2] = (byte) (i >> 8);
        ser[3] = (byte) (i);
        return ser;
    }

    /**
     * ser256(p): serializes the integer p as a 32-byte sequence, most
     * significant byte first.
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
     * ser256(p): serializes the integer p as a 32-byte sequence, least
     * significant byte first.
     *
     * @param p big integer
     * @return 32 byte sequence
     */
    public static byte[] ser256LE(BigInteger p) {

        byte[] byteArray = p.toByteArray();
        ArrayUtils.reverse(byteArray);

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
     * parse256(p): interprets a 32-byte sequence as a 256-bit number, most
     * significant byte first.
     *
     * @param p bytes
     * @return 256 bit number
     */
    public static BigInteger parse256(byte[] p) {
        return new BigInteger(1, p);
    }

    /**
     * parse256LE(p): interprets a 32-byte sequence as a 256-bit number, least
     * significant byte first
     *
     * @param p bytes
     * @return 256 bit number
     */
    public static BigInteger parse256LE(byte[] p) {
        byte[] copy = ArrayUtils.clone(p);
        ArrayUtils.reverse(copy);

        return new BigInteger(1, copy);
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

    /**
     * Get the fingerprint
     *
     * @param keyData key data
     * @return fingerprint
     */
    public static byte[] getFingerprint(byte[] keyData) {
        byte[] point = Secp256k1.serP(Secp256k1.point(HdUtil.parse256(keyData)));
        byte[] h160 = Hash.h160(point);
        return new byte[]{h160[0], h160[1], h160[2], h160[3]};
    }

    public static byte[] ser32LE(long i) {
        byte[] ser = new byte[4];
        ser[3] = (byte) (i >> 24);
        ser[2] = (byte) (i >> 16);
        ser[1] = (byte) (i >> 8);
        ser[0] = (byte) (i);
        return ser;
    }
}

