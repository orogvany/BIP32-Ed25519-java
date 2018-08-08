/**
 * Copyright (c) 2017-2018 The Semux Developers
 *
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package com.github.orogvany.bip32.extern;

import com.github.orogvany.bip32.exception.CryptoException;

/**
 * Hex utility
 */
public class Hex {

    public static final String PREF = "0x";

    private static final char[] intToHex = "0123456789abcdef".toCharArray();
    private static final int[] hexToInt = new int[128];
    static {
        for (byte i = 0; i < 16; i++) {
            if (i < 10) {
                hexToInt['0' + i] = i;
            } else {
                hexToInt['a' + i - 10] = i;
                hexToInt['A' + i - 10] = i;
            }
        }
    }

    private Hex() {
    }

    /**
     * Encodes a byte array into a hex string.
     *
     * @param raw
     * @return
     */
    public static String encode(byte[] raw) {
        char[] hex = new char[raw.length * 2];

        for (int i = 0; i < raw.length; i++) {
            hex[i * 2] = intToHex[(raw[i] & 0xF0) >> 4];
            hex[i * 2 + 1] = intToHex[raw[i] & 0x0F];
        }

        return new String(hex);
    }

    /**
     * Encodes a byte array into hex string.
     *
     * @param raw
     * @return the hex encoding with 0x prefix
     */
    public static String encode0x(byte[] raw) {
        return Hex.PREF + encode(raw);
    }

    /**
     * Decode a hex encoded byte array.
     *
     * @param hex
     * @throws CryptoException
     *             if the input is not a valid hex string
     * @return
     */
    public static byte[] decode(String hex) throws CryptoException {
        if (hex == null || !hex.matches("([0-9a-fA-F]{2})*")) {
            throw new CryptoException("Invalid hex string");
        }

        byte[] raw = new byte[hex.length() / 2];

        char[] chars = hex.toCharArray();
        for (int i = 0; i < chars.length; i += 2) {
            raw[i / 2] = (byte) ((hexToInt[chars[i]] << 4) + hexToInt[chars[i + 1]]);
        }

        return raw;
    }

    /**
     * Decodes a hex encoded byte array.
     * <p>
     * This method will automatically detect the '0x' prefix.
     *
     * @param hex
     * @throws CryptoException
     *             if the input is not a valid hex string
     * @return
     */
    public static byte[] decode0x(String hex) throws CryptoException {
        if (hex != null && hex.startsWith(Hex.PREF)) {
            return decode(hex.substring(2));
        } else {
            return decode(hex);
        }
    }
}
