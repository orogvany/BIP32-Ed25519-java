package com.github.orogvany.bip32.crypto;

public class BitUtil {

    /**
     * Checks bit value from the left, 1 based
     *
     * @param data  data
     * @param index index to check
     * @return true if set
     */
    public static boolean checkBit(byte data, int index) {
        byte bit = (byte) ((data >> (8 - index)) & 1);
        return bit == 0x1;
    }

    /**
     * Set a bit of a byte
     *
     * @param data  data
     * @param index index to set
     * @return byte with bit set
     */
    public static byte setBit(byte data, int index) {
        data |= 1 << (8 - index);
        return data;
    }

    /**
     * Unset a bit of a byte
     *
     * @param data  data
     * @param index index to clear
     * @return byte with bit unset
     */
    public static byte unsetBit(byte data, int index) {
        data &= ~(1 << (8 - index));
        return data;
    }
}
