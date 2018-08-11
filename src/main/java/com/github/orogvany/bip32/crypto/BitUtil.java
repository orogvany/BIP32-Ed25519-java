package com.github.orogvany.bip32.crypto;

public class BitUtil {

    /**
     * Checks bit value from the left, 1 based
     *
     * @param data
     * @param index
     * @return
     */
    public static boolean checkBit(byte data, int index) {

        byte bit = (byte) ((data >> (8 - index)) & 1);

        return bit == 0x1;
    }

    public static byte setBit(byte data, int index) {
        data |= 1 << (8 - index);
        return data;
    }

    public static byte unsetBit(byte data, int index) {
        data &= ~(1 << (8 - index));
        return data;
    }


}
