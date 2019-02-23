package com.github.orogvany.bip32.crypto;

import java.util.BitSet;

public class BitSetUtil {


    public static BitSet addCode(BitSet bitSet, int code) {
        return BitSetUtil.append(bitSet, BitSetUtil.getBitSet(code), 11);
    }


    public static BitSet append(BitSet a, BitSet b, int bLength) {

        //shift A << bLength
        BitSet ret = shift(a, bLength);
        ret.or(b);
        return ret;
    }

    public static BitSet shift(BitSet bitSet, int length) {
        BitSet ret = new BitSet(bitSet.length() + length);
        for (int i = 0; i < bitSet.length(); i++) {
            if (bitSet.get(i)) {
                ret.set(i + length);
            }
        }
        return ret;
    }

    public static byte[] createBytes(BitSet bitset, int numBytes) {
        byte[] ret = new byte[numBytes];

        //todo this is wrong
        byte[] bsArray = bitset.toByteArray();
        int offset = ret.length - bsArray.length;
        if(offset <0)
        {
            return null;
        }

        System.arraycopy( bsArray, 0, ret, 0, numBytes );


        return ret;
    }

    /**
     * For some reason Bitset.valueOf() does not return correct data we
     * expect.
     *
     * @param bytes
     * @return
     */
    public static BitSet createBitset(byte[] bytes) {
        BitSet ret = new BitSet();
        int offset = 0;
        for (byte b : bytes) {
            for (int i = 1; i < 9; i++) {
                if (BitUtil.checkBit(b, i)) {
                    ret.set(offset);
                }
                offset++;
            }
        }
        return ret;
    }


    /**
     * get a printable version of a bitset
     *
     * @param bitset
     * @param length
     * @return
     */
    public static String getBitString(BitSet bitset, int length) {
        StringBuilder ret = new StringBuilder();
        for (int i = 0; i < length; i++) {
            ret.append(bitset.get(i) ? "1" : "0");
        }
        return ret.toString();
    }

    public static int getInt(BitSet range) {

        int ret = 0;
        for (int i = 0; i < 11; i++) {

            ret = ret << 1;
            if (range.get(i)) {
                ret |= 1;
            }
        }
        return ret;
    }

    public static BitSet getBitSet(int value) {
        BitSet ret = new BitSet(11);
        for (int i = 0; i < 11; i++) {
            byte bit = (byte) ((value >> i) & 1);
            if (bit == 0x1) {
                ret.set(10 - i);
            }
        }
        return ret;
    }

}
