package com.github.orogvany.bip32.crypto;

import org.junit.Assert;
import org.junit.Test;

import java.util.BitSet;
import java.util.Random;

public class BitSetUtilTest {

    @Test
    public void testBitsetConversion() {
        //to test/package local
        byte[] bytes = new byte[6];
        new Random().nextBytes(bytes);
        BitSet bs = BitSetUtil.createBitset(bytes);
        byte[] bsBytes = bs.toByteArray();
        byte[] ret = BitSetUtil.createBytes(bs, 6);
        Assert.assertArrayEquals(bytes, ret);
    }
}
