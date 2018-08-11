package com.github.orogvany.bip32;

import com.github.orogvany.bip32.crypto.BitUtil;
import org.junit.Assert;
import org.junit.Test;

public class BitUtilTest {

    @Test
    public void testCheckBitFromLeft()
    {
        byte a = 0x01;
        //th 8th bit from the left is one
        Assert.assertTrue(BitUtil.checkBit(a, 8));

        a = (byte) 0x80;
        Assert.assertTrue(BitUtil.checkBit(a, 1));
    }

    @Test
    public void testSetBit()
    {
        byte a = 0;
        a = BitUtil.setBit(a, 1);
        Assert.assertEquals(a, (byte) 0x80);
        a = BitUtil.setBit(a,5);
        Assert.assertEquals(a, (byte) 0x88);
    }

    @Test
    public void testUnsetBit()
    {
        byte a = (byte) 0x88;
        a = BitUtil.unsetBit(a, 1);
        Assert.assertEquals(a, (byte) 0x08);
        a = BitUtil.unsetBit(a,5);
        Assert.assertEquals(a, (byte) 0x00);
    }
}
