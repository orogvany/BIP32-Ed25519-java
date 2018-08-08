package com.github.orogvany.bip32;

import org.junit.Test;

import java.io.UnsupportedEncodingException;

import static org.junit.Assert.assertEquals;

public class VectorTwoTest extends BaseVectorTest {
    public static final String SEED = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";

    public VectorTwoTest() throws UnsupportedEncodingException {
        super();
    }

    @Test
    public void testMasterNodePrivateKey() {
        String expected = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";
        assertEquals(expected, masterNode.getPrivateKey().getKey());
    }

    @Test
    public void testMasterNodePublicKey() {
        String expected = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
        assertEquals(expected, masterNode.getPublicKey().getKey());
    }

    @Override
    protected String getSeed() {
        return SEED;
    }
}
