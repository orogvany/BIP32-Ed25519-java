package com.github.orogvany.bip32;

import com.github.orogvany.bip32.wallet.HdAddress;
import org.junit.Test;

import java.io.UnsupportedEncodingException;

import static org.junit.Assert.assertEquals;

/**
 * Test vector from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */
public class VectorOneTest extends BaseVectorTest {

    public static final String SEED = "000102030405060708090a0b0c0d0e0f";

    public VectorOneTest() throws UnsupportedEncodingException {
        super();
    }

    @Test
    public void testMasterNodePrivateKey() {
        String expected = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        assertEquals(expected, masterNode.getPrivateKey().getKey());
    }

    @Test
    public void testMasterNodePublicKey() {
        String expected = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        assertEquals(expected, masterNode.getPublicKey().getKey());
    }

    @Test
    public void testChainPrivateKey() {
        String expected = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
        HdAddress chain = hdKeyGenerator.getAddress(masterNode, 0);
        assertEquals(expected, chain.getPrivateKey().getKey());

    }

    @Override
    protected String getSeed() {
        return SEED;
    }
}
