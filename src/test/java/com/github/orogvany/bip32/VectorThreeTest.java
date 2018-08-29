/**
 * Copyright (c) 2018 orogvany
 *
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package com.github.orogvany.bip32;

import com.github.orogvany.bip32.extern.Hex;
import com.github.orogvany.bip32.wallet.HdAddress;
import org.junit.Test;

import java.io.UnsupportedEncodingException;

import static org.junit.Assert.assertEquals;

public class VectorThreeTest extends BaseVectorTest {
    public static final byte[] SEED = Hex.decode("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be");

    public VectorThreeTest() throws UnsupportedEncodingException {
        super();
    }

    @Test
    public void testMasterNodePrivateKey() {
        String expected = "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6";
        assertEquals(expected, masterNode.getPrivateKey().getKey());
    }

    @Test
    public void testMasterNodePublicKey() {
        String expected = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13";
        assertEquals(expected, masterNode.getPublicKey().getKey());
    }

    @Test
    public void testChain0HPrivateKey() {
        String expected = "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L";
        HdAddress chain = hdKeyGenerator.getAddress(masterNode, 0, true);
        assertEquals(expected, chain.getPrivateKey().getKey());
    }

    @Override
    protected byte[] getSeed() {
        return SEED;
    }
}
