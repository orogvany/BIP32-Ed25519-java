/**
 * Copyright (c) 2018 orogvany
 * <p>
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package com.github.orogvany.bip32;

import com.github.orogvany.bip32.extern.Hex;
import com.github.orogvany.bip32.wallet.Bip44;
import com.github.orogvany.bip32.wallet.CoinType;
import com.github.orogvany.bip32.wallet.HdAddress;
import org.junit.Test;

import java.io.UnsupportedEncodingException;

public class Bip44Test {
    private Bip44 bip44 = new Bip44();
    private byte[] seed = Hex.decode("abcdef");

    @Test
    public void testBitcoin() throws UnsupportedEncodingException {
        HdAddress address = bip44.getRootAddressFromSeed(seed, Network.mainnet, CoinType.bitcoin);
        bip44.getAddress(address, 0);
    }

    @Test
    public void testSemux() throws UnsupportedEncodingException {
        HdAddress address = bip44.getRootAddressFromSeed(seed, Network.mainnet, CoinType.semux);
        bip44.getAddress(address, 0);
    }
}
