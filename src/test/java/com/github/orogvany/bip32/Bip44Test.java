package com.github.orogvany.bip32;

import com.github.orogvany.bip32.wallet.Bip44;
import com.github.orogvany.bip32.wallet.CoinType;
import com.github.orogvany.bip32.wallet.HdAddress;
import org.junit.Test;

import java.io.UnsupportedEncodingException;

public class Bip44Test {
    private Bip44 bip44 = new Bip44();

    @Test
    public void testBitcoin() throws UnsupportedEncodingException {
        HdAddress address = bip44.getRootAddressFromSeed("abcdef", Network.mainnet, CoinType.bitcoin);
        bip44.getAddress(address, 0);
    }

    @Test
    public void testSemux() throws UnsupportedEncodingException {
        HdAddress address = bip44.getRootAddressFromSeed("abcdef", Network.mainnet, CoinType.semux);
        bip44.getAddress(address, 0);
    }
}
