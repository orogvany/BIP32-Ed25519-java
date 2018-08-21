package com.github.orogvany.bip32;

import com.github.orogvany.bip32.wallet.HdAddress;
import com.github.orogvany.bip32.wallet.HdKeyGenerator;
import com.github.orogvany.bip32.wallet.key.HdPublicKey;
import org.junit.Assert;
import org.junit.Test;

import java.io.UnsupportedEncodingException;

public class PublicKeyChainTest {

    public static final String SEED = "000102030405060708090a0b0c0d0e0f";

    HdKeyGenerator generator = new HdKeyGenerator();

    @Test
    public void testPubKey0() throws UnsupportedEncodingException {

        HdAddress rootAddress = generator.getAddressFromSeed(SEED, Network.mainnet);
        HdAddress address = generator.getAddress(rootAddress, 0, false);
        //test that the pub key chain generated from only public key matches the other
        HdPublicKey pubKey = generator.getPublicKey(rootAddress.getPublicKey(), 0, false);
        Assert.assertEquals(address.getPublicKey().getKey(), pubKey.getKey());
    }
}
