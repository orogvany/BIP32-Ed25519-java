package com.github.orogvany.bip32;

import com.github.orogvany.bip32.extern.Hex;
import com.github.orogvany.bip32.wallet.HdAddress;
import com.github.orogvany.bip32.wallet.HdKeyGenerator;
import com.github.orogvany.bip32.wallet.key.Curve;
import com.github.orogvany.bip32.wallet.key.HdPrivateKey;
import com.github.orogvany.bip32.wallet.key.HdPublicKey;
import org.junit.Assert;
import org.junit.Test;

import java.io.UnsupportedEncodingException;

public class SlipVectorOneTest {

    public static final String SEED = "000102030405060708090a0b0c0d0e0f";
    public HdKeyGenerator hdKeyGenerator = new HdKeyGenerator();

    @Test
    public void testVectorOneMaster() throws UnsupportedEncodingException {
        byte[] chainCode = Hex.decode("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb");
        byte[] privateKey = Hex.decode("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7");
        byte[] publicKey = Hex.decode("00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed");

        HdAddress<HdPrivateKey, HdPublicKey> address = hdKeyGenerator.getAddressFromSeed(SEED, Network.mainnet, Curve.ed25519);

        Assert.assertArrayEquals(chainCode, address.getPrivateKey().getChainCode());
        Assert.assertArrayEquals(privateKey, address.getPrivateKey().getPrivateKey());
        Assert.assertArrayEquals(publicKey, address.getPublicKey().getPublicKey());

    }
}
