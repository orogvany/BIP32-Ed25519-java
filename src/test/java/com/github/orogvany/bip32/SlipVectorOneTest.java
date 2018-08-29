/**
 * Copyright (c) 2018 orogvany
 *
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package com.github.orogvany.bip32;

import com.github.orogvany.bip32.extern.Hex;
import com.github.orogvany.bip32.wallet.CoinType;
import com.github.orogvany.bip32.wallet.HdAddress;
import com.github.orogvany.bip32.wallet.HdKeyGenerator;
import com.github.orogvany.bip32.wallet.key.Curve;
import com.github.orogvany.bip32.wallet.key.HdPrivateKey;
import com.github.orogvany.bip32.wallet.key.HdPublicKey;
import org.junit.Assert;
import org.junit.Test;

import java.io.UnsupportedEncodingException;

import static org.junit.Assert.fail;

public class SlipVectorOneTest {

    public static final String SEED = "000102030405060708090a0b0c0d0e0f";
    public HdKeyGenerator hdKeyGenerator = new HdKeyGenerator();

    @Test
    public void testVectorOneMaster() throws UnsupportedEncodingException {
        byte[] fingerprint = Hex.decode("00000000");
        byte[] chainCode = Hex.decode("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb");
        byte[] privateKey = Hex.decode("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7");
        byte[] publicKey = Hex.decode("00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed");

        HdAddress<HdPrivateKey, HdPublicKey> address = hdKeyGenerator.getAddressFromSeed(SEED, Network.mainnet, CoinType.semux);

        Assert.assertArrayEquals(fingerprint, address.getPrivateKey().getFingerprint());
        Assert.assertArrayEquals(chainCode, address.getPrivateKey().getChainCode());
        Assert.assertArrayEquals(privateKey, address.getPrivateKey().getPrivateKey());
        Assert.assertArrayEquals(publicKey, address.getPublicKey().getPublicKey());
        Assert.assertEquals(Curve.ed25519, address.getCoinType().getCurve());
    }

    @Test
    public void testUnableToPublicChain() throws UnsupportedEncodingException {
        HdAddress<HdPrivateKey, HdPublicKey> address = hdKeyGenerator.getAddressFromSeed(SEED, Network.mainnet, CoinType.semux);
        try {
            hdKeyGenerator.getPublicKey(address.getPublicKey(), 0, false, Curve.ed25519);
            fail("Should not be able to chain public keys with ed25519");

        } catch (UnsupportedOperationException e) {
            // expected
        }
    }

    @Test
    public void testVector0H() throws UnsupportedEncodingException {
        byte[] fingerprint = Hex.decode("ddebc675");
        byte[] chainCode = Hex.decode("8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69");
        byte[] privateKey = Hex.decode("68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3");
        byte[] publicKey = Hex.decode("008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c");

        HdAddress<HdPrivateKey, HdPublicKey> master = hdKeyGenerator.getAddressFromSeed(SEED, Network.mainnet, CoinType.semux);
        HdAddress<HdPrivateKey, HdPublicKey> address = hdKeyGenerator.getAddress(master, 0, true);

        Assert.assertArrayEquals(fingerprint, address.getPrivateKey().getFingerprint());
        Assert.assertArrayEquals(chainCode, address.getPrivateKey().getChainCode());
        Assert.assertArrayEquals(privateKey, address.getPrivateKey().getPrivateKey());
        Assert.assertArrayEquals(publicKey, address.getPublicKey().getPublicKey());
        Assert.assertEquals(Curve.ed25519, address.getCoinType().getCurve());
    }

    @Test
    public void testVector0H1H() throws UnsupportedEncodingException {
        byte[] fingerprint = Hex.decode("13dab143");
        byte[] chainCode = Hex.decode("a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14");
        byte[] privateKey = Hex.decode("b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2");
        byte[] publicKey = Hex.decode("001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187");

        HdAddress<HdPrivateKey, HdPublicKey> master = hdKeyGenerator.getAddressFromSeed(SEED, Network.mainnet, CoinType.semux);
        HdAddress<HdPrivateKey, HdPublicKey> address = hdKeyGenerator.getAddress(master, 0, true);
        address = hdKeyGenerator.getAddress(address, 1, true);

        Assert.assertArrayEquals(fingerprint, address.getPrivateKey().getFingerprint());
        Assert.assertArrayEquals(chainCode, address.getPrivateKey().getChainCode());
        Assert.assertArrayEquals(privateKey, address.getPrivateKey().getPrivateKey());
        Assert.assertArrayEquals(publicKey, address.getPublicKey().getPublicKey());
        Assert.assertEquals(Curve.ed25519, address.getCoinType().getCurve());
    }

    @Test
    public void testVector0H1H2H() throws UnsupportedEncodingException {
        byte[] fingerprint = Hex.decode("ebe4cb29");
        byte[] chainCode = Hex.decode("2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c");
        byte[] privateKey = Hex.decode("92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9");
        byte[] publicKey = Hex.decode("00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1");

        HdAddress<HdPrivateKey, HdPublicKey> master = hdKeyGenerator.getAddressFromSeed(SEED, Network.mainnet, CoinType.semux);
        HdAddress<HdPrivateKey, HdPublicKey> address = hdKeyGenerator.getAddress(master, 0, true);
        address = hdKeyGenerator.getAddress(address, 1, true);
        address = hdKeyGenerator.getAddress(address, 2, true);

        Assert.assertArrayEquals(fingerprint, address.getPrivateKey().getFingerprint());
        Assert.assertArrayEquals(chainCode, address.getPrivateKey().getChainCode());
        Assert.assertArrayEquals(privateKey, address.getPrivateKey().getPrivateKey());
        Assert.assertArrayEquals(publicKey, address.getPublicKey().getPublicKey());
        Assert.assertEquals(Curve.ed25519, address.getCoinType().getCurve());
    }
}
