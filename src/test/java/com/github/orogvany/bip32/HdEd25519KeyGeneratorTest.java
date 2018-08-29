/**
 * Copyright (c) 2018 orogvany
 *
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package com.github.orogvany.bip32;

import com.github.orogvany.bip32.exception.CryptoException;
import com.github.orogvany.bip32.extern.Hex;
import com.github.orogvany.bip32.wallet.CoinType;
import com.github.orogvany.bip32.wallet.HdAddress;
import com.github.orogvany.bip32.wallet.HdEd25519KeyGenerator;
import com.github.orogvany.bip32.wallet.HdKeyGenerator;
import com.github.orogvany.bip32.wallet.key.HdPrivateKey;
import com.github.orogvany.bip32.wallet.key.HdPublicKey;
import com.github.orogvany.bip32.wallet.key.ed25519.HdEd25519PrivateKey;
import com.github.orogvany.bip32.wallet.key.ed25519.HdEd25519PublicKey;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

@Ignore
public class HdEd25519KeyGeneratorTest {

    public HdEd25519KeyGenerator hdKeyGenerator = new HdEd25519KeyGenerator();
    public HdKeyGenerator generalGenerator = new HdKeyGenerator();

    @Test
    public void testKeyGeneration() throws UnsupportedEncodingException, InvalidKeySpecException {
        byte[] seedBytes = Hex.decode("feeed1");

        HdAddress<HdPrivateKey, HdPublicKey> generalMaster = generalGenerator.getAddressFromSeed(seedBytes, Network.mainnet, CoinType.bitcoin);
        byte[] masterSecret = generalMaster.getPrivateKey().getKeyData();

        HdAddress<HdEd25519PrivateKey, HdEd25519PublicKey> address = hdKeyGenerator.getAddressFromSeed(Hex.encode(masterSecret), Network.mainnet);

        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519");

        EdDSAPrivateKey sk = new EdDSAPrivateKey(new EdDSAPrivateKeySpec(spec, address.getPrivateKey().getEd25519Key()));
        EdDSAPublicKey pk = new EdDSAPublicKey(new EdDSAPublicKeySpec(address.getPublicKey().getEd25519Key(), spec));

        String test = "Here's a message";

        byte[] sig = sign(sk, test.getBytes());
        boolean verified = verify(test.getBytes(), sig, pk);

        Assert.assertTrue(verified);
    }

    @Test
    public void testChildKeyGeneration() throws UnsupportedEncodingException {
        byte[] seedBytes = Hex.decode("feeed1");
        HdAddress<HdPrivateKey, HdPublicKey> generalMaster = generalGenerator.getAddressFromSeed(seedBytes, Network.mainnet, CoinType.bitcoin);
        byte[] masterSecret = generalMaster.getPrivateKey().getKeyData();

        HdAddress<HdEd25519PrivateKey, HdEd25519PublicKey> address = hdKeyGenerator.getAddressFromSeed(Hex.encode(masterSecret), Network.mainnet);

        address = hdKeyGenerator.getAddress(address,0, false);

        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519");

        EdDSAPrivateKey sk = new EdDSAPrivateKey(new EdDSAPrivateKeySpec(spec, address.getPrivateKey().getEd25519Key()));
        EdDSAPublicKey pk = new EdDSAPublicKey(new EdDSAPublicKeySpec(address.getPublicKey().getEd25519Key(), spec));

        String test = "Here's a message";

        byte[] sig = sign(sk, test.getBytes());
        boolean verified = verify(test.getBytes(), sig, pk);

        Assert.assertTrue(verified);
    }

    private static byte[] sign(EdDSAPrivateKey sk, byte[] message) {
        try {
            byte[] sig;

            EdDSAEngine engine = new EdDSAEngine();
            engine.initSign(sk);
            sig = engine.signOneShot(message);

            return sig;
        } catch (SignatureException | InvalidKeyException e) {
            throw new CryptoException(e);
        }
    }

    private static boolean verify(byte[] message, byte[] signature, EdDSAPublicKey pubKey) {
        if (message != null && signature != null) {
            try {

                EdDSAEngine engine = new EdDSAEngine();
                engine.initVerify(pubKey);
                return engine.verifyOneShot(message, signature);
            } catch (Exception e) {
                System.err.println(e.getMessage());
            }
        }

        return false;
    }
}
