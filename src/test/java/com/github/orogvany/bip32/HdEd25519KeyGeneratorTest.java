package com.github.orogvany.bip32;

import com.github.orogvany.bip32.wallet.HdAddress;
import com.github.orogvany.bip32.wallet.HdEd25519Key;
import com.github.orogvany.bip32.wallet.HdEd25519KeyGenerator;
import com.goterl.lazycode.lazysodium.LazySodium;
import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.utils.Key;
import com.goterl.lazycode.lazysodium.utils.KeyPair;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import org.junit.Assert;
import org.junit.Test;

import java.io.UnsupportedEncodingException;

public class HdEd25519KeyGeneratorTest {

    public HdEd25519KeyGenerator hdKeyGenerator = new HdEd25519KeyGenerator();

    @Test
    public void testKeyGeneration() throws UnsupportedEncodingException, SodiumException {
        HdAddress<HdEd25519Key> address = hdKeyGenerator.getAddressFromSeed("abedd123", null);

        EdDSANamedCurveSpec params = EdDSANamedCurveTable.getByName("Ed25519");

        LazySodium lazySodium = new LazySodiumJava(new SodiumJava());

        //make sure test case works
        KeyPair key = lazySodium.cryptoSignKeypair();


        //we have 64 byte extended key and 32 byte pub key, so use live data
        key = new KeyPair(Key.fromBytes(address.getPublicKey().getEd25519Key()), Key.fromBytes(address.getPrivateKey().getEd25519Key()));
        String test = "Here's a message";
        String signed = lazySodium.cryptoSignDetached(test, key.getSecretKey());
        boolean verified = lazySodium.cryptoSignVerifyDetached(signed, test, key.getPublicKey());
        Assert.assertTrue(verified);


    }


}
