package com.github.orogvany.bip32;

import com.github.orogvany.bip32.crypto.BitUtil;
import com.github.orogvany.bip32.wallet.HdAddress;
import com.github.orogvany.bip32.wallet.HdEd25519KeyGenerator;
import com.github.orogvany.bip32.wallet.HdKeyGenerator;
import org.junit.Assert;
import org.junit.Test;

import java.io.UnsupportedEncodingException;

public class HdEd25519KeyGeneratorTest {

    public HdEd25519KeyGenerator hdKeyGenerator = new HdEd25519KeyGenerator();

    @Test
    public void testKeyGeneration() throws UnsupportedEncodingException {
        HdAddress address = hdKeyGenerator.getAddressFromSeed("abedd123", null);
    }


}
