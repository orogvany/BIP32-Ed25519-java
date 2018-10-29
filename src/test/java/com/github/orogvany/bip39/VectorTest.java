package com.github.orogvany.bip39;

import com.github.orogvany.bip32.Base58;
import com.github.orogvany.bip32.Network;
import com.github.orogvany.bip32.extern.Hex;
import com.github.orogvany.bip32.wallet.CoinType;
import com.github.orogvany.bip32.wallet.HdAddress;
import com.github.orogvany.bip32.wallet.HdKeyGenerator;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.util.List;

public class VectorTest {

    @Test
    public void testVectors() throws IOException {
        MnemonicGenerator generator = new MnemonicGenerator();

        VectorReader reader = new VectorReader();
        List<Vector> vectors = reader.getVectors();
        HdKeyGenerator keyGenerator = new HdKeyGenerator();

        String password = "TREZOR";
        for (Vector vector : vectors) {
            String words = generator.getWordlist(vector.getEntropy(), Language.english);
            Assert.assertEquals(vector.getMnemonic(), words);
            byte[] seed = generator.getSeedFromWordlist(words, password);
            Assert.assertEquals(vector.getSeed(), Hex.encode(seed));
            HdAddress address = keyGenerator.getAddressFromSeed(seed, Network.mainnet, CoinType.bitcoin);
            Assert.assertEquals(vector.getHdKey(), Base58.encode(address.getPrivateKey().getKey()));
        }
    }
}
