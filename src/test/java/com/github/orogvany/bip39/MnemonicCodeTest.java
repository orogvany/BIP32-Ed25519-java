package com.github.orogvany.bip39;

import org.junit.Assert;
import org.junit.Test;

import java.security.SecureRandom;

public class MnemonicCodeTest {

    private SecureRandom secureRandom = new SecureRandom();

    @Test
    public void testMnemonicCode() {
        MnemonicCode generator = new MnemonicCode();

        byte[] originalSeed = secureRandom.generateSeed(128 / 8);
        String code = generator.getWordlist(originalSeed, Language.english);
        Assert.assertEquals(12, code.split(" ").length);
        System.out.println(code);
        byte[] seed = generator.getSeedFromWordlist(code, Language.english);
        Assert.assertArrayEquals(originalSeed, seed);
    }
}
