package com.github.orogvany.bip39;

import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.security.SecureRandom;

public class MnemonicGeneratorTest {

    private static SecureRandom secureRandom = new SecureRandom();

    @Test
    public void testHappyPath() {

        Dictionary dictionary;
        try {
            dictionary = new Dictionary(Language.english);
        } catch (IOException e) {
            throw new IllegalArgumentException("Unknown dictionary");
        }

        MnemonicGenerator generator = new MnemonicGenerator();

        String phrase = generator.getWordlist(128, Language.english);

        byte[] seed = generator.getSeedFromWordlist(phrase, "", Language.english);
        byte[] seedAgain = generator.getSeedFromWordlist(phrase, "", Language.english);
        Assert.assertArrayEquals(seed, seedAgain);

        //make sure we can recover the entropy
        byte[] entropy = secureRandom.generateSeed(128 / 8);
        String checkPhrase = generator.getWordlist(entropy, Language.english);
        byte[] calcEntropy = generator.getEntropy(checkPhrase, Language.english);
        Assert.assertArrayEquals(entropy, calcEntropy);


        String[] words = phrase.split(" ");

        int index = dictionary.indexOf(words[0]);


        try {
            words[0] = "asdf";
            generator.getSeedFromWordlist(String.join(" ", words), "", Language.english);
            Assert.fail("Should not allow unknown word");
        } catch (IllegalArgumentException e) {
        }

        try {
            words[0] = dictionary.getWord((index + 1) % 2048);
            generator.getSeedFromWordlist(String.join(" ", words), "", Language.english);
            Assert.fail("Should not allow non-checksum'd words");
        } catch (IllegalArgumentException e) {

        }
    }
}
