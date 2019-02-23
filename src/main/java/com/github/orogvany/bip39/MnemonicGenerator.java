package com.github.orogvany.bip39;

import com.github.orogvany.bip32.crypto.Hash;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.BitSet;

import static com.github.orogvany.bip32.crypto.BitSetUtil.*;
import static com.github.orogvany.bip32.crypto.HmacSha512.pbkdf2HmacSha512;

/**
 * Generate and Process Mnemonic codes
 * <p>
 * TODO - using bitset is probably more pain than it's worth.
 */
public class MnemonicGenerator {

    public static final String SPACE_JP = "\u3000";

    private SecureRandom secureRandom = new SecureRandom();

    public byte[] getSeedFromWordlist(String words, String password, Language language) {
        if (password == null) {
            password = "";
        }

        //check the words are valid (will throw exception if invalid)
        getEntropy(words, language);

        String salt = "mnemonic" + password;
        return pbkdf2HmacSha512(words.trim().toCharArray(), salt.getBytes(Charset.forName("UTF-8")), 2048, 512);
    }

    protected byte[] getEntropy(String words, Language language) {
        Dictionary dictionary;
        try {
            dictionary = new Dictionary(language);
        } catch (IOException e) {
            throw new IllegalArgumentException("Unknown dictionary");
        }

        //validate that things look alright
        String[] wordsList = words.split(" ");
        if (wordsList.length < 12) {
            throw new IllegalArgumentException("Must be at least 12 words");
        }
        if (wordsList.length > 24) {
            throw new IllegalArgumentException("Must be less than 24 words");
        }

        //check all the words are found and build entropy + checksum
        BitSet bitSet = new BitSet();
        for (int i = 0; i < wordsList.length; i++) {
            String word = wordsList[i];
            int code = dictionary.indexOf(word.trim());
            bitSet = addCode(bitSet, code);
            if (code < 0) {
                throw new IllegalArgumentException("Unknown word: " + word);

            }
        }
        int csBits = (wordsList.length * 11) % 8;
        //handle 8 bit cs, which is max
        if (csBits == 0) {
            csBits = 8;
        }
        int entBytes = (wordsList.length * 11 - csBits) / 8;

        byte[] bitSetBytes = createBytes(bitSet, wordsList.length * 11 / 8);
        byte[] entropy = Arrays.copyOfRange(bitSetBytes, 0, entBytes);
        return entropy;
    }

    public String getWordlist(int entropyLength, Language language) {
        byte[] entropy = secureRandom.generateSeed(entropyLength / 8);
        return getWordlist(entropy, language);
    }

    public String getWordlist(byte[] entropy, Language language) {

        int entropyLength = entropy.length * 8;
        Dictionary dictionary;
        try {
            dictionary = new Dictionary(language);
        } catch (IOException e) {
            throw new IllegalArgumentException("Unknown dictionary");
        }
        if (entropyLength < 128) {
            throw new IllegalArgumentException("Entropy must be over 128");
        }
        if (entropyLength > 256) {
            throw new IllegalArgumentException("Entropy must be less than 256");
        }
        if (entropyLength % 32 != 0) {
            throw new IllegalArgumentException("Entropy must be a multiple of 32");
        }
        int checksumLength = entropyLength / 32;
        byte[] hash = Hash.sha256(entropy);

        BitSet hashBitset = createBitset(hash);
        BitSet bitSet = createBitset(entropy);

        BitSet checksum = hashBitset.get(0, checksumLength);
        bitSet = append(checksum, bitSet, entropyLength);

        StringBuilder ret = new StringBuilder();

        int numWords = (entropyLength + checksumLength) / 11;
        for (int i = 0; i < numWords; i++) {
            BitSet range = bitSet.get(i * 11, (i + 1) * 11);
            int wordIdx = 0;
            if (!range.isEmpty()) {
                wordIdx = getInt(range);
            }
            String word = dictionary.getWord(wordIdx);
            if (i > 0) {
                ret.append(" ");
            }
            ret.append(word);

        }

        return ret.toString();
    }
}
