package com.github.orogvany.bip39;

import com.github.orogvany.bip32.crypto.Hash;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.BitSet;

/**
 * Generate and Process Mnemonic codes
 */
public class MnemonicCode {

    private SecureRandom secureRandom = new SecureRandom();

    public byte[] getSeedFromWordlist(String words, Language language) {
        Dictionary dictionary;
        try {
            dictionary = new Dictionary(language);
        } catch (IOException e) {
            throw new IllegalArgumentException("Unknown dictionary");
        }

        return null;
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
        BitSet hashBitset = BitSet.valueOf(hash);

        BitSet bitSet = BitSet.valueOf(entropy);
        BitSet checksum = hashBitset.get(256 - checksumLength, 256);

        bitSet = append(checksum, bitSet, entropyLength);
        StringBuilder ret = new StringBuilder();

        int numWords = (entropyLength + checksumLength) / 11;
        for (int i = 0; i < numWords; i++) {
            BitSet range = bitSet.get(i * 11, (i + 1) * 11);
            int wordIdx = 0;
            if (!range.isEmpty()) {
                wordIdx = (int) range.toLongArray()[0];
            }
            String word = dictionary.getWord(wordIdx);

            if (i > 0) {
                ret.append(" ");
            }
            ret.append(word);

        }

        return ret.toString();
    }

    private BitSet append(BitSet a, BitSet b, int bLength) {

        //shift A << bLenght
        BitSet ret = shift(a, bLength);
        ret.or(b);
        return ret;
    }

    private BitSet shift(BitSet bitSet, int length) {
        BitSet ret = new BitSet(bitSet.length() + length);
        for (int i = 0; i < bitSet.length(); i++) {
            if (bitSet.get(i)) {
                ret.set(i + length);
            }
        }
        return ret;
    }


}
