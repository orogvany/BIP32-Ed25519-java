package com.github.orogvany.bip32.crypto;

import com.github.orogvany.bip32.exception.CryptoException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha256Hash {

    public static byte[] hashTwice(byte[] bytes) {
        return hashTwice(bytes, 0, bytes.length);
    }

    public static byte[] hashTwice(final byte[] bytes, final int offset, final int length) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(bytes, offset, length);
            digest.update(digest.digest());
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Unable to find SHA-256", e);
        }
    }
}
