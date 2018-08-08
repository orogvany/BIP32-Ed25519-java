package com.github.orogvany.bip32.crypto;

import com.github.orogvany.bip32.exception.CryptoException;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;

import java.security.MessageDigest;

/**
 * Basic hash functions
 */
public class Hash {

    /**
     * SHA-256
     * @param input
     * @return
     */
    public static byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    /**
     * H160
     * @param input
     * @return
     */
    public static byte[] h160(byte[] input) {
        try {
            byte[] sha256 = sha256(input);

            RIPEMD160Digest digest = new RIPEMD160Digest();
            digest.update(sha256, 0, sha256.length);
            byte[] out = new byte[20];
            digest.doFinal(out, 0);
            return out;
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }
}
