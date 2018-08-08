package com.github.orogvany.bip32.wallet;

import com.github.orogvany.bip32.crypto.HdUtil;
import com.github.orogvany.bip32.crypto.Sha256Hash;
import com.github.orogvany.bip32.extern.Base58;

import java.util.Arrays;

/**
 * Marshalling code for HDKeys to base58 representations.
 * <p>
 * Will probably be migrated to builder pattern.
 */
public class HdKey {
    private byte[] version;
    private byte[] depth;
    private byte[] fingerprint;
    private byte[] childNumber;
    private byte[] chainCode;
    private byte[] keyData;

    public HdKey(byte[] version, byte[] depth, byte[] fingerprint, byte[] childNumber, byte[] chainCode, byte[] keyData) {
        this.version = version;
        this.depth = depth;
        this.fingerprint = fingerprint;
        this.childNumber = childNumber;
        this.chainCode = chainCode;
        this.keyData = keyData;
    }

    public HdKey() {
    }

    public void setVersion(byte[] version) {
        this.version = version;
    }

    public void setDepth(byte[] depth) {
        this.depth = depth;
    }

    public void setFingerprint(byte[] fingerprint) {
        this.fingerprint = fingerprint;
    }

    public void setChildNumber(byte[] childNumber) {
        this.childNumber = childNumber;
    }

    public void setChainCode(byte[] chainCode) {
        this.chainCode = chainCode;
    }

    public void setKeyData(byte[] keyData) {
        this.keyData = keyData;
    }

    public byte[] getFingerprintBytes() {
        //todo
//        return Hash.h160()
        return null;
    }

    public String getKey() {
        //todo - use builder/buffer
        byte[] key = HdUtil.append(version, depth);
        key = HdUtil.append(key, fingerprint);
        key = HdUtil.append(key, childNumber);
        key = HdUtil.append(key, chainCode);
        key = HdUtil.append(key, keyData);
        byte[] checksum = Sha256Hash.hashTwice(key);
        key = HdUtil.append(key, Arrays.copyOfRange(checksum, 0, 4));
        return Base58.encode(key);
    }
}
