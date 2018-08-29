/**
 * Copyright (c) 2018 orogvany
 * <p>
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package com.github.orogvany.bip32.wallet.key;

import com.github.orogvany.bip32.crypto.Hash;
import com.github.orogvany.bip32.crypto.HdUtil;
import com.github.orogvany.bip32.extern.Base58;

import java.util.Arrays;

/**
 * Marshalling code for HDKeys to base58 representations.
 * <p>
 * Will probably be migrated to builder pattern.
 */
public class HdKey {
    private byte[] version;
    private int depth;
    private byte[] fingerprint;
    private byte[] childNumber;
    private byte[] chainCode;
    private byte[] keyData;

    public HdKey(byte[] version, int depth, byte[] fingerprint, byte[] childNumber, byte[] chainCode, byte[] keyData) {
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

    public void setDepth(int depth) {
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

    public byte[] getChainCode() {
        return chainCode;
    }

    public String getKey() {
        //todo - use builder/buffer
        byte[] key = HdUtil.append(version, new byte[]{(byte) depth});
        key = HdUtil.append(key, fingerprint);
        key = HdUtil.append(key, childNumber);
        key = HdUtil.append(key, chainCode);
        key = HdUtil.append(key, keyData);
        byte[] checksum = Hash.sha256Twice(key);
        key = HdUtil.append(key, Arrays.copyOfRange(checksum, 0, 4));
        return Base58.encode(key);
    }

    public int getDepth() {
        return depth;
    }

    public byte[] getKeyData() {
        return keyData;
    }

    public byte[] getVersion() {
        return version;
    }

    public byte[] getFingerprint() {
        return fingerprint;
    }
}
