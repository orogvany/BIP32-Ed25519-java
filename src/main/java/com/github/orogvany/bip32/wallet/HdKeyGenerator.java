package com.github.orogvany.bip32.wallet;

import com.github.orogvany.bip32.Network;
import com.github.orogvany.bip32.crypto.HdUtil;
import com.github.orogvany.bip32.crypto.HmacSha512;
import com.github.orogvany.bip32.extern.Hex;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Arrays;

public class HdKeyGenerator {

    public HdAddress getAddressFromSeed(String seed, Network network) throws UnsupportedEncodingException {
        byte[] seedBytes = Hex.decode(seed);

        byte[] I = HmacSha512.hmac512(seedBytes, "Bitcoin seed".getBytes("UTF-8"));

        //split into left/right
        byte[] IL = Arrays.copyOfRange(I, 0, 32);
        byte[] IR = Arrays.copyOfRange(I, 32, 64);

        BigInteger masterSecretKey = HdUtil.parse256(IL);
        byte[] masterChainCode = IR;

        //todo - In case IL is 0 or ≥n, the master key is invalid.

        HdKey privateKey = new HdKey();
        //todo - set version/network properly
        privateKey.setVersion(Hex.decode0x("0x0488ADE4"));
        privateKey.setDepth(new byte[]{0});
        privateKey.setFingerprint(new byte[]{0, 0, 0, 0});
        privateKey.setChildNumber(new byte[]{0, 0, 0, 0});
        privateKey.setChainCode(masterChainCode);
        privateKey.setKeyData(HdUtil.append(new byte[]{0}, HdUtil.ser256(masterSecretKey)));

        HdAddress address = new HdAddress();
        address.setPrivateKey(privateKey);

        return address;
    }

    public HdAddress getAddress(HdAddress parent, int depth)
    {
        return null;
    }
}
