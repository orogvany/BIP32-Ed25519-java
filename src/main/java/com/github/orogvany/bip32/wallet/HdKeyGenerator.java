package com.github.orogvany.bip32.wallet;

import com.github.orogvany.bip32.Network;
import com.github.orogvany.bip32.crypto.Hash;
import com.github.orogvany.bip32.crypto.HdUtil;
import com.github.orogvany.bip32.crypto.HmacSha512;
import com.github.orogvany.bip32.crypto.Secp256k1;
import com.github.orogvany.bip32.extern.Hex;
import org.bouncycastle.math.ec.ECPoint;

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
        privateKey.setDepth(0);
        privateKey.setFingerprint(new byte[]{0, 0, 0, 0});
        privateKey.setChildNumber(new byte[]{0, 0, 0, 0});
        privateKey.setChainCode(masterChainCode);
        privateKey.setKeyData(HdUtil.append(new byte[]{0}, HdUtil.ser256(masterSecretKey)));

        HdAddress address = new HdAddress();
        address.setPrivateKey(privateKey);
        ECPoint point = Secp256k1.point(masterSecretKey);

        HdKey publicKey = new HdKey();
        publicKey.setVersion(Hex.decode0x("0x0488B21E"));
        publicKey.setDepth(0);
        publicKey.setFingerprint(new byte[]{0, 0, 0, 0});
        publicKey.setChildNumber(new byte[]{0, 0, 0, 0});
        publicKey.setChainCode(masterChainCode);
        publicKey.setKeyData(Secp256k1.serP(point));
        address.setPublicKey(publicKey);

        return address;
    }

    public HdAddress getAddress(HdAddress parent, long child, boolean isHardened) {
        if (isHardened) {
            child += 0x80000000;
        }

        byte[] xChain = parent.getPrivateKey().getChainCode();
        ///backwards hmac order in method?
        byte[] I;
        if (isHardened) {
            //If so (hardened child): let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i)). (Note: The 0x00 pads the private key to make it 33 bytes long.)
            BigInteger kpar = HdUtil.parse256(parent.getPrivateKey().getKeyData());
            byte[] data = HdUtil.append(new byte[]{0}, HdUtil.ser256(kpar));
            data = HdUtil.append(data, HdUtil.ser32(child));
            I = HmacSha512.hmac512(data, xChain);
        } else {
            //I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i))
            //just use public key
            byte[] key = parent.getPublicKey().getData();
            byte[] xPubKey = HdUtil.append(key, HdUtil.ser32(child));
            I = HmacSha512.hmac512(xPubKey, xChain);
        }

        //split into left/right
        byte[] IL = Arrays.copyOfRange(I, 0, 32);
        byte[] IR = Arrays.copyOfRange(I, 32, 64);
        //The returned child key ki is parse256(IL) + kpar (mod n).
        BigInteger parse256 = HdUtil.parse256(IL);
        BigInteger kpar = HdUtil.parse256(parent.getPrivateKey().getData());
        BigInteger childSecretKey = HdUtil.parse256(IL).add(kpar).mod(Secp256k1.getN());
        byte[] masterChainCode = IR;

        byte[] childNumber = HdUtil.ser32(child);
        byte[] fingerprint = HdUtil.getFingerprint(parent.getPrivateKey().getKeyData());

        HdKey privateKey = new HdKey();
        //todo - set version/network properly
        privateKey.setVersion(Hex.decode0x("0x0488ADE4"));
        privateKey.setDepth(parent.getPrivateKey().getDepth() + 1);
        privateKey.setFingerprint(fingerprint);
        privateKey.setChildNumber(childNumber);
        privateKey.setChainCode(masterChainCode);
        privateKey.setKeyData(HdUtil.append(new byte[]{0}, HdUtil.ser256(childSecretKey)));

        HdAddress address = new HdAddress();
        address.setPrivateKey(privateKey);
        ECPoint point = Secp256k1.point(childSecretKey);

        HdKey publicKey = new HdKey();
        publicKey.setVersion(Hex.decode0x("0x0488B21E"));
        publicKey.setDepth(parent.getPublicKey().getDepth() + 1);

        // can just use fingerprint, but let's use data from parent public key
        byte[] pKd = parent.getPublicKey().getKeyData();
        byte[] h160 = Hash.h160(pKd);
        byte[] childFingerprint = new byte[]{h160[0], h160[1], h160[2], h160[3]};
        //todo - we should be able to derive the child public key just from data
        // in the key.  some more work to do here, then extract methods

        publicKey.setFingerprint(childFingerprint);
        publicKey.setChildNumber(childNumber);
        publicKey.setChainCode(masterChainCode);
        publicKey.setKeyData(Secp256k1.serP(point));
        address.setPublicKey(publicKey);

        return address;
    }
}
