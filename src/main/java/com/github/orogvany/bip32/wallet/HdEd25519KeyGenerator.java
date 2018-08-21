/**
 * Copyright (c) 2018 orogvany
 * <p>
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package com.github.orogvany.bip32.wallet;

import com.github.orogvany.bip32.Network;
import com.github.orogvany.bip32.crypto.BitUtil;
import com.github.orogvany.bip32.crypto.Hash;
import com.github.orogvany.bip32.crypto.HdUtil;
import com.github.orogvany.bip32.crypto.HmacSha512;
import com.github.orogvany.bip32.crypto.Secp256k1;
import com.github.orogvany.bip32.exception.CryptoException;
import com.github.orogvany.bip32.extern.Hex;
import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * We'll get this working a separate implementation, then extract a base class.
 */
public class HdEd25519KeyGenerator {

    private static EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName("Ed25519");

    public HdAddress<HdEd25519Key> getAddressFromSeed(String seed, Network network) throws UnsupportedEncodingException {
        byte[] seedBytes = Hex.decode(seed);

        byte[] K = HmacSha512.hmac512(seedBytes, "Bitcoin seed".getBytes("UTF-8"));
        //supposed to use sha512 instead of hmac for whatever reason.
        //if supposed to be used after master secret, will need to rename method/refactor
        K = Hash.sha512(seedBytes);

        //split into left/right
        byte[] KL = Arrays.copyOfRange(K, 0, 32);
        byte[] KR = Arrays.copyOfRange(K, 32, 64);
        HdEd25519Key privateKey = new HdEd25519Key();
        HdEd25519Key publicKey = new HdEd25519Key();

        //
        // Ed25519 specific
        // if the third highest bit of the last byte of IL is not zero, discard
        boolean klCheck = BitUtil.checkBit(KL[KL.length - 1], 3);
        if (klCheck) {
            throw new CryptoException("This seed cannot be used");
        }

        byte firstByte = KL[0];
        //the lowest 3 bits of the first byte of IL is cleared
        firstByte = BitUtil.unsetBit(firstByte, 8);
        firstByte = BitUtil.unsetBit(firstByte, 7);
        firstByte = BitUtil.unsetBit(firstByte, 6);
        KL[0] = firstByte;

        byte lastByte = KL[KL.length - 1];
        // the highest bit of the last byte is cleared
        lastByte = BitUtil.unsetBit(lastByte, 1);
        // the second highest bit of the last byte is set
        lastByte = BitUtil.setBit(lastByte, 2);
        KL[KL.length - 1] = lastByte;


        //A <- [KL]B is the root public key after encoding
        // Interpret KL as little-endian int and perform a fixed-base scalar multiplication
        BigInteger ILBigInt = HdUtil.parse256LE(KL);
        byte[] ilEncoded = ILBigInt.toByteArray();
        ArrayUtils.reverse(ilEncoded);

        KL = ilEncoded;
        GroupElement rootPublicKey = spec.getB().scalarMultiply(KL);


        //TODO - this is noise, but concentrating on ed25519 pub/priv key
        BigInteger masterSecretKey = HdUtil.parse256(KL);
        //c <- H256(0x01 || K) is the root chain code
        byte[] masterChainCode = Hash.sha256(HdUtil.append(new byte[]{0x01}, K));

        //IL,IR is the extended root private key.
        privateKey.setEd25519Key(HdUtil.append(KL, KR));
        publicKey.setEd25519Key(rootPublicKey.toByteArray());

        //
        // end Ed25519 specific

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

        //todo - implement
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
