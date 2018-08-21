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
import com.github.orogvany.bip32.wallet.key.ed25519.HdEd25519PrivateKey;
import com.github.orogvany.bip32.wallet.key.ed25519.HdEd25519PublicKey;
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

    private static final EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName("Ed25519");


    public HdAddress<HdEd25519PrivateKey, HdEd25519PublicKey> getAddressFromSeed(String seed, Network network) throws UnsupportedEncodingException {
        byte[] seedBytes = Hex.decode(seed);

        //supposed to use sha512 instead of hmac for whatever reason.
        //if supposed to be used after master secret, will need to rename method/refactor
        byte[] K = Hash.sha512(seedBytes);

        //split into left/right
        byte[] KL = Arrays.copyOfRange(K, 0, 32);
        byte[] KR = Arrays.copyOfRange(K, 32, 64);
        HdEd25519PrivateKey privateKey = new HdEd25519PrivateKey();
        HdEd25519PublicKey publicKey = new HdEd25519PublicKey();

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

        privateKey.setVersion(network.getPrivateKeyVersion());
        privateKey.setDepth(0);
        privateKey.setFingerprint(new byte[]{0, 0, 0, 0});
        privateKey.setChildNumber(new byte[]{0, 0, 0, 0});
        privateKey.setChainCode(masterChainCode);
        privateKey.setKeyData(HdUtil.append(new byte[]{0}, HdUtil.ser256(masterSecretKey)));

        HdAddress<HdEd25519PrivateKey, HdEd25519PublicKey> address = new HdAddress<>();
        address.setPrivateKey(privateKey);
        ECPoint point = Secp256k1.point(masterSecretKey);

        publicKey.setVersion(network.getPublicKeyVersion());
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
        //todo - implement chaining

        HdAddress<HdEd25519PrivateKey, HdEd25519PublicKey> address = new HdAddress<>();

        HdEd25519PrivateKey privateKey = new HdEd25519PrivateKey();
        privateKey.setVersion(parent.getPrivateKey().getVersion());
        privateKey.setDepth(0);
        privateKey.setFingerprint(new byte[]{0, 0, 0, 0});
        privateKey.setChildNumber(new byte[]{0, 0, 0, 0});

        HdEd25519PublicKey publicKey = new HdEd25519PublicKey();
        publicKey.setVersion(parent.getPublicKey().getVersion());
        publicKey.setDepth(0);
        publicKey.setFingerprint(new byte[]{0, 0, 0, 0});
        publicKey.setChildNumber(new byte[]{0, 0, 0, 0});

        address.setPublicKey(publicKey);
        address.setPrivateKey(privateKey);
        return address;
    }
}
