/**
 * Copyright (c) 2018 orogvany
 *
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package com.github.orogvany.bip32.crypto;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class Secp256k1 {
    static final X9ECParameters SECP = CustomNamedCurves.getByName("secp256k1");

    /**
     * serP(P): serializes the coordinate pair P = (x,y) as a byte sequence using SEC1's compressed form: (0x02 or 0x03) || ser256(x), where the header byte depends on the parity of the omitted y coordinate.
     *
     * @param p
     * @return
     */
    public static byte[] serP(ECPoint p) {
        return p.getEncoded(true);
    }

    /**
     * point(p): returns the coordinate pair resulting from EC point multiplication (repeated application of the EC group operation) of the secp256k1 base point with the integer p.
     *
     * @param p
     */
    public static ECPoint point(BigInteger p) {
        return SECP.getG().multiply(p);
    }

    public static BigInteger getN() {
        return SECP.getN();
    }
}
