/**
 * Copyright (c) 2018 orogvany
 * <p>
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package com.github.orogvany.bip32.wallet;

import com.github.orogvany.bip32.wallet.key.HdPrivateKey;
import com.github.orogvany.bip32.wallet.key.HdPublicKey;

/**
 * An HD pub/private key
 */
public class HdAddress {

    private final HdPrivateKey privateKey;
    private final HdPublicKey publicKey;
    private final CoinType coinType;
    private final String path;

    public HdAddress(HdPrivateKey privateKey, HdPublicKey publicKey, CoinType coinType, String path) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.coinType = coinType;
        this.path = path;
    }

    public HdPrivateKey getPrivateKey() {
        return privateKey;
    }

    public HdPublicKey getPublicKey() {
        return publicKey;
    }

    public CoinType getCoinType() {
        return coinType;
    }

    public String getPath() {
        return path;
    }
}
