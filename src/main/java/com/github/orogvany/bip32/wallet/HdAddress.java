/**
 * Copyright (c) 2018 orogvany
 *
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package com.github.orogvany.bip32.wallet;

import com.github.orogvany.bip32.wallet.key.HdPrivateKey;
import com.github.orogvany.bip32.wallet.key.HdPublicKey;

/**
 * An HD pub/private key
 */
public class HdAddress<S extends HdPrivateKey, P extends HdPublicKey> {

    private S privateKey;
    private P publicKey;
    private CoinType coinType;

    public S getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(S privateKey) {
        this.privateKey = privateKey;
    }

    public P getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(P publicKey) {
        this.publicKey = publicKey;
    }

    public CoinType getCoinType() {
        return coinType;
    }

    public void setCoinType(CoinType coinType) {
        this.coinType = coinType;
    }
}
