/**
 * Copyright (c) 2018 orogvany
 * <p>
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package com.github.orogvany.bip32.wallet;

/**
 * An HD pub/private key
 */
public class HdAddress<T extends HdKey> {

    private T privateKey;
    private T publicKey;

    public T getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(T privateKey) {
        this.privateKey = privateKey;
    }

    public T getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(T publicKey) {
        this.publicKey = publicKey;
    }
}
