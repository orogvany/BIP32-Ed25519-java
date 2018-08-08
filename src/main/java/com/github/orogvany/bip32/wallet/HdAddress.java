package com.github.orogvany.bip32.wallet;

/**
 * An HD pub/private key
 */
public class HdAddress {

    private HdKey privateKey;
    private HdKey publicKey;

    public HdKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(HdKey privateKey) {
        this.privateKey = privateKey;
    }

    public HdKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(HdKey publicKey) {
        this.publicKey = publicKey;
    }
}
