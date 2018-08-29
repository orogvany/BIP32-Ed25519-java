package com.github.orogvany.bip32.wallet.key;

public enum Curve {
    bitcoin("Bitcoin seed"),
    ed25519("ed25519 seed");

    private String seed;

    Curve(String seed) {
        this.seed = seed;
    }

    public String getSeed() {
        return seed;
    }
}
