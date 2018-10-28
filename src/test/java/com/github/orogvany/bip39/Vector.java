package com.github.orogvany.bip39;

public class Vector {

    private byte[] entropy;
    private String mnemonic;
    private String seed;

    public Vector(byte[] entropy, String mnemonic, String seed) {
        this.entropy = entropy;
        this.mnemonic = mnemonic;
        this.seed = seed;
    }

    public byte[] getEntropy() {
        return entropy;
    }

    public String getMnemonic() {
        return mnemonic;
    }

    public String getSeed() {
        return seed;
    }
}
