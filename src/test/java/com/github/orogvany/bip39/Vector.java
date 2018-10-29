package com.github.orogvany.bip39;

public class Vector {

    private byte[] entropy;
    private String mnemonic;
    private String seed;
    private String hdKey;

    public Vector(byte[] entropy, String mnemonic, String seed, String hdKey) {
        this.entropy = entropy;
        this.mnemonic = mnemonic;
        this.seed = seed;
        this.hdKey = hdKey;
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

    public String getHdKey() {
        return hdKey;
    }
}
