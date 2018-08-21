package com.github.orogvany.bip32.wallet;

/**
 * An HD key for Ed25519
 */
public class HdEd25519Key extends HdKey {
    private byte[] ed25519Key;

    public byte[] getEd25519Key() {
        return ed25519Key;
    }

    public void setEd25519Key(byte[] ed25519Key) {
        this.ed25519Key = ed25519Key;
    }
}
