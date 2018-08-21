package com.github.orogvany.bip32.wallet.key.ed25519;

import com.github.orogvany.bip32.wallet.key.HdPublicKey;

public class HdEd25519PublicKey extends HdPublicKey {
    private byte[] ed25519Key;

    public byte[] getEd25519Key() {
        return ed25519Key;
    }

    public void setEd25519Key(byte[] ed25519Key) {
        this.ed25519Key = ed25519Key;
    }
}
