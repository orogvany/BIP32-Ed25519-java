# BIP32-Ed25519-java
BIP32-Ed25519 HD wallets for java

Work in progress currently.

Hierarchical Deterministic wallets are a boon to bitcoin, as it solves a problem of backups and allows for much needed functionality.
However, it is fairly specific to secp256k1.  

This project aims to first implement the BIP32 with secp256k1, then extend it with compatibility for Ed25519

Please note that code in com.github.orogvany.bip32.extern are temporary constructs, and are licensed under their respective
licenses (apache/MIT)

They are designed to be replaced with open source libs as time permits.

Current state:
BIP32 implemented, still need to extend to ED25519.
Going to use
https://cardanolaunch.com/assets/Ed25519_BIP.pdf
rather than chain.com proposal due to noted incompatibilities and side chain attack.

TODO:
* BIP44 - abstraction for multiple coins heirarchy
* BIP39 - Support for mnemonic codes (should be libs out there already)
* ED25519 implementation