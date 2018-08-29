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
* BIP32 implemented, Ed25519 works for master key
* Not using https://cardanolaunch.com/assets/Ed25519_BIP.pdf, decided on using SLIP-0010 due to ease of implementation and test vectors supplied.
* BIP-44 utility methods exist

TODO:
* BIP39 - Support for mnemonic codes (should be libs out there already)
* A much needed code refactor/cleanup

## Compiling
```
mvn clean install
```

For maven use you can use jitpack

```
<dependency>
    <groupId>com.github.orogvany</groupId>
    <artifactId>BIP32-Ed25519-java</artifactId>
    <version>{latest checkin hash}</version>
</dependency>
```

Jitpack repo

```
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```
