package com.github.orogvany.bip32.wallet;

import com.github.orogvany.bip32.Network;
import com.github.orogvany.bip32.wallet.key.HdPrivateKey;
import com.github.orogvany.bip32.wallet.key.HdPublicKey;

import java.io.UnsupportedEncodingException;

/**
 * Utility class for BIP-44 paths
 */
public class Bip44 {
    private HdKeyGenerator hdKeyGenerator = new HdKeyGenerator();
    // purpose is hardcoded to 44'
    public static final int PURPOSE = 44;
    // we support just one user account
    private static final long ACCOUNT = 0;
    // we support just external addresses, 0 is 'external'
    public static final int CHANGE = 0;


    /**
     * Get a root account address for a given seed
     *
     * @param seed     seed
     * @param network  network
     * @param coinType coinType
     * @return
     * @throws UnsupportedEncodingException
     */
    public HdAddress<HdPrivateKey, HdPublicKey> getRootAddressFromSeed(String seed, Network network, CoinType coinType) throws UnsupportedEncodingException {
        HdAddress<HdPrivateKey, HdPublicKey> masterAddress = hdKeyGenerator.getAddressFromSeed(seed, network, coinType);
        HdAddress<HdPrivateKey, HdPublicKey> purposeAddress = hdKeyGenerator.getAddress(masterAddress, PURPOSE, true);
        HdAddress<HdPrivateKey, HdPublicKey> coinTypeAddress = hdKeyGenerator.getAddress(purposeAddress, coinType.getCoinType(), true);
        HdAddress<HdPrivateKey, HdPublicKey> accountAddress = hdKeyGenerator.getAddress(coinTypeAddress, ACCOUNT, true);
        HdAddress<HdPrivateKey, HdPublicKey> changeAddress = hdKeyGenerator.getAddress(accountAddress, CHANGE, coinType.getAlwaysHardened());

        return changeAddress;
    }

    public HdAddress<HdPrivateKey, HdPublicKey> getAddress(HdAddress address, int index) {
        return hdKeyGenerator.getAddress(address, index, address.getCoinType().getAlwaysHardened());
    }
}
