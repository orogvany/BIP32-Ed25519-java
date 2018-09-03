/**
 * Copyright (c) 2018 orogvany
 *
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package com.github.orogvany.bip32.wallet;

import com.github.orogvany.bip32.Network;

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
    public HdAddress getRootAddressFromSeed(byte[] seed, Network network, CoinType coinType) throws UnsupportedEncodingException {
        HdAddress masterAddress = hdKeyGenerator.getAddressFromSeed(seed, network, coinType);
        HdAddress purposeAddress = hdKeyGenerator.getAddress(masterAddress, PURPOSE, true);
        HdAddress coinTypeAddress = hdKeyGenerator.getAddress(purposeAddress, coinType.getCoinType(), true);
        HdAddress accountAddress = hdKeyGenerator.getAddress(coinTypeAddress, ACCOUNT, true);
        HdAddress changeAddress = hdKeyGenerator.getAddress(accountAddress, CHANGE, coinType.getAlwaysHardened());

        return changeAddress;
    }

    public HdAddress getAddress(HdAddress address, int index) {
        return hdKeyGenerator.getAddress(address, index, address.getCoinType().getAlwaysHardened());
    }
}
