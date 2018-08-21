/**
 * Copyright (c) 2018 orogvany
 *
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package com.github.orogvany.bip32;

import com.github.orogvany.bip32.wallet.HdAddress;
import com.github.orogvany.bip32.wallet.HdKeyGenerator;

import java.io.UnsupportedEncodingException;

public abstract class BaseVectorTest {

    public HdAddress masterNode;
    public HdKeyGenerator hdKeyGenerator = new HdKeyGenerator();

    public BaseVectorTest() throws UnsupportedEncodingException {
        masterNode = hdKeyGenerator.getAddressFromSeed(getSeed(), Network.mainnet);
    }

    protected abstract String getSeed();
}
