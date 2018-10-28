package com.github.orogvany.bip39;

import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.util.List;

public class VectorTest {

    @Test
    public void testVectors() throws IOException {
        MnemonicCode generator = new MnemonicCode();

        VectorReader reader = new VectorReader();
        List<Vector> vectors = reader.getVectors();

        for (Vector vector : vectors) {
            String words = generator.getWordlist(vector.getEntropy(), Language.english);
            Assert.assertEquals(vector.getMnemonic(), words);
        }
    }
}
