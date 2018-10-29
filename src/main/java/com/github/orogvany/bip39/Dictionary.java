package com.github.orogvany.bip39;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class Dictionary {

    private List<String> words = new ArrayList<>();

    public Dictionary(Language language) throws IOException {

        InputStream wordStream = this.getClass().getClassLoader().getResourceAsStream("wordlists/" + language.name() + ".txt");

        BufferedReader reader = new BufferedReader(new InputStreamReader(wordStream));
        String word;

        while ((word = reader.readLine()) != null) {
            words.add(word);
        }
    }

    public String getWord(int wordIdx) {
        return words.get(wordIdx);
    }

    public int indexOf(String word) {
        return words.indexOf(word);
    }
}
