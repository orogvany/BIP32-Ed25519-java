package com.github.orogvany.bip39;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.github.orogvany.bip32.extern.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class VectorReader {

    public List<Vector> getVectors() throws IOException {
        InputStream file = this.getClass().getClassLoader().getResourceAsStream("vector/vector.json");
        ObjectMapper mapper = new ObjectMapper();
        JsonNode tree = mapper.readTree(file);

        JsonNode english = tree.get("english");

        List<Vector> vectors = new ArrayList<>();
        for (int i = 0; i < english.size(); i++) {
            ArrayNode v = (ArrayNode) english.get(i);
            Vector vector = new Vector(Hex.decode(v.get(0).asText()), v.get(1).asText(), v.get(2).asText(), v.get(3).asText());
            vectors.add(vector);
        }

        return vectors;
    }

}
