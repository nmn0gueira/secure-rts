package crypto;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

class CryptoConfigParser {

    static Map<CryptoConfigKey, String> parseFile(String configPath) {
        try (BufferedReader reader = new BufferedReader(new FileReader(configPath))) {
            Map<CryptoConfigKey, String> result = new HashMap<>();
            String line;
            while ((line = reader.readLine()) != null) {
                parseLine(line, result);
            }
            return result;
        } catch (IOException e) {
            throw new RuntimeException("Failed to read crypto config: " + configPath, e);
        }
    }

    static Map<CryptoConfigKey, String> parseString(String config) {
        Map<CryptoConfigKey, String> result = new HashMap<>();
        for (String line : config.split("\n")) {
            parseLine(line, result);
        }
        return result;
    }

    private static void parseLine(String line, Map<CryptoConfigKey, String> result) {
        String trimmed = line.trim();
        if (trimmed.isEmpty() || trimmed.startsWith("#")) return;

        String[] parts = trimmed.split(":", 2);
        if (parts.length != 2) return;
        CryptoConfigKey.fromAlias(parts[0].trim()).ifPresent(key -> {
            String value = parts[1].trim();
            if (!value.equals("NULL")) {
                result.put(key, value);
            }
        });
    }

    /*private static void parseLine(String line, Map<String, String> result) {
        String trimmed = line.trim();

        if (trimmed.isEmpty()
        || trimmed.startsWith("#")
        || trimmed.startsWith("//")
        || (trimmed.startsWith("<") && trimmed.endsWith(">"))
        ) return;
        
        String[] parts = trimmed.split(":",2);

        if (parts.length != 2) return;


        String key = normalizeKey(parts[0].trim());
        String value = parts[1].trim();
        
        result.put(key, value);
    }*/

}
