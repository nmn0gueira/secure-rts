package crypto;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

class CryptoConfigParser {

    static Map<String, String> parseFile(String configPath) {
        try (BufferedReader reader = new BufferedReader(new FileReader(configPath))) {
            Map<String, String> result = new HashMap<>();
            String line;
            while ((line = reader.readLine()) != null) {
                parseLine(line, result);
            }
            return result;
        } catch (IOException e) {
            throw new RuntimeException("Failed to read crypto config: " + configPath, e);
        }
    }

    static Map<String, String> parseString(String config) {
        Map<String, String> result = new HashMap<>();
        for (String line : config.split("\n")) {
            parseLine(line, result);
        }
        return result;
    }

    private static void parseLine(String line, Map<String, String> result) {
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
    }

    private static String normalizeKey(String key) {
        String normalized = key.trim()
                .toLowerCase()
                .replace("-", "_")
                .replace(" ", "_");

        return switch (normalized) {
            case "ciphersuite", "confidentiality" -> "CONFIDENTIALITY";
            case "key", "symmetric_key" -> "SYMMETRIC_KEY";
            case "iv" -> "IV";
            case "integrity" -> "INTEGRITY";
            case "hmac", "mac" -> "MAC";
            case "mackey", "mac_key" -> "MAC_KEY";
            case "h", "hash" -> "H";
            default -> key.trim().toUpperCase();
        };
    }

}
