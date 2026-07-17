package org.example.service;

import java.security.SecureRandom;

public class PasswordGenerator {

    private static final SecureRandom RNG = new SecureRandom();

    // Character sets
    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";
    private static final String SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?";

    // Remove lookalikes: O 0 I l 1 (and optionally others)
    private static final String AMBIGUOUS = "O0Il1";

    public String generate(int length, boolean includeSymbols, boolean noAmbiguous) {
        if (length < 8) {
            throw new IllegalArgumentException("Length must be at least 8.");
        }
        if (length > 128) {
            throw new IllegalArgumentException("Length too large (max 128).");
        }

        String lower = filter(LOWER, noAmbiguous);
        String upper = filter(UPPER, noAmbiguous);
        String digits = filter(DIGITS, noAmbiguous);
        String symbols = includeSymbols ? filter(SYMBOLS, noAmbiguous) : "";

        String all = lower + upper + digits + symbols;
        if (all.isEmpty()) throw new IllegalArgumentException("No characters available.");

        // Ensure at least one char from each selected set
        StringBuilder out = new StringBuilder(length);
        out.append(pick(lower));
        out.append(pick(upper));
        out.append(pick(digits));
        if (includeSymbols) out.append(pick(symbols));

        while (out.length() < length) {
            out.append(all.charAt(RNG.nextInt(all.length())));
        }

        // Shuffle (Fisher–Yates)
        char[] arr = out.toString().toCharArray();
        for (int i = arr.length - 1; i > 0; i--) {
            int j = RNG.nextInt(i + 1);
            char tmp = arr[i];
            arr[i] = arr[j];
            arr[j] = tmp;
        }

        return new String(arr);
    }

    private static String filter(String s, boolean noAmbiguous) {
        if (!noAmbiguous) return s;
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (AMBIGUOUS.indexOf(c) < 0) sb.append(c);
        }
        return sb.toString();
    }

    private static char pick(String set) {
        if (set == null || set.isEmpty()) {
            throw new IllegalArgumentException("Character set is empty.");
        }
        return set.charAt(RNG.nextInt(set.length()));
    }
}