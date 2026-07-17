package org.example.service;

public class PasswordPolicy {

    public static String validate(String password) {
        if (password == null) return "Password cannot be null.";
        if (password.length() < 12) return "Password must be at least 12 characters.";

        boolean hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false;
        for (char c : password.toCharArray()) {
            if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else hasSymbol = true;
        }

        if (!hasLower) return "Password must include a lowercase letter.";
        if (!hasUpper) return "Password must include an uppercase letter.";
        if (!hasDigit) return "Password must include a digit.";
        if (!hasSymbol) return "Password must include a symbol.";

        return null; // valid
    }
}