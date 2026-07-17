package org.example.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordGeneratorTest {
    private final PasswordGenerator generator = new PasswordGenerator();

    @Test
    void generatesRequestedLengthAndRequiredCharacterGroups() {
        String password = generator.generate(24, true, false);
        assertEquals(24, password.length());
        assertTrue(password.chars().anyMatch(Character::isLowerCase));
        assertTrue(password.chars().anyMatch(Character::isUpperCase));
        assertTrue(password.chars().anyMatch(Character::isDigit));
        assertTrue(password.chars().anyMatch(c -> !Character.isLetterOrDigit(c)));
    }

    @Test
    void canExcludeSymbolsAndAmbiguousCharacters() {
        String password = generator.generate(32, false, true);
        assertTrue(password.chars().allMatch(Character::isLetterOrDigit));
        assertTrue(password.chars().noneMatch(c -> "O0Il1".indexOf(c) >= 0));
    }

    @Test
    void rejectsUnsupportedLengths() {
        assertThrows(IllegalArgumentException.class, () -> generator.generate(7, true, false));
        assertThrows(IllegalArgumentException.class, () -> generator.generate(129, true, false));
    }
}
