package org.example.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordPolicyTest {
    @Test
    void acceptsStrongPassword() {
        assertNull(PasswordPolicy.validate("StrongPassword1!"));
    }

    @Test
    void explainsInvalidPasswords() {
        assertEquals("Password cannot be null.", PasswordPolicy.validate(null));
        assertEquals("Password must be at least 12 characters.", PasswordPolicy.validate("Short1!"));
        assertEquals("Password must include a symbol.", PasswordPolicy.validate("LongPassword1"));
    }
}
