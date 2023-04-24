package kryptografia;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SBoxTest {

    @Test
    void translateTest() {
        byte a = (byte) 0xc2;
        assertEquals(0x25, SBox.translate(a));
    }



}