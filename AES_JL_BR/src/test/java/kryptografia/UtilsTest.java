package kryptografia;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class UtilsTest {
    @Test
    void polynomialMultiplicationTest() {
        assertEquals(1, (Utils.polynomialMultiplication((byte) 1, (byte) 1)));
        assertEquals(0, (Utils.polynomialMultiplication((byte) 0, (byte) 0)));
        assertEquals(2, (Utils.polynomialMultiplication((byte) 2, (byte) 1)));
        assertEquals(4, (Utils.polynomialMultiplication((byte) 2, (byte) 2)));
        assertEquals(8, (Utils.polynomialMultiplication((byte) 2, (byte) 4)));
        assertEquals(8, (Utils.polynomialMultiplication((byte) 4, (byte) 2)));
        assertEquals(0b110011, Utils.polynomialMultiplication((byte) 0b110011, (byte) 1));
        assertEquals(0b100000001, Utils.polynomialMultiplication((byte) 0b110011, (byte) 0b1111));
    }

    @Test
    void polynomialDivisionTest() {
        assertEquals(0b1, Utils.polynomialModuloDivision(0b1));
        assertEquals(0b10, Utils.polynomialModuloDivision(0b10));
        assertEquals(0b100, Utils.polynomialModuloDivision(0b100));
        assertEquals(0b1000, Utils.polynomialModuloDivision(0b1000));
        assertEquals(0b10000, Utils.polynomialModuloDivision(0b10000));
        assertEquals(0b1000_00, Utils.polynomialModuloDivision(0b1000_00));
        assertEquals(0b1000_000, Utils.polynomialModuloDivision(0b1000_000));
        assertEquals((byte)0b1000_0000, Utils.polynomialModuloDivision(0b1000_0000));
        assertEquals(0b11011, Utils.polynomialModuloDivision(0b100000000));
        assertEquals(0b11010, Utils.polynomialModuloDivision(0b100000001));
        assertEquals(0b101100, Utils.polynomialModuloDivision(0b1100000001));
    }

    @Test
    void convertStringToByteArrayTest() {
        assertArrayEquals(new byte[]{1, 16}, Utils.hexStringToByteArray("0110"));
    }

}