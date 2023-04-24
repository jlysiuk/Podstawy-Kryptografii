package kryptografia;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class AESTest {
    AES aes;

    @BeforeEach
    void init() throws Exception {
        this.aes = new AES(new byte[]{63, -19, -50, -121, -122, 114, 53, 72, -87, -105, 72, 11, 11, 57, 52, -115});
    }

    @Test
    void shiftRowsTest() {
        byte[] state = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        byte[] expected = new byte[]{0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11};
        byte[] shifted = aes.shiftRows(state);
        System.out.println(Arrays.toString(shifted));
        assertArrayEquals(expected, shifted);
    }

    @Test
    void shiftArrayLeftTest() {
        byte[] state = new byte[]{0,1,2,3};
        byte[] shifted = aes.shiftArrayLeft(state,1);
        byte[] expected = new byte[]{1,2,3,0};
        System.out.println(Arrays.toString(shifted));
        assertArrayEquals(expected, shifted);

        state = new byte[]{0,1,2,3};
        shifted = aes.shiftArrayLeft(state,2);
        expected = new byte[]{2,3,0,1};
        System.out.println(Arrays.toString(shifted));
        assertArrayEquals(expected, shifted);

        state = new byte[]{0,1,2,3};
        shifted = aes.shiftArrayLeft(state,3);
        expected = new byte[]{3,0,1,2};
        System.out.println(Arrays.toString(shifted));
        assertArrayEquals(expected, shifted);
    }

    @Test
    void shiftArrayRightTest() {
        byte[] state = new byte[]{0,1,2,3};
        byte[] shifted = aes.shiftArrayRight(state,1);
        byte[] expected = new byte[]{3,0,1,2};
        System.out.println(Arrays.toString(shifted));
        assertArrayEquals(expected, shifted);

        state = new byte[]{0,1,2,3};
        shifted = aes.shiftArrayRight(state,2);
        expected = new byte[]{2,3,0,1};
        System.out.println(Arrays.toString(shifted));
        assertArrayEquals(expected, shifted);

        state = new byte[]{0,1,2,3};
        shifted = aes.shiftArrayRight(state,3);
        expected = new byte[]{1,2,3,0};
        System.out.println(Arrays.toString(shifted));
        assertArrayEquals(expected, shifted);
    }

    @Test
    void encryptTest() {
        byte[] state = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        byte[] out = aes.encrypt(state);
        System.out.println(Arrays.toString(state));
        System.out.println(Arrays.toString(out));
        assertNotNull(out);

        byte[] state3 = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        byte[] out3 = aes.encrypt(state3);
        System.out.println(Arrays.toString(state3));
        System.out.println(Arrays.toString(out3));
        assertNotNull(out3);

        byte[] state2 = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,16};
        byte[] out2 = aes.encrypt(state2);
        System.out.println(Arrays.toString(state2));
        System.out.println(Arrays.toString(out2));
        assertNotNull(out2);

    }

    @Test
    void decryptTest() {
        byte[] state = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        byte[] out = aes.encrypt(state);
        System.out.println(Arrays.toString(state));
        System.out.println(Arrays.toString(out));
        System.out.println("DECRYPTION:");
        byte[] decrypted = aes.decrypt(out);
        System.out.println(Arrays.toString(decrypted));
        assertNotNull(out);
    }

    @Test
    void reverseKeyTest() {
        System.out.println(Arrays.deepToString(aes.getKeyWords()));
        System.out.println(Arrays.deepToString(aes.getKeyWordsReversed()));
    }

    @Test
    void encodeDecodeTest() {
        byte[] encoded = aes.encode("1234567891123456".getBytes());
        byte[] encrypted = aes.encrypt("1234567891123456".getBytes());
        assertArrayEquals(encoded, encrypted);




        System.out.println(Arrays.toString("123".getBytes()));
        encoded = aes.encode("123".getBytes());
        System.out.println(Arrays.toString(encoded));
        byte[] decoded = aes.decode(encoded);
        System.out.println(Arrays.toString(decoded));
    }





}