package kryptografia;

public class Utils {
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * finite multiplication in Galois Field
     * we multiply 2 polynomials A(x) * B(x) represented as bits of a and b = C'(x)
     * and we reduce C'(x) by AES irreducible polynomial (x^8 + x^4 + x^3 + x + 1)
     * and we get the result
     */
    static public byte fMul(byte a, byte b) {
        int tmp = polynomialMultiplication(a, b);
        return polynomialModuloDivision(tmp);
    }

    static public int polynomialMultiplication(byte a, byte b) {
        int result = 0;
        int aTmp;
        int bTmp;
        for (int i = 0; i < 8; i++) { // for each bit in a
            for (int j = 0; j < 8; j++) { // for each bit in b
                aTmp = a & (1 << i); // when i = 1 -> value of 2^1, when i = 2 -> value of 2^2
                bTmp = b & (1 << j);
                if (aTmp != 0 && bTmp != 0) { // if both values or not 0s we can multiply
                    //potential 1 is at i+j index of result
                    // if 1 already exists we can make switch it to 0 ( because coefficient has to be in GF(2) )
                    result ^= (1 << (i + j));
                }
            }
        }
        return result;
    }


    // RC[8] = x^7 = 0b1000_0000
    // RC[9] = x^8 = 0b10000_0000 mod 100011011
    // RC[10] = x^9 =
    //



//    x^8 mod (x^8 + x^4 + x^3 + x + 1) = 0b0000_0000 - 0b1111_1111




//    x^9 : (x^8 + x^4 + x^3 + x + 1)



    // divide by (x^8 + x^4 + x^3 + x + 1) = 0b100011011
    // returns modulo polynomial
    // take a -> xor first bits by 100011011 shifted by correct amount of bits
    // repeat until a <= 255
    static public byte polynomialModuloDivision(int a) {
        while (a > 255) {
            int shift = getFirstBit(a) - 8;
            a = a ^ (0b100011011 << shift);
        }
        return (byte) a;
    }

    /**
     * @param a int
     * @return first bit set as 1 in an int 32 means biggest value 0 means 0 or 1 number was inputted.
     */
    static public int getFirstBit(int a) {
        int first = 0;
        for (int i = 0; i < 32; i++) {
            if ((a & (1 << i)) != 0) {
                first = i;
            }
        }
        return first;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
