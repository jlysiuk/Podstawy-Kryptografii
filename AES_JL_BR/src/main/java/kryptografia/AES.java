package kryptografia;

public class AES {

    byte[][] keyWords; // 44 words of 32(4bytes) bits
    byte[][] keyWordsReversed; // do deszyfrowania
    byte[] entranceKey;

    //sprawdzanie klucza podanego przez uzytkownika
    public AES(byte[] originalKey) throws Exception {
        //jezeli dlugosc sie nie zgadza to wyrzucany jest błąd
        if (originalKey.length != 16) {
            throw new Exception("key has wrong length!");
        }
        //jezeli dlugosc jest dobra to podany klucz jest przypisywany jako originalKey
        this.entranceKey = originalKey;
        //generowanie podkluczy
        this.keyWords = generateSubKeys(entranceKey);
        this.keyWordsReversed = generateReversedSubKeys(keyWords);
    }

    public byte[][] generateReversedSubKeys(byte[][] keyWords) {
        // starting index - 43
        int k = 0; // word index in keyWordsReversed
        byte[][] tmp = new byte[44][4];
        for (int i = 10; i >= 0; i--) {
            for (int j = 0; j < 4; j++) {
                tmp[k] = keyWords[i * 4 + j];
                k++;
            }
        }
        return tmp;
    }

    /**
     * @param message - bajty do zaszyfrowania
     * @return - zaszyfrowane bajty
     */

    //dzielenie message na bloki
    public byte[] encode(byte[] message) {

        //Okreslamy liczbe blokow. Dzielimy przez 16 poniewaz kazdy blok ma rozmiar 4x4
        int wholeBlocksCount = message.length / 16;
        int charactersToEncodeCount;
        if (wholeBlocksCount == 0) {
            charactersToEncodeCount = 16;   //zmienna okreslajaca rozmiar wynikowej zaszyfrowanej wiadomosci
        } else if (message.length % 16 != 0) {
            charactersToEncodeCount = (wholeBlocksCount + 1) * 16;
        } else {
            charactersToEncodeCount = wholeBlocksCount * 16;
        }

        byte[] result = new byte[charactersToEncodeCount]; //przetrzymywane zaszyfrowane bloki wiadomosci
        byte[] temp = new byte[charactersToEncodeCount]; //kopia oryginalnej wiadomości wraz z dopełnieniem zerami
        byte[] blok = new byte[16]; //tymczasowo przechowywany blok 16-bajtowy, który zostanie poddany szyfrowaniu


        //kopiowanie bajtów oryginalnej wiadomości do tablicy temp
        //i uzupełnienie zerami brakujących bajtów, aby osiągnąć stały rozmiar bloku
        for (int i = 0; i < charactersToEncodeCount; ++i) {
            if (i < message.length) {
                temp[i] = message[i];
            } else {
                temp[i] = 0;
            }
        }

        //blok jest kopiowany z tablicy temp do tablicy blok
        int i = 0;
        while (i < temp.length) {
            for (int j = 0; j < 16; ++j) {
                blok[j] = temp[i++];
            }

            //szyfrowanie bloku
            blok = this.encrypt(blok);
            System.arraycopy(blok, 0, result, i - 16, blok.length);
        }

        return result;
    }

    public byte[] decode(byte[] message) {
        if (message.length % 16 != 0) {
            return null;
        }

        // tablica message jest dzielona na bloki 16-bajtowe i przechowywana w tablicy dwuwymiarowej dataAsBlocks
        int blocksCount = message.length / 16;
        byte[][] dataAsBlocks = new byte[blocksCount][16];

        // ładowanie danych jako bloki do tablicy dataAsBlock:
        int i = 0;
        for (int block = 0; block < blocksCount; block++) {
            for (int b = 0; b < 16; b++) {
                dataAsBlocks[block][b] = message[i];
                i++;
            }
        }


        i = 0;

        // w pętli for każdy blok jest odszyfrowywany z użyciem metody decrypt, a wynikowy blok jest umieszczany w tablicy tmp
        byte[] tmp = new byte[message.length];
        for (int block = 0; block < blocksCount; block++) {
            for (int b = 0; b < 16; b++) {
                tmp[i] = decrypt(dataAsBlocks[block])[b];
                i++;
            }
        }

        // zlicza ilość zer na końcu tablicy tmp, które zostały dodane jako dopełnienie, aby oryginalna wiadomość miała stały rozmiar bloku 16-bajtowego
        int zeros = 0;
        for (int j = 0; j < 16; j++) {
            if (tmp[tmp.length - (j + 1)] == '\0') {
                zeros++;
            } else {
                break;
            }
        }

        //tworzona jest tablica output, do której kopiowane są bajty z tablicy tmp pomijając dodane dopełnienia zerowe.
        // Tablica output jest zwracana jako wynik działania funkcji.
        byte[] output = new byte[blocksCount * 16 - zeros];
        System.arraycopy(tmp, 0, output, 0, blocksCount * 16 - zeros);


        return output;
    }


    /**
     * @param state - 128 bit - 16 byte block
     * @return encrypted 16 block
     */
    public byte[] encrypt(byte[] state) {
        byte[] tmp = state;

        //dodaje klucz rundy do bloku wejściowego
        tmp = addKey(tmp, 0);

//        Następnie wykonuje się kilka transformacji na bloku wejściowym w ramach każdej rundy:
//
//        "subBytes" - zastępuje każdy bajt w bloku wejściowym innym bajtem na podstawie ustalonej tabeli zamiany (S-box).
//
//        "shiftRows" - przesuwa wiersze bloku wejściowego o różne wartości, aby uzyskać dystrybucję bajtów w bloku.
//
//        "mixColumns" - mnoży każdą kolumnę bloku wejściowego przez stałą macierz, co prowadzi do zamieszania danych.
//
//        "addKey" - dodaje kolejny klucz rundy do przekształconego bloku.

        // rundy 1 - 9
        for (int i = 1; i < 10; i++) {
            tmp = subBytes(tmp);
            tmp = shiftRows(tmp);
            tmp = mixColumns(tmp);
            tmp = addKey(tmp, i);
        }

        // ostatnia runda
        tmp = subBytes(tmp);
        tmp = shiftRows(tmp);
        tmp = addKey(tmp, 10);

        return tmp;
    }


    public byte[] decrypt(byte[] state) {
        byte[] tmp = state;

//        Funkcja wykonuje następujące kroki deszyfrowania w odwróconej kolejności:
//
//        "addKey" - dodaje klucz rundy do zaszyfrowanego bloku.
//
//        "shiftRowsReversed" - wykonuje odwrotną operację do "shiftRows". Przesuwa wiersze bloku w przeciwnych kierunkach, aby odzyskać oryginalną dystrybucję bajtów.
//
//        "subBytesReversed" - wykonuje odwrotną operację do "subBytes". Zastępuje każdy bajt w bloku wejściowym innym bajtem na podstawie ustalonej tabeli odwrotnej zamiany (odwrotny S-box).
//
//        "inverseMixColumns" - wykonuje odwrotną operację do "mixColumns". Mnoży każdą kolumnę bloku wejściowego przez odwrotną stałą macierz, aby odzyskać oryginalne dane.

        // inverse round 10:
        tmp = addKey(tmp, 10);
        tmp = shiftRowsReversed(tmp);
        tmp = subBytesReversed(tmp);

        // inverse rounds 9 - 1:
        for (int i = 9; i > 1; i--) {
            tmp = addKey(tmp, i);
            tmp = inverseMixColumns(tmp);
            tmp = shiftRowsReversed(tmp);
            tmp = subBytesReversed(tmp);
        }

        // inverse of round 0:
        tmp = addKey(tmp, 1);
        tmp = inverseMixColumns(tmp);
        tmp = shiftRowsReversed(tmp);
        tmp = subBytesReversed(tmp);
        tmp = addKey(tmp, 0);

        return tmp;
    }

//    Ta funkcja generuje podklucze (subkeys) dla algorytmu szyfrowania AES.
//    Na wejściu przyjmuje 16-bajtowy klucz szyfrowania, a na wyjściu zwraca tablicę bajtów zawierającą 44 słowa klucza,
//    gdzie każde słowo klucza składa się z 4 bajtów.
    public byte[][] generateSubKeys(byte[] keyInput) {
        int j = 0;
        byte[][] tmp = new byte[44][4];
        for (int i = 0; i < 4; i++) {
            for (int k = 0; k < 4; k++) {
                tmp[i][k] = keyInput[j];
            }
        }

        for (int round = 1; round <= 10; round++) {
            tmp[4 * round] = xorWords(tmp[4 * round - 4], g(tmp[4 * round - 1], round));
            tmp[4 * round + 1] = xorWords(tmp[4 * round], tmp[4 * round - 3]);
            tmp[4 * round + 2] = xorWords(tmp[4 * round + 1], tmp[4 * round - 2]);
            tmp[4 * round + 2] = xorWords(tmp[4 * round + 2], tmp[4 * round - 1]);
        }

        return tmp;
    }

    public byte[] addKey(byte[] state, int round) {
        // 10 - ostatnia runda
        // 0 - pierwsza runda
        byte[] tmp = new byte[state.length];
        int start = round * 4;
        int end = start + 4;
        int k = 0;
        for (int i = start; i < end; i++) { //  iterujemy przez słowa klucza
            for (int j = 0; j < 4; j++) { //  iterujemy przez bajty w każdym słowie klucza
                tmp[k] = (byte) (state[k] ^ keyWords[i][j]);
                k++;
            }
        }
        return tmp;
    }

    // W tym kroku każdy bajt stamu poddawany jest transformacji z użyciem tablicy nazywanej SBoxem
    private byte[] subBytes(byte[] state) {
        byte[] tmp = new byte[state.length];
        for (int i = 0; i < state.length; i++) {
            tmp[i] = SBox.translate(state[i]);
        }
        return tmp;
    }

    // Czynnosc odwrotna do subBytes. Uzywana do deszyfrowania
    private byte[] subBytesReversed(byte[] state) {
        byte[] tmp = new byte[state.length];
        for (int i = 0; i < state.length; i++) {
            tmp[i] = SBox.translateReverse(state[i]);
        }
        return tmp;
    }

//    Na początku funkcja tworzy dwuwymiarową tablicę tmp,
//    która pozwala łatwiej przesuwać wiersze macierzy stanu.
//    Następnie funkcja przesuwa drugi wiersz o jeden bajt w lewo,
//    trzeci wiersz o dwa bajty w lewo i czwarty wiersz o trzy bajty w lewo.
//
//    Na końcu funkcja tworzy jednowymiarową tablicę newState, aby móc zwrócić nowy stan po przesunięciach.
    public byte[] shiftRows(byte[] state) {
        // tworzenie tablicy dwuwymiarowej dla latwiejszego zamieniania
        byte[][] tmp = new byte[4][4];
        int k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                tmp[j][i] = state[k];
                k++;
            }
        }

        shiftArrayLeft(tmp[1], 1);
        shiftArrayLeft(tmp[2], 2);
        shiftArrayLeft(tmp[3], 3);

        // tworzenie tablicy jednowymiarowej do zwrocenia
        byte[] newState = new byte[16];
        k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                newState[k] = tmp[j][i];
                k++;
            }
        }

        return newState;
    }

        //funkcja przesuwania wierszy
    public byte[] shiftArrayLeft(byte[] array, int step) {
        for (int i = 0; i < step; i++) {
            int j;
            byte first;
            //Stores the last element of array
            first = array[0];

            for (j = 1; j < array.length; j++) {
                //Shift element of array by one
                array[j - 1] = array[j];
            }
            //Last element of array will be added to the start of array.
            array[array.length - 1] = first;
        }
        return array;
    }

//    Najpierw funkcja tworzy macierz kolumn o wymiarze 4x4, gdzie każda kolumna odpowiada jednej z czterech kolumn w macierzy stanu.
//    Następnie funkcja iteruje przez każdą kolumnę, i przekazuje ją do funkcji pomocniczej multiplySingleColumn
//    , która wykonuje na niej mnożenie macierzowe z określoną macierzą stałą.
//    Wynik tej operacji stanowi nową kolumnę macierzy kolumn.
    public byte[] mixColumns(byte[] state) {
        //tworzenie kolumn

        byte[][] columns = new byte[4][4];
        int k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                columns[i][j] = state[k];
                k++;
            }
        }
        //stosowanie funkcji na kolumnach
        for (int i = 0; i < 4; i++) {
            columns[i] = multiplySingleColumn(columns[i]);
        }

        //tworzenie tablicy jednowymiarowej do zwrocenia
        byte[] tmp = new byte[16];
        k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                tmp[k] = columns[i][j];
                k++;
            }
        }
        return tmp;

    }


    /**
     * @param column do mnozenia przez macierz
     * @return column pomnozona przez macierz:
     * 02 03 01 01
     * 01 02 03 01
     * 01 01 02 03
     * 03 01 01 02
     */
    public byte[] multiplySingleColumn(byte[] column) {
        byte[] c = new byte[4];
        c[0] = (byte) (Utils.fMul((byte) 0x02, column[0]) ^ Utils.fMul((byte) 0x03, column[1]) ^ column[2] ^ column[3]);
        c[1] = (byte) (column[0] ^ Utils.fMul((byte) 0x02, column[1]) ^ Utils.fMul((byte) 0x03, column[2]) ^ column[3]);
        c[2] = (byte) (column[0] ^ column[1] ^ Utils.fMul((byte) 0x02, column[2]) ^ Utils.fMul((byte) 0x03, column[3]));
        c[3] = (byte) (Utils.fMul((byte) 0x03, column[0]) ^ column[1] ^ column[2] ^ Utils.fMul((byte) 0x02, column[3]));
        return c;
    }

    // funkcja odwrotna do mixcolumns
    public byte[] inverseMixColumns(byte[] state) {
        //1. create columns

        byte[][] columns = new byte[4][4];
        int k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                columns[i][j] = state[k];
                k++;
            }
        }

        for (int i = 0; i < 4; i++) {
            columns[i] = multiplySingleColumnReversed(columns[i]);
        }

        byte[] tmp = new byte[16];
        k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                tmp[k] = columns[i][j];
                k++;
            }
        }
        return tmp;

    }

    /**
     * @param column w stanie podczas deszyfrowania
     * @return column pomnozona przez macierz:
     * 0E 0B 0D 09
     * 09 0E 0B 0D
     * 0D 09 0E 0B
     * 0B 0D 09 0E
     */

    public byte[] multiplySingleColumnReversed(byte[] column) {
        byte[] c = new byte[4];
        c[0] = (byte) (Utils.fMul((byte) 0x0E, column[0]) ^ Utils.fMul((byte) 0x0B, column[1]) ^ Utils.fMul((byte) 0x0D, column[2]) ^ Utils.fMul((byte) 0x09, column[3]));
        c[1] = (byte) (Utils.fMul((byte) 0x09, column[0]) ^ Utils.fMul((byte) 0x0E, column[1]) ^ Utils.fMul((byte) 0x0B, column[2]) ^ Utils.fMul((byte) 0x0D, column[3]));
        c[2] = (byte) (Utils.fMul((byte) 0x0D, column[0]) ^ Utils.fMul((byte) 0x09, column[1]) ^ Utils.fMul((byte) 0x0E, column[2]) ^ Utils.fMul((byte) 0x0B, column[3]));
        c[3] = (byte) (Utils.fMul((byte) 0x0B, column[0]) ^ Utils.fMul((byte) 0x0D, column[1]) ^ Utils.fMul((byte) 0x09, column[2]) ^ Utils.fMul((byte) 0x0E, column[3]));
        return c;
    }

    // metoda odwrotna do shiftRows
    public byte[] shiftRowsReversed(byte[] state) {
        // create two-dimensional array for easier shifting
        byte[][] tmp = new byte[4][4];
        int k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                tmp[j][i] = state[k];
                k++;
            }
        }

        shiftArrayRight(tmp[1], 1);
        shiftArrayRight(tmp[2], 2);
        shiftArrayRight(tmp[3], 3);

        // create one dimensional array to return output
        byte[] newState = new byte[16];
        k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                newState[k] = tmp[j][i];
                k++;
            }
        }

        return newState;
    }

//    Ta funkcja przesuwa elementy tablicy bajtów w prawo o określoną ilość kroków.
//    Argumenty funkcji to tablica bajtów, którą chcemy przesunąć, i liczba kroków przesuniecia.
//    W każdej iteracji ostatni element tablicy jest zapisywany do zmiennej last,
//    a następnie każdy element tablicy, począwszy od przedostatniego,
//    jest przesuwany o jeden indeks w kierunku końca tablicy.
//    W kolejnym kroku, wartość last jest umieszczana na pierwszej pozycji w tablicy
//    W ten sposób, po wykonaniu step iteracji, elementy tablicy są przesunięte w prawo o step pozycji.
    byte[] shiftArrayRight(byte[] array, int step) {
        for (int i = 0; i < step; i++) {
            int j;
            byte last;
            //Stores the last element of array
            last = array[array.length - 1];

            for (j = array.length - 2; j >= 0; j--) {
                //Shift element of array by one
                array[j + 1] = array[j];
            }
            //Last element of array will be added to the start of array.
            array[0] = last;
        }
        return array;
    }

    // funkcja XORujaca dwie tablice bajtow
    public byte[] xorWords(byte[] word1, byte[] word2) {
        if (word1.length == word2.length) {
            byte[] tmp = new byte[word1.length];
            for (int i = 0; i < word1.length; i++) {
                tmp[i] = (byte) (word1[i] ^ word2[i]);
            }
            return tmp;
        } else {
            return null;
        }
    }

//    funkcja wykonuje trzy operacje na słowie word:

//    1. Przesunięcie cykliczne wszystkich bajtów o jedno miejsce w lewo (z wyjątkiem pierwszego bajtu).
//    2. Zastąpienie każdego bajtu słowa wartością uzyskaną z tablicy zastępczej SBox, wykorzystując wartość bajtu jako indeks do tablicy.
//    3. Dodanie do pierwszego bajtu słowa word tzw. "round coefficient" - wartości zależnej od rundy szyfrowania, uzyskanej za pomocą operacji dzielenia modulo w ciele skończonym.
//    Funkcja zwraca wynik jako 4-bajtowe słowo uzyskane w wyniku wykonania powyższych operacji na słowie word.
    public byte[] g(byte[] word, int round) {
        byte[] tmp = shiftArrayLeft(word, 1);
        for (int i = 0; i < 4; i++) {
            tmp[i] = SBox.translate(tmp[i]);
        }

        // round coefficient added to first element
        byte RC = Utils.polynomialModuloDivision((byte) (0b1 << (round - 1)));
        tmp[0] ^= RC;

        return tmp;
    }

    public byte[][] getKeyWords() {
        return keyWords;
    }

    public byte[][] getKeyWordsReversed() {
        return keyWordsReversed;
    }

    public byte[] getEntranceKey() {
        return entranceKey;
    }


}
