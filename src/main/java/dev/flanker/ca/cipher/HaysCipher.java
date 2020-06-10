package dev.flanker.ca.cipher;

public class HaysCipher implements Cipher {
    public static final int SUB_BLOCK_SIZE = 4;
    public static final int BLOCK_SIZE = 16;

    public static final int ROUNDS = 6;

    /* v4
    private static final int[] S_BOX = new int[] {
            0x3, 0x8, 0xD, 0x9, 0x6, 0xB, 0xF, 0x0, 0x2, 0x5, 0xC, 0xA, 0x4, 0xE, 0x1, 0x7
    };*/

    private static final int[] S_BOX = new int[] {
            0x2, 0x8, 0x9, 0x7, 0x5, 0xf, 0x0, 0xb, 0xc, 0x1, 0xd, 0xe, 0xa, 0x3, 0x6, 0x4
    };

    /*private static final int[] S_BOX = new int[] {
            0xa, 0x9, 0xd, 0x6, 0xe, 0xb, 0x4, 0x5, 0xf, 0x1, 0x3, 0xc, 0x7, 0x0, 0x8, 0x2
    };*/

    /*private static final int[] S_BOX = new int[] {
            0xf, 0x8, 0xe, 0x9, 0x7, 0x2, 0x0, 0xd, 0xc, 0x6, 0x1, 0x5, 0xb, 0x4, 0x3, 0xa
    };*/

    private static final int[] INV_S_BOX = inverseSBox(S_BOX);

    @Override
    public void encrypt(byte[] data, byte[] key, byte[] ciphertextBuffer) {

    }

    @Override
    public void decrypt(byte[] data, byte[] key, byte[] messageBuffer) {

    }

    public int encrypt(int data, int[] keys) {
        int ciphertext = data;
        for (int i = 0; i < ROUNDS; i++) {
            ciphertext = encryptRound(ciphertext, keys[i]);
        }
        return addKey(ciphertext, keys[ROUNDS]);
    }

    public int encryptRound(int data, int key) {
        return permutation(substitution(addKey(data, key), S_BOX));
    }

    public int decrypt(int data, int[] keys) {
        int message = data;
        for (int i = 0; i < ROUNDS; i++) {
            message = decryptRound(message, keys[i]);
        }
        return addKey(message, keys[ROUNDS]);
    }

    public int decryptRound(int data, int key) {
        return substitution(permutation(addKey(data, key)), INV_S_BOX);
    }

    public int permutation(int data) {
        int result = 0;
        for (int i = 0; i < SUB_BLOCK_SIZE; i++) {
            for (int j = 0; j < SUB_BLOCK_SIZE; j++) {
                int bit = (data >>> (SUB_BLOCK_SIZE * j + i)) & 0x1;
                result |= (bit << (SUB_BLOCK_SIZE * i + j));
            }
        }
        return result;
    }

    private int substitution(int data, int[] sBox) {
        int result = 0;
        for (int i = 0; i < SUB_BLOCK_SIZE; i++) {
            result |= (sBox[(data >>> (SUB_BLOCK_SIZE * i)) & 0xF] << (SUB_BLOCK_SIZE * i));
        }
        return result;
    }

    private int addKey(int data, int key) {
        return data ^ key;
    }

    private static int[] inverseSBox(int[] sBox) {
        int[] inverseBox = new int[sBox.length];
        for (int i = 0; i < sBox.length; i++) {
            inverseBox[sBox[i]] = i;
        }
        return inverseBox;
    }
}
