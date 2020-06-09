package dev.flanker.ca.cipher;

public class HaysCipher implements Cipher {
    public static final int SUB_BLOCK_SIZE = 4;
    public static final int BLOCK_SIZE = 16;

    public static final int ROUNDS = 6;

    private static final int[] S_BOX = new int[] {
            Integer.parseInt("f", 16),
            Integer.parseInt("8", 16),
            Integer.parseInt("e", 16),
            Integer.parseInt("9", 16),
            Integer.parseInt("7", 16),
            Integer.parseInt("2", 16),
            Integer.parseInt("0", 16),
            Integer.parseInt("d", 16),
            Integer.parseInt("c", 16),
            Integer.parseInt("6", 16),
            Integer.parseInt("1", 16),
            Integer.parseInt("5", 16),
            Integer.parseInt("b", 16),
            Integer.parseInt("4", 16),
            Integer.parseInt("3", 16),
            Integer.parseInt("a", 16)
    };

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

    private int permutation(int data) {
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

    public int addKey(int data, int key) {
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
