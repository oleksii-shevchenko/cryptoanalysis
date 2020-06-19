package dev.flanker.ca.analysis;

import dev.flanker.ca.cipher.HeysCipher;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

public final class DataUtil {
    private static final HeysCipher CIPHER = HeysCipher.INSTANCE;

    private DataUtil() { }

    public static int[] genKeys() {
        int[] keys = new int[HeysCipher.ROUNDS + 1];
        for (int i = 0; i < keys.length; i++) {
            keys[i] = ThreadLocalRandom.current().nextInt(1 << HeysCipher.BLOCK_SIZE);
        }
        return keys;
    }

    public static int[] decryptKeys(int[] keys) {
        int[] decrypt = new int[keys.length];
        for (int i = 0; i < keys.length; i++) {
            decrypt[decrypt.length - i - 1] = keys[i];
        }
        return decrypt;
    }

    public static int[] generateInput(int size) {
        int[] ints = new int[size];
        for (int i = 0; i < size; i++) {
            ints[i] = ThreadLocalRandom.current().nextInt(1 << 16);
        }
        return ints;
    }

    public static int[] generateInput(int size, int a) {
        int[] ints = new int[2 * size];
        for (int i = 0; i < size; i++) {
            ints[2 * i] = ThreadLocalRandom.current().nextInt(1 << 16);
            ints[2 * i + 1] = ints[2 * i] ^ a;
        }
        return ints;
    }

    public static Map<Integer, Integer> generateData(int[] key, int size, int a) {
        Map<Integer, Integer> data = new HashMap<>();
        for (int i = 0; i < size; i++) {
            int x = ThreadLocalRandom.current().nextInt(1 << 16);
            data.put(x, CIPHER.encrypt(x, key));
            data.put(x ^ a, CIPHER.encrypt(x ^ a, key));
        }
        return data;
    }

    public static Map<Integer, Integer> generateData(int[] key, int size) {
        Map<Integer, Integer> data = new HashMap<>();
        for (int i = 0; i < size; i++) {
            int x = ThreadLocalRandom.current().nextInt(1 << 16);
            data.put(x, CIPHER.encrypt(x, key));
        }
        return data;
    }

    public static Map<Integer, Integer> encrypt(int[] data, int[] keys) {
        Map<Integer, Integer> result = new HashMap<>();
        for (int x : data) {
            result.put(x, CIPHER.encrypt(x, keys));
        }
        return result;
    }
}
