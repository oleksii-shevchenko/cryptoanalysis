package dev.flanker.ca.analysis;

import dev.flanker.ca.cipher.HaysCipher;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

public class HaysDifferentialCryptoAnalysis {
    /**
     * 1.
     *
     * a = c00
     * b = 1111
     *
     * a = f00
     * b = 1111
     *
     * a = 400
     * b = 1111
     */

    private static final Differential DIFFERENTIAL = new Differential(0xe0, 0x2222);

    private static final HaysCipher CIPHER = new HaysCipher();

    public static void main(String[] args) {
    }

    private int[] genKeys() {
        int[] keys = new int[HaysCipher.ROUNDS + 1];
        for (int i = 0; i < keys.length; i++) {
            keys[i] = ThreadLocalRandom.current().nextInt(1 << HaysCipher.BLOCK_SIZE);
        }
        return keys;
    }

    private int[] decryptKeys(int[] keys) {
        int[] decrypt = new int[keys.length];
        for (int i = 0; i < keys.length; i++) {
            decrypt[decrypt.length - i - 1] = keys[i];
        }
        return decrypt;
    }

    private Map<Integer, Integer> generateData(int[] key, int size, int a) {
        Map<Integer, Integer> data = new HashMap<>();
        for (int i = 0; i < size; i++) {
            int x = ThreadLocalRandom.current().nextInt(1 << 16);
            data.put(x, CIPHER.encrypt(x, key));
            data.put(x ^ a, CIPHER.encrypt(x ^ a, key));
        }
        return data;
    }

    private Map<Integer, Integer> generateData(int[] key, int size) {
        Map<Integer, Integer> data = new HashMap<>();
        for (int i = 0; i < size; i++) {
            int x = ThreadLocalRandom.current().nextInt(1 << 16);
            data.put(x, CIPHER.encrypt(x, key));
        }
        return data;
    }

    private int diffSize(int b) {
        int diffSize = 0;
        for (int i = 0; i < HaysCipher.SUB_BLOCK_SIZE; i++) {
            if ((b >>> (4 * i) & 0xF) != 0) {
                diffSize++;
            }
        }
        return diffSize;
    }

    private int maxByValue(Map<Integer, Integer> map) {
        int key = 0;
        int val = -1;
        for (Map.Entry<Integer, Integer> entry : map.entrySet()) {
            if (entry.getValue() > val) {
                key = entry.getKey();
                val = entry.getValue();
            }
        }
        return key;
    }

    private Map<Integer, Integer> recoverLast(Map<Integer, Integer> data, int a, int b) {
        int mask = differenceMask(b);

        int recovered = 0;
        int count = -1;
        for (int k = 0; k < (1 << HaysCipher.BLOCK_SIZE); k++) {
            int keyCount = 0;
            for (Map.Entry<Integer, Integer> entry : data.entrySet()) {
                int difference =
                        CIPHER.decryptRound(entry.getValue(), k) ^
                        CIPHER.decryptRound(data.get(entry.getKey() ^ a), k);
                keyCount += ((difference & mask) == b ? 1 : 0);
            }
            if (keyCount > count) {
                recovered = k;
                count = keyCount;
            }
        }

        return decomposeKey(recovered);
    }

    private Map<Integer, Integer> decomposeKey(int key) {
        Map<Integer, Integer> decomposed = new HashMap<>();
        for (int i = 0; i < HaysCipher.SUB_BLOCK_SIZE; i++) {
            decomposed.put(i, (key >>> (4 * i)) & 0xF);
        }
        return decomposed;
    }

    private int composeKey(Map<Integer, Integer> parts) {
        int val = 0;
        for (int i = 0; i < HaysCipher.SUB_BLOCK_SIZE; i++) {
            val |= (parts.get(i) << (4 * i));
        }
        return val;
    }

    private int differenceMask(int b) {
        int mask = 0;
        for (int i = 0; i < HaysCipher.SUB_BLOCK_SIZE; i++) {
            if (((b >>> (4 * i)) & 0xF) != 0x0) {
                mask |= (0xF << (4 * i));
            }
        }
        return mask;
    }

    public Collection<Differential> differentialSearch(int a, double p) {
        Map<Integer, Double> step = Map.of(a, 1.0);
        for (int t = 0; t < HaysCipher.ROUNDS - 1; t++) {
            Map<Integer, Double> nextStep = new HashMap<>();
            for (Map.Entry<Integer, Double> diff : step.entrySet()) {
                differentialDescent(nextStep, diff.getKey(), diff.getValue());
            }
            nextStep.entrySet().removeIf(entry -> entry.getValue() < p);
            step = nextStep;
        }
        return step.entrySet()
                .stream()
                .map(entry -> new Differential(a, entry.getKey(), getLevel(entry.getValue())))
                .collect(Collectors.toList());
    }

    private int getLevel(double probability) {
        return (int) (probability * (1 << HaysCipher.BLOCK_SIZE));
    }

    private void differentialDescent(Map<Integer, Double> differences, int b, double p) {
        double[] derivativeDistribution = computeDerivativeDistribution(b);
        for (int j = 0; j < derivativeDistribution.length; j++) {
            differences.put(j, differences.getOrDefault(j, 0.0) + p * derivativeDistribution[j]);
        }
    }

    private double[] computeDerivativeDistribution(int direction) {
        double[] distribution = new double[1 << HaysCipher.BLOCK_SIZE];
        for (int k = 0; k < distribution.length; k++) {
            distribution[CIPHER.encryptRound(0, k) ^ CIPHER.encryptRound(direction, k)] += 1;
        }
        for (int i = 0; i < distribution.length; i++) {
            distribution[i] = distribution[i] / distribution.length;
        }
        return distribution;
    }
}
