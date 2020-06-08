package dev.flanker.ca.analysis;

import dev.flanker.ca.cipher.HaysCipher;
import org.w3c.dom.ls.LSOutput;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

public class HaysDifferentialCryptoAnalysis {
    private static final HaysCipher CIPHER = new HaysCipher();

    public static void main(String[] args) {
        int[] keys = new int[7];
        int[] rev = new int[7];
        for (int i = 0; i < 7; i++) {
            keys[i] = ThreadLocalRandom.current().nextInt(1 << 16);
            rev[6 - i] = keys[i];
        }
        Map<Integer, Integer> c = new HashMap<>();
        for (int i = 0; i < (1 << 14); i++) {
            int x = ThreadLocalRandom.current().nextInt(1 << 16);
            int y = CIPHER.encrypt(x, keys);
            c.put(x, y);
        }
        new HaysDifferentialCryptoAnalysis().lastRoundKey(c, keys[6]);
    }

    public void lastRoundKey(Map<Integer, Integer> ciphertext, int lastKey) {
        double p = 1.0 / (1 << 12);

        List<Differential> differentials = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            differentials.addAll(highProbabilityDifferentials(1 << (4 * i), p));
        }

        for (Differential differential : differentials) {
            int count = 0;
            int max = 0;

            Map<Integer, Integer> pairs = new HashMap<>();
            for (Map.Entry<Integer, Integer> entry : ciphertext.entrySet()) {
                if (ciphertext.containsKey(entry.getKey() ^ differential.getA())) {
                    pairs.put(entry.getKey(), entry.getValue());
                }
            }


            for (int k = 0; k < (1 << 16); k++) {
                int currCount = 0;
                for (Map.Entry<Integer, Integer> entry : pairs.entrySet()) {
                    int b = CIPHER.decryptRound(entry.getValue(), k) ^
                            CIPHER.decryptRound(pairs.get(entry.getKey() ^ differential.getA()), k);
                    currCount += (b == differential.getB() ? 1 : 0);
                }
                if (currCount > count) {
                    count = currCount;
                    max = k;
                }
            }
            System.out.println(count);
            System.out.println(max == lastKey);
        }
    }


    public List<Differential> highProbabilityDifferentials(int a, double p) {
        Map<Integer, Double> differences = Map.of(a, 1.0);
        for (int t = 0; t < 5; t++) {
            Map<Integer, Double> newDifferences = new HashMap<>();
            for (Map.Entry<Integer, Double> diff : differences.entrySet()) {
                computeStep(newDifferences, diff.getKey(), diff.getValue());
            }

            newDifferences.entrySet().removeIf(entry -> entry.getValue() < p);
            differences = newDifferences;
        }

        differences.values().forEach(v -> System.out.println(v * (1 << 16)));

        return differences.keySet()
                .stream()
                .map(b -> new Differential(a, b))
                .collect(Collectors.toList());
    }

    private void computeStep(Map<Integer, Double> differences, int b, double p) {
        double[] derivativeDistribution = computeDerivativeDistribution(b);
        for (int j = 0; j < derivativeDistribution.length; j++) {
            differences.put(j, differences.getOrDefault(j, 0.0) + p * derivativeDistribution[j]);
        }
    }

    private double[] computeDerivativeDistribution(int direction) {
        double[] distribution = new double[1 << HaysCipher.BLOCK_SIZE];
        for (int x = 0; x < distribution.length; x++) {
            distribution[CIPHER.encryptRound(x, 0) ^ CIPHER.encryptRound(x ^ direction, 0)] += 1;
        }
        for (int i = 0; i < distribution.length; i++) {
            distribution[i] /= distribution.length;
        }
        return distribution;
    }
}
