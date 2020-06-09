package dev.flanker.ca.analysis;

import dev.flanker.ca.cipher.HaysCipher;

import java.util.*;
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
        double p = 1.0 / (1 << 10);

        int[] alphas = {
                0xf000, 0x0f00, 0x00f0, 0x000f,
                0x1000, 0x0100, 0x0010, 0x0001,
                0x2000, 0x0200, 0x0020, 0x0002,
                0x3000, 0x0300, 0x0030, 0x0003
        };


        for (int i = 0; i < HaysCipher.SUB_BLOCK_SIZE; i++) {
            System.out.println("Last key " + i + " = " + Integer.toHexString((lastKey >>> (4 * i)) & 0xF));
        }

        Map<Integer, Integer> keyParts = new HashMap<>();
        for (int i = 0; i < HaysCipher.SUB_BLOCK_SIZE; i++) {
            keyParts.put(i, (lastKey >>> (4 * i)) & 0xF);
        }


        Map<Differential, Integer> diffs = new HashMap<>();
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 4; j++) {
                diffs.putAll(highProbabilityDifferentials(i << (4 * j), p));
            }
        }

        Collection<Map<Integer, Integer>> rounds = new ArrayList<>();
        for (Map.Entry<Differential, Integer> diff : diffs.entrySet()) {
            System.out.println("Differential level = " + diff.getValue());

            int diffSize = 0;
            int diffB = diff.getKey().getB();
            for (int i = 0; i < 4; i++) {
                if ((diffB >>> (4 * i) & 0xF) != 0) {
                    diffSize++;
                }
            }

            System.out.println("Diff size = " + diffSize);

            Map<Integer, Integer> preparedData = new HashMap<>();
            for (Map.Entry<Integer, Integer> entry : ciphertext.entrySet()) {
                if (ciphertext.containsKey(entry.getKey() ^ diff.getKey().getA())) {
                    preparedData.put(entry.getKey(), entry.getValue());
                }
            }

            Map<Integer, Integer> parts = recoverLast(preparedData, diff.getKey().getA(), diff.getKey().getB());

            int recoveredSize = 0;
            for (Map.Entry<Integer, Integer> entry : parts.entrySet()) {
                System.out.println("Recovered part " + entry.getKey() + " = " + Integer.toHexString(entry.getValue()));
                System.out.println("Matched = " + (keyParts.get(entry.getKey()).equals(entry.getValue())));
                recoveredSize += (keyParts.get(entry.getKey()).equals(entry.getValue()) ? 1 : 0);
            }
            System.out.println("Recovered size = " + recoveredSize);

            rounds.add(parts);
        }

        for (int i = 0; i < 4; i++) {
            Map<Integer, Integer> votes = new HashMap<>();
            for (Map<Integer, Integer> round : rounds) {
                votes.put(round.get(i), votes.getOrDefault(round.get(i), 0) + 1);
            }
            int key = maxByValue(votes);
            System.out.println("Recovered vote part " + i + " = " + key);
            System.out.println("Matched = " + (key == keyParts.get(i)));
        }
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

    public Map<Differential, Integer> highProbabilityDifferentials(int a, double p) {
        Map<Integer, Double> differences = Map.of(a, 1.0);
        for (int t = 0; t < 5; t++) {
            Map<Integer, Double> newDifferences = new HashMap<>();
            for (Map.Entry<Integer, Double> diff : differences.entrySet()) {
                differentialDescent(newDifferences, diff.getKey(), diff.getValue());
            }

            newDifferences.entrySet().removeIf(entry -> entry.getValue() < p);
            differences = newDifferences;
        }

        Map<Differential, Integer> res = new HashMap<>();
        for (Map.Entry<Integer, Double> entry : differences.entrySet()) {
            int count = (int) (entry.getValue().doubleValue() * (1 << 16));
            res.put(new Differential(a, entry.getKey()), count);
        }
        return res;
    }

    private Map<Integer, Integer> recoverLast(Map<Integer, Integer> data, int a, int b) {
        int mask = differenceMask(b);

        int recovered = 0;
        int count = 0;
        for (int k = 0; k < (1 << 16); k++) {
            if ((k & mask) == 0) {
                continue;
            }
            int keyCount = 0;
            for (Map.Entry<Integer, Integer> entry : data.entrySet()) {
                int difference = CIPHER.decryptRound(entry.getValue(), k) ^
                        CIPHER.decryptRound(data.get(entry.getKey() ^ a), k);
                keyCount += ((difference & mask) == b ? 1 : 0);
            }
            if (keyCount > count) {
                recovered = k;
                count = keyCount;
            }
        }

        Map<Integer, Integer> recoveredParts = new HashMap<>();
        for (int i = 0; i < HaysCipher.SUB_BLOCK_SIZE; i++) {
            recoveredParts.put(i, (recovered >>> (4 * i)) & 0xF);
        }
        return recoveredParts;
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
            distribution[i] /= distribution.length;
        }
        return distribution;
    }
}
