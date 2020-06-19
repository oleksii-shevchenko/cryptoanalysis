package dev.flanker.ca.analysis;

import dev.flanker.ca.cipher.HeysCipher;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public final class LinearCryptoanalysis {
    private static final int LAST_KEYS_NUMBER = 16;

    private static final int KEYS_NUMBER = 100;

    private static final HeysCipher CIPHER = HeysCipher.INSTANCE;

    private static final double[][] S_BOX_LP = computeLinearPotentials();

    private LinearCryptoanalysis() {}

    public static Map<Integer, Integer> recoverFirst(Map<Integer, Integer> data, Collection<Pair> pairs) {
        Map<Integer, Integer> counts = new HashMap<>();
        for (Pair approximation : pairs) {
            for (Integer key : recoverFirst(data, approximation.getA(), approximation.getB())) {
                counts.put(key, counts.getOrDefault(key, 0) + 1);
            }
        }
        return MapUtil.head(counts, LAST_KEYS_NUMBER);
    }

    public static Collection<Integer> recoverFirst(Map<Integer, Integer> data, int a, int b) {
        Map<Integer, Integer> counts = new HashMap<>(1 << 16);
        int[][] dataArray = toArray(data);
        for (int k = 0; k < (1 << HeysCipher.BLOCK_SIZE); k++) {
            int count = 0;
            for (int t = 0; t < dataArray.length; t++) {
                int x = CIPHER.encryptRound(dataArray[t][0], k);
                count += dot(a, x) ^ dot(b, dataArray[t][1]);
            }
            count = Math.max(count, (1 << HeysCipher.BLOCK_SIZE) - count);
            counts.put(k, Math.abs(count));
        }
        return MapUtil.head(counts, KEYS_NUMBER).keySet();
    }

    public static double[] differenceProbabilityDistribution(int a) {
        double[] distribution = new double[1 << HeysCipher.BLOCK_SIZE];
        for (int b = 0; b < distribution.length; b++) {
            distribution[b] = getLp(a, b);
        }
        return distribution;
    }

    private static double getLp(int a, int b) {
        double p = 1.0;
        b = CIPHER.permutation(b);
        for (int i = 0; i < HeysCipher.SUB_BLOCK_SIZE; i++) {
            int aPrime = (a >>> (4 * i)) & 0xF;
            int bPrime = (b >>> (4 * i)) & 0xF;
            p *= S_BOX_LP[aPrime][bPrime];
        }
        return p;
    }

    public static int dot(int x, int y) {
        int z = x & y;
        z = z ^ (z >>> 8);
        z = z ^ (z >>> 4);
        z = z ^ (z >>> 2);
        return (z ^ (z >>> 1)) & 0x1;
    }

    private static double[][] computeLinearPotentials() {
        double[][] lp = new double[1 << HeysCipher.SUB_BLOCK_SIZE][1 << HeysCipher.SUB_BLOCK_SIZE];
        for (int a = 0; a < (1 << HeysCipher.SUB_BLOCK_SIZE); a++) {
            for (int b = 0; b < (1 << HeysCipher.SUB_BLOCK_SIZE); b++) {
                double val = 0;
                for (int x = 0; x < (1 << HeysCipher.SUB_BLOCK_SIZE); x++) {
                    int degree = dot(a, x) ^ dot(b, CIPHER.substitution(x));
                    if (degree == 1) {
                        val--;
                    } else {
                        val++;
                    }
                }
                lp[a][b] = Math.pow(val / (1 << HeysCipher.SUB_BLOCK_SIZE), 2);
            }
        }
        return lp;
    }

    private static int[][] toArray(Map<Integer, Integer> data) {
        int[][] array = new int[data.size()][2];
        int index = 0;
        for (Map.Entry<Integer, Integer> entry : data.entrySet()) {
            array[index][0] = entry.getKey();
            array[index][1] = entry.getValue();
            index++;
        }
        return array;
    }
}
