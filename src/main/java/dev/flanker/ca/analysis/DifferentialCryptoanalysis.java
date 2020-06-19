package dev.flanker.ca.analysis;

import dev.flanker.ca.cipher.HeysCipher;

import java.util.Map;

public final class DifferentialCryptoanalysis {
    private static final HeysCipher CIPHER = HeysCipher.INSTANCE;

    private DifferentialCryptoanalysis() {}

    public static int recoverLast(Map<Integer, Integer> data, int a, int b) {
        int recovered = 0;
        int count = -1;
        for (int k = 0; k < (1 << HeysCipher.BLOCK_SIZE); k++) {
            int keyCount = 0;
            for (Map.Entry<Integer, Integer> entry : data.entrySet()) {
                int x = entry.getKey();
                int xa = x ^ a;

                int y = entry.getValue();
                int ya = data.get(xa);

                int difference = CIPHER.decryptRound(y, k) ^ CIPHER.decryptRound(ya, k);
                keyCount += (difference == b ? 1 : 0);
            }
            if (keyCount > count) {
                recovered = k;
                count = keyCount;
            }
        }

        return recovered;
    }

    public static int differentialSize(int x) {
        int size = 0;
        for (int i = 0; i < HeysCipher.SUB_BLOCK_SIZE; i++) {
            if (((x >>> (4 * i)) & 0xF) != 0) {
                size++;
            }
        }
        return size;
    }

    public static double[] differenceProbabilityDistribution(int a) {
        double[] distribution = new double[1 << HeysCipher.BLOCK_SIZE];
        for (int x = 0; x < distribution.length; x++) {
            distribution[CIPHER.encryptRound(x, 0) ^ CIPHER.encryptRound(x ^ a, 0)]++;
        }
        for (int i = 0; i < distribution.length; i++) {
            distribution[i] /= distribution.length;
        }
        return distribution;
    }

    private static double[][] computeDistribution() {
        double[][] distributionTable = new double[1 << HeysCipher.SUB_BLOCK_SIZE][1 << HeysCipher.SUB_BLOCK_SIZE];
        for (int a = 0; a < (1 << HeysCipher.SUB_BLOCK_SIZE); a++) {
            for (int x = 0; x < (1 << HeysCipher.SUB_BLOCK_SIZE); x++) {
                distributionTable[a][CIPHER.substitution(x) ^ CIPHER.substitution(x ^ a)]++;
            }
        }
        for (int a = 0; a < (1 << HeysCipher.SUB_BLOCK_SIZE); a++) {
            for (int b = 0; b < (1 << HeysCipher.SUB_BLOCK_SIZE); b++) {
                distributionTable[a][b] /= distributionTable[a].length;
            }
        }
        return distributionTable;
    }
}
