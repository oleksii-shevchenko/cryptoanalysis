package dev.flanker.ca.starter;

import dev.flanker.ca.analysis.HaysDifferentialCryptoAnalysis;
import dev.flanker.ca.cipher.HaysCipher;

public class DifferentialCryptoanalysisStarter {
    private static final HaysCipher CIPHER = new HaysCipher();


    public static void main(String[] args) {
        System.out.println(new HaysDifferentialCryptoAnalysis().highProbabilityDifferentials(1, 1.0 / (1 << 14)));
    }
}
