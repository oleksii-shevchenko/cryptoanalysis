package dev.flanker.ca.starter;

import dev.flanker.ca.FileUtil;
import dev.flanker.ca.analysis.BranchAndLimitSearcher;
import dev.flanker.ca.analysis.DataUtil;
import dev.flanker.ca.analysis.LinearCryptoanalysis;
import dev.flanker.ca.analysis.Pair;
import dev.flanker.ca.cipher.HeysCipher;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class LinearCryptoanalysisStarter {
    public static void main(String[] args) {
        firstRoundAttack();
    }

    private static void generateApproximations() {
        double p = 1.0 / (1 << 14);
        BranchAndLimitSearcher searcher = new BranchAndLimitSearcher(LinearCryptoanalysis::differenceProbabilityDistribution);
        Collection<Pair> pairs = new ArrayList<>();
        for (int i = 0; i < HeysCipher.SUB_BLOCK_SIZE; i++) {
            for (int j = 1; j < (1 << HeysCipher.SUB_BLOCK_SIZE); j++) {
                int a = j << (4 * i);
                System.out.println("a = " + Integer.toHexString(a));
                pairs.addAll(searcher.search(a, p, 5));
            }
        }
        System.out.println("Approximations:");
        pairs.forEach(System.out::println);
        System.out.println("Total size = " + pairs.size());

        FileUtil.write(Path.of("./data/linear/approximation.json"), pairs);
    }

    private static void generateInput() {
        int[] input = DataUtil.generateInput(8 * (1 << 16) / 5);
        FileUtil.write(Path.of("./data/linear/input"), input);
    }

    private static void firstRoundAttack() {
        int[] input = FileUtil.read(Path.of("./data/linear/input"));
        int[] output = FileUtil.read(Path.of("./data/linear/output"));

        Map<Integer, Integer> data = new HashMap<>();
        for (int i = 0; i < input.length; i++) {
            data.put(input[i], output[i]);
        }

        System.out.println("Size = " + data.size());

        Collection<Pair> approximations = FileUtil.readPairs(Path.of("./data/linear/approximation.json"))
                .stream()
                .filter(approximation -> approximation.level() > 5)
                .peek(System.out::println)
                .collect(Collectors.toList());

        System.out.println("A = " + approximations.size());

        Map<Integer, Integer> keys = LinearCryptoanalysis.recoverFirst(data, approximations);

        keys.forEach((k, c) -> System.out.println("Key = " + Integer.toHexString(k) + " count = " + c));
    }
}
