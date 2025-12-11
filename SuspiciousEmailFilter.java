import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;

public class SuspiciousEmailFilter {

    private static final String SUSPICIOUS_FILE = "suspicious.txt";
    private static final String EMAILS_FILE = "emails.txt";

    private static final int BLOOM_BIT_SIZE = 1_000_000; // bits
    private static final int BLOOM_NUM_HASHES = 5;

    public static void main(String[] args) {
        try {
            List<String> suspiciousDomains = readLines(SUSPICIOUS_FILE);
            List<String> emailDomains = extractEmailDomains(EMAILS_FILE);

            System.out.println("Loaded " + suspiciousDomains.size() + " suspicious domains.");
            System.out.println("Loaded " + emailDomains.size() + " email addresses.\n");

            BloomFilter bloomFilter = new BloomFilter(BLOOM_BIT_SIZE, BLOOM_NUM_HASHES);
            Set<String> suspiciousSet = new HashSet<>();

            long startBloomAdd = System.nanoTime();
            for (String domain : suspiciousDomains) {
                bloomFilter.add(domain);
            }
            long endBloomAdd = System.nanoTime();
            long bloomAddTimeNs = endBloomAdd - startBloomAdd;

            long startSetAdd = System.nanoTime();
            for (String domain : suspiciousDomains) {
                suspiciousSet.add(domain.toLowerCase().trim());
            }
            long endSetAdd = System.nanoTime();
            long setAddTimeNs = endSetAdd - startSetAdd;

            Runtime runtime = Runtime.getRuntime();
            runtime.gc();
            long memBeforeSet = runtime.totalMemory() - runtime.freeMemory();
            suspiciousSet.clear();
            runtime.gc();
            long memBefore = runtime.totalMemory() - runtime.freeMemory();
            for (String domain : suspiciousDomains) {
                suspiciousSet.add(domain.toLowerCase().trim());
            }
            runtime.gc();
            long memAfter = runtime.totalMemory() - runtime.freeMemory();
            long setMemoryBytes = memAfter - memBefore;

            long bloomMemoryBytes = bloomFilter.approximateMemoryBytes();

            long startBloomCheck = System.nanoTime();
            int bloomPositiveCount = 0;
            for (String domain : emailDomains) {
                if (bloomFilter.contains(domain)) {
                    bloomPositiveCount++;
                }
            }
            long endBloomCheck = System.nanoTime();
            long bloomCheckTimeNs = endBloomCheck - startBloomCheck;

            long startSetCheck = System.nanoTime();
            int setPositiveCount = 0;
            for (String domain : emailDomains) {
                if (suspiciousSet.contains(domain.toLowerCase().trim())) {
                    setPositiveCount++;
                }
            }
            long endSetCheck = System.nanoTime();
            long setCheckTimeNs = endSetCheck - startSetCheck;

            int falsePositives = 0;
            int falseNegatives = 0;

            for (String domain : emailDomains) {
                boolean bloomSays = bloomFilter.contains(domain);
                boolean setSays = suspiciousSet.contains(domain.toLowerCase().trim());

                if (bloomSays && !setSays) {
                    falsePositives++;
                }
                if (!bloomSays && setSays) {
                    falseNegatives++;
                }
            }

            System.out.println("=== BLOOM FILTER PARAMETERS ===");
            System.out.println("Bit array size: " + bloomFilter.getBitSize() + " bits");
            System.out.println("Hash functions: " + bloomFilter.getNumHashFunctions());
            System.out.printf("Bloom Filter memory: %.3f KB%n", bloomMemoryBytes / 1024.0);
            System.out.printf("HashSet memory (approx): %.3f KB%n%n", setMemoryBytes / 1024.0);

            System.out.println("=== ADD PHASE (SUSPICIOUS DOMAINS) ===");
            System.out.printf("Bloom Filter add time: %.3f ms%n", bloomAddTimeNs / 1_000_000.0);
            System.out.printf("HashSet add time:      %.3f ms%n%n", setAddTimeNs / 1_000_000.0);

            System.out.println("=== CHECK PHASE (EMAIL DOMAINS) ===");
            System.out.printf("Bloom Filter check time: %.3f ms%n", bloomCheckTimeNs / 1_000_000.0);
            System.out.printf("HashSet check time:      %.3f ms%n", setCheckTimeNs / 1_000_000.0);
            System.out.println("Bloom positives: " + bloomPositiveCount);
            System.out.println("HashSet positives: " + setPositiveCount + "\n");

            System.out.println("=== ACCURACY (VS HASHSET AS GROUND TRUTH) ===");
            System.out.println("False positives (Bloom says suspicious, HashSet says not): " + falsePositives);
            System.out.println("False negatives (Bloom says NOT, HashSet says suspicious): " + falseNegatives);
            System.out.println("\nDone.");

        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    private static List<String> readLines(String filename) throws IOException {
        List<String> lines = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    lines.add(trimmed);
                }
            }
        }
        return lines;
    }

    private static List<String> extractEmailDomains(String filename) throws IOException {
        List<String> domains = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                String email = line.trim();
                if (!email.isEmpty()) {
                    String domain = extractDomainFromEmail(email);
                    if (domain != null) {
                        domains.add(domain);
                    }
                }
            }
        }
        return domains;
    }

    private static String extractDomainFromEmail(String email) {
        int atIndex = email.lastIndexOf('@');
        if (atIndex == -1 || atIndex == email.length() - 1) {
            return null;
        }
        return email.substring(atIndex + 1).toLowerCase().trim();
    }
}
