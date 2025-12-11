import java.util.BitSet;

public class BloomFilter {

    private final BitSet bitSet;
    private final int bitSize;
    private final int numHashFunctions;

    public BloomFilter(int bitSize, int numHashFunctions) {
        this.bitSize = bitSize;
        this.numHashFunctions = numHashFunctions;
        this.bitSet = new BitSet(bitSize);
    }

    public void add(String element) {
        if (element == null) return;
        String value = element.toLowerCase().trim();
        long hash1 = hash1(value);
        long hash2 = hash2(value);

        for (int i = 0; i < numHashFunctions; i++) {
            long combined = (hash1 + i * hash2 + i * i);
            int index = (int) (Math.abs(combined) % bitSize);
            bitSet.set(index);
        }
    }

    public boolean contains(String element) {
        if (element == null) return false;
        String value = element.toLowerCase().trim();
        long hash1 = hash1(value);
        long hash2 = hash2(value);

        for (int i = 0; i < numHashFunctions; i++) {
            long combined = (hash1 + i * hash2 + i * i);
            int index = (int) (Math.abs(combined) % bitSize);
            if (!bitSet.get(index)) {
                return false;
            }
        }
        return true;
    }

    public int getBitSize() {
        return bitSize;
    }

    public int getNumHashFunctions() {
        return numHashFunctions;
    }

    private long hash1(String s) {
        return s.hashCode() & 0xffffffffL;
    }

    private long hash2(String s) {
        long hash = 0;
        long prime = 1099511628211L; // FNV-like prime
        for (int i = 0; i < s.length(); i++) {
            hash ^= s.charAt(i);
            hash *= prime;
        }
        return hash & 0xffffffffL;
    }

    public long approximateMemoryBytes() {
        // BitSet internally uses long[], but we can approximate by bitSize bits.
        return (long) Math.ceil(bitSize / 8.0);
    }
}
