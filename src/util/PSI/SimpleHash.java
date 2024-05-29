package util.PSI;


import java.util.List;
import java.util.Random;
import java.util.Arrays;
import java.math.BigInteger;
import com.google.common.hash.Hashing;
import com.google.common.hash.Hasher;

public class SimpleHash {

    private static final int LOG_NO_HASHES = (int) (Math.log(Parameters.NUMBER_OF_HASHES) / Math.log(2)) + 1;
    private static final int MASK_OF_POWER_OF_2 = (1 << Parameters.OUTPUT_BITS) - 1;

    private final int noBins;
    private final int[][] simpleHashedData;
    private final int[] occurrences;
    private final List<Long> hashSeed; // Using long for hashSeed
    private int FAIL;
    private final int binCapacity;

    public SimpleHash(List<Long> hashSeed) {
        this.noBins = (1 << Parameters.OUTPUT_BITS);
        this.simpleHashedData = new int[noBins][Parameters.BIN_CAPACITY];
        for (int[] row : simpleHashedData) {
            Arrays.fill(row, -1); // Initialize with -1 to represent empty
        }
        this.occurrences = new int[noBins];
        this.hashSeed = hashSeed;
        this.binCapacity = Parameters.BIN_CAPACITY;
        this.FAIL = 0;
    }

    private static int leftAndIndex(BigInteger item, int index) {
        return ((item.shiftRight(Parameters.OUTPUT_BITS).intValue()) << LOG_NO_HASHES) + index;
    }

    private static int location(long seed, int item) {
        BigInteger bigItem = new BigInteger(String.valueOf(item));
        int itemLeft = bigItem.shiftRight(Parameters.OUTPUT_BITS).intValue();
        int itemRight = bigItem.and(BigInteger.valueOf(MASK_OF_POWER_OF_2)).intValue();
        Hasher hasher = Hashing.murmur3_32((int) (seed ^ (seed >>> 32))).newHasher(); // Handle long seed
        hasher.putInt(itemLeft);
        int hashItemLeft = hasher.hash().asInt() >>> (32 - Parameters.OUTPUT_BITS);
        return hashItemLeft ^ itemRight;
    }

    public void insert(int item, int i) {
        BigInteger bigItem = new BigInteger(String.valueOf(item));
        int loc = location(hashSeed.get(i), item);
        if (occurrences[loc] < binCapacity) {
            simpleHashedData[loc][occurrences[loc]] = leftAndIndex(bigItem, i);
            occurrences[loc]++;
        } else {
            FAIL = 1;
            System.out.println("Simple hashing aborted");
        }
    }

    public int[][] getSimpleHashedData() {
        return simpleHashedData;
    }
}
