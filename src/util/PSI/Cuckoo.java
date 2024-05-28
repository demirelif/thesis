package util.PSI;

import java.util.List;
import java.util.Random;
import java.util.Arrays;
import java.math.BigInteger;

/** The cuckoo hashing class for the client */
public class Cuckoo {
    private static final int outputBits = 16;  // Example value, replace with actual value from parameters
    private static final int numberOfHashes = 4;  // Example value, replace with actual value from parameters
    private static final int maskOfPowerOf2 = (1 << outputBits) - 1;
    private static final int logNoHashes = (int) (Math.log(numberOfHashes) / Math.log(2)) + 1;

    private int numberOfBins;
    private int recursionDepth;
    private Integer[] dataStructure;
    private int insertIndex;
    private int depth;
    private int FAIL;
    private List<Long> hashSeed;

    public Cuckoo(List<Long> hashSeed) {
        this.numberOfBins = 1 << outputBits;
        this.recursionDepth = (int) (8 * Math.log(numberOfBins) / Math.log(2));
        this.dataStructure = new Integer[numberOfBins];
        Arrays.fill(this.dataStructure, null);
        this.insertIndex = new Random().nextInt(numberOfHashes);
        this.depth = 0;
        this.FAIL = 0;
        this.hashSeed = hashSeed;
    }

    public static Long location(Long seed, int item) {
        int itemLeft = item >> outputBits;
        int itemRight = item & maskOfPowerOf2;
        long hashItemLeft = murmurHash3(Integer.toString(itemLeft), seed) >>> (32 - outputBits);
        return hashItemLeft ^ itemRight;
    }

    public static int leftAndIndex(int item, int index) {
        return ((item >> outputBits) << logNoHashes) + index;
    }

    public static int extractIndex(int itemLeftAndIndex) {
        return itemLeftAndIndex & ((1 << logNoHashes) - 1);
    }

    public static int reconstructItem(int itemLeftAndIndex, int currentLocation, int seed) {
        int itemLeft = itemLeftAndIndex >> logNoHashes;
        int hashedItemLeft = (int) (murmurHash3(Integer.toString(itemLeft), (long) seed) >>> (32 - outputBits));
        int itemRight = hashedItemLeft ^ currentLocation;
        return (itemLeft << outputBits) + itemRight;
    }

    public static int randPoint(int bound, int i) {
        Random rand = new Random();
        int value;
        do {
            value = rand.nextInt(bound);
        } while (value == i);
        return value;
    }

    public void insert(int item) {
        int currentLocation = Math.toIntExact(location(hashSeed.get(insertIndex), item));
        Integer currentItem = dataStructure[currentLocation];
        dataStructure[currentLocation] = leftAndIndex(item, insertIndex);

        if (currentItem == null) {
            insertIndex = new Random().nextInt(numberOfHashes);
            depth = 0;
        } else {
            int unwantedIndex = extractIndex(currentItem);
            insertIndex = randPoint(numberOfHashes, unwantedIndex);
            if (depth < recursionDepth) {
                depth++;
                int jumpingItem = reconstructItem(currentItem, currentLocation, Math.toIntExact(hashSeed.get(unwantedIndex)));
                insert(jumpingItem);
            } else {
                FAIL = 1;
            }
        }
    }

    public int getNumberOfBins(){
        return numberOfBins;
    }

    public Integer[] getDataStructure() {
        return dataStructure;
    }

    private static Long murmurHash3(String key, Long seed) {
        // TODO Implement MurmurHash3 or use an existing library
        // This is a placeholder implementation
        // Example: https://github.com/explosion/srsly/blob/master/srsly/_hash.pyx
        Long h = seed;
        for (char c : key.toCharArray()) {
            h = h * 31 + c;
        }
        return h;
    }

}

