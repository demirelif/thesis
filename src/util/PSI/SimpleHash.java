package util.PSI;

import edu.alibaba.mpc4j.crypto.fhe.utils.HashFunction;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class SimpleHash {

    private static final int output_bits = 13; // Example value, replace with actual value
    private static final int number_of_hashes = 3; // Example value, replace with actual value
    private static final int bin_capacity = 536; // Example value, replace with actual value
    private static final int log_no_hashes = (int) (Math.log(number_of_hashes) / Math.log(2)) + 1;
    private static final int mask_of_power_of_2 = (1 << output_bits) - 1;

    private final int no_bins;
    private final BigInteger[][] simple_hashed_data;
    private final int[] occurrences;
    private int FAIL;
    private final List<Long> hash_seeds;

    public SimpleHash(List<Long> hash_seeds) {
        this.no_bins = 1 << output_bits;
        this.simple_hashed_data = new BigInteger[no_bins][bin_capacity];
        for (int i = 0; i < no_bins; i++) {
            Arrays.fill(this.simple_hashed_data[i], null);
        }
        this.occurrences = new int[no_bins];
        Arrays.fill(this.occurrences, 0);
        this.FAIL = 0;
        this.hash_seeds = hash_seeds;
    }

    public void insert(BigInteger item, int i) {
        int loc = location(hash_seeds.get(i), item);
        if (occurrences[loc] < bin_capacity) {
            simple_hashed_data[loc][occurrences[loc]] = leftAndIndex(item, i);
            occurrences[loc]++;
        } else {
            FAIL = 1;
            System.out.println("Simple hashing aborted");
        }
    }

    private static BigInteger leftAndIndex(BigInteger item, int index) {
        return item.shiftRight(output_bits).shiftLeft(log_no_hashes).add(BigInteger.valueOf(index));
    }

    private static int location(long seed, BigInteger item) {
        long itemLeft = item.shiftRight(output_bits).longValue();
        int itemRight = item.and(BigInteger.valueOf(mask_of_power_of_2)).intValue();

        // TODO this method is problematic since it is laking murmur hashing
        return (int) (itemLeft ^ itemRight);
    }

    public static void main(String[] args) {
        // Example usage
        List<Long> seeds = Arrays.asList(123456789L, 10111213141516L, 17181920212223L);
        SimpleHash sh = new SimpleHash(seeds);

        // Test inserting some items
        sh.insert(BigInteger.valueOf(123456789), 0);
        sh.insert(BigInteger.valueOf(987654321), 1);
        // Add more test cases as needed
    }

    public BigInteger[][] getSimpleHashedData(){
        return simple_hashed_data;
    }
}

