package util.PSI;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class Parameters {

    // Sizes of databases of server and client
    public static final int SERVER_SIZE = (int) Math.pow(2, 20);
    public static final int CLIENT_SIZE = 4000;
    public static final int INTERSECTION_SIZE = 3500;

   public static final BigInteger ORDER_OF_GENERATOR = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951");

    // Seeds used by both the Server and the Client for the hash functions
    public static final List<Long> HASH_SEEDS = Arrays.asList(123456789L, 10111213141516L, 17181920212223L);

    // Output bits: number of bits of output of the hash functions
    // Number of bins for simple/Cuckoo Hashing = 2 ** output_bits
    public static final int OUTPUT_BITS = 13;

    // Encryption parameters of the BFV scheme: the plain modulus and the polynomial modulus degree
    public static final int PLAIN_MODULUS = 536903681;
    public static final int POLY_MODULUS_DEGREE = (int) Math.pow(2, 13);

    // The number of hashes we use for simple/Cuckoo hashing
    public static final int NUMBER_OF_HASHES = 3;

    // Length of the database items
    public static final int SIGMA_MAX = (int) (Math.log(PLAIN_MODULUS) / Math.log(2)) + OUTPUT_BITS - ((int) (Math.log(NUMBER_OF_HASHES) / Math.log(2)) + 1);

    // B = [68, 176, 536, 1832, 6727] for log(server_size) = [16, 18, 20, 22, 24]
    public static final int BIN_CAPACITY = 536;

    // Partitioning parameter
    public static final int ALPHA = 16;

    // Windowing parameter
    public static final int ELL = 2;
}
