package util;

import edu.alibaba.mpc4j.crypto.fhe.*;
import edu.alibaba.mpc4j.crypto.fhe.context.EncryptionParameters;
import edu.alibaba.mpc4j.crypto.fhe.context.SchemeType;
import edu.alibaba.mpc4j.crypto.fhe.context.SealContext;
import edu.alibaba.mpc4j.crypto.fhe.modulus.CoeffModulus;
import org.checkerframework.checker.units.qual.C;
import util.Hash.SimpleHash;
import util.PSI.Parameters;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class PrivateSetIntersection {
    public static SealContext context;
    private static BatchEncoder batchEncoder;
    private static Encryptor encryptor;
    private static Decryptor decryptor;
    private static Evaluator evaluator;
    private static final int batchSize = 1;

    public static void createContext() {
        EncryptionParameters parameters = new EncryptionParameters(SchemeType.BFV);
        parameters.setPolyModulusDegree(64);
        parameters.setCoeffModulus(CoeffModulus.create(64, new int[]{40}));
        // t must be a prime number and t mod 2n = 1, then we can us batch encode
        parameters.setPlainModulus(257);
        // SealContext context = new SealContext(parms, false, CoeffModulus.SecLevelType.NONE);
        context = new SealContext(parameters, false, CoeffModulus.SecLevelType.NONE);
    }

    // Step 1: Setup
    public static void setup() throws Exception {
        createContext();
        batchEncoder = new BatchEncoder(context);
        KeyGenerator keyGenerator = new KeyGenerator(context);
        PublicKey publicKey = new PublicKey();
        keyGenerator.createPublicKey(publicKey);
        SecretKey secretKey = keyGenerator.secretKey();
        encryptor = new Encryptor(context, publicKey);
        decryptor = new Decryptor(context, secretKey);
        evaluator = new Evaluator(context);
    }

    private static List<Ciphertext> encryptSet(List<Integer> set){
        List<Ciphertext> ciphertexts = new ArrayList<>();
        for (int i = 0; i < set.size(); i++) {
            Plaintext plain = new Plaintext();
            plain.set(set.get(i));
            ciphertexts.add(encryptor.encrypt(plain));
        }
        System.out.println("Encrypted.");
        return ciphertexts;
    }

    public static Ciphertext encryptStream(List<Integer> elements) {
        int[] set = elements.stream().mapToInt(i -> i).toArray();
        long[] setLong = new long[set.length];
        for (int i = 0; i < set.length; i++) {
            setLong[i] = set[i];
        }

        Plaintext setPlaintexts = new Plaintext();
        batchEncoder.encode(setLong, setPlaintexts);

        return encryptor.encrypt(setPlaintexts);
    }

    /** For longer sets with size bigger than 8, this method should be used */
    public static List<List<String>> homomorphicOperationsForLongStreams(List<Ciphertext> setCiphertexts, int setClientLength, List<Integer> elementsServer) {
        List<List<String>> homomorphicOperations = new ArrayList<>();
        for (int i = 0; i < setCiphertexts.size(); i++) {
            List<String> operationResults = homomorphicOperations(setCiphertexts.get(i), setClientLength, elementsServer);
            homomorphicOperations.add(operationResults);
        }
        return homomorphicOperations;
    }

    // Step 3: Server performs homomorphic operations
    public static List<String> homomorphicOperations(Ciphertext setCiphertextsClient, int setClientLength, List<Integer> elementsServer) {
        List<String> finalProducts = new ArrayList<>();
        try {
            List<int[]> setsPlaintextsServer = new ArrayList<>();
            for (int i = 0; i < elementsServer.size(); i += batchSize) {
                int end = Math.min(i + batchSize, elementsServer.size());
                int[] batch = elementsServer.subList(i, end).stream().mapToInt(Integer::intValue).toArray();
                setsPlaintextsServer.add(batch);
            }
            for (int[] setPlaintextsServer : setsPlaintextsServer) {
                Ciphertext finalProduct = new Ciphertext();

                int[] firstElement = new int[setClientLength];
                Arrays.fill(firstElement, setPlaintextsServer[0]);
                long[] firstElementServerLong = new long[setClientLength];
                for (int i = 0; i < firstElement.length; i++) {
                    firstElementServerLong[i] = firstElement[i];
                }
                Plaintext firstElementServerEncoded = new Plaintext();
                batchEncoder.encode(firstElementServerLong, firstElementServerEncoded);

                evaluator.subPlain(setCiphertextsClient, firstElementServerEncoded, finalProduct);

                for (int i = 1; i < setPlaintextsServer.length; i++) {
                    int[] ithElement = new int[setClientLength];
                    long[] ithElementLong = new long[setClientLength];
                    Arrays.fill(ithElement, setPlaintextsServer[i]);
                    for (int j = 0; j < ithElement.length; j++) {
                        ithElementLong[j] = ithElement[j];
                    }
                    Plaintext ithElementEncoded = new Plaintext();
                    batchEncoder.encode(ithElementLong, ithElementEncoded);
                    Ciphertext temp = new Ciphertext();
                    evaluator.subPlain(setCiphertextsClient, ithElementEncoded, temp);
                    evaluator.multiply(finalProduct, temp, finalProduct);
                }

                int[] randomPlaintext = new int[setClientLength];
                SecureRandom random = new SecureRandom();
                for (int j = 0; j < randomPlaintext.length; j++) {
                    randomPlaintext[j] = random.nextInt();
                }
                long[] randomPlaintextLong = new long[setClientLength];
                for (int j = 0; j < randomPlaintextLong.length; j++) {
                    randomPlaintextLong[j] = (long) randomPlaintext[j];
                }
                Plaintext randomPlaintextEncoded = new Plaintext();
                batchEncoder.encode(randomPlaintextLong, randomPlaintextEncoded);
                evaluator.multiplyPlain(finalProduct, randomPlaintextEncoded, finalProduct);

                String finalProductString = Base64.getEncoder().encodeToString(finalProduct.save());
                finalProducts.add(finalProductString);
            }
            return finalProducts;
        } catch (Exception e) {
            System.err.println(e.getMessage());
            return null;
        }
    }

    // Step 4: Client decrypts the intersection
    public static int decryptIntersection(List<String> finalProducts, int setClientLength) {
        int counter = 0;
        List<Integer> intersectionIndexes = new ArrayList<>();
        for (String finalProduct : finalProducts) {
            Ciphertext finalProductCiphertext = new Ciphertext();
            try {
                byte[] decodedBytes = Base64.getDecoder().decode(finalProduct);
                finalProductCiphertext.load(context, decodedBytes);

                Plaintext decrypted = new Plaintext();
                decryptor.decrypt(finalProductCiphertext, decrypted);

                long[] decoded = new long[batchEncoder.slotCount()];
                batchEncoder.decode(decrypted, decoded);

                for (int i = 0; i < setClientLength; i++) {
                    if (decoded[i] == 0) {
                        counter++;
                    }
                }
            } catch (Exception e) {
                System.out.println(e.getMessage());
                return 0;
            }
        }

        return counter;
    }
}

// Utility class to hold pairs of values
class Pair<K, V> {
    private final K first;
    private final V second;

    public Pair(K first, V second) {
        this.first = first;
        this.second = second;
    }

    public K getFirst() {
        return first;
    }

    public V getSecond() {
        return second;
    }
}
