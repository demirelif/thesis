package util;

import edu.alibaba.mpc4j.crypto.fhe.*;
import edu.alibaba.mpc4j.crypto.fhe.context.EncryptionParameters;
import edu.alibaba.mpc4j.crypto.fhe.context.SchemeType;
import edu.alibaba.mpc4j.crypto.fhe.context.SealContext;
import edu.alibaba.mpc4j.crypto.fhe.modulus.CoeffModulus;
import org.checkerframework.checker.units.qual.C;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class PrivateSetIntersection {
    private static SealContext context;
    private static BatchEncoder batchEncoder;
    private static Encryptor encryptor;
    private static Decryptor decryptor;
    private static Evaluator evaluator;
    private static final int batchSize = 1;

    public static void main(String[] args) throws Exception {
        setup();

        // Sample data
        List<Integer> elementsAlice = Arrays.asList(5,3);
        List<Integer> elementsBob = Arrays.asList(3,5);

        // Step 2: Alice encrypts her elements
        Ciphertext setCiphertextsAlice = encryptStream(elementsAlice);

        // Step 3: Bob performs homomorphic operations
        List<String> finalProducts = homomorphicOperations(setCiphertextsAlice, elementsAlice.size(), elementsBob);

        // Step 4: Alice decrypts the intersection
        assert finalProducts != null;
        int intersectionSize = decryptIntersection(finalProducts, elementsAlice.size());

        System.out.println("Size of common elements: " + intersectionSize);
    }

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
        System.out.println("===============================\nSTEP 1: setup\n===============================");
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

    public static Ciphertext encryptStream(List<Integer> elementsAlice) {
        System.out.println("=========================\nSTEP 2: encrypt elements\n=========================");

        int[] setAlice = elementsAlice.stream().mapToInt(i -> i).toArray();
        long[] setAliceLong = new long[setAlice.length];
        for (int i = 0; i < setAlice.length; i++) {
            setAliceLong[i] = setAlice[i];
        }

        Plaintext setPlaintextsAlice = new Plaintext();
        batchEncoder.encode(setAliceLong, setPlaintextsAlice);

        Ciphertext setCiphertextsAlice = encryptor.encrypt(setPlaintextsAlice);

        System.out.println("Sending clients encrypted elements.");
        return setCiphertextsAlice;
    }

    // Step 3: Bob performs homomorphic operations
    public static List<String> homomorphicOperations(Ciphertext setCiphertextsAlice, int setAliceLength, List<Integer> elementsBob) {
        System.out.println("Participating as server");
        System.out.println("============================================\nSTEP 3: homomorphically compute intersection\n============================================");

        List<String> finalProducts = new ArrayList<>();
        try {
            List<int[]> setsPlaintextsBob = new ArrayList<>();
            for (int i = 0; i < elementsBob.size(); i += batchSize) {
                int end = Math.min(i + batchSize, elementsBob.size());
                int[] batch = elementsBob.subList(i, end).stream().mapToInt(Integer::intValue).toArray();
                setsPlaintextsBob.add(batch);
            }
            for (int[] setPlaintextsBob : setsPlaintextsBob) {
                Ciphertext finalProduct = new Ciphertext();

                int[] firstElementBob = new int[setAliceLength];
                Arrays.fill(firstElementBob, setPlaintextsBob[0]);
                long[] firstElementBobLong = new long[setAliceLength];
                for (int i = 0; i < firstElementBob.length; i++) {
                    firstElementBobLong[i] = firstElementBob[i];
                }
                Plaintext firstElementBobEncoded = new Plaintext();
                batchEncoder.encode(firstElementBobLong, firstElementBobEncoded);

                evaluator.subPlain(setCiphertextsAlice, firstElementBobEncoded, finalProduct);

                for (int i = 1; i < setPlaintextsBob.length; i++) {
                    int[] ithElementBob = new int[setAliceLength];
                    long[] ithElementBobLong = new long[setAliceLength];
                    Arrays.fill(ithElementBob, setPlaintextsBob[i]);
                    for (int j = 0; j < ithElementBob.length; j++) {
                        ithElementBobLong[j] = ithElementBob[j];
                    }
                    Plaintext ithElementBobEncoded = new Plaintext();
                    batchEncoder.encode(ithElementBobLong, ithElementBobEncoded);
                    Ciphertext temp = new Ciphertext();
                    evaluator.subPlain(setCiphertextsAlice, ithElementBobEncoded, temp);
                    evaluator.multiply(finalProduct, temp, finalProduct);
                }

                int[] randomPlaintext = new int[setAliceLength];
                SecureRandom random = new SecureRandom();
                for (int j = 0; j < randomPlaintext.length; j++) {
                    randomPlaintext[j] = random.nextInt();
                }
                long[] randomPlaintextLong = new long[setAliceLength];
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

    // Step 4: Alice decrypts the intersection
    public static int decryptIntersection(List<String> finalProducts, int setAliceLength) {
        System.out.println("Participating as client");
        System.out.println("================================\nSTEP 4: decrypting intersections\n================================\n(belongs to the intersection iff decryption equals 0 in at least one batch)");

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

                for (int i = 0; i < setAliceLength; i++) {
                    if (decoded[i] == 0) {
                        counter++;
                    }
                }
            } catch (Exception e) {
                System.out.println(e.getMessage());
                return 0;
            }
        }

        System.out.println("Finished PSI");
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
