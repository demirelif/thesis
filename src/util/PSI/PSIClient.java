package util.PSI;

import edu.alibaba.mpc4j.crypto.fhe.*;
import edu.alibaba.mpc4j.crypto.fhe.KeyGenerator;
import edu.alibaba.mpc4j.crypto.fhe.context.EncryptionParameters;
import edu.alibaba.mpc4j.crypto.fhe.context.SchemeType;
import edu.alibaba.mpc4j.crypto.fhe.context.SealContext;
import edu.alibaba.mpc4j.crypto.fhe.modulus.CoeffModulus;
import edu.alibaba.mpc4j.crypto.fhe.modulus.Modulus;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.custom.sec.SecP192R1Curve;
import util.Hash.SimpleHash;
import util.OPRF;
import util.PrivateSetIntersection;

import java.io.*;
import java.math.BigInteger;
import java.util.*;

import static com.google.common.graph.Graphs.transpose;
import static util.PSI.AuxiliaryFunctions.windowing;

// Performs Cuckoo hashing
public class PSIClient {
    public boolean isSmallSet;
    private static final ECCurve CURVE_USED = new SecP192R1Curve();
    private static ECPoint G = CURVE_USED.createPoint(
            new BigInteger("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16),
            new BigInteger("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16)
    );

    BigInteger OPRFClientKey = new BigInteger("9876543210"); // Example key, replace with actual logic
    BigInteger ORDER_OF_GENERATOR = Parameters.ORDER_OF_GENERATOR;
    ECPoint clientPointPrecomputed = new FixedPointCombMultiplier().multiply(G, OPRFClientKey.mod(ORDER_OF_GENERATOR));

    List<Ciphertext> ciphertexts = new ArrayList<>();

    /** This hash table is needed when the client's set is too large for homomorphic calculations */
    Integer[][] hashTable;

    private ArrayList<Integer> elements;
    private static final int modulusDegree = 64;
    EncryptionParameters params = new EncryptionParameters(SchemeType.BFV);
    Modulus plainModulus = new Modulus(1 << 6);
   // private SealContext context;
    private KeyGenerator keygen;
    private PublicKey pk;
    private List<Integer> stream;
    Encryptor encryptor;
    Decryptor decryptor;
    OutputStream outputStream;
    InputStream inputStream;
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

    List<List<BigInteger>> encryptedStream;
    private Ciphertext ciphertext;

    public PSIClient() {

    }

    public void addStream(List<Integer> stream){
        this.stream = stream;
        if ( this.stream.size() > Parameters.BIN_CAPACITY ){
            isSmallSet = false;
        } else {
            isSmallSet = true;
        }
    }

    public void addEncryptedStream(List<List<BigInteger>> stream){
        this.encryptedStream = stream;
    }

    public int getStreamLength(){
        return stream.size();
    }
    /** Applying inverse of the secret key, OPRFClientKey */
    public void finalizeOPRF(BigInteger OPRFClientKey, List<List<BigInteger>> PRFedEncodedClientSet ) {
        // Computing the inverse of the secret key
        BigInteger keyInverse = OPRFClientKey.modInverse( OPRF.getOrderOfGenerator() );
        try {
            List<BigInteger> PRFedClientSet = OPRF.clientPrfOnlineParallel(keyInverse, PRFedEncodedClientSet);
            System.out.println("OPRF protocol successful");
            System.out.println("keyInverse: " + keyInverse);
        } catch (Exception e ){
            System.err.println(e);
            System.out.println("OPRF protocol failed");
        }
    }

    protected List<Integer> getStream(){
        return this.stream;
    }

    public Ciphertext getCiphertext(){
        return PrivateSetIntersection.encryptStream(this.stream);
    }

    public List<Ciphertext> getCiphertexts(){
        List<Ciphertext> ciphertexts = new ArrayList<>();
        Integer[][] hashTable = getHashTable();

        for ( int i = 0; i < hashTable.length; i++ ){
            ciphertexts.add(PrivateSetIntersection.encryptStream(Arrays.asList(hashTable[i])));
        }
        return ciphertexts;
    }

    public Integer[][] getHashTable() {
        SimpleHash SH = new SimpleHash(this.stream.size() / Parameters.BIN_CAPACITY);
        SH.initializeHashTable((ArrayList<Integer>) this.stream);
        SH.printHashTable();
        return SH.getHashTable();
    }

    public List<List<BigInteger>> getEncryptedStream(){
        return this.encryptedStream;
    }

    public void clientOnline(ArrayList<Integer> messageIDs) throws IOException {
        int logNoOfHashes = (int) (Math.log(Parameters.NUMBER_OF_HASHES)) + 1;
        int base = (int) Math.pow(2, Parameters.ELL);
        int miniBinCaapacity = Parameters.BIN_CAPACITY / Parameters.ALPHA;
        int log2 = (int) (Math.log(miniBinCaapacity) / Math.log(2));
        int logBELL = log2 / Parameters.ELL + 1;
        int dummyMessageClient = (int) Math.pow(2, (Parameters.SIGMA_MAX - Parameters.OUTPUT_BITS + logNoOfHashes));


        // Setting the private and public contexts for the BFV Homomorphic Encryption scheme
        EncryptionParameters parameters = getParameters();
        BatchEncoder batchEncoder = new BatchEncoder(PrivateSetIntersection.context);

        // Ensure the plainVec array is large enough to hold all batched data
        long[] plainVec = new long[batchEncoder.slotCount()];
        for (int i = 0; i < plainVec.length && i < messageIDs.size(); i++) {
            plainVec[i] = messageIDs.get(i);
        }

        Plaintext plain = new Plaintext();
        batchEncoder.encode(plainVec, plain);

        Ciphertext encrypted = new Ciphertext();
        keygen = new KeyGenerator(PrivateSetIntersection.context);

        PublicKey pk = new PublicKey();
        keygen.createPublicKey(pk);

        Encryptor encryptor = new Encryptor(PrivateSetIntersection.context, pk);
        Decryptor decryptor = new Decryptor(PrivateSetIntersection.context, keygen.secretKey());
        // Encryption - OPRFs
        encryptor.encrypt(plain, encrypted);

        Cuckoo CH = new Cuckoo(Parameters.HASH_SEEDS);
        for ( Integer element : elements ){
            CH.insert(element);
        }

        // Padd the Cuckoo vector with dummy messages for security
        for ( int i = 0; i < CH.getNumberOfBins(); i++ ){
            if ( CH.getDataStructure()[i] == null ){
                // TODO check syntax
                CH.getDataStructure()[i] = dummyMessageClient;
            }
        }

        // Windowing
        List<Integer[][]> windowedItems = new ArrayList<>();
        for ( Integer item : CH.getDataStructure() ){
            windowedItems.add( windowing( item, miniBinCaapacity, Parameters.PLAIN_MODULUS) );
        }

        int[] plainQuery = new int[windowedItems.size()];
        int[][][] encQuery = new int[base - 1][logBELL][windowedItems.size()];

        EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
        parms.setPolyModulusDegree(64);
        //parms.setPlainModulus(plainModulus);
        parms.setCoeffModulus(CoeffModulus.create(64, new int[]{40}));
        // t must be a prime number and t mod 2n = 1, then we can us batch encode
        parms.setPlainModulus(257);
        SealContext context = new SealContext(parms, false, CoeffModulus.SecLevelType.NONE);

        ArrayList<Plaintext> plaintexts = new ArrayList<>();
        // Create batched query to be sent to the server
        for (int j = 0; j < logBELL; j++) {
            for (int i = 0; i < base - 1; i++) {
                if ((i + 1) * Math.pow(base, j) - 1 < miniBinCaapacity) {
                    for (int k = 0; k < windowedItems.size(); k++) {
                        plainQuery[k] = windowedItems.get(k)[i][j];
                    }
                    Plaintext plaintext = BFVVector(context, plainQuery);
                    plaintexts.add(plaintext);
                    // encQuery[i][j] = BFVVector(context, plainQuery);
                    // Placeholder: Use appropriate method for creating BFV vector
                    // enc_query[i][j] = createBFVVector(privateContext, plain_query);
                }
            }
        }

        byte[][][] enc_query_serialized = new byte[base - 1][logBELL][];
        for (int j = 0; j < logBELL; j++) {
            for (int i = 0; i < base - 1; i++) {
                if ((i + 1) * Math.pow(base, j) - 1 < miniBinCaapacity) {
                    // Placeholder: Use appropriate method for serializing BFV vector
                    // enc_query_serialized[i][j] = serialize(enc_query[i][j]);
                }
            }
        }

        // Placeholder: Serialize public context
        // byte[] context_serialized = publicContext.serialize();
        byte[] context_serialized = new byte[0]; // Placeholder
        Object[] message_to_be_sent = {context_serialized, enc_query_serialized};
        byte[] message_to_be_sent_serialized = serialize(message_to_be_sent);

        long t1 = System.currentTimeMillis();
        int L = message_to_be_sent_serialized.length;
        String sL = String.format("%-10d", L);
        outputStream.write(sL.getBytes());
        outputStream.write(message_to_be_sent_serialized);
        System.out.println(" * Sending the context and ciphertext to the server....");

        // Wait for the server's answer
        byte[] buffer = new byte[10];
        inputStream.read(buffer);
        L = Integer.parseInt(new String(buffer).trim());

        byteArrayOutputStream.reset();
        while (byteArrayOutputStream.size() < L) {
            int bytesRead = inputStream.read(buffer);
            if (bytesRead == -1) break;
            byteArrayOutputStream.write(buffer, 0, bytesRead);
        }

        byte[] answer = byteArrayOutputStream.toByteArray();
        long t2 = System.currentTimeMillis();

        // Placeholder: Deserialize and decrypt the server's response
        // List<byte[]> ciphertexts = deserialize(answer);
        List<byte[]> ciphertexts = new ArrayList<>(); // Placeholder
        List<int[]> decryptions = new ArrayList<>();
        for (byte[] ct : ciphertexts) {
            // Placeholder: Decrypt the BFV vector
            // decryptions.add(decryptBFVVector(privateContext, ct));
        }

        List<Integer> recover_CH_structure = new ArrayList<>();
        for (Integer[][] matrix : windowedItems) {
            recover_CH_structure.add(matrix[0][0]);
        }

        int[] count = new int[Parameters.ALPHA];
        List<Integer> client_intersection = new ArrayList<>();

        Scanner g = new Scanner(new File("client_set"));
        List<String> client_set_entries = new ArrayList<>();
        while (g.hasNextLine()) {
            client_set_entries.add(g.nextLine());
        }
        g.close();

        for (int j = 0; j < Parameters.ALPHA; j++) {
            for (int i = 0; i < Parameters.POLY_MODULUS_DEGREE; i++) {
                if (decryptions.get(j)[i] == 0) {
                    count[j]++;
                    // Placeholder: Recover the element from the Cuckoo hash structure
                    // int PRFed_common_element = reconstruct_item(recover_CH_structure.get(i), i, hash_seeds[recover_CH_structure.get(i) % (int) Math.pow(2, log_no_hashes)]);
                    int PRFed_common_element = 0; // Placeholder
                    int index = elements.indexOf(PRFed_common_element);
                    client_intersection.add(Integer.parseInt(client_set_entries.get(index).trim()));
                }
            }
        }

        Scanner h = new Scanner(new File("intersection"));
        List<Integer> real_intersection = new ArrayList<>();
        while (h.hasNextLine()) {
            real_intersection.add(Integer.parseInt(h.nextLine().trim()));
        }
        h.close();

        long t3 = System.currentTimeMillis();
        System.out.printf("\n Intersection recovered correctly: %b%n", client_intersection.equals(real_intersection));
        System.out.println("Disconnecting...\n");
    }

    private EncryptionParameters getParameters(){
        EncryptionParameters parameters = new EncryptionParameters(SchemeType.BFV);
        parameters.setPolyModulusDegree(64);
        parameters.setCoeffModulus(CoeffModulus.create(64, new int[]{40}));
        // t must be a prime number and t mod 2n = 1, then we can us batch encode
        parameters.setPlainModulus(257);
        return parameters;
    }

    // Utility method to serialize an object to byte array
    private static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(obj);
        objectOutputStream.close();
        return byteArrayOutputStream.toByteArray();
    }

    // Utility method to deserialize an object from byte array
    private static <T> T deserialize(byte[] data) throws IOException, ClassNotFoundException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(data);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        T obj = (T) objectInputStream.readObject();
        objectInputStream.close();
        return obj;
    }

    private Plaintext BFVVector(SealContext context, int[] plainQuery ){
        // TODO make sure to use correct numbers from parameters
        BatchEncoder batchEncoder = new BatchEncoder(context);

        // Ensure the plainVec array is large enough to hold all batched data
        long[] plainVec = new long[batchEncoder.slotCount()];
        for (int i = 0; i < plainVec.length && i < plainQuery.length; i++) {
            plainVec[i] = plainQuery[i];
        }

        Plaintext plain = new Plaintext();
        batchEncoder.encode(plainVec, plain);

        Ciphertext encrypted = new Ciphertext();
        keygen = new KeyGenerator(context);

        PublicKey pk = new PublicKey();
        keygen.createPublicKey(pk);

        Encryptor encryptor = new Encryptor(context, pk);
        Decryptor decryptor = new Decryptor(context, keygen.secretKey());
        // Encryption - OPRFs
        encryptor.encrypt(plain, encrypted);
        return plain;
    }

    public void addCiphertext(Ciphertext ciphertext) {
        this.ciphertext = ciphertext;

    }

    public void addCiphertextToList(Ciphertext cp) {
        this.ciphertexts.add(cp);
    }
}
