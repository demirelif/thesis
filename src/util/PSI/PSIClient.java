package util.PSI;

import edu.alibaba.mpc4j.crypto.fhe.*;
import edu.alibaba.mpc4j.crypto.fhe.KeyGenerator;
import edu.alibaba.mpc4j.crypto.fhe.context.EncryptionParameters;
import edu.alibaba.mpc4j.crypto.fhe.context.SchemeType;
import edu.alibaba.mpc4j.crypto.fhe.context.SealContext;
import edu.alibaba.mpc4j.crypto.fhe.modulus.CoeffModulus;
import edu.alibaba.mpc4j.crypto.fhe.modulus.Modulus;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import static com.google.common.graph.Graphs.transpose;
import static util.PSI.AuxiliaryFunctions.windowing;

// Performs Cuckoo hashing
public class PSIClient {
    private ArrayList<Integer> elements;
    private static int port = 4470;
    EncryptionParameters params = new EncryptionParameters(SchemeType.BFV);
    Modulus plainModulus = new Modulus(1 << 6);
    private SealContext context;
    private KeyGenerator keygen;
    private PublicKey pk;
    Encryptor encryptor;
    Decryptor decryptor;
    Socket client;
    OutputStream outputStream;
    InputStream inputStream;
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

    protected PSIClient(ArrayList<Integer> elements) {
        this.elements = elements;
        try {
            client = new Socket("localhost", 4470);
            inputStream = client.getInputStream();
            outputStream = client.getOutputStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void clientOnline(List<Long> messageIDs) throws IOException {
        int logNoOfHashes = (int) (Math.log(Parameters.NUMBER_OF_HASHES)) + 1;
        int base = (int) Math.pow(2, Parameters.ELL);
        int miniBinCaapacity = Parameters.BIN_CAPACITY / Parameters.ALPHA;
        int log2 = (int) (Math.log(miniBinCaapacity) / Math.log(2));
        int logBELL = log2 / Parameters.ELL + 1;
        int dummyMessageClient = (int) Math.pow(2, (Parameters.SIGMA_MAX - Parameters.OUTPUT_BITS + logNoOfHashes));
        try {
            ServerSocket serverSocket = new ServerSocket(port);
        }
        catch (Exception e){
            System.out.println("Expection in Client Online");
        }

        // Setting the private and public contexts for the BFV Homomorphic Encryption scheme
        EncryptionParameters parameters = getParameters();
        BatchEncoder batchEncoder = new BatchEncoder(context);

        // Ensure the plainVec array is large enough to hold all batched data
        long[] plainVec = new long[batchEncoder.slotCount()];
        for (int i = 0; i < plainVec.length && i < messageIDs.size(); i++) {
            plainVec[i] = messageIDs.get(i);
        }

        Plaintext plain = new Plaintext();
        batchEncoder.encode(plainVec, plain);

        Ciphertext encrypted = new Ciphertext();
        context = new SealContext(parameters, false, CoeffModulus.SecLevelType.NONE);
        keygen = new KeyGenerator(context);

        PublicKey pk = new PublicKey();
        keygen.createPublicKey(pk);

        Encryptor encryptor = new Encryptor(context, pk);
        Decryptor decryptor = new Decryptor(context, keygen.secretKey());
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

        int[] plain_query = new int[windowedItems.size()];
        int[][][] enc_query = new int[base - 1][logBELL][windowedItems.size()];

        // Create batched query to be sent to the server
        for (int j = 0; j < logBELL; j++) {
            for (int i = 0; i < base - 1; i++) {
                if ((i + 1) * Math.pow(base, j) - 1 < miniBinCaapacity) {
                    for (int k = 0; k < windowedItems.size(); k++) {
                        plain_query[k] = windowedItems.get(k)[i][j];
                    }
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


}
