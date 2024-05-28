package util.PSI;

import edu.alibaba.mpc4j.crypto.fhe.*;
import edu.alibaba.mpc4j.crypto.fhe.KeyGenerator;
import edu.alibaba.mpc4j.crypto.fhe.context.EncryptionParameters;
import edu.alibaba.mpc4j.crypto.fhe.context.SchemeType;
import edu.alibaba.mpc4j.crypto.fhe.context.SealContext;
import edu.alibaba.mpc4j.crypto.fhe.modulus.CoeffModulus;
import edu.alibaba.mpc4j.crypto.fhe.modulus.Modulus;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;

import static com.google.common.graph.Graphs.transpose;

// Performs Cuckoo hashing
public class PSIClient extends AbstractPSIClient implements Client {
    private static int port = 4470;
    EncryptionParameters params = new EncryptionParameters(SchemeType.BFV);
    Modulus plainModulus = new Modulus(1 << 6);
    private SealContext context;
    private KeyGenerator keygen;
    private PublicKey pk;
    Encryptor encryptor;
    Decryptor decryptor;

    protected PSIClient(ArrayList elements) {
        super(elements);
    }

    private void clientOnline(List<Long> messageIDs) throws IOException {
        int logNoOfHashes = (int) (Math.log(Parameters.NUMBER_OF_HASHES)) + 1;
        int base = 2 * Parameters.ELL;
        int miniBinCaapacity = Parameters.BIN_CAPACITY / Parameters.ALPHA;
        int log2 = (int) (Math.log(miniBinCaapacity) / Math.log(2));
        int logBELL = log2 / Parameters.ELL + 1;
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
    }

    private EncryptionParameters getParameters(){
        EncryptionParameters parameters = new EncryptionParameters(SchemeType.BFV);
        parameters.setPolyModulusDegree(64);
        parameters.setCoeffModulus(CoeffModulus.create(64, new int[]{40}));
        // t must be a prime number and t mod 2n = 1, then we can us batch encode
        parameters.setPlainModulus(257);
        return parameters;
    }

    /** Each PRFed item from the client set is mapped to a Cuckoo hash table */
    private void CuckooHashing(){
    }
}
