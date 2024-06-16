package util.PSI;

import edu.alibaba.mpc4j.crypto.fhe.*;
import edu.alibaba.mpc4j.crypto.fhe.KeyGenerator;
import edu.alibaba.mpc4j.crypto.fhe.context.EncryptionParameters;
import edu.alibaba.mpc4j.crypto.fhe.context.SchemeType;
import edu.alibaba.mpc4j.crypto.fhe.context.SealContext;
import edu.alibaba.mpc4j.crypto.fhe.modulus.CoeffModulus;

import java.math.BigInteger;
import java.util.*;

public class PSI {
    private int batchSize = 3;
    PSIClient psiClient;
    PSIServer psiServer;
    private SealContext context;
    private KeyGenerator keyGen;
    private Evaluator evaluator;

    public PSI() {
    }

    public void addPSIClient(PSIClient psiClient) {
        if ( this.psiClient == null ){
            this.psiClient = psiClient;
        } else {
            System.err.println("Already have a PSI Client");
        }
    }

    public void addPSIServer(PSIServer psiServer) {
        if ( this.psiServer == null ){
            this.psiServer = psiServer;
        } else {
            System.err.println("Already have a PSI Server");
        }
    }

    public void addContext(SealContext context){
        this.context = context;
    }

    public void addKeyGenerator(KeyGenerator keyGenerator){
        this.keyGen = keyGenerator;
    }

    public void competeIntersection(){
        if ( psiClient == null || psiServer == null){
            System.err.println("PSIClient or PSIServer is null");
        }
        else {
                System.out.println("Client has " + psiClient.getStream().size() + " MAC addresses");
                System.out.println("Server has " + psiServer.getStream().size() + " MAC addresses");

                Set<Integer> intersection = new HashSet<>(psiClient.getStream());
                intersection.retainAll(psiServer.getStream());
                System.out.println("The total number of unique nodes " + intersection.size());
            }
    }

    public void homomorphicOperations(List<Integer> clientSet, Ciphertext serverCiphertext){
        long[] setArray = new long[clientSet.size()];
        for ( int i = 0; i < clientSet.size(); i++){
            setArray[i] = (long) clientSet.get(i);
        }

        List<Plaintext> clientPlaintexts = new ArrayList<>();
        for ( int i = 0; i < setArray.length; i+= batchSize){
            // Determine the end index of the current batch
            int end = Math.min(i + batchSize, setArray.length);

            // Create a batch from locations_bob
            long[] batch = Arrays.copyOfRange(setArray, i, end);

            // Add the batch to the list
            Plaintext plaintext = new Plaintext();
            plaintext.set(batch);
            clientPlaintexts.add(plaintext);
        }
        int counter = 0;
        evaluator = new Evaluator(context);

        for (Plaintext plaintext : clientPlaintexts) {
            Ciphertext finalProduct = new Ciphertext();
            evaluator.subPlain(serverCiphertext, plaintext, finalProduct);

        }

    }

    public void competeEncryptedIntersection(){
        if ( psiClient == null || psiServer == null){
            System.err.println("PSIClient or PSIServer is null");
            return;
        }
        psiServer.serverOnline(psiClient.getEncryptedStream());
        System.out.println("Client has " + psiClient.getEncryptedStream().size() + " MAC addresses");
        System.out.println("Server has " + psiServer.getEncryptedStream().size() + " MAC addresses");

        System.out.println("Sigma-MAX from client " + psiClient.getEncryptedStream().get(0));
        System.out.println("Sigma-MAX from server " + psiServer.getEncryptedStream().get(0));

        Set<List<BigInteger>> intersection = new HashSet<>(psiClient.getEncryptedStream());
        intersection.retainAll(psiServer.getEncryptedStream());
        System.out.println(intersection);
        System.out.println("The total number of unique nodes " + intersection.size());

    }

    private static EncryptionParameters getEncryptionParameters(){
        EncryptionParameters parameters = new EncryptionParameters(SchemeType.BFV);
        parameters.setPolyModulusDegree(64);
        parameters.setCoeffModulus(CoeffModulus.create(64, new int[]{40}));
        // t must be a prime number and t mod 2n = 1, then we can us batch encode
        parameters.setPlainModulus(257);
        return parameters;
    }
}
