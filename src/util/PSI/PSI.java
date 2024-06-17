package util.PSI;

import edu.alibaba.mpc4j.crypto.fhe.*;
import edu.alibaba.mpc4j.crypto.fhe.KeyGenerator;
import edu.alibaba.mpc4j.crypto.fhe.context.EncryptionParameters;
import edu.alibaba.mpc4j.crypto.fhe.context.SchemeType;
import edu.alibaba.mpc4j.crypto.fhe.context.SealContext;
import edu.alibaba.mpc4j.crypto.fhe.modulus.CoeffModulus;
import util.PrivateSetIntersection;

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

    public void competeEncryptedIntersection(){
        try {
            PrivateSetIntersection.setup();

            // Client encrypts its elements
            Ciphertext ciphertext = PrivateSetIntersection.encryptStream(psiClient.getStream());

            // Server performs homomorphic operations
            List<String> finalProducts = PrivateSetIntersection.homomorphicOperations(ciphertext, psiClient.getStreamLength(), psiServer.getStream());

            assert finalProducts != null;

            // Client decrypts intersection
            int intersectionSize = PrivateSetIntersection.decryptIntersection(finalProducts, psiClient.getStreamLength());
            System.out.println("Intersection Size " + intersectionSize);

        } catch (Exception e){
            System.err.println(e);
        }
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
