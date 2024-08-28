package util.PSI;

import edu.alibaba.mpc4j.crypto.fhe.*;
import edu.alibaba.mpc4j.crypto.fhe.KeyGenerator;
import edu.alibaba.mpc4j.crypto.fhe.context.EncryptionParameters;
import edu.alibaba.mpc4j.crypto.fhe.context.SchemeType;
import edu.alibaba.mpc4j.crypto.fhe.context.SealContext;
import edu.alibaba.mpc4j.crypto.fhe.modulus.CoeffModulus;
import util.PrivateSetIntersection;

import java.util.*;

public class PSI {
    PSIClient psiClient;
    PSIServer psiServer;
    private SealContext context;
    private KeyGenerator keyGen;
    private Evaluator evaluator;
    private Ciphertext ciphertext;

    public PSI() {
    }

    public void createServer(){
        psiServer = new PSIServer();
    }

    public void createClient(){
        try {
            PrivateSetIntersection.setup();
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }

        psiClient = new PSIClient();
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

    public PSIServer getPSIServer(){
        return this.psiServer;
    }

    public PSIClient getPSIClient(){
        return this.psiClient;
    }

    public void addContext(SealContext context){
        this.context = context;
    }

    public void addKeyGenerator(KeyGenerator keyGenerator){
        this.keyGen = keyGenerator;
    }


    public int competeEncryptedIntersection(){
        try {
            PrivateSetIntersection.setup();
            List<String> finalProducts = PrivateSetIntersection.homomorphicOperations(psiClient.getCiphertext(), psiClient.getStreamLength(), psiServer.getStream());
            assert finalProducts != null;
            // Client decrypts intersection
            int intersectionSize = PrivateSetIntersection.decryptIntersection(finalProducts, psiClient.getStreamLength());
            return intersectionSize;

        } catch (Exception e) {
            System.err.println(e.getMessage());
            return 0;
        }
    }

    public int competeEncryptedIntersectionForBigList(){
        try {
            PrivateSetIntersection.setup();
            int intersectionSize = 0;
            for ( Ciphertext cp : psiClient.getCiphertexts() ){
                List<String> finalProducts = PrivateSetIntersection.homomorphicOperations(cp, Parameters.BIN_CAPACITY, psiServer.getStream());
                assert finalProducts != null;
                // Client decrypts intersection
                intersectionSize += PrivateSetIntersection.decryptIntersection(finalProducts, Parameters.BIN_CAPACITY);
            }
            return intersectionSize;

        } catch (Exception e) {
            System.err.println(e.getMessage());
            return 0;
        }
    }

    public void competeEncryptedIntersection(Ciphertext clientCipherText){
        try {
            PrivateSetIntersection.setup();
            List<String> finalProducts = PrivateSetIntersection.homomorphicOperations(clientCipherText, 3, psiServer.getStream());
            assert finalProducts != null;
            // Client decrypts intersection
            int intersectionSize = PrivateSetIntersection.decryptIntersection(finalProducts, 3);

        } catch (Exception e) {
            System.err.println(e.getMessage());
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
