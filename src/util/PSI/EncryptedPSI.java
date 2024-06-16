package util.PSI;

import edu.alibaba.mpc4j.crypto.fhe.*;
import edu.alibaba.mpc4j.crypto.fhe.KeyGenerator;
import edu.alibaba.mpc4j.crypto.fhe.context.EncryptionParameters;
import edu.alibaba.mpc4j.crypto.fhe.context.SchemeType;
import edu.alibaba.mpc4j.crypto.fhe.context.SealContext;
import edu.alibaba.mpc4j.crypto.fhe.modulus.CoeffModulus;
import util.paillier.Paillier;

import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class EncryptedPSI {
    // these are shared
    private SealContext context;
    private KeyGenerator keygen;


    // Function to generate polynomial coefficients from roots
    public static List<BigInteger> coeffsFromRoots(List<BigInteger> roots, BigInteger modulus) {
        BigInteger[] coefficients = new BigInteger[] {BigInteger.ONE};

        for (BigInteger root : roots) {
            coefficients = convolve(coefficients, new BigInteger[] {BigInteger.ONE, root.negate()}, modulus);
        }

        List<BigInteger> result = new ArrayList<>();
        for (BigInteger coeff : coefficients) {
            result.add(coeff.mod(modulus));
        }

        return result;
    }

    // Helper function to perform convolution and modulus operation
    private static BigInteger[] convolve(BigInteger[] a, BigInteger[] b, BigInteger modulus) {
        BigInteger[] result = new BigInteger[a.length + b.length - 1];

        for (int i = 0; i < result.length; i++) {
            result[i] = BigInteger.ZERO;
        }

        for (int i = 0; i < a.length; i++) {
            for (int j = 0; j < b.length; j++) {
                result[i + j] = result[i + j].add(a[i].multiply(b[j])).mod(modulus);
            }
        }

        return result;
    }

    // Evaluate the polynomial at a given point x using Horner's method
    private static BigInteger evaluatePolynomial(List<BigInteger> coeffs, BigInteger x, BigInteger modulus) {
        BigInteger result = BigInteger.ZERO;
        for (int i = coeffs.size() - 1; i >= 0; i--) {
            result = result.multiply(x).add(coeffs.get(i)).mod(modulus);
        }
        return result;
    }

    // Helper function to convert ECPoint to BigInteger (simplified example)
    private static BigInteger ecPointToBigInteger(ECPoint point) {
        return point.getAffineX().add(point.getAffineY());
    }

    // Simple PSI algorithm with encrypted sets
    public static Set<BigInteger> encryptedPSI(List<BigInteger> serverList, List<BigInteger> clientList, BigInteger modulus, ECPoint evaluationPoint) {
        Set<BigInteger> serverSet = new HashSet<>(serverList);
        Set<BigInteger> clientSet = new HashSet<>(clientList);

        EncryptionParameters parameters = getParametersForClient();
        List<Ciphertext> encryptedClientSet = new ArrayList<>();
        parameters.setPolyModulusDegree(64);
        parameters.setCoeffModulus(CoeffModulus.create(64, new int[]{40}));
        // t must be a prime number and t mod 2n = 1, then we can us batch encode
        parameters.setPlainModulus(257);
        SealContext context;
        KeyGenerator keygen;
        context = new SealContext(parameters, false, CoeffModulus.SecLevelType.NONE);
        keygen = new KeyGenerator(context);
        PublicKey pk = new PublicKey();
        keygen.createPublicKey(pk);
        // Convert ECPoint to BigInteger
        BigInteger evalPoint = ecPointToBigInteger(evaluationPoint);

        // Encrypt server set
        List<BigInteger> encryptedServerSet = new ArrayList<>();
        for (BigInteger elem : serverSet) {
           // encryptedServerSet.add(paillier.encrypt(elem));
        }

        // Encrypt client set
       // Create plaintext


        Encryptor encryptor = new Encryptor(context, pk);
        BatchEncoder batchEncoder = new BatchEncoder(context);

        // Ensure the plainVec array is large enough to hold all batched data
        long[] plainVec = new long[batchEncoder.slotCount()];
        for (int i = 0; i < plainVec.length && i < clientList.size(); i++) {
            plainVec[i] = clientList.get(i).intValue();
            // TODO problematic code
        }

        Plaintext plain = new Plaintext();
        batchEncoder.encode(plainVec, plain);
        System.out.println("Plaintext: " + plain);
        Ciphertext ciphertext = new Ciphertext();
        encryptor.encrypt(plain, ciphertext);
        encryptedClientSet.add(ciphertext);

        // All into 1 cipher text
        System.out.println("Ciphertext: " + ciphertext);
        return null;
    }

    private static EncryptionParameters getParametersForClient(){
        EncryptionParameters parameters = new EncryptionParameters(SchemeType.BFV);
        parameters.setPolyModulusDegree(64);
        parameters.setCoeffModulus(CoeffModulus.create(64, new int[]{40}));
        // t must be a prime number and t mod 2n = 1, then we can us batch encode
        parameters.setPlainModulus(257);
        return parameters;
    }

}
