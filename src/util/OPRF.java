package util;

import edu.alibaba.mpc4j.crypto.fhe.Ciphertext;
import edu.alibaba.mpc4j.crypto.fhe.context.SealContext;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.custom.sec.SecP192R1Curve;
import util.PSI.PSIServer;
import util.PSI.Parameters;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.*;

public class OPRF {
    private static final int NUMBER_OF_PROCESSES = 3;
    public static final int SIGMA_MAX = Parameters.SIGMA_MAX;
    public static final BigInteger MASK = BigInteger.valueOf((2L * SIGMA_MAX) - 1);
    private static final ECCurve CURVE_USED = new SecP192R1Curve();
    private static BigInteger primeOfCurveEquation = CURVE_USED.getField().getCharacteristic();
    private static BigInteger orderOfGenerator = CURVE_USED.getOrder();
    private static int logP = primeOfCurveEquation.bitLength();

    // Correct initialization of G using the generator point of the curve
    private static ECPoint G = CURVE_USED.createPoint(
            new BigInteger("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16),
            new BigInteger("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16)
    );

    public static List<BigInteger> clientPRFOfflineOld(String msgID, ECPoint point) {
        BigInteger msgBigIntID = new BigInteger(msgID);
        ECPoint P = point.multiply(msgBigIntID);
        // Extract the x and y coordinates of the resulting point
        BigInteger xItem = P.getAffineXCoord().toBigInteger();
        BigInteger yItem = P.getAffineYCoord().toBigInteger();
        // Return the coordinates as a list
        return Arrays.asList(xItem, yItem);
    }

    public static List<Integer> clientPrfOffline(List<Integer> vectorOfItems, ECPoint point) {
        List<ECPoint> vectorOfMultiples = new ArrayList<>();
        for (int item : vectorOfItems) {
            ECPoint resultPoint = point.multiply(BigInteger.valueOf(item)).normalize();
            vectorOfMultiples.add(resultPoint);
        }

        List<Integer> output = new ArrayList<>();
        for (ECPoint Q : vectorOfMultiples) {
            BigInteger xItem = Q.getAffineXCoord().toBigInteger();
            BigInteger shiftedXItem = xItem.shiftRight(logP - SIGMA_MAX - 10);
            BigInteger maskedXItem = shiftedXItem.and(MASK);
            output.add(maskedXItem.intValue());
        }

        return output;
    }

    public static List<Integer> serverPrfOffline(List<Integer> vectorOfItems, ECPoint point) {
        List<ECPoint> vectorOfMultiples = new ArrayList<>();
        for (int item : vectorOfItems) {
            ECPoint resultPoint = point.multiply(BigInteger.valueOf(item)).normalize();
            vectorOfMultiples.add(resultPoint);
        }

        List<Integer> output = new ArrayList<>();
        for (ECPoint Q : vectorOfMultiples) {
            BigInteger xItem = Q.getAffineXCoord().toBigInteger();
            BigInteger shiftedXItem = xItem.shiftRight(logP - SIGMA_MAX - 10);
            BigInteger maskedXItem = shiftedXItem.and(MASK);
            output.add(maskedXItem.intValue());
        }

        return output;
    }

    public static List<Integer> serverPrfOfflineParallel(List<Integer> vectorOfItems, ECPoint point) {
        int division = (vectorOfItems.size() + NUMBER_OF_PROCESSES - 1) / NUMBER_OF_PROCESSES;
        List<List<Integer>> inputs = new ArrayList<>();
        for (int i = 0; i < NUMBER_OF_PROCESSES; i++) {
            int start = i * division;
            int end = Math.min(start + division, vectorOfItems.size());
            if (start < end) {
                inputs.add(vectorOfItems.subList(start, end));
            }
        }

        List<Callable<List<Integer>>> tasks = new ArrayList<>();
        for (List<Integer> inputVec : inputs) {
            tasks.add(() -> serverPrfOffline(inputVec, point));
        }

        ExecutorService executor = Executors.newFixedThreadPool(NUMBER_OF_PROCESSES);
        List<Integer> finalOutput = new ArrayList<>();
        try {
            List<Future<List<Integer>>> futures = executor.invokeAll(tasks);
            for (Future<List<Integer>> future : futures) {
                finalOutput.addAll(future.get());
            }
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        } finally {
            executor.shutdown();
        }

        return finalOutput;
    }

    public static List<ECPoint> serverPrfOnlineParallel(BigInteger keyInverse, List<List<BigInteger>> vectorOfPairs) throws ExecutionException, InterruptedException {
        List<ECPoint> vectorOfPoints = new ArrayList<>();
        for (List<BigInteger> pair : vectorOfPairs) {
            ECPoint point = CURVE_USED.createPoint(pair.get(0), pair.get(1));
            vectorOfPoints.add(point);
        }

        int division = vectorOfPoints.size() / NUMBER_OF_PROCESSES;
        List<List<ECPoint>> inputs = new ArrayList<>();
        for (int i = 0; i < NUMBER_OF_PROCESSES; i++) {
            inputs.add(new ArrayList<>(vectorOfPoints.subList(i * division, Math.min((i + 1) * division, vectorOfPoints.size()))));
        }

        if (vectorOfPoints.size() % NUMBER_OF_PROCESSES != 0) {
            inputs.add(new ArrayList<>(vectorOfPoints.subList(NUMBER_OF_PROCESSES * division, vectorOfPoints.size())));
        }

        ExecutorService executorService = Executors.newFixedThreadPool(NUMBER_OF_PROCESSES);
        List<Future<List<ECPoint>>> futures = new ArrayList<>();

        for (List<ECPoint> input : inputs) {
            Callable<List<ECPoint>> task = () -> {
                List<ECPoint> result = new ArrayList<>();
                for (ECPoint point : input) {
                    result.add(point.multiply(keyInverse));
                }
                return result;
            };
            futures.add(executorService.submit(task));
        }

        List<ECPoint> finalOutput = new ArrayList<>();
        for (Future<List<ECPoint>> future : futures) {
            finalOutput.addAll(future.get());
        }

        executorService.shutdown();
        return finalOutput;
    }

    public static List<BigInteger> clientPrfOnline(BigInteger keyInverse, List<List<BigInteger>> vectorOfPairs) {
        List<ECPoint> vectorOfPoints = new ArrayList<>();
        for (List<BigInteger> pair : vectorOfPairs) {
            ECPoint point = CURVE_USED.createPoint(pair.get(0), pair.get(1));
            vectorOfPoints.add(point);
        }

        List<ECPoint> vectorKeyInversePoints = new ArrayList<>();
        for (ECPoint point : vectorOfPoints) {
            ECPoint resultPoint = point.multiply(keyInverse);
            vectorKeyInversePoints.add(resultPoint);
        }

        List<BigInteger> output = new ArrayList<>();
        for (ECPoint point : vectorKeyInversePoints) {
            BigInteger x = point.getAffineXCoord().toBigInteger();
            BigInteger processedValue = x.shiftRight(logP - SIGMA_MAX - 10).and(MASK);
            output.add(processedValue);
        }

        return output;
    }

    public static List<BigInteger> clientPrfOnlineParallel(BigInteger keyInverse, List<List<BigInteger>> vectorOfPairs) throws InterruptedException, ExecutionException {
        int division = vectorOfPairs.size() / NUMBER_OF_PROCESSES;
        List<List<List<BigInteger>>> inputs = new ArrayList<>();

        for (int i = 0; i < NUMBER_OF_PROCESSES; i++) {
            inputs.add(new ArrayList<>(vectorOfPairs.subList(i * division, (i + 1) * division)));
        }

        if (vectorOfPairs.size() % NUMBER_OF_PROCESSES != 0) {
            inputs.add(new ArrayList<>(vectorOfPairs.subList(NUMBER_OF_PROCESSES * division, vectorOfPairs.size())));
        }

        List<Callable<List<BigInteger>>> tasks = new ArrayList<>();
        for (List<List<BigInteger>> input : inputs) {
            tasks.add(() -> clientPrfOnline(keyInverse, input));
        }

        ExecutorService executor = Executors.newFixedThreadPool(NUMBER_OF_PROCESSES);
        List<Future<List<BigInteger>>> futures = executor.invokeAll(tasks);

        List<BigInteger> finalOutput = new ArrayList<>();
        for (Future<List<BigInteger>> future : futures) {
            finalOutput.addAll(future.get());
        }

        executor.shutdown();
        return finalOutput;
    }


    public static List<BigInteger> processClientSetFromServer(List<Integer> clientSet, BigInteger serverKey) {
        List<BigInteger> processedClientSet = new ArrayList<>();
        for (int i = 0; i < clientSet.size(); i++) {
            processedClientSet.add(serverKey.multiply(new BigInteger(String.valueOf(clientSet.get(i)))));
        }
        return processedClientSet;
    }

    public static java.math.BigInteger getOrderOfGenerator() {
        return orderOfGenerator;
    }

    public static List<BigInteger> getClientPRFedSet(List<BigInteger> clientSet, BigInteger clientKey) {
        // Need the reversed OPRFClientKey
        List<BigInteger> processedClientSet = new ArrayList<>();
        BigInteger reversedKey = reverseKey(clientKey);
        for (int i = 0; i < clientSet.size(); i++) {
            processedClientSet.add( clientSet.get(i).multiply(reversedKey) );
        }
        return processedClientSet;
    }

    public static BigInteger reverseKey( BigInteger key ) {
        return key.modInverse( OPRF.getOrderOfGenerator() );
    }

    // PSI RELATED METHODS

    public static List<byte[]> calculateServerAnswer(
            List<ECPoint> allPowers,
            List<ECPoint> transposedPolyCoeffs,
            int alpha,
            int minibinCapacity) {
        List<byte[]> srvAnswer = new ArrayList<>();

        for (int i = 0; i < alpha; i++) {
            ECPoint dotProduct = allPowers.get(0);
            for (int j = 1; j < minibinCapacity; j++) {
                ECPoint term = transposedPolyCoeffs.get((minibinCapacity + 1) * i + j).multiply(allPowers.get(j).getAffineXCoord().toBigInteger());
                dotProduct = dotProduct.add(term);
            }
            ECPoint finalTerm = transposedPolyCoeffs.get((minibinCapacity + 1) * i + minibinCapacity);
            dotProduct = dotProduct.add(finalTerm);

            // Serialize the point (convert to bytes) and add to the result list
            byte[] serializedDotProduct = dotProduct.getEncoded(true);
            srvAnswer.add(serializedDotProduct);
        }

        return srvAnswer;
    }

    public static List<ECPoint> recoverAllPowers(List<List<ECPoint>> receivedEncQuery, int minibinCapacity, int base, int logB_ell) {
        List<ECPoint> allPowers = new ArrayList<>(Collections.nCopies(minibinCapacity, null));

        for (int i = 0; i < base - 1; i++) {
            for (int j = 0; j < logB_ell; j++) {
                int index = (i + 1) * (int) Math.pow(base, j) - 1;
                if (index < minibinCapacity) {
                    allPowers.set(index, receivedEncQuery.get(i).get(j));
                }
            }
        }

        for (int k = 0; k < minibinCapacity; k++) {
            if (allPowers.get(k) == null) {
                allPowers.set(k, powerReconstruct(receivedEncQuery, k + 1));
            }
        }

        Collections.reverse(allPowers);

        return allPowers;
    }

    // Placeholder for the power reconstruction method
    public static ECPoint powerReconstruct(List<List<ECPoint>> receivedEncQuery, int power) {
        // Implement the actual power reconstruction logic here
        return null; // Replace with actual implementation
    }

    // Evaluate the polynomial at a given point x using Horner's method

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
        return point.getAffineXCoord().add(point.getAffineYCoord()).toBigInteger();
    }

    // Simple PSI algorithm
    public static Set<BigInteger> simplePSI(List<Integer> serverList, List<BigInteger> clientList, BigInteger modulus, ECPoint evaluationPoint) {
        Set<BigInteger> serverSet = new HashSet<>();
        for (Integer i : serverList) {
            serverSet.add(BigInteger.valueOf(i));
        }

        Set<BigInteger> clientSet = new HashSet<>(clientList);

        // Convert ECPoint to BigInteger
        BigInteger evalPoint = ecPointToBigInteger(evaluationPoint);

        // Server computes polynomial from its set
        List<BigInteger> serverRoots = new ArrayList<>(serverSet);
        List<BigInteger> serverPolynomial = coeffsFromRoots(serverRoots, modulus);

        // Client computes polynomial from its set
        List<BigInteger> clientRoots = new ArrayList<>(clientSet);
        List<BigInteger> clientPolynomial = coeffsFromRoots(clientRoots, modulus);

        // Evaluate polynomials at the same random point
        BigInteger serverEval = evaluatePolynomial(serverPolynomial, evalPoint, modulus);
        BigInteger clientEval = evaluatePolynomial(clientPolynomial, evalPoint, modulus);

        // Intersection is found if evaluations match
        if (serverEval.equals(clientEval)) {
            System.out.println("found!");
            serverSet.retainAll(clientSet);
            return serverSet;
        } else {
            System.out.println("no intersection found");
            return new HashSet<>();  // No intersection found
        }
    }
    public static void main(String[] args) {
        // Sample data
        List<Integer> serverItems = new ArrayList<>();
        //serverItems.add(1);
       // serverItems.add(2);
        serverItems.add(3);


        List<Integer> clientItems = new ArrayList<>();
        //clientItems.add(8);
        clientItems.add(3);
       // clientItems.add(11);

        List<BigInteger> of = new ArrayList<>();
        of.add(new BigInteger("3"));

        BigInteger oprfServerKey = new BigInteger("1234567890"); // Example key, replace with actual logic
        BigInteger oprfClientKey = new BigInteger("9876543210"); // Example key, replace with actual logic
        BigInteger ORDER_OF_GENERATOR = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951");

        ECPoint serverPointPrecomputed = new FixedPointCombMultiplier().multiply(G, oprfServerKey.mod(ORDER_OF_GENERATOR));
        ECPoint clientPointPrecomputed = new FixedPointCombMultiplier().multiply(G, oprfClientKey.mod(ORDER_OF_GENERATOR));

        try {
            // First server offline to obtain sigma_max bits
            List<Integer> prfedServerSetList = serverPrfOfflineParallel(serverItems, serverPointPrecomputed);
            System.out.println(prfedServerSetList);

            // Client offline does similar
            List<Integer> prfedClientSetList = clientPrfOffline(clientItems, clientPointPrecomputed);
            System.out.println(prfedClientSetList);

            // The server obtains the client's points, multiplies them by oprf_server_key and sends them back to the client.
            List<BigInteger> processedClientSet = processClientSetFromServer(prfedClientSetList, oprfServerKey);
            System.out.println(processedClientSet);

            // Client gets PRFed set
            List<BigInteger> prfedClientSet2 = getClientPRFedSet(processedClientSet, oprfClientKey);
            System.out.println(prfedClientSet2);
            System.out.println("end of OPRF");

            // PSI Starts Here
            //PSIServer server = new PSIServer();
           // server.addStream(prfedServerSetList);
            //server.serverOffline(prfedServerSetList);
            // Server computes the coefficients of the monic polynomial
            simplePSI(serverItems, of, BigInteger.valueOf(Parameters.PLAIN_MODULUS), G);

            // All powers
            // Coefficients
            // alpha
            // minibin capacity
           //  recoverAllPowers(logP);
           //  calculateServerAnswer();

        } catch (Exception e){
            System.err.println(e.getMessage());
        }


            /**
            List<ECPoint> serverPrfSet = serverPrfOnlineParallel(oprfServerKey, serverItems);
            List<BigInteger> clientPrfSet = clientPrfOnlineParallel(oprfClientKey, clientItems);

            System.out.println("Server PRF Set:");
            for (ECPoint point : serverPrfSet) {
                System.out.println("[" + point.getAffineXCoord().toBigInteger() + ", " + point.getAffineYCoord().toBigInteger() + "]");
            }

            System.out.println("Client PRF Set:");
            for (BigInteger value : clientPrfSet) {
                System.out.println(value);
            }
             */

    }

}
