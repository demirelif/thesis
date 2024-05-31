package util;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP192R1Curve;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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

    public static List<BigInteger> clientPRFOffline(String msgID, ECPoint point) {
        BigInteger msgBigIntID = new BigInteger(msgID);
        ECPoint P = point.multiply(msgBigIntID);
        // Extract the x and y coordinates of the resulting point
        int xItem = P.getXCoord().bitLength();
        int yItem = P.getYCoord().bitLength();
        // Return the coordinates as a list
        return Arrays.asList(new BigInteger(String.valueOf(xItem)), new BigInteger(String.valueOf(yItem)));
    }

    public static List<Integer> serverPrfOffline(List<Integer> vectorOfItems, ECPoint point) {
        List<ECPoint> vectorOfMultiples = new ArrayList<>();
        for (int item : vectorOfItems) {
            ECPoint resultPoint = point.multiply(new BigInteger(String.valueOf(item))).normalize();
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

        // Initialize inputsAndPoint list
        List<Pair> inputsAndPoint = new ArrayList<>();
        for (List<Integer> inputVec : inputs) {
            inputsAndPoint.add(new Pair(inputVec, point));
        }

        List<Callable<List<Integer>>> tasks = new ArrayList<>();
        for (Pair pair : inputsAndPoint) {
            tasks.add(() -> serverPrfOffline(pair.inputVec, pair.point));
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

        System.out.println("ServerPRFOffline: " + finalOutput);
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
            System.out.println("-- " + point.toString());
            ECPoint resultPoint = point.multiply(keyInverse);
            System.out.println(resultPoint);
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

    public static java.math.BigInteger getOrderOfGenerator() {
        return orderOfGenerator;
    }
}
