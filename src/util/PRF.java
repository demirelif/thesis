package util;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP192R1Curve;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;

public class PRF {
    private static final int NUMBER_OF_PROCESSES = 5;
    public static final int SIGMA_MAX = Parameters.SIGMA_MAX;
    public static final BigInteger MASK = BigInteger.valueOf((2L *SIGMA_MAX) - 1);


    private static final ECCurve CURVE_USED = new SecP192R1Curve();
    private static BigInteger primeOfCurveEquation = CURVE_USED.getField().getCharacteristic();
    private static BigInteger orderOfGenerator = CURVE_USED.getOrder();
    private static int logP = primeOfCurveEquation.bitLength();

    //TODO this might be wrong
    private static ECPoint G = CURVE_USED.decodePoint(CURVE_USED.getCofactor().toByteArray());

    public static List<BigInteger> clientPRFOffline(String msgID, ECPoint point ){
        BigInteger msgBigIntID = BigInteger.valueOf(Long.parseLong(String.valueOf(msgID)));
        ECPoint P = point.multiply(msgBigIntID);
        // Extract the x and y coordinates of the resulting point
        BigInteger xItem = P.getAffineXCoord().toBigInteger();
        BigInteger yItem = P.getAffineYCoord().toBigInteger();


        // Return the coordinates as a list
        return Arrays.asList(xItem, yItem);
    }

    public static List<BigInteger> serverPrfOffline(List<Integer> vectorOfItems, ECPoint point) {
        List<ECPoint> vectorOfMultiples = new ArrayList<>();
        for (int item : vectorOfItems) {
            BigInteger itemBigInt = BigInteger.valueOf(item);
            vectorOfMultiples.add(point.multiply(itemBigInt));
        }

        List<BigInteger> result = new ArrayList<>();
        for (ECPoint Q : vectorOfMultiples) {
            BigInteger xItem = Q.getAffineXCoord().toBigInteger();
            BigInteger shiftedXItem = xItem.shiftRight(logP - SIGMA_MAX - 10);
            BigInteger maskedXItem = shiftedXItem.and(MASK);
            result.add(maskedXItem);
        }

        return result;
    }

    public static List<BigInteger> serverPrfOfflineParallel(List<Integer> vectorOfItems, ECPoint point) {
        int division = vectorOfItems.size() / NUMBER_OF_PROCESSES;
        List<List<Integer>> inputs = new ArrayList<>();
        for (int i = 0; i < NUMBER_OF_PROCESSES; i++) {
            int start = i * division;
            int end = (i + 1) * division;
            inputs.add(vectorOfItems.subList(start, end));
        }
        if (vectorOfItems.size() % NUMBER_OF_PROCESSES != 0) {
            int startIndex = NUMBER_OF_PROCESSES * division;
            int endIndex = startIndex + (vectorOfItems.size() % NUMBER_OF_PROCESSES);
            inputs.add(vectorOfItems.subList(startIndex, endIndex));
        }

        // Initialize inputsAndPoint list
        List<Pair> inputsAndPoint = new ArrayList<>();
        for (List<Integer> inputVec : inputs) {
            inputsAndPoint.add(new Pair(inputVec, point));
        }
        List<List<BigInteger>> outputs = new ArrayList<>();

        // TODO Not sure about the rest of the algorithm here
        List<Callable<List<BigInteger>>> tasks = new ArrayList<>();
        for (Pair pair : inputsAndPoint) {
            tasks.add(() -> serverPrfOffline(pair.inputVec, pair.point));
        }

        ExecutorService executor = Executors.newFixedThreadPool(NUMBER_OF_PROCESSES);
        List<BigInteger> finalOutput = new ArrayList<>();
        try {
            List<Future<List<BigInteger>>> futures = executor.invokeAll(tasks);
            for (Future<List<BigInteger>> future : futures) {
                finalOutput.addAll(future.get());
            }
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        } finally {
            executor.shutdown();
        }

        return finalOutput;
    }
}