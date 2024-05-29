package util;

import core.Message;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP192R1Curve;
import util.PSI.Pair;
import util.PSI.Parameters;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;

public class OPRF {
    private static final int NUMBER_OF_PROCESSES = 5;
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
        // TODO change this to the actual id
        BigInteger msgBigIntID = new BigInteger(msgID);
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
