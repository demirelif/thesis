package util;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

// The class for elliptic curve
public class PRF {

    // Curve parameters
    static Curve curveUsed = new P192();
    static int primeOfCurveEquation = curveUsed.getP().intValue();
    static int orderOfGenerator = curveUsed.getN().intValue();
    static Point G = new Point(curveUsed.getG().getX().intValue(), curveUsed.getG().getY().intValue(), curveUsed);

    static int sigmaMax = ...; // Assign sigma_max value
    static int mask = (1 << sigmaMax) - 1;

    static int numberOfProcesses = 4;

    public static void main(String[] args) {
        // Your main method logic here
    }

    static List<Integer> serverPRFOffline(List<Integer> vectorOfItems, Point point) {
        List<Integer> vectorOfMultiples = new ArrayList<>();
        for (Integer item : vectorOfItems) {
            Point Q = point.multiply(item);
            vectorOfMultiples.add((Q.getX().intValue() >> (primeOfCurveEquation - sigmaMax - 10)) & mask);
        }
        return vectorOfMultiples;
    }

    static List<Integer> serverPRFOfflineParallel(List<Integer> vectorOfItems, Point point) {
        int division = vectorOfItems.size() / numberOfProcesses;
        List<List<Integer>> inputs = new ArrayList<>();
        for (int i = 0; i < numberOfProcesses; i++) {
            inputs.add(vectorOfItems.subList(i * division, (i + 1) * division));
        }
        if (vectorOfItems.size() % numberOfProcesses != 0) {
            inputs.add(vectorOfItems.subList(numberOfProcesses * division, numberOfProcesses * division + (vectorOfItems.size() % numberOfProcesses)));
        }
        List<List<Integer>> outputs = new ArrayList<>();
        ExecutorService executor = Executors.newFixedThreadPool(numberOfProcesses);
        for (List<Integer> input : inputs) {
            executor.execute(() -> {
                List<Integer> output = serverPRFOffline(input, point);
                synchronized (outputs) {
                    outputs.add(output);
                }
            });
        }
        executor.shutdown();
        while (!executor.isTerminated()) {
            // Wait for all threads to finish
        }
        List<Integer> finalOutput = new ArrayList<>();
        for (List<Integer> outputVector : outputs) {
            finalOutput.addAll(outputVector);
        }
        return finalOutput;
    }

    // Other methods translated similarly
}
