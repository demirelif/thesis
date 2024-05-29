package util.PSI;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class AuxiliaryFunctions {

    private static final int base = (int) Math.pow(2, Parameters.ELL);
    private static final int minibinCapacity = (int) Parameters.BIN_CAPACITY / Parameters.ALPHA;
    private static final int logB_ell =  (int) ( Math.log(minibinCapacity) / Math.log(2)) / Parameters.ELL + 1;


    public static Integer[][] windowing(int y, int bound, int modulus) {
        Integer[][] windowedY = new Integer[base - 1][logB_ell];

        for (int j = 0; j < logB_ell; j++) {
            for (int i = 0; i < base - 1; i++) {
                if ((i + 1) * Math.pow(base, j) - 1 < bound) {
                    windowedY[i][j] = powMod(y, (int) ((i + 1) * Math.pow(base, j)), modulus);
                } else {
                    windowedY[i][j] = null;
                }
            }
        }
        return windowedY;
    }

    private static int powMod(int base, int exponent, int modulus) {
        int result = 1;
        base = base % modulus;
        while (exponent > 0) {
            if ((exponent & 1) == 1) {  // If exponent is odd
                result = (result * base) % modulus;
            }
            exponent = exponent >> 1;  // Divide exponent by 2
            base = (base * base) % modulus;
        }
        return result;
    }

    public static List<BigInteger> coeffsFromRoots(List<BigInteger> roots, int modulus) {
        // Start with the polynomial 1 (which is just a constant term)
        List<BigInteger> coefficients = new ArrayList<>();
        coefficients.add(BigInteger.ONE);

        // Convolve with each root
        for (BigInteger root : roots) {
            coefficients = convolve(coefficients, Arrays.asList(BigInteger.ONE, root.negate()), BigInteger.valueOf(modulus));
        }

        return coefficients;
    }

    private static List<BigInteger> convolve(List<BigInteger> a, List<BigInteger> b, BigInteger modulus) {
        List<BigInteger> result = new ArrayList<>(Arrays.asList(new BigInteger[a.size() + b.size() - 1]));
        for (int i = 0; i < result.size(); i++) {
            result.set(i, BigInteger.ZERO);
        }

        // Perform the convolution operation
        for (int i = 0; i < a.size(); i++) {
            for (int j = 0; j < b.size(); j++) {
                int index = i + j;
                result.set(index, result.get(index).add(a.get(i).multiply(b.get(j))).mod(modulus));
                // Ensure the result is non-negative
                if (result.get(index).compareTo(BigInteger.ZERO) < 0) {
                    result.set(index, result.get(index).add(modulus));
                }
            }
        }

        return result;
    }
}
