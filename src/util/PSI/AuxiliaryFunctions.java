package util.PSI;

import java.math.BigInteger;
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

    public static List<BigInteger> coeffsFromRoots(List<BigInteger> roots, int modulus ){
        return null;
    }
}
