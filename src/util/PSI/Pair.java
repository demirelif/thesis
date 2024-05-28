package util.PSI;

import org.bouncycastle.math.ec.ECPoint;

import java.util.List;

public class Pair {
    public List<Integer> inputVec;
    public ECPoint point;

    public Pair(List<Integer> inputVec, ECPoint point) {
        this.inputVec = inputVec;
        this.point = point;
    }
}
