package util.PSI;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import util.OPRF;

import java.math.BigInteger;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

// Performs simple hashing
public class PSIServer {
    private BigInteger OPRFServerKey = new BigInteger("1234567891011121314151617181920");
    private List<Integer> stream;
    private List<List<BigInteger>> encryptedStream;

    private static final ECCurve CURVE = new SecP256K1Curve();

    private static final BigInteger ORDER_OF_GENERATOR = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951");

    // Defines the generator point G
    private static final ECPoint G = CURVE.createPoint(
            new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
            new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    );

    public PSIServer(){
    }

    public void addStream(List<Integer> stream){
        this.stream = stream;
    }

    public void addEncryptedStream( List<List<BigInteger>> stream ){
        this.encryptedStream = stream;
    }

    private void ServerOnline(){
        double logNoOfHashes = Math.log(Parameters.NUMBER_OF_HASHES) / Math.log(2) + 1;
        int base = (int) Math.pow(2, Parameters.ELL);
        int miniBinCapacity = Parameters.BIN_CAPACITY / Parameters.ALPHA;
        double log2 = Math.log(miniBinCapacity) / Math.log(2);
        int logBELL = (int) ( log2 + 1 );

        if ( encryptedStream == null || encryptedStream.size() == 0 ){
            System.err.println("No encrypted stream found for the server");
            return;
        }

      //  RealMatrix transposedPolyCoeffs = MatrixUtils.createRealMatrix(polyCoeffs).transpose();

    }

    public List<Integer> getStream(){
        return this.stream;
    }

    public  List<List<BigInteger>> getEncryptedStream(){
        return this.encryptedStream;
    }

    public void serverOffline(){
        if ( stream.isEmpty() ){
            System.err.println("The stream of server is empty ");
            return;
        }
        long t0 = System.currentTimeMillis();
        org.bouncycastle.math.ec.ECPoint serverPointPrecomputed = new FixedPointCombMultiplier().multiply(G, OPRFServerKey.mod(ORDER_OF_GENERATOR));

        // Apply PRF to a set of server, using parallel computation
        List<Integer> prfedServerSetList = OPRF.serverPrfOfflineParallel(stream, serverPointPrecomputed);
        Set<Integer> prfedServerSet = new HashSet<>(prfedServerSetList);
        long t1 = System.currentTimeMillis();

        int logNoOfHashes = (int) (Math.log(Parameters.NUMBER_OF_HASHES)) + 1;
        int dummyMessageServer= BigInteger.valueOf(2).pow(Parameters.SIGMA_MAX - Parameters.OUTPUT_BITS + logNoOfHashes).add(BigInteger.ONE).intValue();
        int serverSize = stream.size();
        int miniBinCapacity = Parameters.BIN_CAPACITY / Parameters.OUTPUT_BITS;
        int numberOfBins = (int) Math.pow(2, Parameters.OUTPUT_BITS);

        SimpleHash sh = new SimpleHash(Parameters.HASH_SEEDS);
        for ( int item: prfedServerSet){
            for ( int i = 0; i < Parameters.NUMBER_OF_HASHES; i++ ){
                sh.insert(item, i);
            }
        }

        // Pad with dummyMessages
        for ( int i = 0; i < numberOfBins; i++ ){
            for ( int j = 0; j < Parameters.BIN_CAPACITY; j++ ){
                if ( (sh.getSimpleHashedData()[i][j]) == -1 ){
                    sh.getSimpleHashedData()[i][j] = dummyMessageServer;
                }
            }
        }

        // Perform partitioning and create polynomial coefficients

        List<List<BigInteger>> poly_coeffs = new ArrayList<>();

        for (int i = 0; i < numberOfBins; i++) {
            // Create a list of coefficients of all minibins from concatenating the list of coefficients of each minibin
            List<BigInteger> coeffs_from_bin = new ArrayList<>();

            for (int j = 0; j < Parameters.ALPHA; j++) {

                List<Integer> roots = new ArrayList<>();

                for (int r = 0; r < miniBinCapacity; r++) {
                    int index = miniBinCapacity * j + r;
                    if ( index < sh.getSimpleHashedData()[i].length ){
                        roots.add(sh.getSimpleHashedData()[i][index]);
                    }
                }

                ArrayList<BigInteger> coeffs_from_roots = (ArrayList<BigInteger>) AuxiliaryFunctions.coeffsFromRoots(roots, Parameters.PLAIN_MODULUS);
                coeffs_from_bin.addAll(coeffs_from_roots);
            }
            poly_coeffs.add(coeffs_from_bin);
        }

        long t3 = System.currentTimeMillis();
        addEncryptedStream(poly_coeffs);

        // TODO this part is extremely slow ~ 10s
        System.out.printf("Server OFFLINE time: %.2fs%n", (t3 - t0) / 1000.0);
    }


}
