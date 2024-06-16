package util.PSI;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.custom.sec.SecP192R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.io.ByteArrayOutputStream;

import static util.OPRF.serverPrfOfflineParallel;
import static util.OPRF.serverPrfOnlineParallel;

// Performs simple hashing
public class PSIServer {
    private static final ECCurve CURVE_USED = new SecP192R1Curve();
    private static ECPoint G = CURVE_USED.createPoint(
            new BigInteger("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16),
            new BigInteger("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16)
    );

    private BigInteger OPRFServerKey = new BigInteger("1234567890");
    BigInteger ORDER_OF_GENERATOR = Parameters.ORDER_OF_GENERATOR;
    ECPoint serverPointPrecomputed = new FixedPointCombMultiplier().multiply(G, OPRFServerKey.mod(ORDER_OF_GENERATOR));




    private List<Integer> stream;
    private List<List<BigInteger>> encryptedStream;

    private static final ECCurve CURVE = new SecP256K1Curve();

    public PSIServer(){
    }

    public void addStream(List<Integer> stream){
        this.stream = stream;
    }

    public void addEncryptedStream( List<List<BigInteger>> stream ){
        this.encryptedStream = stream;
    }

    public void serverOffline(List<Integer> serverItems){
        List<Integer> prfedServerSetList = serverPrfOfflineParallel(serverItems, serverPointPrecomputed);
        System.out.println(prfedServerSetList);
    }

    public void serverOnline(List<List<BigInteger>> stream){
        double logNoOfHashes = Math.log(Parameters.NUMBER_OF_HASHES) / Math.log(2) + 1;
        int base = (int) Math.pow(2, Parameters.ELL);
        int miniBinCapacity = Parameters.BIN_CAPACITY / Parameters.ALPHA;
        double log2 = Math.log(miniBinCapacity) / Math.log(2);
        int logBELL = (int) ( log2 + 1 );
        int L;

        if ( encryptedStream == null || encryptedStream.size() == 0 ){
            System.err.println("No encrypted stream found for the server");
            return;
        }
        if ( stream == null || stream.size() == 0 ){
            System.err.println("No stream found for the client");
            return;
        }
        L = stream.size();
        long t0 = System.currentTimeMillis();
        List<ECPoint> PRFedEncodedClientSet = new ArrayList<>();
        try {
            PRFedEncodedClientSet = serverPrfOnlineParallel(OPRFServerKey, stream);
        } catch (Exception e){
            System.err.println("Error in creating server stream " + e.getMessage());
        }


        byte[] PRFedEncodedClientSetSerialized = serialize(PRFedEncodedClientSet);
        L = PRFedEncodedClientSetSerialized.length;
        System.out.println(" * OPRF layer done!");
        long t1 = System.currentTimeMillis();


        //  RealMatrix transposedPolyCoeffs = MatrixUtils.createRealMatrix(polyCoeffs).transpose();

    }

    public List<Integer> getStream(){
        return this.stream;
    }

    public  List<List<BigInteger>> getEncryptedStream(){
        return this.encryptedStream;
    }

    public void serverOfflineOld(List<Integer> OPRFedServerSet){
        if ( stream.isEmpty() ){
            System.err.println("The stream of server is empty ");
            return;
        }
        long t0 = System.currentTimeMillis();
        ECPoint serverPointPrecomputed = new FixedPointCombMultiplier().multiply(G, OPRFServerKey.mod(ORDER_OF_GENERATOR));

        // Apply PRF to a set of server, using parallel computation
       // List<Integer> prfedServerSetList = OPRF.serverPrfOfflineParallel(stream, serverPointPrecomputed);
       // Set<Integer> prfedServerSet = new HashSet<>(prfedServerSetList);
       // long t1 = System.currentTimeMillis();

        int logNoOfHashes = (int) (Math.log(Parameters.NUMBER_OF_HASHES)) + 1;
        int dummyMessageServer= BigInteger.valueOf(2).pow(Parameters.SIGMA_MAX - Parameters.OUTPUT_BITS + logNoOfHashes).add(BigInteger.ONE).intValue();
        int serverSize = stream.size();
        int miniBinCapacity = Parameters.BIN_CAPACITY / Parameters.OUTPUT_BITS;
        int numberOfBins = (int) Math.pow(2, Parameters.OUTPUT_BITS);

        SimpleHash sh = new SimpleHash(Parameters.HASH_SEEDS);
        for ( int item: OPRFedServerSet){
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

        System.out.println("coef " + poly_coeffs.get(0));
        long t3 = System.currentTimeMillis();
        addEncryptedStream(poly_coeffs);


        System.out.printf("Server OFFLINE time: %.2fs%n", (t3 - t0) / 1000.0);
    }


    public static byte[] serialize(List<ECPoint> list) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(list);
            return bos.toByteArray();
        } catch (IOException e) {
            System.err.println("Serialization error");
            return null;
        }
    }

}
