package applications;

import core.*;
import edu.alibaba.mpc4j.crypto.fhe.*;
import edu.alibaba.mpc4j.crypto.fhe.context.EncryptionParameters;
import edu.alibaba.mpc4j.crypto.fhe.context.SchemeType;
import edu.alibaba.mpc4j.crypto.fhe.context.SealContext;
import edu.alibaba.mpc4j.crypto.fhe.modulus.CoeffModulus;
import edu.alibaba.mpc4j.crypto.fhe.modulus.Modulus;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.ECCurve;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import util.PRF;
import util.PSI.AuxiliaryFunctions;
import util.PSI.OPRF;
import util.PSI.Parameters;
import util.PSI.SimpleHash;

import java.math.BigInteger;

import java.net.ServerSocket;
import java.util.*;

public class SensingApplication extends Application {
    public static final String RECEIVER = "Receiver";
    public static final String SENDER = "Sender";
    private String role;

    public static final String PROBE_INTERVAL = "interval";
    public static final String PROBE_DEST_RANGE = "destinationRange";
    public static final String PROBE_SEED = "seed";
    public static final String PROBE_SIZE = "probeSize";

    public static final String APP_ID = "de.in.tum.SensingApplication";

    private double lastProbe = 0;
    private double interval = 10;
    private int seed = 0;
    private int destMin = 0;
    private int destMax = 1;
    private int probeSize = 1;
    private int pongSize = 1;
    private Random rng;

    private double timeInterval = 120;
    private double timeIntervalIncrease = 10;

    // Encryption parameters
    EncryptionParameters params = new EncryptionParameters(SchemeType.BFV);
    Modulus plainModulus = new Modulus(1 << 6);
    private SealContext context;
    private KeyGenerator keygen;
    private PublicKey pk;
    Encryptor encryptor;
    Decryptor decryptor;

    // Defines the curve
    private static final ECCurve CURVE = new SecP256K1Curve();

    private static final BigInteger ORDER_OF_GENERATOR = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951");

    // Defines the generator point G
    private static final ECPoint G = CURVE.createPoint(
            new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
            new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    );
    private static BigInteger secretKeyServer = new BigInteger("1234567891011121314");
    private static BigInteger secretKeyClient = new BigInteger("12345678910111213141516171819222222222222");

    private BigInteger OPRFServerKey = new BigInteger("1234567891011121314151617181920");
    private BigInteger OPRFClientKey = new BigInteger("12345678910111213141516171819222222222222");

    private final HashMap<Message, Double> receivedMessagesServer = new HashMap<>();
    private final HashMap<Message, Double> receivedMessagesClient = new HashMap<>();

    private final List<Message> encryptedMessagesServer = new ArrayList<>();
    private final List<List<BigInteger>> encryptedMessagesClient = new ArrayList<List<BigInteger>>();

    public SensingApplication(Settings s) {
        if (s.contains(PROBE_INTERVAL)){
            this.interval = s.getDouble(PROBE_INTERVAL);
        }
        if (s.contains(PROBE_SEED)){
            this.seed = s.getInt(PROBE_SEED);
        }
        if (s.contains(PROBE_SIZE)) {
            this.probeSize = s.getInt(PROBE_SIZE);
        }
        if (s.contains(PROBE_DEST_RANGE)){
            int[] destination = s.getCsvInts(PROBE_DEST_RANGE, 2);
            this.destMin = destination[0];
            this.destMax = destination[1];
        }


        rng = new Random(this.seed);
        super.setAppID(APP_ID);
    }

    public SensingApplication(SensingApplication s) {
        super(s);
        this.rng = new Random(this.seed);
    }


    private void crowdCountingClientWithEncryption(Message msg){
        List<Long> messageIDs = new ArrayList<>();
        messageIDs.add(3L);

        // Encryption parameters
        EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
        parms.setPolyModulusDegree(64);
        //parms.setPlainModulus(plainModulus);
        parms.setCoeffModulus(CoeffModulus.create(64, new int[]{40}));
        // t must be a prime number and t mod 2n = 1, then we can us batch encode
        parms.setPlainModulus(257);
        SealContext context = new SealContext(parms, false, CoeffModulus.SecLevelType.NONE);
        BatchEncoder batchEncoder = new BatchEncoder(context);

        // Ensure the plainVec array is large enough to hold all batched data
        long[] plainVec = new long[batchEncoder.slotCount()];
        for (int i = 0; i < plainVec.length && i < messageIDs.size(); i++) {
            plainVec[i] = messageIDs.get(i);
        }

        Plaintext plain = new Plaintext();
        batchEncoder.encode(plainVec, plain);

        Ciphertext encrypted = new Ciphertext();
      //  context = new SealContext(parms, false, CoeffModulus.SecLevelType.NONE);
        keygen = new KeyGenerator(context);

        PublicKey pk = new PublicKey();
        keygen.createPublicKey(pk);

        Encryptor encryptor = new Encryptor(context, pk);
        Decryptor decryptor = new Decryptor(context, keygen.secretKey());
        // Encryption - OPRFs
        encryptor.encrypt(plain, encrypted);

        receivedMessagesClient.put(msg, msg.getReceiveTime());
    }

    /** Receives and saves the complete message list for the client */
    private void crowdCountingClient(Message msg){
        receivedMessagesClient.put(msg, msg.getReceiveTime());
    }

    /** Receives and saves the complete message list for the server */
    private void crowdCountingServer(Message msg){
        receivedMessagesServer.put(msg, msg.getReceiveTime());
    }

    /** The preprocessing phase (OPRF, Batching) for the client */
    private void clientOffline(){
        long t0 = System.currentTimeMillis();
        org.bouncycastle.math.ec.ECPoint clientPointPrecomputed = new FixedPointCombMultiplier().multiply(G, secretKeyClient.mod(ORDER_OF_GENERATOR));
        System.out.println("Client Point Precomputed: " + clientPointPrecomputed);

        // OPRF Layer: encoding the client's set as elliptic curve points
        for ( Message msg : receivedMessagesClient.keySet()){
            encryptedMessagesClient.add(PRF.clientPRFOffline(msg.getId(), clientPointPrecomputed));
        }
        long t1 = System.currentTimeMillis();
        System.out.println("Client OFFLINE time: " + (t1 - t0) + " ms");
    }

    /** The preprocessing phase (OPRF, Batching) for the server */
    private void serverOffline(){
        long t0 = System.currentTimeMillis();
        org.bouncycastle.math.ec.ECPoint serverPointPrecomputed = new FixedPointCombMultiplier().multiply(G, secretKeyServer.mod(ORDER_OF_GENERATOR));
        System.out.println("Server Point Precomputed: " + serverPointPrecomputed);


        List<Integer> messageIDs = new ArrayList<>();
        for (Message msg : receivedMessagesServer.keySet()){
            messageIDs.add(Integer.getInteger(msg.getId()));
        }

        // Apply PRF to a set of server, using parallel computation
        List<BigInteger> prfedServerSetList = PRF.serverPrfOfflineParallel(messageIDs, serverPointPrecomputed);
        Set<BigInteger> prfedServerSet = new HashSet<>(prfedServerSetList);
        long t1 = System.currentTimeMillis();

        int logNoOfHashes = (int) (Math.log(Parameters.NUMBER_OF_HASHES)) + 1;
        BigInteger dummyMessageServer= BigInteger.valueOf(2).pow(Parameters.SIGMA_MAX - Parameters.OUTPUT_BITS + logNoOfHashes).add(BigInteger.ONE);
        int serverSize = messageIDs.size();
        int miniBinCapacity = Parameters.BIN_CAPACITY / Parameters.OUTPUT_BITS;
        int numberOfBins = (int) Math.pow(2, Parameters.OUTPUT_BITS);

        SimpleHash sh = new SimpleHash(Parameters.HASH_SEEDS);
        for ( BigInteger item: prfedServerSet){
            for ( int i = 0; i < Parameters.NUMBER_OF_HASHES; i++ ){
                sh.insert(item, i);
            }
        }
        // Perform partitioning and create polynomial coefficients
        long t2 = System.currentTimeMillis();
        List<List<BigInteger>> poly_coeffs = new ArrayList<>();
        for (int i = 0; i < numberOfBins; i++) {
            List<BigInteger> coeffs_from_bin = new ArrayList<>();
            for (int j = 0; j < Parameters.ALPHA; j++) {
                List<BigInteger> roots = new ArrayList<>();
                for (int r = 0; r < miniBinCapacity; r++) {
                    roots.add(sh.getSimpleHashedData()[i][miniBinCapacity * j + r]);
                }
                // TODO this method is currently returning null
                List<BigInteger> coeffs_from_roots = AuxiliaryFunctions.coeffsFromRoots(roots, Parameters.PLAIN_MODULUS);
                coeffs_from_bin.addAll(coeffs_from_roots);
            }
            poly_coeffs.add(coeffs_from_bin);
        }

        // pickle.dump( poly_coeffs, f);

        long t3 = System.currentTimeMillis();

        System.out.printf("Server OFFLINE time: %.2fs%n", (t3 - t0) / 1000.0);
    }


    private void serverOnline(){}

    public static Set<Integer> PSI(Set<Integer> setA, Set<Integer> setB){
        // use Vaikuntanathan

        // Encryption for set A
        Set<BigInteger> encryptedSetA = new HashSet<>();
        for (Integer element : setA) {
            encryptedSetA.add(null); // add the encrypted version here
        }

        Set<BigInteger> encryptedSetB = new HashSet<>();
        for (Integer element : setB) {
            encryptedSetB.add(null); // add the encrypted version here
        }

        // compute intersection

        // return intersection
        return null;
    }

    @Override
    public Message handle(Message msg, DTNHost host) {
        String type = (String) msg.getProperty("type");
        if (type == null) return msg; // Not a probe message
        if (msg.getFrom() == host && type.equalsIgnoreCase("probe")) {
            //  crowdCounting(msg, host);
            // The message identifier
            String id = "probe-" + SimClock.getIntTime() + "-" + host.getAddress();
            Message m = new Message(host, msg.getFrom(), id, 1);
            m.addProperty("type", "probeResponse");
            m.setAppID(APP_ID);
            msg.getTo().messageTransferred(msg.getId(), host);

            if (msg.getTo().getRole().equals("sender")) {
                crowdCountingServer(msg);
            } else if (msg.getTo().getRole().equals("receiver")) {
                crowdCountingClient(msg);
            }
        }

        return msg;
    }

    @Override
    public void update(DTNHost host) {
        Collection<Message> messages = host.getMessageCollection();
        for (Message message : messages) {
            // handle(message, host);
        }
    }

    @Override
    public Application replicate() {
        return new SensingApplication(this);
    }
}
