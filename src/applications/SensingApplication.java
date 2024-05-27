package applications;

import core.*;
import edu.alibaba.mpc4j.crypto.fhe.*;
import edu.alibaba.mpc4j.crypto.fhe.context.EncryptionParameters;
import edu.alibaba.mpc4j.crypto.fhe.context.SchemeType;
import edu.alibaba.mpc4j.crypto.fhe.context.SealContext;
import edu.alibaba.mpc4j.crypto.fhe.modulus.CoeffModulus;
import edu.alibaba.mpc4j.crypto.fhe.modulus.Modulus;
import org.bouncycastle.math.ec.custom.djb.Curve25519;

import java.math.BigInteger;
import java.security.spec.ECPoint;
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

    private static final BigInteger ORDER_OF_GENERATOR = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951");


    private static final ECPoint G = new ECPoint( new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
            new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16));


    private static long secretKeyServer = 1234567891011121314L;
    private static BigInteger secretKeyClient = new BigInteger("12345678910111213141516171819222222222222");


    private int counter = 0;
    private HashMap<Message, Double> receivedMessages = new HashMap<>();

    private long[] messages = {100, 200, 300, 400};

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

    private void crowdCountingClient(Message msg){
        System.out.println("crowd counting -- receiver / client");

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

  //      long[] plainVec2 = new long[batchEncoder.slotCount()];
  //      batchEncoder.decode(plain, plainVec2);

        Ciphertext encrypted = new Ciphertext();
        context = new SealContext(parms, false, CoeffModulus.SecLevelType.NONE);
        keygen = new KeyGenerator(context);

        PublicKey pk = new PublicKey();
        keygen.createPublicKey(pk);

        Encryptor encryptor = new Encryptor(context, pk);
        Decryptor decryptor = new Decryptor(context, keygen.secretKey());

        // Encryption - OPRFs
        encryptor.encrypt(plain, encrypted);
      //  decryptor.decrypt(encrypted, plain);

        // HERE, plain is the variable that holds the message values

        // SEND the messages
        // END OF THE OFFLINE PHASE, ONLY DO THIS ONCE



        if (!(timeInterval > msg.getReceiveTime())) {
            timeInterval = timeIntervalIncrease + timeInterval;
        }
        receivedMessages.put(msg, timeInterval);

        // database of the server
        System.out.println(receivedMessages);
    }

    private void crowdCountingServer(Message msg){
        System.out.println("crowd counting -- sender / server");
        // Preprocessing Phase
        System.out.println("Preprocessing phase is started");
        // Processing, batching, encryption
        List<Long> messageIDs = new ArrayList<>();
        messageIDs.add(3L);

        // database of the server
        System.out.println(Arrays.toString(messages));

        // Send the encrypted message

        // Return the encrypted result

        // Decryption and reporting
    }

    private void clientOffline(){
        long t0 = System.currentTimeMillis();

        // key * generator of elliptic curve
   //     ECPoint clientPointPrecomputed = G.multiply(oprfClientKey.mod(ORDER_OF_GENERATOR));





    }

    private void serverOffline(){

    }
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

            System.out.println(msg.getTo().getRole());
            if (msg.getTo().getRole().equals("sender")) {
                crowdCountingClient(msg);
            } else if (msg.getTo().getRole().equals("receiver")) {
                crowdCountingServer(msg);
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
