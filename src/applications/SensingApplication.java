package applications;

import core.*;
import edu.alibaba.mpc4j.crypto.fhe.*;
import edu.alibaba.mpc4j.crypto.fhe.KeyGenerator;
import edu.alibaba.mpc4j.crypto.fhe.context.EncryptionParameters;
import edu.alibaba.mpc4j.crypto.fhe.context.SchemeType;
import edu.alibaba.mpc4j.crypto.fhe.context.SealContext;
import edu.alibaba.mpc4j.crypto.fhe.modulus.CoeffModulus;
import edu.alibaba.mpc4j.crypto.fhe.modulus.Modulus;
import org.bouncycastle.math.ec.ECCurve;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import util.PSI.*;
import java.math.BigInteger;
import core.SimScenario;

import java.util.*;

public class SensingApplication extends Application {
    private final boolean USE_ENCRYPTION = true;

    // PSI Parameters
    private SealContext context;
    private KeyGenerator keyGen;

    public static final String PROBE_INTERVAL = "interval";
    public static final String PROBE_DEST_RANGE = "destinationRange";
    public static final String PROBE_SEED = "seed";
    public static final String PROBE_SIZE = "probeSize";
    public static final String APP_ID = "de.in.tum.SensingApplication";

    private boolean isPSIed = false;
    public List<DTNHost> hosts = new ArrayList<>();

    private double lastProbe = 0;
    private double interval = 10;
    private int seed = 0;
    private int destMin = 0;
    private int destMax = 1;
    private int probeSize = 1;
    private int pongSize = 1;
    private Random rng;
    private DTNHost dtnHost = null;

    private double timeInterval = 120;
    private double timeIntervalIncrease = 10;

    // Encryption parameters
    EncryptionParameters params = new EncryptionParameters(SchemeType.BFV);
    Modulus plainModulus = new Modulus(1 << 6);

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

    /** The data structure to hold the hashed MAC addresses of the received messages */
    private final List<Integer> MACAddressesServer = new ArrayList<>();
    private final List<Integer> MACAddressesClient = new ArrayList<>();

    private final int[] dummyAddresses = {1,2,3,4};
    private final List<List<BigInteger>> encryptedMessagesServer = new ArrayList<>();
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

        //createEncryptionParameters();

        rng = new Random(this.seed);
        super.setAppID(APP_ID);
    }

    public SensingApplication(SensingApplication s) {
        super(s);
        this.rng = new Random(this.seed);
    }

    /** Receives and saves the complete message list for the client */
    private void crowdCountingClient(Message msg){
        MACAddressesClient.add(msg.getFrom().getAddress());
    }

    /** Receives and saves the complete message list for the server */
    private void crowdCountingServer(Message msg){
        MACAddressesServer.add(msg.getFrom().getAddress());
    }

    @Override
    public Message handle(Message msg, DTNHost host) {
        if ( msg.getId().equals("probe-encrypted-message")){
            if ( msg.getFrom().getAddress() != msg.getTo().getAddress() && !isPSIed && dtnHost.getAddress() == 5){
                isPSIed = true;
                PSIServer psiServer = new PSIServer();
                psiServer.addStream(removeDuplicates(MACAddressesServer));
                PSIClient psiClient = new PSIClient();
                ArrayList<Integer> clientStream = (ArrayList<Integer>) msg.getProperty("body");
                psiClient.addStream(removeDuplicates(clientStream));
                PSI psi = new PSI();
                psi.addPSIClient(psiClient);
                psi.addPSIServer(psiServer);
                if ( USE_ENCRYPTION ){
                    psi.competeEncryptedIntersection();
                } else {
                    psi.competeIntersection();
                }
            }
        }

        String type = (String) msg.getProperty("type");
        if (type == null) return msg; // Not a probe message
        if (msg.getFrom() == host && type.equalsIgnoreCase("probe")) {
            String id = "probe-" + SimClock.getIntTime() + "-" + host.getAddress();
            Message m = new Message(host, msg.getFrom(), id, 1);
            m.addProperty("type", "probeResponse");
            m.setAppID(APP_ID);
            // TODO change this part later
            // TODO why there are multiple hosts with the same address? / calling them multiple times ?
            this.dtnHost = msg.getTo();
            if ( dtnHost.getAddress() == 4 ){
                crowdCountingServer(msg);
            }
            if ( dtnHost.getAddress() == 5 ){
                crowdCountingClient(msg);
            }
        }

        return msg;
    }

    @Override
    public void update(DTNHost host)  {
        if ( dtnHost != null && (MACAddressesClient.size() == 1698) && !isPSIed ){
            isPSIed = true;
            String msgId = "encrypted-message";
            DTNHost receiver = SimScenario.getInstance().getHosts().get(3);
            Message m = new Message(host, receiver, "probe" + "-" +
                            msgId,
                            MACAddressesClient.size()*8);
            m.addProperty("type", "probe");
            m.addProperty("body", MACAddressesClient);
            m.setAppID(APP_ID);
            host.createNewMessage(m);
            host.sendMessage(m.getId(), receiver);
            // Call listeners
            super.sendEventToListeners("ProbeSent", null, host);
        }
    }

    public static <T> List<T> removeDuplicates(List<T> list) {
        // Using LinkedHashSet to maintain insertion order
        Set<T> set = new LinkedHashSet<>(list);
        return new ArrayList<>(set);
    }

    @Override
    public Application replicate() {
        return new SensingApplication(this);
    }
}
