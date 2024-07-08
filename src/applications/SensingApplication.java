package applications;

import core.*;
import edu.alibaba.mpc4j.crypto.fhe.*;
import edu.alibaba.mpc4j.crypto.fhe.KeyGenerator;
import edu.alibaba.mpc4j.crypto.fhe.context.EncryptionParameters;
import edu.alibaba.mpc4j.crypto.fhe.context.SchemeType;
import edu.alibaba.mpc4j.crypto.fhe.context.SealContext;
import edu.alibaba.mpc4j.crypto.fhe.modulus.Modulus;
import org.bouncycastle.math.ec.ECCurve;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import util.Hash.SimpleHash;
import util.PSI.*;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import core.SimScenario;

import java.util.*;

import static util.PrivateSetIntersection.encryptStream;

public class SensingApplication extends Application {
    private final String CLIENT = "client";
    private final String SERVER = "server";
    private final Integer LAST_NODE_ADDRESS = 9;

    private final Integer SIZE = 3;

    PSI PSI = new PSI();

    // PSI Parameters
    private SealContext context;
    private KeyGenerator keyGen;

    private double timeInterval = 0;
    private final double timeIntervalIncrease = 1000;

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
        rng = new Random(this.seed);
        super.setAppID(APP_ID);
    }

    public SensingApplication(SensingApplication s) {
        super(s);
        this.rng = new Random(this.seed);
    }

    /** Receives and saves the complete message list for the client */
    private void crowdCountingClient(Message msg){
        if ( msg.getFrom().getAddress() != 0 ){
            MACAddressesClient.add(msg.getFrom().getAddress());
        }
    }

    /** Receives and saves the complete message list for the server */
    private void crowdCountingServer(Message msg){
        if ( msg.getFrom().getAddress() != 0 ){
            MACAddressesServer.add(msg.getFrom().getAddress());
        }
    }

    @Override
    public Message handle(Message msg, DTNHost host) {
        if ( msg.getId().equals("probe-encrypted-message")){
            long startTime = System.nanoTime(); // Start timer at the beginning of the method
            if ( msg.getFrom().getAddress() != msg.getTo().getAddress() && !isPSIed && dtnHost.getRole().equals(SERVER)){
                //isPSIed = true;
                System.out.println("The server size " + removeDuplicates(MACAddressesServer).size());
                PSIServer psiServer = new PSIServer();
                psiServer.addStream(removeDuplicates(MACAddressesServer));
                PSIClient psiClient = new PSIClient();
                // TODO encrypt it first
                ArrayList<Integer> clientStream = (ArrayList<Integer>) msg.getProperty("body");
                psiClient.addStream(removeDuplicates(clientStream));
                Ciphertext setCiphertextsAlice = encryptStream(removeDuplicates(clientStream));
                psiClient.addCiphertext(setCiphertextsAlice);
                PSI psi = new PSI();
                psi.addPSIClient(psiClient);
                psi.addPSIServer(psiServer);
                int intersectionSize;
                if ( clientStream.size() > 5 ){
                    intersectionSize = psi.competeEncryptedIntersectionForBigList();
                } else {
                    intersectionSize = psi.competeEncryptedIntersection();
                }

               // System.out.println(this.dtnHost.getAddress() + " as the " + this.dtnHost.getRole() + " and " + msg.getFrom() + "as the " + msg.getFrom().getRole());
                long endTime = System.nanoTime();
                long totalDuration = endTime - startTime;
                try (FileWriter writer = new FileWriter("output" + SIZE + ".txt", true)) {
                    writer.write("Intersection size: " + intersectionSize + " " + this.dtnHost.getAddress() + "-" + msg.getFrom().getAddress() + " - duration: " + totalDuration+"\n");
                } catch (IOException e) {
                    System.err.println(e.getMessage());
                }
            }
        }
        else if ( msg.getId().equals("probe-encrypted-set-message")) {
            System.out.println("big");
            long startTime = System.nanoTime(); // Start timer at the beginning of the method
            if (msg.getFrom().getAddress() != msg.getTo().getAddress() && !isPSIed && dtnHost.getRole().equals(SERVER)) {
                PSIServer psiServer = new PSIServer();
                psiServer.addStream(removeDuplicates(MACAddressesServer));
                PSIClient psiClient = new PSIClient();
                ArrayList<Integer> clientStream = (ArrayList<Integer>) msg.getProperty("body");
                SimpleHash SH = new SimpleHash(clientStream.size());
                SH.initializeHashTable(clientStream);
                for ( int i = 0; i < SH.getHashTable().length; i++ ){
                    Ciphertext cp = encryptStream(Arrays.asList(SH.getHashTable()[i]));
                    psiClient.addCiphertextToList(cp);
                }
               // psiClient.addStream(removeDuplicates(clientStream));
               // Ciphertext setCiphertextsAlice = encryptStream(removeDuplicates(clientStream));
               // psiClient.addCiphertext(setCiphertextsAlice);
                PSI psi = new PSI();
                psi.addPSIClient(psiClient);
                psi.addPSIServer(psiServer);

                int intersectionSize = psi.competeEncryptedIntersection();
                System.out.println("done");
                long endTime = System.nanoTime();
                long totalDuration = endTime - startTime;
                try (FileWriter writer = new FileWriter("output.txt", true)) {
                    writer.write("SET 18");
                    writer.write("Intersection size: " + intersectionSize + " " + this.dtnHost.getAddress() + "-" + msg.getFrom().getAddress() + " - duration: " + totalDuration+"\n");
                } catch (IOException e) {
                    System.err.println(e.getMessage());
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
            if ( this.dtnHost == null ){
                return msg;
            }
            if ( this.dtnHost.getRole().equals(SERVER)){
                crowdCountingServer(msg);
            }
            if ( this.dtnHost.getRole().equals(CLIENT)){
                crowdCountingClient(msg);
            }
        }
        return msg;
    }

    @Override
    public void update(DTNHost host)  {
        this.dtnHost = host;
        double currentTime = SimClock.getTime();
        if ( dtnHost != null && (currentTime - timeInterval >= timeIntervalIncrease) && this.dtnHost.getRole().equals(CLIENT)){
            timeInterval = currentTime;
            int currentHostAddress = host.getAddress();
            if ( currentHostAddress == 1 ){
                // Means there is no node before this
                DTNHost receiver = SimScenario.getInstance().getHosts().get(currentHostAddress+1);
                sendEncryptedMessage(receiver);
            }
            else if ( currentHostAddress == LAST_NODE_ADDRESS ){
                // Means this is the last node
                DTNHost receiver = SimScenario.getInstance().getHosts().get(currentHostAddress-1);
                sendEncryptedMessage(receiver);
            }
            else {
                DTNHost receiver1 = SimScenario.getInstance().getHosts().get(currentHostAddress+1);
                DTNHost receiver2 = SimScenario.getInstance().getHosts().get(currentHostAddress-1);
                sendEncryptedMessage(receiver1);
                sendEncryptedMessage(receiver2);
            }
        }
    }

    public static <T> List<T> removeDuplicates(List<T> list) {
        // Using LinkedHashSet to maintain insertion order
        Set<T> set = new LinkedHashSet<>(list);
        return new ArrayList<>(set);
    }

    private void setPSIParties(){
            this.PSI.createServer();
            this.PSI.createClient();
    }

    private void sendEncryptedMessage(DTNHost receiver){
        String msgId = "encrypted-message";
        String msgLongId = "encrypted-set-message";
        List<Integer> uniqueClientSet = removeDuplicates(MACAddressesClient);
        // If the message size too long, it needs to be hashed

        setPSIParties();
        if ( false ){
          //  SimpleHash SH = new SimpleHash(uniqueClientSet.size()/Parameters.BIN_CAPACITY);
          //  SH.initializeHashTable((ArrayList<Integer>) uniqueClientSet);
           // System.out.println("HASH TABLE");
           // SH.printHashTable();

            //int intersectionSize = 0;
            /**
             *             List<Ciphertext> clientSetEcnrypted = new ArrayList<>();
             *             for (int i = 0; i < SH.getHashTable().length; i++) {
             *                 // Client encrypts her elements
             *                 List<Integer> clientList = Arrays.asList(SH.getHashTable()[i]);
             *                 Ciphertext setCiphertexts = encryptStream(clientList);
             *                 clientSetEcnrypted.add(setCiphertexts);
             *             }
             */

            Message m = new Message(this.dtnHost, receiver, "probe" +
                    msgLongId,
                    uniqueClientSet.size() * 8);
            m.addProperty("type", "probe");
            m.addProperty("size", uniqueClientSet.size());
            m.addProperty("body", uniqueClientSet.size());
            m.setAppID(APP_ID);
            dtnHost.createNewMessage(m);
            dtnHost.sendMessage(m.getId(), receiver);
            super.sendEventToListeners("ProbeSent", null, dtnHost);
        } else {
            // TODO change the encryption later
           //  Ciphertext ciphertext = encryptStream(uniqueClientSet);
            Message m = new Message(this.dtnHost, receiver, "probe" + "-" +
                    msgId,
                    uniqueClientSet.size() * 8);
            m.addProperty("type", "probe");
            m.addProperty("size", uniqueClientSet.size());
            m.addProperty("body", uniqueClientSet);
            m.setAppID(APP_ID);
            dtnHost.createNewMessage(m);
            dtnHost.sendMessage(m.getId(), receiver);
            super.sendEventToListeners("ProbeSent", null, dtnHost);
        }
    }

    @Override
    public Application replicate() {
        return new SensingApplication(this);
    }
}
