package applications;

import core.*;

import java.math.BigInteger;
import java.util.*;

/**
 * The application senses the probe messages and process them
 *
 */
public class SensingApplication extends Application {
    /** Role of a sensor node */
    public static final String RECEIVER = "Receiver";
    /** Role of a sensor node */
    public static final String SENDER = "Sender";
    /** Role of the current sensor node */
    private String role;

    /** Probe sensing interval */
    public static final String PROBE_INTERVAL = "interval";
    /** Destination address range - inclusive lower, exclusive upper */
    public static final String PROBE_DEST_RANGE = "destinationRange";
    /** Seed for the app's random number generator */
    public static final String PROBE_SEED = "seed";
    /** Size of the probe message */
    public static final String PROBE_SIZE = "probeSize";

    /** Application ID */
    public static final String APP_ID = "de.in.tum.SensingApplication";

    // Private vars
    private double	lastProbe = 0;
    private double	interval = 10;	/* send one probe every 10 seconds. this interval is configurable */
    private int		seed = 0;
    private int		destMin=0;
    private int		destMax=1;
    private int		probeSize=1;
    private int		pongSize=1;
    private Random	rng;

    /** The number of nodes that has send a message  */
    private int counter = 0;
    private HashMap<String, Integer> messages = new HashMap<>();

    /**
     * Creates a new probing application with the given settings.
     *
     * @param s	Settings to use for initializing the application.
     */
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
            int[] destination = s.getCsvInts(PROBE_DEST_RANGE,2);
            this.destMin = destination[0];
            this.destMax = destination[1];
        }

        rng = new Random(this.seed);
        super.setAppID(APP_ID);
    }


    /**
     * Copy-constructor
     *
     * @param s
     */
    public SensingApplication(SensingApplication s) {
        super(s);
        this.rng = new Random(this.seed);
    }

    private void crowdCounting(Message msg, DTNHost host) {
        String hostName = host.toString();
        char nodeNumber = hostName.charAt(hostName.length() - 1);
        String nodeName = String.valueOf(nodeNumber);
        /** This is the first time this node is sending a message */
        if ( messages.get( nodeName ) == null ){
            messages.put(nodeName, 1);
        }
        /** The node is already encountered before */
        else {
            messages.replace( nodeName, (messages.get(nodeName) + 1 ) );
        }
    }

    public static Set<Integer> PSI(Set<Integer> setA, Set<Integer> setB){
        // use Vaikuntanathan

        // Encryption for set A
        Set<BigInteger> encryptedSetA = new HashSet<>();
        for (Integer element: setA){
            encryptedSetA.add(null); // add the encrypted version here
        }

        Set<BigInteger> encryptedSetB = new HashSet<>();
        for ( Integer element: setB ){
            encryptedSetB.add(null); // add the encrypted version here
        }

        // compute intersection

        // return intersection
        return null;
    }

    private void send(){

    }

    private void receive(){}

    @Override
    public Message handle(Message msg, DTNHost host) {

        System.out.println("thisIsFromP " + host);
        String type = (String)msg.getProperty("type");
        if (type == null) return msg; // Not a probe message
        if (msg.getFrom() == host && type.equalsIgnoreCase("probe")) {

            crowdCounting(msg, host);

            // The message identifier
            String id = "probe-" + SimClock.getIntTime() + "-" + host.getAddress();
            Message m = new Message(host, msg.getFrom(), id, 1);
            m.addProperty("type", "probeResponse");
            m.setAppID(APP_ID);
            msg.getTo().messageTransferred(msg.getId(), host);

        }


        return msg;
    }

    @Override
    public void update(DTNHost host) {
        Collection<Message> messages = host.getMessageCollection();
        for ( Message message : messages ){
           // handle(message, host);

        }
    }

    @Override
    public Application replicate() {
        return new SensingApplication(this);
    }
}
