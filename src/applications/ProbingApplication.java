/*
 * Copyright 2010 Aalto University, ComNet
 * Released under GPLv3. See LICENSE.txt for details.
 */

package applications;

import core.*;

import java.util.Random;

/**
 * The application generates probe messages and sends them to a specified
 * destination range (the destination addresses of the sensors). When a
 * sensor (host) receives the message, it processes it for crowd-counting.
 *
 * @author kaerkkal
 */
public class ProbingApplication extends Application {
	/** Probe generation interval */
	public static final String PROBE_INTERVAL = "interval";
	/** Destination address range - inclusive lower, exclusive upper */
	public static final String PROBE_DEST_RANGE = "destinationRange";
	/** Seed for the app's random number generator */
	public static final String PROBE_SEED = "seed";
	/** Size of the probe message */
	public static final String PROBE_SIZE = "probeSize";

	/** Application ID */
	public static final String APP_ID = "de.in.tum.ProbingApplication";

	// Private vars
	private double	lastProbe = 0;
	private double	interval = 10;	/* send one probe every 10 seconds. this interval is configurable */
	private int		seed = 0;
	private int		destMin=0;
	private int		destMax=1;
	private int		probeSize=1;
	private int		pongSize=1;
	private Random	rng;

	/**
	 * Creates a new probing application with the given settings.
	 *
	 * @param s	Settings to use for initializing the application.
	 */
	public ProbingApplication(Settings s) {
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
	 * @param a
	 */
	public ProbingApplication(ProbingApplication a) {
		super(a);
		this.lastProbe = a.getLastProbe();
		this.interval = a.getInterval();
		this.destMax = a.getDestMax();
		this.destMin = a.getDestMin();
		this.seed = a.getSeed();
		this.pongSize = a.getPongSize();
		this.probeSize = a.getprobeSize();
		this.rng = new Random(this.seed);
	}

	/**
	 * Sends a probe packet if this is an active application instance.
	 *
	 * @param host to which the application instance is attached
	 */
	@Override
	public void update(DTNHost host) {
		double curTime = SimClock.getTime();

		if (host.getAddress() >= destMin && host.getAddress() <= destMax) {
			return;
		}
		if (curTime - this.lastProbe >= this.interval * rng.nextDouble()) {
			/** sends a new probe after some random time no longer than interval
			 * messages get unique IDs labeled with string "probe-SimTime-hostAddr"
			 * so each message can be tracked to the original host
			*/
			DTNHost receiver = randomHost();
			Message m = new Message(host, receiver, "probe" + "-" +
					SimClock.getIntTime() + "-" + host.getAddress(),
					getprobeSize());
			m.addProperty("type", "probe");
			m.setAppID(APP_ID);
			host.createNewMessage(m);
			host.sendMessage(m.getId(), receiver);

			// Call listeners
			super.sendEventToListeners("ProbeSent", null, host);

			this.lastProbe = curTime;
		}
	}


	/**
	 * Handles an incoming message. If the message is a probe packet, the router
	 * keeps a log for further processing (still work in progress).
	 *
	 * @param msg	message received by the router
	 * @param host	host to which the application instance is attached
	 */
	@Override
	public Message handle(Message msg, DTNHost host) {

		String type = (String)msg.getProperty("type");
		if (type == null) return msg; // Not a probe message
		if (msg.getFrom() == host && type.equalsIgnoreCase("probe")) {


			/**
			 *  placeholder for the actual processing of the received probe
			 */

			// The message identifier
			String id = "probe-" + SimClock.getIntTime() + "-" + host.getAddress();
			Message m = new Message(host, msg.getFrom(), id, getprobeSize());
			m.addProperty("type", "probe");
			m.setAppID(APP_ID);
			host.createNewMessage(m);



			super.sendEventToListeners("GotPing", null, host);
			super.sendEventToListeners("SentPong", null, host);
		}
		return msg;
	}

	/**
	 * Draws a random host from the destination range
	 *
	 * @return host
	 */
	private DTNHost randomHost() {
		int destaddr = 0;
		if (destMax == destMin) {
			destaddr = destMin;
		}
		destaddr = destMin + rng.nextInt(destMax - destMin);
		World w = SimScenario.getInstance().getWorld();
		return w.getNodeByAddress(destaddr);
	}

	@Override
	public Application replicate() {
		return new ProbingApplication(this);
	}

	/**
	 * @return the lastProbe
	 */
	private double getLastProbe() {
		return lastProbe;
	}

	/**
	 * @param lastProbe the lastProbe to set
	 */
	public void setlastProbe(double lastProbe) {
		this.lastProbe = lastProbe;
	}

	/**
	 * @return the interval
	 */
	public double getInterval() {
		return interval;
	}

	/**
	 * @param interval the interval to set
	 */
	public void setInterval(double interval) {
		this.interval = interval;
	}

	/**
	 * @return the destMin
	 */
	public int getDestMin() {
		return destMin;
	}

	/**
	 * @param destMin the destMin to set
	 */
	public void setDestMin(int destMin) {
		this.destMin = destMin;
	}

	/**
	 * @return the destMax
	 */
	public int getDestMax() {
		return destMax;
	}

	/**
	 * @param destMax the destMax to set
	 */
	public void setDestMax(int destMax) {
		this.destMax = destMax;
	}

	/**
	 * @return the seed
	 */
	public int getSeed() {
		return seed;
	}

	/**
	 * @param seed the seed to set
	 */
	public void setSeed(int seed) {
		this.seed = seed;
	}

	/**
	 * @return the pongSize
	 */
	public int getPongSize() {
		return pongSize;
	}

	/**
	 * @param pongSize the pongSize to set
	 */
	public void setPongSize(int pongSize) {
		this.pongSize = pongSize;
	}

	/**
	 * @return the probeSize
	 */
	public int getprobeSize() {
		return probeSize;
	}

	/**
	 * @param probeSize the probeSize to set
	 */
	public void setprobeSize(int probeSize) {
		this.probeSize = probeSize;
	}

}
