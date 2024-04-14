/*
 * Copyright 2010 Aalto University, ComNet
 * Released under GPLv3. See LICENSE.txt for details.
 */
package movement;

import core.Coord;
import core.Settings;
import core.SimScenario;

/**
 * Movement model where all nodes move on a line
 * from one end of the simulation area to the other,
 * reappearing at the starting point once they reach
 * the waypoint (at the end)
 */
public class StreetMovement extends MovementModel {
	/** Name space of the settings (append to group name space) */
	public static final String STREET_MOVEMENT_NS = "StreetMovement.";

	/* values for the prototype */
	private int startLoc; /** The start location of the line */
	private int endLoc; /** The end location of the line */

	/* this will be used for splitting nodes into two groups */
	private int nodeCount; /** how many nodes in this formation */
	private int lastIndex; /** index of the previous node */

	/* values for the per-node models */
	private Path nextPath;
	private Coord initLoc;
	private Coord endPoint;

	private int y;

	/**
	 * Creates a new movement model based on a Settings object's settings.
	 * @param s The Settings object where the settings are read from
	 */
	public StreetMovement(Settings s) {
		super(s);

		this.startLoc = 0;
		this.endLoc = super.getMaxX();

		this.nodeCount = s.getInt(core.SimScenario.NROF_HOSTS_S);
		this.lastIndex = 0;
	}

	/**
	 * Copy constructor.
	 * @param sm The StreetMovement prototype
	 */
	public StreetMovement(StreetMovement sm) {
		super(sm);
		this.y = (int) (super.getMaxY() * MovementModel.rng.nextDouble());
		this.initLoc = new Coord(0, this.y);
		this.nextPath = new Path(generateSpeed());
		this.nextPath.addWaypoint(initLoc);

		this.endPoint = new Coord(sm.endLoc, this.initLoc.getY());
		this.nextPath.addWaypoint(endPoint);
		//sm.lastIndex++;
	}


	/**
	 * Returns the the location of the node in the formation
	 * @return the the location of the node in the formation
	 */
	@Override
	public Coord getInitialLocation() {
		return new Coord( 0, this.y );
	}

	@Override
	public Path getPath() {
		Path p = new Path();
		super.getHost().setLocation( new Coord( 0, this.y ) );
		p.addWaypoint( new Coord(SimScenario.getInstance().getWorldSizeX(), this.y), generateSpeed());
		this.y = (int) (MovementModel.rng.nextDouble() * SimScenario.getInstance().getWorldSizeY());
		return p;
	}

	/**
	 * Returns Double.MAX_VALUE (no paths available)
	 */
	@Override
	public double nextPathAvailable() {
		if (nextPath == null) {
			return Double.MAX_VALUE;	// no new paths available
		} else {
			return 0;
		}
	}



	@Override
	public StreetMovement replicate() {
		return new StreetMovement(this);
	}

}
