package util.PSI;

import java.util.ArrayList;

public abstract class AbstractPSIClient<T> {
    /** Maximum number of elements inside client's set */
    private int maxElementSize;
    /** The element set of client */
    protected ArrayList<T> elements;

    protected AbstractPSIClient(ArrayList<T> elements) {
        this.elements = elements;
    }
}
