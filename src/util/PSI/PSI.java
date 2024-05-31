package util.PSI;

import java.util.HashSet;
import java.util.Set;

public class PSI {
    PSIClient psiClient;
    PSIServer psiServer;

    public PSI() {
    }

    public void addPSIClient(PSIClient psiClient) {
        if ( this.psiClient == null ){
            this.psiClient = psiClient;
        } else {
            System.out.println("Already have a PSI Client");
        }
    }

    public void addPSIServer(PSIServer psiServer) {
        if ( this.psiServer == null ){
            this.psiServer = psiServer;
        } else {
            System.out.println("Already have a PSI Server");
        }
    }

    public void competeIntersection(){
        if ( psiClient == null || psiServer == null){
            System.err.println("PSIClient or PSIServer is null");
        }
        else {
            System.out.println("Client has " + psiClient.getStream().size() + " MAC addresses");
            System.out.println("Server has " + psiServer.getStream().size() + " MAC addresses");
            // now we have the data set, let's find the intersection
            Set<Integer> intersection = new HashSet<>(psiClient.getStream());
            intersection.retainAll(psiServer.getStream());
            System.out.println(intersection);
            System.out.println("The total number of unique nodes " + intersection.size());
        }
    }
}
