package util.PSI;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class PSI {
    private boolean USE_ENCRYPTION = true;
    PSIClient psiClient;
    PSIServer psiServer;

    public PSI() {
    }

    public void addPSIClient(PSIClient psiClient) {
        if ( this.psiClient == null ){
            this.psiClient = psiClient;
        } else {
            System.err.println("Already have a PSI Client");
        }
    }

    public void addPSIServer(PSIServer psiServer) {
        if ( this.psiServer == null ){
            this.psiServer = psiServer;
        } else {
            System.err.println("Already have a PSI Server");
        }
    }

    public void competeIntersection(){
        if ( psiClient == null || psiServer == null){
            System.err.println("PSIClient or PSIServer is null");
        }
        else {
            if ( USE_ENCRYPTION ){
                System.out.println("Client has " + psiClient.getEncryptedStream().size() + " MAC addresses");
                System.out.println("Server has " + psiServer.getEncryptedStream().size() + " MAC addresses");

                Set<List<BigInteger>> intersection = new HashSet<>(psiClient.getEncryptedStream());
                intersection.retainAll(psiServer.getEncryptedStream());
                System.out.println(intersection);
                System.out.println("The total number of unique nodes " + intersection.size());
            }
            else {
                System.out.println("Client has " + psiClient.getStream().size() + " MAC addresses");
                System.out.println("Server has " + psiServer.getStream().size() + " MAC addresses");

                Set<Integer> intersection = new HashSet<>(psiClient.getStream());
                intersection.retainAll(psiServer.getStream());
                System.out.println(intersection);
                System.out.println("The total number of unique nodes " + intersection.size());
            }

        }
    }
}
