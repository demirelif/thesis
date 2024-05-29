package util.PSI;

import java.math.BigInteger;
import java.net.ServerSocket;

// Performs simple hashing
public class PSIServer {
    private BigInteger OPRFServerKey = new BigInteger("1234567891011121314151617181920");

    private void ServerOnline(){
        //int port = 4470;
        //ServerSocket serverSocket;
        double logNoOfHashes = Math.log(Parameters.NUMBER_OF_HASHES) / Math.log(2) + 1;
        int base = (int) Math.pow(2, Parameters.ELL);
        int miniBinCapacity = Parameters.BIN_CAPACITY / Parameters.ALPHA;
        double log2 = Math.log(miniBinCapacity) / Math.log(2);
        int logBELL = (int) ( log2 + 1 );

    }
}
