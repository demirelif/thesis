package util.SealPSI.Cuckoo;

import util.SealPSI.Cuckoo.OPRF.OPRFReceiver;

public class PSIServer {
    private OPRFReceiver oprfReceiver;

    public PSIServer(){
        oprfReceiver = new OPRFReceiver();

    }
}
