package routing;

import core.Connection;
import core.Message;
import core.Settings;
import java.util.List;


public class ProbeRouter extends ActiveRouter{

    public ProbeRouter(Settings s) {
        super(s);
    }

    protected ProbeRouter(ProbeRouter r) {
        super(r);
    }

    @Override
    public void update() {
        super.update();

        if (!canStartTransfer()) {
            return; // can't start a new transfer
        }

        if (exchangeDeliverableMessages() != null) {
            return; // started a transfer
        }

        tryAllMessagesToAllConnections();
        dropExpiredMessages();
    }


    @Override
    public ProbeRouter replicate() {
        return new ProbeRouter(this);
    }



    @Override
    protected void dropExpiredMessages() {
        Message[] messages = getMessageCollection().toArray(new Message[0]);
        for (int i = 0; i < messages.length; i++) {
            int ttl = messages[i].getTtl();
            if (ttl <= 0) {
                deleteMessage(messages[i].getId(), false);
            }
        }
    }

    @Override
    protected Connection tryMessagesToConnections(List<Message> messages, List<Connection> connections) {
        for (int i = 0, n = connections.size(); i < n; i++) {
            Connection con = connections.get(i);

            Message started = tryAllMessages(con, messages);
        }

        return null;
    }


}

