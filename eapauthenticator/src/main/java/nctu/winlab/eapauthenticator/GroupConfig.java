package nctu.winlab.eapauthenticator;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.jline.utils.Log;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.TpPort;
import org.onosproject.net.meter.Meter;

public class GroupConfig {
    public byte dscp;            // ip-dscp
    public long meterRate;       // kbps
    public int timeout;          // second
    public Meter meter;
    public List<Destination> acl;    // deny access to these domains

    public GroupConfig() {
        dscp = 0;
        meterRate = 0;
        timeout = 0;
        meter = null;
        acl = new ArrayList<>();
    }

    public void addACL(String domain, String ip, int port, byte protocol) {
        if (domain != null) {
            List <InetAddress> ips = null;
            try {
                ips = Arrays.asList(InetAddress.getAllByName(domain));
            } catch (UnknownHostException e) {
                Log.info("Error: " + e.getMessage());
            }
            for (InetAddress inA : ips) {
                acl.add(new Destination(IpAddress.valueOf(inA) , port, protocol));
            }
        }
        else if (ip != null) {
            acl.add(new Destination(IpAddress.valueOf(ip), port, protocol));
        }
    }

    public class Destination {
        public IpPrefix ip;
        public TpPort port;
        public byte protocol;

        public Destination(IpAddress ip, int port, byte protocol) {
            this.ip = IpPrefix.valueOf(ip, IpPrefix.MAX_INET_MASK_LENGTH);
            this.port = (port == TpPort.MIN_PORT) ? null : TpPort.tpPort(port);
            this.protocol = protocol;
        }
    }
}
