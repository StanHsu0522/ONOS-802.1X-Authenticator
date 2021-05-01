package nctu.winlab.eapauthenticator;

import org.onosproject.net.meter.Meter;
import java.util.Set;
import java.util.HashSet;

public class AuthenticationGroupConfig {
    protected Set<String> users;
    protected byte dscp;
    protected Meter meter;
    protected long meterRate;
    protected int timeout;

    public AuthenticationGroupConfig() {
        users = new HashSet<>();
        dscp = 0;
        meterRate = 0;
        timeout = 0;
    }
}
