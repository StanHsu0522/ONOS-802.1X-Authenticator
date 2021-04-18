package nctu.winlab.eapauthenticator;

import org.onlab.packet.MacAddress;

public class Supplicant {
    public String state;
    public MacAddress mac;
    public long joinTime;       // milisecond
    public Boolean ruleInstalled;
    public String name;
    public String ip;

    public Supplicant(MacAddress mac, String state, String name) {
        this.mac = mac;
        this.state = state;
        this.joinTime = 0;
        this.name = name;
        this.ip = "";
        this.ruleInstalled = false;
    }
}
