package nctu.winlab.eapauthenticator;

import org.onlab.packet.MacAddress;
import org.onosproject.net.flow.FlowRule;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.List;


class SupplicantInstalledFlowrules {
    private final static int LISTSIZE = 10;
    private Map<MacAddress, List<FlowRule>> flowrulesByMac;
    
    public SupplicantInstalledFlowrules() {
        flowrulesByMac = new HashMap<>();
    }

    public void addList(MacAddress dev, List<FlowRule> flows) {
        for (FlowRule flow : flows) {
            flowrulesByMac.computeIfAbsent(dev, k -> new ArrayList<>(LISTSIZE)).add(flow);
        }
    }

    public void add(MacAddress dev, FlowRule flow) {
        flowrulesByMac.computeIfAbsent(dev, k -> new ArrayList<>(LISTSIZE)).add(flow);
    }

    public List<FlowRule> get(MacAddress dev) {
        return flowrulesByMac.remove(dev);
    }
}
