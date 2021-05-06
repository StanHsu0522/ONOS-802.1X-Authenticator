/*
 * Copyright 2020-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nctu.winlab.eapauthenticator;

//import org.onosproject.core.ApplicationId;
//import org.onosproject.core.CoreService;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.opencord.aaa.AaaMachineStatisticsService;
import org.opencord.aaa.AuthenticationService;
import org.opencord.aaa.AuthenticationRecord;
import org.opencord.aaa.AuthenticationEvent;
import org.opencord.aaa.AuthenticationEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;
import static org.onlab.util.Tools.get;

import java.net.InetAddress;
import java.util.Dictionary;
import java.util.Properties;
import java.util.List;
import java.util.Map;
import java.util.Collection;
import java.util.Set;
import java.util.HashSet;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Timer;

import org.onlab.packet.MacAddress;
import org.onlab.packet.IpAddress;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
// import org.onlab.packet.ICMP;
import org.onlab.packet.IpPrefix;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.net.topology.TopologyCluster;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.Path;
import org.onosproject.net.Link;
// import org.onosproject.net.Host;
// import org.onosproject.net.HostId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.host.HostService;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.meter.MeterService;
import org.onosproject.net.meter.MeterRequest;
import org.onosproject.net.meter.DefaultMeterRequest;
import org.onosproject.net.meter.Band;
import org.onosproject.net.meter.DefaultBand;
import org.onosproject.net.meter.Meter;
// import org.onosproject.dhcp.DhcpService;
// import org.onosproject.dhcp.DhcpStore;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
           service = { Authenticator8021xService.class },
           property = {
                "someProperty=Some Default String Value",
            })
public class Authenticator8021xManager implements Authenticator8021xService {

    private static final String FACULTY = "faculty";
    private static final String GUEST = "guest";
    private static final String STAFF = "staff";
    private static final String STUDENT = "student";

    // web's domain name.
    private static final String VIDEOWEB = "video";
    private static final String NCTUNEWE3 = "e3new.nctu.edu.tw";
    private static final String NCTUASSET = "assetweb.nctu.edu.tw";
    // private static final String COOLPC = "coolpc.com.tw";
    // private static final String PCHOME = "pchome.com.tw";
    // private static final String YOUTUBE = "youtube.com";

    // webs which do not have domain name.
    private static final String VIDEOWEBIP = "140.113.194.235";
    private static final String MONITORIP = "192.168.44.103";
    private static final String GATEWAYMAC = "ea:e9:78:fb:fd:00";
    private final ConnectPoint gwCp = ConnectPoint.fromString​("of:000078321bdf7000/10");
    private final ConnectPoint monitorCp = ConnectPoint.fromString​("of:000078321bdf7000/9");
    private static final int DHCPNETMASKLEN = 27;
    // private static Ip4Prefix dhcpNet;

    /** Configure Flow Priority & HardTimeout & Meter rate.*/
    private static final int FLOWPRIORITY = 60000;
    private static final int FORBIDFLOWPRIORITY = 60001;
    private static final int FORWARDINGPRIORITY = 50000;
    private static final int FORBIDFORWARDINGPRIORITY = 50001;
    private static final int FORBIDDHCPFLOWPRIORITY = 40001;
    private static final int FACULTYTIMEOUT =   36000;            // in second
    private static final int STAFFTIMEOUT =     36000;            // in second
    private static final int STUDENTTIMEOUT =   36000;            // in second
    private static final int GUESTTIMEOUT =     180;            // in second
    private static final int FACULTYRATE =  120000;              // in Kbps
    private static final int STAFFRATE =    90000;               // in Kbps
    private static final int STUDENTRATE =  60000;                // in Kbps
    private static final int GUESTRATE =    30000;                 // in Kbps
    private static final long TIMEOUTCHECKFREQUENCY = 10000;

    private String someProperty;
    private ApplicationId appId;

    private final Logger log = LoggerFactory.getLogger(getClass());
    private final AuthenticationLog authenLog = new AuthenticationLog();
    private ReactivePacketProcessor processor = new ReactivePacketProcessor();
    private final AuthenticationEventListener authenticationEventHandler = new InternalAuthenticationEventListener();
    private final Timer timer = new Timer();

    /** User Groups (i.e. Faculty, Staff, Student & Guest)
     * (Group --> user_name)
    */
    private HashMap<String, AuthenticationGroupConfig> groups = new HashMap<>();

    /** Cache DNS resolve i.e. <Domain name, IP address>.
     *  (Domain_name --> resovled_IP_address)
    */
    private HashMap<String, ArrayList<IpAddress>> dnsTable = new HashMap<>();

    /** Denying list for different user types.
     *  (User_type --> list_of_resolved_ip_address)
    */
    private HashMap<String, ArrayList<IpAddress>> deny = new HashMap<>();

    /** ACL for different users.
     *  (MAC_address --> User_type)
    */
    private HashMap<MacAddress, String> acl = new HashMap<>();

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected AaaMachineStatisticsService aaaMachineStatsManager;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected AuthenticationService aaaManager;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected MeterService meterService;

    // @Reference(cardinality = ReferenceCardinality.MANDATORY)
    // protected DhcpService dhcpService;

    @Activate
    protected void activate() {
        // cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("nctu.winlab.eapauthenticator");
        // dhcpNet = Ip4Prefix.valueOf("192.168.44.164/27");
        log.info("Started");

        aaaManager.addListener(authenticationEventHandler);
        packetService.addProcessor(processor, PacketProcessor.director(2));
        requestIntercepts();

        tableInit();
        initialFlowRules();

        // Timeout check per TIMEOUTCHECKFREQUENCY (in minisecond).
        timer.schedule(new TimeoutChecker(), 5000, TIMEOUTCHECKFREQUENCY);
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        aaaManager.removeListener(authenticationEventHandler);
        packetService.removeProcessor(processor);
        withdrawIntercepts();
        timer.cancel();
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
    }

    @Override
    public void getAllUsers() {
        authenLog.getAllUsers();
    }

    @Override
    public void getBadUsers() {
        authenLog.getBadUsers();
    }

    /**
     * Access control list initilization.
     * */
    private void tableInit() {
        /**
         * Resolve domain name.
        */
        dnsTable.put(NCTUNEWE3, new ArrayList<IpAddress>());
        dnsTable.put(NCTUASSET, new ArrayList<IpAddress>());
        // dnsTable.put(COOLPC, new ArrayList<IpAddress>());
        // dnsTable.put(YOUTUBE, new ArrayList<IpAddress>());
        // dnsTable.put(PCHOME, new ArrayList<IpAddress>());
        for (Entry<String, ArrayList<IpAddress>> entry : dnsTable.entrySet()) {
            try {
                InetAddress[] ips = InetAddress.getAllByName(entry.getKey());
                // Type-cast from InetAddress to IpAdress
                for (InetAddress ip : ips) {
                    entry.getValue().add(IpAddress.valueOf(ip));
                }
            } catch (Exception e) {
                log.info("Error: @tableInit() Domain Name resolve!");
                return;
            }
        }
        // sites without domain name
        dnsTable.put(VIDEOWEB, new ArrayList<IpAddress>() {
            {
                add(IpAddress.valueOf(VIDEOWEBIP));
            }
        });

        //Print out the whole deny list
        log.info("[DNS Table]");
        for (Entry<String, ArrayList<IpAddress>> entry : dnsTable.entrySet()) {
            log.info("**'" + entry.getKey() + "'");
            for (IpAddress ip : entry.getValue()) {
                log.info(ip.toString());
            }
        }

        /**
         * Group setting.
        */
        // faculty
        AuthenticationGroupConfig facultyGroup = new AuthenticationGroupConfig();
        facultyGroup.users.add("mspuff");
        facultyGroup.users.add("cctseng");
        facultyGroup.dscp = 1;
        facultyGroup.meterRate = FACULTYRATE;
        facultyGroup.timeout = FACULTYTIMEOUT;
        // Staff
        AuthenticationGroupConfig staffGroup = new AuthenticationGroupConfig();
        staffGroup.users.add("squidward");
        staffGroup.users.add("mrkrabs");
        staffGroup.users.add("jeremy");
        staffGroup.dscp = 2;
        staffGroup.meterRate = STAFFRATE;
        staffGroup.timeout = STAFFTIMEOUT;
        // Student
        AuthenticationGroupConfig studentGroup = new AuthenticationGroupConfig();
        studentGroup.users.add("spongebob");
        studentGroup.users.add("patrick");
        studentGroup.users.add("stan");
        studentGroup.dscp = 3;
        studentGroup.meterRate = STUDENTRATE;
        studentGroup.timeout = STUDENTTIMEOUT;
        // Guest
        AuthenticationGroupConfig guestGroup = new AuthenticationGroupConfig();
        guestGroup.users.add("guest");
        guestGroup.dscp = 4;
        guestGroup.meterRate = GUESTRATE;
        guestGroup.timeout = GUESTTIMEOUT;

        groups.put(FACULTY, facultyGroup);
        groups.put(STAFF, staffGroup);
        groups.put(STUDENT, studentGroup);
        groups.put(GUEST, guestGroup);

         // Group meter setup
         for (Map.Entry<String, AuthenticationGroupConfig> gEntry : groups.entrySet()) {
            Collection<Band> bands = new ArrayList<>();
            bands.add(
                DefaultBand.builder()
                    .withRate(gEntry.getValue().meterRate)
                    .ofType(Band.Type.DROP)
                    .burstSize(gEntry.getValue().meterRate / 100)
                    .build()
            );
            MeterRequest meterReq = DefaultMeterRequest.builder()
                .forDevice(gwCp.deviceId())
                .fromApp(appId)
                .withBands(bands)
                .withUnit(Meter.Unit.KB_PER_SEC)
                .burst()
                .add();
            gEntry.getValue().meter = meterService.submit(meterReq);
        }

        /**
         * Set up deny list.
        */
        deny.put(GUEST, new ArrayList<IpAddress>());
        deny.get(GUEST).addAll(dnsTable.get(NCTUNEWE3));
        deny.get(GUEST).addAll(dnsTable.get(NCTUASSET));
        deny.put(FACULTY, new ArrayList<IpAddress>());
        deny.put(STAFF, new ArrayList<IpAddress>());
        deny.get(STAFF).addAll(dnsTable.get(VIDEOWEB));
        deny.put(STUDENT, new ArrayList<IpAddress>());
        deny.get(STUDENT).addAll(dnsTable.get(NCTUASSET));

        // Print out the whole deny list
        log.info("[ACL Table]");
        for (String k : deny.keySet()) {
            Iterator it = deny.get(k).iterator();
            log.info("{}'s: ", k);
            while (it.hasNext()) {
                log.info(it.next().toString());
            }
        }
    }

    /**
     *  Overide DHCP packet-in flow rule installed by ONOS DHCP APP.
     *  Disable this function when you don't use ONOS DHCP APP.
    */
    private void initialFlowRules() {
        List<FlowRule> flowrulesList = new ArrayList<>();
        Map<String, TrafficSelector.Builder> selectorGroupBuilders = new HashMap<>();

        // Get all network devices
        Set<DeviceId> allDevices = new HashSet<>();
        Set<TopologyCluster> clusters = topologyService.getClusters(topologyService.currentTopology());
        for (TopologyCluster cluster : clusters) {
            Set<DeviceId> devices = topologyService.getClusterDevices(topologyService.currentTopology(), cluster);
            allDevices.addAll(devices);
        }

        // selector and treatment for DHCP forbiden
        TrafficSelector.Builder selectorDhcpForbidBuilder = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4)
            .matchIPProtocol(IPv4.PROTOCOL_UDP)
            .matchUdpDst(TpPort.tpPort(UDP.DHCP_SERVER_PORT))
            .matchUdpSrc(TpPort.tpPort(UDP.DHCP_CLIENT_PORT));
        TrafficTreatment.Builder treatmentDhcpForbidBuilder = DefaultTrafficTreatment.builder().drop();

        // Create selectors for each group
        for (Map.Entry<String, AuthenticationGroupConfig> gEntry : groups.entrySet()) {
            selectorGroupBuilders.put(
                gEntry.getKey(),
                DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPDscp​(gEntry.getValue().dscp)
            );
        }

        /**
         * Install three types of flow rule
         * 1. DHCP forbidden (at each switch)
         * 2. Group forwarding (at each switch)
         * 3. Group forbidden (at core switch)
         */
        for (DeviceId deviceId : allDevices) {

            // 1. DHCP forbidden
            flowrulesList.add(
                DefaultFlowRule.builder()
                    .forTable(0)
                    .forDevice(deviceId)
                    .withSelector(selectorDhcpForbidBuilder.build())
                    .withTreatment(treatmentDhcpForbidBuilder.build())
                    .withPriority(FORBIDDHCPFLOWPRIORITY)
                    .makePermanent()
                    .fromApp(appId)
                    .build()
            );

            // 2. Group forwarding
            TrafficTreatment.Builder treatmentGroupBuilder;
            if (!deviceId.equals(gwCp.deviceId())) {
                Path path = calculatePath(ConnectPoint.fromString​(deviceId.toString() + "/1"), gwCp);
                if (path == null) {
                    log.info("Error: @initialFlowRules() Can't get path to gateway!");
                    return;
                }
                treatmentGroupBuilder = DefaultTrafficTreatment.builder()
                    .setOutput(path.src().port());
                for (TrafficSelector.Builder selectorGroup : selectorGroupBuilders.values()) {
                    flowrulesList.add(
                        DefaultFlowRule.builder()
                        .forTable(0)
                        .forDevice(deviceId)
                        .withSelector(selectorGroup.build())
                        .withTreatment(treatmentGroupBuilder.build())
                        .withPriority(FORWARDINGPRIORITY)
                        .makePermanent()
                        .fromApp(appId)
                        .build()
                    );
                }
            } else {
                Map<String, TrafficTreatment.Builder> treatmentGroupBuilders = new HashMap<>();
                for (Map.Entry<String, AuthenticationGroupConfig> gEntry : groups.entrySet()) {
                    treatmentGroupBuilders.put(
                        gEntry.getKey(),
                        DefaultTrafficTreatment.builder()
                            .setOutput(gwCp.port())
                            .setIpDscp((byte) 0)
                            .meter(gEntry.getValue().meter.id())
                    );
                }
                for (String group : groups.keySet()) {
                    flowrulesList.add(
                        DefaultFlowRule.builder()
                        .forTable(0)
                        .forDevice(deviceId)
                        .withSelector(selectorGroupBuilders.get(group).build())
                        .withTreatment(treatmentGroupBuilders.get(group).build())
                        .withPriority(FORWARDINGPRIORITY)
                        .makePermanent()
                        .fromApp(appId)
                        .build()
                    );
                }
            }
        }

        // 3. Group forbidden
        for (Map.Entry<String, AuthenticationGroupConfig> gEntry : groups.entrySet()) {
            for (IpAddress ip : deny.get(gEntry.getKey())) {
                TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder()
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPDscp​(gEntry.getValue().dscp)
                    .matchIPDst(Ip4Prefix.valueOf(ip, Ip4Prefix.MAX_MASK_LENGTH));
                TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder()
                    .drop();
                flowrulesList.add(
                    DefaultFlowRule.builder()
                        .forTable(0)
                        .forDevice(gwCp.deviceId())
                        .withSelector(selectorBuilder.build())
                        .withTreatment(treatmentBuilder.build())
                        .withPriority(FORBIDFORWARDINGPRIORITY)
                        .makePermanent()
                        .fromApp(appId)
                        .build()
                );
            }
        }

        FlowRule[] flowrulesArr = new FlowRule[flowrulesList.size()];
        // List to arrray casting.
        flowrulesArr = flowrulesList.toArray(flowrulesArr);
        flowRuleService.applyFlowRules(flowrulesArr);
    }

    private class ReactivePacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            MacAddress srcMac = ethPkt.getSourceMAC();

            if (ethPkt == null) {
                return;
            }

            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                if (acl.containsKey(srcMac)) {
                    if (!authenLog.tb.get(srcMac).ruleInstalled) {
                        normalPkt(context, srcMac);
                    }
                } else {
                    // log.info("User ({}) is NOT authenticated!", ethPkt.getSourceMAC());
                }
            }
        }
    }

    private void normalPkt(PacketContext context, MacAddress mac) {
        log.info("enter @normalPkt()");
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
        IpAddress srcIp = IpAddress.valueOf(ipv4Packet.getSourceAddress());
        ConnectPoint clientCp = pkt.receivedFrom();

        authenLog.tb.get(mac).ruleInstalled = true;
        authenLog.tb.get(mac).ip = srcIp.toString();

        List<FlowRule> flowrules = new ArrayList<>();
        String userType = acl.get(mac);
        log.info("UserTypeeeeeeeee: {}", userType);
        AuthenticationGroupConfig group = groups.get(userType);

        Path path = calculatePath(clientCp, gwCp);
        if (path == null) {
            log.info("Error: @normalPkt() Can't get path to gateway!");
            return;
        } else {
            TrafficSelector.Builder selectorBuilderIn = DefaultTrafficSelector.builder()
                .matchEthDst(mac)
                .matchEthType(Ethernet.TYPE_IPV4);
            TrafficSelector.Builder selectorBuilderOut = DefaultTrafficSelector.builder()
                .matchEthSrc(mac)
                .matchEthType(Ethernet.TYPE_IPV4);
            TrafficTreatment.Builder treatmentBuilderOut = DefaultTrafficTreatment.builder()
                .setOutput(path.src().port())
                .setIpDscp(group.dscp);

            flowrules.add(
                DefaultFlowRule.builder()
                    .forTable(0)
                    .forDevice(clientCp.deviceId())
                    .withSelector(selectorBuilderOut.build())
                    .withTreatment(treatmentBuilderOut.build())
                    .withPriority(FLOWPRIORITY)
                    .withHardTimeout(group.timeout)
                    .fromApp(appId)
                    .build()
            );

            // Installing backward flow rule for user
            // path:    link1 ---- link2 ---- ... ---- linkn
            //       (src   dst)(src   dst)   ...   (src   dst)
            //        clientCp                          geCp
            for (Link link : path.links()) {
                TrafficTreatment.Builder treatmentBuilderIn = DefaultTrafficTreatment.builder()
                    .setOutput(link.dst().port());
                flowrules.add(
                    DefaultFlowRule.builder()
                        .forTable(0)
                        .forDevice(link.dst().deviceId())
                        .withSelector(selectorBuilderIn.build())
                        .withTreatment(treatmentBuilderIn.build())
                        .withPriority(FLOWPRIORITY)
                        .withHardTimeout(group.timeout)
                        .fromApp(appId)
                        .build()
                );
            }

            // Last device (clientCp)
            TrafficTreatment.Builder lastTreatmentBuilderIn = DefaultTrafficTreatment.builder()
                .setOutput(clientCp.port());
            flowrules.add(
                DefaultFlowRule.builder()
                    .forTable(0)
                    .forDevice(clientCp.deviceId())
                    .withSelector(selectorBuilderIn.build())
                    .withTreatment(lastTreatmentBuilderIn.build())
                    .withPriority(FLOWPRIORITY)
                    .withHardTimeout(group.timeout)
                    .fromApp(appId)
                    .build()
            );
        }

        // Install path between monitor (plot client) and supplicant (plot server).
        Path monitorPath = calculatePath(clientCp, monitorCp);
        if (monitorPath == null) {
            log.info("Error: @normalPkt() Can't get path to monitor!");
            return;
        } else {
            TrafficSelector.Builder selectorBuilderOut = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPDst(IpPrefix.valueOf(IpAddress.valueOf(MONITORIP),
                                                Ip4Prefix.MAX_INET_MASK_LENGTH));
            TrafficSelector.Builder selectorBuilderIn = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPSrc(IpPrefix.valueOf(IpAddress.valueOf(MONITORIP),
                                                Ip4Prefix.MAX_INET_MASK_LENGTH));

            for (Link link : path.links()) {
                TrafficTreatment.Builder treatmentBuilderOut = DefaultTrafficTreatment.builder()
                    .setOutput(link.src().port());
                TrafficTreatment.Builder treatmentBuilderIn = DefaultTrafficTreatment.builder()
                    .setOutput(link.dst().port());
                flowrules.add(
                    DefaultFlowRule.builder()
                        .forTable(0)
                        .forDevice(link.src().deviceId())
                        .withSelector(selectorBuilderOut.build())
                        .withTreatment(treatmentBuilderOut.build())
                        .withPriority(FLOWPRIORITY)
                        .withHardTimeout(group.timeout)
                        .fromApp(appId)
                        .build()
                );
                flowrules.add(
                    DefaultFlowRule.builder()
                        .forTable(0)
                        .forDevice(link.dst().deviceId())
                        .withSelector(selectorBuilderIn.build())
                        .withTreatment(treatmentBuilderIn.build())
                        .withPriority(FLOWPRIORITY)
                        .withHardTimeout(group.timeout)
                        .fromApp(appId)
                        .build()
                );
            }

            // Last device (clientCp & monitorCp)
            TrafficTreatment.Builder lastTreatmentBuilderOut = DefaultTrafficTreatment.builder()
                .setOutput(monitorCp.port());
            TrafficTreatment.Builder lastTreatmentBuilderIn = DefaultTrafficTreatment.builder()
                .setOutput(clientCp.port());
            flowrules.add(
                DefaultFlowRule.builder()
                    .forTable(0)
                    .forDevice(monitorCp.deviceId())
                    .withSelector(selectorBuilderOut.build())
                    .withTreatment(lastTreatmentBuilderOut.build())
                    .withPriority(FLOWPRIORITY)
                    .withHardTimeout(group.timeout)
                    .fromApp(appId)
                    .build()
            );
            flowrules.add(
                DefaultFlowRule.builder()
                    .forTable(0)
                    .forDevice(clientCp.deviceId())
                    .withSelector(selectorBuilderIn.build())
                    .withTreatment(lastTreatmentBuilderIn.build())
                    .withPriority(FLOWPRIORITY)
                    .withHardTimeout(group.timeout)
                    .fromApp(appId)
                    .build()
            );
        }

        FlowRule[] flowrulesArr = new FlowRule[flowrules.size()];
        // List to array casting.
        flowrulesArr = flowrules.toArray(flowrulesArr);
        flowRuleService.applyFlowRules(flowrulesArr);

        // Send packet to rematch from the start of pipeline.
        packetOut(context, PortNumber.TABLE);
    }

    private Path calculatePath(ConnectPoint cp1, ConnectPoint cp2) {
        Set<Path> paths =
            topologyService.getPaths(topologyService.currentTopology(),
                                    cp1.deviceId(),
                                    cp2.deviceId());
        if (paths.isEmpty()) {
            log.info("Error: @calculatePath() Path is empty when calculate Path");
            return null;
        }

        // Pick a path that does not lead back to where the client is.
        Path path = pickForwardPathIfPossible(paths, cp1.port());
        if (path == null) {
            log.info("Error: @calculatePath() Don't know where to go from here {} to Gateway {}",
                        cp1,
                        cp2);
            return null;
        } else {
            return path;
        }
    }

    private Path pickForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
        for (Path path : paths) {
            if (!path.dst().port().equals(notToPort)) {
                return path;
            }
        }
        return null;
    }

    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    private class InternalAuthenticationEventListener implements AuthenticationEventListener {
        @Override
        public void event(AuthenticationEvent event) {
            AuthenticationRecord aaaAuthenticationRecord = event.authenticationRecord();
            String state = aaaAuthenticationRecord.state();

            if (state.equals("IDLE_STATE")) {
                return;
            }

            MacAddress supMac = aaaAuthenticationRecord.supplicantAddress();
            ConnectPoint connectp = aaaAuthenticationRecord.supplicantConnectPoint();
            String uname = new String(aaaAuthenticationRecord.username());

            log.info("\n************* Authentication Event **************"      +
                    "\n***** SupplicantMacAddress: " + supMac.toString()        +
                    "\n***** ConnectPoint:         " + connectp.toString()      +
                    "\n***** UserName:             " + uname                    +
                    "\n***** State:                " + state);

            // Recording each user's info
            if (!authenLog.tb.containsKey(supMac) && !state.equals("AUTHORIZED_STATE")) {
                Supplicant u = new Supplicant(supMac, state, uname);
                authenLog.tb.put(supMac, u);
            // Updating user log
            } else {
                if (authenLog.tb.get(supMac).name.equals(uname)) {
                    authenLog.tb.get(supMac).state = state;
                }
            }

            /** Some user was authenticated. */
            if (state.equals("AUTHORIZED_STATE")) {
                Date date = new Date();

                // Skip the authorized user
                if (acl.containsKey(supMac)) {
                    if (authenLog.tb.get(supMac).state.equals("AUTHORIZED_STATE")) {
                        log.info("Skip adding user({})", supMac.toString());
                        return;
                    }
                }

                /** Set up ACL. */
                for (Map.Entry<String, AuthenticationGroupConfig> gEntry : groups.entrySet()) {
                    Set tmpset = gEntry.getValue().users;
                    if (tmpset.contains(uname)) {
                        acl.put(supMac, gEntry.getKey());
                        authenLog.tb.get(supMac).joinTime = date.getTime();
                        break;
                    }
                }
                if (!acl.containsKey(supMac)) {
                    log.info("Error: @event() The user({}) is not a registered user!", supMac);
                    return;
                }

                dhcpAllow(supMac, connectp);
            }
        }

        /**
         * Allow DHCP.
         * @param supMac
         * @param cp
         */
        private void dhcpAllow(MacAddress supMac, ConnectPoint cp) {
            log.info("enter @ dhcpAllow()");
            // List<FlowRule> flowrulesDhcpAllowList = new ArrayList<>();
            String userType = acl.get(supMac);
            AuthenticationGroupConfig group = groups.get(userType);

            TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder()
                .matchEthSrc(supMac)
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_UDP)
                .matchUdpDst(TpPort.tpPort(UDP.DHCP_SERVER_PORT))
                .matchUdpSrc(TpPort.tpPort(UDP.DHCP_CLIENT_PORT));
            TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder()
                .setOutput(PortNumber.CONTROLLER);
            FlowRule flow = DefaultFlowRule.builder()
                .forTable(0)
                .forDevice(cp.deviceId())
                .withSelector(selectorBuilder.build())
                .withTreatment(treatmentBuilder.build())
                .withPriority(FLOWPRIORITY)
                .withHardTimeout(group.timeout)
                .fromApp(appId)
                .build();
            flowRuleService.applyFlowRules(flow);
        }
    }

    private class TimeoutChecker extends java.util.TimerTask {

        @Override
        public void run() {
            Date date = new Date();

            for (Map.Entry<MacAddress, Supplicant> entry : authenLog.tb.entrySet()) {
                Supplicant sup = entry.getValue();
                String userType = acl.get(sup.mac);
                AuthenticationGroupConfig group = groups.get(userType);
                long testPeriod = date.getTime() - sup.joinTime;
                if ((int) testPeriod > group.timeout * 1000) {
                    MacAddress mac = entry.getKey();
                    log.info("*** User ({} {} {}) authentication Timeout!!",
                    sup.name,
                    sup.mac.toString(),
                    sup.ip);
                    authenLog.tb.remove(mac);
                    acl.remove(mac);
                    aaaManager.removeAuthenticationStateByMac(mac);

                    /**
                     * TODO: DHCP release
                     */
                    // log.info("DHCPPPPPPPPPPPPPPPPPPP {}", dhcpService.getLeaseTime());
                }
            }
            // log.info("Authentication Timeout checked!s   {}", date);
        }
    }
}
