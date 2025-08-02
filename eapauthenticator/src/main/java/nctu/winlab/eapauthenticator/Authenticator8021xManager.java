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
import org.onosproject.cli.net.IpProtocol;
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
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;
import static org.onlab.util.Tools.get;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.Properties;
import java.util.List;
import java.util.Map;
import java.util.Collection;
import java.util.Set;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.Map.Entry;

import javax.sound.sampled.Port;

import org.onlab.packet.MacAddress;
import org.onlab.packet.RADIUS;
import org.onlab.packet.RADIUSAttribute;
import org.onlab.packet.IpAddress;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onlab.packet.EthType.EtherType;
import org.onlab.packet.dhcp.Dhcp6LeaseQueryOption;
import org.onlab.packet.IpPrefix;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.net.topology.TopologyCluster;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.Path;
import org.onosproject.net.Link;
import org.onosproject.net.DeviceId;
import org.onosproject.net.host.HostService;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.criteria.Criterion.Type;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleEvent;
import org.onosproject.net.flow.FlowRuleListener;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.meter.MeterService;
import org.onosproject.net.meter.MeterState;
import org.onosproject.net.meter.MeterRequest;
import org.onosproject.net.meter.DefaultMeterRequest;
import org.onosproject.net.meter.Band;
import org.onosproject.net.meter.DefaultBand;
import org.onosproject.net.meter.Meter;

import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.DriverManager;
import java.sql.PreparedStatement;

import com.fasterxml.jackson.annotation.JsonProperty.Access;
import com.mysql.cj.jdbc.Driver;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
           service = { Authenticator8021xService.class },
           property = {
                "someProperty=Some Default String Value",
            })
public class Authenticator8021xManager implements Authenticator8021xService {

    private static final String APP_NAME = "nctu.winlab.eapauthenticator";
    protected static final String RADIUS_HOST = "192.168.44.128";
    protected static final MacAddress RADIUS_MAC = MacAddress.valueOf("02:42:ac:11:00:02");
    protected static final int RADIUS_AUTH_PORT = 1812;
    protected static final short SOCKET_BIND_PORT = 9998;
    private static final int UDP_HEADER_LENGTH = 8;
    private static final int PASSWDERRLIMIT = 3;
    private static final int PACKET_RECORD_TIMEOUT = 60;    // in second
    private static final int BLOCKPERIOD = 180;             // in second
    private static final int ERRRSTPERIOD = 60;             // in second
    // private static final String MONITORIP = "192.168.44.103";
    // private final ConnectPoint MONITOR_CONNECT_POINT = ConnectPoint.fromString​("of:000078321bdf7000/9");
    private static final MacAddress GATEWAYMAC = MacAddress.valueOf("D6:D1:77:B1:10:CD");
    private final ConnectPoint GATE_WAY_CONNECT_POINT = ConnectPoint.fromString​("of:000078321bdf7000/1");
    private static final ConnectPoint RADIUS_SERVER_CONNCECT_POINT = ConnectPoint.fromString​("of:000078321bdf7000/12");

    // Configure Flow Priority
    // private static final int FORBIDFLOWPRIORITY = 60001;
    private static final int FLOWPRIORITY = 60000;
    private static final int FORBIDFORWARDINGPRIORITY = 50001;
    private static final int FORWARDINGPRIORITY = 50000;
    private static final int FORBIDDHCPFLOWPRIORITY = 40001;

    // mysql database parameter
    private String dbUrl = "jdbc:mysql://localhost:3306/SDN1X";
    private String dbUser = "stan";
    private String dbPassword = "0416401kh09";

    private String someProperty;

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

    private ApplicationId appId;
    private final Logger log = LoggerFactory.getLogger(getClass());
    private final SupplicantInstalledFlowrules supFlowrules = new SupplicantInstalledFlowrules();
    private final AuthenticationEventListener authenticationEventHandler = new InternalAuthenticationEventListener();
    private final FlowRuleListener flowRuleHandler = new InternalFlowRuleEventListener();
    private final Authenticator8021xCommandImpl commandImpl = new Authenticator8021xCommandImpl();

    // our application-specific event handler for processing user packet-in
    private final ReactivePacketProcessor reactiveProcessor = new ReactivePacketProcessor();

    // our application-specific event handler for processing RADIUS packet
    private final RadiusPacketProcessor radiusProcessor = new RadiusPacketProcessor();

    // Socket based communicator with the RADIUS server
    // SocketBasedRadiusCommunicator comm;
    Map<DeviceId, SocketBasedRadiusCommunicator> commmunicators;

    @Activate
    protected void activate() {
        // cfgService.registerProperties(getClass());
        appId = coreService.registerApplication(APP_NAME);
        aaaManager.addListener(authenticationEventHandler);
        flowRuleService.addListener(flowRuleHandler);
        packetService.addProcessor(radiusProcessor, PacketProcessor.director(3));
        packetService.addProcessor(reactiveProcessor, PacketProcessor.director(4));
        requestIntercepts();

        // Nameless object for executing class static clause.
        // In order to dynamically load MySQL Connector/J JDBC driver (com.mysql.cj.jdbc.Driver)
        try {
            new Driver();
        } catch (SQLException e) {
            log.info("[SQLException] state: " + e.getSQLState() + " message: " + e.getMessage());
        }

        DHCPForbid();
        dbInitialize();
        communicatorInitailize();
        List<String> groups = getAllGroupName();
        for (String grp : groups) {
            log.info("Group '{}' initialing...", grp);
            groupInit(grp);
        }

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        aaaManager.removeListener(authenticationEventHandler);
        withdrawIntercepts();
        packetService.removeProcessor(radiusProcessor);
        packetService.removeProcessor(reactiveProcessor);
        flowRuleService.removeFlowRulesById(appId);
        for (SocketBasedRadiusCommunicator comm : commmunicators.values()) {
            comm.clearLocalState();
        }

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

    public void communicatorInitailize() {
        commmunicators = new HashMap<>();
        try (Connection connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)) {
            try (Statement stmt = connection.createStatement()) {
                String sql = "SELECT switch_uri, wireless_port FROM switch WHERE wireless_port IS NOT NULL";
                try (ResultSet res = stmt.executeQuery(sql)) {
                    if (res.next()) {
                        DeviceId deviceId = DeviceId.deviceId(res.getString("switch_uri"));
                        int supPort = res.getInt("wireless_port");
                        ConnectPoint supCp = new ConnectPoint(deviceId, PortNumber.portNumber(supPort));
                        SocketBasedRadiusCommunicator newComm = new SocketBasedRadiusCommunicator(this, supCp);
                        newComm.initializeLocalState();
                        commmunicators.put(deviceId, newComm);
                    }
                }
            }
        } catch (SQLException e) {
            log.info("[SQLException] state: " + e.getSQLState() + " message: " + e.getMessage());
        }
    }

    public void handleRadiusPacket(RADIUS radiusPacket, AuthenticatorProperties authPro, ConnectPoint authCp, ConnectPoint supCp, Map<Byte, SomeRadiusAttributes> sessions) {
        byte radiusCode;
        String user_name = null;

        byte radSessionId = radiusPacket.getIdentifier();
        SomeRadiusAttributes radReqAttri = sessions.get(radSessionId);
        RADIUSAttribute radiusAttrUserName =
                radiusPacket.getAttribute(RADIUSAttribute.RADIUS_ATTR_USERNAME);
        if (radiusAttrUserName != null) {
            user_name = new String(radiusAttrUserName.getValue(), StandardCharsets.UTF_8);
        }

        // Ether header
        Ethernet eth = new Ethernet();
        eth.setSourceMACAddress(RADIUS_MAC);
        eth.setDestinationMACAddress(authPro.authenMac);
        eth.setEtherType(Ethernet.TYPE_IPV4);

        // IPv4 header
        IPv4 ip = new IPv4();
        ip.setSourceAddress(RADIUS_HOST);
        ip.setDestinationAddress(authPro.authenIp.toString());
        ip.setProtocol(IPv4.PROTOCOL_UDP);

        // UDP header
        UDP udp = new UDP();
        udp.setSourcePort(RADIUS_AUTH_PORT);
        udp.setDestinationPort(authPro.authenPort);
        udp.setPayload(radiusPacket);
        ip.setPayload(udp);
        eth.setPayload(ip);
        eth.setPad(true);

        radiusCode = radiusPacket.getCode();
        switch (radiusCode) {
            case RADIUS.RADIUS_CODE_ACCESS_ACCEPT:
                if (radReqAttri != null){
                    updateDb(radReqAttri.calling_station_id,
                            supCp,
                            user_name,
                            "AUTHORIZED_STATE");
                }
                // clear all the session records related to this mac
                for (Iterator<SomeRadiusAttributes> it=sessions.values().iterator(); it.hasNext();) {
                    if (it.next().calling_station_id.equals(radReqAttri.calling_station_id)) {
                        it.remove();
                    }
                }
                break;
            case RADIUS.RADIUS_CODE_ACCESS_REJECT:
                if (radReqAttri != null) {
                    updateDb(radReqAttri.calling_station_id,
                            supCp,
                            user_name,
                            "UNAUTHORIZED_STATE");
                }
                // clear all the session records related to this mac
                for (Iterator<SomeRadiusAttributes> it=sessions.values().iterator(); it.hasNext();) {
                    if (it.next().calling_station_id.equals(radReqAttri.calling_station_id)) {
                        it.remove();
                    }
                }
                break;
            case RADIUS.RADIUS_CODE_ACCESS_CHALLENGE:
                break;
        }

        sendToDataPlane(eth, authCp);
    }

    @Override
    public void getAllUsers() {
        commandImpl.getAllUsers();
    }

    @Override
    public void getBadUsers() {
        commandImpl.getBadUsers();
    }

    private void dbInitialize() {
        try (Connection connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)) {
            try (Statement stmt = connection.createStatement()) {
                String sql = "DELETE FROM authenLog";
                stmt.executeUpdate(sql);
            }
            try (Statement stmt = connection.createStatement()) {
                String sql = "ALTER TABLE authenLog AUTO_INCREMENT = 1";
                stmt.executeUpdate(sql);
            }
            try (Statement stmt = connection.createStatement()) {
                String sql = "DELETE FROM activeDevice";
                stmt.executeUpdate(sql);
            }
            try (Statement stmt = connection.createStatement()) {
                String sql = "DELETE FROM authorizedDevice";
                stmt.executeUpdate(sql);
            }
        } catch (SQLException e) {
            log.info("[SQLException] (@3000) state: " + e.getSQLState() + " message: " + e.getMessage());
        }
    }

    private Set<DeviceId> getAllSwitch() {
        Set<DeviceId> allDevices = new HashSet<>();
        Set<TopologyCluster> clusters = topologyService.getClusters(topologyService.currentTopology());
        for (TopologyCluster cluster : clusters) {
            Set<DeviceId> devices = topologyService.getClusterDevices(topologyService.currentTopology(), cluster);
            allDevices.addAll(devices);
        }
        return allDevices;
    }

    /**
     * Initially drop all DHCP packet sent from unauthorized device.
     */
    private void DHCPForbid() {
        List<FlowRule> flowrulesTobeInstalled = new ArrayList<>();
        TrafficSelector.Builder selectorDhcpForbidBuilder = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4)
            .matchIPProtocol(IPv4.PROTOCOL_UDP)
            .matchUdpDst(TpPort.tpPort(UDP.DHCP_SERVER_PORT))
            .matchUdpSrc(TpPort.tpPort(UDP.DHCP_CLIENT_PORT));
        TrafficTreatment.Builder treatmentDhcpForbidBuilder = DefaultTrafficTreatment.builder().drop();

        Set<DeviceId> allDevices = getAllSwitch();
        for (DeviceId devId : allDevices) {
            flowrulesTobeInstalled.add(
                DefaultFlowRule.builder()
                    .forTable(0)
                    .forDevice(devId)
                    .withSelector(selectorDhcpForbidBuilder.build())
                    .withTreatment(treatmentDhcpForbidBuilder.build())
                    .withPriority(FORBIDDHCPFLOWPRIORITY)
                    .makePermanent()
                    .fromApp(appId)
                    .build()
            );
        }

        FlowRule[] flowrulesArr = new FlowRule[flowrulesTobeInstalled.size()];
        // List to arrray casting.
        flowrulesArr = flowrulesTobeInstalled.toArray(flowrulesArr);
        flowRuleService.applyFlowRules(flowrulesArr);
    }

    private List<String> getAllGroupName() {
        List<String> grpNames = new ArrayList<>(3);
        try (Connection connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)) {
            try (Statement stmt = connection.createStatement()) {
                String sql = "SELECT group_name FROM `group`";
                try (ResultSet res = stmt.executeQuery(sql)) {
                    while (res.next()) {
                        grpNames.add(res.getString(1));
                    }
                }
            }
        } catch (SQLException e) {
            log.info("[SQLException] (@getAllGroupName) state: " + e.getSQLState() + " message: " + e.getMessage());
        }
        return grpNames;
    }

    /**
     * Setup a new group into network.
     * @param groupName
     */
    private void groupInit(String groupName) {
        GroupConfig grpConf = new GroupConfig();
        List<FlowRule> flowrulesTobeInstalled = new ArrayList<>();
        Set<DeviceId> allDevices = getAllSwitch();

        // query database for some parameters
        try (Connection connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)) {
            try (
                PreparedStatement pStmt = connection.prepareStatement(
                    "SELECT dscp, traffic_rate, login_timeout, dst_domain, dst_ip, dst_port, protocol " +
                    "FROM `group` " +
                    "LEFT JOIN groupACL " +
                    "ON `group`.group_id = groupACL.group_id " +
                    "WHERE group_name = ?"
                )
            ) {
                pStmt.setString(1, groupName);
                try (
                    ResultSet res = pStmt.executeQuery()
                ) {
                    while (res.next()) {
                        if (res.isFirst()) {
                            grpConf.timeout = res.getInt("login_timeout");
                            grpConf.meterRate = res.getInt("traffic_rate");
                            grpConf.dscp = res.getByte("dscp");
                        }
                        grpConf.addACL(
                            res.getString("dst_domain"),
                            res.getString("dst_ip"),
                            res.getInt("dst_port"),
                            res.getByte("protocol")
                        );
                    }
                }
            }
        } catch (SQLException e) {
            log.info("[SQLException] (@6000) state: " + e.getSQLState() + " message: " + e.getMessage());
        }

        // // group meter submition
        // Collection<Band> meterBands = new ArrayList<>();
        // meterBands.add(
        //     DefaultBand.builder()
        //         .withRate(grpConf.meterRate)
        //         .ofType(Band.Type.DROP)
        //         .burstSize(grpConf.meterRate / 100)
        //         .build()
        // );
        // MeterRequest meterReq = DefaultMeterRequest.builder()
        //     .forDevice(GATE_WAY_CONNECT_POINT.deviceId())
        //     .fromApp(appId)
        //     .withBands(meterBands)
        //     .withUnit(Meter.Unit.KB_PER_SEC)
        //     .burst()
        //     .add();
        // grpConf.meter = meterService.submit(meterReq);

        /**
         * Install two types of flow rules
         * 1. Group forwarding (at each switch)
         * 2. Group forbidden (at core switch)
         */
        // 1. Proactively install group-based path for user
        // to go back and forward the gateway.
        TrafficSelector.Builder selectorFwdBuilder = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4)
            .matchIPDscp(grpConf.dscp);
        for (DeviceId devId : allDevices) {
            if (!devId.equals(GATE_WAY_CONNECT_POINT.deviceId())) {

                // find a path from this switch to the gateway
                Path path = calculatePath(ConnectPoint.fromString​(devId.toString().concat("/1")), GATE_WAY_CONNECT_POINT);
                if (path == null) {
                    log.info("Error: (@6001)");
                    return;
                }

                TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder()
                    .setOutput(path.src().port());
                flowrulesTobeInstalled.add(
                    DefaultFlowRule.builder()
                        .forTable(0)
                        .forDevice(devId)
                        .withSelector(selectorFwdBuilder.build())
                        .withTreatment(treatmentBuilder.build())
                        .withPriority(FORWARDINGPRIORITY)
                        .makePermanent()
                        .fromApp(appId)
                        .build()
                );
            } else {
                // // check meter is added
                // while (true) {
                //     if (meterService.getMeter(GATE_WAY_CONNECT_POINT.deviceId(), grpConf.meter.id()).state() == MeterState.ADDED) {
                //         break;
                //     }
                // }
                TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder()
                    .setIpDscp((byte) 0)
                    .setOutput(GATE_WAY_CONNECT_POINT.port());
                    // .meter(grpConf.meter.id());
                flowrulesTobeInstalled.add(
                    DefaultFlowRule.builder()
                        .forTable(0)
                        .forDevice(devId)
                        .withSelector(selectorFwdBuilder.build())
                        .withTreatment(treatmentBuilder.build())
                        .withPriority(FORWARDINGPRIORITY)
                        .makePermanent()
                        .fromApp(appId)
                        .build()
                );
            }
        }

        // 2. Install group-based flowrules to block user access for
        // specified doamin.
        TrafficTreatment.Builder treatmentFrbBuilder = DefaultTrafficTreatment.builder()
            .drop();
        for (GroupConfig.Destination dst : grpConf.acl) {
            TrafficSelector.Builder selectorFrbBuilder = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPDscp​(grpConf.dscp)
                .matchIPDst(dst.ip);
            switch (dst.protocol) {
                case IPv4.PROTOCOL_TCP:
                    selectorFrbBuilder.matchIPProtocol(IPv4.PROTOCOL_TCP);
                    if (dst.port != null) {
                        selectorFrbBuilder.matchTcpDst(dst.port);
                    }
                    break;
                case IPv4.PROTOCOL_UDP:
                    selectorFrbBuilder.matchIPProtocol(IPv4.PROTOCOL_UDP);
                    if (dst.port != null) {
                        selectorFrbBuilder.matchUdpDst(dst.port);
                    }
                    break;
                case IPv4.PROTOCOL_ICMP:
                    selectorFrbBuilder.matchIPProtocol(IPv4.PROTOCOL_ICMP);
                    break;
                case 0:
                    // protocol not specified
                    // (ignored)
                    break;
                default:
                    log.info("Warning: IP protocol {} currently not support!", dst.protocol);
                    break;
            }
            /** 
             * To do ...
             * Support more IP protocols
             */

            flowrulesTobeInstalled.add(
                DefaultFlowRule.builder()
                    .forTable(0)
                    .forDevice(GATE_WAY_CONNECT_POINT.deviceId())
                    .withSelector(selectorFrbBuilder.build())
                    .withTreatment(treatmentFrbBuilder.build())
                    .withPriority(FORBIDFORWARDINGPRIORITY)
                    .makePermanent()
                    .fromApp(appId)
                    .build()
            );
        }

        FlowRule[] flowrulesArr = new FlowRule[flowrulesTobeInstalled.size()];
        // List to arrray casting.
        flowrulesArr = flowrulesTobeInstalled.toArray(flowrulesArr);
        flowRuleService.applyFlowRules(flowrulesArr);
    }

    private class RadiusPacketProcessor implements PacketProcessor {

        // // Packet list for matching access-accept with access-request
        // private Map<Byte, PacketInfo> outgoingPacketMap;

        // // for matching ap with its outgoing packet-list
        // private Map<MacAddress, Map<Byte, PacketInfo>> authenticatorMap = new HashMap<>();

        // // for recording authenticator's location
        // private Map<MacAddress, ConnectPoints> authenticatorLoc = new HashMap<>();

        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            // Extract the original Ethernet frame from the packet information
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (ethPkt == null) {
                return;
            }

            MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();

            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ip4Pkt = (IPv4) ethPkt.getPayload();
                IpAddress srcIp = IpAddress.valueOf(ip4Pkt.getSourceAddress());
                IpAddress dstIp = IpAddress.valueOf(ip4Pkt.getDestinationAddress());

                if (ip4Pkt.getProtocol() == IPv4.PROTOCOL_UDP) {
                    UDP udpPkt = (UDP) ip4Pkt.getPayload();
                    int srcPort = udpPkt.getSourcePort();
                    int dstPort = udpPkt.getDestinationPort();

                    // RADIUS packet
                    if (srcPort == RADIUS_AUTH_PORT || dstPort == RADIUS_AUTH_PORT) {

                        // block this context from other processor to process
                        context.block();
                        
                        handleAuthenticatorPacket(pkt);
                        // // Parsing RADIUS packet
                        // // Serialize udp packet first, then deserialize into RADIUS packet
                        // RADIUS radiusPkt = null;
                        // // ConnectPoints apCps = null;
                        // byte[] udpByte = udpPkt.serialize();
                        // // boolean outgoing = false;
                        // try {
                        //     radiusPkt = RADIUS.deserializer()
                        //                         .deserialize(udpByte,
                        //                                 UDP_HEADER_LENGTH,
                        //                                 udpByte.length - UDP_HEADER_LENGTH);
                        // } catch (DeserializationException dex) {
                        //     log.error("Cannot deserialize packet", dex);
                        //     return;
                        // }
                        // log.info("Got RADIUS Packet from {}.", pkt.receivedFrom());

                        // // Incoming packet (AP Authenticator <-- RADIUS server)
                        // if (srcPort == RADIUS_AUTH_PORT) {
                        //     outgoing = false;
                        //     outgoingPacketMap = authenticatorMap.get(dstMac);
                        //     apCps = authenticatorLoc.get(dstMac);
                        //     if (outgoingPacketMap == null) {
                        //         log.warn("Can't find corresponding AP's information");
                        //     }
                        // }

                        // // Outgoing packet (AP Authenticator --> RADIUS server)
                        // else if (dstPort == RADIUS_AUTH_PORT) {
                        //     outgoing = true;
                        //     outgoingPacketMap = authenticatorMap.get(srcMac);
                        //     apCps = authenticatorLoc.get(srcMac);

                        //     // This is the first outgoing packet sent by this wireless-authenticator.
                        //     if (outgoingPacketMap == null) {
                        //         authenticatorMap.put(srcMac, new HashMap<>());
                        //         outgoingPacketMap = authenticatorMap.get(srcMac);
                        //     }

                        //     // This is the first packet packet-in from new ap.
                        //     if (apCps == null) {
                        //         authenticatorLoc.put(srcMac, new ConnectPoints(context.inPacket().receivedFrom()));
                        //     }

                        //     // wireless-authenticator location changed
                        //     else if (!apCps.authenticatorCP().equals(context.inPacket().receivedFrom())) {
                        //         log.error("Wireless authenticator location changed from {}->{}",
                        //                 apCps.authenticatorCP(), context.inPacket().receivedFrom());
                        //         return;
                        //     }
                        // }

                        // byte pktId = radiusPkt.getIdentifier();
                        // boolean isFirstReq = true;
                        // switch (radiusPkt.getCode()) {
                        //     case RADIUS.RADIUS_CODE_ACCESS_REQUEST:

                        //         // parse RADIUS attributes
                        //         RADIUSAttribute radiusAttrUserName =
                        //                 radiusPkt.getAttribute(RADIUSAttribute.RADIUS_ATTR_USERNAME);
                        //         String user_name = new String();
                        //         if (radiusAttrUserName != null) {
                        //             user_name = new String(radiusAttrUserName.getValue(), StandardCharsets.UTF_8);
                        //         }
                        //         RADIUSAttribute radiusAttrCallingStationId =
                        //                 radiusPkt.getAttribute(RADIUSAttribute.RADIUS_ATTR_CALLING_STATION_ID);
                        //         String calling_station_id = new String();
                        //         if (radiusAttrCallingStationId != null) {
                        //             calling_station_id = new String(radiusAttrCallingStationId.getValue(), StandardCharsets.UTF_8);
                        //             calling_station_id = calling_station_id.replace('-', ':');
                        //         }

                        //         log.debug("ACCESS_REQUEST [radius_id={}, user_name={}, mac_addr={}]",
                        //                 pktId, user_name, calling_station_id);

                        //         // check if this is the first ACCESS_REQUEST sent by this supplicant
                        //         for (PacketInfo pktInfo : outgoingPacketMap.values()) {
                        //             if (pktInfo.mac.equals(MacAddress.valueOf(calling_station_id))) {
                        //                 isFirstReq = false;
                        //                 break;
                        //             }
                        //         }

                        //         if (isFirstReq) {
                        //             updateDb(MacAddress.valueOf(calling_station_id), apCps.supplicantCP(), user_name, "STARTED_STATE");
                        //         }
                        //         outgoingPacketMap.put(pktId, new PacketInfo(calling_station_id, user_name));
                        //         break;

                        //     case RADIUS.RADIUS_CODE_ACCESS_CHALLENGE:
                        //         log.debug("ACCESS_CHALLENGE [radius_id={}]", pktId);
                        //         break;

                        //     case RADIUS.RADIUS_CODE_ACCESS_ACCEPT:
                        //         // Use packet-id to find supplicant information carried in the earlier ACCESS_REQUEST packet.
                        //         PacketInfo supAccPkt = outgoingPacketMap.get(pktId);
                        //         if (supAccPkt == null) {
                        //             log.warn("unkown user has been authorized!");
                        //         }
                        //         else {
                        //             for (Iterator<PacketInfo> it=outgoingPacketMap.values().iterator(); it.hasNext();) {
                        //                 if (it.next().mac.equals(supAccPkt.mac)) {
                        //                     it.remove();
                        //                 }
                        //             }
                        //             log.debug("ACCESS_ACCEPT [radius_id={}, user_name={}, mac_addr={}]",
                        //                     pktId, supAccPkt.user_name, supAccPkt.mac);
                        //             updateDb(supAccPkt.mac, apCps.supplicantCP(), supAccPkt.user_name, "AUTHORIZED_STATE");
                        //         }
                        //         break;

                        //     case RADIUS.RADIUS_CODE_ACCESS_REJECT:
                        //         PacketInfo supRejected = outgoingPacketMap.get(pktId);
                        //         if (supRejected == null) {
                        //             log.warn("unkown user has benn rejected!");
                        //         }
                        //         else {
                        //             for (Iterator<PacketInfo> it=outgoingPacketMap.values().iterator(); it.hasNext();) {
                        //                 if (it.next().mac.equals(supRejected.mac)) {
                        //                     it.remove();
                        //                 }
                        //             }
                        //             log.debug("ACCESS_REJECT [radius_id={}, user_name={}, mac_addr={}]",
                        //                     pktId, supRejected.user_name, supRejected.mac);
                        //             updateDb(supRejected.mac, apCps.supplicantCP(), supRejected.user_name, "UNAUTHORIZED_STATE");
                        //         }
                        //         break;
                        // }

                        // if (outgoing) {
                        //     log.debug("Relay packet to RADIUS server at {}", RADIUS_SERVER_CONNCECT_POINT);
                        //     sendToDataPlane(ethPkt, RADIUS_SERVER_CONNCECT_POINT);
                        // }
                        // else {
                        //     log.debug("Relay packet to AP at {}", apCps);
                        //     sendToDataPlane(ethPkt, apCps.authenticatorCP());
                        // }

                        // // Passively clean up stale packet records
                        // for (Iterator<PacketInfo> itp = outgoingPacketMap.values().iterator(); itp.hasNext();) {
                        //     Calendar cal = Calendar.getInstance();
                        //     PacketInfo pktInfo = itp.next();
                        //     if (pktInfo.timestamp <= cal.getTimeInMillis()) {
                        //         log.debug("Cleaning up stale packet record...");
                        //         itp.remove();
                        //     }
                        // }
                    }
                }
            }
        }

        // // For IEEE 802.1X Authenticators, Calling_Station_ID is used to store the
        // // Supplicant MAC address in ASCII format (upper case only), with octet
        // // values separated by a "-".  Example: "00-10-A4-23-19-C0".
        // // Called_Station_ID is used to store the bridge or Access Point MAC address
        // // in ASCII format (upper case only), with octet values separated by a "-". 
        // // Example: "00-10-A4-23-19-C0". In IEEE 802.11, where the SSID is known, it
        // // SHOULD be appended to the Access Point MAC address, separated from the MAC
        // // address with a ":". Example "00-10-A4-23-19-C0:AP1".
        // private class PacketInfo {
        //     MacAddress mac;         // RADIUS attribute: 'Calling_Station_Id'
        //     String user_name;       // RADIUS attribute: 'User_Name'
        //     long timestamp;
    
        //     PacketInfo(String mac, String user_name) {
        //         this.mac = MacAddress.valueOf(mac);
        //         this.user_name = user_name;

        //         // entry-timeout
        //         Calendar cal = Calendar.getInstance();
        //         cal.add(Calendar.SECOND, PACKET_RECORD_TIMEOUT);
        //         timestamp = cal.getTimeInMillis();
        //     }
        // }

        // private class ConnectPoints {
        //     DeviceId device;
        //     PortNumber authenticator_port;      // ovs port which is used to connect with the authenticator on AP, and we can only know from the first pkt-in (i.e. InboundPacket.receivedFrom())
        //     PortNumber wireless_port;           // ovs-port which is used to connect with the wireless adapter of AP

        //     ConnectPoints(ConnectPoint cp) {
        //         int port = 0;
        //         try (Connection connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)) {
        //             try (Statement stmt = connection.createStatement()) {
        //                 String sql = "SELECT wireless_port FROM switch " +
        //                                 "WHERE switch_uri = '" + cp.deviceId().toString() + "'";
        //                 try (ResultSet res = stmt.executeQuery(sql)) {
        //                     if (res.next()) {
        //                         port = res.getInt("wireless_port");
        //                     }
        //                 }
        //             }
        //         } catch (SQLException e) {
        //             log.info("[SQLException] state: " + e.getSQLState() + " message: " + e.getMessage());
        //         }

        //         this.device = cp.deviceId();
        //         this.authenticator_port = cp.port();
        //         this.wireless_port = PortNumber.portNumber(port);
        //     }

        //     ConnectPoint authenticatorCP() {
        //         return new ConnectPoint(device, authenticator_port);
        //     }

        //     ConnectPoint supplicantCP() {
        //         return new ConnectPoint(device, wireless_port);
        //     }
        // }

        private void handleAuthenticatorPacket(InboundPacket inPacket) {
            Ethernet ethPkt = inPacket.parsed();
            MacAddress srcMac = ethPkt.getSourceMAC();
            DeviceId deviceId = inPacket.receivedFrom().deviceId();
            IPv4 ip4Pkt = (IPv4) ethPkt.getPayload();
            IpAddress srcIp = IpAddress.valueOf(ip4Pkt.getSourceAddress());
            UDP udpPkt = (UDP) ip4Pkt.getPayload();
            int srcPort = udpPkt.getSourcePort();
            RADIUS radiusPkt = null;
            byte[] udpByte = udpPkt.serialize();
            try {
                radiusPkt = RADIUS.deserializer()
                                    .deserialize(udpByte,
                                            UDP_HEADER_LENGTH,
                                            udpByte.length - UDP_HEADER_LENGTH);
            } catch (DeserializationException dex) {
                log.error("Cannot deserialize packet", dex);
            }
            log.info("Got RADIUS Packet from {}.", inPacket.receivedFrom());

            RADIUSAttribute radAtCallingStationId =
            radiusPkt.getAttribute(RADIUSAttribute.RADIUS_ATTR_CALLING_STATION_ID);
            RADIUSAttribute radAtUserName =
            radiusPkt.getAttribute(RADIUSAttribute.RADIUS_ATTR_USERNAME);
            String callingSationId = null;
            String userName = null;
            if (radAtCallingStationId != null) {
                callingSationId = new String(radAtCallingStationId.getValue(), StandardCharsets.UTF_8);
                callingSationId = callingSationId.replace('-', ':');
            }
            if (radAtUserName != null) {
                userName = new String(radAtUserName.getValue(), StandardCharsets.UTF_8);
            }
            SocketBasedRadiusCommunicator comm = commmunicators.get(deviceId);
            if (comm.sessions == null) {
                comm.initializeAuthenticatorProperties(srcMac, srcIp, srcPort, inPacket.receivedFrom());
            }

            byte radSessionId = radiusPkt.getIdentifier();
            byte radCode = radiusPkt.getCode();
            MacAddress supMac = MacAddress.valueOf(callingSationId);
            boolean isFirst = true;
            if (radCode == RADIUS.RADIUS_CODE_ACCESS_REQUEST) {
                for (SomeRadiusAttributes some : comm.sessions.values()) {
                    if (some.calling_station_id.equals(supMac)) {
                        isFirst = false;
                        break;
                    }
                }
                if (isFirst) {
                    updateDb(supMac,
                                comm.getSupplicantConnectionPoint(),
                                userName,
                                "STARTED_STATE");
                }
            }
            comm.sessions.put(radSessionId, new SomeRadiusAttributes(callingSationId, userName));
            comm.sendRadiusPacket(radiusPkt);
        }
    }

    private class ReactivePacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            ConnectPoint connectp = pkt.receivedFrom();
            MacAddress srcMac = ethPkt.getSourceMAC();

            if (ethPkt == null) {
                return;
            }

            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
                IpAddress srcIp = IpAddress.valueOf(ipv4Packet.getSourceAddress());

                try (Connection connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)) {
                    int switchID_now = 0;
                    int switchPort_now = (int) connectp.port().toLong();

                    // reocorded parameters at which this device was authorized
                    int switchID = 0;
                    int switchPort = 0;
                    boolean installed = true;
                    int userID = 0;
                    int grpID = 0;

                    // parameters from table 'group'
                    byte dscp = 0;
                    int timeout = 0;

                    // check the device is authorized or not
                    try (Statement stmtAuthor = connection.createStatement()) {
                        String sql = "SELECT * FROM authorizedDevice " +
                                    "RIGHT JOIN `group` " +
                                    "ON authorizedDevice.group_id = `group`.group_id " +
                                    "WHERE mac = '" + srcMac.toString() + "'";
                        try (ResultSet resAuthor = stmtAuthor.executeQuery(sql)) {
                            if (resAuthor.next()) {

                                switchID = resAuthor.getInt("switch_id");
                                switchPort = resAuthor.getInt("switch_port");
                                installed = resAuthor.getBoolean("rule_installed");
                                userID = resAuthor.getInt("user_id");
                                grpID = resAuthor.getInt("group_id");
                                dscp = resAuthor.getByte("dscp");
                                timeout = resAuthor.getInt("login_timeout");

                                // get switch ID by device uri
                                try (Statement stmt = connection.createStatement()) {
                                    String sqlSw = "SELECT switch_id FROM switch WHERE switch_uri = '" + connectp.deviceId().toString() + "'";
                                    try (ResultSet res = stmt.executeQuery(sqlSw)) {
                                        if (!res.isBeforeFirst()) {
                                            throw new SQLException("Can't find switch " + connectp.deviceId().toString() + " in the table 'switch'!");
                                        }
                                        while (res.next()) {
                                            switchID_now = res.getInt("switch_id");
                                            break;
                                        }
                                    }
                                } catch (SQLException e) {
                                    log.info("[SQLException] (@9000) state: " + e.getSQLState() + " message: " + e.getMessage());
                                }

                                // user location changed
                                if ((switchID_now != switchID) || (switchPort_now != switchPort)) {
                                    // try (PreparedStatement insertIntoLogLoc = connection.prepareStatement(
                                    //     "INSERT INTO authenLog " +
                                    //     "(user_id, mac, ip, switch_id, switch_port, auth_state) " +
                                    //     "VALUES (?, ?, ?, ?, ?, ?)"
                                    // )) {
                                    //     insertIntoLogLoc.setInt(1, userID);
                                    //     insertIntoLogLoc.setString(2, srcMac.toString());
                                    //     insertIntoLogLoc.setString(3, srcIp.toString());
                                    //     insertIntoLogLoc.setInt(4, switchID_now);
                                    //     insertIntoLogLoc.setInt(5, switchPort_now);
                                    //     insertIntoLogLoc.setString(6,
                                    //         String.format("LOC %d/%d->%d/%d",
                                    //             switchID, switchPort, switchID_now, switchPort_now));
                                    //     insertIntoLogLoc.executeUpdate();
                                    // } catch (SQLException e) {
                                    //     log.info("[SQLException] (@9002) state: " + e.getSQLState() + " message: " + e.getMessage());
                                    // }

                                    log.info("Device {} location changed from {}/{} to {}/{} ({})",
                                        srcMac, switchID, switchPort, switchID_now, switchPort_now, connectp.deviceId());

                                    // purge dirty flowrules
                                    List<FlowRule> flowsToBeDel = supFlowrules.get(srcMac);
                                    if (flowsToBeDel != null) {
                                        FlowRule[] flowrulesArr = new FlowRule[flowsToBeDel.size()];
                                        // List to array casting.
                                        flowrulesArr = flowsToBeDel.toArray(flowrulesArr);
                                        flowRuleService.removeFlowRules(flowrulesArr);
                                    }
                                    else {
                                        log.warn("Can't find old flow rules.");
                                    }
                                }

                                // update authorized record
                                try (PreparedStatement updateAuthorized = connection.prepareStatement(
                                    "UPDATE authorizedDevice " +
                                    "SET switch_id = ?, switch_port = ?, ip = ?, rule_installed = ? " +
                                    "WHERE mac = ?"
                                )) {
                                    updateAuthorized.setInt(1, switchID_now);
                                    updateAuthorized.setInt(2, switchPort_now);
                                    updateAuthorized.setString(3, srcIp.toString());
                                    updateAuthorized.setBoolean(4, true);
                                    updateAuthorized.setString(5, srcMac.toString());
                                    updateAuthorized.executeUpdate();
                                } catch (SQLException e) {
                                    log.info("[SQLException] (@9003) state: " + e.getSQLState() + " message: " + e.getMessage());
                                }

                                if (!installed || ((switchID_now != switchID) || (switchPort_now != switchPort))) {
                                     // log user packet-in
                                    try (PreparedStatement insertIntoLogPktIn = connection.prepareStatement(
                                        "INSERT INTO authenLog " +
                                        "(user_id, mac, ip, switch_id, switch_port, auth_state) " +
                                        "VALUES (?, ?, ?, ?, ?, ?)"
                                    )) {
                                        insertIntoLogPktIn.setInt(1, userID);
                                        insertIntoLogPktIn.setString(2, srcMac.toString());
                                        insertIntoLogPktIn.setString(3, srcIp.toString());
                                        insertIntoLogPktIn.setInt(4, switchID_now);
                                        insertIntoLogPktIn.setInt(5, switchPort_now);
                                        insertIntoLogPktIn.setString(6, "NET_ACCESS");
                                        insertIntoLogPktIn.executeUpdate();
                                    } catch (SQLException e) {
                                        log.info("[SQLException] (@9001) state: " + e.getSQLState() + " message: " + e.getMessage());
                                    }

                                    normalPkt(context, srcMac, dscp, timeout, (grpID == 1));
                                }
                            } else {
                                // log.info("User '{}' is NOT authenticated!", ethPkt.getSourceMAC());
                                return;
                            }
                        }
                    } catch (SQLException e) {
                        log.info("[SQLException] (@9004) state: " + e.getSQLState() + " message: " + e.getMessage());
                    }
                } catch (SQLException e) {
                    log.info("[SQLException] (@9005) state: " + e.getSQLState() + " message: " + e.getMessage());
                }
            }
        }
    }

    private void normalPkt(PacketContext context, MacAddress mac, byte dscp, int timeout, boolean softHard) {
        log.info("enter @normalPkt()");
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
        IpAddress srcIp = IpAddress.valueOf(ipv4Packet.getSourceAddress());
        ConnectPoint clientCp = pkt.receivedFrom();

        List<FlowRule> flowrules = new ArrayList<>();

        Path path = calculatePath(clientCp, GATE_WAY_CONNECT_POINT);
        if (path == null) {
            log.error("Error: @normalPkt() Can't get path to gateway!");
            return;
        } else {
            TrafficSelector.Builder selectorBuilderIn = DefaultTrafficSelector.builder()
                .matchEthSrc(GATEWAYMAC)
                .matchEthDst(mac)
                .matchEthType(Ethernet.TYPE_IPV4);
            TrafficSelector.Builder selectorBuilderOut = DefaultTrafficSelector.builder()
                .matchEthSrc(mac)
                .matchEthDst(GATEWAYMAC)
                .matchEthType(Ethernet.TYPE_IPV4);
            TrafficTreatment.Builder treatmentBuilderOut = DefaultTrafficTreatment.builder()
                .setIpDscp(dscp)
                .setOutput(path.src().port());

            FlowRule.Builder flowruleBuilderFron = DefaultFlowRule.builder()
                .forTable(0)
                .forDevice(clientCp.deviceId())
                .withSelector(selectorBuilderOut.build())
                .withTreatment(treatmentBuilderOut.build())
                .withPriority(FLOWPRIORITY)
                .makePermanent()
                .fromApp(appId);
            // if (softHard) {
            //     flowruleBuilderFron.makeTemporary(timeout);
            // } else {
            //     flowruleBuilderFron.withHardTimeout(timeout);
            // }
            flowrules.add(flowruleBuilderFron.build());

            // Installing backward flow rule for user
            // path:   ---link1 ------ link2 ------ ... ------ linkn---
            //         (src | dst)  (src | dst)     ...     (src | dst)
            //   clientCp                                             geCp
            for (Link link : path.links()) {
                TrafficTreatment.Builder treatmentBuilderIn = DefaultTrafficTreatment.builder()
                    .setOutput(link.dst().port());
                FlowRule.Builder flowruleBuilderMid = DefaultFlowRule.builder()
                    .forTable(0)
                    .forDevice(link.dst().deviceId())
                    .withSelector(selectorBuilderIn.build())
                    .withTreatment(treatmentBuilderIn.build())
                    .withPriority(FLOWPRIORITY)
                    .makePermanent()
                    .fromApp(appId);
                // if (softHard) {
                //     flowruleBuilderMid.makeTemporary(timeout);
                // } else {
                //     flowruleBuilderMid.withHardTimeout(timeout);
                // }
                flowrules.add(flowruleBuilderMid.build());
            }

            // Last device (clientCp)
            TrafficTreatment.Builder lastTreatmentBuilderIn = DefaultTrafficTreatment.builder()
                .setOutput(clientCp.port());
            FlowRule.Builder flowruleBuilderRear = DefaultFlowRule.builder()
                .forTable(0)
                .forDevice(clientCp.deviceId())
                .withSelector(selectorBuilderIn.build())
                .withTreatment(lastTreatmentBuilderIn.build())
                .withPriority(FLOWPRIORITY)
                .makePermanent()
                .fromApp(appId);
            // if (softHard) {
            //     flowruleBuilderRear.makeTemporary(timeout);
            // } else {
            //     flowruleBuilderRear.withHardTimeout(timeout);
            // }
            flowrules.add(flowruleBuilderRear.build());
        }

        // // Install path between monitor (plot client) and supplicant (plot server).
        // Path monitorPath = calculatePath(clientCp, MONITOR_CONNECT_POINT);
        // if (monitorPath == null) {
        //     log.info("Error: @normalPkt() Can't get path to monitor!");
        //     return;
        // } else {
        //     TrafficSelector.Builder selectorBuilderOut = DefaultTrafficSelector.builder()
        //         .matchEthSrc(mac)
        //         .matchEthType(Ethernet.TYPE_IPV4)
        //         .matchIPDst(IpPrefix.valueOf(
        //                 IpAddress.valueOf(MONITORIP),
        //                 Ip4Prefix.MAX_INET_MASK_LENGTH)
        //             );
        //     TrafficSelector.Builder selectorBuilderIn = DefaultTrafficSelector.builder()
        //         .matchEthDst(mac)
        //         .matchEthType(Ethernet.TYPE_IPV4)
        //         .matchIPSrc(IpPrefix.valueOf(
        //                 IpAddress.valueOf(MONITORIP),
        //                 Ip4Prefix.MAX_INET_MASK_LENGTH)
        //             );
        //     for (Link link : path.links()) {
        //         TrafficTreatment.Builder treatmentBuilderOut = DefaultTrafficTreatment.builder()
        //             .setOutput(link.src().port());
        //         TrafficTreatment.Builder treatmentBuilderIn = DefaultTrafficTreatment.builder()
        //             .setOutput(link.dst().port());
        //         flowrules.add(
        //             DefaultFlowRule.builder()
        //                 .forTable(0)
        //                 .forDevice(link.src().deviceId())
        //                 .withSelector(selectorBuilderOut.build())
        //                 .withTreatment(treatmentBuilderOut.build())
        //                 .withPriority(FLOWPRIORITY)
        //                 .makePermanent()
        //                 .fromApp(appId)
        //                 .build()
        //         );
        //         flowrules.add(
        //             DefaultFlowRule.builder()
        //                 .forTable(0)
        //                 .forDevice(link.dst().deviceId())
        //                 .withSelector(selectorBuilderIn.build())
        //                 .withTreatment(treatmentBuilderIn.build())
        //                 .withPriority(FLOWPRIORITY)
        //                 .makePermanent()
        //                 .fromApp(appId)
        //                 .build()
        //         );
        //     }
        //     // Last device (clientCp & MONITOR_CONNECT_POINT)
        //     TrafficTreatment.Builder lastTreatmentBuilderOut = DefaultTrafficTreatment.builder()
        //         .setOutput(MONITOR_CONNECT_POINT.port());
        //     TrafficTreatment.Builder lastTreatmentBuilderIn = DefaultTrafficTreatment.builder()
        //         .setOutput(clientCp.port());
        //     flowrules.add(
        //         DefaultFlowRule.builder()
        //             .forTable(0)
        //             .forDevice(MONITOR_CONNECT_POINT.deviceId())
        //             .withSelector(selectorBuilderOut.build())
        //             .withTreatment(lastTreatmentBuilderOut.build())
        //             .withPriority(FLOWPRIORITY)
        //             .makePermanent()
        //             .fromApp(appId)
        //             .build()
        //     );
        //     flowrules.add(
        //         DefaultFlowRule.builder()
        //             .forTable(0)
        //             .forDevice(clientCp.deviceId())
        //             .withSelector(selectorBuilderIn.build())
        //             .withTreatment(lastTreatmentBuilderIn.build())
        //             .withPriority(FLOWPRIORITY)
        //             .makePermanent()
        //             .fromApp(appId)
        //             .build()
        //     );
        // }

        FlowRule[] flowrulesArr = new FlowRule[flowrules.size()];
        // List to array casting.
        flowrulesArr = flowrules.toArray(flowrulesArr);
        flowRuleService.applyFlowRules(flowrulesArr);

        // store the mapping between supplicant and flowrules
        supFlowrules.addList(mac, flowrules);

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

    /**
     * Send ethernet packet to the authenticator.
     * 
     * @param ethernetPkt
     * @param coonectPt
     */
    private void sendToDataPlane(Ethernet ethernetPkt, ConnectPoint coonectPt) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(coonectPt.port()).build();
        OutboundPacket packet = new DefaultOutboundPacket(coonectPt.deviceId(),
                                                          treatment, ByteBuffer.wrap(ethernetPkt.serialize()));
        packetService.emit(packet);
    }

    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    /**
    * Allow DHCP.
    *
    * @param supMac
    * @param cp
    * @param loginTimeout
    */
    private void dhcpAllow(MacAddress supMac, ConnectPoint cp, int loginTimeout, boolean softHard) {
        log.info("enter @ dhcpAllow()");
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder()
            .matchEthSrc(supMac)
            .matchEthType(Ethernet.TYPE_IPV4)
            .matchIPProtocol(IPv4.PROTOCOL_UDP)
            .matchUdpDst(TpPort.tpPort(UDP.DHCP_SERVER_PORT))
            .matchUdpSrc(TpPort.tpPort(UDP.DHCP_CLIENT_PORT));
        TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder()
            .setOutput(PortNumber.CONTROLLER);
        FlowRule.Builder flowbuilder = DefaultFlowRule.builder()
            .forTable(0)
            .forDevice(cp.deviceId())
            .withSelector(selectorBuilder.build())
            .withTreatment(treatmentBuilder.build())
            .withPriority(FLOWPRIORITY)
            .fromApp(appId)
            .makePermanent();
        
        flowRuleService.applyFlowRules(flowbuilder.build());
        // supFlowrules.add(supMac, flow);
    }

    /**
    * Block user for EAP packet
    * @param supMac
    * @param cp
    * @param timeout
    */
    private void eapBlock(MacAddress supMac, ConnectPoint cp, int timeout) {
        log.info("enter @ blockUsr()");
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder()
            .matchEthSrc(supMac)
            .matchEthType(EtherType.EAPOL.ethType().toShort());
        TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder()
            .drop();
        FlowRule flow = DefaultFlowRule.builder()
            .forTable(0)
            .forDevice(cp.deviceId())
            .withSelector(selectorBuilder.build())
            .withTreatment(treatmentBuilder.build())
            .withPriority(FLOWPRIORITY)
            .withHardTimeout(timeout)
            .fromApp(appId)
            .build();
        flowRuleService.applyFlowRules(flow);
    }

    private void updateDb(MacAddress supMac, ConnectPoint connectp, String userName, String state) {
        boolean existActive = false;
        boolean existAuthorized = false;
        int errCtr = 0;

        try (Connection connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)) {
            // retrive user record in table activeDevice
            try (Statement stmt = connection.createStatement()) {
                String sql = "SELECT * FROM activeDevice " +
                                "WHERE mac = '" + supMac.toString() + "'";
                try (ResultSet res = stmt.executeQuery(sql)) {
                    if (res.next()) {
                        existActive = true;
                        errCtr = res.getInt("err_ctr");
                        if (res.getBoolean("blked")) {
                            log.info("User '{}' had been blocked!!", userName);
                            return;
                        }
                    }
                }
            } catch (SQLException e) {
                log.info("[SQLException] (@8001) state: " + e.getSQLState() + " message: " + e.getMessage());
            }

            try (Statement stmt = connection.createStatement()) {
                String sql = "SELECT * FROM authorizedDevice " +
                                "WHERE mac = '" + supMac.toString() + "'";
                try (ResultSet res = stmt.executeQuery(sql)) {
                    if (res.isBeforeFirst()) {
                        existAuthorized = true;
                    }
                }
            } catch (SQLException e) {
                log.info("[SQLException] (@8011) state: " + e.getSQLState() + " message: " + e.getMessage());
            }

            int userID = -1;
            int groupID = -1;
            int loginTimeout = -1;
            int switchID = -1;

            log.info("\n**************** Authentication Event *****************"    +
                     "\n*****    SupplicantMacAddress:  "    + supMac.toString()    +
                     "\n*****    ConnectPoint:          "    + connectp.toString()  +
                     "\n*****    UserName:              "    + userName             +
                     "\n*****    State:                 "    + state                +
                     "\n*******************************************************");

            // get userID by user name
            try (Statement stmt = connection.createStatement()) {
                String sql = "SELECT user_id, user.group_id, login_timeout " +
                                "FROM user LEFT JOIN `group` " +
                                "ON user.group_id = `group`.group_id " +
                                "WHERE user_name = '" + userName + "'";
                try (ResultSet res = stmt.executeQuery(sql)) {
                    if (!res.isBeforeFirst()) {
                        throw new SQLException("Can't find user " + userName + " in the user switch!");
                    }
                    while (res.next()) {
                        userID = res.getInt("user_id");
                        groupID = res.getInt("group_id");
                        loginTimeout = res.getInt("login_timeout");
                        break;
                    }
                }
            } catch (SQLException e) {
                log.info("[SQLException] (@8002) state: " + e.getSQLState() + " message: " + e.getMessage());
            }

            // get switchID by switch uri
            try (Statement stmt = connection.createStatement()) {
                String sql = "SELECT switch_id FROM switch WHERE switch_uri = '" + connectp.deviceId().toString() + "'";
                try (ResultSet res = stmt.executeQuery(sql)) {
                    if (!res.isBeforeFirst()) {
                        throw new SQLException("Can't find switch " + connectp.deviceId().toString() + " in the table switch!");
                    }
                    while (res.next()) {
                        switchID = res.getInt("switch_id");
                        break;
                    }
                }
            } catch (SQLException e) {
                log.info("[SQLException] (@8003) state: " + e.getSQLState() + " message: " + e.getMessage());
            }

            // log for each authentication event
            if (state.equals("AUTHORIZED_STATE") || state.equals("UNAUTHORIZED_STATE")) {
                try (
                    PreparedStatement insertIntoLog = connection.prepareStatement(
                        "INSERT INTO authenLog " +
                        "(user_id, mac, ip, switch_id, switch_port, auth_state) " +
                        "VALUES (?, ?, ?, ?, ?, ?)")
                ) {
                    insertIntoLog.setInt(1, userID);
                    insertIntoLog.setString(2, supMac.toString());
                    insertIntoLog.setString(3, null);
                    insertIntoLog.setInt(4, switchID);
                    insertIntoLog.setInt(5, (int) connectp.port().toLong());
                    insertIntoLog.setString(6, state);
                    insertIntoLog.executeUpdate();
                } catch (SQLException e) {
                    log.info("[SQLException] (@8004) state: " + e.getSQLState() + " message: " + e.getMessage());
                }
            }


            /**
             * Some user was authenticated.
             */
            if (state.equals("AUTHORIZED_STATE")) {

                // allowing authorized device to use DHCP service
                dhcpAllow(supMac, connectp, loginTimeout, (groupID == 1));

                // skip already authorized device
                if (existAuthorized) {
                    log.info("Device '{}' has been authorized!", supMac);
                    return;
                }

                // move record from table activeDevice to authorizedDevice
                if (existActive) {
                    try (Statement stmt = connection.createStatement()) {
                        String sql = "DELETE FROM activeDevice " +
                            "WHERE mac = '" + supMac.toString() + "'";
                        stmt.executeUpdate(sql);
                    } catch (SQLException e) {
                        log.info("[SQLException] (@8006) state: " + e.getSQLState() + " message: " + e.getMessage());
                    }
                }

                Calendar cal = Calendar.getInstance();
                cal.add(Calendar.SECOND, loginTimeout);
                Timestamp ts = new Timestamp(cal.getTimeInMillis());

                try (
                    PreparedStatement insertIntoAuthorized = connection.prepareStatement(
                        "INSERT INTO authorizedDevice " +
                        "(mac, switch_id, switch_port, user_id, group_id, ip, rule_installed, auth_exp_time) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                    )
                ) {
                    insertIntoAuthorized.setString(1, supMac.toString());
                    insertIntoAuthorized.setInt(2, switchID);
                    insertIntoAuthorized.setInt(3, (int) connectp.port().toLong());
                    insertIntoAuthorized.setInt(4, userID);
                    insertIntoAuthorized.setInt(5, groupID);
                    insertIntoAuthorized.setString(6, null);
                    insertIntoAuthorized.setBoolean(7, false);
                    if (groupID == 1) {
                        insertIntoAuthorized.setTimestamp(8, null);
                    } else {
                        insertIntoAuthorized.setTimestamp(8, ts, cal);
                    }
                    insertIntoAuthorized.executeUpdate();
                } catch (SQLException e) {
                    log.info("[SQLException] (@8007) state: " + e.getSQLState() + " message: " + e.getMessage());
                }
            } else {

                // add new entry in table activeDevice for this unseen device
                if (!existActive && !existAuthorized) {
                    try (
                        PreparedStatement insertIntoActive = connection.prepareStatement(
                            "INSERT INTO activeDevice " +
                            "(mac, switch_id, switch_port, user_id, err_ctr, blked, err_exp_time, blk_exp_time) " +
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                        )
                    ) {
                        insertIntoActive.setString(1, supMac.toString());
                        insertIntoActive.setInt(2, switchID);
                        insertIntoActive.setInt(3, (int) connectp.port().toLong());
                        insertIntoActive.setInt(4, userID);
                        insertIntoActive.setInt(5, 0);
                        insertIntoActive.setBoolean(6, false);
                        insertIntoActive.setTimestamp(7, null);
                        insertIntoActive.setTimestamp(8, null);
                        insertIntoActive.executeUpdate();
                    } catch (SQLException e) {
                        log.info("[SQLException] (@8008) state: " + e.getSQLState() + " message: " + e.getMessage());
                    }
                }

                /**
                 * Some one's password is incorrect!!
                 */
                if (state.equals("UNAUTHORIZED_STATE")) {
                    errCtr += 1;
                    if (errCtr > PASSWDERRLIMIT) {
                        Calendar cal = Calendar.getInstance();
                        cal.add(Calendar.SECOND, BLOCKPERIOD);
                        Timestamp blkts = new Timestamp(cal.getTimeInMillis());
                        try (
                            PreparedStatement updateActive = connection.prepareStatement(
                                "UPDATE activeDevice " +
                                "SET err_ctr = ?, blked = ?, err_exp_time = ?, blk_exp_time = ? " +
                                "WHERE mac = ?"
                            )
                        ) {
                            updateActive.setInt(1, 0);
                            updateActive.setBoolean(2, true);
                            updateActive.setTimestamp(3, null);
                            updateActive.setTimestamp(4, blkts, cal);
                            updateActive.setString(5, supMac.toString());
                            updateActive.executeUpdate();
                        } catch (SQLException e) {
                            log.info("[SQLException] (@8009) state: " + e.getSQLState() + " message: " + e.getMessage());
                        }

                        // install drop eapol flow rule
                        eapBlock(supMac, connectp, BLOCKPERIOD);
                    } else {
                        Calendar cal = Calendar.getInstance();
                        cal.add(Calendar.SECOND, ERRRSTPERIOD);
                        Timestamp errts = new Timestamp(cal.getTimeInMillis());
                        try (
                            PreparedStatement updateActive = connection.prepareStatement(
                                "UPDATE activeDevice " +
                                "SET err_ctr = ?, err_exp_time = ? " +
                                "WHERE mac = ?"
                            )
                        ) {
                            updateActive.setInt(1, errCtr);
                            updateActive.setTimestamp(2, errts, cal);
                            updateActive.setString(3, supMac.toString());
                            updateActive.executeUpdate();
                        } catch (SQLException e) {
                            log.info("[SQLException] (@8010) state: " + e.getSQLState() + " message: " + e.getMessage());
                        }
                    }
                }
            }
        } catch (SQLException e) {
            log.info("[SQLException] (@event) state: " + e.getSQLState() + " message: " + e.getMessage());
        }
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
            String userName = new String(aaaAuthenticationRecord.username());

            updateDb(supMac, connectp, userName, state);
        }
    }

    private class InternalFlowRuleEventListener implements FlowRuleListener {
        @Override
        public void event(FlowRuleEvent event) {
            if (event.type() == FlowRuleEvent.Type.RULE_REMOVED) {
                FlowRule rule = event.subject();
                FlowEntry ruleEntry = (FlowEntry) rule;
                if (ruleEntry.appId() == appId.id()) {
                    handleFlowRemoved(ruleEntry);
                }
            }
        }

        private void handleFlowRemoved(FlowEntry ruleEntry) {
            log.info("Flow removed device={}, selector={}, treatment={}, reason={}",
                ruleEntry.deviceId(), ruleEntry.selector(), ruleEntry.treatment(), ruleEntry.reason());

            try (Connection connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)){
                List <User> vips = new ArrayList<>();
                try (Statement stmt = connection.createStatement()) {
                    String sql = "SELECT * " +
                                "FROM authorizedDevice " +
                                "LEFT JOIN switch " +
                                "ON authorizedDevice.switch_id = switch.switch_id " +
                                "WHERE auth_exp_time IS NULL";
                    try (ResultSet res = stmt.executeQuery(sql)) {
                        while (res.next()) {
                            vips.add(
                                new User(
                                    res.getString("mac"),
                                    res.getString("switch_uri")
                                )
                            );
                        }
                    }
                } catch (SQLException e) {
                    log.info("[SQLException] (@5100) state: " + e.getSQLState() + " message: " + e.getMessage());
                }

                EthCriterion ethCrit = (EthCriterion) ruleEntry.selector().getCriterion(Type.ETH_SRC);
                MacAddress srcMac = (ethCrit == null) ? null : ethCrit.mac();
                
                DeviceId devId = ruleEntry.deviceId();
                if ((ruleEntry.selector().getCriterion(Type.IPV4_DST) == null) && (ruleEntry.selector().getCriterion(Type.IP_PROTO) == null)) {
                    for (User vip : vips) {
                        if (vip.devId.equals(devId) && vip.mac.equals(srcMac)) {
                            log.info("Device '{}' authentication timeout!", srcMac);
    
                            try (
                                PreparedStatement pStmt = connection.prepareStatement(
                                    "DELETE FROM authorizedDevice " +
                                    "WHERE mac = ?"
                                )
                            ) {
                                pStmt.setString(1, srcMac.toString());
                                pStmt.executeUpdate();
                            } catch (SQLException e) {
                                log.info("[SQLException] (@5101) state: " + e.getSQLState() + " message: " + e.getMessage());
                            }
                        }
                    }
                    aaaManager.removeAuthenticationStateByMac(srcMac);
                }
            } catch (SQLException e) {
                log.info("[SQLException] (@FlowRuleListener) state: " + e.getSQLState() + " message: " + e.getMessage());
            }
        }

        private class User {
            MacAddress mac;
            DeviceId devId;

            User(String mac, String devId) {
                this.mac = MacAddress.valueOf(mac);
                this.devId = DeviceId.deviceId(devId);
            }
        }
    }
}
