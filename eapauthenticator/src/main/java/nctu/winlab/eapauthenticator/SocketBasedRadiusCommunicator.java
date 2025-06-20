package nctu.winlab.eapauthenticator;

import static org.slf4j.LoggerFactory.getLogger;

import org.glassfish.jersey.internal.guava.ThreadFactoryBuilder;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.RADIUS;
import org.onosproject.net.ConnectPoint;
import org.slf4j.Logger;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


/**
 * Handles Socket based communication with the RADIUS server.
 */
public class SocketBasedRadiusCommunicator {

    private final Logger log = getLogger(getClass());

    // UDP socket for communicating with RADIUS server
    private DatagramSocket radiusSocket;

    // RADIUS server IP addresses
    protected InetAddress radiusIpAddress;

    // RADIUS server port number
    protected short radiusServerPort;

    // socket-based communicator socket bind UDP port
    protected short socketBindPort;

    // authenticaor (the other side) info
    // protected MacAddress authenticatorMac;
    // protected int authenticatorIp;
    // protected int authenticarotPort;
    protected AuthenticatorProperties authenProperties;

    // RADIUS session id <-> Some Radius attributes
    protected Map<Byte, SomeRadiusAttributes> sessions;

    // Connect point of authenticator and supplicant
    private ConnectPoint authenticatorCp;
    private ConnectPoint supplicantCp;

    // Executor for RADIUS communication thread
    private ExecutorService executor;

    Authenticator8021xManager authenticator8021xManager;

    SocketBasedRadiusCommunicator(Authenticator8021xManager authenticator8021xManager, ConnectPoint supplicantCp) {
        this.authenticator8021xManager = authenticator8021xManager;
        this.supplicantCp = supplicantCp;
    }

    public void initializeLocalState() {
        sessions = null;
        try {
            radiusIpAddress = InetAddress.getByName(Authenticator8021xManager.RADIUS_HOST);
        } catch (UnknownHostException e) {
            log.warn("Unable to resolve host {}!", Authenticator8021xManager.RADIUS_HOST);
        }
        radiusServerPort = Authenticator8021xManager.RADIUS_AUTH_PORT;
        socketBindPort = Authenticator8021xManager.SOCKET_BIND_PORT;

        try {
            radiusSocket = new DatagramSocket(null);
            radiusSocket.setReuseAddress(true);
            radiusSocket.bind(new InetSocketAddress(socketBindPort));
        } catch (Exception e) {
            log.error("Can't open RADIUS socket", e);
        }

        log.info("Remote RADIUS Server: {}:{}", radiusIpAddress, radiusServerPort);

        executor = Executors.newSingleThreadExecutor(
                new ThreadFactoryBuilder()
                        .setNameFormat("SDN1X-radius-%d").build());
        executor.execute(radiusListener);
    }

    public void initializeAuthenticatorProperties(MacAddress mac, IpAddress ip, int port, ConnectPoint cp) {
        authenProperties = new AuthenticatorProperties();
        authenProperties.authenMac = mac;
        authenProperties.authenIp = ip;
        authenProperties.authenPort = port;
        authenticatorCp = cp;
        sessions = new HashMap<>();
    }

    public void clearLocalState() {
        radiusSocket.close();
        executor.shutdownNow();
    }

    public ConnectPoint getSupplicantConnectionPoint() {
        return supplicantCp;
    }

    public void sendRadiusPacket(RADIUS radiusPacket) {
        try {
            final byte[] data = radiusPacket.serialize();
            DatagramPacket packet =
                    new DatagramPacket(data, data.length, radiusIpAddress, radiusServerPort);
            radiusSocket.send(packet);
        } catch (IOException e) {
            log.info("Cannot send packet to RADIUS server", e);
        }
    }

    class RadiusListener implements Runnable {

        @Override
        public void run() {
            boolean done = false;
            log.info("UDP listener thread starting up");
            RADIUS inboundRadiusPacket;
            while (!done) {
                try {
                    byte[] packetBuffer = new byte[RADIUS.RADIUS_MAX_LENGTH];
                    DatagramPacket inboundBasePacket =
                            new DatagramPacket(packetBuffer, packetBuffer.length);
                    radiusSocket.receive(inboundBasePacket);
                    try {
                        inboundRadiusPacket =
                                RADIUS.deserializer()
                                        .deserialize(inboundBasePacket.getData(),
                                                0,
                                                inboundBasePacket.getLength());
                        authenticator8021xManager.handleRadiusPacket(
                                                        inboundRadiusPacket,
                                                        authenProperties,
                                                        authenticatorCp,
                                                        supplicantCp,
                                                        sessions);
                    } catch (DeserializationException dex) {
                        log.error("Cannot deserialize packet", dex);
                    }
                } catch (IOException e) {
                    log.info("Socket was closed, exiting listener thread");
                    done = true;
                }
            }
        }
    }

    RadiusListener radiusListener = new RadiusListener();
}