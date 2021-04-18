package nctu.winlab.eapauthenticator;

import java.util.HashMap;
// import java.util.Iterator;
import java.util.Map;
import java.util.Date;
import org.onlab.packet.MacAddress;
import java.util.Arrays;

class AuthenticationLog {
    private static final int INTERVAL = 3;
    private int[] width = {10, 17, 15, 16, 9};
    protected Map<MacAddress, Supplicant> tb;

    public AuthenticationLog() {
        this.tb = new HashMap<MacAddress, Supplicant>();
    }

    public void getAllUsers() {
        Date date = new Date();
        long time = date.getTime();
        // Iterator<Map.Entry<MacAddress, Supplicant>> ittb = tb.entrySet().iterator();
        String fmt = "%-" + String.valueOf(width[0] + INTERVAL) + "s" +
                     "%-" + String.valueOf(width[1] + INTERVAL) + "s" +
                     "%-" + String.valueOf(width[2] + INTERVAL) + "s" +
                     "%-" + String.valueOf(width[3] + INTERVAL) + "s" +
                     "%-" + String.valueOf(width[4] + INTERVAL) + "s" + "\n";
        System.out.printf(fmt, "ID", "MAC", "IP", "State", "Time");
        System.out.printf("-".repeat(Arrays.stream(width).sum() + INTERVAL * 4) + "\n");
        for (Map.Entry mapElement : tb.entrySet()) {
            Supplicant sup = (Supplicant) (mapElement.getValue());
            long periodSec = ((time - sup.joinTime) / 1000) % 60;
            long periodMin = ((time - sup.joinTime) / (1000 * 60)) % 60;
            long periodHour = ((time - sup.joinTime) / (1000 * 60 * 60)) % 60;
            System.out.printf(fmt, sup.name,
                                mapElement.getKey().toString(),
                                sup.ip,
                                sup.state,
                                String.valueOf(periodHour) + ":" +
                                String.valueOf(periodMin) + ":" +
                                String.valueOf(periodSec));
            // System.out.printf(fmt, mapElement.getKey().toString(),
            //                     sup.state,
        }
    }

    public void getBadUsers() {
        String fmt = "%-" + String.valueOf(width[0] + INTERVAL) + "s" +
                "%-" + String.valueOf(width[1] + INTERVAL) + "s" + "\n";
        System.out.printf(fmt, "MAC", "State");
        System.out.printf("-".repeat(Arrays.stream(width).sum() + INTERVAL) + "\n");
        for (Map.Entry<MacAddress, Supplicant> entry : tb.entrySet()) {
            Supplicant sup = entry.getValue();
            if (sup.state.equals("UNAUTHORIZED_STATE")) {
                System.out.printf(fmt, sup.mac, sup.state);
            }
        }
    }
}
