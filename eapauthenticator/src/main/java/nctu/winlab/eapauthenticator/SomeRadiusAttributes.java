package nctu.winlab.eapauthenticator;

import org.onlab.packet.MacAddress;

public class SomeRadiusAttributes {
    MacAddress calling_station_id;          // RADIUS attribute: 'Calling_Station_Id'
    String user_name;                       // RADIUS attribute: 'User_Name'

    SomeRadiusAttributes(String calling_station_id, String user_name) {
        this.calling_station_id = MacAddress.valueOf(calling_station_id);
        this.user_name = user_name;
    }
}
