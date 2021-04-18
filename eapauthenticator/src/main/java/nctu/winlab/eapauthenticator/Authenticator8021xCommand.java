/*
 * Copyright 2019-present Open Networking Foundation
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

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
// import org.apache.karaf.shell.api.action.Option;
// import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
// import org.onosproject.net.config.ConfigFactory;

/**
 * 802.1x Authenticator CLI.
 */
@Service
@Command(scope = "onos", name = "authenctl",
         description = "802.1x Authenticator CLI")
public class Authenticator8021xCommand extends AbstractShellCommand {

    @Argument(index = 0, name = "instruction",
            description = "(get)",
            required = true, multiValued = false)
    private String instruction;

    @Argument(index = 1, name = "contents",
            description = "instruction specific contents",
            required = true, multiValued = true)
    private String[] contents;

    // @Option(name = "-t", aliases = "--target",
    //         description = "Indicate (by index) machine to be operated on.",
    //         required = false, multiValued = false)
    // private int target = ALL_CLIENTS_OPERATION_INDEX;

    private final Authenticator8021xService service = get(Authenticator8021xService.class);

    @Override
    protected void doExecute() {
        switch (instruction) {
            case "get":
                getHandler();
                break;
            // case "set":
            //     setHandler(false);
            //     break;
            // case "unset":
            //     setHandler(true);
            //     break;
            // case "exec":
            //     execHandler();
            //     break;
            default:
                System.out.printf("Invalid instruction: %s\n", instruction);
        }
    }

    private void getHandler() {
        switch (contents[0]) {
            case "users":
                service.getAllUsers();
                break;
            case "unauthorized":
                service.getBadUsers();
                break;
            default:
                System.out.printf("Invalid resource: %s\n", contents[0]);
        }
    }

    // private void setHandler(boolean unsetFlag) {
    //     switch (contents[0]) {
    //         case "controller":
    //             String ip = contents.length > 1 ? contents[1] : null;
    //             if (ip == null) {
    //                 System.out.println("Controller IP should be assigned");
    //                 break;
    //             }
    //             String port = contents.length > 2 ? contents[2] : "";
    //             if (unsetFlag) {
    //                 service.unsetController(target, ip);
    //             } else {
    //                 service.setController(target, ip, port);
    //             }
    //             break;
    //         case "ssid":
    //             if (contents.length < 3) {
    //                 System.out.println("Usage:");
    //                 System.out.println("  sshctl set controller <ip> [port]");
    //                 System.out.println("  sshctl set ssid <ifname> <ssid>");
    //                 break;
    //             }
    //             service.setSsid(target, contents[1], contents[2]);
    //             break;
    //         case "vxlan":
    //             if (contents[1].equals("loopback")) {
    //                 if (contents.length < 3) {
    //                     System.out.println("Usage:");
    //                     System.out.println("  sshctl set vxlan loopback <loopback-id>");
    //                     break;
    //                 }
    //                 service.setVxlanSourceInterfaceLoopback(target, contents[2]);
    //             } else if (contents[2].equals("vlan")) {
    //                 if (contents.length < 4) {
    //                     System.out.println("Usage:");
    //                     System.out.println("  sshctl set vxlan <vnid> vlan <vid>");
    //                     break;
    //                 }
    //                 service.setVxlanVlan(target, contents[1], contents[3]);
    //             } else if (contents[2].equals("vtep")) {
    //                 if (contents.length < 4) {
    //                     System.out.println("Usage:");
    //                     System.out.println("  sshctl set vxlan <vnid> vtep <ip> [mac]");
    //                     break;
    //                 }
    //                 String mac = contents.length > 4 ? contents[4] : "";
    //                 service.setVxlanVtep(target, contents[1], contents[3], mac);
    //             } else {
    //                 System.out.printf("Invalid VXLAN command: %s\n", contents[1]);
    //             }
    //             break;
    //         default:
    //             System.out.printf("Invalid resource: %s\n", contents[0]);
    //     }
    // }

    // private void execHandler() {
    //     service.execCommand(target, contents[0]);
    // }
}
