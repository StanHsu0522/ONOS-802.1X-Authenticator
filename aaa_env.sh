# onos app dhcp static ip mapping set
# onos localhost dhcp-set-static-mapping 08:00:27:6d:0b:41 192.168.44.189
# onos localhost dhcp-set-static-mapping 08:00:27:bc:3d:be 192.168.44.190

onos-netcfg localhost ~/ONOS-802.1X-Authenticator/aaa-conf.json

onos-app localhost install! ~/sadis/app/target/sadis-app-5.1.0.oar
sleep 3
onos-app localhost install! ~/aaa_mod/app/target/aaa-app-2.1.0.oar
sleep 3
onos-app localhost install! ~/ONOS-802.1X-Authenticator/eapauthenticator/target/eapauthenticator-1.0-SNAPSHOT.oar
sleep 3

onos-netcfg localhost ~/ONOS-802.1X-Authenticator/onos-dhcp.json
onos localhost app activate dhcp proxyarp
# onos localhost app activate proxyarp