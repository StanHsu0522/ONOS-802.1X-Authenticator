onos-netcfg localhost ~/Authenticator/onos-dhcp.json
onos-netcfg localhost ~/Authenticator/aaa-conf.json
onos localhost app activate dhcp proxyarp

# onos app dhcp static ip mapping set
onos localhost dhcp-set-static-mapping 08:00:27:6d:0b:41 192.168.44.189
onos localhost dhcp-set-static-mapping 08:00:27:bc:3d:be 192.168.44.190

onos-app localhost install! ~/sadis/app/target/sadis-app-5.1.0.oar
sleep 3
onos-app localhost install! ~/aaa/app/target/aaa-app-2.1.0.oar
sleep 3
onos-app localhost install! ~/Authenticator/eapauthenticator/target/eapauthenticator-1.0-SNAPSHOT.oar
