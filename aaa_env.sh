onos-netcfg localhost ~/eapauthenticator/onos-dhcp.json
onos-netcfg localhost ~/eapauthenticator/aaa-conf.json
onos localhost app activate dhcp proxyarp

onos-app localhost install! ~/sadis/app/target/sadis-app-5.1.0.oar
sleep 3
onos-app localhost install! ~/aaa/app/target/aaa-app-2.1.0.oar
sleep 3
onos-app localhost install! ~/Authenticator/eapauthenticator/target/eapauthenticator-1.0-SNAPSHOT.oar
