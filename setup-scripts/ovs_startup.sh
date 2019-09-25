#!/bin/bash

echo "--------OVS startup and configuration with 4 virtual ports and 1 bridge--------"
echo " run 'sudo ovs-vsctl show' to check the ports and bridge"
echo ""

/sbin/modprobe openvswitch

ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
                 --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
                 --private-key=db:Open_vSwitch,SSL,private_key \
                 --certificate=db:Open_vSwitch,SSL,certificate \
                 --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
                 --pidfile --detach

ovs-vsctl --no-wait init

ovs-vswitchd --pidfile --detach

echo ""
echo "----- Adding a bridge br0 -------"

ovs-vsctl add-br br0

echo ""
echo "------ Setting up vports 1 thru 4 ------"

ip tuntap add mode tap vport1
ip tuntap add mode tap vport2
ip tuntap add mode tap vport3
ip tuntap add mode tap vport4

ip link set vport1 up
ip link set vport2 up
ip link set vport3 up
ip link set vport4 up

echo ""
echo "------- Adding vports 1 thru 4 to bridge br0 ---------"

ovs-vsctl add-port br0 vport1
ovs-vsctl add-port br0 vport2
ovs-vsctl add-port br0 vport3
ovs-vsctl add-port br0 vport4

echo "------ OVS startup and configuration complete ---------"
