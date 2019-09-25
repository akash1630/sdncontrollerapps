#!/bin/bash

echo "------ OVS Setup intilaized -------"
echo ""

apt-get update
apt-get install build-essential fakeroot
apt-get install git
apt-get install libssl-dev libcap-ng-dev
apt-get install python python-dev python-twisted-core python-six
apt-get install autoconf automake libtool
apt-get install perl

git clone https://github.com/openvswitch/ovs

cd ovs

./boot.sh
./configure

make
make install

make modules_install

/sbin/modprobe openvswitch

mkdir -p /usr/local/etc/openvswitch
ovsdb-tool create /usr/local/etc/openvswitch/conf.db vswitchd/vswitch.ovsschema

echo ""
echo "------- OVS Setup complete ---------"
echo "" 
