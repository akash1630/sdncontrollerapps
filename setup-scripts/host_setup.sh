#!/bin/bash

clear

echo "------- Host setup initilaized ---------"
echo ""

apt-get update
apt-get install git
apt-get install python
apt-get install python-pip python-dev build-essential
apt-get install fatrace
apt-get install libnfnetlink-dev
apt-get install libnetfilter-queue-dev


pip install --upgrade pip
pip install psutil
pip install ipaddr
pip install colorama
pip install netfilterqueue
pip install netifaces
pip install scapy
pip install pexpect

echo ""
echo "-------- Host setup finished --------------"
