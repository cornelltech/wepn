#!/bin/bash

mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200
fi

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

dir=$(pwd)

#iptables -t nat -A POSTROUTING -j MASQUERADE

#----------------------OPENVPN--------------------
apt-get install openvpn
cp ./openvpn/conf/* /etc/openvpn
cd /etc/openvpn && openvpn server.conf &

#----------------------NGINX----------------------
apt-get install nginx
cp ./nginx/conf/* /etc/nginx
service nginx start

#----------------------BIND-----------------------
apt-get install bind9
cp ./bind/conf/* /etc/bind
service bind9 start

#----------------------MONITOR--------------------
python3 ./monitor/bin/main.py &


cd $dir
docker-compose build
docker-compose up
