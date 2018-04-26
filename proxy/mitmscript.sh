#!/bin/sh
iptables -t nat -A PREROUTING ! -d 10.8.0.0/24 -p tcp --dport 80 -j REDIRECT --to-port 6000
iptables -t nat -A PREROUTING ! -d 10.8.0.0/24 -p tcp --dport 443 -j REDIRECT --to-port 6000
python-env/bin/mitmproxy --mode transparent --no-http2 -p 6000
iptables -t nat -D PREROUTING 1
iptables -t nat -D PREROUTING 1
