import pyshark
import sqlite3
import socket
from datetime import datetime

conn = sqlite3.connect('/home/ubuntu/global-login/db/global.db')
conn.row_factory = sqlite3.Row
db = conn.cursor()

dns = {}

capture = pyshark.LiveCapture(interface='tun0')
#capture.sniff(timeout=50)
for packet in capture.sniff_continuously():
    print('Just arrived: from '+packet.ip.src+" to "+packet.ip.dst+" -- "+str(packet.layers))
    source = str(packet.ip.src)
    if(source.startswith("10.8.0.") and source != "10.8.0.1" and not 'DNS' in packet):
        if(len(packet.layers)>3): #means no TCP protocol details (ACK,NACK ...)
            l = packet.layers[3:]
            l = list(map(lambda x: x.layer_name.upper(), l))

            domain = None
            if(packet.ip.dst in dns):
                domain = dns[packet.ip.dst]
            else:
                try:
                    domain = socket.gethostbyaddr(packet.ip.dst)[0]
                except socket.herror:
                    domain = "Unknown"
            db.execute("INSERT INTO traffic(source, dest, domain, date, prot, info) VALUES (?,?,?,?,?,?)", (packet.ip.src,packet.ip.dst,domain, datetime.now(), ", ".join(l), "",))
            conn.commit()
    if('DNS' in packet):
        print(packet.dns.__dict__)
        if(hasattr(packet.dns, 'a')):
            dns[packet.dns.a] = packet.dns.qry_name
            print(packet.dns.resp_name)
            print(packet.dns.qry_name)
            print(packet.dns.a)
