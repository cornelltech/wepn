import pyshark
import sqlite3
import socket
import requests
from datetime import datetime
import time

def addAll():
    for row in db.execute("SELECT * FROM raw_traffic").fetchall():
        dest = row[2]
        addIpLocation(dest)

count = 0
time0 = time.time()

def addIpLocation(ip):
    global count
    global time0
    if(time.time()-time0 > 60):
        count = 0
        time0 = time.time()
    location = db.execute("SELECT * FROM ip_location WHERE ip=?", [ip]).fetchone()
    if location == None and count < 140:
        r = requests.get("http://ip-api.com/json/"+ip)
        count += 1
        json = r.json()
        if json["status"]=="success":
            location = json["city"]+","+json["regionName"]+","+json["country"]
            print(ip+" - "+location)
            db.execute("INSERT INTO ip_location(ip, location) VALUES(?, ?)", [ip, location])
        else:
            db.execute("INSERT INTO ip_location(ip, location) VALUES(?, ?)", [ip, "Unknown"])
        conn.commit()


def analyze(packet):
    l = packet.layers[3:]
    l = list(map(lambda x: x.layer_name.upper(), l))

    addIpLocation(packet.ip.dst)

    domain = None
    if(packet.ip.dst in dns):
        domain = dns[packet.ip.dst]
    else:
        try:
            domain = socket.gethostbyaddr(packet.ip.dst)[0]
        except socket.herror:
            domain = "Unknown"
    db.execute("INSERT INTO raw_traffic(source, dest, domain, date, prot, info) VALUES (?,?,?,?,?,?)", (packet.ip.src,packet.ip.dst,domain, datetime.now(), ", ".join(l), packet.length,))

    #print(db.execute("SELECT * FROM day_traffic WHERE ip=? AND protocol=? AND date=?", [packet.ip.src, ", ".join(l), datetime.now().date()]).fetchone())
    if db.execute("SELECT * FROM day_traffic WHERE ip=? AND protocol=? AND date=?", [packet.ip.src, ", ".join(l), str(datetime.now().date())]).fetchone() != None:
        db.execute("UPDATE day_traffic SET amount=amount+1 WHERE ip=? AND protocol=? AND date=?",  [packet.ip.src, ", ".join(l), str(datetime.now().date())])
    else:
        db.execute("INSERT INTO day_traffic(ip,protocol,date,amount) VALUES(?,?,?,?)",  [packet.ip.src, ", ".join(l), str(datetime.now().date()), 1])


    if db.execute("SELECT * FROM ip_traffic WHERE source=? AND dest=?", [packet.ip.src, packet.ip.dst]).fetchone() != None:
        db.execute("UPDATE ip_traffic SET amount=amount+1 WHERE source=? AND dest=?", [packet.ip.src, packet.ip.dst])
    else:
        db.execute("INSERT INTO ip_traffic(source,dest,domain,amount) VALUES(?,?,?,?)",  [packet.ip.src, packet.ip.dst, domain,1])

    conn.commit()


conn = sqlite3.connect('/host/globaldb/global.db')
conn.row_factory = sqlite3.Row
db = conn.cursor()
conn.execute('pragma journal_mode=wal')

dns = {}

capture = pyshark.LiveCapture(interface='tun0',override_prefs={'data.show_as_text':'TRUE'})
print("Entered !")
#capture.sniff(timeout=50)
for packet in capture.sniff_continuously():
    if(not ('SSH' in packet and (packet.ip.dst=="10.8.0.1" or packet.ip.src=="10.8.0.1"))):
        source = str(packet.ip.src)
        if(source.startswith("10.8.0.") and source != "10.8.0.1" and not 'DNS' in packet):
            if(len(packet.layers)>3): #means no TCP protocol details (ACK,NACK ...)
                if('DATA' in packet and not 'SSL' in packet):
                    if("tcp.reassembled.data" in packet.data._all_fields):
                        raw = packet.data._all_fields["tcp.reassembled.data"].replace(":", "")
                    if("data.text" in packet.data._all_fields):
                        print(packet.data._all_fields["data.text"])
                analyze(packet)
        if('DNS' in packet):
            if(hasattr(packet.dns, 'a')):
                print(str(packet.dns.qry_name)+" --> "+packet.dns.a)
                dns[packet.dns.a] = packet.dns.qry_name
