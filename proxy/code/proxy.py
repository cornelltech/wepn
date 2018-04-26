"""
This example shows two ways to redirect flows to another server.
"""
from mitmproxy import http,ctx,websocket,tcp, proxy
import json
import datetime
import sqlite3
import base64
import re
import urllib.parse
import typing
from pprint import pprint

import collections
from enum import Enum

from mitmproxy.exceptions import TlsProtocolException
from mitmproxy.proxy.protocol import TlsLayer, RawTCPLayer

import ipaddress

tls_history = {}

class InterceptionResult(Enum):
    success = True
    failure = False
    skipped = None


class TlsFeedback(TlsLayer):
    """
    Monkey-patch _establish_tls_with_client to get feedback if TLS could be established
    successfully on the client connection (which may fail due to cert pinning).
    """

    def _establish_tls_with_client(self):
        global tls_history
        server_address = self.server_conn.address[0]


        try:
            super(TlsFeedback, self)._establish_tls_with_client()
        except TlsProtocolException as e:
            tls_history[server_address] = {"date":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "host":self._client_hello.sni}
            raise e
        else:
            tls_history.pop(server_address, None)

fbips = []
f = open("code/fbips")
for line in f:
    fbips.append(ipaddress.ip_network(line.strip(), strict=False))
f.close()

def next_layer(next_layer):
    global tls_history,fbips

    if isinstance(next_layer, TlsLayer):
        server_address = next_layer.server_conn.address[0]
        if not server_address in tls_history:
            # We try to intercept.
            # Monkey-Patch the layer to get feedback from the TLSLayer if interception worked.
            next_layer.__class__ = TlsFeedback
        else:
            # We don't intercept - reply with a pass-through layer and add a "skipped" entry.
            ctx.log("TLS passthrough for %s" % repr(next_layer.server_conn.address), "info")
            ctx.log(str(tls_history))
            next_layer_replacement = RawTCPLayer(next_layer.ctx)
            next_layer.reply.send(next_layer_replacement)
            #tls_strategy.record_skipped(server_address)

# def tcp_message(flow: tcp.TCPFlow):
#     global tls_history
#     """
#         A TCP connection has received a message. The most recent message
#         will be flow.messages[-1]. The message is user-modifiable.
#     """
#     server_address = flow.server_conn.address[0]
#     if(server_address in tls_history and blocked(flow.client_conn.address[0][7:], tls_history[server_address]["host"])):
#         flow.kill()
#         return


def blocked(ip_source, host):
    username = db.execute("SELECT username FROM ips WHERE ip=?", (ip_source,)).fetchone()
    if username != None:
        username = username[0]
    else:
        return False
    row = db.execute("SELECT * FROM blockfb WHERE username=?", (username,)).fetchone()
    if(row != None):
        if(host in fbdomains):
            start_min = int(row["start"].split(":")[0])*60+int(row["start"].split(":")[1])
            end_min = int(row["end"].split(":")[0])*60+int(row["end"].split(":")[1])
            now_min = (datetime.datetime.now()-datetime.timedelta(hours=4)).hour*60+datetime.datetime.now().minute
            if(start_min <= now_min and end_min >= now_min):
                return True
    row = db.execute("SELECT * FROM blockadult WHERE username=?", (username,)).fetchone()
    if(row != None):
        if(host in fbdomains):
            return True
    return False



#db = client.global_login

conn = sqlite3.connect('/home/ubuntu/global-login/db/global.db')
conn.row_factory = sqlite3.Row
db = conn.cursor()

adultdomains = []
f = open("code/adultdomains")
for line in f:
    adultdomains.append(line.strip())

fbdomains = []
f = open("code/fbdomains")
for line in f:
    fbdomains.append(line.strip())

addomains = []
f = open("code/addomains")
for line in f:
    addomains.append(line.strip())
totaladsent = 0
totaladrec = 0

youdomains = []
f = open("code/youtubedomains")
for line in f:
    youdomains.append(line.strip())

def check_login(ip_addr):
    return (db.execute("SELECT * FROM ips WHERE ip=?", (ip_addr,)).fetchone() != None)

checked_hosts = set()


def request(flow: http.HTTPFlow):
    global totaladsent, totaladrec;
    if(flow.request.pretty_host == "myvpn"):
        return;

    ip_addr = flow.client_conn.address[0][7:]
    username = db.execute("SELECT username FROM ips WHERE ip=?", (ip_addr,)).fetchone()
    if username != None:
        username = username[0]

    flow.request.headers["Sec-WebSocket-Extensions"] = ""

    f = open("log/log_http", "a")
    #flow.request.get_text to have body
    f.write(ip_addr+"|"+flow.request.method+"|"+flow.request.pretty_host+"|"+flow.request.url+"|"+str(datetime.datetime.now())+"\n")
    f.close()
    #the  [4:] is for "www."
    if(flow.request.pretty_host in adultdomains or flow.request.pretty_host[4:] in adultdomains):
        flow.request.host = "google.com"

    if(flow.request.pretty_host in addomains):
        totaladsent += len(flow.request.content)
        adlog = open("log/log_ad", 'a')
        adlog.write("Sent : "+str(totaladsent)+" -- Received : "+str(totaladrec)+"\n")
        adlog.close()

    if(blocked(ip_addr, flow.request.pretty_host)):
        flow.response = http.HTTPResponse.make(
                 302,  # (optional) status code
                 "",
                 {"Location": "http://myvpn/"}  # (optional) headers
                 )



def response(flow: http.HTTPFlow):
    global totaladrec, totaladsent
    if(flow.request.pretty_host == "myvpn"):
        return flow;

    ip_addr = flow.client_conn.address[0][7:]
    username = db.execute("SELECT username FROM ips WHERE ip=?", (ip_addr,)).fetchone()
    if(username == None):
       flow.response.status_code = 302
       flow.response.headers["Location"] = "http://myvpn/login/"
    else:
       username = username[0]

    if(flow.request.pretty_host in addomains):
        adlog = open("log/log_ad", 'a')
        totaladrec += len(flow.response.content)
        adlog.write("Sent : "+str(totaladsent)+" -- Received : "+str(totaladrec)+"\n")
        adlog.close()

    flow.response.scheme = 'http'
    flow.response.port = 80

    flow.response.headers.pop('Strict-Transport-Security', None)
    flow.response.headers.pop('strict-transport-security', None)
    flow.response.headers.pop('Public-Key-Pins', None)
    flow.response.headers.pop('public-key-pins', None)

    f = open("log/log_http_back", "a")
    f.write(ip_addr+" "+flow.request.method+" "+flow.request.pretty_host+" "+flow.request.url+" "+str(datetime.datetime.now())+"\n"+str(flow.response.headers)+"\n\n")
    f.close()




def websocket_message(flow: websocket.WebSocketFlow):
    f = open("log/log_slack", "a")
    f.write(flow.messages[-1].__repr__()+"\n")
    f.close()
    ctx.log("Websockt !! --> "+flow.messages[-1].__repr__())
    if(not check_login(flow.handshake_flow.client_conn.address[0][7:])):
        flow.handshake_flow.response.status_code = 302
        flow.handshake_flow.response.headers["Location"] = "http://myvpn/"
    # f = open("log_slack", "a")
    # f.write(flow.messages[-1].__repr__()+"\n")
    # f.close()

    # FOR SLACK
    # if(not flow.messages[-1].from_client):
    #     M = json.loads(flow.messages[-1].content)
    #     M["text"] = M["text"] + " --> bidouille"
    #     flow.messages[-1].content = json.dumps(M)
