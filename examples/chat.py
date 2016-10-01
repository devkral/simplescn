#! /usr/bin/env python3
""" license: pd """

import sys
import os
import threading
import socket
import ssl
import json
import logging

from http import server, client
from simplescn import scnrequest
from simplescn.pwrequester import pwcallmethod
from simplescn.tools import scnparse_url, getlocalclient, dhash, default_sslcont, logcheck_con

hserver = None


class chathandler(server.BaseHTTPRequestHandler):
    clienthash = None
    certtupel = (None, None, None)
    default_request_version = "HTTP/1.1"
    
    def wrap(self):
        cont = default_sslcont()
        self.connection = cont.wrap_socket(self.connection, server_side=False)
        self.connection.do_handshake()
        self.clienthash = dhash(ssl.DER_cert_to_PEM_cert(self.connection.getpeercert(True)).strip().rstrip())
        self.rfile = self.connection.makefile(mode='rb')
        self.wfile = self.connection.makefile(mode='wb')
        ret = self.headers.get("Content-Length", "")
        if ret.isdigit():
            #print(self.rfile.read(int(ret)))
            self.certtupel = json.loads(str(self.rfile.read(int(ret)), "utf-8")).get("origcertinfo")
        self.send_response(200)
        self.send_header('Connection', 'keep-alive')
        # hack
        self.send_header("Content-Length", "0")
        self.end_headers()

    def chat(self):
        ret = self.headers.get("Content-Length", "")
        if ret.isdigit():
            print("Client:", self.clienthash)
            print("From:", self.certtupel[1])
            print(str(self.rfile.read(int(ret)), "utf-8"))
        self.send_response(200)
        self.send_header('Connection', 'close')
        self.end_headers()
    def log_request(self, *args):
        pass
    
    def do_POST(self):
        if self.path == "/wrapping":
            self.wrap()
        else:
            self.chat()
        #if self.forcehash:
        #    pass
        

def cmdloop(requester, ownscnport):
    while True:
        inp = input("<action> <actionparams...> <message>:\n").split(" ", 1)
        if inp[0] == "show":
            print("Own address: ::1-{}".format(ownscnport))
            print("Own (intern) port: {}".format(hserver.server_port))
            continue

        if len(inp) < 2:
            print("Error: too less parameters")
            continue
        if inp[0] == "local":
            req = "::1-{}".format(ownscnport), inp[1]
        elif inp[0] == "direct":
            tt = inp[1].split(" ", 1)
            if len(tt) < 2:
                print("Error: too less parameters – direct")
                continue
            req = tt[0], tt[1]
        elif inp[0] == "server":
            tt = inp[1].split(" ", 2)
            if len(tt) < 4:
                print("Error: too less parameters – server")
                continue
            body_server = {"server": tt[0], "name": tt[1], "hash": tt[2]}
            resp_s = requester.do_request("/client/get", body_server, {}, pwhandler=pwcallmethod)
            if resp_s[0]:
                resp_s[0].close()
            if not resp_s[1]:
                print("server name retrieval failed")
                continue
            req = resp_s.get("address"), tt[3]
        else:
            print("No valid action")
            continue
        body = {"name": "examplechat", "address": req[0]}
        resp = requester.do_request("/client/wrap", body, {})
        if logcheck_con(resp, logging.ERROR):
            continue
        
        con = client.HTTPConnection(*scnparse_url(req[0]))
        con.sock = resp[0].sock
        resp[0].sock = None
        ob = bytes(inp[1],"utf-8")
        con.putrequest("POST", "/chat")
        con.putheader("Content-Length", str(len(ob)))
        con.putheader("Content-Type", "application/json")
        con.endheaders()
        con.send(ob)
        respl = con.getresponse()

        if respl.status!=200:
            print(respl.read())

class httpserver(server.HTTPServer):
    address_family = socket.AF_INET6
    socket_type = socket.SOCK_STREAM

def init(requester):
    global hserver
    hserver = httpserver(("::1", 0), chathandler)
    threading.Thread(target=hserver.serve_forever, daemon=True).start()
    body = {"port": hserver.server_port, "name": "examplechat", "post": True, "wrappedport": True}
    resp = requester.do_request("/client/registerservice", body, {})
    resp2 = requester.do_request("/client/show", {}, {})
    if not resp[1] or not resp2[1]:
        print(resp[2])
        print(resp2[2])
        hserver.shutdown()
        return
    requester.saved_kwargs["forcehash"] = resp[3][1]
    requester.saved_kwargs["ownhash"] = resp[3][1]
    cmdloop(requester, resp2[2].get("port"))

if __name__ == "__main__":
    if len(sys.argv) == 2:
        if os.path.exists(sys.argv[1]):
            init(scnrequest.Requester(default_addrcon=sys.argv[1], use_unix=True, pwhandler=pwcallmethod))
        else:
            init(scnrequest.Requester(default_addrcon=sys.argv[1], use_unix=False, pwhandler=pwcallmethod))
    else:
        p = getlocalclient()
        if p:
            init(scnrequest.Requester(default_addrcon=p[0], use_unix=p[1], pwhandler=pwcallmethod))
        else:
            print("Error: client not found", file=sys.stderr)
        #elif os.path.exists(p.format("info")):
        #    init(scnrequest.requester(use_unix=False, forcehash=pjson.get("cert_hash"), pwhandler=pwcallmethod), pjson.get("cserver_ip"))

