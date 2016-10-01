#! /usr/bin/env python3
""" license: pd """

import sys
import os
import socket

from http import server
from simplescn import scnrequest
from simpplescn.pwrequester import pwcallmethod
from simplescn.tools import getlocalclient, rw_socket

hserver = None


class ProxyHandler(server.BaseHTTPRequestHandler):
    requester = None
    default_request_version = "HTTP/1.1"

    def log_request(self, *args):
        pass

    def do_CONNECT(self):
        splitted = self.path.split("/")
        forcehash = None
        if len(splitted) == 2:
            address, service = splitted
        elif len(splitted) == 3:
            address, forcehash, service = splitted
        else:
            self.send_error(400, "invalid address")
            return
        wrapbody = {"address": address, "name": service}
        if forcehash:
            wrapbody["forcehash"] = forcehash
        resp = self.requester.do_request("/client/wrap", wrapbody, {}, keepalive=True)
        if not resp[0] or not resp[1]:
            self.send_error(400, str(resp[2]))
            return
        self.send_response(200)
        self.end_headers()
        sock = resp[0].sock
        resp[0].sock = None
        del resp[0]
        rw_socket(self.connection, sock)
        self.close_connection = True

class httpserver(server.HTTPServer):
    address_family = socket.AF_INET6
    socket_type = socket.SOCK_STREAM

def init(requester, port):
    global hserver
    resp = requester.do_request("/client/show", {}, {})
    if not resp[1]:
        return
    requester.saved_kwargs["forcehash"] = resp[3][1]
    requester.saved_kwargs["ownhash"] = resp[3][1]
    ProxyHandler.requester = requester
    hserver = httpserver(("::1", port), ProxyHandler)
    print('{"port": %s}' % hserver.socket.getsockname()[1])
    hserver.serve_forever()

if __name__ == "__main__":
    if len(sys.argv) == 3:
        if os.path.exists(sys.argv[1]):
            init(scnrequest.Requester(sys.argv[1], use_unix=True, pwhandler=pwcallmethod), int(sys.argv[2]))
        else:
            init(scnrequest.Requester(sys.argv[1], use_unix=False, pwhandler=pwcallmethod), int(sys.argv[2]))
    else:
        port = 0
        if len(sys.argv) == 2:
            port = int(sys.argv[1])
        p = getlocalclient()
        if p:
            init(scnrequest.Requester(p[0], use_unix=p[1], pwhandler=pwcallmethod), port)
        else:
            print("Error: client not found", file=sys.stderr)

