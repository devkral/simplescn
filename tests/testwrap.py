#! /usr/bin/env python3

import unittest
import time
import threading
from http import server, client
import json
import tempfile
import socket

import sys
import os
# fix import
if os.path.dirname(os.path.dirname(os.path.realpath(__file__))) not in sys.path:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
import simplescn
from simplescn import scnrequest
from simplescn.tools import start, default_sslcont

class httpserver(server.HTTPServer):
    address_family = socket.AF_INET6
    socket_type = socket.SOCK_STREAM

class WrapTestHandler(server.BaseHTTPRequestHandler):
    forcehash = None
    certtupel = (None, None, None)
    server_timeout = 4
    default_request_version = "HTTP/1.1"

    def wrap(self):
        cont = default_sslcont()
        self.connection = cont.wrap_socket(self.connection, server_side=False)
        self.connection.do_handshake()
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

    def confirm(self):
        ob = bytes(json.dumps({"origcertinfo":  self.certtupel}), "utf-8")
        self.send_response(200)
        self.send_header("Content-Length", str(len(ob)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(ob)

    def log_request(self, *args):
        pass

    def do_POST(self):
        if self.path == "/wrapping":
            self.wrap()
        else:
            self.confirm()

class TestWrap(unittest.TestCase):
    temptestdir = tempfile.TemporaryDirectory("testwrap")
    temptestdir2 = tempfile.TemporaryDirectory("testwrap")
    #param_server = ["--config={}".format(temptestdir), "--nolock", "--port=0"]
    param_client = ["--config={}".format(temptestdir.name), "--nolock", "--nounix", "--noip=False"]
    param_client2 = ["--config={}".format(temptestdir2.name), "--nolock", "--nounix", "--noip"]

    client = None
    #server = None
    service_server = None

    # needed to run ONCE; setUpModule runs async
    @classmethod
    def setUpClass(cls):
        #print(cls.temptestdir, cls.temptestdir2)
        cls.oldpwcallmethodinst = simplescn.pwcallmethodinst
        simplescn.pwcallmethodinst = lambda msg: ""
        cls.client = start.client(cls.param_client, doreturn=True)
        cls.client_hash = cls.client.links["certtupel"][1]
        cls.client_port = cls.client.links["hserver"].server_port
        cls.client_c_port = cls.client.links["cserver_ip"].server_port
        cls.name = cls.client.links["client"].name

        #cls.client2 = start.client(cls.param_client2, doreturn=True)
        #cls.client_hash2 = cls.client2.links["client"].certtupel[1]
        #cls.client_port2 = cls.client2.links["hserver"].server_port

        #cls.server = start.server(cls.param_server, doreturn=True)
        #cls.server_port = cls.server.links["hserver"].server_port
        cls.service_server = httpserver(("::1", 0), WrapTestHandler)
        threading.Thread(target=cls.service_server.serve_forever, daemon=True).start()
        body = {"port": cls.service_server.server_port, "name": "test1", "post": True, "wrappedport": True}
        cls.client.links["client"] .registerservice(body)
        body = {"port": cls.service_server.server_port, "name": "test2", "post": False, "wrappedport": False}
        cls.client.links["client"] .registerservice(body)

    # needed to run ONCE; tearDownModule runs async
    @classmethod
    def tearDownClass(cls):
        # server side needs some time to cleanup, elsewise strange exceptions happen
        time.sleep(2)
        cls.service_server.shutdown()
        cls.client.quit()
        #cls.client2.quit()
        #cls.server.quit()
        simplescn.pwcallmethodinst = cls.oldpwcallmethodinst

    def test_wrap1(self):
        body = {"address": "::1-{}".format(self.client_port), "name": "test1"}
        wrap1 = scnrequest.do_request("::1-{}".format(self.client_c_port), "/client/wrap", body, {}, keepalive=True, ownhash=self.client_hash)
        self.assertEqual(wrap1[1], True)
        con = client.HTTPConnection("::1", self.client_c_port)
        con.sock = wrap1[0].sock
        wrap1[0].sock = None
        con.putrequest("POST", "/confirm")
        con.putheader("Content-Length", "0")
        con.endheaders()
        resp = con.getresponse()
        ob = resp.read(int(resp.headers["Content-Length"]))
        job = json.loads(str(ob, "utf-8"))
        testob = {"origcertinfo": list(self.client.links["certtupel"])}
        self.assertDictEqual(job, testob)

    def test_wrap2(self):
        body = {"address": "::1-{}".format(self.client_port), "name": "test2"}
        wrap1 = scnrequest.do_request("::1-{}".format(self.client_c_port), "/client/wrap", body, {}, keepalive=True, ownhash=self.client_hash)
        self.assertEqual(wrap1[1], True)
        con = client.HTTPConnection("::1", self.client_c_port)
        con.sock = wrap1[0].sock
        wrap1[0].sock = None
        #sob = bytes(json.dumps({"success": True}), "utf-8")
        con.putrequest("POST", "/confirm")
        con.putheader("Content-Length", "0")
        con.endheaders()
        #con.send(sob)
        resp = con.getresponse()
        ob = resp.read(int(resp.headers["Content-Length"]))
        job = json.loads(str(ob, "utf-8"))
        self.assertDictEqual(job, {"origcertinfo": [None, None, None]})

if __name__ == "__main__":
    unittest.main(verbosity=2)
