#! /usr/bin/env python3

import unittest
import timeit
import time
import tempfile
import threading
import compileall
#import logging

import sys, os
# fix import
if os.path.dirname(os.path.dirname(os.path.realpath(__file__))) not in sys.path:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from http.server import BaseHTTPRequestHandler
from http.client import HTTPSConnection

from simplescn._common import SHTTPServer
from simplescn import scnrequest, tools, config, pwrequester
from simplescn.tools import start

avgtestnum = 50
avg = 0.3

parallelnum = 50
maxtime = 3

printresults = False
if not printresults and "SCNDEBUG" in os.environ:
    printresults = True

def stubconnect(addr, _port):
    con = HTTPSConnection(addr, _port, context=tools.default_sslcont())
    con.request("POST", "/just/stub", body=b"'{}'", headers={"Content-Type": "application/json"})
    resp = con.getresponse()
    resp.read(int(resp.getheader("Content-Length")))

def stubconnect_invalid(addr, _port):
    con = HTTPSConnection(addr, _port, context=tools.default_sslcont())
    con.request("CONNECT", "/just/stub", body=b"'{}'", headers={"Content-Type": "application/json"})
    resp = con.getresponse()
    resp.read(int(resp.getheader("Content-Length")))

def _threaded_bar(func, threadsem, args, kwargs):
    func(*args, **kwargs)
    threadsem.release()

def threaded_bar(func, threadsem, counter, args=(), kwargs={}):
    threadsem.acquire(False)
    threading.Thread(target=_threaded_bar, args=(func, threadsem, args, kwargs), daemon=True).start()
    counter[0] += 1
    if counter[0] >= counter[1]:
        threadsem.acquire(True)

class TestServerHandler(BaseHTTPRequestHandler):
    server_timeout = 4
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Length", str(2))
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_request(self, code='-', size='-'):
        pass

class TestSpeed(unittest.TestCase):
    temptestdir = tempfile.TemporaryDirectory()
    #temptestdir2 = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_speed2")
    param_server = ["--config={}".format(temptestdir.name), "--port=0", "--nolock", "--loglevel=7"]
    param_client = ["--config={}".format(temptestdir.name), "--port=0", "--nolock", "--loglevel=7", "--nounix", "--noip=False"]
    #param_client2 = ["--config={}".format(temptestdir2), "--port=0", "--nolock", "--loglevel=7", "--nounix", "--noip"]
    referencestuff = None
    referencestuffinvalid = None

    # needed to run ONCE; setUpModule runs async
    @classmethod
    def setUpClass(cls):
        compileall.compile_dir(os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "simplescn"))
        cls.oldpwcallmethodinst = pwrequester.pwcallmethodinst
        pwrequester.pwcallmethodinst = lambda msg: ""
        config.debug_mode = False
        config.harden_mode = True
        cls.client = start.client(cls.param_client, doreturn=True)
        cls.client_hash = cls.client.links["certtupel"][1]
        cls.client_port = cls.client.links["hserver"].server_port
        cls.client_port2 = cls.client.links["cserver_ip"].server_port
        cls.name = cls.client.links["client_server"].name

        #cls.client2 = simplescn.__main__.client(cls.param_client2, doreturn=True)

        sslcont = tools.default_sslcont()
        _cpath = os.path.join(cls.temptestdir.name, "client")
        sslcont.load_cert_chain( _cpath+"_cert.pub", _cpath+"_cert.priv")
        cls.testserver = SHTTPServer(("::1", 0), sslcont, TestServerHandler)

        #cls.client2 = simplescn.__main__.client(cls.param_client2, doreturn=True)
        #cls.client_hash2 = cls.client2.links["client"].cert_hash
        #cls.client_port2 = cls.client2.links["hserver"].socket.getsockname()[1]
        
        cls.server = start.server(cls.param_server, doreturn=True)
        cls.server_port = cls.server.links["hserver"].server_port
        cls.server_addressscn = "::1-{}".format(cls.server_port)
        cls.test_server_port = cls.testserver.server_port
        cls.testserver.serve_forever_nonblock()
        # grace period before starting speed tests
        time.sleep(1)

    # needed to run ONCE; tearDownModule runs async
    @classmethod
    def tearDownClass(cls):
        # server side needs some time to cleanup, elsewise strange exceptions happen
        time.sleep(5)
        cls.client.quit()
        #cls.client2.quit()
        cls.server.quit()
        cls.testserver.server_close()
        pwrequester.pwcallmethodinst = cls.oldpwcallmethodinst
        print(cls.referencestuff)
        print(cls.referencestuffinvalid)

    def test_regspeed(self):
        fun = lambda :self.client.links["client"].access_dict("register", {"server": self.server_addressscn})
        ret = timeit.timeit(fun, number=avgtestnum)
        if printresults:
            print("test_regspeed", "{:0.10f}".format(ret/avgtestnum))
        self.assertLess(ret/avgtestnum, avg)

    def test_regspeed_parallel(self):
        counter = [0, parallelnum]
        bar = threading.Semaphore(1)
        fun = lambda : threaded_bar(self.client.links["client"].access_dict, bar, counter, args=("register", {"server": self.server_addressscn}))
        ret = timeit.timeit(fun, number=parallelnum)
        if printresults:
            print("test_regspeed_parallel", "{:0.10f}".format(ret))
        self.assertLess(ret, maxtime)
        time.sleep(2)

    def test_show(self):
        fun = lambda: self.client.links["client"].access_dict("show", {})
        ret = timeit.timeit(fun, number=avgtestnum)
        if printresults:
            print("test_show", "{:0.10f}".format(ret/avgtestnum))
        self.assertLess(ret/avgtestnum, avg)

    def test_show_parallel(self):
        counter = [0, parallelnum]
        bar = threading.Semaphore(1)
        fun = lambda: threaded_bar(self.client.links["client"].access_dict, bar, counter, args=("show", {}))
        ret = timeit.timeit(fun, number=avgtestnum)
        if printresults:
            print("test_show_parallel", "{:0.10f}".format(ret))
        self.assertLess(ret, maxtime)

    def test_capspeed(self):
        fun = lambda: self.client.links["client"].access_dict("cap", {"address": self.server_addressscn})
        ret = timeit.timeit(fun, number=avgtestnum)
        if printresults:
            print("test_capspeed", "{:0.10f}".format(ret/avgtestnum))
        self.assertLess(ret/avgtestnum, avg)
    
    def test_capspeed_parallel(self):
        counter = [0, parallelnum]
        bar = threading.Semaphore(1)
        fun = lambda: threaded_bar(self.client.links["client"].access_dict, bar, counter, args=("cap", {"address": self.server_addressscn}))
        ret = timeit.timeit(fun, number=parallelnum)
        if printresults:
            print("test_capspeed_parallel", "{:0.10f}".format(ret))
        self.assertLess(ret, maxtime)

    def test_invalspeedlocal(self):
        fun = lambda: self.client.links["client"].access_dict("ksksks", {"server": self.server_addressscn})
        ret = timeit.timeit(fun, number=avgtestnum)
        if printresults:
            print("test_invalspeedlocal", "{:0.10f}".format(ret/avgtestnum))
        self.assertLess(ret/avgtestnum, avg)

    def test_connectspeedshow(self):
        fun = lambda: scnrequest.do_request("::1-{}".format(self.client_port2), "/client/show", {}, {})
        ret = timeit.timeit(fun, number=avgtestnum)
        if printresults:
            print("test_connectspeedshow", "{:0.10f}".format(ret/avgtestnum))
        self.assertLess(ret/avgtestnum, avg)


    def test_connectspeedinvalid(self):
        fun = lambda : scnrequest.do_request("::1-{}".format(self.client_port2), "/client/teststubnotvalid", {}, {})
        ret = timeit.timeit(fun, number=avgtestnum)
        if printresults:
            print("test_connectspeedinvalid", "{:0.10f}".format(ret/avgtestnum))
        self.assertLess(ret/avgtestnum, avg)

    def test_connectspeedinvalid_parallel(self):
        counter = [0, parallelnum]
        bar = threading.Semaphore(1)
        fun = lambda : threaded_bar(scnrequest.do_request, bar, counter, args=("::1-{}".format(self.client_port2), "/client/teststubnotvalidparallel", {}, {}))
        ret = timeit.timeit(fun, number=parallelnum)
        if printresults:
            print("test_connectspeedinvalid_parallel", "{:0.10f}".format(ret))
        self.assertLess(ret, maxtime)

    def test_connecttestserver(self):
        fun = lambda : scnrequest.do_request("::1-{}".format(self.test_server_port), "/just/an/url/without/meaning", {}, {})
        ret = timeit.timeit(fun, number=avgtestnum)
        if printresults:
            print("test_connecttestserver", "{:0.10f}".format(ret/avgtestnum))
        self.assertLess(ret/avgtestnum, avg)
    
    def test_connecttestserver_parallel(self):
        counter = [0, parallelnum]
        bar = threading.Semaphore(1)
        fun = lambda : threaded_bar(scnrequest.do_request, bar, counter, args=("::1-{}".format(self.test_server_port), "/just/an/url/without/meaning", {}, {}))
        ret = timeit.timeit(fun, number=parallelnum)
        if printresults:
            print("test_connecttestserver_parallel", "{:0.10f}".format(ret))
        self.assertLess(ret, maxtime)

    def test_connecttestserver_withstub(self):
        fun = lambda : stubconnect("::1", self.test_server_port)
        ret = timeit.timeit(fun, number=avgtestnum)
        TestSpeed.referencestuff = "Reference server with stub: {:0.10f}".format(ret/avgtestnum)
        self.assertLess(ret/avgtestnum, avg)

    def test_connecttestserver_withstubinvalid(self):
        fun = lambda : stubconnect_invalid("::1", self.test_server_port)
        ret = timeit.timeit(fun, number=avgtestnum)
        TestSpeed.referencestuffinvalid = "Reference server with invalid stub: {:0.10f}".format(ret/avgtestnum)
        self.assertLess(ret/avgtestnum, avg)

if __name__ == "__main__":
    unittest.main(verbosity=2)
