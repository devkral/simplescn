#! /usr/bin/env python3
import sys, os
# fix import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import unittest
import shutil
import timeit
import time
import threading
#import logging
from http.server import BaseHTTPRequestHandler
from http.client import HTTPSConnection

import simplescn
from simplescn._common import http_server
from simplescn import scnrequest, tools
import simplescn.__main__

avgtestnum = 20
avg = 0.3

parallelnum = 20
maxtime = 1.2

printresults = False

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
    server_timeout = 5
    def do_POST(self):
        self.send_response(200, "ok")
        self.send_header("Content-Length", str(2))
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"ok")

class TestSpeed(unittest.TestCase):
    temptestdir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_communication")
    #temptestdir2 = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_communication2")
    param_server = ["--config={}".format(temptestdir), "--port=0", "--nolock", "--loglevel=7", "--nounix", "--noip"]
    param_client = ["--config={}".format(temptestdir), "--port=0", "--nolock", "--loglevel=7", "--nounix", "--port=0"]
    #param_client2 = ["--config={}".format(temptestdir2), "--port=0", "--nolock", "--loglevel=7", "--nounix", "--noip"]
    referencestuff = None
    referencestuffinvalid = None
    
    # needed to run ONCE; setUpModule runs async
    @classmethod
    def setUpClass(cls):
        if os.path.isdir(cls.temptestdir):
            shutil.rmtree(cls.temptestdir)
        #if os.path.isdir(cls.temptestdir2):
        #    shutil.rmtree(cls.temptestdir2)
        os.mkdir(cls.temptestdir, 0o700)
        #os.mkdir(cls.temptestdir2, 0o700)
        simplescn.pwcallmethodinst = lambda msg: ""
        cls.oldpwcallmethodinst = simplescn.pwcallmethodinst
        cls.client = simplescn.__main__.client(cls.param_client, doreturn=True)
        cls.client_hash = cls.client.links["client"].certtupel[1]
        cls.client_port = cls.client.links["hserver"].server_port
        cls.client_port2 = cls.client.links["cserver_ip"].server_port
        cls.name = cls.client.links["client"].name
        
        sslcont = tools.default_sslcont()
        _cpath = os.path.join(cls.temptestdir, "client")
        sslcont.load_cert_chain( _cpath+"_cert.pub", _cpath+"_cert.priv")
        cls.testserver = http_server(("::1", 0), sslcont, TestServerHandler)

        #cls.client2 = simplescn.__main__.client(cls.param_client2, doreturn=True)
        #cls.client_hash2 = cls.client2.links["client"].cert_hash
        #cls.client_port2 = cls.client2.links["hserver"].socket.getsockname()[1]
        
        cls.server = simplescn.__main__.server(cls.param_server, doreturn=True)
        cls.server_port = cls.server.links["hserver"].server_port
        cls.server_addressscn = "::1-{}".format(cls.server_port)
        cls.test_server_port = cls.testserver.server_port
        cls.testserver.serve_forever_nonblock()

    # needed to run ONCE; tearDownModule runs async
    @classmethod
    def tearDownClass(cls):
        # server side needs some time to cleanup, elswise strange exceptions happen
        time.sleep(4)
        cls.client.quit()
        cls.server.quit()
        cls.testserver.server_close()
        shutil.rmtree(cls.temptestdir)
        #shutil.rmtree(cls.temptestdir2)
        simplescn.pwcallmethodinst = cls.oldpwcallmethodinst
        print(cls.referencestuff)
        print(cls.referencestuffinvalid)

    def test_regspeed(self):
        fun = lambda :self.client.links["client"].access_dict("register", {"server": self.server_addressscn})
        ret = timeit.timeit(fun, number=avgtestnum)
        if printresults:
            print("test_regspeed", ret/avgtestnum)
        self.assertLess(ret/avgtestnum, avg)

    def test_regspeed_parallel(self):
        counter = [0, parallelnum]
        bar = threading.Semaphore(1)
        fun = lambda : threaded_bar(self.client.links["client"].access_dict, bar, counter, args=("register", {"server": self.server_addressscn}))
        ret = timeit.timeit(fun, number=parallelnum)
        if printresults:
            print("test_regspeed_parallel", ret)
        self.assertLess(ret, maxtime)

    def test_show(self):
        fun = lambda :self.client.links["client"].access_dict("show", {})
        ret = timeit.timeit(fun, number=avgtestnum)
        if printresults:
            print("test_show", ret/avgtestnum)
        self.assertLess(ret/avgtestnum, avg)

    def test_show_parallel(self):
        counter = [0, parallelnum]
        bar = threading.Semaphore(1)
        fun = lambda : threaded_bar(self.client.links["client"].access_dict, bar, counter, args=("show", {}))
        ret = timeit.timeit(fun, number=avgtestnum)
        if printresults:
            print("test_show_parallel", ret)
        self.assertLess(ret, maxtime)

    def test_capspeed(self):
        fun = lambda :self.client.links["client"].access_dict("cap", {"server": self.server_addressscn})
        ret = timeit.timeit(fun, number=avgtestnum)
        if printresults:
            print("test_capspeed", ret/avgtestnum)
        self.assertLess(ret/avgtestnum, avg)
    
    def test_capspeed_parallel(self):
        counter = [0, parallelnum]
        bar = threading.Semaphore(1)
        fun = lambda : threaded_bar(self.client.links["client"].access_dict, bar, counter, args=("cap", {}))
        ret = timeit.timeit(fun, number=parallelnum)
        if printresults:
            print("test_capspeed_parallel", ret)
        self.assertLess(ret, maxtime)

    def test_invalspeed(self):
        fun = lambda :self.client.links["client"].access_dict("ksksks", {"server": self.server_addressscn})
        ret = timeit.timeit(fun, number=avgtestnum)
        if printresults:
            print("test_invalspeed", ret/avgtestnum)
        self.assertLess(ret/avgtestnum, avg)

    def test_connectspeedshow(self):
        fun = lambda : scnrequest.do_request_simple("::1-{}".format(self.client_port2), "/client/show", {}, {})
        ret = timeit.timeit(fun, number=avgtestnum)
        if printresults:
            print("test_connectspeedshow", ret/avgtestnum)
        self.assertLess(ret/avgtestnum, avg)


    def test_connectspeedinvalid(self):
        fun = lambda : scnrequest.do_request_simple("::1-{}".format(self.client_port2), "/client/teststubnotvalid", {}, {})
        ret = timeit.timeit(fun, number=avgtestnum)
        if printresults:
            print("test_connectspeedinvalid", ret/avgtestnum)
        self.assertLess(ret/avgtestnum, avg)

    def test_connectspeedinvalid_parallel(self):
        counter = [0, parallelnum]
        bar = threading.Semaphore(1)
        fun = lambda : threaded_bar(scnrequest.do_request_simple, bar, counter, args=("::1-{}".format(self.client_port2), "/client/teststubnotvalidparallel", {}, {}))
        ret = timeit.timeit(fun, number=parallelnum)
        if printresults:
            print("test_connectspeedivalid_parallel", ret)
        self.assertLess(ret, maxtime)

    def test_connecttestserver(self):
        fun = lambda : scnrequest.do_request_simple("::1-{}".format(self.test_server_port), "/just/an/url/without/meaning", {}, {})
        ret = timeit.timeit(fun, number=avgtestnum)
        if printresults:
            print("test_connecttestserver", ret/avgtestnum)
        self.assertLess(ret/avgtestnum, avg)
    
    def test_connecttestserver_parallel(self):
        counter = [0, parallelnum]
        bar = threading.Semaphore(1)
        fun = lambda : threaded_bar(scnrequest.do_request_simple, bar, counter, args=("::1-{}".format(self.test_server_port), "/just/an/url/without/meaning", {}, {}))
        ret = timeit.timeit(fun, number=parallelnum)
        if printresults:
            print("test_connecttestserver_parallel", ret)
        self.assertLess(ret, maxtime)

    def test_connecttestserver_withstub(self):
        fun = lambda : stubconnect("::1", self.test_server_port)
        ret = timeit.timeit(fun, number=avgtestnum)
        TestSpeed.referencestuff = "Reference server with stub: {}".format(ret/avgtestnum)
        self.assertLess(ret/avgtestnum, avg)

    def test_connecttestserver_withstubinvalid(self):
        fun = lambda : stubconnect_invalid("::1", self.test_server_port)
        ret = timeit.timeit(fun, number=avgtestnum)
        TestSpeed.referencestuffinvalid = "Reference server with invalid stub: {}".format(ret/avgtestnum)
        self.assertLess(ret/avgtestnum, avg)

if __name__ == "__main__":
    unittest.main(verbosity=0)
