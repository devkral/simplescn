#! /usr/bin/env python3
import sys, os
# fix import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import unittest
import logging
import shutil
import timeit
from threading import Thread

import simplescn
from simplescn import config
from simplescn import tools
import simplescn.__main__

def shimrun(cmd, *args):
    try:
        cmd(args)
    except Exception:
        logging.exception("{} failed".format(type(cmd).__name__))


class TestCommunication(unittest.TestCase):
    temptestdir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_communication")
    temptestdir2 = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_communication2")
    param_server = ["--config={}".format(temptestdir), "--port={}".format(0)]
    param_client = ["--config={}".format(temptestdir), "--nocmd"]
    param_client2 = ["--config={}".format(temptestdir2), "--nocmd"]
    
    #client = None
    #server = None
    
    # needed to run ONCE; setUpModule runs async
    @classmethod
    def setUpClass(cls):
        if os.path.isdir(cls.temptestdir):
            shutil.rmtree(cls.temptestdir)
        if os.path.isdir(cls.temptestdir2):
            shutil.rmtree(cls.temptestdir2)
        os.mkdir(cls.temptestdir, 0o700)
        os.mkdir(cls.temptestdir2, 0o700)
        simplescn.pwcallmethodinst = lambda msg: ""
        cls.oldpwcallmethodinst = simplescn.pwcallmethodinst
        cls.client = simplescn.__main__.client(cls.param_client, doreturn=True)
        cls.client_hash = cls.client.links["client"].cert_hash
        cls.client_port = cls.client.links["hserver"].socket.getsockname()[1]
        cls.name = cls.client.links["client"].name
        
        #cls.client2 = simplescn.__main__.client(cls.param_client2, doreturn=True)
        #cls.client_hash2 = cls.client2.links["client"].cert_hash
        #cls.client_port2 = cls.client2.links["hserver"].socket.getsockname()[1]
        
        cls.server = simplescn.__main__.server(cls.param_server, doreturn=True)
        cls.server_port = cls.server.links["hserver"].socket.getsockname()[1]
        
        cls.client_hash3 = tools.dhash("m")
    # needed to run ONCE; tearDownModule runs async
    @classmethod
    def tearDownClass(cls):
        cls.client.quit()
        cls.server.quit()
        shutil.rmtree(cls.temptestdir)
        shutil.rmtree(cls.temptestdir2)
        simplescn.pwcallmethodinst = cls.oldpwcallmethodinst
    
    
    def test_speed(self):
        fun = lambda :self.client.links["client"].access_main("register", server="::1")
        ret = timeit.timeit(fun, number=30)
        self.assertLess(ret, 2)
    
        fun2 = lambda :self.client.links["client"].access_main("cap", server="::1")
        ret2 = timeit.timeit(fun, number=30)
        self.assertLess(ret2, 2)

if __name__ == "__main__":
    unittest.main(verbosity=0)
