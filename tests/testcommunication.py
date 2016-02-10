#! /usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "simplescn"))

import unittest
import logging
import shutil
from threading import Thread

import simplescn
import simplescn.__main__

def shimrun(cmd, *args):
    try:
        cmd(args)
    except Exception:
        logging.exception("{} failed".format(type(cmd).__name__))


class TestCommunication(unittest.TestCase):
    temptestdir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_communication")
    simplescn.server_port = 40040
    param_server = ["--config={}".format(temptestdir), "--port={}".format(simplescn.server_port)]
    param_client = ["--config={}".format(temptestdir), "--nocmd"]
    #client = None
    #server = None
    
    # needed to run ONCE; setUpModule runs async
    @classmethod
    def setUpClass(cls):
        if os.path.isdir(cls.temptestdir):
            shutil.rmtree(cls.temptestdir)
        os.mkdir(cls.temptestdir, 0o700)
        simplescn.pwcallmethodinst = lambda msg, requester: ""
        cls.oldpwcallmethodinst = simplescn.pwcallmethodinst
        cls.client = simplescn.__main__.rawclient(cls.param_client, doreturn=True)
        cls.client_hash = cls.client.links["client"].cert_hash
        cls.name = cls.client.links["client"].name
        cls.server = simplescn.__main__.server(cls.param_server, doreturn=True)

    # needed to run ONCE; tearDownModule runs async
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temptestdir)
        simplescn.pwcallmethodinst = cls.oldpwcallmethodinst

    def test_register_get(self):
        reqister1 = self.client.links["client"].access_main("register", server="::1")
        self.assertEqual(reqister1[0], True)
        self.assertDictEqual(reqister1[1], {'traverse': True, 'mode': 'registered_traversal'})
        ret1 = self.client.links["client"].access_main("get", server="::1", name=self.name, hash=self.client_hash)
        self.assertEqual(ret1[0], True)
        
        register2 = self.client.links["client"].access_main("register", server="127.0.0.1")
        self.assertEqual(register2[0], True)
        self.assertDictEqual(register2[1], {'traverse': True, 'mode': 'registered_traversal'})
        ret2 = self.client.links["client"].access_main("get", server="127.0.0.1", name=self.name, hash=self.client_hash)
        self.assertEqual(ret2[0], True)
        
        register3 = self.client.links["client"].access_main("register", server="127.0.0.1-{}".format(simplescn.server_port))
        self.assertEqual(register3[0], True)
        self.assertDictEqual(register3[1], {'traverse': True, 'mode': 'registered_traversal'})
        
        ret3 = self.client.links["client"].access_main("get", server="127.0.0.1-{}".format(simplescn.server_port), name=self.name, hash=self.client_hash)
        self.assertEqual(ret3[0], True)
        
    def test_cap(self):
        cap_ret = self.client.links["client"].access_main("cap")
        self.assertEqual(cap_ret[0], True, cap_ret[1])
    
    
    def test_info(self):
        info_ret = self.client.links["client"].access_main("info")
        self.assertEqual(info_ret[0], True, info_ret[1])
    
    
    #def test_check(self):
    #    pass
    
    #def test_check_direct(self):
    #    pass
    
if __name__ == "main":
    unittest.main(verbosity=2)
