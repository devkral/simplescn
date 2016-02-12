#! /usr/bin/env python3
import sys, os
# fix import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

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
        cls.client_port = cls.client.links["hserver"].socket.getsockname()[1]
        cls.server = simplescn.__main__.server(cls.param_server, doreturn=True)
        cls.server_port = cls.server.links["hserver"].socket.getsockname()[1]

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
        #print(cap_ret)
    
    def test_info(self):
        info_ret = self.client.links["client"].access_main("info", address="127.0.0.1-{}".format(simplescn.server_port))
        self.assertEqual(info_ret[0], True, info_ret[1])
        self.assertEqual(info_ret[1]["type"], "server")
        
        info_ret = self.client.links["client"].access_main("info")
        self.assertEqual(info_ret[0], True, info_ret[1])
        self.assertEqual(info_ret[1]["type"], "client")
        info_ret = self.client.links["client"].access_main("info", address="localhost-{}".format(self.client_port))
        self.assertEqual(info_ret[0], True, info_ret[1])
        self.assertEqual(info_ret[1]["type"], "client")
    
    def test_services(self):
        services_reg = self.client.links["client"].access_main("registerservice", name="test", port="666")
        self.assertEqual(services_reg[0], True, services_reg[1])
        #print(services_reg)
        services_ret = self.client.links["client"].access_main("getservice", name="test")
        #print(services_ret)
        #self.assertEqual(services_ret[0], True, services_ret[1])
        services_del = self.client.links["client"].access_main("delservice", name="test")
        self.assertEqual(services_del[0], True, services_del[1])
        services_ret = self.client.links["client"].access_main("getservice", name="test")
        self.assertEqual(services_ret[0], False)
        
    
    def test_rename(self):
        change = self.client.links["client"].access_main("changemsg", message="newtestmessage")
        self.assertEqual(change[0], True, change[1])
        change = self.client.links["client"].access_main("changename", name="willi")
        self.assertEqual(change[0], True, change[1])
        ret = self.client.links["client"].access_main("info")
        self.assertEqual(ret[0], True, ret[1])
        self.assertEqual(ret[1].get("message"),"newtestmessage")
        self.assertEqual(ret[1].get("name"),"willi")
        nochange = self.client.links["client"].access_main("changename", name="  willi")
        self.assertEqual(nochange[0], False)

    
    def test_check(self):
        pass
    
    def test_check_direct(self):
        pass
    
if __name__ == "__main__":
    unittest.main(verbosity=2)
