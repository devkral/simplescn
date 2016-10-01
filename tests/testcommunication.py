#! /usr/bin/env python3

import unittest
import tempfile
import time

import sys
import os
# fix import
if os.path.dirname(os.path.dirname(os.path.realpath(__file__))) not in sys.path:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import simplescn
from simplescn import tools, config
from simplescn.tools import start


#def shimrun(cmd, *args):
#    try:
#        cmd(args)
#    except Exception:
#        logging.exception("{} failed".format(type(cmd).__name__))


class TestCommunication(unittest.TestCase):
    temptestdir = tempfile.TemporaryDirectory("testcommunication")
    temptestdir2 = tempfile.TemporaryDirectory("testcommunication2")
    param_server = ["--config={}".format(temptestdir.name), "--nolock", "--port=0"]
    param_client = ["--config={}".format(temptestdir.name), "--nolock", "--nounix", "--noip", "port=0"]
    param_client2 = ["--config={}".format(temptestdir2.name), "--nolock", "--nounix", "--noip", "port=0"]

    #client = None
    #server = None

    # needed to run ONCE; setUpModule runs async
    @classmethod
    def setUpClass(cls):
        cls.oldpwcallmethodinst = simplescn.pwcallmethodinst
        simplescn.pwcallmethodinst = lambda msg: ""
        config.debug_mode = True
        config.harden = False
        cls.client = start.client(cls.param_client, doreturn=True)
        cls.client_hash = cls.client.links["certtupel"][1]
        cls.client_port = cls.client.links["hserver"].server_port
        cls.name = cls.client.links["client_server"].name

        cls.client2 = start.client(cls.param_client2, doreturn=True)
        cls.client_hash2 = cls.client2.links["certtupel"][1]
        cls.client_port2 = cls.client2.links["hserver"].server_port

        cls.server = start.server(cls.param_server, doreturn=True)
        cls.server_port = cls.server.links["hserver"].server_port
        cls.client_hash3 = tools.dhash("m")

    # needed to run ONCE; tearDownModule runs async
    @classmethod
    def tearDownClass(cls):
        # server side needs some time to cleanup, elsewise strange exceptions happen
        time.sleep(4)
        cls.client.quit()
        cls.client2.quit()
        cls.server.quit()
        simplescn.pwcallmethodinst = cls.oldpwcallmethodinst

    def test_register_get(self):
        reqister1 = self.client.links["client"].access_dict("register", {"server": "::1-{}".format(self.server_port)})
        self.assertTrue(reqister1[0], reqister1[1])
        self.assertDictEqual(reqister1[1], {'traverse_needed': True})
        ret1 = self.client.links["client"].access_dict("get", {"server": "::1-{}".format(self.server_port), "name": self.name, "hash": self.client_hash})
        self.assertTrue(ret1[0], ret1[1])
        self.assertTrue(ret1[1]["address"].rfind("-") != -1, ret1[1]["address"])
        self.assertIn("pureaddress", ret1[1], ret1[1])
        self.assertIn("port", ret1[1], ret1[1])

        register2 = self.client.links["client"].access_dict("register", {"server": "127.0.0.1-{}".format(self.server_port)})
        self.assertEqual(register2[0], True, register2[1])
        self.assertDictEqual(register2[1], {'traverse_needed': True}, register2[1])
        ret2 = self.client.links["client"].access_dict("get", {"server": "127.0.0.1-{}".format(self.server_port), "name": self.name, "hash": self.client_hash})
        self.assertEqual(ret2[0], True, ret2[1])
        
        register3 = self.client.links["client"].access_dict("register", {"server": "::1-{}".format(self.server_port+1)})
        self.assertEqual(register3[0], False, register3[1])
        
        ret3 = self.client.links["client"].access_dict("get", {"server": "127.0.0.1-{}".format(self.server_port), "name": self.name, "hash": self.client_hash})
        self.assertEqual(ret3[0], True, ret3[1])
        
        #with self.subTest("test check"):
        #    ret_local1 = self.client.links["client"].access_dict("check", {"server": "::1-{}".format(self.server_port), "name": self.name, "hash": self.client_hash})
        #    self.assertEqual(ret_local1[0], True, ret_local1[1])
        #    ret_remote1 = self.client2.links["client"].access_dict("check", {"server": "::1-{}".format(self.server_port), "name": self.name, "hash": self.client_hash})
        #    self.assertEqual(ret_remote1[0], True, ret_remote1[1])
        
    def test_cap(self):
        cap_ret = self.client.links["client"].access_dict("cap", {})
        self.assertEqual(cap_ret[0], True, cap_ret[1])
        cap_ret = self.client.links["client"].access_dict("cap", {"address": "::1-{}".format(self.server_port)})
        self.assertEqual(cap_ret[0], True, cap_ret[1])
    
    def test_info(self):
        info_ret = self.client.links["client"].access_dict("info", {"address": "::1-{}".format(self.server_port)})
        self.assertEqual(info_ret[0], True, info_ret[1])
        self.assertEqual(info_ret[1]["type"], "server")
        info_ret = self.client.links["client"].access_dict("info", {})
        self.assertEqual(info_ret[0], True, info_ret[1])
        self.assertEqual(info_ret[1]["type"], "client")
        info_ret = self.client.links["client"].access_dict("info", {"address": "localhost-{}".format(self.client_port)})
        self.assertEqual(info_ret[0], True, info_ret[1])
        self.assertEqual(info_ret[1]["type"], "client")
    
    def test_services(self):
        services_reg = self.client.links["client"].access_dict("registerservice", {"name": "test", "port": 666})
        self.assertEqual(services_reg[0], True, services_reg[1])
        services_ret = self.client.links["client"].access_dict("getservice", {"name": "test"})
        self.assertEqual(services_ret[0], True, services_ret[1])
        services_del = self.client.links["client"].access_dict("delservice", {"name": "test"})
        self.assertEqual(services_del[0], True, services_del[1])
        services_ret = self.client.links["client"].access_dict("getservice", {"name": "test"})
        self.assertEqual(services_ret[0], False)

    def test_services_remote(self):
        # unprefixed
        services_reg = self.client2.links["client"].access_dict("registerservice", {"client": "::1-{}".format(self.client_port), "name": "test", "port": 666})
        self.assertEqual(services_reg[0], False, services_reg[1])
        # prefixed
        services_reg = self.client2.links["client"].access_dict("registerservice", {"client": "::1-{}".format(self.client_port), "name": "#test", "port": 666})
        self.assertEqual(services_reg[0], True, services_reg[1])
        services_ret = self.client.links["client"].access_dict("getservice", {"client": "::1-{}".format(self.client_port), "name": "#test"})
        self.assertEqual(services_ret[0], True, services_ret[1])
        services_del = self.client.links["client"].access_dict("delservice", {"client": "::1-{}".format(self.client_port), "name": "#test"})
        self.assertEqual(services_del[0], True, services_del[1])
        services_ret = self.client.links["client"].access_dict("getservice", {"client": "::1-{}".format(self.client_port), "name": "#test"})
        self.assertEqual(services_ret[0], False)

    def test_rename(self):
        change = self.client.links["client"].access_dict("changemsg", {"message": "newtestmessage"})
        self.assertEqual(change[0], True, change[1])
        change = self.client.links["client"].access_dict("changename", {"name": "willi"})
        self.assertEqual(change[0], True, change[1])
        ret = self.client.links["client"].access_dict("info", {})
        self.assertEqual(ret[0], True, ret[1])
        self.assertEqual(ret[1].get("message"), "newtestmessage")
        self.assertEqual(ret[1].get("name"), "willi")
        nochange = self.client.links["client"].access_dict("changename", {"name": "  willi"})
        self.assertEqual(nochange[0], False)
        ret = self.client.links["client"].access_dict("info", {})
        self.assertEqual(ret[0], True, ret[1])
        self.assertEqual(ret[1].get("name"), "willi")

    def test_authviolation(self):
        obdict1 = {"message": "newtestmessage"}
        unchanged1 = self.client.links["client"].do_request("::1-{}".format(self.client_port2), "/client/da", body=obdict1, headers={}, sendclientcert=True, forceport=True)
        self.assertEqual(unchanged1[0], False)
    
    def test_check_direct(self):
        # test self
        ret_local1 = self.client.links["client"].access_dict("check_direct", {"address": "::1-{}".format(self.client_port), "security": "valid", "hash": self.client_hash})
        self.assertEqual(ret_local1[0], True, ret_local1[1])
        
        # test self fail
        ret_local2 = self.client.links["client"].access_dict("check_direct", {"address": "::1-{}".format(self.client_port), "security": "insecure", "hash": self.client_hash})
        self.assertEqual(ret_local2[0], False)
        
        # test remote
        ret_remote1 = self.client.links["client"].access_dict("check_direct", {"address": "::1-{}".format(self.client_port2), "security": "valid", "hash": self.client_hash2})
        self.assertEqual(ret_remote1[0], True, ret_remote1[1])
        
        # test remote fail1
        ret_remote2 = self.client.links["client"].access_dict("check_direct", {"address": "::1-{}".format(self.client_port2), "security": "insecure", "hash": self.client_hash2})
        self.assertEqual(ret_remote2[0], False)
        
        # test remote fail2
        ret_remote3 = self.client.links["client"].access_dict("check_direct", {"address": "::1-{}".format(self.client_port2), "security": "valid", "hash": self.client_hash})
        self.assertEqual(ret_remote3[0], False)
        
        # test remote fail (no certinformation)
        ret_remote3 = self.client.links["client"].access_dict("check_direct", {"address": "::1-{}".format(self.client_port2), "security": "insecure", "hash": self.client_hash3})
        self.assertEqual(ret_remote3[0], False)

if __name__ == "__main__":
    unittest.main(verbosity=2)
