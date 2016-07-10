#! /usr/bin/env python3
import sys
import os
# fix import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import unittest
import shutil
import time

import simplescn
from simplescn import tools
import simplescn.__main__


#def shimrun(cmd, *args):
#    try:
#        cmd(args)
#    except Exception:
#        logging.exception("{} failed".format(type(cmd).__name__))


class TestCommunication(unittest.TestCase):
    temptestdir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_communication")
    temptestdir2 = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_communication2")
    param_server = ["--config={}".format(temptestdir), "--nolock", "--port=0"]
    param_client = ["--config={}".format(temptestdir), "--nolock", "--nounix", "--noip"]
    param_client2 = ["--config={}".format(temptestdir2), "--nolock", "--nounix", "--noip"]
    
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
        #print(cls.temptestdir, cls.temptestdir2)
        simplescn.pwcallmethodinst = lambda msg: ""
        cls.oldpwcallmethodinst = simplescn.pwcallmethodinst
        cls.client = simplescn.__main__.client(cls.param_client, doreturn=True)
        cls.client_hash = cls.client.links["client"].cert_hash
        cls.client_port = cls.client.links["hserver"].socket.getsockname()[1]
        cls.name = cls.client.links["client"].name
        
        cls.client2 = simplescn.__main__.client(cls.param_client2, doreturn=True)
        cls.client_hash2 = cls.client2.links["client"].cert_hash
        cls.client_port2 = cls.client2.links["hserver"].socket.getsockname()[1]
        
        cls.server = simplescn.__main__.server(cls.param_server, doreturn=True)
        cls.server_port = cls.server.links["hserver"].socket.getsockname()[1]
        
        cls.client_hash3 = tools.dhash("m")
    # needed to run ONCE; tearDownModule runs async
    @classmethod
    def tearDownClass(cls):
        # server side needs some time to cleanup, elswise strange exceptions happen
        time.sleep(3)
        cls.client.quit()
        cls.client2.quit()
        cls.server.quit()
        shutil.rmtree(cls.temptestdir)
        shutil.rmtree(cls.temptestdir2)
        simplescn.pwcallmethodinst = cls.oldpwcallmethodinst

    def test_register_get(self):
        reqister1 = self.client.links["client"].access_main("register", server="::1-{}".format(self.server_port))
        self.assertEqual(reqister1[0], True)
        self.assertDictEqual(reqister1[1], {'traverse': True, 'mode': 'registered_traversal'})
        ret1 = self.client.links["client"].access_main("get", server="::1-{}".format(self.server_port), name=self.name, hash=self.client_hash)
        self.assertEqual(ret1[0], True)
        
        register2 = self.client.links["client"].access_main("register", server="127.0.0.1-{}".format(self.server_port))
        self.assertEqual(register2[0], True)
        self.assertDictEqual(register2[1], {'traverse': True, 'mode': 'registered_traversal'})
        ret2 = self.client.links["client"].access_main("get", server="127.0.0.1-{}".format(self.server_port), name=self.name, hash=self.client_hash)
        self.assertEqual(ret2[0], True)
        
        register3 = self.client.links["client"].access_main("register", server="::1-{}".format(self.server_port+1))
        self.assertEqual(register3[0], False)
        
        ret3 = self.client.links["client"].access_main("get", server="127.0.0.1-{}".format(self.server_port), name=self.name, hash=self.client_hash)
        self.assertEqual(ret3[0], True)
        
        with self.subTest("test check"):
            ret_local1 = self.client.links["client"].access_main("check", server="::1-{}".format(self.server_port), name=self.name, hash=self.client_hash)
            self.assertEqual(ret_local1[0], True, ret_local1[1])
            ret_remote1 = self.client2.links["client"].access_main("check", server="::1-{}".format(self.server_port), name=self.name, hash=self.client_hash)
            self.assertEqual(ret_remote1[0], True, ret_remote1[1])
        
    def test_cap(self):
        cap_ret = self.client.links["client"].access_main("cap")
        self.assertEqual(cap_ret[0], True, cap_ret[1])
        cap_ret = self.client.links["client"].access_main("cap", address="::1-{}".format(self.server_port))
        self.assertEqual(cap_ret[0], True, cap_ret[1])
    
    def test_info(self):
        info_ret = self.client.links["client"].access_main("info", address="::1-{}".format(self.server_port))
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
        services_ret = self.client.links["client"].access_main("getservice", name="test")
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
        self.assertEqual(ret[1].get("message"), "newtestmessage")
        self.assertEqual(ret[1].get("name"), "willi")
        nochange = self.client.links["client"].access_main("changename", name="  willi")
        self.assertEqual(nochange[0], False)
        ret = self.client.links["client"].access_main("info")
        self.assertEqual(ret[0], True, ret[1])
        self.assertEqual(ret[1].get("name"), "willi")

    def test_authviolation(self):
        obdict1 = {"message": "newtestmessage"}
        unchanged1 = self.client.links["client"].do_request("::1-{}".format(self.client_port2), "/client/", body=obdict1, sendclientcert=True, forceport=True)
        self.assertEqual(unchanged1[0], False)
    
    def test_check_direct(self):
        # test self
        ret_local1 = self.client.links["client"].access_main("check_direct", address="::1-{}".format(self.client_port), security="valid", hash=self.client_hash)
        self.assertEqual(ret_local1[0], True, ret_local1[1])
        
        # test self fail
        ret_local2 = self.client.links["client"].access_main("check_direct", address="::1-{}".format(self.client_port), security="insecure", hash=self.client_hash)
        self.assertEqual(ret_local2[0], False)
        
        # test remote
        ret_remote1 = self.client.links["client"].access_main("check_direct", address="::1-{}".format(self.client_port2), security="valid", hash=self.client_hash2)
        self.assertEqual(ret_remote1[0], True, ret_remote1[1])
        
        # test remote fail1
        ret_remote2 = self.client.links["client"].access_main("check_direct", address="::1-{}".format(self.client_port2), security="insecure", hash=self.client_hash2)
        self.assertEqual(ret_remote2[0], False)
        
        # test remote fail2
        ret_remote2 = self.client.links["client"].access_main("check_direct", address="::1-{}".format(self.client_port2), security="valid", hash=self.client_hash)
        self.assertEqual(ret_remote2[0], False)
        
        # test remote fail (no certinformation)
        ret_remote3 = self.client.links["client"].access_main("check_direct", address="::1-{}".format(self.client_port2), security="insecure", hash=self.client_hash3)
        self.assertEqual(ret_remote3[0], False)

if __name__ == "__main__":
    unittest.main(verbosity=2)
