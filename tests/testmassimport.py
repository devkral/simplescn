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

def cparam_client(cdir):
    return ["--config={}".format(cdir), "--nolock", "--nounix", "--noip"]

class TestMassimport(unittest.TestCase):
    temptestdirsource = tempfile.TemporaryDirectory("testmassimportsource")

    # needed to run ONCE; setUpModule runs async
    @classmethod
    def setUpClass(cls):
        #print(cls.temptestdir, cls.temptestdir2)
        cls.oldpwcallmethodinst = simplescn.pwcallmethodinst
        simplescn.pwcallmethodinst = lambda msg: ""
        config.debug_mode = True
        config.harden = False
        cls.client = start.client(["--config={}".format(cls.temptestdirsource.name), "--nolock", "--nounix", "--noip=False"], doreturn=True)
        cls.client_hash = cls.client.links["certtupel"][1]
        cls.client_port = cls.client.show()["cserver_ip"][1]
        cls.name = cls.client.links["client_server"].name
        cls.client.links["client"].access_dict("addentity", {"name": "testmass1"})
        cls.client.links["client"].access_dict("addhash", {"name": "testmass1","hash": tools.dhash("a")})
        cls.client.links["client"].access_dict("addhash", {"name": "testmass1","hash": tools.dhash("b")})
        cls.client.links["client"].access_dict("addreference", {"hash": tools.dhash("b"), "reftype" : "surl", "reference": "www.example.com"})
        cls.client.links["client"].access_dict("addreference", {"hash": tools.dhash("b"), "reftype" : "sname", "reference": "timmy"})
        cls.client.links["client"].access_dict("addreference", {"hash": tools.dhash("b"), "reftype" : "url", "reference": "www.ample.com"})
        cls.client.links["client"].access_dict("addentity", {"name": "testmass2"})
        cls.client.links["client"].access_dict("addhash", {"name": "testmass2","hash": tools.dhash("c")})
        cls.client.links["client"].access_dict("addentity", {"name": "testmass3"})
        #cls.client.links["client"].

    # needed to run ONCE; tearDownModule runs async
    @classmethod
    def tearDownClass(cls):
        # server side needs some time to cleanup, elsewise strange exceptions happen
        time.sleep(2)
        cls.client.quit()
        simplescn.pwcallmethodinst = cls.oldpwcallmethodinst

    def test_importall(self):
        with tempfile.TemporaryDirectory("testmassimportdestall") as path:
            _clientd1 = start.client(cparam_client(path), doreturn=True)
            clientd1 = _clientd1.links["client"]
            ret1 = clientd1.access_dict("massimport", {"sourceaddress": "::1-{}".format(self.client_port), "sourcehash": self.client_hash})
            self.assertTrue(ret1[0], ret1[1])
            ttget1 = clientd1.access_dict("getlocal", {"hash": tools.dhash("b")})
            self.assertTrue(ttget1[0], ttget1[1])
            self.assertEqual(ttget1[1]["name"], "testmass1")
            ttget2 = clientd1.access_dict("getreferences", {"certreferenceid": ttget1[1].get("certreferenceid")})
            self.assertTrue(ttget2[0], ttget2[1])
            self.assertEqual(len(ttget2[1]["items"]), 3, ttget2[1]["items"])
            ttget3 = clientd1.access_dict("getreferences", {"certreferenceid": ttget1[1].get("certreferenceid"), "filter": "surl"})
            self.assertTrue(ttget3[0], ttget3[1])
            self.assertEqual(len(ttget3[1]["items"]), 1)
            ttget4 = clientd1.access_dict("getreferences", {"certreferenceid": ttget1[1].get("certreferenceid"), "filter": "fkssk"})
            self.assertTrue(ttget4[0], ttget4[1])
            self.assertEqual(len(ttget4[1]["items"]), 0, ttget4[1])
            ttget5 = clientd1.access_dict("getreferences", {"hash": tools.dhash("b")})
            self.assertTrue(ttget5[0], ttget5[1])
            self.assertEqual(len(ttget5[1]["items"]), 3, ttget5[1])
            ttget6 = clientd1.access_dict("getlocal", {"hash": tools.dhash("c")})
            self.assertTrue(ttget6[0], ttget6[1])
            self.assertEqual(ttget6[1]["name"], "testmass2", ttget6[1])
            ttgetfalse = clientd1.access_dict("getreferences", {"filter": "surl"})
            self.assertFalse(ttgetfalse[0], ttgetfalse[1])

    def test_importhashes(self):
        with tempfile.TemporaryDirectory("testmasshashes") as path:
            _clientd1 = start.client(cparam_client(path), doreturn=True)
            clientd1 = _clientd1.links["client"]
            ret1 = clientd1.access_dict("massimport", {"sourceaddress": "::1-{}".format(self.client_port), \
            "sourcehash": self.client_hash, "hashes": [tools.dhash("b")]})
            self.assertTrue(ret1[0], ret1[1])
            ttget1 = clientd1.access_dict("getlocal", {"hash": tools.dhash("b")})
            self.assertTrue(ttget1[0], ttget1[1])
            ttget2 = clientd1.access_dict("getlocal", {"hash": tools.dhash("c")})
            self.assertFalse(ttget2[0], ttget2[1])

    def test_importnames(self):
        with tempfile.TemporaryDirectory("testmassnames") as path:
            _clientd1 = start.client(cparam_client(path), doreturn=True)
            clientd1 = _clientd1.links["client"]
            ret1 = clientd1.access_dict("massimport", {"sourceaddress": "::1-{}".format(self.client_port), \
            "sourcehash": self.client_hash, "entities": ["testmass1", "testmass3"]})
            self.assertTrue(ret1[0], ret1[1])
            ttget1 = clientd1.access_dict("getlocal", {"hash": tools.dhash("b")})
            self.assertTrue(ttget1[0], ttget1[1])
            ttget2 = clientd1.access_dict("getlocal", {"hash": tools.dhash("c")})
            self.assertFalse(ttget2[0], ttget2[1])
            ttget3 = clientd1.access_dict("exist", {"name": "testmass3"})
            self.assertTrue(ttget3[0], ttget3[1])

    def test_importhashesnames(self):
        with tempfile.TemporaryDirectory("testmasshn") as path:
            _clientd1 = start.client(cparam_client(path), doreturn=True)
            clientd1 = _clientd1.links["client"]
            ret1 = clientd1.access_dict("massimport", {"sourceaddress": "::1-{}".format(self.client_port), \
            "sourcehash": self.client_hash, "hashes": [tools.dhash("b")], "entities": ["testmass2"]})
            self.assertTrue(ret1[0], ret1[1])
            ttget1 = clientd1.access_dict("getlocal", {"hash": tools.dhash("b")})
            self.assertTrue(ttget1[0], ttget1[1])
            ttget2 = clientd1.access_dict("getlocal", {"hash": tools.dhash("c")})
            self.assertTrue(ttget2[0], ttget2[1])
            ttget3 = clientd1.access_dict("exist", {"name": "massimport3"})
            self.assertFalse(ttget3[0], ttget3[1])

if __name__ == "__main__":
    unittest.main(verbosity=2)
