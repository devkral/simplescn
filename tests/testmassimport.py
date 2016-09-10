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
from simplescn import tools
from simplescn.tools import start

def cparam_client(cdir):
    return ["--config={}".format(cdir), "--nolock", "--nounix", "--noip"]

class TestMassimport(unittest.TestCase):
    temptestdirsource = tempfile.TemporaryDirectory("testmassimportsource")
    temptestdirdest1 = tempfile.TemporaryDirectory("testmassimportdest1")
    temptestdirdest1 = tempfile.TemporaryDirectory("testmassimportdest2")
    temptestdirdest1 = tempfile.TemporaryDirectory("testmassimportdest3")

    #client = None
    #server = None

    # needed to run ONCE; setUpModule runs async
    @classmethod
    def setUpClass(cls):
        #print(cls.temptestdir, cls.temptestdir2)
        cls.oldpwcallmethodinst = simplescn.pwcallmethodinst
        simplescn.pwcallmethodinst = lambda msg: ""
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
        _clientd1 = start.client(cparam_client(self.temptestdirdest1.name), doreturn=True)
        clientd1 = _clientd1.links["client"]
        ret1 = clientd1.access_dict("massimport", {"sourceaddress": "::1-{}".format(self.client_port), "sourcehash": self.client_hash})
        self.assertTrue(ret1[0], ret1[1])
        ttget1 = clientd1.access_dict("getlocal", {"hash": tools.dhash("b")})
        self.assertTrue(ttget1[0], ttget1[1])

if __name__ == "__main__":
    unittest.main(verbosity=2)
