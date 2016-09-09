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
#from simplescn import tools
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
        cls.client = start.client(cparam_client(cls.temptestdirsource.name), doreturn=True)
        cls.client_hash = cls.client.links["certtupel"][1]
        cls.client_port = cls.client.links["hserver"].server_port
        cls.name = cls.client.links["client_server"].name
        cls.client.links["client"].access_dict("addentity", {"server": "127.0.0.1-{}".format(cls.server_port)})
        #cls.client.links["client"].

    # needed to run ONCE; tearDownModule runs async
    @classmethod
    def tearDownClass(cls):
        # server side needs some time to cleanup, elsewise strange exceptions happen
        time.sleep(4)
        cls.client.quit()
        simplescn.pwcallmethodinst = cls.oldpwcallmethodinst

if __name__ == "__main__":
    unittest.main(verbosity=2)
