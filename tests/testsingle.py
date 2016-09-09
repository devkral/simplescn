#! /usr/bin/env python3

import tempfile
import unittest
import logging

import os, sys
# fix import
if os.path.dirname(os.path.dirname(os.path.realpath(__file__))) not in sys.path:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import simplescn
from simplescn import tools
from simplescn.tools import start

class Test_getlocalclient(unittest.TestCase):
    temptestdirconf = tempfile.TemporaryDirectory("testsingleconf")
    temptestdirconf2 = tempfile.TemporaryDirectory("testsingleconf2")
    temptestdir2 = tempfile.TemporaryDirectory("testsingle2")
    temptestdir3 = tempfile.TemporaryDirectory("testsingle3")
    temptestdirempty = tempfile.TemporaryDirectory("testsingleempty")
    temptestdirserver = tempfile.TemporaryDirectory("testsingleserver")
    param_client = ["--config={}".format(temptestdirconf.name), "--run={}".format(temptestdir2.name), "--noip", "--nounix", "port=0"]
    param_client2 = ["--config={}".format(temptestdirconf2.name), "--run={}".format(temptestdir3.name), "--nounix", "--noip=False", "port=0"]
    param_server = ["--run={}".format(temptestdirserver.name), "port=0"]
    # needed to run ONCE; setUpModule runs async
    @classmethod
    def setUpClass(cls):
        cls.oldpwcallmethodinst = simplescn.pwcallmethodinst
        simplescn.pwcallmethodinst = lambda msg: ""
        cls.client = start.client(cls.param_client, doreturn=True)
        cls.client2 = start.client(cls.param_client2, doreturn=True)

    @classmethod
    def tearDownClass(cls):
        cls.client.quit()
        #cls.client2.quit()
        simplescn.pwcallmethodinst = cls.oldpwcallmethodinst

    def test_blockclient(self):
        with self.assertLogs(level=logging.INFO):
            client2 = start.client(self.param_client, doreturn=True)
            self.assertIsNone(client2)

    def test_blockserver(self):
        server1 = start.server(self.param_server, doreturn=True)
        self.assertIsNotNone(server1)
        with self.assertLogs(level=logging.INFO):
            server2 = start.server(self.param_server, doreturn=True)
            self.assertIsNone(server2)


    def test_retrieve(self):
        ret = tools.getlocalclient(rundir=self.temptestdirempty.name)
        self.assertIsNone(ret)
        # no connection possible
        with self.assertLogs(level=logging.INFO):
            ret2 = tools.getlocalclient(rundir=self.temptestdir2.name)
            self.assertIsNone(ret2)
        ret3 = tools.getlocalclient(rundir=self.temptestdir3.name)
        self.assertIsNotNone(ret3)
        self.assertTrue(os.path.exists(self.temptestdir3.name))

if __name__ == '__main__':
    unittest.main(verbosity=2)
