#! /usr/bin/env python3

import tempfile
import unittest
import logging

import os, sys
# fix import
if os.path.dirname(os.path.dirname(os.path.realpath(__file__))) not in sys.path:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from simplescn import tools, config, pwrequester
from simplescn.tools import start

class Test_single(unittest.TestCase):
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
        cls.oldpwcallmethodinst = pwrequester.pwcallmethodinst
        pwrequester.pwcallmethodinst = lambda msg: ""
        config.debug_mode = True
        config.harden_mode = False
        cls.client = start.client(cls.param_client, doreturn=True)
        cls.client2 = start.client(cls.param_client2, doreturn=True)

    @classmethod
    def tearDownClass(cls):
        cls.client.quit()
        cls.client2.quit()
        pwrequester.pwcallmethodinst = cls.oldpwcallmethodinst

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

    def test_entityhashreference(self):
        add1 = self.client.links["client"].access_dict("addentity", {"name": "test1"})
        self.assertEqual(add1[0], True, add1)
        with self.assertLogs(level=logging.INFO):
            add2 = self.client.links["client"].access_dict("addentity", {"name": "test1"})
            self.assertEqual(add2[0], False, add2)
        addhash1 = self.client.links["client"].access_dict("addhash", {"name": "test1", "hash": tools.dhash("a"), "type": "client"})
        self.assertEqual(addhash1[0], True, addhash1)
        addhash2 = self.client.links["client"].access_dict("addhash", {"name": "test1", "hash": tools.dhash("testafter"), "type": "client"})
        self.assertEqual(addhash2[0], True, addhash2)
        addref1 = self.client.links["client"].access_dict("addreference", {"hash": tools.dhash("a"), "reference": "True",  "reftype": "autoupd"})
        self.assertEqual(addref1[0], True, addref1)
        addref2 = self.client.links["client"].access_dict("addreference", {"hash": tools.dhash("a"), "reference": "www.test", "reftype": "url"})
        self.assertEqual(addref2[0], True, addref2)
        rename1 = self.client.links["client"].access_dict("renameentity", {"name": "test1", "newname": "test2"})
        self.assertEqual(rename1[0], True, rename1)
        # try after rename
        with self.assertLogs(level=logging.WARNING):
            addhashfail = self.client.links["client"].access_dict("addhash", {"name": "test1", "hash": tools.dhash("b"), "type": "client"})
            self.assertEqual(addhashfail[0], False, addhashfail)
        # deleting a not available object returns True
        dele1 = self.client.links["client"].access_dict("delentity", {"name": "test1"})
        self.assertEqual(dele1[0], True, dele1)
        dele2 = self.client.links["client"].access_dict("delentity", {"name": "test2"})
        self.assertEqual(dele2[0], True, dele2)

    def test_references(self):
        add1 = self.client.links["client"].access_dict("addentity", {"name": "testrefs1"})
        self.assertEqual(add1[0], True)
        addhash1 = self.client.links["client"].access_dict("addhash", {"name": "testrefs1", "hash": tools.dhash("baf"), "type": "client"})
        self.assertEqual(addhash1[0], True)
        addref1 = self.client.links["client"].access_dict("addreference", {"hash": tools.dhash("baf"), "reference": "True",  "reftype": "autoupd"})
        self.assertEqual(addref1[0], True)
        addref2 = self.client.links["client"].access_dict("addreference", {"hash": tools.dhash("baf"), "reference": "www.test.com", "reftype": "url"})
        self.assertEqual(addref2[0], True)

        cliret = self.client.links["client"].access_dict("getlocal", {"hash": tools.dhash("baf")})
        self.assertEqual(cliret[0], True, cliret)
        clicheck = [(cliret[1]["name"], tools.dhash("baf"), cliret[1]["type"], cliret[1]["priority"], cliret[1]["security"], cliret[1]["certreferenceid"])]
        with self.subTest():
            lfindbyref1 = self.client.links["client"].access_dict("findbyref", {"reference": "www.test.com", "reftype": "url"})
            self.assertEqual(lfindbyref1[0], True, lfindbyref1)
            self.assertEqual(lfindbyref1[1]["items"], clicheck)
        with self.subTest():
            lfindbyref2 = self.client.links["client"].access_dict("findbyref", {"reference": "www.test.com"})
            self.assertEqual(lfindbyref2[0], True, lfindbyref2)
            self.assertEqual(lfindbyref2[1]["items"], clicheck)
        with self.subTest():
            lfindbyref3 = self.client.links["client"].access_dict("findbyref", {"reftype": "url"})
            self.assertEqual(lfindbyref3[0], True, lfindbyref3)
            self.assertEqual(lfindbyref3[1]["items"], clicheck)
        with self.subTest():
            lfindbyref4 = self.client.links["client"].access_dict("findbyref", {})
            self.assertEqual(lfindbyref4[0], True, lfindbyref4)
            self.assertEqual(lfindbyref4[1]["items"], clicheck)

        add2 = self.client.links["client"].access_dict("addentity", {"name": "testrefs2"})
        self.assertEqual(add2[0], True)
        addhash2 = self.client.links["client"].access_dict("addhash", {"name": "testrefs2", "hash": tools.dhash("bad"), "type": "client"})
        self.assertEqual(addhash2[0], True, addhash2)
        addref3 = self.client.links["client"].access_dict("addreference", {"hash": tools.dhash("bad"), "reference": "www.test2.com", "reftype": "url"})
        self.assertEqual(addref3[0], True, addref3)
        with self.subTest():
            lgetref1 = self.client.links["client"].access_dict("getreferences", {"hash": tools.dhash("badaf")})
            self.assertEqual(lgetref1[0], False, lgetref1)
        with self.subTest():
            lgetref2 = self.client.links["client"].access_dict("getreferences", {"certreferenceid": cliret[1]["certreferenceid"]})
            self.assertEqual(lgetref2[0], True, lgetref2)
            self.assertEqual(lgetref2[1]["items"], [('True', 'autoupd'), ('www.test.com', 'url')])
        with self.subTest():
            lgetref3 = self.client.links["client"].access_dict("getreferences", {"hash": tools.dhash("baf")})
            self.assertEqual(lgetref3[0], True, lgetref3)
            self.assertEqual(lgetref3[1]["items"], [('True', 'autoupd'), ('www.test.com', 'url')])
        with self.subTest():
            lgetref4 = self.client.links["client"].access_dict("getreferences", {})
            self.assertEqual(lgetref4[0], True, lgetref4)
            self.assertEqual(lgetref4[1]["items"], [('True', 'autoupd'), ('www.test.com', 'url'), ('www.test2.com', 'url')])
        with self.subTest():
            lgetref5 = self.client.links["client"].access_dict("getreferences", {"filter": "autoupd"})
            self.assertEqual(lgetref5[0], True, lgetref5)
            self.assertEqual(lgetref5[1]["items"], [("True", "autoupd")])

if __name__ == '__main__':
    unittest.main(verbosity=2)
