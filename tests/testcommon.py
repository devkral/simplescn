#! /usr/bin/env python3

import os, sys
# fix import
if os.path.dirname(os.path.dirname(os.path.realpath(__file__))) not in sys.path:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))


import unittest
import logging
import shutil
import json

import simplescn
from simplescn import config
from simplescn import tools
from simplescn.tools import checks, start


class TestGenerateError(unittest.TestCase):
    def test_None(self):
        self.assertDictEqual(tools.generate_error(None), {"msg": "unknown", "type":"unknown"})
    def test_stack(self):
        try:
            raise(simplescn.AddressInvalidError)
        except Exception as e:
            try:
                raise(e)
            except Exception as a:
                ec = tools.generate_error(a)
                self.assertIn("msg", ec)
                self.assertIn("type", ec)
                self.assertEqual(ec.get("type"), "AddressInvalidError")
                self.assertIn("stacktrace", ec)
    def test_string(self):
        self.assertDictEqual(tools.generate_error("teststring"), {"msg": "teststring", "type":""})

class TestGenerateCerts(unittest.TestCase):
    temptestdir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_certs")
    
    # needed to run ONCE; setUpModule runs async
    @classmethod
    def setUpClass(cls):
        if os.path.isdir(cls.temptestdir):
            shutil.rmtree(cls.temptestdir)
        os.mkdir(cls.temptestdir, 0o700)
        cls.oldpwcallmethodinst = simplescn.pwcallmethodinst

    # needed to run ONCE; tearDownModule runs async
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temptestdir)
        simplescn.pwcallmethodinst = cls.oldpwcallmethodinst
    
    def test_NoPw(self):
        simplescn.pwcallmethodinst = lambda msg: ""
        tools.generate_certs(os.path.join(self.temptestdir, "testnopw"))
        self.assertTrue(checks.check_certs(os.path.join(self.temptestdir, "testnopw")))
    
    def test_WithPw(self):
        pw = str(os.urandom(10), "utf-8", "backslashreplace")
        simplescn.pwcallmethodinst = lambda msg: pw
        tools.generate_certs(os.path.join(self.temptestdir, "testwithpw"))
        self.assertTrue(checks.check_certs(os.path.join(self.temptestdir, "testwithpw")))
        

class TestAuth(unittest.TestCase):
    # needed to run ONCE; setUpModule runs async
    @classmethod
    def setUpClass(cls):
        cls.hashserver = tools.dhash(os.urandom(10).hex())
        cls.hashserver_wrong = tools.dhash(os.urandom(10).hex())
        
        cls.pwserver = str(os.urandom(10), "utf-8", "backslashreplace")
        cls.pwadmin = str(os.urandom(10), "utf-8", "backslashreplace")
        cls.pwinvalid = str(os.urandom(10), "utf-8", "backslashreplace")
        cls.authserver = tools.SCNAuthServer(cls.hashserver)
        #cls.authclient = tools.scnauth_client()
        cls.authserver.init(tools.dhash(cls.pwserver))
    
    def test_construct_correct(self):
        serverra = self.authserver.request_auth()
        self.assertEqual(serverra.get("algo"), config.DEFAULT_HASHALGORITHM)
        self.assertEqual(serverra.get("snonce"), self.authserver.nonce)
        self.assertIn("timestamp", serverra)
        clienta = tools.scn_hashedpw_auth(tools.dhash(self.pwserver), serverra, self.hashserver)
        self.assertEqual(clienta.get("timestamp"), serverra.get("timestamp"))
        self.assertIn("cnonce", clienta)
        
        #self.assertIn("auth", clienta)
        
    def test_verisuccess(self):
        serverra = self.authserver.request_auth()
        clienta = tools.scn_hashedpw_auth(tools.dhash(self.pwserver), serverra, self.hashserver)
        self.assertTrue(self.authserver.verify(clienta))

    def test_verifalse(self):
        serverra = self.authserver.request_auth()
        clienta = tools.scn_hashedpw_auth(tools.dhash(self.pwinvalid), serverra, self.hashserver)
        self.assertFalse(self.authserver.verify(clienta))
        clienta = tools.scn_hashedpw_auth(tools.dhash(self.pwserver), serverra, self.hashserver_wrong)
        self.assertFalse(self.authserver.verify(clienta))


class Test_safe_mdecode(unittest.TestCase):
    # needed to run ONCE; setUpModule runs async
    @classmethod
    def setUpClass(cls):
        cls.pwserver = str(os.urandom(10), "utf-8", "backslashreplace")
        cls.pwclient = str(os.urandom(10), "utf-8", "backslashreplace")
        cls.pwinvalid = str(os.urandom(10), "utf-8", "backslashreplace")
        cls._testseq_json1 = json.dumps({"action": "show", "headers": {"X-SCN-Authorization": tools.dhash(cls.pwserver)}})
    
    def test_valid_json(self):
        result = tools.safe_mdecode(self._testseq_json1, "application/json")
        self.assertIn("action", result)
        self.assertEqual(result["action"], "show")
        self.assertIn("headers", result)
        self.assertIn("X-SCN-Authorization", result["headers"])
        self.assertEqual(result["headers"]["X-SCN-Authorization"], tools.dhash(self.pwserver))
    
    def test_valid_convert(self):
        result = tools.safe_mdecode(bytes(self._testseq_json1, "utf-8"), "application/json")
        self.assertIn("action", result)
        self.assertEqual(result["action"], "show")
        self.assertIn("headers", result)
        self.assertIn("X-SCN-Authorization", result["headers"])
        self.assertEqual(result["headers"]["X-SCN-Authorization"], tools.dhash(self.pwserver))
        
        result = tools.safe_mdecode(bytes(self._testseq_json1, "iso8859_8"), "application/json", "iso8859_8")
        self.assertIn("action", result)
        self.assertEqual(result["action"], "show")
        self.assertIn("headers", result)
        self.assertIn("X-SCN-Authorization", result["headers"])
        self.assertEqual(result["headers"]["X-SCN-Authorization"], tools.dhash(self.pwserver))

        result = tools.safe_mdecode(bytes(self._testseq_json1, "iso8859_8"), "application/json; charset=iso8859_8")
        self.assertIn("action", result)
        self.assertEqual(result["action"], "show")
        self.assertIn("headers", result)
        self.assertIn("X-SCN-Authorization", result["headers"])
        self.assertEqual(result["headers"]["X-SCN-Authorization"], tools.dhash(self.pwserver))

    def test_errors(self):
        with self.assertLogs(level=logging.ERROR):
            self.assertIsNone(tools.safe_mdecode(self._testseq_json1, "image/png"))
        with self.assertLogs(level=logging.ERROR):
            self.assertIsNone(tools.safe_mdecode(self._testseq_json1, "text/plain"))
        with self.assertLogs(level=logging.ERROR):
            self.assertIsNone(tools.safe_mdecode(bytes(self._testseq_json1, "utf-8"), "application/json", "ksksls"))


class Test_getlocalclient(unittest.TestCase):
    temptestdirconf = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_getlocalclientconf")
    temptestdirconf2 = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_getlocalclientconf2")
    temptestdir2 = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_getlocalclient2")
    temptestdir3 = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_getlocalclient3")
    temptestdirempty = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_getlocalclientempty")
    param_client = ["--config={}".format(temptestdirconf), "--run={}".format(temptestdir2), "--noip", "--nounix"]
    param_client2 = ["--config={}".format(temptestdirconf2), "--run={}".format(temptestdir3), "--nounix", "--noip=False"]
    # needed to run ONCE; setUpModule runs async
    @classmethod
    def setUpClass(cls):
        if os.path.isdir(cls.temptestdirconf):
            shutil.rmtree(cls.temptestdirconf)
        if os.path.isdir(cls.temptestdirconf2):
            shutil.rmtree(cls.temptestdirconf2)
        if os.path.isdir(cls.temptestdir2):
            shutil.rmtree(cls.temptestdir2)
        if os.path.isdir(cls.temptestdir3):
            shutil.rmtree(cls.temptestdir3)
        if os.path.isdir(cls.temptestdirempty):
            shutil.rmtree(cls.temptestdirempty)
        os.mkdir(cls.temptestdirconf, 0o700)
        os.mkdir(cls.temptestdirconf2, 0o700)
        os.mkdir(cls.temptestdirempty, 0o700)
        os.mkdir(cls.temptestdir2, 0o700)
        os.mkdir(cls.temptestdir3, 0o700)
        cls.oldpwcallmethodinst = simplescn.pwcallmethodinst
        simplescn.pwcallmethodinst = lambda msg: ""
        cls.client = start.client(cls.param_client, doreturn=True)
        cls.client2 = start.client(cls.param_client2, doreturn=True)

    @classmethod
    def tearDownClass(cls):
        cls.client.quit()
        #cls.client2.quit()
        shutil.rmtree(cls.temptestdirconf)
        shutil.rmtree(cls.temptestdirconf2)
        shutil.rmtree(cls.temptestdir2)
        shutil.rmtree(cls.temptestdir3)
        shutil.rmtree(cls.temptestdirempty)
        simplescn.pwcallmethodinst = cls.oldpwcallmethodinst

    def test_blockclient(self):
        client2 = start.client(self.param_client, doreturn=True)
        self.assertIsNone(client2)

    def test_retrieve(self):
        ret = tools.getlocalclient(rundir=self.temptestdirempty)
        self.assertIsNone(ret)
        # no connection possible
        ret2 = tools.getlocalclient(rundir=self.temptestdir2)
        self.assertIsNone(ret2)
        ret3 = tools.getlocalclient(rundir=self.temptestdir3)
        self.assertIsNotNone(ret3)

if __name__ == '__main__':
    unittest.main(verbosity=2)
