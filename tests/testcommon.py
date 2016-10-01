#! /usr/bin/env python3

import unittest
import logging
import json
import tempfile

import os, sys
# fix import
if os.path.dirname(os.path.dirname(os.path.realpath(__file__))) not in sys.path:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import simplescn
from simplescn import config
from simplescn import tools
from simplescn.tools import checks


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
    temptestdir = tempfile.TemporaryDirectory("testcommoncerts")
    
    # needed to run ONCE; setUpModule runs async
    @classmethod
    def setUpClass(cls):
        cls.oldpwcallmethodinst = simplescn.pwcallmethodinst
        config.debug_mode = True
        config.harden = False

    # needed to run ONCE; tearDownModule runs async
    @classmethod
    def tearDownClass(cls):
        simplescn.pwcallmethodinst = cls.oldpwcallmethodinst
    
    def test_NoPw(self):
        simplescn.pwcallmethodinst = lambda msg: ""
        tools.generate_certs(os.path.join(self.temptestdir.name, "testnopw"))
        self.assertTrue(checks.check_certs(os.path.join(self.temptestdir.name, "testnopw")))
    
    def test_WithPw(self):
        pw = str(os.urandom(10), "utf-8", "backslashreplace")
        simplescn.pwcallmethodinst = lambda msg: pw
        tools.generate_certs(os.path.join(self.temptestdir.name, "testwithpw"))
        self.assertTrue(checks.check_certs(os.path.join(self.temptestdir.name, "testwithpw")))

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

if __name__ == "__main__":
    unittest.main(verbosity=2)
