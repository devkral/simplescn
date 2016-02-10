#! /usr/bin/env python3

import os, sys
# fix import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))


import unittest
import logging
import shutil
import json
from urllib import parse

import simplescn
import simplescn.common


class TestGenerateError(unittest.TestCase):
    def test_None(self):
        self.assertDictEqual(simplescn.generate_error(None), {"msg": "unknown", "type":"unknown"})
    def test_stack(self):
        try:
            raise(simplescn.AddressInvalidFail)
        except Exception as e:
            try:
                raise(e)
            except Exception as a:
                ec = simplescn.generate_error(a)
                self.assertIn("msg", ec)
                self.assertIn("type", ec)
                self.assertEqual(ec.get("type"), "AddressInvalidFail")
                self.assertIn("stacktrace", ec)
    def test_string(self):
        self.assertDictEqual(simplescn.generate_error("teststring"), {"msg": "teststring", "type":""})

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
        simplescn.pwcallmethodinst = lambda msg, requester: ""
        simplescn.generate_certs(os.path.join(self.temptestdir, "testnopw"))
        self.assertTrue(simplescn.check_certs(os.path.join(self.temptestdir, "testnopw")))
    
    def test_WithPw(self):
        pw = str(os.urandom(10), "utf-8", "backslashreplace")
        simplescn.pwcallmethodinst = lambda msg, requester: pw
        simplescn.generate_certs(os.path.join(self.temptestdir, "testwithpw"))
        self.assertTrue(simplescn.check_certs(os.path.join(self.temptestdir, "testwithpw")))
        
class TestConfigmanager(unittest.TestCase):
    temptestdir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_config")
    
    _testdefault={"default_a": ("aval", str, "a description"),
                "b": ("bval", str, "doc b"),
                "int_d": ("90", int, "doc d")}
    _testoverride={"b": ("bnewval", str, "doc")}
    _testoverridec={"c": ("cnewvalunavailable", str , "doc")}
    
    # needed to run ONCE; setUpModule runs async
    @classmethod
    def setUpClass(cls):
        if os.path.isdir(cls.temptestdir):
            shutil.rmtree(cls.temptestdir)
        os.mkdir(cls.temptestdir, 0o700)

    # needed to run ONCE; tearDownModule runs async
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temptestdir)
        
    def test_Config(self):
        config = simplescn.common.configmanager(os.path.join(self.temptestdir, "testdb"+simplescn.confdb_ending))
        self.assertTrue(os.path.isfile(os.path.join(self.temptestdir, "testdb"+simplescn.confdb_ending)))
        with self.subTest(msg="override without default key"):
            self.assertTrue(config.update(self._testdefault,self._testoverridec))
            self.assertIsNone(config.get_default("c"))
        #config.update(self._testdefault,self._testoverride)
    def test_rw_valid(self):
        config = simplescn.common.configmanager(os.path.join(self.temptestdir, "testdb2"+simplescn.confdb_ending))
        config.update(self._testdefault,self._testoverride)
        self.assertEqual(config.get("default_a"), "aval")
        self.assertTrue(config.set("default_a", "av3al2"))
        self.assertEqual(config.get("default_a"), "av3al2")
        self.assertEqual(config.get_default("default_a"), "aval")
        # b
        self.assertEqual(config.get("b"), "bnewval")
        self.assertEqual(config.get_default("b"), "bval")
        # d
        self.assertEqual(config.get("int_d"), 90)
        self.assertEqual(config.get_default("int_d"), "90")
        
        
    def test_rw_invalid(self):
        config = simplescn.common.configmanager(os.path.join(self.temptestdir, "testdb3"+simplescn.confdb_ending))
        config.update(self._testdefault,self._testoverride)
        with self.assertLogs(level=logging.ERROR):
            self.assertFalse(config.set("c", "llsl"))
        
        with self.assertLogs(level=logging.ERROR):
            self.assertFalse(config.get("c"))
        
        # has no default
        self.assertIsNone(config.get_default("c"))
        #invalid key
        with self.assertLogs(level=logging.ERROR):
            self.assertIsNone(config.get("e"))

    def test_reload(self):
        config = simplescn.common.configmanager(os.path.join(self.temptestdir, "testdb4"+simplescn.confdb_ending))
        config.update(self._testdefault,self._testoverride)
        self.assertTrue(config.set("default_a", "av3al2"))
        self.assertTrue(config.set("b", "kskla"))
        
        del config
        config = simplescn.common.configmanager(os.path.join(self.temptestdir, "testdb4"+simplescn.confdb_ending))
        config.update(self._testdefault,self._testoverride)
        
        self.assertEqual(config.get("default_a"), "av3al2")
        self.assertEqual(config.get("b"), "bnewval")
    
    def test_multiple_update(self):
        config = simplescn.common.configmanager(os.path.join(self.temptestdir, "testdb5"+simplescn.confdb_ending))
        config.update(self._testdefault,self._testoverride)
        with self.assertLogs(level=logging.ERROR):
            self.assertFalse(config.set("c", "llsl"))
        self.assertTrue(config.set("b", "meh"))
        config.update(self._testdefault,self._testoverridec)
        self.assertNotEqual(config.get("c"), "llsl")
        self.assertTrue(config.set("c", "lal"))
        self.assertEqual(config.get("c"), "lal")
        config.update(self._testdefault,self._testoverride)
        
        self.assertEqual(config.get("b"), "bnewval")
        
        

class TestAuth(unittest.TestCase):
    # needed to run ONCE; setUpModule runs async
    @classmethod
    def setUpClass(cls):
        cls.hashserver = simplescn.dhash(os.urandom(10).hex())
        cls.hashserver_wrong = simplescn.dhash(os.urandom(10).hex())
        
        cls.pwserver = str(os.urandom(10), "utf-8", "backslashreplace")
        cls.pwadmin = str(os.urandom(10), "utf-8", "backslashreplace")
        cls.pwinvalid = str(os.urandom(10), "utf-8", "backslashreplace")
        cls.authserver = simplescn.scnauth_server(cls.hashserver)
        cls.authclient = simplescn.scnauth_client()
        cls.authserver.init_realm("server", simplescn.dhash(cls.pwserver))
        cls.authserver.init_realm("admin", simplescn.dhash(cls.pwadmin))
    
    def test_construct_correct(self):
        serverra=self.authserver.request_auth("server")
        self.assertEqual(serverra.get("realm"), "server")
        self.assertEqual(serverra.get("algo"), simplescn.DEFAULT_HASHALGORITHM)
        self.assertEqual(serverra.get("nonce"), self.authserver.realms["server"][1])
        self.assertIn("timestamp", serverra)
        clienta = self.authclient.auth(self.pwserver, serverra, self.hashserver)
        self.assertEqual(clienta.get("timestamp"), serverra.get("timestamp"))
        self.assertIn("auth", clienta)
        
    def test_verisuccess(self):
        serverra = self.authserver.request_auth("server")
        clienta = {"server":self.authclient.auth(self.pwserver, serverra, self.hashserver)}
        self.assertTrue(self.authserver.verify("server", clienta))
    
    def test_veriwrongdomain(self):
        serverra = self.authserver.request_auth("server")
        clienta = {"server":self.authclient.auth(self.pwadmin, serverra, self.hashserver)}
        self.assertFalse(self.authserver.verify("server", clienta))
        clienta["admin"] = self.authclient.auth(self.pwserver, serverra, self.hashserver)
        self.assertFalse(self.authserver.verify("server", clienta))
    
    def test_verifalse(self):
        serverra = self.authserver.request_auth("server")
        clienta = {"server":self.authclient.auth(self.pwinvalid, serverra, self.hashserver)}
        self.assertFalse(self.authserver.verify("server", clienta))
        clienta = {"server":self.authclient.auth(self.pwserver, serverra, self.hashserver_wrong)}
        self.assertFalse(self.authserver.verify("server", clienta))
    
    def test_reauth(self):
        serverra = self.authserver.request_auth("server")
        self.assertIsNone(self.authclient.reauth("123", serverra, self.hashserver))
        clienta = {"server":self.authclient.auth(self.pwserver, serverra, self.hashserver, "123")}
        clienta2 = {"server":self.authclient.reauth("123", serverra, self.hashserver)}
        self.assertIsNone(self.authclient.reauth("d2s3", serverra, self.hashserver))
        self.assertTrue(self.authserver.verify("server", clienta2))
        self.assertEqual(clienta, clienta2)
        
        # delete 
        self.authclient.delauth("123", "server")
        self.assertIsNone(self.authclient.reauth("123", serverra, self.hashserver))
        
        # manually add
        self.authclient.saveauth(self.pwserver, "123", "server")
        self.assertEqual(clienta, {"server":self.authclient.reauth("123", serverra, self.hashserver)})


class Test_safe_mdecode(unittest.TestCase):
    # needed to run ONCE; setUpModule runs async
    @classmethod
    def setUpClass(cls):
        cls.pwserver = str(os.urandom(10), "utf-8", "backslashreplace")
        cls.pwclient = str(os.urandom(10), "utf-8", "backslashreplace")
        cls.pwinvalid = str(os.urandom(10), "utf-8", "backslashreplace")
        
        cls._testseq_json1 = json.dumps({"action": "show", "auth": {"server":cls.pwserver, "client":cls.pwclient}})
        # default
        cls._testseq_qs1 = parse.urlencode({"action": "show", "auth": ["server:{}".format(cls.pwserver), "client:{}".format(cls.pwclient)]}, doseq=True)
        # use jauth (json auth)
        cls._testseq_qs2 = parse.urlencode({"action": "show", "jauth": json.dumps({"server":cls.pwserver, "client":cls.pwclient})}, doseq=True)
        # use jauth (json auth) and overwrite default pw encoding
        cls._testseq_qs3 = parse.urlencode({"action": "show", "jauth": json.dumps({"server":cls.pwserver, "client":cls.pwclient}), "auth": ["server:{}".format(cls.pwinvalid), "client:{}".format(cls.pwinvalid)]}, doseq=True)
    
    def test_valid_json(self):
        result = simplescn.safe_mdecode(self._testseq_json1, "application/json")
        self.assertEqual(result["action"], "show")
        self.assertEqual(result["auth"]["server"], self.pwserver)
        self.assertEqual(result["auth"]["client"], self.pwclient)
    
    def test_valid_convert(self):
        result = simplescn.safe_mdecode(bytes(self._testseq_json1, "utf-8"), "application/json")
        self.assertEqual(result["action"], "show")
        self.assertEqual(result["auth"]["server"], self.pwserver)
        self.assertEqual(result["auth"]["client"], self.pwclient)
        
        result = simplescn.safe_mdecode(bytes(self._testseq_json1, "iso8859_8"), "application/json", "iso8859_8")
        self.assertEqual(result["action"], "show")
        self.assertEqual(result["auth"]["server"], self.pwserver)
        self.assertEqual(result["auth"]["client"], self.pwclient)
        
        
        result = simplescn.safe_mdecode(bytes(self._testseq_json1, "iso8859_8"), "application/json; charset=iso8859_8")
        self.assertEqual(result["action"], "show")
        self.assertEqual(result["auth"]["server"], self.pwserver)
        self.assertEqual(result["auth"]["client"], self.pwclient)
    
    def test_valid_qs_1(self):
        result = simplescn.safe_mdecode(self._testseq_qs1, "application/x-www-form-urlencoded")
        self.assertEqual(result["action"][0], "show")
        self.assertEqual(result["auth"].get("server"), self.pwserver)
        self.assertEqual(result["auth"].get("client"), self.pwclient)
    
    def test_valid_qs_2(self):
        result = simplescn.safe_mdecode(self._testseq_qs2, "application/x-www-form-urlencoded")
        self.assertEqual(result["action"][0], "show")
        self.assertEqual(result["auth"]["server"], self.pwserver)
        self.assertEqual(result["auth"]["client"], self.pwclient)
    
    def test_valid_qs_3(self):
        result = simplescn.safe_mdecode(self._testseq_qs3, "application/x-www-form-urlencoded")
        self.assertEqual(result["action"][0], "show")
        self.assertEqual(result["auth"]["server"], self.pwserver)
        self.assertEqual(result["auth"]["client"], self.pwclient)

    def test_errors(self):
        with self.assertLogs(level=logging.ERROR):
            self.assertIsNone(simplescn.safe_mdecode(self._testseq_json1, "image/png"))
        with self.assertLogs(level=logging.ERROR):
            self.assertIsNone(simplescn.safe_mdecode(self._testseq_json1, "text/plain"))
        with self.assertLogs(level=logging.ERROR):
            self.assertIsNone(simplescn.safe_mdecode(bytes(self._testseq_json1, "utf-8"), "application/json", "ksksls"))

if __name__ == '__main__':
    unittest.main(verbosity=2)
