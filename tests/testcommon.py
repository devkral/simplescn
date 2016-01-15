#! /usr/bin/env python3

import os, sys
# fix import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))


import unittest
import shutil
import base64

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
    @classmethod
    def setUpClass(cls):
        if os.path.isdir(cls.temptestdir):
            shutil.rmtree(cls.temptestdir)
        os.mkdir(cls.temptestdir, 0o700)
        cls.oldpwcallmethodinst = simplescn.pwcallmethodinst

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temptestdir)
        simplescn.pwcallmethodinst = cls.oldpwcallmethodinst
    
    def test_NoPw(self):
        simplescn.pwcallmethodinst = lambda msg, requester: ""
        simplescn.generate_certs(os.path.join(self.temptestdir, "testnopw"))
        self.assertTrue(simplescn.check_certs(os.path.join(self.temptestdir, "testnopw")))
    
    def test_WithPw(self):
        simplescn.pwcallmethodinst = lambda msg, requester: "abfalldakc"
        simplescn.generate_certs(os.path.join(self.temptestdir, "testwithpw"))
        self.assertTrue(simplescn.check_certs(os.path.join(self.temptestdir, "testwithpw")))
        
class TestConfigmanager(unittest.TestCase):
    temptestdir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_config")
    @classmethod
    def setUpClass(cls):
        if os.path.isdir(cls.temptestdir):
            shutil.rmtree(cls.temptestdir)
        os.mkdir(cls.temptestdir, 0o700)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temptestdir)
        
    def test_Config(self):
        config = simplescn.common.configmanager(os.path.join(self.temptestdir, "testdb"+simplescn.confdb_ending))
        testdefault={"default_a": "a"}
    
    #TODO

class TestAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hashserver = simplescn.dhash(base64.urlsafe_b64encode(os.urandom(20)))
        
        cls.pwsclient = base64.urlsafe_b64encode(os.urandom(10))
        cls.pwaclient = base64.urlsafe_b64encode(os.urandom(10))
        cls.pwcclient = base64.urlsafe_b64encode(os.urandom(10))
        cls.authserver = simplescn.scnauth_server(cls.hashserver)
        cls.authclient = simplescn.scnauth_client()
    #TODO

#TODO safe_mdecode, 

if __name__ == '__main__':
    unittest.main(verbosity=2)
