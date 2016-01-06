#! /usr/bin/env python3

import sys
import os
# fix import
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "simplescn"))


import unittest
import shutil
import base64

import common


class TestGenerateError(unittest.TestCase):
    def test_None(self):
        self.assertDictEqual(common.generate_error(None), {"msg": "unknown", "type":"unknown"})
    def test_stack(self):
        try:
            raise(common.AddressInvalidFail)
        except Exception as e:
            try:
                raise(e)
            except Exception as a:
                ec = common.generate_error(a)
                self.assertIn("msg", ec)
                self.assertIn("type", ec)
                self.assertEqual(ec.get("type"), "AddressInvalidFail")
                self.assertIn("stacktrace", ec)
    def test_string(self):
        self.assertDictEqual(common.generate_error("teststring"), {"msg": "teststring", "type":""})

class TestGenerateCerts(unittest.TestCase):
    temptestdir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_certs")
    @classmethod
    def setUpClass(cls):
        if os.path.isdir(cls.temptestdir):
            shutil.rmtree(cls.temptestdir)
        os.mkdir(cls.temptestdir, 0o700)
        cls.oldpwcallmethodinst = common.pwcallmethodinst

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temptestdir)
        common.pwcallmethodinst = cls.oldpwcallmethodinst
    
    def test_NoPw(self):
        common.pwcallmethodinst = lambda msg, requester: ""
        common.generate_certs(os.path.join(self.temptestdir, "testnopw"))
        self.assertTrue(common.check_certs(os.path.join(self.temptestdir, "testnopw")))
    
    def test_WithPw(self):
        common.pwcallmethodinst = lambda msg, requester: "abfalldakc"
        common.generate_certs(os.path.join(self.temptestdir, "testwithpw"))
        self.assertTrue(common.check_certs(os.path.join(self.temptestdir, "testwithpw")))
        
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
        config = common.configmanager(os.path.join(self.temptestdir, "testdb"+common.confdb_ending))
    
    #TODO

class TestAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hashserver = common.dhash(base64.urlsafe_b64encode(os.urandom(20)))
        
        cls.pwsclient = base64.urlsafe_b64encode(os.urandom(10))
        cls.pwaclient = base64.urlsafe_b64encode(os.urandom(10))
        cls.pwcclient = base64.urlsafe_b64encode(os.urandom(10))
        cls.authserver = scnauth_server(cls.hashserver)
        cls.authclient = scnauth_client()
    #TODO

#TODO safe_mdecode, 

if __name__ == '__main__':
    unittest.main(verbosity=2)
