#! /usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "simplescn"))

import unittest
import logging
from threading import Thread

import __main__

def shimrun(cmd, *args, **kwargs):
    try:
        cmd(*args, **kwargs)
    except Exception:
        logging.exception("{} failed".format(type(cmd).__name__))


class TestCommunication(unittest.TestCase):
    temptestdir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "temp_communication")
    param_server = ["--config={}".format(temptestdir), "--port=4040"]
    param_client = ["--config={}".format(temptestdir), "--nocmd"]
    client = None
    server = None
    def setUp(self):
        if os.path.isdir(self.temptestdir):
            shutil.rmtree(self.temptestdir)
        os.mkdir(self.temptestdir, 0o700)
        simplescn.pwcallmethodinst = lambda msg, requester: ""
        self.oldpwcallmethodinst = simplescn.pwcallmethodinst
        self.client = __main__.rawclient_instance
        self.server = __main__.server_instance
        Thread(target=shimrun, args=(__main__.server, *self.param_server), daemon=True).start()
        Thread(target=shimrun, args=(__main__.client, *self.param_client), daemon=True).start()

    def tearDown(self):
        shutil.rmtree(self.temptestdir)
        simplescn.pwcallmethodinst = self.oldpwcallmethodinst

    def test_register(self):
        ret = self.client.access_main("register", server="::1")
        ret2 = self.client.access_main("register", server="127.0.0.1")
        ret3 = self.client.access_main("register", server="127.0.0.1-4040")
    
    def test_caps(self):
        pass
    
    
    def test_check(self):
        pass
    
    def test_check_direct(self):
        pass
    
if __name__ == "main":
    unittest.main(verbosity=2)
