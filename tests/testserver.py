#! /usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "simplescn"))

import unittest

class TestServer(unittest.TestCase):
    pass

if __name__ == "main":
    unittest.main(verbosity=2)
