#! /usr/bin/env python3

import sys, os
if "__file__" not in globals():
    __file__ = sys.argv[0]

sharedir = os.path.dirname(os.path.realpath(__file__))
# append to pathes
if os.path.dirname(os.path.dirname(os.path.realpath(__file__))) not in sys.path:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import simplescn
import simplescn.client
import simplescn.guiclient
import simplescn.server

def client():
    simplescn.client._init_method()

def server():
    simplescn.server._init_method()


def guiclient():
    simplescn.guiclient._init_method()

def nothing():
    pass

if __name__ == "__main__":
    if len(sys.argv)>1:
        toexe= sys.argv[1]
        del sys.argv[1]
        globals().get(toexe, nothing)()

