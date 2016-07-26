#! /usr/bin/env python3

"""
start file for simplescn
license: MIT, see LICENSE.txt
"""

import sys
import os

# don't load different module
if __name__ == "__main__":
    ownpath = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, os.path.dirname(ownpath))

def client(argv=sys.argv[1:]):
    """ wrapper for client """
    from simplescn.tools.start import client
    return client(argv)

def server(argv=sys.argv[1:]):
    """ wrapper for server """
    from simplescn.tools.start import server
    return server(argv)

def cmdcom(argv=sys.argv[1:]):
    """ wrapper for cmdcom """
    from simplescn.cmdcom import _init_method_main as init_cmdcom
    return init_cmdcom(argv)

def cmd_massimport(argv=sys.argv[1:]):
    """ wrapper for cmdmassimport """
    from simplescn.massimport import cmdmassimport
    return cmdmassimport(argv)


def _init_method_main(argv=sys.argv[1:]):
    """ starter method """
    if len(argv) > 0:
        toexe = globals().get(argv[0].strip("_"), None)
        if callable(toexe):
            toexe(argv[1:])
        else:
            print("Not available", file=sys.stderr)
            print("Available: client, server, hashpw, cmdcom, cmd_massimport", file=sys.stderr)
    else:
        print("Available: client, server, hashpw, cmdcom, cmd_massimport", file=sys.stderr)

if __name__ == "__main__":
    _init_method_main()
