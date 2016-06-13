#! /usr/bin/env python3

"""
start file for simplescn
license: MIT, see LICENSE.txt
"""

import sys
import os
import logging
import threading
import signal
import json

if __name__ == "__main__":
    _tpath = os.path.realpath(os.path.dirname(sys.modules[__name__].__file__))
    _tpath = os.path.dirname(_tpath)
    sys.path.insert(0, _tpath)

import simplescn
from simplescn import sharedir, logformat, default_loglevel, loglevel_converter
from simplescn.common import scnparse_args
import simplescn.client
import simplescn.server

running_instances = []

def _signal_handler(_signal, frame):
    """ handles signals; shutdown properly """
    for elem in running_instances:
        if hasattr(elem, "quit"):
            elem.quit()
    logging.shutdown()
    sys.exit(0)

def server(argv=sys.argv[1:], doreturn=False):
    """ start server component """
    _init_scn()
    from simplescn.server import server_paramhelp, default_server_args, server_init
    kwargs = scnparse_args(argv, server_paramhelp, default_server_args)
    os.makedirs(kwargs["config"], 0o750, True)
    server_instance = server_init(**kwargs)
    if doreturn:
        server_instance.serve_forever_nonblock()
        return server_instance
    else:
        running_instances.append(server_instance)
        print(json.dumps(server_instance.show()))
        server_instance.serve_forever_block()

def client(argv=sys.argv[1:], doreturn=False):
    """ client """
    _init_scn()
    from simplescn.client import client_paramhelp, default_client_args, client_init
    kwargs = scnparse_args(argv, client_paramhelp, default_client_args)
    os.makedirs(kwargs["config"], 0o750, True)
    client_instance = client_init(**kwargs)
    if doreturn:
        client_instance.serve_forever_nonblock()
        return client_instance
    else:
        running_instances.append(client_instance)
        print(json.dumps(client_instance.show()))
        client_instance.serve_forever_block()

def hashpw(argv=sys.argv[1:]):
    """ create pw hash for ?pwhash """
    _init_scn()
    from simplescn import dhash
    import base64
    if len(sys.argv) < 2 or sys.argv[1] in ["--help", "help"]:
        print("Usage: {} hashpw <pw>/\"random\"".format(sys.argv[0]))
        return
    pw = argv[0]
    if pw == "random":
        pw = str(base64.urlsafe_b64encode(os.urandom(10)), "utf-8")
    print("pw: {}, hash: {}".format(pw, dhash(pw)))

_is_init_already = False
def _init_scn():
    """ initialize once and only in mainthread """
    global _is_init_already
    if not _is_init_already and threading.current_thread() == threading.main_thread():
        _is_init_already = True
        logging.basicConfig(level=loglevel_converter(default_loglevel), format=logformat)
        signal.signal(signal.SIGINT, _signal_handler)

def _init_method_main():
    """ starter method """
    if len(sys.argv) > 1:
        toexe = sys.argv[1]
        toexe = globals().get(sys.argv[1].strip("_"), None)
        if callable(toexe):
            toexe(sys.argv[2:])
        else:
            print("Not available", file=sys.stderr)
            print("Available: client, server, hashpw", file=sys.stderr)
    else:
        print("Available: client, server, hashpw", file=sys.stderr)

if __name__ == "__main__":
    _init_method_main()
