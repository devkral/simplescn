
"""
start file for simplescn
license: MIT, see LICENSE.txt
"""

import threading
import logging
import signal
import os
import sys
import json

from .. import config
from .._common import scnparse_args, loglevel_converter

###### start ######


def block():
    """ blocks until SIGINT, SIGTERM """
    event = threading.Event()
    def _block(_signal, frame):
       event.set()

    oldhandlersigint = signal.signal(signal.SIGINT, _block)
    oldhandlersigterm = signal.signal(signal.SIGTERM, _block)
    event.wait()
    signal.signal(signal.SIGINT, oldhandlersigint)
    signal.signal(signal.SIGTERM, oldhandlersigterm)



def init_scn(doreturn):
    """ initialize once and only in mainthread """
    # don't activate as debugger may start script as thread
    #assert doreturn or threading.current_thread() == threading.main_thread(), "use doreturn instead starting own thread"
    if not doreturn:
        logging.basicConfig(level=loglevel_converter(config.default_loglevel), format=config.logformat)

def server(argv, doreturn=False):
    """ start server component """
    init_scn(doreturn)
    from ..server import server_paramhelp, default_server_args, ServerInit
    kwargs = scnparse_args(argv, server_paramhelp, default_server_args)
    os.makedirs(kwargs["config"], 0o700, True)
    server_instance = ServerInit.create(**kwargs)
    if doreturn or not server_instance:
        return server_instance
    else:
        print(json.dumps(server_instance.show()))
        block()
        server_instance.quit()

def client(argv, doreturn=False):
    """ start client component """
    init_scn(doreturn)
    from ..client import client_paramhelp, default_client_args, ClientInit
    kwargs = scnparse_args(argv, client_paramhelp, default_client_args)
    os.makedirs(kwargs["config"], 0o700, True)
    client_instance = ClientInit.create(**kwargs)
    if doreturn or not client_instance:
        return client_instance
    else:
        print(json.dumps(client_instance.show()))
        block()
        client_instance.quit()

def cmdcom(argv=sys.argv[1:]):
    """ wrapper for cmdcom """
    from ..cmdcom import init_cmdcom
    return init_cmdcom(argv)

def cmd_massimport(argv=sys.argv[1:]):
    """ wrapper for cmdmassimport """
    from ..massimport import cmdmassimport
    return cmdmassimport(argv)


def hashpw(argv=sys.argv[1:]):
    """ create pw hash for *pwhash """
    from .tools import dhash
    from ..pwrequester import pwcallmethod
    import base64
    if len(sys.argv) and sys.argv[1].strip("-") == "help":
        print("Usage: {} hashpw [<pw>/\"random\"]".format(sys.argv[0]))
        return
    if len(argv) == 0:
        pw = pwcallmethod(config.hashpw_prompt)
    else:
        pw = argv[0]
    
    pw = argv[0]
    if pw == "random":
        pw = str(base64.urlsafe_b64encode(os.urandom(10)), "utf-8")
    print("pw: {}, hash: {}".format(pw, dhash(pw)))

allowed_methods = {"client", "server", "hashpw", "cmdcom", "cmd_massimport"}
def init_method_main(argv=sys.argv[1:]):
    """ starter method """
    if len(argv) > 0:
        if argv[0] in allowed_methods:
            globals()[argv[0]](argv[1:])
            return
        else:
            print("Method not available", file=sys.stderr)
    print("Available:", *allowed_methods, file=sys.stderr)

