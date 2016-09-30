
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
running_instances = []
def _signal_handler(_signal, frame):
    """ handles signals; shutdown properly """
    for elem in running_instances:
        elem.quit()
    logging.shutdown()
    sys.exit(0)

_is_init_already = False
def init_scn():
    """ initialize once and only in mainthread """
    global _is_init_already
    if not _is_init_already and threading.current_thread() == threading.main_thread():
        _is_init_already = True
        logging.basicConfig(level=loglevel_converter(config.default_loglevel), format=config.logformat)
        signal.signal(signal.SIGINT, _signal_handler)

def server(argv, doreturn=False):
    """ start server component """
    init_scn()
    from simplescn.server import server_paramhelp, default_server_args, ServerInit
    kwargs = scnparse_args(argv, server_paramhelp, default_server_args)
    os.makedirs(kwargs["config"], 0o700, True)
    server_instance = ServerInit.create(**kwargs)
    if doreturn or not server_instance:
        return server_instance
    else:
        running_instances.append(server_instance)
        print(json.dumps(server_instance.show()))
        server_instance.join()

def client(argv, doreturn=False):
    """ start client component """
    init_scn()
    from simplescn.client import client_paramhelp, default_client_args, ClientInit
    kwargs = scnparse_args(argv, client_paramhelp, default_client_args)
    os.makedirs(kwargs["config"], 0o700, True)
    client_instance = ClientInit.create(**kwargs)
    if doreturn or not client_instance:
        return client_instance
    else:
        running_instances.append(client_instance)
        print(json.dumps(client_instance.show()))
        client_instance.join()

def cmdcom(argv=sys.argv[1:]):
    """ wrapper for cmdcom """
    from simplescn.cmdcom import init_cmdcom
    return init_cmdcom(argv)

def cmd_massimport(argv=sys.argv[1:]):
    """ wrapper for cmdmassimport """
    from simplescn.massimport import cmdmassimport
    return cmdmassimport(argv)

def hashpw(argv=sys.argv[1:]):
    if len(argv) == 0:
        print(dhash(input(config.pwrealm_prompt)))
    else:
        print(dhash(argv[0]))

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
