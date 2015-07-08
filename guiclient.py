#! /usr/bin/env python3
import sys,os


sharedir=None
if sharedir is None:
    sharedir=os.path.dirname(os.path.realpath(__file__))

if sharedir[-1] == os.sep:
    sharedir = sharedir[:-1]
if sharedir not in sys.path:
    sys.path.append(sharedir)


from os import path

import logging
import signal

from guigtk import clientmain
from guigtk.clientmain import gtkclient_init, do_gtkiteration

import client

import common
from common import configmanager, pluginmanager

#VALError
from common import logger
#init_logger()

#logger=getlogger()

#cm = None

def paramhelp():
    print(\
"""
### parameters ###
config=<dir>: path to config dir
timeout=<number>: #########not implemented yet ###############
server: shall start own server
port=<number>: Port in connection with server
client: url to connect
clientpw: pw for the url
cmd: opens cmd
""")


def signal_handler(*args):
    #global run
    #win.close()
    clientmain.run = False
    #app.close()


if __name__ == "__main__":
    from common import scn_logger, init_logger
    init_logger(scn_logger())
    logger().setLevel(logging.DEBUG)
    signal.signal(signal.SIGINT, signal_handler)
    dclargs = client.default_client_args.copy()
    #del dclargs["cmd"]
    clargs = client.client_args.copy()
    #del clargs["cmd"]
    pluginpathes = [os.path.join(sharedir, "plugins")]

    if len(sys.argv) > 1:
        tparam = ()
        for elem in sys.argv[1:]: #strip filename from arg list
            elem = elem.strip("-")
            if elem in ["help", "h"]:
                paramhelp()
                sys.exit(0)
            else:
                tparam = elem.split("=")
                if len(tparam) == 1:
                    tparam = elem.split(":")
                if len(tparam) == 1:
                    clargs[tparam[0]] = "True"
                    continue
                if tparam[0] in ["pluginpath", "pp"]:
                    pluginpathes += [tparam[1],]
                    continue
                clargs[tparam[0]] = tparam[1]

    configpath = clargs["config"]
    configpath = path.expanduser(configpath)
    if configpath[-1] == os.sep:
        configpath = configpath[:-1]
    clargs["config"] = configpath
    pluginpathes.insert(1,os.path.join(configpath, "plugins"))
    
    configpath_plugins = os.path.join(configpath, "config", "plugins")

    os.makedirs(os.path.join(configpath, "config"), 0o750, True)
    os.makedirs(configpath_plugins, 0o750, True)
    confm = configmanager(os.path.join(configpath, "config", "clientgtkgui.conf"))
    confm.update(dclargs, clargs)

    if confm.getb("noplugins") == False:
        pluginm = pluginmanager(pluginpathes, configpath_plugins, "client")
        if confm.getb("webgui") != False:
            pluginm.interfaces += ["web",]
        pluginm.interfaces += ["cmd","gui"]
    else:
        pluginm = None
    #logger().debug("start client")
    #global cm
    cm = gtkclient_init(confm, pluginm)
    if confm.getb("noplugins") == False:
        pluginm.resources["access"] = cm.links["client"].access
        pluginm.init_plugins()
    do_gtkiteration()
    #del cm
    sys.exit(0)
