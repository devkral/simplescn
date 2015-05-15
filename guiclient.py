#! /usr/bin/env python3
import sys,os

thisdir=os.path.dirname(os.path.realpath(__file__))
if thisdir not in sys.path:
    sys.path.append(thisdir)

guigtk=os.path.join(thisdir,"guigtk")
if guigtk not in sys.path:
    sys.path.append(guigtk)

from os import path

import logging
import signal

import clientmain
from clientmain import gtkclient_init, do_gtkiteration

import client
from client import default_client_args as dclargs

from common import sharedir, configmanager, pluginmanager
#VALError






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
    logging.basicConfig(level=logging.DEBUG)
    signal.signal(signal.SIGINT, signal_handler)

    clargs = client.client_args.copy()
    pluginpathes = ["{}{}plugins".format(sharedir, os.sep)]

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
                    clargs[tparam[0]] = ""
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
    pluginpathes.insert(1, "{}{}plugins".format(configpath, os.sep))

    os.makedirs("{}{}config".format(configpath, os.sep), 0o750, True)
    os.makedirs("{}{}config{}plugins".format(configpath, os.sep, os.sep), 0o750, True)
    confm = configmanager("{}{}config{}{}".format(configpath, os.sep, os.sep, "clientgtkgui.conf"))
    confm.update(dclargs, clargs)

    config_path = path.expanduser(clargs["config"])
    if config_path[-1] == os.sep:
        config_path = config_path[:-1]

    plugins_config = "{}{}config{}plugins".format(configpath, os.sep, os.sep)
    if confm.getb("noplugins") == False:
        pluginm = pluginmanager(pluginpathes, plugins_config)
        if confm.getb("webgui") != False:
            pluginm.interfaces += ["web",]
        if confm.getb("cmd") != False:
            pluginm.interfaces += ["cmd",]
    else:
        pluginm = None
    #logging.debug("start client")
    #global cm
    cm = gtkclient_init(confm, pluginm)
    if confm.getb("noplugins") == False:
        pluginm.init_plugins()
    do_gtkiteration()
    #del cm
    sys.exit(0)
