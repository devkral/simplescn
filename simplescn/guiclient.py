#! /usr/bin/env python3

import sys,os
sharedir = None
if "__file__" not in globals():
    __file__ = sys.argv[0]

if not sharedir:
    # use sys
    sharedir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

# append to pathes
if sharedir[-1] == os.sep:
    sharedir = sharedir[:-1]
if sharedir not in sys.path:
    sys.path.append(sharedir)



import signal

from simplescn.guigtk import clientmain
from simplescn.guigtk.clientmain import gtkclient_init

from simplescn import client
from simplescn.client import paramhelp, client_args

from simplescn.common import configmanager, pluginmanager, confdb_ending
from simplescn.common import logger
import logging

cm = None


def signal_handler(*args):
    #global run
    #win.close()
    clientmain.run = False
    sys.exit(0)
    #app.close()



if __name__ == "__main__":
    from simplescn.common import scn_logger, init_logger
    init_logger(scn_logger())
    logger().setLevel(logging.DEBUG)
    signal.signal(signal.SIGINT, signal_handler)
    dclargs = client.default_client_args.copy()
    del dclargs["cmd"]
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
                    if tparam[0] not in client_args:
                        client_args[tparam[0]] = ["True"]
                    else:
                        client_args[tparam[0]][0] = "True"
                    continue
                if tparam[0] in ["pluginpath", "pp"]:
                    pluginpathes += [tparam[1], ]
                    continue
                if tparam[0] not in client_args:
                    client_args[tparam[0]] = [tparam[1], None]
                else:
                    client_args[tparam[0]][0] = tparam[1]

    configpath = client_args["config"][0]
    configpath = os.path.expanduser(configpath)
    if configpath[-1] == os.sep:
        configpath = configpath[:-1]
    client_args["config"][0] = configpath
    pluginpathes.insert(1, os.path.join(configpath, "plugins"))
    
    configpath_plugins = os.path.join(configpath, "config", "plugins")

    os.makedirs(os.path.join(configpath, "config"), 0o750, True)
    os.makedirs(configpath_plugins, 0o750, True)
    confm = configmanager(os.path.join(configpath, "config", "clientgtkgui{}".format(confdb_ending)))
    confm.update(dclargs, client_args)

    if confm.getb("noplugins") == False:
        pluginm = pluginmanager(pluginpathes, configpath_plugins, "client")
        if confm.getb("webgui") != False:
            pluginm.interfaces += ["web",]
        pluginm.interfaces += ["cmd","gtk"]
    else:
        pluginm = None
    cm = gtkclient_init(confm, pluginm)
    cm.enter_gtkmainloop()
    
    sys.exit(0)
