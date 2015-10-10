#! /usr/bin/env python3

import sys,os
sharedir = None
if "__file__" not in globals():
    __file__ = sys.argv[0]

if not sharedir:
    # use sys
    sharedir = os.path.dirname(os.path.realpath(__file__))

# append to pathes
if sharedir[-1] == os.sep:
    sharedir = sharedir[:-1]
if sharedir not in sys.path:
    sys.path.append(sharedir)


from os import path

import logging
import signal

from guigtk import clientmain
from guigtk.clientmain import gtkclient_init, do_gtkiteration
from guigtk.clientnode import gtkclient_node

import client
from client import paramhelp, client_args

from common import configmanager, pluginmanager, confdb_ending

#VALError
from common import logger
#init_logger()

#logger=getlogger()

cm = None

def open_gtk_node(_address, forcehash=None, switchfrominfo=False):
    gtkclient_node(cm.links, _address, forcehash=forcehash, switchfrominfo=switchfrominfo)
    

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
    del dclargs["cmd"]
    #clargs = client.client_args.copy()
    #del client_args["cmd"]
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
    configpath = path.expanduser(configpath)
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
        pluginm.interfaces += ["cmd","gui"]
    else:
        pluginm = None
    #logger().debug("start client")
    #global cm
    cm = gtkclient_init(confm, pluginm)
    if confm.getb("noplugins") == False:
        pluginm.resources["access"] = cm.links["client"].access_safe
        pluginm.resources["plugin"] = cm.links["client"].use_plugin
        pluginm.resources["open_node"] = open_gtk_node
        pluginm.init_plugins()
    do_gtkiteration()
    #del cm
    sys.exit(0)
