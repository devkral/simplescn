#! /usr/bin/env python3

import sys, os

if __name__ == "__main__":
    _tpath = os.path.realpath(os.path.dirname(sys.modules[__name__].__file__))
    _tpath = os.path.dirname(_tpath)
    sys.path.insert(0, _tpath)

import simplescn
from simplescn import sharedir, confdb_ending
import simplescn.client
import simplescn.server

from simplescn import logger
import signal

def signal_handler(_signal, frame):
    simplescn.client.run = False
    sys.exit(0)

def server():
    from simplescn.common import pluginmanager
    from simplescn.server import server_paramhelp, server_args, server_handler, server_init
    if len(sys.argv) > 1:
        tparam=()
        for elem in sys.argv[1:]: #strip filename from arg list
            elem= elem.strip("-")
            if elem in ["help","h"]:
                server_paramhelp()
                sys.exit(0)
            else:
                tparam = elem.split("=")
                if len(tparam) == 1:
                    tparam=elem.split(":")
                if len(tparam) == 1:
                    server_args[tparam[0]] = "True"
                    continue
                server_args[tparam[0]] = tparam[1]
    
    configpath = os.path.expanduser(server_args["config"])
    if configpath[-1] == os.sep:
        configpath = configpath[:-1]
    #should be gui agnostic so specify here
    if server_args["webgui"] is not None:
        server_handler.webgui = True
        #load static files  
        for elem in os.listdir(os.path.join(sharedir, "static")):
            with open(os.path.join(sharedir, "static", elem), 'rb') as _staticr:
                server_handler.statics[elem]=_staticr.read()
                #against ssl failures
                if len(server_handler.statics[elem]) == 0:
                    server_handler.statics[elem] = b" "
    else:
        server_handler.webgui = False

    cm = server_init(configpath ,**server_args)
    if server_args["useplugins"] is not None:
        pluginpathes = [os.path.join(sharedir, "plugins")]
        pluginpathes.insert(1, os.path.join(configpath, "plugins"))
        configpath_plugins = os.path.join(configpath, "config", "plugins")

        os.makedirs(configpath_plugins, 0o750, True)
    
        pluginm = pluginmanager(pluginpathes, configpath_plugins, "server")
        if server_args["webgui"] is not None:
            pluginm.interfaces+=["web",]
        cm.links["server_server"].pluginmanager = pluginm
        pluginm.resources["access"] = cm.links["server_server"].access_server
        pluginm.init_plugins()
        _broadc = cm.links["server_server"].allowed_plugin_broadcasts
        for _name, plugin in pluginm.plugins.items():
            if hasattr(plugin, "allowed_plugin_broadcasts"):
                for _broadfuncname in getattr(plugin, "allowed_plugin_broadcasts"):
                    _broadc.insert((_name, _broadfuncname))
        
    logger().debug("server initialized. Enter serveloop")
    cm.serve_forever_block()


def rawclient():
    from simplescn.common import pluginmanager, configmanager
    from simplescn.client import client_paramhelp, client_args, default_client_args, cmdloop, client_init
    pluginpathes = [os.path.join(sharedir, "plugins")]
    if len(sys.argv) > 1:
        tparam = ()
        for elem in sys.argv[1:]: #strip filename from arg list
            elem = elem.strip("-")
            if elem in ["help","h"]:
                print(client_paramhelp())
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
    # path  to plugins in config folder
    pluginpathes.insert(1, os.path.join(configpath, "plugins"))
    
    # path to config folder of plugins
    configpath_plugins = os.path.join(configpath, "config", "plugins")
    #if configpath[:-1]==os.sep:
    #    configpath=configpath[:-1]
    
    os.makedirs(os.path.join(configpath, "config"), 0o750, True)
    os.makedirs(configpath_plugins, 0o750, True)
    
    confm = configmanager(os.path.join(configpath, "config", "clientmain{}".format(confdb_ending)))
    confm.update(default_client_args, client_args)
    if confm.getb("noplugins") == False:
        pluginm = pluginmanager(pluginpathes, configpath_plugins, "client")
        if confm.getb("webgui") != False:
            pluginm.interfaces += ["web",]
        if confm.getb("cmd") != False:
            pluginm.interfaces += ["cmd",]
    else:
        pluginm = None
    cm = client_init(confm,pluginm)

    if confm.getb("noplugins") == False:
        pluginm.resources["plugin"] = cm.links["client"].use_plugin
        pluginm.resources["access"] = cm.links["client"].access_safe
        pluginm.init_plugins()
        #for name, elem in pluginm.plugins.items():
        #    if hasattr(elem, "pluginpw"):
        #        cm.links["auth_server"].init_realm("plugin:{}".format(name), dhash(elem.pluginpw))

    logger().debug("start servercomponent (client)")
    if confm.getb("cmd") != False:
        cm.serve_forever_nonblock()
        logger().debug("start console")
        for name, value in cm.links["client"].show({})[1].items():
            print(name, value, sep=":")
        cmdloop(cm)
    
    else:
        cm.serve_forever_block()


def client():
    try:
        client_gtk()
    except Exception as e:
        print(e)
        client_cmd()
        return
def client_gtk():
    from simplescn.guigtk.clientmain import _gtkclient_init_method
    from simplescn.common import pluginmanager, configmanager
    from simplescn.client import client_paramhelp, client_args, default_client_args
    dclargs = default_client_args.copy()
    del dclargs["cmd"]
    pluginpathes = [os.path.join(sharedir, "plugins")]
    if len(sys.argv) > 1:
        tparam = ()
        for elem in sys.argv[1:]: #strip filename from arg list
            elem = elem.strip("-")
            if elem in ["help", "h"]:
                client_paramhelp()
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
    _gtkclient_init_method(confm, pluginm)
    


def _init_method():
    import logging
    from simplescn import scn_logger, init_logger
    init_logger(scn_logger())
    logger().setLevel(logging.DEBUG)
    signal.signal(signal.SIGINT, signal_handler)
    
    #pluginpathes.insert(1, os.path.join(configpath, "plugins"))
    #plugins_config = os.path.join(configpath, "config", "plugins")
    if len(sys.argv)>1:
        toexe = sys.argv[1]
        toexe = globals().get(toexe)
        if toexe:
            del sys.argv[1]
            toexe()
        else:
            print("Not available")
            print("Available: client, rawclient, server")
    else:
        client()

if __name__ == "__main__":
    _init_method()
