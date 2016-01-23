#! /usr/bin/env python3
#license: bsd3, see LICENSE.txt

import sys, os

if __name__ == "__main__":
    _tpath = os.path.realpath(os.path.dirname(sys.modules[__name__].__file__))
    _tpath = os.path.dirname(_tpath)
    sys.path.insert(0, _tpath)

import logging
import signal

import simplescn
from simplescn import sharedir, confdb_ending,logformat
from simplescn.common import scnparse_args
import simplescn.client
import simplescn.server


def signal_handler(_signal, frame):
    simplescn.client.client_init.run = False
    logging.shutdown()
    sys.exit(0)

def server():
    from simplescn.common import pluginmanager
    from simplescn.server import server_paramhelp, overwrite_server_args, server_handler, server_init
    pluginpathes = [os.path.join(sharedir, "plugins")]
    pluginpathes += scnparse_args(server_paramhelp, overwrite_args=overwrite_server_args)
    configpath = overwrite_server_args["config"][0]
    configpath = os.path.expanduser(configpath)
    if configpath[-1] == os.sep:
        configpath = configpath[:-1]
    overwrite_server_args["config"][0] = configpath
    # path  to plugins in config folder
    pluginpathes.insert(1, os.path.join(configpath, "plugins"))
    # path to config folder of plugins
    configpath_plugins = os.path.join(configpath, "config", "plugins")
    
    #should be gui agnostic so specify here
    if overwrite_server_args["webgui"][0] != "False":
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

    cm = server_init(configpath ,**overwrite_server_args)
    if overwrite_server_args["useplugins"][0] != "False":
        os.makedirs(configpath_plugins, 0o750, True)
    
        pluginm = pluginmanager(pluginpathes, configpath_plugins, "server")
        if overwrite_server_args["webgui"] != "False":
            pluginm.interfaces+=["web",]
        cm.links["server_server"].pluginmanager = pluginm
        pluginm.resources["access"] = cm.links["server_server"].access_server
        pluginm.init_plugins()
        _broadc = cm.links["server_server"].allowed_plugin_broadcasts
        for _name, plugin in pluginm.plugins.items():
            if hasattr(plugin, "allowed_plugin_broadcasts"):
                for _broadfuncname in getattr(plugin, "allowed_plugin_broadcasts"):
                    _broadc.insert((_name, _broadfuncname))
        
    logging.debug("server initialized. Enter serveloop")
    cm.serve_forever_block()


def rawclient():
    from simplescn.common import pluginmanager, configmanager
    from simplescn.client import client_paramhelp, overwrite_client_args, default_client_args, cmdloop, client_init
    pluginpathes = [os.path.join(sharedir, "plugins")]
    pluginpathes += scnparse_args(client_paramhelp, default_client_args, overwrite_client_args)
    configpath = overwrite_client_args["config"][0]
    configpath = os.path.expanduser(configpath)
    if configpath[-1] == os.sep:
        configpath = configpath[:-1]
    overwrite_client_args["config"][0] = configpath
    # path  to plugins in config folder
    pluginpathes.insert(1, os.path.join(configpath, "plugins"))
    # path to config folder of plugins
    configpath_plugins = os.path.join(configpath, "config", "plugins")
    
    os.makedirs(os.path.join(configpath, "config"), 0o750, True)
    os.makedirs(configpath_plugins, 0o750, True)
    
    confm = configmanager(os.path.join(configpath, "config", "clientmain{}".format(confdb_ending)))
    confm.update(default_client_args, overwrite_client_args)
    if confm.getb("noplugins") == False:
        pluginm = pluginmanager(pluginpathes, configpath_plugins, "client")
        if confm.getb("webgui") != False:
            pluginm.interfaces += ["web",]
        if confm.getb("nocmd") == False:
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

    logging.debug("start servercomponent (client)")
    if confm.getb("nocmd") == False:
        cm.serve_forever_nonblock()
        logging.debug("start console")
        for name, value in cm.links["client"].show({})[1].items():
            print(name, value, sep=":")
        cmdloop(cm)
    
    else:
        cm.serve_forever_block()


def client():
    try:
        client_gtk()
    except Exception as e:
        logging.error(e)
        rawclient()
        return
def client_gtk():
    from simplescn.guigtk.clientmain import _gtkclient_init_method
    from simplescn.common import pluginmanager, configmanager
    from simplescn.client import client_paramhelp, overwrite_client_args, default_client_args
    
    del default_client_args["nocmd"]
    pluginpathes = [os.path.join(sharedir, "plugins")]
    pluginpathes += scnparse_args(client_paramhelp, default_client_args, overwrite_client_args)
    configpath = overwrite_client_args["config"][0]
    configpath = os.path.expanduser(configpath)
    if configpath[-1] == os.sep:
        configpath = configpath[:-1]
    overwrite_client_args["config"][0] = configpath
    pluginpathes.insert(1, os.path.join(configpath, "plugins"))
    configpath_plugins = os.path.join(configpath, "config", "plugins")

    os.makedirs(os.path.join(configpath, "config"), 0o750, True)
    os.makedirs(configpath_plugins, 0o750, True)
    confm = configmanager(os.path.join(configpath, "config", "clientgtkgui{}".format(confdb_ending)))
    confm.update(default_client_args, overwrite_client_args)

    if confm.getb("noplugins") == False:
        pluginm = pluginmanager(pluginpathes, configpath_plugins, "client")
        if confm.getb("webgui") != False:
            pluginm.interfaces += ["web",]
        pluginm.interfaces += ["cmd","gtk"]
    else:
        pluginm = None
    _gtkclient_init_method(confm, pluginm)


def config_plugin():
    from simplescn.common import overwrite_plugin_config_args, plugin_config_paramhelp
    pluginpathes = [os.path.join(sharedir, "plugins")]
    pluginpathes += scnparse_args(plugin_config_paramhelp, overwrite_args=overwrite_plugin_config_args)
    configpath = overwrite_plugin_config_args["config"][0]
    configpath = os.path.expanduser(configpath)
    if configpath[-1] == os.sep:
        configpath = configpath[:-1]
    overwrite_plugin_config_args["config"][0] = configpath
    # path  to plugins in config folder
    pluginpathes.insert(1, os.path.join(configpath, "plugins"))
    # path to config folder of plugins
    configpath_plugins = os.path.join(configpath, "config", "plugins")

    os.makedirs(os.path.join(configpath, "config"), 0o750, True)
    os.makedirs(configpath_plugins, 0o750, True)
    
    pluginm = pluginmanager(pluginpathes, configpath_plugins, "config_direct")
    pluginm.init_plugins()
    if overwrite_plugin_config_args["plugin"][0] not in pluginm.plugins:
        config = pluginm.load_pluginconfig(overwrite_plugin_config_args["plugin"][0])
        
    else:
        config = pluginm.plugins[overwrite_plugin_config_args["plugin"][0]][1]
    config.set("defaul")

def _init_method():
    import logging
    logging.basicConfig(level=logging.DEBUG, format=logformat)
    
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
