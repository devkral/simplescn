#! /usr/bin/env python3
#license: bsd3, see LICENSE.txt

import sys, os
import logging, threading
import signal

if __name__ == "__main__":
    _tpath = os.path.realpath(os.path.dirname(sys.modules[__name__].__file__))
    _tpath = os.path.dirname(_tpath)
    sys.path.insert(0, _tpath)


import simplescn
from simplescn import sharedir, confdb_ending, logformat, default_loglevel, loglevel_converter
from simplescn.common import scnparse_args
import simplescn.client
import simplescn.server



def signal_handler(_signal, frame):
    simplescn.client.client_init.run = False
    logging.shutdown()
    sys.exit(0)

def server(argv=sys.argv[1:], doreturn=False):
    init_scn()
    from simplescn.common import pluginmanager
    from simplescn.server import server_paramhelp, overwrite_server_args, server_init
    pluginpathes = [os.path.join(sharedir, "plugins")]
    pluginpathes += scnparse_args(argv, server_paramhelp, overwrite_args=overwrite_server_args)
    configpath = overwrite_server_args["config"][0]
    configpath = os.path.expanduser(configpath)
    if configpath[-1] == os.sep:
        configpath = configpath[:-1]
    overwrite_server_args["config"][0] = configpath
    # path  to plugins in config folder
    pluginpathes.insert(1, os.path.join(configpath, "plugins"))
    # path to config folder of plugins
    configpath_plugins = os.path.join(configpath, "config", "plugins")

    server_instance = server_init(configpath, **overwrite_server_args)
    if overwrite_server_args["useplugins"][0] != "False":
        os.makedirs(configpath_plugins, 0o750, True)
        pluginm = pluginmanager(pluginpathes, configpath_plugins, "server")
        if overwrite_server_args["webgui"] != "False":
            pluginm.interfaces += ["web",]
        server_instance.links["server_server"].pluginmanager = pluginm
        pluginm.resources["access"] = server_instance.links["server_server"].access_server
        pluginm.init_plugins()
        _broadc = server_instance.links["server_server"].allowed_plugin_broadcasts
        for _name, plugin in pluginm.plugins.items():
            if hasattr(plugin, "allowed_plugin_broadcasts"):
                for _broadfuncname in getattr(plugin, "allowed_plugin_broadcasts"):
                    _broadc.insert((_name, _broadfuncname))
    if overwrite_server_args["noserver"][0] != "True":
        logging.debug("server initialized. Enter serveloop")
        if doreturn:
            server_instance.serve_forever_nonblock()
            return server_instance
        else:
            server_instance.serve_forever_block()
    else:
        print("You really want a server without a server?", file=sys.stderr)

def rawclient(argv=sys.argv[1:], doreturn=False):
    """ cmd client """
    init_scn()
    from simplescn.common import pluginmanager, configmanager
    from simplescn.client import client_paramhelp, overwrite_client_args, default_client_args, cmdloop, client_init
    pluginpathes = [os.path.join(sharedir, "plugins")]
    pluginpathes += scnparse_args(argv, client_paramhelp, default_client_args, overwrite_client_args)
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
        if confm.getb("webgui") == True:
            pluginm.interfaces += ["web",]
        if confm.getb("nocmd") == False:
            pluginm.interfaces += ["cmd",]
    else:
        pluginm = None
    rawclient_instance = client_init(confm, pluginm)

    if confm.getb("noplugins") == False:
        pluginm.resources["plugin"] = rawclient_instance.links["client"].use_plugin
        pluginm.resources["access"] = rawclient_instance.links["client"].access_safe
        pluginm.init_plugins()
        #for name, elem in pluginm.plugins.items():
        #    if hasattr(elem, "pluginpw"):
        #        rawclient_instance.links["auth_server"].init_realm("plugin:{}".format(name), dhash(elem.pluginpw))

    if not confm.getb("noserver"):
        logging.debug("start servercomponent (client)")
    if not confm.getb("nocmd"):
        if not confm.getb("noserver"):
            rawclient_instance.serve_forever_nonblock()
        logging.debug("start console")
        for name, value in rawclient_instance.links["client"].show({})[1].items():
            print(name, value, sep=":")
        if doreturn:
            threading.Thread(target=cmdloop, args=(rawclient_instance,), daemon=True).start()
            return rawclient_instance
        else:
            cmdloop(rawclient_instance)
    elif not confm.getb("noserver"):
        if doreturn:
            rawclient_instance.serve_forever_nonblock()
            return rawclient_instance
        else:
            rawclient_instance.serve_forever_block()


def client(argv=sys.argv[1:]):
    """ gui client """
    try:
        client_gtk(argv)
    except Exception as exc:
        raise(exc)
        logging.error(exc)
        rawclient(argv)
        return
def client_gtk(argv=sys.argv[1:]):
    """ gtk gui """
    init_scn()
    from simplescn.guigtk.clientmain import _init_method_gtkclient
    from simplescn.common import pluginmanager, configmanager
    from simplescn.client import client_paramhelp, overwrite_client_args, default_client_args

    del default_client_args["nocmd"]
    default_client_args["backlog"] = [str(200), int, "length of backlog"]
    pluginpathes = [os.path.join(sharedir, "plugins")]
    pluginpathes += scnparse_args(argv, client_paramhelp, default_client_args, overwrite_client_args)
    configpath = overwrite_client_args["config"][0]
    configpath = os.path.expanduser(configpath)
    if configpath[-1] == os.sep:
        configpath = configpath[:-1]
    overwrite_client_args["config"][0] = configpath
    pluginpathes.insert(1, os.path.join(configpath, "plugins"))
    configpath_plugins = os.path.join(configpath, "config", "plugins")

    os.makedirs(os.path.join(configpath, "config"), 0o750, True)
    os.makedirs(configpath_plugins, 0o750, True)
    # uses different configuration file than rawclient
    confm = configmanager(os.path.join(configpath, "config", "clientgtkgui{}".format(confdb_ending)))
    confm.update(default_client_args, overwrite_client_args)

    if confm.getb("noplugins") == False:
        pluginm = pluginmanager(pluginpathes, configpath_plugins, "client")
        if confm.getb("webgui") != False:
            pluginm.interfaces += ["web",]
        pluginm.interfaces += ["cmd", "gtk"]
    else:
        pluginm = None
    _init_method_gtkclient(confm, pluginm)

def hashpw():
    """ create pw hash for ?pwhash """
    init_scn()
    from simplescn import dhash
    import base64
    if len(sys.argv) < 2 or sys.argv[1] in ["--help", "help"]:
        print("Usage: {} hashpw <pw>/\"random\"".format(sys.argv[0]))
        return
    pw = sys.argv[1]
    if pw == "random":
        pw = str(base64.urlsafe_b64encode(os.urandom(10)), "utf-8")
    print("pw: {}, hash: {}".format(pw, dhash(pw)))

def config_plugin(argv=sys.argv[1:]):
    """ func: configure plugin without starting gui (useful for server plugins)
        plugin: plugin name
        key: unspecified: list keys
        value: unspecified: get value, else: set value """
    init_scn()
    from simplescn.common import overwrite_plugin_config_args, plugin_config_paramhelp, pluginmanager
    pluginpathes = [os.path.join(sharedir, "plugins")]
    pluginpathes += scnparse_args(argv, plugin_config_paramhelp, overwrite_args=overwrite_plugin_config_args)
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
    #pluginm.init_plugins()
    config = pluginm.load_pluginconfig(overwrite_plugin_config_args["plugin"][0])
    if config is None:
        logging.error("No such plugin: {}".format(overwrite_plugin_config_args["plugin"][0]))
        return
    if overwrite_plugin_config_args["key"][0] == "":
        lres = config.list()
        if isinstance(lres, (tuple, list)) == False:
            return
        for key, val, cls, default, doc, perm in lres:
            print("* key: {}\n  * type: {}\n  * perm: {}\n  * val: {}\n  * default: {}\n  * doc: {}".format(key, type(cls).__name__, perm, val, default, doc))
    elif overwrite_plugin_config_args["value"][0] == "":
        key = overwrite_plugin_config_args["key"][0]
        res1 = config.get_meta(key)
        if isinstance(res1, (tuple, list)) == False:
            return
        val = config.get(key)
        default = config.get_default(key)
        cls, doc, perm = res1
        print("# key: {}\n  * type: {}\n  * perm: {}\n  * val: {}\n  * default: {}\n  * doc: {}".format(key, type(cls).__name__, perm, val, default, doc))
    else:
        print(config.set(overwrite_plugin_config_args["key"][0], overwrite_plugin_config_args["value"][0]))

def check_dependencies():
    try:
        import markdown
    except ImportError:
        print("No markdown support", file=sys.stderr)
    
    try:
        import gi
    except ImportError:
        print("No gtkgui (gobject) support", file=sys.stderr)

is_init_already = False
def init_scn():
    global is_init_already
    #import multiprocessing
    #multiprocessing.freeze_support()
    #multiprocessing.set_start_method('spawn')
    if not is_init_already and threading.current_thread() == threading.main_thread():
        is_init_already = True
        logging.basicConfig(level=loglevel_converter(default_loglevel), format=logformat)
        signal.signal(signal.SIGINT, signal_handler)

def init_method_main():
    """ starter method """

    #pluginpathes.insert(1, os.path.join(configpath, "plugins"))
    #plugins_config = os.path.join(configpath, "config", "plugins")
    if len(sys.argv) > 1:
        toexe = sys.argv[1]
        if toexe in ["init_scn", "signal_handler"]:
            return
        toexe = globals().get(toexe)
        if callable(toexe):
            #del sys.argv[1]
            toexe(sys.argv[2:])
        else:
            print("Not available", file=sys.stderr)
            print("Available: client, rawclient, server, config_plugin, hashpw, check_dependencies", file=sys.stderr)
    else:
        check_dependencies()
        client()

if __name__ == "__main__":
    init_method_main()
