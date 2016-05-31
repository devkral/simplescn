#! /usr/bin/env python3

import sys, os
import json
import struct
import subprocess
import selectors
import socket
from threading import RLock
import logging
from simplescn import pluginconfigdefaults;


detsize_format = "@QB"
detsize_size = struct.calcsize(detsize_format)
retrieve_format = "@{}s"


class pluginmanager(object):
    plugin_config_path = None
    pathes_plugins = None
    pluginloader = None
    resources = None
    plugins = None
    interfaces = None
    redirect_addr = None
    uicreator = None
    
    def __init__(self, pluginloader, pathes_plugins, path_plugins_config, scn_type, resources, uicreator=None):
        if resources is None:
            self.resources = {}
        else:
            self.resources = resources
        self.plugins = {}
        self.interfaces = []
        self.redirect_addr = ""
        self.pluginloader = pluginloader
        self.pathes_plugins = pathes_plugins
        self.uicreator = uicreator
        self.plugin_config_path = plugin_config_path
        self.interfaces.insert(0, scn_type)

    def list_plugins(self):
        temp = {}
        for path in self.pathes_plugins:
            if os.path.isdir(path):
                for plugin in os.listdir(path):
                    if plugin in ["__pycache__", ""] or plugin[0] in " \t\b" or plugin[-1] in " \t\b":
                        continue
                    newpath = os.path.join(path, plugin)
                    if os.path.isdir(newpath) and os.path.isfile(os.path.join(newpath, pluginstartfile)) and plugin not in temp:
                        temp[plugin] = path
        return temp

    def plugin_is_active(self, plugin):
        pconf = configmanager(os.path.join(self.path_plugins_config, "{}{}".format(plugin, confdb_ending)))
        return pconf.getb("state")

    def clean_plugin_config(self):
        lplugins = self.list_plugins()
        lconfig = os.listdir(self.path_plugins_config)
        for dbconf in lconfig:
            #remove .confdb
            if dbconf[:-len(confdb_ending)] not in lplugins:
                os.remove(os.path.join(self.path_plugins_config, dbconf))

    def load_pluginconfig(self, plugin_name):
        pluginlist = self.list_plugins()
        pluginpath = pluginlist.get(plugin_name)
        if pluginpath is None:
            return None
        defaults = {}
        with open(os.path.join(self.path_plugins_config, "{}{}".format(plugin_name, pluginconfigdefaults)), "r") as obread:
            defaults = json.load(obread)
        defaults["state"] = ("False", bool, "is plugin active")
        pconf = configmanager(os.path.join(self.path_plugins_config, "{}{}".format(plugin_name, confdb_ending)))
        pconf.update(defaults)
        return pconf

    def init_plugins(self):
        for plugin in self.list_plugins():
            pconf = configmanager(os.path.join(self.path_plugins_config, "{}{}".format(plugin[0], confdb_ending)))
            
            if not pconf.getb("state"):
                continue
            defaults = {}
            try:
                with open(os.path.join(self.path_plugins_config, "{}{}".format(plugin_name, pluginconfigdefaults)), "r") as obread:
                    defaults = json.load(obread)
            except Exception:
                logging.info("Plugin: {} has no config".format(plugin[0]))
            
            defaults["state"] = ("False", bool, "is plugin active")
            pconf.update(defaults)
            ret = self.plugincontroller.create(plugin[1], self.resources, pconf, self.uicreator)
            if ret:
                self.plugins[plugin[0]] = ret

    def register_remote(self, _addr):
        self.redirect_addr = _addr

    def delete_remote(self):
        self.redirect_addr = ""


class plugincontroller(object):
    procinstance = None
    uicreator = None
    resources = None
    sel = None
    lock = None

    def __init__(self, procinstance, resources, uicreator):
        self.procinstance = procinstance
        self.uicreator = uicreator
        self.resources = resources
        self.lock = RLock()
        self.sel = selectors.DefaultSelector()
        self.sel.register(procinstance.stdout, selectors.EVENT_READ)

    def __del__(self):
        self.procinstance.terminate()
    
    def access(self, command, *args, **kwargs):
        contentsend = bytes(json.dumps((command, args, kwargs)), "utf-8")
        with self.lock:
            if self.procinstance.poll() is not None:
                return (False, "Plugin terminated")
            self.sel.unregister(self.procinstance.stdout)
            self.procinstance.stdin.write(struct.pack(detsize_format, len(contentsend), 0))
            self.procinstance.stdin.write(contentsend)
            size, turn = struct.unpack(detsize_format, con.read(detsize_size))
            content = str(con.read(size), "utf-8")
            self.sel.register(self.procinstance.stdout, selectors.READ)
            return json.loads(content)
    
    def read(self):
        with self.lock:
            size, turn = struct.unpack(detsize_format, self.procinstance.stdout.read(detsize_size))
            if turn != 1:
                return
            #_size = struct.calcsize(retrieve_format.format(size))
            #content = struct.unpack(retrieve_format.format(size), con.read(_size)
            content = str(self.procinstance.stdout.read(size), "utf-8")
            command, args, kwargs = json.loads(content)
            res = self.resources.get(command, lambda *args, **kwargs: (False, "resource does not exist"))
            contentret = bytes(json.dumps(res), "utf-8")
            self.procinstance.stdin.write(struct.pack(detsize_format, len(contentret), 1))
            self.procinstance.stdin.write(contentret)

    @classmethod
    def create(pluginccls, path, resources, configm=None, uicreator=None):
        proc = create_plugin(path, configm)
        if proc.poll() is not None:
            return None
        return pluginccls(proc, resources, uicreator)

    def create_uiinstance(self, *args, **kwargs):
        if self.uicreator is None:
            return None
        return self.uicreator(self.access, *args, **kwargs)
    
    def event_loop(self):
        while True:
            events = p.sel.select()
            for key, mask in events:
                self.read()




class pluginshim(object):
    queue = None
    # requests from plugin
    requestpipe = None
    lock = None
    
    def __init__(self, pipe, requestpipe,):
        QueueHandler.__init__(self, pipe)
        self.plugininstance = plugininstance
        #logging.root.removeHandler(logging.root.handlers[0])
        #logging.root.addHandler(self)
        self.requestpipe = requestpipe
        self.lock = Lock()
    
    #def enqueue(self, record):
    #    self.queue.send([False, record])
        
    def access(self, command, *args, **kwargs):
        with self.lock:
            return self.pluginpipe.send((command, args, kwargs))
    
    def run(self, plugininstance):
        while True:
            try:
                command, args, kwargs = self.queue.recv()
            except Exception:
                break
            try:
                self.queue.send(getattr(plugininstance, command)(*args, **kwargs))
            except Exception as exc:
                logging.error(exc)
    

def create_plugin(path, plugin_config_path=None):
    pshim = pluginshim(pipe, requestpipe, plugin_config_path)
    try:
        ret = pluginshim.create(path)
    except Exception as e:
        logging.error(e)
    if ret:
        pshim.run(ret)

