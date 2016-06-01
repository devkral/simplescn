#! /usr/bin/env python3

import sys
import json
import subprocess
import os
import socket
from threading import Lock, Thread
import logging
from simplescn import pluginconfigdefaults;


class pluginmanager(object):
    plugin_config_path = None
    wlock = None
    pathes_plugins = None
    pluginloader = None
    plugins = None
    interfaces = None
    redirect_addr = None
    uicreator = None
    portpoll = None
    portcom = None

    def __init__(self, pluginloader, portcom, pathes_plugins, path_plugins_config, scn_type, uicreator=None, tempdir="/tmp/"):
        self.plugins = {}
        self.interfaces = []
        self.redirect_addr = ""
        self.wlock = Lock()
        self.pluginloader = pluginloader
        self.portcom = portcom
        self.pathes_plugins = pathes_plugins
        self.uicreator = uicreator
        self.plugin_config_path = plugin_config_path
        self.interfaces.insert(0, scn_type)
        if hasattr(socket, "AF_UNIX"):
            self.portpoll = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.portpoll.bind(os.path.join(tempdir, "pluginmanager"))
        else:
            self.portpoll = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            self.portpoll.bind(("::1", 0))

    def run(self):
        while True:
            recvc = self.portpoll.recv(512)
            name, certhash = str(recvc, "utf-8", errors="ignore").rsplit("/", 1)
            if name not in self.plugins:
                continue
            self.plugins[name].update_ui(certhash)

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
            #remove .confdb from name
            if dbconf[:-len(confdb_ending)] not in lplugins:
                os.remove(os.path.join(self.path_plugins_config, dbconf))

    def load_pluginconfig(self, plugin_name, pluginpath=None):
        if pluginpath is None:
            pluginlist = self.list_plugins()
            pluginpath = pluginlist.get(plugin_name)
        if pluginpath is None:
            return None
        dbpath = os.path.join(self.path_plugins_config, "{}{}".format(plugin_name, confdb_ending))
        dbdefaults = os.path.join(pluginpath, plugin_name, pluginconfigdefaults)
        # no overlays for plugins
        if os.path.isfile(dbdefaults):
            pconf = configmanager.defaults_from_json(dbpath, jpath=dbdefaults, ensure={"pwhash": (str, "", "hashed password, empty for none")})
        else:
            pconf = configmanager(dbpath)
            pconf.update({"pwhash": (str, "", "hashed password, empty for none")})
        return pconf

    def load_plugin(self, name, path):
        pconf = self.load_pluginconfig(name)
        if pconf is None or not pconf.getb("state"):
            return
        ret = self.plugincontroller.create(os.path.join(path, name), self.portcom, self.portpoll, pconf.db_path, self.uicreator)
        if ret:
            with self.wlock:
                self.plugins[name] = ret
        
    def init_plugins(self):
        lplugins = self.list_plugins()
        _threads = []
        for plugin in lplugins.items():
            _threads.append(Thread(target=self.load_plugin, args=(plugin[0], plugin[1]), daemon=True))
            _threads[-1].start()
        for _thread in _threads:
            try:
                _thread.join()
            except Exception:
                pass

    def register_remote(self, _addr):
        self.redirect_addr = _addr

    def delete_remote(self):
        self.redirect_addr = ""


class plugincontroller(object):
    portcom = None
    portpoll = None
    procinstance = None
    uicreator = None
    lock = None

    def __init__(self, procinstance, portcom, portpoll, uicreator):
        self.portcom = portcom
        self.portpoll = portpoll
        self.uicreator = uicreator
        self.procinstance = procinstance
        self.lock = Lock()

    def __del__(self):
        self.procinstance.terminate()

    def update_ui(self, certhash):
        if self.uicreator:
            ui = self.uicreator.uis.get(certhash, None)
            if ui:
                ui.update(self.access("update_ui"))

    def access(self, command, *args, **kwargs):
        contentsend = json.dumps((command, args, kwargs))
        with self.lock:
            if self.procinstance.poll() is not None:
                return (False, "Plugin terminated")
            content = self.procinstance.communicate(contentsend, 15)[0]
        return json.loads(content)

    @classmethod
    def create(pluginccls, path, portcom, portpoll, plugin_config_path="", uicreator=None):
        pargs = [sys.executable, path, portcom, portpoll, plugin_config_path]
        proc = subprocess.Popen(pargs, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        # can miss a crash of a plugin with long loadtime
        
        if proc.poll() is not None:
            return None
        return pluginccls(proc, portcom, portpoll, uicreator)

    def create_uiinstance(self, certhash, *args, **kwargs):
        if self.uicreator is None:
            return None
        return self.uicreator.ui_node_session(self.access, certhash *args, **kwargs)

