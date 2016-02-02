#! /usr/bin/env python3

import sys, os
import json
import multiprocessing
from threading import Lock #only for threads
import logging
multiprocessing.set_start_method('spawn')
from multiprocessing import Pipe




class plugincontroller(object):
    procinstance = None
    lock = None
    pluginpipe = None
    requestpipe = None
    uicreator = None
    
    def __init__(self, procinstance, pipe, requestpipe, uicreator=None):
        self.procinstance = procinstance
        self.lock = Lock()
        self.pluginpipe = pipe
        self.requestpipe = requestpipe
        self.uicreator = uicreator

    def __del__(self):
        self.procinstance.terminate()
    
    def access(self, command, *args, **kwargs):
        with self.lock:
            return self.pluginpipe.send((command, args, kwargs))
    
    def run(self):
        while True:
            try:
                command, args, kwargs = self.requestpipe.recv()
            except Exception:
                logging.error(exc)
                break
            try:
                res = getattr(plugininstance, command)(*args, **kwargs)
            except Exception as exc:
                logging.error(exc)
    
    @classmethod
    def create(plugin, name, path, plugin_config_path=None):
        parent_conn, child_conn = Pipe()
        parent_request, child_request = Pipe()
        proc = multiprocessing.Process(target=create_pluginshim, args=(child_conn, child_request, os.path.join(plugin_config_path, name+confdb_ending), path))
        if not proc.is_alive():
            return None
        return plugin(proc, parent_conn, parent_request)
        
    def create_uiinstance(self, *args, **kwargs):
        if self.uicreator is None:
            return None
        return self.uicreator(self.access, *args, **kwargs)
        


class pluginmanager(object):
    manager = None
    plugin_config_path = None
    pluginloader = None
    plugins = {}
    
    def __init__(self, manager, plugin_config_path):
        self.manager = manager
        self.plugin_config_path = plugin_config_path
    @classmethod
    def create(pluginm, pluginloader=plugincontroller, plugin_config_path=None):
        manager = multiprocessing.Manager()
        if manager is None:
            return None
        return pluginm(manager, plugin_config_path)
    
    def load_plugin(self, plugin):
        ret = self.plugincontroller.create(plugin, path, self.plugin_config_path)
        if ret:
            self.plugins[plugin] = ret
            return ret
        else:
            return None


class pluginshim(object):
    queue = None
    # requests from plugin
    requestpipe = None
    lock = None
    
    def __init__(self, pipe, requestpipe):
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
    

def create_pluginshim(pipe, requestpipe, path, plugin_config_path=None):
    pshim = pluginshim(pipe, requestpipe)
    try:
        ret = None
        #plugin_config_path:
        
    except Exception as e:
        logging.error(e)
    if ret:
        pshim.run(ret)

