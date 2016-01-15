

import os
from simplescn import confdb_ending, check_argsdeco, classify_local, classify_noplugin, classify_admin
from simplescn.common import configmanager

class client_config(object): 
    validactions_config = {"set_config", "set_pluginconfig", "clean_pluginconfig", "reset_configkey", "reset_pluginconfigkey", "list_config", "list_pluginconfig", "get_pluginconfig", "get_config"}
    
    hashdb = None
    links = None
    cert_hash = None


    @check_argsdeco({"key": str, "value": str})
    @classify_admin
    @classify_noplugin
    @classify_local
    def set_config(self, obdict):
        """ func: set key in main configuration of client
            return: success or error
            key: config key
            value: config value """
        return self.links["configmanager"].set(obdict["key"], obdict["value"])


    @check_argsdeco({"key": str})
    @classify_admin
    @classify_noplugin
    @classify_local
    def reset_configkey(self, obdict):
        """ func: reset key in main configuration of client
            return: success or error
            key: config key """
        return self.links["configmanager"].set_default(obdict["key"])
    
    
    @check_argsdeco({"key": str})
    @classify_admin
    @classify_noplugin
    @classify_local
    def get_config(self, obdict):
        """ func: get key in main configuration of client
            return: key value
            key: config key """
        return True, {"value": self.links["configmanager"].get(obdict["key"])}
    
    
    @check_argsdeco(optional={"onlypermanent": bool})
    @classify_admin
    @classify_noplugin
    @classify_local
    def list_config(self, obdict):
        """ func: list main configuration of client
            return: key, value, ...
            onlypermanent: list only permanent settings (default: False) """
        return True, {"items": self.links["configmanager"].list(obdict.get("onlypermanent", False)), "map": ["key", "value", "converter", "default", "doc", "ispermanent"]}

    
    @check_argsdeco({"key": str, "value": str, "plugin": str})
    @classify_admin
    @classify_noplugin
    @classify_local
    def set_pluginconfig(self, obdict):
        """ func: set key in plugin configuration
            return: success or error
            key: config key
            value: config value
            plugin: plugin name """
        pluginm=self.links["client_server"].pluginmanager
        listplugin = pluginm.list_plugins()
        if obdict["plugin"] not in listplugin:
            return False, "plugin does not exist"
        # last case shouldn't exist but be sure
        if obdict["plugin"] not in pluginm.plugins or hasattr(pluginm.plugins[obdict["plugin"]], "config") == False:
            config = configmanager(os.path.join(self.links["config_root"],"config","plugins","{}{}".format(obdict["plugin"], confdb_ending)))
        else:
            config = pluginm.plugins[obdict["plugin"]].config
        return config.set(obdict["key"], obdict["value"])

    
    @check_argsdeco({"key": str, "plugin": str})
    @classify_admin
    @classify_noplugin
    @classify_local
    def reset_pluginconfigkey(self, obdict):
        """ func: reset key in plugin configuration
            return: success or error
            key: config key
            plugin: plugin name """
        pluginm=self.links["client_server"].pluginmanager
        listplugin = pluginm.list_plugins()
        if obdict["plugin"] not in listplugin:
            return False, "plugin does not exist"
        # last case shouldn't exist but be sure
        if obdict["plugin"] not in pluginm.plugins or hasattr(pluginm.plugins[obdict["plugin"]]) == False:
            config = configmanager(os.path.join(self.links["config_root"],"config","plugins","{}{}".format(obdict["plugin"], confdb_ending)))
        else:
            config = pluginm.plugins[obdict["plugin"]].config
        return config.set_default(str(obdict["key"]))
    
    
    @check_argsdeco({"key": str, "plugin": str})
    @classify_admin
    @classify_noplugin
    @classify_local
    def get_pluginconfig(self, obdict):
        """ func: get key in plugin configuration
            return: key value
            key: config key
            plugin: plugin name """
        pluginm=self.links["client_server"].pluginmanager
        listplugin = pluginm.list_plugins()
        if obdict["plugin"] not in listplugin:
            return False, "plugin does not exist"
        # last case shouldn't exist but be sure
        if obdict["plugin"] not in pluginm.plugins or hasattr(pluginm.plugins[obdict["plugin"]])==False:
            config = configmanager(os.path.join(self.links["config_root"],"config","plugins","{}{}".format(obdict["plugin"], confdb_ending)))
        else:
            config = pluginm.plugins[obdict["plugin"]].config
        return True, {"value": config.get(obdict["key"])}
    
    
    @check_argsdeco({"plugin": str}, optional={"onlypermanent": bool})
    @classify_admin
    @classify_noplugin
    @classify_local
    def list_pluginconfig(self, obdict):
        """ func: list plugin configuration
            return: key, value, ...
            onlypermanent: list only permanent settings (default: False)
            plugin: plugin name """
        pluginm = self.links["client_server"].pluginmanager
        listplugin = pluginm.list_plugins()
        if obdict["plugin"] not in listplugin:
            return False, "plugin does not exist"
        # last case shouldn't exist but be sure
        if obdict["plugin"] not in pluginm.plugins or hasattr(pluginm.plugins[obdict["plugin"]], "config") == False:
            _config = configmanager(os.path.join(self.links["config_root"],"config","plugins","{}{}".format(obdict["plugin"], confdb_ending)))
        else:
            _config = pluginm.plugins[obdict["plugin"]].config
        return True, {"items": _config.list(obdict.get("onlypermanent", False)), "map": ["key", "value", "converter", "default", "doc", "ispermanent"]}

    
    @check_argsdeco()
    @classify_admin
    @classify_noplugin
    @classify_local
    def clean_pluginconfig(self, obdict):
        """ func: clean orphan plugin configurations
            return: success or error """
        pluginm=self.links["client_server"].pluginmanager
        pluginm.clean_plugin_config()
        return True
