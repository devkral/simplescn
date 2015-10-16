

import os
from common import configmanager, confdb_ending, check_argsdeco

class client_config(object): 
    validactions_config = {"set_config", "set_pluginconfig", "clean_pluginconfig", "reset_configkey", "reset_pluginconfigkey", "list_config", "list_pluginconfig", "get_pluginconfig", "get_config"}
    
    hashdb = None
    links = None
    cert_hash = None


    @check_argsdeco({"key": (str, "config key"), "value": (str, "key value")})
    def set_config(self, obdict):
        """ set key in main configuration of client """
        return self.links["configmanager"].set(obdict["key"], obdict["value"])

    @check_argsdeco({"key": (str, "config key"), "value": (str, "key value"), "plugin": (str, "plugin name")})
    def set_pluginconfig(self, obdict):
        """ set key in plugin configuration """
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

    @check_argsdeco({"key": (str, "config key"),})
    def reset_configkey(self, obdict):
        """ reset key in main configuration of client """
        return self.links["configmanager"].set_default(obdict["key"])
    
    @check_argsdeco({"key": (str, "config key"),})
    def get_config(self, obdict):
        """ get key in main configuration of client """
        return True, {"value": self.links["configmanager"].get(obdict["key"])}
    
    @check_argsdeco(optional={"onlypermanent":(bool, "shall only permanent settings be included (default: False)")})
    def list_config(self, obdict):
        """ list main configuration of client """
        return True, {"items": self.links["configmanager"].list(obdict.get("onlypermanent", False)), "map": ["key", "value", "converter", "default", "doc", "ispermanent"]}
    
    @check_argsdeco({"key": (str, "config key"), "plugin": (str, "plugin name")})
    def reset_pluginconfigkey(self, obdict):
        """ reset key in plugin configuration """
        pluginm=self.links["client_server"].pluginmanager
        listplugin = pluginm.list_plugins()
        if obdict["plugin"] not in listplugin:
            return False, "plugin does not exist"
        # last case shouldn't exist but be sure
        if obdict["plugin"] not in pluginm.plugins or hasattr(pluginm.plugins[obdict["plugin"]]) == False:
            config = configmanager(os.path.join(self.links["config_root"],"config","plugins","{}{}".format(obdict["plugin"], confdb_ending)))
        else:
            config = pluginm.plugins[obdict["plugin"]].config
        return config.set_default(obdict["key"])
        
    @check_argsdeco({"key": (str, "config key"), "plugin": (str, "plugin name")})
    def get_pluginconfig(self, obdict):
        """ get key in plugin configuration """
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
    
    @check_argsdeco()
    def clean_pluginconfig(self, obdict):
        """ clean orphan plugin configurations """
        pluginm=self.links["client_server"].pluginmanager
        pluginm.clean_plugin_config()
        return True
    
    
    @check_argsdeco({"plugin":(str,)}, optional={"onlypermanent":(bool, "shall only permanent settings be included (default: False)")})
    def list_pluginconfig(self, obdict):
        """ list plugin configuration """
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
