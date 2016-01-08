

###### used by pluginmanager ######

# defaults for config (needed)
config_defaults={}

# interfaces, config, accessable resources (communication with main program), pluginpath, logger
# return None deactivates plugin
def init(interfaces, config, resources, proot, logger):
    print("Hello World")
    return sample_test(interfaces, config, resources, proot, logger)

###### used by pluginmanager end ######



class sample_test(object):
    interfaces = None
    config = None
    resources = None
    proot = None
    logger = None
    
    def __init__(interfaces, config, resources, proot, logger):
        self.interfaces, self.config, self.resources, self.proot, self.logger = interfaces, config, resources, proot, logger
        
    # localized name
    #lname = {"*": "global name", "de": "German name", "de_DE": "German Germany name"}
    
    # dict, just shows up in cmd, do localisation in plugin 
    # please don't localise dict keys
    cmd_node_actions={"foo-action": (self.sampleaction_cmd, "unlocalized description")}

    # do it this way
    cmd_node_localized_actions={"Aktion": "foo-action"}

    # iterable, for node actions, just shows up in gui, do localization in plugin
    gui_node_actions=[{"text":"foo-actionname","action": self.sampleaction, "icon":"optionalfoo-iconlocation", \
"interfaces": ["gtk",], "description": "foo"}, ]

    # iterable, for server actions, just shows up in gui, do localization in plugin
    gui_server_actions=[{"text":"foo-actionname","action":self.sampleaction, "icon":"optionalfoo-iconlocation", \
"interfaces": ["gtk",], "description": "foo"}, ]

    def sampleaction(self, gui, url, window, certhash, dheader):
        print("Hello actions: ", url, gui)


    def sampleaction_cmd(self):
        print("Hello actions world")
        return "Hello actions world"


    #def gui_server_iface(self, gui, _name, _hash, _addressfunc):
    #    pass
    #    return widget

    #def gui_node_iface(self, gui, _name, _hash, _addressfunc, _traversefunc):
    #    pass
    #    return widget

    ### uncomment for being accessable by internet
    ### client:
    # def receive(self, action, _socket, _cert, certhash):
    #     pass
    ## executed when redirected, return False, when redirect should not be executed
    # def rreceive(self, action, _socket, _cert, certhash):
    #     pass
    ### server:
    # def sreceive(action, _socket, _cert, certhash):
    #     pass
