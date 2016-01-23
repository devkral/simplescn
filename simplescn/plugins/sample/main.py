

###### used by pluginmanager ######

# defaults for config (needed)
config_defaults = {"test": ["testvar", str, "testvar description"]}

# interfaces, config, accessable resources (communication with main program), pluginpath, logger
# return None deactivates plugin
def init(interfaces, config, resources, proot):
    print("Hello World")
    return sample_test(interfaces, config, resources, proot)

###### used by pluginmanager end ######



class sample_test(object):
    interfaces = None
    config = None
    resources = None
    proot = None
    
    gui_node_actions = None
    gui_server_actions = None
    cmd_node_actions = None
    cmd_node_localized_actions = None
    
    def __init__(self, interfaces, config, resources, proot):
        self.interfaces, self.config, self.resources, self.proot = interfaces, config, resources, proot
        
        
        # iterable, for node actions, just shows up in gui, do localization in plugin
        gui_node_actions=[{"text":"foo-actionname","action": self.sampleaction, "icon":"optionalfoo-iconlocation", \
"interfaces": ["gtk",], "description": "foo"}, ]

        # iterable, for server actions, just shows up in gui, do localization in plugin
        gui_server_actions=[{"text":"foo-actionname","action":self.sampleaction, "icon":"optionalfoo-iconlocation", \
"interfaces": ["gtk",], "description": "foo"}, ]
        
        # dict, just shows up in cmd, do localisation in plugin 
        # please don't localise dict keys
        cmd_node_actions={"foo-action": (self.sampleaction_cmd, "unlocalized description")}

        # do it this way
        cmd_node_localized_actions={"Aktion": "foo-action"}


    # localized name
    #lname = {"*": "global name", "de": "German name", "de_DE": "German Germany name"}
    
    


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
