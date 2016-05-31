

class test(object):
    # localized name
    lname = {"*": "Test", "de": "Deutsch: Test deutsch", "de_DE": "Deutsch: Test DE"}
    interfaces = None
    config = None
    resources = None
    proot = None
    logger = None

    # initialises plugin. Returns False or Exception for not loading  (needed)
    def __init__(self, interfaces, config, resources, proot):
        self.interfaces, self.config, self.resources, self.proot = interfaces, config, resources, proot
        print("Hello "+self.interfaces[0])
        print("I offer: {}".format(self.interfaces[1:]))


    def sampleaction(self, gui, url, window, certhash, dheader):
        print("Hello actions: ", url, gui)
        resources("open_notify")("Hello actions: {}, {}".format(url, gui))


    def sampleactionpw(self, gui, url, window, certhash, dheader):
        self.resources("open_pwrequest")("Enter password for fun")

    def sampleaction_cmd(self):
        print("Hello actions world")
    
    # dict, just shows up in cmd, do localisation in plugin 
    # please don't localise dict keys
    cmd_node_actions={"foo-action": (sampleaction_cmd, "localized description")}

    # do it this way
    cmd_node_localized_actions={"Aktion": "foo-action"}

    # iterable, for node actions, just shows up in gui, do localization in plugin
    gui_node_actions=[{"text":"test notify","action":sampleaction, "icon":"optionalfoo-iconlocation", \
"interfaces": ["gtk",], "description": "foo"}, 
{"text":"test password dialog","action":sampleactionpw, \
"interfaces": ["gtk",], "description": "foo"}]

    # iterable, for server actions, just shows up in gui, do localization in plugin
    gui_server_actions=[{"text":"foo-actionname","action":sampleaction, "icon":"optionalfoo-iconlocation", \
"interfaces": ["gtk",], "description": "foo"}, ]

    def address_change(self, gui, _address, window, _hash):
        print("address change: {}".format((gui, _address, window, _hash)))

    #def gui_server_iface(gui, _name, _hash, _addressfunc):
    #    pass
    #    return widget

    #def gui_node_iface(gui, _name, _hash, _addressfunc, _traversefunc, window):
    #    pass
    #    return widget


    ### uncomment for being accessable by internet
    ### client:
    # def receive(action, _socket, _cert, certhash):
    #     pass
    ## executed when redirected, return False, when redirect should not be executed
    # def rreceive(action, _socket, _cert, certhash):
    #     pass
    ### server:
    # def sreceive(action, _socket, _cert, certhash):
    #     pass

def init(interfaces, config, resources, proot):
    return test(interfaces, config, resources, proot)
