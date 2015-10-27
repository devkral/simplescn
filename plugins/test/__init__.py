

###### created by pluginmanager ######
# specifies the interfaces
# interfaces

# configmanager (see common)
# config

# resources which can be accessed
# resources

# plugin path
# proot


###### created by pluginmanager end ######


# localized name
lname = {"*": "Test", "de_DE": "Deutsch: Test"}

# defaults for config (needed)
defaults={}

# initialises plugin. Returns False or Exception for not loading  (needed)
def init():
    print("Hello "+interfaces[0])
    print("I offer: {}".format(interfaces[1:]))
    return True


def sampleaction(gui, url, window, certhash, dheader):
    print("Hello actions: ", url, gui)
    resources("open_notify")("Hello actions: {}, {}".format(url, gui))


def sampleactionpw(gui, url, window, certhash, dheader):
    resources("open_pwrequest")("Enter password for fun")

def sampleaction_cmd():
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


#def gui_server_iface(gui, _name, _hash, _address):
#    pass
#    return widget

#def gui_node_iface(gui, _name, _hash, _address):
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
