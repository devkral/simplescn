

###### created by pluginmanager ######
# specifies the interfaces
# interfaces

# configmanager (see common)
# config

# resources which can be accessed
# resources
###### created by pluginmanager end ######

# not implemented yet
# iterable, just shows up in cmd, do localisation in plugin 
# cmd_node_actions={"foo-pluginname": "foo-name" }

# iterable, just shows up in gui, do localisation in plugin
# gui_node_actions={"foo-pluginname":{"text": "foo", "icon":"foo-location"}, }

# uncomment for being accessable by internet
# def receive(action):
#     pass


# defaults for config (needed)
defaults={}

# initialises plugin. Returns False or Exception for not loading  (needed)
def init():
    print("First plugin loaded")
    return True
