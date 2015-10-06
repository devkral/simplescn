
from gi.repository import Gtk, Gdk
from threading import Lock

###### created by pluginmanager ######
# specifies the interfaces
# interfaces

# configmanager (see common)
# config

# resources which can be accessed
# resources

# plugin path
# path


###### created by pluginmanager end ######



# defaults for config (needed)
defaults={}

# initialises plugin. Returns False or Exception for not loading  (needed)
def init():
    global chatbuf
    global chatlock
    chatbuf = {}
    chatlock = {}
    
    return True


def sampleaction(url, dheader):
    print("Hello actions: "+url)
    return "Hello actions, return: "+url


def sampleaction_cmd():
    print("Hello actions world")
    return "Hello actions world"
    
# dict, just shows up in cmd, do localisation in plugin 
# please don't localise dict keys
cmd_node_actions={"foo-action": (sampleaction_cmd, "localized description")}

# do it this way
cmd_node_localized_actions={"Aktion": "foo-action"}

# iterable, for node actions, just shows up in gui, do localization in plugin
gui_node_actions=[{"text":"foo-actionname","action":sampleaction, "icon":"optionalfoo-iconlocation"}, ]

# iterable, for server actions, just shows up in gui, do localization in plugin
gui_server_actions=[{"text":"foo-actionname","action":sampleaction, "icon":"optionalfoo-iconlocation"}, ]



#def gui_server_iface(gui, _name, _hash, _address):
#    pass
#    return widget

def send_text(_address, certhash, _text):
    sock, _cert, _hash = resources("plugin")(_address, "chat", "send_text", forcehash=certhash)
    if sock is None:
        return
    sock.send(bytes(_text, "utf-8"))
    sock.close()

def gtk_send_text(widget, _address, certhash):
    _text = widget.get_text()
    send_text(_address, certhash, _text)
    widget.set_text("")
    with chatlock[certhash]:
        _oldlineno = chatbuf[certhash].get_line_count()
        chatbuf[certhash].insert(chatbuf[certhash].get_end_iter(), "me: "+_text+"\n")
        _newiter = chatbuf[certhash].get_end_iter()
        chatbuf[certhash].apply_tag_by_name("ownposts", chatbuf[certhash].get_iter_at_line(_oldlineno-1), _newiter)

def gui_node_iface(gui, _name, _hash, _address):
    if _hash not in chatlock:
        chatlock[_hash] = Lock()
    if gui != "gtk":
        return None
    
    if _hash not in chatbuf:
        chatbuf[_hash] = Gtk.TextBuffer()
        chatbuf[_hash].create_tag("ownposts", justification=Gtk.Justification.RIGHT, justification_set=True, foreground_rgba=Gdk.RGBA(red=0.0, green=1.0, blue=0.9, alpha=1.0), foreground_set=True)
    chatgrid = Gtk.Grid()
    chatin = Gtk.Entry()
    chatin.connect("activate", gtk_send_text, _address, _hash)
    chattview = Gtk.TextView(buffer=chatbuf[_hash], editable=False, hexpand=True, vexpand=True)
    
    chatswin = Gtk.ScrolledWindow(child=chattview, hexpand=True, vexpand=True)
    
    chatgrid.attach(chatswin, 0, 0, 1, 1)
    chatgrid.attach(chatin, 0, 1, 1, 1)
    return chatgrid


### uncomment for being accessable by internet
### client:
def receive(action, _socket, _cert, certhash):
    with chatlock[certhash]:
        if action == "send_text":
            _text = _socket.read(1500)
            chatbuf[certhash].insert(chatbuf[certhash].get_end_iter(), str(_text, "utf-8")+"\n")
            
    
        
## executed when redirected, return False, when redirect should not be executed
# def rreceive(action, _socket, _cert, certhash):
#     pass
### server:
# def sreceive(action, _socket, _cert, certhash):
#     pass
