
from threading import Lock
#import os
import os.path

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

lname = {"*": "Chat"}


# defaults for config (needed)
defaults = {}

chatbuf = {}
chatlock = {}
openforeign = 0
port_to_answer = None

# initialises plugin. Returns False or Exception for not loading  (needed)
def init():
    global port_to_answer
    if "gtk" not in interfaces:
        return False
    global Gtk, Gdk
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk, Gdk

    port_to_answer = resources("access")("show")[1]["port"]
    return True


def send_file_gui(gui, url, dheader):
    print("Hello actions: "+url)
    #return "Hello actions, return: "+url


def sampleaction_cmd():
    print("Hello actions world")
    #return "Hello actions world"
    
# dict, just shows up in cmd, do localisation in plugin 
# please don't localise dict keys
#cmd_node_actions={"foo-action": (sampleaction_cmd, "localized description")}

# do it this way
#cmd_node_alias_actions={"Aktion": "foo-action"}

# iterable, for node actions, just shows up in gui, do localization in plugin
gui_node_actions=[{"text":" Send file", "action": send_file_gui, \
"interfaces": ["gtk",], "description": "Send a file"}, ]

# iterable, for server actions, just shows up in gui, do localization in plugin
#gui_server_actions=[{"text":"foo-actionname","action":sampleaction, "icon":"optionalfoo-iconlocation"}, ]



#def gui_server_iface(gui, _name, _hash, _address):
#    pass
#    return widget

def send_text(_address, certhash, _text, private_state):
    _text = bytes(_text, "utf-8")
    sock, _cert, _hash = resources("plugin")(_address, "chat", "{}/send_text/{}/{}".format(private_state, len(_text), port_to_answer), forcehash=certhash)
    if sock is None:
        return False
    sock.send(_text)
    sock.close()
    return True

def gtk_send_text(widget, _address, certhash, private_state):
    _text = widget.get_text()
    with chatlock[certhash]:
        send_text(_address, certhash, _text, private_state)
        widget.set_text("")
        _oldlineno = chatbuf[certhash].get_line_count()
        chatbuf[certhash].insert(chatbuf[certhash].get_end_iter(), _text+"\n")
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
    chatin.connect("activate", gtk_send_text, _address, _hash, "public")
    chattview = Gtk.TextView(buffer=chatbuf[_hash], editable=False, hexpand=True, vexpand=True)
    
    chatswin = Gtk.ScrolledWindow(child=chattview, hexpand=True, vexpand=True)
    
    chatgrid.attach(chatswin, 0, 0, 1, 1)
    chatgrid.attach(chatin, 0, 1, 1, 1)
    return chatgrid


### uncomment for being accessable by internet
### client:
def receive(action, _socket, _cert, certhash):
    splitted = action.split("/",3)
    if len(splitted) != 4:
        return
    private, action, answerport, _size = splitted
    if certhash not in chatlock:
        if resources("access")("getlocal", hash=certhash)[0] == False:
            return
        resources("open_node")("{}:{}".format(_socket.getaddrinfo()[0], answerport), page="chat")
        
    if certhash not in chatlock:
        return
    
    with chatlock[certhash]:
        if action == "send_text":
            if private != "private":
                #logob = open (os.path.join(config.get("logdir"), certhash), "a")
                logob = None
            else:
                logob = None
            _text = str(_socket.read(int(_size)), "utf-8")+"\n"
            chatbuf[certhash].insert(chatbuf[certhash].get_end_iter(), _text)
            if logob is not None:
                logob.write(_text)
                logob.close()
    
        
## executed when redirected, return False, when redirect should not be executed
# def rreceive(action, _socket, _cert, certhash):
#     pass
### server:
# def sreceive(action, _socket, _cert, certhash):
#     pass
