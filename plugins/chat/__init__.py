
from threading import Lock
#import os
import sys
import os.path

###### created by pluginmanager ######
# specifies the interfaces
# interfaces

# configmanager (see common)
# config

# resources which can be accessed
# resources

# plugin path
# proot

# this module
# module

###### created by pluginmanager end ######

lname = {"*": "Chat"}


# defaults for config (needed)
defaults = {"chatdir": ["~/.simplescn/chatlogs", str, "directory for chatlogs"]}

chatbuf = {}
chatlock = {}
private_state = {}
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
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir"))), 770)
    return True


def send_file_gui(gui, url, dheader):
    print("Hello actions: "+url)
    #return "Hello actions, return: "+url

def toggle_private(gui, url, state, dheader):
    if state:
        private_state[dheader.get("forcehash")] = "private"
    else:
        private_state[dheader.get("forcehash")] = "normal"

    
# dict, just shows up in cmd, do localisation in plugin 
# please don't localise dict keys
#cmd_node_actions={"foo-action": (sampleaction_cmd, "localized description")}

# do it this way
#cmd_node_alias_actions={"Aktion": "foo-action"}

# iterable, for node actions, just shows up in gui, do localization in plugin
gui_node_actions=[{"text": "Send file", "action": send_file_gui, \
"interfaces": ["gtk",], "description": "Send a file"},{"text":"private", "action": toggle_private, \
"interfaces": ["gtk",], "description": "Toggle private chat", "state": False}, ]

# iterable, for server actions, just shows up in gui, do localization in plugin
#gui_server_actions=[{"text":"foo-actionname","action":sampleaction, "icon":"optionalfoo-iconlocation"}, ]



#def gui_server_iface(gui, _name, _hash, _address):
#    pass
#    return widget

def send_text(_address, certhash, _text):
    _text = bytes(_text, "utf-8")
    if len(_text) == 0:
        return True
    sock, _cert, _hash = resources("plugin")(_address, "chat", "{}/send_text/{}/0/{}".format(private_state.get(certhash, "normal"), len(_text), port_to_answer), forcehash=certhash)
    if sock is None:
        return False
    if private_state[certhash] != "private":
        with open(os.path.join(os.path.expanduser(config.get("chatdir")), certhash+".log"), "a") as wrio:
            wrio.write("o:"+_text+"\n");
    sock.send(_text)
    sock.close()
    return True

def gtk_send_text(widget, _textwidget, _address, certhash):
    _text = _textwidget.get_text()
    with chatlock[certhash]:
        send_text(_address, certhash, _text)
        _textwidget.set_text("")
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
        chatbuf[_hash].create_tag("ownposts", justification=Gtk.Justification.RIGHT, justification_set=True,
                        foreground_rgba=Gdk.RGBA(red=0.0, green=1.0, blue=0.9, alpha=1.0), foreground_set=True)
        with open(os.path.join(os.path.expanduser(config.get("chatdir")), certhash+".log"), "r") as reio:
            for line in reio.readlines():
                _oldlineno = chatbuf[_hash].get_line_count()
                chatbuf[_hash].insert(chatbuf[_hash].get_end_iter(), line[2:])
                _newiter = chatbuf[_hash].get_end_iter()
                if line[:2]:
                    chatbuf[_hash].apply_tag_by_name("ownposts", chatbuf[_hash].get_iter_at_line(_oldlineno-1), _newiter)
    builder = Gtk.Builder()
    builder.add_from_file(os.path.join(proot, "chat.ui"))
    builder.connect_signals(module)
    textsende = builder.get_object("textsende")
    textsende.connect("activate", gtk_send_text, textsende, _address, _hash)
    sendchatb = builder.get_object("sendchatb")
    sendchatb.connect("clicked", gtk_send_text, textsende, _address, _hash)
    cview = builder.get_object("chatview")
    cview.set_buffer(chatbuf[_hash])
    return builder.get_object("chatin")


### uncomment for being accessable by internet
### client:
def receive(action, _socket, _cert, certhash):
    splitted = action.split("/",4)
    if len(splitted) != 5:
        return
    private, action, answerport, startpos, _size = splitted
    if certhash not in chatlock:
        if resources("access")("getlocal", hash=certhash)[0] == False:
            return
        resources("open_node")("{}:{}".format(_socket.getaddrinfo()[0], answerport), page="chat")
        
    if certhash not in chatlock:
        #todo open dialog
        return
    
    with chatlock[certhash]:
        if action == "send_text":
            if private != "private":
                logob = open (os.path.join(os.path.expanduser(config.get("chatdir")), certhash+".log"), "a")
            else:
                logob = None
            _text = str(_socket.read(int(_size)), "utf-8")+"\n"
            chatbuf[certhash].insert(chatbuf[certhash].get_end_iter(), _text)
            if logob is not None:
                logob.write("r:"+_text+"\n")
                logob.close()
    
        
## executed when redirected, return False, when redirect should not be executed
# def rreceive(action, _socket, _cert, certhash):
#     pass
### server:
# def sreceive(action, _socket, _cert, certhash):
#     pass
