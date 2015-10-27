
from threading import Lock
#import os
import sys
import os.path
import hashlib
import shutil

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
defaults = {"chatdir": ["~/.simplescn/chatlogs", str, "directory for chatlogs"], "downloaddir": ["~/Downloads", str, "directory for Downloads"], "maxsizeimg": [4, int, "max image (and text) size in KB"]}

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
    global Gtk, Gdk, GLib, Gio, Pango, Gio
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk, Gdk, GLib, Pango, Gio
    port_to_answer = resources("access")("show")[1]["port"]
    #print(config.list())
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir"))), 0o770, exist_ok=True)
    return True


def init_pathes(_hash):
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir")), _hash), 0o770, exist_ok=True)
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir")), _hash, "images"), 0o770, exist_ok=True)
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir")), _hash, "tosend"), 0o770, exist_ok=True)



def gtk_create_textob(_text, isowner, isprivate):
    ret = Gtk.Label(_text, wrap=True, wrap_mode=Pango.WrapMode.WORD)
    
    #if isowner:
    
    return ret


def gtk_create_imageob(_img, isowner, isprivate):
    return Gtk.Label()


def gtk_create_fileob(_filename, _size, isowner, isprivate):
    return Gtk.Label()
    
def send_file_gui(gui, url, window, certhash, dheader):
    init_pathes(certhash)
    _filech = Gtk.FileChooserDialog(title="Select file", parent=window, select_multiple=False, action=Gtk.FileChooserAction.OPEN, buttons=("OPEN",10, "CANCEL",20))
    if _filech.run()!=10:
        return
    _filename = _filech.get_filename()
    _basename = os.path.basename(_filename)
    shutil.copyfile(_filename, os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "tosend", _basename))
    sock, _cert, _hash = resources("plugin")(self.address, "chat", "{}/send_file/{}/{}".format(private_state.get(certhash, "normal"), len(_textb), port_to_answer), **dheader)
    sock.close()
    #if private_state[certhash] != "private":
    #    with open(os.path.join(os.path.expanduser(config.get("chatdir")), certhash+".log"), "a") as wrio:
    #        wrio.write("o:"+_text+"\n");
    #sock.sendfile(_textb)
    #sock.close()
    #return "Hello actions, return: "+url

def delete_log(gui, url, window, certhash, dheader):
    if certhash not in chatlock:
        return
    with chatlock[certhash]:
        try:
            shutil.rmtree(os.path.join(os.path.expanduser(config.get("chatdir")), certhash))
            #os.remove(os.path.join(os.path.expanduser(config.get("chatdir")), dheader.get("forcehash")+".log"))
        except FileNotFoundError:
            pass
        chatbuf[certhash].delete(chatbuf[certhash].get_start_iter(), chatbuf[certhash].get_end_iter())
    init_pathes(certhash)
        
    #return "Hello actions, return: "+url

def toggle_private(gui, url, window, certhash, state, dheader):
    if state:
        private_state[certhash] = "private"
    else:
        private_state[certhash] = "normal"

    
# dict, just shows up in cmd, do localisation in plugin 
# please don't localise dict keys
#cmd_node_actions={"foo-action": (sampleaction_cmd, "localized description")}

# do it this way
#cmd_node_alias_actions={"Aktion": "foo-action"}

# iterable, for node actions, just shows up in gui, do localization in plugin
gui_node_actions=[{"text": "Send file", "action": send_file_gui, \
"interfaces": ["gtk",], "description": "Send a file"},
{"text":"private", "action": toggle_private, \
"interfaces": ["gtk",], "description": "Toggle private chat", "state": False},
{"text":"Delete log", "action": delete_log, \
"interfaces": ["gtk",], "description": "Delete the chat log"}
]

# iterable, for server actions, just shows up in gui, do localization in plugin
#gui_server_actions=[{"text":"foo-actionname","action":sampleaction, "icon":"optionalfoo-iconlocation"}, ]



#def gui_server_iface(gui, _name, _hash, _address):
#    pass
#    return widget

def send_text(_address, certhash, _text):
    init_pathes(certhash)
    _textb = bytes(_text, "utf-8")
    if len(_textb) == 0:
        return True
    sock, _cert, _hash = resources("plugin")(_address, "chat", "{}/send_text/{}/{}".format(private_state.get(certhash, "normal"), port_to_answer, len(_textb)), forcehash=certhash)
    if sock is None:
        return False
    if private_state[certhash] != "private":
        with open(os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "log.txt"), "a") as wrio:
            wrio.write("ot:"+_text+"\n");
    sock.send(_textb)
    sock.close()
    return True

def gtk_send_text(widget, _textwidget, _address, certhash):
    _text = _textwidget.get_text()
    with chatlock[certhash]:
        send_text(_address, certhash, _text)
        _textwidget.set_text("")
        #_oldlineno = chatbuf[certhash].get_line_count()
        #chatbuf[certhash].insert(chatbuf[certhash].get_end_iter(), _text+"\n")
        #_newiter = chatbuf[certhash].get_end_iter()
        chatbuf[certhash].append(gtk_create_textob(_text, True, private_state.get(certhash, False)))


def gui_node_iface(gui, _name, _hash, _address):
    if _hash not in chatlock:
        chatlock[_hash] = Lock()
    if gui != "gtk":
        return None
    
    if _hash not in chatbuf:
        chatbuf[_hash] = Gio.ListStore()
        #chatbuf[_hash].create_tag("ownposts", justification=Gtk.Justification.RIGHT, justification_set=True,
        #                foreground_rgba=Gdk.RGBA(red=0.0, green=1.0, blue=0.9, alpha=1.0), foreground_set=True)
        #chatbuf[_hash].create_tag("ownposts_private", justification=Gtk.Justification.RIGHT, justification_set=True,
        #                foreground_rgba=Gdk.RGBA(red=1.0, green=0.0, blue=0.0, alpha=1.0), foreground_set=True)
        #chatbuf[_hash].create_tag("remposts_private", justification=Gtk.Justification.LEFT, justification_set=True,
        #                foreground_rgba=Gdk.RGBA(red=1.0, green=0.0, blue=0.0, alpha=1.0), foreground_set=True)
        try:
            with open(os.path.join(os.path.expanduser(config.get("chatdir")), _hash,"log.txt"), "r") as reio:
                for line in reio.readlines():
                    if line[:3] == "ot:":
                        chatbuf[_hash].append(gtk_create_textob(line, True, False))
                    elif line[:3] == "rt:":
                        chatbuf[_hash].append(gtk_create_textob(line, False, False))
        except FileNotFoundError:
            pass
    
    private_state[_hash] = "normal"
    builder = Gtk.Builder()
    builder.add_from_file(os.path.join(proot, "chat.ui"))
    builder.connect_signals(module)
    textsende = builder.get_object("textsende")
    textsende.connect("activate", gtk_send_text, textsende, _address, _hash)
    sendchatb = builder.get_object("sendchatb")
    sendchatb.connect("clicked", gtk_send_text, textsende, _address, _hash)
    clist = builder.get_object("chatlist")
    print(type(chatbuf[_hash]))
    clist.bind_model(chatbuf[_hash], Gtk.ListBoxCreateWidgetFunc)
    return builder.get_object("chatin")



def gtk_receive_text(certhash, _text, _private):
    
    chatbuf[certhash].append(gtk_create_textob(_text, False, _private))
    return False # for not beeing readded (threads_add_idle)


def gtk_receive_img(certhash, _img):
    return False # for not beeing readded (threads_add_idle)

def gtk_receive_file(certhash, _filename, _size):
    return False # for not beeing readded (threads_add_idle)

### uncomment for being accessable by internet
### client:
def receive(action, _socket, _cert, certhash):
    splitted = action.split("/",3)
    if len(splitted) != 4:
        return
    private, action, answerport, _rest = splitted
    if certhash not in chatlock:
        if resources("access")("getlocal", hash=certhash)[0] == False:
            return
        resources("open_node")("{}:{}".format(_socket.getaddrinfo()[0], answerport), page="chat")
    
    if action == "fetch_file":
        name, pos = _rest
        if "/" in name or "\\" in name:
            return
        _path = os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "tosend", name)
        if os.path.isfile(_path):
            _socket.sendfile(_path, pos)
        return
    if certhash not in chatlock:
        #todo open dialog
        return
    init_pathes(certhash)
    
    with chatlock[certhash]:
        if action == "send_text":
            _size = int(_rest)
            if _size > config.get("maxsizeimg")*1024:
                return
            _text = str(_socket.read(_size), "utf-8")+"\n"
            if private != "private":
                with open (os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "log.txt"), "a") as logob:
                    logob.write("rt:"+_text)
                
            if "gtk" in interfaces:
                Gdk.threads_add_idle(GLib.PRIORITY_DEFAULT, gtk_receive_text, certhash, _text, private)
        elif action == "send_img":
            _size = int(_rest)
            if _size > config.get("maxsizeimg")*1024:
                return
            _img = _socket.read(_size)
            
            if private != "private":
                _imgname = hashlib.sha256(_img).hexdigest()
                with open (os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "images", _imgname), "wb") as imgob:
                    imgob.write(_img)
                with open (os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "log.txt"), "a") as logob:
                    logob.write("ri:"+_imgname+"\n")
            
            if "gtk" in interfaces:
                Gdk.threads_add_idle(GLib.PRIORITY_DEFAULT, gtk_receive_img, certhash, _img)
        elif action == "send_file":
            _name, _size = _rest.split("/", 1)
            if private != "private":
                with open (os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "log.txt"), "a") as logob:
                    logob.write("rf:{},{}\n".format(_name, _size))
            if "gtk" in interfaces:
                Gdk.threads_add_idle(GLib.PRIORITY_DEFAULT, gtk_receive_file, certhash, _name, _size)
            
## executed when redirected, return False, when redirect should not be executed
# def rreceive(action, _socket, _cert, certhash):
#     pass
### server:
# def sreceive(action, _socket, _cert, certhash):
#     pass
