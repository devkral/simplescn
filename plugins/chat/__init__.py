
from threading import Lock
#import os
#import sys
import os.path
import hashlib
import shutil
try:
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk, Gdk, Pango, Gio, GLib,  GdkPixbuf
except ImportError:
    gtk_chat = None

###### created by pluginmanager ######
# specifies the interfaces
interfaces = None

# configmanager (see common)
config = None

# resources which can be accessed
resources = None

# plugin path
proot = None

# this module
module = None

###### created by pluginmanager end ######

lname = {"*": "Chat"}


# defaults for config (needed)
defaults = {"chatdir": ["~/.simplescn/chatlogs", str, "directory for chatlogs"], "downloaddir": ["~/Downloads", str, "directory for Downloads"], "maxsizeimg": [2048, int, "max image (and text) size in KB"]}

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
    port_to_answer = resources("access")("show")[1]["port"]
    #print(config.list())
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir"))), 0o770, exist_ok=True)
    return True


def init_pathes(_hash):
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir")), _hash), 0o770, exist_ok=True)
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir")), _hash, "images"), 0o770, exist_ok=True)
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir")), _hash, "tosend"), 0o770, exist_ok=True)


def gtk_create_textob(_text, isowner, isprivate):
    ret = Gtk.Label(_text, wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR, selectable=True)
    
    if isowner:
        ret.set_halign(Gtk.Align.END)
        ret.set_justify(Gtk.Justification.RIGHT)
        if isprivate:
            ret.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=0.3, blue=0.0, alpha=0.9))
        else:
            ret.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=0.3, green=1.0, blue=0.3, alpha=0.7))
            
    else:
        ret.set_halign(Gtk.Align.START)
        ret.set_justify(Gtk.Justification.LEFT)
        if isprivate:
            ret.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=0.0, blue=0.0, alpha=0.9))
        else:
            ret.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=1.0, blue=1.0, alpha=0.7))
    
    return ret


def gtk_create_imageob(_img, isowner, isprivate):
    newimg = GdkPixbuf.new_from_inline(_img)
    newimg = Gtk.Image.new_from_pixbuf(newimg)
    if isowner:
        newimg.set_halign(Gtk.Align.END)
        #if isprivate:
        #    newimg.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=0.3, blue=0.0, alpha=0.9))
        #else:
        #    newimg.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=0.3, green=1.0, blue=0.3, alpha=0.7))
    else:
        newimg.set_halign(Gtk.Align.START)
        #if isprivate:
        #    newimg.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=0.0, blue=0.0, alpha=0.9))
        #else:
        #    newimg.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(red=1.0, green=1.0, blue=1.0, alpha=0.7))
    
    return newimg

def gtk_download(widget, filename, size):
    _filech = Gtk.FileChooserDialog(title="Save to file", parent=widget.get_parent_window(), select_multiple=False, action=Gtk.FileChooserAction.SAVE, buttons=("SAVE",10, "CANCEL",20))
    #filech.set_filename(os.path.join filename)
    if _filech.run()!=10:
        return
    _file2 = _filech.get_filename()
    #TODO: finish retrieving files
    

def gtk_create_fileob(_filename, _size, isowner):
    ret = Gtk.Grid()
    if isowner:
        pass # delete dialog
    else:
        ret.attach_next_to(Gtk.Label("File: {}".format(_filename)), None, Gtk.PositionType.RIGHT, 1, 1)
        downbut = Gtk.Button("Download ({})".format(_size))
        ret.attach_next_to(downbut, None, Gtk.PositionType.RIGHT, 1, 1)
    return ret
    
def gtk_scroll_down(widget, child_prop, scroller):
    if isinstance(widget, Gtk.ListBox): # and scroller.get_value()<10:
        scroller.set_value(100)


def gtk_send_text(widget, _textwidget, _address, certhash):
    _text = _textwidget.get_text()
    with chatlock[certhash]:
        send_text(_address, certhash, _text)
        _textwidget.set_text("")
        #_oldlineno = chatbuf[certhash].get_line_count()
        #chatbuf[certhash].insert(chatbuf[certhash].get_end_iter(), _text+"\n")
        #_newiter = chatbuf[certhash].get_end_iter()
        chatbuf[certhash].append(gtk_chat.gtk_create_textob(_text, True, private_state.get(certhash, False)))

def gtk_send_file(widget, url, window, certhash):
    init_pathes(certhash)
    _filech = Gtk.FileChooserDialog(title="Select file", parent=window, select_multiple=False, action=Gtk.FileChooserAction.OPEN, buttons=("OPEN",10, "CANCEL",20))
    if _filech.run()!=10:
        return
    _filename = _filech.get_filename()
    _basename = os.path.basename(_filename)
    shutil.copyfile(_filename, os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "tosend", _basename))
    if private_state.get(certhash, False):
        privstate = "private"
    else:
        privstate = "normal"
    sock, _cert, _hash = resources("plugin")(url, "chat", "{}/send_file/{}/{}".format(privstate, os.stat(_filename).st_size, port_to_answer), forcehash=certhash)
    sock.close()
    #if private_state[certhash] != "private":
    #    with open(os.path.join(os.path.expanduser(config.get("chatdir")), certhash+".log"), "a") as wrio:
    #        wrio.write("o:"+_text+"\n");
    #sock.sendfile(_textb)
    #sock.close()
    #return "Hello actions, return: "+url

def gtk_send_img(widget, url, window, certhash):
    init_pathes(certhash)
    _filech = Gtk.FileChooserDialog(title="Select image", parent=window, select_multiple=False, action=Gtk.FileChooserAction.OPEN, buttons=("OPEN",10, "CANCEL",20))
    if _filech.run()!=10:
        return
    _filename = _filech.get_filename()
    if private_state.get(certhash, False):
        privstate = "private"
    else:
        privstate = "normal"
    sock, _cert, _hash = resources("plugin")(url, "chat", "{}/send_img/{}/{}".format(privstate, os.stat(_filename).st_size, port_to_answer), forcehash=certhash)
    sock.sendfile(_filename)
    sock.close()

def delete_log(gui, url, window, certhash, dheader):
    if certhash not in chatlock:
        return
    with chatlock[certhash]:
        try:
            shutil.rmtree(os.path.join(os.path.expanduser(config.get("chatdir")), certhash))
            #os.remove(os.path.join(os.path.expanduser(config.get("chatdir")), dheader.get("forcehash")+".log"))
        except FileNotFoundError:
            pass
        chatbuf[certhash].remove_all()
        
    #return "Hello actions, return: "+url

def toggle_private(gui, url, window, certhash, state, dheader):
    if state:
        private_state[certhash] = True
    else:
        private_state[certhash] = False

    
# dict, just shows up in cmd, do localisation in plugin 
# please don't localise dict keys
#cmd_node_actions={"foo-action": (sampleaction_cmd, "localized description")}

# do it this way
#cmd_node_alias_actions={"Aktion": "foo-action"}

#{"text": "Send file", "action": send_file_gui, \
#"interfaces": ["gtk",], "description": "Send a file"},
# iterable, for node actions, just shows up in gui, do localization in plugin
gui_node_actions=[
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
    if private_state.get(certhash, False):
        sock, _cert, _hash = resources("plugin")(_address, "chat", "{}/send_text/{}/{}".format("private", port_to_answer, len(_textb)), forcehash=certhash)
    else:
        sock, _cert, _hash = resources("plugin")(_address, "chat", "{}/send_text/{}/{}".format("normal", port_to_answer, len(_textb)), forcehash=certhash)
    if sock is None:
        return False
    if private_state[certhash] == False:
        with open(os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "log.txt"), "a") as wrio:
            wrio.write("ot:"+_text+"\n");
    sock.send(_textb)
    sock.close()
    return True

def myListBoxCreateWidgetFunc(item, **userdata):
    return item
    
def gui_node_iface(gui, _name, _hash, _address, window):
    if _hash not in chatlock:
        chatlock[_hash] = Lock()
    if gui != "gtk":
        return None
    
    if _hash not in chatbuf:
        chatbuf[_hash] = Gio.ListStore()
        try:
            with open(os.path.join(os.path.expanduser(config.get("chatdir")), _hash,"log.txt"), "r") as reio:
                for line in reio.readlines():
                    if line[-1] == "\n":
                        line = line[:-1]
                    if line[-1] == "\r":
                        line = line[:-1]
                    if line[:3] == "ot:":
                        chatbuf[_hash].append(gtk_create_textob(line[3:], True, False))
                    elif line[:3] == "rt:":
                        chatbuf[_hash].append(gtk_create_textob(line[3:], False, False))
                    elif line[:3] == "oi:":
                        _imgpath = os.path.join(os.path.expanduser(config.get("chatdir")), _hash, "images", line[3:])
                        if os.path.isfile(_imgpath):
                            with open(_imgpath, "rb") as rob:
                                chatbuf[_hash].append(gtk_create_imageob(rob.read(), True, False))
                    elif line[:3] == "ri:":
                        _imgpath = os.path.join(os.path.expanduser(config.get("chatdir")), _hash, "images", line[3:])
                        if os.path.isfile(_imgpath):
                            with open(_imgpath, "rb") as rob:
                                chatbuf[_hash].append(gtk_create_imageob(rob.read(), False, False))
                    elif line[:3] == "of:":
                        _name, _size = line[3:].rsplit(",", 1)
                        chatbuf[_hash].append(gtk_create_fileob(_name, _size, True))
                    elif line[:3] == "rf:":
                        _name, _size = line[3:].rsplit(",", 1)
                        chatbuf[_hash].append(gtk_create_fileob(_name, _size, False))
                    
        except FileNotFoundError:
            pass
    
    private_state[_hash] = False
    builder = Gtk.Builder()
    builder.add_from_file(os.path.join(proot, "chat.ui"))
    builder.connect_signals(module)
    textsende = builder.get_object("textsende")
    textsende.connect("activate", gtk_send_text, textsende, _address, _hash)
    sendchatb = builder.get_object("sendchatb")
    sendchatb.connect("clicked", gtk_send_text, textsende, _address, _hash)
    sendfileb = builder.get_object("sendfileb")
    sendfileb.connect("clicked", gtk_send_file, _address, window, _hash)
    sendimgb = builder.get_object("sendimgb")
    sendimgb.connect("clicked", gtk_send_img, _address, window, _hash)
    
    #TODO: connect and autoscrolldown
    #sendchatb.connect("child_notify", gtk_scroll_down, builder.get_object("chatscroll"))
    clist = builder.get_object("chatlist")
    clist.bind_model(chatbuf[_hash], myListBoxCreateWidgetFunc)
    #clist.bind_model(chatbuf[_hash], Gtk.ListBoxCreateWidgetFunc)
    # broken so use own function to workaround
    return builder.get_object("chatin")



def gtk_receive_text(certhash, _text, _private):
    chatbuf[certhash].append(gtk_create_textob(_text, False, _private))
    return False # for not beeing readded (threads_add_idle)


def gtk_receive_img(certhash, _img, _private):
    chatbuf[certhash].append(gtk_create_imageob(_img, False, _private))
    return False # for not beeing readded (threads_add_idle)

def gtk_receive_file(certhash, _filename, _size):
    chatbuf[certhash].append(gtk_create_fileob(_filename, _size, False))
    return False # for not beeing readded (threads_add_idle)

### uncomment for being accessable by internet
### client:
def receive(action, _socket, _cert, certhash):
    splitted = action.split("/",3)
    if len(splitted) != 4:
        return
    private, action, answerport, _rest = splitted
    if private == "private":
        private = True
    else:
        private = False
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
            _text = str(_socket.read(_size), "utf-8")
            if private == False:
                with open (os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "log.txt"), "a") as logob:
                    logob.write("rt:"+_text+"\n")
                
            if "gtk" in interfaces:
                Gdk.threads_add_idle(GLib.PRIORITY_DEFAULT, gtk_receive_text, certhash, _text, private)
        elif action == "send_img":
            _size = int(_rest)
            if _size > config.get("maxsizeimg")*1024:
                return
            _img = _socket.read(_size)
            
            if private == False:
                _imgname = hashlib.sha256(_img).hexdigest()
                with open (os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "images", _imgname), "wb") as imgob:
                    imgob.write(_img)
                with open (os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "log.txt"), "a") as logob:
                    logob.write("ri:"+_imgname+"\n")
            
            if "gtk" in interfaces:
                Gdk.threads_add_idle(GLib.PRIORITY_DEFAULT, gtk_receive_img, certhash, _img, private)
        elif action == "send_file":
            _name, _size = _rest.split("/", 1)
            if private == False:
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
