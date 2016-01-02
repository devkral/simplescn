
from threading import Lock
try:
    import gtkstuff
except ImportError as e:
    print(e)
    gtkstuff = None
try:
    import plugins.chat.gtkstuff
except ImportError as e:
    print(e)
import sys
print(sys.path)

#import os
#import sys
import datetime
import os.path
import hashlib
import shutil

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

# logger
logger = None

###### created by pluginmanager end ######

lname = {"*": "Chat"}


# defaults for config (needed)
defaults = {"chatdir": ["~/.simplescn/chatlogs", str, "directory for chatlogs"], "downloaddir": ["~/Downloads", str, "directory for Downloads"], "maxsizeimg": ["400", int, "max image size in KB"], "maxsizetext": ["4000", int, "max size text"]}

chatbuf = {}
chatlock = {}
chaturl = {}
private_state = {}
openforeign = 0

def cleanup(widget, certhash):
    del chaturl[certhash]
#port_to_answer = None

reqstring = None

# initialises plugin. Returns False or Exception for not loading  (needed)
def init():
    global reqstring
    if "gtk" not in interfaces:
        return False
    #port_to_answer = resources("access")("show")[1]["port"]
    # assign port to answer
    #/{timestamp}
    reqstring = "{action}/{privstate}/%s{other}" % resources("access")("show")[1]["port"]
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir"))), 0o770, exist_ok=True)
    return True


def init_pathes(_hash):
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir")), _hash), 0o770, exist_ok=True)
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir")), _hash, "images"), 0o770, exist_ok=True)
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir")), _hash, "tosend"), 0o770, exist_ok=True)


def request(url, certhash, action, arguments, traverseserveraddr=None): #, timestamp=create_timestamp()): #, _traversefunc()
    if url is None:
        logger().error("No address")
        return None
    if private_state.get(certhash, False):
        privstate = "private"
    else:
        privstate = "public"
    #sock, _cert, _hash = 
    #, timestamp=timestamp
    return resources("plugin")(url, "chat", reqstring.format(action=action, privstate=privstate, other=arguments), forcehash=certhash, traverseserveraddr=traverseserveraddr)


def create_timestamp():
    return datetime.datetime.today().strftime("%Y_%m_%d_%H_%M_%S")

def parse_timestamp(_inp):
    return datetime.datetime.strptime(_inp, "%Y_%m_%d_%H_%M_%S")

def unparse_timestamp(_inp):
    return _inp.strftime(_inp, "%Y_%m_%d_%H_%M_%S")


def delete_log(gui, _addressfunc, window, certhash, dheader):
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

def toggle_private(gui, _addressfunc, window, certhash, state, dheader):
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

   
# obdict is not a copy
def gui_node_iface(gui, _name, certhash, _addressfunc, _traversefunc, window):
    if certhash not in chatlock:
        chatlock[certhash] = Lock()
    if certhash not in chaturl:
        chaturl[certhash] = (_addressfunc, _traversefunc)
    if gui != "gtk":
        return None
    gtkstuff.gtk_node_iface(_name, certhash, _addressfunc, _traversefunc, window)

### uncomment for being accessable by internet
### client:
def receive(action, _socket, _cert, certhash):
    splitted = action.split("/", 3)
    if len(splitted) != 4:
        return
    action, private, answerport, _rest = splitted
    timestamp = create_timestamp()
    if private == "private":
        private = True
    else:
        private = False
    
    if action == "fetch_file":
        name, pos = _rest.split("/", 1)
        if "/" in name or "\\" in name or name[0] == ".":
            logger().error("Invalid filename")
            return
        _path = os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "tosend", name)
        if os.path.isfile(_path):
            with open(_path, "rb") as rbfile: 
                _socket.sendfile(rbfile, int(pos))
        return
        
    #if certhash not in chatlock:
    #    if resources("access")("getlocal", hash=certhash)[0] == False:
    #        return
    resources("open_node")("{}-{}".format(_socket.getsockname()[0], answerport), page="chat", forcehash=certhash)
    
    if certhash not in chatlock:
        # if still not existent
        return
    init_pathes(certhash)
    
    with chatlock[certhash]:
        if action == "send_text":
            _size = int(_rest)
            if _size > config.get("maxsizetext"):
                return
            countread = 0
            _textb = b""
            while countread <= _size-1024:
                _data = _socket.recv(1024)
                _textb += _data
                countread += len(_data)
            _textb += _socket.recv(_size-countread)
            _text = str(_textb, "utf-8")
            if private == False:
                with open (os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "log.txt"), "a") as logob:
                    logob.write("rt:{timestamp}:{text}\n".format(timestamp=timestamp, text=_text.replace("\n", "\\n").replace("\r", "\\r")))
                    # improve
            if "gtk" in interfaces and gtk is not None:
                gtkstuff.Gdk.threads_add_idle(gtkstuff.GLib.PRIORITY_DEFAULT, gtkstuff.gtk_receive_text, certhash, _text, private, timestamp)
        elif action == "send_img":
            _size = int(_rest)
            if _size > config.get("maxsizeimg")*1024:
                _socket.close()
                return
            countread = 0
            _img = b""
            while countread <= _size-1024:
                _data = _socket.recv(1024)
                _img += _data
                countread += len(_data)
            _img += _socket.recv(_size-countread)
            
            
            if private == False:
                _imgname = hashlib.sha256(_img).hexdigest()+".jpg"
                with open (os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "images", _imgname), "wb") as imgob:
                    imgob.write(_img)
                with open (os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "log.txt"), "a") as logob:
                    logob.write("ri:{timestamp}:{name}\n".format(timestamp=timestamp, name=_imgname))
            
            if "gtk" in interfaces and gtk is not None:
                gtkstuff.Gdk.threads_add_idle(gtkstuff.GLib.PRIORITY_DEFAULT, gtkstuff.gtk_receive_img, certhash, _img, private, timestamp)
        elif action == "send_file":
            _name, _size = _rest.split("/", 1)
            if private == False:
                with open (os.path.join(os.path.expanduser(config.get("chatdir")), certhash, "log.txt"), "a") as logob:
                    logob.write("rf:{timestamp}:{name},{size}\n".format(name=_name, size=_size, timestamp=timestamp))
            if "gtk" in interfaces and gtk is not None:
                gtkstuff.Gdk.threads_add_idle(gtkstuff.GLib.PRIORITY_DEFAULT, gtkstuff.gtk_receive_file, certhash, _name, int(_size), private, timestamp)
    
## executed when redirected, return False, when redirect should not be executed
# def rreceive(action, _socket, _cert, certhash):
#     pass
### server:
# def sreceive(action, _socket, _cert, certhash):
#     pass
