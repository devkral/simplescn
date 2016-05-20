

#import sys
try:
    from . import gtkstuff
except ImportError as e:
    print(e)
    gtkstuff = None
import datetime
import os.path
import hashlib
import shutil
import time
import logging
import json
import socket
from threading import RLock, Thread

###### used by pluginmanager ######

# defaults for config (needed)
config_defaults = {"chatdir": ["~/.simplescn/chatlogs", str, "directory for chatlogs"], "downloaddir": ["~/Downloads", str, "directory for Downloads"], "maxsizeimg": ["4000", int, "max image size in KB"], "maxsizetext": ["4000", int, "max size text in B"], "accept_sensitive": ["True", bool, "accept sensitive stuff"]}

# interfaces, config, accessable resources (communication with main program), pluginpath, logger
# return None deactivates plugin
def init(interfaces, config, resources, proot):
    #global logger
    if "gtk" not in interfaces or gtkstuff is None:
        return None

    #logger = _logger
    #port_to_answer = resources("access")("show")[1]["port"]
    # assign port to answer
    #/{timestamp}
    os.makedirs(os.path.join(os.path.expanduser(config.get("chatdir"))), 0o770, exist_ok=True)
    return chat_plugin(interfaces, config, resources, proot)

###### used by pluginmanager end ######

def create_timestamp():
    return datetime.datetime.today().strftime("%Y_%m_%d_%H_%M_%S")

def parse_timestamp(_inp):
    return datetime.datetime.strptime(_inp, "%Y_%m_%d_%H_%M_%S")

def unparse_timestamp(_inp):
    return _inp.strftime(_inp, "%Y_%m_%d_%H_%M_%S")

class hash_session(object):
    parent = None
    certhash = None
    buffer = None
    buffer_gui = None
    lock = None
    private = None
    accept_sensitive = None
    addressfunc = None
    traversefunc = None
    window = None
    sessionpath = None
    outcounter = None
    _thread = None
    guitype = None
    gui = None
    name = None
    
    def __init__(self, guitype, parent, _name, certhash, _addressfunc, _traversefunc, window):
        self.certhash = certhash
        self.parent = parent
        self.addressfunc = _addressfunc
        self.traversefunc = _traversefunc
        self.window = window
        self.lock = RLock()
        self.private = 0
        self.guitype = guitype
        self.name = _name
        self.accept_sensitive = self.parent.config.getb("accept_sensitive")
        self.buffer = []
        self.sessionpath = os.path.join(os.path.expanduser(self.parent.config.get("chatdir")), certhash)
        self.init_pathes()

        self._thread = Thread(target=self.sendthread, daemon=True)
        self._thread.start()
    
    def init_gui(self):
        if self.guitype != "gtk":
            return None
        return self.parent.gui.gtk_node_iface(self.name, self.certhash, self.addressfunc, self.traversefunc, self.window)

    def init_pathes(self):
        os.makedirs(self.sessionpath, 0o770, exist_ok=True)
        os.makedirs(os.path.join(self.sessionpath, "images"), 0o770, exist_ok=True)
        os.makedirs(os.path.join(self.sessionpath, "tosend"), 0o770, exist_ok=True)
        os.makedirs(os.path.join(self.sessionpath, "out"), 0o770, exist_ok=True)
        self.outcounter = len(os.listdir(os.path.join(self.sessionpath, "out")))//2

    def request(self, action, arguments): #, timestamp=create_timestamp()): #, _traversefunc()
        url = self.addressfunc()
        if url is None:
            logging.error("No address")
            return None
        #sock, _cert, _hash = 
        #, timestamp=timestamp
        return self.parent.resources("plugin")(url, "chat", self.parent.reqstring.format(action=action, privstate=str(self.private), other=arguments), forcehash=self.certhash, traverseserveraddr=self.traversefunc())

    def load(self):
        with self.lock:
            try:
                with open (os.path.join(self.sessionpath, "log.json"), "r") as readob:
                    self.buffer = json.load(readob)
            except Exception:
                pass
            if "gtk" in self.parent.interfaces:
                self.parent.gui.updateb(self.certhash)

    def remove_file(self, name):
        try:
            os.unlink(os.path.join(self.sessionpath, "tosend", name))
        except Exception:
            pass
        with self.lock:
            self.buffer = list(filter(lambda x: x.get("type", "unknown") == "file" and x.get("name", None) == name and x.get("owner") == True, self.buffer))
            self.save()
            if "gtk" in self.parent.interfaces:
                self.parent.gui.updateb(self.certhash)
    
    def remove_download(self, name):
        with self.lock:
            self.buffer = list(filter(lambda x: lambda x: x.get("type", "unknown") == "file" and x.get("name", None) == name and x.get("owner") == False, self.buffer))
            self.save()
            if "gtk" in self.parent.interfaces:
                self.parent.gui.updateb(self.certhash)

    def remove_image(self, nahash):
        try:
            os.unlink(os.path.join(self.sessionpath, "images", nahash+".jpg"))
        except Exception:
            pass
        with self.lock:
            self.buffer = list(filter(lambda x: x.get("hash", None) == nahash, self.buffer)[:])
            if "gtk" in self.parent.interfaces:
                self.parent.gui.updateb(self.certhash)
            self.save()
    def add(self, obj):
        with self.lock:
            self.buffer.append(obj)
            if "gtk" in self.parent.interfaces:
                self.parent.gui.updateb_add(self.certhash)

    def num_private(self):
        return len(list(filter(lambda x: x.get("private", 0) == 1 , self.buffer)))

    def num_sensitive(self):
        return len(list(filter(lambda x: x.get("private", 0) == 2, self.buffer)))
    
    def clear_private(self):
        with self.lock:
            self.buffer = list(filter(lambda x: not x.get("private", 0) >= 1, self.buffer))
            self.save()
            if "gtk" in self.parent.interfaces:
                self.parent.gui.updateb(self.certhash)

    def clear_sensitive(self):
        with self.lock:
            self.buffer = list(filter(lambda x: x.get("private", 0) != 2, self.buffer))
            self.save()
            if "gtk" in self.parent.interfaces:
                self.parent.gui.updateb(self.certhash)
            

    def save (self):
        result = list(filter(lambda x: x.get("private", 0) == 0, self.buffer))
        with self.lock:
            with open (os.path.join(self.sessionpath, "log.json.tmp"), "w") as logob:
                json.dump(result, logob)
            os.replace(os.path.join(self.sessionpath, "log.json.tmp"), os.path.join(self.sessionpath, "log.json"))

    def sendthread(self):
        while True:
            with self.lock:
                self.init_pathes()
                temp = sorted(os.listdir(os.path.join(self.sessionpath, "out")))
            if self.addressfunc() is not None:
                for elem in temp:
                    num, _type = elem.split("_", 1)
                    if _type != "args":
                        continue
                    if not os.path.exists(os.path.join(self.sessionpath, "out", num+"_file")):
                        continue
                    
                    with self.lock:
                        with open(os.path.join(self.sessionpath, "out", str(self.outcounter))+"_args", "r") as readob:
                            action, parameters = readob.read().split("/", 1)
                        _socket, _cert, _hash = self.request(action, parameters)
                        if _socket:
                            with open(os.path.join(self.sessionpath, "out", num+"_file"), "rb") as readob:
                                _socket.sendfile(readob)
                                os.remove(os.path.join(self.sessionpath, "out", num+"_file"))
                                os.remove(os.path.join(self.sessionpath, "out", num+"_args"))
                with self.lock:
                    self.init_pathes()
                    self.outcounter = len(os.listdir(os.path.join(self.sessionpath, "out")))//2
            time.sleep(5)

    # send when connection is available
    def send(self, action, arguments, _ob):
        with self.lock:
            self.init_pathes()
            with open(os.path.join(self.sessionpath, "out", str(self.outcounter))+"_args", "w") as writeob:
                writeob.write(action+"/"+arguments)
            with open(os.path.join(self.sessionpath, "out", str(self.outcounter))+"_file", "wb") as writeob:
                writeob.write(_ob)
            self.outcounter += 1

class chat_plugin(object):
    lname = {"*": "Chat"}

    sessions = None
    openforeign = 0
    reqstring = None
    gui = None

    gui_node_actions = None
    
    def __init__(self, interfaces, config, resources, proot):
        self.interfaces, self.config, self.resources, self.proot = interfaces, config, resources, proot
        self.reqstring = "{action}/{privstate}/%s{other}" % resources("access")("show")[1]["port"]
        self.sessions = {}
        self.gui_node_actions = [{"text":"Delete all messages", "action": self.delete_log, \
"interfaces": ["gtk",], "description": "Delete the chat log"},
{"text":"Delete private messages", "action": self.clear_private, \
"interfaces": ["gtk",], "description": "Delete private and sensitive messages"}, {"text":"Delete sensitive messages", "action": self.clear_sensitive, \
"interfaces": ["gtk",], "description": "Delete sensitive messages"},
{"text":"Accept sensitive messages", "action": self.activate_sensitive, \
"state": self.config.getb("accept_sensitive"), \
"interfaces": ["gtk",], "description": "Accept sensitive messages"}

]
        self.gui = gtkstuff.gtkstuff(self)

    def cleanup(self, widget, certhash):
        self.sessions[certhash].save()
        del self.sessions[certhash]
        #port_to_answer = None

    def delete_log(self, gui, _addressfunc, window, certhash, dheader):
        if certhash not in self.sessions:
            return
        with self.sessions[certhash].lock:
            try:
                shutil.rmtree(os.path.join(os.path.expanduser(self.config.get("chatdir")), certhash))
                #os.remove(os.path.join(os.path.expanduser(config.get("chatdir")), dheader.get("forcehash")+".log"))
            except FileNotFoundError:
                pass
            
            self.sessions[certhash].buffer.clear()
            self.gui.updateb(certhash)
    
    def clear_private(self, gui, _addressfunc, window, certhash, dheader):
        if certhash not in self.sessions:
            return
        self.sessions[certhash].clear_private()
    
    
    def clear_sensitive(self, gui, _addressfunc, window, certhash, dheader):
        if certhash not in self.sessions:
            return
        self.sessions[certhash].clear_sensitive()
    
    def activate_sensitive(self, gui, _addressfunc, window, certhash, state, dheader):
        if not state:
            self.clear_sensitive(gui, _addressfunc, window, certhash, dheader)
        self.sessions[certhash].accept_sensitive = state

    def gui_node_iface(self, guitype, _name, certhash, _addressfunc, _traversefunc, window):
        if guitype != "gtk":
            return None
            
        self.sessions[certhash] = hash_session(guitype, self,  _name, certhash, _addressfunc, _traversefunc, window)
        return self.sessions[certhash].init_gui()

    # not needed because routine
    def address_change(self, gui, _address, window, _hash):
        pass
    
    def check_limits(self, action, size):
        if action == "send_text" and size <= self.config.get("maxsizetext"):
            return True
        elif action == "send_img" and size <= self.config.get("maxsizeimg")*1024:
            return True
        elif action == "send_file":
            return True
        return False
    
    def receive(self, action, _socket, _cert, certhash):
        splitted = action.split("/", 4)
        if len(splitted) == 5:
            action, _private, answerport, _size, _rest = splitted
        elif len(splitted) == 4:
            action, _private, answerport, _size = splitted
        else:
            _socket.close()
            return
        size = int(_size)
        private = int(_private)
        
        #if certhash not in self.chatlock:
        #    if resources("access")("getlocal", hash=certhash)[0] == False:
        #        return
        #    self.resources("open_node")("{}-{}".format(_socket.getsockname()[0], answerport), page="chat", forcehash=certhash)

        if certhash not in self.sessions:
            # if still not existent
            _socket.close()
            return

        if private == 2 and not self.sessions[certhash].accept_sensitive:
            _socket.shutdown(socket.SHUT_RDWR)
            _socket.close()
            return

        if action == "fetch_file":
            pos = size
            name = _rest
            if "/" in name or "\\" in name or name[0] == ".":
                logging.error("Invalid filename")
                return
            _path = os.path.join(self.sessions[certhash].sessionpath, "tosend", name)
            if os.path.isfile(_path):
                with open(_path, "rb") as rbfile: 
                    _socket.sendfile(rbfile, pos)
                _socket.close()
                self.sessions[certhash].remove_file(name)
                try:
                    os.unlink(_path)
                except Exception:
                    pass
            return
        
        if not self.check_limits(action, size):
            _socket.shutdown(socket.SHUT_RDWR)
            _socket.close()
            return
        
        saveob = {}
        saveob["timestamp"] = create_timestamp()
        saveob["private"] = int(private)
        saveob["owner"] = False
        saveob["type"] = "unknown"
    
        self.sessions[certhash].init_pathes()
        
        countread = 0
        data = b""
        if action != "send_file":
            while countread <= size-1024:
                _data = _socket.recv(1024)
                data += _data
                countread += len(_data)
            data += _socket.recv(size-countread)
            _socket.close()
        
        if action == "send_img":
            saveob["type"] = "img"
            _imgname = hashlib.sha256(data).hexdigest()+".jpg"
            _imgname = os.path.join(self.sessions[certhash].sessionpath, "images", _imgname)
            if saveob["private"] == 0:
                with open (_imgname, "wb") as imgob:
                    imgob.write(data)
                saveob["hash"] = hashlib.sha256(data).hexdigest()
            else:
                # if private then save img as "data" because it won't be saved
                saveob["data"] = data
        elif action == "send_text":
            saveob["type"] = "text"
            saveob["text"] = str(data, "utf-8")
        elif action == "send_file":
            saveob["type"] = "file"
            saveob["size"] = size
            saveob["name"] = _rest
        self.sessions[certhash].add(saveob)

    ## executed when redirected, return False, when redirect should not be executed
    # def rreceive(self, action, _socket, _cert, certhash):
    #     pass
    ### server:
    # def sreceive(self, action, _socket, _cert, certhash):
    #     pass
