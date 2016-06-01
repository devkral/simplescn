#! /usr/bin/env python3
#license: bsd3, see LICENSE.txt

import os

from http.client import HTTPSConnection
import time
import threading
import json
import logging
import ssl
import socket

from simplescn import server_port, check_certs, generate_certs, init_config_folder, default_configdir, check_name, dhash, commonscn, check_argsdeco, scnauth_server, max_serverrequest_size, generate_error, gen_result, high_load, medium_load, low_load, very_low_load, InvalidLoadSizeError, InvalidLoadLevelError, generate_error_deco, default_priority, default_timeout, check_updated_certs, traverser_dropper, scnparse_url, create_certhashheader, classify_local, classify_access, http_server, commonscnhandler, default_loglevel, loglevel_converter, connect_timeout, check_hash, check_local, harden_mode, debug_mode, sharedir, file_family

server_broadcast_header = \
{
    "User-Agent": "simplescn/1.0 (broadcast)",
    "Authorization": 'scn {}',
    "Connection": 'keep-alive' # keep-alive is set by server (and client?)
}

class server(commonscn):
    # replace not add (multi instance)
    capabilities = ["basic", "server"]
    nhipmap = None
    nhipmap_cache = ""
    refreshthread = None
    cert_hash = None
    scn_type = "server"
    traverse = None
    links = None
    timeout = None
    connect_timeout = None

    # explicitly allowed, note: server plugin can activate
    # this by their own version of this variable
    allowed_plugin_broadcasts = set()
    # auto set by load balancer
    expire_time = None
    sleep_time = None

    validactions = {"register", "get", "dumpnames", "info", "cap", "prioty", "num_nodes", "open_traversal", "get_ownaddr"}

    def __init__(self, d):
        commonscn.__init__(self)
        # init here (multi instance situation)
        self.nhipmap = {}
        self.nhipmap_cond = threading.Event()
        self.changeip_lock = threading.Lock()
        # now: always None, because set manually
        #  traversesrcaddr = d.get("traversesrcaddr", None)
        if len(very_low_load) != 2 or len(low_load) != 3 or len(medium_load) != 3 or len(high_load) != 3:
            raise InvalidLoadSizeError()
        if high_load[0] < medium_load[0] or medium_load[0] < low_load[0]:
            raise InvalidLoadLevelError()
        if d["name"] is None or len(d["name"]) == 0:
            logging.debug("Name empty")
            d["name"] = "<noname>"
        if d["message"] is None or len(d["message"]) == 0:
            logging.debug("Message empty")
            d["message"] = "<empty>"

        self.timeout = d["timeout"]
        self.connect_timeout = d["connect_timeout"]
        self.priority = int(d["priority"])
        self.cert_hash = d["certhash"]
        self.name = d["name"]
        self.message = d["message"]
        self.links = d["links"]
        self.update_cache()
        self.load_balance(0)
        self.refreshthread = threading.Thread(target=self.refresh_nhipmap, daemon=True)
        self.refreshthread.start()
        # now: traversesrcaddr always invalid, set manually by init
        #  if traversesrcaddr:
        #      self.traverse = traverser_dropper(traversesrcaddr)

    def __del__(self):
        commonscn.__del__(self)
        self.nhipmap_cond.set()
        try:
            self.refreshthread.join(4)
        except Exception as exc:
            logging.error(exc)

    # private, do not include in validactions
    def refresh_nhipmap(self):
        while self.isactive:
            self.changeip_lock.acquire()
            e_time = int(time.time())-self.expire_time
            count = 0
            dump = []
            for _name, hashob in self.nhipmap.items():
                for _hash, val in hashob.items():
                    if val["updatetime"] < e_time:
                        del self.nhipmap[_name][_hash]
                    else:
                        count += 1
                        dump.append((_name, _hash, val.get("security")))
                if len(self.nhipmap[_name]) == 0:
                    del self.nhipmap[_name]
            ### don't annote list with "map" dict structure on serverside (overhead)
            self.cache["dumpnames"] = json.dumps(gen_result(dump, True))
            self.cache["num_nodes"] = json.dumps(gen_result(count, True))
            self.cache["update_time"] = json.dumps(gen_result(int(time.time()), True))
            self.changeip_lock.release()
            self.nhipmap_cond.clear()
            self.load_balance(count)
            time.sleep(self.sleep_time)
            # wait until hashes change
            self.nhipmap_cond.wait()

    # private, do not include in validactions
    def load_balance(self, size_nh):
        if size_nh >= high_load[0]:
            self.sleep_time, self.expire_time = high_load[1:]
        elif size_nh >= medium_load[0]:
            self.sleep_time, self.expire_time = medium_load[1:]
        elif size_nh >= low_load[0]:
            self.sleep_time, self.expire_time = low_load[1:]
        else:
            # very_low_load tuple mustn't have three items
            self.sleep_time, self.expire_time = very_low_load

    # private, do not include in validactions
    def check_register(self, addresst, _hash):
        try:
            _cert = ssl.get_server_certificate(addresst, ssl_version=ssl.PROTOCOL_TLSv1_2).strip().rstrip()
        except ConnectionRefusedError:
            return [False, "use_traversal"]
        except ssl.SSLError:
            return [False, "use_traversal"]
        if _cert is None:
            return [False, "no_cert"]
        if dhash(_cert) != _hash:
            return [False, "hash_mismatch"]
        return [True, "registered_ip"]

    def check_brokencerts(self, _address, _port, _name, certhashlist, newhash):
        """ func: connect to check if requester has broken certs """
        update_list = check_updated_certs(_address, _port, certhashlist, newhash=newhash)
        if update_list in [None, []]:
            return

        self.changeip_lock.acquire(True)
        update_time = int(time.time())
        for _uhash, _usecurity in update_list:
            self.nhipmap[_name][_uhash] = {"security": _usecurity, "hash": newhash, "name": _name, "updatetime": update_time}
        self.changeip_lock.release()
        # notify that change happened
        self.nhipmap_cond.set()

    @check_argsdeco({"name": str, "port": int}, optional={"update": list})
    def register(self, obdict):
        """ func: register client
            return: success or error
            name: client name
            port: listen port of client
            update: list with compromised hashes (includes reason=security) """
        if not check_name(obdict["name"]):
            return False, "invalid_name"
        if obdict["clientcert"] is None:
            return False, "no_cert"

        clientcerthash = obdict["clientcerthash"]
        ret = self.check_register((obdict["clientaddress"][0], obdict["port"]), clientcerthash)
        if not ret[0]:
            ret = self.open_traversal({"clientaddress": ('', obdict["socket"].getsockname()[1]), "destaddr": "{}-{}".format(obdict["clientaddress"][0], obdict["port"])})
            if not ret[0]:
                return ret
            ret = self.check_register((obdict["clientaddress"][0], obdict["port"]), clientcerthash)
            if not ret[0]:
                return False, "unreachable client"
            ret[1] = "registered_traversal"
        elif check_local(obdict["clientaddress"][0]):
            ret[1] = "registered_traversal"
        self.changeip_lock.acquire(False)
        update_time = int(time.time())
        if obdict["name"] not in self.nhipmap:
            self.nhipmap[obdict["name"]] = {}
        if clientcerthash not in self.nhipmap[obdict["name"]]:
            # set security=valid for next step
            self.nhipmap[obdict["name"]][clientcerthash] = {"security": "valid"}
        # when certificate has a compromised flag (!=valid) stop register process
        if self.nhipmap[obdict["name"]][clientcerthash].get("security", "valid") == "valid":
            self.nhipmap[obdict["name"]][clientcerthash]["address"] = obdict["clientaddress"][0]
            self.nhipmap[obdict["name"]][clientcerthash]["port"] = obdict["port"]
            self.nhipmap[obdict["name"]][clientcerthash]["updatetime"] = update_time
            self.nhipmap[obdict["name"]][clientcerthash]["security"] = "valid"
            self.nhipmap[obdict["name"]][clientcerthash]["traverse"] = ret[1] == "registered_traversal"
        self.changeip_lock.release()

        # update broken certs afterwards
        threading.Thread(target=self.check_brokencerts, args=(obdict["clientaddress"][0], obdict["port"], obdict["name"], obdict.get("update", []), clientcerthash), daemon=True).start()

        # notify that change happened
        self.nhipmap_cond.set()
        return True, {"mode": ret[1], "traverse": ret[1] == "registered_traversal"}

    @check_argsdeco({"destaddr": str})
    def open_traversal(self, obdict):
        """ func: open traversal connection
            return: traverse_address (=remote own address)
            destaddr: destination address """
        if self.traverse is None:
            return False, "no traversal possible"
        try:
            destaddr = scnparse_url(obdict.get("destaddr"), True)
        except Exception:
            return False, "destaddr invalid"
        travaddr = obdict.get("clientaddress") #(obdict["clientaddress"][0], travport)
        threading.Thread(target=self.traverse.send_thread, args=(travaddr, destaddr), daemon=True).start()
        return True, {"traverse_address": travaddr}

    @check_argsdeco()
    @classify_local
    def get_ownaddr(self, obdict):
        """ func: return remote own address
            return: remote requester address """
        return True, {"address": obdict.get("clientaddress")}

    @check_argsdeco({"hash": str, "name": str}, optional={"autotraverse": bool})
    def get(self, obdict):
        """ func: get address of a client
            return: client address, client port, security, traverse_address, traverse_needed
            name: client name
            hash: client hash
            autotraverse: open traversal when necessary (default: False) """
        if obdict["name"] not in self.nhipmap:
            return False, "name not exist"
        if obdict["hash"] not in self.nhipmap[obdict["name"]]:
            return False, "hash not exist"
        _obj = self.nhipmap[obdict["name"]][obdict["hash"]]
        if _obj.get("security", "") != "valid":
            _usecurity, _uname, _uhash = _obj.get("security"), _obj["name"], _obj["hash"]
            _obj = self.nhipmap[_obj["name"]][_obj["hash"]]
        else:
            _usecurity = None
        _travaddr = None
        if self.traverse and _obj.get("autotraverse", False):
            _travobj1 = self.open_traversal(obdict)
            if _travobj1[0]:
                _travaddr = _travobj1[1].get("traverse_address")
        if _usecurity:
            return True, {"address": _obj["address"], "security": _usecurity, "port": _obj["port"], "name": _uname, "hash": _uhash, "traverse_needed": _obj["traverse"], "traverse_address":_travaddr}
        else:
            return True, {"address": _obj["address"], "security": "valid", "port": _obj["port"], "traverse_needed": _obj["traverse"], "traverse_address":_travaddr}

    def broadcast_helper(self, _addr, _path, payload, _certhash, timeout=default_timeout, timeout_con=connect_timeout):
        try:
            con = HTTPSConnection(_addr, timeout=connect_timeout)
            con.connect()
            con.socket.settimeout(timeout)
            pcert = ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True))
            hashpcert = dhash(pcert)
            if hashpcert != _certhash:
                return
            _headers = server_broadcast_header.copy()
            _headers["X-certrewrap"], _random = create_certhashheader(self.cert_hash)
            con.putrequest("POST", _path)
            for _name, _val in _headers:
                con.putheader(_name, _val)
            con.putheader("Content-Length", str(len(payload)))
            con.endheaders()
            con.sock = con.sock.unwrap()
            con.sock = self.links["hserver"].sslcont.wrap_socket(con.sock, server_side=True)
            resp = client.HTTPResponse(con.sock, con.debuglevel, method=con._method)
            resp.begin()
            if resp.status != 200:
                logging.error("requesting plugin failed: %s, action: %s, status: %s, reason: %s", plugin, paction, resp.status, resp.reason)
                con.close()
                return
            if _random != resp.getheader("X-certrewrap", ""):
                logging.error("rewrapped cert secret does not match")
                con.close()
                return
            con.send(payload)
            con.close()
        except socket.timeout:
            pass
        except Exception as e:
            logging.debug(e)

    # limited by maxrequest size
    @check_argsdeco({"plugin": str, "receivers": list, "paction": str, "payload": str})
    def broadcast_plugin(self, obdict):
        """ func: broadcast to client plugins
            return: success or error
            plugin: plugin name
            receivers: list with receivertuples
            paction: plugin action
            payload: payload as string """
        _plugin = obdict.get("plugin")
        paction = obdict.get("paction").split("/", 1)[0]
        if (_plugin, paction) not in self.allowed_plugin_broadcasts:
            return False, "not in allowed_plugin_broadcasts"
        for elem in obdict.get("receivers"):
            if len(elem) != 2:
                logging.debug("invalid element: %s", elem)
                continue
            _name, _hash = elem
            if _name not in self.nhipmap:
                continue
            if _hash not in self.nhipmap[_name]:
                continue
            _telem2 = self.nhipmap[_name][_hash]
            self.broadcast_helper("{}-{}".format(_telem2.get("address", ""), _telem2.get("port", -1)), "/plugin/{}/{}".format(_plugin, obdict.get("paction")), bytes(obdict.get("payload"), "utf-8"), self.timeout, self.connect_timeout)

    @generate_error_deco
    @classify_access
    def access_server(self, action, requester="", **obdict):
        if action in self.cache:
            return self.cache[action]
        if action not in ["get", "broadcast_plugin"]:
            return False, "no permission"
        try:
            return getattr(self, action)(obdict)
        except Exception as exc:
            return False, exc

def gen_server_handler():
    class server_handler(commonscnhandler):
        server_version = 'simplescn/1.0 (server)'
        webgui = False

        def handle_server(self, action):
            if self.server.address_family == file_family:
                self.scn_send_answer(500, message="file_family is not supported by server component")
                return
            if action not in self.links["server_server"].validactions:
                self.scn_send_answer(400, message="invalid action - server")
                return
            if not self.links["auth_server"].verify("server", self.auth_info):
                authreq = self.links["auth_server"].request_auth("server")
                ob = bytes(json.dumps(authreq), "utf-8")
                self.scn_send_answer(401, body=ob, docache=False)
                return
            if action in self.links["server_server"].cache:
                # cleanup {} or smaller, protect against big transmissions
                self.cleanup_stale_data(2)
                ob = bytes(self.links["server_server"].cache[action], "utf-8")
                self.scn_send_answer(200, body=ob, docache=False)
                return

            obdict = self.parse_body(max_serverrequest_size)
            if obdict is None:
                return None
            try:
                func = getattr(self.links["server_server"], action)
                success, result = func(obdict)[:2]
                jsonnized = json.dumps(gen_result(result, success))
            except Exception as exc:
                generror = generate_error(exc)
                if not debug_mode or not check_local(self.client_address2[0]):
                    # don't show stacktrace if not permitted and not in debug mode
                    if "stacktrace" in generror:
                        del generror["stacktrace"]
                    # with harden mode do not show errormessage
                    if harden_mode:
                        generror = generate_error("unknown")
                ob = bytes(json.dumps(gen_result(generror, False)), "utf-8")
                self.scn_send_answer(500, body=ob, mime="application/json", docache=False)
                return
            ob = bytes(jsonnized, "utf-8")
            if not success:
                self.scn_send_answer(400, body=ob, mime="application/json", docache=False)
            else:
                self.scn_send_answer(200, body=ob, mime="application/json", docache=False)

        def do_GET(self):
            if not self.init_scn_stuff():
                return
            if self.path == "/favicon.ico":
                if "favicon.ico" in self.statics:
                    self.scn_send_answer(200, body=self.statics["favicon.ico"], docache=True)
                else:
                    self.scn_send_answer(404, docache=True)
                return
            if not self.webgui:
                self.scn_send_answer(404, message="no webgui enabled", docache=True)
            _path = self.path[1:].split("/")
            if _path[0] in ("", "server", "html", "index"):
                self.html("server.html")
                return
            elif  _path[0] == "static" and len(_path) >= 2:
                if _path[1] in self.statics:
                    self.scn_send_answer(200, body=self.statics[_path[1]])
                return
            elif len(_path) == 2:
                self.handle_server(_path[0])
                return
            self.scn_send_answer(404, message="resource not found (GET)", docache=True)

        def do_POST(self):
            if not self.init_scn_stuff():
                return
            splitted = self.path[1:].split("/", 1)
            if len(splitted) == 1:
                resource = splitted[0]
                sub = ""
            else:
                resource = splitted[0]
                sub = splitted[1]
            if resource == "plugin":
                plugindomain = "plugin:{}".format(plugin)
                if not self.do_auth(plugindomain):
                    return
                pluginm = self.links["server_server"].pluginmanager
                split2 = sub.split("/", 1)
                if len(split2) != 2:
                    self.send_error(400, "no plugin/action specified", "No plugin/action was specified")
                    return
                plugin, action = split2
                if plugin not in pluginm.plugins or hasattr(pluginm.plugins[plugin], "sreceive"):
                    self.send_error(404, "plugin not available", "Plugin with name {} does not exist/is not capable of receiving".format(plugin))
                    return

                self.handle_plugin(pluginm.plugins[plugin].sreceive, action)
            # for invalidating and updating, don't use connection afterwards
            elif resource == "usebroken":
                self.handle_usebroken(sub)
            elif resource == "server":
                self.handle_server(sub)
            else:
                self.scn_send_answer(404, message="resource not found (POST)", docache=True)
    return server_handler

class server_init(object):
    config_path = None
    links = None

    def __init__(self, _configpath, **kwargs):
        self.links = {}
        self.links["config_root"] = _configpath
        self.links["handler"] = gen_server_handler()
        _spath = os.path.join(self.links["config_root"], "server")
        port = int(kwargs["port"][0])
        init_config_folder(self.links["config_root"], "server")
        if not check_certs(_spath+"_cert"):
            logging.debug("Certificate(s) not found. Generate new...")
            generate_certs(_spath + "_cert")
            logging.debug("Certificate generation complete")
        with open(_spath+"_cert.pub", 'rb') as readinpubkey:
            pub_cert = readinpubkey.read().strip().rstrip()
        self.links["auth_server"] = scnauth_server(dhash(pub_cert))
        if bool(kwargs["spwhash"][0]):
            if not check_hash(kwargs["spwhash"][0]):
                logging.error("hashtest failed for spwhash, spwhash: %s", kwargs["spwhash"][0])
            else:
                self.links["auth_server"].init_realm("server", kwargs["spwhash"][0])
        elif bool(kwargs["spwfile"][0]):
            with open(kwargs["spwfile"][0], "r") as op:
                pw = op.readline()
                if pw[-1] == "\n":
                    pw = pw[:-1]
                self.links["auth_server"].init_realm("server", dhash(pw))

        if kwargs["webgui"][0] != "False":
            self.links["handler"].webgui = True
            # load static files
            # replace placeholder
            self.links["handler"].statics = {}
            for elem in os.listdir(os.path.join(sharedir, "static")):
                with open(os.path.join(sharedir, "static", elem), 'rb') as _staticr:
                    self.links["handler"].statics[elem] = _staticr.read()
        else:
            self.links["handler"].webgui = False
        _message = None
        _name = None
        with open(_spath+"_name.txt", 'r') as readserver:
            _name = readserver.readline().strip().rstrip()
        with open(_spath+"_message.txt", 'r') as readservmessage:
            _message = readservmessage.read()
        if None in [pub_cert, _name, _message]:
            raise Exception("missing")
        _name = _name.split("/")
        if len(_name) > 2 or not check_name(_name[0]):
            logging.error("Configuration error in %s\nshould be: <name>/<port>\nor name contains some restricted characters", _spath + "_name")

        if port > -1:
            _port = port
        elif len(_name) >= 2:
            _port = int(_name[1])
        else:
            _port = server_port

        serverd = {"name": _name[0], "certhash": dhash(pub_cert), "timeout": kwargs["timeout"][0], "connect_timeout": kwargs["connect_timeout"][0], "priority": kwargs["priority"][0], "message":_message, "links": self.links}
        self.links["handler"].links = self.links
        self.links["server_server"] = server(serverd)

        # server without server have fun if False
        if kwargs["noserver"][0] != "True":
            self.links["hserver"] = http_server(("", _port), _spath+"_cert", self.links["handler"], "Enter server certificate pw", timeout=int(kwargs["timeout"][0]))
            if kwargs["notraversal"][0] != "True":
                srcaddr = self.links["hserver"].socket.getsockname()
                self.links["server_server"].traverse = traverser_dropper(srcaddr)

    def serve_forever_block(self):
        self.links["hserver"].serve_forever()

    def serve_forever_nonblock(self):
        sthread = threading.Thread(target=self.serve_forever_block, daemon=True)
        sthread.start()

#### don't base on sqlite, configmanager as it increases complexity and needed libs
#### but optionally support plugins (some risk)

overwrite_server_args = {
    "config": [default_configdir, str, "<path>: path to config dir"],
    "port": [str(-1), int, "<int>: port of server, -1: use port in \"server_name.txt\""],
    "spwhash": ["", str, "<lowercase hash>: sha256 hash of pw, higher preference than pwfile, lowercase"],
    "spwfile": ["", str, "<file>: file with password (cleartext)"],
    "webgui": ["False", bool, "<bool>: activate webgui"],
    "useplugins": ["False", bool, "<bool>: activate plugins"],
    "priority": [str(default_priority), int, "<int>: set server priority"],
    "connect_timeout": [str(connect_timeout), int, "<int>: set timeout for connecting"],
    "timeout": [str(default_timeout), int, "<int>: set timeout"],
    "loglevel": [str(default_loglevel), loglevel_converter, "<int/str>: loglevel"],
    "notraversal": ["False", bool, "<bool>: disable traversal"],
    "noserver": ["False", bool, "<bool>: deactivate httpserver (=a server without a server, have fun)"]}

def server_paramhelp():
    _temp = "# parameters (non-permanent)\n"
    for _key, elem in sorted(overwrite_server_args.items(), key=lambda x: x[0]):
        _temp += "  * key: {}, value: {}, doc: {}\n".format(_key, elem[0], elem[2])
    return _temp

