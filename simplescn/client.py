#! /usr/bin/env python3
"""
main client stuff (client)
license: MIT, see LICENSE.txt
"""

import sys
import os
import socket
import threading
import json
import logging

from simplescn import config, VALError, AuthNeeded, AddressFail
from simplescn.config import isself, file_family
from simplescn._common import parsepath, parsebool, commonscn, commonscnhandler, http_server, generate_error, gen_result, certhash_db, loglevel_converter


from simplescn.tools import generate_certs, init_config_folder, dhash, rw_socket, scnauth_server, traverser_helper, default_sslcont
from simplescn.tools.checks import check_certs, check_name, check_hash, check_local, check_classify
from simplescn._decos import check_args_deco, classify_local, classify_access
from simplescn._client_admin import client_admin
from simplescn._client_safe import client_safe
from simplescn.scnrequest import requester

#VALMITMError


reference_header = \
{
    "User-Agent": "simplescn/1.0 (client)",
    "Authorization": 'scn {}',
    "Connection": 'keep-alive' # keep-alive is set by server (and client?)
}
class client_client(client_admin, client_safe):
    name = None
    cert_hash = None
    sslcont = None
    hashdb = None
    links = None
    scntraverse_helper = None
    brokencerts = None
    _cache_help = None

    validactions = None
    requester = None

    def __init__(self, name: str, pub_cert_hash: str, _links: dict):
        client_admin.__init__(self)
        client_safe.__init__(self)
        self.links = _links
        self.name = name
        self.cert_hash = pub_cert_hash
        self.hashdb = certhash_db(os.path.join(self.links["config_root"], "certdb.sqlite"))
        if "hserver" in self.links:
            self.sslcont = self.links["hserver"].sslcont
        else:
            self.sslcont = default_sslcont()
        self.brokencerts = []
        self.validactions = set()
        self.requester = requester(ownhash=self.cert_hash, hashdb=self.hashdb, certcontext=self.sslcont)
        

        if "hserver" in self.links:
            self.udpsrcsock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            self.udpsrcsock.settimeout(None)
            self.udpsrcsock.bind(self.links["hserver"].socket.getsockname())
            self.scntraverse_helper = traverser_helper(connectsock=self.links["hserver"].socket, srcsock=self.udpsrcsock)

        for elem in os.listdir(os.path.join(self.links["config_root"], "broken")):
            _splitted = elem.rsplit(".", 1)
            if _splitted[1] != "reason":
                continue
            _hash = _splitted[0]
            with open(os.path.join(self.links["config_root"], "broken", elem), "r") as reado:
                _reason = reado.read().strip().rstrip()
            if check_hash(_hash) and (_hash, _reason) not in self.brokencerts:
                self.brokencerts.append((_hash, _reason))

        # update self.validactions
        self.validactions.update(client_admin.validactions_admin)
        self.validactions.update(client_safe.validactions_safe)
        self._cache_help = self.cmdhelp()

    # return success, body, (name, security), hash
    # return success, body, isself, hash
    # return success, body, None, hash
    def do_request(self, addr_or_con, path: str, body=None, headers=None, forceport=False, forcehash=None, forcetraverse=False, sendclientcert=False):
        """ func: wrapper+ cache certcontext and ownhash """
        return self.requester.do_request_simple(addr_or_con, path, body, headers, forceport=forceport, forcehash=forcehash, forcetraverse=forcetraverse, sendclientcert=sendclientcert)

    @classify_access
    def access_core(self, action, obdict):
        """ internal method to access functions """
        if action in self.validactions:
            gaction = getattr(self, action)
            if check_classify(gaction, "access"):
                return False, "actions: 'classified access not allowed in access_core", isself, self.cert_hash
            if check_classify(gaction, "experimental"):
                logging.warning("action: \"%s\" is experimental", action)
            #with self.client_lock: # not needed, use sqlite's intern locking mechanic
            try:
                return getattr(self, action)(obdict)
            except AuthNeeded as exc:
                raise(exc)
            except Exception as exc:
                return False, exc #.with_traceback(sys.last_traceback)
        else:
            return False, "not in validactions", isself, self.cert_hash

    # help section
    def cmdhelp(self):
        out = "# commands\n"
        for funcname in sorted(self.validactions):
            func = getattr(self, funcname)
            if getattr(func, "__doc__", None) is not None:
                out += "{doc}\n".format(doc=func.__doc__)
            else:
                logging.info("Missing __doc__: %s", funcname)
        return out

### receiverpart of client ###

class client_server(commonscn):
    spmap = None
    scn_type = "client"
    # replace commonscn capabilities
    capabilities = ["basic", "client"]
    validactions = {"info", "getservice", "dumpservices", "cap", "prioty", "registerservice", "delservice"}
    wlock = None
    def __init__(self, dcserver):
        commonscn.__init__(self)
        # init here (multi instance situation)
        self.spmap = {}
        self.wlock = threading.Lock()
        if dcserver["name"] is None or len(dcserver["name"]) == 0:
            logging.info("Name empty")
            dcserver["name"] = "<noname>"
        if dcserver["message"] is None or len(dcserver["message"]) == 0:
            logging.info("Message empty")
            dcserver["message"] = "<empty>"
        self.name = dcserver["name"]
        self.message = dcserver["message"]
        self.priority = dcserver["priority"]
        self.cert_hash = dcserver["certhash"]
        self.cache["dumpservices"] = json.dumps(gen_result({}, True))
        self.update_cache()
    ### the primary way to add or remove a service
    ### can be called by every application on same client
    ### don't annote list with "map" dict structure on serverside (overhead)

    @check_args_deco({"name": str, "port": int}, optional={"invisibleport": bool,"post": bool})
    @classify_local
    def registerservice(self, obdict):
        """ func: register a service = (map port to name)
            return: success or error
            name: service name
            port: port number
            invisibleport: port is not shown (but can wrap)
            post: send http post request with certificate in header to service """
        if obdict.get("clientaddress") is None:
            return False, "bug: clientaddress is None"
        if check_local(obdict.get("clientaddress")[0]):
            with self.wlock:
                self.spmap[obdict.get("name")] = (obdict.get("port"), obdict.get("invisibleport", False), obdict.get("post", False))
                self.cache["dumpservices"] = json.dumps(gen_result(self.spmap, True))
                #self.cache["listservices"] = json.dumps(gen_result(sorted(self.spmap.items(), key=lambda t: t[0]), True))
            return True
        return False, "no permission"

    # don't annote list with "map" dict structure on serverside (overhead)
    @check_args_deco({"name": str})
    @classify_local
    def delservice(self, obdict):
        """ func: delete a service
            return: success or error
            name: service name """
        if obdict.get("clientaddress") is None:
            return False, "bug: clientaddress is None"
        if check_local(obdict.get("clientaddress")[0]):
            with self.wlock:
                if obdict["name"] in self.spmap:
                    del self.spmap[obdict["name"]]
                    self.cache["dumpservices"] = json.dumps(gen_result(self.spmap, True)) #sorted(self.spmap.items(), key=lambda t: t[0]), True))
            return True
        return False, "no permission"

    ### management section - end ###

    @check_args_deco({"name": str})
    @classify_local
    def getservice(self, obdict):
        """ func: get the port of a service
            return: portnumber or negative for invisibleport
            name: servicename """
        if obdict["name"] not in self.spmap:
            return False
        if not self.spmap[obdict["name"]][1]:
            return True, self.spmap[obdict["name"]][0]
        else:
            return True, -1


def gen_client_handler(_links, server=False, client=False, remote=False):
    class client_handler(commonscnhandler):
        server_version = 'simplescn/1.0 (client)'
        handle_remote = remote
        links = _links
        
        def handle_wrap(self, servicename):
            service = self.links["client_server"].spmap.get(servicename, None)
            if service is None:
                # send error
                self.scn_send_answer(404, message="service not available")
                return
            port = service[0]
            sockd = None
            for addr in ["::1", "127.0.0.1"]:
                try:
                    sockd = socket.create_connection((addr, port), self.links["kwargs"].get("connect_timeout"))
                    break
                except Exception as e:
                    logging.debug(e)
                    sockd = None
            if sockd is None:
                self.scn_send_answer(404, message="service not reachable")
                return
            sockd.settimeout(self.links["kwargs"].get("timeout"))
            redout = threading.Thread(target=rw_socket, args=(self.connection, sockd), daemon=True)
            redout.run()
            rw_socket(sockd, self.connection)
        if client:
            def handle_client(self, action):
                if action not in self.links["client"].validactions:
                    self.send_error(400, "invalid action - client")
                    return
                gaction = getattr(self.links["client"], action)
                if not self.handle_remote and \
                    self.server.address_family != file_family and \
                    not check_local(self.client_address2[0]):
                    self.send_error(403, "no permission - client")
                    return
                if check_classify(gaction, "admin"):
                    #if self.client_cert is None:
                    #    self.send_error(403, "no permission (no certrewrap) - admin")
                    #    return
                    if "admin" in self.links["auth_server"].realms:
                        realm = "admin"
                    else:
                        realm = "client"
                else:
                    realm = "client"
                if not self.links["auth_server"].verify(realm, self.auth_info):
                    authreq = self.links["auth_server"].request_auth(realm)
                    ob = bytes(json.dumps(authreq), "utf-8")
                    self.scn_send_answer(401, body=ob, docache=False)
                    return
                obdict = self.parse_body()
                if obdict is None:
                    return
                try:
                    response = self.links["client"].access_core(action, obdict)
                except AuthNeeded as exc:
                    self.scn_send_answer(401, body=exc.reqob, mime="application/json", docache=False)
                    return

                if not response[0]:
                    error = response[1]
                    generror = generate_error(error)
                    if not config.debug_mode or (self.server.address_family != file_family and not check_local(self.client_address2[0])):
                        # don't show stacktrace if not permitted and not in debug mode
                        if "stacktrace" in generror:
                            del generror["stacktrace"]
                        # with harden mode do not show errormessage
                        if config.harden_mode and not isinstance(error, (AddressFail, VALError)):
                            generror = generate_error("unknown")
                    resultob = gen_result(generror, False)
                    status = 500
                else:
                    resultob = gen_result(response[1], True)
                    status = 200
                jsonnized = bytes(json.dumps(resultob), "utf-8")
                self.scn_send_answer(status, body=jsonnized, mime="application/json", docache=False)
        if server:
            def handle_server(self, action):
                if action not in self.links["client_server"].validactions:
                    self.scn_send_answer(400, message="invalid action - server", docache=False)
                    return
                if not self.links["auth_server"].verify("server", self.auth_info):
                    authreq = self.links["auth_server"].request_auth("server")
                    ob = bytes(json.dumps(authreq), "utf-8")
                    self.cleanup_stale_data(config.max_serverrequest_size)
                    self.scn_send_answer(401, body=ob, docache=False)
                    return
                if action in self.links["client_server"].cache:
                    # cleanup {} or smaller, protect against big transmissions
                    self.cleanup_stale_data(2)
                    ob = bytes(self.links["client_server"].cache[action], "utf-8")
                    self.scn_send_answer(200, body=ob, docache=False)
                    return

                obdict = self.parse_body(config.max_serverrequest_size)
                if obdict is None:
                    return None
                try:
                    func = getattr(self.links["client_server"], action)
                    response = func(obdict)
                    jsonnized = json.dumps(gen_result(response[1], response[0]))
                except Exception as exc:
                    generror = generate_error(exc)
                    if not config.debug_mode or self.server.address_family != file_family or not check_local(self.client_address2[0]):
                        # don't show stacktrace if not permitted and not in debug mode
                        if "stacktrace" in generror:
                            del generror["stacktrace"]
                    # with harden mode do not show errormessage
                    if config.harden_mode and not isinstance(exc, (AddressFail, VALError)):
                        generror = generate_error("unknown")
                    ob = bytes(json.dumps(gen_result(generror, False)), "utf-8")
                    self.scn_send_answer(500, body=ob, mime="application/json")
                    return
                if jsonnized is None:
                    jsonnized = json.dumps(gen_result(generate_error("jsonized None"), False))
                    response[0] = False
                ob = bytes(jsonnized, "utf-8")
                if not response[0]:
                    self.scn_send_answer(400, body=ob, mime="application/json", docache=False)
                else:
                    self.scn_send_answer(200, body=ob, mime="application/json", docache=False)
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
            if resource == "wrap":
                if not self.links["auth_server"].verify("server", self.auth_info):
                    authreq = self.links["auth_server"].request_auth("server")
                    ob = bytes(json.dumps(authreq), "utf-8")
                    self.cleanup_stale_data(config.max_serverrequest_size)
                    self.scn_send_answer(401, body=ob, docache=False)
                else:
                    self.handle_wrap(sub)
            elif resource == "usebroken":
                # for invalidating and updating, don't use connection afterwards
                self.handle_usebroken(sub)
            elif server and resource == "server":
                self.handle_server(sub)
            elif client and resource == "client":
                self.handle_client(sub)
            else:
                self.scn_send_answer(404, message="resource not found (POST)", docache=True)
    return client_handler

class client_init(object):
    config_root = None
    plugins_config = None
    links = None
    run = True # necessary for some runmethods

    def __init__(self, **kwargs):
        self.links = {}
        self.links["config_root"] = kwargs.get("config")
        self.links["kwargs"] = kwargs
        handle_remote = False
        _cpath = os.path.join(self.links["config_root"], "client")
        init_config_folder(self.links["config_root"], "client")

        if not check_certs(_cpath + "_cert"):
            logging.info("Certificate(s) not found. Generate new...")
            generate_certs(_cpath + "_cert")
            logging.info("Certificate generation complete")
        with open(_cpath+"_cert.pub", 'rb') as readinpubkey:
            pub_cert = readinpubkey.read().strip().rstrip() #why fail
        #self.links["auth_client"] = scnauth_client()
        self.links["auth_server"] = scnauth_server(dhash(pub_cert))
        if kwargs.get("cpwhash"):
            if not check_hash(kwargs.get("cpwhash")):
                logging.error("hashtest failed for cpwhash, cpwhash: %s", kwargs.get("cpwhash"))
            else:
                # ensure that password is set when allowing remote access
                if kwargs.get("remote"):
                    handle_remote = True
                self.links["auth_server"].init_realm("client", kwargs.get("cpwhash"))
        elif kwargs.get("cpwfile"):
            # ensure that password is set when allowing remote access
            if kwargs.get("remote"):
                handle_remote = True
            with open(kwargs["cpwfile"][0], "r") as op:
                pw = op.readline()
                if pw[-1] == "\n":
                    pw = pw[:-1]
                self.links["auth_server"].init_realm("client", dhash(pw))

        if kwargs.get("apwhash"):
            if not check_hash(kwargs.get("apwhash")):
                logging.error("hashtest failed for apwhash, apwhash: %s", kwargs.get("apwhash"))
            else:
                self.links["auth_server"].init_realm("admin", kwargs.get("apwhash"))
        elif bool(kwargs["apwfile"]):
            with open(kwargs["apwfile"], "r") as op:
                pw = op.readline()
                if pw[-1] == "\n":
                    pw = pw[:-1]
                self.links["auth_server"].init_realm("admin", dhash(pw))
        if bool(kwargs.get("spwhash")):
            if not check_hash(kwargs.get("spwhash")):
                logging.error("hashtest failed for spwhash, spwhash: %s", kwargs.get("spwhash"))
            else:
                self.links["auth_server"].init_realm("server", kwargs.get("spwhash"))
        elif bool(kwargs.get("spwfile")):
            with open(kwargs["spwfile"], "r") as op:
                pw = op.readline()
                if pw[-1] == "\n":
                    pw = pw[:-1]
                self.links["auth_server"].init_realm("server", dhash(pw))

        with open(_cpath+"_name.txt", 'r') as readclient:
            _name = readclient.readline().strip().rstrip() # remove \n
        with open(_cpath+"_message.txt", 'r') as readinmes:
            _message = readinmes.read()
        #report missing file
        if None in [pub_cert, _name, _message]:
            raise Exception("missing")
        _name = _name.split("/")
        if len(_name) > 2 or not check_name(_name[0]):
            logging.error("Configuration error in %s\nshould be: <name>/<port>\nor name contains some restricted characters", _cpath + "_name")
            sys.exit(1)
        if kwargs.get("port") > -1:
            port = kwargs.get("port")
        elif len(_name) >= 2:
            port = int(_name[1])
        else:
            port = config.client_port
        clientserverdict = {"name": _name[0], "certhash": dhash(pub_cert),
                            "priority": kwargs.get("priority"), "message": _message}
        self.links["client_server"] = client_server(clientserverdict)
        # use timeout argument of BaseServer
        if handle_remote:
            self.links["shandler"] = gen_client_handler(self.links, server=True, client=True, remote=True)
        else:
            self.links["shandler"] = gen_client_handler(self.links, server=True, client=False, remote=False)
        self.links["hserver"] = http_server(("", port), _cpath+"_cert", self.links["shandler"], "Enter client certificate pw", timeout=kwargs.get("timeout"))
        if not handle_remote or (not kwargs.get("nounix") and file_family):
            self.links["chandler"] = gen_client_handler(self.links, server=False, client=True, remote=False)
            if file_family is not None:
                rpath = os.path.join(kwargs.get("run"), "{}-simplescn-client.unix".format(os.getuid()))
                self.links["cserver_unix"] = http_server(rpath, _cpath+"_cert", self.links["chandler"], "Enter client certificate pw", timeout=kwargs.get("timeout"), use_unix=True)
                self.links["cserver_unix"].serve_forever_nonblock()
            if not handle_remote and not kwargs.get("noip", False):
                self.links["cserver_ip"] = http_server(("::1", port), _cpath+"_cert", self.links["chandler"], "Enter client certificate pw", timeout=kwargs.get("timeout"))
                self.links["cserver_ip"].serve_forever_nonblock()

        self.links["client"] = client_client(_name[0], dhash(pub_cert), self.links)

    def show(self):
        ret = dict()
        _r = self.links["hserver"]
        ret["hserver"] = _r.server_name, _r.server_port
        _r = self.links.get("cserver_ip", None)
        if _r:
            ret["cserver_ip"] = _r.server_name, _r.server_port
        else:
            ret["cserver_ip"] = ret["hserver"]
        _r = self.links.get("cserver_unix", None)
        if _r:
            ret["cserver_unix"] = _r.server_name
        return ret
    def serve_forever_block(self):
        self.links["hserver"].serve_forever()

    def serve_forever_nonblock(self):
        threading.Thread(target=self.serve_forever_block, daemon=True).start()

#specified seperately because of chicken egg problem
#"config":default_configdir
default_client_args = \
{
    "cpwhash": ["", str, "<lowercase hash>: sha256 hash of pw, higher preference than cpw (needed for remote control), lowercase"],
    "cpwfile": ["", str, "<pw>: password file (needed for remote control)"],
    "apwhash": ["", str, "<lowercase hash>: sha256 hash of pw, higher preference than apw, lowercase"],
    "apwfile": ["", str, "<pw>: password file"],
    "spwhash": ["", str, "<lowercase hash>: sha256 hash of pw, higher preference than spw, lowercase"],
    "spwfile": ["", str, "<pw>: password file"],
    "remote" : ["False", bool, "<bool>: remote reachable (not only localhost) (needs cpwhash/file)"],
    "priority": [str(config.default_priority), int, "<int>: set client priority"],
    "connect_timeout": [str(config.connect_timeout), int, "<int>: set timeout for connecting"],
    "timeout": [str(config.default_timeout), int, "<int>: set default timeout"],
    "loglevel": [str(config.default_loglevel), loglevel_converter, "<int/str>: loglevel"],
    "port": [str(-1), int, "<int>: port of server component, -1: use port in \"client_name.txt\""],
    "config": [config.default_configdir, parsepath, "<dir>: path to config dir"],
    "run": [config.default_runpath, parsepath, "<dir>: path where unix socket and pid are saved"],
    "nounix": ["False", parsebool, "<bool>: deactivate unix socket client server"],
    "noip": ["False", parsebool, "<bool>: deactivate ip socket client server"]
}

def client_paramhelp():
    temp_doc = "# parameters\n"
    for _key, elem in sorted(default_client_args.items(), key=lambda x: x[0]):
        temp_doc += "  * key: {}, default: {}, doc: {}\n".format(_key, elem[0], elem[2])
    return temp_doc


