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
from http import client

from simplescn import config, VALError, AuthNeeded, AddressError, pwcallmethod
from simplescn.config import isself, file_family
#, create_certhashheader
from simplescn._common import parsepath, parsebool, CommonSCN, CommonSCNHandler, SHTTPServer, CerthashDb, loglevel_converter, PermissionHashDb
from simplescn.tools import default_sslcont, try_traverse, SecdirHandler, generate_certs, \
init_config_folder, dhash, rw_socket, SCNAuthServer, TraverserHelper, \
generate_error, gen_result, writemsg
from simplescn.tools.checks import check_certs, check_name, check_hash, check_local, check_classify
from simplescn._decos import check_args_deco, classify_local, classify_accessable, classify_private, generate_validactions_deco
from simplescn._client_admin import ClientClientAdmin
from simplescn._client_safe import ClientClientSafe
from simplescn.scnrequest import Requester


@generate_validactions_deco
class ClientClient(ClientClientAdmin, ClientClientSafe):
    name = None
    certtupel = None
    links = None
    scntraverse_helper = None
    brokencerts = None
    _cache_help = None
    requester = None

    @property
    def validactions(self):
        raise NotImplementedError()

    def __init__(self, name: str, certtupel: tuple, _links: dict):
        ClientClientAdmin.__init__(self)
        ClientClientSafe.__init__(self)
        self.validactions.update(ClientClientAdmin.validactions)
        self.validactions.update(ClientClientSafe.validactions)
        self.links = _links
        self.name = name
        self.certtupel = certtupel
        self.brokencerts = []
        self.requester = Requester(ownhash=self.certtupel[1], hashdb=self.links["hashdb"], certcontext=self.links["hserver"].sslcont)

        self.udpsrcsock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.udpsrcsock.settimeout(None)
        self.udpsrcsock.bind(self.links["hserver"].socket.getsockname())
        self.scntraverse_helper = TraverserHelper(connectsock=self.links["hserver"].socket, srcsock=self.udpsrcsock)
        os.makedirs(os.path.join(self.links["config_root"], "broken"), mode=0o700, exist_ok=True)
        for elem in os.listdir(os.path.join(self.links["config_root"], "broken")):
            _splitted = elem.rsplit(".", 1)
            if _splitted[1] != "reason":
                continue
            _hash = _splitted[0]
            with open(os.path.join(self.links["config_root"], "broken", elem), "r") as reado:
                _reason = reado.read().strip().rstrip()
            if check_hash(_hash) and (_hash, _reason) not in self.brokencerts:
                self.brokencerts.append((_hash, _reason))
        self._cache_help = self.cmdhelp()

    # return success, body, (name, security), hash
    # return success, body, isself, hash
    # return success, body, None, hash
    def do_request(self, addr_or_con, path: str, body, headers: dict, forceport=False, forcehash=None, sendclientcert=False, closecon=True):
        """ func: wrapper+ cache certcontext and ownhash """
        ret = self.requester.do_request(addr_or_con, path, body, headers, forceport=forceport, forcehash=forcehash, sendclientcert=sendclientcert, keepalive=not closecon)
        # for wrapping
        if ret[0]:
            if closecon or not ret[1]:
                ret[0].close()
            else:
                ret[2]["wrappedsocket"] = ret[0].sock
                ret[0].sock = None
        return ret[1:]

    @classify_private
    def access_dict(self, action, obdict):
        """ method to access functions """
        if callable(action):
            gaction = action
        elif action in self.validactions:
            gaction = getattr(self, action)
        else:
            return False, "not in validactions", self.certtupel
        if check_classify(gaction, "private"):
            return False, "actions: 'private functions not allowed in access", self.certtupel
        #with self.client_lock: # not needed, use sqlite's intern locking mechanic
        try:
            return gaction(obdict)
        except AuthNeeded as exc:
            raise exc
        except Exception as exc:
            #raise(exc)
            return False, exc, self.certtupel #.with_traceback(sys.last_traceback)

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

@generate_validactions_deco
class ClientServer(CommonSCN):
    # only servicenames with ports for efficient json generation
    spmap = None
    # meta data to servicename, not neccessary in spmap (hidden)
    spmap_meta = None
    scn_type = "client"
    links = None
    # replace CommonSCN capabilities
    capabilities = None
    wlock = None
    certtupel = None

    @property
    def validactions(self):
        raise NotImplementedError

    def __init__(self, dcserver):
        CommonSCN.__init__(self)
        # init here (multi instance situation)
        self.spmap = {}
        self.spmap_meta = {}
        self.wlock = threading.Lock()
        self.links = dcserver["links"]
        self.capabilities = ["basic", "client", "trust"]
        if not self.links["kwargs"].get("nowrap", False):
            self.capabilities.append("wrap")
        if not self.links["kwargs"].get("notraversal", False):
            self.capabilities.append("traversal")
        if self.links["kwargs"].get("trustforall", False):
            self.capabilities.append("trustforall")

        if dcserver["name"] is None or len(dcserver["name"]) == 0:
            logging.info("Name empty")
            dcserver["name"] = "<noname>"
        if dcserver["message"] is None or len(dcserver["message"]) == 0:
            logging.info("Message empty")
            dcserver["message"] = "<empty>"
        self.name = dcserver["name"]
        self.message = dcserver["message"]
        self.priority = self.links["kwargs"].get("priority")
        self.certtupel = dcserver["certtupel"]
        self.cache["dumpservices"] = json.dumps({"dict": {}})
        self.update_cache()
        self.validactions.update(self.cache.keys())
    ### the primary way to add or remove a service
    ### can be called by every application on same client
    ### don't annote list with "map" dict structure on serverside (overhead)

    @check_args_deco({"name": str, "port": int}, optional={"wrappedport": bool, "post": bool, "hidden": bool})
    @classify_local
    @classify_accessable
    def registerservice(self, obdict, prefix="#"):
        """ func: register a service = (map port to name)
            return: success or error
            name: service name
            port: port number
            wrappedport: port is masked/is not traversable (but can be wrapped)
            hidden: port and servicename are not listed (default: False)
            post: send http post request with certificate in header to service (activates wrappedport if not explicitly deactivated) """
        if not check_local(obdict["clientaddress"][0]):
            return False, generate_error("no permission", False)
        if not check_name(obdict["name"]):
            return False, generate_error("invalid service name", False)
        if prefix and obdict["name"][0] != prefix:
            return False, generate_error("service name without/with wrong prefix", False)
        wrappedport = obdict.get("wrappedport", None)
        # activates wrappedport if unspecified
        if wrappedport is None:
            wrappedport = obdict.get("post", False)
        with self.wlock:
            self.spmap_meta[obdict["name"]] = (obdict.get("port"), wrappedport, obdict.get("post", False))
            if obdict.get("hidden", False) and \
               obdict.get("port") in self.spmap[obdict["name"]]:
                del self.spmap[obdict["name"]]
            else:
                if not wrappedport:
                    self.spmap[obdict["name"]] = obdict.get("port")
                else:
                    self.spmap[obdict["name"]] = -1
            self.cache["dumpservices"] = json.dumps({"dict": self.spmap})
            #self.cache["listservices"] = json.dumps(gen_result(sorted(self.spmap.items(), key=lambda t: t[0]), True))
        return True

    # don't annote list with "map" dict structure on serverside (overhead)
    @check_args_deco({"name": str})
    @classify_local
    @classify_accessable
    def delservice(self, obdict, prefix="#"):
        """ func: delete a service
            return: success or error
            name: service name """
        if not check_local(obdict["clientaddress"][0]):
            return False, generate_error("no permission", False)
        if prefix and obdict["name"][0] != prefix:
            return False, generate_error("service name without/with wrong prefix", False)

        with self.wlock:
            if  obdict["name"] in self.spmap_meta:
                del self.spmap_meta[obdict["name"]]

            if obdict["name"] in self.spmap:
                del self.spmap[obdict["name"]]
                self.cache["dumpservices"] = json.dumps(gen_result(self.spmap)) #sorted(self.spmap.items(), key=lambda t: t[0]), True))
        return True

    ### management section - end ###

    @check_args_deco({"hash": str})
    @classify_accessable
    @classify_local
    def trust(self, obdict: dict):
        """ func: (remote) trust (security level) of client for hash (only accessable for gettrust member)
            return: security trust level
            hash: hash for which trust should be retrieved
        """
        if not self.links["kwargs"].get("trustforall", False):
            if not "origcertinfo" in obdict:
                return False, generate_error("no certificate sent", False)
            if not self.links["permsdb"].exist(obdict["origcertinfo"][1], "gettrust"):
                return False, generate_error("No permission", False)
        hasho = self.links["client"].links["hashdb"].get(obdict.get("hash"))
        if hasho:
            return True, {"security": hasho[3]}
        else:
            return True, {"security": "unknown"}

    @check_args_deco({"name": str})
    @classify_local
    @classify_accessable
    def getservice(self, obdict):
        """ func: get the port of a service
            return: portnumber or negative for wrappedport
            name: servicename """
        serviceob = self.spmap_meta.get(obdict["name"], None)
        if not serviceob:
            return False, generate_error("Service not available", False)

        if not serviceob[1]:
            return True, {"port": serviceob[0]}
        else:
            return True, {"port": -1}

    @check_args_deco({"name": str})
    @classify_accessable
    def traverse_service(self, obdict):
        """ func: traverse to the port of a service
            return: portnumber or error
            name: servicename """
        if not self.links["kwargs"]["notraversal"]:
            return False, generate_error("traversal disabled")
        serviceob = self.spmap_meta.get(obdict["name"], None)
        if not serviceob:
            return False, generate_error("Service not available", False)
        if not serviceob[1]:
            return False, generate_error("Service not traversable", False)
        #_port = obdict.get("destport", None)
        #if not _port:
        #    _port = obdict["clientaddress"][1]
        travaddr = ('', serviceob[0])
        destaddr = obdict["clientaddress"] #(obdict["clientaddress"][0], _port)
        if try_traverse(travaddr, destaddr, connect_timeout=self.links["kwargs"]["connect_timeout"], retries=config.traverse_retries):
            return True, {"port": serviceob[0]}
        else:
            return False, generate_error("Traversal could not opened", False)

def gen_ClientHandler(_links, hasserver=False, hasclient=False, remote=False, nowrap=False):
    checklocalcert = _links["kwargs"].get("checklocalcert", False)
    """ create handler with: links, server_timeout, default_timeout, ... """
    class ClientHandler(CommonSCNHandler):
        """ client handler """
        server_version = 'simplescn/1.0 (client)'
        # set onlylocal variable if remote is deactivated and not server
        onlylocal = not remote and not hasserver
        links = _links
        server_timeout = _links["kwargs"].get("server_timeout")
        etablished_timeout = _links["kwargs"].get("default_timeout")

        def handle_wrap(self, servicename):
            """ wrap service """
            if self.certtupel is None:
                # send error
                self.scn_send_answer(400, message="no certtupel")
                return
            self.cleanup_stale_data(2)
            service = self.links["client_server"].spmap_meta.get(servicename, None)
            if service is None:
                # send error
                self.scn_send_answer(404, message="service not available")
                return
            port = service[0]
            post = service[2]
            wrappedsocket = None
            _waddr = None
            for addr in ["::1", "::ffff:127.0.0.1"]:
                try:
                    # handles udp, tcp, ipv6, ipv4 so use this instead own solution
                    wrappedsocket = socket.create_connection((addr, port), self.links["kwargs"].get("connect_timeout"))
                    _waddr = addr.replace("::ffff:", "")
                    break
                except Exception as e:
                    logging.debug(e)
                    wrappedsocket = None
            if wrappedsocket is None:
                self.scn_send_answer(404, message="service not reachable")
                return
            if post:
                jsonnized = bytes(json.dumps({"origcertinfo": self.certtupel}), "utf-8")
                # feed with real values for server
                con = client.HTTPConnection(_waddr, port)
                con.sock = wrappedsocket
                con.putrequest("POST", "/wrapping")
                con.putheader("Connection", "keep-alive")
                con.putheader("Content-Type", "application/json; charset=utf-8")
                con.putheader("Content-Length", str(len(jsonnized)))
                con.endheaders()
                # extract own context
                cont = self.connection.context
                # wrap socket to wrap
                con.sock = cont.wrap_socket(con.sock, server_side=True)
                con.send(jsonnized)
                resp = con.getresponse()
                resp.read(0)
                wrappedsocket = con.sock
                con.sock = None
                if resp.status != 200 or wrappedsocket is None:
                    self.scn_send_answer(400, message="service speaks not scn post protocol")
                    return
            wrappedsocket.settimeout(self.etablished_timeout)
            self.scn_send_answer(200, body=bytes(json.dumps({"port":port}), "utf-8"), mime="application/json", docache=False, dokeepalive=True)
            self.wfile.flush()
            rw_socket(self.connection, wrappedsocket, self.etablished_timeout)
            self.close_connection = True

        if hasclient:
            def handle_client(self, action):
                """ access to client_client """
                if action not in self.links["client"].validactions:
                    self.scn_send_answer(400, message="invalid action - client", docache=True)
                    return

                gaction = getattr(self.links["client"], action)
                # remote==False but attempt to connect from outside
                if not remote and not self.is_local:
                    self.send_error(400, "no permission - client")
                    return
                # check if checklocalcert or connection is local
                if checklocalcert or not self.is_local:
                    if check_classify(gaction, "admin"):
                        ret = self.links["permsdb"].exist(self.certtupel[1], "admin")
                    else:
                        ret = self.links["permsdb"].exist(self.certtupel[1], "client")
                    if not ret:
                        self.send_error(400, "no permission - client")
                        return
                self.connection.settimeout(self.etablished_timeout)
                obdict = self.parse_body()
                if obdict is None:
                    return
                try:
                    response = self.links["client"].access_dict(gaction, obdict)
                except AuthNeeded as exc:
                    self.scn_send_answer(401, body=bytes(exc.reqob, "utf-8"), mime="application/json", docache=False)
                    return

                if response[0] is False:
                    error = response[1]
                    # with harden mode do not show errormessage
                    if config.harden_mode and not isinstance(error, (AddressError, VALError)):
                        resultob = generate_error("unknown")
                    else:
                        shallstack = not isinstance(error, (AddressError, VALError)) and \
                                     config.debug_mode and \
                                     (self.server.address_family != file_family or check_local(self.client_address[0]))
                        resultob = generate_error(error, shallstack)
                    status = 500
                else:
                    resultob = response[1]
                    status = 200
                if not check_classify(gaction, "local") and not response[2][0] is isself:
                    resultob["origcertinfo"] = response[2]
                if "wrappedsocket" in resultob:
                    wrappedsocket = resultob.pop("wrappedsocket")
                else:
                    wrappedsocket = None
                jsonnized = bytes(json.dumps(resultob), "utf-8", errors="ignore")
                self.scn_send_answer(status, body=jsonnized, mime="application/json", docache=False, dokeepalive=True)
                if wrappedsocket:
                    rw_socket(self.connection, wrappedsocket, self.etablished_timeout)
                    self.close_connection = True

        if hasserver:
            def handle_server(self, action):
                """ access to client_server """
                if action not in self.links["client_server"].validactions:
                    self.scn_send_answer(400, message="invalid action - server", docache=True)
                    return

                if not self.links["auth_server"].verify(self.auth_info):
                    authreq = self.links["auth_server"].request_auth()
                    ob = bytes(json.dumps(authreq), "utf-8")
                    self.cleanup_stale_data(config.max_serverrequest_size)
                    self.scn_send_answer(401, body=ob, docache=False)
                    return
                self.connection.settimeout(self.etablished_timeout)
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
                    # no complicated checks here
                    response = getattr(self.links["client_server"], action)(obdict)
                    jsonnized = json.dumps(response[1])
                except Exception as exc:
                    # with harden mode do not show errormessage
                    if config.harden_mode and not isinstance(exc, (AddressError, VALError)):
                        generror = generate_error("unknown")
                    else:
                        shallstack = not isinstance(exc, (AddressError, VALError)) and \
                                     config.debug_mode and \
                                     (self.server.address_family != file_family or check_local(self.client_address[0]))
                        generror = generate_error(exc, shallstack)
                    ob = bytes(json.dumps(generror), "utf-8")
                    self.scn_send_answer(500, body=ob, mime="application/json")
                    return
                ob = bytes(jsonnized, "utf-8")
                if not response[0]:
                    self.scn_send_answer(400, body=ob, mime="application/json", docache=False)
                else:
                    self.scn_send_answer(200, body=ob, mime="application/json", docache=False)

        def do_POST(self):
            """ access to client_client and client_server """
            if not self.init_scn_stuff():
                self.connection.settimeout(self.server_timeout)
                return
            splitted = self.path[1:].split("/", 1)
            resource = splitted[0]
            if len(splitted) == 1:
                sub = ""
            else:
                sub = splitted[1]
            if resource == "wrap" and not nowrap:
                if not self.links["auth_server"].verify(self.auth_info):
                    authreq = self.links["auth_server"].request_auth()
                    ob = bytes(json.dumps(authreq), "utf-8")
                    self.cleanup_stale_data(config.max_serverrequest_size)
                    self.scn_send_answer(401, body=ob, docache=False)
                else:
                    self.connection.settimeout(self.etablished_timeout)
                    self.handle_wrap(sub)
            elif resource == "usebroken":
                # for invalidating and updating, don't use connection afterwards
                self.handle_usebroken(sub)
            elif hasserver and resource == "server":
                self.handle_server(sub)
            elif hasclient and resource == "client":
                self.handle_client(sub)
            else:
                self.scn_send_answer(404, message="resource not found (POST)", docache=True)
            self.connection.settimeout(self.server_timeout)
    return ClientHandler

class ClientInit(object):
    config_root = None
    links = None
    active = True
    secdirinst = None

    @classmethod
    def create(cls, **kwargs):
        if not kwargs.get("nolock", False):
            secdirpath = os.path.join(kwargs["run"], "{}-simplescn-client".format(os.getuid()))
            secdirinst = SecdirHandler.create(secdirpath, 0o700)
            if not secdirinst:
                logging.info("Client already active (same user, rundirectory) or permission problems")
                return None
        else:
            secdirinst = None
        kwargs["permsdb"] = PermissionHashDb.create(os.path.join(kwargs["config"], "permsdb{}".format(config.dbending)))
        kwargs["hashdb"] = CerthashDb.create(os.path.join(kwargs["config"], "certdb{}".format(config.dbending)))
        if None in [kwargs["permsdb"], kwargs["hashdb"]]:
            logging.error("permsdb (permission db) or hashdb (certificate hash db) could not be initialized")
            return None
        ret = cls(secdirinst, **kwargs)
        cls.secdirinst = secdirinst
        return ret

    def __del__(self):
        if self.links:
            try:
                del self.secdirinst
            except Exception:
                pass

    def __init__(self, secdirinst, **kwargs):
        self.links = {}
        self.links["config_root"] = kwargs.get("config")
        self.links["kwargs"] = kwargs
        _cpath = os.path.join(self.links["config_root"], "client")
        init_config_folder(self.links["config_root"], "client")

        if not check_certs(_cpath + "_cert"):
            logging.info("Certificate(s) not found. Generate new...")
            generate_certs(_cpath + "_cert")
            logging.info("Certificate generation complete")
        with open(_cpath+"_cert.pub", 'rb') as readinpubkey:
            pub_cert = readinpubkey.read().strip().rstrip() #why fail
        #self.links["auth_client"] = scnauth_client()
        self.links["auth_server"] = SCNAuthServer(dhash(pub_cert))
        self.links["permsdb"] = kwargs["permsdb"]
        self.links["hashdb"] = kwargs["hashdb"]

        if bool(kwargs.get("spwhash")):
            if not check_hash(kwargs.get("spwhash")):
                logging.error("hashtest failed for spwhash, spwhash: %s", kwargs.get("spwhash"))
            else:
                self.links["auth_server"].init(kwargs.get("spwhash"))
        elif bool(kwargs.get("spwfile")):
            with open(kwargs["spwfile"], "r") as op:
                pw = op.readline()
                if pw[-1] == "\n":
                    pw = pw[:-1]
                self.links["auth_server"].init(dhash(pw))

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
        sslcont = default_sslcont()
        sslcont.load_cert_chain(_cpath+"_cert.pub", _cpath+"_cert.priv", lambda pwmsg: bytes(pwcallmethod(config.pwdecrypt_prompt), "utf-8"))

        if kwargs.get("remote", False):
            self.links["shandler"] = gen_ClientHandler(self.links, hasserver=True, hasclient=True, remote=True, nowrap=kwargs.get("nowrap", False))
            kwargs["noip"] = True
        else:
            self.links["shandler"] = gen_ClientHandler(self.links, hasserver=True, \
            hasclient=False, remote=False, nowrap=kwargs.get("nowrap", False))
        self.links["hserver"] = SHTTPServer(("::", port), sslcont, self.links["shandler"])

        if not kwargs.get("noip", False) or (not kwargs.get("nounix") and file_family):
            self.links["chandler"] = gen_ClientHandler(self.links, hasserver=False, hasclient=True, remote=False, nowrap=True)
            if file_family is not None and secdirinst:
                rpath = os.path.join(secdirinst.filepath, "socket")
                self.links["cserver_unix"] = SHTTPServer(rpath, sslcont, self.links["chandler"], use_unix=True)
            if not kwargs.get("noip", False):
                self.links["cserver_ip"] = SHTTPServer(("::1", port), sslcont, self.links["chandler"])
                self.links["cserver_ip4"] = SHTTPServer(("::ffff:127.0.0.1", self.links["cserver_ip"].server_port), sslcont, self.links["chandler"])

        certtupel = (isself, dhash(pub_cert), pub_cert)
        self.links["client"] = ClientClient(_name[0], certtupel, self.links)
        clientserverdict = {"name": _name[0], "certtupel": certtupel, "message": _message, "links": self.links}

        self.links["client_server"] = ClientServer(clientserverdict)

        self.links["hserver"].serve_forever_nonblock()
        if "cserver_unix" in self.links:
            self.links["cserver_unix"].serve_forever_nonblock()
        if "cserver_ip" in self.links:
            self.links["cserver_ip"].serve_forever_nonblock()
        if "cserver_ip4" in self.links:
            self.links["cserver_ip4"].serve_forever_nonblock()
        if secdirinst:
            infoobpath = os.path.join(secdirinst.filepath, "info")
            writemsg(infoobpath, json.dumps(self.show()), 0o400)

    def join(self):
        self.links["hserver"].serve_join()

    def quit(self):
        # server may need some time to cleanup, elsewise strange exceptions appear
        if not self.active:
            return
        self.active = False
        self.links["hserver"].server_close()
        if "cserver_ip" in self.links:
            self.links["cserver_ip"].server_close()
        if "cserver_ip4" in self.links:
            self.links["cserver_ip4"].server_close()
        if "cserver_unix" in self.links:
            self.links["cserver_unix"].server_close()
        if self.secdirinst:
            self.secdirinst.cleanup()
            self.secdirinst.filepath = None

    def show(self):
        ret = dict()
        ret["cert_hash"] = self.links["client"].certtupel[1]
        _r = self.links["hserver"]
        ret["hserver"] = _r.server_name, _r.server_port
        _r = self.links.get("cserver_ip", None)
        if _r:
            ret["cserver_ip"] = _r.server_name, _r.server_port
        elif self.links["kwargs"].get("remote", False):
            ret["cserver_ip"] = ret["hserver"]
        _r = self.links.get("cserver_unix", None)
        if _r:
            ret["cserver_unix"] = _r.server_name
        return ret

if config.file_family:
    default_nounix = "False"
    default_noip = "True"
else:
    default_nounix = "True"
    default_noip = "False"

#specified seperately because of chicken egg problem
#"config":default_configdir
default_client_args = \
{
    "spwhash": ["", str, "<lowercase hash>: sha256 hash of pw, higher preference than spw, lowercase"],
    "spwfile": ["", str, "<pw>: password file"],
    "remote" : ["False", parsebool, "<bool>: remote reachable (not only localhost) (needs cpwhash/file), disables client httpserver"],
    "priority": [str(config.default_priority), int, "<int>: set client priority"],
    "connect_timeout": [str(config.connect_timeout), int, "<int>: set timeout for connecting"],
    "server_timeout": [str(config.server_timeout), int, "<int>: set timeout for servercomponent"],
    "timeout": [str(config.default_timeout), int, "<int>: set default timeout (etablished connections)"],
    "loglevel": [str(config.default_loglevel), loglevel_converter, "<int/str>: loglevel"],
    "port": [str(-1), int, "<int>: port of server component, -1: use port in \"client_name.txt\""],
    "config": [config.default_configdir, parsepath, "<dir>: path to config dir"],
    "run": [config.default_runpath, parsepath, "<dir>: path where unix socket and pid are saved"],
    "nounix": [default_nounix, parsebool, "<bool>: deactivate unix socket client server"],
    "noip": [default_noip, parsebool, "<bool>: deactivate ip socket client server"],
    "trustforall": ["False", parsebool, "<bool>: everyone can access hashdb security"],
    "nowrap": ["False", parsebool, "<bool>: disable wrap"],
    "checklocalcert": ["False", parsebool, "<bool>: require certificate for local connections"],
    "notraverse": ["True", parsebool, "<bool>: disable traversal"],
    "nolock": ["False", parsebool, "<bool>: deactivate port lock+unix socket+info"]
}

def client_paramhelp():
    temp_doc = "# parameters\n"
    for _key, elem in sorted(default_client_args.items(), key=lambda x: x[0]):
        temp_doc += "  * key: {}, default: {}, doc: {}\n".format(_key, elem[0], elem[2])
    return temp_doc
