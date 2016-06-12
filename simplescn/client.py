#! /usr/bin/env python3
"""
main client stuff (client)
license: MIT, see LICENSE.txt
"""

import sys
import os
import socket
from http import client
import ssl
import threading
import json
import logging


from simplescn import sharedir
from simplescn.common import parsepath, parsebool

from simplescn.client_admin import client_admin
from simplescn.client_safe import client_safe


from simplescn import check_certs, generate_certs, init_config_folder, default_configdir, dhash, VALNameError, VALHashError, isself, check_name, commonscn, scnparse_url, AddressFail, rw_socket, check_args, safe_mdecode, generate_error, max_serverrequest_size, gen_result, check_result, check_argsdeco, scnauth_server, http_server, generate_error_deco, VALError, client_port, default_priority, default_timeout, check_hash, scnauth_client, traverser_helper, create_certhashheader, classify_local, classify_access, commonscnhandler, default_loglevel, loglevel_converter, connect_timeout, check_local, debug_mode, harden_mode, file_family, check_classify

from simplescn.common import certhash_db
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

    validactions = None

    def __init__(self, _name, _pub_cert_hash, _links):
        client_admin.__init__(self)
        client_safe.__init__(self)
        self.links = _links
        self.name = _name
        self.cert_hash = _pub_cert_hash
        self.hashdb = certhash_db(os.path.join(self.links["config_root"], "certdb.sqlite"))
        if "hserver" in self.links:
            self.sslcont = self.links["hserver"].sslcont
        else:
            self.sslcont = default_sslcont()
        self.brokencerts = []
        self.validactions = set()
        #"remember_auth"
        

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
    def do_request(self, _addr_or_con, _path, body={}, headers=None, forceport=False, forcehash=None, forcetraverse=False, sendclientcert=False, _reauthcount=0, _certtupel=None):
        """ func: use this method to communicate with clients/servers """
        if headers is None:
            headers = body.pop("headers", {})
        elif "headers" in body:
            del body["headers"]
        sendheaders = reference_header.copy()
        for key, value in headers.items():
            if key in ["Connection", "Host", "Accept-Encoding", "Content-Type", "Content-Length", "User-Agent", "X-certrewrap"]:
                continue
            sendheaders[key] = value
        sendheaders["Content-Type"] = "application/json; charset=utf-8"
        if sendclientcert:
            sendheaders["X-certrewrap"], _random = create_certhashheader(self.cert_hash)
        if not isinstance(_addr_or_con, client.HTTPSConnection):
            _addr = scnparse_url(_addr_or_con, force_port=forceport)
            con = client.HTTPSConnection(_addr[0], _addr[1], context=self.sslcont, timeout=self.links["config"].get("connect_timeout"))
            try:
                con.connect()
            except ConnectionRefusedError:
                forcetraverse = True
            if forcetraverse:
                if "traverseserveraddr" not in body:
                    return False, "connection refused and no traversalserver specified", isself, self.cert_hash
                _tsaddr = scnparse_url(body.get("traverseserveraddr"))
                contrav = client.HTTPSConnection(_tsaddr[0], _tsaddr[1], context=self.sslcont, timeout=self.links["config"].get("connect_timeout"))
                contrav.connect()
                _sport = contrav.sock.getsockname()[1]
                retserv = self.do_request(contrav, "/server/open_traversal")
                contrav.close()
                if retserv[0]:
                    con.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    con.sock.bind(('', _sport)) #retserv.get("traverse_address"))
                    for count in range(0, 3):
                        try:
                            con.sock.connect((_addr[0], _addr[1]))
                            break
                        except Exception:
                            pass
                    con.sock = self.sslcont.wrap_socket(con.sock)
                    con.timeout = self.links["config"].get("timeout")
                    con.sock.settimeout(self.links["config"].get("timeout"))
        else:
            con = _addr_or_con
            if con.sock is None:
                con.timeout = self.links["config"].get("connect_timeout")
                try:
                    con.connect()
                except ConnectionRefusedError:
                    pass
            con.timeout = self.links["config"].get("timeout")
            con.sock.settimeout(self.links["config"].get("timeout"))
            #if headers.get("Connection", "") != "keep-alive":
            #    con.connect()
        if _certtupel is None:
            pcert = ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True)).strip().rstrip()
            hashpcert = dhash(pcert)
            if forcehash is not None:
                if forcehash != hashpcert:
                    raise VALHashError()
            elif body.get("forcehash") is not None:
                if body.get("forcehash") != hashpcert:
                    raise VALHashError()
            if hashpcert == self.cert_hash:
                validated_name = isself
            else:
                hashob = self.hashdb.get(hashpcert)
                if hashob:
                    validated_name = (hashob[0], hashob[3]) #name, security
                    if validated_name[0] == isself:
                        raise VALNameError()
                else:
                    validated_name = None
            _certtupel = (validated_name, hashpcert)
        else:
            validated_name, hashpcert = _certtupel
        #start connection
        con.putrequest("POST", _path)
        for key, value in sendheaders.items():
            #if key != "Proxy-Authorization":
            con.putheader(key, value)
        pwcallm = body.get("pwcall_method")
        if "pwcall_method" in body:
            del body["pwcall_method"]
        ob = bytes(json.dumps(body), "utf-8")
        con.putheader("Content-Length", str(len(ob)))
        con.endheaders()
        if sendclientcert:
            con.sock = con.sock.unwrap()
            con.sock = self.sslcont.wrap_socket(con.sock, server_side=True)
        con.send(ob)
        response = con.getresponse()
        servertype = response.headers.get("Server", "")
        logging.debug("Servertype: %s", servertype)
        if response.status == 401:
            body["pwcall_method"] = pwcallm
            auth_parsed = json.loads(sendheaders.get("Authorization", "scn {}").split(" ", 1)[1])
            if not response.headers.get("Content-Length", "").strip().rstrip().isdigit():
                con.close()
                return False, "no content length", _certtupel[0], _certtupel[1]
            readob = response.read(int(response.headers.get("Content-Length")))
            reqob = safe_mdecode(readob, response.headers.get("Content-Type", "application/json; charset=utf-8"))
            if reqob is None:
                con.close()
                return False, "Invalid Authorization request object", _certtupel[0], _certtupel[1]
            realm = reqob.get("realm")
            if callable(pwcallm):
                authob = pwcallm(hashpcert, reqob, _reauthcount)
            else:
                return False, "no way to input passphrase for authorization", _certtupel[0], _certtupel[1]
            if authob is None:
                con.close()
                return False, "Authorization failed", _certtupel[0], _certtupel[1]
            _reauthcount += 1
            auth_parsed[realm] = authob
            sendheaders["Authorization"] = "scn {}".format(json.dumps(auth_parsed).replace("\n", ""))
            return self.do_request(con, _path, body=body, forcehash=forcehash, headers=sendheaders, forceport=forceport, _certtupel=_certtupel, forcetraverse=forcetraverse, sendclientcert=sendclientcert, _reauthcount=_reauthcount)
        else:
            if not response.getheader("Content-Length", "").strip().rstrip().isdigit():
                con.close()
                return False, "No content length", _certtupel[0], _certtupel[1]
            readob = response.read(int(response.getheader("Content-Length")))
            # kill keep-alive connection when finished, or transport connnection
            #if isinstance(_addr_or_con, client.HTTPSConnection) == False:
            con.close()
            if response.status == 200:
                status = True
                if sendclientcert:
                    if _random != response.getheader("X-certrewrap", ""):
                        return False, "rewrapped cert secret does not match", _certtupel[0], _certtupel[1]
            else:
                status = False
            if response.getheader("Content-Type").split(";")[0].strip().rstrip() in ["text/plain", "text/html"]:
                obdict = gen_result(str(readob, "utf-8"), status)
            else:
                obdict = safe_mdecode(readob, response.getheader("Content-Type", "application/json"))
            if not check_result(obdict, status):
                return False, "error parsing request\n{}".format(readob), _certtupel[0], _certtupel[1]

            if status:
                return status, obdict["result"], _certtupel[0], _certtupel[1]
            else:
                return status, obdict["error"], _certtupel[0], _certtupel[1]

    # auth is special variable see safe_mdecode in common
    #@check_argsdeco({"auth": dict, "hash": str, "address": str})
    #@classify_local
    #def remember_auth(self, obdict):
    #    """ func: Remember authentication info for as long the program runs
    #        return: True, when success
    #        auth: authdict
    #        hash: hash to remember
    #        address: address of server/client for which the pw should be saved
    #    """
    #    if obdict.get("hash") is None:
    #        _hashob = self.gethash(obdict)
    #        if not _hashob[0]:
    #            return False, "invalid address for retrieving hash"
    #        _hash = _hashob[1]["hash"]
    #    else:
    #        _hash = obdict.get("hash")
    #    for realm, pw in obdict.get("auth"):
    #        self.links["auth_client"].saveauth(pw, _hash, realm)
    #    return True

    # NEVER include in validactions
    # headers=headers
    # client_address=client_address
    @classify_access
    def access_core(self, action, obdict):
        """ internal method to access functions """
        if action in self.validactions:
            gaction = getattr(self, action)
            if check_classify(gaction, "access"):
                return False, "actions: 'classified access not allowed in access_core", isself, self.cert_hash
            if check_classify(gaction, "insecure"):
                return False, "method call not allowed this way (insecure)", isself, self.cert_hash
            if check_classify(gaction, "experimental"):
                logging.warning("action: \"%s\" is experimental", action)
            #with self.client_lock: # not needed, use sqlite's intern locking mechanic
            try:
                return getattr(self, action)(obdict)
            except Exception as exc:
                return False, exc #.with_traceback(sys.last_traceback)
        else:
            return False, "not in validactions", isself, self.cert_hash

    # NEVER include in validactions
    # for user interactions
    # headers=headers
    # client_address=client_address
    @generate_error_deco
    @classify_access
    def access_main(self, action, **obdict):
        obdict["pwcall_method"] = self.pw_auth
        try:
            return self.access_core(action, obdict)
        except Exception as exc:
            return False, exc

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

    @check_argsdeco({"name": str, "port": int}, optional={"invisibleport": bool,"post": bool})
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
    @check_argsdeco({"name": str})
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

    @check_argsdeco({"name": str})
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


def gen_client_handler():
    class client_handler(commonscnhandler):
        server_version = 'simplescn/1.0 (client)'
        handle_local = False
        handle_remote = False
        webgui = False
        
        def handle_wrap(self, func, servicename):
            service = self.links["client_server"].spmap.get(servicename, None)
            if service is None:
                # send error
                self.scn_send_answer(404, message="service not available")
                return
            port = service[0]
            sockd = None
            for addr in ["::1", "127.0.0.1"]:
                try:
                    sockd = socket.create_connection((addr, port), local_timeout)
                    break
                except Exception as e:
                    logging.debug(e)
                    sockd = None
            if sockd is None:
                self.scn_send_answer(404, message="service not reachable")
                return
            redout = threading.Thread(target=rw_socket, args=(self.connection, sockd), daemon=True)
            redout.run()
            rw_socket(sockd, self.connection)

        def handle_client(self, action):
            if action not in self.links["client"].validactions:
                self.send_error(400, "invalid action - client")
                return
            # redirect overrides handle_local, handle_remote
            gaction = getattr(self.links["client"], action)
            if not self.handle_remote and \
                check_classify(redirect, "redirect") and \
                (not self.handle_local or self.server.address_family != file_family or not check_local(self.client_address2[0])):
                self.send_error(403, "no permission - client")
                return
            if check_classify(redirect, "admin"):
                #if self.client_cert is None:
                #    self.send_error(403, "no permission (no certrewrap) - admin")
                #    return
                if "admin" in self.links["auth_server"].realms:
                    realm = "admin"
                else:
                    realm = "client"
            else:
                realm = "client"
            # if redirect bypass
            gaction = getattr(self.links["client"], action)
            if not check_classify(gaction, "redirect") and \
                    not self.do_auth(realm, self.auth_info):
                return

            obdict = self.parse_body()
            if obdict is None:
                return
            response = self.links["client"].access_main(action, **obdict)

            if not response[0]:
                error = response[1]
                generror = generate_error(error)
                if not debug_mode or self.server.address_family != file_family or not check_local(self.client_address2[0]):
                    # don't show stacktrace if not permitted and not in debug mode
                    if "stacktrace" in generror:
                        del generror["stacktrace"]
                    # with harden mode do not show errormessage
                    if harden_mode and not isinstance(error, (AddressFail, VALError)):
                        generror = generate_error("unknown")
                resultob = gen_result(generror, False)
                status = 500
            else:
                resultob = gen_result(response[1], True)
                status = 200
            jsonnized = bytes(json.dumps(resultob), "utf-8")
            self.scn_send_answer(status, body=jsonnized, mime="application/json", docache=False)

        def handle_server(self, action):
            if action not in self.links["client_server"].validactions:
                self.scn_send_answer(400, message="invalid action - server", docache=False)
                return
            if not self.links["auth_server"].verify("server", self.auth_info):
                authreq = self.links["auth_server"].request_auth("server")
                ob = bytes(json.dumps(authreq), "utf-8")
                self.cleanup_stale_data(max_serverrequest_size)
                self.scn_send_answer(401, body=ob, docache=False)
                return
            if action in self.links["client_server"].cache:
                # cleanup {} or smaller, protect against big transmissions
                self.cleanup_stale_data(2)
                ob = bytes(self.links["client_server"].cache[action], "utf-8")
                self.scn_send_answer(200, body=ob, docache=False)
                return

            obdict = self.parse_body(max_serverrequest_size)
            if obdict is None:
                return None
            try:
                func = getattr(self.links["client_server"], action)
                response = func(obdict)
                jsonnized = json.dumps(gen_result(response[1], response[0]))
            except Exception as exc:
                generror = generate_error(exc)
                if not debug_mode or self.server.address_family != file_family or not check_local(self.client_address2[0]):
                    # don't show stacktrace if not permitted and not in debug mode
                    if "stacktrace" in generror:
                        del generror["stacktrace"]
                # with harden mode do not show errormessage
                if harden_mode and not isinstance(exc, (AddressFail, VALError)):
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
            #if resource == "wrap":
            #    not reader
            #    if not self.links["auth_server"].verify("server", self.auth_info):
            #        authreq = self.links["auth_server"].request_auth("server")
            #        ob = bytes(json.dumps(authreq), "utf-8")
            #        self.cleanup_stale_data(max_serverrequest_size)
            #        self.scn_send_answer(401, body=ob, docache=False)
            #        return
            #    self.handle_wrap(action)
            if resource == "usebroken":
                # for invalidating and updating, don't use connection afterwards
                self.handle_usebroken(sub)
            elif resource == "server":
                self.handle_server(sub)
            elif resource == "client":
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
        logging.root.setLevel(kwargs.get("loglevel"))
        self.links = {"trusted_certhash": ""}
        self.links["config_root"] = kwargs.get("config")
        self.links["handler"] = gen_client_handler()
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
                self.links["handler"].handle_local = True
                # ensure that password is set when allowing remote access
                if kwargs.get("remote"):
                    self.links["handler"].handle_remote = True
                self.links["auth_server"].init_realm("client", kwargs.get("cpwhash"))
        elif kwargs.get("cpwfile"):
            self.links["handler"].handle_local = True
            # ensure that password is set when allowing remote access
            if kwargs.get("remote"):
                self.links["handler"].handle_remote = True
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
            port = client_port
        clientserverdict = {"name": _name[0], "certhash": dhash(pub_cert),
                            "priority": kwargs.get("priority"), "message": _message}
        self.links["client_server"] = client_server(clientserverdict)
        self.links["handler"].links = self.links
        # use timeout argument of BaseServer
        print(kwargs.get("noserver"))
        if not kwargs.get("noserver"):
            self.links["hserver"] = http_server(("", port), _cpath+"_cert", self.links["handler"], "Enter client certificate pw", timeout=kwargs.get("timeout"))
        self.links["client"] = client_client(_name[0], dhash(pub_cert), self.links)

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
    "remote" : ["False", bool, "<bool>: remote reachable (not localhost) (needs cpwhash/file)"],
    "priority": [str(default_priority), int, "<int>: set client priority"],
    "connect_timeout": [str(connect_timeout), int, "<int>: set timeout for connecting"],
    "timeout": [str(default_timeout), int, "<int>: set default timeout"],
    "loglevel": [str(default_loglevel), loglevel_converter, "<int/str>: loglevel"],
    "port": [str(-1), int, "<int>: port of server component, -1: use port in \"client_name.txt\""],
    "config": [default_configdir, parsepath, "<dir>: path to config dir"],
    "noserver": ["False", parsebool , "<bool>: deactivate httpserver"]
}

def client_paramhelp():
    temp_doc = "# parameters\n"
    for _key, elem in sorted(default_client_args.items(), key=lambda x: x[0]):
        temp_doc += "  * key: {}, default: {}, doc: {}\n".format(_key, elem[0], elem[2])
    return temp_doc


