
from http import client
import socket
import json
import ssl
import logging

from simplescn import config
from simplescn.config import isself
from simplescn.tools import default_sslcont, scnparse_url, \
safe_mdecode, encode_bo, try_traverse, \
dhash, create_certhashheader, scn_hashedpw_auth, url_to_ipv6, gen_result, generate_error
from simplescn import AuthNeeded, VALHashError, VALNameError, VALMITMError
from simplescn.tools.checks import namestr, hashstr, checkclass

reference_header = \
{
    "User-Agent": "simplescn/1.0",
    "Authorization": 'scn {}'
}
#"Connection": 'keep-alive' # dokeepalive cares

strip_headers = ["Connection", "Host", "Accept-Encoding", \
"Content-Length", "User-Agent", "X-certrewrap", "X-SCN-Authorization"]

class SCNConnection(client.HTTPSConnection):
    """ easy way to connect with simplescn nodes """
    kwargs = None
    # valid values for certtupel
    # None
    # None, hash, cert
    # isself, hash, cert
    # (name, security), hash, cert
    certtupel = (None, None, None)
    def __init__(self, host, **kwargs):
        # don't implement highlevel stuff here, needed by traversal
        self.kwargs = kwargs
        # init port with 0 (prevents parsing of url)
        super().__init__(host, 0, None)
        self._context = self.kwargs.get("certcontext", default_sslcont())
        self._check_hostname = None
        # throw exception here
        if self.kwargs.get("use_unix", False):
            if self.kwargs.get("forceport", False):
                logging.warning("use_unix used with forceport")
        else:
            self.host, self.port = scnparse_url(host, force_port=kwargs.get("forceport", False))

    def connect(self):
        """ Connect to the host and port specified in __init__ """
        # clear certtupel
        self.certtupel = (None, None, None)
        etimeout = self.kwargs.get("timeout", config.default_timeout)
        contimeout = self.kwargs.get("connect_timeout", config.connect_timeout)
        if self.kwargs.get("use_unix"):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(contimeout)
            self.sock.connect(self.host)
        else:
            #_host = scnparse_url(self.host, force_port=self.kwargs.get("forceport", False))
            _host = url_to_ipv6(self.host, self.port)
            if not _host:
                logging.error("Host could not resolved")
                return
            self.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            self.sock.settimeout(contimeout)
            #self.sock.bind(('', 0))
            try:
                self.sock.connect(_host)
            except (ConnectionRefusedError, socket.timeout):
                _kwargs = self.kwargs.copy()
                _kwargs["use_unix"] = False
                trav = _kwargs.pop("traverseaddress", None)
                if trav is None:
                    self.sock = None
                    return
                contrav = SCNConnection(trav, **_kwargs)
                contrav.connect()
                _sport = contrav.sock.getsockname()[1]
                retserv = do_request(trav, "/server/open_traversal", {"destaddr": _host}, {}, keepalive=True)
                contrav.close()
                if retserv[1]:
                    retries = self.kwargs.get("traverse_retries", config.traverse_retries)
                    self.sock = try_traverse(('', _sport), _host, connect_timeout=contimeout, retries=retries)
                    if not self.sock:
                        return
            # set options for ip
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # set options for all
        self.sock.settimeout(etimeout)
        self.sock = self._context.wrap_socket(self.sock, server_side=False)
        self.sock.do_handshake()
        self._check_cert()
        #if self._tunnel_host:
        #    self._tunnel()

    def _check_cert(self):
        pcert = ssl.DER_cert_to_PEM_cert(self.sock.getpeercert(True)).strip().rstrip()
        hashpcert = dhash(pcert)
        if self.kwargs.get("forcehash", None):
            if self.kwargs["forcehash"] != hashpcert:
                self.sock.close()
                raise VALHashError()
        if hashpcert == self.kwargs.get("ownhash", None):
            validated_name = isself
        else:
            hashob = None
            if self.kwargs.get("hashdb", None):
                hashob = self.kwargs["hashdb"].get(hashpcert)
            validated_name = None
            if hashob:
                validated_name = (hashob[0], hashob[3]) #name, security
                if validated_name[0] == isself:
                    self.sock.close()
                    raise VALNameError()
        self.certtupel = (validated_name, hashpcert, pcert)

    def rewrap(self):
        self.sock = self.sock.unwrap()
        self.sock = self._context.wrap_socket(self.sock, server_side=True)

def init_body_headers(body, headers):
    sendheaders = reference_header.copy()
    if isinstance(body, dict):
        sendbody = bytes(json.dumps(body), "utf-8")
        sendheaders["Content-Type"] = "application/json; charset=utf-8"
    elif isinstance(body, bytes):
        sendbody = body
    sendheaders["Content-Length"] = str(len(sendbody))

    for key, value in headers.items():
        if key not in strip_headers:
            sendheaders[key] = value
    return sendbody, sendheaders

def authorization(pwhashed, reqob, serverhash, sendheaders):
    """ handles auth, headers arg will be changed """
    if not isinstance(reqob, dict):
        return False
    if not pwhashed:
        return False
    auth_parsed = scn_hashedpw_auth(pwhashed, reqob, serverhash) #, serverhash)
    sendheaders["Authorization"] = "scn {}".format(json.dumps(auth_parsed))
    return True

# return connection, success, body, certtupel
# certtupel is None if no
def do_request(addrcon, path: str, body, headers: dict, **kwargs) -> (SCNConnection, bool, dict, tuple):
    """ func: use this method to communicate with clients/servers
        kwargs:
            options:
                * use_unix: use unix sockets instead, overrides forceport
                * sendclientcert: send own certhash to server, requires ownhash and certcontext
                * connect_timeout: timeout for connecting
                * timeout: timeout if connection is etablished
                * keepalive: keep server connection alive
                * forceport: True: raise if no port is given, False: use server port in that case, not compatible with use_unix
                * forcehash: force hash on other side
            special:
                * certcontext: specify certcontext used
                * ownhash: own hash
                * pwhandler: method for handling pws
                * X-SCN-Authorization: dhashed pw (transmitted)
        headers:
            * Authorization: scn pw auth format
            * X-SCN-Authorization: dhashed pw (try to auth)
        throws:
            * AddressError: address was incorrect
            * AddressEmptyError: address was empty
            * EnforcedPortError: no port was given (forceport)
            * VALHashError: wrong hash (forcehash)
            * VALNameError: isself is in db
            * VALMITMError: rewrapped connection contains wrong secret (sendclientcert)
            * AuthNeeded: request Auth, contains con and authob (needed for auth)
    """
    assert addrcon == addrconob, "addrcon is not a valid addrconob".format(type(addrcon))
    assert isinstance(body, (dict, bytes)), "body is neither dict nor bytes, {}".format(type(body))
    sendbody, sendheaders = init_body_headers(body, headers)
    if isinstance(addrcon, SCNConnection):
        con = addrcon
    else:
        con = SCNConnection(addrcon, **kwargs)
    if con.sock is None:
        con.connect()
    if con.sock is None:
        return None, False, generate_error("Could not open connection"), (isself, kwargs.get("ownhash", None), None)

    if kwargs.get("sendclientcert", False):
        if kwargs.get("certcontext", None) and kwargs.get("ownhash", None):
            _header, _random = create_certhashheader(kwargs["ownhash"])
            sendheaders["X-certrewrap"] = _header
        else:
            con.close()
            return None, False, generate_error("missing: certcontext or ownhash"), con.certtupel

    if kwargs.get("keepalive", True):
        sendheaders["Connection"] = 'keep-alive'
    else:
        sendheaders["Connection"] = 'close'
    if kwargs.get("X-SCN-Authorization", None):
        sendheaders["X-SCN-Authorization"] = kwargs["X-SCN-Authorization"]
        del kwargs["X-SCN-Authorization"]
    #start connection
    con.putrequest("POST", path)
    for key, value in sendheaders.items():
        #assert isinstance(value, str), "header has invalid type, {} ({})".format(key, type(value))
        con.putheader(key, value)
    con.endheaders()

    if kwargs.get("sendclientcert", False):
        con.rewrap()
    con.send(sendbody)
    response = con.getresponse()

    if kwargs.get("sendclientcert", False):
        if _random != response.getheader("X-certrewrap", ""):
            con.close()
            return None, False, generate_error("rewrapped cert secret does not match", False), con.certtupel

    if kwargs.get("sendclientcert", False):
        if _random != response.getheader("X-certrewrap", ""):
            con.close()
            raise VALMITMError()
    if response.status == 401:
        if not response.headers.get("Content-Length", "").isdigit():
            con.close()
            return None, False, generate_error("pwrequest has no content length", False), con.certtupel
        readob = response.read(int(response.getheader("Content-Length")))
        reqob = safe_mdecode(readob, response.getheader("Content-Type", "application/json"))
        if headers and headers.get("X-SCN-Authorization", None):
            if authorization(headers["X-SCN-Authorization"], reqob, con.certtupel[1], sendheaders):
                return do_request(con, path, body=body, \
                    headers=sendheaders, kwargs=kwargs)
        elif callable(kwargs.get("pwhandler", None)):
            pw = kwargs.get("pwhandler")(config.pwrealm_prompt)
            if pw:
                kwargs["X-SCN-Authorization"] = dhash(pw, reqob.get("algo"))
                return do_request(con, path, body=body, \
                    headers=sendheaders, kwargs=kwargs)
        raise AuthNeeded(con, str(readob, "utf-8"))
    else:
        if response.status == 200:
            success = True
        else:
            success = False

        if response.getheader("Content-Length", "").isdigit():
            readob = response.read(int(response.getheader("Content-Length")))
            conth = response.getheader("Content-Type", "application/json")
            if conth.split(";")[0].strip().rstrip() == "application/json":
                obdict = safe_mdecode(readob, conth)
            else:
                obdict = gen_result(encode_bo(readob, conth))
        else:
            obdict = gen_result(response.reason)
        #assert isinstance(obdict, dict),  "obdict not a dict"
        if con and not kwargs.get("keepalive", True):
            con.close()
        # origcertinfo[0] is never isself, it is stripped
        if con.certtupel[0] is isself and "origcertinfo" in obdict:
            return con, success, obdict, obdict["origcertinfo"]
        else:
            return con, success, obdict, con.certtupel

def do_request_simple(addrcon, path: str, body: dict, headers: dict, **kwargs):
    """ autoclose connection and strip connection and certificate """
    # keepalive is not possible so deactivate it
    kwargs["keepalive"] = False
    ret = do_request(addrcon, path, body, headers, **kwargs)
    return ret[1], ret[2], ret[3][0], ret[3][1]


def check_addrcon(addrcon):
    if isinstance(addrcon, str) and len(addrcon) <= config.max_urllength:
        return True
    elif isinstance(addrcon, SCNConnection):
        return True
    return False

addrconob = checkclass(check_addrcon, classtype=object)


class ViaServerStruct(object):
    def do_request(self, path: str, body, headers: dict, addrcon=None, **kwargs):
        raise NotImplementedError

    def _do_request2(self, path: str, body, headers: dict, forcehash=None, addrcon=None, **kwargs):
        if forcehash:
            self.do_request(path, body, headers, addrcon=addrcon, forcehash=forcehash, **kwargs)
        else:
            self.do_request(path, body, headers, addrcon=addrcon, **kwargs)

    def via_server(self, server: str, _hash: hashstr, name=None, sforcehash=None, forcehash=None, addrcon=None):
        """func: get client address via a server
            return: return client address or error
            server: server url
            name: client name
            hash: client hash
            sforcehash: enforced server hash
            forcehash: enforced client hash
            addrcon: connection or address of client """
        if name:
            get_b = {"server": server, "hash": _hash, "name": name, "forcehash": sforcehash}
            get_ret = self._do_request2("/client/get", get_b, {}, addrcon=addrcon, forcehash=forcehash)
            if get_ret[1]:
                return get_ret
        grefsb = {"hash": hash, "filter": "sname"}
        getrefs = self._do_request2("/client/getreferences", grefsb, {}, addrcon=addrcon, forcehash=forcehash)
        if not getrefs[1]:
            return getrefs
        newname = getrefs[2]["items"][0][0]
        get_b = {"server": server, "hash": _hash, "name": newname}
        get_ret = self._do_request2("/client/get", get_b, {}, addrcon=addrcon, forcehash=forcehash)
        #if get_ret[1] and get_ret[2].get("hash") != _hash:
        #    logging.warning("Hash has been changed")
        return get_ret

    # extended get
    def checked_get(self, server: str, _hash: hashstr, sname: namestr, name=None, sforcehash=None, forcehash=None, addrcon=None):
        """func: check if client is reachable; update local information when reachable
            return: priority, type, certificate security, (new-)hash (client)
            server: server url
            name: client name
            hash: client certificate hash
            sforcehash: enforced server hash
            forcehash: enforced client hash
            addrcon: connection or address of client or None (use default) """
        via_ret = self.via_server(server, _hash, name=name, sforcehash=sforcehash, forcehash=forcehash, addrcon=addrcon)
        if not via_ret[1]:
            return via_ret
        addressnew = "{address}-{port}".format(**via_ret[2])
        if _hash != via_ret[2].get("hash") or via_ret[2].get("security", "valid") != "valid":
            _forcehash2 = via_ret[1].get("hash")
        else:
            _forcehash2 = None
        _check_directb = {"address": addressnew, "hash": _hash, "security": via_ret[1].get("security", "valid"), "forcehash":_forcehash2}
        direct_ret = self._do_request2("/client/check_direct",  _check_directb, {}, addrcon=addrcon, forcehash=forcehash)
        # return new hash in hash field
        if direct_ret[1]:
            if _hash != direct_ret[3][1]:
                logging.warning("Hash was updated")
                via_ret[2]["security"] = "unverified"
            via_ret[2]["hash"] = direct_ret[3][1]
            return via_ret
        else:
            return direct_ret

    def wrap_via_server(self, server: str, _hash: hashstr, sname: namestr, name=None, sforcehash=None, forcehash=None, addrcon=None):
        """func: wrap via a server
            return: wrap return or error
            server: server url
            name: client name
            hash: client hash
            sname: service name
            sforcehash: enforced server hash
            forcehash: enforced client hash
            addrcon: connection or address of client """

        via_ret = self.checked_get(server, _hash, name=name, forcehash=forcehash, sforcehash=sforcehash, addrcon=addrcon)
        if not via_ret[1]:
            return via_ret
        newaddress = "{address}-{port}".format(**via_ret[2])
        # can throw exception if invalid change
        wrapbody = {"address": newaddress,"name": sname, "forcehash": via_ret[2].get("hash")}
        return self.do_request("/client/wrap", wrapbody, {}, addrcon=addrcon, keepalive=True, forcehash=forcehash)

    def prioty_via_server(self, server: str, _hash: hashstr, sname: namestr, name=None, sforcehash=None, forcehash=None, addrcon=None):
        """func: retrieve priority and type of a client on a server
            return: priority and type
            server: server url
            name: client name
            hash: client hash
            sforcehash: enforced server hash
            forcehash: enforced client hash
            addrcon: connection or address of client or None (use default)"""

        via_ret = self.checked_get(server, _hash, name=name, sforcehash=sforcehash, forcehash=forcehash, addrcon=addrcon)
        if not via_ret[1]:
            return via_ret
        addressnew = "{address}-{port}".format(**via_ret[2])
        # can throw exception if invalid change
        pdirectb = {"address": addressnew, "forcehash": via_ret[2].get("hash")}
        return self._do_request2("/client/prioty_direct", pdirectb, {}, addrcon=addrcon, forcehash=forcehash)


class Requester(ViaServerStruct):
    """ cache arguments, be careful, slows down requests by using copy() """
    saved_kwargs = None
    default_addrcon = None
    def __init__(self, default_addrcon=None, **kwargs):
        """ set default kwargs and address.
             address can be overwritten in a request by specifing addrcon=newaddress
             kwargs can be overwritten in a request by specifing key=newvalue """
        self.default_addrcon = default_addrcon
        self.saved_kwargs = kwargs

    def do_request(self, path, body, headers, addrcon=None, **kwargs):
        if not addrcon:
            addrcon = self.default_addrcon
        _kwargs = self.saved_kwargs.copy()
        _kwargs.update(kwargs)
        return do_request(addrcon, path, body, headers, **_kwargs)

    def do_request_simple(self, path, body, headers, addrcon=None, **kwargs):
        if not addrcon:
            addrcon = self.default_addrcon
        _kwargs = self.saved_kwargs.copy()
        _kwargs.update(kwargs)
        return do_request_simple(addrcon, path, body, headers, **_kwargs)
