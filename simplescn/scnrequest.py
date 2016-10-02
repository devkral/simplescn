
from http import client
import socket
import json
import ssl
import logging
import functools

from . import config
from .config import isself
from .tools import default_sslcont, scnparse_url, \
safe_mdecode, encode_bo, try_traverse, quick_error, \
dhash, create_certhashheader, scn_hashedpw_auth, url_to_ipv6, gen_result
from .exceptions import AuthNeeded, VALHashError, VALNameError, VALMITMError
from .tools.checks import namestr, hashstr, checkclass

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
                _kwargs.pop("hashedpw", None)
                trav = _kwargs.pop("traverseaddress", None)
                if trav is None:
                    self.sock = None
                    return
                headerstraverse = {}
                travpw = _kwargs.pop("traversepw", None)
                if travpw:
                    headerstraverse["X-SCN-Authorization"] = travpw
                contrav = SCNConnection(trav, **_kwargs)
                contrav.connect()
                if not contrav.sock:
                    return
                _sport = contrav.sock.getsockname()[1]
                if self.host == trav:
                    _hosttraverse = "::1-{}".format(_host[1])
                else:
                    _hosttraverse = "{}-{}".format(_host[0], _host[1])
                try:
                    retserv = do_request(trav, "/server/open_traversal", {"destaddr": _hosttraverse}, headerstraverse, keepalive=True)
                except AuthNeeded:
                    contrav.close()
                    self.sock = None
                    logging.info("Auth missmatch/No auth provided for pw protected traversal server")
                    return
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
                * traverseaddress: traverse address
                * traverse_retries: retries to traverse
                * traversepw: dhashed pw for traversal server
                * retrievepw: add hashedpw to obdict (default off)
            special:
                * certcontext: specify certcontext used
                * ownhash: own hash
                * pwhandler: method for handling pws
                * hashedpw: dhashed pw (transmitted as X-SCN-Authorization header)
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
        returns:
            * SCNConnection/None, success, obdict, certtupel
                obdict may contains: hashedpw (if retrievepw), origcertinfo
                please be careful with sensitive hashedpw entry
    """
    assert addrcon in addrconob, "addrcon is not a valid addrconob".format(type(addrcon))
    assert isinstance(body, (dict, bytes)), "body is neither dict nor bytes, {}".format(type(body))
    sendbody, sendheaders = init_body_headers(body, headers)
    if isinstance(addrcon, SCNConnection):
        con = addrcon
    else:
        con = SCNConnection(addrcon, **kwargs)
    if con.sock is None:
        con.connect()
    if con.sock is None:
        return None, False, quick_error("Could not open connection"), (isself, kwargs.get("ownhash", None), None)

    if kwargs.get("sendclientcert", False):
        if kwargs.get("certcontext", None) and kwargs.get("ownhash", None):
            _header, _random = create_certhashheader(kwargs["ownhash"])
            sendheaders["X-certrewrap"] = _header
        else:
            con.close()
            return None, False, quick_error("missing: certcontext or ownhash"), con.certtupel

    if kwargs.get("keepalive", True):
        sendheaders["Connection"] = 'keep-alive'
    else:
        sendheaders["Connection"] = 'close'

    hashedpw = kwargs.pop("hashedpw", None)
    if hashedpw:
        sendheaders["X-SCN-Authorization"] = kwargs["hashedpw"]
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
            return None, False, quick_error("rewrapped cert secret does not match"), con.certtupel

    if kwargs.get("sendclientcert", False):
        if _random != response.getheader("X-certrewrap", ""):
            con.close()
            raise VALMITMError()
    if response.status == 401:
        if not response.headers.get("Content-Length", "").isdigit():
            con.close()
            return None, False, quick_error("pwrequest has no content length"), con.certtupel
        readob = response.read(int(response.getheader("Content-Length")))
        reqob = safe_mdecode(readob, response.getheader("Content-Type", "application/json"))
        if headers and headers.get("X-SCN-Authorization", None):
            if authorization(headers["X-SCN-Authorization"], reqob, con.certtupel[1], sendheaders):
                return do_request(con, path, body=body, \
                    headers=sendheaders, kwargs=kwargs)
        elif callable(kwargs.get("pwhandler", None)):
            pw = kwargs.get("pwhandler")(config.pwrealm_prompt)
            if pw:
                kwargs["hashedpw"] = dhash(pw, reqob.get("algo"))
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
        #assert isinstance(obdict, dict), "obdict not a dict"
        if con and not kwargs.get("keepalive", True):
            con.close()

        # add hashedpw to output if success
        if kwargs.get("retrievepw", False):
            obdict["hashedpw"] = hashedpw
        # origcertinfo[0] is never isself, it is stripped
        if con.certtupel[0] is isself and "origcertinfo" in obdict:
            return con, success, obdict, obdict["origcertinfo"]
        else:
            return con, success, obdict, con.certtupel

def check_addrcon(addrcon):
    if isinstance(addrcon, str) and len(addrcon) <= config.max_urllength:
        return True
    elif isinstance(addrcon, SCNConnection):
        return True
    return False

addrconob = checkclass(check_addrcon, classtype=object)


class ViaServerStruct(object):
    def do_request(self, path: str, body, headers: dict, **kwargs):
        raise NotImplementedError

    def _do_request2(self, path: str, body, headers: dict, forcehash=None, addrcon=None, **kwargs):
        """ strip forcehash if None (don't unset forcehash) """
        if forcehash:
            return self.do_request(path, body, headers, addrcon=addrcon, forcehash=forcehash, **kwargs)
        else:
            return self.do_request(path, body, headers, addrcon=addrcon, **kwargs)

    # warning: contains hashedpw (server pw), be careful
    def via_server(self, _hash: hashstr, server=None, name=None, sforcehash=None, \
                   nosearchs=False, nosearchn=False, forcehash=None, addrcon=None):
        """func: get client address via a server
            return: return client address or error
            server: server url
            name: client name
            hash: client hash
            sforcehash: enforced server hash
            nosearchs: don't search in references for server
            nosearchn: don't search in references for name
            forcehash: enforced client hash
            addrcon: connection or address of client """
        if not nosearchs or not nosearchs:
            # check if hash exists
            ghashexist = {"hash": _hash}
            ghash = self._do_request2("/client/getlocal", ghashexist, \
                                               {}, addrcon=addrcon, forcehash=forcehash)
        if not nosearchs and ghash[1]:
            grefsb = {"hash": _hash, "filter": "surl"}
            getrefs_server = self._do_request2("/client/getreferences", grefsb, \
                                               {}, addrcon=addrcon, forcehash=forcehash)
            if not getrefs_server[1]:
                return getrefs_server
            serverlist = [elem[0] for elem in getrefs_server[2]["items"]]
        else:
            serverlist = []
        if server:
            serverlist.insert(0, server)
        if not nosearchn and ghash[1]:
            grefsb = {"hash": _hash, "filter": "sname"}
            getrefs_name = self._do_request2("/client/getreferences", grefsb, \
                                             {}, addrcon=addrcon, forcehash=forcehash)
            if not getrefs_name[1]:
                return getrefs_name
            namelist = [elem[0] for elem in getrefs_name[2]["items"]]
        else:
            namelist = []
        if name:
            namelist.insert(0, name)

        get_ret = None, False, quick_error("no reference found"), (None, None, None)
        for _server in serverlist:
            for _name in namelist:
                get_b = {"server": _server, "hash": _hash, "name": _name}
                if sforcehash:
                    get_b["forcehash"] = sforcehash
                get_ret = self._do_request2("/client/get", get_b, {}, \
                                            addrcon=addrcon, forcehash=forcehash, retrievepw=True)
                if get_ret[1]:
                    get_ret[2]["server"] = _server
                    return get_ret
        return get_ret

    def via_direct(self, _hash: hashstr, addresses=None, traverseaddress=None, traversepw=None, forcehash=None, addrcon=None):
        """func: check if client is reachable; update local information when reachable
            return: priority, type, certificate security, (new-)hash (client)
            addresses: list with scnparsable addresses (for connecting direct)
            traverseaddress: address of server to use for traversal
            hash: remote client certificate hash
            forcehash: enforced (local) client hash
            addrcon: connection or address of client or None (use default) """
        if addresses:
            addresslist = addresses
        else:
            ghashexist = {"hash": _hash}
            ghash = self._do_request2("/client/getlocal", ghashexist, \
                                               {}, addrcon=addrcon, forcehash=forcehash)
            if not ghash[1]:
                return ghash
            grefsb = {"hash": _hash, "filter": "url"}
            getrefs_address = self._do_request2("/client/getreferences", grefsb, {}, \
                                                addrcon=addrcon, forcehash=forcehash)
            if not getrefs_address[1]:
                return getrefs_address
            addresslist = [elem[0] for elem in getrefs_address[2]["items"]]
        direct_ret = None, False, quick_error("addresslist empty"), (None, None, None)
        for _address in addresslist:
            _check_directb = {"address": _address, "hash": _hash, "forcehash": _hash}
            if traverseaddress:
                _check_directb["traverseaddress"] = traverseaddress
            if traversepw:
                _check_directb["traversepw"] = traversepw
            direct_ret = self._do_request2("/client/check_direct", _check_directb, {}, \
                                           addrcon=addrcon, forcehash=forcehash)
            if direct_ret[1]:
                return direct_ret
        return direct_ret

    # extended get
    # warning: contains hashedpw (server pw), be careful
    def checked_get(self, _hash: hashstr, server=None, name=None, sforcehash=None, \
                    nosearchs=False, nosearchn=False, forcehash=None, addrcon=None):
        """func: check if client is reachable; update local information when reachable
            return: priority, type, certificate security, (new-)hash (client)
            server: server url
            name: remote client name
            hash: remote client certificate hash
            sforcehash: enforced server hash
            forcehash: enforced (local) client hash
            addrcon: connection or address of client or None (use default) """
        via_ret = self.via_server(_hash, server=server, name=name, sforcehash=sforcehash, \
            nosearchs=nosearchs, nosearchn=nosearchn, forcehash=forcehash, addrcon=addrcon)
        if not via_ret[1]:
            return via_ret
        _check_directb = {"address": via_ret[2]["address"], "hash": _hash, \
                          "security": via_ret[2].get("security", "valid")}
        if via_ret[2].get("security", "valid") != "valid":
            _check_directb["forcehash"] = via_ret[2].get("hash")
        if "name" in via_ret[2]:
            _check_directb["sname"] = via_ret[2]["name"]
        if via_ret[2].get("traverse_needed", False):
            _check_directb["traverseaddress"] = via_ret[2]["server"]
            if via_ret[2]["hashedpw"]:
                _check_directb["traversepw"] = via_ret[2]["hashedpw"]
        direct_ret = self._do_request2("/client/check_direct", _check_directb, {}, \
                                       addrcon=addrcon, forcehash=forcehash)
        # return new hash in hash field
        if direct_ret[1]:
            if _hash != direct_ret[3][1]:
                logging.warning("Hash was updated")
                via_ret[2]["security"] = "unverified"
            via_ret[2]["hash"] = direct_ret[3][1]
            # warning: contains still hashedpw (server pw), be careful
            return via_ret
        else:
            return direct_ret

    def wrap_via_server(self, _hash: hashstr, sname: namestr, server=None, name=None, sforcehash=None, \
                        nosearchs=False, nosearchn=False, forcehash=None, addrcon=None):
        """func: wrap via a server
            return: wrap return or error
            server: server url
            name: remote client name
            hash: remote client hash
            sname: service name
            sforcehash: enforced server hash
            forcehash: enforced (local) client hash
            addrcon: connection or address of client """

        via_ret = self.checked_get(_hash, server=server, name=name, sforcehash=sforcehash, \
        nosearchs=nosearchs, nosearchn=nosearchn, forcehash=forcehash, addrcon=addrcon)
        if not via_ret[1]:
            return via_ret
        # can throw exception if invalid change
        wrapbody = {"address": via_ret[2]["address"], "name": sname, "forcehash": via_ret[2]["hash"]}
        if via_ret[2].get("traverse_needed", False):
            wrapbody["traverseaddress"] = via_ret[2]["server"]
            if via_ret[2]["hashedpw"]:
                wrapbody["traversepw"] = via_ret[2]["hashedpw"]
        ret = self.do_request("/client/wrap", wrapbody, {}, addrcon=addrcon, keepalive=True, forcehash=forcehash)
        if ret[1]:
            ret[2]["address"] = via_ret[2]["address"]
        return ret

    def prioty_via_server(self, _hash: hashstr, sname: namestr, server=None, name=None, sforcehash=None, \
                          nosearchs=False, nosearchn=False, forcehash=None, addrcon=None):
        """func: retrieve priority and type of a client on a server
            return: priority and type
            server: server url
            name: client name
            hash: client hash
            sforcehash: enforced server hash
            forcehash: enforced client hash
            addrcon: connection or address of client or None (use default)"""

        via_ret = self.checked_get(_hash, server=server, name=name, sforcehash=sforcehash, \
        nosearchs=nosearchs, nosearchn=nosearchn, forcehash=forcehash, addrcon=addrcon)
        if not via_ret[1]:
            return via_ret
        # can throw exception if invalid change
        pdirectb = {"address": via_ret[2]["address"], "forcehash": via_ret[2]["hash"]}
        if via_ret[2].get("traverse_needed", False):
            pdirectb["traverseaddress"] = via_ret[2]["server"]
            if via_ret[2]["hashedpw"]:
                pdirectb["traversepw"] = via_ret[2]["hashedpw"]
        ret = self._do_request2("/client/prioty_direct", pdirectb, {}, addrcon=addrcon, forcehash=forcehash)
        if ret[1]:
            ret[2]["address"] = via_ret[2]["address"]
        return ret

class Requester(ViaServerStruct):
    """ cache arguments, be careful, slows down requests by using copy() """
    p = None
    def __init__(self, addrcon=None, **kwargs):
        """ set default kwargs and address.
             address can be overwritten in a request by specifing addrcon=newaddress
             kwargs can be overwritten in a request by specifing key=newvalue """
        self.p = functools.partial(do_request, addrcon=addrcon, **kwargs)

    def do_request(self, path, body, headers, **kwargs):
        """ wrapped do_request """
        assert self.p.keywords.get("addrcon") or kwargs.get("addrcon"), "No addrcon given"
        #assert "addrcon" in kwargs and not kwargs["addrcon"], "addrcon set to None"
        if "addrcon" in kwargs and not kwargs["addrcon"]:
            del kwargs["addrcon"]
        return self.p(path=path, body=body, headers=headers, **kwargs)
