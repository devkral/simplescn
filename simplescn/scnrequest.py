
from http import client
import socket
import json
import ssl

from simplescn import config
from simplescn.config import isself

from simplescn.tools import default_sslcont, scnparse_url, \
safe_mdecode, encode_bo, \
dhash, create_certhashheader, scnauth_client

from simplescn import AuthNeeded, VALHashError, VALNameError, VALMITMError
from simplescn._common import gen_result, check_result


auth_instance = scnauth_client()

reference_header = \
{
    "User-Agent": "simplescn/1.0",
    "Authorization": 'scn {}',
    "Connection": 'keep-alive' # keep-alive is set by server (and client?)
}

strip_headers = ["Connection", "Host", "Accept-Encoding", \
"Content-Length", "User-Agent", "X-certrewrap"]

class requester(object):
    saved_kwargs = None
    def __init__(self, **kwargs):
        self.saved_kwargs = kwargs
    
    def do_request(self, addr_or_con, path, body=None, headers=None, **kwargs):
        _kwargs = self.saved_kwargs.copy()
        _kwargs.update(kwargs)
        return do_request(addr_or_con, path, body=body, headers=headers, **_kwargs)

    def do_request_simple(self, addr_or_con, path, body=None, headers=None, **kwargs):
        _kwargs = self.saved_kwargs.copy()
        _kwargs.update(kwargs)
        return do_request_simple(addr_or_con, path, body=body, headers=headers, **_kwargs)


class SCNConnection(client.HTTPSConnection):
    """ easy way to connect with simplescn nodes """
    kwargs = None
    
    # valid values for certtupel
    # None
    # None, hash, cert
    # isself, hash, cert
    # (name, security), hash, cert
    certtupel = None
    def __init__(self, host, **kwargs):
        # don't implement highlevel stuff here, needed by traversal
        self.kwargs = kwargs
        super().__init__(host, 0, None)
        self._context = self.kwargs.get("certcontext", default_sslcont())
        self._check_hostname = None
        # throw exception here
        scnparse_url(self.host, force_port=kwargs.get("forceport", False))
    
    def connect(self):
        """Connect to the host and port specified in __init__."""
        
        if self.kwargs.get("use_unix"):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(self.host)
        else:
            _host = scnparse_url(self.host, force_port=self.kwargs.get("forceport", False))
            try:
                self.sock = self._create_connection(
                _host, self.kwargs.get("connect_timeout", config.connect_timeout), self.source_address)
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
                retserv = do_request(contrav, "/server/open_traversal", {})
                contrav.close()
                if retserv[0]:
                    self.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    self.sock.bind(('', _sport))
                    self.sock.settimeout(self.kwargs.get("connect_timeout", config.connect_timeout))
                    for count in range(0, self.kwargs.get("traverse_retries", config.traverse_retries)):
                        try:
                            self.sock.connect(_host)
                            break
                        except Exception:
                            pass
                    else:
                        return None
            # set options for ip
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # set options for all
        self.sock.settimeout(self.kwargs.get("timeout", config.default_timeout))
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
                raise VALHashError()
        if hashpcert == self.kwargs.get("ownhash", None):
            validated_name = isself
        else:
            hashob = None
            if self.kwargs.get("hashdb", None):
                hashob = self.kwargs["hashdb"].get(hashpcert)
            if hashob:
                validated_name = (hashob[0], hashob[3]) #name, security
                if validated_name[0] == isself:
                    raise VALNameError()
            else:
                validated_name = None
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
    elif isinstance(body, str):
        sendbody = bytes(body, "utf-8")
    else:
        sendbody = None
    if sendbody:
        sendheaders["Content-Length"] = str(len(sendbody))

    if headers:
        for key, value in headers.items():
            if key not in strip_headers:
                sendheaders[key] = value
    return sendbody, sendheaders



def authorisation(pwhandler, reqob, serverhash, headers):
    """ handles auth, headers arg will be changed """
    if not isinstance(reqob, dict):
        return False
    realm = reqob.get("realm")
    pw = pwhandler(realm)
    if not pw:
        return False
    auth_parsed = json.loads(headers.get("Authorization", "scn {}").split(" ", 1)[1])
    auth_parsed[realm] = auth_instance.auth(pw, reqob, serverhash) #, serverhash)
    headers["Authorization"] = "scn {}".format(json.dumps(auth_parsed).replace("\n", ""))
    return True

# return connection, success, body, certtupel
# certtupel is None if no
def _do_request(addr_or_con, path, body, headers, kwargs):
    """ func: main part for communication, use wrapper instead """

    sendbody, sendheaders = init_body_headers(body, headers)

    if isinstance(addr_or_con, SCNConnection):
        con = addr_or_con
    else:
        con = SCNConnection(addr_or_con, **kwargs)
    if con.sock is None:
        con.connect()
    if con.sock is None:
        return None, False, "Could not open connection", (isself, kwargs.get("ownhash", None), None)

    if kwargs.get("sendclientcert", False):
        if kwargs.get("certcontext", None) and kwargs.get("ownhash", None):
            _header, _random = create_certhashheader(kwargs["ownhash"])
            sendheaders["X-certrewrap"] = _header
        else:
            con.close()
            return None, False, "missing: certcontext or ownhash", con.certtupel

    if kwargs.get("originalcert", None):
        sendheaders["X-original_cert"] = kwargs.get("originalcert")

    #start connection
    con.putrequest("POST", path)
    for key, value in sendheaders.items():
        con.putheader(key, value)

    con.endheaders()
    if kwargs.get("sendclientcert", False):
        con.rewrap()
    con.send(sendbody)
    response = con.getresponse()

    if kwargs.get("sendclientcert", False):
        if _random != response.getheader("X-certrewrap", ""):
            con.close()
            return None, False, "rewrapped cert secret does not match", con.certtupel

    if kwargs.get("sendclientcert", False):
        if _random != response.getheader("X-certrewrap", ""):
            con.close()
            raise VALMITMError()
    if response.status == 401:
        if not response.headers.get("Content-Length", "").strip().rstrip().isdigit():
            con.close()
            return None, False, "pwrequest has no content length", con.certtupel
        readob = response.read(int(response.getheader("Content-Length")))
        if callable(kwargs.get("pwhandler", None)):
            reqob = safe_mdecode(readob, response.getheader("Content-Type", "application/json"))
            if authorisation(kwargs["pwhandler"], reqob, con.certtupel[1], sendheaders):
                return do_request(con, path, body=body, \
                    headers=sendheaders, **kwargs)
        raise AuthNeeded(con, str(readob, "utf-8"))
    else:
        if response.status == 200:
            success = True
        else:
            success = False

        if response.getheader("Content-Length", "").strip().rstrip().isdigit():
            readob = response.read(int(response.getheader("Content-Length")))
            conth = response.getheader("Content-Type", "application/json")
            if conth.split(";")[0].strip().rstrip() in ["text/plain", "text/html"]:
                obdict = gen_result(encode_bo(readob, conth), success)
            else:
                obdict = safe_mdecode(readob, conth)
            if not check_result(obdict, success):
                con.close()
                return None, False, "error parsing request\n{}".format(readob), con.certtupel
        else:
            obdict = gen_result(response.reason, success)
        if success:
            return con, True, obdict["result"], con.certtupel
        else:
            return con, False, obdict["error"], con.certtupel

def do_request(addr_or_con, path, body=None, headers=None, **kwargs):
    """ func: use this method to communicate with clients/servers
        kwargs:
            options:
                * use_unix: use unix sockets instead
                * tense: (True) False: add certificate of communication partner
                * forcehash: force hash on other side
                * sendclientcert: send own certhash to server, requires ownhash and certcontext
                * originalcert: send original cert (maybe removed)
                * connect_timeout: timeout for connecting
                * timeout: timeout if connection is etablished
                * forceport: True: raise if no port is given, False: use server port in that case
            special:
                * certcontext: specify certcontext used
                * ownhash: own hash
                * pwhandler: method for handling pws
        headers:
            * Authorization: scn pw auth format
        throws:
            * AddressFail: address was incorrect
            * AddressEmptyFail: address was empty
            * EnforcedPortFail: no port was given (forceport)
            * VALHashError: wrong hash (forcehash)
            * VALNameError: isself is in db
            * VALMITMError: rewrapped connection contains wrong secret (sendclientcert)
            * AuthNeeded: request Auth, contains con and authob (needed for auth)
    """
    ret = _do_request(addr_or_con, path, body, headers, kwargs)
    if kwargs.get("tense", True):
        return ret[0], ret[1], ret[2], ret[3][0], ret[3][1]
    else:
        return ret

def do_request_simple(addr_or_con, path, body=None, headers=None, **kwargs):
    """ autoclose connection """
    ret = do_request(addr_or_con, path, body=body, headers=headers, **kwargs)
    if ret[0]:
        ret[0].close()
    return ret[1:]