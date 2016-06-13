
from http import client
import socket
import json
import ssl


from simplescn import default_sslcont, scnparse_url, default_timeout, \
connect_timeout, gen_result, safe_mdecode, encode_bo, check_result, \
isself, dhash, create_certhashheader, \
AuthNeeded, VALHashError, VALNameError, VALMITMError, scnauth_client

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
    
    def do_request(self, *args, **kwargs):
        _kwargs = self.saved_kwargs.copy()
        _kwargs.update(kwargs)
        return do_request(*args, **_kwargs)

    def do_request_mold(self, *args, **kwargs):
        _kwargs = self.saved_kwargs.copy()
        _kwargs.update(kwargs)
        return do_request_mold(*args, **_kwargs)

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

def init_connection(addr_or_con, certcontext, traverseaddress=None, **kwargs):
    if not isinstance(addr_or_con, client.HTTPSConnection):
        if kwargs.get("use_unix", False):
            _addr = (addr_or_con, 0)
        else:
            _addr = scnparse_url(addr_or_con, force_port=kwargs.get("forceport", False))
        con = client.HTTPSConnection(_addr[0], _addr[1], context=certcontext,\
            timeout=kwargs.get("connect_timeout", kwargs.get("connect_timeout")))
        if kwargs.get("use_unix", False):
            con.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            con.sock.connect(addr_or_con)
            con.sock = certcontext.wrap_socket(con.sock)
    else:
        con = addr_or_con
    if not kwargs.get("forcetraverse", None) and con.sock is None:
        try:
            con.connect()
        except (ConnectionRefusedError, socket.timeout):
            forcetraverse = True

    if con.sock is None and not kwargs.get("use_unix", False) \
        and kwargs.get("forcetraverse", None)\
        and kwargs.get("traverseaddress", None):
        _tsaddr = scnparse_url(kwargs["traverseaddress"])
        contrav = client.HTTPSConnection(_tsaddr[0], _tsaddr[1], context=kwargs.get("connect_timeout", connect_timeout))
        contrav.connect()
        _sport = contrav.sock.getsockname()[1]
        retserv = do_request(contrav, "/server/open_traversal", {})
        contrav.close()
        if retserv[0]:
            con.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            con.sock.bind(('', _sport))
            con.sock.settimeout(kwargs.get("connect_timeout", connect_timeout))
            for count in range(0, 3):
                try:
                    con.sock.connect((_addr[0], _addr[1]))
                    break
                except Exception:
                    pass
            con.sock = certcontext.wrap_socket(con.sock)
            con.timeout = kwargs.get("timeout", default_timeout)
            con.sock.settimeout(kwargs.get("timeout", default_timeout))
    else:
        return None
    return con


# return can be:
# None, hash, cert
# isself, hash, cert
# (name, security), hash, cert
def check_cert(pcert, hashdb, ownhash, **kwargs):
    hashpcert = dhash(pcert)
    if kwargs.get("forcehash", None):
        if kwargs["forcehash"] != hashpcert:
            raise VALHashError()
    if hashpcert == ownhash:
        validated_name = isself
    else:
        hashob = None
        if hashdb:
            hashob = hashdb.get(hashpcert)
        if hashob:
            validated_name = (hashob[0], hashob[3]) #name, security
            if validated_name[0] == isself:
                raise VALNameError()
        else:
            validated_name = None
    return validated_name, hashpcert, pcert


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
def do_request(addr_or_con, path, body=None, headers=None, *, _certtupel=None, **kwargs):
    """ func: use this method to communicate with clients/servers
        kwargs:
            options:
                * use_unix: use unix sockets instead
                * forcehash: force hash on other side
                * sendclientcert: send own certhash to server, requires ownhash and certcontext
                * originalcert: send original cert (maybe removed)
                * connect_timeout: timeout for connecting
                * timeout: timeout if connection is etablished
                * forceport: True: raise if no port is given, False: use server port in that case
            special:
                * certcontext: specify certcontext used
                * ownhash: own hash
                * owncert: own cert
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
    if not kwargs.get("certcontext", None):
        kwargs["certcontext"] = default_sslcont()

    sendbody, sendheaders = init_body_headers(body, headers)

    con = init_connection(addr_or_con, **kwargs)
    if not con:
        return None, False, "no connection", (isself, kwargs.get("ownhash", None), kwargs.get("owncert", None))
    pcert = ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True)).strip().rstrip()
    if not _certtupel:
        _certtupel = check_cert(pcert, **kwargs)

    if kwargs.get("sendclientcert", False):
        if kwargs.get("certcontext", None) and kwargs.get("ownhash", None):
            sendheaders["X-certrewrap"], _random = create_certhashheader(kwargs["ownhash"])
        else:
            con.close()
            return None, False, "missing: certcontext or ownhash", _certtupel

    #start connection
    con.putrequest("POST", path)
    for key, value in sendheaders.items():
        con.putheader(key, value)
    if kwargs.get("originalcert", None):
        con.putheader("X-original_cert", kwargs.get("originalcert"))
    con.endheaders()
    if kwargs.get("sendclientcert", False):
        con.sock = con.sock.unwrap()
        con.sock = kwargs["certcontext"].wrap_socket(con.sock, server_side=True)
    con.send(sendbody)
    response = con.getresponse()
    if kwargs.get("sendclientcert", False):
        if _random != response.getheader("X-certrewrap", ""):
            con.close()
            return None, False, "rewrapped cert secret does not match", _certtupel

    if kwargs.get("sendclientcert", False):
        if _random != response.getheader("X-certrewrap", ""):
            con.close()
            raise VALMITMError()
    if response.status == 401:
        if not response.headers.get("Content-Length", "").strip().rstrip().isdigit():
            con.close()
            return None, False, "pwrequest has no content length", _certtupel
        readob = response.read(int(response.getheader("Content-Length")))
        if callable(kwargs.get("pwhandler", None)):
            reqob = safe_mdecode(readob, response.getheader("Content-Type", "application/json"))
            if authorisation(kwargs["pwhandler"], reqob, sendheaders):
                return do_request(addr_or_con, path, body=body, \
                    headers=sendheaders, _certtupel=_certtupel, **kwargs)
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
                return None, False, "error parsing request\n{}".format(readob), _certtupel
        else:
            obdict = gen_result("", success)
        if success:
            return con, True, obdict["result"], _certtupel
        else:
            return con, False, obdict["error"], _certtupel

def do_request_mold(*args, **kwargs):
    ret = do_request(*args, **kwargs)
    if ret[0]:
        ret[0].close()
    return ret[1], ret[2], ret[3][0], ret[3][1]
