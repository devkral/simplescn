
from http import client
import socket
import json

from simplescn import default_sslcont, scnparse_url

timeout = 60
connect_timeout = 10

reference_header = \
{
    "User-Agent": "simplescn/1.0",
    "Authorization": 'scn {}',
    "Connection": 'keep-alive' # keep-alive is set by server (and client?)
}

strip_headers = ["Connection", "Host", "Accept-Encoding", "Content-Length", "User-Agent", "X-certrewrap"]

strip_body = ["pwcall_method", "sendcertcontext", "headers", "hashdb"]


default_special_params = {
    "headers": None,
    "forceport": False,
    "forcehash": None,
    "forcetraverse": None,
    "traverseaddress": None,
    "certcontext": None,
    "sendhash": None,
    "hashdb": None,
    "ownhash": None,
    "pwcall_method": None,
    "timeout": timeout,
    "connect_timeout": connect_timeout
}

class requester(object):
    
    saved_kwargs = None
    def __init__(self, **kwargs):
        self.saved_kwargs = kwargs
    
    def do_request(self, *args, **kwargs):
        _kwargs = kwargs.copy()
        _kwargs.update(self.saved_kwargs)
        return do_request(*args, **_kwargs)
    
    def do_getcon(self, *args, **kwargs):
        _kwargs = kwargs.copy()
        _kwargs.update(self.saved_kwargs)
        return do_getcon(*args, **_kwargs)

def init_body_headers(body, headers):
    sendheaders = reference_header.copy()
    if isinstance(body, dict):
        if headers is None:
            headers = body.get("headers", {})
        sendbody = bytes(json.dumps(list(filter(lambda x: x not in strip_body, body))), "utf-8")
        sendheaders["Content-Type"] = "application/json; charset=utf-8"
    elif isinstance(body, bytes):
        sendbody = body
    else:
        sendbody = bytes(body, "utf-8")
    sendheaders["Content-Length"] = str(len(sendbody))

    if headers:
        for key, value in headers.items():
            if key not in strip_headers:
                sendheaders[key] = value
    return sendbody, sendheaders

def extract_params(_dict, destroy=False, params=None):
    if not params:
        params = default_special_params.copy()
    if destroy:
        eme = _dict.pop
    else:
        eme = _dict.get
    for elem, val in params.items():
        params[elem] = eme(elem, val)
    return params

def init_connection(addr_or_con, connect_timeout, timeout, certcontext, forceport=False, sendhash=None, forcetraverse=False, traverseaddress=None, **k):
    if not isinstance(addr_or_con, client.HTTPSConnection):
        _addr = scnparse_url(addr_or_con, force_port=forceport)
        con = client.HTTPSConnection(_addr[0], _addr[1], context=certcontext, timeout=connect_timeout)
    else:
        con = addr_or_con
    if not forcetraverse and con.sock is None:
        try:
            con.connect()
        except (ConnectionRefusedError, socket.timeout):
            forcetraverse = True

    if con.sock is None and forcetraverse and traverseaddress:
        _tsaddr = scnparse_url(traverseaddress)
        contrav = client.HTTPSConnection(_tsaddr[0], _tsaddr[1], context=connect_timeout)
        contrav.connect()
        _sport = contrav.sock.getsockname()[1]
        retserv = self.do_request(contrav, "/server/open_traversal")
        contrav.close()
        if retserv[0]:
            con.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            con.sock.bind(('', _sport))
            for count in range(0, 3):
                try:
                    con.sock.connect((_addr[0], _addr[1]))
                    break
                except Exception:
                    pass
            con.sock = self.sslcont.wrap_socket(con.sock)
            con.timeout = timeout
            con.sock.settimeout(timeout)
    else:
        return None
    return con



def check_cert(hashpcert, hashdb, ownhash, forcehash=None, **k):
    if forcehash is not None:
        if forcehash != hashpcert:
            raise VALHashError()
    elif forcehash is not None:
        if forcehash != hashpcert:
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
    return validated_name, hashpcert

def authorisation(con, auth_parsed, pwcall_method=None, **k):
    if not response.headers.get("Content-Length", "").strip().rstrip().isdigit():
        return False, "no content length"
    readob = response.read(int(response.headers.get("Content-Length")))
    reqob = safe_mdecode(readob, response.headers.get("Content-Type", "application/json; charset=utf-8"))
    if reqob is None:
        return False, "Invalid Authorization request object"
    realm = reqob.get("realm")
    if callable(pwcall_method):
        authob = pwcall_method(hashpcert, reqob, _reauthcount)
    else:
        return False, "no way to input passphrase for authorization"
    if authob is None:
        return False, "Authorization failed"
    return True, auth_parsed

def do_getcon(addr_or_con, path, headers, _reauthcount=0, _certtupel=None, **kwargs):
    params = extract_params(kwargs, False)
    con = init_connection(addr_or_con, **params)
    if not _certtupel:
        try:
            pcert = ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True)).strip().rstrip()
            hashpcert = dhash(pcert)
            _certtupel = check_cert(hashpcert, **params)
        except VALError as exc:
            logging.error(exc)
            return None, None, None
    
    if not params.get("certcontext", None):
        params["certcontext"] = default_sslcont()
    
    if params.get("sendhash", None):
        sendheaders["X-certrewrap"], _random = create_certhashheader(sendhash)
    #start connection
    con.putrequest("POST", path)
    for key, value in sendheaders.items():
        con.putheader(key, value)
    if params.get("originalcert"):
        con.putheader("X-original_cert", params.get("originalcert"))
    con.endheaders()
    if sendclientcert:
        con.sock = con.sock.unwrap()
        con.sock = self.sslcont.wrap_socket(con.sock, server_side=True)
    response = con.getresponse()
    if sendclientcert:
        if _random != response.getheader("X-certrewrap", ""):
            logging.error("rewrapped cert secret does not match: %s, %s", _certtupel[0], _certtupel[1])
            return None, None, None
    if response.status == 401:
        auth_parsed = json.loads(sendheaders.get("Authorization", "scn {}").split(" ", 1)[1])
        authok, authob = authorisation(con, auth_parsed, params)
        if not authok:
            con.close()
            logging.info(authob)
            return None, None, None
        _reauthcount += 1
        auth_parsed[realm] = authob
        sendheaders["Authorization"] = "scn {}".format(json.dumps(auth_parsed).replace("\n", ""))
        return self.do_getcon(con, path, headers=sendheaders, _certtupel=_certtupel, _reauthcount=_reauthcount, **params)
    elif response.status != 200:
        logging.warning(authob)
        return None, None, None
    else:
        
        pass

# return success, body, (name, security), hash
# return success, body, isself, hash
# return success, body, None, hash
def do_request(addr_or_con, path, body, headers=None, extract_from_body=False, *, _reauthcount=0, _certtupel=None, **kwargs):
    """ func: use this method to communicate with clients/servers """
    if _reauthcount == 0:
        if extract_from_body and isinstance(body, dict):
            params = extract_params(body, True)
            params = extract_params(kwargs, False, params=params)
        else:
            params = extract_params(kwargs, False)
    
    if not params.get("certcontext", None):
        params["certcontext"] = default_sslcont()

    
    sendbody, sendheaders = init_body_headers(body, headers)
    
    
    con = init_connection(addr_or_con, **params)
    if not _certtupel:
        pcert = ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True)).strip().rstrip()
        hashpcert = dhash(pcert)
        _certtupel = check_cert(hashpcert, **params)

    if params.get("sendcertcontext", None) and params.get("sendhash", None):
        sendheaders["X-certrewrap"], _random = create_certhashheader(sendhash)

    #start connection
    con.putrequest("POST", path)
    for key, value in sendheaders.items():
        con.putheader(key, value)
    if params.get("originalcert", None):
        con.putheader("X-original_cert", params.get("originalcert"))
    con.endheaders()
    if sendclientcert:
        con.sock = con.sock.unwrap()
        con.sock = self.sslcont.wrap_socket(con.sock, server_side=True)
    con.send(sendbody)
    response = con.getresponse()
    if sendclientcert:
        if _random != response.getheader("X-certrewrap", ""):
            return False, "rewrapped cert secret does not match", _certtupel[0], _certtupel[1]
    servertype = response.headers.get("Server", "")
    logging.debug("Servertype: %s", servertype)
    if response.status == 401:
        auth_parsed = json.loads(sendheaders.get("Authorization", "scn {}").split(" ", 1)[1])
        authok, authob = authorisation(con, auth_parsed, params)
        if not authok:
            con.close()
            return False, authob, _certtupel[0], _certtupel[1]
        _reauthcount += 1
        auth_parsed[realm] = authob
        sendheaders["Authorization"] = "scn {}".format(json.dumps(auth_parsed).replace("\n", ""))
        return self.do_request(con, path, body=body, headers=sendheaders, _certtupel=_certtupel, _reauthcount=_reauthcount, **params)
    else:
        # kill keep-alive connection when finished, or transport connnection
        #if isinstance(addr_or_con, client.HTTPSConnection) == False:
        if not response.getheader("Content-Length", "").strip().rstrip().isdigit():
            return False, "No content length", _certtupel[0], _certtupel[1]
        readob = response.read(int(response.getheader("Content-Length")))
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

