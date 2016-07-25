"""
tools
license: MIT, see LICENSE.txt
"""

import functools
import os
import ssl
import logging
import socket
from http.client import HTTPSConnection

from simplescn import config, pwcallmethod
from simplescn.config import isself

from simplescn.tools import badnamechars, dhash, default_sslcont, url_to_ipv6

allowed_permissions = {"gettrust", "admin", "client"}

def check_reference(_reference):
    if _reference is None:
        return False
    if len(_reference) > 100:
        return False
    if not all(c not in "\0'\"\x1A\x7F" for c in _reference):
        return False
    return True

def check_reference_type(_reference_type):
    if _reference_type is None:
        return False
    if len(_reference_type) > config.max_typelength:
        return False
    if not all(c in "0123456789abcdefghijklmnopqrstuvxyz_" for c in _reference_type):
        return False
    return True

def check_security(_security):
    if _security in config.security_states:
        return True
    return False

def check_local(addr):
    if addr.lower() in ["127.0.0.1", "::1", "::ffff:127.0.0.1"]:
        return True
    return False

#def check_local_user(port):
#    import psutil
#    if addr.lower() in ["127.0.0.1", "::1", "::ffff:127.0.0.1"]:
#        return True
#    return False


# DEFAULT_HASHALGORITHM_len for default hash algo
# but None by default for validating hashes of other length
def check_hash(hashstr, length=None):
    """ check if valid hash (for scn) """
    if hashstr in [None, ""]:
        return False
    if length and len(hashstr) != length:
        return False
    # don't allow uppercase as it could confuse clients+servers and lowercase is default
    if not all(c in "0123456789abcdef" for c in hashstr):
        return False
    return True

def check_name(_name, maxlength=config.max_namelength):
    """ check node name """
    if _name is None:
        return False
    # name shouldn't be too long or 0
    if len(_name) > maxlength or len(_name) == 0:
        return False
    for char in _name:
        # ensure no bad, control characters
        if char in badnamechars or not char.isprintable():
            return False
    # name shouldn't be isself as it is used
    if _name == isself:
        return False
    return True

@functools.lru_cache(maxsize=16)
def check_typename(_type, maxlength=config.max_typelength):
    """ check if valid node type """
    if _type is None:
        return False
    # type shouldn't be too long or 0
    if len(_type) > maxlength or len(_type) == 0:
        return False
    # ensure no bad characters
    if not _type.isalpha() or not _type.islower():
        return False
    # type shouldn't be isself as it is used
    if _type == isself:
        return False
    return True


def check_trustpermission(_type):
    if _type is None:
        return False
    if _type in allowed_permissions:
        return True
    return False

def check_conftype(_value, _converter):
    try:
        if _converter is bool:
            if str(_value) not in ["False", "True"]:
                return False
        else:
            _converter(str(_value))
    except Exception as exc:
        logging.error("invalid value converter: %s value: %s error: %s", _converter, _value, exc)
        return False
    return True

def check_certs(path):
    privpath = "{}.priv".format(path)
    pubpath = "{}.pub".format(path)
    if not os.path.exists(privpath) or not os.path.exists(pubpath):
        return False
    try:
        _context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        _context.load_cert_chain(pubpath, keyfile=privpath, password=lambda: bytes(pwcallmethod("Enter passphrase for decrypting privatekey:"), "utf-8"))
        return True
    except Exception as exc:
        logging.error(exc)
    return False

# removed support for checking multiple classifier in one call
# reason: huge speed improvements
@functools.lru_cache()
def check_classify(func, perm: str) -> bool:
    if not hasattr(func, "classify"):
        return False
    return perm in func.classify

# args is iterable with (argname, type)
# _moddic is modified
def check_args(_moddict, requires=None, optional=None, error=None):
    if not requires:
        requires = {}
    if not optional:
        optional = {}
    if error is None:
        error = []
    search = set()
    if not isinstance(requires, dict):
        raise TypeError("requires wrong type: " + type(requires).__name__)
    if not isinstance(optional, dict):
        raise TypeError("optional wrong type: " + type(optional).__name__)
    search.update(requires.items())
    #_optionallist = [elemoptional[0] for elemoptional in optional]
    search.update(optional.items())
    for argname, value in search:
        _type = value
        if argname not in _moddict:
            if argname in optional:
                continue
            error.append(argname)
            error.append("argname not found")
            return False
        if isinstance(_moddict[argname], _type):
            continue
        if _type is tuple and isinstance(_moddict[argname], list):
            _moddict[argname] = tuple(_moddict[argname])
            continue
        if _type is list and isinstance(_moddict[argname], tuple):
            _moddict[argname] = list(_moddict[argname])
            continue
        # strip array and try again (limitation of www-parser) (not needed anymore)
        # if not _type in (tuple, list) and isinstance(_moddict[argname], (tuple, list)):
        #    _moddict[argname] = _moddict[argname][0]
        # is a number given as string?
        if _type is int and isinstance(_moddict[argname], str) and _moddict[argname].strip().rstrip().isdecimal():
            _moddict[argname] = int(_moddict[argname])
        # check if everything is right now
        if isinstance(_moddict[argname], _type):
            continue
        error.append(argname)
        error.append("wrong type: {}, {}".format(type(_moddict[argname]).__name__, _moddict[argname]))
        return False
    return True

cert_update_header = \
{
    "User-Agent": "simplescn/1.0 (update-cert)",
    "Authorization": 'scn {}',
    "Connection": 'keep-alive'
}

# can't use SCNConnection here. creates a cycle
# timeouts are better than close; they are dynamically adjusted
def check_updated_certs(_address, _port, certhashlist, newhash=None, timeout=config.default_timeout, connect_timeout=config.connect_timeout, traversefunc=None):
    update_list = []
    if None in [_address, _port]:
        logging.error("address or port empty")
        return None
    addr, _port = url_to_ipv6(_address, _port)
    cont = default_sslcont()
    con = HTTPSConnection(addr, _port, context=cont, timeout=connect_timeout)
    try:
        con.connect()
    except (ConnectionRefusedError, socket.timeout):
        if not traversefunc:
            logging.warning("Connection failed")
            return None
        # try_traverse does not work here, scnreqest creates loop
        con.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        con.sock.bind(('', 0))
        traversefunc(("", con.sock.getsockname()[1]))
        con.sock.settimeout(connect_timeout)
        for count in range(0, config.traverse_retries):
            try:
                con.sock.connect((addr, _port))
                break
            except Exception:
                pass
        else:
            logging.warning("traversal failed")
            return None
    con.sock.settimeout(timeout)
    oldhash = dhash(ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True)).strip().rstrip())
    if newhash and newhash != oldhash:
        return None
    oldsslcont = con.sock.context
    for _hash, _security in certhashlist:
        con.request("POST", "/usebroken/{hash}".format(hash=_hash), headers=cert_update_header)
        con.sock = con.sock.unwrap()
        con.sock = cont.wrap_socket(con.sock, server_side=False)
        con.sock.do_handshake()
        brokensslcert = ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True)).strip().rstrip()
        con.sock = con.sock.unwrap()
        # without next line the connection would be unencrypted now
        con.sock = oldsslcont.wrap_socket(con.sock, server_side=False)
        # con.sock.do_handshake()
        ret = con.getresponse()
        if ret.status != 200:
            logging.info("checking cert failed, code: %s, reason: %s", ret.status, ret.reason)
            continue
        if con.sock and oldhash != dhash(ssl.DER_cert_to_PEM_cert(con.sock.getpeercert(True)).strip().rstrip()):
            logging.error("certificate switch detected, stop checking")
            break
        if dhash(brokensslcert) == _hash:
            update_list.append((_hash, _security))
    con.close()
    return update_list
