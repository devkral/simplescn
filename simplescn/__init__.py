#! /usr/bin/env python3

"""
load parameters, stuff
license: MIT, see LICENSE.txt
"""

#__all__ = ["simplescn.tools", "AuthNeeded", "AddressError"]
#__all__ += ["EnforcedPortError", "AddressEmptyError", "AddressInvalidError"]
#__all__ += ["InvalidLoadError"]
#__all__ += ["VALError", "VALNameError", "VALHashError", "VALMITMError"]
#__all__ += ["pwcallmethodinst", "pwcallmethodinst", "resp_st"]

###### signaling ######

class AuthNeeded(Exception):
    reqob = None
    con = None
    def __init__(self, con, reqob):
        super().__init__()
        self.reqob = reqob
        self.con = con

class AddressError(Exception):
    msg = ''
    basemsg = '<address>[-<port>]:\n'
    def __str__(self):
        return self.basemsg + self.msg

class EnforcedPortError(AddressError):
    msg = 'address is lacking -<port>'
class AddressEmptyError(AddressError):
    msg = 'address is empty'
class AddressInvalidError(AddressError):
    msg = 'address is invalid'

class InvalidLoadError(Exception):
    msg = ''
    def __str__(self):
        return self.msg
class InvalidLoadSizeError(InvalidLoadError):
    msg = 'Load is invalid tuple/list (needs 3 items or 2 in case of very_low_load)'
class InvalidLoadLevelError(InvalidLoadError):
    msg = 'Load levels invalid (not high_load>medium_load>low_load)'

class VALError(Exception):
    msg = ''
    basemsg = 'validation failed:\n'
    def __str__(self):
        return self.basemsg + self.msg
class VALNameError(VALError):
    msg = 'Name spoofed/does not match'
class VALHashError(VALError):
    msg = 'Hash does not match'
class VALMITMError(VALError):
    msg = 'MITM-attack suspected: nonce missing or check failed'

def inp_passw_cmd(msg):
    from getpass import getpass
    return getpass(msg+":\n")
pwcallmethodinst = inp_passw_cmd

# returns pw or ""
def pwcallmethod(msg):
    return pwcallmethodinst(msg)
