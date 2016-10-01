"""
exceptions, errors
license: MIT, see LICENSE.txt
"""

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
    msg = 'address lacking -<port>'
class AddressEmptyError(AddressError):
    msg = 'address empty'
class AddressLengthError(AddressError):
    msg = 'address too long'
class AddressInvalidError(AddressError):
    msg = 'address invalid'

class InvalidLoadError(Exception):
    msg = ''
    def __str__(self):
        return self.msg
class InvalidLoadSizeError(InvalidLoadError):
    msg = 'Load invalid tuple/list (needs 3 items or 2 in case of very_low_load)'
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
    msg = 'MITM-attack suspected: nonce check failed (rewrap))'
