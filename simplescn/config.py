"""
load parameters and init socket
license: MIT, see LICENSE.txt
"""

import socket

# load parameters in simplescn namespace
# don't load directly from parameters
# because parameters can be overwritten by parameters_overwrite
try:
    from simplescn.parameters_overwrite import *
except ImportError:
    from simplescn.parameters import *
socket.setdefaulttimeout(default_timeout)


# define file_family
if hasattr(socket, "AF_UNIX"):
    file_family = socket.AF_UNIX
else:
    file_family = None
