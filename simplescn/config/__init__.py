"""
load parameters and init socket
license: MIT, see LICENSE.txt
"""

import socket

# load parameters in simplescn namespace
# don't load directly from parameters
# because parameters can be overwritten by parameters_overwrite
try:
    from .parameters_overwrite import *
except ImportError:
    from .parameters import *
socket.setdefaulttimeout(default_timeout)


if use_sorteddict in {None, "sortedcontainer"}:
    try:
        from sortedcontainers import SortedDict as sorteddict
    except ImportError:
        sorteddict = None

if use_sorteddict in {None, "blist"}:
    if not sorteddict:
        try:
            from blist import sorteddict
        except ImportError:
            sorteddict = None

if use_sorteddict and not sorteddict:
    logging.warning("sorteddict not found")

# define file_family
if hasattr(socket, "AF_UNIX"):
    file_family = socket.AF_UNIX
else:
    file_family = None
