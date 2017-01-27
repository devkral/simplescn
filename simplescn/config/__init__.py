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


if not hasattr(os, "fork") and not use_threading:
    if use_threading is False:
        logging.warning("fork not supported fallback to threading")
    use_threading = True
if use_threading:
    import threading
    RLock = threading.RLock
    Lock = threading.Lock
    Event = threading.Event
    List = list
    Dict = dict
    if config.sorteddict:
        SDict = config.sorteddict
    else:
        SDict = dict
    class Namespace(object):
        lock = None
        def __init__(self, **kwargs):
            self.lock = Lock()
            self.__dict__.update(kwargs)

else:
    import multiprocessing
    manager = multiprocessing.Manager()
    Lock = manager.Lock
    RLock = manager.RLock
    Event = manager.Event
    List = manager.list
    Dict = manager.dict
    if config.sorteddict:
        manager.register('SDict', config.sorteddict, DictProxy)
        SDict = manager.SDict
    else:
        SDict = manager.dict
    Namespace = manager.Namespace

# define file_family
if hasattr(socket, "AF_UNIX"):
    file_family = socket.AF_UNIX
else:
    file_family = None
