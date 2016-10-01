
import functools

from .tools import quick_error
from .tools.checks import check_args

#def generate_permissionactions_deco(DecoClass):
#    DecoClass.validactions_admin = set()
#    DecoClass.validactions_normal = set()
#    for key, value in DecoClass.__dict__.items():
#        if not callable(value) or key[0] == "_":
#            continue
#        tClassify = getattr(value, "classify", None)
#        if not tClassify:
#            continue
#        if "accessable" in tClassify:
#            if "admin" in tClassify:
#                DecoClass.validactions_admin.add(key)
#            else:
#                DecoClass.validactions_normal.add(key)
#    return DecoClass

def _add_validaction(validactions, key, value):
    if not callable(value) or key[0] == "_":
        return
    tClassify = getattr(value, "classify", None)
    if not tClassify:
        return
    if "accessable" in tClassify:
        validactions.add(key)

def generate_validactions_deco(DecoClass):
    DecoClass.validactions = set()
    for parent in DecoClass.__bases__:
        for key, value in parent.__dict__.items():
            _add_validaction(DecoClass.validactions, key, value)
    for key, value in DecoClass.__dict__.items():
        _add_validaction(DecoClass.validactions, key, value)
    return DecoClass

# signals that method needs admin permission
def classify_admin(func):
    if not hasattr(func, "classify"):
        func.classify = set()
    func.classify.add("admin")
    return func

# signals that method only access internal methods and send no requests (e.g. do_request)
def classify_local(func):
    if not hasattr(func, "classify"):
        func.classify = set()
    func.classify.add("local")
    return func

# signals that method is private and should not be accessable
def classify_private(func):
    if not hasattr(func, "classify"):
        func.classify = set()
    func.classify.add("private")
    if "accessable" in func.classify:
        raise TypeError("can't be accessable and private")
    return func

# signals that method is access method
#access = accessing client/server
def classify_accessable(func):
    if not hasattr(func, "classify"):
        func.classify = set()
    func.classify.add("accessable")
    if "private" in func.classify:
        raise TypeError("can't be accessable and private")
    return func

def gen_doc_deco(func):
    # skip when no documentation is available
    if func.__doc__ is None:
        return func
    requires = getattr(func, "requires", {})
    optional = getattr(func, "optional", {})
    _docrequires = {}
    _docoptional = {}
    _docfunc, _docreturn = "n.a.", "n.a."
    for line in func.__doc__.split("\n"):
        parsed = line.split(":", 1)
        if len(parsed) != 2:
            continue
        _key = parsed[0].strip().rstrip()
        if _key == "func":
            _docfunc = parsed[1].strip().rstrip()
        if _key == "return":
            _docreturn = parsed[1].strip().rstrip()
        if _key in requires:
            _docrequires[_key] = parsed[1].strip().rstrip()
        if _key in optional:
            _docoptional[_key] = parsed[1].strip().rstrip()
    spacing = " "
    sep = "\n        * "
    if len(getattr(func, "classify", set())) > 0:
        classify = " ({})".format(", ".join(sorted(func.classify)))
    else:
        classify = ""
    # double space == first layer
    newdoc = "  * {}{classify}: {}\n    *{spaces}return: {}\n".format(func.__name__, _docfunc, _docreturn, spaces=spacing, classify=classify)
    if len(requires) == 0:
        newdoc = "{}    *{spaces}requires: n.a.{sep}".format(newdoc, spaces=spacing, sep=sep)
    else:
        newdoc = "{}    *{spaces}requires:\n        *{spaces}".format(newdoc, spaces=spacing)
    for key in requires.keys():
        newdoc = "{}{}({}): {}{sep}".format(newdoc, key, requires[key].__name__, _docrequires.get(key, "n.a."), sep=sep)
    if len(optional) != 0:
        newdoc = "{}\n    *{spaces}optional:\n        *{spaces}".format(newdoc[:-len(sep)], spaces=spacing)
    for key in optional.keys():
        newdoc = "{}{}({}): {}{sep}".format(newdoc, key, optional[key].__name__, _docoptional.get(key, "n.a."), sep=sep)
    func.__origdoc__ = func.__doc__
    func.__doc__ = newdoc[:-len(sep)]
    return func

# args is iterable with (argname, type)
# obdict (=_moddict) is modified
# -> Tuple[bool, Union[str, dict], Union[str, tuple, None], Union[str, None]]:
def check_args_deco(requires=None, optional=None):
    if not requires:
        requires = {}
    if not optional:
        optional = {}

    def func_to_check(func):
        @gen_doc_deco
        @functools.wraps(func)
        def get_args(self, obdict, **kwargs) -> (bool, dict, tuple):
            error = []
            if not check_args(obdict, requires, optional, error=error):
                assert len(error) == 2, "assert: check_args failed ({})+error broken: {}".format(func.__name__, error)
                return False, quick_error("check_args failed ({}) argument: {}, reason: {}".format(func.__name__, *error)), self.links["certtupel"]
            resp = func(self, obdict, **kwargs)
            assert resp is not None, "assert: no return value in function {}".format(type(func).__name__)

            if isinstance(resp, bool) or len(resp) == 1:
                if isinstance(resp, bool):
                    success = resp
                else:
                    success = resp[0]
                if success:
                    return True, {}, self.links["certtupel"]
                else:
                    return False, {}, self.links["certtupel"]
            elif len(resp) == 2:
                assert isinstance(resp[1], dict), "bug: second return value of {} is not dict (type: {}): {}".format(func.__name__, type(resp[1]), resp[1])
                return resp[0], resp[1], self.links["certtupel"]
            else:
                assert isinstance(resp[1], dict), "bug: second return value of {} is not dict (type: {}): {}".format(func.__name__, type(resp[1]), resp[1])
                return resp
        get_args.requires = requires
        get_args.optional = optional
        get_args.classify = getattr(func, "classify", set())
        #get_args.__doc__ = func.__doc__
        #get_args.__name__ = func.__name__
        return get_args
    return func_to_check
