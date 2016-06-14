

from simplescn.config import isself
from simplescn._common import generate_error
from simplescn.tools.checks import check_args

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

# signals that method is experimental
def classify_experimental(func):
    if not hasattr(func, "classify"):
        func.classify = set()
    func.classify.add("experimental")
    return func

# signals that method is access method
#access = accessing client/server
def classify_access(func):
    if not hasattr(func, "classify"):
        func.classify = set()
    func.classify.add("access")
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
def check_args_deco(requires=None, optional=None):
    if not requires:
        requires = {}
    if not optional:
        optional = {}
    def func_to_check(func):
        def get_args(self, obdict):
            error = []
            if not check_args(obdict, requires, optional, error=error):
                return False, "check_args failed ({}) arg: {}, reason:{}".format(func.__name__, *error), isself, self.cert_hash
            resp = func(self, obdict)
            if resp is None:
                return False, "bug: no return value in function {}".format(type(func).__name__), isself, self.cert_hash
            if isinstance(resp, bool) or len(resp) == 1:
                if not isinstance(resp, bool):
                    resp = resp[0]
                if resp:
                    return True, "{} finished successfully".format(func.__name__), isself, self.cert_hash
                else:
                    return False, "{} failed".format(func.__name__), isself, self.cert_hash
            elif len(resp) == 2:
                return resp[0], resp[1], isself, self.cert_hash
            else:
                return resp
        get_args.requires = requires
        get_args.optional = optional
        get_args.__doc__ = func.__doc__
        get_args.__name__ = func.__name__
        get_args.classify = getattr(func, "classify", set())
        return gen_doc_deco(get_args)
    return func_to_check


def generate_error_deco(func):
    def get_args(self, *args, **kwargs):
        resp = func(self, *args, **kwargs)
        if len(resp) == 4:
            _name = resp[2]
            _hash = resp[3]
        else:
            _name = isself
            _hash = self.cert_hash
        if not resp[0]:
            return False, generate_error(resp[1]), _name, _hash
        return resp
    return get_args
