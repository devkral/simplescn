# 0.6
## bugfixes

# 0.5
## bugfixes
* all headers were send to server in some methods
* document parameters
* fix missing stacktrace

## changes
* scnrequest can retrieve remote certificate from client instance
* use classify_local
* expose public certificate
* access_dict can take function (speed improvements)
* certtupel instead cert_hash (speed improvements (less copies) and needed for exposing certificate)
* remove support for multiple classifier (not used) in check_classify (speed improvements)
* change do_request return format
* remove tense option
* remove do_request_simple calls in client

# 0.4
## bug fixes
* crash in register can lead to pinger fail
* fix warning in tests
## changes
* move stuff to tools

# 0.3
## important bugfixes
* fix sending client pw to server

## changes
* change whole cmd structure to improve speed
* only passwords for server component, for remote client and admin a certificate based authentification is used (not tested)
* cmdcom uses now "action" instead of "command"


## new features
* cert hash based protection
* improved pw stuff
* unix sockets
* advanced url support (by using getaddrinfo, causes a small slowdown on clientside)
* wrap, traverse support (untested and deactivated)

