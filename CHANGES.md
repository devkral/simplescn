

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

