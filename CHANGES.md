# 0.7

## changes
* remove cleanoldfiles hack
* get_pidlock returns now state instead path or None
* move name to client_server
* add name to show() information
* generate_validactions_deco is now recursive
* add check_priority
* use daemon threads for SHTTPServer
* add tests (locking, massimport)
* use TemporaryDirectory for tests
* findbyref supports filtering
* use smart classes
* wrappedcon instead wrappedsocket
* optimize hashdb, permsdb
* add exist
* remove mode from register
* add option to configure traversal behaviour for local clients
* Requester calls changed
* move prioty, check to ViaServer
* add sname parameter to check_direct
* change get address field

## bugfixes
* better verification serveranswers
* fix multiinstance bugs
* fix tests
* fix massimport
* drastically improve speed by not using Requester
* fix blocked pw requests by moving composed requests
* fix cleaning certreferences

# 0.6.2
## bugfixes
* fix cleanup of old files after crash
## changes
* add cleanupoldfiles option to getlocalclient

# 0.6
## bugfixes
* unix sockets are better secured
* protect regex against long urls
* fix wrap support
* add example

## changes
* require prefix for foreign created services
* rename *trust to *perm
* move trusteddb, hasdb into links
* add more modes for registerservice
* announce client with info file
* change defaults
* speed up by using caches
* move starter of client, server to start
* rename classes to python naming convention
* move certtupel to links (isself support serverside)

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

