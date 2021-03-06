# 0.8.0
## changes
* remove certrefcount hack
* autoupdate old db format (0.7.1 can't do this)
* add option for updating old db format
* prepare for multiprocessing
* add forking support (untested)
* add register_hash (for permanent registering a hash)
* add check_register_hook for access control

## bugfixes
* add missing sqlite3 pragmas (if db is changed)
* db can stay locked if exception happens

# 0.71
## changes
* add merge option for renameentity
* add more pwrequest providers
* relax search restrictions of getreferences, findbyref
* add autoregister
* prepare for alternative rw_socket implementations

## bugfixes
* transfer and cleanup leftovers
* fix exception in __del__
* fix hang in rw_socket
* fix missing unique
* use STDIN instead sys.argv (more privacy)

# 0.7
## changes
* remove cleanoldfiles hack
* get_pidlock returns now state instead path or None
* move name to client_server
* add name to show() information
* generate_validactions_deco is now recursive
* add check_priority
* add tests (locking, massimport)
* use TemporaryDirectory for tests
* findbyref supports filtering
* use smart classes
* wrappedcon instead wrappedsocket
* optimize hashdb, permsdb
* add exist
* remove mode from register
* add option to configure traversal behavior for local clients
* Requester calls changed
* move prioty, check to ViaServer
* ViaServer provides via_direct, via_server using references
* add sname parameter to check_direct
* change get address field
* rename traverse to traverse_needed (register)
* add direct_proxy to cmdcom
* do_request can add pw to returned dict
* no warning if message is empty
* add proxy example(untested)
* logcheck supports do_request answers
* add logcheck_con
* fix+improve cmdcom single
* register allows to use a different name to register with
* fix sending packets at arbitary addresses (DDOS prevention)
* reorganize simplescn structure
* remove do_request_simple
* Requester uses partial and p.keywords instead saved_kwargs
* remove running_instances
* speed by sorting serverside

## bugfixes
* better validation of serveranswers
* fix multiinstance bugs
* fix tests
* fix massimport
* drastically improve speed by not using Requester
* fix blocked pw requests by moving composed requests
* fix cleaning certreferences
* fix traversal (still untested)
* fix invalid chars in default name
* fix loop_unix

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

