Simple, secure, with plugins enhanceable, communication platform.
This includes the management of dynamic ips and ports
Just register your clients with their own new generated keys
Nodes are not permanent, a restart deletes the entries on the server

Features:
* passwordprotection
* semi-decentral + encrypted
* simple portmapper, easy to integrate in other applications

Dependencies:
* python >=3.5
* python-cryptography (python3 version) (pip: cryptography)
* psutil (pip: psutil) (for pid lock, not needed with "nolock" option)
* optional: markdown (pip: markdown) (for more beautiful help)

# Security:

Man in the middle attacks are possible if:
* attacker knows the password or no password is set
* and the client has no hash of the public cert of the communication partner
* or the certificate is hacked (obvious)
As worse it sounds it is an unavoidable risk. Even OTR suffers from these problems.
Its nature lies in the decentral structure.
This means the user has to verify (server) hashes. This is not hard and is assisted by a friendlist and scn servers, which both use is strongly recommended.
In contrast to similar solutions it is up to the user putting certificates into the friendlist.

Openssl:
this program uses openssl for:
* retrieving certificates
* tls 1.2
replacing openssl with libressl should work

# Usage:
## with installation
scnmain parameters...
scnconnect parameters...

## without installation
python3 ./simplescn parameters...
python3 ./simplescn/cmdcom parameters...

parameters for scnmain:
client, server, pwhash (for creating a compatible hash), cmdcom (if scnconnect/cmdcom is hidden)

e.g. "scnmain server" for starting a server
pws can be set with:
scnmain server spwhash=$(scnmain pwhash test_pw)

parameters for scnconnect:

..._unix: use unix socket (not windows)
test, test_unix: start server+client+cmdloop
single, single_test &#91;url&#93;: send command to &#91;url&#93;
single, single_test &#91;url&#93;: cmdloop with &#91;url&#93;


# Installation

## pip

python -m pip [https://github.com/devkral/simplescn](https://github.com/devkral/simplescn)

or

python -m pip path-to-local-simplescn-repo

## Notes:

# Overwrite parameters:
copy parameters.py and save it as parameters_overwrite.py in the same folder

rawclient and gtkclient use different config files
the plugins will use the same config among the different clients except an other configdirectory is given

# urlsyntax
simplescn uses a different urlsyntax (for supporting ipv4/ipv6 without &#91;&#93;):
url&#91;-port&#93;
e.g. testfoo.test.com-4040, 127.0.0.1-4040, ::1-4040, ::1, testfoo-lla.com-4040

if no port is given the default server-port is used, this is possible for some methods
if the url ends with - and a number (only true for very, very rare local networks), port must be specified with -

# scn
This is a rewrite of scn.
It got too complex because of unnecessary features (channels and specialized nodes), too much lowlevel work (an own protocol), focus on gui and a client and serverside account management.


