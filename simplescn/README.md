Simple, secure, with plugins enhanceable, communication platform.
This includes the management of dynamic ips and ports
Just register your clients with their own new generated keys
Nodes are not permanent, a restart deletes the entries on the server

Features:
* passwordprotection
* semi-decentral + encrypted
* simple portmapper, easy to integrate in other applications
* entirely controllable by a webbrowser (frontend not finished)

Dependencies:
* python-cryptography (python3 version) (pip: cryptography)
* python3
* optional: pygobject/python-gobject (python3 version) (pip impossible)(for gui)
* optional: markdown (pip: markdown)(for more beautiful help)

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

# Installation
Requirements: working python and setuptools, pip

python3 setup.py install
or
python3 setup.py install --user

# Usage:

gui-client (falls back to cmd client when no gui is found):
simplescns client parameters...

cmd-client:
simplescns rawclient parameters...

client without a command line interface:
simplescns rawclient nocmd=True parameters...
or
simplescns rawclient nocmd parameters...

server:
simplescns server

# Installation
## without installation, execute from repo
python3 ./simplescn parameters...


## pip

# windows extra (for gui)
install python3.4:

download pygi-slimgtk... from http://sourceforge.net/projects/pygobjectwin32/files/ and extract

use 3.4 version if slimgtk is not updated to python3.5
# normal routine

python -m pip [https://github.com/devkral/simplescn](https://github.com/devkral/simplescn)&#91;features comma seperated&#93;

or

python -m pip path-to-local-simplescn-repo&#91;features comma seperated&#93;

&#91;features comma seperated&#93; = e.g. &#91;gtkgui, mdhelp&#93;
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


