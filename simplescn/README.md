Simple, secure, with plugins enhanceable, communication platform.
This includes the management of dynamic ips and ports
Just register your clients with their own new generated keys
Nodes are not permanent, a restart deletes the entries on the server

Features:
* passwordprotection
* entirely controllable by a webbrowser (frontend not finished)

Dependencies:
* python-cryptography (python3 version) (pip: cryptography)
* python-gobject (python3 version) (pip: PyGObject???)
* gtk3
* python3

Security:

Man in the middle attacks are possible if:
* attacker knows the password or no password is set
* and the client has no hash of the public cert of the communication partner
* or the certificate is hacked (obvious)
As worse it sounds it is an unavoidable risk. Even OTR suffers from these problems.
Its nature lies in the decentral structure.
This means the user has to verify (server) hashes. This is not hard and is assisted by a friendlist and scn servers, which both use is strongly recommended.
In contrast to similar solutions it is up to the user putting certificates into the friendlist.



This is a rewrite of scn.
It got too complex because of unnecessary features (channels and nodes), too much lowlevel work (an own protocol), focus on gui and a client and serverside account management.


