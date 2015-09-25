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


This is a rewrite of scn.
It got too complex because of unnecessary features (channels and nodes), too much lowlevel work (an own protocol), focus on gui and a client and serverside account management.


