Crypto-Cookie
=============
Package to encrypt and sign cookie content.  Before using make sure you really
need to secure cookie content: if at all possible any information should be
held server-side, the cookie merely acting as a handle to this information.  If
you really do need to hold actual content in the cookie then this package may be
able to help.

Releases
--------
 * 0.2.0: altered to disable Paste AuthTicket's signature since the derived
   implementation signs the cookie separately following encryption
 * 0.1.0: initial release