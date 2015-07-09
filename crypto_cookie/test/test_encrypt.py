#!/usr/bin/env python


import unittest
import os
import logging
import hmac
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from ..encoding import Encoding

log = logging.getLogger(__name__)


class CookieEncryptTestCase(unittest.TestCase):
                
    def test01_encrypt_and_decrypt(self):
        backend = default_backend()
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(b"a secret message") + encryptor.finalize()
        decryptor = cipher.decryptor()
        log.info("test01_encrypt_and_decrypt: %r", 
                 decryptor.update(ct) + decryptor.finalize())
 
    def test02_encrypt_and_decrypt(self):
        backend = default_backend()
        key = os.urandom(32)
        iv = os.urandom(16)

        encryption_cipher = Cipher(algorithms.AES(key), modes.CBC(iv), 
                                   backend=backend)
        encryptor = encryption_cipher.encryptor()
        ct = encryptor.update(b"a secret message") + encryptor.finalize()

        decryption_cipher = Cipher(algorithms.AES(key), modes.CBC(iv), 
                                   backend=backend)
        decryptor = decryption_cipher.decryptor()
        log.info("test02_encrypt_and_decrypt: %r", 
                 decryptor.update(ct) + decryptor.finalize())

    def test03_hmac_digest(self):
        key = os.urandom(32)
        
        signature = hmac.new(key, b"a secret message", hashlib.sha256)
        digest = signature.hexdigest()
        log.info("Digest is %r", digest)
        
    def test04_encode_and_decode_msg(self):
        key = os.urandom(32)
        encoded_msg = Encoding.encode_msg(b'a secret message', key)
        
        log.info('encoded message: %r', encoded_msg)
        
        msg = Encoding.decode_msg(encoded_msg, key)
        
        log.info('decoded message: %r', msg)
        

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
