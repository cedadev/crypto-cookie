#!/usr/bin/env python


import unittest
import os
import logging
import hmac
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from crypto_cookie.encoding import Encoder
from crypto_cookie.auth_tkt import SecureCookie

log = logging.getLogger(__name__)


class EncryptionAndSignatureTestCase(unittest.TestCase):
                
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


class EncoderTestCase(unittest.TestCase):        
    def test01_encode_and_decode_msg(self):
        key = os.urandom(32)
        encoded_msg = Encoder.encode_msg(b'a secret message', key)
        
        log.info('encoded message: %r', encoded_msg)
        
        msg = Encoder.decode_msg(encoded_msg, key)
        
        log.info('decoded message: %r', msg)
        

class SecureCookieTestCase(unittest.TestCase):
    def test01_create_cookie(self):
        secret = os.urandom(32)
        
        cookie = SecureCookie(secret, 'pjk', '127.0.0.1')
        cookie_val = cookie.cookie_value()
        
        log.info('Cookie value: %r', cookie_val)
        
    def test02_check_cookie(self):
        secret = os.urandom(32)
        
        cookie = SecureCookie(secret, 'pjk', '127.0.0.1')
        cookie_val = cookie.cookie_value()

        session = {
            'authkit.cookie.user': None,
            'authkit.cookie.user_data': None
        }
        
        ticket = SecureCookie.parse_ticket(secret, cookie_val, '127.0.0.1', 
                                           session)
        
        log.info('ticket: %r', ticket)
        
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
