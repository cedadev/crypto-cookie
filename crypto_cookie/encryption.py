'''
Created on 9 Jul 2015

@author: philipkershaw
'''
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class Encryption(object):
    '''Class for handling encryption and decryption.  It uses symmetric key
    method'''
    MODE = modes.CBC
    ALGORITHM = algorithms.AES
    INITIALISATION_VECTOR_LEN = 16
    
    @classmethod
    def encrypt(cls, msg, key):
        backend = default_backend()
        iv = os.urandom(cls.INITIALISATION_VECTOR_LEN)

        encryption_cipher = Cipher(cls.ALGORITHM(key), cls.MODE(iv), 
                                   backend=backend)
        encryptor = encryption_cipher.encryptor()
        cipher_text = encryptor.update(msg) + encryptor.finalize()

        return cipher_text, iv

    @classmethod
    def decrypt(cls, cipher_text, key, iv):
        backend = default_backend()

        decryption_cipher = Cipher(algorithms.AES(key), cls.MODE(iv), 
                                   backend=backend)
        decryptor = decryption_cipher.decryptor()
        decrypted_msg = decryptor.update(cipher_text) + decryptor.finalize()
        
        return decrypted_msg