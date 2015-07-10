"""Encryption module for crypto-cookie package
"""
__author__ = "@philipkershaw"
__date__ = "09/07/15"
__copyright__ = "(C) 2015 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class Encryption(object):
    '''Class for handling encryption and decryption.  It uses symmetric key
    method'''
    DEFAULT_MODE = modes.CBC
    DEFAULT_ALGORITHM = algorithms.AES
    DEFAULT_IV_LEN = 16
    DEFAULT_PADDING_CHAR = ' '
    DEFAULT_MSG_SIZE_FACTOR = 8
    
    def __init__(self, 
                 algorithm=DEFAULT_ALGORITHM, 
                 mode=DEFAULT_MODE,
                 iv_len=DEFAULT_IV_LEN,
                 padding_char=DEFAULT_PADDING_CHAR,
                 msg_size_factor=DEFAULT_MSG_SIZE_FACTOR):
        '''Set hash algorithm and encoding method'''
        self.algorithm = algorithm
        self.mode = mode
        self.iv_len = iv_len
        self.padding_char = padding_char
        self.msg_size_factor = msg_size_factor
        
    def encrypt(self, msg, key):
        backend = default_backend()
        iv = os.urandom(self.iv_len)

        encryption_cipher = Cipher(self.algorithm(key), self.mode(iv), 
                                   backend=backend)
        encryptor = encryption_cipher.encryptor()
                
        # Ensure length is an even multiple of 8
        if self.padding_char or self.msg_size_factor:
            n_padding_chars = len(msg) % self.msg_size_factor
            padded_msg = msg + self.padding_char * n_padding_chars
        else:
            padded_msg = msg
            
        cipher_text = encryptor.update(padded_msg) + encryptor.finalize()

        return cipher_text, iv

    def decrypt(self, cipher_text, key, iv):
        backend = default_backend()

        decryption_cipher = Cipher(self.algorithm(key), self.mode(iv), 
                                   backend=backend)
        decryptor = decryption_cipher.decryptor()
        padded_decrypted_msg = decryptor.update(cipher_text) + \
                                                        decryptor.finalize()
        decrypted_msg = padded_decrypted_msg.rstrip(self.padding_char)
        
        
        return decrypted_msg