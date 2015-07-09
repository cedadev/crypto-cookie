'''
Created on 9 Jul 2015

@author: philipkershaw
'''
from .encryption import Encryption
from .signature import Signature


class Encoder(object):
    '''Class to encrypt, sign and encode messages and handle the equivalent
    signature verification and decryption.  Uses symmetric key encryption
    (AES) and HMAC signature.
    '''
    
    @classmethod
    def encode_msg(cls, msg, key):
        cipher_text, iv = cls._encrypt(msg, key)
        
        encoded_cipher_text = cipher_text.encode('hex')
        
        digest = Signature.sign(encoded_cipher_text, key)
        
        delimiter = "-"
        encoded_msg = delimiter.join([encoded_cipher_text,
                                      iv.encode('hex'),
                                      digest])
        
        return encoded_msg
        
    @classmethod
    def decode_msg(cls, encoded_msg, key):
        delimiter = "-"
        encoded_cipher_text, encoded_iv, digest = encoded_msg.split(delimiter)
        
        cipher_text = encoded_cipher_text.decode('hex')
        iv = encoded_iv.decode('hex')
        
        Signature.verify_signature(encoded_cipher_text, digest, key)
        
        msg = Encryption.decrypt(cipher_text, key, iv)
        
        return msg