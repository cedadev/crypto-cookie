"""Encoding module for crypto-cookie package
"""
from pip._vendor.urllib3.util.request import ACCEPT_ENCODING
from types import FunctionType
__author__ = "@philipkershaw"
__date__ = "09/07/15"
__copyright__ = "(C) 2015 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
from .encryption import Encryption
from .signature import Signature


class Encoder(object):
    '''Class to encrypt, sign and encode messages and handle the equivalent
    signature verification and decryption.  Uses symmetric key encryption
    (AES) and HMAC signature.
    '''
    DEFAULT_ENCODING = {
        'encode': lambda bytes_: getattr(bytes_, 'hex')(), 
        'decode': lambda bytes_: bytes.fromhex(bytes_.decode('utf-8'))
    }
    DEFAULT_DELIMITER = b"-"
    
    def __init__(self, encoding=DEFAULT_ENCODING, delimiter=DEFAULT_DELIMITER,
                 signature_kw=None, encryption_kw=None):
        '''Set encoding method'''
        self._encoding = None
        self.encoding = encoding
        
        if signature_kw is None:
            signature_kw = {}

        self.signature = Signature(**signature_kw)
        
        if encryption_kw is None:
            encryption_kw = {}
            
        self.encryption = Encryption(**encryption_kw)
        
        self._delimiter = None
        self.delimiter = delimiter
      
    @property
    def delimiter(self):
        return self._delimiter
    
    @delimiter.setter
    def delimiter(self, value):
        if not isinstance(value, bytes):
            raise TypeError('Expecting byte type for delimiter; got {!r} '
                            'type'.format(value))
        
        self._delimiter = value
        
    @property
    def encoding(self):
        return self._encoding.copy()
    
    @encoding.setter
    def encoding(self, value):
        if not isinstance(value, dict):
            raise TypeError('Expecting dict type for encoding')
        
        if 'encode' not in value or 'decode' not in value:
            raise ValueError('Expecting "encode" and "decode" keys in '
                             'encodings dict')
        
        if not callable(value['encode']):
            raise TypeError('Expecting callable for encoding["encode"]')
         
        if not callable(value['decode']):
            raise TypeError('Expecting callable for encoding["decode"]')
               
        self._encoding = value
        
    def encode_msg(self, msg, key):
        '''Encrypt message, encode it, sign it and concatenate encoded cipher
        text, encoded initialisation vector and signature
        '''
        cipher_text, iv = self.encryption.encrypt(msg, key)
        
        # Nb. encoded message is stripped to allow for base 64 encoding where
        # an in this case unwanted new line character is added.  Decoding is
        # not affected by this change
        encoded_cipher_text = self.encoding['encode'](cipher_text).strip()
        b_encoded_cipher_text = encoded_cipher_text.encode('utf-8')
        
        encoded_iv = self.encoding['encode'](iv).strip()
        b_encoded_iv = encoded_iv.encode('utf-8')
        
        digest = self.signature.sign(b_encoded_cipher_text, key)
        
        encoded_digest = self.encoding['encode'](digest).strip()
        b_encoded_digest = encoded_digest.encode('utf-8')
        
        encoded_msg = self.delimiter.join([b_encoded_cipher_text, 
                                           b_encoded_iv,
                                           b_encoded_digest])
        
        return encoded_msg
        
    def decode_msg(self, encoded_msg, key):
        '''Decode message, check signature and decrypt'''
        encoded_cipher_text, encoded_iv, encoded_digest = encoded_msg.split(
                                                                self.delimiter)
        
        cipher_text = self.encoding['decode'](encoded_cipher_text)
        iv = self.encoding['decode'](encoded_iv)
        digest = self.encoding['decode'](encoded_digest)
        
        self.signature.verify_signature(encoded_cipher_text, digest, key)
        
        msg = self.encryption.decrypt(cipher_text, key, iv)
        
        return msg