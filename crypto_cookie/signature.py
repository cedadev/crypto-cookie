"""Signature module for crypto-cookie package
"""
__author__ = "@philipkershaw"
__date__ = "09/07/15"
__copyright__ = "(C) 2015 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import hmac
import hashlib


class VerificationError(Exception):
    """Raise if signature verification failed"""
    
    
class Signature(object):
    """Class for handling HMAC signature of messages"""
    HASH_ALGORITHM = hashlib.sha256
    
    @classmethod
    def sign(cls, msg, key):
        """Calculate digest for input message using the given key"""
        signature = hmac.new(key, msg, cls.HASH_ALGORITHM)
        digest = signature.hexdigest()

        return digest

    @classmethod
    def verify_signature(cls, msg, digest, key):
        """Verify digest for input message"""
        calculated_digest = cls.sign(msg, key)
        
        if calculated_digest != digest:
            raise VerificationError("Signature verification failed: "
                                    "the calculated digest (%r) doesn't "
                                    "match the input value %r" % 
                                    (calculated_digest, digest))