'''
Created on 9 Jul 2015

@author: philipkershaw
'''
import hashlib
from paste.auth.auth_tkt import AuthTicket, BadTicket, parse_ticket

DEFAULT_DIGEST = hashlib.sha256


class SecureCookie(AuthTicket):
    '''Use custom cookie implementation for AuthKit to enable compatibility
    with CEDA site services dj_security which uses Paste's AuthTicket
    '''
    
    @classmethod
    def parse_ticket(cls, secret, ticket, ip, session, decrypt=True):
        '''Parse cookie and check its signature.
        
        :var secret: shared secret used between multiple trusted peers to 
        verify signature of cookie
        :var ticket: signed cookie content
        :var ip: originating client IP address - extracted from X Forwarded
        or Remote address iterms in HTTP header
        :var session: AuthKit session object content
        :return: tuple of parsed cookie content
        '''
        if session is not None:
            if not session.has_key('authkit.cookie.user'):
                raise BadTicket('No authkit.cookie.user key exists in the '
                                'session')
            if not session.has_key('authkit.cookie.user_data'):
                raise BadTicket('No authkit.cookie.user_data key exists in the '
                                'session')

        if decrypt:
            # Decrypt content
            ticket_ = cls._decrypt(secret, ticket)
        else:
            ticket_ = ticket
               
        return parse_ticket(secret, ticket_, ip, digest_algo=DEFAULT_DIGEST)
        
    @classmethod
    def _decrypt(cls, secret, encrypted_ticket):
        """Decrypt cookie"""
