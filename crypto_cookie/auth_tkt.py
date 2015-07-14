"""Cookie implementation based on Paste's AuthTicket for crypto-cookie package
"""
__author__ = "@philipkershaw"
__date__ = "09/07/15"
__copyright__ = "(C) 2015 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
from urllib import unquote as url_unquote

from paste.auth.auth_tkt import AuthTicket, BadTicket

from .encoding import Encoder

    
class SecureCookie(AuthTicket):
    '''Use custom cookie implementation for AuthKit to enable compatibility
    with CEDA site services dj_security which uses Paste's AuthTicket
    '''

    def digest(self):
        '''Don't calculate a digest because this is done as an independent step
        following encryption of the cookie
        '''
        return ''
    
    @classmethod
    def parse_ticket(cls, secret, ticket, ip, session):
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

        decrypted_ticket = Encoder().decode_msg(ticket, secret)
        
        try:
            timestamp = int(decrypted_ticket[:8], 16)
            
        except ValueError as e:
            raise BadTicket('Timestamp is not a hex integer: %s' % e)
            
        try:
            userid, data = decrypted_ticket[8:].split('!', 1)
            
        except ValueError:
            raise BadTicket('userid is not followed by !')
        
        userid = url_unquote(userid)
        if '!' in data:
            tokens, user_data = data.split('!', 1)
        else:
            # @@: Is this the right order?
            tokens = ''
            user_data = data
    
        tokens = tokens.split(',')
    
        return timestamp, userid, tokens, user_data
    
    def cookie_value(self):
        """Extend cookie_value method to enable encryption, encoding and signing 
        of encrypted cipher text
        
        :return: signed and encrypted cookie encoded as hexadecimal string
        """
        cookie_val = super(SecureCookie, self).cookie_value()
        
        encoded_cookie_val = Encoder().encode_msg(cookie_val, self.secret)
        
        return encoded_cookie_val
