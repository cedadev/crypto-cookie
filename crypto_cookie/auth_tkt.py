"""Cookie implementation based on Paste's AuthTicket for crypto-cookie package
"""
__author__ = "@philipkershaw"
__date__ = "09/07/15"
__copyright__ = "(C) 2015 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import time as time_mod
from http.cookies import SimpleCookie
from urllib.parse import unquote as url_unquote
from urllib.parse import quote as url_quote
import base64

from .encoding import Encoder


class BadTicket(Exception):
    '''Invalid Cookie'''
    
      
class SecureCookie:
    '''Use custom cookie implementation for AuthKit to enable compatibility
    with CEDA site services dj_security which uses Paste's AuthTicket
    '''
    
    def __init__(self, secret, userid, ip, tokens=(), user_data='',
                 time=None, cookie_name='auth_tkt', **kwargs):
        '''Ensure compatibility with interface for 
        authkit.cookie.AuthKitTicket'''      
        self.secret = secret
        self.userid = userid
        self.ip = ip
        
        if not isinstance(tokens, str):
            tokens = ','.join(tokens)
            
        self.tokens = tokens
        self.user_data = user_data
        
        if time is None:
            self.time = time_mod.time()
        else:
            self.time = time
            
        self.cookie_name = cookie_name
            
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
        
        # Decode 
        decoded_ticket = base64.b64decode(ticket.encode('utf-8')).strip()
        isinstance(ticket, str)
        print(ticket)
        print(decoded_ticket)
        decrypted_ticket = Encoder().decode_msg(decoded_ticket, secret)
        b_decrypted_ticket = decrypted_ticket.decode('utf-8')
        
        try:
            timestamp = int(b_decrypted_ticket[:8], 16)
            
        except ValueError as e:
            raise BadTicket('Timestamp is not a hex integer: %s' % e)
            
        try:
            userid, data = b_decrypted_ticket[8:].split('!', 1)
            
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
        """Extend cookie_value method to enable encryption, encoding and 
        signing of encrypted cipher text
        
        :return: signed and encrypted cookie encoded as hexadecimal string
        """
        cookie_val = '%s%08x%s!' % (self.digest(), int(self.time), 
                                    url_quote(self.userid))
        if self.tokens:
            cookie_val += self.tokens + '!'
            
        cookie_val += self.user_data
       
        encoded_cookie_val = Encoder().encode_msg(cookie_val.encode('utf-8'), 
                                                  self.secret.encode('utf-8'))
#         encoded_cookie_val = Encoder().encode_msg(cookie_val.encode('ascii'), 
#                                                   self.secret.encode('ascii'))
       
        return encoded_cookie_val

    def cookie(self):
        c = SimpleCookie()
        cookie_val = self.cookie_value()
        enc_cookie_val = base64.b64encode(cookie_val).strip()
        c[self.cookie_name] = enc_cookie_val.decode('utf-8')
        c[self.cookie_name]['path'] = '/'

        return c
