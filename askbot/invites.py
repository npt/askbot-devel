import urllib

from django.conf import settings

from cryptography import fernet

def _get_fernet_key():
    """Returns 'a URL-safe base64-encoded 32-byte key' based on settings.SECRET_KEY"""
    import base64
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.hmac import HMAC
    from cryptography.hazmat.primitives.hashes import SHA256

    hmac = HMAC(settings.SECRET_KEY, SHA256(), backend=default_backend())
    hmac.update('askbot.invites')
    bin_key = hmac.finalize()
    return base64.urlsafe_b64encode(bin_key)

fernet_instance = fernet.Fernet(_get_fernet_key())


class TokenError(Exception):
    pass

def invite_to_token(username, email):
    plain_token = 'invite1;%s;%s' % (urllib.quote(username), urllib.quote(email))
    return fernet_instance.encrypt(plain_token)

def token_to_invite(token):
    if isinstance(token, unicode):
        token = str(token)
    try:
        plain_token = fernet_instance.decrypt(token)
    except fernet.InvalidToken as ex:
        raise TokenError(*ex.args)
    parts = plain_token.split(';')
    if parts and parts[0] == 'invite1' and len(parts) == 3:
        username = urllib.unquote(parts[1])
        email = urllib.unquote(parts[2])
        return username, email
    else:
        raise TokenError("invalid token plaintext: %r" % plain_token)


if __name__ == '__main__':
    import sys
    if len(sys.argv) == 3:
        user, email = sys.argv[1:]
        print invite_to_token(user, email)
    elif len(sys.argv) == 2:
        user, email = token_to_invite(sys.argv[1])
        print user
        print email
