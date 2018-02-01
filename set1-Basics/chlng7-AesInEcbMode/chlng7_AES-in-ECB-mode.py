#!/usr/bin/python

# The Base64-encoded content in chlng7_file has been encrypted via AES-128 in ECB mode under the key "YELLOW SUBMARINE".
# (case-sensitive, without the quotes; exactly 16 characters;
# I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
#
# Decrypt it. You know the key, after all.
#
# Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
#
# Do this with code.
# You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB
# working in code for a reason. You'll need it a lot later on, and not just for attacking ECB.

from Crypto.Cipher import AES
import base64

obj = AES.new('YELLOW SUBMARINE', AES.MODE_ECB)


def file_base64_to_hex(file):
    # remove file from previous execution of script (catch the exception and continue if no such file exists)
    try:
        os.remove("chlng7_file_hex_encrypted")
    except Exception:
        pass
    # first create a new file to write the hex encoded (encrypted) file and then open the base64 encoded file
    hex_file = open("chlng7_file_hex_encrypted", "a")
    base64_file = open(file, "r").read()
    for base64_ciphertext in base64_file.split('\n'):
        hex_file.write(base64_to_hex(base64_ciphertext))
    return hex_file


def base64_to_hex(base64_str):
    # encode the base64 string into an ascii string
    ascii_str = base64.b64decode(base64_str)
    # convert every 2 hex digits into an ascii character
    # ascii_str = ''.join(chr(int(hex_str[i:i+2], 16)) for i in range(0, len(hex_str), 2))
    hex_str = "".join("{:02x}".format(ord(c)) for c in ascii_str)
    # return the base64 string
    return hex_str

file_base64_to_hex("chlng7_file")
hex_file = open("chlng7_file_hex_encrypted", "r").read()
for ciphertext in hex_file.split('\n'):
    print ciphertext
    plaintext = obj.decrypt(ciphertext)
    s = unicode(plaintext).encode('hex')
    print s
