#!/usr/bin/python

# convert base64 to hex
#
# the string: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
# 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
#
# should produce: 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

import sys
import base64

# the hex string is the 1st argument on the command line
base64_str = sys.argv[1]

# encode the base64 string into an ascii string
ascii_str = base64.b64decode(base64_str)

# convert every 2 hex digits into an ascii character
# ascii_str = ''.join(chr(int(hex_str[i:i+2], 16)) for i in range(0, len(hex_str), 2))
hex_str = "".join("{:02x}".format(ord(c)) for c in ascii_str)



# print the base64 string
sys.stdout.write(hex_str)
