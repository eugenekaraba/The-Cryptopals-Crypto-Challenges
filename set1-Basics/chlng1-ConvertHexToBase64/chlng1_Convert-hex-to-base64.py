#!/usr/bin/python

# convert hex to base64
#
# the string:
# 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
#
# should produce:
# SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

import sys

# the hex string is the 1st argument on the command line
hex_str = sys.argv[1]

# convert every 2 hex digits into an ascii character
ascii_str = ''.join(chr(int(hex_str[i:i+2], 16)) for i in range(0, len(hex_str), 2))

# encode the ascii string into a base64 string
base64_str = ascii_str.encode('base64', 'strict')

# print the base64 string
sys.stdout.write(base64_str)
