#!/usr/bin/python

# Write a function that takes two equal-length buffers and produces their XOR combination.
# If your function works properly, then when you feed it the string:
# 1c0111001f010100061a024b53535009181c
# ... after hex decoding, and when XOR'd against:
# 686974207468652062756c6c277320657965
# ... should produce:
# 746865206b696420646f6e277420706c6179

import sys

# the hex strings are the 1st and 2nd arguments on the command line
hex_str_1 = sys.argv[1]
hex_str_2 = sys.argv[2]

# important function: zip
# This function returns a list of tuples, where the i-th tuple contains the
# i-th element from each of the argument sequences or iterables.

# for each 2 digit tuple (with each digit being taken from the 2 input strings),
# turn the digits into hexadecimal integer and xor them
# turn the result into hex and append it to the rest of the digits
result = ''.join(hex(int(a, 16) ^ int(b, 16))[2:] for a, b in zip(hex_str_1, hex_str_2))

# 2 ways to print out the result
# I prefer stdout
# print result
sys.stdout.write(result)
