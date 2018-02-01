#!/usr/bin/python

# There's a file here (chlng6-gile).
# It's been base64'd after being encrypted with repeating-key XOR.
# Decrypt it. Here's how:

# 1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.

# 2. Write a function to compute the edit distance/Hamming distance between two strings.
# The Hamming distance is just the number of differing bits. The distance between:
# this is a test
# and
# wokka wokka!!!
# is 37. Make sure your code agrees before you proceed.
str1 = "this is a test"
str2 = "wokka wokka!!!"

def hamming_distance(str1, str2):
    return_values = list()
    str1_ascii = str1.encode("hex")
    str2_ascii = str2.encode("hex")
    # str1_ascii_bin = bin(int(str1_ascii, 16))
    # str2_ascii_bin = bin(int(str2_ascii, 16))
    # str1_ascii_bin = str1_ascii_bin[2:]
    # if len(str1_ascii_bin) % 2 != 0:
    #     str1_ascii_bin = '0'+str1_ascii_bin
    # str2_ascii_bin = str2_ascii_bin[2:]
    # if len(str2_ascii_bin) % 2 != 0:
    #     str2_ascii_bin = '0'+str2_ascii_bin
    # return_values.append(str1_ascii_bin)
    # return_values.append(str2_ascii_bin)

    xor = ''.join(hex(int(a, 16) ^ int(b, 16))[2:] for a, b in zip(str1_ascii, str2_ascii))
    xor_bin = bin(int(xor, 16))
    xor_bin = xor_bin[2:]
    distance = xor_bin.count('1')
    return distance

print hamming_distance(str1, str2)