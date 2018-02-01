#!/usr/bin/python

# There's a file here (chlng6-gile).
# It's been base64'd after being encrypted with repeating-key XOR.
# Decrypt it. Here's how:

# imports
from __future__ import division
import base64
import os
import textwrap
import string


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
    str1_ascii = str1.encode("hex")
    str2_ascii = str2.encode("hex")
    # xor the 2 strings
    xor_hex = ''.join(hex(int(a, 16) ^ int(b, 16))[2:] for a, b in zip(str1_ascii, str2_ascii))
    xor_bin = bin(int(xor_hex, 16))
    # remove the preceding 0b of the binary representation
    xor_bin = xor_bin[2:]
    # count the occurrences of 1 in the XORed value
    distance = xor_bin.count('1')
    return distance


# 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes,
# and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
# 4. The KEYSIZE with the smallest normalized edit distance is probably the key.
# You could proceed perhaps with the smallest 2-3 KEYSIZE values.
# Or take 4 KEYSIZE blocks instead of 2 and average the distances.
def possible_keysizes(file):
    keysize_length_candidates = list()
    # remove file from previous execution of script (catch the exception and continue if no such file exists)
    try:
        os.remove("chlng6_file_hex_encrypted")
    except Exception:
        pass
    # first create a new file to write the hex encoded (encrypted) file and then open the base64 encoded file
    hex_file = open("chlng6_file_hex_encrypted", "a")
    base64_file = open(file, "r").read()
    for base64_ciphertext in base64_file.split('\n'):
        hex_file.write(base64_to_hex(base64_ciphertext))
        # comment out the append of new lines because it might be the
        # case that a KEYSIZE is greater than the line length
        # hex_file.write("\n")
    # try KEYSIZE from 2 to 40 and store the 5 KEYSIZES with the minimum Hamming distance
    hex_ciphertext = open("chlng6_file_hex_encrypted", "r").read()
    for keysize in range(4, 81, 2):
        distance = 0
        if int(len(hex_ciphertext)/keysize) % 2 != 1:
            blocks = int(len(hex_ciphertext)/keysize)
        else:
            blocks = int(len(hex_ciphertext)/keysize)-1
        for n in range(0, int(blocks/2)-1):
            distance = distance + hamming_distance(hex_ciphertext[(n*keysize):((n+1)*keysize)],
                                                   hex_ciphertext[((n+1)*keysize):((n+2)*keysize)])
        distance = distance/int(blocks/2)
        keysize_length_candidates.append(tuple((int(keysize/2), distance/keysize)))
    keysize_length_candidates = sorted(keysize_length_candidates, key=lambda x: x[1])
    top_five = keysize_length_candidates[0:5]
    return top_five


def base64_to_hex(base64_str):
    # encode the base64 string into an ascii string
    ascii_str = base64.b64decode(base64_str)
    # convert every 2 hex digits into an ascii character
    # ascii_str = ''.join(chr(int(hex_str[i:i+2], 16)) for i in range(0, len(hex_str), 2))
    hex_str = "".join("{:02x}".format(ord(c)) for c in ascii_str)
    # return the base64 string
    return hex_str


def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))


def find_individual_key(target):
    # the frequency of the English alphabet letters starting from a to z.
    # A is the 3rd more frequent letter therefore it is weighted with 24 and so on.
    scores = [24, 7, 15, 17, 26, 11, 10, 19, 22, 4, 5, 16, 13, 21, 23, 8, 2, 18, 20, 25, 14, 6, 12, 3, 9, 1]

    # variables for the maximum score and the best candidate letter
    cur_max = 0
    best = 0

    # for each candidate letter in the alphabet do...
    for candidate in string.letters:

        # initialize the current sum
        cur_sum = 0

        # convert the character in ascii hex representation
        ascii = candidate.encode("hex")
        # xor the target with the ascii hex representation of the candidate letter
        result = ''.join(hex(int(a, 16) ^ int(b, 16))[2:] for a, b in zip(target, (len(target)//2)*ascii))
        # convert the result from integer to string by converting every 2 digits into a character
        ascii_str = ''.join(chr(int(result[i:i + 2], 16)) for i in range(0, len(result), 2))
        # lowercase the string in order to calculate the frequency of each letter
        ascii_str = ascii_str.lower()

        # calculate the frequency
        for character in ascii_str:
            if character in string.letters:
                cur_sum = cur_sum + scores[string.lowercase.index(character)]
            else:
                cur_sum = cur_sum + 0
        if cur_sum > cur_max:
            cur_max = cur_sum
            best = candidate

    # calculate the plaintext for the best candidate
    ascii_best = best.encode("hex")
    result_best = ''.join(hex(int(a, 16) ^ int(b, 16))[2:] for a, b in zip(target, (len(target)//2)*ascii_best))
    ascii_str_best = ''.join(chr(int(result_best[i:i + 2], 16)) for i in range(0, len(result_best), 2))

    return best

# 5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
def create_keysize_blocks(file, top_five, index):
    keysize_blocks_bytes = list()
    keysize = top_five[index][0]*2
    hex_ciphertext = open(file, "r").read()
    try:
        os.remove("chlng6_file_hex_encrypted_blocks")
    except Exception:
        pass
    hex_ciphertext_blocks = open("chlng6_file_hex_encrypted_blocks", "a")
    keysize_blocks = textwrap.wrap(hex_ciphertext, keysize)
    if len(keysize_blocks[-1]) < keysize:
        keysize_blocks = keysize_blocks[:-1]
    # create the ciphertext into a list of lists.
    # Each outer list is the line and each inner list are the hex characters

    for block in keysize_blocks:
        keysize_block_bytes = list(chunkstring(block, 2))
        keysize_blocks_bytes.append(keysize_block_bytes)
    # return keysize_blocks_bytes
    # transpose
    transposed_blocks = map(list, zip(*keysize_blocks_bytes))

    # I need a function to convert list to string
    for i in transposed_blocks:
        print find_individual_key(''.join(i))

    # return transposed_blocks
    #     for i in range(0, int(keysize/2)):
    #         transposed_blocks.insert(i, keysize_block_bytes)
    #         print i
    # return transposed_blocks
    # return keysize_block_bytes


create_keysize_blocks("chlng6_file_hex_encrypted", possible_keysizes("chlng6_file"), 0)


