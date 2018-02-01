#!/usr/bin/python

# One of the 60-character strings in file chlng4_file has been encrypted by single-character XOR.
#
# Find it.
#
# (Your code from chlng3_Single-byte-XOR-cipher.py should help.)

import string
from collections import Counter

# the english letters and the space " " character in the order of their frequency in the english alphabet
# the assumption is that the space " " character has higher frequency over all the english letters
eng_freq = [' ', 'e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l', 'c', 'u',
            'm', 'w', 'f', 'g', 'y', 'p', 'b', 'v', 'k', 'j', 'x', 'q', 'z']


# this function returns the most frequent characters (bytes) of the ciphertext
# if n number of bytes have the same (highest) frequency it returns all n of them
def get_most_freq_cipher_chars(ciphertext):
    n = 2
    cipher_chars_list = [ciphertext[i:i+n] for i in range(0, len(ciphertext), n)]
    cipher_chars_freq = Counter(cipher_chars_list)
    most_freq_cipher_chars = [k for k, v in cipher_chars_freq.iteritems() if v == max(cipher_chars_freq.values())]
    return most_freq_cipher_chars


# this function takes the list of most frequent characters and XORs
# each one of them with the character indicated from eng_freq
def get_possible_keys(most_freq_cipher_chars, eng_freq_index):
    candidate_key_list = list()
    for char in most_freq_cipher_chars:
        candidate_char_plain = eng_freq[eng_freq_index].encode("hex")
        candidate_key = hex(int(char, 16) ^ int(candidate_char_plain, 16))
        candidate_key_list.append(candidate_key)
    return candidate_key_list


# this function calculates the possible plaintext list according to the proposed list of possible keys
def calculate_plaintexts(ciphertext, possible_keys):
    candidate_plaintext_list = list()
    for key in possible_keys:
        candidate_plaintext_hex = ''.join(hex(int(a, 16) ^ int(b, 16))[2:]
                                          for a, b in zip(ciphertext, (len(ciphertext) / 2) * key[2:]))
        candidate_plaintext_string = ''.join(chr(int(candidate_plaintext_hex[i:i + 2], 16))
                                             for i in range(0, len(candidate_plaintext_hex), 2))
        candidate_plaintext_list.append(candidate_plaintext_string)
    return candidate_plaintext_list


# this function filters the non printable characters plaintexts out and prints a "None" instead
def filter(plaintext):
    if all(c in string.printable for c in plaintext):
        return plaintext


# this function puts everything together in a nice format
def diagnostics(ciphertext, eng_freq_index):
    print "------------------------------------------------------------------------------------------------------------"
    print "ciphertext: ", ciphertext
    most_freq_chars = get_most_freq_cipher_chars(ciphertext)
    print "most common cipher characters (in hex)", get_most_freq_cipher_chars(ciphertext)
    print "analysis is performed for \"", eng_freq[eng_freq_index], "\" as the most frequent plaintext character"
    possible_keys = get_possible_keys(most_freq_chars, eng_freq_index)
    print "most possible keys: ", possible_keys
    print "possible plaintexts:"
    for plaintext in calculate_plaintexts(ciphertext, possible_keys):
        print filter(plaintext)
    print "------------------------------------------------------------------------------------------------------------"


f = open("chlng4_file", "r").read()
for ciphertext in f.split('\n'):
    diagnostics(ciphertext, 0)

# The code outputs lines in the form:
# ------------------------------------------------------------------------------------------------------------
# ciphertext:  3649211f210456051e290f1b4c584d0749220c280b2a50531f262901503e
# most common cipher characters (in hex) ['50', '49', '29', '1f', '21']
# analysis is performed for "   " as the most frequent plaintext character
# most possible keys:  ['0x70', '0x69', '0x9', '0x3f', '0x1']
# possible plaintexts:
# None
# _ HvHm?lw@fr%1$n KeAbC9:vO@h9W
# None
# None
# None
# ------------------------------------------------------------------------------------------------------------
#
# After iterating over the elements in the eng_freq you can find the readable plaintext by inspection of the output
