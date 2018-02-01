#!/usr/bin/python

# The hex encoded string:
#
# 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
# ... has been XOR'd against a single character. Find the key, decrypt the message.
#
# You can do this by hand. But don't: write code to do it for you.
#
# How? Devise some method for "scoring" a piece of English plaintext.
# Character frequency is a good metric. Evaluate each output and choose the one with the best score.

import string

target = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

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
    result = ''.join(hex(int(a, 16) ^ int(b, 16))[2:] for a, b in zip(target, (len(target)/2)*ascii))
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
result_best = ''.join(hex(int(a, 16) ^ int(b, 16))[2:] for a, b in zip(target, (len(target)/2)*ascii_best))
ascii_str_best = ''.join(chr(int(result_best[i:i + 2], 16)) for i in range(0, len(result_best), 2))

print "Does the phrase \"", ascii_str_best, "\" make sense to you?. If it does then the key is letter ", best

# calculate the plaintext for the best candidate's uppercase counterpart
best = best.upper()
ascii_best = best.encode("hex")
result_best = ''.join(hex(int(a, 16) ^ int(b, 16))[2:] for a, b in zip(target, (len(target)/2)*ascii_best))
ascii_str_best = ''.join(chr(int(result_best[i:i + 2], 16)) for i in range(0, len(result_best), 2))

print "Does the phrase \"", ascii_str_best, "\" make sense to you?. If it does then the key is letter ", best.upper()
