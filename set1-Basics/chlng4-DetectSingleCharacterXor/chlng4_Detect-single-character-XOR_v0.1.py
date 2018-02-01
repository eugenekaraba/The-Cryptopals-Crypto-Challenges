#!/usr/bin/python

# One of the 60-character strings in file chlng4_file has been encrypted by single-character XOR.
#
# Find it.
#
# (Your code from chlng3_Single-byte-XOR-cipher.py should help.)

import string

words = ["the", "be", "to", "of", "and", "a", "in", "that", "have", "I", "it", "for", "not", "on", "with", "as", "you",
         "do", "at", "this", "but", "his", "by", "from", "they", "we", "say", "her", "she", "or", "an", "will", "my",
         "one", "all", "would", "there", "their", "what", "so", "up", "out", "if", "about", "who", "get", "which", "go",
         "me", "when", "make", "can", "like", "time", "no", "just", "him", "know", "take", "people", "into", "year",
         "your", "good", "some", "could", "them", "see", "other", "than", "then", "now", "look", "only", "come", "its",
         "over", "think", "also", "back", "after", "use", "two", "how", "our", "work", "first", "well"]

def decrypt(target, key_index, case):
    scores = [24, 7, 15, 17, 26, 11, 10, 19, 22, 4, 5, 16, 13, 21, 23, 8, 2, 18, 20, 25, 14, 6, 12, 3, 9, 1]

    # variables for the maximum score and the best candidate letter
    cur_max = 0
    best = 0

    # list of tuples with scores and candidate
    tuples = list()

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
        tuples.append(tuple((candidate, cur_sum)))
        # if cur_sum > cur_max:
        #     cur_max = cur_sum
        #     best = candidate
        # tuples.append(tuple((best, cur_max)))

    tuples = sorted(tuples, key=lambda x: x[1], reverse=True)

    # calculate the plaintext for the best candidate
    ascii_best = tuples[key_index][0].encode("hex")
    result_best = ''.join(hex(int(a, 16) ^ int(b, 16))[2:] for a, b in zip(target, (len(target)/2)*ascii_best))
    ascii_str_best = ''.join(chr(int(result_best[i:i + 2], 16)) for i in range(0, len(result_best), 2))

    if case == "low":
        return ascii_str_best, tuples[key_index][0]

    # calculate the plaintext for the best candidate's uppercase counterpart
    best = tuples[key_index][0].upper()
    ascii_best = best.encode("hex")
    result_best = ''.join(hex(int(a, 16) ^ int(b, 16))[2:] for a, b in zip(target, (len(target)/2)*ascii_best))
    ascii_str_best = ''.join(chr(int(result_best[i:i + 2], 16)) for i in range(0, len(result_best), 2))

    if case == "upper":
        return ascii_str_best, tuples[key_index][0].upper()


    # print tuples

# print decrypt("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", 1, "upper")

f = open("chlng4_file", "r").read()
#print f.split('\n')
for word in words:
    for ciphertext in f.split('\n'):
        for key_index in range (1, 27):
            if decrypt(ciphertext, key_index, "low")[0].find(word) != -1:
                if all(c in string.printable for c in decrypt(ciphertext, key_index, "low")[0]):
                    print ciphertext, key_index, "low"
                    print decrypt(ciphertext, key_index, "low")[0]
        for key_index in range (1, 27):
            if decrypt(ciphertext, key_index, "upper")[0].find(word) != -1:
                if all(c in string.printable for c in decrypt(ciphertext, key_index, "upper")[0]):
                    print ciphertext, key_index, "upper"
                    print decrypt(ciphertext, key_index, "upper")[0]


# to do : use all(ord(char) < 128 for char in 'string') to check if all characters of plaintext are in the ascii range