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


import base64
import os
import numpy

key = "YELLOW SUBMARINE"


# This function receives a base64 encoded string and returns the equivalent hex encoded string
def base64_to_hex(base64_str):
    # encode the base64 string into an ascii string
    ascii_str = base64.b64decode(base64_str)
    # convert every 2 hex digits into an ascii character
    # ascii_str = ''.join(chr(int(hex_str[i:i+2], 16)) for i in range(0, len(hex_str), 2))
    hex_str = "".join("{:02x}".format(ord(c)) for c in ascii_str)
    # return the base64 string
    return hex_str


# This function turns a Base64 encoded file to a hex encoded one.
# It receives 2 arguments, a file (from_file) in Base64 encoding and the
# name of the hex file (to_file) that is about to create
def file_base64_to_hex(from_file, to_file):
    # remove to_file from previous execution of script (catch the exception and continue if no such file exists)
    try:
        os.remove(to_file)
    except Exception:
        pass
    # first create a new file to write the hex encoded (encrypted) file and then open the base64 encoded file
    hex_file = open(to_file, "a")
    base64_file = open(from_file, "r").read()
    for base64_ciphertext in base64_file.split('\n'):
        hex_file.write(base64_to_hex(base64_ciphertext))


# This function returns a generator, using a generator comprehension.
# The generator returns the string sliced, from 0 + a multiple of the length of the chunks,
# to the length of the chunks + a multiple of the length of the chunks.

# You can iterate over the generator like a list,
# tuple or string - for i in chunkstring(s,n): , or convert it into a list (for instance) with list(generator).
# https://stackoverflow.com/questions/18854620/
# whats-the-best-way-to-split-a-string-into-fixed-length-chunks-and-work-with-the
def chunkstring(string, length):
    return (string[0 + i:length + i] for i in range(0, len(string), length))


# This function breaks the hex encoded ciphertext file into 128 bits blocks (16 bytes or 32 hex characters).
# For this challenge we know that we do not need padding because the hex ciphertext is divided by 16 (bytes).
# After that function, the ciphertext is in a form suitable to apply the AES cycles.
def file_hex_to_blocks(from_file, to_file):
    # remove to_file from previous execution of script (catch the exception and continue if no such file exists)
    try:
        os.remove(to_file)
    except Exception:
        pass
    # first create a new file to write the hex encoded (encrypted) file and then open the base64 encoded file
    blocks_file = open(to_file, "a")
    hex_file = open(from_file, "r").read()
    for i in list(chunkstring(hex_file, 32)):
        blocks_file.write(i)
        blocks_file.write("\n")


# Byte Substitution Layer for encryption. Receives a byte (one character) as an argument and returns the
# corresponding byte from the sbox
def byte_substitution_enc(byte):
    sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    return sbox[byte]


# Byte Substitution Layer for decryption. Receives a byte (one character) as an argument and returns the
# corresponding byte from the sboxInv (inverse sbox)
def byte_substitution_dec(byte):
    sboxInv = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]
    return sboxInv[byte]

# This function rotates the elements of a list
def rotate(l, n):
    return l[n:] + l[:n]

# returns a string splitted in substrings of fixed length
def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))


# This function operates on a string of 128 bits.
# It receives the block as argument and returns the
# def file_byte_substitution_dec(block):


# Expansion Key function. Takes as argument the initial key and delivers a table of 11 keys.
# These 11 keys are used from 0 till 10 (in this order) fro the encryption and from 10 till 0 fro decryption
def key_expansion(init_key_str):
    Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    init_key = ''.join(char.encode('hex_codec') for char in init_key_str)
    # there is an aes 128 expanded key example in this reference for verification of the code
    # http://openschemes.com/2010/03/03/fun-with-aes-128-example-encryption-with-aes-trainer/
    # use the init_key = "000102030405060708090a0b0c0d0e0f" to see that it works
    # init_key = "000102030405060708090a0b0c0d0e0f"

    # the keys_enc list is the list with the 11 keys_enc that will be used to the 11 rounds
    keys_enc = list()
    # the 1st key of the keys_enc list is the
    keys_enc.append(init_key)

    # for 10 rounds do
    for round in range(0, 10):
        # 4th word of the previous round key = last 4 bytes of the previous round key
        fourth_word_of_previous_key = keys_enc[round][-8:]
        # the 4th word of the previous round key rotated
        rotated_fourth_word_of_previous_key = rotate(fourth_word_of_previous_key, 2)
        # the rotated 4th word of the previous round key substituted
        rotated_fourth_word_of_previous_key_substitution = list(map(lambda x:
                                                                    byte_substitution_enc(int(x, 16)),
                                                                    chunkstring(rotated_fourth_word_of_previous_key,2)))
        # the 1st word of the previous round key = first 4 bytes of previous round key
        first_word_of_previous_key = keys_enc[round][:8]
        # the Rcon string contains the Rcon elements in order
        # we pick the ones we need for each round by dividing with 10
        roundth_column_of_rcon = list()
        for position in range(0, len(Rcon)):
            if position % 10 == round:
                roundth_column_of_rcon.append(Rcon[position])

        # the buffer_round_key contains the word that is produced if we XOR
        # fourth_word_of_previous_key XOR rotated_fourth_word_of_previous_key_substitution XOR roundth_column_of_rcon
        buffer_round_key = list()
        for i in range(4):
            buffer_round_key.append(hex(rotated_fourth_word_of_previous_key_substitution[i] ^
                                        int(list(chunkstring(first_word_of_previous_key,2))[i], 16) ^
                                        roundth_column_of_rcon[i])[2:].zfill(2))

        # buffer_round_key is appended with the
        # previous_word_of_current_round_key XOR corresponding_word_of_previous_round_key
        for word in range(1,4):
            previous_word_of_current_round_key = buffer_round_key[-4:]
            for i in range(4):
                buffer_round_key.append(hex(int(previous_word_of_current_round_key[i], 16) ^
                                            int(list(chunkstring(keys_enc[round][(word * 8):(word * 8) + 8],2))[i], 16))[2:].zfill(2))

        keys_enc.append(''.join(char for char in buffer_round_key))
    # for key in keys_enc:
    #     print key
    return keys_enc

# ("chlng7_file", "hex_1")
# # hex_file = open("chlng7_file_hex_encrypted", "r").read()
# # for ciphertext in hex_file.split('\n'):
# #     print ciphertext
# file_hex_to_blocks("hex_1", "blocks_1")
#

def inverse_shift_rows(B):
    Binv = [B[0:2], B[26:28], B[20:22], B[14:16], B[8:10], B[2:4], B[28:30], B[22:24], B[16:18], B[10:12], B[4:6],
            B[30:32], B[24:26], B[18:20], B[12:14], B[6:8]]
    return ''.join(Binv)

def key_addition(ciphertext, key):
    return "".join(chr(ord(ciphertext_char) ^ ord(key_char))
                   for ciphertext_char, key_char in zip(ciphertext.decode("hex"), key.decode("hex"))).encode("hex")

def inverse_byte_substitution(ciphertext):
    return "".join((list(map(lambda x:
                             hex(byte_substitution_dec(int(x, 16)))[2:].zfill(2), chunkstring(ciphertext, 2)))))

def inverse_mix_column(ciphertext):
    inverse_matrix = numpy.array([[0x0E, 0x0B, 0x0D, 0x09],
                               [0x09, 0x0E, 0x0B, 0x0D],
                               [0x0D, 0x09, 0x0E, 0x0B],
                               [0x0B, 0x0D, 0x09, 0x0E]])
    ciphertext_input_int = map(ord, ciphertext.decode('hex'))
    for i in range(4):
        buffer_input_int = numpy.array(ciphertext_input_int[i*4:i*4+4])[numpy.newaxis]
        buffer_input_int = buffer_input_int.T
        buffer_output_int = numpy.dot(inverse_matrix, buffer_input_int)
        print buffer_output_int

    # for char in chunkstring(ciphertext,2):
    #     # buffer_input.append(char)
    #     buffer_input_int = map(ord, .decode('hex'))
    #     map(int, buffer_input)
    return ciphertext_input_int
    # for i in range(4):
    #
    #     B = list()
    #     Array = numpy
    #     B[0:4] = numpy.array([C[0], C[1], C[2], C[3]]).dot(Array)



# keys_encryption = key_expansion(key)
# keys_decryption = keys_encryption[::-1]
# print keys_decryption

# print inverse_shift_rows("091230aade3eb330dbaa4358f88d2a6c")
# print key_addition("091230aade3eb330dbaa4358f88d2a6c", "37b72d0cf4c22c344aec4142d00ce530")
# print inverse_byte_substitution("091230aade3eb330dbaa4358f88d2a6c")

print inverse_mix_column("091230aade3eb330dbaa4358f88d2a6c")
