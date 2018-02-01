#!/usr/bin/python

# Here is the opening stanza of an important work of the English language:
#
# Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal
#
#
# Encrypt it, under the key "ICE", using repeating-key XOR.
#
# In repeating-key XOR, you'll sequentially apply each byte of the key;
# the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.
#
# It should come out to:
#
# 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
# a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
#

# Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file.
# Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.

# the demo plaintext, ciphertext and key
str1 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
cipher = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a" \
         "653e2b2027630c692b20283165286326302e27282f"
key = "ICE"


# this function creates the key string according to the length of the plaintext
def create_key(text, key):
    keystream = (len(text) / len(key)) * key + key[:(len(text) % len(key))]

    return keystream


# this function encrypts the plaintext
def encrypt(plaintext, keystream):
    plaintext = plaintext.encode("hex")
    keystream = keystream.encode("hex")
    ciphertext = ''.join(hex(int(a, 16) ^ int(b, 16))[2:] for a, b in zip(plaintext, keystream))
    return ciphertext


# this function decrypts the ciphertext
def decrypt(ciphertext, keystream):
    keystream = keystream.encode("hex")
    plaintext_hex = ''.join(hex(int(a, 16) ^ int(b, 16))[2:] for a, b in zip(ciphertext, keystream))
    plaintext = ''.join(chr(int(plaintext_hex[i:i + 2], 16)) for i in range(0, len(plaintext_hex), 2))
    return plaintext


# encryption
print encrypt(str1, create_key(str1, key))

# decryption
print decrypt(cipher, create_key(cipher, key))
