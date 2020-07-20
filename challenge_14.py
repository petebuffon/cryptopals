"""Byte-at-a-time ECB decryption (Harder)"""
from base64 import b64decode
from secrets import choice
from challenge_6 import chunks
from challenge_7 import ECB
from challenge_9 import pkcs7
from challenge_11 import generate_bytes, detect_ecb


def encryption_oracle(your_string):
    """Concatenates 'random_prefix', 'your_string' and 'unknown_string', adds PKCS#7 padding, and
    encrypts the resulting string with AES-128-ECB using a randomally generated key."""
    unknown_string = b64decode("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpci
    BjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vL
    CBJIGp1c3QgZHJvdmUgYnkK""")
    plaintext = RANDOM_PREFIX + your_string + unknown_string
    plaintext = pkcs7(plaintext, 16)
    ciphertext = ECB(KEY).encrypt(plaintext)
    return ciphertext


def extract_secret(oracle, offset, keysize):
    """Extracts secret text from encryption oracle with a known offst and keysize."""
    plaintext = b""
    # iterate over the blocksize
    for i in range(0, len(oracle(b"A"*offset + b"")[16:]), keysize):
        h = keysize - 1
        for j in range(keysize):
            block = oracle(b"A"*offset + b"A"*h)[16:][i:i+keysize]
            byte_dict = {}
            for k in range(127):
                byte_dict[k] = oracle(b"A"*offset + b"A"*h + plaintext + bytes([k]))[16:][i:i+keysize]
            for key, value in byte_dict.items():
                if block == value:
                    plaintext += bytes([key])
            h -= 1
    return plaintext


def extract_prefix_secret():
    """Iterate over offsets from 0-16 returning secret when output != b''"""
    for i in range(16):
        if extract_secret(encryption_oracle, i, 16) != b"":
            return extract_secret(encryption_oracle, i, 16)


KEY = generate_bytes(16)
RANDOM_PREFIX = generate_bytes(16)

# print(extract_prefix_secret())
