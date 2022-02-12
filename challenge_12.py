"""Byte-at-a-time ECB decryption (Simple)."""
from os import urandom
from base64 import b64decode
from challenge_07 import ECB
from challenge_09 import pkcs7_pad
from challenge_11 import detect_ecb


def encryption_oracle(your_string):
    """Encryption oracle with text input."""
    unknown_string = b64decode("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpci
    BjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vL
    CBJIGp1c3QgZHJvdmUgYnkK""")
    plaintext = your_string + unknown_string
    plaintext = pkcs7_pad(plaintext, 16)
    ciphertext = ECB(KEY).encrypt(plaintext)
    return ciphertext


def detect_blocksize(oracle):
    """Detect cipher blocksize."""
    n = len(oracle(b""))
    for i in range(1, 101):
        k = len(oracle(b"A"*i))
        if k > n:
            n = k
            break
    for j in range(1, 101):
        k = len(oracle(b"A"*j))
        if k > n:
            return j - i


def extract_secret(oracle, keysize):
    """Extract secret text from encryption oracle with a known keysize."""
    plaintext = b""
    # iterate over the blocksize
    for i in range(0, len(oracle(b"")), keysize):
        h = keysize - 1
        for j in range(keysize):
            block = oracle(b"A"*h)[i:i+keysize]
            byte_dict = {}
            for k in range(127):
                byte_dict[k] = oracle(b"A"*h + plaintext + bytes([k]))[i:i+keysize]
            for key, value in byte_dict.items():
                if block == value:
                    plaintext += bytes([key])
            h -= 1
    return plaintext


# KEY = urandom(16)
# print(detect_blocksize(encryption_oracle))
# print(detect_ecb(encryption_oracle, 16))
# print(extract_secret(encryption_oracle, 16))
