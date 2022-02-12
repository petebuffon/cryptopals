"""An ECB/CBC detection oracle."""
from os import urandom
from secrets import choice
from challenge_06 import chunks
from challenge_07 import ECB
from challenge_08 import count_repeats
from challenge_09 import pkcs7_pad
from challenge_10 import CBC


def encryption_oracle(plaintext):
    """Encryption oracle with text input."""
    keysize = 16
    plaintext = urandom(choice(range(5, 11))) + plaintext
    plaintext += urandom(choice(range(5, 11)))
    plaintext = pkcs7_pad(plaintext, keysize)
    key = urandom(keysize)

    method = choice(range(0, 2))
    if method == 0:
        ciphertext = ECB(key).encrypt(plaintext)
    else:
        ciphertext = CBC(key, urandom(keysize)).encrypt(plaintext)

    return ciphertext


def detect_ecb(oracle, keysize):
    """Detect ECB encryption."""
    c = chunks(oracle(b"A"*100), keysize)
    if count_repeats(c) > 0:
        return True
    else:
        return False

# detect_ecb(encryption_oracle, 16)
