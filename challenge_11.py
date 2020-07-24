"""An ECB/CBC detection oracle."""
from secrets import randbits, choice
from challenge_6 import chunks
from challenge_7 import ECB
from challenge_8 import count_repeats
from challenge_9 import pkcs7
from challenge_10 import CBC


def generate_bytes(n):
    """Generate n number of random bytes in a Byte object."""
    bstring = b""
    for i in range(n):
        bstring += bytes([randbits(8)])
    return bstring


def encryption_oracle(plaintext):
    """Encryption oracle with text input."""
    keysize = 16
    plaintext = generate_bytes(choice(range(5, 11))) + plaintext
    plaintext += generate_bytes(choice(range(5, 11)))
    plaintext = pkcs7(plaintext, keysize)
    key = generate_bytes(keysize)

    method = choice(range(0, 2))
    if method == 0:
        ciphertext = ECB(key).encrypt(plaintext)
    else:
        ciphertext = CBC(key, generate_bytes(keysize)).encrypt(plaintext)

    return ciphertext


def detect_ecb(oracle, keysize):
    """Detect ECB encryption."""
    c = chunks(oracle(b"A"*100), keysize)
    if count_repeats(c) > 0:
        return True
    else:
        return False

# detect_ecb(encryption_oracle, 16)
