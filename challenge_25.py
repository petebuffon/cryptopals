"""Break "random access read/write" AES CTR"""
from base64 import b64decode
from os import urandom
from copy import deepcopy
from challenge_02 import xor
from challenge_07 import ECB
from challenge_18 import CTR


def edit(ciphertext, offset, newtext):
    """Exposed edit CTR ciphertext API"""
    n = len(newtext)
    counter = offset // 16
    padding = offset % 16
    newciphertext = CTR(KEY, NONCE).encrypt(b"A" * padding + newtext, counter=counter)[padding:]
    ciphertext[offset:offset + n] = newciphertext

# random key and nonce
KEY = urandom(16)
NONCE = urandom(16)

# decrypt ECB ciphertext (challenge 07) and encrypt with CTR
with open("25.txt") as f:
    tmp_ciphertext = f.read()
tmp_ciphertext = b64decode(tmp_ciphertext)
plaintext = ECB(b"YELLOW SUBMARINE").decrypt(tmp_ciphertext)
ciphertext = bytearray(CTR(KEY, NONCE).encrypt(plaintext))

# deep copy ciphertext
mod_ciphertext = deepcopy(ciphertext)
# modified plaintext AAA...
mod_plaintext = b"A" * len(mod_ciphertext)
# generate modified ciphertext using modified plaintext
edit(mod_ciphertext, KEY, 0, mod_plaintext)
# keystream = modified ciphertext ^ modified plaintext
keystream = xor(mod_ciphertext, mod_plaintext)
# plaintext = keystream ^ ciphertext
cracked = xor(keystream, ciphertext)
