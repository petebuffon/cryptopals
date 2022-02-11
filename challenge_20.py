"""Break fixed-nonce CTR statistically."""
from base64 import b64decode
from challenge_02 import xor
from challenge_03 import KeyScore
from challenge_06 import transpose
from challenge_11 import generate_bytes
from challenge_18 import CTR


def brute_ctr(ciphertext, keysize):
    """Brute force ciphertext encrypted with CTR."""
    key = b""
    for chunk in ciphertext:
        key += KeyScore(chunk).key
    n = len(ciphertext)
    k = keysize
    keystream = n // k * key + key[:n % k]
    return keystream


# encrypt lines in file
KEY = generate_bytes(16)
NONCE = b"\x00\x00\x00\x00\x00\x00\x00\x00"
COUNTER = 0
ciphertexts = []
with open("20.txt", "r") as file:
    for line in file:
        plaintext = b64decode(line)
        ciphertexts.append(CTR(KEY, NONCE).encrypt(plaintext))

# length of smallest ciphertext
n = min(len(ciphertext) for ciphertext in ciphertexts)
# break ciphertexts into chunks of smallest ciphertext
truncated = [ciphertext[:n] for ciphertext in ciphertexts]
transposed = transpose(truncated, 53)

keystream = brute_ctr(transposed, n)
plaintext = [xor(chunk, keystream) for chunk in truncated]
for line in plaintext:
    print(line.decode())
