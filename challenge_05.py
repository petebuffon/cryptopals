"""Implement repeating-key XOR."""
from challenge_02 import xor


def repeating_key_xor_encrypt(plaintext, key):
    """Encrypts plaintext with repeating-key XOR."""
    n = len(plaintext)
    k = len(key)
    return xor(n // k * key + key[:n % k], plaintext)


# plaintext = b"Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
# key = b"ICE"
# print(repeating_key_xor_encrypt(plaintext, key).hex())
