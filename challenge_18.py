"""Implement CTR, the stream cipher mode."""
from base64 import b64decode
from struct import pack
from challenge_02 import xor
from challenge_06 import chunks
from challenge_07 import ECB


class CTR:
    """Encryption or decryption of plaintext/ciphertext using AES-128-CTR."""

    def __init__(self, key, nonce):
        """Key and nonce."""
        self.key = key
        self.nonce = nonce

    def encrypt(self, plaintext):
        """Encrypt ciphertext with key using AES-128-CTR."""
        counter = 0
        ciphertext = b""
        c = chunks(plaintext, 16)
        for chunk in c:
            n = len(chunk)
            keystream = ECB(self.key).encrypt(self.nonce + pack("Q", counter))
            ciphertext += xor(keystream[0:n], chunk)
            counter += 1
        return ciphertext

    def decrypt(self, ciphertext):
        """Decrypt ciphertext with key using AES-128-CTR."""
        counter = 0
        plaintext = b""
        c = chunks(ciphertext, 16)
        for chunk in c:
            n = len(chunk)
            keystream = ECB(self.key).encrypt(self.nonce + pack("Q", counter))
            plaintext += xor(keystream[0:n], chunk)
            counter += 1
        return plaintext


ciphertext = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
KEY = b"YELLOW SUBMARINE"
NONCE = b"\x00\x00\x00\x00\x00\x00\x00\x00"

# print(CTR(KEY, NONCE).decrypt(ciphertext))
